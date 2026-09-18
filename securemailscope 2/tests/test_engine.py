"""Engine tests: parsing, scoring, grounding, and the properties that matter
for a public demo — chiefly that a well-configured domain scores 100 with
nothing to fix, and that a check which could not run never looks like a failure.
"""
from __future__ import annotations

import pytest

from app import ai
from app.ai import deterministic
from app.ai.validation import ValidationError, parse_and_validate
from app.checks import dkim, dmarc, policy, spf
from app.engine import scanner, scoring
from app.engine.scanner import InvalidDomain, ScanOptions
from app.models import Severity, Status
from app.resolver import FixtureResolver
from tests import fixtures


def scan(zone: dict, domain: str):
    """Run a full scan against a recorded zone with all live probing disabled."""
    return scanner.scan(
        domain,
        ScanOptions(probe_tls=False, enumerate_tls_versions=False,
                    fetch_mta_sts_policy=False),
        resolver=FixtureResolver(zone),
    )


# --------------------------------------------------------------------------- SPF

def test_spf_strict_record_passes():
    r = spf.run("secure.example", FixtureResolver(fixtures.WELL_CONFIGURED))
    assert not [f for f in r.findings if f.counts_against_score]
    assert r.raw["dns_lookups"] == 1                      # one include


def test_spf_missing_record_is_high_severity():
    r = spf.run("nothing.example", FixtureResolver({}))
    ids = {f.id for f in r.findings}
    assert "spf.missing" in ids
    assert next(f for f in r.findings if f.id == "spf.missing").severity == Severity.HIGH


def test_spf_plus_all_is_critical():
    r = spf.run("spoofable.example", FixtureResolver(fixtures.SPOOFABLE))
    finding = next(f for f in r.findings if f.id == "spf.all_pass")
    assert finding.severity == Severity.CRITICAL
    assert finding.status == Status.FAIL


def test_spf_flags_neutral_broad_range_and_ptr():
    r = spf.run("broken.example", FixtureResolver(fixtures.MISCONFIGURED))
    ids = {f.id for f in r.findings}
    assert "spf.all_neutral" in ids
    assert "spf.overly_broad_range" in ids
    assert "spf.ptr_mechanism" in ids


def test_spf_counts_nested_include_lookups():
    """The lookup budget must be counted by walking includes, not by counting
    the terms in the top-level record."""
    r = spf.run("broken.example", FixtureResolver(fixtures.MISCONFIGURED))
    # ip4 costs nothing; ptr + include = 2, relay adds a+mx+include = 3,
    # deep adds a+mx+a+a = 4 → 9 total.
    assert r.raw["dns_lookups"] == 9


def test_spf_concatenates_split_txt_strings():
    """RFC 7208 requires multi-string TXT records to be joined without separators."""
    zone = {"TXT:split.example": ["v=spf1 include:_spf.example.com -all"]}
    r = spf.run("split.example", FixtureResolver(zone))
    assert not any(f.id == "spf.syntax_error" for f in r.findings)


# --------------------------------------------------------------------------- DMARC

def test_dmarc_reject_policy_passes():
    r = dmarc.run("secure.example", FixtureResolver(fixtures.WELL_CONFIGURED))
    assert not [f for f in r.findings if f.counts_against_score]


def test_dmarc_missing_is_critical():
    r = dmarc.run("nothing.example", FixtureResolver({}))
    finding = next(f for f in r.findings if f.id == "dmarc.missing")
    assert finding.severity == Severity.CRITICAL


def test_dmarc_flags_none_subdomain_and_pct():
    r = dmarc.run("broken.example", FixtureResolver(fixtures.MISCONFIGURED))
    ids = {f.id for f in r.findings}
    assert "dmarc.policy_none" in ids
    assert "dmarc.no_aggregate_reporting" in ids
    # sp=none only matters when the apex policy is stronger; here p=none already
    # fails, so the subdomain finding must not be double-counted.
    assert "dmarc.subdomain_policy_weak" not in ids


def test_dmarc_subdomain_exemption_flagged_when_apex_enforces():
    zone = {"TXT:_dmarc.x.example": ["v=DMARC1; p=reject; sp=none; rua=mailto:a@x.example"]}
    r = dmarc.run("x.example", FixtureResolver(zone))
    assert any(f.id == "dmarc.subdomain_policy_weak" for f in r.findings)


# --------------------------------------------------------------------------- DKIM

def test_dkim_measures_real_key_size():
    r = dkim.run("secure.example", FixtureResolver(fixtures.WELL_CONFIGURED),
                 selectors=["google", "selector1"])
    assert all(k["key_bits"] == 2048 for k in r.raw["keys"])
    assert not [f for f in r.findings if f.counts_against_score]


def test_dkim_flags_short_key_and_testing_mode():
    r = dkim.run("broken.example", FixtureResolver(fixtures.MISCONFIGURED),
                 selectors=["google"])
    ids = {f.id for f in r.findings}
    assert "dkim.short_key.google" in ids
    assert "dkim.testing_mode.google" in ids
    assert r.raw["keys"][0]["key_bits"] == 1024


def test_dkim_absence_is_reported_as_undiscovered_not_absent():
    """Selectors cannot be enumerated, so the tool must not claim DKIM is missing."""
    r = dkim.run("nothing.example", FixtureResolver({}), selectors=["google", "s1"])
    finding = next(f for f in r.findings if f.id == "dkim.not_discovered")
    assert finding.severity == Severity.MEDIUM
    assert "does not prove DKIM is absent" in finding.detail


def test_dkim_malformed_key_is_flagged():
    zone = {"TXT:google._domainkey.bad.example": ["v=DKIM1; k=rsa; p=!!!notbase64!!!"]}
    r = dkim.run("bad.example", FixtureResolver(zone), selectors=["google"])
    assert any(f.id == "dkim.malformed.google" for f in r.findings)


# --------------------------------------------------------------------------- policy

def test_mta_sts_missing_flagged():
    r = policy.run_mta_sts("nothing.example", FixtureResolver({}), fetch_policy=False)
    assert any(f.id == "mta_sts.missing" for f in r.findings)


def test_tls_rpt_present_passes():
    r = policy.run_tls_rpt("secure.example", FixtureResolver(fixtures.WELL_CONFIGURED))
    assert any(f.id == "tls_rpt.ok" for f in r.findings)


def test_bimi_absence_carries_no_weight():
    r = policy.run_bimi("nothing.example", FixtureResolver({}))
    finding = r.findings[0]
    assert finding.status == Status.NOT_APPLICABLE
    assert not finding.counts_against_score
    assert scoring.CHECK_WEIGHTS["bimi"] == 0.0


# --------------------------------------------------------------------------- scoring

def test_well_configured_domain_scores_full_marks():
    """The demo question: 'what if I give it a domain with perfect config?'"""
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    assert a.score.score == 100
    assert a.score.grade == "A+"
    assert a.findings_by_severity() == []


def test_misconfigured_domain_scores_poorly():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    assert a.score.score < 55
    assert a.score.grade in ("F", "D-", "D", "D+", "C-")
    assert len(a.findings_by_severity()) >= 5


def test_spoofable_domain_scores_near_zero():
    a = scan(fixtures.SPOOFABLE, "spoofable.example")
    assert a.score.score < 25


def test_score_is_bounded():
    for zone, domain in [
        (fixtures.WELL_CONFIGURED, "secure.example"),
        (fixtures.MISCONFIGURED, "broken.example"),
        (fixtures.SPOOFABLE, "spoofable.example"),
        ({}, "empty.example"),
    ]:
        a = scan(zone, domain)
        assert -1 <= a.score.score <= 100


def test_one_check_cannot_deduct_more_than_its_weight():
    a = scan(fixtures.SPOOFABLE, "spoofable.example")
    for deduction in a.score.deductions:
        if deduction.get("excluded"):
            continue
        assert deduction["points"] <= scoring.CHECK_WEIGHTS[deduction["check"]] + 0.001


def test_inconclusive_check_is_excluded_not_failed():
    """A scanner-side network restriction must never be reported as a weakness."""
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    transport = next(c for c in a.checks if c.check_id == "transport")
    # TLS probing is off, so transport is inconclusive.
    assert scoring._is_inconclusive(transport)
    excluded = [d["check"] for d in a.score.deductions if d.get("excluded")]
    assert "transport" in excluded
    # And the score is unaffected by its exclusion.
    assert a.score.score == 100
    assert a.score.max_points < sum(scoring.CHECK_WEIGHTS.values())


def test_domain_with_no_mx_is_not_penalised_for_transport():
    a = scan(fixtures.NO_MAIL, "nomail.example")
    assert a.score.score == 100


def test_grade_bands_are_monotonic():
    previous = None
    for value in range(100, -1, -1):
        grade = scoring.grade_for(value)
        assert grade in {g for _, g in scoring.GRADE_BANDS}
        previous = grade
    assert scoring.grade_for(100) == "A+"
    assert scoring.grade_for(0) == "F"


# --------------------------------------------------------------------------- input

@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://example.com/path?q=1", "example.com"),
    ("user@example.com", "example.com"),
    ("example.com:443", "example.com"),
    ("example.com.", "example.com"),
    ("  sub.example.co.uk  ", "sub.example.co.uk"),
])
def test_domain_normalisation(raw, expected):
    assert scanner.normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "not a domain", "localhost", "192.0.2.1", "-bad.com"])
def test_invalid_domains_rejected(raw):
    with pytest.raises(InvalidDomain):
        scanner.normalise_domain(raw)


# --------------------------------------------------------------------------- narrative

def test_deterministic_narrative_for_clean_domain_proposes_nothing():
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    n = deterministic.generate(a)
    assert n.remediation_steps == []
    assert n.attack_scenarios == []
    assert "nothing to remediate" in n.summary.lower()


def test_deterministic_narrative_describes_real_findings():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    n = deterministic.generate(a)
    assert n.source == "deterministic"
    assert n.remediation_steps
    assert any("spoof" in s.lower() for s in n.attack_scenarios + [n.summary])
    # Every step must point at a finding the engine actually produced.
    valid = {f.id for f in a.findings}
    assert all(step["finding_id"] in valid for step in n.remediation_steps)


def test_narrative_falls_back_when_no_provider():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    n = ai.generate_narrative(a, provider=None, use_llm=False)
    assert n.source == "deterministic"
    assert n.fallback_reason


# --------------------------------------------------------------------------- grounding

def test_validation_rejects_invented_score():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    raw = '{"summary": "The domain scores 95/100 and is in good shape.", ' \
          '"attack_scenarios": [], "remediation_steps": []}'
    with pytest.raises(ValidationError, match="claims a score"):
        parse_and_validate(raw, a)


def test_validation_rejects_invented_grade():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    raw = '{"summary": "Overall this earns a grade of A.", ' \
          '"attack_scenarios": [], "remediation_steps": []}'
    with pytest.raises(ValidationError, match="claims grade"):
        parse_and_validate(raw, a)


def test_validation_rejects_unknown_finding_reference():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    raw = '{"summary": "Issues found.", "attack_scenarios": [], ' \
          '"remediation_steps": [{"action": "Fix it", "finding_id": "spf.nonexistent"}]}'
    with pytest.raises(ValidationError, match="unknown finding id"):
        parse_and_validate(raw, a)


def test_validation_rejects_manufactured_work_on_clean_domain():
    """The hallucination case that matters most on a demo stage."""
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    raw = '{"summary": "Mostly fine.", "attack_scenarios": [], ' \
          '"remediation_steps": [{"action": "Consider tightening SPF"}]}'
    with pytest.raises(ValidationError, match="no issues but"):
        parse_and_validate(raw, a)


def test_validation_rejects_manufactured_scenarios_on_clean_domain():
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    raw = '{"summary": "Fine.", "attack_scenarios": ["An attacker could spoof you."], ' \
          '"remediation_steps": []}'
    with pytest.raises(ValidationError):
        parse_and_validate(raw, a)


def test_validation_accepts_grounded_narrative():
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    finding_id = a.findings_by_severity()[0].id
    score = a.score.score
    raw = (f'```json\n{{"summary": "The domain scores {score}/100. DMARC is not '
           f'enforcing.", "attack_scenarios": ["Forged mail is delivered."], '
           f'"remediation_steps": [{{"priority": "1", "finding_id": "{finding_id}", '
           f'"action": "Move DMARC to p=reject.", "rationale": "Largest risk reduction."}}]}}\n```')
    payload = parse_and_validate(raw, a)
    assert payload["summary"].startswith("The domain scores")


def test_validation_rejects_non_json():
    a = scan(fixtures.WELL_CONFIGURED, "secure.example")
    with pytest.raises(ValidationError):
        parse_and_validate("I'm afraid I can't do that.", a)


def test_llm_prompt_contains_only_engine_output():
    """The model must not be handed anything it could mistake for a new finding."""
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    prompt = ai._build_user_prompt(a)
    import json as _json
    payload = _json.loads(prompt)
    assert set(payload) == {"domain", "score", "grade", "scanned_at",
                            "checks_that_could_not_complete", "findings"}
    engine_ids = {f.id for f in a.findings}
    assert {f["id"] for f in payload["findings"]} == engine_ids


# --------------------------------------------------------------------------- report

def test_pdf_builds_for_every_fixture():
    from app.report import build_pdf
    for zone, domain in [
        (fixtures.WELL_CONFIGURED, "secure.example"),
        (fixtures.MISCONFIGURED, "broken.example"),
        (fixtures.SPOOFABLE, "spoofable.example"),
        ({}, "empty.example"),
    ]:
        a = scan(zone, domain)
        a.narrative = deterministic.generate(a)
        pdf = build_pdf(a.to_dict())
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 2000


def test_assessment_serialises_to_json():
    import json as _json
    a = scan(fixtures.MISCONFIGURED, "broken.example")
    a.narrative = deterministic.generate(a)
    text = _json.dumps(a.to_dict(), default=str)
    assert _json.loads(text)["domain"] == "broken.example"


# --------------------------------------------------------------------------- resolver

def test_resolver_caches_repeat_queries():
    resolver = FixtureResolver(fixtures.WELL_CONFIGURED)
    resolver.query("secure.example", "TXT")
    resolver.query("secure.example", "TXT")
    assert resolver.query_log.count("TXT:secure.example") == 1


def test_doh_txt_unquoting_joins_chunks():
    from app.resolver import _unquote_txt
    assert _unquote_txt('"v=spf1 " "include:a.example -all"') == "v=spf1 include:a.example -all"
    assert _unquote_txt('"simple"') == "simple"
