"""Tests for one property that decides whether the tool can be trusted at all:
a failure on the scanner's side must never be reported as a weakness in the
domain being assessed.

These cover the paths a judge or a user is most likely to hit accidentally —
port 25 blocked by a cloud provider, a filtered resolver, a proxy in the way.
"""
from __future__ import annotations

from unittest import mock

from app.checks import policy, spf, transport
from app.engine import scanner, scoring
from app.engine.scanner import ScanOptions
from app.models import Status
from app.resolver import DNSError, FixtureResolver
from tests import fixtures


class FailingResolver(FixtureResolver):
    """Every lookup raises, as it would behind a filtered resolver."""

    def _do_query(self, name: str, rdtype: str):
        raise DNSError("simulated resolver failure")


def test_dns_failure_produces_error_not_failure():
    r = spf.run("example.com", FailingResolver({}))
    assert r.error
    assert all(f.status == Status.ERROR for f in r.findings)
    assert not any(f.counts_against_score for f in r.findings)


def test_total_dns_failure_yields_no_score_not_zero():
    """Scoring 0 would read as 'catastrophically insecure'. It must read as
    'not determined'."""
    a = scanner.scan(
        "example.com",
        ScanOptions(probe_tls=False, fetch_mta_sts_policy=False),
        resolver=FailingResolver({}),
    )
    assert a.score.score == -1
    assert a.score.grade == "N/A"
    assert scoring.risk_label(a.score.score) == "Not determined"


def test_blocked_port_25_is_reported_as_inconclusive():
    """The single most common environment problem: cloud hosts block outbound 25."""
    with mock.patch("app.checks.transport._probe_host") as probe:
        probe.return_value = {
            "host": "mx1.example.com", "connected": False, "error": "TimeoutError",
            "starttls": False, "tls": None, "certificate": None, "versions": {},
        }
        r = transport.run("example.com", FixtureResolver({
            "MX:example.com": ["10 mx1.example.com"],
        }), probe_tls=True, enumerate_versions=False)

    finding = r.findings[0]
    assert finding.id == "transport.unreachable"
    assert finding.status == Status.ERROR
    assert not finding.counts_against_score
    assert scoring._is_inconclusive(r)
    # And the wording must point at the scanner, not blame the domain.
    assert "blocks outbound port 25" in finding.detail


def test_mta_sts_connection_failure_is_inconclusive_not_a_finding():
    """A proxy or egress restriction between the scanner and the policy host."""
    with mock.patch("app.checks.policy._fetch_mta_sts_policy") as fetch:
        fetch.return_value = {
            "url": "https://mta-sts.example.com/.well-known/mta-sts.txt",
            "error": "URLError: Tunnel connection failed: 403 Forbidden",
            "server_responded": False,
        }
        r = policy.run_mta_sts("example.com", FixtureResolver({
            "TXT:_mta-sts.example.com": ["v=STSv1; id=1"],
        }))

    finding = next(f for f in r.findings if f.id.startswith("mta_sts.policy"))
    assert finding.status == Status.ERROR
    assert not finding.counts_against_score


def test_mta_sts_http_error_is_a_real_finding():
    """By contrast, a policy host that answers 404 really is misconfigured."""
    with mock.patch("app.checks.policy._fetch_mta_sts_policy") as fetch:
        fetch.return_value = {
            "url": "https://mta-sts.example.com/.well-known/mta-sts.txt",
            "error": "HTTP 404",
            "server_responded": True,
        }
        r = policy.run_mta_sts("example.com", FixtureResolver({
            "TXT:_mta-sts.example.com": ["v=STSv1; id=1"],
        }))

    finding = next(f for f in r.findings if f.id == "mta_sts.policy_unreachable")
    assert finding.status == Status.FAIL
    assert finding.counts_against_score


def test_partial_failure_scores_only_what_was_assessed():
    """DNS works, port 25 does not — the score must reflect the DNS checks alone."""
    a = scanner.scan(
        "secure.example",
        ScanOptions(probe_tls=False, fetch_mta_sts_policy=False),
        resolver=FixtureResolver(fixtures.WELL_CONFIGURED),
    )
    assert a.score.score == 100
    assert a.score.max_points < sum(scoring.CHECK_WEIGHTS.values())
    excluded = {d["check"] for d in a.score.deductions if d.get("excluded")}
    assert "transport" in excluded


def test_crashing_check_does_not_abort_the_scan():
    with mock.patch("app.checks.dkim.run", side_effect=RuntimeError("boom")):
        a = scanner.scan(
            "secure.example",
            ScanOptions(probe_tls=False, fetch_mta_sts_policy=False),
            resolver=FixtureResolver(fixtures.WELL_CONFIGURED),
        )
    dkim_check = next(c for c in a.checks if c.check_id == "dkim")
    assert dkim_check.error and "boom" in dkim_check.error
    # Every other check still ran, and the score excludes the broken one.
    assert len(a.checks) == 7
    assert a.score.score == 100
