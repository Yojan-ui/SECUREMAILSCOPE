"""SPF (RFC 7208) record discovery and evaluation.

Checks performed:
  * exactly one v=spf1 TXT record exists at the apex
  * the terminal `all` mechanism and its qualifier (-, ~, ?, +)
  * the 10-term DNS-lookup limit, counted by actually walking includes
  * deprecated / overly broad mechanisms (ptr, bare ip4 /0-/8, +all)
  * redirect= handling and macro presence
"""
from __future__ import annotations

import re
import time
from typing import Any

from ..models import Category, CheckResult, Finding, Severity, Status
from ..resolver import BaseResolver, DNSError, NoRecord

CHECK_ID = "spf"
CATEGORY = Category.AUTHENTICATION

# RFC 7208 §4.6.4: these mechanisms each cost one DNS lookup, capped at 10.
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}

_TERM_RE = re.compile(
    r"^(?P<qualifier>[+\-~?])?(?P<name>[a-z0-9_\-]+)(?:(?P<sep>[:=])(?P<value>\S*))?$",
    re.IGNORECASE,
)


def run(domain: str, resolver: BaseResolver) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id=CHECK_ID, name="SPF", category=CATEGORY)

    try:
        records = [
            r for r in resolver.query_optional(domain, "TXT", domain)
            if r.lower().startswith("v=spf1")
        ]
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(
            Finding(
                id="spf.lookup_failed",
                title="SPF record could not be retrieved",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"The TXT lookup for {domain} failed: {exc}. "
                       "No conclusion about SPF can be drawn from this scan.",
                evidence={"error": str(exc)},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.raw["records"] = records

    if not records:
        result.findings.append(
            Finding(
                id="spf.missing",
                title="No SPF record published",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail=f"{domain} publishes no v=spf1 TXT record. Receiving mail servers "
                       "have no authorised-sender list to check against, so mail claiming "
                       "to come from this domain cannot be validated by SPF.",
                evidence={"txt_records_checked": True, "spf_records_found": 0},
                remediation='Publish a TXT record at the apex, e.g. '
                            '"v=spf1 include:_spf.yourprovider.com -all", listing every '
                            "service that sends mail as this domain.",
                reference="RFC 7208 §3",
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if len(records) > 1:
        # RFC 7208 §4.5: multiple SPF records is a PermError — receivers stop evaluating.
        result.findings.append(
            Finding(
                id="spf.multiple_records",
                title=f"{len(records)} SPF records published",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail="More than one v=spf1 record exists. RFC 7208 requires receivers to "
                       "treat this as a permanent error and abandon SPF evaluation entirely, "
                       "so the domain is effectively unprotected by SPF.",
                evidence={"records": records},
                remediation="Merge the records into a single TXT record with one v=spf1 prefix.",
                reference="RFC 7208 §4.5",
            )
        )

    record = records[0]
    parsed = _parse(record)
    result.raw["parsed"] = parsed

    if parsed["syntax_errors"]:
        result.findings.append(
            Finding(
                id="spf.syntax_error",
                title="SPF record contains invalid terms",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="These terms are not valid SPF syntax and may cause receivers to "
                       f"return PermError: {', '.join(parsed['syntax_errors'])}.",
                evidence={"invalid_terms": parsed["syntax_errors"], "record": record},
                remediation="Correct or remove the invalid terms.",
                reference="RFC 7208 §7.1",
            )
        )

    _evaluate_all_mechanism(parsed, record, result)
    _evaluate_lookup_budget(domain, parsed, resolver, result)
    _evaluate_broad_mechanisms(parsed, record, result)

    if not any(f.counts_against_score for f in result.findings):
        result.findings.append(
            Finding(
                id="spf.ok",
                title="SPF record is present and well-formed",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"A single valid SPF record ends in "
                       f"{parsed['all_qualifier'] or ''}all and stays within the "
                       "10-lookup limit.",
                evidence={"record": record},
            )
        )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _parse(record: str) -> dict[str, Any]:
    terms: list[dict[str, Any]] = []
    syntax_errors: list[str] = []
    all_qualifier: str | None = None
    redirect: str | None = None

    for raw_term in record.split()[1:]:  # skip the v=spf1 version token
        m = _TERM_RE.match(raw_term)
        if not m:
            syntax_errors.append(raw_term)
            continue
        name = m.group("name").lower()
        term = {
            "raw": raw_term,
            "qualifier": m.group("qualifier") or "+",
            "name": name,
            "value": m.group("value"),
        }
        if name == "all":
            all_qualifier = term["qualifier"]
        elif name == "redirect":
            redirect = m.group("value")
        elif name not in _LOOKUP_MECHANISMS and name not in {"ip4", "ip6", "exp"}:
            syntax_errors.append(raw_term)
        terms.append(term)

    return {
        "terms": terms,
        "syntax_errors": syntax_errors,
        "all_qualifier": all_qualifier,
        "redirect": redirect,
        "has_macros": "%{" in record,
    }


def _evaluate_all_mechanism(parsed: dict[str, Any], record: str, result: CheckResult) -> None:
    qualifier = parsed["all_qualifier"]

    if qualifier is None:
        if parsed["redirect"]:
            result.findings.append(
                Finding(
                    id="spf.redirect_terminal",
                    title="SPF terminates in a redirect",
                    status=Status.PASS,
                    severity=Severity.INFO,
                    category=CATEGORY,
                    detail=f"The record delegates evaluation to {parsed['redirect']}. "
                           "The effective policy is whatever that domain publishes.",
                    evidence={"redirect": parsed["redirect"]},
                )
            )
            return
        result.findings.append(
            Finding(
                id="spf.no_all",
                title="SPF record has no terminal `all` mechanism",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="Without a closing `all`, unlisted senders fall through to a neutral "
                       "result, which receivers treat much like having no policy at all.",
                evidence={"record": record},
                remediation="Append `-all` (strict) or `~all` (soft fail) to the record.",
                reference="RFC 7208 §5.1",
            )
        )
        return

    if qualifier == "+":
        result.findings.append(
            Finding(
                id="spf.all_pass",
                title="SPF record ends in `+all`",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                category=CATEGORY,
                detail="`+all` tells every receiver that any host on the internet is an "
                       "authorised sender for this domain. This is strictly worse than "
                       "publishing no SPF record, because it converts SPF from a control "
                       "into an explicit authorisation of any sender.",
                evidence={"record": record, "qualifier": "+"},
                remediation="Replace `+all` with `-all` and enumerate legitimate senders.",
                reference="RFC 7208 §5.1",
            )
        )
    elif qualifier == "?":
        result.findings.append(
            Finding(
                id="spf.all_neutral",
                title="SPF record ends in `?all` (neutral)",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail="A neutral result carries no more weight than having no SPF record. "
                       "Receivers are explicitly told to treat the sender as unverified.",
                evidence={"record": record, "qualifier": "?"},
                remediation="Move to `~all` while monitoring, then to `-all`.",
                reference="RFC 7208 §5.1",
            )
        )
    elif qualifier == "~":
        result.findings.append(
            Finding(
                id="spf.all_softfail",
                title="SPF record ends in `~all` (soft fail)",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail="Soft fail asks receivers to accept but mark unauthorised mail. This is "
                       "the correct setting while you are still discovering senders, but it "
                       "leaves a gap once your sender inventory is complete.",
                evidence={"record": record, "qualifier": "~"},
                remediation="Once DMARC reports show no legitimate sources failing SPF, "
                            "tighten `~all` to `-all`.",
                reference="RFC 7208 §5.1",
            )
        )


def _evaluate_lookup_budget(domain: str, parsed: dict[str, Any],
                            resolver: BaseResolver, result: CheckResult) -> None:
    """Walk includes/redirects to count real DNS-lookup terms (limit: 10)."""
    seen: set[str] = set()

    def count(target: str, terms: list[dict[str, Any]], depth: int) -> int:
        total = 0
        if depth > 10:
            return total
        for term in terms:
            name = term["name"]
            if name not in _LOOKUP_MECHANISMS and name != "redirect":
                continue
            total += 1
            nested_domain = term["value"]
            if name not in ("include", "redirect") or not nested_domain:
                continue
            if "%{" in nested_domain or nested_domain in seen:
                continue
            seen.add(nested_domain)
            try:
                nested = [
                    r for r in resolver.query_optional(nested_domain, "TXT", domain)
                    if r.lower().startswith("v=spf1")
                ]
            except DNSError:
                continue
            if nested:
                total += count(nested_domain, _parse(nested[0])["terms"], depth + 1)
        return total

    lookups = count(domain, parsed["terms"], 0)
    result.raw["dns_lookups"] = lookups

    if lookups > 10:
        result.findings.append(
            Finding(
                id="spf.lookup_limit_exceeded",
                title=f"SPF exceeds the 10 DNS-lookup limit ({lookups} required)",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail=f"Evaluating this record requires {lookups} DNS lookups. RFC 7208 caps "
                       "this at 10; beyond it receivers return PermError and SPF stops "
                       "protecting the domain — including for senders listed early in the "
                       "record, since evaluation order is not guaranteed to save them.",
                evidence={"lookups": lookups, "limit": 10, "includes": sorted(seen)},
                remediation="Flatten or consolidate includes, or drop unused providers. "
                            "Several vendors publish a single consolidated include for this.",
                reference="RFC 7208 §4.6.4",
            )
        )
    elif lookups >= 8:
        result.findings.append(
            Finding(
                id="spf.lookup_limit_near",
                title=f"SPF is close to the DNS-lookup limit ({lookups}/10)",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail=f"{lookups} of the 10 permitted lookups are in use. Adding one more "
                       "mail provider — or a provider expanding their own include — would "
                       "break SPF evaluation for the whole domain.",
                evidence={"lookups": lookups, "limit": 10},
                remediation="Reduce the number of include: terms before adding senders.",
                reference="RFC 7208 §4.6.4",
            )
        )


def _evaluate_broad_mechanisms(parsed: dict[str, Any], record: str, result: CheckResult) -> None:
    for term in parsed["terms"]:
        if term["name"] == "ptr":
            result.findings.append(
                Finding(
                    id="spf.ptr_mechanism",
                    title="SPF uses the deprecated `ptr` mechanism",
                    status=Status.WARN,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail="`ptr` is deprecated: it is slow, imposes load on reverse-DNS "
                           "infrastructure, and some receivers skip it entirely, producing "
                           "inconsistent results for the same message.",
                    evidence={"term": term["raw"]},
                    remediation="Replace `ptr` with explicit ip4/ip6 or include terms.",
                    reference="RFC 7208 §5.5",
                )
            )
        if term["name"] in ("ip4", "ip6") and term["value"]:
            prefix = term["value"].split("/")[-1] if "/" in term["value"] else None
            if prefix and prefix.isdigit() and term["name"] == "ip4" and int(prefix) <= 8:
                result.findings.append(
                    Finding(
                        id="spf.overly_broad_range",
                        title=f"SPF authorises an extremely large IP range ({term['raw']})",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        category=CATEGORY,
                        detail=f"{term['value']} authorises at least 16 million addresses as "
                               "legitimate senders. An attacker with a host anywhere in that "
                               "range passes SPF for this domain.",
                        evidence={"term": term["raw"], "prefix_length": int(prefix)},
                        remediation="Narrow the range to the addresses your mail servers "
                                    "actually use.",
                        reference="RFC 7208 §5.6",
                    )
                )
