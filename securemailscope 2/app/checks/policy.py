"""MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and BIMI checks.

MTA-STS is the control that stops an on-path attacker from stripping STARTTLS
(a downgrade to cleartext that SMTP's opportunistic TLS otherwise permits
silently), so it is verified properly: the DNS record *and* the HTTPS-hosted
policy file, with the mode and MX list parsed from it.
"""
from __future__ import annotations

import re
import time
from typing import Any

from ..models import Category, CheckResult, Finding, Severity, Status
from ..resolver import BaseResolver, DNSError

CATEGORY = Category.POLICY
_TAG_RE = re.compile(r"^\s*(?P<tag>[a-z]+)\s*=\s*(?P<value>[^;]*)\s*$", re.IGNORECASE)

MTA_STS_POLICY_MAX_BYTES = 64 * 1024
MTA_STS_FETCH_TIMEOUT = 8.0


# --------------------------------------------------------------------------- MTA-STS

def run_mta_sts(domain: str, resolver: BaseResolver, fetch_policy: bool = True,
                receives_mail: bool = True) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id="mta_sts", name="MTA-STS", category=CATEGORY)
    record_name = f"_mta-sts.{domain}"

    if not receives_mail:
        # MTA-STS governs how senders deliver *to* this domain. A domain that
        # publishes no MX receives no mail, so the control has nothing to protect
        # and its absence is not a weakness.
        result.findings.append(
            Finding(
                id="mta_sts.not_applicable",
                title="MTA-STS does not apply (domain receives no mail)",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{domain} publishes no MX records, so there is no inbound mail path "
                       "for MTA-STS to protect.",
                evidence={"mx_records": 0},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        records = [
            r for r in resolver.query_optional(record_name, "TXT", domain)
            if r.lower().replace(" ", "").startswith("v=stsv1")
        ]
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(_lookup_error("mta_sts", "MTA-STS", record_name, exc, CATEGORY))
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.raw["record_name"] = record_name
    result.raw["records"] = records

    if not records:
        result.findings.append(
            Finding(
                id="mta_sts.missing",
                title="MTA-STS is not configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail=f"No MTA-STS record exists at {record_name}. SMTP's opportunistic TLS "
                       "can be stripped by an on-path attacker simply by removing the "
                       "STARTTLS advertisement from the server greeting — the sending server "
                       "then delivers the message in cleartext and nothing alerts either "
                       "party. MTA-STS is the mechanism that makes TLS mandatory and "
                       "detectable for inbound mail.",
                evidence={"queried": record_name, "records_found": 0},
                remediation=f'Publish TXT "v=STSv1; id=<timestamp>" at {record_name} and host '
                            f"a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt, "
                            "starting in mode: testing before moving to mode: enforce.",
                reference="RFC 8461 §3",
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    tags = _parse_tags(records[0])
    result.raw["tags"] = tags

    if not tags.get("id"):
        result.findings.append(
            Finding(
                id="mta_sts.no_id",
                title="MTA-STS record is missing the `id=` tag",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="`id=` is mandatory: senders use it to detect that the policy has "
                       "changed. Without it, cached policies are never refreshed.",
                evidence={"record": records[0]},
                remediation="Add id= with a value that changes whenever the policy changes.",
                reference="RFC 8461 §3.1",
            )
        )

    if not fetch_policy:
        result.findings.append(
            Finding(
                id="mta_sts.policy_not_fetched",
                title="MTA-STS record found; policy file not retrieved",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail="The DNS record is published, but policy-file retrieval was disabled "
                       "for this scan, so the policy's mode could not be confirmed. MTA-STS "
                       "is therefore excluded from the score rather than counted as passing.",
                evidence={"record": records[0]},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    policy = _fetch_mta_sts_policy(domain)
    result.raw["policy"] = policy

    if policy.get("error"):
        # Distinguish a real problem with the domain's policy host from a failure
        # on the scanner's side. A server that answers with an HTTP error, or with
        # an invalid certificate, is genuinely misconfigured. A connection that
        # never completed may equally mean this machine has no route out, and must
        # not be reported as a weakness in the assessed domain.
        if policy.get("server_responded"):
            result.findings.append(
                Finding(
                    id="mta_sts.policy_unreachable",
                    title="MTA-STS policy file could not be retrieved",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail=f"The DNS record advertises MTA-STS, but the policy at "
                           f"https://mta-sts.{domain}/.well-known/mta-sts.txt could not be "
                           f"fetched ({policy['error']}). Senders that cannot retrieve the "
                           "policy fall back to opportunistic TLS, so the protection the "
                           "record advertises is not actually in effect.",
                    evidence={"url": policy.get("url"), "error": policy["error"]},
                    remediation="Serve the policy file over valid HTTPS at that exact path.",
                    reference="RFC 8461 §3.2",
                )
            )
        else:
            result.error = policy["error"]
            result.findings.append(
                Finding(
                    id="mta_sts.policy_fetch_failed",
                    title="MTA-STS policy file could not be reached from this scanner",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    category=CATEGORY,
                    detail=f"The DNS record is published, but the connection to "
                           f"https://mta-sts.{domain}/.well-known/mta-sts.txt did not "
                           f"complete ({policy['error']}). This may be an outbound network "
                           "restriction on the machine running the scan rather than a "
                           "problem with the domain, so MTA-STS is excluded from the score "
                           "rather than counted as failing. Re-run from a host with "
                           "unrestricted outbound HTTPS to confirm.",
                    evidence={"url": policy.get("url"), "error": policy["error"]},
                )
            )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    mode = (policy.get("mode") or "").lower()
    if mode == "enforce":
        result.findings.append(
            Finding(
                id="mta_sts.ok",
                title="MTA-STS is published in enforce mode",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"Policy lists {len(policy.get('mx', []))} MX pattern(s) with "
                       f"max_age {policy.get('max_age')}s. Senders will refuse to deliver "
                       "if TLS cannot be negotiated to a matching host.",
                evidence={"mode": mode, "mx": policy.get("mx"), "max_age": policy.get("max_age")},
            )
        )
    elif mode in ("testing", "none"):
        result.findings.append(
            Finding(
                id="mta_sts.not_enforcing",
                title=f"MTA-STS policy is in `{mode}` mode",
                status=Status.WARN,
                severity=Severity.MEDIUM if mode == "testing" else Severity.HIGH,
                category=CATEGORY,
                detail=f"In {mode} mode senders report failures but still deliver over a "
                       "downgraded or unauthenticated connection, so a STARTTLS-stripping "
                       "attacker is observed but not stopped.",
                evidence={"mode": mode, "policy": policy.get("body", "")[:500]},
                remediation="Once TLS-RPT reports show no failures, set mode: enforce.",
                reference="RFC 8461 §5",
            )
        )
    else:
        result.findings.append(
            Finding(
                id="mta_sts.invalid_mode",
                title="MTA-STS policy has an invalid `mode`",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail=f"mode={mode or '(absent)'!r} is not one of enforce, testing or none. "
                       "Senders will discard the policy.",
                evidence={"mode": mode, "policy": policy.get("body", "")[:500]},
                remediation="Set mode: to enforce, testing or none.",
                reference="RFC 8461 §3.2",
            )
        )

    if policy.get("max_age") is not None and policy["max_age"] < 86400:
        result.findings.append(
            Finding(
                id="mta_sts.short_max_age",
                title=f"MTA-STS max_age is only {policy['max_age']}s",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail="A short max_age narrows the window in which a cached policy protects "
                       "senders. RFC 8461 recommends at least a few weeks in steady state.",
                evidence={"max_age": policy["max_age"]},
                remediation="Raise max_age to 604800 (one week) or more once stable.",
                reference="RFC 8461 §3.2",
            )
        )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _fetch_mta_sts_policy(domain: str) -> dict[str, Any]:
    """GET the policy file. Read-only HTTPS request to a well-known public path."""
    import ssl
    import urllib.error
    import urllib.request

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    out: dict[str, Any] = {"url": url}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecureMailScope/1.0 (+passive-assessment)"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=MTA_STS_FETCH_TIMEOUT, context=ctx) as resp:
            out["server_responded"] = True
            if resp.status != 200:
                out["error"] = f"HTTP {resp.status}"
                return out
            body = resp.read(MTA_STS_POLICY_MAX_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # The policy host answered — this is the domain's own misconfiguration.
        out["error"] = f"HTTP {exc.code}"
        out["server_responded"] = True
        return out
    except ssl.SSLError as exc:
        # TLS was negotiated with the policy host and failed: RFC 8461 requires a
        # valid certificate here, so this is a genuine finding about the domain.
        out["error"] = f"TLS error: {exc}"
        out["server_responded"] = True
        return out
    except Exception as exc:
        # Connection never completed. Could be the domain, could be this machine's
        # network — the caller treats it as inconclusive rather than guessing.
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["server_responded"] = False
        return out

    out["body"] = body
    mx: list[str] = []
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            mx.append(value)
        elif key == "mode":
            out["mode"] = value.lower()
        elif key == "version":
            out["version"] = value
        elif key == "max_age":
            try:
                out["max_age"] = int(value)
            except ValueError:
                out["max_age"] = None
    out["mx"] = mx
    return out


# --------------------------------------------------------------------------- TLS-RPT

def run_tls_rpt(domain: str, resolver: BaseResolver,
                receives_mail: bool = True) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id="tls_rpt", name="TLS-RPT", category=CATEGORY)
    record_name = f"_smtp._tls.{domain}"

    if not receives_mail:
        result.findings.append(
            Finding(
                id="tls_rpt.not_applicable",
                title="TLS-RPT does not apply (domain receives no mail)",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{domain} publishes no MX records, so there are no inbound TLS "
                       "negotiations to report on.",
                evidence={"mx_records": 0},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        records = [
            r for r in resolver.query_optional(record_name, "TXT", domain)
            if r.lower().replace(" ", "").startswith("v=tlsrptv1")
        ]
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(_lookup_error("tls_rpt", "TLS-RPT", record_name, exc, CATEGORY))
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.raw["record_name"] = record_name
    result.raw["records"] = records

    if not records:
        result.findings.append(
            Finding(
                id="tls_rpt.missing",
                title="TLS-RPT is not configured",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail=f"No TLS-RPT record at {record_name}. Sending servers have nowhere to "
                       "report failed TLS negotiations, so a downgrade attack or an expired "
                       "certificate on your MX would produce no signal to your team — you "
                       "would learn about it from users, if at all.",
                evidence={"queried": record_name, "records_found": 0},
                remediation=f'Publish TXT "v=TLSRPTv1; rua=mailto:tls-reports@{domain}" at '
                            f"{record_name}.",
                reference="RFC 8460 §3",
            )
        )
    else:
        tags = _parse_tags(records[0])
        result.raw["tags"] = tags
        if not tags.get("rua"):
            result.findings.append(
                Finding(
                    id="tls_rpt.no_rua",
                    title="TLS-RPT record has no `rua=` destination",
                    status=Status.WARN,
                    severity=Severity.LOW,
                    category=CATEGORY,
                    detail="The record exists but specifies no reporting address, so no "
                           "reports are delivered anywhere.",
                    evidence={"record": records[0]},
                    remediation="Add rua=mailto: or rua=https: to the record.",
                    reference="RFC 8460 §3",
                )
            )
        else:
            result.findings.append(
                Finding(
                    id="tls_rpt.ok",
                    title="TLS-RPT is configured",
                    status=Status.PASS,
                    severity=Severity.INFO,
                    category=CATEGORY,
                    detail=f"TLS failure reports are sent to {tags['rua']}.",
                    evidence={"rua": tags["rua"]},
                )
            )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


# --------------------------------------------------------------------------- BIMI

def run_bimi(domain: str, resolver: BaseResolver) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id="bimi", name="BIMI", category=CATEGORY)
    record_name = f"default._bimi.{domain}"

    try:
        records = [
            r for r in resolver.query_optional(record_name, "TXT", domain)
            if r.lower().replace(" ", "").startswith("v=bimi1")
        ]
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(_lookup_error("bimi", "BIMI", record_name, exc, CATEGORY))
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.raw["record_name"] = record_name
    result.raw["records"] = records

    if not records:
        # BIMI is optional and brand-facing; its absence is informational only
        # and carries no score weight.
        result.findings.append(
            Finding(
                id="bimi.not_configured",
                title="BIMI is not configured",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                category=CATEGORY,
                detail="No BIMI record found. BIMI displays a verified brand logo beside "
                       "authenticated mail; it is optional, requires DMARC at enforcement "
                       "first, and its absence is not a security weakness.",
                evidence={"queried": record_name},
                reference="draft-blank-ietf-bimi",
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    tags = _parse_tags(records[0])
    result.raw["tags"] = tags
    has_vmc = bool(tags.get("a"))
    result.findings.append(
        Finding(
            id="bimi.configured",
            title="BIMI is configured" + (" with a VMC" if has_vmc else " without a VMC"),
            status=Status.PASS,
            severity=Severity.INFO,
            category=CATEGORY,
            detail=f"Logo published at {tags.get('l') or '(none)'}."
                   + ("" if has_vmc else " No Verified Mark Certificate is referenced, so "
                      "several major mailbox providers will not display the logo."),
            evidence={"record": records[0], "tags": tags},
        )
    )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


# --------------------------------------------------------------------------- shared

def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        m = _TAG_RE.match(part)
        if m:
            tags[m.group("tag").lower()] = m.group("value").strip()
    return tags


def _lookup_error(check_id: str, label: str, name: str, exc: Exception,
                  category: Category) -> Finding:
    return Finding(
        id=f"{check_id}.lookup_failed",
        title=f"{label} record could not be retrieved",
        status=Status.ERROR,
        severity=Severity.INFO,
        category=category,
        detail=f"The TXT lookup for {name} failed: {exc}. No conclusion about {label} "
               "can be drawn from this scan.",
        evidence={"error": str(exc), "queried": name},
    )
