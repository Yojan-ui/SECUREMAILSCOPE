"""DMARC (RFC 7489) policy discovery and evaluation.

DMARC is the control that actually decides what a receiver *does* with mail
that fails SPF/DKIM, so it carries the heaviest weight in the scoring model.
Checks: record presence and validity, p= strictness, sp= for subdomains,
pct= partial enforcement, alignment modes (adkim/aspf), and rua/ruf reporting.
"""
from __future__ import annotations

import re
import time
from typing import Any

from ..models import Category, CheckResult, Finding, Severity, Status
from ..resolver import BaseResolver, DNSError

CHECK_ID = "dmarc"
CATEGORY = Category.AUTHENTICATION

_VALID_POLICIES = {"none", "quarantine", "reject"}
_TAG_RE = re.compile(r"^\s*(?P<tag>[a-z]+)\s*=\s*(?P<value>[^;]*)\s*$", re.IGNORECASE)


def run(domain: str, resolver: BaseResolver) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id=CHECK_ID, name="DMARC", category=CATEGORY)
    record_name = f"_dmarc.{domain}"

    try:
        records = [
            r for r in resolver.query_optional(record_name, "TXT", domain)
            if r.lower().replace(" ", "").startswith("v=dmarc1")
        ]
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(
            Finding(
                id="dmarc.lookup_failed",
                title="DMARC record could not be retrieved",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"The TXT lookup for {record_name} failed: {exc}. No conclusion "
                       "about DMARC can be drawn from this scan.",
                evidence={"error": str(exc), "queried": record_name},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.raw["record_name"] = record_name
    result.raw["records"] = records

    if not records:
        result.findings.append(
            Finding(
                id="dmarc.missing",
                title="No DMARC record published",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                category=CATEGORY,
                detail=f"No DMARC policy exists at {record_name}. Nothing instructs receiving "
                       "servers what to do with mail that fails SPF or DKIM, and no one "
                       "receives reports about who is sending as this domain. In practice "
                       "this means the domain can be spoofed in phishing and business-email-"
                       "compromise campaigns with no enforcement standing in the way.",
                evidence={"queried": record_name, "records_found": 0},
                remediation=f'Publish a TXT record at {record_name}, starting at '
                            '"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to collect '
                            "reports, then move to p=quarantine and finally p=reject.",
                reference="RFC 7489 §6.3",
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if len(records) > 1:
        result.findings.append(
            Finding(
                id="dmarc.multiple_records",
                title=f"{len(records)} DMARC records published",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail="RFC 7489 requires receivers to ignore the domain's DMARC policy "
                       "entirely when more than one record is found, leaving the domain "
                       "unenforced.",
                evidence={"records": records},
                remediation="Remove all but one DMARC TXT record.",
                reference="RFC 7489 §6.6.3",
            )
        )

    record = records[0]
    tags = _parse_tags(record)
    result.raw["tags"] = tags

    _evaluate_policy(domain, tags, record, result)
    _evaluate_subdomain_policy(tags, record, result)
    _evaluate_percentage(tags, record, result)
    _evaluate_alignment(tags, record, result)
    _evaluate_reporting(tags, record, result)

    if not any(f.counts_against_score for f in result.findings):
        result.findings.append(
            Finding(
                id="dmarc.ok",
                title="DMARC is published and enforcing",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"Policy p={tags.get('p')} applies to 100% of mail, with aggregate "
                       "reporting configured.",
                evidence={"record": record, "tags": tags},
            )
        )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        m = _TAG_RE.match(part)
        if m:
            tags[m.group("tag").lower()] = m.group("value").strip()
    return tags


def _evaluate_policy(domain: str, tags: dict[str, str], record: str, result: CheckResult) -> None:
    policy = tags.get("p", "").lower()

    if policy not in _VALID_POLICIES:
        result.findings.append(
            Finding(
                id="dmarc.invalid_policy",
                title="DMARC record has a missing or invalid `p=` tag",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                category=CATEGORY,
                detail=f"`p=` is required and must be none, quarantine or reject; found "
                       f"{tags.get('p') or '(absent)'!r}. Receivers discard a DMARC record "
                       "without a valid policy, so the domain is unprotected.",
                evidence={"record": record, "p": tags.get("p")},
                remediation="Set a valid p= value.",
                reference="RFC 7489 §6.3",
            )
        )
        return

    if policy == "none":
        result.findings.append(
            Finding(
                id="dmarc.policy_none",
                title="DMARC policy is `p=none` (monitoring only)",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail="`p=none` asks receivers to report on failures but to deliver the mail "
                       f"anyway. A message forged as @{domain} that fails both SPF and DKIM "
                       "still lands in the recipient's inbox, so the domain remains usable "
                       "for phishing and invoice-fraud campaigns. Monitoring mode is the "
                       "correct first step, but it is not enforcement.",
                evidence={"record": record, "p": "none"},
                remediation="After reviewing aggregate reports for legitimate senders, move "
                            "to p=quarantine, then p=reject.",
                reference="RFC 7489 §6.3",
            )
        )
    elif policy == "quarantine":
        result.findings.append(
            Finding(
                id="dmarc.policy_quarantine",
                title="DMARC policy is `p=quarantine`",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="Failing mail is delivered to the spam folder rather than rejected. "
                       "This blunts most campaigns, but the message is still delivered and a "
                       "recipient who checks their spam folder can still act on it.",
                evidence={"record": record, "p": "quarantine"},
                remediation="Move to p=reject once reports show no legitimate mail failing.",
                reference="RFC 7489 §6.3",
            )
        )


def _evaluate_subdomain_policy(tags: dict[str, str], record: str, result: CheckResult) -> None:
    sp = tags.get("sp", "").lower()
    p = tags.get("p", "").lower()
    if not sp:
        return  # subdomains inherit p=, which is already scored
    if sp == "none" and p in ("quarantine", "reject"):
        result.findings.append(
            Finding(
                id="dmarc.subdomain_policy_weak",
                title="Subdomain policy `sp=none` undercuts the domain policy",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail=f"The apex is protected by p={p}, but sp=none exempts every subdomain. "
                       "Attackers routinely spoof plausible-looking subdomains such as "
                       "billing.example.com or hr.example.com precisely because they are "
                       "left unenforced while the apex is locked down.",
                evidence={"record": record, "p": p, "sp": "none"},
                remediation="Set sp= to match p=, or remove sp= so subdomains inherit it.",
                reference="RFC 7489 §6.3",
            )
        )


def _evaluate_percentage(tags: dict[str, str], record: str, result: CheckResult) -> None:
    raw = tags.get("pct", "100")
    try:
        pct = int(raw)
    except ValueError:
        result.findings.append(
            Finding(
                id="dmarc.invalid_pct",
                title="DMARC `pct=` is not a number",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail=f"pct={raw!r} is invalid; receiver behaviour is undefined.",
                evidence={"record": record, "pct": raw},
                remediation="Remove pct= or set it to an integer between 0 and 100.",
                reference="RFC 7489 §6.3",
            )
        )
        return

    if pct < 100 and tags.get("p", "").lower() in ("quarantine", "reject"):
        result.findings.append(
            Finding(
                id="dmarc.partial_enforcement",
                title=f"DMARC policy applies to only {pct}% of mail",
                status=Status.FAIL,
                severity=Severity.MEDIUM if pct >= 50 else Severity.HIGH,
                category=CATEGORY,
                detail=f"pct={pct} means receivers apply the policy to {pct}% of failing "
                       f"messages and fall back to the next weaker policy for the other "
                       f"{100 - pct}%. A spoofing campaign that sends enough messages simply "
                       "gets the remainder delivered.",
                evidence={"record": record, "pct": pct},
                remediation="Set pct=100 (or remove the tag) once rollout is complete.",
                reference="RFC 7489 §6.3",
            )
        )


def _evaluate_alignment(tags: dict[str, str], record: str, result: CheckResult) -> None:
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    relaxed = [name for name, mode in (("adkim", adkim), ("aspf", aspf)) if mode == "r"]

    # Alignment mode is reported but not scored. Relaxed is the RFC default and
    # the right choice for most organisations, so treating it as a weakness would
    # penalise almost every correctly configured domain and devalue the score.
    if relaxed:
        detail = (
            "Relaxed alignment (the RFC default) lets any subdomain satisfy DMARC for the "
            "organisational domain. This is appropriate for most organisations. Strict "
            "alignment narrows the set of hosts that can authenticate as the domain, which "
            "is worth considering if no subdomain is delegated to a third party."
        )
    else:
        detail = ("Strict alignment is configured for both SPF and DKIM: only the exact "
                  "domain, not its subdomains, can satisfy DMARC.")

    result.findings.append(
        Finding(
            id="dmarc.alignment_mode",
            title=f"DMARC alignment: adkim={adkim}, aspf={aspf}",
            status=Status.PASS,
            severity=Severity.INFO,
            category=CATEGORY,
            detail=detail,
            evidence={"adkim": adkim, "aspf": aspf, "record": record},
            reference="RFC 7489 §3.1",
        )
    )


def _evaluate_reporting(tags: dict[str, str], record: str, result: CheckResult) -> None:
    if not tags.get("rua"):
        result.findings.append(
            Finding(
                id="dmarc.no_aggregate_reporting",
                title="No DMARC aggregate reporting address (`rua=`)",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="Without rua=, no one receives the daily reports showing which hosts "
                       "are sending as this domain and whether they pass authentication. "
                       "Spoofing campaigns and misconfigured legitimate senders both go "
                       "unnoticed, and there is no data on which to base a move to p=reject.",
                evidence={"record": record},
                remediation="Add rua=mailto:dmarc-reports@yourdomain (or a reporting service).",
                reference="RFC 7489 §7.1",
            )
        )
