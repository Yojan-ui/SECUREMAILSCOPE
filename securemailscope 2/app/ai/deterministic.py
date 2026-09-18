"""Rule-based narrative generator.

This is the fallback whenever the LLM is unavailable — no API key, no network,
rate limited, or its output failed validation. It is deliberately good enough to
demo on its own: the tool never depends on a live API call to produce a usable
report.

Every sentence here is assembled from findings the engine actually produced.
"""
from __future__ import annotations

from ..models import Assessment, Finding, Narrative, Severity, Status, utcnow
from ..engine.scoring import risk_label

# What an attacker gains from each specific weakness. Keyed by finding id prefix
# so per-host and per-selector findings match too.
ATTACK_SCENARIOS: dict[str, str] = {
    "dmarc.missing":
        "An attacker can send mail with your exact domain in the From: header and no "
        "receiving server has instructions to reject it. The usual play is an invoice "
        "or payment-detail change sent to your finance team or your customers, arriving "
        "from what looks precisely like your domain.",
    "dmarc.policy_none":
        "Forged mail is reported to you but still delivered. A spoofing campaign runs to "
        "completion; you find out afterwards from the aggregate reports, which is useful "
        "for forensics and useless for prevention.",
    "dmarc.policy_quarantine":
        "Forged mail reaches the spam folder rather than being rejected. Targeted "
        "recipients who search their spam for an expected message — a delivery notice, an "
        "invoice — can still find and act on it.",
    "dmarc.subdomain_policy_weak":
        "The apex is protected but every subdomain is not. An attacker registers nothing "
        "and needs nothing: they simply send as billing.yourdomain or hr.yourdomain, which "
        "recipients read as more official, not less.",
    "dmarc.partial_enforcement":
        "Only a fraction of failing mail is acted on. An attacker sending in volume gets "
        "the remainder delivered normally.",
    "dmarc.no_aggregate_reporting":
        "Nobody receives the daily reports naming the hosts that send as your domain, so "
        "an ongoing spoofing campaign produces no signal your team can act on.",
    "spf.missing":
        "Receivers have no list of authorised senders to check against, so one of the two "
        "signals DMARC depends on is simply absent.",
    "spf.all_pass":
        "The record explicitly authorises every host on the internet to send as your "
        "domain. An attacker's mail does not merely evade SPF — it passes it.",
    "spf.all_neutral":
        "Unlisted senders get a neutral result, which receivers weigh the same as having "
        "no policy at all.",
    "spf.lookup_limit_exceeded":
        "Receivers abandon SPF evaluation with a permanent error, so the entire record "
        "stops protecting the domain — including the senders correctly listed in it.",
    "spf.overly_broad_range":
        "Any host inside the authorised range passes SPF for your domain. On shared "
        "hosting or a cloud provider's range, that includes machines you do not control.",
    "dkim.not_discovered":
        "If no DKIM signature is applied, forwarded mail loses SPF alignment and DMARC has "
        "only one signal left to work with, which increases both spoofing exposure and "
        "false rejections of your own legitimate mail.",
    "dkim.weak_key":
        "A key this short can be factored. An attacker who recovers the private key signs "
        "forged mail that verifies as genuine and passes DMARC alignment — the forgery is "
        "then indistinguishable from real mail at the receiving end.",
    "dkim.short_key":
        "A 1024-bit key is within reach of a well-resourced attacker; recovering it would "
        "let them sign forged mail that verifies correctly.",
    "dkim.testing_mode":
        "Receivers are told to treat signature failures as if the message were unsigned, "
        "so the signature provides no enforcement benefit.",
    "transport.no_starttls":
        "Mail to this host crosses the internet in cleartext. Anyone on the network path — "
        "a compromised router, a hostile network operator — reads message bodies and "
        "attachments, including password-reset links and anything else sent by mail.",
    "transport.legacy_tls":
        "An on-path attacker can force the handshake down to the deprecated version and "
        "attack the connection there, where the known weaknesses are.",
    "transport.no_modern_tls":
        "Senders configured for modern TLS only cannot negotiate an encrypted connection "
        "at all, leaving cleartext delivery or a bounce as the outcomes.",
    "transport.weak_cipher":
        "The negotiated suite does not provide meaningful confidentiality against an "
        "attacker able to capture the traffic.",
    "transport.cert_expired":
        "Senders that validate certificates refuse delivery, while senders using "
        "opportunistic TLS accept the expired certificate silently — so the failure is "
        "intermittent and easy to miss until mail starts bouncing.",
    "transport.cert_self_signed":
        "The certificate cannot be validated against any trust store, so an on-path "
        "attacker can substitute their own and the sending server has no way to tell.",
    "transport.cert_invalid":
        "The chain does not validate, which breaks delivery from any sender enforcing "
        "MTA-STS and removes the authentication guarantee for everyone else.",
    "mta_sts.missing":
        "Without MTA-STS, an on-path attacker strips the STARTTLS advertisement from your "
        "server's greeting. The sending server sees a host that does not support TLS, "
        "falls back to cleartext, and delivers the message in the clear. Neither side sees "
        "an error.",
    "mta_sts.not_enforcing":
        "Failures are reported but delivery proceeds over the downgraded connection, so "
        "the downgrade is observed rather than prevented.",
    "mta_sts.policy_unreachable":
        "Senders that cannot fetch the policy fall back to opportunistic TLS, so the "
        "protection the DNS record advertises is not actually in effect.",
    "tls_rpt.missing":
        "No one receives reports of failed TLS negotiations, so a downgrade attack or an "
        "expired certificate on your MX produces no alert to your team.",
}


def generate(assessment: Assessment, fallback_reason: str | None = None) -> Narrative:
    findings = assessment.findings_by_severity()
    score = assessment.score.score if assessment.score else -1
    domain = assessment.domain

    if not findings:
        return _clean_bill(assessment, fallback_reason)

    summary = _summary(domain, score, findings, assessment)
    scenarios = _scenarios(findings)
    steps = _remediation(findings)

    return Narrative(
        source="deterministic",
        summary=summary,
        attack_scenarios=scenarios,
        remediation_steps=steps,
        generated_at=utcnow(),
        fallback_reason=fallback_reason,
    )


def _clean_bill(assessment: Assessment, fallback_reason: str | None) -> Narrative:
    """The 'perfect config' answer. No invented findings, no hedging filler."""
    domain = assessment.domain
    assessed: list[str] = []
    unavailable: list[str] = []      # the scan could not determine anything
    inapplicable: list[str] = []     # the control genuinely does not apply here

    for check in assessment.checks:
        statuses = {f.status for f in check.findings}
        if check.error or not check.findings or statuses == {Status.ERROR}:
            unavailable.append(check.name)
        elif statuses <= {Status.NOT_APPLICABLE, Status.ERROR}:
            inapplicable.append(check.name)
        else:
            assessed.append(check.name)

    summary = (
        f"{domain} passed every check this assessment was able to complete. "
        f"{_join(assessed)} {'were' if len(assessed) != 1 else 'was'} examined and found "
        "correctly configured. There is nothing to remediate."
    )
    if inapplicable:
        summary += (
            f" {_join(inapplicable)} {'do' if len(inapplicable) > 1 else 'does'} not apply "
            "to this domain and {} excluded from the score."
            .format("were" if len(inapplicable) > 1 else "was")
        )
    if unavailable:
        plural = "they are" if len(unavailable) > 1 else "it is"
        summary += (
            f" Note that {_join(unavailable)} could not be evaluated during this scan, so "
            f"{plural} excluded from the score rather than counted as passing — a gap in "
            "coverage, not a clean result."
        )
    summary += (
        " Email security posture is not a one-time state: certificates expire, providers "
        "change their sending infrastructure, and DKIM keys need periodic rotation. The "
        "useful next step is scheduled re-assessment, not further hardening."
    )

    return Narrative(
        source="deterministic",
        summary=summary,
        attack_scenarios=[],
        remediation_steps=[],
        generated_at=utcnow(),
        fallback_reason=fallback_reason,
    )


def _join(items: list[str]) -> str:
    if not items:
        return "no checks"
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _summary(domain: str, score: int, findings: list[Finding],
             assessment: Assessment) -> str:
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]

    counts = []
    for label, group in (("critical", critical), ("high-severity", high)):
        if group:
            counts.append(f"{len(group)} {label}")
    other = len(findings) - len(critical) - len(high)
    if other:
        counts.append(f"{other} lower-severity")

    grade = assessment.score.grade if assessment.score else "N/A"
    opening = (
        f"{domain} scores {score}/100 ({grade}) — {risk_label(score).lower()}. "
        f"The assessment found {' and '.join(counts) if counts else 'no'} issue"
        f"{'s' if len(findings) != 1 else ''}."
    )

    lead = critical or high or findings
    headline = lead[0]
    body = f" The most consequential — {headline.title} — matters because: {headline.detail}"

    spoofable = any(
        f.id in ("dmarc.missing", "dmarc.policy_none", "dmarc.invalid_policy")
        for f in findings
    )
    cleartext = any(f.id.startswith("transport.no_starttls") for f in findings)

    closing = ""
    if spoofable and cleartext:
        closing = (
            f" Taken together, the two headline problems are that mail can be forged as "
            f"@{domain} without being rejected, and that mail sent to {domain} can be read "
            "in transit. Those are separate failures with separate fixes, and both are "
            "routinely exploited."
        )
    elif spoofable:
        closing = (
            f" The practical consequence is that {domain} is currently spoofable: an "
            "attacker can put your domain in the From: header of a phishing or invoice-"
            "fraud message and receiving servers have no instruction to stop it."
        )
    elif cleartext:
        closing = (
            f" The practical consequence is that mail sent to {domain} is not reliably "
            "encrypted in transit and can be read by anyone on the network path."
        )

    return opening + body + closing


def _scenarios(findings: list[Finding]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for finding in findings:
        for key, text in ATTACK_SCENARIOS.items():
            if finding.id == key or finding.id.startswith(key + "."):
                if text not in seen:
                    seen.add(text)
                    out.append(text)
                break
        if len(out) >= 5:
            break
    return out


def _remediation(findings: list[Finding]) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    for index, finding in enumerate(findings, start=1):
        if not finding.remediation:
            continue
        steps.append({
            "priority": str(index),
            "severity": finding.severity.value,
            "finding_id": finding.id,
            "title": finding.title,
            "action": finding.remediation,
            "reference": finding.reference or "",
        })
    return steps
