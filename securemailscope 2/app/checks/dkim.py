"""DKIM (RFC 6376) selector discovery and key-strength analysis.

DKIM keys are published per selector, and there is no way to enumerate
selectors from DNS alone — the selector only appears in the header of a signed
message. So this check probes a list of selectors used by the major mail
platforms plus common conventions. A domain with no discovered selector is
reported honestly as "not discovered", never as "no DKIM": absence of evidence
is stated as such.

For each key found, the public key is decoded and its real modulus size is
measured rather than inferred from the base64 length.
"""
from __future__ import annotations

import base64
import re
import time
from typing import Any

from ..models import Category, CheckResult, Finding, Severity, Status
from ..resolver import BaseResolver, DNSError

CHECK_ID = "dkim"
CATEGORY = Category.AUTHENTICATION

# Selectors published by the major platforms, plus widespread conventions.
# Ordered so that the most common land first; the probe stops early once it has
# found keys, keeping the query count low.
DEFAULT_SELECTORS = [
    "google", "selector1", "selector2",           # Google Workspace, Microsoft 365
    "k1", "k2", "k3",                             # Mailchimp / Mandrill
    "s1", "s2", "mail", "dkim", "default",        # common conventions
    "smtp", "email", "mx", "key1", "key2",
    "zoho", "zohomail",                           # Zoho
    "pm", "pm1", "pm2",                           # Postmark
    "sig1", "sig2",                               # Zoho / misc
    "mandrill", "sendgrid", "mailjet", "mailgun",
    "amazonses", "ses",                           # Amazon SES
    "protonmail", "protonmail2", "protonmail3",
    "fm1", "fm2", "fm3",                          # Fastmail
    "hs1-", "hs2-",                               # HubSpot (prefixes)
    "everlytickey1", "everlytickey2",
    "20230601", "20240101",                       # date-style selectors
]

_TAG_RE = re.compile(r"^\s*(?P<tag>[a-z]+)\s*=\s*(?P<value>.*)\s*$", re.IGNORECASE | re.DOTALL)

# Key sizes below this are considered factorable/weak by current guidance.
RSA_MIN_ACCEPTABLE = 1024
RSA_RECOMMENDED = 2048


def run(domain: str, resolver: BaseResolver,
        selectors: list[str] | None = None,
        sends_mail: bool = True) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id=CHECK_ID, name="DKIM", category=CATEGORY)
    candidates = selectors or DEFAULT_SELECTORS

    if not sends_mail:
        # The domain publishes an SPF record authorising no senders at all, which
        # is the documented way to declare "this domain sends no mail". There is
        # nothing for DKIM to sign.
        result.findings.append(
            Finding(
                id="dkim.not_applicable",
                title="DKIM does not apply (domain declares it sends no mail)",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{domain} publishes an SPF record that authorises no senders, which "
                       "declares the domain sends no mail. There is no outbound mail for "
                       "DKIM to sign.",
                evidence={"spf_authorises_no_senders": True},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    discovered: list[dict[str, Any]] = []
    probed = 0
    lookup_errors = 0

    for selector in candidates:
        name = f"{selector}._domainkey.{domain}"
        probed += 1
        try:
            records = resolver.query_optional(name, "TXT", domain)
        except DNSError:
            lookup_errors += 1
            continue
        for record in records:
            if "p=" not in record and "v=dkim1" not in record.lower():
                continue
            key_info = _analyse_key(selector, record)
            discovered.append(key_info)
        # Once we have two keys we have enough to judge the domain's posture;
        # continuing would only add queries against the target's resolver.
        if len(discovered) >= 2 and probed >= 6:
            break

    result.raw["selectors_probed"] = probed
    result.raw["selectors_found"] = [k["selector"] for k in discovered]
    result.raw["keys"] = discovered

    if lookup_errors and not discovered:
        result.error = f"{lookup_errors} selector lookups failed"
        result.findings.append(
            Finding(
                id="dkim.lookup_failed",
                title="DKIM selector probing could not complete",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{lookup_errors} of {probed} selector lookups failed. No conclusion "
                       "about DKIM can be drawn from this scan.",
                evidence={"failed_lookups": lookup_errors, "probed": probed},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if not discovered:
        result.findings.append(
            Finding(
                id="dkim.not_discovered",
                title="No DKIM key found at any probed selector",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail=f"None of the {probed} selectors commonly used by mail platforms "
                       f"resolved for {domain}. DKIM selectors cannot be enumerated from DNS, "
                       "so this does not prove DKIM is absent — the domain may sign with a "
                       "custom selector this scan did not guess. Confirm by inspecting the "
                       "DKIM-Signature header of a message sent from the domain.",
                evidence={"selectors_probed": probed, "selectors": candidates[:probed]},
                remediation="If DKIM is not configured, enable signing at your mail provider "
                            "and publish the selector key. If it is configured under a custom "
                            "selector, supply it to this tool for an accurate reading.",
                reference="RFC 6376 §3.6",
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    for key in discovered:
        _evaluate_key(key, result)

    if not any(f.counts_against_score for f in result.findings):
        sizes = ", ".join(
            f"{k['selector']} ({k['algorithm']}-{k['key_bits']})"
            for k in discovered if k.get("key_bits")
        )
        result.findings.append(
            Finding(
                id="dkim.ok",
                title="DKIM keys are present and of adequate strength",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"Discovered signing keys: {sizes}.",
                evidence={"keys": [{k: v for k, v in key.items() if k != "raw"}
                                   for key in discovered]},
            )
        )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _analyse_key(selector: str, record: str) -> dict[str, Any]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        m = _TAG_RE.match(part)
        if m:
            tags[m.group("tag").lower()] = m.group("value").strip()

    info: dict[str, Any] = {
        "selector": selector,
        "raw": record,
        "tags": tags,
        "algorithm": (tags.get("k") or "rsa").lower(),
        "testing_mode": "y" in {f.strip() for f in tags.get("t", "").split(":")},
        "revoked": "p" in tags and tags["p"].strip() == "",
        "key_bits": None,
        "parse_error": None,
    }

    pubkey = re.sub(r"\s+", "", tags.get("p", ""))
    if not pubkey:
        return info

    try:
        der = base64.b64decode(pubkey, validate=True)
    except Exception as exc:  # malformed base64
        info["parse_error"] = f"public key is not valid base64: {exc}"
        return info

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        key = load_der_public_key(der)
        if isinstance(key, rsa.RSAPublicKey):
            info["algorithm"] = "rsa"
            info["key_bits"] = key.key_size
            info["public_exponent"] = key.public_numbers().e
        elif isinstance(key, ed25519.Ed25519PublicKey):
            info["algorithm"] = "ed25519"
            info["key_bits"] = 256
        else:
            info["algorithm"] = type(key).__name__
    except Exception as exc:
        # Ed25519 DKIM keys are published as raw 32-byte values, not DER.
        if info["algorithm"] == "ed25519" and len(der) == 32:
            info["key_bits"] = 256
        else:
            info["parse_error"] = f"could not decode public key: {exc}"

    return info


def _evaluate_key(key: dict[str, Any], result: CheckResult) -> None:
    selector = key["selector"]

    if key["revoked"]:
        result.findings.append(
            Finding(
                id=f"dkim.revoked.{selector}",
                title=f"DKIM selector `{selector}` is published with an empty key (revoked)",
                status=Status.WARN,
                severity=Severity.LOW,
                category=CATEGORY,
                detail="An empty p= tag revokes the key. This is correct practice after "
                       "rotation, but signatures from this selector will no longer verify — "
                       "confirm no sender is still using it.",
                evidence={"selector": selector, "record": key["raw"]},
                remediation="Remove the record once no in-flight mail references the selector.",
                reference="RFC 6376 §3.6.1",
            )
        )
        return

    if key["parse_error"]:
        result.findings.append(
            Finding(
                id=f"dkim.malformed.{selector}",
                title=f"DKIM key at `{selector}` could not be parsed",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail=f"The published key is malformed ({key['parse_error']}). Receivers "
                       "cannot verify signatures made with this selector, so mail signed by "
                       "it fails DKIM and falls back to SPF alone.",
                evidence={"selector": selector, "error": key["parse_error"]},
                remediation="Re-publish the key exactly as issued by your mail provider.",
                reference="RFC 6376 §3.6.1",
            )
        )
        return

    if key["testing_mode"]:
        result.findings.append(
            Finding(
                id=f"dkim.testing_mode.{selector}",
                title=f"DKIM selector `{selector}` is in testing mode (`t=y`)",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                category=CATEGORY,
                detail="`t=y` tells receivers to treat verification failures as if the message "
                       "were unsigned. Signatures from this selector therefore provide no "
                       "enforcement benefit — including for DMARC alignment.",
                evidence={"selector": selector, "record": key["raw"]},
                remediation="Remove t=y once signing is confirmed working.",
                reference="RFC 6376 §3.6.1",
            )
        )

    bits = key.get("key_bits")
    algorithm = key.get("algorithm")

    if algorithm == "rsa" and bits:
        if bits < RSA_MIN_ACCEPTABLE:
            result.findings.append(
                Finding(
                    id=f"dkim.weak_key.{selector}",
                    title=f"DKIM key at `{selector}` is only {bits}-bit RSA",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    detail=f"A {bits}-bit RSA modulus is well below any current guidance and is "
                           "factorable with modest resources. An attacker who recovers the "
                           "private key can produce signatures that verify as genuine, "
                           "defeating DKIM and satisfying DMARC alignment for forged mail.",
                    evidence={"selector": selector, "key_bits": bits, "algorithm": "rsa"},
                    remediation="Rotate to a 2048-bit RSA key.",
                    reference="RFC 8301 §3.2",
                )
            )
        elif bits < RSA_RECOMMENDED:
            result.findings.append(
                Finding(
                    id=f"dkim.short_key.{selector}",
                    title=f"DKIM key at `{selector}` is {bits}-bit RSA",
                    status=Status.WARN,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail=f"RFC 8301 sets 1024 bits as the minimum receivers must accept and "
                           "2048 as the recommended size. A 1024-bit key is within reach of a "
                           "well-resourced attacker and should be rotated.",
                    evidence={"selector": selector, "key_bits": bits, "algorithm": "rsa"},
                    remediation="Rotate to a 2048-bit RSA key at your mail provider.",
                    reference="RFC 8301 §3.2",
                )
            )
