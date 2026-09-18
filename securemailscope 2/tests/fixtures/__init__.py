"""Recorded DNS zones used by the test suite.

These stand in for live lookups so the engine's parsing, scoring and grounding
logic can be verified deterministically, offline, and in CI.

`WELL_CONFIGURED` is what a correctly hardened domain looks like. `MISCONFIGURED`
collects the failure modes the engine is expected to catch. `PARTIAL` exercises
the inconclusive path, where a check cannot complete and must be excluded from
the score rather than counted as a failure.
"""
from __future__ import annotations

import json
from pathlib import Path

_KEYS = json.loads((Path(__file__).parent / "dkim_keys.json").read_text())
RSA_2048 = _KEYS["2048"]
RSA_1024 = _KEYS["1024"]


WELL_CONFIGURED: dict[str, list[str] | None] = {
    "TXT:secure.example": [
        "v=spf1 include:_spf.provider.example -all",
        "some-unrelated-verification-token=abc123",
    ],
    "TXT:_spf.provider.example": ["v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all"],
    "TXT:_dmarc.secure.example": [
        "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; "
        "rua=mailto:dmarc@secure.example; ruf=mailto:forensic@secure.example"
    ],
    "TXT:google._domainkey.secure.example": [f"v=DKIM1; k=rsa; p={RSA_2048}"],
    "TXT:selector1._domainkey.secure.example": [f"v=DKIM1; k=rsa; p={RSA_2048}"],
    "TXT:_mta-sts.secure.example": ["v=STSv1; id=20260901120000"],
    "TXT:_smtp._tls.secure.example": ["v=TLSRPTv1; rua=mailto:tls@secure.example"],
    "TXT:default._bimi.secure.example": [],
    "MX:secure.example": ["10 mx1.secure.example", "20 mx2.secure.example"],
}


MISCONFIGURED: dict[str, list[str] | None] = {
    # SPF: neutral terminal mechanism, a /8 range, and the deprecated ptr term.
    "TXT:broken.example": ["v=spf1 ip4:10.0.0.0/8 ptr include:relay.example ?all"],
    "TXT:relay.example": ["v=spf1 a mx include:deep.example ~all"],
    "TXT:deep.example": ["v=spf1 a mx a:one.example a:two.example ~all"],
    # DMARC: monitoring only, subdomains exempt, partial, no reporting.
    "TXT:_dmarc.broken.example": ["v=DMARC1; p=none; sp=none; pct=40"],
    # DKIM: a 1024-bit key published in testing mode.
    "TXT:google._domainkey.broken.example": [f"v=DKIM1; k=rsa; t=y; p={RSA_1024}"],
    # No MTA-STS, no TLS-RPT.
    "MX:broken.example": ["10 mail.broken.example"],
}


SPOOFABLE: dict[str, list[str] | None] = {
    # The worst realistic case: SPF authorises the entire internet, no DMARC at all.
    "TXT:spoofable.example": ["v=spf1 +all"],
    "MX:spoofable.example": ["10 mail.spoofable.example"],
}


NO_MAIL: dict[str, list[str] | None] = {
    # A domain that sends no mail and says so. Should not be scored as insecure
    # for lacking transport security it does not need.
    "TXT:nomail.example": ["v=spf1 -all"],
    "TXT:_dmarc.nomail.example": ["v=DMARC1; p=reject; rua=mailto:d@nomail.example"],
    "MX:nomail.example": [],
}
