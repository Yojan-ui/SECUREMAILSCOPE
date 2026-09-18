"""Scan orchestration: runs every check against one domain and scores it."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from ..checks import dkim, dmarc, policy, spf, transport
from ..models import Assessment, utcnow
from ..resolver import BaseResolver, build_resolver
from . import scoring

# Conservative hostname syntax check. Anything that is not a plausible domain is
# rejected before a single packet leaves the machine.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

ProgressFn = Callable[[str, str, int], None]


class InvalidDomain(ValueError):
    """The supplied string is not a scannable public domain name."""


@dataclass
class ScanOptions:
    probe_tls: bool = True
    enumerate_tls_versions: bool = True
    fetch_mta_sts_policy: bool = True
    dkim_selectors: list[str] | None = None
    resolver_mode: str = "auto"
    timeout: float = 5.0


def normalise_domain(value: str) -> str:
    """Accept what a user is likely to paste and reduce it to a bare domain."""
    if not value or not value.strip():
        raise InvalidDomain("Enter a domain name.")

    candidate = value.strip().lower()
    candidate = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", candidate)   # strip scheme
    candidate = candidate.split("/")[0].split("?")[0]              # strip path/query
    if "@" in candidate:                                           # accept an address
        candidate = candidate.rsplit("@", 1)[1]
    candidate = candidate.split(":")[0]                            # strip port
    candidate = candidate.rstrip(".")

    try:
        candidate = candidate.encode("idna").decode("ascii")       # IDN → punycode
    except UnicodeError:
        raise InvalidDomain(f"{value!r} is not a valid domain name.")

    if not _DOMAIN_RE.match(candidate):
        raise InvalidDomain(f"{value!r} is not a valid domain name.")

    if candidate.split(".")[-1].isdigit():
        raise InvalidDomain("Enter a domain name, not an IP address.")

    return candidate


def scan(domain: str, options: ScanOptions | None = None,
         resolver: BaseResolver | None = None,
         on_progress: ProgressFn | None = None) -> Assessment:
    """Run the full assessment. Every step is a passive, read-only lookup."""
    options = options or ScanOptions()
    domain = normalise_domain(domain)
    resolver = resolver or build_resolver(options.resolver_mode, timeout=options.timeout)

    assessment = Assessment(
        domain=domain,
        started_at=utcnow(),
        scan_id=uuid.uuid4().hex[:12],
    )

    # Establish two facts first, because several checks are only meaningful in
    # light of them. Both lookups are cached, so the checks below reuse them
    # rather than re-querying the target.
    receives_mail = _receives_mail(domain, resolver)
    sends_mail = _sends_mail(domain, resolver)

    steps: list[tuple[str, str, Callable[[], Any]]] = [
        ("spf", "Checking SPF policy",
         lambda: spf.run(domain, resolver)),
        ("dmarc", "Checking DMARC enforcement",
         lambda: dmarc.run(domain, resolver)),
        ("dkim", "Discovering DKIM selectors and key strength",
         lambda: dkim.run(domain, resolver, options.dkim_selectors, sends_mail)),
        ("mta_sts", "Checking MTA-STS policy",
         lambda: policy.run_mta_sts(domain, resolver, options.fetch_mta_sts_policy,
                                    receives_mail)),
        ("tls_rpt", "Checking TLS reporting",
         lambda: policy.run_tls_rpt(domain, resolver, receives_mail)),
        ("bimi", "Checking BIMI",
         lambda: policy.run_bimi(domain, resolver)),
        ("transport", "Probing MX hosts for STARTTLS and TLS support",
         lambda: transport.run(domain, resolver, options.probe_tls,
                               options.enumerate_tls_versions)),
    ]

    total = len(steps)
    for index, (check_id, label, fn) in enumerate(steps):
        if on_progress:
            on_progress(check_id, label, int(index / total * 100))
        try:
            assessment.checks.append(fn())
        except Exception as exc:  # a broken check must not abort the scan
            from ..models import Category, CheckResult, Finding, Severity, Status
            assessment.checks.append(
                CheckResult(
                    check_id=check_id,
                    name=check_id.upper(),
                    category=Category.AUTHENTICATION,
                    error=f"{type(exc).__name__}: {exc}",
                    findings=[Finding(
                        id=f"{check_id}.crashed",
                        title=f"{check_id} check failed to run",
                        status=Status.ERROR,
                        severity=Severity.INFO,
                        category=Category.AUTHENTICATION,
                        detail=f"The check raised {type(exc).__name__}: {exc}. This control "
                               "was not assessed and is excluded from the score.",
                        evidence={"exception": f"{type(exc).__name__}: {exc}"},
                    )],
                )
            )

    assessment.score = scoring.score(assessment)
    assessment.finished_at = utcnow()

    if on_progress:
        on_progress("done", "Scan complete", 100)

    return assessment


def _receives_mail(domain: str, resolver: BaseResolver) -> bool:
    """True unless the domain publishes no usable MX. A null MX (RFC 7505) is an
    explicit declaration that the domain accepts no mail."""
    try:
        records = resolver.query_optional(domain, "MX", domain)
    except Exception:
        return True                      # assume it does; never penalise on a lookup failure
    usable = [r for r in records if r.split()[-1].rstrip(".") not in ("", ".")]
    return bool(usable)


def _sends_mail(domain: str, resolver: BaseResolver) -> bool:
    """False only when SPF authorises no senders at all — the documented way to
    say 'this domain sends no mail'. Anything ambiguous counts as sending."""
    try:
        records = [
            r for r in resolver.query_optional(domain, "TXT", domain)
            if r.lower().startswith("v=spf1")
        ]
    except Exception:
        return True
    if len(records) != 1:
        return True

    terms = records[0].split()[1:]
    if not terms:
        return True
    # Exactly "-all" and nothing else: no mechanism authorises any host.
    return not (len(terms) == 1 and terms[0].lower() == "-all")
