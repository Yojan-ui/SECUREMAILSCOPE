"""Core data model for SecureMailScope.

Everything the engine produces flows through these structures. The AI layer is
only ever handed a serialized `Assessment` — it cannot see the network, cannot
re-run checks, and cannot alter a score.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Impact of a finding, ordered by how much attacker leverage it grants."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


class Status(str, Enum):
    """Outcome of an individual check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"      # the check could not complete (network, timeout)
    NOT_APPLICABLE = "n/a"


class Category(str, Enum):
    AUTHENTICATION = "Authentication"   # SPF, DKIM, DMARC
    TRANSPORT = "Transport Security"    # STARTTLS, TLS versions, certificates
    POLICY = "Policy & Reporting"       # MTA-STS, TLS-RPT, BIMI


@dataclass
class Finding:
    """One observation about the domain.

    `evidence` holds the raw record or probe result the finding was derived
    from. Nothing downstream may assert anything that is not traceable to an
    evidence value here.
    """

    id: str
    title: str
    status: Status
    severity: Severity
    category: Category
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    reference: str | None = None

    @property
    def counts_against_score(self) -> bool:
        return self.status in (Status.WARN, Status.FAIL)


@dataclass
class CheckResult:
    """All findings from one check module, plus the raw data it gathered."""

    check_id: str
    name: str
    category: Category
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None

    @property
    def worst_status(self) -> Status:
        if self.error:
            return Status.ERROR
        order = [Status.ERROR, Status.FAIL, Status.WARN, Status.PASS, Status.NOT_APPLICABLE]
        for s in order:
            if any(f.status == s for f in self.findings):
                return s
        return Status.NOT_APPLICABLE


@dataclass
class ScoreBreakdown:
    """How the composite score was arrived at — fully auditable."""

    score: int
    grade: str
    max_points: float
    earned_points: float
    category_scores: dict[str, dict[str, float]] = field(default_factory=dict)
    deductions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Narrative:
    """Plain-English risk story. `source` records who wrote it."""

    source: str                      # "llm:claude-…" or "deterministic"
    summary: str
    attack_scenarios: list[str] = field(default_factory=list)
    remediation_steps: list[dict[str, str]] = field(default_factory=list)
    model: str | None = None
    generated_at: str | None = None
    fallback_reason: str | None = None


@dataclass
class Assessment:
    """The complete result of scanning one domain."""

    domain: str
    started_at: str
    finished_at: str | None = None
    checks: list[CheckResult] = field(default_factory=list)
    score: ScoreBreakdown | None = None
    narrative: Narrative | None = None
    scan_id: str | None = None
    engine_version: str = "1.0.0"

    @property
    def findings(self) -> list[Finding]:
        return [f for c in self.checks for f in c.findings]

    def findings_by_severity(self) -> list[Finding]:
        """Worst first. Within a severity, the check that carries more weight
        leads — so a DMARC failure outranks an SPF failure of the same severity,
        which is the order a reader should act in."""
        from .engine.scoring import CHECK_WEIGHTS

        check_of = {f.id: c.check_id for c in self.checks for f in c.findings}
        return sorted(
            [f for f in self.findings if f.counts_against_score],
            key=lambda f: (f.severity.rank, -CHECK_WEIGHTS.get(check_of.get(f.id, ""), 0.0)),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self, dict_factory=_dict_factory)


def _dict_factory(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for k, v in items:
        out[k] = v.value if isinstance(v, Enum) else v
    return out


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
