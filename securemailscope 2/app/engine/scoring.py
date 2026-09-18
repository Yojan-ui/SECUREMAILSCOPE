"""Composite scoring.

The model is deliberately simple enough to explain to a judge or a CISO in one
sentence: every check owns a share of 100 points, weighted by how much attacker
leverage a failure in that check actually grants, and each finding removes a
fraction of its check's points according to severity.

Two properties matter and are enforced here:

  * A check that could not complete (DNS failure, port 25 blocked) is removed
    from the denominator rather than scored as a failure. A network problem on
    the scanner's side must never be reported as a weakness in the domain.
  * A domain with nothing wrong scores 100. There is no floor of manufactured
    deductions and no curve — "nothing to fix" is a reachable result.
"""
from __future__ import annotations

from typing import Any

from ..models import Assessment, Category, CheckResult, ScoreBreakdown, Severity, Status

# Share of the 100-point total owned by each check.
#
# DMARC carries the most weight because it is the only control that tells a
# receiver to *act*: SPF and DKIM produce a verdict, DMARC turns that verdict
# into rejection. A domain can have flawless SPF and DKIM and still be freely
# spoofable if DMARC is absent or set to p=none.
CHECK_WEIGHTS: dict[str, float] = {
    "dmarc": 30.0,
    "transport": 25.0,
    "spf": 20.0,
    "dkim": 15.0,
    "mta_sts": 7.0,
    "tls_rpt": 3.0,
    "bimi": 0.0,      # brand presentation, not a security control
}

# Fraction of a check's points removed by one finding of each severity.
SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH: 0.60,
    Severity.MEDIUM: 0.30,
    Severity.LOW: 0.10,
    Severity.INFO: 0.00,
}

GRADE_BANDS: list[tuple[int, str]] = [
    (95, "A+"), (90, "A"), (85, "A-"),
    (80, "B+"), (75, "B"), (70, "B-"),
    (65, "C+"), (60, "C"), (55, "C-"),
    (50, "D+"), (45, "D"), (40, "D-"),
    (0, "F"),
]


def score(assessment: Assessment) -> ScoreBreakdown:
    max_points = 0.0
    earned_points = 0.0
    deductions: list[dict[str, Any]] = []
    category_totals: dict[str, dict[str, float]] = {}

    for check in assessment.checks:
        weight = CHECK_WEIGHTS.get(check.check_id, 0.0)
        if weight == 0.0:
            continue

        if _is_inconclusive(check):
            # Excluded from both numerator and denominator.
            deductions.append({
                "check": check.check_id,
                "finding": None,
                "severity": None,
                "points": 0.0,
                "excluded": True,
                "reason": check.error or "check could not complete",
            })
            continue

        max_points += weight
        penalty_fraction = 0.0

        for finding in check.findings:
            if not finding.counts_against_score:
                continue
            fraction = SEVERITY_PENALTY.get(finding.severity, 0.0)
            if fraction == 0.0:
                continue
            penalty_fraction += fraction
            deductions.append({
                "check": check.check_id,
                "finding": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "points": round(min(fraction, 1.0) * weight, 2),
                "excluded": False,
            })

        # A single check cannot remove more than its own weight.
        penalty_fraction = min(penalty_fraction, 1.0)
        check_earned = weight * (1.0 - penalty_fraction)
        earned_points += check_earned

        cat = check.category.value
        bucket = category_totals.setdefault(cat, {"max": 0.0, "earned": 0.0})
        bucket["max"] += weight
        bucket["earned"] += check_earned

    if max_points == 0.0:
        # Every weighted check was inconclusive — report no score rather than 0,
        # which would read as "catastrophically insecure".
        return ScoreBreakdown(
            score=-1, grade="N/A", max_points=0.0, earned_points=0.0,
            category_scores={}, deductions=deductions,
        )

    raw = (earned_points / max_points) * 100.0
    final = int(round(raw))

    for cat, bucket in category_totals.items():
        bucket["percent"] = round((bucket["earned"] / bucket["max"]) * 100.0, 1) \
            if bucket["max"] else 0.0
        bucket["max"] = round(bucket["max"], 2)
        bucket["earned"] = round(bucket["earned"], 2)

    # Deductions are reported largest-first so the report leads with what matters.
    deductions.sort(key=lambda d: (d.get("excluded", False), -d.get("points", 0.0)))

    return ScoreBreakdown(
        score=final,
        grade=grade_for(final),
        max_points=round(max_points, 2),
        earned_points=round(earned_points, 2),
        category_scores=category_totals,
        deductions=deductions,
    )


def grade_for(value: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if value >= threshold:
            return letter
    return "F"


def _is_inconclusive(check: CheckResult) -> bool:
    """True when the scan could not determine anything about this control."""
    if check.error:
        return True
    if not check.findings:
        return True
    return all(f.status in (Status.ERROR, Status.NOT_APPLICABLE) for f in check.findings)


def risk_label(value: int) -> str:
    if value < 0:
        return "Not determined"
    if value >= 90:
        return "Low risk"
    if value >= 75:
        return "Moderate risk"
    if value >= 50:
        return "Elevated risk"
    return "High risk"


def category_summary(assessment: Assessment) -> dict[str, dict[str, Any]]:
    """Per-category rollup used by the dashboard and the PDF."""
    out: dict[str, dict[str, Any]] = {}
    for category in Category:
        checks = [c for c in assessment.checks if c.category == category]
        if not checks:
            continue
        failures = [f for c in checks for f in c.findings if f.status == Status.FAIL]
        warnings = [f for c in checks for f in c.findings if f.status == Status.WARN]
        out[category.value] = {
            "checks": len(checks),
            "failures": len(failures),
            "warnings": len(warnings),
            "passes": len([f for c in checks for f in c.findings if f.status == Status.PASS]),
        }
    return out
