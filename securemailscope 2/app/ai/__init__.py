"""Narrative generation: LLM where available, deterministic always."""
from __future__ import annotations

import json
import logging
from typing import Any

from ..models import Assessment, Narrative, Status, utcnow
from . import deterministic
from .llm import LLMError, LLMProvider, build_provider
from .validation import ValidationError, parse_and_validate

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the reporting layer of SecureMailScope, a passive email security posture \
assessment tool. A deterministic scanning engine has already performed every check and \
computed the score. Your only job is to explain, in plain English, what the engine \
found.

Hard constraints:
- You must not introduce any finding, weakness, or observation that is not present in \
the findings given to you. If the engine found nothing wrong, say so plainly; do not \
manufacture advice to appear useful.
- You must not state a score or grade other than the one supplied.
- Findings with status "error" mean the check could not complete. Describe these as not \
assessed. Never describe them as passing and never describe them as failing.
- Every remediation step must reference the finding_id it addresses.
- Do not speculate about the organisation, its size, its industry, or incidents it may \
have experienced. You know only what is in the findings.

Write for a technically literate executive — a CISO reading a one-page summary. Explain \
what an attacker could concretely do with each gap, in terms of actions and outcomes \
rather than protocol mechanics. Be direct and specific; avoid filler such as "in today's \
threat landscape".

Respond with a single JSON object and nothing else:
{
  "summary": "2-4 paragraphs of prose. No bullet points, no headings.",
  "attack_scenarios": ["Concrete scenario tied to a specific finding.", "..."],
  "remediation_steps": [
    {"priority": "1", "finding_id": "<exact id from the findings>",
     "action": "What to do, specifically.",
     "rationale": "Why this one is first."}
  ]
}
Order remediation by the risk actually reduced, not by ease. If there are no findings, \
return empty arrays for attack_scenarios and remediation_steps."""


def generate_narrative(assessment: Assessment,
                       provider: LLMProvider | None = None,
                       use_llm: bool = True) -> Narrative:
    """Produce the narrative, falling back to the rule-based writer on any problem."""
    if not use_llm:
        return deterministic.generate(assessment, fallback_reason="LLM disabled for this scan")

    provider = provider or build_provider()
    if provider is None:
        return deterministic.generate(
            assessment,
            fallback_reason="No LLM provider configured (set ANTHROPIC_API_KEY to enable)",
        )
    if not provider.configured:
        return deterministic.generate(
            assessment,
            fallback_reason=f"{provider.name} provider is not configured",
        )

    try:
        raw = provider.complete(SYSTEM_PROMPT, _build_user_prompt(assessment))
    except LLMError as exc:
        log.warning("LLM call failed for %s: %s", assessment.domain, exc)
        return deterministic.generate(assessment, fallback_reason=f"LLM call failed: {exc}")

    try:
        payload = parse_and_validate(raw, assessment)
    except ValidationError as exc:
        # This is the important path: a model that drifts from the findings is
        # discarded rather than shown with a caveat.
        log.warning("LLM narrative rejected for %s: %s", assessment.domain, exc)
        return deterministic.generate(
            assessment, fallback_reason=f"LLM output failed grounding validation: {exc}"
        )

    return Narrative(
        source=f"llm:{provider.name}",
        model=provider.model,
        summary=payload["summary"].strip(),
        attack_scenarios=[s.strip() for s in payload.get("attack_scenarios", [])],
        remediation_steps=[_normalise_step(s, i)
                           for i, s in enumerate(payload.get("remediation_steps", []), 1)],
        generated_at=utcnow(),
    )


def _normalise_step(step: dict[str, Any], index: int) -> dict[str, str]:
    return {
        "priority": str(step.get("priority") or index),
        "finding_id": str(step.get("finding_id") or ""),
        "action": str(step.get("action", "")).strip(),
        "rationale": str(step.get("rationale", "")).strip(),
    }


def _build_user_prompt(assessment: Assessment) -> str:
    """Serialise findings for the model. Evidence is included so the narrative can
    be specific; nothing else about the domain is."""
    score = assessment.score
    findings_payload = []
    for check in assessment.checks:
        for finding in check.findings:
            findings_payload.append({
                "id": finding.id,
                "check": check.check_id,
                "title": finding.title,
                "status": finding.status.value,
                "severity": finding.severity.value,
                "category": finding.category.value,
                "detail": finding.detail,
                "evidence": _trim(finding.evidence),
                "engine_remediation": finding.remediation,
                "reference": finding.reference,
            })

    inconclusive = [
        {"check": c.check_id, "reason": c.error}
        for c in assessment.checks
        if c.error or (c.findings and all(f.status == Status.ERROR for f in c.findings))
    ]

    return json.dumps({
        "domain": assessment.domain,
        "score": score.score if score else None,
        "grade": score.grade if score else None,
        "scanned_at": assessment.started_at,
        "checks_that_could_not_complete": inconclusive,
        "findings": findings_payload,
    }, indent=2)


def _trim(evidence: dict[str, Any], limit: int = 600) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in evidence.items():
        text = json.dumps(value, default=str)
        out[key] = value if len(text) <= limit else text[:limit] + "…"
    return out
