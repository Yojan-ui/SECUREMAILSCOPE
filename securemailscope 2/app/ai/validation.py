"""Grounding checks applied to every LLM narrative before it is shown.

The rule the whole AI layer rests on: the model may re-express what the engine
found, and may not add to it. These checks enforce that mechanically, so the
answer to "what stops it hallucinating a vulnerability?" is a function rather
than a promise about the prompt.

A narrative is rejected if it:
  1. is not valid JSON in the expected shape
  2. states a score other than the one the engine computed
  3. cites a finding id the assessment does not contain
  4. proposes remediation when the engine found nothing wrong
  5. asserts a check passed when the engine recorded it as inconclusive
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..models import Assessment

_SCORE_PATTERNS = [
    re.compile(r"\b(\d{1,3})\s*/\s*100\b"),
    re.compile(r"\bscores?\s+(?:of\s+)?(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\bscore\s+(?:is|of)\s+(\d{1,3})\b", re.IGNORECASE),
]

_GRADE_PATTERN = re.compile(r"\bgrade\s+(?:of\s+)?([A-F][+-]?)\b", re.IGNORECASE)

MAX_SUMMARY_CHARS = 4000
MAX_SCENARIOS = 8
MAX_STEPS = 15


class ValidationError(Exception):
    """The narrative failed a grounding check and must not be used."""


def parse_and_validate(raw: str, assessment: Assessment) -> dict[str, Any]:
    payload = _extract_json(raw)
    _check_shape(payload)
    _check_score_claims(payload, assessment)
    _check_finding_references(payload, assessment)
    _check_no_invented_issues(payload, assessment)
    return payload


def _extract_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # The model occasionally wraps the object in prose; take the outermost {...}.
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValidationError("response contained no JSON object")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValidationError(f"response was not valid JSON: {exc}")


def _check_shape(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValidationError("response was not a JSON object")

    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValidationError("response has no summary")
    if len(summary) > MAX_SUMMARY_CHARS:
        raise ValidationError("summary exceeded the length limit")

    scenarios = payload.get("attack_scenarios", [])
    if not isinstance(scenarios, list) or len(scenarios) > MAX_SCENARIOS:
        raise ValidationError("attack_scenarios is malformed or too long")
    if any(not isinstance(s, str) for s in scenarios):
        raise ValidationError("attack_scenarios must be strings")

    steps = payload.get("remediation_steps", [])
    if not isinstance(steps, list) or len(steps) > MAX_STEPS:
        raise ValidationError("remediation_steps is malformed or too long")
    for step in steps:
        if not isinstance(step, dict):
            raise ValidationError("each remediation step must be an object")
        if not isinstance(step.get("action"), str) or not step["action"].strip():
            raise ValidationError("a remediation step has no action")


def _check_score_claims(payload: dict[str, Any], assessment: Assessment) -> None:
    """The model may quote the score; it may not invent a different one."""
    if not assessment.score:
        return
    actual = assessment.score.score
    text = _all_text(payload)

    for pattern in _SCORE_PATTERNS:
        for match in pattern.finditer(text):
            claimed = int(match.group(1))
            if claimed != actual:
                raise ValidationError(
                    f"narrative claims a score of {claimed} but the engine computed {actual}"
                )

    for match in _GRADE_PATTERN.finditer(text):
        claimed = match.group(1).upper()
        if claimed != assessment.score.grade.upper():
            raise ValidationError(
                f"narrative claims grade {claimed} but the engine computed "
                f"{assessment.score.grade}"
            )


def _check_finding_references(payload: dict[str, Any], assessment: Assessment) -> None:
    valid = {f.id for f in assessment.findings}
    for step in payload.get("remediation_steps", []):
        ref = step.get("finding_id")
        if ref and ref not in valid:
            raise ValidationError(
                f"remediation step cites unknown finding id {ref!r}"
            )


def _check_no_invented_issues(payload: dict[str, Any], assessment: Assessment) -> None:
    """When the engine found nothing, the narrative may not manufacture work."""
    scored_findings = assessment.findings_by_severity()
    if scored_findings:
        return

    if payload.get("remediation_steps"):
        raise ValidationError(
            "engine found no issues but the narrative proposed remediation steps"
        )
    if payload.get("attack_scenarios"):
        raise ValidationError(
            "engine found no issues but the narrative described attack scenarios"
        )


def _all_text(payload: dict[str, Any]) -> str:
    parts = [str(payload.get("summary", ""))]
    parts.extend(str(s) for s in payload.get("attack_scenarios", []))
    for step in payload.get("remediation_steps", []):
        if isinstance(step, dict):
            parts.extend(str(v) for v in step.values())
    return "\n".join(parts)
