"""PDF report generation.

Produces the artifact a security team would actually circulate: score and grade
on the cover, prioritised findings with evidence, the narrative, a remediation
plan, and an explicit statement of scope and method so the reader knows exactly
what was and was not done to their infrastructure.
"""
from __future__ import annotations

import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

from .engine.scoring import CHECK_WEIGHTS, risk_label
from .models import Severity, Status

INK = colors.HexColor("#141414")
MUTED = colors.HexColor("#6b6b6b")
RULE = colors.HexColor("#d8d5d0")
PAPER = colors.HexColor("#faf9f7")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#8f1d1d"),
    "high": colors.HexColor("#b5521c"),
    "medium": colors.HexColor("#8a6d1f"),
    "low": colors.HexColor("#4a6b8a"),
    "info": MUTED,
}

GRADE_COLORS = {
    "A": colors.HexColor("#2d6a4f"), "B": colors.HexColor("#4a7c59"),
    "C": colors.HexColor("#8a6d1f"), "D": colors.HexColor("#b5521c"),
    "F": colors.HexColor("#8f1d1d"), "N": MUTED,
}


def build_pdf(assessment: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Email Security Posture Assessment — {assessment['domain']}",
        author="SecureMailScope",
        subject="Passive cryptographic and email authentication posture assessment",
    )

    s = _styles()
    story: list[Any] = []

    _cover(story, assessment, s)
    _executive_summary(story, assessment, s)
    _score_breakdown(story, assessment, s)
    story.append(PageBreak())
    _findings(story, assessment, s)
    _remediation(story, assessment, s)
    _methodology(story, assessment, s)

    doc.build(story, onFirstPage=_page_furniture, onLaterPages=_page_furniture)
    return buf.getvalue()


# --------------------------------------------------------------------------- styles

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=22, leading=27, textColor=INK, alignment=TA_LEFT, spaceAfter=2),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, leading=15, textColor=MUTED, spaceAfter=14),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=13.5, leading=17, textColor=INK, spaceBefore=16, spaceAfter=7),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10.5, leading=14, textColor=INK, spaceBefore=10, spaceAfter=3),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=14.5, textColor=INK, spaceAfter=8),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=11.5, textColor=MUTED, spaceAfter=5),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"], fontName="Courier",
            fontSize=7.5, leading=10.5, textColor=colors.HexColor("#3a3a3a"),
            backColor=PAPER, borderPadding=4, spaceAfter=6),
        "score": ParagraphStyle(
            "score", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=52, leading=54, alignment=TA_CENTER),
        "grade": ParagraphStyle(
            "grade", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=17, leading=20, alignment=TA_CENTER),
        "gradelabel": ParagraphStyle(
            "gradelabel", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, alignment=TA_CENTER, textColor=MUTED),
    }


def _page_furniture(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 11 * mm, "SecureMailScope — passive email security posture assessment")
    canvas.drawRightString(A4[0] - 20 * mm, 11 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(20 * mm, 14 * mm, A4[0] - 20 * mm, 14 * mm)
    canvas.restoreState()


# --------------------------------------------------------------------------- sections

def _cover(story: list[Any], a: dict[str, Any], s: dict[str, ParagraphStyle]) -> None:
    score = a.get("score") or {}
    value = score.get("score", -1)
    grade = score.get("grade", "N/A")
    colour = GRADE_COLORS.get(grade[0].upper() if grade else "N", MUTED)

    story.append(Paragraph("Email Security Posture Assessment", s["title"]))
    story.append(Paragraph(a["domain"], s["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=0.6, color=RULE, spaceAfter=14))

    gauge = [
        [Paragraph(f'<font color="{colour.hexval()}">{value if value >= 0 else "—"}</font>',
                   s["score"])],
        [Paragraph(f'<font color="{colour.hexval()}">{grade}</font>', s["grade"])],
        [Paragraph(risk_label(value), s["gradelabel"])],
    ]
    gauge_tbl = Table(gauge, colWidths=[42 * mm])
    gauge_tbl.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, RULE),
        ("BACKGROUND", (0, 0), (-1, -1), PAPER),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    started = _fmt_date(a.get("started_at"))
    findings = a.get("checks", [])
    counts = _counts(a)
    meta_rows = [
        ["Scan date", started],
        ["Scan ID", a.get("scan_id", "—")],
        ["Checks run", str(len(findings))],
        ["Findings", f"{counts['fail']} failing, {counts['warn']} warnings, "
                     f"{counts['pass']} passing"],
        ["Narrative", _narrative_label(a)],
        ["Engine version", a.get("engine_version", "1.0.0")],
    ]
    meta = Table([[Paragraph(f"<b>{k}</b>", s["small"]), Paragraph(v, s["small"])]
                  for k, v in meta_rows], colWidths=[30 * mm, 68 * mm])
    meta.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
    ]))

    layout = Table([[gauge_tbl, meta]], colWidths=[48 * mm, 102 * mm])
    layout.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(layout)
    story.append(Spacer(1, 8))


def _executive_summary(story: list[Any], a: dict[str, Any],
                       s: dict[str, ParagraphStyle]) -> None:
    narrative = a.get("narrative") or {}
    story.append(Paragraph("Executive summary", s["h2"]))

    summary = narrative.get("summary") or "No narrative was generated for this scan."
    for para in summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(_esc(para.strip()), s["body"]))

    scenarios = narrative.get("attack_scenarios") or []
    if scenarios:
        story.append(Paragraph("What an attacker could do with this", s["h3"]))
        for item in scenarios:
            story.append(Paragraph(f"— {_esc(item)}", s["body"]))

    if narrative.get("fallback_reason"):
        story.append(Paragraph(
            f"Narrative generated by the built-in rule-based writer. "
            f"Reason: {_esc(narrative['fallback_reason'])}", s["small"]))


def _score_breakdown(story: list[Any], a: dict[str, Any],
                     s: dict[str, ParagraphStyle]) -> None:
    score = a.get("score") or {}
    cats = score.get("category_scores") or {}
    if not cats:
        return

    story.append(Paragraph("Score by category", s["h2"]))
    rows = [["Category", "Earned", "Available", "Result"]]
    for name, bucket in cats.items():
        rows.append([
            name,
            f"{bucket.get('earned', 0):.1f}",
            f"{bucket.get('max', 0):.1f}",
            f"{bucket.get('percent', 0):.0f}%",
        ])

    tbl = Table(rows, colWidths=[62 * mm, 28 * mm, 28 * mm, 32 * mm])
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, colors.HexColor("#eceae7")),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(tbl)

    excluded = [d for d in score.get("deductions", []) if d.get("excluded")]
    if excluded:
        names = ", ".join(d["check"] for d in excluded)
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            f"Excluded from scoring because the check could not complete: {names}. "
            "These are neither counted as passing nor as failing — the score is "
            "calculated over the checks that returned a conclusive result.", s["small"]))


def _findings(story: list[Any], a: dict[str, Any], s: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Findings", s["h2"]))

    all_findings = [f for c in a.get("checks", []) for f in c.get("findings", [])]
    scored = [f for f in all_findings if f.get("status") in ("fail", "warn")]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    scored.sort(key=lambda f: order.get(f.get("severity", "info"), 9))

    if not scored:
        story.append(Paragraph(
            "No failing or warning findings. Every check that returned a conclusive "
            "result passed.", s["body"]))
    else:
        for finding in scored:
            story.append(_finding_block(finding, s))

    passed = [f for f in all_findings if f.get("status") == "pass"]
    if passed:
        story.append(Paragraph("Controls verified as correctly configured", s["h3"]))
        for finding in passed:
            story.append(Paragraph(f"— {_esc(finding['title'])}", s["small"]))

    skipped = [f for f in all_findings if f.get("status") in ("error", "n/a")]
    if skipped:
        story.append(Paragraph("Not assessed", s["h3"]))
        for finding in skipped:
            story.append(Paragraph(
                f"— {_esc(finding['title'])}: {_esc(finding.get('detail', ''))}", s["small"]))


def _finding_block(finding: dict[str, Any], s: dict[str, ParagraphStyle]) -> Any:
    sev = finding.get("severity", "info")
    colour = SEVERITY_COLORS.get(sev, MUTED)
    parts = [
        Paragraph(
            f'<font color="{colour.hexval()}"><b>[{sev.upper()}]</b></font> '
            f'<b>{_esc(finding["title"])}</b>', s["h3"]),
        Paragraph(_esc(finding.get("detail", "")), s["body"]),
    ]

    evidence = finding.get("evidence") or {}
    if evidence:
        rendered = "<br/>".join(
            f"{_esc(str(k))} = {_esc(_short(v))}" for k, v in list(evidence.items())[:6]
        )
        parts.append(Paragraph(rendered, s["mono"]))

    if finding.get("remediation"):
        parts.append(Paragraph(
            f"<b>Fix:</b> {_esc(finding['remediation'])}", s["body"]))
    if finding.get("reference"):
        parts.append(Paragraph(f"Reference: {_esc(finding['reference'])}", s["small"]))

    parts.append(Spacer(1, 4))
    return KeepTogether(parts)


def _remediation(story: list[Any], a: dict[str, Any], s: dict[str, ParagraphStyle]) -> None:
    steps = (a.get("narrative") or {}).get("remediation_steps") or []
    if not steps:
        return

    story.append(Paragraph("Remediation plan", s["h2"]))
    story.append(Paragraph(
        "Ordered by risk reduced, not by effort required.", s["small"]))

    rows = [["#", "Action", "Severity"]]
    for step in steps[:12]:
        action = step.get("action", "")
        if step.get("rationale"):
            action += f"<br/><font color='{MUTED.hexval()}' size='7.5'>" \
                      f"{_esc(step['rationale'])}</font>"
        rows.append([
            step.get("priority", ""),
            Paragraph(action if "<" in action else _esc(action),
                      ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5,
                                     leading=12, textColor=INK)),
            step.get("severity", "") or _sev_for(a, step.get("finding_id", "")),
        ])

    tbl = Table(rows, colWidths=[9 * mm, 119 * mm, 22 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, colors.HexColor("#eceae7")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)


def _methodology(story: list[Any], a: dict[str, Any], s: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Method and scope", s["h2"]))
    story.append(Paragraph(
        "This assessment is passive and read-only. It consists of public DNS lookups "
        "(SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI records), an HTTPS GET of the "
        "domain's published MTA-STS policy file, and SMTP connections to the mail hosts "
        "the domain itself advertises in its MX records, used to observe the server's "
        "own STARTTLS advertisement and complete a TLS handshake.", s["body"]))
    story.append(Paragraph(
        "The assessment does not send test phishing messages, does not attempt "
        "authentication or authentication bypass, does not relay or deliver mail, does "
        "not access mailbox contents, and does not attempt to exploit any weakness it "
        "identifies. No credentials are used and no data is submitted to the target. "
        "Connections are closed with QUIT and are rate-limited per domain.", s["body"]))

    weights = ", ".join(
        f"{name} {int(weight)}" for name, weight in
        sorted(CHECK_WEIGHTS.items(), key=lambda kv: -kv[1]) if weight
    )
    story.append(Paragraph(
        f"Scoring assigns each check a share of 100 points weighted by the attacker "
        f"leverage a failure grants ({weights}). Each finding removes a fraction of its "
        "check's points by severity: critical 100%, high 60%, medium 30%, low 10%. A "
        "check that could not complete is removed from the denominator rather than "
        "counted as a failure, so a network restriction on the scanner is never reported "
        "as a weakness in the assessed domain.", s["body"]))
    story.append(Paragraph(
        "The narrative section is generated from the findings above and is constrained "
        "to them: it cannot introduce a finding the engine did not produce, and any "
        "generated text that references an unknown finding or states a score other than "
        "the computed one is rejected and replaced by the built-in rule-based writer.",
        s["body"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%d %B %Y at %H:%M')} · "
        f"Scan ID {a.get('scan_id', '—')}", s["small"]))


# --------------------------------------------------------------------------- helpers

def _counts(a: dict[str, Any]) -> dict[str, int]:
    out = {"pass": 0, "warn": 0, "fail": 0, "error": 0}
    for check in a.get("checks", []):
        for finding in check.get("findings", []):
            key = finding.get("status")
            if key in out:
                out[key] += 1
    return out


def _narrative_label(a: dict[str, Any]) -> str:
    narrative = a.get("narrative") or {}
    source = narrative.get("source", "—")
    if source.startswith("llm:"):
        return f"AI-generated ({narrative.get('model') or source.split(':', 1)[1]})"
    if source == "deterministic":
        return "Rule-based (built-in)"
    return source


def _sev_for(a: dict[str, Any], finding_id: str) -> str:
    for check in a.get("checks", []):
        for finding in check.get("findings", []):
            if finding.get("id") == finding_id:
                return finding.get("severity", "")
    return ""


def _short(value: Any, limit: int = 110) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _fmt_date(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%d %B %Y, %H:%M UTC")
    except ValueError:
        return value
