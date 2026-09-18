#!/usr/bin/env python3
"""Command-line entry point.

    python cli.py example.com
    python cli.py example.com --json
    python cli.py example.com --pdf report.pdf
    python cli.py example.com --no-tls-probe --resolver doh
"""
from __future__ import annotations

import argparse
import json
import sys

from app import ai
from app.engine import scanner
from app.engine.scanner import InvalidDomain, ScanOptions
from app.engine.scoring import risk_label
from app.report import build_pdf
from app.storage import Store

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
COLORS = {
    "critical": "\033[31m", "high": "\033[33m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[2m", "pass": "\033[32m",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="securemailscope",
        description="Passive email security posture assessment.",
    )
    parser.add_argument("domain")
    parser.add_argument("--json", action="store_true", help="emit the full assessment as JSON")
    parser.add_argument("--pdf", metavar="PATH", help="write the PDF report to PATH")
    parser.add_argument("--no-tls-probe", action="store_true",
                        help="skip SMTP/TLS probing (DNS checks only)")
    parser.add_argument("--no-llm", action="store_true",
                        help="use the rule-based narrative writer only")
    parser.add_argument("--resolver", choices=["auto", "system", "doh"], default="auto")
    parser.add_argument("--selectors", help="comma-separated DKIM selectors to check")
    parser.add_argument("--save", action="store_true", help="record the scan in the database")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        globals().update(RESET="", BOLD="", DIM="")
        COLORS.update({k: "" for k in COLORS})

    options = ScanOptions(
        probe_tls=not args.no_tls_probe,
        enumerate_tls_versions=not args.no_tls_probe,
        resolver_mode=args.resolver,
        dkim_selectors=args.selectors.split(",") if args.selectors else None,
    )

    def progress(check_id: str, label: str, percent: int) -> None:
        if not args.json:
            print(f"{DIM}[{percent:3d}%] {label}{RESET}", file=sys.stderr)

    try:
        assessment = scanner.scan(args.domain, options, on_progress=progress)
    except InvalidDomain as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    assessment.narrative = ai.generate_narrative(assessment, use_llm=not args.no_llm)

    if args.save:
        Store().save(assessment)

    if args.pdf:
        with open(args.pdf, "wb") as fh:
            fh.write(build_pdf(assessment.to_dict()))
        print(f"PDF report written to {args.pdf}", file=sys.stderr)

    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2, default=str))
        return 0

    _print_report(assessment)
    score = assessment.score.score if assessment.score else -1
    return 0 if score >= 70 else 1


def _print_report(assessment) -> None:
    score = assessment.score
    value = score.score if score else -1

    print()
    print(f"{BOLD}{assessment.domain}{RESET}")
    print(f"{'─' * max(len(assessment.domain), 40)}")
    if value >= 0:
        print(f"Score: {BOLD}{value}/100{RESET}  Grade: {BOLD}{score.grade}{RESET}"
              f"  {DIM}({risk_label(value)}){RESET}")
    else:
        print(f"Score: {DIM}not determined — no check returned a conclusive result{RESET}")

    for name, bucket in (score.category_scores if score else {}).items():
        bar_len = int(bucket["percent"] / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {name:<20} {bar} {bucket['percent']:>5.1f}%")

    issues = assessment.findings_by_severity()
    if issues:
        print(f"\n{BOLD}Findings ({len(issues)}){RESET}")
        for finding in issues:
            colour = COLORS.get(finding.severity.value, "")
            print(f"\n  {colour}[{finding.severity.value.upper()}]{RESET} {finding.title}")
            print(f"      {_wrap(finding.detail, 6)}")
            if finding.remediation:
                print(f"      {DIM}Fix: {_wrap(finding.remediation, 11)}{RESET}")
    else:
        print(f"\n{COLORS['pass']}No failing or warning findings.{RESET}")

    skipped = [
        f for c in assessment.checks for f in c.findings
        if f.status.value == "error"
    ]
    if skipped:
        print(f"\n{BOLD}Not assessed{RESET}")
        for finding in skipped:
            print(f"  {DIM}– {finding.title}{RESET}")

    if assessment.narrative:
        label = ("AI narrative" if assessment.narrative.source.startswith("llm")
                 else "Rule-based narrative")
        print(f"\n{BOLD}{label}{RESET}")
        print(f"  {_wrap(assessment.narrative.summary, 2)}")
        if assessment.narrative.fallback_reason:
            print(f"\n  {DIM}({assessment.narrative.fallback_reason}){RESET}")
    print()


def _wrap(text: str, indent: int, width: int = 88) -> str:
    import textwrap
    return ("\n" + " " * indent).join(
        textwrap.wrap(text, width=width - indent) or [""]
    )


if __name__ == "__main__":
    sys.exit(main())
