#!/usr/bin/env python3
"""Export a click-to-open, offline copy of the interface.

The app is a server: it needs Python running to scan anything. This produces a
folder of plain .html files that open by double-click with no install at all, so
the interface can be seen (and demoed on a laptop with no setup) before anyone
runs the real thing.

What it keeps: every page exactly as the app renders it, the stylesheet inlined,
and the generated PDF reports alongside.
What it drops: the scan form and HTMX polling, since those need the server. The
form is replaced by a short note pointing at the launcher.

    python tools/export_preview.py --base http://127.0.0.1:8000 --out preview
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=20) as resp:
        return resp.read()


def scan_filename(scan_id: str) -> str:
    return f"scan-{scan_id}.html"


def rewrite(html: str, css: str, scan_ids: list[str], *, is_index: bool) -> str:
    # Inline the stylesheet so a single file works from file:// with no server.
    html = html.replace(
        '<link rel="stylesheet" href="/static/style.css">',
        f"<style>\n{css}\n</style>",
    )

    # HTMX only drives live scan progress, which cannot run without the backend.
    html = re.sub(r'\s*<script src="https://unpkg\.com/htmx[^>]*></script>', "", html)

    # Point navigation at the exported files.
    for sid in scan_ids:
        html = html.replace(f'href="/scan/{sid}/report.pdf"', f'href="report-{sid}.pdf"')
        html = html.replace(f'href="/scan/{sid}"', f'href="{scan_filename(sid)}"')
    html = html.replace('href="/history"', 'href="history.html"')
    html = html.replace('href="/"', 'href="index.html"')

    # The API docs are served by the running app.
    html = html.replace('<a href="/docs">API</a>', "")

    # Replace the live scan form with an honest note.
    form = re.search(r'<form class="scan-form".*?</form>\s*', html, re.S)
    if form:
        html = html.replace(form.group(0), OFFLINE_NOTICE)
        html = re.sub(r'<p class="form-note">.*?</p>', "", html, flags=re.S)

    if is_index:
        html = html.replace("</main>", PREVIEW_FOOTNOTE + "</main>")

    return html


OFFLINE_NOTICE = """
<div class="alert" style="background:var(--med-bg);border-color:var(--med);color:var(--med)">
  <strong>This is the offline preview.</strong>
  Every page here is the real interface rendered from real scan output, but scanning a new
  domain needs the engine running. Open <code>START-HERE.txt</code> in this folder to
  launch the full app in one command.
</div>
"""

PREVIEW_FOOTNOTE = """
<section class="panel" style="margin-top:18px">
  <h2>What you can open here</h2>
  <dl class="checklist">
    <dt>A domain that can be spoofed</dt>
    <dd>Scores 22/100. DMARC sits at <code>p=none</code>, so forged mail is reported and
        delivered anyway. Ten findings, each with the record it was read from.</dd>
    <dt>A correctly configured domain</dt>
    <dd>Scores 100/100 with an empty fix list, which is the answer to "what happens if the
        domain is already fine".</dd>
    <dt>A worst-case domain</dt>
    <dd><code>v=spf1 +all</code> and no DMARC at all: SPF actively authorises the whole
        internet to send as the domain.</dd>
  </dl>
</section>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--out", default="preview")
    ap.add_argument("--scans", help="JSON mapping of domain to scan id")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    css = fetch(f"{base}/static/style.css").decode()

    if args.scans:
        scan_ids = list(json.loads(args.scans).values())
    else:
        listing = fetch(f"{base}/api/scan-list").decode()
        scan_ids = [row["scan_id"] for row in json.loads(listing)]

    pages = [("index.html", "/", True), ("history.html", "/history", False)]
    pages += [(scan_filename(s), f"/scan/{s}", False) for s in scan_ids]

    for name, path, is_index in pages:
        html = fetch(base + path).decode()
        (out / name).write_text(rewrite(html, css, scan_ids, is_index=is_index))
        print(f"  wrote {name}")

    for sid in scan_ids:
        (out / f"report-{sid}.pdf").write_bytes(fetch(f"{base}/scan/{sid}/report.pdf"))
        print(f"  wrote report-{sid}.pdf")

    print(f"\nPreview written to {out.resolve()}")
    print("Open index.html in any browser. No install needed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
