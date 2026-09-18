"""FastAPI application: server-rendered UI, JSON API and PDF export."""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import ai
from .engine import scanner
from .engine.scanner import InvalidDomain, ScanOptions
from .engine.scoring import risk_label
from .models import Assessment
from .report import build_pdf
from .storage import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("securemailscope")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))


def _ticks(text: Any) -> Any:
    """Render `backticked` spans in engine text as inline code.

    Findings quote record fragments (`p=none`, `~all`) in backticks so the same
    string reads correctly in the terminal, the PDF and here. Escape first, then
    substitute, so nothing in a DNS record can inject markup.
    """
    import html
    import re

    from markupsafe import Markup

    escaped = html.escape(str(text))
    return Markup(re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped))


templates.env.filters["ticks"] = _ticks

app = FastAPI(
    title="SecureMailScope",
    description="Passive cryptographic and email-authentication posture assessment",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web" / "static")), name="static")

store = Store(os.environ.get("SMS_DB_PATH") or Store.__init__.__defaults__[0])
executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan")

CACHE_MINUTES = int(os.environ.get("SMS_CACHE_MINUTES", "15"))
USE_LLM = os.environ.get("SMS_DISABLE_LLM", "").lower() not in ("1", "true", "yes")


# --------------------------------------------------------------------------- job state

@dataclass
class Job:
    job_id: str
    domain: str
    status: str = "queued"          # queued | running | done | failed
    percent: int = 0
    step: str = "Queued"
    scan_id: str | None = None
    error: str | None = None
    started: float = field(default_factory=time.monotonic)
    log: list[str] = field(default_factory=list)


_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()

# Per-client throttle: one scan submission every few seconds, so the service
# cannot be pointed at a target as a traffic amplifier.
_last_submit: dict[str, float] = {}
SUBMIT_INTERVAL = 3.0


def _register(job: Job) -> None:
    with _jobs_lock:
        _jobs[job.job_id] = job
        if len(_jobs) > 200:                       # bound memory
            oldest = sorted(_jobs.values(), key=lambda j: j.started)[:50]
            for stale in oldest:
                _jobs.pop(stale.job_id, None)


def _run_scan(job: Job) -> None:
    def progress(check_id: str, label: str, percent: int) -> None:
        job.step = label
        job.percent = percent
        job.log.append(label)

    job.status = "running"
    try:
        assessment = scanner.scan(
            job.domain,
            ScanOptions(
                probe_tls=os.environ.get("SMS_DISABLE_TLS_PROBE", "").lower()
                not in ("1", "true", "yes"),
            ),
            on_progress=progress,
        )
        job.step = "Generating risk narrative"
        job.percent = 92
        assessment.narrative = ai.generate_narrative(assessment, use_llm=USE_LLM)
        store.save(assessment)
        job.scan_id = assessment.scan_id
        job.percent = 100
        job.step = "Complete"
        job.status = "done"
    except InvalidDomain as exc:
        job.status, job.error = "failed", str(exc)
    except Exception as exc:
        log.exception("scan failed for %s", job.domain)
        job.status, job.error = "failed", f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- pages

@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    return templates.TemplateResponse(request, "index.html", {
        "recent": store.recent(8),
        "stats": store.stats(),
        "llm_enabled": USE_LLM and ai.build_provider() is not None,
    })


@app.post("/scan")
def start_scan(request: Request, domain: str = Form(...)) -> Any:
    client = request.client.host if request.client else "anonymous"
    now = time.monotonic()
    if now - _last_submit.get(client, 0.0) < SUBMIT_INTERVAL:
        return templates.TemplateResponse(request, "index.html", {
            "recent": store.recent(8),
            "stats": store.stats(),
            "error": "Please wait a few seconds between scans.",
            "llm_enabled": USE_LLM,
        }, status_code=429)
    _last_submit[client] = now

    try:
        normalised = scanner.normalise_domain(domain)
    except InvalidDomain as exc:
        return templates.TemplateResponse(request, "index.html", {
            "recent": store.recent(8),
            "stats": store.stats(),
            "error": str(exc),
            "llm_enabled": USE_LLM,
        }, status_code=400)

    cached = store.cached_scan(normalised, CACHE_MINUTES)
    if cached:
        return RedirectResponse(f"/scan/{cached['scan_id']}?cached=1", status_code=303)

    job = Job(job_id=uuid.uuid4().hex[:12], domain=normalised)
    _register(job)
    executor.submit(_run_scan, job)
    return RedirectResponse(f"/progress/{job.job_id}", status_code=303)


@app.get("/progress/{job_id}", response_class=HTMLResponse)
def progress_page(request: Request, job_id: str) -> Any:
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown scan job")
    return templates.TemplateResponse(request, "progress.html", {"job": job})


@app.get("/progress/{job_id}/fragment", response_class=HTMLResponse)
def progress_fragment(request: Request, job_id: str) -> Any:
    """Polled by the progress page. Returns a redirect header when finished."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown scan job")
    response = templates.TemplateResponse(
        request, "_progress_fragment.html", {"job": job}
    )
    if job.status == "done" and job.scan_id:
        response.headers["HX-Redirect"] = f"/scan/{job.scan_id}"
    return response


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_result(request: Request, scan_id: str, cached: int = 0) -> Any:
    assessment = store.get(scan_id)
    if not assessment:
        raise HTTPException(404, "Scan not found")

    return templates.TemplateResponse(request, "result.html", {
        "a": assessment,
        "cached": bool(cached),
        "risk": risk_label((assessment.get("score") or {}).get("score", -1)),
        "history": store.history_for(assessment["domain"], 10),
        "grouped": _group_findings(assessment),
        "verdicts": _verdicts(assessment),
    })


@app.get("/scan/{scan_id}/report.pdf")
def scan_report(scan_id: str) -> Response:
    assessment = store.get(scan_id)
    if not assessment:
        raise HTTPException(404, "Scan not found")
    pdf = build_pdf(assessment)
    filename = f"securemailscope-{assessment['domain']}-{scan_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/history", response_class=HTMLResponse)
def history(request: Request) -> Any:
    return templates.TemplateResponse(request, "history.html", {
        "scans": store.recent(50),
        "stats": store.stats(),
    })


# --------------------------------------------------------------------------- JSON API

@app.get("/api/scan/{domain}")
def api_scan(domain: str, use_llm: bool = True, probe_tls: bool = True) -> Any:
    """Synchronous scan. Intended for scripting and CI, not for the browser UI."""
    try:
        normalised = scanner.normalise_domain(domain)
    except InvalidDomain as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    cached = store.cached_scan(normalised, CACHE_MINUTES)
    if cached:
        return JSONResponse({"cached": True, **cached})

    assessment: Assessment = scanner.scan(normalised, ScanOptions(probe_tls=probe_tls))
    assessment.narrative = ai.generate_narrative(assessment, use_llm=use_llm and USE_LLM)
    store.save(assessment)
    return JSONResponse({"cached": False, **assessment.to_dict()})


@app.get("/api/scan-result/{scan_id}")
def api_scan_result(scan_id: str) -> Any:
    assessment = store.get(scan_id)
    if not assessment:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    return JSONResponse(assessment)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "llm_configured": ai.build_provider() is not None}


# --------------------------------------------------------------------------- helpers

def _group_findings(assessment: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    groups: dict[str, list[dict[str, Any]]] = {
        "issues": [], "passing": [], "not_assessed": []
    }
    for check in assessment.get("checks", []):
        for finding in check.get("findings", []):
            entry = {**finding, "check_name": check.get("name")}
            status = finding.get("status")
            if status in ("fail", "warn"):
                groups["issues"].append(entry)
            elif status == "pass":
                groups["passing"].append(entry)
            else:
                groups["not_assessed"].append(entry)
    groups["issues"].sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    return groups


def _verdicts(assessment: dict[str, Any]) -> list[dict[str, str]]:
    """The two questions a domain owner actually wants answered.

    Everything else on the results page is the evidence behind these. Each
    verdict is derived from findings the engine produced, and a control the scan
    could not reach is reported as unknown rather than guessed either way.
    """
    ids = {f["id"]: f for c in assessment.get("checks", []) for f in c.get("findings", [])}
    checks = {c["check_id"]: c for c in assessment.get("checks", [])}

    def inconclusive(check_id: str) -> bool:
        check = checks.get(check_id)
        if not check:
            return True
        if check.get("error"):
            return True
        return all(f.get("status") in ("error", "n/a") for f in check.get("findings", []))

    # 1. Can someone send mail as this domain and have it delivered?
    if inconclusive("dmarc"):
        spoof = ("Not known", "unknown",
                 "The DMARC record could not be read during this scan.")
    elif "dmarc.missing" in ids:
        spoof = ("Yes", "bad",
                 "No DMARC policy exists, so no receiving server is told to reject forged mail.")
    elif "dmarc.invalid_policy" in ids:
        spoof = ("Yes", "bad",
                 "The DMARC record has no valid policy, so receivers discard it.")
    elif "dmarc.policy_none" in ids:
        spoof = ("Yes", "bad",
                 "DMARC is set to p=none. Forgery is reported to you and delivered anyway.")
    elif "dmarc.policy_quarantine" in ids:
        spoof = ("Partly", "warn",
                 "DMARC is set to p=quarantine, so forged mail reaches the spam folder "
                 "rather than being rejected.")
    elif "dmarc.partial_enforcement" in ids:
        spoof = ("Partly", "warn",
                 "The policy applies to only a percentage of mail, so the rest is delivered.")
    elif "dmarc.subdomain_policy_weak" in ids:
        spoof = ("Subdomains only", "warn",
                 "The apex is protected but sp=none leaves every subdomain open.")
    else:
        spoof = ("No", "good",
                 "DMARC is published at enforcement, so forged mail is rejected before delivery.")

    # 2. Is mail to this domain encrypted on the way in?
    if inconclusive("transport"):
        transit = ("Not known", "unknown",
                   "The mail servers could not be reached on port 25 from this scanner.")
    elif "transport.no_mx" in ids:
        transit = ("Not applicable", "unknown",
                   "This domain publishes no MX records, so it receives no mail.")
    elif any(k.startswith("transport.no_starttls") for k in ids):
        transit = ("No", "bad",
                   "At least one mail server does not offer STARTTLS, so mail arrives in cleartext.")
    elif any(k.startswith("transport.no_modern_tls") for k in ids):
        transit = ("Unreliably", "bad",
                   "A mail server accepts neither TLS 1.2 nor 1.3, so modern senders cannot "
                   "negotiate encryption.")
    elif any(k.startswith(("transport.legacy_tls", "transport.weak_cipher")) for k in ids):
        transit = ("Weakly", "warn",
                   "Encryption is offered, but deprecated versions or weak ciphers are accepted.")
    elif any(k.startswith(("transport.cert_expired", "transport.cert_invalid",
                           "transport.cert_self_signed")) for k in ids):
        transit = ("Not verifiably", "warn",
                   "TLS is offered, but the certificate does not validate, so the server "
                   "cannot be authenticated.")
    elif "mta_sts.missing" in ids:
        transit = ("Usually", "warn",
                   "TLS is available, but without MTA-STS an on-path attacker can strip it "
                   "and force cleartext delivery.")
    else:
        transit = ("Yes", "good",
                   "The mail servers offer STARTTLS with modern TLS and a valid certificate.")

    return [
        {"question": "Can someone send mail pretending to be this domain?",
         "answer": spoof[0], "tone": spoof[1], "because": spoof[2]},
        {"question": "Is mail sent to this domain encrypted in transit?",
         "answer": transit[0], "tone": transit[1], "because": transit[2]},
    ]
