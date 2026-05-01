"""
OWASP ZAP Vulnerability Scanner - FastAPI Backend
Connects to a locally running ZAP daemon and orchestrates security scans.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl, validator
from typing import List, Optional
import uuid
import os
import time
import logging

from zap_scanner import ZAPScanner
from report_generator import generate_pdf_report

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnScan API",
    description="OWASP ZAP-powered vulnerability scanner backend",
    version="1.0.0",
)

# Allow the React dev server to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for scan jobs  { scan_id -> job_dict }
scan_jobs: dict = {}

# ─── Request / Response Models ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str
    vulnerabilities: List[str]  # e.g. ["sql_injection", "xss", "csrf", ...]

    @validator("target_url")
    def validate_url(cls, v):
        """Ensure URL starts with http:// or https://"""
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @validator("vulnerabilities")
    def validate_vulns(cls, v):
        allowed = {"sql_injection", "xss", "csrf", "broken_auth", "dir_traversal", "scan_all"}
        for item in v:
            if item not in allowed:
                raise ValueError(f"Unknown vulnerability type: {item}")
        return v


class ScanStatus(BaseModel):
    scan_id: str
    status: str          # queued | spidering | scanning | done | error
    progress: int        # 0-100
    message: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Quick health-check used by the frontend."""
    return {"status": "ok"}


@app.post("/scan/start")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Accept a scan request, create a job record, then run the scan
    asynchronously so the HTTP response returns immediately.
    """
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "message": "Scan queued…",
        "target_url": req.target_url,
        "vulnerabilities": req.vulnerabilities,
        "results": [],
        "report_path": None,
    }

    # Run the actual scan in the background
    background_tasks.add_task(run_scan, scan_id, req.target_url, req.vulnerabilities)

    return {"scan_id": scan_id, "message": "Scan started"}


@app.get("/scan/status/{scan_id}", response_model=ScanStatus)
def get_status(scan_id: str):
    """Poll this endpoint to track scan progress."""
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(
        scan_id=scan_id,
        status=job["status"],
        progress=job["progress"],
        message=job["message"],
    )


@app.get("/scan/results/{scan_id}")
def get_results(scan_id: str):
    """Return final vulnerability findings once status == 'done'."""
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job["status"] not in ("done", "error"):
        raise HTTPException(status_code=400, detail="Scan not finished yet")
    return {
        "scan_id": scan_id,
        "target_url": job["target_url"],
        "status": job["status"],
        "results": job["results"],
    }


@app.get("/scan/report/{scan_id}")
def download_report(scan_id: str):
    """Stream the PDF report for download."""
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="Scan not finished yet")

    # Generate (or re-use) the PDF
    if not job["report_path"] or not os.path.exists(job["report_path"]):
        path = generate_pdf_report(
            scan_id=scan_id,
            target_url=job["target_url"],
            results=job["results"],
        )
        job["report_path"] = path

    return FileResponse(
        job["report_path"],
        media_type="application/pdf",
        filename=f"vuln_report_{scan_id[:8]}.pdf",
    )


# ─── Background scan logic ────────────────────────────────────────────────────

def run_scan(scan_id: str, target_url: str, vulnerabilities: List[str]):
    """
    Orchestrates the full ZAP scan pipeline:
      1. Spider the target
      2. Configure & run active scan (only selected rules)
      3. Wait for passive scan queue to drain
      4. Fetch & filter alerts
    """
    job = scan_jobs[scan_id]

    try:
        scanner = ZAPScanner()

        # ── 1. Spider ──────────────────────────────────────────────────────
        job["status"] = "spidering"
        job["message"] = "Spidering target website…"
        job["progress"] = 5
        logger.info(f"[{scan_id}] Spider start → {target_url}")

        spider_id = scanner.start_spider(target_url)
        _wait_for_spider(scanner, spider_id, scan_id, job)

        # ── 2. Active scan ─────────────────────────────────────────────────
        job["status"] = "scanning"
        job["message"] = "Configuring scan rules…"
        job["progress"] = 40
        logger.info(f"[{scan_id}] Active scan start")

        # Resolve the "scan_all" shortcut
        effective_vulns = vulnerabilities
        if "scan_all" in vulnerabilities:
            effective_vulns = ["sql_injection", "xss", "csrf", "broken_auth", "dir_traversal"]

        ascan_id = scanner.start_active_scan(target_url, effective_vulns)

        job["message"] = "Running active vulnerability scan…"
        _wait_for_active_scan(scanner, ascan_id, scan_id, job)

        # ── 3. Passive scan drain ──────────────────────────────────────────
        # ZAP runs passive rules on all collected traffic after the active scan.
        # Wait for that queue to drain so we capture all findings.
        job["message"] = "Waiting for passive scan to finish…"
        job["progress"] = 94
        scanner.wait_for_passive_scan(timeout=120)

        # ── 4. Alerts ──────────────────────────────────────────────────────
        job["message"] = "Collecting results…"
        job["progress"] = 97
        raw_alerts = scanner.get_alerts(target_url)
        results = scanner.filter_and_enrich_alerts(raw_alerts, effective_vulns)

        job["results"] = results
        job["status"] = "done"
        job["progress"] = 100
        job["message"] = f"Scan complete — {len(results)} finding(s)"
        logger.info(f"[{scan_id}] Done: {len(results)} alerts")

    except Exception as exc:
        logger.exception(f"[{scan_id}] Scan error: {exc}")
        job["status"] = "error"
        job["message"] = f"Scan failed: {str(exc)}"
        job["progress"] = 0


def _wait_for_spider(scanner, spider_id, scan_id, job, timeout=90):
    """
    Poll spider until done or 90 s timeout.
    Spider is shallow (maxChildren=5) so 90 s is plenty.
    Stall detection: if progress freezes for 30 s, move on.
    """
    deadline      = time.time() + timeout
    last_pct      = -1
    stall_by      = time.time() + 30

    while time.time() < deadline:
        pct = scanner.spider_progress(spider_id)
        job["progress"] = 5 + int(pct * 0.30)
        job["message"]  = f"Spidering… {pct}% complete"

        if pct >= 100:
            return

        if pct != last_pct:
            last_pct = pct
            stall_by = time.time() + 30   # reset stall timer on any movement

        if time.time() > stall_by:
            logger.warning(f"Spider stalled at {pct}% — moving to active scan.")
            return

        time.sleep(3)

    logger.warning("Spider timed out — moving on.")


def _wait_for_active_scan(scanner, ascan_id, scan_id, job, timeout=600):
    """
    Poll active scan until done or 10 min timeout.
    Because we only enable a handful of rules (not all 200+), 10 min is
    more than enough for most sites.
    Stall detection: if progress freezes for 2 min, collect whatever is there.
    """
    deadline  = time.time() + timeout
    last_pct  = -1
    stall_by  = time.time() + 120

    while time.time() < deadline:
        pct = scanner.active_scan_progress(ascan_id)
        job["progress"] = 36 + int(pct * 0.55)
        job["message"]  = f"Active scan… {pct}% complete"

        if pct != last_pct:
            last_pct = pct
            stall_by = time.time() + 120   # reset on movement

        if pct >= 100:
            logger.info(f"[{scan_id}] Active scan finished.")
            return

        if time.time() > stall_by:
            logger.warning(f"Active scan stalled at {pct}% — collecting alerts now.")
            return

        time.sleep(4)

    logger.warning("Active scan timed out — collecting alerts anyway.")