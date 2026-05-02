"""
Manual vulnerability scanner backend built with FastAPI.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, validator
from typing import List
import uuid
import os
import logging

from manual_scanner import ManualVulnerabilityScanner
from report_generator import generate_pdf_report

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnScan API",
    description="Manual web vulnerability scanner backend",
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
    Runs the manual scan pipeline:
      1. Crawl the target with BFS
      2. Execute the selected heuristic vulnerability checks
      3. Store normalized findings
    """
    job = scan_jobs[scan_id]

    try:
        scanner = ManualVulnerabilityScanner()
        job["status"] = "spidering"
        job["message"] = "Preparing scan…"
        job["progress"] = 2
        logger.info(f"[{scan_id}] Manual scan start → {target_url}")

        def on_progress(progress: int, message: str):
            job["progress"] = progress
            job["message"] = message
            job["status"] = "spidering" if progress < 35 else "scanning"

        results = scanner.scan(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            progress_callback=on_progress,
        )

        job["results"] = results
        job["status"] = "done"
        job["progress"] = 100
        job["message"] = f"Scan complete — {len(results)} finding(s)"
        logger.info(f"[{scan_id}] Done: {len(results)} findings")

    except Exception as exc:
        logger.exception(f"[{scan_id}] Scan error: {exc}")
        job["status"] = "error"
        job["message"] = f"Scan failed: {str(exc)}"
        job["progress"] = 0
