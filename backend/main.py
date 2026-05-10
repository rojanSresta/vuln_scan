"""
Manual vulnerability scanner backend built with FastAPI.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, List

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from database import ScanRecord, Session as UserSession, SessionLocal, User, init_db
from scanner import ManualVulnerabilityScanner
from report_generator import generate_pdf_report
from security import generate_session_token, hash_password, verify_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VulnScan API",
    description="Manual web vulnerability scanner backend",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_jobs: dict[str, dict[str, Any]] = {}
ALLOWED_VULNERABILITIES = {
    "sql_injection",
    "xss",
    "csrf",
    "broken_auth",
    "dir_traversal",
    "scan_all",
}


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def serialize_scan(record: ScanRecord) -> dict[str, Any]:
    return {
        "scan_id": record.scan_id,
        "target_url": record.target_url,
        "status": record.status,
        "progress": record.progress,
        "message": record.message,
        "vulnerabilities": record.vulnerabilities or [],
        "results": record.results or [],
        "report_available": record.status == "done",
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def parse_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return token


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = parse_bearer_token(authorization)
    session = db.execute(select(UserSession).where(UserSession.token == token)).scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session.user


class ScanRequest(BaseModel):
    target_url: str
    vulnerabilities: List[str]

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return value

    @field_validator("vulnerabilities")
    @classmethod
    def validate_vulns(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("Select at least one vulnerability type")
        for item in value:
            if item not in ALLOWED_VULNERABILITIES:
                raise ValueError(f"Unknown vulnerability type: {item}")
        return value


class AuthRequest(BaseModel):
    full_name: str | None = None
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = re.sub(r"\s+", " ", value).strip()
        if not cleaned:
            raise ValueError("Full name is required")
        return cleaned


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str


class AuthResponse(BaseModel):
    token: str
    user: UserResponse


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: AuthRequest, db: Session = Depends(get_db)) -> AuthResponse:
    if not payload.full_name:
        raise HTTPException(status_code=422, detail="Full name is required")

    existing = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.flush()

    token = generate_session_token()
    db.add(UserSession(token=token, user_id=user.id))
    db.commit()
    db.refresh(user)
    return AuthResponse(token=token, user=user)


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: AuthRequest, db: Session = Depends(get_db)) -> AuthResponse:
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = generate_session_token()
    db.add(UserSession(token=token, user_id=user.id))
    db.commit()
    return AuthResponse(token=token, user=user)


@app.get("/auth/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return current_user


@app.post("/auth/logout")
def logout(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    token = parse_bearer_token(authorization)
    session = db.execute(select(UserSession).where(UserSession.token == token)).scalar_one_or_none()
    if session:
        db.delete(session)
        db.commit()
    return {"message": "Logged out"}


@app.post("/scan/start")
def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    scan_id = str(uuid.uuid4())
    vulnerabilities = req.vulnerabilities
    if "scan_all" in vulnerabilities:
        vulnerabilities = ["scan_all"]

    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "message": "Scan queued...",
        "target_url": req.target_url,
        "vulnerabilities": vulnerabilities,
        "results": [],
        "report_path": None,
    }

    with session_scope() as db:
        db.add(
            ScanRecord(
                scan_id=scan_id,
                user_id=current_user.id,
                target_url=req.target_url,
                vulnerabilities=vulnerabilities,
                status="queued",
                progress=0,
                message="Scan queued...",
                results=[],
                report_path=None,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )

    background_tasks.add_task(run_scan, scan_id, current_user.id, req.target_url, vulnerabilities)
    return {"scan_id": scan_id, "message": "Scan started"}


@app.get("/scan/status/{scan_id}", response_model=ScanStatus)
def get_status(scan_id: str, current_user: User = Depends(get_current_user)) -> ScanStatus:
    job = scan_jobs.get(scan_id)
    if job:
        record = load_scan(scan_id, current_user.id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ScanStatus(
            scan_id=scan_id,
            status=job["status"],
            progress=job["progress"],
            message=job["message"],
        )

    record = require_scan(scan_id, current_user.id)
    return ScanStatus(
        scan_id=record.scan_id,
        status=record.status,
        progress=record.progress,
        message=record.message,
    )


@app.get("/scan/results/{scan_id}")
def get_results(scan_id: str, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    record = require_scan(scan_id, current_user.id)
    if record.status not in {"done", "error"}:
        raise HTTPException(status_code=400, detail="Scan not finished yet")
    return {
        "scan_id": record.scan_id,
        "target_url": record.target_url,
        "status": record.status,
        "results": record.results or [],
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


@app.get("/scan/report/{scan_id}")
def download_report(scan_id: str, current_user: User = Depends(get_current_user)) -> FileResponse:
    record = require_scan(scan_id, current_user.id)
    if record.status != "done":
        raise HTTPException(status_code=400, detail="Scan not finished yet")

    report_path = record.report_path
    if not report_path or not os.path.exists(report_path):
        report_path = generate_pdf_report(
            scan_id=scan_id,
            target_url=record.target_url,
            results=record.results or [],
        )
        with session_scope() as db:
            persisted = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one()
            persisted.report_path = report_path
            persisted.updated_at = utc_now()

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"vuln_report_{scan_id[:8]}.pdf",
    )


@app.get("/history")
def get_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    records = db.execute(
        select(ScanRecord)
        .where(ScanRecord.user_id == current_user.id)
        .order_by(desc(ScanRecord.created_at))
    ).scalars()
    return {"items": [serialize_scan(record) for record in records]}


@app.get("/history/{scan_id}")
def get_history_item(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    record = db.execute(
        select(ScanRecord).where(
            ScanRecord.scan_id == scan_id,
            ScanRecord.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialize_scan(record)


def load_scan(scan_id: str, user_id: int) -> ScanRecord | None:
    with session_scope() as db:
        return db.execute(
            select(ScanRecord).where(
                ScanRecord.scan_id == scan_id,
                ScanRecord.user_id == user_id,
            )
        ).scalar_one_or_none()


def require_scan(scan_id: str, user_id: int) -> ScanRecord:
    record = load_scan(scan_id, user_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


def update_scan_record(scan_id: str, **fields: Any) -> None:
    with session_scope() as db:
        record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
        if not record:
            return
        for key, value in fields.items():
            setattr(record, key, value)
        record.updated_at = utc_now()


def run_scan(scan_id: str, user_id: int, target_url: str, vulnerabilities: List[str]) -> None:
    job = scan_jobs[scan_id]

    try:
        scanner = ManualVulnerabilityScanner()
        job["status"] = "spidering"
        job["message"] = "Preparing scan..."
        job["progress"] = 2
        update_scan_record(scan_id, status="spidering", progress=2, message="Preparing scan...")
        logger.info("[%s] Manual scan start -> %s", scan_id, target_url)

        def on_progress(progress: int, message: str) -> None:
            status = "spidering" if progress < 35 else "scanning"
            job["progress"] = progress
            job["message"] = message
            job["status"] = status
            update_scan_record(scan_id, status=status, progress=progress, message=message)

        results = scanner.scan(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            progress_callback=on_progress,
        )

        job["results"] = results
        job["status"] = "done"
        job["progress"] = 100
        job["message"] = f"Scan complete - {len(results)} finding(s)"
        update_scan_record(
            scan_id,
            status="done",
            progress=100,
            message=job["message"],
            results=results,
        )
        logger.info("[%s] Done: %s findings", scan_id, len(results))

    except Exception as exc:
        logger.exception("[%s] Scan error: %s", scan_id, exc)
        job["status"] = "error"
        job["message"] = f"Scan failed: {exc}"
        job["progress"] = 0
        update_scan_record(
            scan_id,
            status="error",
            progress=0,
            message=job["message"],
            results=[],
        )
    finally:
        # The database is the source of truth after each update.
        scan_jobs.pop(scan_id, None)
