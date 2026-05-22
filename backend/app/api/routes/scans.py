"""Scan endpoints"""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
async def create_scan(target_url: str, vulnerabilities: list[str]):
    """Start a new vulnerability scan"""
    return {"scan_id": "test-scan-123", "status": "starting"}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan status"""
    return {"scan_id": scan_id, "status": "running", "progress": 50}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a scan"""
    return {"scan_id": scan_id, "status": "cancelled"}
