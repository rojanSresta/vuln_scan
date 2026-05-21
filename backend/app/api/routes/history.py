"""Scan history endpoints"""

from fastapi import APIRouter

router = APIRouter(prefix="/history", tags=["history"])


@router.get("")
async def get_history():
    """Get scan history"""
    return {"scans": []}


@router.get("/{scan_id}")
async def get_history_item(scan_id: str):
    """Get specific scan result"""
    return {"scan_id": scan_id, "results": []}
