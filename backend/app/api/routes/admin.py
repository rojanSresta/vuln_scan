"""Admin endpoints"""

from fastapi import APIRouter

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats")
async def get_stats():
    """Get admin statistics"""
    return {"total_scans": 0, "total_vulnerabilities": 0}


@router.post("/login")
async def admin_login(username: str, password: str):
    """Admin login"""
    return {"token": "admin-token-123"}
