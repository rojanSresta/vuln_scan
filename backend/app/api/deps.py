"""FastAPI dependencies"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthCredentials

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthCredentials = Depends(security)):
    """Get current authenticated user"""
    # TODO: Implement JWT validation
    return {"id": 1, "username": "test_user"}
