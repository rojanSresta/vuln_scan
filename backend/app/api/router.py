"""Main API router"""

from fastapi import APIRouter
from app.api.routes import scans, history, admin

api_router = APIRouter()

api_router.include_router(scans.router)
api_router.include_router(history.router)
api_router.include_router(admin.router)
