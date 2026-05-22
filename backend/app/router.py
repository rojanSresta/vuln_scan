"""Registers all API controllers."""

from fastapi import APIRouter

from app.controllers.admin_controller import router as admin_router
from app.controllers.auth_controller import router as auth_router
from app.controllers.history_controller import router as history_router
from app.controllers.scan_controller import router as scan_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(admin_router)
api_router.include_router(scan_router)
api_router.include_router(history_router)
