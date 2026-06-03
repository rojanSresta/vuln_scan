"""FastAPI application entry point."""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, CORS_ORIGINS
from app.database import init_db
from app.router import api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_TITLE,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
    )

    # Loud warning if the backend was started without a configured CORS allowlist
    # in a deployed environment. Without CORS_ORIGINS, the default falls back to
    # localhost-only origins, and any production frontend (Vercel, Netlify, etc.)
    # will have its requests silently blocked by the browser — which looks
    # exactly like "XSS scan started but no results came back."
    if not os.getenv("CORS_ORIGINS") and os.getenv("APP_ENV") in {"production", "prod"}:
        logger.warning(
            "APP_ENV=%s but CORS_ORIGINS is not set. The default CORS allowlist "
            "is localhost-only; browser requests from your production frontend "
            "will be blocked. Set CORS_ORIGINS to your frontend origin(s), "
            "comma-separated.",
            os.getenv("APP_ENV"),
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def on_startup() -> None:
        browsers_path = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "(playwright default)")
        logger.info("Playwright browser path: %s", browsers_path)
        init_db()
        try:
            from app.scanner.playwright_browser import verify_chromium_launch

            verify_chromium_launch()
            logger.info("Chromium startup check passed")
        except Exception as exc:
            logger.error(
                "Chromium startup check FAILED — XSS scans will not work until this is "
                "fixed. Use Render Docker runtime with backend/Dockerfile. Detail: %s",
                exc,
            )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(api_router)
    return app


app = create_app()
