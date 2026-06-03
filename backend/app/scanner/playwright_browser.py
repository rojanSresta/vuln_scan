"""Shared Chromium launch settings for XSS checks and startup verification."""

from __future__ import annotations

import logging
import os

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

CHROMIUM_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]


def verify_chromium_launch() -> None:
    """Raise with a actionable message if Chromium cannot start."""
    browsers_path = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                chromium_sandbox=False,
                args=CHROMIUM_LAUNCH_ARGS,
            )
            browser.close()
    except PlaywrightError as exc:
        hint = (
            "Deploy the backend with Docker (backend/Dockerfile on Render), not "
            "Render's native Python runtime. The image "
            "mcr.microsoft.com/playwright/python:v1.50.0-noble includes Chromium; "
            "pip-only installs cannot run browser-based XSS checks."
        )
        path_note = f" PLAYWRIGHT_BROWSERS_PATH={browsers_path!r}." if browsers_path else ""
        raise RuntimeError(f"Chromium launch failed: {exc}.{path_note} {hint}") from exc


def launch_chromium(playwright):
    return playwright.chromium.launch(
        headless=True,
        chromium_sandbox=False,
        args=CHROMIUM_LAUNCH_ARGS,
    )
