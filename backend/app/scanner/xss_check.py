"""Reflected XSS vulnerability check confirmed by browser execution."""

from __future__ import annotations

import json
import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.check_helpers import first_reflectable_field
from app.scanner.payload_loader import PayloadLoader
from app.scanner.scan_types import CrawlContext, PageRecord, VulnerabilityFinding
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

DIALOG_WAIT_MS = 1200
PAGE_TIMEOUT_MS = 8000

# Required when Chromium runs inside Docker/Render (often as root, small /dev/shm).
CHROMIUM_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]


class XssCheck(VulnerabilityCheck):
    category = "xss"

    def __init__(self, client):
        super().__init__(client)
        self.payloads = PayloadLoader.load(self.category)

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=CHROMIUM_LAUNCH_ARGS,
                )
                try:
                    page = browser.new_page()
                    finding_url = self._scan_query_alerts(page, context.pages) or self._scan_form_alerts(page, context.pages)
                finally:
                    browser.close()
        except PlaywrightError as exc:
            # Vercel serverless functions (and most PaaS runtimes) cannot launch
            # Chromium — they have no system libraries and no Playwright browser
            # binaries. If we silently returned [] here, XSS would appear to "run"
            # in production but find nothing, which is misleading. Surface the
            # reason via the scan progress message instead.
            message = (
                "XSS browser confirmation skipped: Playwright/Chromium is not available "
                "in this environment. The XSS check requires a runtime with Playwright "
                "and its system dependencies installed (run via the provided Docker setup, "
                "or any host that has run `playwright install --with-deps chromium`)."
            )
            logger.warning("Skipping XSS browser confirmation because Playwright failed: %s", exc)
            raise RuntimeError(message) from exc

        if finding_url:
            return [self._make_finding(finding_url)]
        return []

    def _scan_query_alerts(self, browser_page: Page, pages: list[PageRecord]) -> str | None:
        for crawled_page in pages:
            for param in crawled_page.query_params:
                for payload in self.payloads:
                    self.client._check_cancelled()
                    test_url = self._url_with_payload(crawled_page.url, param, payload)
                    if self._alert_appears_on_url(browser_page, test_url):
                        return test_url
        return None

    def _scan_form_alerts(self, browser_page: Page, pages: list[PageRecord]) -> str | None:
        for crawled_page in pages:
            for form in crawled_page.forms:
                field = first_reflectable_field(form)
                if not field:
                    continue
                for payload in self.payloads:
                    self.client._check_cancelled()
                    submission = {item.name: item.value or "test" for item in form.fields}
                    submission[field.name] = payload

                    if form.method == "get":
                        test_url = self._url_with_params(form.action_url, submission)
                        if self._alert_appears_on_url(browser_page, test_url):
                            return test_url
                    elif self._alert_appears_after_form_submit(browser_page, form.page_url, field.name, submission):
                        return form.action_url
        return None

    def _alert_appears_on_url(self, page: Page, url: str) -> bool:
        if not self._is_in_scope(url):
            return False

        try:
            return self._with_dialog_listener(page, lambda: page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS))
        except (PlaywrightError, PlaywrightTimeoutError) as exc:
            logger.debug("Skipping XSS URL test for %s: %s", url, exc)
            return False

    def _alert_appears_after_form_submit(
        self,
        page: Page,
        page_url: str,
        field_name: str,
        submission: dict[str, str],
    ) -> bool:
        if not self._is_in_scope(page_url):
            return False

        try:
            page.goto(page_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            selector = f"[name={json.dumps(field_name)}]"
            form_selector = f"form:has({selector})"
            form = page.locator(form_selector).first
            form.evaluate(
                """
                (form, values) => {
                    for (const element of Array.from(form.elements)) {
                        if (element.name && Object.prototype.hasOwnProperty.call(values, element.name)) {
                            element.value = values[element.name];
                        }
                    }
                }
                """,
                submission,
            )
            return self._with_dialog_listener(
                page,
                lambda: form.evaluate(
                    "(form) => form.requestSubmit ? form.requestSubmit() : form.submit()"
                ),
            )
        except (PlaywrightError, PlaywrightTimeoutError) as exc:
            logger.debug("Skipping XSS form test for %s field %s: %s", page_url, field_name, exc)
            return False

    def _with_dialog_listener(self, page: Page, action) -> bool:
        alert_seen = False

        def handle_dialog(dialog):
            nonlocal alert_seen
            if dialog.type == "alert":
                alert_seen = True
            dialog.accept()

        page.on("dialog", handle_dialog)
        try:
            action()
            page.wait_for_timeout(DIALOG_WAIT_MS)
        finally:
            page.remove_listener("dialog", handle_dialog)
        return alert_seen

    @staticmethod
    def _url_with_payload(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    @staticmethod
    def _url_with_params(url: str, params: dict[str, str]) -> str:
        parsed = urlparse(url)
        existing = parse_qs(parsed.query, keep_blank_values=True)
        for key, value in params.items():
            existing[key] = [value]
        query = urlencode(existing, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    def _make_finding(self, url: str) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            name="Cross Site Scripting (Reflected)",
            risk="High",
            url=url,
            description="A reflected XSS payload executed in a browser and triggered an alert dialog.",
            solution="Encode untrusted output before rendering it in HTML and enforce a strict Content Security Policy.",
            explanation="The scanner confirmed script execution by loading the payload in Playwright and observing an alert() dialog.",
            reference=self.build_reference("reflected XSS"),
            cwe_id="79",
            wasc_id="8",
        )
