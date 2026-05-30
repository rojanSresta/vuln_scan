"""Crawls pages on the same host as the target URL."""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import requests

from app.scanner.html_parser import HtmlParser
from app.scanner.http_client import HttpClient
from app.scanner.scan_types import CrawlContext, PageRecord, ProgressCallback

logger = logging.getLogger(__name__)


class WebCrawler:
    def __init__(self, client: HttpClient, max_pages: int = 12):
        self.client = client
        self.max_pages = max_pages

    def crawl(self, target_url: str, progress_callback: Optional[ProgressCallback] = None) -> CrawlContext:
        parsed_target = urlparse(target_url)
        visited = set()
        queue = [target_url]
        pages: list[PageRecord] = []

        while queue and len(pages) < self.max_pages:
            current = queue.pop(0)
            normalized = self._normalize_url(current)
            if normalized in visited:
                continue

            visited.add(normalized)
            if progress_callback:
                progress_callback(min(35, 5 + len(pages) * 3), f"Crawling {normalized}...")

            try:
                response = self.client.get(current)
            except requests.RequestException as exc:
                logger.debug("Skipping %s during crawl: %s", current, exc)
                continue

            content_type = response.headers.get("Content-Type", "")
            text = response.text if "text/html" in content_type or not content_type else response.text[:0]
            parser = HtmlParser(response.url)
            if text:
                try:
                    parser.feed(text)
                except Exception:
                    logger.debug("HTML parse failed for %s", response.url)

            page = PageRecord(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                text=text,
                content_type=content_type,
                forms=parser.forms,
                links=parser.links,
            )
            pages.append(page)

            for link in parser.links:
                if self._should_visit(link, parsed_target) and self._normalize_url(link) not in visited:
                    queue.append(link)

        return CrawlContext(target_url=target_url, pages=pages)

    def _should_visit(self, url: str, target: Any) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.netloc != target.netloc:
            return False
        if parsed.fragment:
            return False
        return True

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
