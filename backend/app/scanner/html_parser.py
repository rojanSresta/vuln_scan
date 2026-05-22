"""Parses HTML links and forms from a page."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from app.scanner.scan_types import FormField, FormRecord


class HtmlParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.forms: List[FormRecord] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(urljoin(self.base_url, href))
        elif tag == "form":
            action = urljoin(self.base_url, attr_map.get("action", "") or self.base_url)
            method = (attr_map.get("method", "get") or "get").lower()
            self._current_form = {
                "page_url": self.base_url,
                "action_url": action,
                "method": method,
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(
                    FormField(
                        name=name,
                        field_type=(attr_map.get("type", "text") or "text").lower(),
                        value=attr_map.get("value", ""),
                    )
                )
        elif tag == "textarea" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(FormField(name=name, field_type="textarea"))
        elif tag == "select" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(FormField(name=name, field_type="select"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(FormRecord(**self._current_form))
            self._current_form = None
