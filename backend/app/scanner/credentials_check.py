"""Default credentials vulnerability check."""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

import requests

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.payload_loader import PayloadLoader
from app.scanner.scan_types import CrawlContext, FormField, FormRecord, VulnerabilityFinding

LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "session", "account")
USERNAME_FIELD_KEYWORDS = ("user", "email", "login", "name", "account")
FAILURE_HINTS = (
    "invalid",
    "incorrect",
    "failed",
    "wrong password",
    "denied",
    "try again",
    "bad credentials",
    "login failed",
    "authentication failed",
)
SUCCESS_HINTS = ("logout", "sign out", "dashboard", "welcome", "my account", "profile")


class DefaultCredentialsCheck(VulnerabilityCheck):
    category = "default_credentials"

    def __init__(self, client):
        super().__init__(client)
        self.usernames = PayloadLoader.load_usernames()
        self.passwords = PayloadLoader.load_passwords()

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        for page in context.pages:
            for form in page.forms:
                fields = self._resolve_login_fields(form)
                if not fields:
                    continue
                username_field, password_field = fields
                baseline = self._baseline_attempt(form, username_field.name, password_field.name)

                for username in self.usernames:
                    for password in self.passwords:
                        submission = {field.name: field.value or "" for field in form.fields}
                        submission[username_field.name] = username
                        submission[password_field.name] = password
                        try:
                            response = self.submit_form(form, submission)
                        except requests.RequestException:
                            continue
                        if self._login_succeeded(response, baseline):
                            return [
                                VulnerabilityFinding(
                                    name="Default Credentials Accepted",
                                    risk="High",
                                    url=form.action_url,
                                    description=(
                                        f"The login form accepted a weak credential pair: "
                                        f"username '{username}' with password '{password}'."
                                    ),
                                    solution="Disable default accounts, enforce strong unique passwords, and implement account lockout.",
                                    explanation="Weak or factory-default credentials allow unauthorised access without exploiting other flaws.",
                                    reference=self.build_reference("default credentials"),
                                    cwe_id="521",
                                    wasc_id="2",
                                )
                            ]
        return []

    def _resolve_login_fields(self, form: FormRecord) -> Optional[tuple[FormField, FormField]]:
        if not self._is_auth_form(form):
            return None

        password_fields = [field for field in form.fields if field.field_type == "password"]
        if not password_fields:
            return None

        password_field = password_fields[0]
        username_field = None
        for field in form.fields:
            if field is password_field:
                continue
            if field.field_type in {"hidden", "submit", "button", "password"}:
                continue
            if any(keyword in field.name.lower() for keyword in USERNAME_FIELD_KEYWORDS):
                username_field = field
                break

        if username_field is None:
            text_fields = [f for f in form.fields if f.field_type in {"text", "email", "search", "tel"}]
            if text_fields:
                username_field = text_fields[0]

        if username_field is None:
            return None
        return username_field, password_field

    def _is_auth_form(self, form: FormRecord) -> bool:
        has_password = any(field.field_type == "password" for field in form.fields)
        if not has_password:
            return False
        combined = f"{form.page_url} {form.action_url}".lower()
        return any(keyword in combined for keyword in LOGIN_KEYWORDS)

    def _baseline_attempt(self, form: FormRecord, username_field: str, password_field: str) -> requests.Response | None:
        fake_user = f"nonexistent-{uuid4().hex[:10]}"
        fake_pass = f"invalid-{uuid4().hex[:10]}"
        submission = {field.name: field.value or "" for field in form.fields}
        submission[username_field] = fake_user
        submission[password_field] = fake_pass
        try:
            return self.submit_form(form, submission)
        except requests.RequestException:
            return None

    def _response_signature(self, response: requests.Response) -> tuple[int, str, str]:
        location = (response.headers.get("Location", "") or "").lower()
        set_cookie = (response.headers.get("Set-Cookie", "") or "").lower()
        return (response.status_code, location, set_cookie[:200])

    def _login_succeeded(
        self,
        response: requests.Response,
        baseline: requests.Response | None,
    ) -> bool:
        body = response.text.lower()
        if any(hint in body for hint in FAILURE_HINTS):
            return False

        location = response.headers.get("Location", "").lower()
        response_sig = self._response_signature(response)
        baseline_sig = self._response_signature(baseline) if baseline else None

        has_success_hint = any(hint in body for hint in SUCCESS_HINTS) or any(hint in location for hint in SUCCESS_HINTS)
        redirects_away_from_login = (
            response.status_code in {301, 302, 303, 307, 308}
            and bool(location)
            and not any(keyword in location for keyword in LOGIN_KEYWORDS)
        )

        # Stronger rule to avoid false positives on public sites:
        # require explicit success indicators and behavior that differs from clearly-invalid creds.
        if not (has_success_hint or redirects_away_from_login):
            return False
        if baseline_sig is not None and response_sig == baseline_sig:
            return False
        return True
