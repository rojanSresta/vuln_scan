"""Small helpers shared by vulnerability check classes."""

from __future__ import annotations

import re
from typing import Dict, Optional

from app.scanner.scan_types import FormField, FormRecord, SQL_ERROR_PATTERNS


def sql_error_detected(response) -> bool:
    body = response.text.lower()
    return response.status_code >= 500 or any(re.search(pattern, body) for pattern in SQL_ERROR_PATTERNS)


def form_submission(form: FormRecord, target_field: str, payload: str, default: str) -> Dict[str, str]:
    submission = {field.name: field.value or default for field in form.fields}
    submission[target_field] = payload
    return submission


def first_input_field(form: FormRecord) -> Optional[FormField]:
    for field in form.fields:
        if field.field_type in {"text", "search", "textarea", "select", "email", "number"}:
            return field
    return None


def first_reflectable_field(form: FormRecord) -> Optional[FormField]:
    for field in form.fields:
        if field.field_type not in {"hidden", "password", "submit"}:
            return field
    return None
