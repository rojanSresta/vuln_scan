"""Shared utilities for vulnerability checks - avoid duplication"""

from typing import Optional, Dict
from urllib.parse import parse_qs, urlparse, urlunparse
import requests


def probe_query_param(
    client,
    url: str,
    param: str,
    payload: str,
) -> Optional[requests.Response]:
    """Probe a URL query parameter with a payload"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    flat_params = {key: values[0] if values else "" for key, values in params.items()}
    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
    
    try:
        return client.get(clean_url, params=flat_params)
    except requests.RequestException:
        return None


def submit_form(
    client,
    form,
    data: Dict[str, str],
) -> requests.Response:
    """Submit a form with data"""
    if form.method == "post":
        return client.post(form.action_url, data)
    return client.get(form.action_url, params=data)


def has_token_name(field_name: str, keywords: tuple) -> bool:
    """Check if field name matches CSRF token keywords"""
    lowered = field_name.lower()
    return any(keyword in lowered for keyword in keywords)


def is_state_changing_form(form, keywords: tuple) -> bool:
    """Check if form looks like it changes state (login, delete, etc)"""
    action_bits = f"{form.page_url} {form.action_url}".lower()
    return any(keyword in action_bits for keyword in keywords) or any(
        field.field_type == "password" for field in form.fields
    )
