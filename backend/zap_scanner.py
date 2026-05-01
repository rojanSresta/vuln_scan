"""
zap_scanner.py  —  All ZAP API interactions.

Performance tuning
──────────────────
Scan speed is controlled by three things:
  1. Spider depth / thread count   → kept low
  2. Number of active scan rules   → only selected rules are enabled
  3. Active scan thread count      → bumped up so rules run in parallel

CSRF category fix
─────────────────
Each vulnerability maps to its OWN set of plugin IDs with NO overlap.
The filter_and_enrich_alerts() method uses ONLY the IDs for the selected
category, so a CSRF alert will never appear under Broken Auth or vice-versa.
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Set

import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(BACKEND_DIR.parent / ".env")

# ─── ZAP connection settings ──────────────────────────────────────────────────
ZAP_BASE_URL = "http://127.0.0.1:8080"
ZAP_API_KEY = os.getenv("ZAP_API_KEY")

if not ZAP_API_KEY:
    raise RuntimeError(
        "Missing ZAP_API_KEY. Set it in backend/.env or project-root .env before starting the backend."
    )

# ─── Vulnerability → ZAP active-scan plugin IDs ───────────────────────────────
# IMPORTANT: No ID appears in more than one category.
# This guarantees that when you scan for CSRF only, you only see CSRF alerts,
# and when you scan for Broken Auth only, you only see Broken Auth alerts.
# ─── Active scan rules to ENABLE per category ────────────────────────────────
# Only rules that directly probe for that specific vulnerability type.
# ZAP will run ONLY these rules — everything else stays disabled.
VULN_RULE_MAP: Dict[str, List[int]] = {
    # SQLi: error-based, blind boolean, blind time, union, out-of-band
    "sql_injection": [40018, 40019, 40020, 40021, 40022, 40024, 90018],
    # XSS: reflected, persistent, DOM-based
    "xss":           [40012, 40014, 40016, 40017],
    # CSRF: checks for missing/weak anti-CSRF tokens on forms
    "csrf":          [20012],
    # Broken Auth: forceful browsing, credential stuffing indicators
    "broken_auth":   [10105, 10200],
    # Directory Traversal: path traversal attacks
    "dir_traversal": [6, 7],
}

# ─── Alert filter map ─────────────────────────────────────────────────────────
# Which ZAP plugin IDs count as a finding for each category.
# This is used AFTER the scan to filter the alerts list.
#
# Includes passive-scan IDs (different from active rule IDs) where relevant.
# Every ID appears in EXACTLY ONE category — zero cross-contamination.
#
# Deliberately excluded (too noisy / wrong category):
#   10010  Cookie No HttpOnly Flag          — cookie hardening, not auth bypass
#   10011  Cookie Without Secure Flag       — cookie hardening, not auth bypass
#   10017  Cross-Domain JS Inclusion        — supply-chain, not auth
#   10098  Cross-Domain Misconfiguration    — CORS issue, not auth
#   10055  CSP issues                       — header hygiene, not XSS exploit
#   10038  CSP: no fallback directive       — same
#   10096  Timestamp Disclosure             — generic info leak, not a category
#   10032/10033  Path info disclosure       — too broad for dir_traversal
#   90022  Request params analysis          — too broad for SQLi
ALERT_FILTER_MAP: Dict[str, Set[int]] = {
    # Only real SQLi attack findings
    "sql_injection": {40018, 40019, 40020, 40021, 40022, 40024, 90018},

    # Only real XSS attack findings
    "xss":           {40012, 40014, 40016, 40017},

    # 20012 = active CSRF token check
    # 10202 = passive "Absence of Anti-CSRF Tokens" (fires when forms lack tokens)
    "csrf":          {20012, 10202},

    # Only active broken-auth findings — no passive cookie/header noise
    "broken_auth":   {10105, 10200},

    # Only active path traversal findings
    "dir_traversal": {6, 7},
}

# ─── Risk level labels ────────────────────────────────────────────────────────
# ZAP returns riskcode as either an int OR a string — normalise to int first
RISK_MAP = {3: "High", 2: "Medium", 1: "Low", 0: "Informational"}

# ─── Short descriptions per alert name ────────────────────────────────────────
# Replaces ZAP's verbose paragraph with a single plain sentence.
SHORT_DESCRIPTIONS: Dict[str, str] = {
    "SQL Injection":
        "The app passes user input directly into database queries without sanitisation.",
    "Cross Site Scripting (Reflected)":
        "User input is echoed back in the page without encoding, allowing script injection.",
    "Cross Site Scripting (Persistent)":
        "Malicious scripts saved to the database execute for every user who views the page.",
    "Cross-Site Request Forgery (CSRF)":
        "Requests lack a secret token, so attackers can forge actions on behalf of logged-in users.",
    "Absence of Anti-CSRF Tokens":
        "Forms have no unique token to verify the request came from your own site.",
    "Anti CSRF Tokens Check":
        "CSRF tokens are missing or too weak on one or more forms.",
    "Path Traversal":
        "URL parameters accept ../ sequences, letting attackers read files outside the web root.",
    "Remote OS Command Injection":
        "User input is executed as an OS command on the server.",
    "Weak Authentication Method":
        "Authentication uses an insecure mechanism that can be bypassed or brute-forced.",
    "Session ID in URL Rewrite":
        "Session tokens appear in URLs, exposing them in logs and browser history.",
    "Cookie No HttpOnly Flag":
        "Session cookies lack the HttpOnly flag, making them readable by JavaScript.",
    "Cookie Without Secure Flag":
        "Cookies are sent over plain HTTP and can be intercepted on the network.",
    "Information Disclosure":
        "The server reveals version numbers or internal paths in responses.",
    "Missing Anti-clickjacking Header":
        "No X-Frame-Options header — the page can be embedded in a hidden iframe.",
    "X-Content-Type-Options Header Missing":
        "The browser may misinterpret file types, enabling MIME-sniffing attacks.",
    "Timestamp Disclosure":
        "Unix timestamps in responses can help attackers fingerprint the server.",
}

# ─── Short fix per alert name ─────────────────────────────────────────────────
SHORT_FIXES: Dict[str, str] = {
    "SQL Injection":
        "Use parameterised queries or a prepared statement library. Never concatenate user input into SQL.",
    "Cross Site Scripting (Reflected)":
        "HTML-encode all user input before rendering it. Use a Content Security Policy header.",
    "Cross Site Scripting (Persistent)":
        "Sanitise input on write and encode output on read. Apply a strict CSP.",
    "Cross-Site Request Forgery (CSRF)":
        "Add a per-session, per-form CSRF token and verify it server-side on every state-changing request.",
    "Absence of Anti-CSRF Tokens":
        "Include a hidden CSRF token in every form and validate it on submission.",
    "Anti CSRF Tokens Check":
        "Generate a cryptographically random token per session and embed it in all forms.",
    "Path Traversal":
        "Validate and sanitise file paths. Use a whitelist of allowed directories and reject ../ sequences.",
    "Remote OS Command Injection":
        "Never pass user input to shell commands. Use library functions with separate argument lists.",
    "Weak Authentication Method":
        "Enforce strong passwords, account lockout, and multi-factor authentication.",
    "Session ID in URL Rewrite":
        "Store session IDs in cookies only, never in URLs. Set HttpOnly and Secure flags.",
    "Cookie No HttpOnly Flag":
        "Set the HttpOnly attribute on all session cookies to block JavaScript access.",
    "Cookie Without Secure Flag":
        "Set the Secure attribute on all cookies so they are only sent over HTTPS.",
    "Information Disclosure":
        "Suppress version headers (Server, X-Powered-By). Show generic error pages to users.",
    "Missing Anti-clickjacking Header":
        "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive.",
    "X-Content-Type-Options Header Missing":
        "Add 'X-Content-Type-Options: nosniff' to all responses.",
    "Timestamp Disclosure":
        "Remove or obfuscate timestamps from public responses.",
}

# ─── Plain-English explanations ───────────────────────────────────────────────
SIMPLE_EXPLANATIONS: Dict[str, str] = {
    "SQL Injection":
        "Attackers can manipulate database queries by injecting special characters, potentially leaking or destroying data.",
    "Cross Site Scripting (Reflected)":
        "Malicious scripts can be injected via URLs and run in victims' browsers, stealing cookies or redirecting users.",
    "Cross Site Scripting (Persistent)":
        "Malicious scripts stored on the server execute automatically for every visitor, enabling widespread attacks.",
    "Cross-Site Request Forgery (CSRF)":
        "An attacker's page can silently submit requests on behalf of a logged-in user without their knowledge.",
    "Absence of Anti-CSRF Tokens":
        "Forms are missing unique tokens that verify requests come from your site, making CSRF attacks easy.",
    "Anti CSRF Tokens Check":
        "Forms appear to be missing or have weak CSRF tokens, leaving users vulnerable to forged requests.",
    "Path Traversal":
        "Attackers can read files outside the web root (e.g. /etc/passwd) using ../ sequences in URL parameters.",
    "Remote OS Command Injection":
        "User input is passed to the server's OS shell, letting attackers run arbitrary system commands.",
    "Weak Authentication Method":
        "The login mechanism lacks adequate protection and could be bypassed or brute-forced.",
    "Session ID in URL Rewrite":
        "Session tokens appear in URLs, exposing them in browser history, server logs, and referrer headers.",
    "Cookie No HttpOnly Flag":
        "Session cookies can be read by JavaScript, making them vulnerable to XSS-based session theft.",
    "Cookie Without Secure Flag":
        "Cookies are sent over plain HTTP, meaning they can be intercepted by network attackers.",
    "Information Disclosure":
        "The server is leaking internal details (versions, error messages, paths) that help attackers map the system.",
    "Missing Anti-clickjacking Header":
        "The page can be embedded in a hidden iframe, tricking users into clicking things they didn't intend to.",
    "X-Content-Type-Options Header Missing":
        "Browsers may guess file types incorrectly, which can enable certain script-injection attacks.",
}


class ZAPScanner:
    """Thin wrapper around the ZAP REST API."""

    def __init__(self):
        self.base = ZAP_BASE_URL
        self.key  = ZAP_API_KEY
        self._verify_connection()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get(self, path: str, params: dict = None) -> dict:
        params = params or {}
        params["apikey"] = self.key
        resp = requests.get(f"{self.base}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _get_safe(self, path: str, params: dict = None) -> dict:
        try:
            return self._get(path, params)
        except Exception as exc:
            logger.debug(f"Safe GET {path} failed: {exc}")
            return {}

    def _verify_connection(self):
        try:
            self._get("/JSON/core/view/version/")
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot connect to ZAP at {self.base}. "
                "Start ZAP first:\n"
                "  zap.sh -daemon -port 8080 -config api.key=changeme"
            )

    # ── Speed: configure ZAP options before every scan ────────────────────────

    def _configure_speed_options(self):
        """
        Tune ZAP for faster scans.
        These are set via the core/ascan options API.
        """
        options = {
            # Active scan: run 5 threads per host (default is 2)
            "/JSON/ascan/action/setOptionThreadPerHost/": {"Integer": "5"},
            # Active scan: max alerts per rule per page (stops over-reporting)
            "/JSON/ascan/action/setOptionMaxAlertsPerRule/": {"Integer": "5"},
            # Active scan: max scan depth
            "/JSON/ascan/action/setOptionMaxDepth/": {"Integer": "5"},
            # Core: max response body size to parse (16 MB default causes large-file errors)
            "/JSON/core/action/setOptionMaxResponseBodySizeInBytes/": {"Integer": "5242880"},
        }
        for path, params in options.items():
            try:
                self._get(path, params)
            except Exception as exc:
                logger.debug(f"Option {path} not available: {exc}")

    # ── Spider ────────────────────────────────────────────────────────────────

    def start_spider(self, target_url: str) -> str:
        """
        Start a shallow spider scan.
        maxChildren=5 limits how many links are followed per page,
        keeping the crawl fast without missing important pages.
        """
        data = self._get("/JSON/spider/action/scan/", {
            "url":         target_url,
            "recurse":     "true",
            "maxChildren": "5",     # ← key speed limiter; raise if you want deeper crawl
        })
        return data["scan"]

    def spider_progress(self, spider_id: str) -> int:
        data = self._get_safe("/JSON/spider/view/status/", {"scanId": spider_id})
        try:
            return int(data.get("status", 0))
        except (ValueError, TypeError):
            return 0

    # ── Active scan ───────────────────────────────────────────────────────────

    def start_active_scan(self, target_url: str, vulnerabilities: List[str]) -> str:
        self._configure_speed_options()
        self._configure_scan_policy(vulnerabilities)
        data = self._get("/JSON/ascan/action/scan/", {
            "url":         target_url,
            "recurse":     "true",
            "inScopeOnly": "false",
        })
        return data["scan"]

    def active_scan_progress(self, ascan_id: str) -> int:
        data = self._get_safe("/JSON/ascan/view/status/", {"scanId": ascan_id})
        try:
            return int(data.get("status", 0))
        except (ValueError, TypeError):
            return 0

    def wait_for_passive_scan(self, timeout: int = 60):
        """Wait for ZAP's passive scan queue to drain (max `timeout` seconds)."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self._get_safe("/JSON/pscan/view/recordsToScan/")
            remaining = int(data.get("recordsToScan", 0))
            if remaining == 0:
                return
            logger.info(f"Passive scan queue: {remaining} records left…")
            time.sleep(3)
        logger.warning("Passive scan wait timed out — collecting alerts anyway.")

    # ── Alerts ────────────────────────────────────────────────────────────────

    def get_alerts(self, target_url: str) -> List[Dict[str, Any]]:
        data = self._get("/JSON/core/view/alerts/", {
            "baseurl": target_url,
            "start":   "0",
            "count":   "500",
        })
        return data.get("alerts", [])

    def filter_and_enrich_alerts(
        self, alerts: List[Dict], vulnerabilities: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Filter alerts so ONLY findings relevant to the selected vulnerability
        categories are returned.

        Uses ALERT_FILTER_MAP (not VULN_RULE_MAP) because passive scan rules
        can fire alerts with different plugin IDs than the active rules.

        Each plugin ID belongs to exactly ONE category — no cross-contamination.
        """
        # Build the exact set of allowed plugin IDs for what the user selected
        allowed_ids: Set[int] = set()
        for vuln in vulnerabilities:
            allowed_ids.update(ALERT_FILTER_MAP.get(vuln, set()))

        seen_names: set = set()
        results = []

        for alert in alerts:
            try:
                plugin_id = int(alert.get("pluginId", 0))
            except (ValueError, TypeError):
                continue

            # Strict filter — only IDs explicitly listed for selected categories
            if allowed_ids and plugin_id not in allowed_ids:
                continue

            name = alert.get("alert", "Unknown")
            # Deduplicate by name (same vuln on 50 URLs → show once)
            if name in seen_names:
                continue
            seen_names.add(name)

            # Log the raw alert so you can see exactly what ZAP sends
            logger.debug(f"ALERT raw: name={name!r} riskcode={alert.get('riskcode')!r} riskdesc={alert.get('riskdesc')!r}")

            # --- Risk resolution (belt AND braces) ---
            # ZAP provides two fields; use both to avoid "Informational" false reads:
            #   riskdesc  e.g. "High (3)"  → most reliable, parse the word before " ("
            #   riskcode  e.g. 3 or "3"   → fallback
            risk = "Informational"  # safe default

            riskdesc = str(alert.get("riskdesc", "")).strip()
            if riskdesc:
                # "High (3)"  →  "High"
                word = riskdesc.split(" (")[0].strip().capitalize()
                if word in ("High", "Medium", "Low", "Informational"):
                    risk = word

            # If riskdesc didn't give us a useful answer, fall back to riskcode
            if risk == "Informational":
                try:
                    rc = int(alert.get("riskcode", 0))
                except (ValueError, TypeError):
                    rc = 0
                risk = RISK_MAP.get(rc, "Informational")

            risk_code = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}[risk]

            results.append({
                "name":        name,
                "risk":        risk,
                "risk_code":   risk_code,
                "url":         alert.get("url", ""),
                "description": self._short_description(name),
                "solution":    self._short_fix(name),
                "reference":   alert.get("reference", ""),
                "cwe_id":      alert.get("cweid", ""),
                "wasc_id":     alert.get("wascid", ""),
                "explanation": self._simple_explanation(name),
            })

        order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        results.sort(key=lambda r: order.get(r["risk"], 4))
        return results

    # ── Scan policy ───────────────────────────────────────────────────────────

    def _configure_scan_policy(self, vulnerabilities: List[str]):
        """
        1. Disable ALL active scan rules.
        2. Enable only the rules for the selected vulnerability categories.
        Each rule is toggled individually so a missing ID skips gracefully.
        """
        try:
            self._get("/JSON/ascan/action/disableAllScanners/")
            logger.info("All active scan rules disabled.")
        except Exception as exc:
            logger.warning(f"disableAllScanners failed: {exc}")

        enable_ids: Set[int] = set()
        for vuln in vulnerabilities:
            enable_ids.update(VULN_RULE_MAP.get(vuln, []))

        enabled = 0
        for rule_id in enable_ids:
            try:
                self._get("/JSON/ascan/action/enableScanners/", {"ids": str(rule_id)})
                enabled += 1
            except Exception:
                logger.debug(f"Rule {rule_id} not in this ZAP build — skipped.")

        logger.info(f"Enabled {enabled}/{len(enable_ids)} rules for: {vulnerabilities}")

    # ── Explanation helper ────────────────────────────────────────────────────

    def _lookup(self, name: str, table: dict, fallback: str) -> str:
        """Generic lookup: exact key match first, then keyword fallback."""
        lower = name.lower()
        for key, val in table.items():
            if key.lower() in lower:
                return val
        # Keyword fallbacks
        if "sql" in lower:
            return table.get("SQL Injection", fallback)
        if "xss" in lower or "cross site script" in lower:
            return table.get("Cross Site Scripting (Reflected)", fallback)
        if "csrf" in lower or "anti-csrf" in lower or "anti csrf" in lower:
            return table.get("Absence of Anti-CSRF Tokens", fallback)
        if "traversal" in lower or "path traversal" in lower:
            return table.get("Path Traversal", fallback)
        if "command" in lower or "injection" in lower:
            return table.get("Remote OS Command Injection", fallback)
        if "session" in lower or "cookie" in lower:
            return table.get("Cookie No HttpOnly Flag", fallback)
        if "disclosure" in lower or "timestamp" in lower:
            return table.get("Information Disclosure", fallback)
        return fallback

    def _simple_explanation(self, alert_name: str) -> str:
        """One-sentence plain-English explanation shown in the results table."""
        return self._lookup(alert_name, SIMPLE_EXPLANATIONS, "A security issue was detected on this page.")

    def _short_description(self, alert_name: str) -> str:
        """One-sentence technical description (replaces ZAP's verbose paragraph)."""
        return self._lookup(alert_name, SHORT_DESCRIPTIONS, "A vulnerability was detected.")

    def _short_fix(self, alert_name: str) -> str:
        """One-sentence recommended fix."""
        return self._lookup(alert_name, SHORT_FIXES, "Review and apply the relevant security controls.")
