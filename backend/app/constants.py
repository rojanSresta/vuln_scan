"""All magic strings and constants in one place"""

# Vulnerability categories
VULN_CATEGORIES = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "csrf": "CSRF",
    "broken_auth": "Broken Authentication",
    "dir_traversal": "Directory Traversal",
}

# SQL injection detection patterns
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"postgresql",
    r"sqlite",
    r"odbc",
    r"ora-\d+",
    r"unclosed quotation mark",
    r"syntax error near",
]

# Directory traversal detection patterns
TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0",
    r"\[extensions\]",
    r"\[fonts\]",
]

# Risk level scores
RISK_CODES = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

# Default vulnerabilities to scan
DEFAULT_VULNS = [
    "sql_injection",
    "xss",
    "csrf",
    "broken_auth",
    "dir_traversal",
]

# Keywords for heuristic detection
AUTH_FORM_KEYWORDS = ("login", "signin", "auth", "session", "account")
TOKEN_KEYWORDS = ("csrf", "xsrf", "token", "authenticity")
STATE_CHANGING_KEYWORDS = ("login", "signin", "signup", "register", "password", "update", "delete", "reset", "profile")
SESSION_PARAM_KEYWORDS = ("session", "sid", "token", "auth")
FILE_PARAM_KEYWORDS = ("file", "path", "page", "template", "folder", "doc", "document", "download", "image")

# Scanner settings
DEFAULT_REQUEST_TIMEOUT = 12
DEFAULT_MAX_PAGES = 12
