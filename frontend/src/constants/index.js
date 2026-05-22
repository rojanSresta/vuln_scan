export const API = process.env.REACT_APP_API_URL || "http://localhost:8000";
export const TOKEN_KEY = process.env.TOKEN_KEY || "wavs_token";
export const ADMIN_TOKEN_KEY = process.env.ADMIN_TOKEN_KEY || "wavs_admin_token";

export const VULN_OPTIONS = [
  { id: "sql_injection", label: "SQL Injection", desc: "Detect query manipulation attempts" },
  { id: "xss", label: "Cross-Site Scripting", desc: "Find reflected script injection points" },
  { id: "dir_traversal", label: "Directory Traversal", desc: "Probe unsafe file path access" },
  { id: "missing_headers", label: "Missing Header", desc: "Check for absent security response headers" },
  { id: "default_credentials", label: "Default Credentials", desc: "Try common username and password pairs on login forms" },
];

export const RISK_META = {
  High: { color: "var(--risk-high)", bg: "var(--risk-high-bg)" },
  Medium: { color: "var(--risk-medium)", bg: "var(--risk-medium-bg)" },
  Low: { color: "var(--risk-low)", bg: "var(--risk-low-bg)" },
  Informational: { color: "var(--risk-info)", bg: "var(--risk-info-bg)" },
};
