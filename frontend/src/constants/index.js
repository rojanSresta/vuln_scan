const DEFAULT_API = "http://localhost:8000";
export const API = process.env.REACT_APP_API_URL || DEFAULT_API;

// Warn loudly when the frontend was built without REACT_APP_API_URL.
// In production this almost always means the Vercel env var is missing and
// the browser will try to call http://localhost:8000 (which doesn't exist),
// so every API request — including starting an XSS scan — silently fails.
if (typeof window !== "undefined" && API === DEFAULT_API && !process.env.REACT_APP_API_URL) {
  // eslint-disable-next-line no-console
  console.warn(
    "[WAVS] REACT_APP_API_URL is not set. The frontend will call http://localhost:8000, " +
      "which only works when the API runs on the same machine. On Vercel, set " +
      "REACT_APP_API_URL to your deployed backend URL in Project Settings → Environment Variables " +
      "and redeploy."
  );
}

export const TOKEN_KEY = process.env.REACT_APP_TOKEN_KEY || "wavs_token";
export const ADMIN_TOKEN_KEY = process.env.REACT_APP_ADMIN_TOKEN_KEY || "wavs_admin_token";

export const VULN_OPTIONS = [
  { id: "sql_injection", label: "SQL Injection", desc: "Try SQLi payloads against login forms" },
  { id: "xss", label: "Cross-Site Scripting", desc: "Confirm reflected payloads with browser alerts" },
  { id: "dir_traversal", label: "Directory Traversal", desc: "Probe unsafe file path access" },
  { id: "missing_headers", label: "Missing Header", desc: "Check for absent security response headers" },
  { id: "default_credentials", label: "Default Credentials", desc: "Try common username and password pairs on login forms" },
];

export const RISK_META = {
  High: { className: "text-risk-high bg-risk-high/10" },
  Medium: { className: "text-risk-medium bg-risk-medium/10" },
  Low: { className: "text-risk-low bg-risk-low/10" },
  Informational: { className: "text-risk-info bg-risk-info/10" },
};
