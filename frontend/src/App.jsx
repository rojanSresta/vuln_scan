import React, { useEffect, useRef, useState } from "react";
import "./App.css";

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";
const TOKEN_KEY = process.env.TOKEN_KEY;

const VULN_OPTIONS = [
  { id: "sql_injection", label: "SQL Injection", desc: "Detect query manipulation attempts" },
  { id: "xss", label: "Cross-Site Scripting", desc: "Find reflected script injection points" },
  { id: "csrf", label: "CSRF", desc: "Check forms for missing CSRF protections" },
  { id: "broken_auth", label: "Broken Authentication", desc: "Inspect weak auth and session handling" },
  { id: "dir_traversal", label: "Directory Traversal", desc: "Probe unsafe file path access" },
];

const RISK_META = {
  High: { color: "var(--risk-high)", bg: "var(--risk-high-bg)" },
  Medium: { color: "var(--risk-medium)", bg: "var(--risk-medium-bg)" },
  Low: { color: "var(--risk-low)", bg: "var(--risk-low-bg)" },
  Informational: { color: "var(--risk-info)", bg: "var(--risk-info-bg)" },
};

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ full_name: "", email: "", password: "" });
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);

  const [view, setView] = useState("scan");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistory, setSelectedHistory] = useState(null);

  const [targetUrl, setTargetUrl] = useState("");
  const [selected, setSelected] = useState([]);
  const [scanAll, setScanAll] = useState(false);
  const [phase, setPhase] = useState("idle");
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const [results, setResults] = useState([]);
  const [errorMsg, setErrorMsg] = useState("");
  const [expandedRows, setExpandedRows] = useState({});

  const pollRef = useRef(null);
  const resultsRef = useRef(null);

  const apiFetch = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (!(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(`${API}${path}`, { ...options, headers });
    if (!response.ok) {
      let detail = "Request failed";
      try {
        const payload = await response.json();
        detail = payload.detail || detail;
      } catch {
        detail = response.statusText || detail;
      }
      throw new Error(detail);
    }
    return response;
  };

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const resetScanState = () => {
    stopPolling();
    setPhase("idle");
    setScanId(null);
    setProgress(0);
    setStatusMsg("");
    setResults([]);
    setErrorMsg("");
    setExpandedRows({});
  };

  const loadHistory = async (preferredScanId = null) => {
    if (!token) return;
    setHistoryLoading(true);
    try {
      const response = await apiFetch("/history", { method: "GET" });
      const payload = await response.json();
      const items = payload.items || [];
      setHistory(items);

      if (preferredScanId) {
        const matched = items.find((item) => item.scan_id === preferredScanId);
        setSelectedHistory(matched || items[0] || null);
      } else {
        setSelectedHistory((current) => {
          if (!items.length) return null;
          return items.find((item) => item.scan_id === current?.scan_id) || items[0];
        });
      }
    } catch (error) {
      setErrorMsg(error.message);
    } finally {
      setHistoryLoading(false);
    }
  };

  const fetchCurrentUser = async () => {
    const response = await apiFetch("/auth/me", { method: "GET" });
    const payload = await response.json();
    setUser(payload);
  };

  useEffect(() => {
    if (!token) {
      setUser(null);
      return undefined;
    }

    let cancelled = false;
    const bootstrap = async () => {
      try {
        await fetchCurrentUser();
        if (!cancelled) {
          await loadHistory();
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem(TOKEN_KEY);
          setToken("");
          setUser(null);
        }
      }
    };

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => () => stopPolling(), []);

  const canStart = /^https?:\/\/.+/.test(targetUrl.trim()) && (scanAll || selected.length > 0);

  const riskStats = results.reduce((acc, item) => {
    acc[item.risk] = (acc[item.risk] || 0) + 1;
    return acc;
  }, {});

  const historyResults = selectedHistory?.results || [];
  const historyRiskStats = historyResults.reduce((acc, item) => {
    acc[item.risk] = (acc[item.risk] || 0) + 1;
    return acc;
  }, {});

  const setAuthField = (field, value) => {
    setAuthForm((current) => ({ ...current, [field]: value }));
  };

  const handleAuth = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      const endpoint = authMode === "signup" ? "/auth/signup" : "/auth/login";
      const payload =
        authMode === "signup"
          ? authForm
          : { email: authForm.email, password: authForm.password };
      const response = await fetch(`${API}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorPayload = await response.json();
        throw new Error(errorPayload.detail || "Authentication failed");
      }

      const data = await response.json();
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      setAuthForm({ full_name: "", email: "", password: "" });
      setView("scan");
      setErrorMsg("");
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthBusy(false);
    }
  };

  const logout = async () => {
    try {
      if (token) {
        await apiFetch("/auth/logout", { method: "POST" });
      }
    } catch {
      // Local cleanup is enough if the server session no longer exists.
    } finally {
      stopPolling();
      localStorage.removeItem(TOKEN_KEY);
      setToken("");
      setUser(null);
      setHistory([]);
      setSelectedHistory(null);
      resetScanState();
    }
  };

  const toggleVuln = (id) => {
    setSelected((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  };

  const toggleScanAll = () => {
    setScanAll((current) => {
      if (!current) setSelected([]);
      return !current;
    });
  };

  const pollStatus = async (id) => {
    try {
      const statusResponse = await apiFetch(`/scan/status/${id}`, { method: "GET" });
      const statusData = await statusResponse.json();
      setProgress(statusData.progress);
      setStatusMsg(statusData.message);

      if (statusData.status === "done") {
        stopPolling();
        const resultsResponse = await apiFetch(`/scan/results/${id}`, { method: "GET" });
        const resultData = await resultsResponse.json();
        setResults(resultData.results || []);
        setPhase("done");
        await loadHistory(id);
        setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 200);
      } else if (statusData.status === "error") {
        stopPolling();
        setErrorMsg(statusData.message);
        setPhase("error");
        await loadHistory(id);
      }
    } catch (error) {
      stopPolling();
      setErrorMsg(error.message);
      setPhase("error");
    }
  };

  const startScan = async () => {
    setPhase("scanning");
    setProgress(0);
    setStatusMsg("Preparing scanner...");
    setResults([]);
    setErrorMsg("");
    setExpandedRows({});

    try {
      const response = await apiFetch("/scan/start", {
        method: "POST",
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          vulnerabilities: scanAll ? ["scan_all"] : selected,
        }),
      });
      const payload = await response.json();
      setScanId(payload.scan_id);
      pollRef.current = setInterval(() => pollStatus(payload.scan_id), 3000);
      await loadHistory(payload.scan_id);
    } catch (error) {
      setErrorMsg(error.message);
      setPhase("error");
    }
  };

  const downloadReport = async (reportScanId) => {
    try {
      const response = await apiFetch(`/scan/report/${reportScanId}`, { method: "GET" });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `vuln_report_${reportScanId.slice(0, 8)}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setErrorMsg(error.message);
    }
  };

  const openHistoryItem = async (item) => {
    setView("history");
    try {
      const response = await apiFetch(`/history/${item.scan_id}`, { method: "GET" });
      const payload = await response.json();
      setSelectedHistory(payload);
    } catch (error) {
      setErrorMsg(error.message);
    }
  };

  if (!user) {
    return (
      <div className="auth-page">
        <div className="simple-card auth-card">
          <div className="auth-header">
            <div className="brand">WAVS</div>
            <h1>Login to continue</h1>
            <p>Use your account to run scans and review saved reports.</p>
          </div>

          <div className="tabs">
            <button className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>
              Login
            </button>
            <button className={authMode === "signup" ? "active" : ""} onClick={() => setAuthMode("signup")}>
              Sign Up
            </button>
          </div>

          {authMode === "signup" && (
            <label className="field">
              <span>Full name</span>
              <input
                type="text"
                value={authForm.full_name}
                onChange={(event) => setAuthField("full_name", event.target.value)}
                placeholder="Enter your full name"
              />
            </label>
          )}

          <label className="field">
            <span>Email</span>
            <input
              type="email"
              value={authForm.email}
              onChange={(event) => setAuthField("email", event.target.value)}
              placeholder="name@example.com"
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              type="password"
              value={authForm.password}
              onChange={(event) => setAuthField("password", event.target.value)}
              placeholder="At least 8 characters"
            />
          </label>

          {authError && <div className="alert error">{authError}</div>}

          <button className="button button-primary" onClick={handleAuth} disabled={authBusy}>
            {authBusy ? "Please wait..." : authMode === "signup" ? "Create account" : "Login"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <div className="brand">WAVS</div>
          <p className="topbar-subtitle">Manual vulnerability scanner</p>
        </div>

        <nav className="topbar-nav">
          <button className={view === "scan" ? "active" : ""} onClick={() => setView("scan")}>
            Scan
          </button>
          <button className={view === "history" ? "active" : ""} onClick={() => setView("history")}>
            History
          </button>
        </nav>

        <div className="topbar-user">
          <div>
            <strong>{user.full_name}</strong>
            <span>{user.email}</span>
          </div>
          <button className="button button-secondary" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      <main className="page">
        {errorMsg && <div className="alert error">Action failed: {errorMsg}</div>}

        {view === "scan" && (
          <div className="content-grid">
            <section className="simple-card">
              <div className="section-head">
                <div>
                  <h2>Start a new scan</h2>
                  <p>Select a target and the checks you want to run.</p>
                </div>
              </div>

              <label className="field">
                <span>Target URL</span>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(event) => setTargetUrl(event.target.value)}
                  placeholder="https://example.com"
                  disabled={phase === "scanning"}
                />
              </label>

              <div className="option-list">
                <button
                  className={`option-item ${scanAll ? "active" : ""}`}
                  onClick={toggleScanAll}
                  disabled={phase === "scanning"}
                >
                  <strong>Scan All</strong>
                  <span>Run every available check</span>
                </button>

                {VULN_OPTIONS.map((item) => (
                  <button
                    key={item.id}
                    className={`option-item ${selected.includes(item.id) && !scanAll ? "active" : ""}`}
                    onClick={() => !scanAll && toggleVuln(item.id)}
                    disabled={phase === "scanning" || scanAll}
                  >
                    <strong>{item.label}</strong>
                    <span>{item.desc}</span>
                  </button>
                ))}
              </div>

              <div className="actions">
                <button className="button button-primary" disabled={!canStart || phase === "scanning"} onClick={startScan}>
                  {phase === "scanning" ? "Scanning..." : "Start Scan"}
                </button>
                <button className="button button-secondary" onClick={resetScanState}>
                  Reset
                </button>
              </div>
            </section>

            <aside className="simple-card side-card">
              <h3>Quick Info</h3>
              <div className="stats">
                <div className="stat-box">
                  <span>Saved scans</span>
                  <strong>{history.length}</strong>
                </div>
                <div className="stat-box">
                  <span>Completed</span>
                  <strong>{history.filter((item) => item.status === "done").length}</strong>
                </div>
              </div>

              <div className="mini-list">
                <h4>Recent reports</h4>
                {historyLoading && <p className="muted">Loading history...</p>}
                {!historyLoading && history.length === 0 && <p className="muted">No saved reports yet.</p>}
                {history.slice(0, 4).map((item) => (
                  <button key={item.scan_id} className="mini-item" onClick={() => openHistoryItem(item)}>
                    <strong>{safeHostname(item.target_url)}</strong>
                    <span>{formatDate(item.created_at)}</span>
                  </button>
                ))}
              </div>
            </aside>

            {phase === "scanning" && (
              <section className="simple-card full-width">
                <div className="section-head">
                  <div>
                    <h2>Scan progress</h2>
                    <p>{statusMsg}</p>
                  </div>
                  <strong className="progress-label">{progress}%</strong>
                </div>

                <div className="progress-track">
                  <div className="progress-fill" style={{ width: `${progress}%` }} />
                </div>
              </section>
            )}

            {phase === "done" && (
              <section ref={resultsRef} className="simple-card full-width">
                <div className="section-head">
                  <div>
                    <h2>Scan results</h2>
                    <p>{results.length} finding(s) were recorded for this run.</p>
                  </div>
                  {scanId && (
                    <button className="button button-secondary" onClick={() => downloadReport(scanId)}>
                      Download PDF
                    </button>
                  )}
                </div>

                <RiskStrip stats={riskStats} />

                <ResultsTable
                  items={results}
                  expandedRows={expandedRows}
                  onToggleRow={(index) =>
                    setExpandedRows((current) => ({ ...current, [index]: !current[index] }))
                  }
                />
              </section>
            )}
          </div>
        )}

        {view === "history" && (
          <div className="history-grid">
            <section className="simple-card">
              <div className="section-head">
                <div>
                  <h2>History</h2>
                  <p>Open any previous scan to view details or download the report again.</p>
                </div>
              </div>

              <div className="history-list">
                {historyLoading && <p className="muted">Loading history...</p>}
                {!historyLoading && history.length === 0 && <p className="muted">No scan history yet.</p>}
                {history.map((item) => (
                  <button
                    key={item.scan_id}
                    className={`history-item ${selectedHistory?.scan_id === item.scan_id ? "active" : ""}`}
                    onClick={() => openHistoryItem(item)}
                  >
                    <div>
                      <strong>{safeHostname(item.target_url)}</strong>
                      <span>{item.target_url}</span>
                    </div>
                    <div className="history-meta">
                      <span>{formatDate(item.created_at)}</span>
                      <span className={`status-badge status-${item.status}`}>{item.status}</span>
                    </div>
                  </button>
                ))}
              </div>
            </section>

            <section className="simple-card">
              {selectedHistory ? (
                <>
                  <div className="section-head">
                    <div>
                      <h2>Scan detail</h2>
                      <p>{selectedHistory.target_url}</p>
                    </div>
                    {selectedHistory.report_available && (
                      <button className="button button-secondary" onClick={() => downloadReport(selectedHistory.scan_id)}>
                        Download Again
                      </button>
                    )}
                  </div>

                  <div className="detail-grid">
                    <div className="stat-box">
                      <span>Scan ID</span>
                      <strong>{selectedHistory.scan_id}</strong>
                    </div>
                    <div className="stat-box">
                      <span>Checks</span>
                      <strong>{(selectedHistory.vulnerabilities || []).join(", ") || "Not available"}</strong>
                    </div>
                  </div>

                  <RiskStrip stats={historyRiskStats} />

                  <ResultsTable items={historyResults} expandedRows={{}} onToggleRow={() => {}} readOnly />
                </>
              ) : (
                <p className="muted">Choose a saved scan to inspect its details.</p>
              )}
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

function RiskStrip({ stats }) {
  return (
    <div className="risk-strip">
      {Object.keys(RISK_META).map((risk) =>
        stats[risk] ? (
          <span
            key={risk}
            className="risk-pill"
            style={{ color: RISK_META[risk].color, background: RISK_META[risk].bg }}
          >
            {risk}: {stats[risk]}
          </span>
        ) : null
      )}
    </div>
  );
}

function ResultsTable({ items, expandedRows, onToggleRow, readOnly = false }) {
  if (!items.length) {
    return <p className="muted">No findings were recorded for this scan.</p>;
  }

  return (
    <div className="results-list">
      {items.map((item, index) => {
        const expanded = !!expandedRows[index];
        const meta = RISK_META[item.risk] || RISK_META.Informational;

        return (
          <div key={`${item.name}-${index}`} className="result-item">
            <div className="result-top">
              <div>
                <strong>{item.name}</strong>
                <p>{item.explanation}</p>
              </div>
              <span className="risk-pill" style={{ color: meta.color, background: meta.bg }}>
                {item.risk}
              </span>
            </div>

            <div className="result-meta">
              <span>{item.url || "No URL provided"}</span>
              {!readOnly && (
                <button className="text-link" onClick={() => onToggleRow(index)}>
                  {expanded ? "Hide details" : "View details"}
                </button>
              )}
            </div>

            {(readOnly || expanded) && (
              <div className="result-details">
                <p><strong>Description:</strong> {item.description}</p>
                <p><strong>Solution:</strong> {item.solution || "Review the affected endpoint and apply the relevant security control."}</p>
                {item.reference && <p><strong>Reference:</strong> {item.reference}</p>}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function formatDate(value) {
  if (!value) return "Unknown date";
  return new Date(value).toLocaleString();
}
