/**
 * App.jsx  —  VulnScan main application
 *
 * State machine:
 *   idle → scanning → done (or error)
 *
 * The app talks to FastAPI on localhost:8000 (proxied in development).
 */

import React, { useState, useEffect, useRef, useCallback } from "react";
import "./App.css";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";

const VULN_OPTIONS = [
  {
    id: "sql_injection",
    label: "SQL Injection",
    desc: "Database query manipulation via malicious input",
    icon: "💉",
  },
  {
    id: "xss",
    label: "Cross-Site Scripting (XSS)",
    desc: "Malicious script injection into web pages",
    icon: "📜",
  },
  {
    id: "csrf",
    label: "CSRF",
    desc: "Unauthorized commands from a trusted user",
    icon: "🔄",
  },
  {
    id: "broken_auth",
    label: "Broken Authentication",
    desc: "Weak session management & credential handling",
    icon: "🔑",
  },
  {
    id: "dir_traversal",
    label: "Directory Traversal",
    desc: "Access to files outside the web root",
    icon: "📁",
  },
];

const RISK_META = {
  High:          { color: "var(--high)", bg: "var(--high-bg)",  dot: "🔴" },
  Medium:        { color: "var(--med)",  bg: "var(--med-bg)",   dot: "🟡" },
  Low:           { color: "var(--low)",  bg: "var(--low-bg)",   dot: "🔵" },
  Informational: { color: "var(--info)", bg: "var(--info-bg)",  dot: "⚪" },
};

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [targetUrl,     setTargetUrl]     = useState("");
  const [selected,      setSelected]      = useState([]);
  const [scanAll,       setScanAll]       = useState(false);
  const [phase,         setPhase]         = useState("idle"); // idle|scanning|done|error
  const [scanId,        setScanId]        = useState(null);
  const [progress,      setProgress]      = useState(0);
  const [statusMsg,     setStatusMsg]     = useState("");
  const [results,       setResults]       = useState([]);
  const [errorMsg,      setErrorMsg]      = useState("");
  const [expandedRows,  setExpandedRows]  = useState({});

  const pollRef = useRef(null);
  const resultsRef = useRef(null);

  // ── Helpers ───────────────────────────────────────────────────────────────

  const toggleVuln = (id) => {
    setSelected(prev =>
      prev.includes(id) ? prev.filter(v => v !== id) : [...prev, id]
    );
  };

  const toggleScanAll = () => {
    setScanAll(prev => {
      if (!prev) setSelected([]); // clear individual when scan_all is on
      return !prev;
    });
  };

  const canStart =
    targetUrl.trim().match(/^https?:\/\/.+/) &&
    (scanAll || selected.length > 0);

  // ── Polling ───────────────────────────────────────────────────────────────

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const pollStatus = useCallback(async (id) => {
    try {
      const res = await fetch(`${API}/scan/status/${id}`);
      if (!res.ok) throw new Error("Status fetch failed");
      const data = await res.json();

      setProgress(data.progress);
      setStatusMsg(data.message);

      if (data.status === "done") {
        stopPolling();
        // Fetch final results
        const rRes = await fetch(`${API}/scan/results/${id}`);
        const rData = await rRes.json();
        setResults(rData.results);
        setPhase("done");
        setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 200);
      } else if (data.status === "error") {
        stopPolling();
        setErrorMsg(data.message);
        setPhase("error");
      }
    } catch (e) {
      stopPolling();
      setErrorMsg(`Connection error: ${e.message}`);
      setPhase("error");
    }
  }, [stopPolling]);

  // ── Start scan ────────────────────────────────────────────────────────────

  const startScan = async () => {
    setPhase("scanning");
    setProgress(0);
    setStatusMsg("Connecting to ZAP…");
    setResults([]);
    setErrorMsg("");
    setExpandedRows({});

    const vulns = scanAll ? ["scan_all"] : selected;

    try {
      const res = await fetch(`${API}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl.trim(), vulnerabilities: vulns }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to start scan");
      }

      const data = await res.json();
      setScanId(data.scan_id);

      // Poll every 3 seconds
      pollRef.current = setInterval(() => pollStatus(data.scan_id), 3000);
    } catch (e) {
      setErrorMsg(e.message);
      setPhase("error");
    }
  };

  // Stop polling on unmount
  useEffect(() => () => stopPolling(), [stopPolling]);

  // ── Download PDF ──────────────────────────────────────────────────────────

  const downloadReport = () => {
    window.open(`${API}/scan/report/${scanId}`, "_blank");
  };

  // ── Toggle row expand ─────────────────────────────────────────────────────

  const toggleRow = (idx) =>
    setExpandedRows(prev => ({ ...prev, [idx]: !prev[idx] }));

  // ── Risk stats ────────────────────────────────────────────────────────────

  const riskStats = results.reduce(
    (acc, r) => { acc[r.risk] = (acc[r.risk] || 0) + 1; return acc; },
    {}
  );

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-icon">⬡</span>
            <span className="logo-text">WAVS</span>
          </div>
        </div>
      </header>

      <main className="main">

        {/* ── Hero ── */}
        <section className="hero">
          <div className="hero-badge">
            <span className="badge-dot" /> Active Security Scanner
          </div>
          <h1 className="hero-title">
            Find vulnerabilities<br />
            <span className="accent">before attackers do.</span>
          </h1>
          <p className="hero-sub">
            Enter a target URL, choose which vulnerability classes to probe,
            and let WAVS do the heavy lifting.
          </p>
        </section>

        {/* ── Scan form ── */}
        <section className="card scan-card">
          <div className="card-label">
            <span className="card-label-num">01</span> TARGET
          </div>

          <div className="url-row">
            <div className="url-icon">🎯</div>
            <input
              className="url-input"
              type="text"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              disabled={phase === "scanning"}
              spellCheck={false}
            />
          </div>

          {/* ── Vuln selection ── */}
          <div className="card-label" style={{ marginTop: "2rem" }}>
            <span className="card-label-num">02</span> VULNERABILITY TYPES
          </div>

          <div className="vuln-grid">
            {/* Scan All */}
            <button
              className={`vuln-btn scan-all-btn ${scanAll ? "active" : ""}`}
              onClick={toggleScanAll}
              disabled={phase === "scanning"}
            >
              <span className="vuln-icon">🌐</span>
              <span className="vuln-info">
                <span className="vuln-name">Scan All</span>
                <span className="vuln-desc">Run every available test</span>
              </span>
              <span className="vuln-check">{scanAll ? "✓" : "+"}</span>
            </button>

            {VULN_OPTIONS.map(v => (
              <button
                key={v.id}
                className={`vuln-btn ${selected.includes(v.id) && !scanAll ? "active" : ""} ${scanAll ? "dimmed" : ""}`}
                onClick={() => !scanAll && toggleVuln(v.id)}
                disabled={phase === "scanning" || scanAll}
              >
                <span className="vuln-icon">{v.icon}</span>
                <span className="vuln-info">
                  <span className="vuln-name">{v.label}</span>
                  <span className="vuln-desc">{v.desc}</span>
                </span>
                <span className="vuln-check">
                  {selected.includes(v.id) && !scanAll ? "✓" : "+"}
                </span>
              </button>
            ))}
          </div>

          {/* ── Start button ── */}
          <button
            className={`start-btn ${phase === "scanning" ? "scanning" : ""}`}
            onClick={startScan}
            disabled={!canStart || phase === "scanning"}
          >
            {phase === "scanning" ? (
              <>
                <span className="spinner" />
                Scanning…
              </>
            ) : (
              <>
                <span>▶</span> Start Scan
              </>
            )}
          </button>
        </section>

        {/* ── Progress ── */}
        {phase === "scanning" && (
          <section className="card progress-card">
            <div className="progress-header">
              <span className="progress-label">{statusMsg}</span>
              <span className="progress-pct">{progress}%</span>
            </div>
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="progress-steps">
              {[
                { label: "Spider", at: 5 },
                { label: "Configure", at: 38 },
                { label: "Active Scan", at: 40 },
                { label: "Results", at: 95 },
              ].map(s => (
                <div
                  key={s.label}
                  className={`progress-step ${progress >= s.at ? "done" : ""}`}
                >
                  <span className="step-dot" />
                  <span className="step-label">{s.label}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ── Error ── */}
        {phase === "error" && (
          <section className="card error-card">
            <div className="error-icon">⚠</div>
            <div className="error-body">
              <strong>Scan Failed</strong>
              <p>{errorMsg}</p>
              <p className="error-hint">
                Ensure ZAP is running:<br />
                <code>zap.sh -daemon -port 8080 -config api.key=zap_api_key</code>
              </p>
            </div>
            <button className="retry-btn" onClick={() => setPhase("idle")}>
              Try Again
            </button>
          </section>
        )}

        {/* ── Results ── */}
        {phase === "done" && (
          <section ref={resultsRef} className="results-section">

            {/* Stats bar */}
            <div className="results-header">
              <div>
                <h2 className="results-title">Scan Results</h2>
                <p className="results-sub">
                  {results.length} finding{results.length !== 1 ? "s" : ""} on{" "}
                  <span className="accent">{targetUrl}</span>
                </p>
              </div>
              <button className="download-btn" onClick={downloadReport}>
                ⬇ Download PDF Report
              </button>
            </div>

            {/* Risk summary chips */}
            {results.length > 0 && (
              <div className="risk-chips">
                {["High", "Medium", "Low", "Informational"].map(level => (
                  riskStats[level] ? (
                    <div
                      key={level}
                      className="risk-chip"
                      style={{
                        color: RISK_META[level].color,
                        background: RISK_META[level].bg,
                        borderColor: RISK_META[level].color + "40",
                      }}
                    >
                      {RISK_META[level].dot} {level}: <strong>{riskStats[level]}</strong>
                    </div>
                  ) : null
                ))}
              </div>
            )}

            {results.length === 0 ? (
              <div className="card no-findings">
                <span className="no-findings-icon">✅</span>
                <div>
                  <strong>No vulnerabilities detected</strong>
                  <p>No issues found for the selected scan categories.</p>
                </div>
              </div>
            ) : (
              /* Results table */
              <div className="card table-card">
                <table className="results-table">
                  <thead>
                    <tr>
                      <th>Vulnerability</th>
                      <th>Risk</th>
                      <th>Plain-English Explanation</th>
                      <th>URL</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r, i) => {
                      const rm = RISK_META[r.risk] || RISK_META.Informational;
                      const expanded = expandedRows[i];
                      return (
                        <React.Fragment key={i}>
                          <tr className={`result-row ${expanded ? "expanded" : ""}`}>
                            <td className="col-name">
                              <span className="vuln-name-cell">{r.name}</span>
                              {r.cwe_id && (
                                <span className="cwe-tag">CWE-{r.cwe_id}</span>
                              )}
                            </td>
                            <td className="col-risk">
                              <span
                                className="risk-badge"
                                style={{
                                  color: rm.color,
                                  background: rm.bg,
                                  borderColor: rm.color + "50",
                                }}
                              >
                                {r.risk}
                              </span>
                            </td>
                            <td className="col-explanation">
                              {r.explanation}
                            </td>
                            <td className="col-url">
                              <span className="url-cell" title={r.url}>
                                {r.url ? new URL(r.url).pathname.slice(0, 30) + (r.url.length > 30 ? "…" : "") : "—"}
                              </span>
                            </td>
                            <td className="col-expand">
                              <button
                                className="expand-btn"
                                onClick={() => toggleRow(i)}
                                title="Toggle details"
                              >
                                {expanded ? "▲" : "▼"}
                              </button>
                            </td>
                          </tr>
                          {expanded && (
                            <tr className="detail-row">
                              <td colSpan={5}>
                                <div className="detail-panel">
                                  <div className="detail-block">
                                    <div className="detail-label">⚡ What Is It</div>
                                    <p>{r.description || r.explanation}</p>
                                  </div>
                                  <div className="detail-block">
                                    <div className="detail-label">🔧 How To Fix</div>
                                    <p>{r.solution || "Review and apply the relevant security controls."}</p>
                                  </div>
                                  {r.reference && (
                                    <div className="detail-block">
                                      <div className="detail-label">References</div>
                                      <p className="ref-text">{r.reference}</p>
                                    </div>
                                  )}
                                  <div className="detail-meta">
                                    <span>Full URL: <code>{r.url}</code></span>
                                    {r.wasc_id && <span>WASC-{r.wasc_id}</span>}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Re-scan */}
            <div style={{ textAlign: "center", marginTop: "2rem" }}>
              <button
                className="retry-btn"
                onClick={() => { setPhase("idle"); setResults([]); }}
              >
                ↩ New Scan
              </button>
            </div>
          </section>
        )}
      </main>

      <footer className="app-footer">
        <span>VulnScan · Final Year Project · Powered by OWASP ZAP</span>
      </footer>
    </div>
  );
}