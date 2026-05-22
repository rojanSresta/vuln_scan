import React from "react";
import { VULN_OPTIONS } from "../../constants";
import { formatDate, safeHostname } from "../../utils/format";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";

export default function ScanView({
  canStart,
  cancelScan,
  downloadReport,
  expandedRows,
  history,
  historyLoading,
  onHistoryOpen,
  onRowToggle,
  onScanAllToggle,
  onStartScan,
  onTargetUrlChange,
  onVulnToggle,
  phase,
  progress,
  results,
  resultsRef,
  riskStats,
  scanAll,
  scanId,
  selected,
  statusMsg,
  targetUrl,
}) {
  return (
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
            onChange={(event) => onTargetUrlChange(event.target.value)}
            placeholder="https://example.com"
            disabled={phase === "scanning"}
          />
        </label>

        <div className="option-list">
          <button
            className={`option-item ${scanAll ? "active" : ""}`}
            onClick={onScanAllToggle}
            disabled={phase === "scanning"}
          >
            <strong>Scan All</strong>
            <span>Run every available check</span>
          </button>

          {VULN_OPTIONS.map((item) => (
            <button
              key={item.id}
              className={`option-item ${selected.includes(item.id) && !scanAll ? "active" : ""}`}
              onClick={() => !scanAll && onVulnToggle(item.id)}
              disabled={phase === "scanning" || scanAll}
            >
              <strong>{item.label}</strong>
              <span>{item.desc}</span>
            </button>
          ))}
        </div>

        <div className="actions">
          <button className="button button-primary" disabled={!canStart || phase === "scanning"} onClick={onStartScan}>
            {phase === "scanning" ? "Scanning..." : "Start Scan"}
          </button>
          {phase === "scanning" && (
            <button className="button button-secondary" onClick={cancelScan}>
              Cancel
            </button>
          )}
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
            <button key={item.scan_id} className="mini-item" onClick={() => onHistoryOpen(item)}>
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

          <ResultsTable items={results} expandedRows={expandedRows} onToggleRow={onRowToggle} />
        </section>
      )}
    </div>
  );
}
