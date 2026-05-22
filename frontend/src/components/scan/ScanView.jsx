import React from "react";
import { VULN_OPTIONS } from "../../constants";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";

export default function ScanView({
  canStart,
  cancelScan,
  downloadReport,
  expandedRows,
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
  targetUrl,
}) {
  return (
    <div className="content-grid">
      <section className="simple-card full-width">
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

      {phase === "scanning" && (
        <section className="simple-card full-width">
          <div className="section-head">
            <h2>Scanning</h2>
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
