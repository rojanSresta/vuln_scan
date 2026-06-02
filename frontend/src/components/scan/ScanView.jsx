import React from "react";
import { VULN_OPTIONS } from "../../constants";
import {
  btnPrimary,
  btnSecondary,
  card,
  field,
  fieldLabel,
  input,
  sectionDesc,
  sectionHead,
  sectionTitle,
} from "../../ui/classes";
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
  scanMessage,
  selected,
  targetUrl,
}) {
  const optionBase =
    "w-full rounded-xl border border-wavs-border bg-wavs-soft p-4 text-left transition hover:border-wavs-accent/40 hover:bg-[#eef7f0] disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-wavs-soft";
  const optionActive =
    "border-wavs-accent bg-[#e8f4ed] ring-2 ring-wavs-accent/40 shadow-[0_12px_28px_rgba(20,108,67,0.14)]";

  return (
    <div className="space-y-6">
      <section className={card}>
        <div className={sectionHead}>
          <div>
            <h2 className={sectionTitle}>Start a new scan</h2>
            <p className={sectionDesc}>Select a target and the checks you want to run.</p>
          </div>
        </div>

        <label className={field}>
          <span className={fieldLabel}>Enter full URL (must start with http:// or https://)</span>
          <input
            className={input}
            type="text"
            value={targetUrl}
            onChange={(event) => onTargetUrlChange(event.target.value)}
            placeholder="https://example.com"
            disabled={phase === "scanning"}
          />
        </label>

        <div className="mb-5 grid gap-3 sm:grid-cols-2">
          <button
            type="button"
            className={`${optionBase} ${scanAll ? optionActive : ""}`}
            onClick={onScanAllToggle}
            disabled={phase === "scanning"}
          >
            <strong className="block text-wavs-text">Scan All</strong>
            <span className="mt-1 block text-sm text-wavs-muted">Run every available check</span>
          </button>

          {VULN_OPTIONS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`${optionBase} ${selected.includes(item.id) && !scanAll ? optionActive : ""}`}
              onClick={() => !scanAll && onVulnToggle(item.id)}
              disabled={phase === "scanning" || scanAll}
            >
              <strong className="block text-wavs-text">{item.label}</strong>
              <span className="mt-1 block text-sm text-wavs-muted">{item.desc}</span>
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className={btnPrimary}
            disabled={!canStart || phase === "scanning"}
            onClick={onStartScan}
          >
            {phase === "scanning" ? "Scanning..." : "Start Scan"}
          </button>
          {phase === "scanning" && (
            <button type="button" className={btnSecondary} onClick={cancelScan}>
              Cancel
            </button>
          )}
        </div>
      </section>

      {phase === "scanning" && (
        <section className={card}>
          <div className={`${sectionHead} !mb-3`}>
            <div className="min-w-0">
              <h2 className={sectionTitle}>Scanning</h2>
              <p className={`${sectionDesc} break-all`}>{scanMessage || "Preparing scanner..."}</p>
            </div>
            <strong className="text-lg font-semibold text-wavs-accent">{progress}%</strong>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-wavs-border">
            <div
              className="h-full rounded-full bg-wavs-accent transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </section>
      )}

      {phase === "done" && (
        <section ref={resultsRef} className={card}>
          <div className={sectionHead}>
            <div>
              <h2 className={sectionTitle}>Scan results</h2>
              <p className={sectionDesc}>{results.length} finding(s) were recorded for this run.</p>
            </div>
            {scanId && (
              <button type="button" className={btnSecondary} onClick={() => downloadReport(scanId)}>
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
