import React from "react";
import { formatDate, safeHostname } from "../../utils/format";
import { statusBadgeClass } from "../../utils/status";
import {
  btnSecondary,
  card,
  muted,
  sectionDesc,
  sectionHead,
  sectionTitle,
} from "../../ui/classes";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";

const historyItemBase =
  "w-full rounded-xl border border-wavs-border bg-white p-4 text-left transition hover:border-wavs-accent/30";
const historyItemActive = "border-wavs-accent bg-wavs-accent/5 ring-1 ring-wavs-accent/20";

export default function HistoryView({
  downloadReport,
  history,
  historyLoading,
  historyResults,
  historyRiskStats,
  onHistoryOpen,
  selectedHistory,
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section className={card}>
        <div className={sectionHead}>
          <div>
            <h2 className={sectionTitle}>History</h2>
            <p className={sectionDesc}>Open any previous scan to view details or download the report again.</p>
          </div>
        </div>

        <div className="space-y-3">
          {historyLoading && <p className={muted}>Loading history...</p>}
          {!historyLoading && history.length === 0 && <p className={muted}>No scan history yet.</p>}
          {history.map((item) => (
            <button
              key={item.scan_id}
              type="button"
              className={`${historyItemBase} ${
                selectedHistory?.scan_id === item.scan_id ? historyItemActive : ""
              }`}
              onClick={() => onHistoryOpen(item)}
            >
              <div>
                <strong className="block text-wavs-text">{safeHostname(item.target_url)}</strong>
                <span className="mt-1 block break-all text-sm text-wavs-muted">{item.target_url}</span>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="text-wavs-muted">{formatDate(item.created_at)}</span>
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${statusBadgeClass(item.status)}`}
                >
                  {item.status}
                </span>
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className={card}>
        {selectedHistory ? (
          <>
            <div className={sectionHead}>
              <div>
                <h2 className={sectionTitle}>Scan detail</h2>
                <p className={`${sectionDesc} break-all`}>{selectedHistory.target_url}</p>
              </div>
              {selectedHistory.report_available && (
                <button
                  type="button"
                  className={btnSecondary}
                  onClick={() => downloadReport(selectedHistory.scan_id)}
                >
                  Download Again
                </button>
              )}
            </div>

            <div className="mb-5 grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                  Scan ID
                </span>
                <strong className="mt-1 block break-all text-sm text-wavs-text">
                  {selectedHistory.scan_id}
                </strong>
              </div>
              <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                  Checks
                </span>
                <strong className="mt-1 block text-sm text-wavs-text">
                  {(selectedHistory.vulnerabilities || []).join(", ") || "Not available"}
                </strong>
              </div>
            </div>

            <RiskStrip stats={historyRiskStats} />
            <ResultsTable items={historyResults} expandedRows={{}} onToggleRow={() => {}} readOnly />
          </>
        ) : (
          <p className={muted}>Choose a saved scan to inspect its details.</p>
        )}
      </section>
    </div>
  );
}
