import React from "react";
import { formatDate, safeHostname } from "../../utils/format";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";

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
              onClick={() => onHistoryOpen(item)}
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
  );
}
