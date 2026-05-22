import React, { useMemo, useState } from "react";
import { formatDate, safeHostname } from "../../utils/format";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";
import AdminPagination from "./AdminPagination";

function buildRiskStats(results) {
  return (results || []).reduce(
    (stats, item) => {
      const key = item.risk || "Informational";
      stats[key] = (stats[key] || 0) + 1;
      return stats;
    },
    { High: 0, Medium: 0, Low: 0, Informational: 0 }
  );
}

export default function AdminScansPanel({
  userOptions,
  selectedUserId,
  scans,
  scansMeta,
  scansPage,
  scansLoading,
  selectedScan,
  actionBusy,
  onSelectUser,
  onPageChange,
  onSelectScan,
  onRemoveScan,
}) {
  const [expandedRows, setExpandedRows] = useState({});

  const selectedUser = userOptions.find((user) => String(user.id) === String(selectedUserId));

  const riskStats = useMemo(
    () => buildRiskStats(selectedScan?.results),
    [selectedScan]
  );

  const handleRemove = async (scan) => {
    const confirmed = window.confirm(`Delete scan record for ${scan.target_url}?`);
    if (!confirmed) return;
    await onRemoveScan(scan.scan_id);
  };

  return (
    <div className="history-grid admin-scans-grid">
      <section className="simple-card">
        <div className="section-head">
          <div>
            <h2>Scan records</h2>
            <p>Select a user to view their scan history.</p>
          </div>
        </div>

        <label className="field admin-user-select">
          <span>User</span>
          <select
            value={selectedUserId}
            onChange={(event) => onSelectUser(event.target.value)}
            disabled={!userOptions.length || scansLoading}
          >
            {!userOptions.length && <option value="">No users available</option>}
            {userOptions.map((user) => (
              <option key={user.id} value={String(user.id)}>
                {user.full_name} ({user.email}) — {user.scan_count} scan{user.scan_count === 1 ? "" : "s"}
              </option>
            ))}
          </select>
        </label>

        {scansLoading && <p className="muted">Loading scans...</p>}

        {!scansLoading && selectedUserId && scans.length === 0 && (
          <p className="muted">No scan records for {selectedUser?.full_name || "this user"}.</p>
        )}

        <div className="history-list">
          {scans.map((scan) => (
            <button
              key={scan.scan_id}
              type="button"
              className={`history-item ${selectedScan?.scan_id === scan.scan_id ? "active" : ""}`}
              onClick={() => onSelectScan(scan)}
            >
              <div>
                <strong>{safeHostname(scan.target_url)}</strong>
                <span>{scan.target_url}</span>
              </div>
              <div className="history-meta">
                <span>{formatDate(scan.created_at)}</span>
                <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
              </div>
            </button>
          ))}
        </div>

        <AdminPagination
          page={scansPage}
          totalPages={scansMeta.total_pages}
          total={scansMeta.total}
          disabled={scansLoading || actionBusy || !selectedUserId}
          onPageChange={onPageChange}
        />
      </section>

      <section className="simple-card">
        {selectedScan ? (
          <>
            <div className="section-head">
              <div>
                <h2>Scan report</h2>
                <p>{selectedScan.target_url}</p>
                <span className="admin-cell-sub">
                  Scanned by {selectedScan.user_name} ({selectedScan.user_email})
                </span>
              </div>
              <button
                type="button"
                className="button button-secondary admin-danger-btn"
                disabled={actionBusy}
                onClick={() => handleRemove(selectedScan)}
              >
                Delete record
              </button>
            </div>

            <div className="detail-grid">
              <div className="stat-box">
                <span>Status</span>
                <strong className={`status-badge status-${selectedScan.status}`}>{selectedScan.status}</strong>
              </div>
              <div className="stat-box">
                <span>Checks</span>
                <strong>{(selectedScan.vulnerabilities || []).join(", ") || "None"}</strong>
              </div>
              <div className="stat-box">
                <span>Findings</span>
                <strong>{selectedScan.results?.length || 0}</strong>
              </div>
              <div className="stat-box">
                <span>Updated</span>
                <strong>{formatDate(selectedScan.updated_at)}</strong>
              </div>
            </div>

            <RiskStrip stats={riskStats} />
            <ResultsTable
              items={selectedScan.results || []}
              expandedRows={expandedRows}
              onToggleRow={(index) =>
                setExpandedRows((current) => ({ ...current, [index]: !current[index] }))
              }
            />
          </>
        ) : (
          <p className="muted">Select a scan record to review findings.</p>
        )}
      </section>
    </div>
  );
}
