import React, { useMemo, useState } from "react";
import { formatDate, safeHostname } from "../../utils/format";
import { buildRiskStats } from "../../utils/risk";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";
import AdminPagination from "./AdminPagination";

export default function AdminManagePanel({
  users,
  usersMeta,
  usersPage,
  usersLoading,
  selectedUserId,
  scans,
  scansMeta,
  scansPage,
  scansLoading,
  selectedScan,
  actionBusy,
  onSelectUser,
  onUsersPageChange,
  onScansPageChange,
  onSelectScan,
  onRemoveUser,
  onRemoveScan,
}) {
  const [expandedRows, setExpandedRows] = useState({});

  const riskStats = useMemo(
    () => buildRiskStats(selectedScan?.results),
    [selectedScan]
  );

  const selectedUser = users.find((user) => String(user.id) === String(selectedUserId));

  const handleRemoveUser = async (user) => {
    if (user.is_admin) return;
    const confirmed = window.confirm(
      `Remove account for ${user.email}? This deletes all scan history for this user.`
    );
    if (!confirmed) return;
    await onRemoveUser(user.id);
  };

  const handleRemoveScan = async (scan) => {
    const confirmed = window.confirm(`Delete scan record for ${scan.target_url}?`);
    if (!confirmed) return;
    await onRemoveScan(scan.scan_id);
  };

  return (
    <div className="admin-manage-layout">
      <section className="simple-card">
        <div className="section-head">
          <div>
            <h2>Users & scan records</h2>
            <p>Select a user to view and manage their scans. Remove test accounts (e.g. old signups) with Remove.</p>
          </div>
        </div>

        {usersLoading && <p className="muted">Loading users...</p>}

        <div className="admin-table-wrap">
          <table className="admin-table admin-users-select-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Scans</th>
                <th>Joined</th>
                <th>Role</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelected = String(user.id) === String(selectedUserId);
                return (
                  <tr
                    key={user.id}
                    className={isSelected ? "admin-user-row-selected" : "admin-user-row"}
                    onClick={() => onSelectUser(String(user.id))}
                  >
                    <td>{user.full_name}</td>
                    <td>{user.email}</td>
                    <td>{user.scan_count}</td>
                    <td>{formatDate(user.created_at)}</td>
                    <td>{user.is_admin ? "Admin" : "User"}</td>
                    <td>
                      {!user.is_admin && (
                        <button
                          type="button"
                          className="button button-secondary admin-danger-btn"
                          disabled={actionBusy}
                          onClick={(event) => {
                            event.stopPropagation();
                            handleRemoveUser(user);
                          }}
                        >
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!usersLoading && users.length === 0 && <p className="muted">No users found.</p>}
        </div>

        <AdminPagination
          page={usersPage}
          totalPages={usersMeta.total_pages}
          total={usersMeta.total}
          disabled={usersLoading || actionBusy}
          onPageChange={onUsersPageChange}
        />
      </section>

      <div className="history-grid admin-scans-grid">
        <section className="simple-card">
          <div className="section-head">
            <div>
              <h2>Scan history</h2>
              <p>
                {selectedUser
                  ? `Scans for ${selectedUser.full_name} (${selectedUser.email})`
                  : "Select a user from the table above."}
              </p>
            </div>
          </div>

          {scansLoading && <p className="muted">Loading scans...</p>}

          {!scansLoading && selectedUserId && scans.length === 0 && (
            <p className="muted">No scan records for this user.</p>
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
            onPageChange={onScansPageChange}
          />
        </section>

        <section className="simple-card">
          {selectedScan ? (
            <>
              <div className="section-head">
                <div>
                  <h2>Scan report</h2>
                  <p>{selectedScan.target_url}</p>
                </div>
                <button
                  type="button"
                  className="button button-secondary admin-danger-btn"
                  disabled={actionBusy}
                  onClick={() => handleRemoveScan(selectedScan)}
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
            <p className="muted">Select a scan to review findings.</p>
          )}
        </section>
      </div>
    </div>
  );
}
