import React, { useMemo, useState } from "react";
import { formatDate, safeHostname } from "../../utils/format";
import { buildRiskStats } from "../../utils/risk";
import { statusBadgeClass } from "../../utils/status";
import {
  btnDanger,
  btnSecondary,
  card,
  muted,
  sectionDesc,
  sectionHead,
  sectionTitle,
} from "../../ui/classes";
import ResultsTable from "../common/ResultsTable";
import RiskStrip from "../common/RiskStrip";
import AdminPagination from "./AdminPagination";

const historyItemBase =
  "w-full rounded-xl border border-wavs-border bg-wavs-soft p-4 text-left transition hover:border-wavs-accent/40 hover:bg-[#eef7f0]";
const historyItemActive =
  "border-wavs-accent bg-[#e8f4ed] ring-2 ring-wavs-accent/25 shadow-[0_12px_28px_rgba(20,108,67,0.14)]";

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

  const riskStats = useMemo(() => buildRiskStats(selectedScan?.results), [selectedScan]);
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
    <div className="space-y-6">
      <section className={card}>
        <div className={sectionHead}>
          <div>
            <h2 className={sectionTitle}>Users & scan records</h2>
            <p className={sectionDesc}>
              Select a user to view and manage their scans. Remove test accounts (e.g. old signups) with
              Remove.
            </p>
          </div>
        </div>

        {usersLoading && <p className={muted}>Loading users...</p>}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-wavs-border text-wavs-muted">
                <th className="pb-3 pr-4 font-medium pl-3">Name</th>
                <th className="pb-3 pr-4 font-medium">Email</th>
                <th className="pb-3 pr-4 font-medium">Scans</th>
                <th className="pb-3 pr-4 font-medium">Joined</th>
                <th className="pb-3 pr-4 font-medium">Role</th>
                <th className="pb-3 font-medium" />
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelected = String(user.id) === String(selectedUserId);
                return (
                  <tr
                    key={user.id}
                    className={`cursor-pointer border-b border-wavs-border/70 transition last:border-0 ${
                      isSelected
                        ? "bg-[#e8f4ed] shadow-[inset_4px_0_0_#146c43]"
                        : "hover:bg-wavs-soft"
                    }`}
                    onClick={() => onSelectUser(String(user.id))}
                  >
                    <td className="py-3 pr-4 pl-3">{user.full_name}</td>
                    <td className="py-3 pr-4">{user.email}</td>
                    <td className="py-3 pr-4">{user.scan_count}</td>
                    <td className="py-3 pr-4 text-wavs-muted">{formatDate(user.created_at)}</td>
                    <td className="py-3 pr-4">{user.is_admin ? "Admin" : "User"}</td>
                    <td className="py-3">
                      {!user.is_admin && (
                        <button
                          type="button"
                          className={btnDanger}
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
          {!usersLoading && users.length === 0 && <p className={`${muted} mt-4`}>No users found.</p>}
        </div>

        <AdminPagination
          page={usersPage}
          totalPages={usersMeta.total_pages}
          total={usersMeta.total}
          disabled={usersLoading || actionBusy}
          onPageChange={onUsersPageChange}
        />
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className={card}>
          <div className={sectionHead}>
            <div>
              <h2 className={sectionTitle}>Scan history</h2>
              <p className={sectionDesc}>
                {selectedUser
                  ? `Scans for ${selectedUser.full_name} (${selectedUser.email})`
                  : "Select a user from the table above."}
              </p>
            </div>
          </div>

          {scansLoading && <p className={muted}>Loading scans...</p>}
          {!scansLoading && selectedUserId && scans.length === 0 && (
            <p className={muted}>No scan records for this user.</p>
          )}

          <div className="space-y-3">
            {scans.map((scan) => (
              <button
                key={scan.scan_id}
                type="button"
                className={`${historyItemBase} ${
                  selectedScan?.scan_id === scan.scan_id ? historyItemActive : ""
                }`}
                onClick={() => onSelectScan(scan)}
              >
                <div>
                  <strong className="block text-wavs-text">{safeHostname(scan.target_url)}</strong>
                  <span className="mt-1 block break-all text-sm text-wavs-muted">{scan.target_url}</span>
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
                  <span className="text-wavs-muted">{formatDate(scan.created_at)}</span>
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${statusBadgeClass(scan.status)}`}
                  >
                    {scan.status}
                  </span>
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

        <section className={card}>
          {selectedScan ? (
            <>
              <div className={sectionHead}>
                <div>
                  <h2 className={sectionTitle}>Scan report</h2>
                  <p className={`${sectionDesc} break-all`}>{selectedScan.target_url}</p>
                </div>
                <button
                  type="button"
                  className={btnDanger}
                  disabled={actionBusy}
                  onClick={() => handleRemoveScan(selectedScan)}
                >
                  Delete record
                </button>
              </div>

              <div className="mb-5 grid gap-3 sm:grid-cols-2">
                <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                  <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                    Status
                  </span>
                  <span
                    className={`mt-2 inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${statusBadgeClass(selectedScan.status)}`}
                  >
                    {selectedScan.status}
                  </span>
                </div>
                <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                  <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                    Checks
                  </span>
                  <strong className="mt-1 block text-sm text-wavs-text">
                    {(selectedScan.vulnerabilities || []).join(", ") || "None"}
                  </strong>
                </div>
                <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                  <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                    Findings
                  </span>
                  <strong className="mt-1 block text-sm text-wavs-text">
                    {selectedScan.results?.length || 0}
                  </strong>
                </div>
                <div className="rounded-xl border border-wavs-border bg-wavs-soft p-4">
                  <span className="block text-xs font-medium uppercase tracking-wide text-wavs-muted">
                    Updated
                  </span>
                  <strong className="mt-1 block text-sm text-wavs-text">
                    {formatDate(selectedScan.updated_at)}
                  </strong>
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
            <p className={muted}>Select a scan to review findings.</p>
          )}
        </section>
      </div>
    </div>
  );
}
