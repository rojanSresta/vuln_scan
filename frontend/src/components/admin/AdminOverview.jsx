import React from "react";
import { formatDate, safeHostname } from "../../utils/format";
import { statusBadgeClass } from "../../utils/status";
import { card, muted, sectionDesc, sectionHead, sectionTitle, textLink } from "../../ui/classes";

export default function AdminOverview({ stats, onOpenScan }) {
  if (!stats) {
    return <p className={muted}>Loading overview...</p>;
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2">
        <article className="rounded-2xl border border-wavs-border bg-wavs-soft p-5">
          <span className="text-sm text-wavs-muted">Total users</span>
          <strong className="mt-2 block text-3xl font-semibold text-wavs-text">{stats.total_users}</strong>
        </article>
        <article className="rounded-2xl border border-wavs-border bg-wavs-soft p-5">
          <span className="text-sm text-wavs-muted">Total scans</span>
          <strong className="mt-2 block text-3xl font-semibold text-wavs-text">{stats.total_scans}</strong>
        </article>
      </section>

      <section className={card}>
        <div className={sectionHead}>
          <div>
            <h2 className={sectionTitle}>Recent scans</h2>
            <p className={sectionDesc}>Latest website scans submitted by users.</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-wavs-border text-wavs-muted">
                <th className="pb-3 pr-4 font-medium">Target</th>
                <th className="pb-3 pr-4 font-medium">User</th>
                <th className="pb-3 pr-4 font-medium">Status</th>
                <th className="pb-3 pr-4 font-medium">Findings</th>
                <th className="pb-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {(stats.recent_scans || []).map((scan) => (
                <tr
                  key={scan.scan_id}
                  className="border-b border-wavs-border/70 bg-wavs-soft/70 transition last:border-0 hover:bg-[#eef7f0]"
                >
                  <td className="py-3 pr-4 align-top">
                    <button type="button" className={textLink} onClick={() => onOpenScan(scan)}>
                      {safeHostname(scan.target_url)}
                    </button>
                    <span className="mt-1 block max-w-xs break-all text-xs text-wavs-muted">
                      {scan.target_url}
                    </span>
                  </td>
                  <td className="py-3 pr-4 align-top">
                    <strong className="block text-wavs-text">{scan.user_name}</strong>
                    <span className="text-xs text-wavs-muted">{scan.user_email}</span>
                  </td>
                  <td className="py-3 pr-4 align-top">
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${statusBadgeClass(scan.status)}`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-3 pr-4 align-top">{scan.results?.length || 0}</td>
                  <td className="py-3 align-top text-wavs-muted">{formatDate(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {(stats.recent_scans || []).length === 0 && <p className={`${muted} mt-4`}>No scans recorded yet.</p>}
        </div>
      </section>
    </div>
  );
}
