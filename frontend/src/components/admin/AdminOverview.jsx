import React from "react";
import { formatDate, safeHostname } from "../../utils/format";

export default function AdminOverview({ stats, onOpenScan }) {
  if (!stats) {
    return <p className="muted">Loading overview...</p>;
  }

  const statusEntries = Object.entries(stats.scans_by_status || {});

  return (
    <div className="admin-overview">
      <section className="admin-stat-grid">
        <article className="admin-stat-card">
          <span>Total users</span>
          <strong>{stats.total_users}</strong>
        </article>
        <article className="admin-stat-card">
          <span>Total scans</span>
          <strong>{stats.total_scans}</strong>
        </article>
        <article className="admin-stat-card">
          <span>Active sessions</span>
          <strong>{stats.active_sessions}</strong>
        </article>
      </section>

      <section className="simple-card">
        <div className="section-head">
          <div>
            <h2>Scans by status</h2>
            <p>Quick view of scan pipeline health across all accounts.</p>
          </div>
        </div>
        {statusEntries.length === 0 ? (
          <p className="muted">No scan records yet.</p>
        ) : (
          <div className="admin-status-grid">
            {statusEntries.map(([status, count]) => (
              <div key={status} className="admin-status-item">
                <span className={`status-badge status-${status}`}>{status}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="simple-card">
        <div className="section-head">
          <div>
            <h2>Recent scans</h2>
            <p>Latest website scans submitted by users.</p>
          </div>
        </div>
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>User</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {(stats.recent_scans || []).map((scan) => (
                <tr key={scan.scan_id}>
                  <td>
                    <button type="button" className="text-link" onClick={() => onOpenScan(scan)}>
                      {safeHostname(scan.target_url)}
                    </button>
                    <span className="admin-cell-sub">{scan.target_url}</span>
                  </td>
                  <td>
                    <strong>{scan.user_name}</strong>
                    <span className="admin-cell-sub">{scan.user_email}</span>
                  </td>
                  <td>
                    <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
                  </td>
                  <td>{scan.results?.length || 0}</td>
                  <td>{formatDate(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {(stats.recent_scans || []).length === 0 && <p className="muted">No scans recorded yet.</p>}
        </div>
      </section>
    </div>
  );
}
