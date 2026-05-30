import React from "react";
import {
  brand,
  btnSecondary,
  sectionDesc,
  topbar,
  topbarNav,
  navPill,
  navPillActive,
} from "../../ui/classes";

export default function AdminTopbar({ user, view, onViewChange, onLogout, onRefresh, loading }) {
  return (
    <header className={topbar}>
      <div>
        <div className={brand}>WAVS Admin</div>
        <p className={sectionDesc}>System monitoring and user management</p>
      </div>

      <nav className={topbarNav}>
        <button
          type="button"
          className={view === "overview" ? navPillActive : navPill}
          onClick={() => onViewChange("overview")}
        >
          Overview
        </button>
        <button
          type="button"
          className={view === "manage" ? navPillActive : navPill}
          onClick={() => onViewChange("manage")}
        >
          Users & scans
        </button>
      </nav>

      <div className="flex flex-wrap items-center gap-3">
        <div className="text-right text-sm">
          <strong className="block text-wavs-text">{user.full_name}</strong>
          <span className="text-wavs-muted">{user.email}</span>
        </div>
        <button type="button" className={btnSecondary} onClick={onRefresh} disabled={loading}>
          Refresh
        </button>
        <button type="button" className={btnSecondary} onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  );
}
