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

export default function Topbar({ user, view, onViewChange, onLogout }) {
  return (
    <header className={topbar}>
      <div>
        <div className={brand}>WAVS</div>
        <p className={sectionDesc}>Find vulnerabilities before they find you</p>
      </div>

      <nav className={topbarNav}>
        <button
          type="button"
          className={view === "scan" ? navPillActive : navPill}
          onClick={() => onViewChange("scan")}
        >
          Scan
        </button>
        <button
          type="button"
          className={view === "history" ? navPillActive : navPill}
          onClick={() => onViewChange("history")}
        >
          History
        </button>
      </nav>

      <div className="flex flex-wrap items-center gap-3">
        <div className="text-right text-sm">
          <strong className="block text-wavs-text">{user.full_name}</strong>
          <span className="text-wavs-muted">{user.email}</span>
        </div>
        <button type="button" className={btnSecondary} onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  );
}
