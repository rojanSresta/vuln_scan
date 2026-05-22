import React from "react";

export default function Topbar({ user, view, onViewChange, onLogout }) {
  return (
    <header className="topbar">
      <div>
        <div className="brand">WAVS</div>
        <p className="topbar-subtitle">Find vulnerabilities before they find you</p>
      </div>

      <nav className="topbar-nav">
        <button className={view === "scan" ? "active" : ""} onClick={() => onViewChange("scan")}>
          Scan
        </button>
        <button className={view === "history" ? "active" : ""} onClick={() => onViewChange("history")}>
          History
        </button>
      </nav>

      <div className="topbar-user">
        <div>
          <strong>{user.full_name}</strong>
          <span>{user.email}</span>
        </div>
        <button className="button button-secondary" onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  );
}
