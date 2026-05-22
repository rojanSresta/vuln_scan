import React from "react";

export default function AdminTopbar({ user, view, onViewChange, onLogout, onRefresh, loading }) {
  return (
    <header className="topbar admin-topbar">
      <div>
        <div className="brand">WAVS Admin</div>
        <p className="topbar-subtitle">System monitoring and user management</p>
      </div>

      <nav className="topbar-nav">
        <button className={view === "overview" ? "active" : ""} onClick={() => onViewChange("overview")}>
          Overview
        </button>
        <button className={view === "users" ? "active" : ""} onClick={() => onViewChange("users")}>
          Users
        </button>
        <button className={view === "scans" ? "active" : ""} onClick={() => onViewChange("scans")}>
          Scan records
        </button>
      </nav>

      <div className="topbar-user">
        <div>
          <strong>{user.full_name}</strong>
          <span>{user.email}</span>
        </div>
        <button className="button button-secondary" onClick={onRefresh} disabled={loading}>
          Refresh
        </button>
        <button className="button button-secondary" onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  );
}
