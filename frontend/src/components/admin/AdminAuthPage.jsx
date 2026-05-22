import React from "react";

export default function AdminAuthPage({ busy, error, form, onFieldChange, onLogin }) {
  return (
    <div className="auth-page">
      <div className="simple-card auth-card admin-auth-card">
        <div className="auth-header">
          <div className="brand">WAVS Admin</div>
          <h1>Admin sign in</h1>
          <p>Monitor users, review scan records, and manage system data.</p>
        </div>

        <label className="field">
          <span>Admin email</span>
          <input
            type="email"
            value={form.email}
            onChange={(event) => onFieldChange("email", event.target.value)}
            placeholder="admin@wavs.local"
          />
        </label>

        <label className="field">
          <span>Password</span>
          <input
            type="password"
            value={form.password}
            onChange={(event) => onFieldChange("password", event.target.value)}
            placeholder="Admin password"
          />
        </label>

        {error && <div className="alert error">{error}</div>}

        <button className="button button-primary" onClick={onLogin} disabled={busy}>
          {busy ? "Signing in..." : "Enter admin panel"}
        </button>
      </div>
    </div>
  );
}
