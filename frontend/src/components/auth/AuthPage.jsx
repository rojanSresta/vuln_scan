import React from "react";

export default function AuthPage({
  authBusy,
  authError,
  authForm,
  authMode,
  onAuth,
  onModeChange,
  onFieldChange,
}) {
  return (
    <div className="auth-page">
      <div className="simple-card auth-card">
        <div className="auth-header">
          <div className="brand">WAVS</div>
          <h1>Login to continue</h1>
          <p>Use your account to run scans and review saved reports.</p>
        </div>

        <div className="tabs">
          <button className={authMode === "login" ? "active" : ""} onClick={() => onModeChange("login")}>
            Login
          </button>
          <button className={authMode === "signup" ? "active" : ""} onClick={() => onModeChange("signup")}>
            Sign Up
          </button>
        </div>

        {authMode === "signup" && (
          <label className="field">
            <span>Full name</span>
            <input
              type="text"
              value={authForm.full_name}
              onChange={(event) => onFieldChange("full_name", event.target.value)}
              placeholder="Enter your full name"
            />
          </label>
        )}

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={authForm.email}
            onChange={(event) => onFieldChange("email", event.target.value)}
            placeholder="name@example.com"
          />
        </label>

        <label className="field">
          <span>Password</span>
          <input
            type="password"
            value={authForm.password}
            onChange={(event) => onFieldChange("password", event.target.value)}
            placeholder="At least 8 characters"
          />
        </label>

        {authError && <div className="alert error">{authError}</div>}

        <button className="button button-primary" onClick={onAuth} disabled={authBusy}>
          {authBusy ? "Please wait..." : authMode === "signup" ? "Create account" : "Login"}
        </button>
      </div>
    </div>
  );
}
