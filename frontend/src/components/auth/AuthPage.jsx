import React from "react";
import { useState } from "react";

function EyeIcon({ open }) {
  if (open) {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path
          d="M2.25 12s3.75-6.75 9.75-6.75S21.75 12 21.75 12 18 18.75 12 18.75 2.25 12 2.25 12Z"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle
          cx="12"
          cy="12"
          r="3"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
        />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M3 3l18 18"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M10.585 10.586A2 2 0 0 0 13.414 13.415"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M9.88 5.09A10.94 10.94 0 0 1 12 4.875c6 0 9.75 7.125 9.75 7.125a17.43 17.43 0 0 1-4.358 5.143"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M6.228 6.227C3.97 7.76 2.25 12 2.25 12s3.75 7.125 9.75 7.125a10.77 10.77 0 0 0 3.318-.522"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function AuthPage({
  authBusy,
  authError,
  authForm,
  authMode,
  authSuccess,
  onAuth,
  onModeChange,
  onFieldChange,
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

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
          <div className="password-input">
            <input
              type={showPassword ? "text" : "password"}
              value={authForm.password}
              onChange={(event) => onFieldChange("password", event.target.value)}
              placeholder="At least 8 characters"
            />
            <button
              type="button"
              className="password-toggle"
              aria-label={showPassword ? "Hide password" : "Show password"}
              onClick={() => setShowPassword((current) => !current)}
            >
              <EyeIcon open={showPassword} />
            </button>
          </div>
        </label>

        {authMode === "signup" && (
          <label className="field">
            <span>Confirm password</span>
            <div className="password-input">
              <input
                type={showConfirmPassword ? "text" : "password"}
                value={authForm.confirm_password}
                onChange={(event) => onFieldChange("confirm_password", event.target.value)}
                placeholder="Re-enter your password"
              />
              <button
                type="button"
                className="password-toggle"
                aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                onClick={() => setShowConfirmPassword((current) => !current)}
              >
                <EyeIcon open={showConfirmPassword} />
              </button>
            </div>
          </label>
        )}

        {authSuccess && <div className="alert success">{authSuccess}</div>}
        {authError && <div className="alert error">{authError}</div>}

        <button className="button button-primary" onClick={onAuth} disabled={authBusy}>
          {authBusy ? "Please wait..." : authMode === "signup" ? "Create account" : "Login"}
        </button>
      </div>
    </div>
  );
}
