import React from "react";
import {
  alertError,
  brand,
  btnPrimary,
  card,
  field,
  fieldLabel,
  input,
  sectionDesc,
  sectionTitle,
} from "../../ui/classes";

export default function AdminAuthPage({ busy, error, form, onFieldChange, onLogin }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className={`${card} w-full max-w-md`}>
        <div className="mb-6 text-center">
          <div className={brand}>WAVS Admin</div>
          <h1 className={sectionTitle}>Admin sign in</h1>
          <p className={sectionDesc}>Monitor users, review scan records, and manage system data.</p>
        </div>

        <label className={field}>
          <span className={fieldLabel}>Admin email</span>
          <input
            className={input}
            type="email"
            value={form.email}
            onChange={(event) => onFieldChange("email", event.target.value)}
            placeholder="admin@wavs.local"
          />
        </label>

        <label className={field}>
          <span className={fieldLabel}>Password</span>
          <input
            className={input}
            type="password"
            value={form.password}
            onChange={(event) => onFieldChange("password", event.target.value)}
            placeholder="Admin password"
          />
        </label>

        {error && <div className={alertError}>{error}</div>}

        <button type="button" className={`${btnPrimary} w-full`} onClick={onLogin} disabled={busy}>
          {busy ? "Signing in..." : "Enter admin panel"}
        </button>
      </div>
    </div>
  );
}
