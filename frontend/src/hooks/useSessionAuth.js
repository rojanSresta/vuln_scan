import { useEffect, useState } from "react";
import { apiClient } from "../services/api_client";
import { formatApiError } from "../utils/errors";

/**
 * Shared token + /me bootstrap for user and admin sessions.
 * Keeps login UI separate while avoiding duplicate auth logic.
 */
export function useSessionAuth({ storageKey, mePath, loginPath, emptyForm, loginErrorMessage }) {
  const [token, setToken] = useState(() => localStorage.getItem(storageKey) || "");
  const [user, setUser] = useState(null);
  const [form, setForm] = useState(emptyForm);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const setField = (field, value) => {
    setError("");
    setForm((current) => ({ ...current, [field]: value }));
  };

  useEffect(() => {
    if (!token) {
      setUser(null);
      return undefined;
    }

    let cancelled = false;
    const bootstrap = async () => {
      try {
        const response = await apiClient.request(mePath, { method: "GET", token });
        const payload = await response.json();
        if (!cancelled) {
          setUser(payload);
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem(storageKey);
          setToken("");
          setUser(null);
        }
      }
    };

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [token, storageKey, mePath]);

  const login = async (body) => {
    setBusy(true);
    setError("");
    try {
      const response = await apiClient.request(loginPath, {
        method: "POST",
        body: JSON.stringify(body),
      });
      const data = await response.json();
      localStorage.setItem(storageKey, data.token);
      setToken(data.token);
      setUser(data.user);
      setForm(emptyForm);
      return { ok: true, data };
    } catch (err) {
      const message = err instanceof Error ? err.message : formatApiError(err, loginErrorMessage);
      setError(message);
      return { ok: false };
    } finally {
      setBusy(false);
    }
  };

  const logout = async (logoutPath = "/auth/logout") => {
    try {
      if (token) {
        await apiClient.request(logoutPath, { method: "POST", token });
      }
    } catch {
      // Local cleanup is enough if the server session no longer exists.
    } finally {
      localStorage.removeItem(storageKey);
      setToken("");
      setUser(null);
      setForm(emptyForm);
    }
  };

  const resetForm = (nextForm) => {
    setError("");
    setForm(nextForm);
  };

  return {
    busy,
    error,
    form,
    login,
    logout,
    resetForm,
    setField,
    setError,
    token,
    user,
  };
}
