import { useEffect, useState } from "react";
import { ADMIN_TOKEN_KEY, API } from "../constants";
import { apiFetch } from "../services/api";
import { formatApiError } from "../utils/errors";

const EMPTY_FORM = { email: "", password: "" };

export function useAdminAuth() {
  const [token, setToken] = useState(() => localStorage.getItem(ADMIN_TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const setField = (field, value) => {
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
        const response = await apiFetch("/admin/me", { method: "GET", token });
        const payload = await response.json();
        if (!cancelled) {
          setUser(payload);
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem(ADMIN_TOKEN_KEY);
          setToken("");
          setUser(null);
        }
      }
    };

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const login = async () => {
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API}/admin/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      if (!response.ok) {
        const payload = await response.json();
        throw new Error(formatApiError(payload.detail, "Admin login failed"));
      }

      const data = await response.json();
      localStorage.setItem(ADMIN_TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      setForm(EMPTY_FORM);
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : formatApiError(err, "Admin login failed");
      setError(message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    try {
      if (token) {
        await apiFetch("/auth/logout", { method: "POST", token });
      }
    } catch {
      // Local cleanup is enough if the server session no longer exists.
    } finally {
      localStorage.removeItem(ADMIN_TOKEN_KEY);
      setToken("");
      setUser(null);
      setForm(EMPTY_FORM);
    }
  };

  return {
    busy,
    error,
    form,
    login,
    logout,
    setField,
    token,
    user,
  };
}
