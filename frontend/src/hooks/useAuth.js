import { useEffect, useState } from "react";
import { TOKEN_KEY, API } from "../constants";
import { apiFetch } from "../services/api";
import { formatApiError } from "../utils/errors";

const EMPTY_AUTH_FORM = { full_name: "", email: "", password: "" };

export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState(EMPTY_AUTH_FORM);
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);

  const setAuthField = (field, value) => {
    setAuthForm((current) => ({ ...current, [field]: value }));
  };

  const fetchCurrentUser = async (currentToken) => {
    const response = await apiFetch("/auth/me", { method: "GET", token: currentToken });
    return response.json();
  };

  useEffect(() => {
    if (!token) {
      setUser(null);
      return undefined;
    }

    let cancelled = false;
    const bootstrap = async () => {
      try {
        const payload = await fetchCurrentUser(token);
        if (!cancelled) {
          setUser(payload);
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem(TOKEN_KEY);
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

  const handleAuth = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      const endpoint = authMode === "signup" ? "/auth/signup" : "/auth/login";
      const payload =
        authMode === "signup"
          ? authForm
          : { email: authForm.email, password: authForm.password };

      const response = await fetch(`${API}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorPayload = await response.json();
        throw new Error(formatApiError(errorPayload.detail, "Authentication failed"));
      }

      const data = await response.json();
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      setAuthForm(EMPTY_AUTH_FORM);
      setAuthError("");
      return true;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : formatApiError(error, "Authentication failed");
      setAuthError(message);
      return false;
    } finally {
      setAuthBusy(false);
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
      localStorage.removeItem(TOKEN_KEY);
      setToken("");
      setUser(null);
      setAuthForm(EMPTY_AUTH_FORM);
    }
  };

  return {
    authBusy,
    authError,
    authForm,
    authMode,
    handleAuth,
    logout,
    setAuthField,
    setAuthMode,
    token,
    user,
  };
}
