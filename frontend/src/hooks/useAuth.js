import { useState } from "react";
import { TOKEN_KEY } from "../constants";
import { apiClient } from "../services/api_client";
import { formatApiError } from "../utils/errors";
import { useSessionAuth } from "./useSessionAuth";

const EMPTY_AUTH_FORM = { full_name: "", email: "", password: "", confirm_password: "" };

export function useAuth() {
  const [authMode, setAuthModeState] = useState("login");
  const [authSuccess, setAuthSuccess] = useState("");

  const session = useSessionAuth({
    storageKey: TOKEN_KEY,
    mePath: "/auth/me",
    loginPath: "/auth/login",
    emptyForm: EMPTY_AUTH_FORM,
    loginErrorMessage: "Authentication failed",
  });

  const setAuthField = (field, value) => {
    setAuthSuccess("");
    session.setField(field, value);
  };

  const setAuthMode = (mode) => {
    setAuthModeState(mode);
    session.setError("");
    setAuthSuccess("");
    session.resetForm({ ...EMPTY_AUTH_FORM, email: session.form.email });
  };

  const handleAuth = async () => {
    session.setError("");
    setAuthSuccess("");

    if (authMode === "signup" && session.form.password !== session.form.confirm_password) {
      session.setError("Passwords do not match");
      return { ok: false, mode: authMode };
    }

    if (authMode === "signup") {
      try {
        const response = await apiClient.request("/auth/signup", {
          method: "POST",
          body: JSON.stringify({
            full_name: session.form.full_name,
            email: session.form.email,
            password: session.form.password,
          }),
        });
        const data = await response.json();
        setAuthModeState("login");
        session.resetForm({ ...EMPTY_AUTH_FORM, email: session.form.email });
        setAuthSuccess(data.message || "Signed up successfully. Please log in.");
        return { ok: true, mode: "signup" };
      } catch (error) {
        const message =
          error instanceof Error ? error.message : formatApiError(error, "Authentication failed");
        session.setError(message);
        return { ok: false, mode: authMode };
      }
    }

    const result = await session.login({
      email: session.form.email,
      password: session.form.password,
    });
    return { ok: result.ok, mode: "login" };
  };

  return {
    authBusy: session.busy,
    authError: session.error,
    authForm: session.form,
    authMode,
    handleAuth,
    authSuccess,
    logout: session.logout,
    setAuthField,
    setAuthMode,
    token: session.token,
    user: session.user,
  };
}
