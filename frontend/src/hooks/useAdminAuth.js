import { ADMIN_TOKEN_KEY } from "../constants";
import { useSessionAuth } from "./useSessionAuth";

const EMPTY_FORM = { email: "", password: "" };

export function useAdminAuth() {
  const session = useSessionAuth({
    storageKey: ADMIN_TOKEN_KEY,
    mePath: "/admin/me",
    loginPath: "/admin/login",
    emptyForm: EMPTY_FORM,
    loginErrorMessage: "Admin login failed",
  });

  const login = async () => {
    return session.login(session.form);
  };

  return {
    busy: session.busy,
    error: session.error,
    form: session.form,
    login,
    logout: session.logout,
    setField: session.setField,
    token: session.token,
    user: session.user,
  };
}
