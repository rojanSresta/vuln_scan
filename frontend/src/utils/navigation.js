import { useCallback, useEffect, useState } from "react";

export const ADMIN_LOGIN_PATH = "/admin/login";
export const ADMIN_HOME_PATH = "/admin";

export function isAdminPath(pathname = window.location.pathname) {
  return pathname === ADMIN_HOME_PATH || pathname.startsWith(`${ADMIN_HOME_PATH}/`);
}

export function isAdminLoginPath(pathname = window.location.pathname) {
  return pathname === ADMIN_LOGIN_PATH;
}

export function navigate(path) {
  if (window.location.pathname === path) return;
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function usePathname() {
  const [pathname, setPathname] = useState(() => window.location.pathname);

  useEffect(() => {
    const onChange = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onChange);
    return () => window.removeEventListener("popstate", onChange);
  }, []);

  return pathname;
}

export function useAdminRoute() {
  const pathname = usePathname();
  const onAdminRoute = isAdminPath(pathname) || isAdminLoginPath(pathname);
  const goToAdminLogin = useCallback(() => navigate(ADMIN_LOGIN_PATH), []);
  const goToAdminHome = useCallback(() => navigate(ADMIN_HOME_PATH), []);

  return { pathname, onAdminRoute, isAdminLoginPath: isAdminLoginPath(pathname), goToAdminLogin, goToAdminHome };
}
