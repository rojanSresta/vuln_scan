import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../services/api";

export const ADMIN_PAGE_SIZE = 10;

function buildQuery(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  });
  const query = search.toString();
  return query ? `?${query}` : "";
}

export function useAdminPanel(token) {
  const [view, setView] = useState("overview");
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [error, setError] = useState("");

  const [users, setUsers] = useState([]);
  const [usersPage, setUsersPage] = useState(1);
  const [usersMeta, setUsersMeta] = useState({ total: 0, total_pages: 1 });
  const [usersLoading, setUsersLoading] = useState(false);

  const [userOptions, setUserOptions] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [scans, setScans] = useState([]);
  const [scansPage, setScansPage] = useState(1);
  const [scansMeta, setScansMeta] = useState({ total: 0, total_pages: 1 });
  const [scansLoading, setScansLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);

  const loadStats = useCallback(async () => {
    const response = await apiFetch("/admin/stats", { method: "GET", token });
    return response.json();
  }, [token]);

  const fetchUsers = useCallback(
    async (page) => {
      if (!token) return;
      setUsersLoading(true);
      setError("");
      try {
        const response = await apiFetch(
          `/admin/users${buildQuery({ page, page_size: ADMIN_PAGE_SIZE })}`,
          { method: "GET", token }
        );
        const payload = await response.json();
        setUsers(payload.items || []);
        setUsersPage(payload.page || page);
        setUsersMeta({
          total: payload.total || 0,
          total_pages: payload.total_pages || 1,
        });
      } catch (err) {
        setError(err.message);
      } finally {
        setUsersLoading(false);
      }
    },
    [token]
  );

  const fetchUserOptions = useCallback(async () => {
    if (!token) return [];
    const response = await apiFetch("/admin/users/options", { method: "GET", token });
    const payload = await response.json();
    const items = payload.items || [];
    setUserOptions(items);
    return items;
  }, [token]);

  const fetchScans = useCallback(
    async (userId, page) => {
      if (!token || !userId) {
        setScans([]);
        setScansMeta({ total: 0, total_pages: 1 });
        return;
      }
      setScansLoading(true);
      setError("");
      try {
        const response = await apiFetch(
          `/admin/scans${buildQuery({ user_id: userId, page, page_size: ADMIN_PAGE_SIZE })}`,
          { method: "GET", token }
        );
        const payload = await response.json();
        setScans(payload.items || []);
        setScansPage(payload.page || page);
        setScansMeta({
          total: payload.total || 0,
          total_pages: payload.total_pages || 1,
        });
      } catch (err) {
        setError(err.message);
      } finally {
        setScansLoading(false);
      }
    },
    [token]
  );

  const refreshOverview = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      setStats(await loadStats());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [loadStats, token]);

  useEffect(() => {
    if (!token || view !== "overview") return;
    refreshOverview();
  }, [refreshOverview, token, view]);

  useEffect(() => {
    if (!token || view !== "users") return;
    fetchUsers(usersPage);
  }, [fetchUsers, token, usersPage, view]);

  useEffect(() => {
    if (!token || view !== "scans") return;
    fetchUserOptions().then((options) => {
      if (!options.length) {
        setSelectedUserId("");
        return;
      }
      setSelectedUserId((current) => current || String(options[0].id));
    });
  }, [fetchUserOptions, token, view]);

  useEffect(() => {
    if (!token || view !== "scans" || !selectedUserId) return;
    fetchScans(selectedUserId, scansPage);
  }, [fetchScans, scansPage, selectedUserId, token, view]);

  const refresh = async () => {
    if (view === "overview") {
      await refreshOverview();
    } else if (view === "users") {
      await fetchUsers(usersPage);
    } else if (view === "scans") {
      const options = await fetchUserOptions();
      const userId = selectedUserId || (options[0] ? String(options[0].id) : "");
      if (userId) {
        await fetchScans(userId, scansPage);
      }
    }
  };

  const changeUsersPage = (page) => {
    setUsersPage(page);
  };

  const changeScansPage = (page) => {
    setScansPage(page);
    setSelectedScan(null);
  };

  const changeSelectedUser = (userId) => {
    setSelectedUserId(userId);
    setScansPage(1);
    setSelectedScan(null);
  };

  const removeUser = async (userId) => {
    setActionBusy(true);
    setError("");
    try {
      await apiFetch(`/admin/users/${userId}`, { method: "DELETE", token });
      if (String(selectedUserId) === String(userId)) {
        setSelectedUserId("");
        setSelectedScan(null);
        setScans([]);
      }
      const options = await fetchUserOptions();
      if (view === "users") {
        const nextPage = users.length === 1 && usersPage > 1 ? usersPage - 1 : usersPage;
        setUsersPage(nextPage);
        await fetchUsers(nextPage);
      }
      if (view === "scans") {
        const nextId = options[0] ? String(options[0].id) : "";
        setSelectedUserId(nextId);
        setScansPage(1);
        if (nextId) {
          await fetchScans(nextId, 1);
        }
      }
      if (view === "overview") {
        await refreshOverview();
      }
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setActionBusy(false);
    }
  };

  const removeScan = async (scanId) => {
    setActionBusy(true);
    setError("");
    try {
      await apiFetch(`/admin/scans/${scanId}`, { method: "DELETE", token });
      if (selectedScan?.scan_id === scanId) {
        setSelectedScan(null);
      }
      if (selectedUserId) {
        const nextPage = scans.length === 1 && scansPage > 1 ? scansPage - 1 : scansPage;
        setScansPage(nextPage);
        await fetchScans(selectedUserId, nextPage);
      }
      if (view === "overview") {
        await refreshOverview();
      }
      await fetchUserOptions();
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setActionBusy(false);
    }
  };

  const openScan = async (scan) => {
    setView("scans");
    setSelectedUserId(String(scan.user_id));
    setSelectedScan(scan);
    setScansPage(1);
    await fetchUserOptions();
    await fetchScans(String(scan.user_id), 1);
  };

  return {
    actionBusy,
    changeScansPage,
    changeSelectedUser,
    changeUsersPage,
    error,
    loading: loading || usersLoading || scansLoading,
    openScan,
    refresh,
    removeScan,
    removeUser,
    scans,
    scansLoading,
    scansMeta,
    scansPage,
    selectedScan,
    selectedUserId,
    setSelectedScan,
    setView,
    stats,
    userOptions,
    users,
    usersLoading,
    usersMeta,
    usersPage,
    view,
  };
}
