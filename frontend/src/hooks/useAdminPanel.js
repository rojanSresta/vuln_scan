import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../services/api";
import { buildQuery } from "../utils/query";

export const ADMIN_PAGE_SIZE = 10;

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
      if (!token) return [];
      setUsersLoading(true);
      setError("");
      try {
        const response = await apiFetch(
          `/admin/users${buildQuery({ page, page_size: ADMIN_PAGE_SIZE })}`,
          { method: "GET", token }
        );
        const payload = await response.json();
        const items = payload.items || [];
        setUsers(items);
        setUsersPage(payload.page || page);
        setUsersMeta({
          total: payload.total || 0,
          total_pages: payload.total_pages || 1,
        });
        return items;
      } catch (err) {
        setError(err.message);
        return [];
      } finally {
        setUsersLoading(false);
      }
    },
    [token]
  );

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

  const refreshManage = useCallback(async () => {
    const items = await fetchUsers(usersPage);
    const userId = selectedUserId || (items[0] ? String(items[0].id) : "");
    if (userId && !selectedUserId) {
      setSelectedUserId(userId);
    }
    if (userId) {
      await fetchScans(userId, scansPage);
    }
  }, [fetchScans, fetchUsers, scansPage, selectedUserId, usersPage]);

  useEffect(() => {
    if (!token || view !== "overview") return;
    refreshOverview();
  }, [refreshOverview, token, view]);

  useEffect(() => {
    if (!token || view !== "manage") return;
    fetchUsers(usersPage).then((items) => {
      if (!items.length) {
        setSelectedUserId("");
        return;
      }
      const stillVisible = items.some((user) => String(user.id) === String(selectedUserId));
      if (!selectedUserId || !stillVisible) {
        setSelectedUserId(String(items[0].id));
        setScansPage(1);
        setSelectedScan(null);
      }
    });
  }, [fetchUsers, selectedUserId, token, usersPage, view]);

  useEffect(() => {
    if (!token || view !== "manage" || !selectedUserId) return;
    fetchScans(selectedUserId, scansPage);
  }, [fetchScans, scansPage, selectedUserId, token, view]);

  const refresh = async () => {
    if (view === "overview") {
      await refreshOverview();
    } else if (view === "manage") {
      await refreshManage();
    }
  };

  const changeUsersPage = (page) => {
    setUsersPage(page);
    setSelectedScan(null);
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
      const nextPage = users.length === 1 && usersPage > 1 ? usersPage - 1 : usersPage;
      setUsersPage(nextPage);
      const items = await fetchUsers(nextPage);
      const nextId = items[0] ? String(items[0].id) : "";
      setSelectedUserId(nextId);
      setScansPage(1);
      if (nextId) {
        await fetchScans(nextId, 1);
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
      await fetchUsers(usersPage);
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setActionBusy(false);
    }
  };

  const openScan = async (scan) => {
    setView("manage");
    setSelectedUserId(String(scan.user_id));
    setSelectedScan(scan);
    setScansPage(1);
    setUsersPage(1);
    await fetchUsers(1);
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
    users,
    usersLoading,
    usersMeta,
    usersPage,
    view,
  };
}
