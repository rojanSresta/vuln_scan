import { useEffect, useRef, useState } from "react";
import { apiFetch } from "../services/api";
import { buildRiskStats } from "../utils/risk";

export function useScanner(token) {
  const [view, setView] = useState("scan");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistory, setSelectedHistory] = useState(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [selected, setSelected] = useState([]);
  const [scanAll, setScanAll] = useState(false);
  const [phase, setPhase] = useState("idle");
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanMessage, setScanMessage] = useState("");
  const [results, setResults] = useState([]);
  const [errorMsg, setErrorMsg] = useState("");
  const [expandedRows, setExpandedRows] = useState({});
  const pollRef = useRef(null);
  const resultsRef = useRef(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const resetScanState = () => {
    stopPolling();
    setPhase("idle");
    setScanId(null);
    setProgress(0);
    setScanMessage("");
    setResults([]);
    setErrorMsg("");
    setExpandedRows({});
  };

  const cancelScan = async () => {
    if (!scanId || phase !== "scanning") return;

    stopPolling();
    try {
      const response = await apiFetch(`/scan/cancel/${scanId}`, { method: "POST", token });
      const payload = await response.json();
      setProgress(payload.progress ?? 0);
      setScanMessage(payload.message || "");
      setPhase("cancelled");
      setResults([]);
      await loadHistory(scanId);
    } catch (error) {
      setErrorMsg(error.message);
      setPhase("error");
    }
  };

  const loadHistory = async (preferredScanId = null) => {
    if (!token) return;
    setHistoryLoading(true);
    try {
      const response = await apiFetch("/history", { method: "GET", token });
      const payload = await response.json();
      const items = payload.items || [];
      setHistory(items);

      if (preferredScanId) {
        const matched = items.find((item) => item.scan_id === preferredScanId);
        setSelectedHistory(matched || items[0] || null);
      } else {
        setSelectedHistory((current) => {
          if (!items.length) return null;
          return items.find((item) => item.scan_id === current?.scan_id) || items[0];
        });
      }
    } catch (error) {
      setErrorMsg(error.message);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (!token) {
      setHistory([]);
      setSelectedHistory(null);
      resetScanState();
      return;
    }
    loadHistory();
  }, [token]);

  useEffect(() => () => stopPolling(), []);

  const toggleVuln = (id) => {
    setSelected((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  };

  const toggleScanAll = () => {
    setScanAll((current) => {
      if (!current) {
        setSelected([]);
      }
      return !current;
    });
  };

  const pollStatus = async (id) => {
    try {
      const statusResponse = await apiFetch(`/scan/status/${id}`, { method: "GET", token });
      const statusData = await statusResponse.json();
      setProgress(statusData.progress);
      setScanMessage(statusData.message || "");

      if (statusData.status === "done") {
        stopPolling();
        const resultsResponse = await apiFetch(`/scan/results/${id}`, { method: "GET", token });
        const resultData = await resultsResponse.json();
        setResults(resultData.results || []);
        setPhase("done");
        await loadHistory(id);
        setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 200);
      } else if (statusData.status === "cancelled") {
        stopPolling();
        setResults([]);
        setPhase("cancelled");
        await loadHistory(id);
      } else if (statusData.status === "error") {
        stopPolling();
        setErrorMsg(statusData.message);
        setPhase("error");
        await loadHistory(id);
      }
    } catch (error) {
      stopPolling();
      setErrorMsg(error.message);
      setPhase("error");
    }
  };

  const startScan = async () => {
    setPhase("scanning");
    setProgress(0);
    setScanMessage("Preparing scanner...");
    setResults([]);
    setErrorMsg("");
    setExpandedRows({});

    try {
      const response = await apiFetch("/scan/start", {
        method: "POST",
        token,
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          vulnerabilities: scanAll ? ["scan_all"] : selected,
        }),
      });
      const payload = await response.json();
      setScanId(payload.scan_id);
      pollRef.current = setInterval(() => pollStatus(payload.scan_id), 3000);
      await loadHistory(payload.scan_id);
    } catch (error) {
      setErrorMsg(error.message);
      setPhase("error");
    }
  };

  const downloadReport = async (reportScanId) => {
    try {
      const response = await apiFetch(`/scan/report/${reportScanId}`, { method: "GET", token });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `vuln_report_${reportScanId.slice(0, 8)}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setErrorMsg(error.message);
    }
  };

  const openHistoryItem = async (item) => {
    setView("history");
    try {
      const response = await apiFetch(`/history/${item.scan_id}`, { method: "GET", token });
      const payload = await response.json();
      setSelectedHistory(payload);
    } catch (error) {
      setErrorMsg(error.message);
    }
  };

  const canStart = /^https?:\/\/.+/.test(targetUrl.trim()) && (scanAll || selected.length > 0);

  const riskStats = buildRiskStats(results);
  const historyResults = selectedHistory?.results || [];
  const historyRiskStats = buildRiskStats(historyResults);

  return {
    canStart,
    cancelScan,
    downloadReport,
    errorMsg,
    expandedRows,
    history,
    historyLoading,
    historyResults,
    historyRiskStats,
    loadHistory,
    openHistoryItem,
    phase,
    progress,
    resetScanState,
    results,
    resultsRef,
    riskStats,
    scanMessage,
    scanAll,
    scanId,
    selected,
    selectedHistory,
    setErrorMsg,
    setExpandedRows,
    setSelectedHistory,
    setTargetUrl,
    setView,
    startScan,
    targetUrl,
    toggleScanAll,
    toggleVuln,
    view,
  };
}
