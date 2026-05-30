import React, { useEffect } from "react";
import AdminApp from "./components/admin/AdminApp";
import AdminAuthPage from "./components/admin/AdminAuthPage";
import AuthPage from "./components/auth/AuthPage";
import HistoryView from "./components/history/HistoryView";
import Topbar from "./components/layout/Topbar";
import ScanView from "./components/scan/ScanView";
import { useAdminAuth } from "./hooks/useAdminAuth";
import { useAdminPanel } from "./hooks/useAdminPanel";
import { useAuth } from "./hooks/useAuth";
import { useScanner } from "./hooks/useScanner";
import { useAdminRoute } from "./utils/navigation";
import { alertError, page, shell } from "./ui/classes";

export default function App() {
  const { onAdminRoute, isAdminLoginPath, goToAdminHome, goToAdminLogin } = useAdminRoute();
  const auth = useAuth();
  const admin = useAdminAuth();
  const scanner = useScanner(auth.token);
  const adminPanel = useAdminPanel(admin.token);

  useEffect(() => {
    if (!onAdminRoute) return;
    if (admin.user && isAdminLoginPath) {
      goToAdminHome();
    } else if (!admin.user && !isAdminLoginPath) {
      goToAdminLogin();
    }
  }, [admin.user, goToAdminHome, goToAdminLogin, isAdminLoginPath, onAdminRoute]);

  const handleAuth = async () => {
    const result = await auth.handleAuth();
    if (!result.ok || result.mode !== "login") return;
    scanner.setView("scan");
    scanner.setErrorMsg("");
    await scanner.loadHistory();
  };

  const handleLogout = async () => {
    await auth.logout();
    scanner.setView("scan");
  };

  const handleAdminLogin = async () => {
    const result = await admin.login();
    if (!result.ok) return;
    goToAdminHome();
    // Panel loads stats after admin.token updates (do not call refresh here — token is still stale).
  };

  const handleAdminLogout = async () => {
    await admin.logout();
    adminPanel.setView("overview");
    goToAdminLogin();
  };

  if (onAdminRoute) {
    if (!admin.user) {
      return (
        <AdminAuthPage
          busy={admin.busy}
          error={admin.error}
          form={admin.form}
          onFieldChange={admin.setField}
          onLogin={handleAdminLogin}
        />
      );
    }

    return <AdminApp admin={{ ...admin, logout: handleAdminLogout }} panel={adminPanel} />;
  }

  if (!auth.user) {
    return (
      <AuthPage
        authBusy={auth.authBusy}
        authError={auth.authError}
        authForm={auth.authForm}
        authMode={auth.authMode}
        authSuccess={auth.authSuccess}
        onAuth={handleAuth}
        onFieldChange={auth.setAuthField}
        onModeChange={auth.setAuthMode}
      />
    );
  }

  return (
    <div className={shell}>
      <Topbar user={auth.user} view={scanner.view} onViewChange={scanner.setView} onLogout={handleLogout} />

      <main className={page}>
        {scanner.errorMsg && <div className={alertError}>Action failed: {scanner.errorMsg}</div>}

        {scanner.view === "scan" && (
          <ScanView
            canStart={scanner.canStart}
            cancelScan={scanner.cancelScan}
            downloadReport={scanner.downloadReport}
            expandedRows={scanner.expandedRows}
            onRowToggle={(index) =>
              scanner.setExpandedRows((current) => ({ ...current, [index]: !current[index] }))
            }
            onScanAllToggle={scanner.toggleScanAll}
            onStartScan={scanner.startScan}
            onTargetUrlChange={scanner.setTargetUrl}
            onVulnToggle={scanner.toggleVuln}
            phase={scanner.phase}
            progress={scanner.progress}
            results={scanner.results}
            resultsRef={scanner.resultsRef}
            riskStats={scanner.riskStats}
            scanAll={scanner.scanAll}
            scanId={scanner.scanId}
            scanMessage={scanner.scanMessage}
            selected={scanner.selected}
            targetUrl={scanner.targetUrl}
          />
        )}

        {scanner.view === "history" && (
          <HistoryView
            downloadReport={scanner.downloadReport}
            history={scanner.history}
            historyLoading={scanner.historyLoading}
            historyResults={scanner.historyResults}
            historyRiskStats={scanner.historyRiskStats}
            onHistoryOpen={scanner.openHistoryItem}
            selectedHistory={scanner.selectedHistory}
          />
        )}
      </main>
    </div>
  );
}
