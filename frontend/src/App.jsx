import React from "react";
import AuthPage from "./components/auth/AuthPage";
import HistoryView from "./components/history/HistoryView";
import Topbar from "./components/layout/Topbar";
import ScanView from "./components/scan/ScanView";
import { useAuth } from "./hooks/useAuth";
import { useScanner } from "./hooks/useScanner";
import "./styles/app.css";
import "./styles/auth.css";
import "./styles/history.css";
import "./styles/results.css";
import "./styles/scan.css";

export default function App() {
  const auth = useAuth();
  const scanner = useScanner(auth.token);

  const handleAuth = async () => {
    await auth.handleAuth();
    scanner.setView("scan");
    scanner.setErrorMsg("");
    await scanner.loadHistory();
  };

  const handleLogout = async () => {
    await auth.logout();
    scanner.setView("scan");
  };

  if (!auth.user) {
    return (
      <AuthPage
        authBusy={auth.authBusy}
        authError={auth.authError}
        authForm={auth.authForm}
        authMode={auth.authMode}
        onAuth={handleAuth}
        onFieldChange={auth.setAuthField}
        onModeChange={auth.setAuthMode}
      />
    );
  }

  return (
    <div className="app-shell">
      <Topbar user={auth.user} view={scanner.view} onViewChange={scanner.setView} onLogout={handleLogout} />

      <main className="page">
        {scanner.errorMsg && <div className="alert error">Action failed: {scanner.errorMsg}</div>}

        {scanner.view === "scan" && (
          <ScanView
            canStart={scanner.canStart}
            downloadReport={scanner.downloadReport}
            expandedRows={scanner.expandedRows}
            history={scanner.history}
            historyLoading={scanner.historyLoading}
            onHistoryOpen={scanner.openHistoryItem}
            onReset={scanner.resetScanState}
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
            selected={scanner.selected}
            statusMsg={scanner.statusMsg}
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
