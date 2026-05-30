import React from "react";
import { alertError, muted, page, shell } from "../../ui/classes";
import AdminManagePanel from "./AdminManagePanel";
import AdminOverview from "./AdminOverview";
import AdminTopbar from "./AdminTopbar";

export default function AdminApp({ admin, panel }) {
  return (
    <div className={shell}>
      <AdminTopbar
        user={admin.user}
        view={panel.view}
        loading={panel.loading}
        onViewChange={panel.setView}
        onRefresh={panel.refresh}
        onLogout={admin.logout}
      />

      <main className={page}>
        {panel.error && <div className={alertError}>Action failed: {panel.error}</div>}
        {panel.loading && <p className={`${muted} mb-4`}>Refreshing data...</p>}

        {panel.view === "overview" && <AdminOverview stats={panel.stats} onOpenScan={panel.openScan} />}

        {panel.view === "manage" && (
          <AdminManagePanel
            users={panel.users}
            usersMeta={panel.usersMeta}
            usersPage={panel.usersPage}
            usersLoading={panel.usersLoading}
            selectedUserId={panel.selectedUserId}
            scans={panel.scans}
            scansMeta={panel.scansMeta}
            scansPage={panel.scansPage}
            scansLoading={panel.scansLoading}
            selectedScan={panel.selectedScan}
            actionBusy={panel.actionBusy}
            onSelectUser={panel.changeSelectedUser}
            onUsersPageChange={panel.changeUsersPage}
            onScansPageChange={panel.changeScansPage}
            onSelectScan={panel.setSelectedScan}
            onRemoveUser={panel.removeUser}
            onRemoveScan={panel.removeScan}
          />
        )}
      </main>
    </div>
  );
}
