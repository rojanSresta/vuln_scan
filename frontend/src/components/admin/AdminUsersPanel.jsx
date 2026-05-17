import React from "react";
import { formatDate } from "../../utils/format";
import AdminPagination from "./AdminPagination";

export default function AdminUsersPanel({
  users,
  usersMeta,
  usersPage,
  usersLoading,
  actionBusy,
  onPageChange,
  onRemoveUser,
}) {
  const handleRemove = async (user) => {
    if (user.is_admin) return;
    const confirmed = window.confirm(
      `Remove account for ${user.email}? This deletes all scan history for this user.`
    );
    if (!confirmed) return;
    await onRemoveUser(user.id);
  };

  return (
    <section className="simple-card">
      <div className="section-head">
        <div>
          <h2>Manage users</h2>
          <p>View registered accounts and remove user access when needed.</p>
        </div>
      </div>

      {usersLoading && <p className="muted">Loading users...</p>}

      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Scans</th>
              <th>Joined</th>
              <th>Role</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.full_name}</td>
                <td>{user.email}</td>
                <td>{user.scan_count}</td>
                <td>{formatDate(user.created_at)}</td>
                <td>{user.is_admin ? "Admin" : "User"}</td>
                <td>
                  {!user.is_admin && (
                    <button
                      type="button"
                      className="button button-secondary admin-danger-btn"
                      disabled={actionBusy}
                      onClick={() => handleRemove(user)}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!usersLoading && users.length === 0 && <p className="muted">No users found.</p>}
      </div>

      <AdminPagination
        page={usersPage}
        totalPages={usersMeta.total_pages}
        total={usersMeta.total}
        disabled={usersLoading || actionBusy}
        onPageChange={onPageChange}
      />
    </section>
  );
}
