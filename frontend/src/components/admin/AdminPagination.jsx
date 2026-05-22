import React from "react";

export default function AdminPagination({ page, totalPages, total, onPageChange, disabled }) {
  if (totalPages <= 1 && total === 0) return null;

  return (
    <div className="admin-pagination">
      <span className="muted">
        Page {page} of {totalPages} ({total} total)
      </span>
      <div className="admin-pagination-actions">
        <button
          type="button"
          className="button button-secondary"
          disabled={disabled || page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <button
          type="button"
          className="button button-secondary"
          disabled={disabled || page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
