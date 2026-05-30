import React from "react";
import { btnSecondary, muted } from "../../ui/classes";

export default function AdminPagination({ page, totalPages, total, onPageChange, disabled }) {
  if (totalPages <= 1 && total === 0) return null;

  return (
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
      <span className={muted}>
        Page {page} of {totalPages} ({total} total)
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          className={btnSecondary}
          disabled={disabled || page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <button
          type="button"
          className={btnSecondary}
          disabled={disabled || page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
