import React from "react";
import { RISK_META } from "../../constants";
import { card, muted, riskPill, textLink } from "../../ui/classes";

export default function ResultsTable({ items, expandedRows, onToggleRow, readOnly = false }) {
  if (!items.length) {
    return <p className={muted}>No findings were recorded for this scan.</p>;
  }

  return (
    <div className="space-y-3">
      {items.map((item, index) => {
        const expanded = !!expandedRows[index];
        const meta = RISK_META[item.risk] || RISK_META.Informational;

        return (
          <div key={`${item.name}-${index}`} className={`${card} !p-4`}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <strong className="block text-wavs-text">{item.name}</strong>
                <p className="mt-1 text-sm text-wavs-muted">{item.explanation}</p>
              </div>
              <span className={`${riskPill} shrink-0 ${meta.className}`}>{item.risk}</span>
            </div>

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm text-wavs-muted">
              <span className="break-all">{item.url || "No URL provided"}</span>
              {!readOnly && (
                <button type="button" className={textLink} onClick={() => onToggleRow(index)}>
                  {expanded ? "Hide details" : "View details"}
                </button>
              )}
            </div>

            {(readOnly || expanded) && (
              <div className="mt-4 space-y-2 border-t border-wavs-border pt-4 text-sm text-wavs-softtext">
                <p>
                  <strong>Description:</strong> {item.description}
                </p>
                <p>
                  <strong>Solution:</strong>{" "}
                  {item.solution || "Review the affected endpoint and apply the relevant security control."}
                </p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
