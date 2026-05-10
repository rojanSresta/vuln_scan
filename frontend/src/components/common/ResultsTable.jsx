import React from "react";
import { RISK_META } from "../../constants";

export default function ResultsTable({ items, expandedRows, onToggleRow, readOnly = false }) {
  if (!items.length) {
    return <p className="muted">No findings were recorded for this scan.</p>;
  }

  return (
    <div className="results-list">
      {items.map((item, index) => {
        const expanded = !!expandedRows[index];
        const meta = RISK_META[item.risk] || RISK_META.Informational;

        return (
          <div key={`${item.name}-${index}`} className="result-item">
            <div className="result-top">
              <div>
                <strong>{item.name}</strong>
                <p>{item.explanation}</p>
              </div>
              <span className="risk-pill" style={{ color: meta.color, background: meta.bg }}>
                {item.risk}
              </span>
            </div>

            <div className="result-meta">
              <span>{item.url || "No URL provided"}</span>
              {!readOnly && (
                <button className="text-link" onClick={() => onToggleRow(index)}>
                  {expanded ? "Hide details" : "View details"}
                </button>
              )}
            </div>

            {(readOnly || expanded) && (
              <div className="result-details">
                <p><strong>Description:</strong> {item.description}</p>
                <p><strong>Solution:</strong> {item.solution || "Review the affected endpoint and apply the relevant security control."}</p>
                {item.reference && <p><strong>Reference:</strong> {item.reference}</p>}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
