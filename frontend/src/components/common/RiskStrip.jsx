import React from "react";
import { RISK_META } from "../../constants";

export default function RiskStrip({ stats }) {
  return (
    <div className="risk-strip">
      {Object.keys(RISK_META).map((risk) =>
        stats[risk] ? (
          <span
            key={risk}
            className="risk-pill"
            style={{ color: RISK_META[risk].color, background: RISK_META[risk].bg }}
          >
            {risk}: {stats[risk]}
          </span>
        ) : null
      )}
    </div>
  );
}
