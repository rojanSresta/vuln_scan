import React from "react";
import { RISK_META } from "../../constants";
import { riskPill } from "../../ui/classes";

export default function RiskStrip({ stats }) {
  return (
    <div className="mb-5 flex flex-wrap gap-2">
      {Object.keys(RISK_META).map((risk) =>
        stats[risk] ? (
          <span key={risk} className={`${riskPill} ${RISK_META[risk].className}`}>
            {risk}: {stats[risk]}
          </span>
        ) : null
      )}
    </div>
  );
}
