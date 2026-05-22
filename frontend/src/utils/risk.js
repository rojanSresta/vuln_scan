/** Count findings by risk level for RiskStrip. */
export function buildRiskStats(results, withDefaults = false) {
  const stats = withDefaults ? { High: 0, Medium: 0, Low: 0, Informational: 0 } : {};
  for (const item of results || []) {
    const key = item.risk || "Informational";
    stats[key] = (stats[key] || 0) + 1;
  }
  return stats;
}
