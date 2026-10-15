/** Parse an API timestamp. The API speaks UTC; a value without an offset is UTC, not local time. */
export function parseTime(iso) {
  if (iso === null || iso === undefined || iso === "") return new Date(NaN);
  if (typeof iso === "number") return new Date(iso);
  const s = String(iso);
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) || !/\d{2}:\d{2}/.test(s) ? s : `${s}Z`);
}

export function timeAgo(iso) {
  if (!iso) return "—";
  const t = parseTime(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function compact(n) {
  if (n === null || n === undefined) return "—";
  if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

export function bandFor(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH_RISK";
  if (score >= 40) return "SUSPICIOUS";
  if (score >= 20) return "MONITOR";
  return "NORMAL";
}

export function short(id, n = 8) {
  return (id || "").slice(0, n);
}

export function routeTo(path) {
  window.location.hash = path.startsWith("#") ? path : `#${path}`;
}
