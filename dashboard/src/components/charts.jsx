import { useState } from "react";

/* Status roles carry decision state; every segment also has an icon + label in the legend. */
export const DECISION_ORDER = ["ALLOW", "MONITOR", "RESTRICT", "MFA_REQUIRED", "HUMAN_APPROVAL", "BLOCK"];
const DECISION_ROLE = {
  ALLOW: "good",
  MONITOR: "neutral",
  RESTRICT: "warning",
  MFA_REQUIRED: "serious",
  HUMAN_APPROVAL: "serious-alt",
  BLOCK: "critical",
};
const DECISION_LABEL = {
  ALLOW: "✓ Allow",
  MONITOR: "◉ Monitor",
  RESTRICT: "◐ Restrict",
  MFA_REQUIRED: "🔐 Step-up",
  HUMAN_APPROVAL: "✋ Approval",
  BLOCK: "⛔ Block",
};

/** Stacked horizontal bar of decisions with a legend (identity never by color alone). */
export function DecisionMix({ counts }) {
  const [hover, setHover] = useState(null);
  const entries = DECISION_ORDER.map((d) => [d, counts?.[d] || 0]).filter(([, n]) => n > 0);
  const total = entries.reduce((s, [, n]) => s + n, 0);
  if (!total) return <div className="empty">No decisions in the last 24 hours.</div>;
  return (
    <div className="viz decision-mix">
      <div className="stack-bar" role="img" aria-label="Decision mix, last 24 hours">
        {entries.map(([d, n]) => (
          <span
            key={d}
            className={`seg role-${DECISION_ROLE[d]}`}
            style={{ flexGrow: n }}
            onMouseEnter={() => setHover(d)}
            onMouseLeave={() => setHover(null)}
          />
        ))}
      </div>
      <div className="legend">
        {entries.map(([d, n]) => (
          <span key={d} className={`legend-item ${hover === d ? "hot" : ""}`}>
            <span className={`swatch role-${DECISION_ROLE[d]}`} />
            {DECISION_LABEL[d]} <strong>{n}</strong>
            <span className="muted"> ({Math.round((n / total) * 100)}%)</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Risk waterfall: each factor's share of the final score (single series, labelled). */
export function RiskWaterfall({ factors, total }) {
  const [hover, setHover] = useState(null);
  if (!factors || factors.length === 0) return <div className="empty small">No risk evidence — baseline only.</div>;
  const max = Math.max(total || 0, ...factors.map((f) => f.score), 1);
  return (
    <div className="viz waterfall">
      {factors.map((f, i) => (
        <div
          key={`${f.name}-${i}`}
          className={`wf-row ${hover === i ? "hot" : ""}`}
          onMouseEnter={() => setHover(i)}
          onMouseLeave={() => setHover(null)}
        >
          <span className="wf-name mono">{f.name}</span>
          <span className="wf-track">
            <span className="wf-bar" style={{ width: `${(f.score / max) * 100}%` }} />
          </span>
          <span className="wf-val">+{f.score}</span>
          {hover === i && (
            <div className="tooltip" role="tooltip">
              <strong>{f.name}</strong> · likelihood {Math.round((f.likelihood || 0) * 100)}%<br />
              {f.reason}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/** Single-series sparkline of risk per call, with a per-point hover tooltip. */
export function Sparkline({ points, height = 56, labels = [] }) {
  const [hover, setHover] = useState(null);
  if (!points || points.length < 2) return null;
  const w = Math.max(160, points.length * 28);
  const pad = 6;
  const x = (i) => pad + (i * (w - pad * 2)) / (points.length - 1);
  const y = (v) => height - pad - (v / 100) * (height - pad * 2);
  const d = points.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  return (
    <div className="viz sparkline-wrap">
      <svg width={w} height={height} viewBox={`0 0 ${w} ${height}`} className="sparkline" role="img" aria-label="Risk per call">
        <line x1={pad} x2={w - pad} y1={y(80)} y2={y(80)} className="ref-line" />
        <line x1={pad} x2={w - pad} y1={y(60)} y2={y(60)} className="ref-line faint" />
        <path d={d} className="spark-path" />
        {points.map((v, i) => (
          <g key={i} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
            <circle cx={x(i)} cy={y(v)} r={12} className="hit" />
            <circle cx={x(i)} cy={y(v)} r={hover === i ? 5 : 4} className={`dot ${v >= 80 ? "critical" : v >= 60 ? "serious" : ""}`} />
          </g>
        ))}
      </svg>
      {hover !== null && (
        <div className="tooltip inline" role="tooltip">
          #{hover + 1} {labels[hover] || ""} · risk <strong>{points[hover]}</strong>
        </div>
      )}
    </div>
  );
}
