import { useState } from "react";

const DECISION_ICON = {
  ALLOW: "✓",
  MONITOR: "◉",
  RESTRICT: "◐",
  MFA_REQUIRED: "🔐",
  HUMAN_APPROVAL: "✋",
  QUARANTINE: "☣",
  BLOCK: "⛔",
};

export function Pill({ value, kind, title }) {
  if (!value) return <span className="pill">—</span>;
  const icon = kind === "decision" ? DECISION_ICON[value] : null;
  return (
    <span className={`pill ${value}`} title={title || value}>
      {icon && <span aria-hidden="true">{icon} </span>}
      {String(value).replaceAll("_", " ")}
    </span>
  );
}

export function Card({ title, actions, children, className = "", subtitle }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <p className="muted small">{subtitle}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatTile({ label, value, hint, tone, onClick }) {
  return (
    <button type="button" className={`stat-tile ${tone || ""}`} onClick={onClick} disabled={!onClick}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </button>
  );
}

export function severityTone(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "serious";
  if (score >= 40) return "warning";
  if (score >= 20) return "info";
  return "good";
}

/** Meter: the fill carries severity; the track is a lighter step of the same ramp. */
export function Meter({ value, max = 100, label, width }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const tone = severityTone(value);
  return (
    <span className={`meter ${tone}`} style={width ? { width } : undefined} title={`${label || "risk"} ${value}/${max}`}>
      <span className="meter-fill" style={{ width: `${pct}%` }} />
      <span className="meter-value">{value}</span>
    </span>
  );
}

export function Modal({ title, onClose, children, wide }) {
  return (
    <div className="modal-overlay" onClick={onClose} role="presentation">
      <div className={`modal ${wide ? "wide" : ""}`} onClick={(e) => e.stopPropagation()} role="dialog" aria-label={title}>
        <header className="modal-head">
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">✕</button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children, actions }) {
  return (
    <div className="drawer-overlay" onClick={onClose} role="presentation">
      <aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label={title}>
        <header className="modal-head">
          <h2>{title}</h2>
          <div className="row gap">
            {actions}
            <button className="icon-btn" onClick={onClose} aria-label="Close">✕</button>
          </div>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t} role="tab" aria-selected={value === t} className={value === t ? "active" : ""} onClick={() => onChange(t)}>
          {t}
        </button>
      ))}
    </div>
  );
}

export function Json({ value, max = 4000 }) {
  const text = JSON.stringify(value, null, 2) || "";
  return <pre className="json">{text.length > max ? `${text.slice(0, max)}\n…` : text}</pre>;
}

export function CopyButton({ text, label = "Copy" }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          setDone(false);
        }
      }}
    >
      {done ? "Copied ✓" : label}
    </button>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function ErrorNote({ error }) {
  if (!error) return null;
  return <div className="err">⚠ {error}</div>;
}

/** Placeholder while a request is in flight; the error once it failed. */
export function Pending({ error, label = "Loading…" }) {
  if (error) return <ErrorNote error={error} />;
  return <div className="loading" role="status"><span className="spinner" aria-hidden="true" />{label}</div>;
}

export function Findings({ items }) {
  if (!items || items.length === 0) return <Empty>No findings.</Empty>;
  return (
    <ul className="findings">
      {items.map((f, i) => (
        <li key={i} className={`finding ${f.severity}`}>
          <Pill value={f.severity} />
          <div>
            <strong>{f.title}</strong>
            {f.field && <span className="muted small"> · {f.field}</span>}
            {f.evidence && <div className="mono small evidence">{f.evidence}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function Chips({ items, className = "" }) {
  return (
    <span className="chips">
      {(items || []).map((c) => (
        <span key={c} className={`chip ${className} ${c}`}>{String(c).replaceAll("_", " ")}</span>
      ))}
    </span>
  );
}
