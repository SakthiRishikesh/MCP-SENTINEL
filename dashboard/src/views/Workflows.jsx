import { useState } from "react";
import { api, usePoll } from "../api.js";
import { RiskWaterfall, Sparkline } from "../components/charts.jsx";
import { Card, Empty, Meter, Pending, Pill } from "../components/ui.jsx";
import { routeTo, short, timeAgo } from "../format.js";
import { TrifectaDots } from "./Overview.jsx";
import { WorkflowReplay } from "../components/replay.jsx";

const ROLE_ICON = { PRIVATE_SOURCE: "🗄", UNTRUSTED_SOURCE: "🌐", EGRESS_SINK: "📤" };

function WorkflowDetail({ id }) {
  const wf = usePoll(() => api.get(`/v1/workflows/${encodeURIComponent(id)}`), [id], 3000);
  const [open, setOpen] = useState(null);
  const w = wf.data;
  if (!w) return <Pending error={wf.error} />;
  const s = w.summary;
  return (
    <div className="stack">
      <div className="row gap wrap">
        <h2 className="mono">{w.workflow_id}</h2>
        <TrifectaDots t={s.trifecta} />
        {s.secret_in_context && <span className="chip SECRET">secret in context</span>}
        {s.tainted_tokens > 0 && <span className="chip">{s.tainted_tokens} tainted tokens tracked</span>}
      </div>
      {Object.keys(s.risk_memory || {}).length > 0 && (
        <p className="small">Risk memory (decaying): {Object.entries(s.risk_memory).map(([k, v]) => `${k} ${Math.round(v * 100)}%`).join(" · ")}</p>
      )}
      <WorkflowReplay workflowId={id} />
      <Card title="Risk per call">
        <Sparkline points={w.receipts.map((r) => r.risk_score)} labels={w.receipts.map((r) => r.tool)} />
      </Card>
      <Card title="Data flow" subtitle="Executed calls carry their toxic-flow roles; denied calls never moved data">
        <div className="flow-lane">
          {w.calls.map((c, i) => (
            <div key={i} className="flow-step">
              <div className={`flow-node ${c.allowed ? "" : "denied"} ${c.data_class}`}>
                <span className="mono small">{c.tool}</span>
                <Pill value={c.decision} kind="decision" />
                <span className="small">{(c.flow_roles || []).map((r) => <span key={r} title={r}>{ROLE_ICON[r] || "•"}</span>)} {c.data_class}</span>
                {c.destination && <span className="mono tiny truncate" title={c.destination}>→ {c.destination}</span>}
              </div>
              {i < w.calls.length - 1 && <span className="flow-arrow">→</span>}
            </div>
          ))}
        </div>
        <p className="muted small">🗄 private data · 🌐 untrusted content · 📤 egress</p>
      </Card>
      <Card title="Decisions">
        {w.receipts.map((r, i) => (
          <div key={r.receipt_id} className="receipt-row">
            <button className="row between full" onClick={() => setOpen(open === i ? null : i)}>
              <span className="row gap"><span className="mono">{r.tool}</span><Pill value={r.decision} kind="decision" /></span>
              <span className="row gap"><Meter value={r.risk_score} width={110} /><span className="muted small">{short(r.receipt_id)}</span></span>
            </button>
            {open === i && (
              <div className="receipt-body">
                <ul className="plain">{(r.reasons || []).map((x, j) => <li key={j} className="small">• {x}</li>)}</ul>
                <h4>Risk factors</h4>
                <RiskWaterfall factors={r.factors} total={r.risk_score} />
                <h4>Gates</h4>
                <div className="gates">{(r.gates || []).map((g, j) => <span key={j} className={`gate ${g.status}`} title={g.detail}>{g.status === "pass" ? "✓" : g.status === "warn" ? "!" : "✕"} {g.gate}</span>)}</div>
              </div>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

export default function Workflows({ selected }) {
  const list = usePoll(() => api.get("/v1/workflows?limit=50"), [], 5000);
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Workflows</h1>
          <p className="muted">A workflow is a short-lived agent session. Sentinel tracks capability transitions, data classes, tainted secrets and the three trifecta legs across its calls.</p>
        </div>
      </div>
      <div className="split">
        <div className="split-list">
          {(list.data || []).length === 0 ? <Empty>No workflows yet.</Empty> : (
            <ul className="list">
              {list.data.map((w) => (
                <li key={w.workflow_id}>
                  <button className={`list-item ${selected === w.workflow_id ? "active" : ""}`} onClick={() => routeTo(`/workflows/${encodeURIComponent(w.workflow_id)}`)}>
                    <div className="mono small truncate">{w.workflow_id}</div>
                    <div className="row between small"><TrifectaDots t={w.trifecta} /><Meter value={w.max_risk} width={60} /></div>
                    <div className="muted small">{w.subject} · {w.calls} calls · {w.blocked} blocked · {timeAgo(w.last_activity)}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="split-main">{selected ? <WorkflowDetail id={selected} /> : <Empty>Select a workflow.</Empty>}</div>
      </div>
    </div>
  );
}

