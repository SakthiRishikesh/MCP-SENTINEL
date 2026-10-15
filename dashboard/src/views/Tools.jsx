import { useMemo, useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Chips, Drawer, Empty, ErrorNote, Findings, Json, Pill, Tabs } from "../components/ui.jsx";
import { routeTo, timeAgo } from "../format.js";

const CAPS = ["READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"];

function ProfileEditor({ tool, onSaved, toast }) {
  const [caps, setCaps] = useState(tool.capabilities || []);
  const [sens, setSens] = useState(tool.sensitivity || "LOW");
  return (
    <div className="stack">
      <p className="muted small">Lock an administrator-defined capability profile. A later rug pull that expands the tool's semantics is still gated (Sentinel uses the union of the locked and live semantics).</p>
      <div className="chips">
        {CAPS.map((c) => (
          <label key={c} className="checkbox-row chip-check">
            <input type="checkbox" checked={caps.includes(c)} onChange={() => setCaps((x) => (x.includes(c) ? x.filter((y) => y !== c) : [...x, c]))} />
            <span className="mono small">{c}</span>
          </label>
        ))}
      </div>
      <div className="row gap">
        <select className="input input-sm" value={sens} onChange={(e) => setSens(e.target.value)}>
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <button className="btn btn-sm btn-primary" disabled={!caps.length} onClick={async () => {
          try {
            await api.put(`/v1/tools/${encodeURIComponent(tool.tool_id)}/profile`, { capabilities: caps, sensitivity: sens });
            toast("Profile locked");
            onSaved();
          } catch (e) {
            toast(e.message, true);
          }
        }}>Lock profile</button>
      </div>
    </div>
  );
}

function ToolDetail({ toolId, onClose, toast, isAdmin }) {
  const [tab, setTab] = useState("What the model sees");
  const detail = usePoll(() => api.get(`/v1/tools/${encodeURIComponent(toolId)}/detail`), [toolId], 5000);
  const t = detail.data;
  async function act(label, fn) {
    try {
      await fn();
      toast(label);
      detail.reload();
    } catch (e) {
      toast(e.message, true);
    }
  }
  if (!t) return <Drawer title="Tool" onClose={onClose}><ErrorNote error={detail.error} /></Drawer>;
  const changed = t.live_hash && t.approved_hash && t.live_hash !== t.approved_hash;
  const actions = isAdmin && (
    <>
      {(t.review_state !== "APPROVED" || changed) && <button className="btn btn-sm btn-primary" onClick={() => act("Definition approved & pinned", () => api.post(`/v1/tools/${encodeURIComponent(toolId)}/approve`))}>Approve live definition</button>}
      <button className="btn btn-sm btn-danger" onClick={() => act("Tool rejected", () => api.post(`/v1/tools/${encodeURIComponent(toolId)}/reject`))}>Reject</button>
    </>
  );
  return (
    <Drawer title={t.exposed_name || t.tool_name} onClose={onClose} actions={actions}>
      <div className="row gap wrap">
        <Pill value={t.trust_status} /> <Pill value={t.review_state} /> <Pill value={t.sensitivity} />
        <Chips items={t.capabilities} /> <Chips items={t.flow_roles} className="role" />
        {t.profile_locked && <span className="chip">profile locked</span>}
      </div>
      <p className="muted small">Pinned {t.approved_hash ? <span className="mono">{t.approved_hash.slice(0, 16)}…</span> : "— (not approved)"} · live <span className="mono">{(t.live_hash || "").slice(0, 16)}…</span> {changed && <span className="danger-text">· DRIFTED</span>}</p>
      {isAdmin && (
        <div className="row gap">
          <select className="input input-sm" value={t.trust_status} onChange={(e) => act("Trust updated", () => api.put(`/v1/tools/${encodeURIComponent(toolId)}/trust`, { trust_status: e.target.value }))}>
            {["TRUSTED", "MONITORED", "RESTRICTED", "QUARANTINED", "BLOCKED"].map((x) => <option key={x}>{x}</option>)}
          </select>
        </div>
      )}
      <Tabs tabs={["What the model sees", "Live definition", "Findings", "Semantics", "Behaviour", "History"]} value={tab} onChange={setTab} />
      {tab === "What the model sees" && (
        <div className="stack">
          <p className="muted small">The model is always served the <strong>pinned</strong> definition. A changed upstream description never reaches the LLM until an administrator approves it.</p>
          <Json value={t.served_definition} />
        </div>
      )}
      {tab === "Live definition" && <Json value={t.live_definition} />}
      {tab === "Findings" && <Findings items={t.scan_findings} />}
      {tab === "Semantics" && (
        <div className="stack">
          <ul className="plain">{(t.inference?.evidence || []).map((e, i) => <li key={i} className="small">• {e}</li>)}</ul>
          {(t.inference?.annotation_conflicts || []).length > 0 && <div className="err">{t.inference.annotation_conflicts.join("; ")}</div>}
          {isAdmin && <ProfileEditor tool={t} onSaved={detail.reload} toast={toast} />}
        </div>
      )}
      {tab === "Behaviour" && (
        <div className="stack">
          <p className="small">Samples: <strong>{t.behavior.samples}</strong> {t.behavior.learning ? "(learning)" : ""} · drift likelihood <strong>{Math.round(t.behavior.drift * 100)}%</strong></p>
          {(t.behavior.recent_anomalies || []).length === 0 ? <Empty>No behavioural anomalies.</Empty> : (
            <ul className="plain">{t.behavior.recent_anomalies.map((a, i) => <li key={i}><Pill value={a.severity} /> {a.message}</li>)}</ul>
          )}
          <Json value={t.baseline} />
        </div>
      )}
      {tab === "History" && ((t.changes || []).length === 0 ? <Empty>No changes.</Empty> : (
        <table className="table compact">
          <thead><tr><th>Type</th><th>Class</th><th>Score</th><th>Status</th><th>When</th></tr></thead>
          <tbody>{t.changes.map((c) => (
            <tr key={c.change_id} className="clickable" onClick={() => routeTo(`/integrity/${c.change_id}`)}>
              <td>{c.change_type}</td><td><Pill value={c.classification} /></td><td>{c.score}</td><td><Pill value={c.status} /></td><td className="muted">{timeAgo(c.detected_at)}</td>
            </tr>
          ))}</tbody>
        </table>
      ))}
    </Drawer>
  );
}

export default function Tools({ toast, isAdmin, selected }) {
  const tools = usePoll(() => api.get("/v1/tools"), [], 5000);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");
  const rows = useMemo(() => (tools.data || []).filter((t) => {
    if (q && !`${t.exposed_name} ${t.tool_name} ${t.description}`.toLowerCase().includes(q.toLowerCase())) return false;
    if (filter === "risk") return ["RESTRICTED", "QUARANTINED", "BLOCKED"].includes(t.trust_status) || ["CHANGED", "PENDING_REVIEW"].includes(t.review_state);
    if (filter === "sensitive") return (t.capabilities || []).some((c) => ["SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"].includes(c));
    return true;
  }), [tools.data, q, filter]);
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Tool integrity registry</h1>
          <p className="muted">Each tool's raw definition is pinned on first sight (TOFU), scanned for poisoning, profiled into capabilities and toxic-flow roles, and baselined at runtime.</p>
        </div>
      </div>
      <div className="row gap">
        <input className="input" style={{ maxWidth: 320 }} placeholder="Search tools…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input input-sm" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">All tools</option>
          <option value="risk">At risk / under review</option>
          <option value="sensitive">Sensitive capabilities</option>
        </select>
      </div>
      <ErrorNote error={tools.error} />
      <Card>
        {rows.length === 0 ? <Empty>No tools match.</Empty> : (
          <table className="table">
            <thead><tr><th>Exposed as</th><th>Capabilities</th><th>Flow roles</th><th>Sensitivity</th><th>Trust</th><th>Review</th><th>Scan</th><th>Behaviour</th></tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.tool_id} className="clickable" onClick={() => routeTo(`/tools/${encodeURIComponent(t.tool_id)}`)}>
                  <td><span className="mono">{t.exposed_name || t.tool_name}</span><div className="muted small truncate">{t.description}</div></td>
                  <td><Chips items={t.capabilities} /></td>
                  <td><Chips items={t.flow_roles} className="role" /></td>
                  <td><Pill value={t.sensitivity} /></td>
                  <td><Pill value={t.trust_status} /></td>
                  <td><Pill value={t.review_state} /></td>
                  <td>{t.worst_finding ? <Pill value={t.worst_finding} /> : <span className="good-text small">clean</span>}</td>
                  <td className="small">{t.behavior.samples} calls{t.behavior.drift > 0.05 ? <span className="warn-text"> · drift {Math.round(t.behavior.drift * 100)}%</span> : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {selected && <ToolDetail toolId={selected} onClose={() => routeTo("/tools")} toast={toast} isAdmin={isAdmin} />}
    </div>
  );
}
