import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Chips, Empty, ErrorNote, Pending, Pill } from "../components/ui.jsx";

const CAPS = ["READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"];
const ROLES = ["USER", "DEVELOPER", "ANALYST", "SECURITY_ADMIN", "SYSTEM_ADMIN"];
const LOCKDOWN = [
  ["off", "Normal", "risk-adaptive enforcement"],
  ["approve_writes", "Approve writes", "every state-changing call needs a human"],
  ["deny_all", "Deny all", "emergency stop: no tool calls at all"],
];

function RuleForm({ onCreated, toast }) {
  const [form, setForm] = useState({ name: "", effect: "REQUIRE_APPROVAL", server: "", tool: "", capabilities: [], roles: [], priority: 100, reason: "" });
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const toggle = (k, v) => setForm((f) => ({ ...f, [k]: f[k].includes(v) ? f[k].filter((x) => x !== v) : [...f[k], v] }));
  async function submit(e) {
    e.preventDefault();
    setError("");
    const match = {};
    if (form.server) match.server = form.server;
    if (form.tool) match.tool = form.tool;
    if (form.capabilities.length) match.capabilities = form.capabilities;
    if (form.roles.length) match.roles = form.roles;
    try {
      await api.post("/v1/policy/rules", { name: form.name, effect: form.effect, match, priority: Number(form.priority) || 100, reason: form.reason });
      toast("Rule created");
      onCreated();
      setForm((f) => ({ ...f, name: "", tool: "", server: "", reason: "" }));
    } catch (err) {
      setError(err.message);
    }
  }
  return (
    <form className="form" onSubmit={submit}>
      <div className="form-row">
        <label>Name<input className="input" required value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Approve every delete" /></label>
        <label>Effect
          <select className="input" value={form.effect} onChange={(e) => set("effect", e.target.value)}>
            <option value="REQUIRE_APPROVAL">Require human approval</option>
            <option value="REQUIRE_MFA">Require step-up MFA</option>
            <option value="DENY">Deny</option>
          </select>
        </label>
        <label>Priority<input className="input" type="number" value={form.priority} onChange={(e) => set("priority", e.target.value)} /></label>
      </div>
      <div className="form-row">
        <label>Server (glob)<input className="input mono" value={form.server} onChange={(e) => set("server", e.target.value)} placeholder="github*" /></label>
        <label>Tool (glob)<input className="input mono" value={form.tool} onChange={(e) => set("tool", e.target.value)} placeholder="*delete*" /></label>
      </div>
      <div className="chips">{CAPS.map((c) => <label key={c} className="checkbox-row chip-check"><input type="checkbox" checked={form.capabilities.includes(c)} onChange={() => toggle("capabilities", c)} /><span className="mono small">{c}</span></label>)}</div>
      <div className="chips">{ROLES.map((r) => <label key={r} className="checkbox-row chip-check"><input type="checkbox" checked={form.roles.includes(r)} onChange={() => toggle("roles", r)} /><span className="small">{r}</span></label>)}</div>
      <label>Reason shown to the agent and in receipts<input className="input" value={form.reason} onChange={(e) => set("reason", e.target.value)} /></label>
      <ErrorNote error={error} />
      <div className="modal-actions"><button className="btn btn-primary">Add rule</button></div>
    </form>
  );
}

export default function Policy({ toast, isAdmin }) {
  const policy = usePoll(() => api.get("/v1/policy"), [], 5000);
  const p = policy.data;
  async function lockdown(mode) {
    if (mode !== "off" && !window.confirm(`Switch Sentinel to "${mode}"? This affects every agent immediately.`)) return;
    try {
      await api.put("/v1/policy/lockdown", { mode, reason: "dashboard" });
      toast(`Lockdown: ${mode}`);
      policy.reload();
    } catch (e) {
      toast(e.message, true);
    }
  }
  if (!p) return <Pending error={policy.error} />;
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Policy</h1>
        <p className="muted">RBAC + capability + context + risk. Policy is enforced outside the LLM, so a manipulated model can only ever <em>propose</em> a call.</p>
      </div></div>
      <Card title="Lockdown" subtitle="Incident response switch">
        <div className="segmented">
          {LOCKDOWN.map(([mode, label, hint]) => (
            <button key={mode} className={`seg-btn ${p.lockdown === mode ? "active" : ""} ${mode}`} disabled={!isAdmin} onClick={() => lockdown(mode)} title={hint}>
              <strong>{label}</strong><span className="small muted">{hint}</span>
            </button>
          ))}
        </div>
      </Card>
      <div className="grid-2">
        <Card title="Decision thresholds" subtitle="risk 0–100 = likelihood × impact">
          <dl className="kv">
            <dt>Monitor from</dt><dd>{p.thresholds.monitor}</dd>
            <dt>Restrict / step-up for state-changing calls from</dt><dd>{p.thresholds.restrict}</dd>
            <dt>Step-up MFA from</dt><dd>{p.thresholds.step_up}</dd>
            <dt>Block from</dt><dd>{p.thresholds.block}</dd>
            <dt>α (likelihood share)</dt><dd>{p.thresholds.alpha}</dd>
          </dl>
        </Card>
        <Card title="Hard rules (always win over risk)">
          <ul className="plain small">{p.hard_rules.map((r) => <li key={r}>• {r}</li>)}</ul>
        </Card>
      </div>
      <Card title="Roles × capabilities" subtitle="Sensitive capabilities also require step-up and a temporary lease">
        <table className="table compact matrix">
          <thead><tr><th>Role</th>{CAPS.map((c) => <th key={c} className="small">{c.replaceAll("_", " ")}{p.sensitive_capabilities.includes(c) ? " 🔐" : ""}</th>)}</tr></thead>
          <tbody>{Object.entries(p.roles).map(([role, caps]) => (
            <tr key={role}><td><strong>{role}</strong></td>{CAPS.map((c) => <td key={c} className={caps.includes(c) ? "yes" : "no"}>{caps.includes(c) ? "✓" : "—"}</td>)}</tr>
          ))}</tbody>
        </table>
      </Card>
      <Card title="Policy-as-code rules" subtitle="Rules can only make decisions stricter; they never bypass hard gates">
        {p.rules.length === 0 ? <Empty>No custom rules.</Empty> : (
          <table className="table compact">
            <thead><tr><th>Name</th><th>Effect</th><th>Match</th><th>Priority</th><th /></tr></thead>
            <tbody>{p.rules.map((r) => (
              <tr key={r.rule_id}>
                <td>{r.name}<div className="muted small">{r.reason}</div></td>
                <td><Pill value={r.effect} /></td>
                <td className="small mono">{r.match.server && `server=${r.match.server} `}{r.match.tool && `tool=${r.match.tool} `}{r.match.capabilities && <Chips items={r.match.capabilities} />}{r.match.roles && ` roles=${r.match.roles.join(",")}`}</td>
                <td>{r.priority}</td>
                <td>{isAdmin && <button className="btn btn-sm btn-danger" onClick={async () => { await api.del(`/v1/policy/rules/${r.rule_id}`); policy.reload(); }}>Delete</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
        {isAdmin && <RuleForm onCreated={policy.reload} toast={toast} />}
      </Card>
    </div>
  );
}
