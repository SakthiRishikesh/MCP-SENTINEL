import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, CopyButton, Empty, ErrorNote, Meter, Pill, Tabs } from "../components/ui.jsx";
import { parseTime, short, timeAgo } from "../format.js";

function Ledger() {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const key = usePoll(() => api.get("/v1/audit/public-key"), []);
  async function verify() {
    setBusy(true);
    try {
      setResult(await api.get("/v1/audit/verify"));
    } catch (e) {
      setResult({ ok: false, reason: e.message });
    }
    setBusy(false);
  }
  return (
    <Card
      title="Tamper-evident decision ledger"
      subtitle="Every receipt is hash-chained (SHA-256) and Ed25519-signed; editing, deleting or re-ordering any record breaks the chain"
      actions={<button className="btn btn-sm btn-primary" disabled={busy} onClick={verify}>{busy ? "Verifying…" : "Verify chain"}</button>}
    >
      {result && (result.ok
        ? <p className="good-text">✓ Ledger intact — {result.checked} receipts verified · head <span className="mono">{short(result.head, 16)}</span></p>
        : <p className="danger-text">✕ Ledger broken at seq {result.broken_seq}: {result.reason}</p>)}
      {key.data && <div className="row gap"><span className="muted small">Ed25519 public key for offline verification</span><CopyButton text={key.data.public_key_pem} label="Copy public key" /></div>}
    </Card>
  );
}

function Receipts({ onReceipt }) {
  const [decision, setDecision] = useState("");
  const receipts = usePoll(() => api.get(`/v1/receipts?limit=150${decision ? `&decision=${decision}` : ""}`), [decision], 4000);
  return (
    <Card title="Decision receipts" actions={
      <select className="input input-sm" value={decision} onChange={(e) => setDecision(e.target.value)}>
        <option value="">All decisions</option>
        {["ALLOW", "MONITOR", "RESTRICT", "MFA_REQUIRED", "HUMAN_APPROVAL", "BLOCK"].map((d) => <option key={d}>{d}</option>)}
      </select>
    }>
      <ErrorNote error={receipts.error} />
      {(receipts.data || []).length === 0 ? <Empty>No receipts.</Empty> : (
        <table className="table compact">
          <thead><tr><th>#</th><th>Tool</th><th>Decision</th><th>Risk</th><th>Identity</th><th>Workflow</th><th>Policy</th><th>When</th></tr></thead>
          <tbody>{receipts.data.map((r) => (
            <tr key={r.receipt_id} className="clickable" onClick={() => onReceipt(r)}>
              <td className="muted small">{r.seq}</td>
              <td className="mono">{r.tool}</td>
              <td><Pill value={r.decision} kind="decision" /></td>
              <td><Meter value={r.risk_score} width={80} /></td>
              <td>{r.identity}</td>
              <td className="mono small truncate">{r.workflow_id}</td>
              <td className="mono small">{r.payload?.policy_id}</td>
              <td className="muted nowrap">{timeAgo(r.timestamp)}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
    </Card>
  );
}

function Events() {
  const [type, setType] = useState("");
  const events = usePoll(() => api.get(`/v1/events?limit=150&exclude_decisions=true${type ? `&event_type=${type}` : ""}`), [type], 4000);
  const types = ["rug_pull", "tool_changed", "tool_added", "behavior_anomaly", "process_anomaly", "output_injection", "sandbox", "runtime_compromise", "mfa_satisfied", "approval_resolved", "server_registered", "lockdown", "trust_change"];
  return (
    <Card title="Security events" actions={
      <select className="input input-sm" value={type} onChange={(e) => setType(e.target.value)}>
        <option value="">All events</option>
        {types.map((t) => <option key={t}>{t}</option>)}
      </select>
    }>
      {(events.data || []).length === 0 ? <Empty>No events.</Empty> : (
        <ul className="alerts">
          {events.data.map((e) => (
            <li key={e.event_id} className={`alert ${e.severity}`}>
              <Pill value={e.severity} />
              <div><div>{e.message}</div><div className="muted small">{e.event_type} · {timeAgo(e.timestamp)}</div></div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function Leases({ toast, isAdmin }) {
  const leases = usePoll(() => api.get("/v1/leases"), [], 4000);
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Capability leases</h1>
        <p className="muted">Sensitive capabilities are never granted forever: a lease is bound to one workflow, subject, server and tool — and, for CRITICAL tools, to the exact approved arguments — and expires or is revoked on integrity, runtime or risk events.</p>
      </div></div>
      <Card>
        {(leases.data || []).length === 0 ? <Empty>No leases issued yet. They appear after a step-up.</Empty> : (
          <table className="table compact">
            <thead><tr><th>Capability</th><th>Tool</th><th>Subject</th><th>Scope</th><th>State</th><th>Expires</th><th>Revocation</th><th /></tr></thead>
            <tbody>{leases.data.map((l) => (
              <tr key={l.lease_id}>
                <td><Pill value={l.capability} /></td><td className="mono">{l.tool_name}</td><td>{l.subject}</td>
                <td className="small">{l.action_bound ? "exact action" : "tool in workflow"}</td>
                <td><Pill value={l.state} /></td><td className="muted small">{parseTime(l.expires_at).toLocaleTimeString()}</td>
                <td className="small">{l.revoked_reason || "—"}</td>
                <td>{isAdmin && ["ACTIVE", "EXPIRING"].includes(l.state) && <button className="btn btn-sm btn-danger" onClick={async () => { try { await api.post(`/v1/leases/${l.lease_id}/revoke`); toast("Lease revoked"); leases.reload(); } catch (e) { toast(e.message, true); } }}>Revoke</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

export default function Audit({ onReceipt }) {
  const [tab, setTab] = useState("Receipts");
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Audit</h1>
        <p className="muted">Who did what, through which agent and server, why it was allowed or denied — with a ledger you can verify independently.</p>
      </div></div>
      <Ledger />
      <Tabs tabs={["Receipts", "Security events"]} value={tab} onChange={setTab} />
      {tab === "Receipts" ? <Receipts onReceipt={onReceipt} /> : <Events />}
    </div>
  );
}
