import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Empty, ErrorNote, Pending, Pill } from "../components/ui.jsx";
import { timeAgo } from "../format.js";

const TYPES = [
  { value: "slack", label: "Slack", hint: "Incoming webhook URL (https://hooks.slack.com/services/…)" },
  { value: "teams", label: "Microsoft Teams", hint: "Workflows webhook URL (posts an Adaptive Card)" },
  { value: "ntfy", label: "ntfy push (phone / desktop)", hint: "Topic URL, e.g. https://ntfy.sh/your-secret-topic" },
  { value: "webhook", label: "Generic webhook", hint: "Receives JSON; add a secret to get an X-Sentinel-Signature HMAC header" },
];
const KIND_TEXT = {
  approval: "A call needs human approval",
  mfa: "A call needs step-up (MFA)",
  sandbox_block: "The sandbox blocked a call",
  sandbox_evasion: "A server changed files outside its sandbox prediction",
  server_unsafe: "A server was judged NOT SAFE",
  rug_pull: "A malicious rug pull was detected",
};

function AddChannel({ onAdded, isAdmin }) {
  const [form, setForm] = useState({ type: "slack", url: "", name: "", secret: "", token: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const type = TYPES.find((t) => t.value === form.type);
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.post("/v1/notifications/channels", form);
      setForm({ ...form, url: "", name: "", secret: "", token: "" });
      onAdded();
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <div className="row gap wrap">
        <label className="grow">Channel<select className="input" value={form.type} onChange={(e) => set("type", e.target.value)}>
          {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}</select></label>
        <label className="grow"><span>Name <span className="muted small">(optional)</span></span><input className="input" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="#security-approvals" /></label>
      </div>
      <label><span>URL <span className="muted small">{type?.hint}</span></span>
        <input className="input mono" type="password" autoComplete="off" required value={form.url} onChange={(e) => set("url", e.target.value)} placeholder="https://…" /></label>
      {form.type === "webhook" && <label><span>Signing secret <span className="muted small">(optional)</span></span><input className="input mono" type="password" autoComplete="off" value={form.secret} onChange={(e) => set("secret", e.target.value)} /></label>}
      {form.type === "ntfy" && <label><span>Access token <span className="muted small">(optional, for protected topics)</span></span><input className="input mono" type="password" autoComplete="off" value={form.token} onChange={(e) => set("token", e.target.value)} /></label>}
      <ErrorNote error={error} />
      <div className="modal-actions"><button className="btn btn-primary" disabled={busy || !isAdmin}>{busy ? "Saving…" : "Add channel"}</button></div>
    </form>
  );
}

export default function Alerts({ isAdmin, toast }) {
  const cfg = usePoll(() => api.get("/v1/notifications"), [], 5000);
  const [busy, setBusy] = useState("");
  const c = cfg.data;
  async function act(label, fn, ok) {
    setBusy(label);
    try {
      const res = await fn();
      toast(typeof ok === "function" ? ok(res) : ok);
      cfg.reload();
    } catch (e) {
      toast(e.message);
    }
    setBusy("");
  }
  if (!c) return <Pending error={cfg.error} />;
  const kinds = new Set(c.kinds);
  const toggle = (k) => {
    const next = kinds.has(k) ? c.kinds.filter((x) => x !== k) : [...c.kinds, k];
    act("kinds", () => api.put("/v1/notifications/kinds", { kinds: next }), "Saved");
  };
  const all = [...c.channels.map((ch, i) => ({ ...ch, index: i })), ...c.env_channels];
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Alerts &amp; approvals on the go</h1>
        <p className="muted">When a call needs a person, or Sentinel blocks something serious, it pings you right away: in Slack, Teams, on your phone (ntfy) or any webhook. Each message includes the effect the call would have had in the sandbox. The link opens the approval page, where you still sign in and pass step-up; a notification never approves anything by itself.</p>
      </div></div>
      <div className="grid-2">
        <Card title="Channels" subtitle="Webhook URLs are stored encrypted and never shown again"
          actions={isAdmin && all.length > 0 && <button className="btn btn-sm" disabled={!!busy} onClick={() => act("test", () => api.post("/v1/notifications/test"), (r) => `Test sent: ${r.deliveries.filter((d) => d.ok).length}/${r.deliveries.length} delivered`)}>{busy === "test" ? "Sending…" : "Send test"}</button>}>
          {all.length === 0 ? <Empty>No channels yet. Add one below.</Empty> : (
            <table className="table compact">
              <thead><tr><th>Channel</th><th>Destination</th><th /></tr></thead>
              <tbody>{all.map((ch, i) => (
                <tr key={i}>
                  <td><strong>{ch.name}</strong><div className="muted small">{ch.type}{ch.signed ? " · signed" : ""}</div></td>
                  <td className="mono small">{ch.url}</td>
                  <td>{ch.env ? <span className="muted small">set by environment</span> : isAdmin && <button className="btn btn-sm btn-danger" disabled={!!busy} onClick={() => act("del", () => api.del(`/v1/notifications/channels/${ch.index}`), "Channel removed")}>Remove</button>}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
          <h4>Add a channel</h4>
          <AddChannel isAdmin={isAdmin} onAdded={() => { toast("Channel added"); cfg.reload(); }} />
        </Card>
        <Card title="What to send" subtitle="Approvals and step-ups link straight to the approval page">
          <div className="stack">
            {c.available_kinds.filter((k) => k !== "test").map((k) => (
              <label key={k} className="checkbox-row"><input type="checkbox" disabled={!isAdmin || !!busy} checked={kinds.has(k)} onChange={() => toggle(k)} /> {KIND_TEXT[k] || k}</label>
            ))}
          </div>
          <h4>Recent deliveries</h4>
          {(c.history || []).length === 0 ? <Empty>Nothing sent yet.</Empty> : (
            <table className="table compact">
              <thead><tr><th>When</th><th>Event</th><th>Channel</th><th>Result</th></tr></thead>
              <tbody>{c.history.map((h, i) => (
                <tr key={i}>
                  <td className="small muted">{timeAgo(new Date(h.at * 1000).toISOString())}</td>
                  <td className="small">{h.title}</td>
                  <td className="small">{h.channel?.name}</td>
                  <td><Pill value={h.ok ? "ALLOW" : "BLOCK"} title={h.error || String(h.status)} /> <span className="muted small">{h.status ?? h.error}</span></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}
