import { useEffect, useMemo, useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Drawer, Empty, Modal, Pending, Pill } from "../components/ui.jsx";
import { timeAgo } from "../format.js";

const TITLES = ["Security analyst", "Developer", "Viewer"];

function AddMember({ onClose, onAdded, toast }) {
  const [form, setForm] = useState({ name: "", email: "", role: "Security analyst", password: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await api.post("/v1/org/members", form);
      toast(`Added ${form.email}`);
      onAdded();
      onClose();
    } catch (err) { setError(err.message); setBusy(false); }
  };
  return (
    <Modal title="Add a team member" onClose={onClose}>
      <form className="form" onSubmit={submit}>
        <div className="form-row">
          <label className="auth-field2"><span>Full name</span><input className="input" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Jordan Lee" /></label>
          <label className="auth-field2"><span>Email</span><input className="input" type="email" required value={form.email} onChange={(e) => set("email", e.target.value)} placeholder="person@company.com" /></label>
        </div>
        <div className="form-row">
          <label className="auth-field2"><span>Role</span><select className="input" value={form.role} onChange={(e) => set("role", e.target.value)}>{TITLES.map((t) => <option key={t}>{t}</option>)}</select></label>
          <label className="auth-field2"><span>Temporary password <span className="muted small">(so they can sign in)</span></span><input className="input mono" type="text" minLength={8} value={form.password} onChange={(e) => set("password", e.target.value)} placeholder="min 8 characters" /></label>
        </div>
        {error && <div className="err">⚠ {error}</div>}
        <div className="modal-actions"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Adding…" : "Add member"}</button></div>
      </form>
    </Modal>
  );
}

function AccessDrawer({ member, onClose, toast, reload }) {
  const catalog = usePoll(() => api.get("/v1/org/catalog"), []);
  const [state, setState] = useState(null); // { [server_id]: { on: bool, tools: Set<string> | null (null=all) } }
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.get(`/v1/org/members/${member.account_id}/assignments`).then((d) => {
      const next = {};
      for (const a of d.assignments) next[a.server_id] = { on: true, tools: a.tools.includes("*") ? null : new Set(a.tools) };
      setState(next);
    }).catch(() => setState({}));
  }, [member.account_id]);
  const servers = catalog.data || [];
  const toggleServer = (sid) => setState((s) => ({ ...s, [sid]: s[sid]?.on ? { on: false, tools: null } : { on: true, tools: null } }));
  const toggleAll = (sid, all) => setState((s) => ({ ...s, [sid]: { on: true, tools: all ? null : new Set() } }));
  const toggleTool = (sid, tool) => setState((s) => {
    const cur = s[sid]?.tools instanceof Set ? new Set(s[sid].tools) : new Set();
    cur.has(tool) ? cur.delete(tool) : cur.add(tool);
    return { ...s, [sid]: { on: true, tools: cur } };
  });
  const save = async () => {
    setBusy(true);
    const grants = Object.entries(state || {})
      .filter(([, v]) => v.on)
      .map(([server_id, v]) => ({ server_id, tools: v.tools === null ? ["*"] : [...v.tools] }))
      .filter((g) => g.tools.length > 0);
    try {
      await api.put(`/v1/org/members/${member.account_id}/assignments`, { grants });
      toast(`Access updated for ${member.name || member.email}`);
      reload();
      onClose();
    } catch (err) { toast(err.message, true); setBusy(false); }
  };
  return (
    <Drawer title={`Access · ${member.name || member.email}`} onClose={onClose}
      actions={<button className="btn btn-primary" disabled={busy || !state} onClick={save}>{busy ? "Saving…" : "Save access"}</button>}>
      <p className="muted small">Choose which MCP servers and tools this employee may use. Everything else is blocked at call time, whatever a prompt asks for.</p>
      {!state ? <Pending error={catalog.error} /> : servers.length === 0 ? <Empty>No servers registered yet.</Empty> : (
        <div className="access-list">
          {servers.map((srv) => {
            const cur = state[srv.server_id] || { on: false, tools: null };
            return (
              <div className={`access-server ${cur.on ? "is-on" : ""}`} key={srv.server_id}>
                <label className="access-server-head">
                  <input type="checkbox" checked={cur.on} onChange={() => toggleServer(srv.server_id)} />
                  <strong>{srv.server_name}</strong>
                  <span className="muted small">{srv.tools.length} tools · {srv.transport}</span>
                </label>
                {cur.on && (
                  <div className="access-tools">
                    <label className="access-scope"><input type="radio" name={`scope-${srv.server_id}`} checked={cur.tools === null} onChange={() => toggleAll(srv.server_id, true)} /> All tools</label>
                    <label className="access-scope"><input type="radio" name={`scope-${srv.server_id}`} checked={cur.tools !== null} onChange={() => toggleAll(srv.server_id, false)} /> Specific tools</label>
                    {cur.tools !== null && (
                      <div className="access-tool-grid">
                        {srv.tools.map((t) => (
                          <label key={t} className="access-tool"><input type="checkbox" checked={cur.tools.has(t)} onChange={() => toggleTool(srv.server_id, t)} /> <span className="mono small">{t}</span></label>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Drawer>
  );
}

function MemberRow({ m, onAccess, onChange, toast }) {
  const [editing, setEditing] = useState(false);
  const [pw, setPw] = useState("");
  const isAdmin = m.org_role === "admin";
  const patch = async (body, msg) => {
    try { await api.patch(`/v1/org/members/${m.account_id}`, body); toast(msg); onChange(); } catch (e) { toast(e.message, true); }
  };
  const remove = async () => {
    if (!window.confirm(`Remove ${m.email} from the organization? Their access is revoked immediately.`)) return;
    try { await api.del(`/v1/org/members/${m.account_id}`); toast(`Removed ${m.email}`); onChange(); } catch (e) { toast(e.message, true); }
  };
  const assignedCount = Array.isArray(m.assignments) ? m.assignments.length : null;
  return (
    <>
      <tr className={m.disabled ? "is-disabled" : ""}>
        <td><div className="mono">{m.name || "—"}</div><div className="muted small">{m.email}</div></td>
        <td><Pill value={isAdmin ? "Admin" : (m.title || "Employee")} /></td>
        <td className="small">{isAdmin ? <span className="muted">full access</span> : assignedCount === 0 ? <span className="warn-text">no tools yet</span> : <span className="good-text">{assignedCount} server{assignedCount === 1 ? "" : "s"}</span>}</td>
        <td className="small">{m.can_login ? <span className="good-text">can sign in</span> : <span className="muted">invited (set a password)</span>}{m.disabled && <> · <span className="danger-text">disabled</span></>}</td>
        <td className="small muted">{m.last_login ? timeAgo(m.last_login) : "never"}</td>
        <td className="row gap">
          {!isAdmin && <button className="btn btn-sm" onClick={() => onAccess(m)}>Access</button>}
          <button className="btn btn-sm" onClick={() => setEditing(!editing)}>Edit</button>
          {!isAdmin && <button className="btn btn-sm btn-danger" onClick={remove}>Remove</button>}
        </td>
      </tr>
      {editing && (
        <tr className="member-edit"><td colSpan={6}>
          <div className="row gap wrap">
            {!isAdmin && (
              <label className="inline-field"><span>Role</span>
                <select className="input input-sm" defaultValue={m.title || "Viewer"} onChange={(e) => patch({ role: e.target.value }, "Role updated")}>{TITLES.map((t) => <option key={t}>{t}</option>)}</select>
              </label>
            )}
            <label className="inline-field"><span>Set password</span>
              <input className="input input-sm mono" type="text" value={pw} placeholder="min 8 chars" onChange={(e) => setPw(e.target.value)} />
            </label>
            <button className="btn btn-sm" disabled={pw.length < 8} onClick={() => { patch({ password: pw }, "Password set"); setPw(""); }}>Save password</button>
            {!isAdmin && <button className="btn btn-sm" onClick={() => patch({ disabled: !m.disabled }, m.disabled ? "Re-enabled" : "Disabled")}>{m.disabled ? "Enable" : "Disable"}</button>}
          </div>
        </td></tr>
      )}
    </>
  );
}

export default function OrgConsole({ toast }) {
  const org = usePoll(() => api.get("/v1/org"), [], 5000);
  const [adding, setAdding] = useState(false);
  const [access, setAccess] = useState(null);
  const d = org.data;
  const members = useMemo(() => (d?.members || []).slice().sort((a, b) => (a.org_role === "admin" ? -1 : 1) - (b.org_role === "admin" ? -1 : 1)), [d]);
  if (!d) return <Pending error={org.error} />;
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Team &amp; Access</h1>
          <p className="muted">Manage who is in <strong>{d.org.name}</strong> and exactly which MCP servers and tools each employee may use. Assignments are enforced on every call, not just hidden in the UI.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setAdding(true)}>+ Add member</button>
      </div>
      <div className="kpi-row">
        <div className="kpi"><span className="kpi-v">{d.members.length}</span><span className="kpi-l">members</span></div>
        <div className="kpi"><span className="kpi-v">{d.admins}</span><span className="kpi-l">admins</span></div>
        <div className="kpi"><span className="kpi-v">{d.employees}</span><span className="kpi-l">employees</span></div>
        <div className="kpi"><span className="kpi-v">{d.org.size || "—"}</span><span className="kpi-l">org size</span></div>
      </div>
      <Card title="Members" subtitle="Employees see only the tools you assign; admins have full control of the workspace">
        <table className="table">
          <thead><tr><th>Member</th><th>Role</th><th>Assigned access</th><th>Sign-in</th><th>Last login</th><th /></tr></thead>
          <tbody>
            {members.map((m) => <MemberRow key={m.account_id} m={m} toast={toast} onChange={org.reload} onAccess={setAccess} />)}
          </tbody>
        </table>
        {members.length === 0 && <Empty>No members yet.</Empty>}
      </Card>
      {adding && <AddMember onClose={() => setAdding(false)} onAdded={org.reload} toast={toast} />}
      {access && <AccessDrawer member={access} onClose={() => setAccess(null)} toast={toast} reload={org.reload} />}
    </div>
  );
}
