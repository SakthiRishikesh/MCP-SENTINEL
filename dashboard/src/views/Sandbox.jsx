import { useState } from "react";
import { api, usePoll } from "../api.js";
import { SandboxPreview } from "../components/sandbox.jsx";
import { Card, Drawer, Empty, ErrorNote, Pending, Pill, StatTile } from "../components/ui.jsx";
import { timeAgo } from "../format.js";

function StatusCard({ isAdmin, toast }) {
  const status = usePoll(() => api.get("/v1/sandbox/status"), [], 4000);
  const [error, setError] = useState("");
  const s = status.data;
  if (!s) return <Card title="Sandbox engine"><Pending error={status.error} label="Checking Docker…" /></Card>;
  async function build() {
    setError("");
    try {
      await api.post("/v1/sandbox/image/build");
      toast("Building the sandbox image…");
      status.reload();
    } catch (e) {
      setError(e.message);
    }
  }
  const backend = s.active_backend;
  return (
    <Card title="Sandbox engine" subtitle={s.containment}
      actions={isAdmin && s.docker.available && <button className="btn btn-sm" disabled={s.build.status === "building"} onClick={build}>{s.build.status === "building" ? "Building…" : s.docker.image_ready ? "Rebuild image" : "Build image"}</button>}>
      <div className="row gap wrap">
        <Pill value={backend === "docker" ? "ACTIVE" : backend === "process" ? "MONITOR" : "RESTRICTED"} title={backend} />
        <strong>{backend === "docker" ? "Docker containment" : backend === "process" ? "Process sandbox (observation only)" : backend === "off" ? "Pre-flight disabled" : "Docker required but unavailable"}</strong>
        <span className="muted small">mode {s.mode} · pre-flight {s.preflight}</span>
      </div>
      <dl className="kv small">
        <dt>Docker</dt><dd>{s.docker.detail}</dd>
        <dt>Image</dt><dd className="mono">{s.docker.image} {s.docker.image_ready ? <span className="good-text">ready</span> : <span className="warn-text">not built</span>}</dd>
        <dt>Blast radius</dt><dd>block calls deleting more than {s.limits.max_deletes} files or modifying more than {s.limits.max_modifications}</dd>
      </dl>
      {s.build.status !== "idle" && (
        <div className="small"><Pill value={s.build.status === "ready" ? "ACCEPTED" : s.build.status === "failed" ? "REJECTED" : "PENDING"} title={s.build.status} /> image build {s.build.status}
          {(s.build.log || []).length > 0 && <pre className="logs">{s.build.log.join("\n")}</pre>}</div>
      )}
      {backend === "process" && <p className="small warn-text">Install and start Docker Desktop, then build the image: every call then runs with no network, a read-only system and only a copy of your files. Without it, tools that execute code or send data cannot be pre-flighted and changes to files are escalated when they cannot be verified.</p>}
      <ErrorNote error={error} />
    </Card>
  );
}

function UndoList({ isAdmin, toast }) {
  const undo = usePoll(() => api.get("/v1/undo?limit=30"), [], 6000);
  const [busy, setBusy] = useState("");
  async function revert(u) {
    setBusy(u.undo_id);
    try {
      const res = await api.post(`/v1/undo/${u.undo_id}`);
      toast(`Undone: ${res.restored.length} restored, ${res.removed.length} removed${res.conflicts.length ? `, ${res.conflicts.length} conflict(s)` : ""}`);
      undo.reload();
    } catch (e) {
      toast(e.message);
    }
    setBusy("");
  }
  const rows = undo.data || [];
  return (
    <Card title="Time machine" subtitle="Every file change a tool call made is journalled with the previous version">
      {rows.length === 0 ? <Empty>No file changes yet.</Empty> : (
        <table className="table">
          <thead><tr><th>When</th><th>Tool</th><th>Changes</th><th>Status</th><th /></tr></thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.undo_id}>
                <td className="small muted">{timeAgo(u.created_at)}</td>
                <td className="mono small">{u.exposed_name}</td>
                <td className="small">{u.summary}{u.evasion && <div className="danger-text">sandbox evasion: unpredicted changes were reverted</div>}</td>
                <td><Pill value={u.status} /></td>
                <td>{u.status === "AVAILABLE" && <button className="btn btn-sm" disabled={!isAdmin || busy === u.undo_id} onClick={() => revert(u)}>{busy === u.undo_id ? "Undoing…" : "Undo"}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

export default function Sandbox({ isAdmin, toast }) {
  const runs = usePoll(() => api.get("/v1/sandbox/runs?limit=60"), [], 4000);
  const [open, setOpen] = useState(null);
  const list = runs.data || [];
  const count = (v) => list.filter((r) => r.verdict === v).length;
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Sandbox pre-flight</h1>
        <p className="muted">Zero trust for every local tool call: before a call touches your real files, Sentinel runs it against a throw-away copy in an isolated sandbox with planted decoy credentials and no real network, and reads what actually happened. A malicious call is blocked even if someone approves it; a surprising one waits for a person with a preview of its exact effect; after a real call, any change the sandbox did not predict is reverted.</p>
      </div></div>
      <div className="tile-grid">
        <StatTile label="Pre-flighted (recent)" value={list.length} />
        <StatTile label="Blocked" value={count("MALICIOUS") + count("DANGEROUS")} tone={count("MALICIOUS") + count("DANGEROUS") ? "critical" : undefined} />
        <StatTile label="Escalated" value={list.filter((r) => r.action === "ESCALATED").length} tone="warning" />
        <StatTile label="Not verifiable" value={count("INCONCLUSIVE")} />
      </div>
      <div className="grid-2">
        <StatusCard isAdmin={isAdmin} toast={toast} />
        <UndoList isAdmin={isAdmin} toast={toast} />
      </div>
      <Card title="Recent pre-flight runs">
        {list.length === 0 ? <Empty>No local tool calls yet. Calls to remote (HTTP) servers run elsewhere and are guarded by policy, taint tracking and output checks instead.</Empty> : (
          <table className="table">
            <thead><tr><th>When</th><th>Tool</th><th>Verdict</th><th>Action</th><th>Effect</th><th>Backend</th></tr></thead>
            <tbody>
              {list.map((r) => (
                <tr key={r.run_id} className="clickable" onClick={() => setOpen(r)}>
                  <td className="small muted">{timeAgo(r.created_at)}</td>
                  <td className="mono small">{r.exposed_name}</td>
                  <td><Pill value={r.verdict} /></td>
                  <td><Pill value={r.action === "ALLOWED" ? "ALLOW" : r.action === "BLOCKED" ? "BLOCK" : r.action === "ESCALATED" ? "HUMAN_APPROVAL" : "PENDING"} title={r.action} /></td>
                  <td className="small">{r.preview?.headline}{r.reasons?.[0] ? <div className="muted">{r.reasons[0]}</div> : null}</td>
                  <td className="small muted">{r.backend}{r.duration_ms ? ` · ${Math.round(r.duration_ms)} ms` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {open && (
        <Drawer title={`Pre-flight · ${open.exposed_name}`} onClose={() => setOpen(null)}>
          <p className="muted small">{timeAgo(open.created_at)} · workflow <span className="mono">{open.workflow_id}</span> · by {open.subject} · receipt <span className="mono">{(open.receipt_id || "").slice(0, 8)}</span></p>
          <SandboxPreview sandbox={open} />
          {(open.findings || []).length > 0 && (
            <ul className="plain small">{open.findings.map((f, i) => <li key={i}><Pill value={f.level === "NOTICE" ? "INFO" : f.level} title={f.rule} /> {f.message}</li>)}</ul>
          )}
        </Drawer>
      )}
    </div>
  );
}
