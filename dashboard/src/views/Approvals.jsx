import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Empty, ErrorNote, Json, Meter, Pending, Pill } from "../components/ui.jsx";
import { routeTo, timeAgo } from "../format.js";
import { SandboxPreview } from "../components/sandbox.jsx";

export function ApprovalPage({ kind, id, session, toast }) {
  const item = usePoll(() => api.get(kind === "mfa" ? `/v1/mfa/challenges/${id}` : `/v1/approvals/${id}`), [kind, id, session.token], 2000);
  const totp = usePoll(() => (session.token ? api.get("/v1/mfa/totp/status") : Promise.resolve(null)), [session.token]);
  const runs = usePoll(() => api.get(`/v1/sandbox/runs?${kind === "mfa" ? "challenge_id" : "approval_id"}=${id}&limit=1`), [kind, id], 5000);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const d = item.data;
  if (!d) return <Pending error={item.error} />;
  const pending = d.status === "PENDING";
  const subject = d.subject;
  const mine = session.identity && session.identity.subject === subject;

  async function run(fn, ok) {
    setBusy(true);
    setError("");
    try {
      await fn();
      toast(ok);
      item.reload();
    } catch (e) {
      setError(e.message);
    }
    setBusy(false);
  }

  return (
    <div className="stack approval-page">
      <div className="page-head">
        <div>
          <h1>{kind === "mfa" ? "🔐 Step-up authentication" : "✋ Human approval"}</h1>
          <p className="muted">An AI agent asked to run a sensitive tool. Review exactly what will run. Approval covers {kind === "mfa" ? "this workflow and — for CRITICAL tools — only these exact arguments" : "one execution of this exact request"}.</p>
        </div>
        <Pill value={d.status} />
      </div>
      {(d.sandbox || runs.data?.[0]) && (
        <Card title="What this call would do" subtitle="Sentinel already ran it once in the sandbox, against a copy of your files with decoy credentials and no real network">
          <SandboxPreview sandbox={d.sandbox || runs.data[0]} />
        </Card>
      )}
      <div className="grid-2">
        <Card title="Requested action">
          <dl className="kv">
            <dt>Tool</dt><dd className="mono">{d.exposed_name || d.tool_name || d.request?.exposed_name}</dd>
            <dt>Requested by</dt><dd className="mono">{subject}</dd>
            <dt>Workflow</dt><dd className="mono small">{d.workflow_id}</dd>
            {d.capability && <><dt>Capability</dt><dd><Pill value={d.capability} /></dd></>}
            <dt>Risk</dt><dd><Meter value={d.risk_score || 0} width={140} /></dd>
            <dt>Requested</dt><dd>{timeAgo(d.created_at)}</dd>
          </dl>
          <h4>Arguments</h4>
          <Json value={d.arguments_preview || d.request?.arguments_preview} />
        </Card>
        <Card title="Why Sentinel paused it">
          <ul className="plain">{(d.reasons || []).map((r, i) => <li key={i}>• {r}</li>)}</ul>
          {!pending && <p className="good-text">This request is {d.status.toLowerCase()}{d.method ? ` (${d.method})` : ""}{d.resolver ? ` by ${d.resolver}` : ""}. The agent's held call continues automatically, or it can retry.</p>}
          {pending && kind === "mfa" && (
            <div className="stack">
              {!mine && (
                <div className="notice">You are signed in as <strong>{session.identity?.subject || "nobody"}</strong>; this step-up belongs to <strong>{subject}</strong> and must be approved by them.</div>
              )}
              {mine && totp.data?.enrolled && (
                <form className="row gap" onSubmit={(e) => { e.preventDefault(); run(() => api.post(`/v1/mfa/challenges/${id}/verify`, { code }), "Step-up satisfied"); }}>
                  <input className="input otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
                  <button className="btn btn-primary" disabled={busy || code.length !== 6}>Verify & approve</button>
                </form>
              )}
              {mine && totp.data && !totp.data.enrolled && (
                <div className="stack">
                  {session.authMode === "demo" && <button className="btn btn-primary" disabled={busy} onClick={() => run(() => api.post(`/v1/mfa/challenges/${id}/verify`, { demo: true }), "Approved (demo confirmation)")}>Approve (demo confirmation)</button>}
                  <p className="muted small">No authenticator enrolled for {subject}. <a href="#/connect">Enrol TOTP</a> so step-ups require a real second factor.</p>
                </div>
              )}
              {mine && <button className="btn btn-danger" disabled={busy} onClick={() => run(() => api.post(`/v1/mfa/challenges/${id}/deny`), "Denied")}>Deny</button>}
            </div>
          )}
          {pending && kind === "approval" && (
            <div className="row gap">
              <button className="btn btn-primary" disabled={busy || !session.isAdmin} onClick={() => run(() => api.post(`/v1/approvals/${id}/approve`), "Approved")}>Approve once</button>
              <button className="btn btn-danger" disabled={busy || !session.isAdmin} onClick={() => run(() => api.post(`/v1/approvals/${id}/deny`), "Denied")}>Deny</button>
              {!session.isAdmin && <span className="muted small">Requires SECURITY_ADMIN.</span>}
            </div>
          )}
          <ErrorNote error={error} />
        </Card>
      </div>
    </div>
  );
}

export default function Approvals({ inbox }) {
  const history = usePoll(() => api.get("/v1/approvals?limit=30"), [], 5000);
  const items = [...(inbox?.mfa || []), ...(inbox?.approvals || [])];
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Approvals inbox</h1>
          <p className="muted">Step-up and human approvals happen out of band — a prompt-injected model can ask, but only a person with the second factor can approve.</p>
        </div>
      </div>
      <Card title={`Waiting now (${items.length})`}>
        {items.length === 0 ? <Empty>Nothing is waiting for a human.</Empty> : (
          <ul className="inbox-list">
            {items.map((it) => {
              const id = it.challenge_id || it.approval_id;
              return (
                <li key={id} className="inbox-item">
                  <span>{it.kind === "mfa" ? "🔐" : "✋"}</span>
                  <div>
                    <strong className="mono">{it.exposed_name || it.tool_name}</strong>
                    <div className="muted small">{it.subject} · {timeAgo(it.created_at)} · {(it.reasons || [])[0]}</div>
                  </div>
                  <Meter value={it.risk_score || 0} width={90} />
                  <button className="btn btn-sm btn-primary" onClick={() => routeTo(`/approve/${it.kind}/${id}`)}>Review</button>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
      <Card title="Recent human approvals">
        {(history.data || []).length === 0 ? <Empty>No approval requests yet.</Empty> : (
          <table className="table compact">
            <thead><tr><th>Tool</th><th>Requested by</th><th>Status</th><th>Risk</th><th>Resolver</th><th>When</th></tr></thead>
            <tbody>{history.data.map((a) => (
              <tr key={a.approval_id} className="clickable" onClick={() => routeTo(`/approve/approval/${a.approval_id}`)}>
                <td className="mono">{a.tool_name}</td><td>{a.subject}</td><td><Pill value={a.status} /></td><td>{a.risk_score}</td><td>{a.resolver || "—"}</td><td className="muted">{timeAgo(a.created_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
