import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Chips, Empty, ErrorNote, Findings, Json, Meter, Pill, Tabs } from "../components/ui.jsx";
import { routeTo, timeAgo } from "../format.js";

function DiffLines({ lines }) {
  if (!lines || lines.length === 0) return null;
  return (
    <pre className="diff">
      {lines.map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") ? "hunk" : ""}>{l || " "}</div>
      ))}
    </pre>
  );
}

function ChangeView({ changeId, toast, isAdmin, onResolved }) {
  const change = usePoll(() => api.get(`/v1/integrity/changes/${changeId}`), [changeId]);
  const c = change.data;
  if (!c) return <ErrorNote error={change.error} />;
  const diff = c.diff || {};
  async function resolve(action) {
    try {
      await api.post(`/v1/integrity/changes/${changeId}/resolve`, { action });
      toast(`Change ${action}ed`);
      change.reload();
      onResolved();
    } catch (e) {
      toast(e.message, true);
    }
  }
  return (
    <div className="stack">
      <div className="row between wrap">
        <div className="row gap wrap">
          <h2 className="mono">{c.tool_name}</h2>
          <Pill value={c.classification} /> <Pill value={c.status} /> <span className="chip">{c.change_type}</span>
          <span className="row gap small">rug-pull score <Meter value={c.score} width={90} /></span>
        </div>
        {isAdmin && c.status === "OPEN" && (
          <div className="row gap">
            <button className="btn btn-sm btn-danger" onClick={() => resolve("reject")}>Reject (keep blocked)</button>
            <button className="btn btn-sm btn-primary" onClick={() => resolve("accept")}>Accept & re-pin</button>
          </div>
        )}
      </div>
      <p className="muted small">Detected {timeAgo(c.detected_at)} on {c.server_id}. Until accepted, the model keeps receiving the pinned definition{c.classification === "MALICIOUS" ? " and the tool is quarantined" : ""}.</p>
      <Card title="Why Sentinel flagged it"><Findings items={c.findings} /></Card>
      {diff.description && (
        <Card title="Description diff" subtitle={`similarity ${Math.round((diff.description.similarity || 0) * 100)}%`}>
          <DiffLines lines={diff.description.unified} />
        </Card>
      )}
      {(diff.params || diff.annotations || diff.capabilities || diff.other_fields) && (
        <Card title="Structural & semantic changes">
          <dl className="kv">
            {diff.params?.added?.length > 0 && <><dt>Parameters added</dt><dd><Chips items={diff.params.added} className="add" /></dd></>}
            {diff.params?.removed?.length > 0 && <><dt>Parameters removed</dt><dd><Chips items={diff.params.removed} className="del" /></dd></>}
            {diff.params?.newly_required?.length > 0 && <><dt>Newly required</dt><dd><Chips items={diff.params.newly_required} /></dd></>}
            {diff.params?.changed?.length > 0 && <><dt>Parameters changed</dt><dd className="mono small">{diff.params.changed.map((p) => `${p.param}${p.relaxed ? ` (relaxed: ${p.relaxed.join(", ")})` : ""}`).join("; ")}</dd></>}
            {diff.annotations && <><dt>Annotations</dt><dd className="mono small">{Object.entries(diff.annotations).map(([k, [o, n]]) => `${k}: ${o} → ${n}`).join("; ")}</dd></>}
            {diff.capabilities && <><dt>Capabilities</dt><dd><Chips items={diff.capabilities.old} /> → <Chips items={diff.capabilities.new} /> <span className="muted small">({diff.capabilities.sensitivity?.join(" → ")})</span></dd></>}
            {diff.other_fields && <><dt>Other fields</dt><dd className="mono small">{diff.other_fields.join(", ")}</dd></>}
          </dl>
        </Card>
      )}
      <div className="grid-2">
        <Card title="Pinned (approved)"><Json value={c.old_definition} /></Card>
        <Card title="Live (what the server advertises now)"><Json value={c.new_definition} /></Card>
      </div>
    </div>
  );
}

function ToxicFlows() {
  const flows = usePoll(() => api.get("/v1/integrity/toxic-flows"), [], 10000);
  const f = flows.data;
  if (!f) return <ErrorNote error={flows.error} />;
  const legs = [
    ["private_sources", "Private-data sources", "read files, mail, databases, secrets"],
    ["untrusted_sources", "Untrusted-content sources", "web pages, issues, emails, lookups"],
    ["egress_sinks", "Egress sinks", "send, post, fetch URLs, execute code"],
  ];
  return (
    <div className="stack">
      <div className="row gap wrap">
        <Pill value={f.level} />
        <strong>{f.lethal_trifecta ? "The lethal trifecta is reachable with the current toolset." : "No complete toxic path in the current toolset."}</strong>
        {f.injection_to_rce && <span className="warn-text">Untrusted content → code execution path exists.</span>}
      </div>
      <div className="flow-columns">
        {legs.map(([k, title, hint]) => (
          <Card key={k} title={`${title} (${f.legs[k].length})`} subtitle={hint}>
            {f.legs[k].length === 0 ? <Empty>none</Empty> : <ul className="plain mono small">{f.legs[k].map((n) => <li key={n}>{n}</li>)}</ul>}
          </Card>
        ))}
      </div>
      {f.example_paths.length > 0 && (
        <Card title="Example toxic paths" subtitle="private → untrusted → egress">
          <table className="table compact">
            <thead><tr><th>Reads private data</th><th>Ingests untrusted content</th><th>Sends it out</th><th>Scope</th></tr></thead>
            <tbody>{f.example_paths.map((p, i) => (
              <tr key={i}><td className="mono">{p.private_source}</td><td className="mono">{p.untrusted_source}</td><td className="mono">{p.egress_sink}</td><td>{p.single_server ? "single server" : `${p.servers.length} servers`}</td></tr>
            ))}</tbody>
          </table>
        </Card>
      )}
      <Card title="Remediation">
        <p>{f.remediation.explanation}</p>
        {f.remediation.remove_or_restrict_servers.length > 0 && <p>Smallest leg to cut: <Chips items={f.remediation.remove_or_restrict_servers.map((id) => f.server_names[id] || id)} /></p>}
      </Card>
    </div>
  );
}

export default function Integrity({ toast, isAdmin, selected }) {
  const [tab, setTab] = useState("Rug pulls & changes");
  const [status, setStatus] = useState("OPEN");
  const changes = usePoll(() => api.get(`/v1/integrity/changes${status === "ALL" ? "" : `?status=${status}`}`), [status], 5000);
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Integrity & rug-pull detection</h1>
          <p className="muted">Sentinel re-lists every server periodically, whenever a server announces <span className="mono">list_changed</span>, and just before sensitive calls. Any drift from the pinned definition is diffed, classified and contained.</p>
        </div>
      </div>
      <Tabs tabs={["Rug pulls & changes", "Toxic-flow map"]} value={tab} onChange={setTab} />
      {tab === "Toxic-flow map" ? <ToxicFlows /> : (
        <div className="split">
          <div className="split-list">
            <select className="input input-sm" value={status} onChange={(e) => setStatus(e.target.value)}>
              {["OPEN", "ALL", "ACCEPTED", "REJECTED", "AUTO_ACCEPTED", "SUPERSEDED"].map((s) => <option key={s}>{s}</option>)}
            </select>
            {(changes.data || []).length === 0 ? <Empty>No {status === "ALL" ? "" : status.toLowerCase()} changes. Definitions match their pins.</Empty> : (
              <ul className="list">
                {changes.data.map((c) => (
                  <li key={c.change_id}>
                    <button className={`list-item ${selected === c.change_id ? "active" : ""}`} onClick={() => routeTo(`/integrity/${c.change_id}`)}>
                      <div className="row between"><span className="mono">{c.tool_name}</span><Pill value={c.classification} /></div>
                      <div className="row between small muted"><span>{c.change_type} · score {c.score}</span><span>{timeAgo(c.detected_at)}</span></div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="split-main">
            {selected ? <ChangeView changeId={selected} toast={toast} isAdmin={isAdmin} onResolved={changes.reload} /> : <Empty>Select a change to see the diff.</Empty>}
          </div>
        </div>
      )}
    </div>
  );
}
