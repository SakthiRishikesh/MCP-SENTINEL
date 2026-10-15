import { api, usePoll } from "../api.js";
import { DecisionMix } from "../components/charts.jsx";
import { Card, Empty, Meter, Pill, StatTile, severityTone } from "../components/ui.jsx";
import { bandFor, compact, routeTo, timeAgo } from "../format.js";

export default function Overview({ summary, onReceipt }) {
  const receipts = usePoll(() => api.get("/v1/receipts?limit=14"), [], 3000);
  const events = usePoll(() => api.get("/v1/events?limit=10&exclude_decisions=true"), [], 4000);
  const flows = usePoll(() => api.get("/v1/integrity/toxic-flows"), [], 10000);
  const workflows = usePoll(() => api.get("/v1/workflows?limit=6"), [], 5000);
  if (!summary) return <Empty>Connecting to the control plane…</Empty>;
  const s = summary;
  const risk = s.active_risk || 0;
  const tf = flows.data;
  return (
    <div className="stack">
      <div className="overview-top">
        <Card className="hero-card" title="Active risk" subtitle="Highest risk decided in the last 15 minutes">
          <div className="hero">
            <span className="hero-figure">{risk}</span>
            <span className="hero-unit">/100</span>
            <Pill value={bandFor(risk)} />
          </div>
          <Meter value={risk} />
          <p className="muted small">Risk = likelihood (fused evidence) × impact (capability, data class, egress). Hard policy overrides it.</p>
        </Card>
        <div className="tile-grid">
          <StatTile label="MCP servers" value={s.servers.total} hint={`${s.servers.connected} connected · ${s.servers.trusted} trusted`} onClick={() => routeTo("/servers")} />
          <StatTile label="Protected tools" value={s.tools.total} hint={`${s.tools.quarantined} quarantined · ${s.tools.under_review} under review`} tone={s.tools.quarantined ? "critical" : ""} onClick={() => routeTo("/tools")} />
          <StatTile label="Tool calls (24h)" value={compact(s.calls_24h)} hint={`${s.high_risk_calls} high-risk`} onClick={() => routeTo("/audit")} />
          <StatTile label="Blocked calls" value={s.blocked_calls} hint="policy, data-flow or risk" tone={s.blocked_calls ? "critical" : ""} onClick={() => routeTo("/audit")} />
          <StatTile label="Step-ups / approvals" value={s.mfa_challenges + s.human_approvals} hint={`${s.pending_approvals + (s.pending_mfa || 0)} waiting now`} tone={s.pending_approvals + (s.pending_mfa || 0) ? "serious" : ""} onClick={() => routeTo("/approvals")} />
          <StatTile label="Rug-pull alerts" value={s.rug_pulls} hint={`${s.tool_changes} open definition changes`} tone={s.rug_pulls ? "critical" : ""} onClick={() => routeTo("/integrity")} />
          <StatTile label="High-severity alerts" value={s.behavior_alerts} hint="rug pulls, runtime & output anomalies (24h)" tone={s.behavior_alerts ? "warning" : ""} onClick={() => routeTo("/audit")} />
          <StatTile label="Active leases" value={s.active_leases} hint="temporary capability grants" onClick={() => routeTo("/leases")} />
          <StatTile label="Caller anomalies" value={s.entity_anomalies_24h || 0} hint={`${s.entities || 0} callers profiled (24h)`} tone={s.entity_anomalies_24h ? "warning" : ""} onClick={() => routeTo("/entities")} />
        </div>
      </div>

      <div className="grid-2">
        <Card title="Decision mix" subtitle="Last 24 hours">
          <DecisionMix counts={s.decisions_24h} />
        </Card>
        <Card
          title="Toxic-flow exposure"
          subtitle="Can an injected agent read private data, ingest untrusted content AND send it out?"
          actions={<button className="btn btn-sm" onClick={() => routeTo("/integrity")}>Open map</button>}
        >
          {!tf ? <Empty>Analysing toolset…</Empty> : (
            <div className="trifecta-summary">
              <div className="row gap">
                <Pill value={tf.level} />
                <span>{tf.lethal_trifecta ? "Lethal trifecta reachable with the current toolset" : "No complete toxic path"}</span>
              </div>
              <div className="legs">
                <span className="leg"><strong>{tf.counts.private_sources}</strong> private-data sources</span>
                <span className="leg"><strong>{tf.counts.untrusted_sources}</strong> untrusted-content sources</span>
                <span className="leg"><strong>{tf.counts.egress_sinks}</strong> egress sinks</span>
              </div>
              {tf.injection_to_rce && <p className="warn-text">⚠ Untrusted content can reach a code-execution tool (injection → RCE path).</p>}
              <p className="muted small">Sentinel enforces this per workflow at call time: completing the trifecta raises risk; moving tainted secrets out is a hard block.</p>
            </div>
          )}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Live decisions" subtitle="Every call is decided outside the model and receipted">
          {!receipts.data || receipts.data.length === 0 ? <Empty>No tool calls yet. Connect Claude Desktop (Connect tab) and ask it to use a tool.</Empty> : (
            <table className="table compact fixed">
              <colgroup><col /><col style={{ width: "164px" }} /><col style={{ width: "88px" }} /><col style={{ width: "76px" }} /></colgroup>
              <thead><tr><th>Tool · why</th><th>Decision</th><th>Risk</th><th>When</th></tr></thead>
              <tbody>
                {receipts.data.map((r) => (
                  <tr key={r.receipt_id} className="clickable" onClick={() => onReceipt(r)}>
                    <td className="truncate" title={(r.reasons || [])[0]}>
                      <span className="mono">{r.tool}</span>
                      <div className="muted small truncate">{(r.reasons || [])[0]}</div>
                    </td>
                    <td><Pill value={r.decision} kind="decision" /></td>
                    <td><Meter value={r.risk_score} width={72} /></td>
                    <td className="muted nowrap small">{timeAgo(r.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Security alerts" subtitle="Rug pulls, behaviour drift, sandbox verdicts, approvals">
          {!events.data || events.data.length === 0 ? <Empty>All quiet.</Empty> : (
            <ul className="alerts">
              {events.data.map((e) => (
                <li key={e.event_id} className={`alert ${e.severity}`}>
                  <Pill value={e.severity} />
                  <div>
                    <div>{e.message}</div>
                    <div className="muted small">{e.event_type} · {timeAgo(e.timestamp)}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Active workflows" subtitle="Per-session data flow (lethal-trifecta legs) and risk memory"
        actions={<button className="btn btn-sm" onClick={() => routeTo("/workflows")}>All workflows</button>}>
        {!workflows.data || workflows.data.length === 0 ? <Empty>No workflows yet.</Empty> : (
          <div className="wf-cards">
            {workflows.data.map((w) => (
              <button key={w.workflow_id} className="wf-card" onClick={() => routeTo(`/workflows/${encodeURIComponent(w.workflow_id)}`)}>
                <span className="mono small truncate">{w.workflow_id}</span>
                <TrifectaDots t={w.trifecta} />
                <span className="row gap small"><Meter value={w.max_risk} width={70} /> {w.calls} calls · {w.blocked} blocked</span>
                {w.secret_in_context && <span className="chip SECRET">secret in context</span>}
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

export function TrifectaDots({ t }) {
  if (!t) return null;
  const legs = [
    ["private_data", "Private data read"],
    ["untrusted_content", "Untrusted content ingested"],
    ["external_comm", "External communication"],
  ];
  const complete = legs.every(([k]) => t[k]);
  return (
    <span className={`trifecta ${complete ? "complete" : ""}`} title={complete ? "All three legs present" : "Lethal trifecta legs"}>
      {legs.map(([k, label]) => (
        <span key={k} className={`leg-dot ${t[k] ? "on" : ""}`} title={`${label}: ${t[k] ? "yes" : "no"}`}>
          {t[k] ? "●" : "○"}
        </span>
      ))}
      <span className="small muted">{complete ? " trifecta" : ""}{t.injection_seen ? " · injection seen" : ""}</span>
    </span>
  );
}
