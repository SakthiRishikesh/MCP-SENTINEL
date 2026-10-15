import { api, usePoll } from "../api.js";
import { Card, Chips, Empty, Pending, Pill } from "../components/ui.jsx";
import { routeTo, timeAgo } from "../format.js";

/** 24-slot UTC hour-of-day histogram of a subject's activity. */
function HourBars({ hours }) {
  const max = Math.max(1, ...(hours || []));
  return (
    <div className="hourbars" title="Activity by hour of day (UTC)">
      {(hours || []).map((h, i) => (
        <span key={i} className="hourbar" title={`${String(i).padStart(2, "0")}:00 UTC — ${h} call${h === 1 ? "" : "s"}`}>
          <span className="hourbar-fill" style={{ height: `${Math.round((h / max) * 100)}%` }} />
        </span>
      ))}
    </div>
  );
}

function EntityDetail({ subject }) {
  const q = usePoll(() => api.get(`/v1/entities/${encodeURIComponent(subject)}`), [subject], 4000);
  const e = q.data;
  if (!e) return <Pending error={q.error} />;
  return (
    <div className="stack">
      <div className="row gap wrap">
        <h2 className="mono">{e.subject}</h2>
        <Pill value={e.established ? "ESTABLISHED" : "LEARNING"} />
        {e.anomaly_count > 0 && <span className="chip RESTRICTED">{e.anomaly_count} anomalies</span>}
      </div>
      <div className="kpi-row">
        <div className="kpi"><span className="kpi-v">{e.calls}</span><span className="kpi-l">calls</span></div>
        <div className="kpi"><span className="kpi-v">{e.sensitive_calls}</span><span className="kpi-l">sensitive</span></div>
        <div className="kpi"><span className="kpi-v">{Math.round(e.sensitive_rate * 100)}%</span><span className="kpi-l">sensitive rate</span></div>
        <div className="kpi"><span className="kpi-v">{e.denied}</span><span className="kpi-l">denied</span></div>
        <div className="kpi"><span className="kpi-v">{e.servers}</span><span className="kpi-l">servers</span></div>
        <div className="kpi"><span className="kpi-v">{e.peak_minute_rate}</span><span className="kpi-l">peak/min</span></div>
      </div>
      <Card title="Learned baseline" subtitle="What is normal for this caller; deviations from it become risk evidence">
        <dl className="kv small">
          <dt>Capabilities</dt><dd><Chips items={e.capabilities} /></dd>
          <dt>Agents</dt><dd>{(e.agents || []).map((a) => <span key={a} className="mono chip">{a}</span>)}</dd>
          <dt>Top tools</dt><dd>{(e.top_tools || []).map((t) => <span key={t.tool} className="mono chip" title={`${t.count} calls`}>{t.tool}</span>)}</dd>
          <dt>First seen</dt><dd>{timeAgo(e.first_seen)}</dd>
          <dt>Last seen</dt><dd>{timeAgo(e.last_seen)}</dd>
        </dl>
        <h4>Activity by hour (UTC)</h4>
        <HourBars hours={e.hours} />
      </Card>
      <Card title="Behavioural anomalies" subtitle="Calls that deviated from this caller's baseline">
        {(e.recent_anomalies || []).length === 0 ? <Empty>No anomalies — this caller has stayed within its baseline.</Empty> : (
          <ul className="alerts">
            {e.recent_anomalies.map((a, i) => (
              <li key={i} className={`alert ${a.severity}`}>
                <Pill value={a.severity} />
                <div>
                  <div>{a.message}</div>
                  <div className="muted small">{a.tool ? <span className="mono">{a.tool}</span> : null} {a.at ? `· ${timeAgo(a.at)}` : ""}</div>
                  {(a.anomalies || []).length > 1 && <ul className="plain small muted">{a.anomalies.slice(1).map((x, j) => <li key={j}>• {x}</li>)}</ul>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

export default function Entities({ selected }) {
  const list = usePoll(() => api.get("/v1/entities"), [], 5000);
  const rows = list.data || [];
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Entities</h1>
          <p className="muted">Behavioural analytics for every caller — users and agents, not just servers. Sentinel learns each one's normal tools, servers, capabilities and hours, then flags deviations (a new sensitive capability, an unfamiliar agent, off-hours access, volume spikes) as risk evidence on the call.</p>
        </div>
      </div>
      {list.error && <Pending error={list.error} />}
      <div className="split">
        <div className="split-list">
          {rows.length === 0 ? <Empty>No callers yet. Ask Claude to use a tool and a profile appears here.</Empty> : (
            <ul className="list">
              {rows.map((e) => (
                <li key={e.subject}>
                  <button className={`list-item ${selected === e.subject ? "active" : ""}`} onClick={() => routeTo(`/entities/${encodeURIComponent(e.subject)}`)}>
                    <div className="row between"><span className="mono truncate">{e.subject}</span><Pill value={e.established ? "ESTABLISHED" : "LEARNING"} /></div>
                    <div className="muted small">{e.calls} calls · {e.sensitive_calls} sensitive · {e.servers} server{e.servers === 1 ? "" : "s"}</div>
                    <div className="row between small">
                      <span className="muted">{(e.capabilities || []).slice(0, 3).join(", ")}</span>
                      {e.anomalies > 0 && <span className="danger-text">⚠ {e.anomalies}</span>}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="split-main">{selected ? <EntityDetail subject={selected} /> : <Empty>Select a caller to see its baseline and anomalies.</Empty>}</div>
      </div>
    </div>
  );
}
