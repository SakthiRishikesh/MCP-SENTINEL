import { Empty, Pill } from "./ui.jsx";

const VERDICT_TEXT = {
  SAFE: "Tested in the sandbox first: nothing unexpected happened.",
  SUSPICIOUS: "Tested in the sandbox first: this call does something you should check before it runs.",
  DANGEROUS: "Blocked: in the sandbox this call had far more effect than a normal request should.",
  MALICIOUS: "Blocked: in the sandbox this tool did something no honest tool does. No approval can override this.",
  INCONCLUSIVE: "Sentinel could not test this call in the sandbox.",
};

export function UnifiedDiff({ text }) {
  if (!text) return null;
  return (
    <pre className="diff">
      {text.split("\n").map((line, i) => {
        const cls = line.startsWith("@@") ? "hunk" : line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "";
        return <div key={i} className={cls}>{line || " "}</div>;
      })}
    </pre>
  );
}

/** What the sandbox saw when it ran the call against a copy of the files. */
export function SandboxPreview({ sandbox, compact = false }) {
  if (!sandbox) return null;
  const p = sandbox.preview || {};
  const files = p.files || [];
  const tone = { SAFE: "ok", SUSPICIOUS: "warn", INCONCLUSIVE: "warn", DANGEROUS: "danger", MALICIOUS: "danger" }[sandbox.verdict] || "";
  return (
    <div className={`safety ${tone}`}>
      <div className="row gap wrap">
        <Pill value={sandbox.verdict} />
        <strong className="grow">{VERDICT_TEXT[sandbox.verdict] || sandbox.verdict}</strong>
        <span className="muted small">{sandbox.backend === "docker" ? "Docker sandbox" : sandbox.backend === "process" ? "process sandbox" : sandbox.backend}{p.duration_ms ? ` · ${Math.round(p.duration_ms)} ms` : ""}</span>
      </div>
      {(sandbox.reasons || []).length > 0 && <ul className="small">{sandbox.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
      <div><strong>Effect preview:</strong> {p.headline || "No file changes"}</div>
      {!compact && files.length > 0 && (
        <div className="stack">
          {files.slice(0, 12).map((f, i) => (
            <div key={i}>
              <div className="row gap small"><Pill value={f.change.toUpperCase()} /><span className="mono break">{f.path}</span>
                {f.size_after != null && <span className="muted">{f.size_before != null ? `${f.size_before} → ` : ""}{f.size_after} bytes</span>}</div>
              <UnifiedDiff text={f.diff} />
            </div>
          ))}
          {(p.more_files || 0) + Math.max(0, files.length - 12) > 0 && <div className="muted small">… and {(p.more_files || 0) + Math.max(0, files.length - 12)} more file(s)</div>}
        </div>
      )}
      {(p.network || []).length > 0 && (
        <div className="small"><strong>Network attempts</strong> (nothing left the sandbox): {p.network.map((n) => `${n.host || "?"}${n.port ? `:${n.port}` : ""}${n.canary || n.env_canary ? " (carrying credentials)" : ""}`).join(", ")}</div>
      )}
      {(p.processes || []).length > 0 && (
        <div className="small"><strong>Programs started:</strong> {p.processes.map((x) => `${x.name}${x.blocked ? " (blocked)" : ""}`).join(", ")}</div>
      )}
      {(p.decoy_reads || []).length > 0 && <div className="small danger-text"><strong>Opened planted credentials:</strong> {p.decoy_reads.map((d) => `~/${d}`).join(", ")}</div>}
      {(p.home_writes || []).length > 0 && <div className="small"><strong>Writes outside your folder:</strong> {p.home_writes.map((d) => `~/${d}`).join(", ")}</div>}
      {p.error && <div className="small muted">{p.error}</div>}
    </div>
  );
}

export function AuditTable({ audit }) {
  if (!audit) return <Empty>Not audited yet.</Empty>;
  const tools = Object.entries(audit.tools || {});
  return (
    <div className="stack">
      <div className="row gap wrap small">
        <Pill value={audit.status} /><span className="muted">{audit.backend} backend</span>
        {audit.summary && <span>{Object.entries(audit.summary).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(" · ")}</span>}
        {(audit.startup_hosts || []).length > 0 && <span className="muted">start-up network: {audit.startup_hosts.join(", ")}</span>}
      </div>
      {audit.note && <div className="muted small">{audit.note}</div>}
      {(audit.tool_list_mismatch || []).length > 0 && <div className="small warn-text">Tools missing inside the sandbox: {audit.tool_list_mismatch.join(", ")}</div>}
      {tools.length > 0 && (
        <table className="table compact">
          <thead><tr><th>Tool</th><th>Verdict</th><th>Observed</th></tr></thead>
          <tbody>
            {tools.map(([name, t]) => (
              <tr key={name}>
                <td className="mono">{name}</td>
                <td><Pill value={t.verdict} /></td>
                <td className="small">
                  {[t.writes && "writes files", t.deletes && "deletes files", (t.hosts || []).length && `network: ${t.hosts.join(", ")}`,
                    (t.processes || []).length && `runs: ${t.processes.join(", ")}`].filter(Boolean).join(" · ") || <span className="muted">no side effects</span>}
                  {(t.reasons || []).length > 0 && <div className="warn-text">{t.reasons.join("; ")}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
