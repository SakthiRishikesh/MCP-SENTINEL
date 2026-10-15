import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, usePoll } from "../api.js";
import { Card, CopyButton, ErrorNote, Pending, Pill } from "../components/ui.jsx";

function Check({ tone, title, children }) {
  const icon = { ok: "✓", warn: "!", bad: "✕" }[tone];
  return (
    <li className={`check ${tone}`}>
      <span className="check-icon" aria-hidden="true">{icon}</span>
      <div><div className="check-title">{title}</div>{children && <div className="small muted">{children}</div>}</div>
    </li>
  );
}

/** What Sentinel can see of Claude Desktop on this computer, including anything that bypasses it. */
function DesktopStatus({ c }) {
  const d = c.desktop || {};
  const live = (c.clients || []).filter((x) => x.name.startsWith("Claude Desktop"));
  const connected = live.filter((x) => x.connected);
  const bypassExtensions = (d.extensions || []).filter((e) => e.enabled);
  return (
    <ul className="checks">
      {d.error ? <Check tone="bad" title="Claude Desktop config is unreadable">{d.error}</Check>
        : d.exists ? <Check tone="ok" title="Claude Desktop config found"><span className="mono">{d.config_path}</span></Check>
          : <Check tone="warn" title="No Claude Desktop config yet">Install Claude Desktop and start it once, or run the install command below. Expected at <span className="mono">{d.config_path}</span></Check>}
      {d.installed ? <Check tone="ok" title="MCP-Sentinel is installed in Claude Desktop" />
        : <Check tone="bad" title="MCP-Sentinel is not in Claude Desktop yet">Run the install command below, then restart Claude Desktop.</Check>}
      {connected.length > 0
        ? <Check tone="ok" title={`Connected now: ${connected.map((x) => x.name).join(", ")}`}>Claude's bridge checked in {Math.round(connected[0].seconds_ago)}s ago as <span className="mono">{connected[0].subject}</span>.</Check>
        : <Check tone="warn" title="Claude Desktop is not connected">{d.installed ? "Start (or restart) Claude Desktop; it launches Sentinel's bridge automatically." : "Install first, then restart Claude Desktop."}</Check>}
      {(d.unprotected_servers || []).map((name) => (
        <Check key={name} tone="bad" title={`"${name}" bypasses Sentinel`}>Claude Desktop runs it directly, so its calls are never checked. Move it behind Sentinel with the import command below.</Check>
      ))}
      {bypassExtensions.map((e) => (
        <Check key={e.id} tone="bad" title={`Extension "${e.name}" bypasses Sentinel`}>Desktop Extensions talk to Claude directly. Turn it off in Claude Desktop → Settings → Extensions and connect the same server here instead.</Check>
      ))}
    </ul>
  );
}

function TotpEnrollment({ session, toast }) {
  const status = usePoll(() => (session.token ? api.get("/v1/mfa/totp/status") : Promise.resolve(null)), [session.token]);
  const [enroll, setEnroll] = useState(null);
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    if (!enroll) return;
    QRCode.toDataURL(enroll.otpauth_uri, { margin: 1, width: 200 }).then(setQr).catch(() => setQr(""));
  }, [enroll]);
  async function start() {
    setError("");
    try {
      setEnroll(await api.post("/v1/mfa/totp/enroll", status.data?.enrolled ? { code } : {}));
      setCode("");
    } catch (e) {
      setError(e.message);
    }
  }
  async function activate() {
    setError("");
    try {
      await api.post("/v1/mfa/totp/activate", { code });
      toast("Authenticator activated — step-ups now require your TOTP code");
      setEnroll(null);
      setCode("");
      status.reload();
    } catch (e) {
      setError(e.message);
    }
  }
  if (!session.token) return <p className="muted">Sign in first.</p>;
  return (
    <div className="stack">
      <p>Status for <strong>{session.identity?.subject}</strong>: {status.data?.enrolled ? <span className="good-text">authenticator active</span> : <span className="warn-text">no authenticator — step-ups fall back to demo confirmation</span>}</p>
      {!enroll && (
        <div className="row gap">
          {status.data?.enrolled && <input className="input otp" placeholder="current code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} maxLength={6} />}
          <button className="btn btn-primary" onClick={start}>{status.data?.enrolled ? "Rotate authenticator" : "Enrol authenticator (TOTP)"}</button>
        </div>
      )}
      {enroll && (
        <div className="totp-enroll">
          {qr && <img src={qr} width={200} height={200} alt="TOTP QR code" />}
          <div className="stack">
            <p className="small">Scan with Google Authenticator, Microsoft Authenticator, 1Password or Authy — or type the secret:</p>
            <div className="row gap"><span className="mono secret">{enroll.secret}</span><CopyButton text={enroll.secret} /></div>
            <div className="row gap">
              <input className="input otp" inputMode="numeric" maxLength={6} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
              <button className="btn btn-primary" disabled={code.length !== 6} onClick={activate}>Activate</button>
            </div>
          </div>
        </div>
      )}
      <ErrorNote error={error} />
    </div>
  );
}

export default function Connect({ session, toast }) {
  const claude = usePoll(() => api.get("/v1/integrations/claude-desktop"), [], 5000);
  const c = claude.data;
  const account = session.account || {};
  const configText = c ? JSON.stringify(c.config, null, 2) : "";
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Connect</h1>
        <p className="muted">Add one MCP server to Claude Desktop or Claude Code — MCP-Sentinel — and every server you connect here appears behind it, risk-gated.</p>
      </div></div>
      <div className="grid-2">
        <Card title="1 · Claude Desktop" subtitle="Settings → Developer → Edit Config, or let the CLI do it">
          {!c ? <Pending error={claude.error} /> : (
            <div className="stack">
              <DesktopStatus c={c} />
              <div className="row between"><span className="small muted">claude_desktop_config.json</span><CopyButton text={configText} /></div>
              <pre className="json">{configText}</pre>
              <p className="small">Or run (keeps a backup of your config):</p>
              <div className="row gap"><code className="mono small cmd">{c.cli}</code><CopyButton text={c.cli} /></div>
              <p className="small">Move your existing Claude Desktop servers behind Sentinel in one step:</p>
              <div className="row gap"><code className="mono small cmd">{c.import_cli}</code><CopyButton text={c.import_cli} /></div>
              <ul className="plain small">{c.notes.map((n) => <li key={n}>ⓘ {n}</li>)}</ul>
            </div>
          )}
        </Card>
        <Card title="2 · Claude Code" subtitle="CLI, IDE extensions and the desktop app's Code tab">
          {c && (
            <div className="stack">
              <p className="small">Let the CLI register the same stdio bridge with Claude Code (uses <span className="mono">claude mcp add-json</span>):</p>
              <div className="row gap"><code className="mono small cmd">{c.claude_code_cli}</code><CopyButton text={c.claude_code_cli} /></div>
              <p className="small">Move your existing Claude Code servers (<span className="mono">~/.claude.json</span>, <span className="mono">.mcp.json</span>) behind Sentinel:</p>
              <div className="row gap"><code className="mono small cmd">{c.claude_code_import_cli}</code><CopyButton text={c.claude_code_import_cli} /></div>
              <p className="small">Or add it by hand:</p>
              <div className="row gap"><code className="mono small cmd">{c.claude_code}</code><CopyButton text={c.claude_code} /></div>
              <p className="small muted">Other Streamable-HTTP clients (Cursor, VS Code, MCP Inspector) can use <span className="mono">{c.streamable_http_url}</span> with <span className="mono">Authorization: Bearer &lt;token&gt;</span>; the endpoint validates Origin and is bound to 127.0.0.1 by default.</p>
            </div>
          )}
        </Card>
      </div>
      <div className="grid-2">
        <Card title="3 · Your account" subtitle="Roles come from your signed session — never from an MCP request">
          <p>Signed in as <strong>{account.name || account.email || account.account_id || "—"}</strong> <span className="muted small">{account.email}</span></p>
          <p className="row gap wrap">
            {(account.roles || []).map((r) => <Pill key={r} value={r} />)}
            {account.account_type && <Pill value={account.org_role ? `${account.account_type}/${account.org_role}` : account.account_type} />}
            {account.organization && <span className="muted small">· {account.organization.name}</span>}
          </p>
          <p className="muted small">Claude Desktop's local bridge acts as <span className="mono">local-user</span>. The seeded individual account (<span className="mono">you@demo.dev</span>) shares that subject, so it can approve the bridge's step-ups.</p>
          <button className="btn btn-sm" onClick={session.logout}>Log out</button>
        </Card>
        <Card title="4 · Step-up authenticator" subtitle="Real RFC 6238 TOTP; codes are single-use (replay-protected)">
          <TotpEnrollment session={session} toast={toast} />
        </Card>
      </div>
    </div>
  );
}
