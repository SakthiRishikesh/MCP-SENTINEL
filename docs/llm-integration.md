# Connecting Claude Desktop, Claude Code and other clients

MCP-Sentinel is an MCP server for your client and an MCP client for every upstream server. You add **only Sentinel** to your client. Every other server is connected through Sentinel's dashboard or API, and its tools appear in the client as `<server-slug>__<tool>`.

```
Claude Desktop ──stdio──► python -m sentinel.bridge ──HTTP (127.0.0.1)──► Sentinel API ──► upstream MCP servers
Claude Code / Cursor / any Streamable-HTTP client ─────── /mcp ─────────► Sentinel API ──► upstream MCP servers
```

## 1. Start Sentinel

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"   # or: python -m venv .venv && pip install -e ".[dev]"
(cd dashboard && npm install && npm run build)   # optional: the dashboard is then served by the API
mcp-sentinel serve                                # http://127.0.0.1:8443
```

You don't have to start it first: when Claude launches the bridge and nothing answers on a loopback `SENTINEL_API_URL`, the bridge starts the API in the background (log: `~/.mcp-sentinel/sentinel.log`). `mcp-sentinel stop` stops it, and `mcp-sentinel doctor` checks the whole setup.

In demo mode (the default), the dashboard signs you in automatically as `local-user` with the SECURITY_ADMIN role. The demo token endpoint only answers loopback clients, and the API binds to `127.0.0.1` by default. Do not expose demo mode on a network.

Without a built dashboard, run `npm run dev` in `dashboard/` and open http://localhost:5173. Set `SENTINEL_DASHBOARD_URL` so the approval links point at it.

## 2. Claude Desktop

```bash
mcp-sentinel install-claude        # or: python -m sentinel.cli install-claude
```

This merges the following entry into `claude_desktop_config.json` and keeps a timestamped `.sentinel-backup-*` copy of the old file:

```json
{
  "mcpServers": {
    "mcp-sentinel": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "sentinel.bridge"],
      "env": {"SENTINEL_API_URL": "http://127.0.0.1:8443", "SENTINEL_SUBJECT": "local-user", "SENTINEL_ROLE": "SECURITY_ADMIN"}
    }
  }
}
```

The config file is searched for in these locations:

* macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
* Linux (community builds such as `claude-desktop-debian`): `~/.config/Claude/claude_desktop_config.json`
* Windows: `%APPDATA%\Claude\claude_desktop_config.json`, plus the Microsoft Store (MSIX) location under `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\`

Pass `--config <path>` to use another file. `mcp-sentinel claude-config` prints the entry without writing anything. Restart Claude Desktop afterwards. The dashboard's **Connect** page then shows whether Claude Desktop is connected right now, and flags anything that still reaches Claude without Sentinel: other servers in the config and enabled **Desktop Extensions** (Settings → Extensions), which cannot be proxied and should be turned off.

**Move existing servers behind Sentinel:**

```bash
mcp-sentinel import-claude --replace [--sandbox]
```

This registers every other server in your Claude config with Sentinel. The command, arguments and environment are encrypted at rest. Sentinel connects to each server, pins its tools and scans them. `--sandbox` first runs each stdio server in the honeypot. `--replace` then removes every successfully imported server from Claude's config, so nothing can reach those tools around Sentinel. Servers that failed to import stay where they were, so they keep working.

**Add servers later** under *Servers → Connect server* in the dashboard. Presets cover Filesystem, Fetch, Memory and Git, or you can enter any command or URL. Local servers (`npx`, `uvx`, `docker`, `python`, …) run as child processes of the API, with a minimal inherited environment plus the variables you provide. Remote servers can use Streamable HTTP, with automatic fallback to legacy HTTP+SSE.

### Tool list refresh

Sentinel sends `notifications/tools/list_changed` whenever its catalogue changes. Claude Desktop does not reliably act on that notification and caches the tool list for the session. For that reason the bridge also exposes four meta-tools that work immediately:

| Meta-tool | Purpose |
|---|---|
| `sentinel_discover_tools` | list everything currently available through Sentinel, including servers added after Claude started |
| `sentinel_invoke` | call any of those tools by exact name. This goes through the **same enforcement** and is not a bypass |
| `sentinel_status` | pending approvals, active leases, recent decisions for this session |
| `sentinel_explain_decision` | explain a decision from the receipt id shown in a result |

To see newly added servers as native tools, toggle the `mcp-sentinel` connector off and on, or restart Claude Desktop.

### What Claude sees

* **Descriptions are pinned.** Claude receives the approved definition with a one-line Sentinel note, never a later live version.
* **Every result ends with a banner**, for example `🛡️ MCP-Sentinel · MONITOR · risk 30/100 (MONITOR) · receipt 1a2b3c4d`, so the model and the user can both see the decision.
* **Blocked calls** return `isError: true` with the reason and the receipt id. The model is told not to try to work around the block.
* **Step-up.** When a call needs MFA or human approval, the bridge **holds the call open**. It sends progress notifications every few seconds and opens the approval page in your browser (`SENTINEL_OPEN_BROWSER=1`). After you approve with TOTP, demo confirmation or an IdP MFA claim, the identical call is retried and its result is returned in the same turn. If nobody approves within `SENTINEL_WAIT_SECONDS` (default 50), the result contains the approval link, and Claude can call the tool again after approval.

### Bridge environment

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_API_URL` | `http://127.0.0.1:8443` | Sentinel API |
| `SENTINEL_TOKEN` | — | user access token (OIDC mode). In demo mode a loopback demo token is minted and renewed automatically |
| `SENTINEL_SUBJECT` / `SENTINEL_ROLE` | `local-user` / `SECURITY_ADMIN` | identity for demo tokens |
| `SENTINEL_OPEN_BROWSER` | `1` | open approval pages automatically |
| `SENTINEL_WAIT_SECONDS` | API setting (50) | how long a call is held open waiting for approval |
| `SENTINEL_WORKFLOW_ID` | per session | fixed workflow id. By default a new workflow starts after 30 minutes idle (`SENTINEL_WORKFLOW_IDLE_SECONDS`) |
| `SENTINEL_AUTOSTART` | `1` | start the API if it is not running (loopback URLs only) |

The bridge writes only MCP messages to stdout, and diagnostics go to stderr. On Windows it forces UTF-8 with `\n` line endings.

## 3. Claude Code

Claude Code (CLI, IDE extensions and the desktop app's Code tab) launches the same stdio bridge:

```bash
mcp-sentinel install-claude-code                 # runs: claude mcp add-json --scope user mcp-sentinel '{"type":"stdio",…}'
mcp-sentinel install-claude-code --scope project --project .   # or per project (.mcp.json)
```

If the `claude` CLI is not on PATH, the command prints the exact `claude mcp add-json …` line to run.

Move the servers Claude Code already uses behind Sentinel:

```bash
mcp-sentinel import-claude --from code --replace [--project /path/to/repo]
```

This reads user-scope servers from `~/.claude.json`, the project's local-scope servers, and the project's `.mcp.json`. It expands `${VAR}` / `${VAR:-default}` references the way Claude Code does, and reports unresolved ones instead of registering a broken server. Each server is registered with Sentinel. With `--replace`, each successfully imported server is then removed from Claude Code (`claude mcp remove`), so nothing bypasses Sentinel.

Sentinel announces catalogue changes with `notifications/tools/list_changed`. If new tools don't appear, run `/mcp` in Claude Code and reconnect `mcp-sentinel`.

## 4. Cursor, VS Code and other Streamable HTTP clients

Sentinel also serves MCP Streamable HTTP at `http://127.0.0.1:8443/mcp`. It supports protocol versions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05, `Mcp-Session-Id` sessions, and returns 202 for notifications. The endpoint enforces Origin and Host validation (DNS-rebinding defence) and requires a bearer token:

```bash
TOKEN=$(mcp-sentinel token --role SECURITY_ADMIN --subject local-user | python -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
claude mcp add --transport http mcp-sentinel http://127.0.0.1:8443/mcp --header "Authorization: Bearer $TOKEN"   # also works for Claude Code
```

Demo tokens expire after an hour, so the stdio bridge (which renews them) is the better choice for daily use. When the client supports URL-mode elicitation, step-up is requested through it. Otherwise the call is held open while the dashboard's approval inbox pops up.

## 5. Your own agent or application (REST)

Applications that run their own tool loop, for example with any LLM provider's function calling, can use the REST policy gateway directly:

```http
POST /v1/mcp/tools/call
Authorization: Bearer <end-user access token>

{"workflow_id": "conversation-42", "exposed_name": "github__create_issue",
 "arguments": {"title": "…"}, "user_intent": "File the bug the user described", "agent_id": "my-agent"}
```

You can also pass `server_id` + `tool_name` instead of `exposed_name`. The response contains:

* `decision`, `risk_score`, `state`, `reasons`, `factors` and `receipt_id`;
* `explainability`: the gate trace, likelihood, impact and policy;
* `mfa_challenge_id` / `approval_id` and `approval_url` when an obligation is pending;
* `execution`, `output` (already passed through the output firewall) and `mcp_result` for executed calls.

Treat the decision as authoritative. Map each tool name your model can call to a **fixed** server/tool pair, and never let model output choose server ids or endpoints. Keep tokens and upstream credentials server-side.

## 6. Production identity

Set `SENTINEL_AUTH_MODE=oidc` with `SENTINEL_JWT_ISSUER`, `SENTINEL_JWT_AUDIENCE` and `SENTINEL_OIDC_JWKS_URL`. A Keycloak realm is included in `identity/keycloak/`. HS* algorithms are rejected in OIDC mode, demo tokens and demo confirmation are disabled, and step-up uses TOTP or the IdP's MFA claims (`acr`/`amr`). Give the bridge a short-lived user token through `SENTINEL_TOKEN`, and never put it in prompts or commit it.
