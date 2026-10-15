# Compatible MCP servers

MCP-Sentinel speaks standard MCP to every upstream server: stdio (any command), Streamable HTTP, and legacy HTTP+SSE. Any spec-compliant server works. Add a server under **Servers → Connect server** (presets cover the ones below), or import your existing Claude Desktop / Claude Code configuration with `mcp-sentinel import-claude`.

## Verified with Sentinel

Each server below was registered through the API, honeypot-sandboxed, discovered and pinned, vulnerability-scanned, and called through the stdio bridge (the process Claude launches).

| Server | Launch (pinned) | Tools | Notes from testing |
|---|---|---|---|
| **Filesystem** | `npx -y @modelcontextprotocol/server-filesystem@2026.8.31 <folder>` | 14 | Reads ALLOW; credential paths (`~/.ssh`, `.env`, …) BLOCK before the server sees them; writes are WRITE capability; file contents are DLP-redacted |
| **Memory** (knowledge graph) | `npx -y @modelcontextprotocol/server-memory@2026.8.31` | 9 | Grade A; active probes run against `search_nodes` inside the honeypot |
| **Everything** (MCP reference/test server) | `npx -y @modelcontextprotocol/server-everything@2026.8.31` | 13 | Exercises every content type: images, `structuredContent`, resource links, annotations and long-running tasks all pass through. `get-env` is correctly classified as SECRET_ACCESS. Also verified in `streamableHttp` and `sse` modes |
| **Fetch** | `uvx mcp-server-fetch==2026.8.18` | 1 | EXTERNAL_LOOKUP + egress sink: taint tracking blocks secrets placed in URLs. Needs outbound internet |
| **Git** | `uvx mcp-server-git==2026.8.18 --repository <repo>` | 12 | Status/log/diff ALLOW; `git_reset` is a HIGH-sensitivity write |
| **Time** | `uvx mcp-server-time==2026.8.18` | 2 | Grade A |
| **Sequential Thinking** | `npx -y @modelcontextprotocol/server-sequential-thinking@2026.8.31` | 1 | Grade A |

Transports verified against the official MCP TypeScript SDK: Streamable HTTP with `Mcp-Session-Id` sessions, legacy HTTP+SSE, and automatic fallback from an HTTP URL to SSE. Paginated `tools/list` and servers that write stray non-protocol lines to stdout are handled.

## Expected to work (remote servers)

These use Streamable HTTP with a static header or no authentication, which Sentinel supports. They could not be reached from our test environment (egress policy), so they are listed without a guarantee.

| Server | URL | Auth |
|---|---|---|
| DeepWiki | `https://mcp.deepwiki.com/mcp` | none |
| Context7 (library docs) | `https://mcp.context7.com/mcp` | none, or an API key header |
| GitHub (remote) | `https://api.githubcopilot.com/mcp/` | `Authorization: Bearer <fine-grained PAT>` |

Servers that **only** offer an interactive OAuth login (no static token) are not supported yet: Sentinel does not run the MCP OAuth flow to upstream servers. A common workaround is a local stdio wrapper such as `npx mcp-remote <url>`, which handles the login and exposes stdio to Sentinel.

## Tips

* **Pin versions** (`pkg@1.2.3`, `pkg==1.2.3`). An unpinned `npx -y pkg` can run different code on every launch, so Sentinel flags it as a supply-chain rug-pull risk.
* **Secrets go in the server's environment field.** They are stored encrypted, never shown to the model, and the scanner flags tokens passed on the command line.
* **Windows:** use `npx` / `uvx` as usual; Sentinel resolves `npx.cmd`. If a launcher isn't found, give its absolute path.
* **First launch of an `npx`/`uvx` server** downloads the package; registration waits up to `SENTINEL_UPSTREAM_CONNECT_TIMEOUT_SECONDS` (90 s).
* If `npx` reports `ENOTEMPTY` or `ERR_MODULE_NOT_FOUND` inside `~/.npm/_npx`, an install was interrupted. Delete that folder and retry (Sentinel's error message says so).
* Every server is vulnerability-scanned as it is added; the add dialog shows a SAFE / CAUTION / NOT SAFE verdict and the recommended fixes.

## Project-specific live operations servers

These two servers are implemented in this repository and read the live Sentinel API. They are separate from the reference-server compatibility list above.

| Server | Launch | Tools | Purpose |
|---|---|---|---|
| **Sentinel Operations** | `python <repo>\\mcp_servers\\operations.py` | 4 | Reads current posture, registered servers/tools, and security events |
| **Sentinel Live Report** | `python <repo>\\mcp_servers\\reporter.py <report-folder>` | 1 | Writes a live API report under a configured folder, without overwriting existing reports |

## A live security review workflow

The project includes two local MCP servers for a real operational workflow. **Sentinel Operations** exposes `get_live_posture`, `list_registered_servers`, `list_security_alerts`, and `inspect_registered_server`. **Sentinel Live Report** exposes `write_live_security_report`, which queries the same running Sentinel API and writes a Markdown summary under the folder passed as its second launch argument. It does not seed examples or create fake events; empty registry/event sections say that there were no matching live records. The report tool creates a new filename and refuses to overwrite an existing file.

Use the tools in this order:

1. Call `get_live_posture` to read current counts and Sentinel health.
2. Call `list_registered_servers` and `list_security_alerts` to identify a real server or event that needs review.
3. Pass the returned `server_id` to `inspect_registered_server` to review its live trust state, tools, and findings.
4. Call `write_live_security_report`, optionally passing that `server_id`, to save the current posture and related live records in the configured report folder. Choose `destination_name` when you want a specific new filename; otherwise the server generates a timestamped one.

In the dashboard, choose **Servers -> Connect server -> Local (stdio)** and select the **Sentinel Operations (live)** preset. Set Command to your Python executable (on Windows, `<repo>\.venv\Scripts\python.exe`) and replace the script placeholder with the absolute path to `mcp_servers/operations.py`. Repeat with **Sentinel Live Report**, supplying the absolute path to `mcp_servers/reporter.py` and an existing report folder. In demo mode the read-only API is available locally without a token. For OIDC, add `SENTINEL_API_URL` and a valid `SENTINEL_TOKEN` in the server Environment field. The default API URL is `http://127.0.0.1:8443`; when the API runs inside Compose, use its service URL and a container-visible report folder instead. For Windows host paths, run Sentinel natively as described in [windows.md](windows.md).

The report server has a WRITE capability, so Sentinel previews its file creation under the normal policy and sandbox flow. The Operations server is read-only.
