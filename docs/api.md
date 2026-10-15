# API

Base URL: `http://127.0.0.1:8443`. Interactive OpenAPI docs are served at `/docs`.

Authentication is `Authorization: Bearer <jwt>`. In demo mode, read-only dashboard endpoints are open and management endpoints require SECURITY_ADMIN or SYSTEM_ADMIN. In OIDC mode every endpoint except `/health` requires a token. Requests whose `Host` header is not in the allowlist get 400 (DNS-rebinding defence).

## MCP

| Method | Path | Purpose |
|---|---|---|
| POST | `/mcp` | MCP Streamable HTTP endpoint: `initialize`, `ping`, `tools/list`, `tools/call`, empty `resources/list` and `prompts/list`, meta-tools. Requires a bearer token; validates `Origin`, `MCP-Protocol-Version` and `Mcp-Session-Id` |
| GET | `/mcp` | 405 (no server-initiated SSE stream) |
| DELETE | `/mcp` | end an MCP session |

## Gateway (policy enforcement point)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/mcp/tools/list` | the catalogue exactly as served to clients (pinned definitions, exposed names) |
| GET | `/v1/mcp/catalog/version` | catalogue fingerprint; the bridge polls it and emits `tools/list_changed` |
| POST | `/v1/mcp/tools/call` | authorise and, if allowed, execute through the output firewall |

`POST /v1/mcp/tools/call` takes `exposed_name` **or** `server_id` + `tool_name`, plus `arguments`, `workflow_id`, `user_intent` and `agent_id`. Runtime evidence comes only from Sentinel's own sensors; client-supplied telemetry fields are ignored.

The response contains:

* `decision`: ALLOW, MONITOR, RESTRICT, MFA_REQUIRED, HUMAN_APPROVAL, QUARANTINE or BLOCK;
* `risk_score`, `state`, `reasons`, `factors`, `receipt_id`, `policy_id`, `lease_id`, `restrictions`;
* `explainability`: the gate trace, likelihood, impact, impact reasons, flow roles and matched rules;
* `mfa_challenge_id` / `approval_id` / `approval_url` when an obligation is pending;
* `execution` (`executed`, `error`, `telemetry`), `output` (after the output firewall), `output_report` and `mcp_result`.

## Servers and tools

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/servers` · `/v1/servers/{id}` | trust registry; the detail view includes masked config, findings, connection status and logs |
| POST | `/v1/servers` | register a stdio, Streamable HTTP or SSE server (`run_sandbox`, `connect`), then discover and pin it |
| POST | `/v1/servers/import` | import a Claude Desktop, Claude Code (`.mcp.json` / `~/.claude.json`, optional `project`), Cursor or VS Code config; `${VAR}` references are expanded |
| PATCH / DELETE | `/v1/servers/{id}` | edit (enable, slug, config) or remove |
| POST | `/v1/servers/{id}/discover` | re-list the server now and run the rug-pull analysis |
| POST | `/v1/servers/{id}/scan` | vulnerability scan `{"active": false}`; the latest grade is shown on the server |
| POST | `/v1/servers/{id}/sandbox` | run the honeypot |
| POST | `/v1/servers/{id}/audit` | behaviour audit: exercise every tool in the sandbox on a synthetic workspace (`?wait=true` to run synchronously); the result is in the server view as `behavior_audit` |
| POST | `/v1/servers/{id}/verify` | legacy synthetic verification probe |
| PUT | `/v1/servers/{id}/trust` | manual trust status |
| GET | `/v1/servers/{id}/logs` | upstream stderr and log notifications |
| GET | `/v1/tools` · `/v1/tools/{tool_id}/detail` | integrity registry: pinned vs live definition, scan findings, inference, baseline |
| POST | `/v1/tools/{tool_id}/approve` · `/reject` | review decisions |
| PUT | `/v1/tools/{tool_id}/trust` · `/profile` | trust status, or a locked capability profile |
| GET | `/v1/integrity/changes` · `/{id}` | rug-pull ledger with structured diffs |
| POST | `/v1/integrity/changes/{id}/resolve` | `{"action": "accept" \| "reject"}` (accept re-pins only while the live definition still matches) |
| GET | `/v1/integrity/toxic-flows` | toolset-wide lethal-trifecta and toxic-flow analysis with remediation |

## Sandbox pre-flight and undo

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/sandbox/status` | active backend (docker / process / off), Docker and image state, image build progress, limits |
| POST | `/v1/sandbox/image/build` | build the sandbox runtime image (admin) |
| GET | `/v1/sandbox/runs?server_id=&verdict=&approval_id=&challenge_id=&receipt_id=` | pre-flight history: verdict, action (ALLOWED / ESCALATED / BLOCKED / NOT_RUN), findings and effect preview |
| GET | `/v1/sandbox/runs/{run_id}` | one run |
| GET | `/v1/undo?server_id=` · `/v1/undo/{receipt_id}` | undo journal: the file changes each executed call made |
| POST | `/v1/undo/{receipt_id}` | restore the previous versions and remove created files (admin); files changed again since are reported as conflicts |

`POST /v1/mcp/tools/call` responses include `sandbox` (verdict, action, preview) and, when files changed, `output_report.undo_id`; `output_report.sandbox_evasion` is set when the real call did more than the sandbox predicted. Approval views (`/v1/approvals/{id}`) carry the same `sandbox` preview.

## Vulnerability scans

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/scans?server_id=` | scan history (grade, worst severity, counts) |
| GET | `/v1/scans/{id}` | full report |
| GET | `/v1/scans/{id}/report.html` · `/report.json` | downloadable reports (`?download=1` for an attachment); HTML is served with a no-script CSP |

## Step-up and approvals

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/mfa/challenges/{id}` | challenge detail (tool, argument preview, risk, reasons) |
| POST | `/v1/mfa/challenges/{id}/verify` | `{"code": "123456"}` (TOTP), `{"demo": true}` (demo mode, no authenticator enrolled), or an MFA-satisfied IdP token. Only the user who triggered the call can verify |
| POST | `/v1/mfa/challenges/{id}/deny` | deny the held call |
| POST | `/v1/mfa/complete` | legacy: complete a challenge with IdP MFA claims |
| GET / POST / DELETE | `/v1/mfa/totp/status` · `/enroll` · `/activate` · `/v1/mfa/totp` | TOTP enrolment (RFC 6238, secret encrypted at rest) |
| GET / POST | `/v1/approvals` · `/v1/approvals/{id}` · `/v1/approvals/{id}/{approve\|deny}` | human approvals (single-use; self-approval only in demo mode) |
| GET | `/v1/inbox` | pending MFA challenges and approvals for the current user |

## Audit, workflows, leases

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/receipts` · `/v1/receipts/{id}` · `/v1/receipts/{id}/explain` | decision receipts |
| GET | `/v1/audit/verify` | verify the hash chain and Ed25519 signatures: `{ok, checked, head}` or `{ok: false, broken_seq, reason}` |
| GET | `/v1/audit/public-key` | receipt-signing public key (PEM) |
| GET | `/v1/events` | security events |
| GET | `/v1/workflows` · `/v1/workflows/{id}` | workflows with sequence, flow roles and trifecta state |
| GET / POST | `/v1/leases` · `/v1/leases/{id}/revoke` | capability leases |
| GET | `/v1/session/status` | posture summary (used by `sentinel_status`) |
| GET | `/v1/dashboard/summary` | dashboard counters |
| GET | `/v1/entities` | per-caller behavioural baselines (UEBA), most anomalous first |
| GET | `/v1/entities/{subject}` | one caller's learned baseline, hour-of-day activity and recent anomalies |

## Policy

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/policy` | thresholds, role → capability matrix, rules, lockdown |
| GET / POST / PUT / DELETE | `/v1/policy/rules[/{id}]` | admin rules: `effect` DENY, REQUIRE_MFA or REQUIRE_APPROVAL; `match` on server, tool glob, capabilities, roles |
| GET / PUT | `/v1/policy/lockdown` | `{"mode": "off" \| "approve_writes" \| "deny_all"}` |

## Misc

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness, store backend, version |
| POST | `/v1/demo/token?role=&subject=&mfa=` | demo JWT (demo mode, loopback clients only) |
| GET | `/v1/auth/whoami` | identity seen by Sentinel |
| GET | `/v1/integrations/claude-desktop` | ready-to-paste Claude Desktop and Claude Code configuration and CLI commands, this computer's Claude Desktop status (installed, bypassing servers and extensions) and the MCP clients connected right now |
| GET | `/v1/integrations/info` | API and dashboard URLs, auth mode, approval wait |
