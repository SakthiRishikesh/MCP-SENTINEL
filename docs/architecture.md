# MCP-Sentinel architecture

MCP-Sentinel is a **policy enforcement point (PEP)** that sits between MCP clients and MCP servers. It is also an MCP server to the client and an MCP client to every upstream server. The policy engine is the **policy decision point (PDP)**. The LLM can propose tool calls but cannot authorise them.

```
Claude Desktop / Claude Code ──stdio──► sentinel.bridge ──HTTP──┐
Cursor / VS Code / any client ──Streamable HTTP /mcp──►│  MCP-Sentinel control plane (FastAPI)
Dashboard (React) ──REST /v1──────────────────────►│
                                                   │  frontend → gateway → pipeline (PDP) → upstream manager
                                                   └──► stdio servers (npx/uvx/docker/python), Streamable HTTP, legacy SSE
```

## Request path of one `tools/call`

1. **Frontend** (`sentinel/mcp_frontend.py`). It resolves the exposed name `slug__tool` to `(server_id, tool)`. It also serves the meta-tools and holds the call open during step-up, using progress notifications plus an `open_url` or URL-mode elicitation.
2. **Gateway** (`sentinel/gateway.py`). Before running a sensitive or non-trusted tool, it **re-lists the upstream server just in time** (at most every 3 s). For other tools it does this when the listing is older than `SENTINEL_JIT_INTEGRITY_SECONDS`. A rug pull is therefore caught *before* the call runs, not on the next poll.
3. **Pipeline** (`sentinel/pipeline.py`, `ControlPlane.authorize`) runs a gated cascade. Every gate is recorded in the receipt:

   | Gate | Hard-fails on |
   |---|---|
   | identity | missing/expired/invalid token; roles come only from the IdP token |
   | agent | the agent id in the request disagrees with the token's agent claim |
   | server | unknown, disabled, QUARANTINED or BLOCKED server |
   | tool | unknown, REJECTED, QUARANTINED or BLOCKED tool, or a tool removed upstream |
   | semantic_change | (warn) the live definition differs from the pinned one, or the tool is pending review |
   | input | path traversal, credential paths, shell chaining, dangerous commands, metadata SSRF, dangerous URL schemes |
   | policy | RBAC × capability, admin DENY rules, lockdown, restricted server running a sensitive tool, forbidden destinations |
   | dataflow | content taint (secret bytes leaving), SECRET/CRITICAL data to an external sink |
   | risk | score ≥ block threshold |

   Gates that pass contribute **evidence** to the risk engine instead: the trust prior, schema drift, soft input findings, sequence transitions, context mismatch, the lethal trifecta, prompt-injection in arguments, velocity, behavioural drift and workflow risk memory. See [risk-engine.md](risk-engine.md).
4. **Obligations**. MFA step-up (RFC 6238 TOTP, the IdP ACR/AMR claims, or demo confirmation) and/or human approval (single-use and bound to a request hash). When either is satisfied, a **capability lease** is granted. Each lease is bound to the workflow, subject, server, tool and capability, and for CRITICAL tools to the exact arguments (`scope_hash`).
5. **Sandbox pre-flight** (`sentinel/preflight.py`, `sandbox/shadow.py`). For local (stdio) servers the call first runs against a copy of the server's folders in a Docker sandbox (no network, decoy credentials), or in the process sandbox when Docker is unavailable. The verdict can block the call, escalate it to a human with an effect preview, or let it through. See [sandbox.md](sandbox.md).
6. **Execution** (`sentinel/upstream/manager.py`). The manager runs the call on a persistent upstream session. It snapshots the server's process tree before and after the call to record new children and new remote hosts.
7. **Effect verification**. The real folders are diffed against the pre-call mirror: every change is journalled for undo, and changes the sandbox did not predict are reverted and the tool quarantined.
8. **Output firewall** (`Gateway._guard_output`). It strips invisible/ANSI characters and redacts secrets with DLP (unless SECRET_ACCESS was authorised and the decision is not RESTRICT). Prompt injections are spotlighted or quarantined. The behavioural baseline is updated, secret fingerprints are added to the workflow's taint store, and the output is **withheld** if the tool misbehaved during the call.
9. **Receipt** (`sentinel/receipts.py`). The receipt is appended to a SHA-256 hash chain and signed with Ed25519. It records the gate trace, the risk factors, likelihood × impact, and the obligations.

## Tool catalogue and integrity

* **Discovery** (`integrity/discovery.py`) lists every server periodically (`SENTINEL_DISCOVERY_INTERVAL_SECONDS`), on `notifications/tools/list_changed`, before sensitive calls, and on demand. It then reconciles the result against the pins. See [rug-pull-detection.md](rug-pull-detection.md).
* **Served definition** (`integrity/registry.served_definition`). Claude receives the **pinned** definition, or a sanitised live one for tools that have not been approved yet. A Sentinel note is prepended to the description. Tools that are REJECTED, QUARANTINED, BLOCKED, removed or on a disabled server are not exposed at all.
* **Capability inference** (`integrity/capabilities.py`). Capabilities, sensitivity and toxic-flow roles are inferred from the name (the first verb decides), the parameters and the description. Annotations are treated as **untrusted hints**: they can raise risk but never lower it, and contradictions count as evidence.
* **Toxic flows** (`integrity/toxicflow.py`). This analysis works across the whole toolset. It looks for paths from a private source through an untrusted source to an egress sink, flags injection-to-RCE paths, and computes the minimal set of servers to cut.

## Processes and state

| Component | Where |
|---|---|
| API + dashboard | `mcp-sentinel serve` (uvicorn; serves `dashboard/dist` at `/` when built) |
| stdio bridge | `python -m sentinel.bridge`, launched by Claude Desktop. It holds no secrets and mints a loopback-only demo token, or uses `SENTINEL_TOKEN` |
| Upstream sessions | inside the API process; stdio children run in their own process group/session with a minimal environment |
| Background jobs | discovery loop and process-monitor loop (`SENTINEL_BACKGROUND_JOBS_ENABLED`) |
| Database | SQLite (WAL) by default, PostgreSQL via `SENTINEL_DATABASE_URL`. New columns are added automatically to existing databases |
| Hot state | in-memory or Redis (`SENTINEL_REDIS_URL`): workflow extras, taint fingerprints, risk memory, MFA challenges |
| Keys | `keys/secrets.key` (Fernet, encrypts upstream configs and TOTP secrets) and `keys/receipts.key` (Ed25519), created with mode 0600 |

## Modules

| Path | Role |
|---|---|
| `sentinel/` | app, pipeline, gateway, MCP frontend/bridge, receipts, DLP, netutil, CLI |
| `sentinel/upstream/` | MCP client (stdio, Streamable HTTP, legacy SSE) and connection manager |
| `sentinel/routes/` | REST API (core, gateway, servers, scans, sandbox, tools, approvals, audit, policy) |
| `sentinel/preflight.py` · `sentinel/safety.py` | what the gateway does with a sandbox verdict · the SAFE / CAUTION / NOT SAFE verdict for a server |
| `sentinel/clientconfig.py` | Claude Desktop / Claude Code / Cursor / VS Code config discovery, parsing and `${VAR}` expansion |
| `identity/` | OIDC/JWT verification, demo tokens, a Keycloak realm for OIDC mode |
| `policy/` | policy decision point and admin rules |
| `integrity/` | registry, discovery, poisoning scanner, rug-pull diff, capability inference, supply chain, toxic flows, vulnerability scanner (`vulnscan.py`, SecureMCP port) |
| `risk/` | evidence-fusion engine and workflow risk memory |
| `workflow/` | sequential analyser and context/intent engine |
| `dataflow/` | data classification, exfiltration guard, content taint |
| `mfa/` | TOTP, enrolment, step-up challenges |
| `monitoring/` | process monitor, per-tool statistical behavioural baselines, and per-caller behaviour analytics (UEBA, `entity.py`) |
| `sandbox/` | shadow execution: Docker and process backends, in-container supervisor (`agent.py`), verdict rules, workspace mirrors and undo, launch recipes; plus the honeypot (which also hosts active vulnerability probes) |
| `dashboard/` | React UI (it never makes security decisions) |

## Trust is never permanent

TRUSTED means "acceptable right now". Integrity drift, runtime anomalies, honeypot findings and policy events move servers and tools to MONITORED, RESTRICTED, QUARANTINED or BLOCKED. Only an administrator moves them back up.
