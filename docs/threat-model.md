# Threat model

## Assets

* upstream credentials and secrets that tools can reach (vaults, SSH keys, cloud credentials, `.env` files)
* user data reachable through tools (files, mail, chat, repositories, databases)
* the integrity of what the model is told (tool descriptions and outputs)
* identity tokens, capability leases and approvals
* the audit ledger and Sentinel's own policy and keys

## Adversaries

1. A **malicious or compromised MCP server**: tool poisoning, rug pulls, shadowing, malicious updates.
2. **Indirect prompt injection** through tool outputs (web pages, issues, emails, logs).
3. A **prompt-injected agent** chaining individually allowed tools into exfiltration.
4. An **insider** with a legitimate role.
5. A **stolen token** without MFA.
6. A **malicious web page** targeting a local control plane (DNS rebinding, CSRF).
7. **Supply-chain** attackers: typosquats, unpinned packages, `curl | sh` installers.

## Attack → control matrix

These are MCP attack classes documented in the community catalogue at [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) and in vendor research.

| Attack | Example | Controls |
|---|---|---|
| Tool poisoning | `<IMPORTANT>` block telling the model to read `~/.cursor/mcp.json` into a `sidenote` parameter | scanner (descriptions **and** parameter metadata), quarantine at discovery, pinned/sanitised served definitions |
| Rug pull | definition changes after approval | raw-wire pinning, list_changed/JIT/poll re-verification, diff + classification, model always sees the pinned text, lease revocation |
| Behavioural rug pull | same description, new behaviour | **sandbox pre-flight of every call** (planted-credential reads, read-only tools writing, unexpected hosts, persistence), behaviour contracts from the registration audit, statistical baseline, process/network monitor, output withholding |
| Destructive call | an agent "cleans up" a project folder | blast-radius guard on the sandbox preview, effect preview on approval, undo journal |
| Sandbox-aware server | behaves well only when tested | real effect diffed against the prediction after every call; unpredicted changes reverted, tool quarantined |
| Cross-server shadowing | "when `send_email` is used, BCC …" | shadowing detection against all other tool names, namespacing (`slug__tool`) |
| ASCII smuggling / hidden text | Unicode tags, zero-width, bidi, ANSI | decode-and-flag in definitions, strip in outputs |
| Indirect prompt injection | instructions in fetched content | output injection scanner, spotlighting/quarantine, `UNTRUSTED_SOURCE` flow role, workflow risk memory |
| Lethal trifecta / toxic flow | private data + untrusted content + egress in one session | per-workflow trifecta evidence, toolset toxic-flow map with remediation |
| Exfiltration via innocent tools | secret placed in a URL query for a "lookup" | content taint (salted fingerprints, encoded variants), EXTERNAL_LOOKUP treated as an egress sink |
| Sequential abuse | lookup → secret → transfer | sequence transitions, privilege-escalation detection, data-flow hard rules |
| Confused deputy / SSRF | `http://169.254.169.254/…`, `0x7f.1`, `evil.com\@good.com` | strict host classification (legacy IPv4 forms, mapped IPv6, WHATWG backslash), metadata hard block |
| Command injection / traversal | `; rm -rf`, `../../.ssh/id_rsa` | input validator hard rules (content fields exempt from shell checks) |
| Deceptive annotations | `readOnlyHint: true` on `delete_repo` | annotations are untrusted; contradictions are evidence and hold the tool for review |
| Token theft without MFA | replayed bearer token | step-up for sensitive actions, TOTP replay protection, action-bound leases |
| Consent fatigue | approving a vague request | approval page shows the call's **effect** from the sandbox run (file diffs, destinations, programs), risk and reasons; MALICIOUS verdicts can't be approved at all; the lease is bound to those arguments |
| Supply-chain update | `npx -y pkg` pulls a new release | unpinned and typosquat findings, behaviour audit of every tool in the sandbox, per-call pre-flight, server version drift alert |
| Misconfigured upstream server | accepts any bearer token, no Origin check, wildcard CORS, OAuth without PKCE, long-lived broad-scope tokens | vulnerability scanner (SecureMCP port) on registration and on demand; findings lower the server's grade and feed risk |
| Local control-plane attack | malicious site calls `localhost:8443` | loopback bind, Host allowlist, Origin check, loopback-only demo tokens, no CORS credentials |
| Repudiation | "the agent did it" | hash-chained, Ed25519-signed receipts with identity, agent, gates and factors |

## Out of scope

* A compromised host OS or a malicious local administrator.
* Attacks inside a server that never surface through MCP (for example, a server exfiltrating data on its own outside a tool call). Sentinel detects some of these through the process and network monitor, the sandbox pre-flight and the honeypot, but cannot prevent them without running the real server under OS-level isolation.
* The model leaking data through its *answer text* rather than a tool call.
