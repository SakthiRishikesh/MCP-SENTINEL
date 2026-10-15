# Rug-pull detection

A *rug pull* is an MCP server that looks safe when you approve it and changes later. There are three variants:

* **Definition rug pull.** The tool's description, schema or annotations change after approval. Example: a hidden `<IMPORTANT>` block telling the model to read `~/.ssh/id_rsa` and pass it in a new `context` parameter.
* **Behavioural rug pull.** The definition stays the same but the implementation changes. The tool starts returning injections, contacting new hosts or spawning shells.
* **Supply-chain rug pull.** An unpinned `npx -y pkg` or `uvx pkg` silently installs a new, compromised release on the next start.

MCP-Sentinel handles each variant with a separate layer.

## 1. Pin the raw wire object (TOFU)

When Sentinel first sees a tool, it stores the **entire raw tool object** that the server returned: name, title, description, `inputSchema`, `outputSchema`, `annotations`, `_meta` and any other fields. It also stores a canonical SHA-256 of that object. A pin that hashes only the fields an approval dialog displays misses most real-world changes.

* A clean new tool is auto-approved: TRUSTED for curated tools, MONITORED otherwise (`SENTINEL_AUTO_PIN_CLEAN_TOOLS`).
* A tool the scanner rates SUSPICIOUS is pinned as PENDING_REVIEW and RESTRICTED. A MALICIOUS tool is pinned as PENDING_REVIEW and QUARANTINED, and is never exposed.
* After the server's baseline is established, a tool that **appears** later is recorded as an ADDED change for review. A tool that **disappears** is marked removed, and its leases are revoked.

## 2. Re-verify continuously, and just before use

The live definition is re-listed:

* every `SENTINEL_DISCOVERY_INTERVAL_SECONDS` (default 60);
* immediately when the upstream server sends `notifications/tools/list_changed`;
* **just before execution**: within 3 s for sensitive or non-trusted tools, and within `SENTINEL_JIT_INTEGRITY_SECONDS` (default 15) for other tools;
* on demand (*Servers → Re-scan*, `POST /v1/servers/{id}/discover`).

The just-before-execution check closes the gap where a server changes between two polls.

## 3. Diff and classify the drift (`integrity/rugpull.py`)

When the live hash differs from the pinned hash, Sentinel computes a structured diff:

* a unified diff of the description;
* parameters added, removed, changed and newly required;
* annotation flips toward risk (`readOnlyHint` true→false, `destructiveHint` false→true, …);
* the inferred capability, sensitivity and toxic-flow roles before and after the change;
* any other changed fields.

It also rescans the new definition with the poisoning scanner. Each finding is weighted, and the drift is classified:

| Class | Trigger | Action |
|---|---|---|
| COSMETIC | whitespace, punctuation or letter case only | auto re-pinned and recorded |
| BENIGN | low-impact wording or metadata drift | keeps working; tool downgraded to MONITORED; change OPEN |
| SUSPICIOUS | capability or privilege expansion, new sensitive parameters (`url`, `command`, `context`, `bcc`, …), a risky annotation flip, a sensitivity increase, a large rewrite, or medium-severity new poisoning | tool RESTRICTED, its leases revoked, **approval required** before sensitive use |
| MALICIOUS | new high or critical poisoning indicators (hidden instructions, secrecy, approval bypass, credential exfiltration, cross-server shadowing, Unicode smuggling) | tool QUARANTINED, server RESTRICTED, **every lease on the server revoked** |

The same drift is reported only once. If the server reverts to the pinned definition, the change is closed automatically, but any quarantine stays in place until an administrator clears it.

**The model never sees the new text.** Claude is always served the *pinned* definition (`served_definition`), so a poisoned description cannot reach the LLM even in the window before an administrator reacts. Accepting a change (`POST /v1/integrity/changes/{id}/resolve` with `accept`) re-pins it, but only while it still matches the live definition. Rejecting the change quarantines the tool.

Server-level drift is tracked too. A change in the server's reported name or version moves the server to MONITORED, and `instructions` are scanned for injection.

## 4. Behavioural baseline (`monitoring/baseline.py`)

For every executed call Sentinel records:

* latency;
* output size and top-level structure;
* domains referenced in the output;
* whether the output contained prompt-injection or secret-like content;
* for stdio servers, the **child processes and remote hosts** that appeared in the server's process tree during the call (psutil snapshots before and after).

After 5 samples, deviations raise anomalies. Examples: a z-score outlier in latency or size, a new external domain, injection content never seen in the baseline, a suspicious child such as `curl`, `bash` or `nc`, or a new remote host. An anomaly of MEDIUM severity or higher is **never learned into the baseline**, so a compromised tool keeps alerting instead of becoming the new normal. The anomaly score decays (half-life 30 min) and feeds the risk engine as `behavior_drift`. A HIGH anomaly *during* a call withholds that call's output.

Between calls, the process monitor (`SENTINEL_PROCESS_MONITOR_*`) learns each stdio server's normal children and connections for 120 s, then raises events for new ones.

## 5. Supply chain and honeypot (`integrity/supplychain.py`, `sandbox/honeypot.py`)

Sentinel flags these at registration:

* unpinned packages run through a package runner (`npx -y pkg`, `uvx pkg`, `pipx run pkg`, …) with no version, or with `latest`;
* typosquats of well-known MCP packages (Levenshtein distance);
* shell wrappers such as `curl … | sh`;
* privileged or host-mounted Docker flags;
* secrets in arguments;
* plaintext remote transports and metadata endpoints.

The optional **honeypot** starts a local server once in a throw-away HOME that is full of canary credentials. Its traffic goes through a recording proxy that only lets package registries through. The honeypot then lists the tools (and can optionally exercise read-only ones). Reading a decoy file, emitting a canary or contacting a non-registry host marks the server SUSPICIOUS, HIGH_RISK or MALICIOUS_OR_COMPROMISED before it ever touches real data.

## Try it

**A real supply-chain update.** Register an older release of the official Filesystem server, then bump the pin, as an unpinned `npx -y` would on its next launch:

1. **Servers → Connect server**: command `npx`, args `-y`, `@modelcontextprotocol/server-filesystem@2025.3.28`, `<folder>`.
2. **Server → Config**: change the version to `@2026.8.31` → **Save & reconnect** (or `PATCH /v1/servers/{id}` with the new `args`).

Sentinel reconnects and diffs the new definitions against the pins: 11 changed tools (SUSPICIOUS where parameters were added or became required, BENIGN for wording) and 3 new tools recorded as additions after the baseline. Changed tools are RESTRICTED and their leases revoked. Claude keeps receiving the pinned text until you accept each change under **Rug pulls**.

**Hidden-instruction rug pull.** `pytest tests/test_rugpull.py -v` runs a real MCP server that starts advertising a poisoned definition mid-session. It shows Sentinel classifying it MALICIOUS, quarantining the tool, restricting the server, blocking the next call, and never serving the new text to the model. It also covers just-in-time re-verification right before a sensitive call.
