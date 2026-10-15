# Known limitations

## Verification scope

* Upstream compatibility was verified with the official reference servers (Filesystem, Memory, Everything in stdio, Streamable HTTP and SSE modes, Fetch, Git, Time, Sequential Thinking) and with real version updates; see [mcp-servers.md](mcp-servers.md). Remote servers that need an interactive OAuth login are not supported yet.
* The client side (stdio bridge and `/mcp`) is exercised in CI with scripted JSON-RPC clients that behave like Claude: handshake, `tools/list`, calls with progress tokens, held step-up, `list_changed`. It was also run inside Claude Desktop for Linux (`claude-desktop-unofficial` 1.19367; both the chat and the agent-mode bridge connect and list tools). Other client versions can differ in details such as progress-notification timeouts and how `open_url` is handled.
* Claude Desktop caches its tool list and does not reliably honour `notifications/tools/list_changed`. Servers added after Claude starts can be used straight away through `sentinel_discover_tools` / `sentinel_invoke`; to see them as native tools, toggle the connector or restart Claude.
* A held step-up call lasts `SENTINEL_WAIT_SECONDS` (50 s by default), which is chosen to stay under typical client request timeouts. If approval comes later, Claude has to call the tool again. The lease is then already in place.

## Detection limits

* The poisoning scanner and capability inference are heuristics: patterns, a verb lexicon, schema shape. A novel phrasing can evade them, and unusual tool names can be over-classified. Every result is shown with its evidence and can be overridden with a locked profile.
* TOFU pinning trusts the **first** definition it sees. The honeypot, the poisoning and vulnerability scanners and the supply-chain checks reduce that risk but cannot remove it. Locking a reviewed capability profile is the strongest option.
* The vulnerability scanner's active probes only call tools inferred as read-only. Injection flaws reachable only through write tools are not exercised, and TLS checks are skipped behind an HTTPS proxy.
* Behavioural baselines need at least 5 samples before they flag drift, and a slow, gradual drift can stay under the z-score thresholds.
* Process and network monitoring uses psutil snapshots taken around each call and every few seconds. Very short-lived processes or connections can be missed, and remote HTTP servers can only be observed through their outputs.
* The honeypot and the **process** sandbox backend run the server as the **same OS user** in a decoy HOME behind a recording proxy. They are best-effort detectors, not a security boundary: a server that ignores `HOME`/proxy variables can evade them. The Docker backend is the containment boundary; tools that execute code or send data are only pre-flighted with Docker.
* Sandbox pre-flight applies to **local** servers only. Remote servers run elsewhere; their calls rely on policy, risk, taint tracking and the output firewall.
* The sandbox reproduces effects on the copied folders and the decoy home. Remote effects (a SaaS API call) are seen as a network attempt and destination only, and have no undo. A server that fingerprints the sandbox can behave differently there: unpredicted *file* changes of the real call are caught and reverted afterwards, unpredicted network actions are not. See [sandbox.md](sandbox.md#limits).
* Content-taint tracking matches exact values and common encodings (URL, base64, hex). Secrets that are transformed (split, encrypted, paraphrased) are not matched. The data-flow rules and the trifecta evidence still apply.
* Sentinel cannot see what the model writes in its *reply*. It controls tool calls and tool outputs only.

## Platform

* Single process. Upstream sessions, background jobs and hot state (unless Redis is configured) live in one API process, so there is no high availability.
* Only MCP **tools** are proxied. Resources, prompts and sampling are not forwarded (Sentinel answers `resources/list` and `prompts/list` with empty lists), and upstream server→client requests other than `ping` are refused.
* Remote upstream servers authenticate with static headers or bearer tokens. MCP OAuth authorisation flows to upstream servers are not implemented.
* Demo mode uses an HS256 shared secret and offers demo confirmation in place of MFA. Use OIDC (`SENTINEL_AUTH_MODE=oidc`) and TOTP or IdP MFA outside a local demo.
* Claude Desktop **Desktop Extensions** (for example the built-in Filesystem extension) talk to Claude directly and cannot be put behind Sentinel. The dashboard's Connect page and `mcp-sentinel doctor` list the enabled ones; turn them off and connect the same server through Sentinel instead.

## Future work

* gVisor / Firecracker runtimes for the shadow sandbox, and an option to run the real stdio servers inside containers too
* MCP OAuth 2.1 to upstream servers, and per-user upstream credentials
* signed server attestations (Sigstore, in-toto) and a shared, signed rug-pull intelligence feed
* resource and prompt proxying with the same pinning and scanning
* WebAuthn step-up directly in the approval page
* Redis streams and leader election for horizontal scale
