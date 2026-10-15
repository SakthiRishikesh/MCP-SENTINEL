# Sandboxed tool calls (shadow execution)

Every call to a **local** MCP server is executed twice: first against a throw-away copy of your files in an isolated sandbox, then, only if that run was clean, for real. Sentinel judges the call on what it *did* in the sandbox, not on what the tool or the model claims. The goal is that a person who clicks "approve" without reading anything cannot let a malicious call through.

```
Claude ─► Sentinel gateway ─► authorize (identity, policy, risk) ─┐
                                                                   ▼
        ┌──────────────────────── pre-flight ─────────────────────────────────┐
        │ 1. sync a private mirror of the server's folders (incremental)      │
        │ 2. copy the mirror, plant decoy credentials in a fake home          │
        │ 3. start a copy of the server in the sandbox, make the same call    │
        │    (paths rewritten to the copy, real secrets swapped for canaries) │
        │ 4. diff files, read the sensors → verdict + effect preview          │
        └─────────────────────────────────────────────────────────────────────┘
             MALICIOUS / DANGEROUS ─► BLOCK (no approval can override MALICIOUS)
             SUSPICIOUS / unverifiable write ─► human approval with the preview
             SAFE ─► real call ─► diff the real folders ─► undo journal
                                         └─► changes the sandbox did not predict?
                                             revert them, withhold output, quarantine
```

Code: `sandbox/shadow.py` (manager, backends, audit), `sandbox/agent.py` (in-container supervisor), `sandbox/verdict.py` (rules), `sandbox/workspace.py` (mirrors, diffs, path mapping), `sandbox/launch.py` (launch recipes), `sentinel/preflight.py` (what the gateway does with a verdict).

## Backends

| | **Docker** (default when Docker Desktop / Engine is running) | **Process** (fallback) |
|---|---|---|
| Isolation | `docker run --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m`, unprivileged user, only the copied folders and a decoy home mounted | the server runs as you, with `HOME` pointed at a decoy and a recording proxy; **observation, not containment** |
| Network | none. A DNS sinkhole answers every lookup with 127.0.0.1 and connection sinks record the HTTP `Host` / TLS SNI (and any canary in the first bytes), so every destination is visible and nothing leaves | proxy-aware clients go through a recording proxy that only tunnels to package registries |
| Files read | inotify on the decoy home: any open of `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.env`, Claude / Cursor configs, `.git-credentials` | access times of the planted files and psutil open files |
| Processes | `/proc` sampler inside the container, plus command shims (`curl`, `wget`, `nc`, `ssh`, `base64`, `openssl`, …) first on `PATH` that log the attempt and refuse | psutil children, plus the same shims |
| Scope | every tool | tools that execute code, control infrastructure or send data are **not** pre-flighted (they would really run); with `SENTINEL_SANDBOX_STRICT` such calls that write or execute go to a human |

The image (`docker/sandbox-runtime.Dockerfile`) contains Node, npm, Python and uv, and nothing else (no curl, no compilers). Build it from the dashboard (**Sandbox → Build image**); in `auto` mode Sentinel also starts the build the first time it needs the image and uses the process backend meanwhile. Base images can point at a mirror (`SENTINEL_SANDBOX_NODE_IMAGE`, `SENTINEL_SANDBOX_PYTHON_IMAGE`); a corporate CA bundle from `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS` is used for the build and installs.

### Launch recipes (Docker)

The user's command is turned into an *install* phase (network on, **install scripts disabled**, server code never runs) and a *run* phase (no network, package mounted read-only):

| Command | Install | Run |
|---|---|---|
| `npx [-y] pkg@ver args…`, `npx -p pkg bin args…` | `npm install --ignore-scripts pkg@ver` | `node …/node_modules/pkg/<bin>` |
| `uvx pkg[==ver] args…`, `uvx --from spec cmd`, `uv tool run …` | `uv venv` + `uv pip install` | `…/venv/bin/<cmd>` |
| `python script.py args…` | none | the script's folder mounted read-only |
| `node script.js args…` | none | the package folder mounted read-only |

Installs are cached per package spec. A server that cannot run in the container (native add-ons that need install scripts, `python -m`, custom binaries) falls back to the process backend for that server only, and the reason is shown.

### What is copied

The server's *roots* are the absolute folders and files in its arguments, environment and working directory (system folders and the server's own code excluded). Each root has a private mirror under `~/.mcp-sentinel/sandbox/mirrors/`, re-synchronised incrementally (size + mtime) before every call; `node_modules`, virtualenvs and caches are skipped. Limits: `SENTINEL_SANDBOX_MAX_FILES` (5,000) and `SENTINEL_SANDBOX_MAX_BYTES` (200 MB) per root; beyond that the snapshot is partial and the preview says so. If a server is given your whole home folder, the sandbox maps it to the decoy home instead of copying it.

Real credentials never enter the sandbox: environment variables that look like secrets (`*TOKEN*`, `*KEY*`, `*SECRET*`, `*PASSWORD*`, …) are replaced by a traceable stand-in, distinct from the canaries planted in the decoy files.

## Verdict rules

| Verdict | Rule | Example |
|---|---|---|
| **MALICIOUS** | opened a planted credential file the request did not name | a "weather" tool reads `~/.ssh/id_rsa` |
| | planted credentials in the output, or in any network attempt (including DNS names) | |
| | sent the server's own credentials to a host that is not its configured API | |
| | a tool declared read-only (annotation or inferred) modified or deleted files | `search_logs` deletes `notes.txt` |
| | deleted files outside the paths named in the request | `write_file(a.txt)` also deletes `b.txt` |
| | wrote a startup script or credential store (`.bashrc`, `.ssh/`, LaunchAgents, Claude config, …) | |
| | installed a git hook it was not asked to write | |
| | started a network utility (`curl`, `wget`, `nc`, `ssh`, …) without being a code-execution tool | |
| **DANGEROUS** (blast radius) | more than `SENTINEL_SANDBOX_MAX_DELETES` (25) deletions, ≥ 50 % of a folder deleted, more than 100 modifications, or > 100 MB written in one call. Moves and renames are recognised and not counted as deletions | "clean up" that would wipe a project |
| **SUSPICIOUS** | a local (non-network) tool contacting a host that is not in the arguments, the server's config, its audited behaviour contract or a destination a person already approved | telemetry or exfiltration endpoints |
| | edits CI / editor automation (`.github/workflows`, `.vscode/tasks.json`, `Makefile`, `package.json`, …) it was not asked to touch; modifies files beyond the ones named | |
| | started a shell without being a code-execution tool; returns its own API credentials; reads a credential file that *was* explicitly requested | |
| **INCONCLUSIVE** | the sandbox could not run the call (launch failure, timeout, Docker required but missing) | |
| **SAFE** | none of the above | |

What the gateway does with each verdict:

* **MALICIOUS** → `BLOCK` (`deny.sandbox`) even when the user already passed MFA or a human approval; the tool is quarantined, the workflow's capability leases are revoked, and a pending approval or step-up for the same call is cancelled so nobody can approve it.
* **DANGEROUS** → `BLOCK` (`deny.blast_radius`) for this call only. Raise the limits if large operations are intended.
* **SUSPICIOUS**, or **INCONCLUSIVE** for a tool that writes, executes or is annotated destructive (with `SENTINEL_SANDBOX_STRICT=true`) → `HUMAN_APPROVAL` (`escalate.sandbox`). The approval page shows the effect preview: every file that would be created / modified / deleted with a unified diff, network attempts, programs started. Approval is bound to that exact request; once approved, the retried call is pre-flighted again and runs (unless the new run is MALICIOUS).
* Calls that already need MFA or approval for other reasons are pre-flighted too, so their approval screen shows the preview.

Every run is stored (`GET /v1/sandbox/runs`) and every block or escalation writes a signed receipt that references the superseded one.

## After the real call: undo and evasion detection

The mirror holds the pre-call state, so after the real call Sentinel diffs the real folders against it:

* **Time machine.** Every change is journalled with the previous version of each modified or deleted file (`~/.mcp-sentinel/sandbox/journal/<receipt>`). **Sandbox → Time machine → Undo** (`POST /v1/undo/{receipt_id}`) restores them and removes created files, unless they changed again since (reported as a conflict). The last `SENTINEL_UNDO_RETENTION` (200) journals are kept.
* **Sandbox evasion.** If the real call modified or deleted files the sandbox run did not touch (a server that detects the sandbox and behaves differently, or a delayed payload), Sentinel restores those files immediately, withholds the tool's output from the model, quarantines the tool and raises a CRITICAL event. The check only runs when the sandbox run was complete (no errors, no partial snapshot).

## Behaviour audit at registration

When a local server is added from the dashboard, Sentinel exercises **every tool** once in the sandbox (read-only tools first, destructive last), with arguments derived from each input schema and pointing into a synthetic workspace, never your files. The result:

* a per-tool verdict and **behaviour contract** (files written / deleted, network destinations, programs started) shown under the server's *Sandbox* tab; hosts and programs from the contract are expected in later calls;
* tools judged MALICIOUS are quarantined before the model can call them;
* the audit feeds the server's SAFE / CAUTION / NOT SAFE verdict;
* a server that advertises different tools inside the sandbox is flagged.

Re-run it from the server drawer or `POST /v1/servers/{id}/audit`.

## Settings

| Variable | Default | |
|---|---|---|
| `SENTINEL_SANDBOX_MODE` | `auto` | `auto` (Docker when available, else process), `docker` (require Docker; without it, write / execute calls go to a person), `process`, `off` |
| `SENTINEL_SANDBOX_PREFLIGHT` | `all` | `all` calls, only `writes` (tools with write / execute / send capabilities), or `off` |
| `SENTINEL_SANDBOX_AUDIT_ON_REGISTER` | `true` | behaviour audit when a local server is added |
| `SENTINEL_SANDBOX_STRICT` | `true` | unverifiable write / execute calls need a person |
| `SENTINEL_SANDBOX_MAX_DELETES` / `_MAX_MODIFICATIONS` | 25 / 100 | blast-radius guard |
| `SENTINEL_SANDBOX_DIR` | `~/.mcp-sentinel/sandbox` | mirrors, package cache, journals |
| `SENTINEL_SANDBOX_IMAGE` | `mcp-sentinel/sandbox:1` | |
| `SENTINEL_SANDBOX_CALL_TIMEOUT_SECONDS` | 25 | |

Measured with the official Filesystem server on Docker: ~1.2 s per pre-flight (container start + server start + call), ~10 s once for the first install; its 14-tool behaviour audit finishes within a few seconds of registration.

## Limits

* **Remote servers cannot be sandboxed**: their code runs on someone else's machine. Their calls are still covered by policy, risk scoring, taint tracking, the output firewall and the vulnerability scan.
* Effects outside the copied folders and the decoy home (for example a SaaS API) are not reproduced: in Docker the network is cut, so the sandbox sees the *attempt* and the destination, not the remote effect. With swapped credentials, API-backed tools usually fail in the sandbox; such runs are judged on their side effects, network destinations and processes.
* A server can still behave differently in the sandbox (environment fingerprinting, time bombs). The evasion check catches file changes it makes for real, not network actions taken only for real. Remote effects have no undo.
* The process backend is not a security boundary (same OS user). Use Docker for containment.
* Pre-flight doubles the work of each call and serialises calls to the same server while one is verified.
* Docker Desktop (Linux and macOS) can only bind-mount folders listed under **Settings → Resources → File sharing**; on Linux that is just your home folder by default, so `/tmp` or `/opt` are refused. Sentinel probes each folder once: its own sandbox folder (`~/.mcp-sentinel/sandbox`) must be shared, and the code of a `python script.py` / `node script.js` server outside a shared folder is copied into the sandbox folder first. If the sandbox folder itself is not shared, the dashboard and `mcp-sentinel doctor` say so and the process backend is used. Docker Engine without Desktop can mount anything.
* When Sentinel itself runs in Docker Compose, its container has no Docker CLI or socket, so it uses the process backend. Giving it the host's Docker socket would enable the Docker backend, but it also hands Sentinel control of the host's Docker. Prefer running Sentinel directly on the host for the full sandbox.

## Alternatives considered

| Approach | Why not (or not yet) |
|---|---|
| Run the real server permanently inside a container | Strongest containment, but breaks servers that must touch the real system (keychains, GUI apps, local databases) and gives no *preview* or approval of an individual call. Shadow execution keeps the real server unchanged and still contains the test run. Can be combined: point the real server at a container too. |
| gVisor / Firecracker / Kata micro-VMs for the shadow run | Better kernel isolation than runc. Not available on Docker Desktop for macOS/Windows; a drop-in later via `--runtime=runsc`. |
| WebAssembly (WASI) sandbox | Excellent isolation and start-up time, but almost no MCP server ships as WASM today. |
| OS sandboxes (macOS `sandbox-exec`, Linux Landlock + seccomp, Windows Sandbox / AppContainer) | Platform-specific and cannot provide a copy-on-write view of your files plus an observable fake network in one mechanism. |
| Copy-on-write snapshots (APFS clones, btrfs/ZFS snapshots, overlayfs) | Faster than copying for big folders; overlayfs needs privileges. The incremental mirror is portable and also gives undo and evasion detection. |
| "Dry-run" flags in tools / MCP annotations | Self-reported by the server, so a malicious server lies; Sentinel uses annotations only as claims to check (a read-only tool that writes is MALICIOUS). |
| Record and replay of the sandbox run instead of a second real call | Would guarantee the real effect equals the preview, but only works for pure file operations; Sentinel instead verifies the real effect against the prediction afterwards and reverts surprises. |
