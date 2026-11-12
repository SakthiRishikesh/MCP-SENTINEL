# MCP-Sentinel

**An adaptive, zero-trust security control plane for the Model Context Protocol (MCP).**

MCP-Sentinel sits between MCP clients such as Claude Desktop or Claude Code and the MCP servers they use. Connect a client to Sentinel once, then add local or remote MCP servers through the dashboard. Sentinel checks and governs tool calls outside the model: it applies identity and policy controls, evaluates risk, can run local calls through a sandbox preflight, records decisions, and filters returned content.

The model can request a tool call; Sentinel makes the enforcement decision. For local stdio servers, Sentinel can first run a call against a disposable workspace and compare the observed result with the real call. Suspicious calls can require human review, and malicious calls are blocked regardless of approval.

> **Project status:** the default setup is a local development/demo configuration. Demo authentication and seeded accounts are convenient for trying the project, but are not production identity configuration. Review the [security model](docs/security-model.md), [threat model](docs/threat-model.md), and [limitations](docs/limitations.md) before exposing an instance to other users or networks.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation and local setup](#installation-and-local-setup)
- [Run MCP-Sentinel](#run-mcp-sentinel)
- [Connect an MCP client](#connect-an-mcp-client)
- [Add MCP servers](#add-mcp-servers)
- [Configuration](#configuration)
- [Docker Compose](#docker-compose)
- [Development](#development)
- [API and technical details](#api-and-technical-details)
- [Troubleshooting](#troubleshooting)
- [Documentation and references](#documentation-and-references)
- [Contributing](#contributing)
- [License](#license)

## Features

- **MCP gateway:** exposes a Streamable HTTP MCP endpoint and a stdio bridge for clients. Local stdio, Streamable HTTP, and SSE upstream servers are supported.
- **Policy and identity controls:** role and capability checks, configurable rules, organization membership and assignments, lockdown, MFA step-up, human approvals, and short-lived scoped leases.
- **Risk analysis:** combines policy context with workflow history, caller behavior, data flow, tool capabilities, and other evidence. Hard policy decisions remain authoritative.
- **Local-call sandboxing:** optional shadow execution for local tools, behavior audits on registration, effect previews, blast-radius checks, and comparison of predicted versus actual effects. Docker provides stronger containment; process mode is a fallback with weaker isolation.
- **Server and tool integrity checks:** tool-definition pinning and drift detection, tool-poisoning checks, vulnerability scans, and supply-chain signals.
- **Data and output protections:** input validation, secret redaction, taint tracking, prompt-injection detection, and output filtering.
- **Audit and incident response:** signed, hash-chained decision receipts, workflow replay, undo journals, alerts, and signed incident reports.
- **Web interface:** a landing/auth site at `/` and the login-gated control dashboard at `/app` when the frontends have been built.

See [DEMO.md](DEMO.md) for a guided walk-through and the [documentation index](#documentation-and-references) for subsystem details.

## Architecture

```text
MCP client (stdio bridge or Streamable HTTP)
                 |
                 v
         MCP-Sentinel gateway  <---->  Dashboard / REST API
                 |
    identity, integrity, validation,
    policy, risk, approval / MFA,
    sandbox preflight, output filters,
    audit receipts
                 |
                 v
      Local or remote MCP servers
```

The Python service is a FastAPI application. It manages upstream MCP connections and serves the REST API, MCP endpoint, and built frontend assets. SQLite is the default database; Redis is optional for shared state. Docker is used by the stronger sandbox backend when available and configured. The React/Vite frontends are built separately and served by the Python service.

More detail: [architecture](docs/architecture.md), [MCP integrations](docs/llm-integration.md), [sandbox](docs/sandbox.md), and [API](docs/api.md).

## Requirements

For a local host installation:

- **Python 3.11 or newer.** The Makefile uses [uv](https://docs.astral.sh/uv/) to create a Python 3.12 environment. `pip` and `venv` work when a suitable Python is already installed.
- **Node.js 18 or newer** and npm to build the landing site and dashboard, and to run npm-based MCP servers such as `npx` servers.
- **uv** if you use `uvx`-based MCP servers. Install instructions are at [docs.astral.sh/uv](https://docs.astral.sh/uv/).
- **Docker Desktop or Docker Engine** for the Docker sandbox backend. Without a usable Docker daemon, automatic mode falls back to the process sandbox, which does not provide equivalent containment.
- An MCP client (for example, [Claude Desktop](https://claude.com/download) or [Claude Code](https://docs.anthropic.com/en/docs/claude-code)) to use tools through the stdio bridge.

Docker Compose is an alternative for a shared local-stack demonstration. It starts Sentinel with PostgreSQL, Redis, and the dashboard proxy; see [Docker Compose](#docker-compose).

## Installation and local setup

Clone the repository and enter its directory:

```bash
git clone <repository-url>
cd MCP-SENTINEL-main
```

### Linux and macOS

The Makefile sets up the Python environment, installs the package in editable mode, builds both frontends, and builds the sandbox image when Docker is running:

```bash
make setup
```

If you prefer to run the steps yourself:

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"

cd web && npm install && npm run build && cd ..
cd dashboard && npm install && npm run build && cd ..

docker build -t mcp-sentinel/sandbox:1 \
  -f docker/sandbox-runtime.Dockerfile docker/
```

The Docker image build is needed for the Docker sandbox backend. You can also build the image later from **Dashboard → Sandbox → Build image**. If Docker is unavailable, setup can still be used without the image, with the process sandbox's reduced isolation.

### Windows

Run in PowerShell from the repository directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

Push-Location .\web
npm install
npm run build
Pop-Location

Push-Location .\dashboard
npm install
npm run build
Pop-Location

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-windows.ps1
```

The Windows launcher serves the local application and stores state under `%LOCALAPPDATA%\MCP-Sentinel`. Local stdio MCP servers that need Windows paths should connect to a Sentinel process running on the Windows host. See [Running on Windows](docs/windows.md) for more detail and a safe filesystem-server example.

## Run MCP-Sentinel

Start the API and dashboard server:

```bash
# Linux/macOS, after `make setup`
make run

# Or from any platform with the environment activated
mcp-sentinel serve
```

By default the service binds to `127.0.0.1:8443`. Open [http://127.0.0.1:8443](http://127.0.0.1:8443) for the landing/sign-in page and [http://127.0.0.1:8443/app](http://127.0.0.1:8443/app) for the dashboard. API documentation is available at [http://127.0.0.1:8443/docs](http://127.0.0.1:8443/docs) while the service is running.

Useful CLI commands:

```bash
mcp-sentinel serve            # start the API and built UI
mcp-sentinel stop             # stop an API process started by Sentinel
mcp-sentinel doctor            # inspect Python, Docker, tools, and client setup
mcp-sentinel init              # initialize/seed the database
mcp-sentinel claude-config     # print a client configuration without changing it
```

On a Windows checkout, invoke the command through the virtual environment, for example `\.venv\Scripts\mcp-sentinel.exe serve`, or use the supplied PowerShell launcher. When Claude starts the Sentinel bridge while the API is down, the bridge can start the API in the background; its log is under `~/.mcp-sentinel/` on Unix-like systems.

### Demo sign-in

In the default demo configuration, the application seeds example accounts with the password `sentinel`:

| Account | Purpose |
| --- | --- |
| `you@demo.dev` | Individual dashboard account |
| `admin@northstar.dev` | Organization administrator, including Team & Access |
| `analyst@northstar.dev` | Organization employee with assigned access |

These accounts and demo token issuance are for local evaluation only. Do not use the default password or demo signing secret for a deployed instance.

## Connect an MCP client

For Claude Desktop, the CLI edits the client configuration and keeps a timestamped backup of an existing file:

```bash
mcp-sentinel install-claude
```

For Claude Code:

```bash
mcp-sentinel install-claude-code
```

Restart or reconnect the MCP client to load Sentinel. The bridge uses stdio between the client and Sentinel. Sentinel's HTTP MCP endpoint is available at `/mcp` for clients that support Streamable HTTP. See [docs/llm-integration.md](docs/llm-integration.md) for other clients, manual configuration, and authentication notes.

To move existing Claude-configured servers behind Sentinel, start the API first and then import them:

```bash
mcp-sentinel import-claude --replace
mcp-sentinel import-claude --from code --replace
```

`--replace` removes successfully imported entries from the client configuration so they are reached through Sentinel. Review the resulting client configuration and dashboard after importing. Claude Desktop extensions can connect directly to servers and bypass Sentinel; disable any extension you want governed and add its server through Sentinel instead.

## Add MCP servers

The registry starts empty. In the dashboard, open **Servers → Connect server** and choose a transport:

- **Local (stdio):** command, arguments, environment, and allowed workspace folders. The command must be installed and resolvable by Sentinel (`npx`, `uvx`, Python, or another executable).
- **Remote HTTP/SSE:** the server URL and any required headers or authentication settings.

Sentinel discovers and pins tool definitions, applies checks, and (when enabled) performs a scan and local behavior audit during registration. Inspect the trust status and findings before using a server. With clients that cache tool lists, reconnect or restart the client after adding a server. Sentinel also exposes discovery/invocation meta-tools while the client refreshes its tool list.

The [compatible server guide](docs/mcp-servers.md) lists known server setups. The [demo guide](DEMO.md) walks through connecting reference servers and trying representative controls.

## Configuration

Settings use the `SENTINEL_` prefix. Pydantic settings load the repository `.env` first and then a `.env` in the current working directory; process environment variables can also configure settings. Start with [.env.example](.env.example), and do not commit real credentials or secrets.

Common settings:

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_ENV` | `dev` | Environment label. |
| `SENTINEL_LOG_LEVEL` | `INFO` | Application log level. |
| `SENTINEL_AUTH_MODE` | `demo` | `demo` for local evaluation or `oidc` for an OIDC/JWKS-backed deployment. |
| `SENTINEL_DATABASE_URL` | SQLite database in the repository | SQLAlchemy database URL. PostgreSQL support is available with the `postgres` extra. |
| `SENTINEL_REDIS_URL` | empty | Optional Redis URL; empty uses in-process state. |
| `SENTINEL_GATEWAY_HOST` | `127.0.0.1` | Bind address. Loopback is the local-first default. |
| `SENTINEL_GATEWAY_PORT` | `8443` | API and locally served UI port. |
| `SENTINEL_SANDBOX_MODE` | `auto` | `auto`, `docker`, `process`, or `off`. |
| `SENTINEL_SANDBOX_PREFLIGHT` | `all` | `all`, `writes`, or `off` for local-call preflight selection. |
| `SENTINEL_SANDBOX_IMAGE` | `mcp-sentinel/sandbox:1` | Docker image used for sandbox runs. |
| `SENTINEL_DEMO_JWT_SECRET` | demo-only placeholder | Shared secret for demo tokens. Replace it for local custom setups; use OIDC for non-demo deployments. |

The configuration also includes risk thresholds, approval and lease timeouts, allowed hosts and CORS origins, scan behavior, notification channels, and data-flow controls. See [sentinel/config.py](sentinel/config.py) for the complete list and defaults. For OIDC, configure `SENTINEL_AUTH_MODE=oidc`, the issuer/audience, JWKS URL, client ID, and accepted asymmetric JWT algorithms for your identity provider.

State is stored in the configured database and key files. By default, the SQLite database is `sentinel.db` in the repository and signing/encryption keys are under `keys/`; sandbox caches, logs, and related runtime data are under `~/.mcp-sentinel/` on Unix-like systems. Back up and protect these locations according to your deployment needs.

## Docker Compose

For a containerized local stack with PostgreSQL, Redis, Sentinel, and the dashboard proxy:

```bash
docker compose up --build
```

Open [http://localhost:3000](http://localhost:3000) for the dashboard. The Sentinel API is published on `http://localhost:8444` by default; change the host port with `SENTINEL_HOST_PORT`, for example:

```bash
SENTINEL_HOST_PORT=9000 docker compose up --build
```

Compose uses demo authentication and demo credentials in its checked-in configuration. Treat it as a local evaluation stack: replace credentials and configure production authentication before broader exposure. This container setup does not mount the host Docker socket, so Sentinel's Docker sandbox backend is not available inside it; use a host installation for full local-server sandbox containment and the desktop stdio bridge. Persistent named volumes hold PostgreSQL data and Sentinel keys.

## Development

The project uses Python with setuptools, FastAPI, SQLAlchemy, pytest, and two Vite/React frontends. The package is installed editable with `pip install -e ".[dev]"` or the equivalent `uv` command above.

Useful commands from the repository root:

```bash
make setup       # install Python dependencies, build both frontends, build sandbox image if Docker runs
make run         # run the local service
make doctor      # diagnose local runtime and client setup
make test        # run the Python test suite
make reset-demo  # reset demo activity while retaining registered servers
```

Without Make, run tests with:

```bash
python -m pytest -q
```

Frontend development servers can be run independently:

```bash
cd web && npm install && npm run dev
cd dashboard && npm install && npm run dev
```

The Vite configuration proxies API requests to the local Sentinel service. Build both frontends with `npm run build` in each directory before expecting the Python service to serve their static assets. Useful code areas include `sentinel/` for the gateway, API, configuration, and persistence; `identity/`, `policy/`, `risk/`, `integrity/`, `sandbox/`, `workflow/`, and `mcp_servers/` for core subsystems; and `dashboard/` plus `web/` for the UI.

## API and technical details

- REST endpoints are versioned under `/v1`; interactive OpenAPI docs are served at `/docs` and the schema at `/openapi.json` by FastAPI.
- The MCP endpoint is `/mcp` for Streamable HTTP; the stdio client adapter is `mcp-sentinel bridge` (normally launched by the MCP client).
- The default persistence backend is SQLite. PostgreSQL is supported through the `postgres` optional dependency. Redis is optional and backs shared ephemeral state when configured.
- Tool calls pass through identity, server trust and tool-integrity checks, input validation, policy/capability enforcement, risk evaluation, any required step-up/approval, execution controls, output filtering, and receipt recording. See [architecture](docs/architecture.md) and [API reference](docs/api.md).
- MCP-Sentinel supports standard local and remote MCP transport patterns; details and known compatibility notes are in [docs/mcp-servers.md](docs/mcp-servers.md).

## Troubleshooting

- **Run `mcp-sentinel doctor` first.** It checks the local runtime, sandbox readiness, MCP launch tools, and client configuration.
- **The dashboard is missing or unstyled:** build both `web` and `dashboard` frontends with `npm run build` in their directories, then restart the service.
- **No sandbox containment:** ensure Docker is running and build `mcp-sentinel/sandbox:1`. In automatic mode, Sentinel can fall back to process mode, which has weaker isolation and may request approval for effects it cannot verify.
- **MCP server command cannot be found:** install its runtime/package manager and ensure the command (`npx`, `uvx`, etc.) is on the PATH inherited by Sentinel. Check the server's connection details in the dashboard.
- **New tools do not appear in the client:** reconnect the Sentinel MCP server or restart the client. Some clients cache tool definitions; the Sentinel discovery/invocation meta-tools remain available.
- **A local path is inaccessible:** ensure the upstream server's configured root includes it. For Windows host paths, run Sentinel on Windows; a container cannot access host paths unless they are mounted. See [docs/windows.md](docs/windows.md).
- **A Claude Desktop extension bypasses policy:** disable the direct extension and connect its MCP server behind Sentinel.

## Documentation and references

- [Live demo](DEMO.md) · [Compatible MCP servers](docs/mcp-servers.md)
- [Architecture](docs/architecture.md) · [API](docs/api.md) · [MCP client integration](docs/llm-integration.md)
- [Sandbox](docs/sandbox.md) · [Risk engine](docs/risk-engine.md) · [Vulnerability scanner](docs/vulnerability-scanner.md) · [Rug-pull detection](docs/rug-pull-detection.md)
- [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md)
- [Windows setup](docs/windows.md) · [Notifications and incident reports](docs/notifications-and-reports.md)
- [Model Context Protocol](https://modelcontextprotocol.io/) · [Python](https://www.python.org/) · [Node.js](https://nodejs.org/) · [Docker](https://docs.docker.com/)

## Contributing

Contributions are welcome. Before opening a change:

1. Check existing issues and documentation so the change fits the project behavior and security model.
2. Keep changes focused, document configuration or behavior changes, and include tests for changed behavior where appropriate.
3. Run the relevant checks locally, including `make test` for Python changes and frontend builds for UI changes.
4. Describe the behavior changed, the checks run, and any limitations or security implications in the pull request.

Do not include secrets, personal data, real credentials, or unreviewed security-sensitive samples in commits. The package metadata declares Apache-2.0; retain attribution for third-party components.

## License

The package metadata declares the Apache-2.0 license. This checkout does not currently include a `LICENSE` text file, so consult the distribution or repository maintainers for the license text. The vulnerability scanner incorporates ideas from [SecureMCP](https://github.com/makalin/SecureMCP); see the project's notices and source for attribution and licensing details.
