# MCP-Sentinel developer shortcuts (Linux / macOS). Windows: see README.md.
PY      := .venv/bin/python
CLI     := .venv/bin/mcp-sentinel
IMAGE   := mcp-sentinel/sandbox:1

.PHONY: setup venv web dashboard frontend sandbox-image run stop doctor claude claude-code test reset-demo

setup: venv frontend sandbox-image ## everything needed for a local install
	@printf '\nDone. Next: make claude && make run   (then open http://127.0.0.1:8443 and sign in)\n'

venv:
	@command -v uv >/dev/null || { echo "uv is required: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	uv venv --allow-existing --python 3.12 .venv
	uv pip install --python $(PY) -e ".[dev]"

frontend: web dashboard  ## build the landing/auth site (/) and the dashboard (/app)

web:
	cd web && npm install --no-audit --no-fund && npm run build

dashboard:
	cd dashboard && npm install --no-audit --no-fund && npm run build

sandbox-image:
	@docker info >/dev/null 2>&1 || { echo "Docker is not running: start Docker Desktop, then run 'make sandbox-image' (Sentinel falls back to the process sandbox meanwhile)"; exit 0; }
	docker build -t $(IMAGE) -f docker/sandbox-runtime.Dockerfile docker/

run:
	$(CLI) serve

stop:
	$(CLI) stop

doctor:
	$(CLI) doctor

claude:
	$(CLI) install-claude

claude-code:
	$(CLI) install-claude-code

test:
	$(PY) -m pytest -q

reset-demo:  ## clear demo activity and refresh ~/sentinel-demo (keeps servers; use ARGS="--wipe --start")
	bash scripts/reset-demo.sh $(ARGS)
