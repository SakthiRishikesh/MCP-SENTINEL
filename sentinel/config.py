from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


def _csv(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


class Settings(BaseSettings):
    # the project's .env first, then one in the working directory (later files win)
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=(str(REPO_ROOT / ".env"), ".env"), extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"
    auth_mode: Literal["demo", "oidc"] = "demo"
    jwt_issuer: str = "http://localhost:8080/realms/mcp-sentinel"
    jwt_audience: str = "mcp-sentinel"
    jwt_algorithms: str = "RS256,HS256"
    demo_jwt_secret: str = "change-me-demo-only-not-for-production"
    oidc_jwks_url: str = "http://localhost:8080/realms/mcp-sentinel/protocol/openid-connect/certs"
    oidc_client_id: str = "mcp-sentinel"
    database_url: str = f"sqlite:///{REPO_ROOT / 'sentinel.db'}"  # absolute: the same data whatever the working directory
    redis_url: str = ""  # empty = in-process store; docker-compose sets redis://redis:6379/0
    # Local-first: bind to loopback by default (MCP Streamable HTTP guidance / DNS-rebinding defence).
    gateway_host: str = "127.0.0.1"
    gateway_port: int = 8443
    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://localhost:8443,http://127.0.0.1:8443"
    # Host-header allowlist (DNS-rebinding defence). "*" disables the check.
    allowed_hosts: str = "localhost,127.0.0.1,::1,[::1],sentinel,host.docker.internal,testserver"
    tls_enabled: bool = False
    public_url: str = ""  # externally reachable base URL of the API, used in approval links
    dashboard_url: str = ""  # defaults to public_url when the built dashboard is served by the API
    static_dashboard_dir: str = str(REPO_ROOT / "dashboard" / "dist")   # the dashboard SPA, served under /app
    static_web_dir: str = str(REPO_ROOT / "web" / "dist")               # the landing + auth site, served at /

    lease_default_seconds: int = 120
    workflow_ttl_seconds: int = 1800
    mfa_ttl_seconds: int = 300
    approval_ttl_seconds: int = 600
    mfa_acr: str = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
    allow_self_approval: bool | None = None  # None => allowed only in demo mode
    demo_token_loopback_only: bool = True

    # Risk thresholds (0-100). Hard policy always overrides these.
    restrict_risk_threshold: int = 40
    mfa_risk_threshold: int = 60
    block_risk_threshold: int = 80
    risk_alpha: float = 0.5  # share of the risk carried by likelihood alone (rest is modulated by impact)
    risk_memory_half_life_seconds: int = 600
    velocity_calls_per_minute: int = 30

    # Upstream MCP servers
    allow_stdio_servers: bool = True
    upstream_timeout_seconds: float = 45.0
    scan_on_register: bool = True  # passive vulnerability scan right after a server is added
    upstream_connect_timeout_seconds: float = 90.0
    discovery_interval_seconds: int = 60
    jit_integrity_seconds: int = 15
    auto_pin_clean_tools: bool = True
    process_monitor_enabled: bool = True
    process_monitor_interval_seconds: float = 5.0
    background_jobs_enabled: bool = True
    # Seed ready-to-use demo accounts (an individual + an organization with admin & employees) so the
    # login-gated dashboard can be tried immediately. Disabled in tests.
    seed_demo_accounts: bool = True

    # Sandbox pre-flight ("shadow execution") for local stdio servers: every call first runs against a
    # throw-away copy of the server's files with decoy credentials; the real call only follows a clean run.
    sandbox_mode: Literal["auto", "docker", "process", "off"] = "auto"  # auto = Docker when available
    sandbox_preflight: Literal["all", "writes", "off"] = "all"  # which calls are pre-flighted
    sandbox_audit_on_register: bool = True  # exercise every tool in the sandbox when a server is added
    sandbox_dir: str = str(Path.home() / ".mcp-sentinel" / "sandbox")
    sandbox_image: str = "mcp-sentinel/sandbox:1"
    sandbox_node_image: str = "node:22-slim"
    sandbox_python_image: str = "python:3.12-slim"
    sandbox_call_timeout_seconds: float = 25.0
    sandbox_install_timeout_seconds: float = 300.0
    sandbox_max_files: int = 5000  # per workspace root
    sandbox_max_bytes: int = 200 * 1024 * 1024
    sandbox_max_deletes: int = 25  # blast-radius guard: more deletions than this in one call is blocked
    sandbox_max_modifications: int = 100
    sandbox_strict: bool = True  # destructive calls the sandbox could not verify need human approval
    sandbox_memory: str = "512m"
    sandbox_cpus: str = "1"
    undo_retention: int = 200  # undo journals kept (oldest pruned first)
    sandbox_runtime: str = ""  # OCI runtime for sandbox / contained servers, e.g. "runsc" (gVisor)

    # Out-of-band notifications (also configurable in the dashboard, stored encrypted)
    notify_slack_webhook_url: str = ""
    notify_teams_webhook_url: str = ""
    notify_ntfy_url: str = ""
    notify_ntfy_token: str = ""
    notify_webhook_urls: str = ""  # comma-separated generic JSON webhooks
    notify_webhook_secret: str = ""  # HMAC-SHA256 signing secret for the generic webhooks
    notify_events: str = "approval,mfa,sandbox_block,sandbox_evasion,server_unsafe,rug_pull"

    # Data-flow / egress
    internal_domains: str = "internal,local,localhost,lan,corp,home.arpa,svc,cluster.local"
    allowed_egress_domains: str = ""
    dlp_redact_outputs: bool = True

    # MCP front-end (Claude Desktop bridge / Streamable HTTP endpoint)
    approval_wait_seconds: int = 50
    expose_meta_tools: bool = True
    result_banner: bool = True

    secrets_key_file: str = str(REPO_ROOT / "keys" / "sentinel.key")
    receipt_key_file: str = str(REPO_ROOT / "keys" / "receipt_ed25519.pem")

    roles: str = "USER,DEVELOPER,ANALYST,SECURITY_ADMIN,SYSTEM_ADMIN"

    @property
    def cors_origin_list(self) -> list[str]:
        return _csv(self.cors_origins)

    @property
    def allowed_host_list(self) -> list[str]:
        return _csv(self.allowed_hosts)

    @property
    def jwt_algorithm_list(self) -> list[str]:
        algs = _csv(self.jwt_algorithms)
        if self.auth_mode == "demo":
            # Demo tokens are HMAC-signed with the shared demo secret; nothing else is acceptable.
            return ["HS256"]
        # Never accept symmetric algorithms against an OIDC JWKS (algorithm-confusion defence).
        return [a for a in algs if not a.upper().startswith("HS")] or ["RS256"]

    @property
    def role_list(self) -> list[str]:
        return _csv(self.roles)

    @property
    def internal_domain_list(self) -> list[str]:
        return [d.lower().lstrip(".") for d in _csv(self.internal_domains)]

    @property
    def allowed_egress_domain_list(self) -> list[str]:
        return [d.lower().lstrip(".") for d in _csv(self.allowed_egress_domains)]

    @property
    def self_approval_allowed(self) -> bool:
        if self.allow_self_approval is None:
            return self.auth_mode == "demo"
        return self.allow_self_approval

    @property
    def api_base_url(self) -> str:
        if self.public_url:
            return self.public_url.rstrip("/")
        host = self.gateway_host if self.gateway_host not in {"0.0.0.0", "::"} else "localhost"
        scheme = "https" if self.tls_enabled else "http"
        return f"{scheme}://{host}:{self.gateway_port}"

    @property
    def dashboard_base_url(self) -> str:
        if self.dashboard_url:
            return self.dashboard_url.rstrip("/")
        if Path(self.static_dashboard_dir).joinpath("index.html").exists():
            return self.api_base_url
        return "http://localhost:5173"


@lru_cache
def get_settings() -> Settings:
    return Settings()
