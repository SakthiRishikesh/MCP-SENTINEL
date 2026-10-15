"""Capability inference for arbitrary MCP tools.

A tool's name, input schema, description and annotations are combined into a
machine-readable capability profile (capabilities, sensitivity, flow roles). Annotations
are *untrusted hints* (MCP spec): they may raise the assessed risk but never lower it, and a
contradiction between annotations and the tool's evident semantics is itself evidence of
deception.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sentinel.types import (
    CAPABILITY_SENSITIVITY,
    Capability,
    FlowRole,
    Sensitivity,
    max_sensitivity,
    primary_capability,
)

READ_VERBS = {
    "read", "get", "list", "search", "find", "query", "view", "show", "describe", "lookup", "look", "inspect",
    "count", "stat", "stats", "info", "status", "head", "tail", "cat", "grep", "retrieve", "load", "open",
    "check", "explain", "summarize", "summarise", "analyze", "analyse", "scan", "tree", "diff", "history",
    "preview", "resolve", "validate", "verify", "compare", "calculate", "convert", "parse", "screenshot",
    "snapshot", "observe", "watch", "poll", "download", "export_view", "sequentialthinking", "think",
}
WRITE_VERBS = {
    "write", "create", "update", "delete", "remove", "rm", "modify", "edit", "insert", "set", "put", "patch",
    "move", "mv", "rename", "copy", "cp", "commit", "push", "merge", "add", "append", "save", "store", "mkdir",
    "make", "drop", "truncate", "replace", "close", "archive", "assign", "label", "approve", "enable", "disable",
    "reset", "clear", "fork", "star", "unstar", "upsert", "import", "fill", "click", "type", "press", "select",
    "hover", "drag", "submit", "book", "order", "buy", "purchase", "pay", "cancel", "schedule", "register",
}
DESTRUCTIVE_VERBS = {
    "delete", "remove", "rm", "drop", "truncate", "destroy", "purge", "wipe", "erase", "kill",
    "terminate", "revoke", "reset", "overwrite", "force", "uninstall", "shred", "nuke",
}
# Words that are verbs in browser/UI automation but nouns elsewhere ("get_file_type", "select_rows").
AMBIGUOUS_WRITE = {"type", "select", "set", "label", "order", "book", "close", "fill", "star", "register", "import", "add"}
TRANSFER_VERBS = {
    "send", "post", "email", "mail", "notify", "message", "msg", "sms", "tweet", "publish", "share", "upload",
    "export", "transfer", "forward", "webhook", "broadcast", "reply", "comment", "dm", "invite", "emit",
    "transmit", "exfil", "sync", "pay", "wire",
}
SECRET_TOKENS = {
    "secret", "secrets", "credential", "credentials", "cred", "creds", "password", "passwords", "passwd",
    "apikey", "vault", "keychain", "keyring", "privatekey", "dotenv", "env", "environment", "token", "tokens",
    "otp", "mfa", "seed", "mnemonic", "wallet",
}
EXEC_TOKENS = {
    "exec", "execute", "shell", "command", "cmd", "bash", "sh", "zsh", "powershell", "pwsh", "terminal",
    "script", "eval", "spawn", "subprocess", "repl", "interpreter", "applescript", "osascript",
}
INFRA_TOKENS = {
    "deploy", "restart", "reboot", "shutdown", "scale", "isolate", "quarantine", "provision", "instance",
    "container", "docker", "kubectl", "k8s", "pod", "cluster", "vm", "firewall", "iam", "permission",
    "permissions", "grant", "edr", "cron", "infrastructure", "infra", "terraform", "ansible", "dns", "route",
    "service", "daemon", "process", "kill", "sudo", "chmod", "chown",
}
EXTERNAL_TOKENS = {
    "fetch", "http", "https", "url", "web", "browse", "browser", "navigate", "crawl", "scrape", "google",
    "bing", "brave", "websearch", "whois", "weather", "news", "wikipedia", "reddit", "twitter", "youtube",
    "internet", "online", "intel", "threat", "reputation", "geoip", "ip", "domain", "rss", "tavily",
    "exa", "perplexity", "firecrawl", "playwright", "puppeteer",
}
PRIVATE_NOUNS = {
    "file", "files", "dir", "directory", "folder", "path", "db", "database", "sql", "table", "tables",
    "record", "records", "mail", "email", "emails", "inbox", "messages", "chat", "chats", "calendar", "event",
    "events", "contact", "contacts", "note", "notes", "memory", "memories", "doc", "docs", "document",
    "documents", "drive", "sheet", "sheets", "repo", "repository", "issue", "issues", "pr", "source", "log",
    "logs", "customer", "customers", "user", "users", "account", "accounts", "ticket", "tickets", "graph",
    "entities", "entity", "history", "clipboard", "screen", "photos", "health", "bank", "transactions",
}
UNTRUSTED_NOUNS = {
    "web", "url", "page", "html", "website", "search", "email", "emails", "mail", "inbox", "issue", "issues",
    "comment", "comments", "pr", "message", "messages", "chat", "news", "feed", "rss", "tweet", "post",
    "posts", "reddit", "ticket", "tickets", "review", "reviews", "document", "documents", "pdf",
}

URL_PARAMS = {"url", "uri", "href", "link", "endpoint", "webhook", "webhook_url", "callback_url", "target_url"}
EXEC_PARAMS = {"command", "cmd", "script", "shell", "commands", "shell_command"}
PATH_PARAMS = {"path", "file", "filename", "filepath", "file_path", "directory", "dir", "folder", "source", "destination_path"}
SQL_PARAMS = {"sql", "query_sql", "statement"}
RECIPIENT_PARAMS = {"to", "recipient", "recipients", "channel", "channel_id", "email", "phone", "chat_id", "user_id", "cc", "bcc"}
BODY_PARAMS = {"body", "message", "text", "content", "payload", "data", "html", "attachment", "attachments", "blocks"}
SECRET_PARAMS = {"password", "secret", "token", "api_key", "apikey", "private_key", "credential", "credentials"}


def tokenize(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


@dataclass
class Inference:
    capabilities: list[Capability]
    sensitivity: Sensitivity
    flow_roles: list[FlowRole]
    destructive: bool = False
    confidence: str = "medium"
    resource: str = ""
    evidence: list[str] = field(default_factory=list)
    annotation_conflicts: list[str] = field(default_factory=list)

    @property
    def primary(self) -> Capability:
        return primary_capability(self.capabilities)

    def as_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [c.value for c in self.capabilities],
            "primary": self.primary.value,
            "sensitivity": self.sensitivity.value,
            "flow_roles": [r.value for r in self.flow_roles],
            "destructive": self.destructive,
            "confidence": self.confidence,
            "resource": self.resource,
            "evidence": self.evidence[:20],
            "annotation_conflicts": self.annotation_conflicts,
        }


def _param_names(schema: dict[str, Any] | None) -> set[str]:
    props = (schema or {}).get("properties") or {}
    return {str(k).lower() for k in props} if isinstance(props, dict) else set()


def infer(tool: dict[str, Any], *, server_transport: str = "stdio") -> Inference:
    name = str(tool.get("name") or "")
    description = str(tool.get("description") or "")
    title = str(tool.get("title") or (tool.get("annotations") or {}).get("title") or "")
    annotations = tool.get("annotations") or {}
    params = _param_names(tool.get("inputSchema") or tool.get("schema"))
    name_tokens = tokenize(name) + tokenize(title)
    tokens = set(name_tokens)
    desc_tokens = set(tokenize(description[:600]))
    caps: set[Capability] = set()
    evidence: list[str] = []
    destructive = False

    def add(cap: Capability, why: str) -> None:
        if cap not in caps:
            caps.add(cap)
            evidence.append(f"{cap.value}: {why}")

    verb = name_tokens[0] if name_tokens else ""
    lead = set(name_tokens[:2])  # verbs may follow a namespace noun: "github_create_issue", "browser_click"
    all_verbs = READ_VERBS | WRITE_VERBS | TRANSFER_VERBS | DESTRUCTIVE_VERBS
    first_verb = next((t for t in name_tokens if t in all_verbs), "")
    # "get_post" reads a post; "post_message" sends one: the first verb in the name decides.
    read_only_verb = first_verb in READ_VERBS and first_verb not in (WRITE_VERBS | TRANSFER_VERBS | DESTRUCTIVE_VERBS)
    code_like = tokens & {"run", "execute", "exec", "eval", "python", "javascript", "js", "notebook", "sandbox", "interpreter"}

    sql_exec = bool(tokens & {"query", "sql"} and tokens & {"execute", "exec", "run"})
    if sql_exec:
        add(Capability.WRITE, "executes arbitrary queries (can modify data)")
    elif (tokens & EXEC_TOKENS and not read_only_verb) or params & EXEC_PARAMS or ("code" in params and code_like) or (
        verb == "run" and not tokens & {"query", "report", "search", "sql", "report"}
    ):
        add(Capability.CODE_EXECUTION, "executes commands/code (" + ", ".join(sorted((tokens & EXEC_TOKENS) | (params & EXEC_PARAMS)) or ["run"]) + ")")
    secret_hit = sorted((tokens & SECRET_TOKENS) | (params & SECRET_PARAMS if read_only_verb else set()))
    if secret_hit and not (set(secret_hit) <= {"token", "tokens"} and tokens & {"count", "counter", "tokenize", "estimate", "usage", "limit"}):
        add(Capability.SECRET_ACCESS, f"handles secrets ({', '.join(secret_hit)})")
    if tokens & {"api", "access", "private", "ssh", "auth", "signing"} and tokens & {"key", "keys"}:
        add(Capability.SECRET_ACCESS, "handles keys")
    infra_hit = tokens & INFRA_TOKENS
    if infra_hit and (not read_only_verb or infra_hit & {"isolate", "quarantine", "restart", "reboot", "shutdown", "kill", "grant", "sudo"}):
        add(Capability.INFRASTRUCTURE_CONTROL, f"controls infrastructure ({', '.join(sorted(infra_hit))})")
    if (tokens & TRANSFER_VERBS and not read_only_verb) or (params & RECIPIENT_PARAMS and params & BODY_PARAMS):
        add(Capability.DATA_TRANSFER, "sends data to a recipient/destination")
    if params & URL_PARAMS and (params & BODY_PARAMS or tokens & {"post", "put", "request", "webhook", "upload"}):
        add(Capability.DATA_TRANSFER, "sends a request body to a caller-chosen URL")
    write_hit = (tokens & (WRITE_VERBS - AMBIGUOUS_WRITE)) | (lead & AMBIGUOUS_WRITE)
    if write_hit or (params & SQL_PARAMS and not read_only_verb):
        add(Capability.WRITE, f"modifies state ({', '.join(sorted(write_hit)) or 'sql'})")
    if tokens & DESTRUCTIVE_VERBS:
        destructive = True
        add(Capability.WRITE, "destructive verb")
    if tokens & EXTERNAL_TOKENS or params & URL_PARAMS:
        add(Capability.EXTERNAL_LOOKUP, "reaches external resources (" + ", ".join(sorted((tokens & EXTERNAL_TOKENS) | (params & URL_PARAMS))) + ")")
    if tokens & READ_VERBS or (not caps and verb in READ_VERBS):
        add(Capability.READ, f"reads data ({verb or 'read'})")

    # Description is weaker evidence: only used when the name/schema were inconclusive.
    if not caps:
        if desc_tokens & {"execute", "shell", "command"}:
            add(Capability.CODE_EXECUTION, "description mentions command execution")
        elif desc_tokens & TRANSFER_VERBS:
            add(Capability.DATA_TRANSFER, "description mentions sending data")
        elif desc_tokens & {"delete", "create", "update", "write", "modify"}:
            add(Capability.WRITE, "description mentions modification")
        elif desc_tokens & {"fetch", "http", "url", "website", "internet", "web"}:
            add(Capability.EXTERNAL_LOOKUP, "description mentions web access")
    confidence = "high" if len(evidence) >= 1 and verb else "medium"
    if not caps:
        add(Capability.READ, "no capability keywords matched; defaulting to READ")
        confidence = "low"

    # Annotations: can only add risk; contradictions are recorded as deception evidence.
    conflicts: list[str] = []
    ro = annotations.get("readOnlyHint")
    if ro is True and caps & {Capability.WRITE, Capability.DATA_TRANSFER, Capability.CODE_EXECUTION, Capability.INFRASTRUCTURE_CONTROL}:
        conflicts.append(
            "annotations claim readOnlyHint=true but the tool's name/schema indicate "
            + ", ".join(sorted(c.value for c in caps if c != Capability.READ and c != Capability.EXTERNAL_LOOKUP))
        )
    if ro is False and caps <= {Capability.READ, Capability.EXTERNAL_LOOKUP}:
        add(Capability.WRITE, "annotations declare readOnlyHint=false")
    if annotations.get("destructiveHint") is True and ro is not True:
        destructive = True
        add(Capability.WRITE, "annotations declare destructiveHint=true")
    if annotations.get("destructiveHint") is False and destructive:
        conflicts.append("annotations claim destructiveHint=false but the tool name is destructive")

    capabilities = sorted(caps, key=lambda c: list(Capability).index(c))
    sens = max_sensitivity([CAPABILITY_SENSITIVITY[c] for c in capabilities])
    if destructive and sens in {Sensitivity.LOW, Sensitivity.MEDIUM}:
        sens = Sensitivity.HIGH

    roles: set[FlowRole] = set()
    open_world = annotations.get("openWorldHint") is True
    if Capability.SECRET_ACCESS in caps or (Capability.READ in caps and (tokens | params) & PRIVATE_NOUNS):
        roles.add(FlowRole.PRIVATE_SOURCE)
    if server_transport == "stdio" and Capability.READ in caps and params & PATH_PARAMS:
        roles.add(FlowRole.PRIVATE_SOURCE)
    if Capability.EXTERNAL_LOOKUP in caps or (open_world and Capability.READ in caps) or (tokens & UNTRUSTED_NOUNS and Capability.READ in caps):
        roles.add(FlowRole.UNTRUSTED_SOURCE)
    # Any external lookup sends its arguments to a third party, so it is also an exfiltration channel.
    if (
        caps & {Capability.DATA_TRANSFER, Capability.CODE_EXECUTION, Capability.EXTERNAL_LOOKUP}
        or (Capability.WRITE in caps and (open_world or tokens & {"issue", "comment", "post", "pr", "gist", "page", "publish"}))
    ):
        roles.add(FlowRole.EGRESS_SINK)

    resource_tokens = [t for t in name_tokens if t not in READ_VERBS | WRITE_VERBS | TRANSFER_VERBS | {"run"}]
    return Inference(
        capabilities=capabilities,
        sensitivity=sens,
        flow_roles=sorted(roles, key=lambda r: r.value),
        destructive=destructive,
        confidence=confidence,
        resource="_".join(resource_tokens[:3]) or name,
        evidence=evidence,
        annotation_conflicts=conflicts,
    )
