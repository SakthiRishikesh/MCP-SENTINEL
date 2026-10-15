from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.types import Capability, IdentityContext, Sensitivity, ToolCallRequest
from workflow.analyzer import WorkflowState as WF

INTENT_KEYWORDS: dict[Capability, set[str]] = {
    Capability.SECRET_ACCESS: {"credential", "secret", "password", "token", "key", "vault", "login", "access", "rotate"},
    Capability.DATA_TRANSFER: {"send", "share", "email", "mail", "post", "upload", "export", "transfer", "notify", "message",
                               "publish", "forward", "report", "exfil"},
    Capability.INFRASTRUCTURE_CONTROL: {"isolate", "restart", "deploy", "block", "quarantine", "shutdown", "scale", "contain",
                                        "remediate", "kill", "reboot"},
    Capability.CODE_EXECUTION: {"run", "execute", "script", "command", "build", "test", "install", "compile", "debug", "code",
                                "shell", "terminal"},
    Capability.WRITE: {"create", "update", "write", "save", "edit", "delete", "fix", "add", "change", "ticket", "incident",
                       "file", "commit", "open"},
}
GENERIC_INTENTS = {"", "mcp client tool call", "claude desktop tool call", "unknown"}


@dataclass
class ContextFinding:
    reasonable: bool
    reasons: list[str]
    risk_delta: int
    signals: list[tuple[str, float, str]] = field(default_factory=list)


class ContextualEngine:
    """Is this tool call reasonable for *this* identity, in *this* workflow, right now?"""

    def evaluate(
        self,
        *,
        identity: IdentityContext,
        request: ToolCallRequest,
        tool: object | None,
        workflow: WF,
        capability: Capability,
        sensitivity: Sensitivity | None = None,
    ) -> ContextFinding:
        signals: list[tuple[str, float, str]] = []
        intent = (request.user_intent or workflow.intent or "").strip().lower()
        if intent not in GENERIC_INTENTS and capability in INTENT_KEYWORDS and capability != Capability.WRITE:
            if not any(k in intent for k in INTENT_KEYWORDS[capability]):
                signals.append(("intent_mismatch", 0.30, f"{capability.value} is not implied by the declared user intent"))
        sens = sensitivity or getattr(tool, "sensitivity", None)
        if sens is not None and Sensitivity(sens) in {Sensitivity.HIGH, Sensitivity.CRITICAL} and identity.agent_id in {"", "unknown-agent"}:
            signals.append(("unknown_agent", 0.10, "high-sensitivity action from an unidentified agent"))
        reasons = [s[2] for s in signals]
        risk = int(round(sum(p for _, p, _ in signals) * 50))
        reasonable = not signals
        if reasonable:
            reasons.append("tool call is consistent with workflow context")
        return ContextFinding(reasonable=reasonable, reasons=reasons, risk_delta=risk, signals=signals)
