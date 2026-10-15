from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on round-trip; normalise every datetime we compare to UTC-aware."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class TrustStatus(str, Enum):
    TRUSTED = "TRUSTED"
    MONITORED = "MONITORED"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"


TRUST_ORDER = [
    TrustStatus.TRUSTED,
    TrustStatus.MONITORED,
    TrustStatus.RESTRICTED,
    TrustStatus.QUARANTINED,
    TrustStatus.BLOCKED,
]


def worse_trust(a: str, b: str) -> str:
    """Return the more restrictive of two trust states (unknown values are treated as MONITORED)."""
    order = [t.value for t in TRUST_ORDER]
    ia = order.index(a) if a in order else 1
    ib = order.index(b) if b in order else 1
    return order[max(ia, ib)]


class LeaseState(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRING = "EXPIRING"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    RESTRICT = "RESTRICT"
    MFA_REQUIRED = "MFA_REQUIRED"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


# Decisions that result in the upstream tool actually being executed.
# RESTRICT executes under restrictions (strict output sanitisation, no lease extension).
EXECUTABLE_DECISIONS = {Decision.ALLOW, Decision.MONITOR, Decision.RESTRICT}


class RiskBand(str, Enum):
    NORMAL = "NORMAL"
    MONITOR = "MONITOR"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Capability(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXTERNAL_LOOKUP = "EXTERNAL_LOOKUP"
    SECRET_ACCESS = "SECRET_ACCESS"
    DATA_TRANSFER = "DATA_TRANSFER"
    INFRASTRUCTURE_CONTROL = "INFRASTRUCTURE_CONTROL"
    CODE_EXECUTION = "CODE_EXECUTION"


class Sensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SENSITIVITY_ORDER = [Sensitivity.LOW, Sensitivity.MEDIUM, Sensitivity.HIGH, Sensitivity.CRITICAL]


def max_sensitivity(values: list[Sensitivity | str]) -> Sensitivity:
    best = Sensitivity.LOW
    for v in values:
        s = Sensitivity(v)
        if SENSITIVITY_ORDER.index(s) > SENSITIVITY_ORDER.index(best):
            best = s
    return best


class DataClass(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    CRITICAL = "CRITICAL"


DATA_CLASS_ORDER = [DataClass.PUBLIC, DataClass.INTERNAL, DataClass.CONFIDENTIAL, DataClass.SECRET, DataClass.CRITICAL]


class Role(str, Enum):
    USER = "USER"
    DEVELOPER = "DEVELOPER"
    ANALYST = "ANALYST"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


class ReviewState(str, Enum):
    """Lifecycle of a tool definition in the integrity registry (TOFU pinning)."""

    APPROVED = "APPROVED"  # live definition == pinned definition
    PENDING_REVIEW = "PENDING_REVIEW"  # new tool whose static scan raised findings
    CHANGED = "CHANGED"  # live definition drifted from the pinned one (possible rug pull)
    REJECTED = "REJECTED"  # an admin rejected the definition


class ChangeClass(str, Enum):
    """Classification of a tool definition change (rug-pull analysis)."""

    COSMETIC = "COSMETIC"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class FlowRole(str, Enum):
    """Roles a tool can play in a toxic data flow (the "lethal trifecta")."""

    PRIVATE_SOURCE = "PRIVATE_SOURCE"  # reads private / sensitive data
    UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"  # ingests attacker-controllable content
    EGRESS_SINK = "EGRESS_SINK"  # can communicate data outside the trust boundary


CAPABILITY_SENSITIVITY: dict[Capability, Sensitivity] = {
    Capability.READ: Sensitivity.LOW,
    Capability.WRITE: Sensitivity.MEDIUM,
    Capability.EXTERNAL_LOOKUP: Sensitivity.LOW,
    Capability.SECRET_ACCESS: Sensitivity.CRITICAL,
    Capability.DATA_TRANSFER: Sensitivity.HIGH,
    Capability.INFRASTRUCTURE_CONTROL: Sensitivity.CRITICAL,
    Capability.CODE_EXECUTION: Sensitivity.CRITICAL,
}

ALL_CAPABILITIES = set(Capability)

ROLE_DEFAULT_CAPABILITIES: dict[str, set[Capability]] = {
    Role.USER.value: {Capability.READ},
    Role.DEVELOPER.value: {
        Capability.READ,
        Capability.WRITE,
        Capability.EXTERNAL_LOOKUP,
        Capability.CODE_EXECUTION,
    },
    Role.ANALYST.value: {
        Capability.READ,
        Capability.EXTERNAL_LOOKUP,
        Capability.WRITE,
    },
    Role.SECURITY_ADMIN.value: set(ALL_CAPABILITIES),
    Role.SYSTEM_ADMIN.value: set(ALL_CAPABILITIES),
}

SENSITIVE_CAPABILITIES = {
    Capability.SECRET_ACCESS,
    Capability.DATA_TRANSFER,
    Capability.INFRASTRUCTURE_CONTROL,
    Capability.CODE_EXECUTION,
}


def primary_capability(capabilities: list[Capability | str]) -> Capability:
    """The most sensitive capability of a tool drives authorization and impact."""
    caps = [Capability(c) for c in capabilities] or [Capability.READ]
    order = [Capability.READ, Capability.EXTERNAL_LOOKUP, Capability.WRITE, Capability.DATA_TRANSFER,
             Capability.SECRET_ACCESS, Capability.INFRASTRUCTURE_CONTROL, Capability.CODE_EXECUTION]
    return max(caps, key=order.index)


class IdentityContext(BaseModel):
    subject: str
    agent_id: str
    issuer: str
    audience: str | list[str]
    expires_at: datetime | None = None
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    acr: str | None = None
    amr: list[str] = Field(default_factory=list)
    token_valid: bool = True
    mfa_satisfied: bool = False
    session_id: str | None = None
    # account / multi-tenancy (empty for legacy demo/OIDC tokens)
    account_type: str = ""   # "individual" | "organization" | ""
    org_id: str = ""
    org_role: str = ""       # "admin" | "employee" | ""
    display_name: str = ""

    @property
    def is_org_admin(self) -> bool:
        return self.account_type == "organization" and self.org_role == "admin"

    @property
    def is_org_employee(self) -> bool:
        return self.account_type == "organization" and self.org_role == "employee"


class ToolCallRequest(BaseModel):
    workflow_id: str
    server_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_intent: str = ""
    agent_id: str | None = None
    destination: str | None = None
    resource: str | None = None


class RiskFactor(BaseModel):
    name: str
    score: int
    reason: str
    likelihood: float = 0.0
    category: str = "evidence"


class RiskResult(BaseModel):
    score: int
    band: RiskBand
    factors: list[RiskFactor] = Field(default_factory=list)
    hard_block: bool = False
    hard_block_reason: str | None = None
    likelihood: float = 0.0
    impact: float = 0.0
    model: str = "evidence-fusion/likelihood-x-impact"


class SecurityDecision(BaseModel):
    decision: Decision
    risk: RiskResult
    reasons: list[str] = Field(default_factory=list)
    required_capability: Capability | None = None
    lease_id: str | None = None
    policy_id: str | None = None
    mfa_challenge_id: str | None = None
    approval_id: str | None = None
    receipt_id: str | None = None
    restrictions: list[str] = Field(default_factory=list)
    explainability: dict[str, Any] = Field(default_factory=dict)
    approval_consumed: bool = False  # a human approved exactly this request (the sandbox does not re-escalate it)
