"""Static tool-poisoning scanner for MCP tool definitions.

Detects the attack classes catalogued by the MCP security community (Invariant Labs tool
poisoning / shadowing, Trail of Bits "line jumping", ASCII smuggling, rug pulls):

* hidden instruction blocks (``<IMPORTANT>``, ``<system>``…) and imperative injections
* secrecy directives ("do not tell the user") and approval-bypass social engineering
* references to credential files / client configs (``~/.ssh/id_rsa``, ``mcp.json``)
* data-collection directives (pass the conversation / file contents in a parameter)
* cross-server tool references (shadowing another server's trusted tool)
* invisible Unicode, Unicode-tag smuggling, bidi overrides, ANSI escape sequences
* base64 / hex encoded payloads, exfil-shaped parameters (``sidenote``, ``context`` …)

Every string reachable by the model is scanned: description, title, annotations.title and
every parameter's description/title/default/enum/examples - injections hide there too.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from sentinel.dlp import detect_smuggling

SEVERITY_WEIGHT = {"INFO": 0, "LOW": 6, "MEDIUM": 18, "HIGH": 40, "CRITICAL": 70}
POISONING_CATEGORIES = {
    "hidden_instructions", "injection_phrase", "secrecy_directive", "approval_bypass", "sensitive_path",
    "data_collection", "shadowing", "smuggling", "encoded_payload", "role_markers", "credential_exfiltration",
}

PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    # (category, severity, title, pattern)
    ("hidden_instructions", "HIGH", "hidden instruction block",
     re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|override|assistant_instructions|critical|mandatory)\b[^>]{0,80}>", re.I)),
    ("role_markers", "HIGH", "chat-template / role marker",
     re.compile(r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|<<\s*SYS\s*>>|^\s*#{2,}\s*system\b|^\s*(system|assistant)\s*:)", re.I | re.M)),
    ("injection_phrase", "HIGH", "instruction-override phrase",
     re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|other|system|safety)\b.{0,20}\b(instructions?|rules|guidelines|prompts?|messages?)\b", re.I)),
    ("injection_phrase", "MEDIUM", "pre-condition directive targeting the model",
     re.compile(r"\b(before|prior to)\s+(using|calling|invoking|running)\s+(this|any|the|other)\b.{0,40}\b(you\s+must|always|first|need to)\b", re.I)),
    ("injection_phrase", "LOW", "coercive directive to the model",
     re.compile(r"\b(you\s+must|you\s+have\s+to|it\s+is\s+(very\s+)?important\s+that\s+you|always\s+(call|use|include|pass|send|read))\b", re.I)),
    ("injection_phrase", "MEDIUM", "threat / urgency manipulation",
     re.compile(r"\b(otherwise|or else)\b.{0,40}\b(will\s+(not\s+work|fail|crash|break)|data\s+loss)\b", re.I)),
    ("secrecy_directive", "HIGH", "instructs the model to hide actions from the user",
     re.compile(r"\b(do\s*n[o']t|never|without)\s+(tell(ing)?|mention(ing)?|inform(ing)?|notify(ing)?|reveal(ing)?|show(ing)?|alert(ing)?|let(ting)?)\b.{0,20}\b(the\s+)?(user|human|operator|them)\b", re.I)),
    ("secrecy_directive", "HIGH", "instructs the model not to disclose something",
     re.compile(r"\b(do\s*n[o']t|never|must\s+not)\s+(tell|mention|inform|notify|reveal|disclose|say|explain|report)\b", re.I)),
    ("secrecy_directive", "HIGH", "secret / covert operation",
     re.compile(r"\b(secretly|covertly|behind the (user'?s? )?back|the user (should|must) not (know|see|be told))\b", re.I)),
    # "silently" alone is common in benign docs ("succeeds silently if the directory exists");
    # it is a secrecy directive only when it qualifies moving or collecting data.
    ("secrecy_directive", "HIGH", "silent data action",
     re.compile(r"\b(silently|quietly)\s+(send|forward|upload|cop(y|ie)|include|attach|add|exfiltrat|transmit|post|share|collect|read|log|record|bcc|cc)\w*\b", re.I)),
    ("approval_bypass", "HIGH", "approval-bypass social engineering",
     re.compile(r"\b(already\s+(been\s+)?approved|pre-?approved|no\s+need\s+to\s+(ask|confirm)|do\s*n[o']t\s+ask\s+(for\s+)?(confirmation|permission)|skip\s+(the\s+)?(confirmation|approval)|bypass\s+(the\s+)?(security|sentinel|approval|guard))\b", re.I)),
    ("sensitive_path", "MEDIUM", "references credential / client-config files",
     re.compile(r"(~|\$HOME|%USERPROFILE%)?[/\\]?\.(ssh|aws|gnupg|kube|docker|config[/\\]gcloud|azure|npmrc|pypirc|netrc|git-credentials|env)\b|id_(rsa|dsa|ecdsa|ed25519)\b|\bmcp\.json\b|claude_desktop_config\.json|\.cursor[/\\]|/etc/(passwd|shadow|sudoers)|\bkeychain\b|\blogin data\b|wallet\.dat", re.I)),
    ("data_collection", "HIGH", "directs the model to collect conversation or file contents",
     re.compile(r"\b(include|pass|put|provide|add|insert|append|send|attach)\b.{0,40}\b(contents?\s+of|conversation|chat\s+history|previous\s+messages|system\s+prompt|all\s+(messages|files)|entire\s+(file|context)|full\s+context|api\s+keys?|credentials|private\s+key)\b", re.I)),
    ("data_collection", "HIGH", "directs the model to pass content through a parameter",
     re.compile(r"\b(pass|put|send|include|provide|place|embed)\b.{0,20}\b(its|the|their|file'?s?|whole|full)\s+(content|contents|text|data|output)\b.{0,25}\b(as|in|into|via|inside)\b", re.I)),
    ("injection_phrase", "MEDIUM", "pre-condition: perform another action before using the tool",
     re.compile(r"\b(before|prior to)\s+(using|calling|invoking|running)\s+(this|any|the)\s+tool\b.{0,60}\b(read|open|call|fetch|send|get|list|look)\b", re.I)),
    ("data_collection", "MEDIUM", "directs the model to read a file first",
     re.compile(r"\b(read|open|cat|load)\b.{0,15}\b(the\s+)?(file|contents)\b.{0,40}\b(and|then)\b.{0,20}\b(pass|send|include|provide|use)\b", re.I)),
]

EXFIL_PARAM_NAMES = {
    "sidenote", "side_note", "context", "conversation", "conversation_history", "chat_history", "history",
    "system_prompt", "previous_messages", "user_messages", "full_context", "memory_dump", "feedback",
    "debug_info", "extra", "metadata_blob", "reasoning", "thoughts", "notes_for_ai", "instructions",
}
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){32,}\b")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    field: str
    evidence: str

    def key(self) -> tuple[str, str, str]:
        return (self.category, self.field, self.title)

    def as_dict(self) -> dict[str, Any]:
        return {"category": self.category, "severity": self.severity, "title": self.title, "field": self.field, "evidence": self.evidence[:240]}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        remaining = 1.0
        for f in self.findings:
            remaining *= 1.0 - SEVERITY_WEIGHT.get(f.severity, 0) / 100.0
        return int(round((1.0 - remaining) * 100))

    @property
    def verdict(self) -> str:
        if any(f.severity == "CRITICAL" for f in self.findings) or any(
            f.severity == "HIGH" and f.category in POISONING_CATEGORIES for f in self.findings
        ):
            return "MALICIOUS"
        if self.score >= 10:
            return "SUSPICIOUS"
        return "CLEAN"

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "score": self.score, "findings": [f.as_dict() for f in self.findings]}


def _snippet(text: str, start: int, end: int, pad: int = 50) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return ("…" if s else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


def _strings_of(tool: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if tool.get("description"):
        out.append(("description", str(tool["description"])))
    if tool.get("title"):
        out.append(("title", str(tool["title"])))
    ann = tool.get("annotations") or {}
    if isinstance(ann, dict) and ann.get("title"):
        out.append(("annotations.title", str(ann["title"])))

    def walk_schema(schema: Any, path: str, depth: int = 0) -> None:
        if depth > 8 or not isinstance(schema, dict):
            return
        for key in ("description", "title", "default", "examples", "enum", "const", "$comment"):
            if key in schema and schema[key] not in (None, ""):
                value = schema[key]
                text = " | ".join(map(str, value)) if isinstance(value, list) else str(value)
                out.append((f"{path}.{key}" if path else key, text))
        props = schema.get("properties")
        if isinstance(props, dict):
            for name, sub in props.items():
                walk_schema(sub, f"param:{name}", depth + 1)
        for key in ("items", "additionalProperties"):
            if isinstance(schema.get(key), dict):
                walk_schema(schema[key], f"{path}.{key}" if path else key, depth + 1)
        for key in ("anyOf", "oneOf", "allOf"):
            for i, sub in enumerate(schema.get(key) or []):
                walk_schema(sub, f"{path}.{key}[{i}]" if path else f"{key}[{i}]", depth + 1)

    walk_schema(tool.get("inputSchema") or tool.get("schema") or {}, "inputSchema")
    return out


def _decoded_payload(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)
    return raw.decode("ascii", errors="replace") if printable > 0.9 else None


def scan_text(text: str, field_name: str, *, other_tool_names: Iterable[str] = (), own_name: str = "") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings
    smuggling = detect_smuggling(text)
    if smuggling.tag_chars:
        findings.append(Finding("smuggling", "CRITICAL", "Unicode tag characters (ASCII smuggling)", field_name,
                                f"hidden text: {smuggling.decoded_hidden_text[:160]!r}"))
    if smuggling.invisible >= 3:
        findings.append(Finding("smuggling", "HIGH", "invisible / bidi control characters", field_name,
                                f"{smuggling.invisible} invisible characters"))
    if smuggling.ansi_sequences:
        findings.append(Finding("smuggling", "HIGH", "ANSI terminal escape sequences (terminal deception)", field_name,
                                f"{smuggling.ansi_sequences} escape sequences"))
    if smuggling.variation_selectors >= 8:
        findings.append(Finding("smuggling", "HIGH", "variation-selector run (emoji smuggling)", field_name,
                                f"{smuggling.variation_selectors} selectors"))
    seen: set[tuple[str, str]] = set()
    for category, severity, title, pattern in PATTERNS:
        m = pattern.search(text)
        if m and (category, title) not in seen:
            seen.add((category, title))
            findings.append(Finding(category, severity, title, field_name, _snippet(text, *m.span())))
    for m in BASE64_RE.finditer(text):
        decoded = _decoded_payload(m.group(0))
        if decoded:
            findings.append(Finding("encoded_payload", "HIGH", "base64-encoded text payload", field_name,
                                    f"decodes to: {decoded[:120]!r}"))
            # decoded payloads get the same treatment (one level deep)
            for sub in scan_text(decoded, field_name + "(decoded)", other_tool_names=other_tool_names, own_name=own_name):
                if sub.category != "encoded_payload":
                    findings.append(sub)
            break
    if HEX_RE.search(text):
        findings.append(Finding("encoded_payload", "LOW", "long hex blob", field_name, "hex-encoded data"))
    urls = URL_IN_TEXT_RE.findall(text)
    if urls and field_name in {"description", "title"}:
        sev = "MEDIUM" if re.search(r"\b(send|sent|post|upload|forward|report|mirror(ed)?|cop(y|ied)|sync(ed)?|share[ds]?|exfil\w*)\b", text, re.I) else "LOW"
        findings.append(Finding("embedded_url", sev, "URL embedded in tool metadata", field_name, ", ".join(urls[:3])))
    lowered = text.lower()
    for other in other_tool_names:
        if not other or other == own_name or len(other) < 4:
            continue
        name = re.escape(other.lower())
        if re.search(r"[_.\-]|[a-z][A-Z]", other):  # identifier-like names: a plain mention is a reference
            pattern = rf"(?<![A-Za-z0-9_]){name}(?![A-Za-z0-9_])"
        else:  # plain words ("fetch", "search") only count when explicitly referenced as a tool
            pattern = rf"[`'\"]{name}[`'\"]|\b{name}\s+tool\b|\btool\s+(named|called)\s+[`'\"]?{name}\b"
        if re.search(pattern, lowered):
            imperative = re.search(r"\b(when|whenever|always|instead|also|must|before|after)\b", lowered)
            findings.append(Finding(
                "shadowing", "HIGH" if imperative else "MEDIUM",
                "references another server's tool (cross-server shadowing)", field_name,
                f"mentions '{other}'" + (" with behavioural directive" if imperative else ""),
            ))
            break
    return findings


def scan_tool(tool: dict[str, Any], *, other_tool_names: Iterable[str] = (), annotation_conflicts: Iterable[str] = ()) -> ScanResult:
    others = list(other_tool_names)
    own = str(tool.get("name") or "")
    result = ScanResult()
    for field_name, text in _strings_of(tool):
        result.findings.extend(scan_text(text, field_name, other_tool_names=others, own_name=own))
    desc = str(tool.get("description") or "")
    if len(desc) > 6000:
        result.findings.append(Finding("excessive_length", "MEDIUM", "very long description can hide instructions", "description", f"{len(desc)} characters"))
    elif len(desc) > 2500:
        result.findings.append(Finding("excessive_length", "LOW", "long description", "description", f"{len(desc)} characters"))
    props = ((tool.get("inputSchema") or tool.get("schema") or {}).get("properties") or {})
    if isinstance(props, dict):
        for name in props:
            if str(name).lower() in EXFIL_PARAM_NAMES:
                result.findings.append(Finding(
                    "exfil_parameter", "MEDIUM", "parameter name suggests a conversation/context exfiltration channel",
                    f"param:{name}", f"parameter '{name}'",
                ))
    for conflict in annotation_conflicts:
        result.findings.append(Finding("annotation_conflict", "MEDIUM", "annotations contradict tool semantics", "annotations", conflict))
    # Mentioning ~/.aws is fine for an AWS tool; *telling the model to read/pass it* is credential theft.
    by_field: dict[str, set[str]] = {}
    for f in result.findings:
        by_field.setdefault(f.field.replace("(decoded)", ""), set()).add(f.category)
    for fld, cats in by_field.items():
        if "sensitive_path" in cats and cats & {"data_collection", "secrecy_directive", "hidden_instructions", "injection_phrase"}:
            result.findings.append(Finding(
                "credential_exfiltration", "CRITICAL", "instructs the model to read and hand over credential files", fld,
                "sensitive path combined with " + ", ".join(sorted(cats & {"data_collection", "secrecy_directive", "hidden_instructions", "injection_phrase"})),
            ))
    return result


def scan_server_instructions(instructions: str) -> ScanResult:
    """Server ``instructions`` are injected into the model context by some clients."""
    return ScanResult(findings=scan_text(instructions or "", "server.instructions"))
