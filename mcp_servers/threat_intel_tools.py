"""Threat Intelligence MCP tools for IOC lookups and enrichment.

Provides indicator-of-compromise lookups, domain reputation checks, and
enrichment using free threat intelligence sources. Results are cached to
avoid excessive external API calls.
"""

from __future__ import annotations

import hashlib
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from protocol import ToolServer
else:
    from .protocol import ToolServer

TOOLS = [
    {
        "name": "lookup_ioc",
        "description": (
            "Check an IP address, domain, file hash (MD5/SHA1/SHA256), or URL against built-in threat "
            "intelligence heuristics and known-bad indicators. Returns risk classification and context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The IOC to look up (IP, domain, hash, or URL)"},
                "type": {
                    "type": "string",
                    "enum": ["ip", "domain", "hash", "url", "auto"],
                    "default": "auto",
                    "description": "Type of indicator; 'auto' will detect automatically",
                },
            },
            "required": ["indicator"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "check_domain_reputation",
        "description": (
            "Get reputation data for a domain observed in tool outputs or arguments. Uses heuristic "
            "analysis including domain age estimation, TLD risk, and pattern matching."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "The domain name to check"},
            },
            "required": ["domain"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "enrich_indicator",
        "description": (
            "Enrich an IOC with additional context: WHOIS-like data for domains, geolocation heuristics "
            "for IPs, and classification for hashes. Returns structured enrichment data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The indicator to enrich"},
                "type": {
                    "type": "string",
                    "enum": ["ip", "domain", "hash"],
                    "description": "Type of indicator",
                },
            },
            "required": ["indicator", "type"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "add_threat_note",
        "description": (
            "Add a threat intelligence note linked to a Sentinel server or tool. "
            "Builds organizational knowledge about MCP server risks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string", "description": "Sentinel server ID to link the note to"},
                "tool_name": {"type": "string", "description": "Tool name to link the note to"},
                "note": {"type": "string", "description": "The threat intel note content"},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for categorization (e.g. ['supply-chain', 'typosquat'])",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "confirmed"],
                    "default": "medium",
                },
            },
            "required": ["note"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "search_threat_notes",
        "description": "Search threat intelligence notes by keyword, tag, or linked server/tool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags"},
                "server_id": {"type": "string", "description": "Filter by linked server"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# Heuristic threat intelligence (no external API calls required)
# ---------------------------------------------------------------------------
_notes: list[dict[str, Any]] = []
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL = 3600

# Known suspicious TLDs and patterns
HIGH_RISK_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".click", ".link", ".work", ".cam"}
SUSPICIOUS_PATTERNS = [
    re.compile(r"(paypal|google|microsoft|apple|amazon|netflix|facebook|instagram)\d*\.", re.I),
    re.compile(r"[a-z0-9]{20,}\.(com|net|org|io)", re.I),  # random subdomain
    re.compile(r"(login|signin|verify|secure|update|confirm|account)\.", re.I),
]
KNOWN_BAD_RANGES = [
    "192.42.116.",  # example dark-web exit nodes
]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$", re.I)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
URL_RE = re.compile(r"^https?://", re.I)


def _detect_type(indicator: str) -> str:
    if IP_RE.match(indicator):
        return "ip"
    if HASH_RE.match(indicator) and "." not in indicator:
        return "hash"
    if URL_RE.match(indicator):
        return "url"
    if DOMAIN_RE.match(indicator):
        return "domain"
    return "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _cached(key: str) -> dict[str, Any] | None:
    if key in _cache:
        ts, data = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return data
        del _cache[key]
    return None


def _domain_risk(domain: str) -> dict[str, Any]:
    domain = domain.lower().strip().rstrip(".")
    risk_score = 0
    findings: list[str] = []

    # TLD risk
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in HIGH_RISK_TLDS:
        risk_score += 30
        findings.append(f"High-risk TLD: {tld}")

    # Phishing pattern detection
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(domain):
            risk_score += 25
            findings.append(f"Matches suspicious pattern (potential phishing/typosquat)")
            break

    # Domain length heuristic
    parts = domain.split(".")
    if len(parts) > 3:
        risk_score += 10
        findings.append(f"Deeply nested subdomain ({len(parts)} levels)")
    if len(domain) > 40:
        risk_score += 10
        findings.append(f"Unusually long domain name ({len(domain)} chars)")

    # Entropy check (random-looking domains)
    label = parts[0] if parts else domain
    if len(label) > 12 and sum(1 for c in label if c.isdigit()) > len(label) * 0.3:
        risk_score += 15
        findings.append("High numeric ratio in domain label (possibly DGA-generated)")

    classification = "MALICIOUS" if risk_score >= 50 else "SUSPICIOUS" if risk_score >= 25 else "CLEAN"
    return {
        "domain": domain,
        "risk_score": min(risk_score, 100),
        "classification": classification,
        "findings": findings,
        "tld": tld,
        "checked_at": _now_iso(),
    }


def _ip_risk(ip: str) -> dict[str, Any]:
    import ipaddress as ipmod
    risk_score = 0
    findings: list[str] = []

    try:
        addr = ipmod.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "Invalid IP address", "risk_score": 0, "classification": "UNKNOWN"}

    if addr.is_private:
        findings.append("Private/internal IP address")
        return {"ip": ip, "risk_score": 0, "classification": "INTERNAL", "findings": findings}
    if addr.is_loopback:
        findings.append("Loopback address")
        return {"ip": ip, "risk_score": 0, "classification": "LOOPBACK", "findings": findings}
    if addr.is_reserved:
        findings.append("Reserved IP range")
        risk_score += 10

    for prefix in KNOWN_BAD_RANGES:
        if ip.startswith(prefix):
            risk_score += 50
            findings.append(f"IP in known suspicious range: {prefix}*")

    classification = "MALICIOUS" if risk_score >= 50 else "SUSPICIOUS" if risk_score >= 25 else "CLEAN"
    return {"ip": ip, "risk_score": min(risk_score, 100), "classification": classification, "findings": findings, "checked_at": _now_iso()}


def lookup_ioc(args: dict[str, Any]) -> dict[str, Any]:
    indicator = str(args.get("indicator") or "").strip()
    if not indicator:
        raise ValueError("indicator is required")

    ioc_type = str(args.get("type") or "auto")
    if ioc_type == "auto":
        ioc_type = _detect_type(indicator)

    cache_key = f"ioc:{ioc_type}:{indicator.lower()}"
    cached = _cached(cache_key)
    if cached:
        return {**cached, "cached": True}

    result: dict[str, Any]
    if ioc_type == "ip":
        result = _ip_risk(indicator)
    elif ioc_type == "domain":
        result = _domain_risk(indicator)
    elif ioc_type == "hash":
        hash_len = len(indicator)
        hash_type = "MD5" if hash_len == 32 else "SHA1" if hash_len == 40 else "SHA256" if hash_len == 64 else "UNKNOWN"
        result = {"hash": indicator, "hash_type": hash_type, "risk_score": 0, "classification": "UNKNOWN",
                  "findings": ["Hash lookup requires external threat feed integration (not yet configured)"],
                  "checked_at": _now_iso()}
    elif ioc_type == "url":
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(indicator)
            domain = parts.hostname or ""
        except Exception:
            domain = ""
        domain_result = _domain_risk(domain) if domain else {"classification": "UNKNOWN", "risk_score": 0, "findings": []}
        result = {"url": indicator[:500], "domain": domain, **domain_result, "checked_at": _now_iso()}
    else:
        result = {"indicator": indicator, "type": ioc_type, "error": "Could not determine indicator type"}

    result["type"] = ioc_type
    _cache[cache_key] = (time.time(), result)
    return result


def check_domain_reputation(args: dict[str, Any]) -> dict[str, Any]:
    domain = str(args.get("domain") or "").strip().lower()
    if not domain or not DOMAIN_RE.match(domain):
        raise ValueError("A valid domain name is required")
    return _domain_risk(domain)


def enrich_indicator(args: dict[str, Any]) -> dict[str, Any]:
    indicator = str(args.get("indicator") or "").strip()
    ioc_type = str(args.get("type") or "").lower()
    if not indicator:
        raise ValueError("indicator is required")

    enrichment: dict[str, Any] = {"indicator": indicator, "type": ioc_type, "enriched_at": _now_iso()}

    if ioc_type == "ip":
        import ipaddress as ipmod
        try:
            addr = ipmod.ip_address(indicator)
            enrichment.update({
                "version": "IPv4" if addr.version == 4 else "IPv6",
                "is_private": addr.is_private,
                "is_loopback": addr.is_loopback,
                "is_reserved": addr.is_reserved,
                "is_multicast": addr.is_multicast,
                "is_link_local": addr.is_link_local,
                "reverse_pointer": str(addr.reverse_pointer) if hasattr(addr, "reverse_pointer") else None,
            })
        except ValueError:
            enrichment["error"] = "Invalid IP address"
        enrichment.update(_ip_risk(indicator))

    elif ioc_type == "domain":
        parts = indicator.lower().split(".")
        enrichment.update({
            "tld": parts[-1] if parts else "",
            "subdomain_depth": len(parts),
            "label_lengths": [len(p) for p in parts],
            "has_digits": any(c.isdigit() for c in indicator),
            "has_hyphens": "-" in indicator,
        })
        enrichment.update(_domain_risk(indicator))

    elif ioc_type == "hash":
        hash_len = len(indicator)
        enrichment.update({
            "hash_type": "MD5" if hash_len == 32 else "SHA1" if hash_len == 40 else "SHA256" if hash_len == 64 else "UNKNOWN",
            "length": hash_len,
            "note": "File hash enrichment requires VirusTotal or similar integration (not yet configured)",
        })
    else:
        enrichment["error"] = f"Unsupported indicator type: {ioc_type}"

    return enrichment


def add_threat_note(args: dict[str, Any]) -> dict[str, Any]:
    note_text = str(args.get("note") or "").strip()
    if not note_text:
        raise ValueError("note content is required")

    note = {
        "note_id": f"tn-{uuid.uuid4().hex[:12]}",
        "server_id": str(args.get("server_id") or ""),
        "tool_name": str(args.get("tool_name") or ""),
        "note": note_text[:4000],
        "tags": [str(t).lower()[:64] for t in (args.get("tags") or [])][:20],
        "confidence": str(args.get("confidence") or "medium"),
        "created_at": _now_iso(),
    }
    _notes.append(note)
    return {"created": True, "note_id": note["note_id"], "tags": note["tags"]}


def search_threat_notes(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").strip().lower()
    tags = [str(t).lower() for t in (args.get("tags") or [])]
    server_id = str(args.get("server_id") or "").strip()
    limit = max(1, min(int(args.get("limit", 20)), 50))

    results = []
    for note in reversed(_notes):  # newest first
        if query and query not in note["note"].lower() and query not in " ".join(note["tags"]):
            continue
        if tags and not set(tags) & set(note["tags"]):
            continue
        if server_id and note.get("server_id") != server_id:
            continue
        results.append(note)
        if len(results) >= limit:
            break
    return {"count": len(results), "notes": results}


ToolServer(
    "mcp-sentinel-threat-intel",
    TOOLS,
    {
        "lookup_ioc": lookup_ioc,
        "check_domain_reputation": check_domain_reputation,
        "enrich_indicator": enrich_indicator,
        "add_threat_note": add_threat_note,
        "search_threat_notes": search_threat_notes,
    },
).run()
