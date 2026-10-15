"""URL / host classification shared by input validation, policy and the data-flow guard.

The previous implementation used substring checks (``"internal" in dest``), which let
``https://evil.com/?q=internal`` or ``internal.attacker.com`` pass as internal. Everything here
parses the host properly, follows WHATWG backslash semantics and understands the
legacy IPv4 notations (``2130706433``, ``0x7f.1``, ``0177.0.0.1``) used in SSRF bypasses.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

URL_RE = re.compile(
    r"(?i)\b((?:https?|wss?|ftp|ftps|sftp|tftp|file|gopher|dict|ldap|ldaps|smb|jar|netdoc|data)://[^\s\"'<>`]+)"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\b")
HOSTLIKE_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?(?::\d{1,5})?$", re.I)

DESTINATION_KEYS = {
    "url", "uri", "href", "link", "endpoint", "destination", "dest", "target", "host", "hostname", "domain",
    "webhook", "webhook_url", "callback", "callback_url", "server", "to", "recipient", "recipients",
    "email", "address", "remote", "upload_url", "base_url",
}

METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}

DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ldap", "ldaps", "jar", "netdoc", "tftp", "smb", "data"}


class HostClass(str, Enum):
    METADATA = "METADATA"
    LOOPBACK = "LOOPBACK"
    PRIVATE = "PRIVATE"
    LINK_LOCAL = "LINK_LOCAL"
    RESERVED = "RESERVED"
    INTERNAL_NAME = "INTERNAL_NAME"
    PUBLIC = "PUBLIC"
    UNKNOWN = "UNKNOWN"


@dataclass
class Destination:
    raw: str
    scheme: str
    host: str
    host_class: HostClass

    @property
    def is_external(self) -> bool:
        return self.host_class == HostClass.PUBLIC

    def as_dict(self) -> dict[str, str]:
        return {"raw": self.raw[:300], "scheme": self.scheme, "host": self.host, "class": self.host_class.value}


def _parse_legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """inet_aton semantics: 1-4 parts, each decimal / 0x-hex / 0-octal."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    nums: list[int] = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    limits = {1: [2**32], 2: [256, 2**24], 3: [256, 256, 2**16], 4: [256, 256, 256, 256]}[len(nums)]
    if any(n < 0 or n >= lim for n, lim in zip(nums, limits)):
        return None
    value = 0
    for n in nums[:-1]:
        value = (value << 8) | n
    shift = 8 * (4 - len(nums) + 1)
    value = (value << shift) | nums[-1] if len(nums) < 4 else (value << 8) | nums[-1]
    try:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    except ValueError:
        return None


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    h = host.strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = _parse_legacy_ipv4(h) if re.fullmatch(r"[0-9a-fA-Fx.]+", h) else None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def domain_matches(host: str, suffix: str) -> bool:
    host = host.lower().rstrip(".")
    suffix = suffix.lower().lstrip(".").rstrip(".")
    return bool(suffix) and (host == suffix or host.endswith("." + suffix))


def classify_host(host: str, internal_domains: Iterable[str] = ()) -> HostClass:
    if not host:
        return HostClass.UNKNOWN
    h = host.lower().strip().rstrip(".")
    if h in METADATA_HOSTS:
        return HostClass.METADATA
    ip = parse_ip(h)
    if ip is not None:
        if str(ip) in METADATA_HOSTS:
            return HostClass.METADATA
        if ip.is_loopback or ip.is_unspecified:
            return HostClass.LOOPBACK
        if ip.is_link_local:
            return HostClass.LINK_LOCAL
        if ip.is_private:
            return HostClass.PRIVATE
        if ip.is_reserved or ip.is_multicast:
            return HostClass.RESERVED
        return HostClass.PUBLIC
    if h == "localhost" or h.endswith(".localhost"):
        return HostClass.LOOPBACK
    if "." not in h:
        return HostClass.INTERNAL_NAME  # single-label names only resolve on the local network
    if any(domain_matches(h, d) for d in internal_domains):
        return HostClass.INTERNAL_NAME
    return HostClass.PUBLIC


def parse_destination(raw: str, internal_domains: Iterable[str] = ()) -> Destination | None:
    value = (raw or "").strip()
    if not value:
        return None
    email = EMAIL_RE.fullmatch(value)
    if email:
        host = email.group(1).lower()
        return Destination(value, "mailto", host, classify_host(host, internal_domains))
    if value.lower().startswith("mailto:"):
        m = EMAIL_RE.search(value)
        if m:
            host = m.group(1).lower()
            return Destination(value, "mailto", host, classify_host(host, internal_domains))
    if "://" not in value:
        bare_localhost = re.fullmatch(r"(?i)localhost(?::\d{1,5})?", value) is not None
        if not bare_localhost and not HOSTLIKE_RE.match(value) and parse_ip(value.split(":")[0]) is None:
            return None
        value_for_parse = "https://" + value
    else:
        value_for_parse = value
    # WHATWG URL parsers treat "\" like "/" for special schemes: http://evil.com\@good.com -> evil.com
    value_for_parse = value_for_parse.replace("\\", "/")
    try:
        parts = urlsplit(value_for_parse)
        host = parts.hostname or ""
    except ValueError:
        return None
    host = unquote(host).lower()
    scheme = (parts.scheme or "").lower()
    return Destination(raw, scheme, host, classify_host(host, internal_domains))


def _walk_strings(value: Any, key: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    if depth > 12:
        return
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_strings(v, str(k), depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item, key, depth + 1)


def walk_strings(value: Any) -> list[tuple[str, str]]:
    return list(_walk_strings(value))


def extract_destinations(arguments: Any, internal_domains: Iterable[str] = (), extra: Iterable[str] = ()) -> list[Destination]:
    """Every network destination referenced anywhere in tool arguments (URLs, emails, host fields)."""
    internal_domains = list(internal_domains)
    found: dict[str, Destination] = {}
    candidates: list[str] = [e for e in extra if e]
    for key, text in walk_strings(arguments):
        candidates.extend(m.group(1).rstrip(").,;]") for m in URL_RE.finditer(text))
        candidates.extend(m.group(0) for m in EMAIL_RE.finditer(text))
        if key.lower() in DESTINATION_KEYS and text.strip() and len(text) < 2048:
            candidates.append(text.strip())
    for raw in candidates:
        dest = parse_destination(raw, internal_domains)
        if dest and (dest.host or dest.scheme in DANGEROUS_SCHEMES) and dest.raw not in found:
            found[dest.raw] = dest
    return list(found.values())


def is_allowed_egress(host: str, allowed_domains: Iterable[str]) -> bool:
    return any(domain_matches(host, d) for d in allowed_domains)
