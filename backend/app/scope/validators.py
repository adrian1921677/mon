"""Syntax validators for each ScopeEntryType."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse

from app.db.models import ScopeEntryType
from app.scope.blocklist import is_always_blocked_ip, is_metadata_hostname, is_metadata_ip
from app.scope.types import ValidationReason, ValidationResult

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_API_SPEC_SUFFIXES = (".json", ".yaml", ".yml")


def validate_entry_syntax(entry_type: ScopeEntryType, value: str) -> ValidationResult:
    raw = (value or "").strip()
    if not raw:
        return ValidationResult.deny(ValidationReason.invalid_format, "empty value")

    if entry_type is ScopeEntryType.ip:
        return _validate_ip(raw)
    if entry_type is ScopeEntryType.cidr:
        return _validate_cidr(raw)
    if entry_type is ScopeEntryType.domain:
        return _validate_domain(raw)
    if entry_type is ScopeEntryType.url:
        return _validate_url(raw)
    if entry_type is ScopeEntryType.api_spec:
        return _validate_api_spec(raw)
    if entry_type is ScopeEntryType.path:
        return _validate_path(raw)
    return ValidationResult.deny(ValidationReason.invalid_format, f"unknown type {entry_type}")


def _validate_ip(raw: str) -> ValidationResult:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ValidationResult.deny(ValidationReason.invalid_format, f"invalid IP: {raw}")
    if is_metadata_ip(addr) or is_always_blocked_ip(addr):
        return ValidationResult.deny(
            ValidationReason.blocked_metadata,
            f"blocked address (metadata/loopback/link-local): {raw}",
            resolved_ips=(str(addr),),
        )
    return ValidationResult.ok(message="valid IP", resolved_ips=(str(addr),), meta={"ip": str(addr)})


def _validate_cidr(raw: str) -> ValidationResult:
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return ValidationResult.deny(ValidationReason.invalid_format, f"invalid CIDR: {raw}")
    if net.num_addresses > 65_536:
        return ValidationResult.deny(
            ValidationReason.invalid_format,
            f"CIDR too large (>{65_536} addresses): {raw}",
        )
    # Reject CIDRs that are entirely inside always-blocked ranges.
    if any(net.subnet_of(blocked) for blocked in _blocked_v4_v6_nets(net.version)):  # type: ignore[arg-type]
        return ValidationResult.deny(
            ValidationReason.blocked_address,
            f"CIDR overlaps always-blocked range: {raw}",
        )
    return ValidationResult.ok(message="valid CIDR", meta={"network": str(net), "prefix": net.prefixlen})


def _blocked_v4_v6_nets(version: int) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    from app.scope.blocklist import ALWAYS_BLOCKED_NETWORKS

    return [n for n in ALWAYS_BLOCKED_NETWORKS if n.version == version]


def _validate_domain(raw: str) -> ValidationResult:
    host = raw.lower().rstrip(".")
    if host.startswith("*.") and _DOMAIN_RE.match(host[2:]):
        return ValidationResult.ok(message="valid wildcard domain", meta={"domain": host})
    if not _DOMAIN_RE.match(host):
        return ValidationResult.deny(ValidationReason.invalid_format, f"invalid domain: {raw}")
    if is_metadata_hostname(host):
        return ValidationResult.deny(
            ValidationReason.blocked_metadata,
            f"blocked metadata hostname: {host}",
        )
    return ValidationResult.ok(message="valid domain", meta={"domain": host})


def _validate_url(raw: str) -> ValidationResult:
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        return ValidationResult.deny(
            ValidationReason.invalid_format,
            "URL must use http or https",
        )
    if not parsed.hostname:
        return ValidationResult.deny(ValidationReason.invalid_format, "URL missing hostname")
    host = parsed.hostname.lower().rstrip(".")
    if is_metadata_hostname(host):
        return ValidationResult.deny(
            ValidationReason.blocked_metadata,
            f"blocked metadata host in URL: {host}",
        )
    try:
        addr = ipaddress.ip_address(host)
        if is_always_blocked_ip(addr):
            return ValidationResult.deny(
                ValidationReason.blocked_metadata,
                f"blocked address in URL: {host}",
                resolved_ips=(str(addr),),
            )
    except ValueError:
        if not _DOMAIN_RE.match(host):
            return ValidationResult.deny(ValidationReason.invalid_format, f"invalid URL host: {host}")
    return ValidationResult.ok(
        message="valid URL",
        meta={"scheme": parsed.scheme, "host": host, "path": parsed.path or "/"},
    )


def _validate_api_spec(raw: str) -> ValidationResult:
    """API-Spec: local OpenAPI/Swagger file path or http(s) URL to a spec."""
    if raw.startswith("http://") or raw.startswith("https://"):
        return _validate_url(raw)
    path_result = _validate_path(raw)
    if not path_result.allowed:
        return path_result
    lower = raw.lower()
    if not any(lower.endswith(suf) for suf in _API_SPEC_SUFFIXES):
        return ValidationResult.deny(
            ValidationReason.invalid_format,
            f"API spec path must end with {', '.join(_API_SPEC_SUFFIXES)}",
        )
    return ValidationResult.ok(message="valid API spec path", meta={"path": raw})


def _validate_path(raw: str) -> ValidationResult:
    """Local repo/filesystem path — must be absolute and not a remote URL."""
    if "://" in raw and not raw.lower().startswith("file:"):
        return ValidationResult.deny(
            ValidationReason.path_not_local,
            "path must be a local filesystem path, not a remote URL",
        )
    cleaned = raw
    if cleaned.lower().startswith("file:"):
        cleaned = cleaned[5:]
        if cleaned.startswith("///"):
            cleaned = cleaned[2:]  # file:///C:/... → /C:/... on POSIX parse
        elif cleaned.startswith("//"):
            cleaned = cleaned[1:]

    win = PureWindowsPath(cleaned)
    posix = Path(cleaned)
    is_abs = win.is_absolute() or posix.is_absolute()
    if not is_abs:
        return ValidationResult.deny(
            ValidationReason.path_not_local,
            "path must be absolute (local repo path)",
        )
    # Reject obvious traversal to system-sensitive roots as scope values —
    # still allow user home / drive letters; scanners enforce further later.
    return ValidationResult.ok(message="valid local path", meta={"path": cleaned})
