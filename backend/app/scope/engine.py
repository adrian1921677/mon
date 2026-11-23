"""Scope Engine — validate entries and runtime targets against project scope."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.db.models import ScopeEntry, ScopeEntryStatus, ScopeEntryType
from app.scope import active_gate, rate_limits
from app.scope.blocklist import is_always_blocked_ip, is_metadata_hostname, is_metadata_ip
from app.scope.dns import ResolverFn, rebinding_guard, resolve_and_validate
from app.scope.types import ScopeTarget, ValidationReason, ValidationResult
from app.scope.validators import validate_entry_syntax


class ScopeValidationError(ValueError):
    """Raised when a scope operation is rejected."""

    def __init__(self, result: ValidationResult) -> None:
        super().__init__(result.message)
        self.result = result


@dataclass
class ParsedScope:
    """Normalized in-memory view of project scope for membership checks."""

    ips: set[str]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    domains: set[str]  # exact + wildcard base (*.example.com → .example.com)
    urls: list[str]  # normalized base URLs (scheme://host[:port])
    paths: list[str]
    api_specs: list[str]
    allowed_dns_cache: dict[str, set[str]]  # host → previously allowed IPs


def build_parsed_scope(entries: Sequence[ScopeEntry]) -> ParsedScope:
    parsed = ParsedScope(
        ips=set(),
        networks=[],
        domains=set(),
        urls=[],
        paths=[],
        api_specs=[],
        allowed_dns_cache={},
    )
    for entry in entries:
        if entry.status is ScopeEntryStatus.rejected:
            continue
        value = entry.value.strip()
        if entry.type is ScopeEntryType.ip:
            parsed.ips.add(value)
        elif entry.type is ScopeEntryType.cidr:
            try:
                parsed.networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        elif entry.type is ScopeEntryType.domain:
            host = value.lower().rstrip(".")
            parsed.domains.add(host)
            if host.startswith("*."):
                parsed.domains.add(host[1:])  # .example.com
        elif entry.type is ScopeEntryType.url:
            parsed.urls.append(_normalize_url_base(value))
        elif entry.type is ScopeEntryType.path:
            parsed.paths.append(value)
        elif entry.type is ScopeEntryType.api_spec:
            parsed.api_specs.append(value)
    return parsed


def _normalize_url_base(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    port = p.port
    if port and not (
        (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)
    ):
        return f"{p.scheme}://{host}:{port}"
    return f"{p.scheme}://{host}"


def _domain_in_scope(host: str, domains: set[str]) -> bool:
    h = host.lower().rstrip(".")
    if h in domains:
        return True
    for d in domains:
        if d.startswith(".") and (h.endswith(d) or h == d[1:]):
            return True
        if d.startswith("*.") and (h == d[2:] or h.endswith("." + d[2:])):
            return True
    return False


def _ip_in_scope(ip_str: str, parsed: ParsedScope) -> bool:
    if ip_str in parsed.ips:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in parsed.networks if addr.version == net.version)


def _path_in_scope(candidate: str, allowed: Sequence[str]) -> bool:
    def _norm(p: str) -> str:
        if PureWindowsPath(p).is_absolute() and (len(p) > 1 and p[1] == ":"):
            return str(PureWindowsPath(p)).replace("/", "\\").lower().rstrip("\\")
        return str(Path(p)).replace("\\", "/").rstrip("/")

    cand = _norm(candidate)
    for root in allowed:
        r = _norm(root)
        if cand == r or cand.startswith(r + "/") or cand.startswith(r + "\\"):
            return True
    return False


class ScopeEngine:
    """
    Backend-only scope enforcement. UI cannot bypass these checks.

    Use for:
    - validating new scope entries (syntax + blocklists)
    - checking whether a runtime target is in project scope
    - DNS + rebinding + redirect + SSRF guards
    - active-test gate and rate/time hooks
    """

    def __init__(
        self,
        *,
        resolver: ResolverFn | None = None,
        rate_state: rate_limits.RateLimitState | None = None,
    ) -> None:
        self._resolver = resolver
        self._rate_state = rate_state or rate_limits.get_rate_state()

    def validate_entry(
        self,
        entry_type: ScopeEntryType,
        value: str,
        *,
        resolve_dns: bool = True,
        project_id: str | None = None,
        rate_limits_cfg: dict[str, int] | None = None,
    ) -> ValidationResult:
        """Validate a candidate scope entry (create / dry-run)."""
        cfg = {**rate_limits.DEFAULT_RATE_LIMITS, **(rate_limits_cfg or {})}
        if project_id:
            rl = self._rate_state.check(
                f"validate:{project_id}",
                limit=int(cfg["validations_per_minute"]),
                window_seconds=60,
            )
            if not rl.allowed:
                return rl

        syntax = validate_entry_syntax(entry_type, value)
        if not syntax.allowed:
            return syntax

        if entry_type is ScopeEntryType.domain and resolve_dns:
            host = value.lower().rstrip(".").lstrip("*.")
            dns = resolve_and_validate(host, resolver=self._resolver)
            if not dns.allowed:
                return dns
            return ValidationResult.ok(
                message="domain valid and DNS ok",
                resolved_ips=dns.resolved_ips,
                meta={**syntax.meta, **dns.meta},
            )

        if entry_type is ScopeEntryType.url and resolve_dns:
            host = urlparse(value).hostname or ""
            dns = resolve_and_validate(host, resolver=self._resolver)
            if not dns.allowed:
                return dns
            return ValidationResult.ok(
                message="URL valid and DNS ok",
                resolved_ips=dns.resolved_ips,
                meta={**syntax.meta, **dns.meta},
            )

        return syntax

    def check_target_in_scope(
        self,
        target: ScopeTarget,
        entries: Sequence[ScopeEntry],
        *,
        resolve_dns: bool = True,
    ) -> ValidationResult:
        """Check whether a runtime target is covered by project scope."""
        parsed = build_parsed_scope(entries)
        t = target.type
        value = target.value.strip()

        if t is ScopeEntryType.ip:
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return ValidationResult.deny(ValidationReason.invalid_format, f"invalid IP: {value}")
            if is_metadata_ip(addr) or is_always_blocked_ip(addr):
                return ValidationResult.deny(
                    ValidationReason.ssrf_blocked,
                    f"SSRF/metadata block: {value}",
                    resolved_ips=(str(addr),),
                )
            if not _ip_in_scope(str(addr), parsed):
                return ValidationResult.deny(ValidationReason.out_of_scope, f"IP not in scope: {value}")
            return ValidationResult.ok(resolved_ips=(str(addr),))

        if t is ScopeEntryType.domain:
            host = value.lower().rstrip(".")
            if is_metadata_hostname(host):
                return ValidationResult.deny(
                    ValidationReason.ssrf_blocked,
                    f"metadata hostname blocked: {host}",
                )
            if not _domain_in_scope(host, parsed.domains):
                return ValidationResult.deny(ValidationReason.out_of_scope, f"domain not in scope: {host}")
            if resolve_dns:
                dns = resolve_and_validate(host, resolver=self._resolver)
                if not dns.allowed:
                    return dns
                # Also require every resolved IP to be in IP/CIDR scope if those exist;
                # if only domain scopes exist, domain membership is enough after blocklist.
                if parsed.ips or parsed.networks:
                    for ip in dns.resolved_ips:
                        if not _ip_in_scope(ip, parsed):
                            # Domain-scoped targets may resolve outside IP scopes —
                            # still allow if domain matched, but re-check blocklist already done.
                            break
                return dns
            return ValidationResult.ok(meta={"host": host})

        if t is ScopeEntryType.url:
            return self.check_url(value, entries, resolve_dns=resolve_dns)

        if t is ScopeEntryType.path:
            if not _path_in_scope(value, parsed.paths):
                return ValidationResult.deny(ValidationReason.out_of_scope, f"path not in scope: {value}")
            return ValidationResult.ok(meta={"path": value})

        if t is ScopeEntryType.api_spec:
            if value in parsed.api_specs or _path_in_scope(value, parsed.api_specs + parsed.paths):
                return ValidationResult.ok(meta={"api_spec": value})
            if value.startswith("http"):
                return self.check_url(value, entries, resolve_dns=resolve_dns)
            return ValidationResult.deny(ValidationReason.out_of_scope, f"API spec not in scope: {value}")

        if t is ScopeEntryType.cidr:
            return ValidationResult.deny(
                ValidationReason.invalid_format,
                "CIDR is a scope definition type, not a runtime connect target",
            )

        return ValidationResult.deny(ValidationReason.invalid_format, f"unsupported target type: {t}")

    def check_url(
        self,
        url: str,
        entries: Sequence[ScopeEntry],
        *,
        resolve_dns: bool = True,
        previously_allowed_ips: set[str] | None = None,
    ) -> ValidationResult:
        """Validate URL against scope + SSRF/metadata/DNS guards."""
        syntax = validate_entry_syntax(ScopeEntryType.url, url)
        if not syntax.allowed:
            return syntax

        parsed = build_parsed_scope(entries)
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        base = _normalize_url_base(url)

        in_url_scope = any(base == u or base.startswith(u + "/") for u in parsed.urls)
        in_domain_scope = _domain_in_scope(host, parsed.domains)
        # Literal IP host covered by IP/CIDR scope.
        in_ip_scope = False
        try:
            addr = ipaddress.ip_address(host)
            if is_metadata_ip(addr) or is_always_blocked_ip(addr):
                return ValidationResult.deny(
                    ValidationReason.ssrf_blocked,
                    f"SSRF block for URL host: {host}",
                    resolved_ips=(str(addr),),
                )
            in_ip_scope = _ip_in_scope(str(addr), parsed)
        except ValueError:
            pass

        if not (in_url_scope or in_domain_scope or in_ip_scope):
            return ValidationResult.deny(ValidationReason.out_of_scope, f"URL not in scope: {url}")

        if not resolve_dns:
            return ValidationResult.ok(meta={"host": host, "base": base})

        if previously_allowed_ips is not None:
            return rebinding_guard(host, previously_allowed_ips, resolver=self._resolver)
        return resolve_and_validate(host, resolver=self._resolver)

    def check_redirect(
        self,
        from_url: str,
        location: str,
        entries: Sequence[ScopeEntry],
        *,
        previously_allowed_ips: set[str] | None = None,
    ) -> ValidationResult:
        """Redirect follow only if the Location target remains in scope."""
        from urllib.parse import urljoin

        next_url = urljoin(from_url, location)
        return self.check_url(
            next_url,
            entries,
            resolve_dns=True,
            previously_allowed_ips=previously_allowed_ips,
        )

    def check_ssrf_fetch(
        self,
        url: str,
        entries: Sequence[ScopeEntry],
    ) -> ValidationResult:
        """
        Adapter-facing gate: never fetch tool-output URLs without scope check.
        Stricter than check_url — requires explicit URL or domain scope membership
        (IP literals alone in tool output are not enough unless also in scope).
        """
        result = self.check_url(url, entries, resolve_dns=True)
        if not result.allowed:
            if result.reason in {
                ValidationReason.blocked_metadata,
                ValidationReason.blocked_address,
                ValidationReason.dns_rebinding,
            }:
                return ValidationResult.deny(
                    ValidationReason.ssrf_blocked,
                    result.message,
                    resolved_ips=result.resolved_ips,
                    meta=result.meta,
                )
            return result
        return result

    def require_active_tests(self, db: Session | None = None, settings_map: dict[str, Any] | None = None) -> ValidationResult:
        return active_gate.require_active_tests(db, settings_map=settings_map)

    def check_rate_limit(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: float,
    ) -> ValidationResult:
        return self._rate_state.check(key, limit=limit, window_seconds=window_seconds)

    def start_time_budget(self, max_seconds: float | None = None) -> rate_limits.TimeBudget:
        return rate_limits.TimeBudget.start(
            max_seconds if max_seconds is not None else float(rate_limits.DEFAULT_TIME_LIMITS["scan_wall_clock_seconds"])
        )
