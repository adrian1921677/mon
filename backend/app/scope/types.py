"""Shared types for the Scope Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any

from app.db.models import ScopeEntryType


class ValidationReason(str, Enum):
    ok = "ok"
    invalid_format = "invalid_format"
    blocked_metadata = "blocked_metadata"
    blocked_address = "blocked_address"
    out_of_scope = "out_of_scope"
    dns_failed = "dns_failed"
    dns_rebinding = "dns_rebinding"
    redirect_out_of_scope = "redirect_out_of_scope"
    ssrf_blocked = "ssrf_blocked"
    path_not_local = "path_not_local"
    active_tests_disabled = "active_tests_disabled"
    rate_limited = "rate_limited"
    time_budget_exceeded = "time_budget_exceeded"


@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    reason: ValidationReason
    message: str = ""
    resolved_ips: tuple[str, ...] = ()
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(
        cls,
        *,
        message: str = "ok",
        resolved_ips: tuple[str, ...] = (),
        meta: dict[str, Any] | None = None,
    ) -> ValidationResult:
        return cls(
            allowed=True,
            reason=ValidationReason.ok,
            message=message,
            resolved_ips=resolved_ips,
            meta=meta or {},
        )

    @classmethod
    def deny(
        cls,
        reason: ValidationReason,
        message: str,
        *,
        resolved_ips: tuple[str, ...] = (),
        meta: dict[str, Any] | None = None,
    ) -> ValidationResult:
        return cls(
            allowed=False,
            reason=reason,
            message=message,
            resolved_ips=resolved_ips,
            meta=meta or {},
        )


@dataclass(frozen=True)
class ScopeTarget:
    """A candidate target to validate against project scope."""

    type: ScopeEntryType
    value: str
    meta: dict[str, Any] = field(default_factory=dict)


IpAddr = IPv4Address | IPv6Address
IpNet = IPv4Network | IPv6Network
