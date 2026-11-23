"""DNS resolution with rebinding protection."""

from __future__ import annotations

import socket
from collections.abc import Callable
from ipaddress import ip_address

from app.scope.blocklist import is_always_blocked_ip, is_metadata_ip
from app.scope.types import ValidationReason, ValidationResult

ResolverFn = Callable[[str], list[str]]


def default_resolve(hostname: str) -> list[str]:
    """Resolve A/AAAA via getaddrinfo — returns unique IP strings."""
    results: list[str] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            results.append(ip)
    return results


def resolve_and_validate(
    hostname: str,
    *,
    resolver: ResolverFn | None = None,
    allow_private: bool = True,
) -> ValidationResult:
    """
    Resolve hostname and reject metadata / always-blocked IPs.

    DNS-rebinding protection: all resolved addresses are checked; if *any*
    address is blocked, the whole resolution is denied. Callers that need
    connect-time re-check should call this again immediately before connect.
    """
    host = hostname.strip().lower().rstrip(".")
    resolve = resolver or default_resolve

    # Literal IP in "hostname" position.
    try:
        addr = ip_address(host)
        if is_metadata_ip(addr) or is_always_blocked_ip(addr):
            return ValidationResult.deny(
                ValidationReason.blocked_metadata,
                f"blocked address: {host}",
                resolved_ips=(str(addr),),
            )
        if not allow_private and (addr.is_private or addr.is_loopback):
            return ValidationResult.deny(
                ValidationReason.blocked_address,
                f"private/loopback not allowed: {host}",
                resolved_ips=(str(addr),),
            )
        return ValidationResult.ok(resolved_ips=(str(addr),), meta={"host": host})
    except ValueError:
        pass

    ips = resolve(host)
    if not ips:
        return ValidationResult.deny(ValidationReason.dns_failed, f"DNS resolution failed: {host}")

    blocked: list[str] = []
    for ip_str in ips:
        try:
            addr = ip_address(ip_str)
        except ValueError:
            blocked.append(ip_str)
            continue
        if is_metadata_ip(addr) or is_always_blocked_ip(addr):
            blocked.append(ip_str)
        elif not allow_private and (addr.is_private or addr.is_loopback):
            blocked.append(ip_str)

    if blocked:
        # Treat mixed good+bad as rebinding risk.
        reason = (
            ValidationReason.dns_rebinding
            if len(blocked) < len(ips)
            else ValidationReason.blocked_metadata
        )
        return ValidationResult.deny(
            reason,
            f"DNS resolved to blocked address(es): {', '.join(blocked)}",
            resolved_ips=tuple(ips),
            meta={"blocked": blocked, "host": host},
        )

    return ValidationResult.ok(
        message=f"resolved {host}",
        resolved_ips=tuple(ips),
        meta={"host": host},
    )


def rebinding_guard(
    hostname: str,
    previously_allowed_ips: set[str],
    *,
    resolver: ResolverFn | None = None,
) -> ValidationResult:
    """
    Re-resolve before connect. Deny if the set of IPs changed to include
    addresses that were not in the previously validated set, or any blocked IP.
    """
    result = resolve_and_validate(hostname, resolver=resolver)
    if not result.allowed:
        return result
    current = set(result.resolved_ips)
    if not current.issubset(previously_allowed_ips):
        new_ips = current - previously_allowed_ips
        return ValidationResult.deny(
            ValidationReason.dns_rebinding,
            f"DNS rebinding detected — new IPs: {', '.join(sorted(new_ips))}",
            resolved_ips=tuple(current),
            meta={"previous": sorted(previously_allowed_ips), "current": sorted(current)},
        )
    return result
