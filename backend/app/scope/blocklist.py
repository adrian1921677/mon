"""Hard blocklists: cloud metadata, link-local, and other SSRF sinks."""

from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

# Cloud / hypervisor metadata endpoints (SSRF classics).
METADATA_IPV4 = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure IMDS
        "169.254.170.2",  # AWS ECS task metadata
        "169.254.169.253",  # AWS DNS resolver (IMDS-adjacent)
    }
)

METADATA_IPV6 = frozenset(
    {
        "fd00:ec2::254",  # AWS IMDS IPv6
    }
)

METADATA_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)

# Always-blocked networks (never in scope unless explicitly allowlisted later —
# Phase 2: always deny for outbound/connect targets).
ALWAYS_BLOCKED_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ip_network("0.0.0.0/8"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("169.254.0.0/16"),  # link-local incl. IMDS
    ip_network("fe80::/10"),
    ip_network("ff00::/8"),  # multicast
)


def is_metadata_hostname(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if host in METADATA_HOSTNAMES:
        return True
    # Bare IP literals that are metadata addresses.
    try:
        addr = ip_address(host)
    except ValueError:
        return False
    return is_metadata_ip(addr)


def is_metadata_ip(addr: IPv4Address | IPv6Address) -> bool:
    text = str(addr)
    if text in METADATA_IPV4 or text in METADATA_IPV6:
        return True
    # Entire link-local range is treated as metadata/SSRF-sensitive for connect.
    for net in ALWAYS_BLOCKED_NETWORKS:
        if addr.version == net.version and addr in net:
            if isinstance(net, IPv4Network) and net.network_address.packed[:2] == b"\xa9\xfe":
                return True
            if isinstance(net, IPv6Network) and str(net).startswith("fe80"):
                return True
    return text in METADATA_IPV4 or text in METADATA_IPV6


def is_always_blocked_ip(addr: IPv4Address | IPv6Address) -> bool:
    """True for loopback, link-local, unspecified, multicast — SSRF sinks."""
    if is_metadata_ip(addr):
        return True
    for net in ALWAYS_BLOCKED_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    return False


def is_private_or_reserved(addr: IPv4Address | IPv6Address) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )
