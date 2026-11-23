"""Nmap adapter skeleton — full CLI in Phase 4."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class NmapAdapter(SkeletonAdapter):
    scanner_id = "nmap"
    display_name = "Nmap"
    description = "Network discovery and port scanning."
    capabilities = frozenset({Capability.network})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("nmap",)
    accepted_target_types = frozenset(
        {ScopeEntryType.ip, ScopeEntryType.cidr, ScopeEntryType.domain}
    )
    install_hint = "Install Nmap (Windows installer / Npcap, or WSL: apt install nmap)."
