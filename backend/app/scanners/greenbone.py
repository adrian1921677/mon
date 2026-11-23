"""Greenbone/OpenVAS adapter skeleton — full CLI in Phase 7."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class GreenboneAdapter(SkeletonAdapter):
    scanner_id = "greenbone"
    display_name = "Greenbone / OpenVAS"
    description = "Vulnerability management (typically Docker)."
    capabilities = frozenset({Capability.network})
    preferred_runtime = RuntimeKind.docker
    is_active = True
    integration_phase = 7
    binary_names = ("gvm-cli", "omp", "gvmd")
    accepted_target_types = frozenset(
        {ScopeEntryType.ip, ScopeEntryType.cidr, ScopeEntryType.domain}
    )
    install_hint = "Greenbone typically runs via Docker — configure in Tool Manager (Phase 7)."
