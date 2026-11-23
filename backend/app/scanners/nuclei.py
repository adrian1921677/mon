"""Nuclei adapter skeleton — full CLI in Phase 5."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class NucleiAdapter(SkeletonAdapter):
    scanner_id = "nuclei"
    display_name = "Nuclei"
    description = "Template-based vulnerability scanner."
    capabilities = frozenset({Capability.web, Capability.network})
    preferred_runtime = RuntimeKind.wsl
    is_active = True
    integration_phase = 5
    binary_names = ("nuclei",)
    accepted_target_types = frozenset(
        {ScopeEntryType.url, ScopeEntryType.domain, ScopeEntryType.ip}
    )
    install_hint = "Install Nuclei binary or via WSL (Phase 5)."
