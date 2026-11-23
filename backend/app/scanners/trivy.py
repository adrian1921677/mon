"""Trivy adapter skeleton — full CLI in Phase 4."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class TrivyAdapter(SkeletonAdapter):
    scanner_id = "trivy"
    display_name = "Trivy"
    description = "Vulnerability / misconfiguration scanner for repos and images."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 4
    binary_names = ("trivy",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Trivy (binary/WSL/Docker) — Phase 4 CLI integration."
