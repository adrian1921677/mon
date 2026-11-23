"""Semgrep adapter skeleton — full CLI in Phase 4."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class SemgrepAdapter(SkeletonAdapter):
    scanner_id = "semgrep"
    display_name = "Semgrep"
    description = "Static analysis for source code."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 4
    binary_names = ("semgrep",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Semgrep (pip/WSL) — Phase 4 CLI integration."
