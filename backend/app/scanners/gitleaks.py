"""Gitleaks adapter skeleton — full CLI in Phase 4."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class GitleaksAdapter(SkeletonAdapter):
    scanner_id = "gitleaks"
    display_name = "Gitleaks"
    description = "Secret scanning in git repositories."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 4
    binary_names = ("gitleaks",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Gitleaks (binary/WSL) — Phase 4 CLI integration."
