"""Linux Security Audit adapter skeleton — Phase 7 (WSL)."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class LinuxHostAuditAdapter(SkeletonAdapter):
    scanner_id = "linux_host_audit"
    display_name = "Linux Host Audit"
    description = "CIS-like Linux host checks via WSL (no exploits)."
    capabilities = frozenset({Capability.host})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 7
    binary_names = ("bash", "sh")
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Requires WSL2 — Phase 7 integration."
