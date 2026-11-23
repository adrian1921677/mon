"""Windows Security Audit adapter skeleton — Phase 7."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class WindowsHostAuditAdapter(SkeletonAdapter):
    scanner_id = "windows_host_audit"
    display_name = "Windows Host Audit"
    description = "Local Windows security posture checks (no exploits)."
    capabilities = frozenset({Capability.host})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 7
    binary_names = ("powershell", "pwsh")
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Uses local PowerShell on Windows — Phase 7 integration."
