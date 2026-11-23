"""testssl.sh adapter skeleton — full CLI in Phase 5."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class TestsslAdapter(SkeletonAdapter):
    scanner_id = "testssl"
    display_name = "testssl.sh"
    description = "TLS/SSL configuration checks."
    capabilities = frozenset({Capability.web, Capability.network})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 5
    binary_names = ("testssl.sh", "testssl")
    accepted_target_types = frozenset(
        {ScopeEntryType.url, ScopeEntryType.domain, ScopeEntryType.ip}
    )
    install_hint = "Install testssl.sh under WSL or Docker (Phase 5)."
