"""OWASP ZAP adapter skeleton — full CLI in Phase 5."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class ZapAdapter(SkeletonAdapter):
    scanner_id = "zap"
    display_name = "OWASP ZAP"
    description = "Web application security scanner (Java / Docker)."
    capabilities = frozenset({Capability.web})
    preferred_runtime = RuntimeKind.docker
    is_active = True
    integration_phase = 5
    binary_names = ("zap.sh", "zap-cli", "zap")
    accepted_target_types = frozenset({ScopeEntryType.url, ScopeEntryType.domain})
    install_hint = "Install ZAP or run via Docker/WSL (Phase 5)."
