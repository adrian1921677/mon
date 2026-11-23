"""Schemathesis adapter skeleton — full CLI in Phase 6."""

from __future__ import annotations

from app.db.models import ScopeEntryType
from app.scanners.base import Capability, RuntimeKind
from app.scanners.skeleton import SkeletonAdapter


class SchemathesisAdapter(SkeletonAdapter):
    scanner_id = "schemathesis"
    display_name = "Schemathesis"
    description = "Property-based API testing from OpenAPI specs."
    capabilities = frozenset({Capability.api})
    preferred_runtime = RuntimeKind.native
    is_active = True
    integration_phase = 6
    binary_names = ("schemathesis", "st")
    accepted_target_types = frozenset({ScopeEntryType.api_spec, ScopeEntryType.url})
    install_hint = "Install Schemathesis in a venv — Phase 6 CLI integration."
