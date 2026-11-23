"""Scanner registry and adapters (Phase 3)."""

from app.scanners.base import (
    Capability,
    InstallationInfo,
    InstallationStatus,
    NormalizedFinding,
    ParseArtifacts,
    RuntimeKind,
    ScanContext,
    ScannerAdapter,
    ScannerError,
    ScannerNotImplementedError,
    ScannerNotInstalledError,
)
from app.scanners.registry import ScannerRegistry, get_registry, reset_registry

__all__ = [
    "Capability",
    "InstallationInfo",
    "InstallationStatus",
    "NormalizedFinding",
    "ParseArtifacts",
    "RuntimeKind",
    "ScanContext",
    "ScannerAdapter",
    "ScannerError",
    "ScannerNotImplementedError",
    "ScannerNotInstalledError",
    "ScannerRegistry",
    "get_registry",
    "reset_registry",
]
