"""Skeleton adapter base — clean not-installed / NotImplemented paths."""

from __future__ import annotations

from typing import Any

from app.process.manager import CommandSpec, ProcessManager, ProcessResult
from app.scanners.base import (
    InstallationInfo,
    InstallationStatus,
    NormalizedFinding,
    ParseArtifacts,
    RuntimeKind,
    ScanContext,
    ScannerAdapter,
    ScannerNotImplementedError,
    ScannerNotInstalledError,
)
from app.scanners.install_probe import probe_binaries
from app.scope.types import ScopeEntryType, ScopeTarget, ValidationReason, ValidationResult


class SkeletonAdapter(ScannerAdapter):
    """
    Productive scanner stub for Phase 3.

    - Reports real installation status (PATH probe).
    - Refuses build/execute/parse with NotImplemented until its integration phase.
    - Never emits fake findings.
    """

    accepted_target_types: frozenset[ScopeEntryType] = frozenset()
    install_hint: str = ""

    async def check_installation(self) -> InstallationInfo:
        return probe_binaries(
            self.binary_names,
            runtime=self.preferred_runtime,
            hint=self.install_hint,
        )

    async def get_version(self) -> str | None:
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            return None
        # Full version parsing lands with CLI integration.
        return info.version or "unknown"

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        if self.accepted_target_types and target.type not in self.accepted_target_types:
            allowed = ", ".join(sorted(t.value for t in self.accepted_target_types))
            return ValidationResult.deny(
                ValidationReason.invalid_format,
                f"{self.scanner_id} accepts target types: {allowed}",
            )
        if not target.value.strip():
            return ValidationResult.deny(ValidationReason.invalid_format, "empty target")
        return ValidationResult.ok(message=f"{self.scanner_id} target shape ok")

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        raise ScannerNotImplementedError(self.scanner_id, self.integration_phase)

    async def execute(self, ctx: ScanContext, process_manager: ProcessManager) -> ProcessResult:
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            raise ScannerNotInstalledError(self.scanner_id, info.message)
        raise ScannerNotImplementedError(self.scanner_id, self.integration_phase)

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        raise ScannerNotImplementedError(self.scanner_id, self.integration_phase)

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        # Explicit empty / error — never fabricate security findings.
        raise ScannerNotImplementedError(self.scanner_id, self.integration_phase)
