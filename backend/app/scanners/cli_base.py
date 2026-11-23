"""Shared helpers for Phase-4+ CLI adapters (real binaries, no fake findings)."""

from __future__ import annotations

import re
from typing import Any

from app.process.manager import CommandSpec, ProcessManager, ProcessResult, ProcessStatus
from app.scanners.base import (
    InstallationInfo,
    InstallationStatus,
    NormalizedFinding,
    ParseArtifacts,
    ScanContext,
    ScannerAdapter,
    ScannerNotInstalledError,
)
from app.scanners.install_probe import probe_binaries
from app.scanners.skeleton import SkeletonAdapter
from app.scope.types import ScopeEntryType, ScopeTarget, ValidationReason, ValidationResult


def resolve_binary(info: InstallationInfo, names: tuple[str, ...]) -> str:
    if info.binary_path:
        return info.binary_path
    meta_name = (info.meta or {}).get("binary")
    if isinstance(meta_name, str) and meta_name:
        return meta_name
    if names:
        return names[0]
    raise ScannerNotInstalledError("unknown", "no binary configured")


class CliScannerAdapter(SkeletonAdapter):
    """
    Base for fully integrated CLI scanners.

    - Real PATH probe + version command
    - build_command → execute via ProcessManager only
    - Subclasses implement build_command / parse / normalize
    """

    version_args: tuple[str, ...] = ("--version",)
    #: Exit codes that mean "ran successfully" (possibly with findings).
    success_exit_codes: frozenset[int] = frozenset({0})
    version_regex: re.Pattern[str] | None = None

    async def get_version(self) -> str | None:
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            return None
        binary = resolve_binary(info, self.binary_names)
        # Lightweight sync probe via shutil already done; try --version through
        # a short ProcessManager run when available is nicer but keep simple:
        # parse from a one-shot subprocess would duplicate ProcessManager —
        # adapters may override. Default: return probe meta or "installed".
        return info.version or "installed"

    async def probe_version(self, process_manager: ProcessManager) -> str | None:
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            return None
        binary = resolve_binary(info, self.binary_names)
        result = await process_manager.run(
            CommandSpec(
                argv=(binary, *self.version_args),
                timeout_seconds=30.0,
            )
        )
        text = f"{result.stdout}\n{result.stderr}".strip()
        if self.version_regex:
            match = self.version_regex.search(text)
            if match:
                return match.group(1)
        # First non-empty line as fallback
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line[:128]
        return None

    async def check_installation(self) -> InstallationInfo:
        info = probe_binaries(
            self.binary_names,
            runtime=self.preferred_runtime,
            hint=self.install_hint,
        )
        return info

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        return super().validate_target(target)

    async def execute(self, ctx: ScanContext, process_manager: ProcessManager) -> ProcessResult:
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            raise ScannerNotInstalledError(self.scanner_id, info.message)
        # Attach binary into options for build_command
        ctx.options = {**(ctx.options or {}), "_binary": resolve_binary(info, self.binary_names)}
        spec = self.build_command(ctx)
        return await process_manager.run(spec)

    def process_succeeded(self, result: ProcessResult) -> bool:
        if result.status is not ProcessStatus.completed:
            return False
        code = 0 if result.exit_code is None else result.exit_code
        return code in self.success_exit_codes

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        raise NotImplementedError

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        raise NotImplementedError

    def _binary_from_ctx(self, ctx: ScanContext) -> str:
        binary = (ctx.options or {}).get("_binary")
        if isinstance(binary, str) and binary:
            return binary
        if self.binary_names:
            return self.binary_names[0]
        raise ScannerNotInstalledError(self.scanner_id)


def compatible_targets(
    adapter: ScannerAdapter,
    targets: list[ScopeTarget],
) -> list[ScopeTarget]:
    return [t for t in targets if adapter.validate_target(t).allowed]


def require_path_target(target: ScopeTarget) -> ValidationResult:
    if target.type is not ScopeEntryType.path:
        return ValidationResult.deny(
            ValidationReason.invalid_format,
            "expected local path target",
        )
    if not target.value.strip():
        return ValidationResult.deny(ValidationReason.invalid_format, "empty path")
    return ValidationResult.ok(message="path target ok")
