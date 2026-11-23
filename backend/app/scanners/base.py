"""Scanner adapter interface — shared by all tools (Phase 3+)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from app.process.manager import CommandSpec, ProcessManager, ProcessResult
from app.scope.types import ScopeTarget, ValidationResult


class Capability(str, Enum):
    network = "network"
    web = "web"
    code = "code"
    api = "api"
    host = "host"
    pipeline_test = "pipeline_test"


class RuntimeKind(str, Enum):
    native = "native"
    wsl = "wsl"
    docker = "docker"


class InstallationStatus(str, Enum):
    installed = "installed"
    not_installed = "not_installed"
    unknown = "unknown"
    error = "error"


class ScannerError(Exception):
    """Base error for scanner adapters."""


class ScannerNotInstalledError(ScannerError):
    def __init__(self, scanner_id: str, message: str | None = None) -> None:
        self.scanner_id = scanner_id
        super().__init__(message or f"scanner '{scanner_id}' is not installed")


class ScannerNotImplementedError(ScannerError):
    """CLI integration not ready yet (Phase 4–7)."""

    def __init__(self, scanner_id: str, phase: int, message: str | None = None) -> None:
        self.scanner_id = scanner_id
        self.phase = phase
        super().__init__(
            message
            or f"scanner '{scanner_id}' CLI integration lands in Phase {phase}; no fake findings"
        )


@dataclass(frozen=True)
class InstallationInfo:
    status: InstallationStatus
    version: str | None = None
    path_or_runtime: str = RuntimeKind.native.value
    message: str = ""
    binary_path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Runtime context passed into adapter build/execute/parse."""

    project_id: str
    scan_id: str
    task_id: str
    targets: list[ScopeTarget]
    depth: str = "standard"
    options: dict[str, Any] = field(default_factory=dict)
    work_dir: Path | None = None
    allow_test_findings: bool = False


@dataclass
class NormalizedFinding:
    """Normalized finding — never invent these for production UI stubs."""

    title: str
    severity: str
    category: str
    fingerprint_parts: tuple[str, ...]
    raw_ref: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParseArtifacts:
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    files: dict[str, Path] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter(ABC):
    """
    Binding interface for every scanner adapter.

    Methods:
      check_installation, get_version, validate_target,
      build_command, execute, parse_results, normalize_findings
    """

    scanner_id: str
    display_name: str
    description: str = ""
    capabilities: frozenset[Capability] = frozenset()
    preferred_runtime: RuntimeKind = RuntimeKind.native
    #: Requires ``security.active_tests_enabled`` before execution.
    is_active: bool = False
    #: Echo / harness only — never shown as productive findings in the UI.
    is_test_only: bool = False
    #: Phase that ships full CLI integration (4–7).
    integration_phase: int = 4
    binary_names: tuple[str, ...] = ()

    @abstractmethod
    async def check_installation(self) -> InstallationInfo:
        """Probe local/WSL/Docker availability — never invent a green status."""

    @abstractmethod
    async def get_version(self) -> str | None:
        """Return tool version string or None if unavailable."""

    @abstractmethod
    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        """Adapter-level target shape check (scope membership is ScopeEngine)."""

    @abstractmethod
    def build_command(self, ctx: ScanContext) -> CommandSpec:
        """Build argv CommandSpec — never a shell string."""

    @abstractmethod
    async def execute(self, ctx: ScanContext, process_manager: ProcessManager) -> ProcessResult:
        """Run via ProcessManager only (no direct subprocess / shell)."""

    @abstractmethod
    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        """Parse raw tool output into structured intermediate form."""

    @abstractmethod
    def normalize_findings(
        self,
        parsed: Any,
        ctx: ScanContext,
    ) -> list[NormalizedFinding]:
        """Map parsed output to NormalizedFinding — empty list if none / not ready."""
