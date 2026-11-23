"""Echo adapter — pipeline integration tests only. Never production findings."""

from __future__ import annotations

import sys
from typing import Any

from app.process.manager import CommandSpec, ProcessManager, ProcessResult
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
)
from app.scope.types import ScopeTarget, ValidationResult


class EchoAdapter(ScannerAdapter):
    """
    Runs a harmless echo/print via ProcessManager to exercise the pipeline.

    Marked ``is_test_only`` — Tool Manager / production scan APIs exclude it
    unless ``allow_test_adapters`` is set. Never surfaces as real UI findings.
    """

    scanner_id = "echo"
    display_name = "Echo (pipeline test)"
    description = "Test harness only — echoes targets; not a security scanner."
    capabilities = frozenset({Capability.pipeline_test})
    preferred_runtime = RuntimeKind.native
    is_active = False
    is_test_only = True
    integration_phase = 3
    binary_names = ("echo",)

    async def check_installation(self) -> InstallationInfo:
        # Always available via the Python interpreter used to run the backend.
        return InstallationInfo(
            status=InstallationStatus.installed,
            version="builtin",
            path_or_runtime=RuntimeKind.native.value,
            message="uses python -c print (pipeline test only)",
            binary_path=sys.executable,
            meta={"test_only": True},
        )

    async def get_version(self) -> str | None:
        return "builtin"

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        if not target.value.strip():
            from app.scope.types import ValidationReason

            return ValidationResult.deny(ValidationReason.invalid_format, "empty target")
        return ValidationResult.ok(message="echo accepts any non-empty target")

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        payload = "|".join(t.value for t in ctx.targets) or "echo-ok"
        # argv list only — no shell.
        return CommandSpec(
            argv=(sys.executable, "-c", "import sys; print(sys.argv[1])", payload),
            timeout_seconds=30.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    async def execute(self, ctx: ScanContext, process_manager: ProcessManager) -> ProcessResult:
        spec = self.build_command(ctx)
        return await process_manager.run(spec)

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        return {"echo": (artifacts.stdout or "").strip(), "exit_code": artifacts.exit_code}

    def normalize_findings(
        self,
        parsed: Any,
        ctx: ScanContext,
    ) -> list[NormalizedFinding]:
        if not ctx.allow_test_findings:
            # Production / UI path: never emit findings from echo.
            return []
        text = ""
        if isinstance(parsed, dict):
            text = str(parsed.get("echo") or "")
        if not text:
            return []
        return [
            NormalizedFinding(
                title=f"[TEST-ONLY] echo: {text[:120]}",
                severity="info",
                category="pipeline_test",
                fingerprint_parts=("echo", "test-only", text[:64]),
                raw_ref="echo-stdout",
                meta={"test_only": True, "not_a_security_finding": True},
            )
        ]


def assert_not_for_ui_findings(adapter: ScannerAdapter) -> None:
    if adapter.is_test_only:
        raise ScannerError(
            f"adapter '{adapter.scanner_id}' is test-only and must not feed the production UI"
        )
