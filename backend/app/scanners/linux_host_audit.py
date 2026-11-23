"""
Linux Security Audit adapter — Phase 7.

Read-only CIS-like checks via WSL2 (``wsl``) or native ``bash`` on Linux.
No exploits. Scope: local host markers (path / localhost ip/domain).
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

from app.db.models import ScopeEntryType
from app.process.manager import CommandSpec
from app.scanners.base import (
    Capability,
    InstallationInfo,
    InstallationStatus,
    NormalizedFinding,
    ParseArtifacts,
    RuntimeKind,
    ScanContext,
)
from app.scanners.cli_base import CliScannerAdapter
from app.scope.types import ScopeTarget, ValidationReason, ValidationResult

_SCRIPT = Path(__file__).resolve().parent / "scripts" / "linux_host_audit.sh"

_LOCAL_IPS = frozenset({"127.0.0.1", "::1"})

_SEV = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class LinuxHostAuditAdapter(CliScannerAdapter):
    scanner_id = "linux_host_audit"
    display_name = "Linux Host Audit"
    description = "CIS-like Linux host checks via WSL2 or native bash (read-only, no exploits)."
    capabilities = frozenset({Capability.host})
    preferred_runtime = RuntimeKind.wsl
    is_active = False
    integration_phase = 7
    binary_names = ("wsl", "bash")
    accepted_target_types = frozenset(
        {ScopeEntryType.path, ScopeEntryType.ip, ScopeEntryType.domain}
    )
    install_hint = (
        "On Windows 11: enable WSL2 so `wsl` is on PATH. "
        "On Linux: `bash` + `python3` for the bundled script. "
        "See scanners/docs/linux_host_audit.md."
    )
    version_args = ("--version",)
    success_exit_codes = frozenset({0})

    async def check_installation(self) -> InstallationInfo:
        if not _SCRIPT.is_file():
            return InstallationInfo(
                status=InstallationStatus.error,
                path_or_runtime=self.preferred_runtime.value,
                message=f"audit script missing: {_SCRIPT}",
            )

        if sys.platform == "win32":
            wsl = shutil.which("wsl")
            if wsl:
                return InstallationInfo(
                    status=InstallationStatus.installed,
                    path_or_runtime=RuntimeKind.wsl.value,
                    binary_path=str(Path(wsl)),
                    message=f"found wsl at {wsl}",
                    meta={"binary": "wsl", "mode": "wsl"},
                )
            return InstallationInfo(
                status=InstallationStatus.not_installed,
                path_or_runtime=RuntimeKind.wsl.value,
                message=self.install_hint,
            )

        bash = shutil.which("bash")
        if bash:
            return InstallationInfo(
                status=InstallationStatus.installed,
                path_or_runtime=RuntimeKind.native.value,
                binary_path=str(Path(bash)),
                message=f"found bash at {bash}",
                meta={"binary": "bash", "mode": "native"},
            )
        return InstallationInfo(
            status=InstallationStatus.not_installed,
            path_or_runtime=RuntimeKind.native.value,
            message=self.install_hint,
        )

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        if target.type not in self.accepted_target_types:
            allowed = ", ".join(sorted(t.value for t in self.accepted_target_types))
            return ValidationResult.deny(
                ValidationReason.invalid_format,
                f"{self.scanner_id} accepts target types: {allowed}",
            )
        if not target.value.strip():
            return ValidationResult.deny(ValidationReason.invalid_format, "empty target")
        if target.type is ScopeEntryType.ip:
            if target.value.strip().lower() not in _LOCAL_IPS:
                return ValidationResult.deny(
                    ValidationReason.invalid_format,
                    "linux_host_audit only allows local host (127.0.0.1 / ::1)",
                )
        if target.type is ScopeEntryType.domain:
            if target.value.strip().lower() != "localhost":
                return ValidationResult.deny(
                    ValidationReason.invalid_format,
                    "linux_host_audit only allows domain localhost",
                )
        return ValidationResult.ok(message="linux_host_audit local target ok")

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_json = work / f"linux-host-audit-{ctx.task_id}.json"
        if not _SCRIPT.is_file():
            raise FileNotFoundError(f"linux audit script missing: {_SCRIPT}")

        mode = ((ctx.options or {}).get("_mode") or "").strip()
        binary = self._binary_from_ctx(ctx)
        # Prefer meta from check_installation when available
        meta_bin = (ctx.options or {}).get("_binary")
        if isinstance(meta_bin, str) and meta_bin:
            binary = meta_bin

        # Detect mode from binary name when options lack it
        bin_name = Path(binary).name.lower()
        if not mode:
            mode = "wsl" if bin_name == "wsl" or sys.platform == "win32" else "native"

        script_path = str(_SCRIPT)
        if mode == "wsl":
            # Translate Windows path to WSL path when possible; otherwise pass as-is
            # and rely on /mnt/c/... — ProcessManager runs on Windows host.
            wsl_script = script_path
            if len(script_path) > 2 and script_path[1] == ":":
                drive = script_path[0].lower()
                rest = script_path[2:].replace("\\", "/")
                wsl_script = f"/mnt/{drive}{rest}"
            wsl_out = str(out_json)
            if len(wsl_out) > 2 and wsl_out[1] == ":":
                drive = wsl_out[0].lower()
                rest = wsl_out[2:].replace("\\", "/")
                wsl_out = f"/mnt/{drive}{rest}"
            argv = (
                binary if bin_name == "wsl" else (shutil.which("wsl") or "wsl"),
                "-e",
                "bash",
                wsl_script,
                "--out",
                wsl_out,
            )
        else:
            argv = (
                binary if bin_name == "bash" else (shutil.which("bash") or "bash"),
                script_path,
                "--out",
                str(out_json),
            )

        ctx.options = {
            **(ctx.options or {}),
            "linux_host_audit_json": str(out_json),
            "linux_host_audit_mode": mode,
        }
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=120.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    async def execute(self, ctx: ScanContext, process_manager):  # type: ignore[override]
        info = await self.check_installation()
        if info.status is not InstallationStatus.installed:
            from app.scanners.base import ScannerNotInstalledError

            raise ScannerNotInstalledError(self.scanner_id, info.message)
        mode = (info.meta or {}).get("mode") or ("wsl" if sys.platform == "win32" else "native")
        binary = info.binary_path or ((info.meta or {}).get("binary") if info.meta else None) or "bash"
        ctx.options = {
            **(ctx.options or {}),
            "_binary": binary,
            "_mode": mode,
        }
        spec = self.build_command(ctx)
        return await process_manager.run(spec)

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("linux_host_audit_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace").strip()
        elif (artifacts.stdout or "").strip().startswith("{"):
            text = artifacts.stdout.strip()
        if not text and artifacts.stdout:
            raw = artifacts.stdout.strip()
            start = raw.find("{")
            end = raw.rfind("}")
            if start >= 0 and end > start:
                text = raw[start : end + 1]
        if not text:
            return {
                "checks": [],
                "raw_empty": True,
                "exit_code": artifacts.exit_code,
                "stderr": (artifacts.stderr or "")[:500],
            }
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return {
                "checks": [],
                "parse_error": str(exc),
                "exit_code": artifacts.exit_code,
            }
        if not isinstance(data, dict):
            return {"checks": [], "parse_error": "unexpected root", "exit_code": artifacts.exit_code}
        checks = [c for c in (data.get("checks") or []) if isinstance(c, dict)]
        return {
            "checks": checks,
            "host": data.get("host"),
            "os": data.get("os"),
            "exit_code": artifacts.exit_code,
        }

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        host = str(parsed.get("host") or "local")
        for check in parsed.get("checks") or []:
            if not isinstance(check, dict):
                continue
            status = str(check.get("status") or "info").lower()
            if status not in {"fail", "warn"}:
                continue
            cid = str(check.get("id") or check.get("title") or "check")
            title = str(check.get("title") or cid)[:512]
            severity = _SEV.get(str(check.get("severity") or "medium").lower(), "medium")
            if status == "warn" and severity == "info":
                severity = "low"
            detail = str(check.get("detail") or "")
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    category="host.linux",
                    fingerprint_parts=("linux_host_audit", cid, host),
                    raw_ref=f"linux_host_audit:{cid}",
                    evidence=[
                        {
                            "kind": "host_check",
                            "path_or_blob_ref": f"{status}: {detail}".strip(),
                        }
                    ],
                    meta={
                        "check_id": cid,
                        "status": status,
                        "detail": detail,
                        "host": host,
                        "os": parsed.get("os"),
                    },
                )
            )
        return findings
