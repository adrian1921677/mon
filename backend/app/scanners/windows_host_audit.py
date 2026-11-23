"""
Windows Security Audit adapter — Phase 7.

Read-only local PowerShell checks (Defender, Firewall, UAC, SMBv1, RDP NLA, …).
No exploits, no remoting. Scope: local host markers (path/ip/domain).
"""

from __future__ import annotations

import json
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
from app.scanners.install_probe import probe_binaries
from app.scope.types import ScopeTarget, ValidationReason, ValidationResult

_SCRIPT = Path(__file__).resolve().parent / "scripts" / "windows_host_audit.ps1"

_LOCAL_IPS = frozenset({"127.0.0.1", "::1"})

_SEV = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _is_local_host_target(target: ScopeTarget) -> bool:
    value = target.value.strip()
    if not value:
        return False
    lower = value.lower()
    if target.type is ScopeEntryType.ip:
        return lower in _LOCAL_IPS
    if target.type is ScopeEntryType.domain:
        return lower in {"localhost"}
    if target.type is ScopeEntryType.path:
        # Any path scope authorizes *local* host audit (checks run on this machine).
        # Prefer explicit markers; still accept other paths as explicit project consent.
        return True
    return False


class WindowsHostAuditAdapter(CliScannerAdapter):
    scanner_id = "windows_host_audit"
    display_name = "Windows Host Audit"
    description = "Local Windows security posture checks (read-only, no exploits)."
    capabilities = frozenset({Capability.host})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 7
    binary_names = ("powershell", "pwsh")
    accepted_target_types = frozenset(
        {ScopeEntryType.path, ScopeEntryType.ip, ScopeEntryType.domain}
    )
    install_hint = (
        "Requires Windows PowerShell (`powershell`) or PowerShell 7 (`pwsh`) on PATH. "
        "Runs the bundled read-only script scanners/scripts/windows_host_audit.ps1."
    )
    version_args = ("-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()")
    success_exit_codes = frozenset({0})

    async def check_installation(self) -> InstallationInfo:
        info = probe_binaries(
            self.binary_names,
            runtime=self.preferred_runtime,
            hint=self.install_hint,
        )
        if info.status is not InstallationStatus.installed:
            return info
        if not _SCRIPT.is_file():
            return InstallationInfo(
                status=InstallationStatus.error,
                path_or_runtime=RuntimeKind.native.value,
                message=f"audit script missing: {_SCRIPT}",
            )
        # On non-Windows, powershell/pwsh may exist but host checks are N/A.
        if sys.platform != "win32":
            # Still allow pwsh for fixture/dev if user insists — mark installed but
            # message clarifies platform. Script uses Windows-only cmdlets.
            info = InstallationInfo(
                status=info.status,
                version=info.version,
                path_or_runtime=info.path_or_runtime,
                binary_path=info.binary_path,
                message=(
                    f"{info.message}; note: full Windows audit cmdlets require Windows "
                    f"(current platform={sys.platform})"
                ),
                meta={**(info.meta or {}), "platform": sys.platform},
            )
        return info

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        if target.type not in self.accepted_target_types:
            allowed = ", ".join(sorted(t.value for t in self.accepted_target_types))
            return ValidationResult.deny(
                ValidationReason.invalid_format,
                f"{self.scanner_id} accepts target types: {allowed}",
            )
        if not target.value.strip():
            return ValidationResult.deny(ValidationReason.invalid_format, "empty target")
        if target.type in {ScopeEntryType.ip, ScopeEntryType.domain}:
            if not _is_local_host_target(target):
                return ValidationResult.deny(
                    ValidationReason.invalid_format,
                    "windows_host_audit only allows local host (127.0.0.1 / ::1 / localhost)",
                )
        return ValidationResult.ok(message="windows_host_audit local target ok")

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_json = work / f"windows-host-audit-{ctx.task_id}.json"
        if not _SCRIPT.is_file():
            raise FileNotFoundError(f"windows audit script missing: {_SCRIPT}")

        # powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script -OutFile out
        argv = (
            binary,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_SCRIPT),
            "-OutFile",
            str(out_json),
        )
        ctx.options = {
            **(ctx.options or {}),
            "windows_host_audit_json": str(out_json),
        }
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=120.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("windows_host_audit_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace").strip()
        elif (artifacts.stdout or "").strip().startswith("{"):
            text = artifacts.stdout.strip()
        # PowerShell may emit BOM / trailing noise — take last JSON object-ish block
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
            # Only surface fail/warn as findings; pass/info stay out of findings DB noise
            # except warn — include fail + warn.
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
                    category="host.windows",
                    fingerprint_parts=("windows_host_audit", cid, host),
                    raw_ref=f"windows_host_audit:{cid}",
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
