"""
Gitleaks adapter — Phase 4 CLI integration.

Secret scanning on local path scopes. JSON report file; secrets redacted in evidence.
Exit code 1 = leaks found (treated as successful run).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.db.models import ScopeEntryType
from app.process.manager import CommandSpec
from app.scanners.base import Capability, NormalizedFinding, ParseArtifacts, RuntimeKind, ScanContext
from app.scanners.cli_base import CliScannerAdapter

_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


def _redact(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "***"
    return f"{secret[:3]}…{secret[-2:]} (redacted)"


class GitleaksAdapter(CliScannerAdapter):
    scanner_id = "gitleaks"
    display_name = "Gitleaks"
    description = "Secret scanning in git repositories and directories."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("gitleaks",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Gitleaks binary (or WSL)."
    version_args = ("version",)
    version_regex = _VERSION_RE
    success_exit_codes = frozenset({0, 1})

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        paths = [t.value for t in ctx.targets if self.validate_target(t).allowed]
        if not paths:
            raise ValueError("gitleaks: no path targets")
        source = str(Path(paths[0]).expanduser())

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        report = work / f"gitleaks-{ctx.task_id}.json"

        # Prefer directory scan; --no-git when not a git repo is safer for CI fixtures.
        no_git = not (Path(source) / ".git").exists()
        argv_list: list[str] = [
            binary,
            "detect",
            "--source",
            source,
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
        ]
        if no_git:
            argv_list.append("--no-git")
        if (ctx.depth or "").lower() == "deep":
            # Include verbose rule context; still no network
            argv_list.extend(["--verbose"])

        ctx.options = {**(ctx.options or {}), "gitleaks_json": str(report)}
        return CommandSpec(
            argv=tuple(argv_list),
            cwd=str(work),
            timeout_seconds=600.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("gitleaks_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace").strip()
        elif (artifacts.stdout or "").strip().startswith("["):
            text = artifacts.stdout.strip()
        if not text:
            return {"leaks": [], "exit_code": artifacts.exit_code}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return {"leaks": [], "parse_error": str(exc), "exit_code": artifacts.exit_code}
        if isinstance(data, list):
            return {"leaks": data, "exit_code": artifacts.exit_code}
        if isinstance(data, dict) and "leaks" in data:
            return data
        return {"leaks": [], "parse_error": "unexpected root", "exit_code": artifacts.exit_code}

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for leak in parsed.get("leaks") or []:
            if not isinstance(leak, dict):
                continue
            rule = str(leak.get("RuleID") or leak.get("Rule") or "secret")
            desc = str(leak.get("Description") or rule)
            file_path = str(leak.get("File") or leak.get("Path") or "")
            line = leak.get("StartLine") or leak.get("Line") or 0
            # Prefer tool fingerprint when present; still namespace with scanner id
            tool_fp = str(leak.get("Fingerprint") or "")
            secret = str(leak.get("Secret") or "")
            title = f"Secret detected: {desc} in {file_path}:{line}"
            fp_parts = (
                ("gitleaks", tool_fp)
                if tool_fp
                else ("gitleaks", rule, file_path, str(line))
            )
            findings.append(
                NormalizedFinding(
                    title=title[:512],
                    severity="high",
                    category="secret.gitleaks",
                    fingerprint_parts=fp_parts,
                    raw_ref=f"{file_path}:{line}:{rule}",
                    evidence=[
                        {
                            "kind": "secret_location",
                            "path_or_blob_ref": f"{file_path}:{line} rule={rule} sample={_redact(secret)}",
                        }
                    ],
                    meta={"rule": rule, "file": file_path, "line": line},
                )
            )
        return findings
