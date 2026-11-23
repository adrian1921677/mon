"""
Semgrep adapter — Phase 4 CLI integration.

Static analysis on local path scopes. JSON report on stdout.
Default ruleset: ``p/ci`` (risk-low / CI-oriented, no custom remote trust beyond Semgrep registry).
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

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

_SEV_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
    "INVENTORY": "info",
    "EXPERIMENT": "low",
    "CRITICAL": "critical",
}


class SemgrepAdapter(CliScannerAdapter):
    scanner_id = "semgrep"
    display_name = "Semgrep"
    description = "Static analysis for source code (path scope)."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("semgrep",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Semgrep: pip install semgrep (or WSL)."
    version_args = ("--version",)
    version_regex = _VERSION_RE
    # 0 = clean, 1 = findings — both are successful runs
    success_exit_codes = frozenset({0, 1})

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        paths = [t.value for t in ctx.targets if self.validate_target(t).allowed]
        if not paths:
            raise ValueError("semgrep: no path targets")
        # Scan first compatible path (multi-path via extra argv)
        primary = str(Path(paths[0]).expanduser())
        config = "p/ci"
        if (ctx.depth or "").lower() == "deep":
            config = "auto"
        elif (ctx.depth or "").lower() == "quick":
            config = "p/security-audit"

        argv = (
            binary,
            "scan",
            "--json",
            "--quiet",
            "--config",
            config,
            "--metrics=off",
            primary,
            *paths[1:],
        )
        return CommandSpec(
            argv=argv,
            cwd=primary if Path(primary).is_dir() else str(Path(primary).parent),
            timeout_seconds=900.0 if (ctx.depth or "").lower() == "deep" else 600.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        text = (artifacts.stdout or "").strip()
        if not text:
            # Sometimes JSON lands in stderr when quiet fails
            text = (artifacts.stderr or "").strip()
        if not text:
            return {"results": [], "exit_code": artifacts.exit_code}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try last JSON object in stream
            start = text.find("{")
            if start < 0:
                return {"results": [], "parse_error": "not json", "exit_code": artifacts.exit_code}
            try:
                data = json.loads(text[start:])
            except json.JSONDecodeError as exc:
                return {"results": [], "parse_error": str(exc), "exit_code": artifacts.exit_code}
        if not isinstance(data, dict):
            return {"results": [], "parse_error": "unexpected root", "exit_code": artifacts.exit_code}
        data.setdefault("exit_code", artifacts.exit_code)
        return data

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for item in parsed.get("results") or []:
            if not isinstance(item, dict):
                continue
            check_id = str(item.get("check_id") or "unknown")
            path = str(item.get("path") or "")
            start = item.get("start") or {}
            line = start.get("line") if isinstance(start, dict) else None
            extra = item.get("extra") or {}
            severity_raw = str(extra.get("severity") or "INFO").upper()
            severity = _SEV_MAP.get(severity_raw, "info")
            message = str(extra.get("message") or check_id)
            title = f"{check_id}: {message}"[:512]
            loc = f"{path}:{line}" if line is not None else path
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    category="sast.semgrep",
                    fingerprint_parts=("semgrep", check_id, path, str(line or 0)),
                    raw_ref=loc or check_id,
                    evidence=[
                        {
                            "kind": "code_location",
                            "path_or_blob_ref": loc or path or check_id,
                        }
                    ],
                    meta={"check_id": check_id, "path": path, "line": line},
                )
            )
        return findings
