"""
Trivy adapter — Phase 4 CLI integration.

Filesystem / repo scan on local path scopes. JSON to stdout.
Defaults: ``trivy fs`` with exit-code 0 so findings are carried via JSON, not process failure.
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

_VERSION_RE = re.compile(r"Version:\s*([\d.]+)", re.IGNORECASE)

_SEV = {
    "UNKNOWN": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class TrivyAdapter(CliScannerAdapter):
    scanner_id = "trivy"
    display_name = "Trivy"
    description = "Vulnerability / misconfiguration scanner for local paths."
    capabilities = frozenset({Capability.code})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("trivy",)
    accepted_target_types = frozenset({ScopeEntryType.path})
    install_hint = "Install Trivy binary (or WSL/Docker)."
    version_args = ("--version",)
    version_regex = _VERSION_RE
    success_exit_codes = frozenset({0, 1})

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        paths = [t.value for t in ctx.targets if self.validate_target(t).allowed]
        if not paths:
            raise ValueError("trivy: no path targets")
        primary = str(Path(paths[0]).expanduser())

        depth = (ctx.depth or "standard").lower()
        severity = "HIGH,CRITICAL" if depth == "quick" else "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
        scanners = "vuln" if depth == "quick" else "vuln,misconfig,secret"

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_json = work / f"trivy-{ctx.task_id}.json"

        argv = (
            binary,
            "fs",
            "--format",
            "json",
            "--output",
            str(out_json),
            "--severity",
            severity,
            "--scanners",
            scanners,
            "--exit-code",
            "0",
            "--quiet",
            primary,
        )
        ctx.options = {**(ctx.options or {}), "trivy_json": str(out_json)}
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=900.0 if depth == "deep" else 600.0,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("trivy_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace")
        elif (artifacts.stdout or "").strip().startswith("{"):
            text = artifacts.stdout
        if not text.strip():
            return {"Results": [], "exit_code": artifacts.exit_code}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return {"Results": [], "parse_error": str(exc), "exit_code": artifacts.exit_code}
        if not isinstance(data, dict):
            return {"Results": [], "parse_error": "unexpected root", "exit_code": artifacts.exit_code}
        data.setdefault("exit_code", artifacts.exit_code)
        return data

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for result in parsed.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or "")
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("VulnerabilityID") or vuln.get("VulnerabilityID") or "unknown")
                pkg = str(vuln.get("PkgName") or "")
                sev = _SEV.get(str(vuln.get("Severity") or "UNKNOWN").upper(), "info")
                title_raw = str(vuln.get("Title") or vid)
                title = f"{vid}: {title_raw} ({pkg})" if pkg else f"{vid}: {title_raw}"
                findings.append(
                    NormalizedFinding(
                        title=title[:512],
                        severity=sev,
                        category="vuln.trivy",
                        fingerprint_parts=("trivy", "vuln", vid, pkg, target),
                        raw_ref=f"{target}:{vid}:{pkg}",
                        evidence=[
                            {
                                "kind": "vulnerability",
                                "path_or_blob_ref": f"{target} {vid} {pkg}".strip(),
                            }
                        ],
                        meta={"vulnerability_id": vid, "pkg": pkg, "target": target},
                    )
                )
            for mis in result.get("Misconfigurations") or []:
                if not isinstance(mis, dict):
                    continue
                mid = str(mis.get("ID") or mis.get("AvdID") or "misconfig")
                sev = _SEV.get(str(mis.get("Severity") or "UNKNOWN").upper(), "info")
                title = str(mis.get("Title") or mid)
                findings.append(
                    NormalizedFinding(
                        title=f"{mid}: {title}"[:512],
                        severity=sev,
                        category="misconfig.trivy",
                        fingerprint_parts=("trivy", "misconfig", mid, target),
                        raw_ref=f"{target}:{mid}",
                        evidence=[{"kind": "misconfig", "path_or_blob_ref": f"{target} {mid}"}],
                        meta={"id": mid, "target": target},
                    )
                )
            for secret in result.get("Secrets") or []:
                if not isinstance(secret, dict):
                    continue
                rule = str(secret.get("RuleID") or "secret")
                sev = _SEV.get(str(secret.get("Severity") or "UNKNOWN").upper(), "high")
                title = str(secret.get("Title") or rule)
                loc = str(secret.get("StartLine") or "")
                findings.append(
                    NormalizedFinding(
                        title=f"Secret: {title}"[:512],
                        severity=sev,
                        category="secret.trivy",
                        fingerprint_parts=("trivy", "secret", rule, target, loc),
                        raw_ref=f"{target}:{rule}:{loc}",
                        evidence=[
                            {
                                "kind": "secret_location",
                                "path_or_blob_ref": f"{target}:{loc} ({rule})",
                            }
                        ],
                        meta={"rule": rule, "target": target, "line": loc},
                    )
                )
        return findings
