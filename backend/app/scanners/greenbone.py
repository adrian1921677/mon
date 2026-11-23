"""
Greenbone / OpenVAS adapter — Phase 7 CLI integration.

Runs live GMP scans via ``gvm-cli`` (gvm-tools) through
``python -m app.scanners.runners.gvm_scan``. Active-Gate required.
Parses OpenVAS/Greenbone XML reports into normalized findings.
Never invents findings when the tool is missing.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

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
from app.scope.types import ScopeTarget

_VERSION_RE = re.compile(r"([\d.]+)")

_THREAT = {
    "log": "info",
    "debug": "info",
    "false positive": "info",
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class GreenboneAdapter(CliScannerAdapter):
    scanner_id = "greenbone"
    display_name = "Greenbone / OpenVAS"
    description = (
        "Network vulnerability management via GMP (gvm-cli / Docker). "
        "Active-Gate required — never invents findings."
    )
    capabilities = frozenset({Capability.network})
    preferred_runtime = RuntimeKind.docker
    is_active = True
    integration_phase = 7
    binary_names = ("gvm-cli", "gvm-script")
    accepted_target_types = frozenset(
        {ScopeEntryType.ip, ScopeEntryType.cidr, ScopeEntryType.domain}
    )
    install_hint = (
        "Install gvm-tools (`pip install gvm-tools`) so `gvm-cli` is on PATH, "
        "and run Greenbone Community Edition (Docker). "
        "Set HCK_GVM_PASSWORD (+ optional HCK_GVM_SOCKET / HCK_GREENBONE_DOCKER_EXEC). "
        "See scanners/docs/greenbone.md."
    )
    version_args = ("--version",)
    version_regex = _VERSION_RE
    success_exit_codes = frozenset({0})

    async def check_installation(self) -> InstallationInfo:
        info = probe_binaries(
            self.binary_names,
            runtime=self.preferred_runtime,
            hint=self.install_hint,
        )
        if info.status is InstallationStatus.installed:
            return info
        # Docker-exec path: docker present + container name configured.
        import os

        container = (os.environ.get("HCK_GREENBONE_DOCKER_EXEC") or "").strip()
        docker = shutil.which("docker")
        if container and docker:
            return InstallationInfo(
                status=InstallationStatus.installed,
                path_or_runtime=RuntimeKind.docker.value,
                binary_path=docker,
                message=f"docker exec path configured ({container})",
                meta={"binary": "docker", "container": container},
            )
        return info

    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for target in ctx.targets:
            if not self.validate_target(target).allowed:
                continue
            value = target.value.strip()
            if value:
                hosts.append(value)
        return hosts

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        hosts = self._hosts(ctx)
        if not hosts:
            raise ValueError("greenbone: no compatible ip/cidr/domain targets")

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_xml = work / f"greenbone-{ctx.task_id}.xml"
        depth = (ctx.depth or "standard").lower()
        if depth not in {"quick", "standard", "deep"}:
            depth = "standard"

        # Ensure Active-Gate was honored at scan create; defense in depth.
        if not (ctx.options or {}).get("active_tests_enabled"):
            raise ValueError(
                "greenbone: Active-Gate required (security.active_tests_enabled)"
            )

        argv = (
            sys.executable,
            "-m",
            "app.scanners.runners.gvm_scan",
            "--targets",
            ",".join(hosts),
            "--out",
            str(out_xml),
            "--depth",
            depth,
        )
        timeout = 360.0 if depth == "quick" else 2400.0 if depth == "deep" else 1200.0
        ctx.options = {
            **(ctx.options or {}),
            "greenbone_xml": str(out_xml),
            "greenbone_hosts": hosts,
            "greenbone_depth": depth,
        }
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=timeout,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
            sensitive_flags=(
                "--password",
                "--token",
                "--api-key",
                "-p",
                "--gmp-password",
            ),
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        xml_path = artifacts.files.get("greenbone_xml")
        raw = ""
        if xml_path and xml_path.is_file():
            raw = xml_path.read_text(encoding="utf-8", errors="replace")
        elif "<report" in (artifacts.stdout or "") or "<result" in (artifacts.stdout or ""):
            raw = artifacts.stdout
        if not raw.strip():
            return {
                "results": [],
                "raw_empty": True,
                "exit_code": artifacts.exit_code,
                "stderr": (artifacts.stderr or "")[:500],
            }
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            return {
                "results": [],
                "parse_error": str(exc),
                "exit_code": artifacts.exit_code,
            }

        results: list[dict[str, Any]] = []
        for el in root.iter():
            if el.tag != "result" and not el.tag.endswith("}result"):
                continue
            # Skip nested wrappers without NVT
            nvt = el.find("nvt")
            if nvt is None:
                for child in el:
                    if child.tag == "nvt" or child.tag.endswith("}nvt"):
                        nvt = child
                        break
            name_el = el.find("name")
            threat_el = el.find("threat")
            severity_el = el.find("severity")
            host_el = el.find("host")
            port_el = el.find("port")
            desc_el = el.find("description")

            oid = ""
            nvt_name = ""
            if nvt is not None:
                oid = nvt.get("oid") or ""
                n_el = nvt.find("name")
                if n_el is not None and n_el.text:
                    nvt_name = n_el.text.strip()

            title = ""
            if name_el is not None and name_el.text:
                title = name_el.text.strip()
            elif nvt_name:
                title = nvt_name
            if not title and not oid:
                continue

            threat = (threat_el.text or "medium").strip().lower() if threat_el is not None else "medium"
            # Skip pure log noise unless explicitly wanted
            if threat in {"log", "debug", "false positive"}:
                continue

            host = ""
            if host_el is not None:
                host = (host_el.text or "").strip() or host_el.get("ip") or ""
            port = (port_el.text or "").strip() if port_el is not None else ""
            desc = (desc_el.text or "").strip() if desc_el is not None else ""
            sev_score = (severity_el.text or "").strip() if severity_el is not None else ""

            results.append(
                {
                    "oid": oid,
                    "title": title,
                    "threat": threat,
                    "severity_score": sev_score,
                    "host": host,
                    "port": port,
                    "description": desc[:2000],
                    "nvt_name": nvt_name,
                }
            )
        return {"results": results, "exit_code": artifacts.exit_code}

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for item in parsed.get("results") or []:
            if not isinstance(item, dict):
                continue
            threat = str(item.get("threat") or "medium").lower()
            severity = _THREAT.get(threat, "medium")
            # Prefer CVSS-ish score for critical bump
            try:
                score = float(item.get("severity_score") or 0)
                if score >= 9.0:
                    severity = "critical"
                elif score >= 7.0 and severity not in {"critical"}:
                    severity = "high"
            except (TypeError, ValueError):
                pass
            oid = str(item.get("oid") or "unknown")
            host = str(item.get("host") or "")
            port = str(item.get("port") or "")
            title = str(item.get("title") or item.get("nvt_name") or oid)[:512]
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    category="network.greenbone",
                    fingerprint_parts=("greenbone", oid, host, port),
                    raw_ref=f"greenbone:{oid}:{host}:{port}",
                    evidence=[
                        {
                            "kind": "openvas_result",
                            "path_or_blob_ref": (
                                f"oid={oid} host={host} port={port} threat={threat}"
                            ).strip(),
                        }
                    ],
                    meta={
                        "oid": oid,
                        "host": host,
                        "port": port,
                        "threat": threat,
                        "severity_score": item.get("severity_score"),
                        "description": item.get("description"),
                    },
                )
            )
        return findings
