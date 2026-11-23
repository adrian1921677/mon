"""
Nmap adapter — Phase 4 CLI integration.

Passive / low-risk defaults (TCP connect, limited ports; no NSE exploit scripts).
Output: XML via ``-oX`` into the scan work directory.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.process.manager import CommandSpec
from app.scanners.base import Capability, NormalizedFinding, ParseArtifacts, RuntimeKind, ScanContext
from app.scanners.cli_base import CliScannerAdapter
from app.db.models import ScopeEntryType

_VERSION_RE = re.compile(r"Nmap version\s+([\d.]+)", re.IGNORECASE)


class NmapAdapter(CliScannerAdapter):
    scanner_id = "nmap"
    display_name = "Nmap"
    description = "Network discovery and port scanning (TCP connect, risk-low defaults)."
    capabilities = frozenset({Capability.network})
    preferred_runtime = RuntimeKind.native
    is_active = False
    integration_phase = 4
    binary_names = ("nmap",)
    accepted_target_types = frozenset(
        {ScopeEntryType.ip, ScopeEntryType.cidr, ScopeEntryType.domain}
    )
    install_hint = "Install Nmap (Windows installer / Npcap, or WSL: apt install nmap)."
    version_args = ("--version",)
    version_regex = _VERSION_RE
    success_exit_codes = frozenset({0})

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        targets = [t.value for t in ctx.targets if self.validate_target(t).allowed]
        if not targets:
            raise ValueError("nmap: no compatible targets")

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_xml = work / f"nmap-{ctx.task_id}.xml"

        # Risk-low profiles: TCP connect only, no aggressive NSE.
        depth = (ctx.depth or "standard").lower()
        if depth == "quick":
            scan_args = ("-sn",)  # host discovery only
        elif depth == "deep":
            scan_args = ("-sT", "--top-ports", "1000", "--open")
        else:
            scan_args = ("-sT", "-F", "--open")  # standard: fast TCP ports

        argv = (
            binary,
            *scan_args,
            "-oX",
            str(out_xml),
            "--",
            *targets,
        )
        timeout = 120.0 if depth == "quick" else 600.0 if depth == "deep" else 300.0
        ctx.options = {**(ctx.options or {}), "nmap_xml": str(out_xml)}
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=timeout,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        xml_path = artifacts.files.get("nmap_xml")
        raw = ""
        if xml_path and xml_path.is_file():
            raw = xml_path.read_text(encoding="utf-8", errors="replace")
        elif artifacts.stdout.strip().startswith("<?xml") or "<nmaprun" in artifacts.stdout:
            raw = artifacts.stdout
        if not raw.strip():
            return {"hosts": [], "raw_empty": True, "exit_code": artifacts.exit_code}

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            return {"hosts": [], "parse_error": str(exc), "exit_code": artifacts.exit_code}

        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            addrs = [
                a.get("addr", "")
                for a in host.findall("address")
                if a.get("addrtype") in {"ipv4", "ipv6"}
            ]
            status_el = host.find("status")
            up = (status_el.get("state") if status_el is not None else "unknown") == "up"
            ports: list[dict[str, Any]] = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state_el = port.find("state")
                    state = state_el.get("state") if state_el is not None else ""
                    if state != "open":
                        continue
                    service_el = port.find("service")
                    ports.append(
                        {
                            "protocol": port.get("protocol") or "tcp",
                            "port": int(port.get("portid") or 0),
                            "state": state,
                            "service": (service_el.get("name") if service_el is not None else None),
                        }
                    )
            hosts.append({"addresses": addrs, "up": up, "ports": ports})
        return {"hosts": hosts, "exit_code": artifacts.exit_code}

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for host in parsed.get("hosts") or []:
            addrs = host.get("addresses") or []
            addr = addrs[0] if addrs else "unknown"
            if host.get("up") and not host.get("ports"):
                # Host discovery only (quick profile)
                findings.append(
                    NormalizedFinding(
                        title=f"Host up: {addr}",
                        severity="info",
                        category="network.host",
                        fingerprint_parts=("nmap", "host-up", addr),
                        raw_ref=f"nmap:host:{addr}",
                        evidence=[{"kind": "host", "path_or_blob_ref": addr}],
                        meta={"addresses": addrs},
                    )
                )
            for port in host.get("ports") or []:
                proto = port.get("protocol") or "tcp"
                port_no = port.get("port")
                service = port.get("service") or "unknown"
                title = f"Open port {proto}/{port_no} ({service}) on {addr}"
                findings.append(
                    NormalizedFinding(
                        title=title,
                        severity="info",
                        category="network.port",
                        fingerprint_parts=("nmap", "open-port", addr, str(proto), str(port_no)),
                        raw_ref=f"nmap:{addr}:{proto}/{port_no}",
                        evidence=[
                            {
                                "kind": "port",
                                "path_or_blob_ref": f"{addr} {proto}/{port_no} {service}",
                            }
                        ],
                        meta={"address": addr, "port": port_no, "protocol": proto, "service": service},
                    )
                )
        return findings
