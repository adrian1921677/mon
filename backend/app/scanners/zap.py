"""
OWASP ZAP adapter — Phase 5 CLI integration.

Passive-first: ``zap-baseline.py`` (or zap.sh quick) by default.
Active / full scan only when depth=deep **and** Active-Gate
(``security.active_tests_enabled``) is set — never invent findings.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from app.db.models import ScopeEntryType
from app.process.manager import CommandSpec
from app.scanners.base import Capability, NormalizedFinding, ParseArtifacts, RuntimeKind, ScanContext
from app.scanners.cli_base import CliScannerAdapter
from app.scope.types import ScopeTarget

_VERSION_RE = re.compile(r"(?:ZAP|OWASP ZAP).*?([\d.]+)", re.IGNORECASE)

_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _as_http_url(target: ScopeTarget) -> str | None:
    value = target.value.strip()
    if not value:
        return None
    if target.type is ScopeEntryType.url:
        return value
    if target.type is ScopeEntryType.domain:
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value.rstrip('/')}"
    return None


class ZapAdapter(CliScannerAdapter):
    scanner_id = "zap"
    display_name = "OWASP ZAP"
    description = "Web application security scanner — baseline/passive-first; active only with Active-Gate."
    capabilities = frozenset({Capability.web})
    preferred_runtime = RuntimeKind.native
    # Baseline is passive; active mode is gated inside build_command via options.
    is_active = False
    integration_phase = 5
    binary_names = ("zap-baseline.py", "zap-full-scan.py", "zap.sh", "zaproxy", "zap")
    accepted_target_types = frozenset({ScopeEntryType.url, ScopeEntryType.domain})
    install_hint = (
        "Install OWASP ZAP and put zap-baseline.py / zap.sh on PATH "
        "(or WSL/Docker image with ZAP scripts)."
    )
    version_args = ("-version",)
    version_regex = _VERSION_RE
    # Baseline: 0 pass, 1 warn, 2 fail thresholds — all mean the tool ran.
    success_exit_codes = frozenset({0, 1, 2})

    def _target_urls(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        for target in ctx.targets:
            if not self.validate_target(target).allowed:
                continue
            url = _as_http_url(target)
            if url:
                urls.append(url)
        return urls

    def _wants_active(self, ctx: ScanContext) -> bool:
        return (ctx.depth or "standard").lower() == "deep"

    def _active_enabled(self, ctx: ScanContext) -> bool:
        return bool((ctx.options or {}).get("active_tests_enabled"))

    def _resolve_script(self, binary: str, *, active: bool) -> str:
        name = Path(binary).name.lower()
        if active:
            if "full-scan" in name:
                return binary
            full = shutil.which("zap-full-scan.py")
            if full:
                return full
            if name in {"zap.sh", "zaproxy", "zap"}:
                return binary
            raise ValueError(
                "zap: active/full scan requires zap-full-scan.py (or zap.sh) on PATH"
            )
        if "baseline" in name:
            return binary
        baseline = shutil.which("zap-baseline.py")
        if baseline:
            return baseline
        if name in {"zap.sh", "zaproxy", "zap"} or "full-scan" in name:
            # Prefer baseline script; fall back to zap.sh quick for passive-first.
            return binary if name in {"zap.sh", "zaproxy", "zap"} else (
                shutil.which("zap-baseline.py") or binary
            )
        return binary

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        urls = self._target_urls(ctx)
        if not urls:
            raise ValueError("zap: no compatible URL/domain targets")

        wants_active = self._wants_active(ctx)
        if wants_active and not self._active_enabled(ctx):
            raise ValueError(
                "zap: active/full scan (depth=deep) requires "
                "security.active_tests_enabled=true (Active-Gate)"
            )

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_json = work / f"zap-{ctx.task_id}.json"
        primary = urls[0]
        script = self._resolve_script(binary, active=wants_active)
        script_name = Path(script).name.lower()

        if script_name.endswith(".py") or "baseline" in script_name or "full-scan" in script_name:
            # Official packaged wrappers — JSON via -J; -I ignore warn exit for persistence.
            argv: tuple[str, ...] = (
                script,
                "-t",
                primary,
                "-J",
                str(out_json),
                "-I",
            )
        else:
            # zap.sh / zaproxy — quick URL + JSON report (passive-leaning; no extra attack flags).
            argv = (
                script,
                "-cmd",
                "-quickurl",
                primary,
                "-report_json",
                str(out_json),
            )

        depth = (ctx.depth or "standard").lower()
        timeout = 300.0 if depth == "quick" else 1200.0 if wants_active else 600.0
        ctx.options = {
            **(ctx.options or {}),
            "zap_json": str(out_json),
            "zap_mode": "active" if wants_active else "baseline",
            "zap_target": primary,
        }
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=timeout,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("zap_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace").strip()
        elif (artifacts.stdout or "").strip().startswith("{"):
            text = artifacts.stdout.strip()
        if not text:
            return {"site": [], "alerts": [], "exit_code": artifacts.exit_code, "raw_empty": True}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return {
                "site": [],
                "alerts": [],
                "parse_error": str(exc),
                "exit_code": artifacts.exit_code,
            }
        if not isinstance(data, dict):
            return {
                "site": [],
                "alerts": [],
                "parse_error": "unexpected root",
                "exit_code": artifacts.exit_code,
            }

        alerts: list[dict[str, Any]] = []
        # Traditional ZAP JSON: { "site": [ { "alerts": [ ... ] } ] }
        for site in data.get("site") or []:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts") or []:
                if isinstance(alert, dict):
                    alerts.append(alert)
        # Some exporters put alerts at top level
        for alert in data.get("alerts") or []:
            if isinstance(alert, dict):
                alerts.append(alert)

        return {
            "site": data.get("site") or [],
            "alerts": alerts,
            "exit_code": artifacts.exit_code,
        }

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for alert in parsed.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            plugin = str(
                alert.get("pluginid")
                or alert.get("pluginId")
                or alert.get("alertRef")
                or alert.get("alertref")
                or "unknown"
            )
            name = str(alert.get("name") or alert.get("alert") or plugin)
            risk_raw = str(alert.get("riskcode") or alert.get("risk") or "0").strip().lower()
            severity = _RISK_MAP.get(risk_raw, _RISK_MAP.get(risk_raw.split()[0], "info"))
            cwe = str(alert.get("cweid") or alert.get("cwe") or "")
            instances = alert.get("instances") or []
            uri = ""
            if instances and isinstance(instances[0], dict):
                uri = str(instances[0].get("uri") or instances[0].get("url") or "")
            target = uri or str((ctx.options or {}).get("zap_target") or "")
            title = f"{name}" + (f" @ {uri}" if uri else "")
            findings.append(
                NormalizedFinding(
                    title=title[:512],
                    severity=severity,
                    category="web.zap",
                    fingerprint_parts=("zap", plugin, name, target),
                    raw_ref=f"zap:{plugin}:{target}",
                    evidence=[
                        {
                            "kind": "web_alert",
                            "path_or_blob_ref": f"{name} | {target or uri} | cwe={cwe}".strip(),
                        }
                    ],
                    meta={
                        "pluginid": plugin,
                        "cwe": cwe,
                        "uri": uri,
                        "riskcode": risk_raw,
                        "mode": (ctx.options or {}).get("zap_mode"),
                    },
                )
            )
        return findings
