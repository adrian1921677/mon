"""
Nuclei adapter — Phase 5 CLI integration.

Controlled templates only: allowlisted tags, hard exclude of exploit/DoS/intrusive
templates. No uncontrolled ``-t`` / blank tag runs. Never invent findings.
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
from app.scope.types import ScopeTarget

_VERSION_RE = re.compile(r"(?:Nuclei|^)\s*v?([\d.]+)", re.IGNORECASE)

# Hard denylist — never pass through even if a caller asks.
_EXCLUDE_TAGS = (
    "exploit",
    "dos",
    "ddos",
    "intrusive",
    "fuzz",
    "fuzzing",
    "bruteforce",
    "brute",
    "rce",
)

# Allowlisted tag sets by depth (comma-separated for nuclei -tags).
_TAGS_QUICK = "tech,exposure"
_TAGS_STANDARD = "tech,exposure,misconfig,vuln"
_TAGS_DEEP_SAFE = "tech,exposure,misconfig,vuln,cve,default-login"
# Deep + Active-Gate may add panel/config discovery — still no exploit/dos.
_TAGS_DEEP_ACTIVE = "tech,exposure,misconfig,vuln,cve,default-login,panel,config"

_SEV = {
    "unknown": "info",
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _as_nuclei_target(target: ScopeTarget) -> str | None:
    value = target.value.strip()
    if not value:
        return None
    if target.type is ScopeEntryType.url:
        return value
    if target.type is ScopeEntryType.domain:
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value.rstrip('/')}"
    if target.type is ScopeEntryType.ip:
        return value
    return None


class NucleiAdapter(CliScannerAdapter):
    scanner_id = "nuclei"
    display_name = "Nuclei"
    description = (
        "Template-based web/network scanner with controlled (non-exploit) template tags."
    )
    capabilities = frozenset({Capability.web, Capability.network})
    preferred_runtime = RuntimeKind.native
    # Controlled templates are risk-managed; no blanket Active-Gate for standard runs.
    is_active = False
    integration_phase = 5
    binary_names = ("nuclei",)
    accepted_target_types = frozenset(
        {ScopeEntryType.url, ScopeEntryType.domain, ScopeEntryType.ip}
    )
    install_hint = "Install Nuclei binary (GitHub releases) or via WSL: go install / package manager."
    version_args = ("-version",)
    version_regex = _VERSION_RE
    # 0 = clean, 1 = findings matched
    success_exit_codes = frozenset({0, 1})

    def _target_values(self, ctx: ScanContext) -> list[str]:
        out: list[str] = []
        for target in ctx.targets:
            if not self.validate_target(target).allowed:
                continue
            value = _as_nuclei_target(target)
            if value:
                out.append(value)
        return out

    def _tags_for(self, ctx: ScanContext) -> str:
        depth = (ctx.depth or "standard").lower()
        active = bool((ctx.options or {}).get("active_tests_enabled"))
        if depth == "quick":
            return _TAGS_QUICK
        if depth == "deep":
            return _TAGS_DEEP_ACTIVE if active else _TAGS_DEEP_SAFE
        return _TAGS_STANDARD

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        targets = self._target_values(ctx)
        if not targets:
            raise ValueError("nuclei: no compatible URL/domain/IP targets")

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_jsonl = work / f"nuclei-{ctx.task_id}.jsonl"
        tags = self._tags_for(ctx)
        exclude = ",".join(_EXCLUDE_TAGS)

        depth = (ctx.depth or "standard").lower()
        # Conservative concurrency / rate — avoid DoS-like load.
        rate = "20" if depth == "quick" else "40" if depth == "standard" else "60"
        concurrency = "5" if depth == "quick" else "10" if depth == "standard" else "15"

        # One -u per target; nuclei accepts repeated -u.
        url_args: list[str] = []
        for t in targets:
            url_args.extend(["-u", t])

        argv = (
            binary,
            *url_args,
            "-jsonl",
            "-o",
            str(out_jsonl),
            "-tags",
            tags,
            "-exclude-tags",
            exclude,
            "-rate-limit",
            rate,
            "-c",
            concurrency,
            "-disable-update-check",
            "-no-color",
            "-silent",
        )
        ctx.options = {
            **(ctx.options or {}),
            "nuclei_jsonl": str(out_jsonl),
            "nuclei_tags": tags,
        }
        timeout = 300.0 if depth == "quick" else 900.0 if depth == "deep" else 600.0
        return CommandSpec(
            argv=argv,
            cwd=str(work),
            timeout_seconds=timeout,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        jsonl_path = artifacts.files.get("nuclei_jsonl")
        text = ""
        if jsonl_path and jsonl_path.is_file():
            text = jsonl_path.read_text(encoding="utf-8", errors="replace")
        elif (artifacts.stdout or "").strip():
            text = artifacts.stdout

        events: list[dict[str, Any]] = []
        if not text.strip():
            return {"events": [], "exit_code": artifacts.exit_code, "raw_empty": True}

        # JSONL (one object per line) or a JSON array
        stripped = text.strip()
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return {"events": [], "parse_error": str(exc), "exit_code": artifacts.exit_code}
            if isinstance(data, list):
                events = [e for e in data if isinstance(e, dict)]
            return {"events": events, "exit_code": artifacts.exit_code}

        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                events.append(obj)
        return {"events": events, "exit_code": artifacts.exit_code}

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        for event in parsed.get("events") or []:
            if not isinstance(event, dict):
                continue
            template_id = str(
                event.get("template-id")
                or event.get("template_id")
                or event.get("templateID")
                or "unknown"
            )
            info = event.get("info") if isinstance(event.get("info"), dict) else {}
            name = str(info.get("name") or template_id)
            sev_raw = str(info.get("severity") or event.get("severity") or "info").lower()
            severity = _SEV.get(sev_raw, "info")
            host = str(
                event.get("host")
                or event.get("matched-at")
                or event.get("matched_at")
                or event.get("ip")
                or ""
            )
            matched = str(event.get("matched-at") or event.get("matched_at") or host)
            # Drop events whose template tags intersect denylist (defense in depth).
            tags = info.get("tags") or event.get("tags") or []
            if isinstance(tags, str):
                tag_set = {t.strip().lower() for t in tags.split(",")}
            elif isinstance(tags, list):
                tag_set = {str(t).strip().lower() for t in tags}
            else:
                tag_set = set()
            if tag_set & set(_EXCLUDE_TAGS):
                continue

            title = f"{name} ({template_id})" + (f" @ {matched}" if matched else "")
            findings.append(
                NormalizedFinding(
                    title=title[:512],
                    severity=severity,
                    category="web.nuclei",
                    fingerprint_parts=("nuclei", template_id, matched or host),
                    raw_ref=f"nuclei:{template_id}:{matched or host}",
                    evidence=[
                        {
                            "kind": "nuclei_match",
                            "path_or_blob_ref": f"{template_id} @ {matched or host}",
                        }
                    ],
                    meta={
                        "template_id": template_id,
                        "host": host,
                        "matched_at": matched,
                        "tags": sorted(tag_set),
                    },
                )
            )
        return findings
