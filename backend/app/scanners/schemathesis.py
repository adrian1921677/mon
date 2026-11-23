"""
Schemathesis adapter — Phase 6 CLI integration.

Property-based API testing from OpenAPI/API-Spec scope entries.
Active-Gate required (``is_active=True``) — requests hit the live API.
Risk-averse defaults: positive mode, limited phases/examples; fuzzing only
on depth=deep. Never invent findings.
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
from app.scope.types import ScopeTarget, ValidationReason, ValidationResult

_VERSION_RE = re.compile(r"(?:schemathesis|st)\s+(?:version\s+)?v?([\d.]+)", re.IGNORECASE)

_SEV = {
    "unknown": "info",
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Depth → phases / examples / generation mode (risk-averse ladder).
_PHASES_QUICK = "examples"
_PHASES_STANDARD = "examples,coverage"
_PHASES_DEEP = "examples,coverage,fuzzing"

_MAX_EX_QUICK = "10"
_MAX_EX_STANDARD = "25"
_MAX_EX_DEEP = "50"


def _is_http_location(value: str) -> bool:
    lower = value.lower()
    return lower.startswith("http://") or lower.startswith("https://")


def _spec_location(target: ScopeTarget) -> str | None:
    value = target.value.strip()
    if not value:
        return None
    if target.type is ScopeEntryType.api_spec:
        return value
    # URL that looks like an OpenAPI document may also serve as LOCATION.
    if target.type is ScopeEntryType.url and any(
        value.lower().endswith(suf) for suf in (".json", ".yaml", ".yml", "/openapi.json", "/swagger.json")
    ):
        return value
    return None


def _base_url(target: ScopeTarget) -> str | None:
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


class SchemathesisAdapter(CliScannerAdapter):
    scanner_id = "schemathesis"
    display_name = "Schemathesis"
    description = (
        "Property-based API testing from OpenAPI specs — Active-Gate required; "
        "risk-averse phases by default."
    )
    capabilities = frozenset({Capability.api})
    preferred_runtime = RuntimeKind.native
    # Always sends real HTTP requests → Active-Gate at scan create.
    is_active = True
    integration_phase = 6
    binary_names = ("schemathesis", "st")
    accepted_target_types = frozenset({ScopeEntryType.api_spec, ScopeEntryType.url})
    install_hint = (
        "Install Schemathesis (pip install schemathesis) so `schemathesis` or `st` "
        "is on PATH (venv recommended)."
    )
    version_args = ("--version",)
    version_regex = _VERSION_RE
    # 0 = clean, 1 = failures found (still a successful run with findings)
    success_exit_codes = frozenset({0, 1})

    def validate_target(self, target: ScopeTarget) -> ValidationResult:
        """Compatible primary target = api_spec or OpenAPI document URL (not bare API base)."""
        if not target.value.strip():
            return ValidationResult.deny(ValidationReason.invalid_format, "empty target")
        if target.type is ScopeEntryType.api_spec:
            return ValidationResult.ok(message="schemathesis api_spec ok")
        if target.type is ScopeEntryType.url and _spec_location(target):
            return ValidationResult.ok(message="schemathesis OpenAPI URL ok")
        if target.type is ScopeEntryType.url:
            # Allowed in scope as --url companion, but not a standalone primary target.
            return ValidationResult.deny(
                ValidationReason.invalid_format,
                "schemathesis needs api_spec (or OpenAPI document URL); "
                "plain URL is only used as --url with a file-based spec",
            )
        return ValidationResult.deny(
            ValidationReason.invalid_format,
            "schemathesis accepts target types: api_spec, url (OpenAPI document)",
        )

    def _spec_targets(self, ctx: ScanContext) -> list[str]:
        out: list[str] = []
        for target in ctx.targets:
            if not self.validate_target(target).allowed:
                continue
            loc = _spec_location(target)
            if loc:
                out.append(loc)
        return out

    def _url_targets(self, ctx: ScanContext) -> list[str]:
        """API base URLs from scope (url entries that are not the OpenAPI document)."""
        out: list[str] = []
        for target in ctx.targets:
            if target.type is not ScopeEntryType.url:
                continue
            if not target.value.strip():
                continue
            # Prefer plain API base URLs over OpenAPI document URLs for --url.
            if _spec_location(target):
                continue
            url = _base_url(target)
            if url:
                out.append(url)
        return out

    def _phases_for(self, ctx: ScanContext) -> str:
        depth = (ctx.depth or "standard").lower()
        if depth == "quick":
            return _PHASES_QUICK
        if depth == "deep":
            return _PHASES_DEEP
        return _PHASES_STANDARD

    def _max_examples_for(self, ctx: ScanContext) -> str:
        depth = (ctx.depth or "standard").lower()
        if depth == "quick":
            return _MAX_EX_QUICK
        if depth == "deep":
            return _MAX_EX_DEEP
        return _MAX_EX_STANDARD

    def _mode_for(self, ctx: ScanContext) -> str:
        depth = (ctx.depth or "standard").lower()
        # Negative / all only on deep (still behind Active-Gate via is_active).
        if depth == "deep":
            return "all"
        return "positive"

    def build_command(self, ctx: ScanContext) -> CommandSpec:
        binary = self._binary_from_ctx(ctx)
        specs = self._spec_targets(ctx)
        if not specs:
            raise ValueError(
                "schemathesis: no compatible api_spec (or OpenAPI URL) target in scope"
            )

        location = specs[0]
        base_urls = self._url_targets(ctx)
        # File-based schemas require an explicit API base URL.
        if not _is_http_location(location) and not base_urls:
            raise ValueError(
                "schemathesis: file-based api_spec requires an in-scope url/domain "
                "as --url (API base)"
            )

        work = ctx.work_dir or Path.cwd()
        work.mkdir(parents=True, exist_ok=True)
        out_json = work / f"schemathesis-{ctx.task_id}.json"

        depth = (ctx.depth or "standard").lower()
        phases = self._phases_for(ctx)
        max_examples = self._max_examples_for(ctx)
        mode = self._mode_for(ctx)
        workers = "1" if depth == "quick" else "2"

        argv_list: list[str] = [
            binary,
            "run",
            location,
            "--report",
            "json",
            "--report-json-path",
            str(out_json),
            "--phases",
            phases,
            "--mode",
            mode,
            "--max-examples",
            max_examples,
            "--workers",
            workers,
            "--output-sanitize",
            "true",
        ]
        if base_urls:
            argv_list.extend(["--url", base_urls[0]])

        ctx.options = {
            **(ctx.options or {}),
            "schemathesis_json": str(out_json),
            "schemathesis_location": location,
            "schemathesis_base_url": base_urls[0] if base_urls else None,
            "schemathesis_phases": phases,
            "schemathesis_mode": mode,
        }
        timeout = 180.0 if depth == "quick" else 900.0 if depth == "deep" else 480.0
        return CommandSpec(
            argv=tuple(argv_list),
            cwd=str(work),
            timeout_seconds=timeout,
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
        )

    def parse_results(self, artifacts: ParseArtifacts) -> Any:
        json_path = artifacts.files.get("schemathesis_json")
        text = ""
        if json_path and json_path.is_file():
            text = json_path.read_text(encoding="utf-8", errors="replace").strip()
        elif (artifacts.stdout or "").strip().startswith("{"):
            text = artifacts.stdout.strip()
        if not text:
            return {
                "failures": [],
                "errors": [],
                "exit_code": artifacts.exit_code,
                "raw_empty": True,
            }
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return {
                "failures": [],
                "errors": [],
                "parse_error": str(exc),
                "exit_code": artifacts.exit_code,
            }
        if not isinstance(data, dict):
            return {
                "failures": [],
                "errors": [],
                "parse_error": "unexpected root",
                "exit_code": artifacts.exit_code,
            }

        failures = [f for f in (data.get("failures") or []) if isinstance(f, dict)]
        errors = [e for e in (data.get("errors") or []) if isinstance(e, dict)]
        return {
            "failures": failures,
            "errors": errors,
            "operations": data.get("operations") if isinstance(data.get("operations"), dict) else {},
            "test_cases": data.get("test_cases") if isinstance(data.get("test_cases"), dict) else {},
            "phases": data.get("phases") if isinstance(data.get("phases"), dict) else {},
            "exit_code": data.get("exit_code", artifacts.exit_code),
            "stop_reason": data.get("stop_reason"),
            "complete": data.get("complete"),
        }

    def normalize_findings(self, parsed: Any, ctx: ScanContext) -> list[NormalizedFinding]:
        if not isinstance(parsed, dict):
            return []
        findings: list[NormalizedFinding] = []
        location = str((ctx.options or {}).get("schemathesis_location") or "")
        base = str((ctx.options or {}).get("schemathesis_base_url") or "")

        for failure in parsed.get("failures") or []:
            if not isinstance(failure, dict):
                continue
            ftype = str(failure.get("type") or failure.get("code") or "UnknownFailure")
            title_base = str(failure.get("title") or ftype)
            sev_raw = str(failure.get("severity") or "medium").lower()
            severity = _SEV.get(sev_raw, "medium")
            ops = failure.get("operations") or []
            if isinstance(ops, str):
                op_list = [ops]
            elif isinstance(ops, list):
                op_list = [str(o) for o in ops if o]
            else:
                op_list = []
            op_key = ",".join(op_list) if op_list else "*"
            count = failure.get("count")
            title = title_base
            if op_list:
                title = f"{title_base} @ {op_list[0]}" + (
                    f" (+{len(op_list) - 1})" if len(op_list) > 1 else ""
                )
            findings.append(
                NormalizedFinding(
                    title=title[:512],
                    severity=severity,
                    category="api.schemathesis",
                    fingerprint_parts=("schemathesis", ftype, op_key, location or base),
                    raw_ref=f"schemathesis:{ftype}:{op_key}",
                    evidence=[
                        {
                            "kind": "api_check_failure",
                            "path_or_blob_ref": (
                                f"{ftype} | ops={op_key} | count={count} | "
                                f"loc={location or base}"
                            ).strip(),
                        }
                    ],
                    meta={
                        "type": ftype,
                        "operations": op_list,
                        "count": count,
                        "location": location,
                        "base_url": base,
                        "phases": (ctx.options or {}).get("schemathesis_phases"),
                        "mode": (ctx.options or {}).get("schemathesis_mode"),
                    },
                )
            )

        # Schema / runtime errors (not check failures) — surface as findings too.
        for err in parsed.get("errors") or []:
            if not isinstance(err, dict):
                continue
            etype = str(err.get("type") or err.get("code") or "Error")
            message = str(err.get("message") or err.get("title") or etype)
            findings.append(
                NormalizedFinding(
                    title=f"Schemathesis error: {message}"[:512],
                    severity="high",
                    category="api.schemathesis",
                    fingerprint_parts=("schemathesis", "error", etype, location or base),
                    raw_ref=f"schemathesis:error:{etype}",
                    evidence=[
                        {
                            "kind": "api_run_error",
                            "path_or_blob_ref": f"{etype}: {message}",
                        }
                    ],
                    meta={
                        "type": etype,
                        "message": message,
                        "location": location,
                        "base_url": base,
                    },
                )
            )
        return findings
