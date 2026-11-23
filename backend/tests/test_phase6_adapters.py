"""Phase 6 adapters — Schemathesis parse/normalize from fixtures; Active-Gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db.models import ScopeEntryType
from app.findings.fingerprint import fingerprint_for
from app.process.manager import CommandSpec
from app.scanners.base import ParseArtifacts, ScanContext
from app.scanners.schemathesis import SchemathesisAdapter
from app.scope.types import ScopeTarget

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(**kwargs) -> ScanContext:
    base = dict(
        project_id="p1",
        scan_id="s1",
        task_id="t1",
        targets=[],
        depth="standard",
        options={},
    )
    base.update(kwargs)
    return ScanContext(**base)


def test_schemathesis_parse_normalize_fixture():
    adapter = SchemathesisAdapter()
    raw = (FIXTURES / "schemathesis" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=1))
    assert len(parsed["failures"]) == 3
    assert len(parsed["errors"]) == 1
    findings = adapter.normalize_findings(
        parsed,
        _ctx(options={"schemathesis_location": "/tmp/openapi.yaml", "schemathesis_base_url": "https://api.example.test"}),
    )
    assert len(findings) == 4  # 3 failures + 1 error
    assert all(f.category == "api.schemathesis" for f in findings)
    sevs = {f.severity for f in findings}
    assert "critical" in sevs
    assert "medium" in sevs
    assert "high" in sevs
    fp_a = fingerprint_for("schemathesis", findings[0].fingerprint_parts)
    fp_b = fingerprint_for("schemathesis", findings[0].fingerprint_parts)
    assert fp_a == fp_b
    titles = " ".join(f.title for f in findings)
    assert "Server error" in titles
    assert "Schemathesis error" in titles


def test_schemathesis_build_command_file_spec_needs_url():
    adapter = SchemathesisAdapter()
    ctx = _ctx(
        targets=[
            ScopeTarget(type=ScopeEntryType.api_spec, value="/opt/demo/openapi.yaml"),
        ],
        options={"_binary": "schemathesis"},
        work_dir=Path("/tmp"),
    )
    with pytest.raises(ValueError, match="requires an in-scope url"):
        adapter.build_command(ctx)


def test_schemathesis_build_command_standard_defaults():
    adapter = SchemathesisAdapter()
    ctx = _ctx(
        targets=[
            ScopeTarget(type=ScopeEntryType.api_spec, value="/opt/demo/openapi.yaml"),
            ScopeTarget(type=ScopeEntryType.url, value="https://api.example.test"),
        ],
        depth="standard",
        options={"_binary": "schemathesis"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert isinstance(spec, CommandSpec)
    assert spec.argv[0] == "schemathesis"
    assert "run" in spec.argv
    assert "/opt/demo/openapi.yaml" in spec.argv
    assert "--url" in spec.argv
    assert "https://api.example.test" in spec.argv
    assert "--report" in spec.argv
    assert "json" in spec.argv
    assert "--report-json-path" in spec.argv
    assert "--phases" in spec.argv
    phases = spec.argv[spec.argv.index("--phases") + 1]
    assert phases == "examples,coverage"
    assert "stateful" not in phases
    assert "fuzzing" not in phases
    mode = spec.argv[spec.argv.index("--mode") + 1]
    assert mode == "positive"
    assert (ctx.options or {}).get("schemathesis_phases") == "examples,coverage"


def test_schemathesis_build_command_http_spec_no_url_required():
    adapter = SchemathesisAdapter()
    ctx = _ctx(
        targets=[
            ScopeTarget(
                type=ScopeEntryType.api_spec,
                value="https://api.example.test/openapi.json",
            ),
        ],
        depth="quick",
        options={"_binary": "st"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "st"
    assert "https://api.example.test/openapi.json" in spec.argv
    assert "--url" not in spec.argv
    phases = spec.argv[spec.argv.index("--phases") + 1]
    assert phases == "examples"
    mode = spec.argv[spec.argv.index("--mode") + 1]
    assert mode == "positive"


def test_schemathesis_deep_enables_fuzzing():
    adapter = SchemathesisAdapter()
    ctx = _ctx(
        targets=[
            ScopeTarget(type=ScopeEntryType.api_spec, value="/opt/demo/openapi.json"),
            ScopeTarget(type=ScopeEntryType.url, value="https://lab.example.test"),
        ],
        depth="deep",
        options={"_binary": "schemathesis"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    phases = spec.argv[spec.argv.index("--phases") + 1]
    assert "fuzzing" in phases
    assert "stateful" not in phases
    mode = spec.argv[spec.argv.index("--mode") + 1]
    assert mode == "all"


def test_schemathesis_validate_target_shapes():
    adapter = SchemathesisAdapter()
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.api_spec, value="/tmp/openapi.yaml")
    ).allowed
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.url, value="https://api.example.test/openapi.json")
    ).allowed
    # Plain API base is not a primary target
    assert not adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.url, value="https://api.example.test")
    ).allowed
    assert not adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.1")
    ).allowed


@pytest.mark.asyncio
async def test_phase6_not_installed_shape():
    adapter = SchemathesisAdapter()
    info = await adapter.check_installation()
    assert info.status.value in {"installed", "not_installed", "error", "unknown"}
    if info.status.value == "not_installed":
        assert info.message
