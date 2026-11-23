"""Phase 5 adapters — ZAP / Nuclei parse/normalize from fixtures; Active-Gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.findings.fingerprint import fingerprint_for
from app.process.manager import CommandSpec
from app.scanners.base import ParseArtifacts, ScanContext
from app.scanners.nuclei import NucleiAdapter
from app.scanners.zap import ZapAdapter
from app.db.models import ScopeEntryType
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


def test_zap_parse_normalize_fixture():
    adapter = ZapAdapter()
    raw = (FIXTURES / "zap" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=0))
    assert len(parsed["alerts"]) == 3
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 3
    assert all(f.category == "web.zap" for f in findings)
    sevs = {f.severity for f in findings}
    assert "low" in sevs
    assert "medium" in sevs
    assert "info" in sevs
    fp_a = fingerprint_for("zap", findings[0].fingerprint_parts)
    fp_b = fingerprint_for("zap", findings[0].fingerprint_parts)
    assert fp_a == fp_b


def test_zap_build_command_baseline():
    adapter = ZapAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.url, value="https://example.test")],
        depth="standard",
        options={"_binary": "zap-baseline.py"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert isinstance(spec, CommandSpec)
    assert spec.argv[0] == "zap-baseline.py"
    assert "-t" in spec.argv
    assert "https://example.test" in spec.argv
    assert "-J" in spec.argv
    assert (ctx.options or {}).get("zap_mode") == "baseline"


def test_zap_build_command_domain_to_https():
    adapter = ZapAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.domain, value="lab.example.test")],
        options={"_binary": "zap-baseline.py"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert "https://lab.example.test" in spec.argv


def test_zap_active_requires_gate():
    adapter = ZapAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.url, value="https://example.test")],
        depth="deep",
        options={"_binary": "zap-full-scan.py", "active_tests_enabled": False},
        work_dir=Path("/tmp"),
    )
    with pytest.raises(ValueError, match="Active-Gate|active_tests"):
        adapter.build_command(ctx)


def test_zap_active_with_gate():
    adapter = ZapAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.url, value="https://example.test")],
        depth="deep",
        options={"_binary": "zap-full-scan.py", "active_tests_enabled": True},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert "zap-full-scan.py" in spec.argv[0] or spec.argv[0].endswith("zap-full-scan.py")
    assert (ctx.options or {}).get("zap_mode") == "active"


def test_nuclei_parse_normalize_filters_exploit():
    adapter = NucleiAdapter()
    raw = (FIXTURES / "nuclei" / "sample.jsonl").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=1))
    assert len(parsed["events"]) == 4  # raw events include exploit line
    findings = adapter.normalize_findings(parsed, _ctx())
    # exploit-tagged event dropped
    assert len(findings) == 3
    assert all(f.category == "web.nuclei" for f in findings)
    assert all("exploit" not in (f.meta.get("tags") or []) for f in findings)
    titles = " ".join(f.title for f in findings)
    assert "Dangerous Exploit" not in titles


def test_nuclei_build_command_controlled_tags():
    adapter = NucleiAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.url, value="https://example.test")],
        depth="standard",
        options={"_binary": "nuclei"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "nuclei"
    assert "-u" in spec.argv
    assert "https://example.test" in spec.argv
    assert "-tags" in spec.argv
    tags_idx = spec.argv.index("-tags")
    tags = spec.argv[tags_idx + 1]
    assert "tech" in tags
    assert "misconfig" in tags
    assert "-exclude-tags" in spec.argv
    excl = spec.argv[spec.argv.index("-exclude-tags") + 1]
    assert "exploit" in excl
    assert "dos" in excl
    assert "-disable-update-check" in spec.argv
    # No blank uncontrolled template path
    assert "-t" not in spec.argv


def test_nuclei_deep_tags_expand_with_gate():
    adapter = NucleiAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.8")],
        depth="deep",
        options={"_binary": "nuclei", "active_tests_enabled": True},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    tags = spec.argv[spec.argv.index("-tags") + 1]
    assert "cve" in tags
    assert "panel" in tags


@pytest.mark.asyncio
async def test_phase5_not_installed_shape():
    for adapter in (ZapAdapter(), NucleiAdapter()):
        info = await adapter.check_installation()
        assert info.status.value in {"installed", "not_installed", "error", "unknown"}
        if info.status.value == "not_installed":
            assert info.message
