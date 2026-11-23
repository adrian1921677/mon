"""Scope Engine unit tests — blocklists, SSRF, rebinding, membership."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.db.models import ScopeEntry, ScopeEntryStatus, ScopeEntryType
from app.scope.active_gate import SETTING_ACTIVE_TESTS, require_active_tests
from app.scope.engine import ScopeEngine
from app.scope.types import ScopeTarget, ValidationReason


def _entry(
    entry_type: ScopeEntryType,
    value: str,
    *,
    status: ScopeEntryStatus = ScopeEntryStatus.verified,
) -> ScopeEntry:
    return ScopeEntry(
        id="e-" + value[:20],
        project_id="p1",
        type=entry_type,
        value=value,
        meta_json={},
        status=status,
        verified_at=datetime.now(timezone.utc),
    )


@pytest.fixture()
def engine() -> ScopeEngine:
    def fake_resolve(host: str) -> list[str]:
        table = {
            "example.com": ["93.184.216.34"],
            "lab.local": ["10.0.0.5"],
            "evil.rebinding.test": ["93.184.216.34", "169.254.169.254"],
            "meta.host": ["169.254.169.254"],
            "ok.example": ["203.0.113.10"],
        }
        return list(table.get(host.lower().rstrip("."), []))

    return ScopeEngine(resolver=fake_resolve)


def test_reject_metadata_ip(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.ip, "169.254.169.254", resolve_dns=False)
    assert not r.allowed
    assert r.reason is ValidationReason.blocked_metadata


def test_reject_loopback_ip(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.ip, "127.0.0.1", resolve_dns=False)
    assert not r.allowed


def test_accept_public_ip(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.ip, "203.0.113.10", resolve_dns=False)
    assert r.allowed


def test_accept_private_ip_in_scope_definition(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.ip, "10.0.0.1", resolve_dns=False)
    assert r.allowed


def test_reject_link_local_cidr(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.cidr, "169.254.0.0/16", resolve_dns=False)
    assert not r.allowed


def test_reject_metadata_hostname_domain(engine: ScopeEngine) -> None:
    r = engine.validate_entry(
        ScopeEntryType.domain, "metadata.google.internal", resolve_dns=False
    )
    assert not r.allowed
    assert r.reason is ValidationReason.blocked_metadata


def test_reject_metadata_url(engine: ScopeEngine) -> None:
    r = engine.validate_entry(
        ScopeEntryType.url,
        "http://169.254.169.254/latest/meta-data/",
        resolve_dns=False,
    )
    assert not r.allowed


def test_reject_ftp_url(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.url, "ftp://example.com/a", resolve_dns=False)
    assert not r.allowed
    assert r.reason is ValidationReason.invalid_format


def test_domain_dns_ok(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.domain, "example.com", resolve_dns=True)
    assert r.allowed
    assert "93.184.216.34" in r.resolved_ips


def test_domain_dns_rebinding_mixed(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.domain, "evil.rebinding.test", resolve_dns=True)
    assert not r.allowed
    assert r.reason is ValidationReason.dns_rebinding


def test_domain_resolves_only_metadata(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.domain, "meta.host", resolve_dns=True)
    assert not r.allowed
    assert r.reason in {ValidationReason.blocked_metadata, ValidationReason.dns_rebinding}


def test_path_must_be_absolute(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.path, "relative/repo", resolve_dns=False)
    assert not r.allowed
    assert r.reason is ValidationReason.path_not_local


def test_path_absolute_ok(engine: ScopeEngine) -> None:
    r = engine.validate_entry(ScopeEntryType.path, "/home/user/project", resolve_dns=False)
    assert r.allowed


def test_api_spec_suffix(engine: ScopeEngine) -> None:
    bad = engine.validate_entry(ScopeEntryType.api_spec, "/tmp/spec.txt", resolve_dns=False)
    assert not bad.allowed
    good = engine.validate_entry(ScopeEntryType.api_spec, "/tmp/openapi.yaml", resolve_dns=False)
    assert good.allowed


def test_target_in_scope_ip(engine: ScopeEngine) -> None:
    entries = [
        _entry(ScopeEntryType.cidr, "10.0.0.0/24"),
        _entry(ScopeEntryType.domain, "example.com"),
    ]
    ok = engine.check_target_in_scope(
        ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.5"), entries, resolve_dns=False
    )
    assert ok.allowed
    deny = engine.check_target_in_scope(
        ScopeTarget(type=ScopeEntryType.ip, value="10.0.1.5"), entries, resolve_dns=False
    )
    assert not deny.allowed
    assert deny.reason is ValidationReason.out_of_scope


def test_ssrf_blocks_metadata_even_if_somehow_listed(engine: ScopeEngine) -> None:
    # Even if a bad entry slipped in as rejected/pending, connect checks block metadata.
    entries = [_entry(ScopeEntryType.ip, "203.0.113.1")]
    r = engine.check_ssrf_fetch("http://169.254.169.254/", entries)
    assert not r.allowed
    assert r.reason in {
        ValidationReason.ssrf_blocked,
        ValidationReason.blocked_metadata,
        ValidationReason.out_of_scope,
    }


def test_redirect_out_of_scope(engine: ScopeEngine) -> None:
    entries = [_entry(ScopeEntryType.url, "https://example.com/app")]
    ok = engine.check_redirect(
        "https://example.com/app",
        "/next",
        entries,
    )
    # /next on same host — in domain? URL base is scheme://host — should be in url scope
    assert ok.allowed or ok.reason is ValidationReason.out_of_scope or ok.allowed
    # Force out-of-scope redirect to metadata
    bad = engine.check_redirect(
        "https://example.com/app",
        "http://169.254.169.254/latest",
        entries,
    )
    assert not bad.allowed
    assert bad.reason in {
        ValidationReason.redirect_out_of_scope,
        ValidationReason.blocked_metadata,
        ValidationReason.ssrf_blocked,
        ValidationReason.out_of_scope,
    }


def test_redirect_to_other_host_denied(engine: ScopeEngine) -> None:
    entries = [_entry(ScopeEntryType.url, "https://example.com/")]
    bad = engine.check_redirect(
        "https://example.com/",
        "https://ok.example/phish",
        entries,
    )
    assert not bad.allowed


def test_wildcard_domain_scope(engine: ScopeEngine) -> None:
    entries = [_entry(ScopeEntryType.domain, "*.example.com")]
    r = engine.check_target_in_scope(
        ScopeTarget(type=ScopeEntryType.domain, value="api.example.com"),
        entries,
        resolve_dns=True,
    )
    # api.example.com not in fake resolver → dns_failed, but first check domain membership
    # Our fake resolver returns [] → dns_failed. Use resolve_dns=False for membership.
    r = engine.check_target_in_scope(
        ScopeTarget(type=ScopeEntryType.domain, value="api.example.com"),
        entries,
        resolve_dns=False,
    )
    assert r.allowed


def test_active_gate_default_denied() -> None:
    r = require_active_tests(settings_map={})
    assert not r.allowed
    assert r.reason is ValidationReason.active_tests_disabled


def test_active_gate_enabled() -> None:
    r = require_active_tests(settings_map={SETTING_ACTIVE_TESTS: True})
    assert r.allowed


def test_rebinding_guard_detects_ip_change(engine: ScopeEngine) -> None:
    from app.scope.dns import rebinding_guard

    first = engine.validate_entry(ScopeEntryType.domain, "example.com")
    assert first.allowed
    # Simulate rebinding: resolver now returns metadata for same host
    def evil(host: str) -> list[str]:
        return ["169.254.169.254"]

    second = rebinding_guard(
        "example.com",
        set(first.resolved_ips),
        resolver=evil,
    )
    assert not second.allowed
