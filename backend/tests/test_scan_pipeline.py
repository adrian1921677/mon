"""Scan pipeline stub — ScopeEngine + ProcessManager + Active-Gate."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import Finding, ScanStatus
from app.db.session import get_db
from app.scope.active_gate import SETTING_ACTIVE_TESTS


def _create_project(client: TestClient) -> str:
    res = client.post("/api/v1/projects", json={"name": "Scan Lab", "description": "t"})
    assert res.status_code == 201
    return res.json()["id"]


def _add_ip_scope(client: TestClient, project_id: str, value: str = "10.0.0.5") -> None:
    res = client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"type": "ip", "value": value, "meta_json": {}},
    )
    assert res.status_code == 201, res.text


def _db_session(client: TestClient) -> Session:
    gen = client.app.dependency_overrides[get_db]()
    return next(gen)


def test_scan_rejects_echo_without_test_flag(client: TestClient):
    pid = _create_project(client)
    _add_ip_scope(client, pid)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["echo"], "depth": "quick"},
    )
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert detail.get("test_only") is True or "test-only" in str(detail).lower()


def test_scan_nmap_missing_or_runs_without_fake_findings(client: TestClient):
    """Nmap: not installed → failed; if installed may complete — never invents findings."""
    pid = _create_project(client)
    _add_ip_scope(client, pid)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["nmap"], "depth": "quick"},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["status"] in {"failed", "completed"}
    assert len(body["tasks"]) == 1
    task = body["tasks"][0]
    assert task["scanner_id"] == "nmap"
    assert task["status"] in {"failed", "completed"}
    assert task["log_path"]
    log = task["log_path"].lower()
    if task["status"] == "failed":
        assert (
            "not installed" in log
            or "phase" in log
            or "failed" in log
            or "error" in log
            or "timeout" in log
        )

    # No findings when binary missing; if nmap ran against 10.0.0.5 results may exist —
    # never assert invented rows when status failed due to missing install.
    if "not installed" in log:
        db = _db_session(client)
        assert db.query(Finding).filter(Finding.project_id == pid).count() == 0


def test_active_gate_blocks_greenbone(client: TestClient):
    pid = _create_project(client)
    _add_ip_scope(client, pid)
    client.put(
        f"/api/v1/settings/{SETTING_ACTIVE_TESTS}",
        json={"value_json": False},
    )
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["greenbone"], "depth": "standard"},
    )
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "active" in str(detail).lower()


def test_active_gate_allows_greenbone_when_enabled(client: TestClient):
    pid = _create_project(client)
    _add_ip_scope(client, pid)
    client.put(
        f"/api/v1/settings/{SETTING_ACTIVE_TESTS}",
        json={"value_json": True},
    )
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["greenbone"], "depth": "standard"},
    )
    assert res.status_code == 201, res.text
    task = res.json()["tasks"][0]
    assert task["status"] == "failed"  # not installed / not implemented — no fake findings


def test_echo_pipeline_with_test_flag(client: TestClient):
    pid = _create_project(client)
    _add_ip_scope(client, pid)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={
            "scanner_ids": ["echo"],
            "depth": "quick",
            "allow_test_adapters": True,
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    task = body["tasks"][0]
    assert task["scanner_id"] == "echo"
    assert task["status"] == ScanStatus.completed.value
    db = _db_session(client)
    assert db.query(Finding).count() == 0


def test_scan_requires_scope(client: TestClient):
    pid = _create_project(client)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["nmap"]},
    )
    assert res.status_code == 400


def test_scan_incompatible_target(client: TestClient):
    pid = _create_project(client)
    res = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "path", "value": "/tmp/repo", "meta_json": {}},
    )
    assert res.status_code == 201
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["nmap"]},
    )
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "compatible" in str(detail).lower() or "compatible" in str(detail.get("message", "")).lower()


def test_list_scans(client: TestClient):
    pid = _create_project(client)
    res = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "path", "value": "/tmp/code", "meta_json": {}},
    )
    assert res.status_code == 201
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["gitleaks"]},
    )
    assert res.status_code == 201
    listed = client.get(f"/api/v1/projects/{pid}/scans")
    assert listed.status_code == 200
    assert len(listed.json()) >= 1


def _add_url_scope(
    client: TestClient,
    project_id: str,
    value: str = "http://10.20.30.40/",
) -> None:
    """Use an IP-literal URL so CI does not depend on public DNS."""
    res = client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={"type": "url", "value": value, "meta_json": {}},
    )
    assert res.status_code == 201, res.text


def test_scan_zap_missing_or_runs_without_fake_findings(client: TestClient):
    pid = _create_project(client)
    _add_url_scope(client, pid)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["zap"], "depth": "standard"},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["status"] in {"failed", "completed"}
    task = body["tasks"][0]
    assert task["scanner_id"] == "zap"
    assert task["status"] in {"failed", "completed"}
    assert task["log_path"]
    if "not installed" in (task["log_path"] or "").lower():
        db = _db_session(client)
        assert db.query(Finding).filter(Finding.project_id == pid).count() == 0


def test_scan_nuclei_missing_or_runs_without_fake_findings(client: TestClient):
    pid = _create_project(client)
    _add_url_scope(client, pid)
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["nuclei"], "depth": "quick"},
    )
    assert res.status_code == 201, res.text
    task = res.json()["tasks"][0]
    assert task["scanner_id"] == "nuclei"
    assert task["status"] in {"failed", "completed"}
    assert task["log_path"]
    if "not installed" in (task["log_path"] or "").lower():
        db = _db_session(client)
        assert db.query(Finding).filter(Finding.project_id == pid).count() == 0


def test_zap_deep_without_gate_fails_task(client: TestClient):
    """Baseline adapter is not class-active; deep still needs Active-Gate in build_command."""
    pid = _create_project(client)
    _add_url_scope(client, pid)
    client.put(
        f"/api/v1/settings/{SETTING_ACTIVE_TESTS}",
        json={"value_json": False},
    )
    res = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"scanner_ids": ["zap"], "depth": "deep"},
    )
    assert res.status_code == 201, res.text
    task = res.json()["tasks"][0]
    assert task["scanner_id"] == "zap"
    # Missing binary OR Active-Gate denial — both fail without fake findings
    assert task["status"] == "failed"
    log = (task["log_path"] or "").lower()
    assert (
        "active" in log
        or "not installed" in log
        or "gate" in log
        or "active_tests" in log
    )
    db = _db_session(client)
    assert db.query(Finding).filter(Finding.project_id == pid).count() == 0
