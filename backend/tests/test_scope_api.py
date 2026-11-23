"""Scope CRUD + validate API tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.scope.active_gate import SETTING_ACTIVE_TESTS


def _project(client: TestClient) -> str:
    r = client.post("/api/v1/projects", json={"name": "Scope Lab", "description": None})
    assert r.status_code == 201
    return r.json()["id"]


def test_scope_crud_ip(client: TestClient) -> None:
    pid = _project(client)
    created = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "ip", "value": "203.0.113.50", "meta_json": {}},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "verified"
    entry_id = body["id"]

    listed = client.get(f"/api/v1/projects/{pid}/scope")
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    got = client.get(f"/api/v1/projects/{pid}/scope/{entry_id}")
    assert got.status_code == 200
    assert got.json()["value"] == "203.0.113.50"

    deleted = client.delete(f"/api/v1/projects/{pid}/scope/{entry_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/projects/{pid}/scope").json() == []


def test_scope_rejects_metadata(client: TestClient) -> None:
    pid = _project(client)
    r = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "ip", "value": "169.254.169.254"},
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["allowed"] is False
    assert "metadata" in detail["reason"] or "blocked" in detail["reason"]


def test_scope_cidr_and_path(client: TestClient) -> None:
    pid = _project(client)
    cidr = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "cidr", "value": "10.10.0.0/24"},
    )
    assert cidr.status_code == 201
    path = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "path", "value": "/opt/repos/demo"},
    )
    assert path.status_code == 201
    api_spec = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "api_spec", "value": "/opt/repos/demo/openapi.json"},
    )
    assert api_spec.status_code == 201


def test_validate_target_out_of_scope(client: TestClient) -> None:
    pid = _project(client)
    client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "cidr", "value": "10.0.0.0/24"},
    )
    r = client.post(
        f"/api/v1/projects/{pid}/scope/validate",
        json={
            "mode": "target",
            "type": "ip",
            "value": "192.168.1.1",
            "resolve_dns": False,
        },
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "out_of_scope"


def test_validate_ssrf_metadata(client: TestClient) -> None:
    pid = _project(client)
    r = client.post(
        f"/api/v1/projects/{pid}/scope/validate",
        json={
            "mode": "ssrf",
            "type": "url",
            "value": "http://169.254.169.254/latest/meta-data/",
            "resolve_dns": True,
        },
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is False


def test_active_gate_via_validate(client: TestClient) -> None:
    pid = _project(client)
    denied = client.post(
        f"/api/v1/projects/{pid}/scope/validate",
        json={"mode": "active_gate", "type": "ip", "value": "1.1.1.1"},
    )
    assert denied.status_code == 200
    assert denied.json()["allowed"] is False

    client.put(
        f"/api/v1/settings/{SETTING_ACTIVE_TESTS}",
        json={"value_json": True},
    )
    allowed = client.post(
        f"/api/v1/projects/{pid}/scope/validate",
        json={"mode": "active_gate", "type": "ip", "value": "1.1.1.1"},
    )
    assert allowed.json()["allowed"] is True


def test_relative_path_rejected(client: TestClient) -> None:
    pid = _project(client)
    r = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "path", "value": "relative/path"},
    )
    assert r.status_code == 422
