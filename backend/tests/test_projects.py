"""Projects CRUD tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_create_list_get_update_delete_project(client: TestClient) -> None:
    create = client.post(
        "/api/v1/projects",
        json={"name": "Demo Lab", "description": "Autorisierte Testumgebung"},
    )
    assert create.status_code == 201
    project = create.json()
    assert project["name"] == "Demo Lab"
    assert project["id"]
    project_id = project["id"]

    listed = client.get("/api/v1/projects")
    assert listed.status_code == 200
    assert any(p["id"] == project_id for p in listed.json())

    fetched = client.get(f"/api/v1/projects/{project_id}")
    assert fetched.status_code == 200
    assert fetched.json()["description"] == "Autorisierte Testumgebung"

    updated = client.patch(
        f"/api/v1/projects/{project_id}",
        json={"name": "Demo Lab Renamed"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Demo Lab Renamed"

    audits = client.get("/api/v1/audit-events", params={"project_id": project_id})
    assert audits.status_code == 200
    actions = {e["action"] for e in audits.json()}
    assert "project.created" in actions
    assert "project.updated" in actions

    deleted = client.delete(f"/api/v1/projects/{project_id}")
    assert deleted.status_code == 204

    missing = client.get(f"/api/v1/projects/{project_id}")
    assert missing.status_code == 404


def test_get_unknown_project(client: TestClient) -> None:
    response = client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_settings_stub(client: TestClient) -> None:
    put = client.put(
        "/api/v1/settings/ui.theme",
        json={"value_json": {"mode": "system"}},
    )
    assert put.status_code == 200
    assert put.json()["key"] == "ui.theme"
    assert put.json()["value_json"] == {"mode": "system"}

    got = client.get("/api/v1/settings/ui.theme")
    assert got.status_code == 200
    assert got.json()["value_json"]["mode"] == "system"

    listed = client.get("/api/v1/settings")
    assert listed.status_code == 200
    assert any(s["key"] == "ui.theme" for s in listed.json())
