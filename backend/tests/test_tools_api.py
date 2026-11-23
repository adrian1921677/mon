"""Tool Manager API tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_tools_excludes_echo_by_default(client: TestClient):
    res = client.get("/api/v1/tools")
    assert res.status_code == 200
    tools = res.json()
    ids = {t["scanner_id"] for t in tools}
    assert "nmap" in ids
    assert "semgrep" in ids
    assert "echo" not in ids
    for t in tools:
        assert t["is_test_only"] is False
        assert "status" in t
        assert t["status"] in {"installed", "not_installed", "unknown", "error"}


def test_list_tools_can_include_echo(client: TestClient):
    res = client.get("/api/v1/tools", params={"include_test_only": True})
    assert res.status_code == 200
    ids = {t["scanner_id"] for t in res.json()}
    assert "echo" in ids


def test_refresh_persists_installations(client: TestClient):
    res = client.post("/api/v1/tools/refresh")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) >= 12
    assert all("scanner_id" in r and "status" in r for r in rows)

    stored = client.get("/api/v1/tools/installations")
    assert stored.status_code == 200
    stored_ids = {r["scanner_id"] for r in stored.json()}
    assert "nmap" in stored_ids
    assert "echo" not in stored_ids


def test_get_tool_detail(client: TestClient):
    res = client.get("/api/v1/tools/trivy")
    assert res.status_code == 200
    body = res.json()
    assert body["scanner_id"] == "trivy"
    assert body["integration_phase"] == 4
    assert body["display_name"]


def test_get_unknown_tool_404(client: TestClient):
    res = client.get("/api/v1/tools/does-not-exist")
    assert res.status_code == 404
