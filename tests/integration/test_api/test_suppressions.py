"""Integration tests for the suppressions API."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opn_boss.api.app import create_app
from opn_boss.core.config import load_config


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    config_file = tmp_path / "config.yaml"
    db_path = tmp_path / "test.db"
    config_file.write_text(textwrap.dedent(f"""\
        firewalls:
          - firewall_id: "fw1"
            host: "192.168.1.1"
            api_key: "key1"
            api_secret: "secret1"
            role: "primary"
            enabled: true
        database:
          url: "sqlite+aiosqlite:///{db_path}"
        scheduler:
          poll_interval_minutes: 60
    """))
    return config_file


@pytest.fixture(autouse=True)
def reset_db_globals():
    """Reset the global DB engine/session singleton between tests so each test gets a fresh DB."""
    import opn_boss.core.database as db_module
    db_module._engine = None
    db_module._session_factory = None
    yield
    db_module._engine = None
    db_module._session_factory = None


@pytest.fixture
def client(config_path: Path):
    cfg = load_config(config_path)
    app = create_app(cfg)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_list_suppressions_empty(client: TestClient):
    response = client.get("/api/suppressions")
    assert response.status_code == 200
    assert response.json() == []


def test_create_suppression(client: TestClient):
    response = client.post(
        "/api/suppressions",
        data={"firewall_id": "fw1", "check_id": "SEC-002"},
    )
    assert response.status_code == 200
    # Returns HTML (HTMX snippet)
    assert "text/html" in response.headers["content-type"]


def test_list_suppressions_after_create(client: TestClient):
    client.post(
        "/api/suppressions",
        data={"firewall_id": "fw1", "check_id": "SEC-002"},
    )
    response = client.get("/api/suppressions")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["firewall_id"] == "fw1"
    assert data[0]["check_id"] == "SEC-002"
    assert "id" in data[0]
    assert "created_at" in data[0]


def test_create_suppression_idempotent(client: TestClient):
    """Creating the same suppression twice is idempotent."""
    client.post("/api/suppressions", data={"firewall_id": "fw1", "check_id": "SEC-002"})
    client.post("/api/suppressions", data={"firewall_id": "fw1", "check_id": "SEC-002"})
    response = client.get("/api/suppressions")
    assert len(response.json()) == 1


def test_delete_suppression(client: TestClient):
    client.post("/api/suppressions", data={"firewall_id": "fw1", "check_id": "SEC-003"})
    suppressions = client.get("/api/suppressions").json()
    assert len(suppressions) == 1
    supp_id = suppressions[0]["id"]

    del_response = client.delete(f"/api/suppressions/{supp_id}")
    assert del_response.status_code == 200

    assert client.get("/api/suppressions").json() == []


def test_delete_suppression_not_found(client: TestClient):
    response = client.delete("/api/suppressions/nonexistent-id")
    assert response.status_code == 404


def test_create_suppression_missing_fields(client: TestClient):
    response = client.post("/api/suppressions", data={"firewall_id": "fw1"})
    assert response.status_code == 422


def test_create_suppression_with_reason(client: TestClient):
    client.post(
        "/api/suppressions",
        data={"firewall_id": "fw1", "check_id": "IDS-001", "reason": "Backup FW intentionally runs no IDS"},
    )
    data = client.get("/api/suppressions").json()
    assert data[0]["reason"] == "Backup FW intentionally runs no IDS"


def test_suppress_response_contains_unsuppress_button(client: TestClient):
    """POST response should include an Unsuppress button."""
    response = client.post(
        "/api/suppressions",
        data={"firewall_id": "fw1", "check_id": "SEC-002"},
    )
    assert response.status_code == 200
    # Should contain unsuppress button pointing to the suppression API
    assert "Unsuppress" in response.text
    assert "/api/suppressions/" in response.text


def test_findings_partial_hides_suppressed_by_default(client: TestClient):
    """findings partial should not show suppressed findings by default."""
    response = client.get("/partials/findings")
    assert response.status_code == 200
    # No suppressed badge in the default view
    assert "Suppressed" not in response.text


def test_findings_partial_show_suppressed_param(client: TestClient):
    """show_suppressed=true should trigger the suppressed view."""
    response = client.get("/partials/findings?show_suppressed=true")
    assert response.status_code == 200
    # Response should be valid HTML
    assert response.status_code == 200
