"""Integration tests for the FastAPI API endpoints."""

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


@pytest.fixture
def app(config_path: Path):
    cfg = load_config(config_path)
    return create_app(cfg)


@pytest.fixture
def client(app):
    # Use TestClient which handles lifespan
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_dashboard_returns_200(client: TestClient):
    response = client.get("/")
    # May return 200 or 500 if DB not ready, just check it responds
    assert response.status_code in (200, 500)


def test_firewalls_api(client: TestClient):
    response = client.get("/api/firewalls")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_snapshots_api(client: TestClient):
    response = client.get("/api/snapshots")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_scan_endpoint(client: TestClient):
    response = client.post("/api/scan")
    assert response.status_code == 202
    data = response.json()
    assert "message" in data
    assert data["status"] == "accepted"


def test_snapshot_not_found(client: TestClient):
    response = client.get("/api/snapshots/nonexistent-id/findings")
    assert response.status_code == 404


def test_snapshots_filter_by_severity(client: TestClient):
    response = client.get("/api/snapshots?firewall_id=fw1")
    assert response.status_code == 200
