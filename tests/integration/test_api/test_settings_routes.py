"""Integration tests for settings API routes."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from opn_boss.api.app import create_app
from opn_boss.core.config import load_config


@pytest.fixture()
def secret_key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture()
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
def reset_db_globals():  # type: ignore[no-untyped-def]
    import opn_boss.core.database as db

    db._engine = None
    db._session_factory = None
    yield
    db._engine = None
    db._session_factory = None


@pytest.fixture()
def app_with_key(config_path: Path, secret_key: str, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", secret_key)
    cfg = load_config(config_path)
    return create_app(cfg)


@pytest.fixture()
def client_with_key(app_with_key):  # type: ignore[no-untyped-def]
    with TestClient(app_with_key, raise_server_exceptions=False) as c:
        yield c


def test_list_firewall_configs_empty(client_with_key: TestClient) -> None:
    """GET /api/settings/firewalls returns list (may be empty or have bootstrapped fw)."""
    response = client_with_key.get("/api/settings/firewalls")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_create_firewall_requires_key(tmp_path: Path) -> None:
    """POST /api/settings/firewalls returns 503 when key not set."""
    os.environ.pop("OPNBOSS_SECRET_KEY", None)

    import opn_boss.core.database as db

    db._engine = None
    db._session_factory = None

    config_file = tmp_path / "config.yaml"
    db_path = tmp_path / "test2.db"
    config_file.write_text(textwrap.dedent(f"""\
        firewalls:
          - firewall_id: "fw1"
            host: "192.168.1.1"
            api_key: "k"
            api_secret: "s"
        database:
          url: "sqlite+aiosqlite:///{db_path}"
        scheduler:
          poll_interval_minutes: 60
    """))
    cfg = load_config(config_file)
    app = create_app(cfg)
    with TestClient(app, raise_server_exceptions=False) as c:
        response = c.post("/api/settings/firewalls", data={
            "firewall_id": "test",
            "host": "1.2.3.4",
            "api_key": "k",
            "api_secret": "s",
        })
    assert response.status_code == 503

    db._engine = None
    db._session_factory = None


def test_get_scheduler_settings(client_with_key: TestClient) -> None:
    response = client_with_key.get("/api/settings/scheduler")
    assert response.status_code == 200
    data = response.json()
    assert "poll_interval_minutes" in data


def test_get_llm_settings(client_with_key: TestClient) -> None:
    response = client_with_key.get("/api/settings/llm")
    assert response.status_code == 200
    data = response.json()
    assert "enabled" in data
    assert "model" in data


def test_settings_page_renders(client_with_key: TestClient) -> None:
    response = client_with_key.get("/settings")
    assert response.status_code == 200
    assert b"Settings" in response.content
