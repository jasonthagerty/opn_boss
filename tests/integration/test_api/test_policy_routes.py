"""Integration tests for policy analysis routes."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from opn_boss.api.app import create_app
from opn_boss.core.config import load_config
from opn_boss.core.exceptions import LLMUnavailableError


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
        llm:
          enabled: true
          model: "phi3:mini"
          base_url: "http://localhost:11434"
    """))
    return config_file


@pytest.fixture(autouse=True)
def reset_db_globals():
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


def test_get_summary_no_data(client: TestClient):
    """GET summary returns 404 when no summary exists yet."""
    response = client.get("/api/policy/fw1/summary")
    assert response.status_code == 404


def test_get_history_empty(client: TestClient):
    """GET history returns empty list when no queries."""
    response = client.get("/api/policy/fw1/history")
    assert response.status_code == 200
    assert response.json() == []


def test_analyze_returns_html_on_llm_error(client: TestClient):
    """POST analyze returns HTMX error card when Ollama unavailable."""
    with patch("opn_boss.llm.client.OllamaClient.generate",
               AsyncMock(side_effect=LLMUnavailableError("Cannot connect to Ollama"))):
        response = client.post("/api/policy/fw1/analyze")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "LLM Error" in response.text or "Cannot connect" in response.text


def test_whatif_missing_scenario(client: TestClient):
    """POST whatif with no scenario returns error card."""
    response = client.post("/api/policy/fw1/whatif", data={})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_whatif_llm_error(client: TestClient):
    """POST whatif returns error card when LLM unavailable."""
    with patch("opn_boss.llm.client.OllamaClient.generate",
               AsyncMock(side_effect=LLMUnavailableError("Ollama not running"))):
        response = client.post(
            "/api/policy/fw1/whatif",
            data={"scenario": "Would SSH from 1.2.3.4 be allowed?"},
        )
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
