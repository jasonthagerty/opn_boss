"""Tests for ServicesCollector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opn_boss.collectors.services import ServicesCollector
from opn_boss.core.types import CollectorResult


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.firewall_id = "fw1"
    return client


@pytest.mark.asyncio
async def test_services_all_running(mock_client):
    mock_client.get = AsyncMock(return_value={"status": "running"})
    collector = ServicesCollector(mock_client)
    result = await collector.collect()

    assert isinstance(result, CollectorResult)
    assert result.success is True
    assert result.data["unbound"]["running"] is True
    assert result.data["ids"]["running"] is True


@pytest.mark.asyncio
async def test_services_unbound_stopped(mock_client):
    async def fake_get(endpoint: str):
        if "unbound" in endpoint:
            return {"status": "stopped"}
        return {"status": "running"}

    mock_client.get = AsyncMock(side_effect=fake_get)
    collector = ServicesCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    assert result.data["unbound"]["running"] is False
    assert result.data["ids"]["running"] is True


@pytest.mark.asyncio
async def test_services_endpoint_unreachable(mock_client):
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
    collector = ServicesCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    # running == None means "could not determine" — not False
    assert result.data["unbound"]["running"] is None
    assert result.data["unbound"]["status"] == "unreachable"
    assert result.data["ids"]["running"] is None


@pytest.mark.asyncio
async def test_services_running_integer_flag(mock_client):
    """OPNSense may return running=1 instead of status='running'."""
    mock_client.get = AsyncMock(return_value={"running": 1})
    collector = ServicesCollector(mock_client)
    result = await collector.collect()

    assert result.data["unbound"]["running"] is True


@pytest.mark.asyncio
async def test_services_collector_name(mock_client):
    mock_client.get = AsyncMock(return_value={"status": "running"})
    collector = ServicesCollector(mock_client)
    result = await collector.collect()

    assert result.collector_name == "services"
    assert result.firewall_id == "fw1"
