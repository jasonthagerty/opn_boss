"""Tests for FirewallLogsCollector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opn_boss.collectors.firewall_logs import FirewallLogsCollector


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.firewall_id = "fw1"
    return client


@pytest.mark.asyncio
async def test_firewall_logs_success(mock_client):
    log_entries = [
        {"action": "pass", "src": "192.168.1.1", "dst": "8.8.8.8", "dstport": "53", "proto": "udp"},
        {"action": "block", "src": "10.0.0.1", "dst": "10.0.0.2", "dstport": "22", "proto": "tcp"},
    ]
    mock_client.get = AsyncMock(return_value={"digest": log_entries})
    collector = FirewallLogsCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    assert result.collector_name == "firewall_logs"
    assert "entries" in result.data
    assert result.data["total"] == 2


@pytest.mark.asyncio
async def test_firewall_logs_empty(mock_client):
    mock_client.get = AsyncMock(return_value={"digest": []})
    collector = FirewallLogsCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    assert result.data["entries"] == []
    assert result.data["total"] == 0


@pytest.mark.asyncio
async def test_firewall_logs_api_error(mock_client):
    mock_client.get = AsyncMock(side_effect=RuntimeError("Connection refused"))
    collector = FirewallLogsCollector(mock_client)
    result = await collector.collect()

    assert result.success is False
    assert "Connection refused" in result.error
