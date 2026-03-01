"""Tests for NatRulesCollector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opn_boss.collectors.nat_rules import NatRulesCollector


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.firewall_id = "fw1"
    return client


@pytest.mark.asyncio
async def test_nat_rules_success(mock_client):
    mock_client.post = AsyncMock(return_value={
        "rows": [{"enabled": "1", "interface": "wan", "protocol": "tcp", "destination_port": "80", "target": "192.168.1.10", "local_port": "80"}],
        "rowCount": 1,
    })
    collector = NatRulesCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    assert result.collector_name == "nat_rules"
    assert "port_forwards" in result.data
    assert "outbound_nat" in result.data
    assert result.data["pf_count"] == 1


@pytest.mark.asyncio
async def test_nat_rules_empty(mock_client):
    mock_client.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
    collector = NatRulesCollector(mock_client)
    result = await collector.collect()

    assert result.success is True
    assert result.data["port_forwards"] == []
    assert result.data["outbound_nat"] == []
    assert result.data["pf_count"] == 0
    assert result.data["onat_count"] == 0


@pytest.mark.asyncio
async def test_nat_rules_api_error(mock_client):
    mock_client.post = AsyncMock(side_effect=RuntimeError("API error"))
    collector = NatRulesCollector(mock_client)
    result = await collector.collect()

    assert result.success is False
    assert "API error" in result.error
