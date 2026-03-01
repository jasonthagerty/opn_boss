"""Tests for the base collector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opn_boss.collectors.base import BaseCollector
from opn_boss.core.types import CollectorResult


class ConcreteCollector(BaseCollector):
    name = "test_collector"

    async def _collect(self):
        return {"value": 42}


class FailingCollector(BaseCollector):
    name = "failing_collector"

    async def _collect(self):
        raise RuntimeError("API is down")


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.firewall_id = "fw1"
    return client


@pytest.mark.asyncio
async def test_collect_success(mock_client):
    collector = ConcreteCollector(mock_client)
    result = await collector.collect()

    assert isinstance(result, CollectorResult)
    assert result.success is True
    assert result.data == {"value": 42}
    assert result.collector_name == "test_collector"
    assert result.firewall_id == "fw1"
    assert result.error is None
    assert result.duration_ms >= 0


@pytest.mark.asyncio
async def test_collect_failure(mock_client):
    collector = FailingCollector(mock_client)
    result = await collector.collect()

    assert isinstance(result, CollectorResult)
    assert result.success is False
    assert result.error == "API is down"
    assert result.data == {}
    assert result.duration_ms >= 0
