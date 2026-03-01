"""Tests for OllamaClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from opn_boss.core.config import LLMConfig
from opn_boss.core.exceptions import LLMUnavailableError
from opn_boss.llm.client import OllamaClient


@pytest.fixture
def llm_config():
    return LLMConfig(
        enabled=True,
        base_url="http://localhost:11434",
        model="phi3:mini",
        timeout_seconds=30.0,
    )


@pytest.mark.asyncio
async def test_generate_success(llm_config):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "The firewall allows HTTP traffic."}

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client

        client = OllamaClient(llm_config)
        result = await client.generate("test prompt")

    assert result == "The firewall allows HTTP traffic."


@pytest.mark.asyncio
async def test_generate_model_not_found(llm_config):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "model not found"

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client

        client = OllamaClient(llm_config)
        with pytest.raises(LLMUnavailableError, match="not found"):
            await client.generate("test prompt")


@pytest.mark.asyncio
async def test_generate_connection_error(llm_config):
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client_class.return_value = mock_client

        client = OllamaClient(llm_config)
        with pytest.raises(LLMUnavailableError, match="Cannot connect"):
            await client.generate("test prompt")


@pytest.mark.asyncio
async def test_generate_timeout(llm_config):
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_client_class.return_value = mock_client

        client = OllamaClient(llm_config)
        with pytest.raises(LLMUnavailableError, match="timed out"):
            await client.generate("test prompt")
