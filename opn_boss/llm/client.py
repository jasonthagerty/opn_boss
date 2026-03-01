"""Async Ollama LLM client."""

from __future__ import annotations

import httpx

from opn_boss.core.config import LLMConfig
from opn_boss.core.exceptions import LLMUnavailableError


class OllamaClient:
    """Async client for the Ollama REST API."""

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    async def generate(self, prompt: str) -> str:
        """Call Ollama /api/generate and return the response text."""
        try:
            async with httpx.AsyncClient(
                base_url=self._config.base_url,
                timeout=httpx.Timeout(self._config.timeout_seconds),
            ) as client:
                response = await client.post(
                    "/api/generate",
                    json={
                        "model": self._config.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                )
                if response.status_code == 404:
                    raise LLMUnavailableError(
                        f"Model '{self._config.model}' not found in Ollama. "
                        f"Run: ollama pull {self._config.model}"
                    )
                if response.status_code >= 400:
                    raise LLMUnavailableError(
                        f"Ollama returned HTTP {response.status_code}: {response.text[:200]}"
                    )
                data = response.json()
                return str(data.get("response", ""))
        except LLMUnavailableError:
            raise
        except httpx.ConnectError as exc:
            raise LLMUnavailableError(
                f"Cannot connect to Ollama at {self._config.base_url}. "
                "Is Ollama running? Try: ollama serve"
            ) from exc
        except httpx.TimeoutException as exc:
            raise LLMUnavailableError(
                f"Ollama timed out after {self._config.timeout_seconds}s. "
                "The model may be loading — try again in a moment."
            ) from exc
        except Exception as exc:
            raise LLMUnavailableError(f"Unexpected LLM error: {exc}") from exc
