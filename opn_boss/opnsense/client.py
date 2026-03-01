"""Async OPNSense API client with error mapping and probe support."""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any

import httpx

from opn_boss.core.config import FirewallConfig
from opn_boss.core.exceptions import (
    OPNSenseAuthError,
    OPNSenseConnectionError,
    OPNSenseError,
    OPNSenseNotFoundError,
    OPNSenseTimeoutError,
)

logger = logging.getLogger(__name__)


class OPNSenseClient:
    """Async HTTP client for the OPNSense REST API.

    Usage::

        async with OPNSenseClient(config) as client:
            data = await client.get("/api/core/firmware/info")
    """

    def __init__(self, config: FirewallConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> OPNSenseClient:
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url,
            auth=(self._config.api_key, self._config.api_secret),
            verify=self._config.verify_ssl,
            timeout=httpx.Timeout(
                connect=5.0,
                read=self._config.timeout_seconds,
                write=5.0,
                pool=5.0,
            ),
            # Do NOT set Content-Type globally — OPNSense rejects it on GET requests
            headers={"Accept": "application/json"},
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def firewall_id(self) -> str:
        return self._config.firewall_id

    async def probe(self) -> bool:
        """Quick reachability check. Returns True if the host responds."""
        try:
            client = httpx.AsyncClient(
                base_url=self._config.base_url,
                auth=(self._config.api_key, self._config.api_secret),
                verify=self._config.verify_ssl,
                timeout=httpx.Timeout(connect=3.0, read=5.0, write=2.0, pool=2.0),
            )
            async with client:
                resp = await client.get("/api/core/firmware/info")
                return resp.status_code < 500
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError):
            return False
        except Exception:
            return False

    async def get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Perform a GET request and return parsed JSON."""
        if self._client is None:
            raise RuntimeError("OPNSenseClient must be used as async context manager")
        try:
            response = await self._client.get(endpoint, params=params)
            return self._handle_response(response, endpoint)
        except httpx.TimeoutException as exc:
            raise OPNSenseTimeoutError(
                f"Timeout on {endpoint}",
                firewall_id=self._config.firewall_id,
            ) from exc
        except httpx.ConnectError as exc:
            raise OPNSenseConnectionError(
                f"Cannot connect to {self._config.host}: {exc}",
                firewall_id=self._config.firewall_id,
            ) from exc
        except httpx.NetworkError as exc:
            raise OPNSenseConnectionError(
                f"Network error on {endpoint}: {exc}",
                firewall_id=self._config.firewall_id,
            ) from exc
        except OPNSenseError:
            raise
        except Exception as exc:
            raise OPNSenseError(
                f"Unexpected error on {endpoint}: {exc}",
                firewall_id=self._config.firewall_id,
            ) from exc

    async def post(
        self, endpoint: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Perform a POST request and return parsed JSON."""
        if self._client is None:
            raise RuntimeError("OPNSenseClient must be used as async context manager")
        try:
            response = await self._client.post(endpoint, json=json or {})
            return self._handle_response(response, endpoint)
        except httpx.TimeoutException as exc:
            raise OPNSenseTimeoutError(
                f"Timeout on POST {endpoint}",
                firewall_id=self._config.firewall_id,
            ) from exc
        except httpx.ConnectError as exc:
            raise OPNSenseConnectionError(
                f"Cannot connect to {self._config.host}: {exc}",
                firewall_id=self._config.firewall_id,
            ) from exc
        except OPNSenseError:
            raise
        except Exception as exc:
            raise OPNSenseError(
                f"Unexpected error on POST {endpoint}: {exc}",
                firewall_id=self._config.firewall_id,
            ) from exc

    def _handle_response(
        self, response: httpx.Response, endpoint: str
    ) -> dict[str, Any]:
        """Map HTTP status codes to domain exceptions."""
        if response.status_code in (401, 403):
            raise OPNSenseAuthError(
                f"Authentication failed for {endpoint} (HTTP {response.status_code})",
                firewall_id=self._config.firewall_id,
                status_code=response.status_code,
            )
        if response.status_code == 404:
            raise OPNSenseNotFoundError(
                f"Endpoint not found: {endpoint}",
                firewall_id=self._config.firewall_id,
                status_code=404,
            )
        if response.status_code >= 500:
            raise OPNSenseError(
                f"Server error on {endpoint} (HTTP {response.status_code})",
                firewall_id=self._config.firewall_id,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise OPNSenseError(
                f"Client error on {endpoint} (HTTP {response.status_code}): {response.text[:200]}",
                firewall_id=self._config.firewall_id,
                status_code=response.status_code,
            )

        try:
            return response.json()  # type: ignore[no-any-return]
        except Exception:
            return {"_raw": response.text}
