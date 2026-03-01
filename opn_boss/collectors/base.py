"""Base collector abstract class."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from opn_boss.core.logging_config import get_logger
from opn_boss.core.types import CollectorResult
from opn_boss.opnsense.client import OPNSenseClient


class BaseCollector(ABC):
    """Abstract base for all OPNSense data collectors."""

    #: Override in subclasses to name this collector
    name: str = "base"

    def __init__(self, client: OPNSenseClient) -> None:
        self._client = client
        self._logger = get_logger(f"opn_boss.collectors.{self.name}")

    @abstractmethod
    async def _collect(self) -> dict[str, Any]:
        """Fetch raw data from the OPNSense API.

        Returns a dict of collected data. Raise exceptions on failure.
        """
        ...

    async def collect(self) -> CollectorResult:
        """Run the collector and wrap results in a CollectorResult."""
        start = time.monotonic()
        try:
            data = await self._collect()
            duration_ms = (time.monotonic() - start) * 1000
            self._logger.debug(
                "Collector %s succeeded in %.1fms for %s",
                self.name,
                duration_ms,
                self._client.firewall_id,
            )
            return CollectorResult(
                collector_name=self.name,
                firewall_id=self._client.firewall_id,
                success=True,
                data=data,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            self._logger.warning(
                "Collector %s failed for %s: %s",
                self.name,
                self._client.firewall_id,
                exc,
            )
            return CollectorResult(
                collector_name=self.name,
                firewall_id=self._client.firewall_id,
                success=False,
                error=str(exc),
                duration_ms=duration_ms,
            )
