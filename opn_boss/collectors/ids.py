"""IDS/IPS service status collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class IDSCollector(BaseCollector):
    name = "ids"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.get("/api/ids/service/status")
        return {
            "running": data.get("running", 0) == 1 or data.get("status") == "running",
            "status": data.get("status", "unknown"),
            "raw": data,
        }
