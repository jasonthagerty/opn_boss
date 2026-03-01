"""Interface statistics collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class InterfacesCollector(BaseCollector):
    name = "interfaces"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.get("/api/diagnostics/interface/getInterfaceStatistics")
        ifaces = data.get("statistics", {})
        return {
            "interfaces": ifaces,
            "count": len(ifaces),
            "raw": data,
        }
