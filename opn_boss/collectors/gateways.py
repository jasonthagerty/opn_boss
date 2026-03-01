"""Gateway status collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class GatewaysCollector(BaseCollector):
    name = "gateways"

    async def _collect(self) -> dict[str, Any]:
        # OPNSense 26.x uses /api/routes/gateway/status
        data = await self._client.get("/api/routes/gateway/status")
        items = data.get("items", [])
        return {
            "gateways": items,
            "total": len(items),
            "down_count": sum(1 for g in items if g.get("status") in ("down", "loss", "highdelay")),
            "raw": data,
        }
