"""Routing table collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class RoutesCollector(BaseCollector):
    name = "routes"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.get("/api/routes/routes/getroute")
        rows = data.get("route", [])
        if isinstance(rows, dict):
            rows = list(rows.values())
        return {
            "routes": rows,
            "total": len(rows),
            "raw": data,
        }
