"""Unbound DNS diagnostics collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class DNSCollector(BaseCollector):
    name = "dns"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.get("/api/unbound/diagnostics/stats")
        stats = data.get("data", {})
        return {
            "queries_total": int(stats.get("total.num.queries", 0)),
            "cache_hits": int(stats.get("total.num.cachehits", 0)),
            "unwanted_queries": int(stats.get("total.unwanted.queries", 0)),
            "running": data.get("status") != "error",
            "raw": data,
        }
