"""Firewall log diagnostics collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class FirewallLogsCollector(BaseCollector):
    name = "firewall_logs"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.get(
            "/api/diagnostics/firewall/log",
            params={"limit": 500},
        )
        entries = data.get("digest", data.get("entries", []))
        if isinstance(entries, dict):
            entries = list(entries.values())
        return {
            "entries": entries,
            "total": len(entries),
        }
