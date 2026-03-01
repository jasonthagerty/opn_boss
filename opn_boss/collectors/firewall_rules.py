"""Firewall rules collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class FirewallRulesCollector(BaseCollector):
    name = "firewall_rules"

    async def _collect(self) -> dict[str, Any]:
        # Fetch all rules (up to 1000)
        data = await self._client.post(
            "/api/firewall/filter/searchRule",
            json={"current": 1, "rowCount": 1000, "searchPhrase": ""},
        )
        rows = data.get("rows", [])
        return {
            "total": data.get("total", 0),
            "rules": rows,
            "enabled_count": sum(1 for r in rows if r.get("enabled") == "1"),
            "disabled_count": sum(1 for r in rows if r.get("enabled") != "1"),
        }
