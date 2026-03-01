"""DHCPv4 lease collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class DHCPCollector(BaseCollector):
    name = "dhcp"

    async def _collect(self) -> dict[str, Any]:
        data = await self._client.post(
            "/api/dhcpv4/leases/searchLease",
            json={"current": 1, "rowCount": 2000, "searchPhrase": ""},
        )
        rows = data.get("rows", [])
        return {
            "total": data.get("total", len(rows)),
            "leases": rows,
            "active_count": sum(1 for r in rows if r.get("type") == "active"),
        }
