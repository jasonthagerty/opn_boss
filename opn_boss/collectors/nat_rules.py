"""NAT rules collector (port forwards and outbound NAT)."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class NatRulesCollector(BaseCollector):
    name = "nat_rules"

    async def _collect(self) -> dict[str, Any]:
        pf_data = await self._client.post(
            "/api/firewall/nat/searchRule",
            json={"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
        onat_data = await self._client.post(
            "/api/firewall/nat/searchOutboundRule",
            json={"current": 1, "rowCount": 500, "searchPhrase": ""},
        )
        port_forwards = pf_data.get("rows", [])
        outbound_nat = onat_data.get("rows", [])
        return {
            "port_forwards": port_forwards,
            "outbound_nat": outbound_nat,
            "pf_count": len(port_forwards),
            "onat_count": len(outbound_nat),
        }
