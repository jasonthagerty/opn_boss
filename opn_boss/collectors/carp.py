"""CARP (HA) settings and status collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class CARPCollector(BaseCollector):
    name = "carp"

    async def _collect(self) -> dict[str, Any]:
        # Try multiple CARP endpoint paths across OPNSense versions
        from opn_boss.core.exceptions import OPNSenseNotFoundError

        data: dict[str, Any] = {}
        for path in ["/api/carp/settings/getStatus", "/api/carp/status/get"]:
            try:
                data = await self._client.get(path)
                break
            except OPNSenseNotFoundError:
                continue

        if not data or "errorMessage" in data:
            # CARP plugin not installed / not configured — return explicit marker
            return {"carp_available": False, "carp_status": "unavailable", "vips": {}}

        vips = data.get("carp", {})
        if not vips:
            vips = {k: v for k, v in data.items() if isinstance(v, dict)}
        return {
            "carp_available": True,
            "carp_status": data.get("carp_status", "unknown"),
            "allow_preempt": data.get("allow_preempt", ""),
            "vips": vips,
            "raw": data,
        }
