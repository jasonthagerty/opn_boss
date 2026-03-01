"""Firmware version collector."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class FirmwareCollector(BaseCollector):
    name = "firmware"

    async def _collect(self) -> dict[str, Any]:
        # /api/core/firmware/status works on OPNSense 26.x; /api/core/firmware/info may 400
        data = await self._client.get("/api/core/firmware/status")
        return {
            "product_version": data.get("product_version", ""),
            "product_latest": data.get("product_latest", data.get("product_version", "")),
            "needs_reboot": data.get("needs_reboot", "0"),
            "new_packages_available": bool(data.get("new_packages", [])),
            "all_packages_uptodate": not bool(data.get("new_packages", [])),
            "raw": data,
        }
