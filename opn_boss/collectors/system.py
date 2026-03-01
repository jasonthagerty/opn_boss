"""System status collector."""

from __future__ import annotations

import re
from typing import Any

from opn_boss.collectors.base import BaseCollector


def _parse_uptime_seconds(uptime_str: str) -> float:
    """Parse OPNSense uptime string like '21 days, 03:04:31' into seconds."""
    if not uptime_str:
        return 0.0
    total = 0.0
    day_match = re.search(r"(\d+)\s+day", uptime_str)
    if day_match:
        total += int(day_match.group(1)) * 86400
    time_match = re.search(r"(\d+):(\d+):(\d+)", uptime_str)
    if time_match:
        total += int(time_match.group(1)) * 3600
        total += int(time_match.group(2)) * 60
        total += int(time_match.group(3))
    return total


class SystemCollector(BaseCollector):
    name = "system"

    async def _collect(self) -> dict[str, Any]:
        mem_data = await self._client.get("/api/diagnostics/system/systemResources")
        time_data: dict[str, Any] = {}
        try:
            time_data = await self._client.get("/api/diagnostics/system/systemTime")
        except Exception:
            pass

        memory = mem_data.get("memory", {})
        mem_total = int(memory.get("total", 0))
        mem_used = int(memory.get("used", 0))
        mem_pct = round((mem_used / mem_total) * 100, 1) if mem_total else 0

        uptime_str = time_data.get("uptime", "")
        uptime_sec = _parse_uptime_seconds(uptime_str)

        return {
            "cpu_usage": 0,
            "memory_total": mem_total,
            "memory_used": mem_used,
            "memory_percent": mem_pct,
            "disk_used": 0,
            "disk_total": 0,
            "disk_percent": 0,
            "uptime": uptime_str,
            "uptime_seconds": uptime_sec,
            "loadavg": time_data.get("loadavg", ""),
            "raw": {**mem_data, **time_data},
        }
