"""System status collector."""

from __future__ import annotations

import re
from typing import Any

from opn_boss.collectors.base import BaseCollector
from opn_boss.core.logging_config import get_logger

_logger = get_logger(__name__)


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


def _parse_disk(data: dict[str, Any]) -> tuple[int, int, float]:
    """Extract (used_bytes, total_bytes, percent) from systemResources response.

    OPNSense may return disk info under several different key names depending on
    the firmware version.  We try each known layout and return (0, 0, 0.0) if
    nothing matches, so callers can skip the check rather than false-alarm.
    """
    # Layout 1: {"disk": {"used": "...", "total": "...", "capacity": "90%"}}
    disk = data.get("disk")
    if isinstance(disk, dict):
        try:
            used = int(disk.get("used", 0))
            total = int(disk.get("total", 0))
            # Prefer pre-computed capacity if present
            cap = disk.get("capacity", "")
            if cap:
                pct = float(str(cap).replace("%", "").strip())
            elif total:
                pct = round((used / total) * 100, 1)
            else:
                pct = 0.0
            if total:
                return used, total, pct
        except (ValueError, TypeError):
            pass

    # Layout 2: {"filesystem": [{"used": "...", "total": "...", "capacity": "90%"}, ...]}
    # Take the first (root) filesystem entry
    filesystems = data.get("filesystem")
    if isinstance(filesystems, list) and filesystems:
        entry = filesystems[0]
        if isinstance(entry, dict):
            try:
                used = int(entry.get("used", 0))
                total = int(entry.get("total", 0))
                cap = entry.get("capacity", "")
                if cap:
                    pct = float(str(cap).replace("%", "").strip())
                elif total:
                    pct = round((used / total) * 100, 1)
                else:
                    pct = 0.0
                if total:
                    return used, total, pct
            except (ValueError, TypeError):
                pass

    return 0, 0, 0.0


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

        disk_used, disk_total, disk_pct = _parse_disk(mem_data)
        _logger.debug("disk raw section: %s", mem_data.get("disk", mem_data.get("filesystem")))

        return {
            "cpu_usage": 0,
            "memory_total": mem_total,
            "memory_used": mem_used,
            "memory_percent": mem_pct,
            "disk_used": disk_used,
            "disk_total": disk_total,
            "disk_percent": disk_pct,
            "uptime": uptime_str,
            "uptime_seconds": uptime_sec,
            "loadavg": time_data.get("loadavg", ""),
            "raw": {**mem_data, **time_data},
        }
