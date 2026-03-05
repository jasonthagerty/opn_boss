"""Service status collector — checks running state of key OPNSense services."""

from __future__ import annotations

from typing import Any

from opn_boss.collectors.base import BaseCollector


class ServicesCollector(BaseCollector):
    name = "services"

    # (key, API endpoint) pairs for services to monitor
    _SERVICES: list[tuple[str, str]] = [
        ("unbound", "/api/unbound/service/status"),
        ("ids", "/api/ids/service/status"),
    ]

    async def _collect(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for svc_name, endpoint in self._SERVICES:
            try:
                data = await self._client.get(endpoint)
                running: bool | None = bool(
                    data.get("status") == "running"
                    or data.get("running") in (1, True, "true", "running")
                )
                results[svc_name] = {
                    "running": running,
                    "status": data.get("status", "unknown"),
                }
            except Exception:
                # None means "endpoint unreachable" — avoids false alarms on transient API errors
                results[svc_name] = {"running": None, "status": "unreachable"}
        return results
