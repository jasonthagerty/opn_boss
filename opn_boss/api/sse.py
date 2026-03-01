"""Server-Sent Events manager for real-time dashboard updates."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from opn_boss.core.logging_config import get_logger

logger = get_logger(__name__)


class SSEManager:
    """Manage SSE subscriber queues and broadcast events."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[str]] = []

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all connected SSE clients."""
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        dead: list[asyncio.Queue[str]] = []
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)

        for q in dead:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

        if self._subscribers:
            logger.debug("SSE broadcast '%s' to %d client(s)", event, len(self._subscribers))

    async def subscribe(self) -> AsyncIterator[str]:
        """Async generator yielding SSE messages for one client."""
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        logger.debug("SSE client connected (%d total)", len(self._subscribers))
        try:
            # Send a heartbeat immediately
            yield ": heartbeat\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield msg
                except TimeoutError:
                    # Send keep-alive comment
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass
            logger.debug("SSE client disconnected (%d remaining)", len(self._subscribers))

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
