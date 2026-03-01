"""GET /api/events — Server-Sent Events stream."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from opn_boss.api.dependencies import get_sse_manager
from opn_boss.api.sse import SSEManager

router = APIRouter()


@router.get("/api/events")
async def sse_stream(
    sse_manager: SSEManager = Depends(get_sse_manager),
) -> StreamingResponse:
    """Stream real-time scan events via Server-Sent Events."""
    return StreamingResponse(
        sse_manager.subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
