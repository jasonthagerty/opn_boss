"""FastAPI dependency injection helpers."""

from __future__ import annotations

from fastapi import Request

from opn_boss.api.sse import SSEManager
from opn_boss.service.main import OPNBossService


def get_service(request: Request) -> OPNBossService:
    return request.app.state.service  # type: ignore[no-any-return]


def get_sse_manager(request: Request) -> SSEManager:
    return request.app.state.sse_manager  # type: ignore[no-any-return]
