"""POST /api/scan — trigger an on-demand scan."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from opn_boss.api.dependencies import get_service
from opn_boss.api.models import ScanResponse
from opn_boss.service.main import OPNBossService

router = APIRouter()


@router.post("/api/scan", response_model=ScanResponse, status_code=202)
async def trigger_scan(service: OPNBossService = Depends(get_service)) -> ScanResponse:
    """Trigger an immediate scan of all firewalls (async, returns 202)."""
    asyncio.create_task(service.run_scan())
    return ScanResponse(message="Scan started. Results will stream via /api/events.")
