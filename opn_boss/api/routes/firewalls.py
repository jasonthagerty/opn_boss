"""GET /api/firewalls — list firewall states."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from opn_boss.api.dependencies import get_service
from opn_boss.api.models import FirewallStateResponse
from opn_boss.service.main import OPNBossService

router = APIRouter()


@router.get("/api/firewalls", response_model=list[FirewallStateResponse])
async def list_firewalls(
    service: OPNBossService = Depends(get_service),
) -> list[FirewallStateResponse]:
    """List current state of all configured firewalls."""
    states = await service.get_firewall_states()
    return [FirewallStateResponse(**s) for s in states]
