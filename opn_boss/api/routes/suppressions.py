"""Suppressions API routes."""

from __future__ import annotations

import pathlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select

from opn_boss.api.dependencies import get_service
from opn_boss.core.database import FindingDB, SnapshotDB, SuppressionDB, get_session_factory
from opn_boss.service.main import OPNBossService

TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


@router.post("/api/suppressions", response_class=HTMLResponse)
async def create_suppression(
    request: Request,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Create a suppression. Returns HTMX <tr> replacing the finding row."""
    form = await request.form()
    firewall_id = str(form.get("firewall_id", "")).strip()
    check_id = str(form.get("check_id", "")).strip()
    reason = form.get("reason")

    if not firewall_id or not check_id:
        raise HTTPException(status_code=422, detail="firewall_id and check_id are required")

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        # Upsert: return existing or create new
        result = await session.execute(
            select(SuppressionDB).where(
                SuppressionDB.firewall_id == firewall_id,
                SuppressionDB.check_id == check_id,
            )
        )
        supp = result.scalar_one_or_none()
        if not supp:
            supp = SuppressionDB(
                firewall_id=firewall_id,
                check_id=check_id,
                reason=str(reason) if reason else None,
            )
            session.add(supp)
            await session.commit()
            await session.refresh(supp)

        # Query the latest finding for this (firewall_id, check_id) for row rendering
        latest_snap_sub = (
            select(SnapshotDB.id)
            .where(SnapshotDB.firewall_id == firewall_id)
            .order_by(desc(SnapshotDB.started_at))
            .limit(1)
            .scalar_subquery()
        )
        f_result = await session.execute(
            select(FindingDB).where(
                FindingDB.snapshot_id == latest_snap_sub,
                FindingDB.check_id == check_id,
            )
        )
        finding = f_result.scalar_one_or_none()

    return templates.TemplateResponse(
        request,
        "partials/suppressed_row.html",
        {
            "f": finding,
            "suppression_id": supp.id,
            "firewall_id": firewall_id,
            "check_id": check_id,
        },
    )


@router.get("/api/suppressions")
async def list_suppressions(
    service: OPNBossService = Depends(get_service),
) -> list[dict[str, Any]]:
    """List all suppressions."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        result = await session.execute(select(SuppressionDB))
        suppressions = result.scalars().all()
    return [
        {
            "id": s.id,
            "firewall_id": s.firewall_id,
            "check_id": s.check_id,
            "reason": s.reason,
            "created_at": s.created_at.isoformat(),
        }
        for s in suppressions
    ]


@router.delete("/api/suppressions/{suppression_id}", response_class=HTMLResponse)
async def delete_suppression(
    suppression_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Delete a suppression. Returns empty response — HTMX removes the row."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        supp = await session.get(SuppressionDB, suppression_id)
        if not supp:
            raise HTTPException(status_code=404, detail="Suppression not found")
        await session.delete(supp)
        await session.commit()
    return HTMLResponse(content="")
