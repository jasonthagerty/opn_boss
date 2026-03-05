"""GET / — Jinja2 dashboard."""

from __future__ import annotations

import pathlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from opn_boss.api.dependencies import get_service
from opn_boss.api.filters import register_filters
from opn_boss.service.main import OPNBossService

TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
register_filters(templates.env)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Main dashboard page."""
    firewall_states = await service.get_firewall_states()
    snapshots = await service.get_latest_snapshots()

    # Merge state + snapshot data for the template
    fw_data = []
    for fw_state in firewall_states:
        snap = next(
            (s for s in snapshots if s.get("firewall_id") == fw_state["firewall_id"]),
            None,
        )
        fw_data.append({
            "firewall_id": fw_state["firewall_id"],
            "online": fw_state["online"],
            "role": fw_state["role"],
            "last_seen": fw_state.get("last_seen"),
            "snapshot": snap,
        })

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "firewalls": fw_data,
            "page_title": "OPNBoss Dashboard",
        },
    )


@router.get("/firewall/{firewall_id}", response_class=HTMLResponse)
async def firewall_detail(
    request: Request,
    firewall_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Detail page for a single firewall."""
    from sqlalchemy import desc, select

    from opn_boss.core.database import FindingDB, SnapshotDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        # Get recent snapshots for this firewall
        result = await session.execute(
            select(SnapshotDB)
            .where(SnapshotDB.firewall_id == firewall_id)
            .order_by(desc(SnapshotDB.started_at))
            .limit(10)
        )
        snaps = result.scalars().all()

        findings: list[FindingDB] = []
        if snaps:
            latest_snap = snaps[0]
            result2 = await session.execute(
                select(FindingDB).where(FindingDB.snapshot_id == latest_snap.id)
            )
            findings = list(result2.scalars().all())

    states = await service.get_firewall_states()
    fw_state = next((s for s in states if s["firewall_id"] == firewall_id), None)

    policy_summary = None
    if service._policy_service is not None:
        policy_summary = await service._policy_service.get_latest_summary(firewall_id)

    return templates.TemplateResponse(
        request,
        "firewall_detail.html",
        {
            "firewall_id": firewall_id,
            "fw_state": fw_state,
            "snapshots": snaps,
            "findings": findings,
            "has_llm": service._config.llm.enabled,
            "policy_summary": policy_summary,
            "page_title": f"OPNBoss \u2014 {firewall_id}",
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Settings configuration page."""
    from sqlalchemy import select

    from opn_boss.core.crypto import is_key_configured
    from opn_boss.core.database import FirewallConfigDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        result = await session.execute(
            select(FirewallConfigDB).order_by(FirewallConfigDB.firewall_id)
        )
        fw_configs = result.scalars().all()

    scheduler_interval = service._config.scheduler.poll_interval_minutes
    llm_config = service._config.llm

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "page_title": "OPNBoss \u2014 Settings",
            "fw_configs": fw_configs,
            "key_configured": is_key_configured(),
            "scheduler_interval": scheduler_interval,
            "llm_enabled": llm_config.enabled,
            "llm_model": llm_config.model,
            "llm_base_url": llm_config.base_url,
            "llm_timeout": llm_config.timeout_seconds,
        },
    )


@router.get("/partials/findings", response_class=HTMLResponse)
async def findings_partial(
    request: Request,
    firewall_id: str | None = None,
    severity: str | None = None,
    show_suppressed: bool = False,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """HTMX partial: findings table — one entry per (firewall, check_id) from each firewall's latest snapshot."""
    from sqlalchemy import case, func, select

    from opn_boss.core.database import FindingDB, SnapshotDB, SuppressionDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        # Latest snapshot per firewall (deduplicated at source)
        latest_per_fw = (
            select(
                SnapshotDB.firewall_id,
                func.max(SnapshotDB.started_at).label("max_ts"),
            )
            .group_by(SnapshotDB.firewall_id)
            .subquery()
        )
        result = await session.execute(
            select(SnapshotDB).join(
                latest_per_fw,
                (SnapshotDB.firewall_id == latest_per_fw.c.firewall_id)
                & (SnapshotDB.started_at == latest_per_fw.c.max_ts),
            )
        )
        snaps = result.scalars().all()
        snap_ids = [s.id for s in snaps]

        severity_order = case(
            {"critical": 1, "warning": 2, "info": 3, "ok": 4},
            value=FindingDB.severity,
            else_=5,
        )
        q = select(FindingDB).where(FindingDB.snapshot_id.in_(snap_ids))
        if not show_suppressed:
            q = q.where(FindingDB.suppressed == False)  # noqa: E712
        if firewall_id:
            q = q.where(FindingDB.firewall_id == firewall_id)
        if severity:
            q = q.where(FindingDB.severity == severity)
        q = q.order_by(severity_order, FindingDB.firewall_id, FindingDB.check_id)

        result2 = await session.execute(q)
        findings = result2.scalars().all()

        # Build suppression map for Unsuppress buttons (only needed when showing suppressed)
        suppression_map: dict[str, dict[str, str | None]] = {}
        if show_suppressed:
            supp_result = await session.execute(select(SuppressionDB))
            suppression_map = {
                f"{s.firewall_id}:{s.check_id}": {"id": s.id, "reason": s.reason}
                for s in supp_result.scalars().all()
            }

    return templates.TemplateResponse(
        request,
        "partials/findings_table.html",
        {
            "findings": findings,
            "show_suppressed": show_suppressed,
            "suppression_map": suppression_map,
        },
    )


@router.get("/api/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(
    request: Request,
    finding_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """HTMX partial: full finding detail modal."""
    from opn_boss.core.database import FindingDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        finding = await session.get(FindingDB, finding_id)

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return templates.TemplateResponse(
        request,
        "partials/finding_detail.html",
        {"finding": finding},
    )
