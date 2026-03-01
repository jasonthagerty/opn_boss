"""Snapshot API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from opn_boss.api.dependencies import get_service
from opn_boss.api.models import FindingResponse, SnapshotResponse, SnapshotWithFindings
from opn_boss.service.main import OPNBossService

router = APIRouter()


@router.get("/api/snapshots", response_model=list[SnapshotResponse])
async def list_snapshots(
    firewall_id: str | None = Query(default=None),
    limit: int = Query(default=50, le=500),
    service: OPNBossService = Depends(get_service),
) -> list[SnapshotResponse]:
    """List recent scan snapshots, optionally filtered by firewall."""
    from sqlalchemy import desc, select

    from opn_boss.core.database import SnapshotDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        q = select(SnapshotDB).order_by(desc(SnapshotDB.started_at)).limit(limit)
        if firewall_id:
            q = q.where(SnapshotDB.firewall_id == firewall_id)
        result = await session.execute(q)
        snaps = result.scalars().all()

    return [
        SnapshotResponse(
            snapshot_id=s.id,
            firewall_id=s.firewall_id,
            started_at=s.started_at,
            completed_at=s.completed_at,
            status=s.status,
            critical_count=s.critical_count,
            warning_count=s.warning_count,
            info_count=s.info_count,
            ok_count=s.ok_count,
            total_findings=s.critical_count + s.warning_count + s.info_count + s.ok_count,
        )
        for s in snaps
    ]


@router.get("/api/snapshots/{snapshot_id}/findings", response_model=SnapshotWithFindings)
async def get_snapshot_findings(
    snapshot_id: str,
    severity: str | None = Query(default=None),
    service: OPNBossService = Depends(get_service),
) -> SnapshotWithFindings:
    """Get a snapshot with all its findings."""
    from sqlalchemy import select

    from opn_boss.core.database import FindingDB, SnapshotDB, get_session_factory

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        snap = await session.get(SnapshotDB, snapshot_id)
        if not snap:
            raise HTTPException(status_code=404, detail="Snapshot not found")

        q = select(FindingDB).where(FindingDB.snapshot_id == snapshot_id)
        if severity:
            q = q.where(FindingDB.severity == severity)
        result = await session.execute(q)
        findings = result.scalars().all()

    return SnapshotWithFindings(
        snapshot_id=snap.id,
        firewall_id=snap.firewall_id,
        started_at=snap.started_at,
        completed_at=snap.completed_at,
        status=snap.status,
        critical_count=snap.critical_count,
        warning_count=snap.warning_count,
        info_count=snap.info_count,
        ok_count=snap.ok_count,
        total_findings=snap.critical_count + snap.warning_count + snap.info_count + snap.ok_count,
        findings=[
            FindingResponse(
                id=f.id,
                check_id=f.check_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                category=f.category,
                firewall_id=f.firewall_id,
                evidence=f.evidence or {},
                remediation=f.remediation,
                ts=f.ts,
            )
            for f in findings
        ],
    )
