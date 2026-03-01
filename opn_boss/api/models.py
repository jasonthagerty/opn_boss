"""Pydantic request/response schemas for the API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    check_id: str
    title: str
    description: str
    severity: str
    category: str
    firewall_id: str
    evidence: dict[str, Any]
    remediation: str | None
    ts: datetime


class SnapshotResponse(BaseModel):
    snapshot_id: str
    firewall_id: str
    started_at: datetime
    completed_at: datetime | None
    status: str
    critical_count: int
    warning_count: int
    info_count: int
    ok_count: int
    total_findings: int


class FirewallStateResponse(BaseModel):
    firewall_id: str
    online: bool
    role: str
    last_seen: str | None
    last_checked: str | None


class ScanResponse(BaseModel):
    message: str
    status: str = "accepted"


class SnapshotWithFindings(SnapshotResponse):
    findings: list[FindingResponse]
