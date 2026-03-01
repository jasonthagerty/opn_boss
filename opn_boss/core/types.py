"""Core domain types: enums, dataclasses, and result containers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


class Category(StrEnum):
    SECURITY = "security"
    MULTIWAN = "multiwan"
    HA_RECOVERY = "ha_recovery"
    PERFORMANCE = "performance"


@dataclass
class Finding:
    """A single analysis finding from a check."""

    check_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    firewall_id: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    ts: datetime = field(default_factory=datetime.utcnow)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "firewall_id": self.firewall_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "ts": self.ts.isoformat(),
        }


@dataclass
class CollectorResult:
    """Result from a single collector run."""

    collector_name: str
    firewall_id: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0
    ts: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SnapshotSummary:
    """Summary of a completed scan snapshot."""

    snapshot_id: str
    firewall_id: str
    started_at: datetime
    completed_at: datetime | None
    status: str  # "running" | "completed" | "failed" | "offline"
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    ok_count: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return self.critical_count + self.warning_count + self.info_count + self.ok_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "firewall_id": self.firewall_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "ok_count": self.ok_count,
            "total_findings": self.total_findings,
        }
