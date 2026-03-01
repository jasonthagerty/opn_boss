"""Tests for core types."""

from __future__ import annotations

from datetime import datetime

from opn_boss.core.types import Category, Finding, Severity, SnapshotSummary


def test_finding_to_dict():
    f = Finding(
        check_id="SEC-001",
        title="Test finding",
        description="Test description",
        severity=Severity.WARNING,
        category=Category.SECURITY,
        firewall_id="fw1",
        evidence={"key": "value"},
        remediation="Fix it",
    )
    d = f.to_dict()
    assert d["check_id"] == "SEC-001"
    assert d["severity"] == "warning"
    assert d["category"] == "security"
    assert d["firewall_id"] == "fw1"
    assert d["evidence"] == {"key": "value"}
    assert "id" in d
    assert "ts" in d


def test_finding_defaults():
    f = Finding(
        check_id="TEST-001",
        title="T",
        description="D",
        severity=Severity.OK,
        category=Category.PERFORMANCE,
        firewall_id="fw1",
    )
    assert f.evidence == {}
    assert f.remediation is None
    assert isinstance(f.ts, datetime)
    assert len(f.id) == 36  # UUID


def test_snapshot_summary_total():
    s = SnapshotSummary(
        snapshot_id="snap-1",
        firewall_id="fw1",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        status="completed",
        critical_count=2,
        warning_count=3,
        info_count=5,
        ok_count=10,
    )
    assert s.total_findings == 20


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.WARNING.value == "warning"
    assert Severity.INFO.value == "info"
    assert Severity.OK.value == "ok"


def test_category_values():
    assert Category.SECURITY.value == "security"
    assert Category.MULTIWAN.value == "multiwan"
    assert Category.HA_RECOVERY.value == "ha_recovery"
    assert Category.PERFORMANCE.value == "performance"
