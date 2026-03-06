"""Tests for HaRecoveryAnalyzer."""

from __future__ import annotations

import pytest

from opn_boss.analyzers.ha_recovery import HaRecoveryAnalyzer
from opn_boss.core.types import CollectorResult, Severity


def make_result(name: str, data: dict, success: bool = True) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        firewall_id="fw2",
        success=success,
        data=data,
    )


@pytest.fixture
def analyzer() -> HaRecoveryAnalyzer:
    return HaRecoveryAnalyzer()


def test_ha002_carp_fault(analyzer: HaRecoveryAnalyzer):
    results = {
        "carp": make_result("carp", {"carp_status": "FAULT", "vips": {}}),
    }
    findings = analyzer.analyze("fw2", results)
    ha002 = [f for f in findings if f.check_id == "HA-002"]
    assert len(ha002) == 1
    assert ha002[0].severity == Severity.WARNING


def test_ha002_carp_master(analyzer: HaRecoveryAnalyzer):
    results = {
        "carp": make_result("carp", {"carp_status": "MASTER", "vips": {"vip1": {"advskew": "0"}}}),
    }
    findings = analyzer.analyze("fw2", results)
    ha002 = [f for f in findings if f.check_id == "HA-002"]
    assert len(ha002) == 1
    assert ha002[0].severity == Severity.OK


def test_ha004_ra_conflict_on_carp_fault(analyzer: HaRecoveryAnalyzer):
    """HA-004 should fire when CARP is in FAULT state."""
    results = {
        "carp": make_result("carp", {"carp_status": "FAULT", "vips": {}}),
        "interfaces": make_result("interfaces", {"interfaces": {}}),
    }
    findings = analyzer.analyze("fw2", results)
    ha004 = [f for f in findings if f.check_id == "HA-004"]
    assert len(ha004) == 1
    assert ha004[0].remediation is not None
    assert "radvd" in ha004[0].remediation.lower() or "Router Advertisement" in ha004[0].remediation


def test_ha004_ra_conflict_with_icmpv6(analyzer: HaRecoveryAnalyzer):
    """HA-004 critical when RA output detected on interfaces."""
    results = {
        "carp": make_result("carp", {"carp_status": "MASTER", "vips": {"v1": {"advskew": "0"}}}),
        "interfaces": make_result("interfaces", {
            "interfaces": {
                "em0": {"icmp6_output": 150},
                "em1": {"icmp6_output": 0},
            }
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha004 = [f for f in findings if f.check_id == "HA-004"]
    assert len(ha004) == 1
    assert ha004[0].severity == Severity.CRITICAL


def test_ha005_advskew_inconsistent(analyzer: HaRecoveryAnalyzer):
    results = {
        "carp": make_result("carp", {
            "carp_status": "BACKUP",
            "vips": {
                "vip1": {"advskew": "100"},
                "vip2": {"advskew": "150"},  # inconsistent!
            },
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha005 = [f for f in findings if f.check_id == "HA-005"]
    assert len(ha005) == 1
    assert ha005[0].severity == Severity.WARNING


def test_ha009_no_vips(analyzer: HaRecoveryAnalyzer):
    results = {
        "carp": make_result("carp", {"carp_status": "MASTER", "vips": {}}),
    }
    findings = analyzer.analyze("fw2", results)
    ha009 = [f for f in findings if f.check_id == "HA-009"]
    assert len(ha009) == 1
    assert ha009[0].severity == Severity.INFO


def test_ha_remediation_contains_steps(analyzer: HaRecoveryAnalyzer):
    """RA conflict remediation should include actionable steps."""
    results = {
        "carp": make_result("carp", {"carp_status": "INIT", "vips": {}}),
        "interfaces": make_result("interfaces", {"interfaces": {}}),
    }
    findings = analyzer.analyze("fw2", results)
    ha004 = [f for f in findings if f.check_id == "HA-004"]
    assert ha004, "HA-004 should fire for INIT state"
    remediation = ha004[0].remediation or ""
    assert "Router Advertisement" in remediation
    assert len(remediation) > 200  # Should be detailed


def test_empty_results_no_raise(analyzer: HaRecoveryAnalyzer):
    findings = analyzer.analyze("fw2", {})
    assert isinstance(findings, list)


# ── HA-010: Unbound DNS down ──────────────────────────────────────────────────

def test_ha010_unbound_stopped(analyzer: HaRecoveryAnalyzer):
    """HA-010 CRITICAL when Unbound reports running=False."""
    results = {
        "services": make_result("services", {
            "unbound": {"running": False, "status": "stopped"},
            "ids": {"running": True, "status": "running"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha010 = [f for f in findings if f.check_id == "HA-010"]
    assert len(ha010) == 1
    assert ha010[0].severity == Severity.CRITICAL


def test_ha010_unbound_running_no_finding(analyzer: HaRecoveryAnalyzer):
    results = {
        "services": make_result("services", {
            "unbound": {"running": True, "status": "running"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    assert not any(f.check_id == "HA-010" for f in findings)


def test_ha010_unbound_unreachable_warning(analyzer: HaRecoveryAnalyzer):
    """HA-010 WARNING when endpoint returned None (unreachable)."""
    results = {
        "services": make_result("services", {
            "unbound": {"running": None, "status": "unreachable"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha010 = [f for f in findings if f.check_id == "HA-010"]
    assert len(ha010) == 1
    assert ha010[0].severity == Severity.WARNING


def test_ha010_remediation_mentions_disk(analyzer: HaRecoveryAnalyzer):
    results = {
        "services": make_result("services", {
            "unbound": {"running": False, "status": "stopped"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha010 = [f for f in findings if f.check_id == "HA-010"]
    assert ha010
    remediation = ha010[0].remediation or ""
    assert "disk" in remediation.lower() or "/var/log" in remediation


# ── HA-011: Other services down ───────────────────────────────────────────────

def test_ha011_other_service_down(analyzer: HaRecoveryAnalyzer):
    """HA-011 WARNING for non-unbound/ids service that is down."""
    results = {
        "services": make_result("services", {
            "unbound": {"running": True, "status": "running"},
            "ids": {"running": True, "status": "running"},
            "hostwatch": {"running": False, "status": "stopped"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    ha011 = [f for f in findings if f.check_id == "HA-011"]
    assert len(ha011) == 1
    assert ha011[0].severity == Severity.WARNING
    assert "hostwatch" in ha011[0].title


def test_ha011_no_finding_when_all_running(analyzer: HaRecoveryAnalyzer):
    results = {
        "services": make_result("services", {
            "unbound": {"running": True, "status": "running"},
            "ids": {"running": True, "status": "running"},
            "hostwatch": {"running": True, "status": "running"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    assert not any(f.check_id == "HA-011" for f in findings)


def test_ha011_ids_down_not_duplicated(analyzer: HaRecoveryAnalyzer):
    """IDS down should NOT trigger HA-011 — it has its own check (SEC-002)."""
    results = {
        "services": make_result("services", {
            "ids": {"running": False, "status": "stopped"},
            "unbound": {"running": True, "status": "running"},
        }),
    }
    findings = analyzer.analyze("fw2", results)
    assert not any(f.check_id == "HA-011" for f in findings)
