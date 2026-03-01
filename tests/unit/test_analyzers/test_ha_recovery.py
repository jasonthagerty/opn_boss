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
