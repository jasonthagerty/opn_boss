"""Tests for SecurityAnalyzer."""

from __future__ import annotations

import pytest

from opn_boss.analyzers.security import SecurityAnalyzer
from opn_boss.core.types import CollectorResult, Severity


def make_result(name: str, data: dict, success: bool = True) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        firewall_id="fw1",
        success=success,
        data=data,
    )


@pytest.fixture
def analyzer() -> SecurityAnalyzer:
    return SecurityAnalyzer()


def test_sec001_firmware_up_to_date(analyzer: SecurityAnalyzer):
    results = {
        "firmware": make_result("firmware", {
            "product_version": "24.7.1",
            "product_latest": "24.7.1",
        })
    }
    findings = analyzer.analyze("fw1", results)
    sec001 = [f for f in findings if f.check_id == "SEC-001"]
    assert len(sec001) == 1
    assert sec001[0].severity == Severity.OK


def test_sec001_firmware_outdated(analyzer: SecurityAnalyzer):
    results = {
        "firmware": make_result("firmware", {
            "product_version": "24.1.0",
            "product_latest": "24.7.1",
        })
    }
    findings = analyzer.analyze("fw1", results)
    sec001 = [f for f in findings if f.check_id == "SEC-001"]
    assert len(sec001) == 1
    assert sec001[0].severity == Severity.WARNING
    assert sec001[0].remediation is not None


def test_sec002_ids_not_running(analyzer: SecurityAnalyzer):
    results = {
        "ids": make_result("ids", {"running": False, "status": "stopped"})
    }
    findings = analyzer.analyze("fw1", results)
    sec002 = [f for f in findings if f.check_id == "SEC-002"]
    assert len(sec002) == 1
    assert sec002[0].severity == Severity.CRITICAL


def test_sec002_ids_running(analyzer: SecurityAnalyzer):
    results = {
        "ids": make_result("ids", {"running": True, "status": "running"})
    }
    findings = analyzer.analyze("fw1", results)
    sec002 = [f for f in findings if f.check_id == "SEC-002"]
    assert len(sec002) == 1
    assert sec002[0].severity == Severity.OK


def test_sec004_any_any_rule(analyzer: SecurityAnalyzer):
    results = {
        "firewall_rules": make_result("firewall_rules", {
            "total": 5,
            "enabled_count": 5,
            "disabled_count": 0,
            "rules": [
                {
                    "type": "pass",
                    "enabled": "1",
                    "source_net": "any",
                    "destination": "any",
                    "destination_port": "any",
                    "description": "Bad rule",
                }
            ],
        })
    }
    findings = analyzer.analyze("fw1", results)
    sec004 = [f for f in findings if f.check_id == "SEC-004"]
    assert len(sec004) == 1
    assert sec004[0].severity == Severity.WARNING


def test_sec006_ssh_on_wan(analyzer: SecurityAnalyzer):
    results = {
        "firewall_rules": make_result("firewall_rules", {
            "total": 3,
            "enabled_count": 3,
            "disabled_count": 0,
            "rules": [
                {
                    "type": "pass",
                    "enabled": "1",
                    "interface": "wan",
                    "destination_port": "22",
                    "source_net": "any",
                    "destination": "any",
                }
            ],
        })
    }
    findings = analyzer.analyze("fw1", results)
    sec006 = [f for f in findings if f.check_id == "SEC-006"]
    assert len(sec006) == 1
    assert sec006[0].severity == Severity.CRITICAL


def test_sec010_many_disabled(analyzer: SecurityAnalyzer):
    results = {
        "firewall_rules": make_result("firewall_rules", {
            "total": 50,
            "enabled_count": 30,
            "disabled_count": 20,
            "rules": [],
        })
    }
    findings = analyzer.analyze("fw1", results)
    sec010 = [f for f in findings if f.check_id == "SEC-010"]
    assert len(sec010) == 1
    assert sec010[0].severity == Severity.INFO


def test_empty_collector_results(analyzer: SecurityAnalyzer):
    """Analyzer should not raise with empty/failed collectors."""
    findings = analyzer.analyze("fw1", {})
    # Should return findings (informational ones at minimum)
    assert isinstance(findings, list)
