"""Tests for MultiWANAnalyzer."""

from __future__ import annotations

import pytest

from opn_boss.analyzers.multiwan import MultiWANAnalyzer
from opn_boss.core.types import CollectorResult, Severity


def make_result(name: str, data: dict, success: bool = True) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        firewall_id="fw1",
        success=success,
        data=data,
    )


@pytest.fixture
def analyzer() -> MultiWANAnalyzer:
    return MultiWANAnalyzer()


def test_mw001_primary_wan_down(analyzer: MultiWANAnalyzer):
    results = {
        "gateways": make_result("gateways", {
            "gateways": [
                {"name": "WAN_DHCP", "status": "down", "descr": "Primary WAN"},
            ],
            "total": 1,
        })
    }
    findings = analyzer.analyze("fw1", results)
    mw001 = [f for f in findings if f.check_id == "MW-001"]
    assert len(mw001) == 1
    assert mw001[0].severity == Severity.CRITICAL


def test_mw001_primary_wan_up(analyzer: MultiWANAnalyzer):
    results = {
        "gateways": make_result("gateways", {
            "gateways": [
                {"name": "WAN_DHCP", "status": "online", "descr": "Primary WAN"},
            ],
            "total": 1,
        })
    }
    findings = analyzer.analyze("fw1", results)
    mw001 = [f for f in findings if f.check_id == "MW-001"]
    assert len(mw001) == 0


def test_mw006_he_high_latency(analyzer: MultiWANAnalyzer):
    results = {
        "gateways": make_result("gateways", {
            "gateways": [
                {"name": "HE.NET_TUNNEL", "status": "online", "delay": "200ms", "descr": "Hurricane Electric IPv6"},
            ],
            "total": 1,
        })
    }
    findings = analyzer.analyze("fw1", results)
    mw006 = [f for f in findings if f.check_id == "MW-006"]
    assert len(mw006) == 1
    assert mw006[0].severity == Severity.WARNING


def test_mw007_packet_loss(analyzer: MultiWANAnalyzer):
    results = {
        "gateways": make_result("gateways", {
            "gateways": [
                {"name": "WAN_DHCP", "status": "loss", "loss": "10%"},
            ],
            "total": 1,
        })
    }
    findings = analyzer.analyze("fw1", results)
    mw007 = [f for f in findings if f.check_id == "MW-007"]
    assert len(mw007) == 1


def test_mw004_single_gateway(analyzer: MultiWANAnalyzer):
    """Single gateway should trigger MW-004."""
    results = {
        "gateways": make_result("gateways", {
            "gateways": [{"name": "WAN", "status": "online"}],
            "total": 1,
        })
    }
    findings = analyzer.analyze("fw1", results)
    mw004 = [f for f in findings if f.check_id == "MW-004"]
    assert len(mw004) == 1


def test_empty_results(analyzer: MultiWANAnalyzer):
    findings = analyzer.analyze("fw1", {})
    assert isinstance(findings, list)
