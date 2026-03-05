"""Tests for PerformanceAnalyzer."""

from __future__ import annotations

import pytest

from opn_boss.analyzers.performance import PerformanceAnalyzer
from opn_boss.core.types import CollectorResult, Severity


def make_result(name: str, data: dict, success: bool = True) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        firewall_id="fw1",
        success=success,
        data=data,
    )


@pytest.fixture
def analyzer() -> PerformanceAnalyzer:
    return PerformanceAnalyzer()


def test_perf001_high_cpu(analyzer: PerformanceAnalyzer):
    results = {
        "system": make_result("system", {"cpu_usage": 95.0})
    }
    findings = analyzer.analyze("fw1", results)
    perf001 = [f for f in findings if f.check_id == "PERF-001"]
    assert len(perf001) == 1
    assert perf001[0].severity == Severity.CRITICAL


def test_perf001_normal_cpu(analyzer: PerformanceAnalyzer):
    results = {
        "system": make_result("system", {"cpu_usage": 45.0})
    }
    findings = analyzer.analyze("fw1", results)
    perf001 = [f for f in findings if f.check_id == "PERF-001"]
    assert len(perf001) == 0


def test_perf002_high_memory(analyzer: PerformanceAnalyzer):
    # 92.5% — above WARNING (90%) but below CRITICAL (95%)
    results = {
        "system": make_result("system", {
            "memory_total": 8_000_000,
            "memory_used": 7_400_000,
            "memory_percent": 92.5,
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf002 = [f for f in findings if f.check_id == "PERF-002"]
    assert len(perf002) == 1
    assert perf002[0].severity == Severity.WARNING


def test_perf002_critical_memory(analyzer: PerformanceAnalyzer):
    # 97.5% — above CRITICAL (95%)
    results = {
        "system": make_result("system", {
            "memory_total": 8_000_000,
            "memory_used": 7_800_000,
            "memory_percent": 97.5,
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf002 = [f for f in findings if f.check_id == "PERF-002"]
    assert len(perf002) == 1
    assert perf002[0].severity == Severity.CRITICAL


def test_perf002_normal_memory(analyzer: PerformanceAnalyzer):
    # 85% — below WARNING threshold, should not fire
    results = {
        "system": make_result("system", {
            "memory_total": 8_000_000,
            "memory_used": 6_800_000,
            "memory_percent": 85.0,
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf002 = [f for f in findings if f.check_id == "PERF-002"]
    assert len(perf002) == 0


def test_perf005_interface_errors(analyzer: PerformanceAnalyzer):
    results = {
        "interfaces": make_result("interfaces", {
            "interfaces": {
                "em0": {"ierrors": 500, "oerrors": 0},
                "em1": {"ierrors": 0, "oerrors": 0},
            }
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf005 = [f for f in findings if f.check_id == "PERF-005"]
    assert len(perf005) == 1
    assert perf005[0].severity == Severity.WARNING


def test_perf007_dhcp_pool_full(analyzer: PerformanceAnalyzer):
    results = {
        "dhcp": make_result("dhcp", {
            "total": 100,
            "active_count": 95,
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf007 = [f for f in findings if f.check_id == "PERF-007"]
    assert len(perf007) == 1
    assert perf007[0].severity == Severity.WARNING


def test_perf009_short_uptime(analyzer: PerformanceAnalyzer):
    results = {
        "system": make_result("system", {"uptime_seconds": 120})  # 2 minutes
    }
    findings = analyzer.analyze("fw1", results)
    perf009 = [f for f in findings if f.check_id == "PERF-009"]
    assert len(perf009) == 1
    assert perf009[0].severity == Severity.INFO


def test_perf009_normal_uptime(analyzer: PerformanceAnalyzer):
    results = {
        "system": make_result("system", {"uptime_seconds": 86400})  # 24 hours
    }
    findings = analyzer.analyze("fw1", results)
    perf009 = [f for f in findings if f.check_id == "PERF-009"]
    assert len(perf009) == 0


def test_perf010_interface_drops(analyzer: PerformanceAnalyzer):
    results = {
        "interfaces": make_result("interfaces", {
            "interfaces": {
                "em0": {"iqdrops": 1000},
            }
        })
    }
    findings = analyzer.analyze("fw1", results)
    perf010 = [f for f in findings if f.check_id == "PERF-010"]
    assert len(perf010) == 1


def test_empty_results(analyzer: PerformanceAnalyzer):
    findings = analyzer.analyze("fw1", {})
    assert isinstance(findings, list)


def test_perf011_load_avg_critical(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {"loadavg": "11.5, 8.2, 6.1"})}
    findings = analyzer.analyze("fw1", results)
    f = next((f for f in findings if f.check_id == "PERF-011"), None)
    assert f is not None
    assert f.severity == Severity.CRITICAL


def test_perf011_load_avg_warning(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {"loadavg": "5.2, 4.0, 3.1"})}
    findings = analyzer.analyze("fw1", results)
    f = next((f for f in findings if f.check_id == "PERF-011"), None)
    assert f is not None
    assert f.severity == Severity.WARNING


def test_perf011_load_avg_ok(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {"loadavg": "0.5, 0.4, 0.3"})}
    findings = analyzer.analyze("fw1", results)
    assert not any(f.check_id == "PERF-011" for f in findings)


def test_perf011_no_loadavg(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {"loadavg": ""})}
    findings = analyzer.analyze("fw1", results)
    assert not any(f.check_id == "PERF-011" for f in findings)


# ── PERF-012: Log filesystem usage ───────────────────────────────────────────

def test_perf012_critical(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {
        "disk_percent": 90.0,
        "disk_used": 460_000,
        "disk_total": 512_000,
    })}
    findings = analyzer.analyze("fw1", results)
    f = next((f for f in findings if f.check_id == "PERF-012"), None)
    assert f is not None
    assert f.severity == Severity.CRITICAL


def test_perf012_warning(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {
        "disk_percent": 75.0,
        "disk_used": 384_000,
        "disk_total": 512_000,
    })}
    findings = analyzer.analyze("fw1", results)
    f = next((f for f in findings if f.check_id == "PERF-012"), None)
    assert f is not None
    assert f.severity == Severity.WARNING


def test_perf012_no_finding_below_threshold(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {
        "disk_percent": 50.0,
        "disk_used": 256_000,
        "disk_total": 512_000,
    })}
    findings = analyzer.analyze("fw1", results)
    assert not any(f.check_id == "PERF-012" for f in findings)


def test_perf012_zero_disk_percent_skipped(analyzer: PerformanceAnalyzer):
    """disk_percent == 0 means data unavailable — must not false-alarm."""
    results = {"system": make_result("system", {
        "disk_percent": 0,
        "disk_used": 0,
        "disk_total": 0,
    })}
    findings = analyzer.analyze("fw1", results)
    assert not any(f.check_id == "PERF-012" for f in findings)


def test_perf012_remediation_mentions_suricata(analyzer: PerformanceAnalyzer):
    results = {"system": make_result("system", {"disk_percent": 88.0})}
    findings = analyzer.analyze("fw1", results)
    f = next((f for f in findings if f.check_id == "PERF-012"), None)
    assert f is not None
    remediation = f.remediation or ""
    assert "suricata" in remediation.lower() or "intrusion" in remediation.lower()
