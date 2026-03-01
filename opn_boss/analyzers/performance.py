"""Performance analyzer: PERF-001 through PERF-010."""

from __future__ import annotations

from typing import Any

from opn_boss.analyzers.base import BaseAnalyzer
from opn_boss.core.types import Category, CollectorResult, Finding, Severity


class PerformanceAnalyzer(BaseAnalyzer):
    category = "performance"

    # Thresholds
    CPU_CRITICAL = 90.0
    MEMORY_WARNING = 90.0
    MEMORY_CRITICAL = 95.0
    WAN_MBPS_WARNING = 800.0  # ~800 Mbps
    STATE_TABLE_CRITICAL = 85.0
    DISK_WARNING = 80.0
    DHCP_POOL_WARNING = 90.0
    SHORT_UPTIME_HOURS = 1.0

    def analyze(
        self,
        firewall_id: str,
        collector_results: dict[str, CollectorResult],
    ) -> list[Finding]:
        findings: list[Finding] = []
        system = self._get_data(collector_results, "system")
        interfaces = self._get_data(collector_results, "interfaces")
        dns = self._get_data(collector_results, "dns")
        dhcp = self._get_data(collector_results, "dhcp")

        findings += self._perf001_cpu(firewall_id, system)
        findings += self._perf002_memory(firewall_id, system)
        findings += self._perf003_wan_util(firewall_id, interfaces)
        findings += self._perf004_state_table(firewall_id, system)
        findings += self._perf005_iface_errors(firewall_id, interfaces)
        findings += self._perf006_dns_spike(firewall_id, dns)
        findings += self._perf007_dhcp_pool(firewall_id, dhcp)
        findings += self._perf008_disk(firewall_id, system)
        findings += self._perf009_short_uptime(firewall_id, system)
        findings += self._perf010_iface_drops(firewall_id, interfaces)

        return findings

    def _perf001_cpu(self, firewall_id: str, system: dict[str, Any]) -> list[Finding]:
        if not system:
            return []
        try:
            cpu = float(system.get("cpu_usage", 0))
        except (ValueError, TypeError):
            return []
        if cpu >= self.CPU_CRITICAL:
            return [Finding(
                check_id="PERF-001",
                title=f"CPU usage critical ({cpu:.0f}%)",
                description=(
                    f"CPU utilization is {cpu:.0f}%, exceeding the {self.CPU_CRITICAL}% threshold. "
                    "High CPU can cause packet drops and connection timeouts."
                ),
                severity=Severity.CRITICAL,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"cpu_pct": cpu},
                remediation=(
                    "Check running processes under Diagnostics → Activity. "
                    "Common causes: IDS/IPS with too many rules, large NAT table, "
                    "or software update running in background."
                ),
            )]
        return []

    def _perf002_memory(self, firewall_id: str, system: dict[str, Any]) -> list[Finding]:
        if not system:
            return []
        total = system.get("memory_total", 0)
        used = system.get("memory_used", 0)
        pct = system.get("memory_percent", 0)

        if not total:
            return []
        try:
            pct = float(str(pct).replace("%", "") or 0)
            if pct == 0 and total and used:
                pct = (float(used) / float(total)) * 100
        except (ValueError, TypeError):
            return []

        if pct >= self.MEMORY_CRITICAL:
            return [Finding(
                check_id="PERF-002",
                title=f"Memory usage critical ({pct:.0f}%)",
                description=(
                    f"Memory utilization is {pct:.0f}%, above the {self.MEMORY_CRITICAL}% critical threshold. "
                    "At this level the firewall may begin actively swapping, causing instability."
                ),
                severity=Severity.CRITICAL,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"memory_pct": pct, "used": used, "total": total},
                remediation=(
                    "Review memory consumers under Diagnostics → Activity. "
                    "Consider reducing IDS rule sets or adding RAM."
                ),
            )]
        if pct >= self.MEMORY_WARNING:
            return [Finding(
                check_id="PERF-002",
                title=f"Memory usage high ({pct:.0f}%)",
                description=(
                    f"Memory utilization is {pct:.0f}%, above the {self.MEMORY_WARNING}% threshold. "
                    "On BSD systems this often reflects file cache (ARC/inactive pages) rather than "
                    "true memory pressure. Monitor swap I/O rate to confirm whether action is needed."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"memory_pct": pct, "used": used, "total": total},
                remediation=(
                    "Review memory consumers under Diagnostics → Activity. "
                    "Check swap I/O rate — if swap is not actively paging, this is likely "
                    "normal BSD cache behaviour. Consider reducing IDS rule sets or adding RAM "
                    "if swap I/O is sustained."
                ),
            )]
        return []

    def _perf003_wan_util(self, firewall_id: str, interfaces: dict[str, Any]) -> list[Finding]:
        """Check for high WAN interface utilization."""
        ifaces = interfaces.get("interfaces", {})
        warnings = []
        for name, stats in ifaces.items():
            if not isinstance(stats, dict):
                continue
            if "wan" not in name.lower():
                continue
            try:
                in_bps = float(stats.get("ibytes", 0))
                out_bps = float(stats.get("obytes", 0))
                # Convert to Mbps (rough estimate — bytes are cumulative)
                # For instantaneous we'd need delta; flag if total is very large
                total_gb = (in_bps + out_bps) / (1024 ** 3)
                if total_gb > 100:  # more than 100 GB suggests high utilization
                    warnings.append({"interface": name, "total_gb": total_gb})
            except (ValueError, TypeError):
                continue
        if warnings:
            return [Finding(
                check_id="PERF-003",
                title="High WAN interface data volume",
                description=(
                    f"WAN interface(s) {[w['interface'] for w in warnings]} show high "
                    "cumulative byte counts. Monitor for sustained high utilization."
                ),
                severity=Severity.INFO,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"interfaces": warnings},
            )]
        return []

    def _perf004_state_table(self, firewall_id: str, system: dict[str, Any]) -> list[Finding]:
        """Check state table fill percentage."""
        if not system:
            return []
        raw = system.get("raw", {})
        # State table info may be in pfstats or states key
        states_used = raw.get("states", {}).get("current", 0) if isinstance(raw, dict) else 0
        states_max = raw.get("states", {}).get("max", 0) if isinstance(raw, dict) else 0
        if not states_max:
            return []
        try:
            pct = (float(states_used) / float(states_max)) * 100
        except (ValueError, ZeroDivisionError):
            return []
        if pct >= self.STATE_TABLE_CRITICAL:
            return [Finding(
                check_id="PERF-004",
                title=f"State table nearly full ({pct:.0f}%)",
                description=(
                    f"The firewall state table is {pct:.0f}% full "
                    f"({states_used:,}/{states_max:,} states). "
                    "A full state table will cause new connections to be dropped."
                ),
                severity=Severity.CRITICAL,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"states_used": states_used, "states_max": states_max, "pct": pct},
                remediation=(
                    "Increase state table size under System → Advanced → Firewall. "
                    "Investigate applications creating excessive connections. "
                    "Check for port scans or DDoS activity."
                ),
            )]
        return []

    def _perf005_iface_errors(self, firewall_id: str, interfaces: dict[str, Any]) -> list[Finding]:
        """Flag interfaces with input/output errors."""
        ifaces = interfaces.get("interfaces", {})
        error_ifaces = []
        for name, stats in ifaces.items():
            if not isinstance(stats, dict):
                continue
            try:
                ierrors = int(stats.get("ierrors", 0))
                oerrors = int(stats.get("oerrors", 0))
                if ierrors > 100 or oerrors > 100:
                    error_ifaces.append({
                        "interface": name,
                        "ierrors": ierrors,
                        "oerrors": oerrors,
                    })
            except (ValueError, TypeError):
                continue
        if error_ifaces:
            return [Finding(
                check_id="PERF-005",
                title=f"Interface errors on {len(error_ifaces)} interface(s)",
                description=(
                    f"Interfaces with elevated error counts: "
                    f"{[i['interface'] for i in error_ifaces]}. "
                    "Errors indicate hardware or cabling issues."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"interfaces": error_ifaces},
                remediation=(
                    "Check physical cables, SFP modules, and switch ports. "
                    "Review interface settings (speed/duplex auto-negotiation)."
                ),
            )]
        return []

    def _perf006_dns_spike(self, firewall_id: str, dns: dict[str, Any]) -> list[Finding]:
        """Detect DNS query spikes — unwanted queries may indicate DNS abuse."""
        if not dns:
            return []
        unwanted = dns.get("unwanted_queries", 0)
        total = dns.get("queries_total", 1)
        if total < 100:
            return []
        try:
            pct = (float(unwanted) / float(total)) * 100
        except (ValueError, ZeroDivisionError):
            return []
        if pct > 10:
            return [Finding(
                check_id="PERF-006",
                title=f"High DNS unwanted query rate ({pct:.0f}%)",
                description=(
                    f"Unbound reports {unwanted:,} unwanted queries out of {total:,} total "
                    f"({pct:.0f}%). This may indicate a misconfigured client or DNS abuse."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"unwanted_queries": unwanted, "total_queries": total, "pct": pct},
                remediation=(
                    "Enable DNS query logging to identify the source. "
                    "Consider enabling DNS blacklisting under Services → Unbound DNS → Blocklists."
                ),
            )]
        return []

    def _perf007_dhcp_pool(self, firewall_id: str, dhcp: dict[str, Any]) -> list[Finding]:
        """Warn if DHCP lease pool is near exhaustion."""
        if not dhcp:
            return []
        total = dhcp.get("total", 0)
        active = dhcp.get("active_count", 0)
        if total < 10:
            return []
        try:
            pct = (float(active) / float(total)) * 100
        except (ValueError, ZeroDivisionError):
            return []
        if pct >= self.DHCP_POOL_WARNING:
            return [Finding(
                check_id="PERF-007",
                title=f"DHCP lease pool nearly exhausted ({pct:.0f}%)",
                description=(
                    f"DHCP pool is {pct:.0f}% full ({active}/{total} leases used). "
                    "New devices may fail to get an IP address."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"active_leases": active, "total_leases": total, "pct": pct},
                remediation=(
                    "Expand the DHCP range under Services → DHCPv4. "
                    "Review and remove stale static mappings."
                ),
            )]
        return []

    def _perf008_disk(self, firewall_id: str, system: dict[str, Any]) -> list[Finding]:
        if not system:
            return []
        disk_pct = system.get("disk_percent", 0)
        try:
            pct = float(str(disk_pct).replace("%", "") or 0)
        except (ValueError, TypeError):
            return []
        if pct >= self.DISK_WARNING:
            return [Finding(
                check_id="PERF-008",
                title=f"Disk usage high ({pct:.0f}%)",
                description=(
                    f"Disk utilization is {pct:.0f}%, above the {self.DISK_WARNING}% threshold. "
                    "Full disk can prevent logging and cause system instability."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"disk_pct": pct},
                remediation=(
                    "Check large files: System → Log Files. "
                    "Reduce log retention or RRD data. "
                    "Consider clearing the pkg cache: pkg clean -y."
                ),
            )]
        return []

    def _perf009_short_uptime(self, firewall_id: str, system: dict[str, Any]) -> list[Finding]:
        """Flag a recent reboot (uptime < 1 hour)."""
        if not system:
            return []
        uptime_sec = system.get("uptime_seconds", 0)
        try:
            uptime_sec = float(uptime_sec or 0)
        except (ValueError, TypeError):
            return []
        threshold_sec = self.SHORT_UPTIME_HOURS * 3600
        if 0 < uptime_sec < threshold_sec:
            hours = uptime_sec / 3600
            return [Finding(
                check_id="PERF-009",
                title=f"Short uptime ({hours:.1f}h) — recent reboot",
                description=(
                    f"Uptime is {hours:.1f} hours. The firewall was recently rebooted. "
                    "Verify this was intentional and check for crash logs."
                ),
                severity=Severity.INFO,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"uptime_seconds": uptime_sec},
                remediation=(
                    "Review System → Log Files → System for crash or reboot cause."
                ),
            )]
        return []

    def _perf010_iface_drops(self, firewall_id: str, interfaces: dict[str, Any]) -> list[Finding]:
        """Flag interfaces with input drops (buffer/queue drops)."""
        ifaces = interfaces.get("interfaces", {})
        drop_ifaces = []
        for name, stats in ifaces.items():
            if not isinstance(stats, dict):
                continue
            try:
                idrops = int(stats.get("iqdrops", 0))
                if idrops > 500:
                    drop_ifaces.append({"interface": name, "drops": idrops})
            except (ValueError, TypeError):
                continue
        if drop_ifaces:
            return [Finding(
                check_id="PERF-010",
                title=f"Interface input drops on {len(drop_ifaces)} interface(s)",
                description=(
                    f"Interfaces {[d['interface'] for d in drop_ifaces]} show input queue drops. "
                    "Drops indicate the system cannot process packets fast enough."
                ),
                severity=Severity.WARNING,
                category=Category.PERFORMANCE,
                firewall_id=firewall_id,
                evidence={"interfaces": drop_ifaces},
                remediation=(
                    "Investigate high-traffic interfaces. "
                    "Consider hardware offloading: System → Advanced → Networking. "
                    "Check CPU utilization during peak traffic."
                ),
            )]
        return []
