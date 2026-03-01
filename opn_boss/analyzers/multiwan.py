"""Multi-WAN & failover analyzer: MW-001 through MW-008."""

from __future__ import annotations

from typing import Any

from opn_boss.analyzers.base import BaseAnalyzer
from opn_boss.core.types import Category, CollectorResult, Finding, Severity


class MultiWANAnalyzer(BaseAnalyzer):
    category = "multiwan"

    def analyze(
        self,
        firewall_id: str,
        collector_results: dict[str, CollectorResult],
    ) -> list[Finding]:
        findings: list[Finding] = []
        gateways = self._get_data(collector_results, "gateways")
        interfaces = self._get_data(collector_results, "interfaces")

        findings += self._mw001_primary_wan_down(firewall_id, gateways)
        findings += self._mw002_lte_failover_offline(firewall_id, gateways)
        findings += self._mw003_he_ipv6_down(firewall_id, gateways)
        findings += self._mw004_no_gateway_group(firewall_id, gateways)
        findings += self._mw005_lte_never_tested(firewall_id, gateways)
        findings += self._mw006_he_latency(firewall_id, gateways)
        findings += self._mw007_packet_loss(firewall_id, gateways)
        findings += self._mw008_asymmetric_routing(firewall_id, interfaces, gateways)

        return findings

    def _find_gateways(self, gateways: dict[str, Any], keywords: list[str]) -> list[dict[str, Any]]:
        items = gateways.get("gateways", [])
        result = []
        for gw in items:
            name = (gw.get("name", "") + " " + gw.get("descr", "")).lower()
            if any(kw.lower() in name for kw in keywords):
                result.append(gw)
        return result

    def _is_gateway_down(self, gw: dict[str, Any]) -> bool:
        """Check if a gateway is down, using both status and status_translated fields."""
        status = gw.get("status", "").lower()
        translated = gw.get("status_translated", "").lower()
        return status in ("down", "loss", "highdelay") or "offline" in translated

    def _mw001_primary_wan_down(self, firewall_id: str, gateways: dict[str, Any]) -> list[Finding]:
        if not gateways:
            return []
        items = gateways.get("gateways", [])
        # Primary WAN: one named WAN/DHCP/fiber/fastwyre, excluding LTE/5G/tunnel/IPv6
        lte_keywords = ("lte", "4g", "5g", "cellular", "mobile", "zte", "modem")
        tunnel_keywords = ("he.", "hurricane", "6in4", "tunnel", "v6", "ipv6")
        primary = [
            g for g in items
            if not any(kw in g.get("name", "").lower() for kw in lte_keywords + tunnel_keywords)
        ]
        if not primary:
            primary = items[:1]
        down = [g for g in primary if self._is_gateway_down(g)]
        if down:
            return [Finding(
                check_id="MW-001",
                title="Primary WAN gateway is down",
                description=(
                    f"Gateway {down[0].get('name', 'unknown')} is reporting status "
                    f"'{down[0].get('status')}'. Primary internet connectivity is lost."
                ),
                severity=Severity.CRITICAL,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                evidence={"gateways": [g.get("name") for g in down]},
                remediation=(
                    "Check physical WAN connection and ISP status. "
                    "Verify gateway monitoring settings under System → Gateways."
                ),
            )]
        return []

    def _mw002_lte_failover_offline(
        self, firewall_id: str, gateways: dict[str, Any]
    ) -> list[Finding]:
        lte_gws = self._find_gateways(gateways, ["lte", "4g", "5g", "cellular", "mobile", "zte"])
        if not lte_gws:
            return [Finding(
                check_id="MW-002",
                title="No LTE/cellular failover gateway configured",
                description=(
                    "No LTE or cellular failover gateway was detected. "
                    "If primary WAN fails, there is no automatic failover path."
                ),
                severity=Severity.WARNING,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                remediation=(
                    "Consider adding an LTE/cellular modem as a failover WAN. "
                    "Configure a gateway group with the LTE gateway as Tier 2."
                ),
            )]
        down = [g for g in lte_gws if self._is_gateway_down(g)]
        if down:
            return [Finding(
                check_id="MW-002",
                title="LTE failover gateway is offline",
                description=(
                    f"LTE failover gateway '{down[0].get('name')}' is down. "
                    "Failover will not work if primary WAN fails."
                ),
                severity=Severity.WARNING,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                evidence={"gateway": down[0].get("name"), "status": down[0].get("status")},
                remediation="Check LTE modem, SIM card, and carrier signal.",
            )]
        return []

    def _mw003_he_ipv6_down(self, firewall_id: str, gateways: dict[str, Any]) -> list[Finding]:
        he_gws = self._find_gateways(gateways, ["he.", "hurricane", "6in4", "ipv6"])
        if not he_gws:
            return []
        down = [g for g in he_gws if g.get("status", "").lower() in ("down", "loss")]
        if down:
            return [Finding(
                check_id="MW-003",
                title="Hurricane Electric IPv6 tunnel is down",
                description=(
                    f"HE.net IPv6 tunnel gateway '{down[0].get('name')}' is reporting "
                    f"status '{down[0].get('status')}'. IPv6 connectivity may be lost."
                ),
                severity=Severity.WARNING,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                evidence={"gateway": down[0].get("name")},
                remediation=(
                    "Check tunnel endpoint status at tunnelbroker.net. "
                    "Verify the tunnel's source IP matches your current WAN IP."
                ),
            )]
        return []

    def _mw004_no_gateway_group(self, firewall_id: str, gateways: dict[str, Any]) -> list[Finding]:
        """Check that at least one gateway group (for failover/load-balance) exists."""
        # Gateway groups are not in the status API but we can infer from having 2+ gateways.
        # Count all gateways (IPv4 + IPv6 + tunnels all count).
        items = gateways.get("gateways", [])
        if len(items) < 2:
            return [Finding(
                check_id="MW-004",
                title="Only one WAN gateway configured",
                description=(
                    "Only one gateway is configured. Without a failover gateway group, "
                    "there is no redundancy if the primary WAN fails."
                ),
                severity=Severity.WARNING,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                remediation=(
                    "Add a secondary WAN (LTE/cable/fiber) and configure a gateway group "
                    "under System → Gateways → Groups for automatic failover."
                ),
            )]
        return []

    def _mw005_lte_never_tested(
        self, firewall_id: str, gateways: dict[str, Any]
    ) -> list[Finding]:
        lte_gws = self._find_gateways(gateways, ["lte", "4g", "5g", "cellular", "zte"])
        for gw in lte_gws:
            # If monitor IP is empty or 0.0.0.0 → never configured for monitoring
            monitor = gw.get("monitor", "")
            if not monitor or monitor == "0.0.0.0":
                return [Finding(
                    check_id="MW-005",
                    title="LTE gateway has no monitor IP (never tested)",
                    description=(
                        f"Gateway '{gw.get('name')}' has no monitor IP configured. "
                        "Without monitoring, OPNSense cannot detect when failover is needed."
                    ),
                    severity=Severity.WARNING,
                    category=Category.MULTIWAN,
                    firewall_id=firewall_id,
                    evidence={"gateway": gw.get("name")},
                    remediation=(
                        "Set a monitor IP (e.g., 8.8.8.8 or carrier gateway) for the "
                        "LTE gateway under System → Gateways → All Gateways."
                    ),
                )]
        return []

    def _mw006_he_latency(self, firewall_id: str, gateways: dict[str, Any]) -> list[Finding]:
        he_gws = self._find_gateways(gateways, ["he.", "hurricane", "6in4"])
        for gw in he_gws:
            try:
                delay = float(str(gw.get("delay", "0")).replace("ms", "").strip() or 0)
            except (ValueError, AttributeError):
                delay = 0.0
            if delay > 150:
                return [Finding(
                    check_id="MW-006",
                    title=f"HE.net IPv6 tunnel latency is high ({delay:.0f}ms)",
                    description=(
                        f"IPv6 tunnel gateway '{gw.get('name')}' has latency of {delay:.0f}ms, "
                        "exceeding the 150ms threshold. IPv6 performance is degraded."
                    ),
                    severity=Severity.WARNING,
                    category=Category.MULTIWAN,
                    firewall_id=firewall_id,
                    evidence={"gateway": gw.get("name"), "delay_ms": delay},
                    remediation=(
                        "Check for WAN congestion. Consider switching to a different "
                        "HE.net tunnel endpoint closer to your location."
                    ),
                )]
        return []

    def _mw007_packet_loss(self, firewall_id: str, gateways: dict[str, Any]) -> list[Finding]:
        items = gateways.get("gateways", [])
        high_loss = []
        for gw in items:
            try:
                loss_str = str(gw.get("loss", "0")).replace("%", "").strip()
                loss = float(loss_str or 0)
            except (ValueError, AttributeError):
                loss = 0.0
            if loss > 5.0:
                high_loss.append({"name": gw.get("name"), "loss": loss})

        if high_loss:
            worst = max(high_loss, key=lambda x: x["loss"])
            return [Finding(
                check_id="MW-007",
                title=f"High packet loss on gateway ({worst['loss']:.0f}%)",
                description=(
                    f"Gateway '{worst['name']}' is experiencing {worst['loss']:.0f}% "
                    "packet loss, exceeding the 5% threshold."
                ),
                severity=Severity.WARNING,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                evidence={"gateways": high_loss},
                remediation=(
                    "Check ISP line quality, cables, and modem logs. "
                    "Persistent packet loss may indicate a hardware or line fault."
                ),
            )]
        return []

    def _mw008_asymmetric_routing(
        self, firewall_id: str, interfaces: dict[str, Any], gateways: dict[str, Any]
    ) -> list[Finding]:
        """Detect potential asymmetric routing (informational)."""
        items = gateways.get("gateways", [])
        active_gws = [g for g in items if g.get("status", "") not in ("down",)]
        if len(active_gws) >= 2:
            return [Finding(
                check_id="MW-008",
                title="Multiple active gateways — verify asymmetric routing",
                description=(
                    f"{len(active_gws)} gateways are active. With multi-WAN, ensure "
                    "reply-to rules are configured to prevent asymmetric routing issues."
                ),
                severity=Severity.INFO,
                category=Category.MULTIWAN,
                firewall_id=firewall_id,
                evidence={"active_gateways": [g.get("name") for g in active_gws]},
                remediation=(
                    "Ensure firewall pass rules have 'reply-to' configured. "
                    "Under System → Advanced → Firewall, enable 'Disable reply-to' "
                    "only if you understand the routing implications."
                ),
            )]
        return []
