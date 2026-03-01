"""Security analyzer: SEC-001 through SEC-010."""

from __future__ import annotations

from typing import Any

from opn_boss.analyzers.base import BaseAnalyzer
from opn_boss.core.types import Category, CollectorResult, Finding, Severity


class SecurityAnalyzer(BaseAnalyzer):
    category = "security"

    def analyze(
        self,
        firewall_id: str,
        collector_results: dict[str, CollectorResult],
    ) -> list[Finding]:
        findings: list[Finding] = []
        firmware = self._get_data(collector_results, "firmware")
        ids_data = self._get_data(collector_results, "ids")
        rules_data = self._get_data(collector_results, "firewall_rules")
        interfaces = self._get_data(collector_results, "interfaces")

        findings += self._sec001_firmware_outdated(firewall_id, firmware)
        findings += self._sec002_ids_down(firewall_id, ids_data)
        findings += self._sec003_admin_on_wan(firewall_id, interfaces, rules_data)
        findings += self._sec004_any_any_rules(firewall_id, rules_data)
        findings += self._sec005_anti_lockout(firewall_id, rules_data)
        findings += self._sec006_ssh_on_wan(firewall_id, rules_data)
        findings += self._sec007_dns_recursion_on_wan(firewall_id, rules_data)
        findings += self._sec008_ids_no_wan(firewall_id, ids_data, interfaces)
        findings += self._sec009_no_default_deny(firewall_id, rules_data)
        findings += self._sec010_many_disabled(firewall_id, rules_data)

        return findings

    def _sec001_firmware_outdated(
        self, firewall_id: str, fw: dict[str, Any]
    ) -> list[Finding]:
        if not fw:
            return []
        current = fw.get("product_version", "")
        latest = fw.get("product_latest", "")
        if not latest or not current:
            return []
        if current == latest:
            return [Finding(
                check_id="SEC-001",
                title="Firmware up to date",
                description=f"Running {current}, latest is {latest}.",
                severity=Severity.OK,
                category=Category.SECURITY,
                firewall_id=firewall_id,
                evidence={"current": current, "latest": latest},
            )]
        return [Finding(
            check_id="SEC-001",
            title="Firmware outdated",
            description=(
                f"Running version {current} but {latest} is available. "
                "Outdated firmware may contain unpatched security vulnerabilities."
            ),
            severity=Severity.WARNING,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            evidence={"current": current, "latest": latest},
            remediation=(
                "Navigate to System → Firmware → Updates and apply the latest update."
            ),
        )]

    def _sec002_ids_down(self, firewall_id: str, ids: dict[str, Any]) -> list[Finding]:
        if not ids:
            return [Finding(
                check_id="SEC-002",
                title="IDS/IPS status unknown",
                description="Could not retrieve IDS/IPS service status.",
                severity=Severity.WARNING,
                category=Category.SECURITY,
                firewall_id=firewall_id,
            )]
        running = ids.get("running", False)
        if running:
            return [Finding(
                check_id="SEC-002",
                title="IDS/IPS running",
                description="Intrusion Detection/Prevention System is active.",
                severity=Severity.OK,
                category=Category.SECURITY,
                firewall_id=firewall_id,
            )]
        return [Finding(
            check_id="SEC-002",
            title="IDS/IPS is not running",
            description=(
                "The Intrusion Detection/Prevention System (Suricata) is not running. "
                "Malicious traffic may go undetected."
            ),
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            evidence={"status": ids.get("status", "")},
            remediation=(
                "Navigate to Services → Intrusion Detection → Administration "
                "and enable the IDS service."
            ),
        )]

    def _sec003_admin_on_wan(
        self, firewall_id: str, interfaces: dict[str, Any], rules: dict[str, Any]
    ) -> list[Finding]:
        """Check if WebGUI (port 443/80) is accessible from WAN."""
        rules_list = rules.get("rules", [])
        wan_admin_rules = [
            r for r in rules_list
            if r.get("interface", "").lower() in ("wan", "opt1")
            and r.get("destination_port") in ("443", "80", "8080", "8443")
            and r.get("type", "").lower() == "pass"
            and r.get("enabled") == "1"
        ]
        if wan_admin_rules:
            return [Finding(
                check_id="SEC-003",
                title="Admin UI accessible from WAN",
                description=(
                    "Firewall rules allow HTTP/HTTPS traffic to admin ports from WAN. "
                    "This exposes the management interface to the internet."
                ),
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                firewall_id=firewall_id,
                evidence={"matching_rules": len(wan_admin_rules)},
                remediation=(
                    "Remove or disable rules that allow WAN access to admin ports. "
                    "Restrict management access to LAN or VPN interfaces only."
                ),
            )]
        return []

    def _sec004_any_any_rules(self, firewall_id: str, rules: dict[str, Any]) -> list[Finding]:
        """Detect pass rules with source=any, destination=any, port=any."""
        rules_list = rules.get("rules", [])
        any_any = [
            r for r in rules_list
            if r.get("type", "").lower() == "pass"
            and r.get("enabled") == "1"
            and r.get("source_net", "") in ("any", "0.0.0.0/0", "")
            and r.get("destination", "") in ("any", "0.0.0.0/0", "")
            and r.get("destination_port", "") in ("any", "")
        ]
        if any_any:
            return [Finding(
                check_id="SEC-004",
                title="Any-any pass rules detected",
                description=(
                    f"Found {len(any_any)} enabled rule(s) that pass all traffic "
                    "(source: any, destination: any, port: any). "
                    "These rules bypass all security controls."
                ),
                severity=Severity.WARNING,
                category=Category.SECURITY,
                firewall_id=firewall_id,
                evidence={
                    "count": len(any_any),
                    "rule_descriptions": [r.get("description", r.get("uuid", "")) for r in any_any[:5]],
                },
                remediation=(
                    "Review and restrict any-any rules. Apply the principle of least privilege — "
                    "only permit traffic that is explicitly required."
                ),
            )]
        return []

    def _sec005_anti_lockout(self, firewall_id: str, rules: dict[str, Any]) -> list[Finding]:
        """Verify anti-lockout rule is present."""
        rules_list = rules.get("rules", [])
        lockout = [
            r for r in rules_list
            if "lockout" in r.get("description", "").lower()
            or r.get("type") == "pass"
            and r.get("destination_port") in ("443", "80")
        ]
        if lockout:
            return []
        return [Finding(
            check_id="SEC-005",
            title="Anti-lockout rule not explicitly visible in API",
            description=(
                "No explicit anti-lockout rule was found via the API. "
                "OPNSense has an implicit anti-lockout rule unless disabled in "
                "System → Advanced → Admin Access. This is informational only."
            ),
            severity=Severity.INFO,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            remediation=(
                "Ensure System → Advanced → Admin Access has 'Disable anti-lockout rule' "
                "unchecked, or manually add a rule allowing admin access from LAN."
            ),
        )]

    def _sec006_ssh_on_wan(self, firewall_id: str, rules: dict[str, Any]) -> list[Finding]:
        """Check for SSH (22) pass rules on WAN interface."""
        rules_list = rules.get("rules", [])
        ssh_wan = [
            r for r in rules_list
            if r.get("interface", "").lower() in ("wan", "opt1")
            and r.get("destination_port") == "22"
            and r.get("type", "").lower() == "pass"
            and r.get("enabled") == "1"
        ]
        if ssh_wan:
            return [Finding(
                check_id="SEC-006",
                title="SSH accessible from WAN",
                description=(
                    "Firewall rules allow SSH (port 22) from WAN. "
                    "Exposing SSH to the internet invites brute-force attacks."
                ),
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                firewall_id=firewall_id,
                evidence={"matching_rules": len(ssh_wan)},
                remediation=(
                    "Remove WAN-to-SSH rules. If remote access is required, "
                    "use VPN or restrict SSH to specific trusted IP addresses."
                ),
            )]
        return []

    def _sec007_dns_recursion_on_wan(
        self, firewall_id: str, rules: dict[str, Any]
    ) -> list[Finding]:
        """Check for DNS (53) pass rules on WAN — open resolver risk."""
        rules_list = rules.get("rules", [])
        dns_wan = [
            r for r in rules_list
            if r.get("interface", "").lower() in ("wan",)
            and r.get("destination_port") in ("53", "853")
            and r.get("type", "").lower() == "pass"
            and r.get("enabled") == "1"
        ]
        if dns_wan:
            return [Finding(
                check_id="SEC-007",
                title="DNS recursion potentially exposed on WAN",
                description=(
                    "Rules allow DNS traffic (port 53/853) from WAN. "
                    "An open DNS resolver can be abused for amplification attacks."
                ),
                severity=Severity.WARNING,
                category=Category.SECURITY,
                firewall_id=firewall_id,
                evidence={"matching_rules": len(dns_wan)},
                remediation=(
                    "Block inbound DNS from WAN unless you intentionally run "
                    "an authoritative DNS server. Enable DNS rebind protection."
                ),
            )]
        return []

    def _sec008_ids_no_wan(
        self, firewall_id: str, ids: dict[str, Any], interfaces: dict[str, Any]
    ) -> list[Finding]:
        """Warn if IDS is running but WAN interface may not be monitored."""
        if not ids.get("running"):
            return []
        # We can't easily determine interface binding without IDS settings API,
        # so emit an informational check as a reminder.
        return [Finding(
            check_id="SEC-008",
            title="Verify IDS covers WAN interface",
            description=(
                "IDS/IPS is running. Confirm that it monitors the WAN interface "
                "to detect inbound threats."
            ),
            severity=Severity.INFO,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            remediation=(
                "Go to Services → Intrusion Detection → Administration → Interfaces "
                "and ensure WAN is checked."
            ),
        )]

    def _sec009_no_default_deny(self, firewall_id: str, rules: dict[str, Any]) -> list[Finding]:
        """Check for a default-deny (block all) rule."""
        rules_list = rules.get("rules", [])
        deny_all = [
            r for r in rules_list
            if r.get("type", "").lower() in ("block", "reject")
            and r.get("source_net", "") in ("any", "0.0.0.0/0", "")
            and r.get("enabled") == "1"
        ]
        if deny_all:
            return []
        return [Finding(
            check_id="SEC-009",
            title="No explicit default-deny rule found",
            description=(
                "No block-all rule was detected. OPNSense has an implicit deny, "
                "but an explicit rule aids visibility and auditing."
            ),
            severity=Severity.INFO,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            remediation=(
                "Consider adding a block rule at the bottom of each interface's "
                "rule set with logging enabled for denied traffic visibility."
            ),
        )]

    def _sec010_many_disabled(self, firewall_id: str, rules: dict[str, Any]) -> list[Finding]:
        """Flag if there are many disabled rules that may indicate cruft."""
        disabled = rules.get("disabled_count", 0)
        total = rules.get("total", 0)
        if total == 0 or disabled < 10:
            return []
        pct = (disabled / total) * 100
        if pct < 20:
            return []
        return [Finding(
            check_id="SEC-010",
            title=f"Many disabled rules ({disabled}/{total})",
            description=(
                f"{disabled} of {total} rules are disabled ({pct:.0f}%). "
                "Accumulated disabled rules are hard to audit and may hide risks."
            ),
            severity=Severity.INFO,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            evidence={"disabled": disabled, "total": total, "pct": pct},
            remediation=(
                "Review disabled rules. Remove those that are no longer needed "
                "to keep the rule set clean and auditable."
            ),
        )]
