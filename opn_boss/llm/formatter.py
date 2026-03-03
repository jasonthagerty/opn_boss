"""Formats collector data into compact text for LLM prompts."""

from __future__ import annotations

from typing import Any

MAX_RULES = 200


class PolicyFormatter:
    """Converts raw collector data into readable text for LLM consumption."""

    def format_rules(self, rules: list[dict[str, Any]]) -> str:
        """Format firewall filter rules into one line each."""
        lines: list[str] = []
        for rule in rules[:MAX_RULES]:
            if rule.get("enabled") not in ("1", True, 1):
                continue
            action = rule.get("type", rule.get("action", "pass")).upper()
            iface = rule.get("interface", rule.get("interface_name", "any"))
            proto = rule.get("protocol", "any")
            src = rule.get("source_net", rule.get("source", "any"))
            dst = rule.get("destination_net", rule.get("destination", "any"))
            dport = rule.get("destination_port", "")
            desc = rule.get("description", rule.get("descr", ""))
            dst_part = f"{dst}:{dport}" if dport else dst
            line = f"[{action}] {iface} {proto} {src} \u2192 {dst_part}"
            if desc:
                line += f"  # {desc}"
            lines.append(line)
        if not lines:
            return "(no enabled filter rules)"
        return "\n".join(lines)

    def format_nat(self, nat_data: dict[str, Any]) -> str:
        """Format NAT rules (port forwards and outbound NAT)."""
        lines: list[str] = []

        port_forwards = nat_data.get("port_forwards", [])
        if port_forwards:
            lines.append("=== Port Forwards (DNAT) ===")
            for rule in port_forwards[:50]:
                if rule.get("enabled") not in ("1", True, 1):
                    continue
                iface = rule.get("interface", "any")
                proto = rule.get("protocol", "any")
                dst_port = rule.get("destination_port", "")
                target = rule.get("target", "")
                local_port = rule.get("local_port", dst_port)
                desc = rule.get("description", rule.get("descr", ""))
                line = f"[DNAT] {iface} {proto} :{dst_port} \u2192 {target}:{local_port}"
                if desc:
                    line += f"  # {desc}"
                lines.append(line)

        outbound_nat = nat_data.get("outbound_nat", [])
        if outbound_nat:
            lines.append("=== Outbound NAT (SNAT/Masquerade) ===")
            for rule in outbound_nat[:50]:
                if rule.get("enabled") not in ("1", True, 1):
                    continue
                iface = rule.get("interface", "any")
                src = rule.get("source_net", rule.get("source", "any"))
                desc = rule.get("description", rule.get("descr", ""))
                line = f"[SNAT] {iface} {src} \u2192 masquerade"
                if desc:
                    line += f"  # {desc}"
                lines.append(line)

        if not lines:
            return "(no NAT rules)"
        return "\n".join(lines)

    def format_routes(self, routes: list[dict[str, Any]]) -> str:
        """Format routing table."""
        lines: list[str] = []
        for route in routes[:100]:
            if not isinstance(route, dict):
                continue
            network = route.get("network", route.get("destination", "unknown"))
            gateway = route.get("gateway", "direct")
            iface = route.get("netif", route.get("interface", ""))
            line = f"{network} via {gateway}"
            if iface:
                line += f" ({iface})"
            lines.append(line)
        if not lines:
            return "(no routes)"
        return "\n".join(lines)
