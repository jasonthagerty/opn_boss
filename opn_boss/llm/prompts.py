"""Prompt builders for LLM policy analysis."""

from __future__ import annotations

from typing import Any

_OPNSENSE_DOCS = """\
OPNSense documentation references (cite relevant URLs in your recommendations):
- Firewall rules:        https://docs.opnsense.org/manual/firewall.html
- IDS/IPS (Suricata):   https://docs.opnsense.org/manual/ids.html
- NAT (port fwd/SNAT):  https://docs.opnsense.org/manual/nat.html
- High Availability:    https://docs.opnsense.org/manual/hacarp.html
- Firmware & updates:   https://docs.opnsense.org/manual/updates.html
- WireGuard VPN:        https://docs.opnsense.org/manual/wireguard-client.html
- OpenVPN:              https://docs.opnsense.org/manual/vpnet.html
- DNS resolver:         https://docs.opnsense.org/manual/unbound.html
- Aliases & GeoIP:      https://docs.opnsense.org/manual/aliases.html
- Traffic shaping:      https://docs.opnsense.org/manual/shaping.html
- Two-factor auth:      https://docs.opnsense.org/manual/two_factor.html\
"""


def build_summary_prompt(rules_text: str, nat_text: str, routes_text: str) -> str:
    return f"""You are a network security analyst reviewing an OPNSense firewall configuration.

Respond in EXACTLY two sections using these exact headers (do not add extra headers):

## Policy Summary

Write 3-5 paragraphs covering:
1. What traffic is ALLOWED and from/to where
2. What traffic is BLOCKED
3. Key NAT rules and what they expose
4. Routing and network segmentation
5. Any notable security patterns

## Recommendations

List specific, actionable improvements directly relevant to this configuration. For each item:
- State the issue briefly
- Explain the risk or benefit
- End the item with the relevant OPNSense documentation URL on its own line

Only include recommendations where there is a clear gap or risk in the rules shown. Skip categories where the configuration is already adequate. If no improvements are needed, write "No significant improvements identified."

{_OPNSENSE_DOCS}

=== FILTER RULES ===
{rules_text}

=== NAT RULES ===
{nat_text}

=== ROUTING TABLE ===
{routes_text}
"""


def build_whatif_prompt(rules_text: str, nat_text: str, routes_text: str, scenario: str) -> str:
    return f"""You are a network security analyst with access to an OPNSense firewall's current configuration.

Answer this specific question about the firewall policy:
{scenario}

Base your answer ONLY on the rules shown below. If the rules don't have enough information, say so clearly.
Provide a direct YES/NO/MAYBE answer followed by a brief explanation referencing specific rules.

=== FILTER RULES ===
{rules_text}

=== NAT RULES ===
{nat_text}

=== ROUTING TABLE ===
{routes_text}

Answer:"""


def build_log_evidence_prompt(scenario: str, matching_logs: list[dict[str, Any]]) -> str:
    log_lines = []
    for entry in matching_logs[:20]:
        action = entry.get("action", "?")
        src = entry.get("src", "?")
        dst = entry.get("dst", "?")
        dport = entry.get("dstport", "")
        proto = entry.get("proto", "")
        ts = entry.get("time", "")
        line = f"[{action}] {src} \u2192 {dst}"
        if dport:
            line += f":{dport}"
        if proto:
            line += f" ({proto})"
        if ts:
            line += f" at {ts}"
        log_lines.append(line)

    log_text = "\n".join(log_lines) if log_lines else "(no matching log entries)"

    return f"""Supplementary log evidence for the question: "{scenario}"

Recent firewall log entries matching this traffic pattern:
{log_text}

Based on this log evidence, has this type of traffic actually occurred? What does the evidence show?"""
