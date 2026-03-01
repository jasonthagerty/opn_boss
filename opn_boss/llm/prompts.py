"""Prompt builders for LLM policy analysis."""

from __future__ import annotations

from typing import Any


def build_summary_prompt(rules_text: str, nat_text: str, routes_text: str) -> str:
    return f"""You are a network security analyst. Analyze the following OPNSense firewall configuration and provide a clear, concise summary of the security policy in plain English.

Focus on:
1. What traffic is ALLOWED and from/to where
2. What traffic is BLOCKED
3. Key NAT rules and what they expose
4. Routing and network segmentation
5. Any notable security patterns or concerns

Be specific and practical. Write 3-5 paragraphs maximum.

=== FILTER RULES ===
{rules_text}

=== NAT RULES ===
{nat_text}

=== ROUTING TABLE ===
{routes_text}

Policy Summary:"""


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
