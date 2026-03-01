"""Tests for prompt builders."""

from __future__ import annotations

from opn_boss.llm.prompts import (
    build_log_evidence_prompt,
    build_summary_prompt,
    build_whatif_prompt,
)


def test_build_summary_prompt_contains_sections():
    prompt = build_summary_prompt("RULES", "NAT", "ROUTES")
    assert "RULES" in prompt
    assert "NAT" in prompt
    assert "ROUTES" in prompt
    assert "Policy Summary" in prompt


def test_build_whatif_prompt_contains_scenario():
    scenario = "Would SSH from 1.2.3.4 to 10.0.0.5 be allowed?"
    prompt = build_whatif_prompt("RULES", "NAT", "ROUTES", scenario)
    assert scenario in prompt
    assert "RULES" in prompt


def test_build_log_evidence_prompt():
    logs = [
        {"action": "pass", "src": "192.168.1.1", "dst": "8.8.8.8", "dstport": "53", "proto": "udp"},
    ]
    prompt = build_log_evidence_prompt("DNS traffic to 8.8.8.8", logs)
    assert "8.8.8.8" in prompt
    assert "DNS traffic" in prompt


def test_build_log_evidence_empty_logs():
    prompt = build_log_evidence_prompt("some scenario", [])
    assert "no matching log entries" in prompt
