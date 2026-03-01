"""Tests for PolicyFormatter."""

from __future__ import annotations

import pytest

from opn_boss.llm.formatter import PolicyFormatter


@pytest.fixture
def formatter():
    return PolicyFormatter()


def test_format_rules_enabled_only(formatter):
    rules = [
        {"enabled": "1", "type": "pass", "interface": "wan", "protocol": "tcp",
         "source_net": "any", "destination_net": "10.0.0.1", "destination_port": "80",
         "description": "HTTP in"},
        {"enabled": "0", "type": "block", "interface": "lan", "protocol": "any",
         "source_net": "any", "destination_net": "any", "description": "disabled rule"},
    ]
    result = formatter.format_rules(rules)
    assert "HTTP in" in result
    assert "disabled rule" not in result
    assert "[PASS]" in result


def test_format_rules_empty(formatter):
    result = formatter.format_rules([])
    assert "no enabled filter rules" in result


def test_format_nat_port_forward(formatter):
    nat_data = {
        "port_forwards": [
            {"enabled": "1", "interface": "wan", "protocol": "tcp",
             "destination_port": "8080", "target": "192.168.1.10", "local_port": "80",
             "description": "Web server"},
        ],
        "outbound_nat": [],
    }
    result = formatter.format_nat(nat_data)
    assert "DNAT" in result
    assert "8080" in result
    assert "192.168.1.10" in result


def test_format_nat_empty(formatter):
    result = formatter.format_nat({"port_forwards": [], "outbound_nat": []})
    assert "no NAT rules" in result


def test_format_routes(formatter):
    routes = [
        {"network": "0.0.0.0/0", "gateway": "203.0.113.1", "netif": "em0"},
        {"network": "192.168.1.0/24", "gateway": "direct", "netif": "em1"},
    ]
    result = formatter.format_routes(routes)
    assert "0.0.0.0/0" in result
    assert "203.0.113.1" in result
    assert "192.168.1.0/24" in result


def test_format_routes_empty(formatter):
    result = formatter.format_routes([])
    assert "no routes" in result
