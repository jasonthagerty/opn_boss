"""Tests for configuration loading."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from opn_boss.core.config import AppConfig, FirewallConfig, load_config
from opn_boss.core.exceptions import ConfigError


def test_firewall_config_base_url():
    fw = FirewallConfig(
        firewall_id="fw1",
        host="192.168.1.1",
        api_key="key",
        api_secret="secret",
    )
    assert fw.base_url == "https://192.168.1.1:443"


def test_firewall_config_invalid_role():
    with pytest.raises(ValueError, match="role"):
        FirewallConfig(
            firewall_id="fw1",
            host="192.168.1.1",
            api_key="k",
            api_secret="s",
            role="invalid",
        )


def test_load_config_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/path/config.yaml")


def test_load_config_valid(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(textwrap.dedent("""\
        firewalls:
          - firewall_id: "fw1"
            host: "192.168.1.1"
            api_key: "testkey"
            api_secret: "testsecret"
            role: "primary"
            enabled: true
        scheduler:
          poll_interval_minutes: 10
        api:
          port: 9090
    """))
    cfg = load_config(config_file)
    assert len(cfg.firewalls) == 1
    assert cfg.firewalls[0].firewall_id == "fw1"
    assert cfg.scheduler.poll_interval_minutes == 10
    assert cfg.api.port == 9090


def test_env_var_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_API_KEY", "my-real-key")
    config_file = tmp_path / "config.yaml"
    config_file.write_text(textwrap.dedent("""\
        firewalls:
          - firewall_id: "fw1"
            host: "10.0.0.1"
            api_key: "${MY_API_KEY}"
            api_secret: "secret"
            role: "primary"
    """))
    cfg = load_config(config_file)
    assert cfg.firewalls[0].api_key == "my-real-key"


def test_duplicate_firewall_ids(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(textwrap.dedent("""\
        firewalls:
          - firewall_id: "fw1"
            host: "192.168.1.1"
            api_key: "k"
            api_secret: "s"
            role: "primary"
          - firewall_id: "fw1"
            host: "192.168.1.2"
            api_key: "k2"
            api_secret: "s2"
            role: "backup"
    """))
    with pytest.raises(ConfigError, match="unique"):
        load_config(config_file)
