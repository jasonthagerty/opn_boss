"""Configuration models and YAML loader with environment variable substitution."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from opn_boss.core.exceptions import ConfigError


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} patterns in config values."""
    if isinstance(value, str):
        def replacer(match: re.Match[str]) -> str:
            var_name = match.group(1)
            env_val = os.environ.get(var_name)
            if env_val is None:
                return match.group(0)  # leave unexpanded if not set
            return env_val

        return re.sub(r"\$\{([^}]+)\}", replacer, value)
    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


class FirewallConfig(BaseModel):
    firewall_id: str
    host: str
    api_key: str
    api_secret: str
    verify_ssl: bool = False
    role: str = "primary"  # "primary" | "backup"
    enabled: bool = True
    timeout_seconds: float = 10.0
    port: int = 443

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("primary", "backup"):
            raise ValueError(f"role must be 'primary' or 'backup', got: {v!r}")
        return v

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class SchedulerConfig(BaseModel):
    poll_interval_minutes: int = Field(default=5, ge=1, le=1440)
    retention_days: int = Field(default=30, ge=1, le=365)


class APIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///data/opn_boss.db"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "text"  # "json" | "text"

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log level must be one of {valid}")
        return upper


class AppConfig(BaseModel):
    firewalls: list[FirewallConfig] = Field(default_factory=list)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("firewalls")
    @classmethod
    def validate_firewalls(cls, v: list[FirewallConfig]) -> list[FirewallConfig]:
        if not v:
            raise ValueError("At least one firewall must be configured")
        ids = [fw.firewall_id for fw in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Firewall IDs must be unique")
        return v


def load_config(config_path: str | Path = "config/config.yaml") -> AppConfig:
    """Load and validate configuration from a YAML file."""
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML config: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Config file must be a YAML mapping")

    expanded = _expand_env_vars(raw)

    try:
        return AppConfig.model_validate(expanded)
    except Exception as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc
