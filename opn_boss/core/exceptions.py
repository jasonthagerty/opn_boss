"""Custom exceptions for OPNBoss."""


class OPNBossError(Exception):
    """Base exception for all OPNBoss errors."""


class OPNSenseError(OPNBossError):
    """Generic OPNSense API error."""

    def __init__(self, message: str, firewall_id: str = "", status_code: int = 0) -> None:
        super().__init__(message)
        self.firewall_id = firewall_id
        self.status_code = status_code


class OPNSenseTimeoutError(OPNSenseError):
    """OPNSense API request timed out."""


class OPNSenseAuthError(OPNSenseError):
    """OPNSense API authentication failed (401/403)."""


class OPNSenseConnectionError(OPNSenseError):
    """Cannot connect to OPNSense host."""


class OPNSenseNotFoundError(OPNSenseError):
    """OPNSense API endpoint not found (404)."""


class ConfigError(OPNBossError):
    """Configuration is invalid or missing."""


class CollectorError(OPNBossError):
    """A collector failed to gather data."""

    def __init__(self, message: str, collector_name: str = "") -> None:
        super().__init__(message)
        self.collector_name = collector_name
