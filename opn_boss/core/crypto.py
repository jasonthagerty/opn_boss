"""Fernet symmetric encryption for credential storage."""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from opn_boss.core.exceptions import ConfigError


def _get_fernet() -> Fernet:
    key = os.environ.get("OPNBOSS_SECRET_KEY", "").strip()
    if not key:
        raise ConfigError("OPNBOSS_SECRET_KEY is not set. Run `opnboss gen-key` to generate one.")
    try:
        return Fernet(key.encode())
    except Exception as exc:
        raise ConfigError(
            "OPNBOSS_SECRET_KEY is not a valid Fernet key. Run `opnboss gen-key` to generate a new one."
        ) from exc


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns URL-safe base64 ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt ciphertext. Raises ConfigError on failure."""
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ConfigError(
            "Failed to decrypt credential — OPNBOSS_SECRET_KEY may have changed."
        ) from exc


def is_key_configured() -> bool:
    """Return True if OPNBOSS_SECRET_KEY is set and is a valid Fernet key."""
    key = os.environ.get("OPNBOSS_SECRET_KEY", "").strip()
    if not key:
        return False
    try:
        Fernet(key.encode())
        return True
    except Exception:
        return False


def generate_key() -> str:
    """Generate and return a new Fernet key as a URL-safe base64 string."""
    return Fernet.generate_key().decode()
