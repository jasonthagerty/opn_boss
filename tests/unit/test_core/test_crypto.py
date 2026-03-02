"""Unit tests for opn_boss.core.crypto."""

from __future__ import annotations

import pytest

from opn_boss.core.exceptions import ConfigError


def test_generate_key_returns_valid_fernet_key() -> None:
    """generate_key() returns a string that can be used as a Fernet key."""
    from cryptography.fernet import Fernet

    from opn_boss.core.crypto import generate_key

    key = generate_key()
    assert isinstance(key, str)
    # Should not raise
    Fernet(key.encode())


def test_is_key_configured_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPNBOSS_SECRET_KEY", raising=False)
    from opn_boss.core.crypto import is_key_configured

    assert is_key_configured() is False


def test_is_key_configured_true_when_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.fernet import Fernet

    from opn_boss.core.crypto import is_key_configured

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", key)
    assert is_key_configured() is True


def test_is_key_configured_false_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", "not-a-valid-key")
    from opn_boss.core.crypto import is_key_configured

    assert is_key_configured() is False


def test_encrypt_decrypt_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.fernet import Fernet

    from opn_boss.core.crypto import decrypt, encrypt

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", key)

    plaintext = "my-secret-api-key-12345"
    ciphertext = encrypt(plaintext)
    assert ciphertext != plaintext
    assert decrypt(ciphertext) == plaintext


def test_encrypt_raises_when_key_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPNBOSS_SECRET_KEY", raising=False)
    from opn_boss.core.crypto import encrypt

    with pytest.raises(ConfigError, match="OPNBOSS_SECRET_KEY"):
        encrypt("hello")


def test_decrypt_raises_on_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.fernet import Fernet

    from opn_boss.core.crypto import decrypt

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", key)

    with pytest.raises(ConfigError, match="decrypt"):
        decrypt("not-valid-ciphertext")


def test_decrypt_raises_on_key_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.fernet import Fernet

    from opn_boss.core.crypto import decrypt, encrypt

    key1 = Fernet.generate_key().decode()
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", key1)
    ciphertext = encrypt("hello")

    key2 = Fernet.generate_key().decode()
    monkeypatch.setenv("OPNBOSS_SECRET_KEY", key2)
    with pytest.raises(ConfigError):
        decrypt(ciphertext)
