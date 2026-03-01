"""Unit tests for database model definitions."""

from __future__ import annotations

import inspect

from opn_boss.core.database import FindingDB, SuppressionDB


def test_finding_db_has_suppressed_field():
    """FindingDB must have a suppressed boolean column."""
    columns = {c.key for c in FindingDB.__mapper__.columns}
    assert "suppressed" in columns


def test_finding_db_suppressed_default_falsy():
    """FindingDB suppressed is falsy when not explicitly set (DB default is False)."""
    f = FindingDB(
        id="test-id",
        snapshot_id="snap-id",
        check_id="SEC-001",
        title="Test",
        description="Desc",
        severity="warning",
        category="security",
        firewall_id="fw1",
    )
    assert not f.suppressed  # None until persisted; DB insert default is 0/False


def test_suppression_db_exists():
    """SuppressionDB model must be importable and have expected columns."""
    columns = {c.key for c in SuppressionDB.__mapper__.columns}
    assert "id" in columns
    assert "firewall_id" in columns
    assert "check_id" in columns
    assert "reason" in columns
    assert "created_at" in columns


def test_suppression_db_tablename():
    assert SuppressionDB.__tablename__ == "suppressions"


def test_suppression_db_unique_constraint():
    """SuppressionDB must have a unique constraint on (firewall_id, check_id)."""
    from sqlalchemy import UniqueConstraint
    constraints = SuppressionDB.__table__.constraints
    unique_constraints = [c for c in constraints if isinstance(c, UniqueConstraint)]
    assert len(unique_constraints) == 1
    cols = {col.name for col in unique_constraints[0].columns}
    assert cols == {"firewall_id", "check_id"}


def test_finding_db_suppressed_can_be_set():
    """FindingDB.suppressed can be set to True."""
    f = FindingDB(
        id="test-id",
        snapshot_id="snap-id",
        check_id="SEC-001",
        title="Test",
        description="Desc",
        severity="critical",
        category="security",
        firewall_id="fw1",
        suppressed=True,
    )
    assert f.suppressed is True
