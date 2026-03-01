"""SQLAlchemy async database models and session factory."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class FirewallStateDB(Base):
    __tablename__ = "firewall_state"

    firewall_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    online: Mapped[bool] = mapped_column(Boolean, default=False)
    role: Mapped[str] = mapped_column(String(16), default="primary")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_checked: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class SnapshotDB(Base):
    __tablename__ = "snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    ok_count: Mapped[int] = mapped_column(Integer, default=0)

    findings: Mapped[list[FindingDB]] = relationship(
        "FindingDB", back_populates="snapshot", cascade="all, delete-orphan"
    )
    collector_runs: Mapped[list[CollectorRunDB]] = relationship(
        "CollectorRunDB", back_populates="snapshot", cascade="all, delete-orphan"
    )


class FindingDB(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    snapshot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    snapshot: Mapped[SnapshotDB] = relationship("SnapshotDB", back_populates="findings")


class CollectorRunDB(Base):
    __tablename__ = "collector_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    snapshot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    snapshot: Mapped[SnapshotDB] = relationship("SnapshotDB", back_populates="collector_runs")


class SuppressionDB(Base):
    __tablename__ = "suppressions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("firewall_id", "check_id"),)


class PolicySummaryDB(Base):
    __tablename__ = "policy_summaries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)


class WhatIfQueryDB(Base):
    __tablename__ = "whatif_queries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firewall_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scenario: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False)
    log_evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    model: Mapped[str] = mapped_column(String(128), nullable=False)


# Engine + session factory (initialized at app startup)
_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(db_url: str):  # type: ignore[return]
    """Create and return the async engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            db_url,
            echo=False,
            connect_args={"check_same_thread": False},
        )
    return _engine


def get_session_factory(db_url: str) -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        engine = get_engine(db_url)
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def create_tables(db_url: str) -> None:
    """Create all tables if they don't exist, and run any pending migrations."""
    engine = get_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migration: add suppressed column to existing findings tables
        try:
            await conn.execute(
                text("ALTER TABLE findings ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT 0")
            )
        except Exception:
            pass  # Column already exists on fresh or already-migrated DBs


async def get_session(db_url: str) -> AsyncGenerator[AsyncSession, None]:
    """Async generator yielding a database session."""
    factory = get_session_factory(db_url)
    async with factory() as session:
        yield session
