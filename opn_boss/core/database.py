"""SQLAlchemy async database models and session factory."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from opn_boss.core.config import FirewallConfig
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
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


class FirewallConfigDB(Base):
    __tablename__ = "firewall_configs"

    firewall_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=443)
    role: Mapped[str] = mapped_column(String(16), default="primary")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_seconds: Mapped[float] = mapped_column(Float, default=10.0)
    api_key_enc: Mapped[str] = mapped_column(Text, nullable=False)
    api_secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_firewall_config(self) -> FirewallConfig:
        """Decrypt credentials and return a FirewallConfig."""
        from opn_boss.core.config import FirewallConfig
        from opn_boss.core.crypto import decrypt

        return FirewallConfig(
            firewall_id=self.firewall_id,
            host=self.host,
            port=self.port,
            role=self.role,
            enabled=self.enabled,
            verify_ssl=self.verify_ssl,
            timeout_seconds=self.timeout_seconds,
            api_key=decrypt(self.api_key_enc),
            api_secret=decrypt(self.api_secret_enc),
        )


class AppSettingsDB(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# Engine + session factory (initialized at app startup)
_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(db_url: str) -> AsyncEngine:
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


async def get_setting(session: AsyncSession, key: str, default: Any = None) -> Any:
    """Get a JSON-encoded setting value from app_settings."""
    import json

    row = await session.get(AppSettingsDB, key)
    if row is None:
        return default
    try:
        return json.loads(row.value)
    except Exception:
        return default


async def set_setting(session: AsyncSession, key: str, value: Any) -> None:
    """Set a JSON-encoded setting value in app_settings."""
    import json

    row = await session.get(AppSettingsDB, key)
    if row is None:
        row = AppSettingsDB(key=key, value=json.dumps(value))
        session.add(row)
    else:
        row.value = json.dumps(value)
