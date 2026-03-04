"""OPNBossService — main orchestrator for scanning and analysis."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from opn_boss.analyzers.ha_recovery import HaRecoveryAnalyzer
from opn_boss.analyzers.multiwan import MultiWANAnalyzer
from opn_boss.analyzers.performance import PerformanceAnalyzer
from opn_boss.analyzers.security import SecurityAnalyzer
from opn_boss.collectors.carp import CARPCollector
from opn_boss.collectors.dhcp import DHCPCollector
from opn_boss.collectors.dns import DNSCollector
from opn_boss.collectors.firewall_logs import FirewallLogsCollector
from opn_boss.collectors.firewall_rules import FirewallRulesCollector
from opn_boss.collectors.firmware import FirmwareCollector
from opn_boss.collectors.gateways import GatewaysCollector
from opn_boss.collectors.ids import IDSCollector
from opn_boss.collectors.interfaces import InterfacesCollector
from opn_boss.collectors.nat_rules import NatRulesCollector
from opn_boss.collectors.routes import RoutesCollector
from opn_boss.collectors.system import SystemCollector
from opn_boss.core.config import AppConfig, FirewallConfig
from opn_boss.core.database import (
    CollectorRunDB,
    FindingDB,
    FirewallConfigDB,
    FirewallStateDB,
    SnapshotDB,
    SuppressionDB,
    get_session_factory,
)
from opn_boss.core.logging_config import get_logger
from opn_boss.core.types import (
    Category,
    CollectorResult,
    Finding,
    Severity,
    SnapshotSummary,
)
from opn_boss.notifications.dispatcher import NotificationDispatcher
from opn_boss.opnsense.client import OPNSenseClient

logger = get_logger(__name__)

# SSE broadcast callback type
BroadcastFn = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]


class OPNBossService:
    """Main service orchestrating scans across all configured firewalls."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._session_factory = get_session_factory(config.database.url)
        self._analyzers = [
            SecurityAnalyzer(),
            MultiWANAnalyzer(),
            HaRecoveryAnalyzer(),
            PerformanceAnalyzer(),
        ]
        self._broadcast: BroadcastFn | None = None
        self._scan_lock = asyncio.Lock()
        self._policy_service: Any = None  # set by create_app if LLM enabled
        self._notification_dispatcher = NotificationDispatcher(config.database.url)

    def set_broadcast(self, fn: BroadcastFn) -> None:
        """Register SSE broadcast callback."""
        self._broadcast = fn

    async def _emit(self, event: str, data: dict[str, Any]) -> None:
        if self._broadcast:
            try:
                await self._broadcast(event, data)
            except Exception:
                pass  # never let SSE errors break scan

    async def _load_firewalls_from_db(self) -> list[FirewallConfig]:
        """Load enabled firewalls from DB (with decryption). Falls back to config if DB is empty."""
        from opn_boss.core.crypto import is_key_configured

        if not is_key_configured():
            # No encryption key -> use YAML config as-is
            return [fw for fw in self._config.firewalls if fw.enabled]

        async with self._session_factory() as session:
            result = await session.execute(
                select(FirewallConfigDB).where(FirewallConfigDB.enabled == True)  # noqa: E712
            )
            db_firewalls = result.scalars().all()

        if not db_firewalls:
            # DB empty -> fall back to YAML config for backward compat
            return [fw for fw in self._config.firewalls if fw.enabled]

        firewalls: list[FirewallConfig] = []
        for fw_db in db_firewalls:
            try:
                firewalls.append(fw_db.to_firewall_config())
            except Exception as exc:
                logger.error("Failed to decrypt credentials for %s: %s", fw_db.firewall_id, exc)
        return firewalls

    async def run_scan(self) -> list[SnapshotSummary]:
        """Scan all enabled firewalls concurrently."""
        async with self._scan_lock:
            enabled = await self._load_firewalls_from_db()
            logger.info("Starting scan of %d firewall(s)", len(enabled))
            await self._emit("scan_started", {"firewall_count": len(enabled)})

            tasks = [self._scan_one_firewall(fw) for fw in enabled]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            summaries: list[SnapshotSummary] = []
            for fw, result in zip(enabled, results):
                if isinstance(result, Exception):
                    logger.error("Scan of %s raised an exception: %s", fw.firewall_id, result)
                else:
                    summaries.append(result)  # type: ignore[arg-type]

            await self._emit("scan_completed", {"summaries": len(summaries)})
            return summaries

    async def _scan_one_firewall(self, fw: FirewallConfig) -> SnapshotSummary:
        """Scan a single firewall, handling offline gracefully."""
        snapshot_id = str(uuid.uuid4())
        started_at = datetime.now(UTC)

        async with self._session_factory() as session:
            # Persist snapshot as running
            snap = SnapshotDB(
                id=snapshot_id,
                firewall_id=fw.firewall_id,
                started_at=started_at,
                status="running",
            )
            session.add(snap)
            await session.commit()

        # Probe reachability first
        client = OPNSenseClient(fw)
        online = await client.probe()
        await self._update_firewall_state(fw, online)

        if not online:
            logger.warning("Firewall %s is offline — skipping collectors", fw.firewall_id)
            return await self._finalize_offline(snapshot_id, fw, started_at)

        # Collect data from all collectors
        logger.info("Collecting data from %s", fw.firewall_id)
        collector_results = await self._run_collectors(fw, snapshot_id)

        # Run analysis
        all_findings: list[Finding] = []
        for analyzer in self._analyzers:
            try:
                findings = analyzer.analyze(fw.firewall_id, collector_results)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("Analyzer %s failed: %s", type(analyzer).__name__, exc)

        # Persist findings
        summary = await self._persist_results(snapshot_id, fw, started_at, collector_results, all_findings)

        # Auto-generate policy summary if LLM is enabled
        if self._policy_service is not None:
            try:
                await self._policy_service.generate_summary(
                    fw.firewall_id,
                    snapshot_id=snapshot_id,
                    collector_results=collector_results,
                )
                logger.info("Policy summary generated for %s", fw.firewall_id)
            except Exception as exc:
                logger.warning("Policy summary generation failed for %s: %s", fw.firewall_id, exc)

        # Dispatch notifications for new critical findings (errors are non-fatal)
        try:
            await self._notification_dispatcher.dispatch(
                fw.firewall_id, snapshot_id, all_findings
            )
        except Exception as exc:
            logger.warning(
                "Notification dispatch failed for %s: %s", fw.firewall_id, exc
            )

        await self._emit("scan_firewall_complete", {
            "firewall_id": fw.firewall_id,
            "snapshot_id": snapshot_id,
            "critical": summary.critical_count,
            "warning": summary.warning_count,
        })

        return summary

    async def _run_collectors(
        self, fw: FirewallConfig, snapshot_id: str
    ) -> dict[str, CollectorResult]:
        """Run all collectors for a firewall, saving raw results to DB."""
        collector_results: dict[str, CollectorResult] = {}

        async with OPNSenseClient(fw) as client:
            collector_classes = [
                FirmwareCollector,
                SystemCollector,
                FirewallRulesCollector,
                GatewaysCollector,
                InterfacesCollector,
                IDSCollector,
                CARPCollector,
                DNSCollector,
                DHCPCollector,
                RoutesCollector,
                NatRulesCollector,
                FirewallLogsCollector,
            ]
            tasks = [cls(client).collect() for cls in collector_classes]  # type: ignore[abstract]
            results: list[CollectorResult] = await asyncio.gather(*tasks)

        # Save collector runs to DB
        async with self._session_factory() as session:
            for result in results:
                collector_results[result.collector_name] = result
                run = CollectorRunDB(
                    snapshot_id=snapshot_id,
                    collector_name=result.collector_name,
                    firewall_id=result.firewall_id,
                    success=result.success,
                    data=result.data,
                    error=result.error,
                    duration_ms=result.duration_ms,
                )
                session.add(run)
            await session.commit()

        return collector_results

    async def _persist_results(
        self,
        snapshot_id: str,
        fw: FirewallConfig,
        started_at: datetime,
        collector_results: dict[str, CollectorResult],
        findings: list[Finding],
    ) -> SnapshotSummary:
        """Persist findings to DB and return summary."""
        from sqlalchemy import select

        completed_at = datetime.now(UTC)

        async with self._session_factory() as session:
            # Load suppressed check_ids for this firewall
            supp_result = await session.execute(
                select(SuppressionDB).where(SuppressionDB.firewall_id == fw.firewall_id)
            )
            suppressed_keys = {s.check_id for s in supp_result.scalars().all()}

            # Counts exclude suppressed findings
            critical = sum(1 for f in findings if f.severity == Severity.CRITICAL and f.check_id not in suppressed_keys)
            warning = sum(1 for f in findings if f.severity == Severity.WARNING and f.check_id not in suppressed_keys)
            info = sum(1 for f in findings if f.severity == Severity.INFO and f.check_id not in suppressed_keys)
            ok = sum(1 for f in findings if f.severity == Severity.OK and f.check_id not in suppressed_keys)

            snap = await session.get(SnapshotDB, snapshot_id)
            if snap:
                snap.status = "completed"
                snap.completed_at = completed_at
                snap.critical_count = critical
                snap.warning_count = warning
                snap.info_count = info
                snap.ok_count = ok

            for f in findings:
                fdb = FindingDB(
                    id=f.id,
                    snapshot_id=snapshot_id,
                    check_id=f.check_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value,
                    category=f.category.value,
                    firewall_id=f.firewall_id,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    suppressed=f.check_id in suppressed_keys,
                    ts=f.ts,
                )
                session.add(fdb)

            await session.commit()

        return SnapshotSummary(
            snapshot_id=snapshot_id,
            firewall_id=fw.firewall_id,
            started_at=started_at,
            completed_at=completed_at,
            status="completed",
            critical_count=critical,
            warning_count=warning,
            info_count=info,
            ok_count=ok,
            findings=findings,
        )

    async def _finalize_offline(
        self, snapshot_id: str, fw: FirewallConfig, started_at: datetime
    ) -> SnapshotSummary:
        """Create an offline snapshot with HA-001 finding."""
        offline_finding = Finding(
            check_id="HA-001",
            title=f"{fw.firewall_id} is unreachable",
            description=(
                f"Firewall '{fw.firewall_id}' did not respond to the probe request. "
                f"Host: {fw.host}. The firewall may be powered off, have a network issue, "
                "or be experiencing a hardware failure."
            ),
            severity=Severity.CRITICAL,
            category=Category.HA_RECOVERY,
            firewall_id=fw.firewall_id,
            evidence={"host": fw.host, "role": fw.role},
            remediation=(
                "1. Verify physical power and network cable connections.\n"
                "2. Try to ping the management IP from the local network.\n"
                "3. Check CARP status on the primary firewall.\n"
                "4. If this is firewall2, see HA-004 for RA conflict remediation."
            ),
        )

        completed_at = datetime.now(UTC)

        async with self._session_factory() as session:
            from sqlalchemy import select

            # Check if HA-001 is suppressed for this firewall
            supp_result = await session.execute(
                select(SuppressionDB).where(
                    SuppressionDB.firewall_id == fw.firewall_id,
                    SuppressionDB.check_id == "HA-001",
                )
            )
            is_suppressed = supp_result.scalar_one_or_none() is not None

            snap = await session.get(SnapshotDB, snapshot_id)
            if snap:
                snap.status = "offline"
                snap.completed_at = completed_at
                snap.critical_count = 0 if is_suppressed else 1

            fdb = FindingDB(
                id=offline_finding.id,
                snapshot_id=snapshot_id,
                check_id=offline_finding.check_id,
                title=offline_finding.title,
                description=offline_finding.description,
                severity=offline_finding.severity.value,
                category=offline_finding.category.value,
                firewall_id=offline_finding.firewall_id,
                evidence=offline_finding.evidence,
                remediation=offline_finding.remediation,
                suppressed=is_suppressed,
                ts=offline_finding.ts,
            )
            session.add(fdb)
            await session.commit()

        await self._emit("firewall_offline", {
            "firewall_id": fw.firewall_id,
            "host": fw.host,
            "snapshot_id": snapshot_id,
        })

        return SnapshotSummary(
            snapshot_id=snapshot_id,
            firewall_id=fw.firewall_id,
            started_at=started_at,
            completed_at=completed_at,
            status="offline",
            critical_count=1,
            findings=[offline_finding],
        )

    async def _update_firewall_state(self, fw: FirewallConfig, online: bool) -> None:
        """Update the firewall_state table."""
        async with self._session_factory() as session:
            state = await session.get(FirewallStateDB, fw.firewall_id)
            if state is None:
                state = FirewallStateDB(
                    firewall_id=fw.firewall_id,
                    role=fw.role,
                )
                session.add(state)
            state.online = online
            state.role = fw.role
            state.last_checked = datetime.now(UTC)
            if online:
                state.last_seen = datetime.now(UTC)
            await session.commit()

    async def get_latest_snapshots(self) -> list[dict[str, Any]]:
        """Get the most recent snapshot per firewall."""
        from sqlalchemy import text

        async with self._session_factory() as session:
            # Get latest snapshot per firewall
            result = await session.execute(
                text("""
                    SELECT s.* FROM snapshots s
                    INNER JOIN (
                        SELECT firewall_id, MAX(started_at) as max_ts
                        FROM snapshots
                        GROUP BY firewall_id
                    ) latest ON s.firewall_id = latest.firewall_id
                    AND s.started_at = latest.max_ts
                    ORDER BY s.firewall_id
                """)
            )
            rows = result.mappings().all()
            return [dict(row) for row in rows]

    async def get_firewall_states(self) -> list[dict[str, Any]]:
        """Get all firewall states."""
        from sqlalchemy import select

        async with self._session_factory() as session:
            result = await session.execute(select(FirewallStateDB))
            states = result.scalars().all()
            return [
                {
                    "firewall_id": s.firewall_id,
                    "online": s.online,
                    "role": s.role,
                    "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    "last_checked": s.last_checked.isoformat() if s.last_checked else None,
                }
                for s in states
            ]
