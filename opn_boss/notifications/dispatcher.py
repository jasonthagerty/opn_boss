"""Notification dispatcher -- fires webhook/Slack alerts for new critical findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import desc, select

from opn_boss.core.database import (
    FindingDB,
    SnapshotDB,
    SuppressionDB,
    get_session_factory,
    get_setting,
)
from opn_boss.core.logging_config import get_logger
from opn_boss.core.types import Finding, Severity

logger = get_logger(__name__)


class NotificationDispatcher:
    """Dispatches webhook and Slack alerts for new critical findings."""

    def __init__(self, db_url: str) -> None:
        self._session_factory = get_session_factory(db_url)

    async def dispatch(
        self,
        firewall_id: str,
        snapshot_id: str,
        findings: list[Finding],
    ) -> None:
        """Fire notifications for any CRITICAL findings that are new since last scan."""
        async with self._session_factory() as session:
            webhook_url: str = await get_setting(
                session, "notifications.webhook_url", ""
            )
            slack_url: str = await get_setting(
                session, "notifications.slack_webhook_url", ""
            )

            if not webhook_url and not slack_url:
                return  # nothing configured

            suppressed_keys = await self._load_suppressed_keys(session, firewall_id)
            prev_critical_ids = await self._prev_critical_check_ids(
                session, firewall_id, snapshot_id
            )

        new_criticals = [
            f
            for f in findings
            if f.severity == Severity.CRITICAL
            and f.check_id not in suppressed_keys
            and f.check_id not in prev_critical_ids
        ]

        if not new_criticals:
            return

        logger.info(
            "Dispatching notifications: %d new critical finding(s) on %s",
            len(new_criticals),
            firewall_id,
        )

        if webhook_url:
            await self._post_webhook(webhook_url, firewall_id, new_criticals)
        if slack_url:
            await self._post_slack(slack_url, firewall_id, new_criticals)

    async def test_webhook(
        self, url: str, firewall_id: str = "test-firewall"
    ) -> None:
        """Send a test webhook payload."""
        from opn_boss.core.types import Category

        test_finding = Finding(
            check_id="TEST-001",
            title="Test Notification",
            description="This is a test notification from OPNBoss.",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            evidence={},
            remediation=None,
        )
        await self._post_webhook(url, firewall_id, [test_finding])

    async def test_slack(
        self, url: str, firewall_id: str = "test-firewall"
    ) -> None:
        """Send a test Slack notification."""
        from opn_boss.core.types import Category

        test_finding = Finding(
            check_id="TEST-001",
            title="Test Notification",
            description="This is a test notification from OPNBoss.",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            firewall_id=firewall_id,
            evidence={},
            remediation=None,
        )
        await self._post_slack(url, firewall_id, [test_finding])

    async def _load_suppressed_keys(
        self, session: Any, firewall_id: str
    ) -> set[str]:
        result = await session.execute(
            select(SuppressionDB).where(
                SuppressionDB.firewall_id == firewall_id
            )
        )
        return {s.check_id for s in result.scalars().all()}

    async def _prev_critical_check_ids(
        self,
        session: Any,
        firewall_id: str,
        current_snapshot_id: str,
    ) -> set[str]:
        """Return CRITICAL (non-suppressed) check_ids from the most recent prior snapshot."""
        prev_snap_subq = (
            select(SnapshotDB.id)
            .where(SnapshotDB.firewall_id == firewall_id)
            .where(SnapshotDB.id != current_snapshot_id)
            .where(SnapshotDB.status == "completed")
            .order_by(desc(SnapshotDB.started_at))
            .limit(1)
            .scalar_subquery()
        )
        result = await session.execute(
            select(FindingDB.check_id)
            .where(FindingDB.snapshot_id == prev_snap_subq)
            .where(FindingDB.severity == "critical")
            .where(FindingDB.suppressed == False)  # noqa: E712
        )
        return {row[0] for row in result.all()}

    async def _post_webhook(
        self, url: str, firewall_id: str, findings: list[Finding]
    ) -> None:
        payload: dict[str, Any] = {
            "event": "new_critical_findings",
            "firewall_id": firewall_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "new_critical_count": len(findings),
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
            logger.info(
                "Webhook notification sent to %s (status %d)", url, resp.status_code
            )
        except Exception as exc:
            logger.warning("Webhook notification failed (%s): %s", url, exc)

    async def _post_slack(
        self, url: str, firewall_id: str, findings: list[Finding]
    ) -> None:
        finding_blocks: list[dict[str, Any]] = []
        for f in findings:
            text = f"*{f.check_id}* -- {f.title}\n{f.description}"
            finding_blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": text}}
            )
            finding_blocks.append({"type": "divider"})

        payload: dict[str, Any] = {
            "text": f":rotating_light: New critical findings on *{firewall_id}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": ":rotating_light: OPNBoss Alert: New Critical Findings",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Firewall:* `{firewall_id}`\n"
                            f"*New Critical Findings:* {len(findings)}\n"
                            f"*Time:* {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}"
                        ),
                    },
                },
                {"type": "divider"},
                *finding_blocks,
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
            logger.info("Slack notification sent (status %d)", resp.status_code)
        except Exception as exc:
            logger.warning("Slack notification failed (%s): %s", url, exc)
