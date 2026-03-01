"""APScheduler async job setup for periodic scans."""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from opn_boss.core.config import AppConfig
from opn_boss.core.logging_config import get_logger

logger = get_logger(__name__)


def create_scheduler(service: OPNBossService, config: AppConfig) -> AsyncIOScheduler:  # type: ignore[name-defined]  # noqa: F821
    """Create and configure an APScheduler instance.

    Args:
        service: The OPNBossService instance to call run_scan on.
        config: Application configuration.

    Returns:
        Configured (but not yet started) AsyncIOScheduler.
    """
    # Suppress APScheduler's verbose logging
    logging.getLogger("apscheduler").setLevel(logging.WARNING)

    scheduler = AsyncIOScheduler()

    interval_minutes = config.scheduler.poll_interval_minutes

    scheduler.add_job(
        service.run_scan,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="periodic_scan",
        name="Periodic OPNSense scan",
        replace_existing=True,
        misfire_grace_time=60,
        max_instances=1,
    )

    logger.info(
        "Scheduler configured: scan every %d minute(s)",
        interval_minutes,
    )

    return scheduler


# Avoid circular import at module level
from opn_boss.service.main import OPNBossService  # noqa: E402
