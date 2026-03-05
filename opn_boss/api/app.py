"""FastAPI application factory with lifespan management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from opn_boss.api.sse import SSEManager
from opn_boss.core.config import AppConfig
from opn_boss.core.database import create_tables
from opn_boss.core.logging_config import get_logger
from opn_boss.scheduler.jobs import create_scheduler
from opn_boss.service.main import OPNBossService

logger = get_logger(__name__)


async def bootstrap_from_yaml(config: AppConfig, db_url: str) -> None:
    """Import YAML firewalls into DB on first run if DB is empty and key is set."""
    from sqlalchemy import func, select

    from opn_boss.core.crypto import encrypt, is_key_configured
    from opn_boss.core.database import FirewallConfigDB, get_session_factory

    if not is_key_configured() or not config.firewalls:
        return

    factory = get_session_factory(db_url)
    async with factory() as session:
        count = await session.scalar(select(func.count()).select_from(FirewallConfigDB))
        if count and count > 0:
            return
        for fw in config.firewalls:
            session.add(
                FirewallConfigDB(
                    firewall_id=fw.firewall_id,
                    host=fw.host,
                    port=fw.port,
                    role=fw.role,
                    enabled=fw.enabled,
                    verify_ssl=fw.verify_ssl,
                    timeout_seconds=fw.timeout_seconds,
                    api_key_enc=encrypt(fw.api_key),
                    api_secret_enc=encrypt(fw.api_secret),
                )
            )
        await session.commit()
        logger.info("Bootstrapped %d firewall(s) from config.yaml into DB", len(config.firewalls))


def create_app(config: AppConfig) -> FastAPI:
    """Create and configure the FastAPI application."""
    service = OPNBossService(config)
    sse_manager = SSEManager()
    service.set_broadcast(sse_manager.broadcast)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Startup
        logger.info("OPNBoss starting up...")
        await create_tables(config.database.url)
        await bootstrap_from_yaml(config, config.database.url)

        app.state.service = service
        app.state.sse_manager = sse_manager
        app.state.config = config

        # Initialize policy analysis service if LLM is enabled
        if config.llm.enabled:
            from opn_boss.llm.service import PolicyAnalysisService
            policy_svc = PolicyAnalysisService(config.llm, config.database.url)
            service._policy_service = policy_svc

        # Start scheduler
        scheduler = create_scheduler(service, config)
        scheduler.start()
        app.state.scheduler = scheduler

        # Run initial scan on startup
        import asyncio
        asyncio.create_task(service.run_scan())

        logger.info("OPNBoss ready on port %d", config.api.port)

        yield

        # Shutdown
        logger.info("OPNBoss shutting down...")
        scheduler.shutdown(wait=False)

    app = FastAPI(
        title="OPNBoss",
        description="OPNSense Analyzer & Recommendation Service",
        version="0.2.0",
        lifespan=lifespan,
    )

    # Static files
    import pathlib
    static_dir = pathlib.Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routers
    from opn_boss.api.routes import dashboard, firewalls, policy, scan, snapshots, suppressions
    from opn_boss.api.routes import settings as settings_mod
    from opn_boss.api.routes import sse as sse_routes

    app.include_router(dashboard.router)
    app.include_router(firewalls.router)
    app.include_router(snapshots.router)
    app.include_router(scan.router)
    app.include_router(sse_routes.router)
    app.include_router(suppressions.router)
    app.include_router(policy.router)
    app.include_router(settings_mod.router)
    app.include_router(settings_mod.partials_router)

    return app
