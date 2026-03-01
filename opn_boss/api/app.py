"""FastAPI application factory with lifespan management."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from opn_boss.api.sse import SSEManager
from opn_boss.core.config import AppConfig
from opn_boss.core.database import create_tables
from opn_boss.core.logging_config import get_logger
from opn_boss.scheduler.jobs import create_scheduler
from opn_boss.service.main import OPNBossService

logger = get_logger(__name__)


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

        app.state.service = service
        app.state.sse_manager = sse_manager
        app.state.config = config

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
        version="0.1.0",
        lifespan=lifespan,
    )

    # Static files
    import pathlib
    static_dir = pathlib.Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routers
    from opn_boss.api.routes import dashboard, firewalls, scan, snapshots, suppressions
    from opn_boss.api.routes import sse as sse_routes

    app.include_router(dashboard.router)
    app.include_router(firewalls.router)
    app.include_router(snapshots.router)
    app.include_router(scan.router)
    app.include_router(sse_routes.router)
    app.include_router(suppressions.router)

    return app
