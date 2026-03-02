"""Settings API routes — firewall CRUD, scheduler, LLM configuration."""

from __future__ import annotations

import pathlib
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from opn_boss.api.dependencies import get_service
from opn_boss.core.database import FirewallConfigDB, get_session_factory
from opn_boss.core.logging_config import get_logger
from opn_boss.service.main import OPNBossService

logger = get_logger(__name__)

TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/api/settings", tags=["settings"])
partials_router = APIRouter(prefix="/partials/settings", tags=["settings-partials"])


def _mask_key(enc_value: str) -> str:
    """Return masked display for an encrypted credential."""
    return "••••••••" + enc_value[-4:] if len(enc_value) >= 4 else "••••••••"


def _require_key() -> None:
    """Raise 503 if OPNBOSS_SECRET_KEY is not configured."""
    from opn_boss.core.crypto import is_key_configured

    if not is_key_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "OPNBOSS_SECRET_KEY is not set. "
                "Run `opnboss gen-key` to generate one, then set the environment variable."
            ),
        )


# ---------------------------------------------------------------------------
# Firewall CRUD
# ---------------------------------------------------------------------------


@router.get("/firewalls", response_model=None)
async def list_firewall_configs(
    service: OPNBossService = Depends(get_service),
) -> list[dict[str, Any]]:
    """List all firewall configurations (credentials masked)."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        result = await session.execute(
            select(FirewallConfigDB).order_by(FirewallConfigDB.firewall_id)
        )
        configs = result.scalars().all()

    return [
        {
            "firewall_id": c.firewall_id,
            "host": c.host,
            "port": c.port,
            "role": c.role,
            "enabled": c.enabled,
            "verify_ssl": c.verify_ssl,
            "timeout_seconds": c.timeout_seconds,
            "api_key_masked": _mask_key(c.api_key_enc),
            "api_secret_masked": _mask_key(c.api_secret_enc),
        }
        for c in configs
    ]


@router.post("/firewalls", response_class=HTMLResponse)
async def create_firewall_config(
    request: Request,
    firewall_id: Annotated[str, Form()],
    host: Annotated[str, Form()],
    port: Annotated[int, Form()] = 443,
    role: Annotated[str, Form()] = "primary",
    enabled: Annotated[str | None, Form()] = None,
    verify_ssl: Annotated[str | None, Form()] = None,
    timeout_seconds: Annotated[float, Form()] = 10.0,
    api_key: Annotated[str, Form()] = "",
    api_secret: Annotated[str, Form()] = "",
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Create a new firewall configuration."""
    _require_key()
    from opn_boss.core.crypto import encrypt

    bool_enabled = enabled is not None
    bool_verify_ssl = verify_ssl is not None

    if not api_key or not api_secret:
        return templates.TemplateResponse(
            request,
            "partials/settings_flash.html",
            {"success": False, "message": "API key and secret are required."},
        )

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        existing = await session.get(FirewallConfigDB, firewall_id)
        if existing:
            return templates.TemplateResponse(
                request,
                "partials/settings_flash.html",
                {
                    "success": False,
                    "message": f"Firewall '{firewall_id}' already exists.",
                },
            )
        session.add(
            FirewallConfigDB(
                firewall_id=firewall_id,
                host=host,
                port=port,
                role=role,
                enabled=bool_enabled,
                verify_ssl=bool_verify_ssl,
                timeout_seconds=timeout_seconds,
                api_key_enc=encrypt(api_key),
                api_secret_enc=encrypt(api_secret),
            )
        )
        await session.commit()
        fw = await session.get(FirewallConfigDB, firewall_id)

    if fw is None:
        raise HTTPException(status_code=500, detail="Failed to create firewall config")

    return templates.TemplateResponse(
        request,
        "partials/firewall_config_row.html",
        {
            "fw": fw,
            "api_key_masked": _mask_key(fw.api_key_enc),
            "api_secret_masked": _mask_key(fw.api_secret_enc),
        },
    )


@router.put("/firewalls/{fw_id}", response_class=HTMLResponse)
async def update_firewall_config(
    request: Request,
    fw_id: str,
    host: Annotated[str, Form()],
    port: Annotated[int, Form()] = 443,
    role: Annotated[str, Form()] = "primary",
    enabled: Annotated[str | None, Form()] = None,
    verify_ssl: Annotated[str | None, Form()] = None,
    timeout_seconds: Annotated[float, Form()] = 10.0,
    api_key: Annotated[str, Form()] = "",
    api_secret: Annotated[str, Form()] = "",
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Update a firewall configuration. Blank api_key/secret keeps existing values."""
    _require_key()

    bool_enabled = enabled is not None
    bool_verify_ssl = verify_ssl is not None

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        fw = await session.get(FirewallConfigDB, fw_id)
        if fw is None:
            raise HTTPException(status_code=404, detail=f"Firewall '{fw_id}' not found")

        fw.host = host
        fw.port = port
        fw.role = role
        fw.enabled = bool_enabled
        fw.verify_ssl = bool_verify_ssl
        fw.timeout_seconds = timeout_seconds

        if api_key.strip():
            from opn_boss.core.crypto import encrypt

            fw.api_key_enc = encrypt(api_key)
        if api_secret.strip():
            from opn_boss.core.crypto import encrypt

            fw.api_secret_enc = encrypt(api_secret)

        await session.commit()
        await session.refresh(fw)

        return templates.TemplateResponse(
            request,
            "partials/firewall_config_row.html",
            {
                "fw": fw,
                "api_key_masked": _mask_key(fw.api_key_enc),
                "api_secret_masked": _mask_key(fw.api_secret_enc),
            },
        )


@router.delete("/firewalls/{fw_id}")
async def delete_firewall_config(
    fw_id: str,
    service: OPNBossService = Depends(get_service),
) -> dict[str, str]:
    """Delete a firewall configuration."""
    _require_key()

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        fw = await session.get(FirewallConfigDB, fw_id)
        if fw is None:
            raise HTTPException(status_code=404, detail=f"Firewall '{fw_id}' not found")
        await session.delete(fw)
        await session.commit()

    return {"status": "deleted", "firewall_id": fw_id}


@router.post("/firewalls/{fw_id}/test", response_class=HTMLResponse)
async def test_firewall_connection(
    request: Request,
    fw_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Test connectivity to a firewall."""
    _require_key()

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        fw_db = await session.get(FirewallConfigDB, fw_id)
        if fw_db is None:
            raise HTTPException(status_code=404, detail=f"Firewall '{fw_id}' not found")
        try:
            fw_config = fw_db.to_firewall_config()
        except Exception as exc:
            return templates.TemplateResponse(
                request,
                "partials/connection_test_result.html",
                {"firewall_id": fw_id, "online": False, "error": str(exc)},
            )

    from opn_boss.opnsense.client import OPNSenseClient

    online = await OPNSenseClient(fw_config).probe()

    return templates.TemplateResponse(
        request,
        "partials/connection_test_result.html",
        {"firewall_id": fw_id, "online": online, "error": None},
    )


# ---------------------------------------------------------------------------
# Scheduler settings
# ---------------------------------------------------------------------------


@router.get("/scheduler")
async def get_scheduler_settings(
    service: OPNBossService = Depends(get_service),
) -> dict[str, Any]:
    """Get current scheduler settings."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        from opn_boss.core.database import get_setting

        interval = await get_setting(
            session,
            "scheduler.poll_interval_minutes",
            service._config.scheduler.poll_interval_minutes,
        )
    return {"poll_interval_minutes": interval}


@router.put("/scheduler", response_class=HTMLResponse)
async def update_scheduler_settings(
    request: Request,
    poll_interval_minutes: Annotated[int, Form()],
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Update scheduler interval and reschedule the APScheduler job."""
    if poll_interval_minutes < 1 or poll_interval_minutes > 1440:
        return templates.TemplateResponse(
            request,
            "partials/settings_flash.html",
            {
                "success": False,
                "message": "Interval must be between 1 and 1440 minutes.",
            },
        )

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        from opn_boss.core.database import set_setting

        await set_setting(session, "scheduler.poll_interval_minutes", poll_interval_minutes)
        await session.commit()

    # Reschedule the APScheduler job
    try:
        scheduler = request.app.state.scheduler
        from apscheduler.triggers.interval import IntervalTrigger

        scheduler.reschedule_job(
            "periodic_scan",
            trigger=IntervalTrigger(minutes=poll_interval_minutes),
        )
        logger.info("Rescheduled periodic scan to every %d minute(s)", poll_interval_minutes)
    except Exception as exc:
        logger.warning("Could not reschedule job: %s", exc)

    return templates.TemplateResponse(
        request,
        "partials/settings_flash.html",
        {
            "success": True,
            "message": f"Scan interval updated to {poll_interval_minutes} minute(s).",
        },
    )


# ---------------------------------------------------------------------------
# LLM settings
# ---------------------------------------------------------------------------


@router.get("/llm")
async def get_llm_settings(
    service: OPNBossService = Depends(get_service),
) -> dict[str, Any]:
    """Get current LLM settings."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        from opn_boss.core.database import get_setting

        llm_enabled = await get_setting(session, "llm.enabled", service._config.llm.enabled)
        model = await get_setting(session, "llm.model", service._config.llm.model)
        llm_base_url = await get_setting(session, "llm.base_url", service._config.llm.base_url)
        timeout = await get_setting(
            session, "llm.timeout_seconds", service._config.llm.timeout_seconds
        )
    return {
        "enabled": llm_enabled,
        "model": model,
        "base_url": llm_base_url,
        "timeout_seconds": timeout,
    }


@router.put("/llm", response_class=HTMLResponse)
async def update_llm_settings(
    request: Request,
    enabled: Annotated[str | None, Form()] = None,
    model: Annotated[str, Form()] = "phi3:mini",
    base_url: Annotated[str, Form()] = "http://localhost:11434",
    timeout_seconds: Annotated[float, Form()] = 120.0,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Update LLM settings."""
    bool_enabled = enabled is not None

    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        from opn_boss.core.database import set_setting

        await set_setting(session, "llm.enabled", bool_enabled)
        await set_setting(session, "llm.model", model)
        await set_setting(session, "llm.base_url", base_url)
        await set_setting(session, "llm.timeout_seconds", timeout_seconds)
        await session.commit()

    return templates.TemplateResponse(
        request,
        "partials/settings_flash.html",
        {"success": True, "message": "LLM settings saved."},
    )


# ---------------------------------------------------------------------------
# Partials (HTMX form endpoints)
# ---------------------------------------------------------------------------


@partials_router.get("/firewall-form", response_class=HTMLResponse)
async def new_firewall_form(request: Request) -> HTMLResponse:
    """Return empty firewall add form."""
    return templates.TemplateResponse(
        request,
        "partials/firewall_form.html",
        {"fw": None},
    )


@partials_router.get("/firewall-form/{fw_id}", response_class=HTMLResponse)
async def edit_firewall_form(
    request: Request,
    fw_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Return pre-populated firewall edit form."""
    factory = get_session_factory(service._config.database.url)
    async with factory() as session:
        fw = await session.get(FirewallConfigDB, fw_id)
        if fw is None:
            raise HTTPException(status_code=404, detail=f"Firewall '{fw_id}' not found")
    return templates.TemplateResponse(
        request,
        "partials/firewall_form.html",
        {"fw": fw, "api_key_masked": _mask_key(fw.api_key_enc)},
    )
