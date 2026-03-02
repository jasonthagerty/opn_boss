"""Policy analysis API routes."""

from __future__ import annotations

import pathlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from opn_boss.api.dependencies import get_service
from opn_boss.core.exceptions import LLMUnavailableError
from opn_boss.llm.service import PolicyAnalysisService
from opn_boss.service.main import OPNBossService

TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _get_policy_service(service: OPNBossService) -> PolicyAnalysisService | None:
    """Get the PolicyAnalysisService from app state."""
    svc = service._policy_service
    if svc is None:
        return None
    return svc  # type: ignore[no-any-return]


@router.get("/api/policy/{firewall_id}/summary")
async def get_policy_summary(
    firewall_id: str,
    service: OPNBossService = Depends(get_service),
) -> dict[str, Any]:
    """Return the latest policy summary as JSON."""
    policy_svc = _get_policy_service(service)
    if policy_svc is None:
        raise HTTPException(status_code=503, detail="LLM analysis is disabled in config")

    summary = await policy_svc.get_latest_summary(firewall_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="No policy summary yet -- trigger an analysis first")

    return {
        "id": summary.id,
        "firewall_id": summary.firewall_id,
        "snapshot_id": summary.snapshot_id,
        "generated_at": summary.generated_at.isoformat(),
        "model": summary.model,
        "summary": summary.summary,
    }


@router.post("/api/policy/{firewall_id}/analyze", response_class=HTMLResponse)
async def analyze_policy(
    request: Request,
    firewall_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Generate (or regenerate) policy summary. Returns HTMX partial."""
    policy_svc = _get_policy_service(service)
    if policy_svc is None:
        return templates.TemplateResponse(
            request,
            "partials/llm_error.html",
            {"error": "LLM analysis is disabled in config (llm.enabled: false)"},
        )

    try:
        summary = await policy_svc.generate_summary(firewall_id)
        return templates.TemplateResponse(
            request,
            "partials/policy_summary.html",
            {"summary": summary, "firewall_id": firewall_id},
        )
    except LLMUnavailableError as exc:
        return templates.TemplateResponse(
            request,
            "partials/llm_error.html",
            {"error": str(exc)},
        )


@router.post("/api/policy/{firewall_id}/whatif", response_class=HTMLResponse)
async def whatif_query(
    request: Request,
    firewall_id: str,
    service: OPNBossService = Depends(get_service),
) -> HTMLResponse:
    """Submit a what-if query. Returns HTMX response card."""
    policy_svc = _get_policy_service(service)
    if policy_svc is None:
        return templates.TemplateResponse(
            request,
            "partials/llm_error.html",
            {"error": "LLM analysis is disabled in config (llm.enabled: false)"},
        )

    form = await request.form()
    scenario = str(form.get("scenario", "")).strip()
    if not scenario:
        return templates.TemplateResponse(
            request,
            "partials/llm_error.html",
            {"error": "Please enter a scenario to analyze."},
        )

    try:
        query = await policy_svc.query_whatif(firewall_id, scenario)
        return templates.TemplateResponse(
            request,
            "partials/whatif_card.html",
            {"query": query},
        )
    except LLMUnavailableError as exc:
        return templates.TemplateResponse(
            request,
            "partials/llm_error.html",
            {"error": str(exc)},
        )


@router.get("/api/policy/{firewall_id}/history")
async def policy_history(
    firewall_id: str,
    service: OPNBossService = Depends(get_service),
) -> list[dict[str, Any]]:
    """List past what-if queries for a firewall."""
    policy_svc = _get_policy_service(service)
    if policy_svc is None:
        return []

    queries = await policy_svc.list_whatif_queries(firewall_id)
    return [
        {
            "id": q.id,
            "firewall_id": q.firewall_id,
            "created_at": q.created_at.isoformat(),
            "scenario": q.scenario,
            "response": q.response,
            "log_evidence": q.log_evidence,
            "model": q.model,
        }
        for q in queries
    ]
