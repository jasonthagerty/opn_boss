"""Live integration tests for Ollama LLM / PolicyAnalysisService.

These tests require:
  - Ollama running at http://localhost:11434
  - Model 'llama3.2:3b' pulled (ollama pull llama3.2:3b)

Run with:
  uv run pytest tests/integration/test_llm_live.py -v -s
"""

from __future__ import annotations

import textwrap

import pytest

from opn_boss.core.config import LLMConfig
from opn_boss.core.database import create_tables
from opn_boss.core.types import CollectorResult
from opn_boss.llm.service import PolicyAnalysisService

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:3b"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_globals():
    import opn_boss.core.database as db_module

    db_module._engine = None
    db_module._session_factory = None
    yield
    db_module._engine = None
    db_module._session_factory = None


@pytest.fixture
def llm_config() -> LLMConfig:
    return LLMConfig(
        enabled=True,
        model=OLLAMA_MODEL,
        base_url=OLLAMA_URL,
        timeout_seconds=120.0,
    )


@pytest.fixture
def tmp_db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path}/live_test.db"


@pytest.fixture
async def policy_svc(llm_config: LLMConfig, tmp_db_url: str) -> PolicyAnalysisService:
    await create_tables(tmp_db_url)
    return PolicyAnalysisService(llm_config=llm_config, db_url=tmp_db_url)


def _make_result(name: str, data: dict) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        firewall_id="fw-live",
        success=True,
        data=data,
        duration_ms=0.0,
    )


# Minimal but realistic firewall ruleset
SAMPLE_COLLECTOR_RESULTS: dict[str, CollectorResult] = {
    "firewall_rules": _make_result(
        "firewall_rules",
        {
            "rules": [
                {
                    "enabled": "1",
                    "interface": "wan",
                    "protocol": "tcp",
                    "source": {"any": "1"},
                    "destination": {"network": "lan", "port": "22"},
                    "description": "Allow SSH from anywhere",
                    "action": "pass",
                },
                {
                    "enabled": "1",
                    "interface": "lan",
                    "protocol": "any",
                    "source": {"network": "lan"},
                    "destination": {"any": "1"},
                    "description": "LAN to any",
                    "action": "pass",
                },
                {
                    "enabled": "1",
                    "interface": "wan",
                    "protocol": "any",
                    "source": {"any": "1"},
                    "destination": {"any": "1"},
                    "description": "Block all inbound",
                    "action": "block",
                },
            ]
        },
    ),
    "routes": _make_result(
        "routes",
        {
            "routes": [
                {
                    "network": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "interface": "wan",
                    "flags": "UGS",
                },
                {
                    "network": "192.168.1.0/24",
                    "gateway": "link#0",
                    "interface": "lan",
                    "flags": "U",
                },
            ]
        },
    ),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.live_llm
async def test_generate_summary_returns_nonempty_text(
    policy_svc: PolicyAnalysisService,
):
    """PolicyAnalysisService.generate_summary returns a non-empty policy summary."""
    result = await policy_svc.generate_summary(
        firewall_id="fw-live",
        collector_results=SAMPLE_COLLECTOR_RESULTS,
    )

    assert result is not None
    assert result.firewall_id == "fw-live"
    assert result.model == OLLAMA_MODEL
    assert len(result.summary) > 50, "Summary should be substantive"
    print(f"\n--- POLICY SUMMARY ---\n{result.summary[:800]}\n")


@pytest.mark.asyncio
@pytest.mark.live_llm
async def test_query_whatif_ssh_blocked(
    policy_svc: PolicyAnalysisService,
):
    """query_whatif answers whether SSH from the internet would be blocked."""
    result = await policy_svc.query_whatif(
        firewall_id="fw-live",
        scenario="Would SSH traffic from a remote IP on the internet reach a server at 192.168.1.50?",
        collector_results=SAMPLE_COLLECTOR_RESULTS,
    )

    assert result is not None
    assert result.firewall_id == "fw-live"
    assert result.model == OLLAMA_MODEL
    assert len(result.response) > 30, "Response should be substantive"
    print(f"\n--- WHATIF RESPONSE ---\n{result.response[:800]}\n")


@pytest.mark.asyncio
@pytest.mark.live_llm
async def test_generate_summary_persisted_to_db(
    policy_svc: PolicyAnalysisService,
):
    """Generated summary is saved to the DB and retrievable via get_latest_summary."""
    await policy_svc.generate_summary(
        firewall_id="fw-live",
        collector_results=SAMPLE_COLLECTOR_RESULTS,
    )

    latest = await policy_svc.get_latest_summary("fw-live")
    assert latest is not None
    assert latest.firewall_id == "fw-live"
    assert len(latest.summary) > 10


@pytest.mark.asyncio
@pytest.mark.live_llm
async def test_whatif_query_persisted_to_db(
    policy_svc: PolicyAnalysisService,
):
    """What-if query is saved and appears in list_whatif_queries."""
    scenario = "Can a host on the LAN reach external DNS (port 53)?"
    await policy_svc.query_whatif(
        firewall_id="fw-live",
        scenario=scenario,
        collector_results=SAMPLE_COLLECTOR_RESULTS,
    )

    history = await policy_svc.list_whatif_queries("fw-live")
    assert len(history) == 1
    assert history[0].scenario == scenario
    assert len(history[0].response) > 10
