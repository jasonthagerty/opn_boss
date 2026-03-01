"""Policy analysis service -- orchestrates LLM calls against firewall data."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import desc, select

from opn_boss.core.config import LLMConfig
from opn_boss.core.database import (
    CollectorRunDB,
    PolicySummaryDB,
    SnapshotDB,
    WhatIfQueryDB,
    get_session_factory,
)
from opn_boss.core.exceptions import LLMUnavailableError
from opn_boss.core.logging_config import get_logger
from opn_boss.core.types import CollectorResult
from opn_boss.llm.client import OllamaClient
from opn_boss.llm.formatter import PolicyFormatter
from opn_boss.llm.prompts import (
    build_log_evidence_prompt,
    build_summary_prompt,
    build_whatif_prompt,
)

logger = get_logger(__name__)


def _find_log_matches(entries: list[dict[str, Any]], scenario: str) -> list[dict[str, Any]]:
    """Simple keyword match: find log entries whose src/dst appear in the scenario text."""
    scenario_lower = scenario.lower()
    matches = []
    for entry in entries:
        src = str(entry.get("src", ""))
        dst = str(entry.get("dst", ""))
        dport = str(entry.get("dstport", ""))
        if src in scenario_lower or dst in scenario_lower or dport in scenario_lower:
            matches.append(entry)
        if len(matches) >= 20:
            break
    return matches


class PolicyAnalysisService:
    """Orchestrates LLM-based policy analysis."""

    def __init__(self, llm_config: LLMConfig, db_url: str) -> None:
        self._llm_config = llm_config
        self._db_url = db_url
        self._client = OllamaClient(llm_config)
        self._formatter = PolicyFormatter()
        self._session_factory = get_session_factory(db_url)

    async def _load_collector_data(
        self, firewall_id: str, collector_name: str
    ) -> dict[str, Any]:
        """Load the most recent collector run data from DB."""
        async with self._session_factory() as session:
            latest_snap = (
                select(SnapshotDB.id)
                .where(SnapshotDB.firewall_id == firewall_id)
                .order_by(desc(SnapshotDB.started_at))
                .limit(1)
                .scalar_subquery()
            )
            result = await session.execute(
                select(CollectorRunDB).where(
                    CollectorRunDB.snapshot_id == latest_snap,
                    CollectorRunDB.firewall_id == firewall_id,
                    CollectorRunDB.collector_name == collector_name,
                    CollectorRunDB.success == True,  # noqa: E712
                )
            )
            run = result.scalar_one_or_none()
            return run.data if run else {}

    async def generate_summary(
        self,
        firewall_id: str,
        snapshot_id: str | None = None,
        collector_results: dict[str, CollectorResult] | None = None,
    ) -> PolicySummaryDB:
        """Generate a policy summary using the LLM."""
        # Load data from collector_results (live scan) or from DB (historical)
        if collector_results:
            rules_data = collector_results.get("firewall_rules")
            rules_list = rules_data.data.get("rules", []) if rules_data and rules_data.success else []
            nat_data_raw = collector_results.get("nat_rules")
            nat_dict = nat_data_raw.data if nat_data_raw and nat_data_raw.success else {}
            routes_data = collector_results.get("routes")
            routes_list = routes_data.data.get("routes", []) if routes_data and routes_data.success else []
        else:
            fw_rules_data = await self._load_collector_data(firewall_id, "firewall_rules")
            rules_list = fw_rules_data.get("rules", [])
            nat_dict = await self._load_collector_data(firewall_id, "nat_rules")
            routes_raw = await self._load_collector_data(firewall_id, "routes")
            routes_list = routes_raw.get("routes", [])

        rules_text = self._formatter.format_rules(rules_list)
        nat_text = self._formatter.format_nat(nat_dict)
        routes_text = self._formatter.format_routes(routes_list)

        prompt = build_summary_prompt(rules_text, nat_text, routes_text)
        summary_text = await self._client.generate(prompt)

        record = PolicySummaryDB(
            id=str(uuid.uuid4()),
            firewall_id=firewall_id,
            snapshot_id=snapshot_id or "",
            generated_at=datetime.utcnow(),
            model=self._llm_config.model,
            summary=summary_text,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)

        return record

    async def query_whatif(
        self,
        firewall_id: str,
        scenario: str,
        collector_results: dict[str, CollectorResult] | None = None,
    ) -> WhatIfQueryDB:
        """Answer a what-if policy question using the LLM."""
        if collector_results:
            rules_data = collector_results.get("firewall_rules")
            rules_list = rules_data.data.get("rules", []) if rules_data and rules_data.success else []
            nat_data_raw = collector_results.get("nat_rules")
            nat_dict = nat_data_raw.data if nat_data_raw and nat_data_raw.success else {}
            routes_data = collector_results.get("routes")
            routes_list = routes_data.data.get("routes", []) if routes_data and routes_data.success else []
            logs_data = collector_results.get("firewall_logs")
            log_entries = logs_data.data.get("entries", []) if logs_data and logs_data.success else []
        else:
            fw_rules_data = await self._load_collector_data(firewall_id, "firewall_rules")
            rules_list = fw_rules_data.get("rules", [])
            nat_dict = await self._load_collector_data(firewall_id, "nat_rules")
            routes_raw = await self._load_collector_data(firewall_id, "routes")
            routes_list = routes_raw.get("routes", [])
            logs_raw = await self._load_collector_data(firewall_id, "firewall_logs")
            log_entries = logs_raw.get("entries", [])

        rules_text = self._formatter.format_rules(rules_list)
        nat_text = self._formatter.format_nat(nat_dict)
        routes_text = self._formatter.format_routes(routes_list)

        prompt = build_whatif_prompt(rules_text, nat_text, routes_text, scenario)
        response_text = await self._client.generate(prompt)

        # Find matching log evidence
        matching_logs = _find_log_matches(log_entries, scenario)
        log_evidence: list[dict[str, Any]] = []
        if matching_logs:
            evidence_prompt = build_log_evidence_prompt(scenario, matching_logs)
            try:
                evidence_text = await self._client.generate(evidence_prompt)
                log_evidence = matching_logs
                response_text = response_text + "\n\n**Log Evidence:**\n" + evidence_text
            except LLMUnavailableError:
                log_evidence = matching_logs  # include raw logs even if LLM fails

        record = WhatIfQueryDB(
            id=str(uuid.uuid4()),
            firewall_id=firewall_id,
            created_at=datetime.utcnow(),
            scenario=scenario,
            response=response_text,
            log_evidence=log_evidence,
            model=self._llm_config.model,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)

        return record

    async def get_latest_summary(self, firewall_id: str) -> PolicySummaryDB | None:
        """Return the most recent policy summary for a firewall."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(PolicySummaryDB)
                .where(PolicySummaryDB.firewall_id == firewall_id)
                .order_by(desc(PolicySummaryDB.generated_at))
                .limit(1)
            )
            return result.scalar_one_or_none()

    async def list_whatif_queries(self, firewall_id: str) -> list[WhatIfQueryDB]:
        """Return past what-if queries for a firewall."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(WhatIfQueryDB)
                .where(WhatIfQueryDB.firewall_id == firewall_id)
                .order_by(desc(WhatIfQueryDB.created_at))
                .limit(20)
            )
            return list(result.scalars().all())
