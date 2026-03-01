"""Base analyzer abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from opn_boss.core.types import CollectorResult, Finding


class BaseAnalyzer(ABC):
    """Abstract base for all rule-based analyzers.

    Analyzers are pure functions over collected data — no I/O.
    """

    #: Category label, e.g. "security"
    category: str = "base"

    @abstractmethod
    def analyze(
        self,
        firewall_id: str,
        collector_results: dict[str, CollectorResult],
    ) -> list[Finding]:
        """Run all checks and return findings.

        Args:
            firewall_id: The firewall being analyzed.
            collector_results: Mapping of collector name → CollectorResult.

        Returns:
            List of Finding instances (never raises).
        """
        ...

    def _get_data(
        self,
        collector_results: dict[str, CollectorResult],
        collector_name: str,
    ) -> dict[str, Any]:
        """Safely get data from a collector result, returning empty dict on miss."""
        result = collector_results.get(collector_name)
        if result is None or not result.success:
            return {}
        return result.data
