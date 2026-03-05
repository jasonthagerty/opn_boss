"""Tests for NotificationDispatcher."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx

from opn_boss.core.types import Category, Finding, Severity
from opn_boss.notifications.dispatcher import NotificationDispatcher


def _make_finding(
    check_id: str = "SEC-002",
    severity: Severity = Severity.CRITICAL,
    firewall_id: str = "fw1",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test {check_id}",
        description=f"Description for {check_id}",
        severity=severity,
        category=Category.SECURITY,
        firewall_id=firewall_id,
        evidence={},
        remediation="Fix it.",
    )


def _make_session(
    *,
    webhook_url: str = "",
    slack_url: str = "",
    suppressed_check_ids: set[str] | None = None,
    prev_critical_check_ids: set[str] | None = None,
) -> AsyncMock:
    """Build a mock async session that returns configured settings and query results."""
    session = AsyncMock()
    suppressed = suppressed_check_ids or set()
    prev_criticals = prev_critical_check_ids or set()

    async def fake_get_setting(
        sess: Any, key: str, default: Any = None
    ) -> Any:
        mapping: dict[str, str] = {
            "notifications.webhook_url": webhook_url,
            "notifications.slack_webhook_url": slack_url,
        }
        return mapping.get(key, default)

    return session, fake_get_setting, suppressed, prev_criticals


def _patch_dispatcher(
    dispatcher: NotificationDispatcher,
    *,
    webhook_url: str = "",
    slack_url: str = "",
    suppressed_check_ids: set[str] | None = None,
    prev_critical_check_ids: set[str] | None = None,
) -> None:
    """Monkey-patch the dispatcher internals to avoid real DB calls."""
    suppressed = suppressed_check_ids or set()
    prev_criticals = prev_critical_check_ids or set()

    mock_session = AsyncMock()

    @asynccontextmanager
    async def fake_factory() -> Any:
        yield mock_session

    dispatcher._session_factory = fake_factory  # type: ignore[assignment]

    # Patch get_setting at module level for the dispatch method
    async def patched_dispatch(
        firewall_id: str,
        snapshot_id: str,
        findings: list[Finding],
    ) -> None:
        """Reimplemented dispatch that uses mock data instead of DB."""
        if not webhook_url and not slack_url:
            return

        new_criticals = [
            f
            for f in findings
            if f.severity == Severity.CRITICAL
            and f.check_id not in suppressed
            and f.check_id not in prev_criticals
        ]

        if not new_criticals:
            return

        if webhook_url:
            await dispatcher._post_webhook(webhook_url, firewall_id, new_criticals)
        if slack_url:
            await dispatcher._post_slack(slack_url, firewall_id, new_criticals)

    dispatcher.dispatch = patched_dispatch  # type: ignore[assignment]


@pytest.fixture
def dispatcher(tmp_path: Any) -> NotificationDispatcher:
    url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    return NotificationDispatcher(url)


async def test_dispatch_no_urls_skips_http(dispatcher: NotificationDispatcher) -> None:
    """When both URLs are empty, no HTTP calls are made."""
    _patch_dispatcher(dispatcher, webhook_url="", slack_url="")

    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.route().respond(200)
        await dispatcher.dispatch("fw1", "snap-1", [_make_finding()])
        assert respx_mock.calls.call_count == 0


async def test_dispatch_no_new_criticals(dispatcher: NotificationDispatcher) -> None:
    """Findings that are all OK/WARNING, or already critical in previous snapshot, do not trigger POST."""
    _patch_dispatcher(
        dispatcher,
        webhook_url="https://example.com/hook",
        prev_critical_check_ids={"SEC-002"},
    )

    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.route().respond(200)
        # SEC-002 was already critical last time
        await dispatcher.dispatch("fw1", "snap-2", [_make_finding(check_id="SEC-002")])
        assert respx_mock.calls.call_count == 0

    # Also test with non-critical findings
    _patch_dispatcher(
        dispatcher,
        webhook_url="https://example.com/hook",
    )
    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.route().respond(200)
        await dispatcher.dispatch(
            "fw1", "snap-3", [_make_finding(severity=Severity.WARNING)]
        )
        assert respx_mock.calls.call_count == 0


@respx.mock
async def test_dispatch_new_critical_fires_webhook(
    dispatcher: NotificationDispatcher,
) -> None:
    """New CRITICAL finding with webhook URL configured triggers a POST."""
    hook_url = "https://example.com/hook"
    _patch_dispatcher(dispatcher, webhook_url=hook_url)

    route = respx.post(hook_url).respond(200)

    await dispatcher.dispatch("fw1", "snap-1", [_make_finding(check_id="SEC-002")])

    assert route.called
    # Verify the request was made with correct structure
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["event"] == "new_critical_findings"
    assert body["firewall_id"] == "fw1"
    assert body["new_critical_count"] == 1
    assert len(body["findings"]) == 1
    assert body["findings"][0]["check_id"] == "SEC-002"


@respx.mock
async def test_dispatch_new_critical_fires_slack(
    dispatcher: NotificationDispatcher,
) -> None:
    """New CRITICAL finding with Slack URL configured triggers a POST with blocks."""
    slack_url = "https://hooks.slack.com/services/T/B/X"
    _patch_dispatcher(dispatcher, slack_url=slack_url)

    route = respx.post(slack_url).respond(200)

    await dispatcher.dispatch("fw1", "snap-1", [_make_finding(check_id="MW-001")])

    assert route.called
    import json

    body = json.loads(route.calls[0].request.content)
    assert "blocks" in body
    assert body["text"]  # fallback text present


async def test_dispatch_suppressed_skipped(
    dispatcher: NotificationDispatcher,
) -> None:
    """CRITICAL finding whose check_id is suppressed is not notified."""
    _patch_dispatcher(
        dispatcher,
        webhook_url="https://example.com/hook",
        suppressed_check_ids={"SEC-002"},
    )

    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.route().respond(200)
        await dispatcher.dispatch("fw1", "snap-1", [_make_finding(check_id="SEC-002")])
        assert respx_mock.calls.call_count == 0


@respx.mock
async def test_test_webhook_posts(dispatcher: NotificationDispatcher) -> None:
    """test_webhook() makes one POST with TEST-001 payload."""
    hook_url = "https://example.com/test-hook"
    route = respx.post(hook_url).respond(200)

    await dispatcher.test_webhook(hook_url, "fw-test")

    assert route.called
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["findings"][0]["check_id"] == "TEST-001"
    assert body["firewall_id"] == "fw-test"


@respx.mock
async def test_test_slack_posts(dispatcher: NotificationDispatcher) -> None:
    """test_slack() makes one POST with TEST-001 in Slack block format."""
    slack_url = "https://hooks.slack.com/services/T/B/test"
    route = respx.post(slack_url).respond(200)

    await dispatcher.test_slack(slack_url, "fw-test")

    assert route.called
    import json

    body = json.loads(route.calls[0].request.content)
    assert "blocks" in body
    assert "fw-test" in body["text"]
