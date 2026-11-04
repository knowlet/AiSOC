"""Wazuh resumes completed windows without dropping newly indexed older rows.

These tests exercise the connector's real HTTP client against transport
fixtures. PostgreSQL persistence and the scheduler's acceptance boundary are
covered separately by the live checkpoint suite.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import respx
from app.connectors.wazuh import WazuhConnector

INDEXER = "https://wazuh-checkpoint.example.test:9200"


def _hit(identifier: str, timestamp: str) -> dict[str, Any]:
    return {
        "_index": "wazuh-alerts-fixture",
        "_id": identifier,
        "_source": {
            "@timestamp": timestamp,
            "rule": {"id": "100100", "level": 12, "description": "Synthetic checkpoint event"},
            "agent": {"id": "001", "name": "fixture-host"},
            "full_log": f"Synthetic record {identifier}",
        },
    }


def _page(hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "_scroll_id": "checkpoint-fixture-scroll",
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"hits": hits},
    }


def _routes(mock: respx.MockRouter, hits: list[dict[str, Any]]) -> respx.Route:
    search = mock.post(f"{INDEXER}/wazuh-alerts-*/_search").respond(200, json=_page(hits))
    mock.post(f"{INDEXER}/_search/scroll").respond(200, json=_page([]))
    mock.delete(f"{INDEXER}/_search/scroll").respond(200, json={"succeeded": True, "num_freed": 1})
    return search


def _connector() -> WazuhConnector:
    return WazuhConnector(INDEXER, "fixture-user", "fixture-password", vuln_mode="alerts")


def test_wazuh_declares_durable_checkpointing() -> None:
    assert WazuhConnector.checkpoints() is True


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_restart_fetches_from_the_durable_window_even_after_a_long_outage(respx_mock: respx.MockRouter) -> None:
    previous = datetime.now(UTC) - timedelta(hours=3)
    connector = _connector()
    connector.set_checkpoint({"version": 1, "completed_through": {"alerts": previous.isoformat()}, "seen": []})
    search = _routes(respx_mock, [])

    assert await connector.fetch_alerts(since_seconds=300) == []

    query = json.loads(search.calls[0].request.content)
    window = query["query"]["bool"]["must"][0]["range"]["@timestamp"]
    assert not window["gte"].startswith("now"), "the persisted position must determine the restart lookback"
    assert datetime.fromisoformat(window["gte"]) <= previous
    assert datetime.fromisoformat(window["lte"]) > previous


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_a_complete_empty_window_still_stages_progress(respx_mock: respx.MockRouter) -> None:
    connector = _connector()
    search = _routes(respx_mock, [])

    assert await connector.fetch_alerts() == []

    checkpoint = connector.get_checkpoint()
    assert checkpoint is not None, "quiet windows need a durable recovery position too"
    query = json.loads(search.calls[0].request.content)
    end = query["query"]["bool"]["must"][0]["range"]["@timestamp"]["lte"]
    assert checkpoint["completed_through"]["alerts"] == end


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_restart_dedups_seen_ids_but_keeps_new_older_and_same_time_documents(respx_mock: respx.MockRouter) -> None:
    timestamp = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    first = _connector()
    search = _routes(respx_mock, [_hit("later-id-z", timestamp)])
    assert len(await first.fetch_alerts()) == 1
    persisted = first.get_checkpoint()

    # Both late records sort before the old event-time watermark. Their
    # identities, not their order, determine whether they have been seen.
    older = (datetime.fromisoformat(timestamp) - timedelta(seconds=30)).isoformat()
    search.respond(200, json=_page([_hit("later-id-z", timestamp), _hit("earlier-id-a", timestamp), _hit("late-older", older)]))
    restarted = _connector()
    restarted.set_checkpoint(persisted)

    events = await restarted.fetch_alerts()

    assert [event["alert_id"] for event in events] == ["wazuh-alerts-fixture::earlier-id-a", "wazuh-alerts-fixture::late-older"]
    assert len({event["external_id"] for event in events}) == 2


@pytest.mark.asyncio
async def test_inventory_sync_drains_every_sink_sized_chunk_before_confirming(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.scheduler import ConnectorScheduler
    from app.vulnerabilities import MAX_FINDINGS_PER_SYNC

    findings = [{"cve_id": f"CVE-2026-{number:05d}", "hostname": "fixture-host"} for number in range(MAX_FINDINGS_PER_SYNC + 1)]
    accepted: list[dict[str, Any]] = []
    order: list[str] = []

    async def sink(_engine: Any, *, tenant_id: Any, findings: list[dict[str, Any]]) -> dict[str, int]:
        assert tenant_id == "fixture-tenant"
        assert len(findings) <= MAX_FINDINGS_PER_SYNC, "the real sink truncates a larger call"
        accepted.extend(findings)
        order.append("persist")
        return {"findings_inserted": len(findings), "findings_touched": 0, "skipped": 0}

    monkeypatch.setattr("app.vulnerabilities.sync_findings", sink)
    connector = SimpleNamespace(
        fetch_vulnerability_findings=AsyncMock(return_value=findings),
        confirm_vulnerability_sync=Mock(side_effect=lambda: order.append("confirm")),
    )
    target = SimpleNamespace(id="fixture-connector", connector_type="wazuh", tenant_id="fixture-tenant")

    await ConnectorScheduler(engine=object())._sync_vulnerability_findings(connector, target)  # type: ignore[arg-type]

    assert accepted == findings
    assert order == ["persist", "persist", "confirm"]


@pytest.mark.asyncio
async def test_a_later_inventory_sink_failure_never_confirms_the_staged_window(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.scheduler import ConnectorScheduler
    from app.vulnerabilities import MAX_FINDINGS_PER_SYNC

    findings = [{"cve_id": f"CVE-2026-{number:05d}", "hostname": "fixture-host"} for number in range(MAX_FINDINGS_PER_SYNC + 1)]
    sink = AsyncMock(
        side_effect=[
            {"findings_inserted": MAX_FINDINGS_PER_SYNC, "findings_touched": 0, "skipped": 0},
            RuntimeError("synthetic inventory transaction failure"),
        ]
    )
    monkeypatch.setattr("app.vulnerabilities.sync_findings", sink)
    connector = SimpleNamespace(fetch_vulnerability_findings=AsyncMock(return_value=findings), confirm_vulnerability_sync=Mock())
    target = SimpleNamespace(id="fixture-connector", connector_type="wazuh", tenant_id="fixture-tenant")

    await ConnectorScheduler(engine=object())._sync_vulnerability_findings(connector, target)  # type: ignore[arg-type]

    assert sink.await_count == 2
    connector.confirm_vulnerability_sync.assert_not_called()


@pytest.mark.asyncio
async def test_inventory_accounting_mismatch_does_not_confirm_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.scheduler import ConnectorScheduler

    monkeypatch.setattr(
        "app.vulnerabilities.sync_findings", AsyncMock(return_value={"findings_inserted": 0, "findings_touched": 0, "skipped": 0})
    )
    connector = SimpleNamespace(
        fetch_vulnerability_findings=AsyncMock(return_value=[{"cve_id": "CVE-2026-10001"}]), confirm_vulnerability_sync=Mock()
    )
    target = SimpleNamespace(id="fixture-connector", connector_type="wazuh", tenant_id="fixture-tenant")

    await ConnectorScheduler(engine=object())._sync_vulnerability_findings(connector, target)  # type: ignore[arg-type]

    connector.confirm_vulnerability_sync.assert_not_called()


def test_inventory_progress_is_only_eligible_after_its_sink_confirms() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    checkpoint = WazuhCheckpoint()
    previous = "2026-11-01T00:00:00+00:00"
    advanced = "2026-11-01T02:00:00+00:00"
    checkpoint.load({"version": 1, "completed_through": {"alerts": previous, "vulnerabilities": previous}, "seen": []})
    checkpoint.stage("alerts", advanced)
    checkpoint.stage("vulnerabilities", advanced)

    alerts_only = checkpoint.snapshot([])
    assert alerts_only is not None
    assert alerts_only["completed_through"] == {"alerts": advanced, "vulnerabilities": previous}
    checkpoint.confirm_vulnerability_sync()
    both_streams = checkpoint.snapshot([])
    assert both_streams is not None
    assert both_streams["completed_through"] == {"alerts": advanced, "vulnerabilities": advanced}


def test_window_resume_parses_offsets_instead_of_lexically_ordering_timestamps() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    checkpoint = WazuhCheckpoint(overlap_seconds=300)
    checkpoint.load({"version": 1, "completed_through": {"alerts": "2026-11-01T09:00:00+08:00"}, "seen": []})

    window = checkpoint.query_range("alerts", 300, now=datetime(2026, 11, 1, 3, 0, tzinfo=UTC))

    assert window == {"gte": "2026-11-01T00:55:00+00:00", "lte": "2026-11-01T03:00:00+00:00"}


def test_loading_a_checkpoint_discards_previous_staged_progress() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    checkpoint = WazuhCheckpoint()
    checkpoint.stage("alerts", "2026-11-01T03:00:00+00:00")
    checkpoint.stage("vulnerabilities", "2026-11-01T03:00:00+00:00")
    checkpoint.confirm_vulnerability_sync()
    checkpoint.load(None)

    assert checkpoint.snapshot([]) is None


def test_first_attempt_anchor_survives_restart_without_claiming_completion() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    initial = WazuhCheckpoint()
    durable = initial.prepare(300, inventory=True)
    assert durable is not None
    assert durable["completed_through"] == {}
    start = datetime.fromisoformat(durable["pending_from"]["alerts"])

    restarted = WazuhCheckpoint()
    restarted.load(durable)
    assert restarted.prepare(300, inventory=True) is None
    window = restarted.query_range("alerts", 300, now=start + timedelta(hours=3))

    assert datetime.fromisoformat(window["gte"]) == start
    assert restarted.snapshot([]) is None, "a recovery anchor must not pretend the failed search completed"


def test_a_failed_first_inventory_sync_keeps_its_original_lower_bound() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    state = WazuhCheckpoint()
    initial = state.prepare(300)
    assert initial is not None
    state.load(initial)
    end = datetime.now(UTC).isoformat()
    state.stage("alerts", end)
    state.stage("vulnerabilities", end)
    saved = state.snapshot(["seen-document"])
    assert saved is not None
    assert saved["completed_through"] == {"alerts": end}
    assert saved["pending_from"] == {"vulnerabilities": initial["pending_from"]["vulnerabilities"]}

    restarted = WazuhCheckpoint()
    restarted.load(saved)
    lower = datetime.fromisoformat(initial["pending_from"]["vulnerabilities"])
    window = restarted.query_range("vulnerabilities", 3600, now=lower + timedelta(hours=4))
    assert datetime.fromisoformat(window["gte"]) == lower


def test_enabling_inventory_keeps_the_accepted_alert_ids_and_boundary() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    state = WazuhCheckpoint()
    previous = "2026-11-01T01:00:00+00:00"
    state.load({"version": 1, "completed_through": {"alerts": previous}, "seen": ["accepted-document"]})
    saved = state.prepare(300, inventory=True)

    assert saved is not None
    assert saved["completed_through"] == {"alerts": previous}
    assert saved["seen"] == ["accepted-document"]
    assert set(saved["pending_from"]) == {"vulnerabilities"}


def test_bootstrap_window_includes_the_configured_lateness_margin() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    state = WazuhCheckpoint(overlap_seconds=900)
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    window = state.query_range("alerts", 300, now=now)

    assert datetime.fromisoformat(window["gte"]) <= now - timedelta(minutes=10)
    assert datetime.fromisoformat(window["lte"]) == now


def test_retrying_inventory_discards_a_previously_confirmed_staged_position() -> None:
    from app.connectors.wazuh_checkpoint import WazuhCheckpoint

    state = WazuhCheckpoint()
    state.stage("vulnerabilities", "2026-11-01T03:00:00+00:00")
    state.confirm_vulnerability_sync()
    state.query_range("vulnerabilities", 3600)

    assert state.snapshot([]) is None


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_a_corrupt_durable_window_fails_instead_of_resuming_a_shorter_range(respx_mock: respx.MockRouter) -> None:
    connector = _connector()
    connector.set_checkpoint({"version": 1, "completed_through": {"alerts": "invalid"}, "seen": []})
    search = _routes(respx_mock, [])

    with pytest.raises(ValueError, match="checkpoint is invalid"):
        await connector.fetch_alerts()

    assert search.call_count == 0
    assert connector.get_checkpoint() is None


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_search_failure_does_not_stage_a_new_checkpoint(respx_mock: respx.MockRouter) -> None:
    connector = _connector()
    _routes(respx_mock, [])
    respx_mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=httpx.Response(503, json={"error": "synthetic outage"}))

    with pytest.raises(RuntimeError):
        await connector.fetch_alerts()

    assert connector.get_checkpoint() is None
