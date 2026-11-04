"""Indexer failover restarts a whole frozen window without partial delivery."""

from __future__ import annotations

import json
import ssl
from copy import deepcopy

import httpx
import pytest
import respx
from app.connectors.wazuh import WazuhConnector

PRIMARY = "https://primary.wazuh.example.test:9200"
SECONDARY = "https://secondary.wazuh.example.test:9200"
INDEX = "wazuh-alerts-*"


def _hit(identifier: str, index: str = "wazuh-alerts-2026.11.01") -> dict:
    return {
        "_id": identifier,
        "_index": index,
        "_source": {
            "@timestamp": "2026-11-01T01:00:00Z",
            "rule": {"id": "100100", "level": 12, "description": "Synthetic rule"},
            "agent": {"id": "001", "name": "fixture-host"},
            "full_log": "Synthetic log line",
        },
    }


def _page(hits: list[dict], cursor: str, **extra: object) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "_scroll_id": cursor,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits},
            **extra,
        },
    )


def _connector() -> WazuhConnector:
    return WazuhConnector(PRIMARY, "fixture-user", "fixture-password", indexer_urls=SECONDARY, vuln_mode="alerts")


def test_rule_id_is_separate_from_document_identity() -> None:
    connector = WazuhConnector(PRIMARY, "fixture-user", "fixture-password")
    first = _hit("one")
    same_rule = _hit("two")
    other_index = _hit("one", "wazuh-alerts-2026.11.02")

    events = [connector.normalize(hit) for hit in (first, same_rule, other_index, deepcopy(first))]

    assert len({event["external_id"] for event in events}) == 3
    assert events[0]["external_id"] == events[3]["external_id"]
    assert {event["rule_id"] for event in events} == {"100100"}
    assert {event["rule_name"] for event in events} == {"Synthetic rule"}
    assert events[0]["alert_id"] == "one"
    assert events[0]["raw_event"]["full_log"] == "Synthetic log line"


def test_document_identity_fallback_includes_the_log_and_is_order_independent() -> None:
    connector = WazuhConnector(PRIMARY, "fixture-user", "fixture-password")
    first = _hit("one")
    del first["_id"]
    second = deepcopy(first)
    second["_source"]["full_log"] = "A different synthetic log line at the same time"
    reordered = {"_source": dict(reversed(list(first["_source"].items()))), "_index": first["_index"]}

    events = [connector.normalize(hit) for hit in (first, second, reordered)]

    assert events[0]["external_id"] != events[1]["external_id"]
    assert events[0]["external_id"] == events[2]["external_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 502, 503, 504])
@respx.mock(assert_all_called=True)
async def test_transient_search_status_tries_the_next_node(respx_mock: respx.MockRouter, status: int) -> None:
    primary = respx_mock.post(f"{PRIMARY}/{INDEX}/_search").respond(status)
    secondary = respx_mock.post(f"{SECONDARY}/{INDEX}/_search").mock(return_value=_page([], "second"))
    respx_mock.delete(f"{SECONDARY}/_search/scroll").respond(200)

    connector = _connector()
    assert await connector.fetch_alerts() == []
    assert primary.calls[0].request.content == secondary.calls[0].request.content
    assert connector.get_checkpoint() is not None


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_mid_scroll_failover_discards_partial_hits_and_restarts_the_same_window(respx_mock: respx.MockRouter) -> None:
    first_search = respx_mock.post(f"{PRIMARY}/{INDEX}/_search").mock(return_value=_page([_hit("discarded")], "primary-cursor"))
    respx_mock.post(f"{PRIMARY}/_search/scroll").mock(side_effect=httpx.ReadTimeout("synthetic timeout"))
    clear_first = respx_mock.delete(f"{PRIMARY}/_search/scroll").respond(200)
    next_search = respx_mock.post(f"{SECONDARY}/{INDEX}/_search").mock(return_value=_page([_hit("one"), _hit("two")], "secondary-cursor"))
    continuation = respx_mock.post(f"{SECONDARY}/_search/scroll").mock(return_value=_page([], "secondary-last"))
    clear_last = respx_mock.delete(f"{SECONDARY}/_search/scroll").respond(200)

    events = await _connector().fetch_alerts()

    assert [event["alert_id"] for event in events] == ["one", "two"]
    assert first_search.calls[0].request.content == next_search.calls[0].request.content
    assert json.loads(continuation.calls[0].request.content)["scroll_id"] == "secondary-cursor"
    assert json.loads(clear_first.calls[0].request.content)["scroll_id"] == ["primary-cursor"]
    assert json.loads(clear_last.calls[0].request.content)["scroll_id"] == ["secondary-last"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 500])
@respx.mock(assert_all_called=False)
async def test_permanent_http_errors_do_not_try_another_node(respx_mock: respx.MockRouter, status: int) -> None:
    primary = respx_mock.post(f"{PRIMARY}/{INDEX}/_search").respond(status, text="fixture-password")
    secondary = respx_mock.post(f"{SECONDARY}/{INDEX}/_search").mock(return_value=_page([], "unused"))
    connector = _connector()

    with pytest.raises(RuntimeError, match=str(status)) as raised:
        await connector.fetch_alerts()

    assert "fixture-password" not in str(raised.value)
    assert primary.call_count == 1
    assert secondary.call_count == 0
    assert connector.get_checkpoint() is None


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_certificate_validation_error_is_visible_without_failover(respx_mock: respx.MockRouter) -> None:
    failure = httpx.ConnectError("certificate verification failed: fixture-password")
    failure.__cause__ = ssl.SSLCertVerificationError("synthetic certificate mismatch")
    primary = respx_mock.post(f"{PRIMARY}/{INDEX}/_search").mock(side_effect=failure)
    secondary = respx_mock.post(f"{SECONDARY}/{INDEX}/_search").mock(return_value=_page([], "unused"))

    with pytest.raises(RuntimeError, match="TLS") as raised:
        await _connector().fetch_alerts()

    assert "fixture-password" not in str(raised.value)
    assert primary.call_count == 1
    assert secondary.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("partial", [{"timed_out": True}, {"_shards": {"total": 2, "successful": 1, "failed": 1}}])
@respx.mock(assert_all_called=True)
async def test_partial_search_restarts_on_another_node(respx_mock: respx.MockRouter, partial: dict) -> None:
    respx_mock.post(f"{PRIMARY}/{INDEX}/_search").mock(return_value=_page([_hit("discarded")], "partial", **partial))
    respx_mock.delete(f"{PRIMARY}/_search/scroll").respond(200)
    respx_mock.post(f"{SECONDARY}/{INDEX}/_search").mock(return_value=_page([], "complete"))
    respx_mock.delete(f"{SECONDARY}/_search/scroll").respond(200)

    assert await _connector().fetch_alerts() == []


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_all_nodes_failing_does_not_stage_progress(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{PRIMARY}/{INDEX}/_search").mock(side_effect=httpx.ConnectError("synthetic node outage"))
    respx_mock.post(f"{SECONDARY}/{INDEX}/_search").respond(503)
    connector = _connector()

    with pytest.raises(RuntimeError, match="503"):
        await connector.fetch_alerts()

    assert connector.get_checkpoint() is None


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_connection_health_uses_the_same_nodes(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{PRIMARY}/_cluster/health").respond(503)
    respx_mock.get(f"{SECONDARY}/_cluster/health").respond(200, json={"status": "green"})

    assert await _connector().test_connection() == {"success": True, "connector": "wazuh"}
