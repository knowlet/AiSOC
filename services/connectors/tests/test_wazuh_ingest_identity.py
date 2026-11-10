"""Wazuh documents retain distinct, replay-stable identities through ingest."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from app.connectors.wazuh import WazuhConnector
from app.ingest_client import IngestClient

INDEX = "wazuh-alerts-4.x-2026.11.03"
INDEXER = "https://wazuh.test:9200"
INGEST = "http://ingest.test"


def _hit(number: int, *, index: str = INDEX) -> dict[str, Any]:
    return {
        "_index": index,
        "_id": f"document-{number}",
        "_source": {
            "@timestamp": "2026-11-03T12:00:00Z",
            "rule": {"id": "100100", "level": 12, "description": "Synthetic identity regression event"},
            "agent": {"id": "001", "name": "fixture-host"},
        },
    }


def _connector() -> WazuhConnector:
    return WazuhConnector(INDEXER, "fixture-user", "fixture-password", vuln_mode="alerts")


def test_same_rule_and_timestamp_do_not_collapse_distinct_documents() -> None:
    connector = _connector()
    events = [connector.normalize(_hit(number)) for number in range(1001)]

    assert len({event["external_id"] for event in events}) == 1001
    assert {event["rule_id"] for event in events} == {"100100"}
    assert [event["alert_id"] for event in events] == [f"document-{number}" for number in range(1001)]
    assert all(event["external_id"].startswith(f"{INDEX}::") for event in events)


def test_document_identity_is_scoped_to_the_index_and_stable_on_replay() -> None:
    connector = _connector()
    first = connector.normalize(_hit(1))
    second = connector.normalize(_hit(1, index="wazuh-alerts-4.x-2026.11.04"))

    assert first["external_id"] != second["external_id"]
    assert first["alert_id"] == second["alert_id"], "the existing display ID remains unchanged"
    assert connector.normalize(_hit(1))["external_id"] == first["external_id"]


@pytest.mark.parametrize("missing", ["_index", "_id"])
def test_normalize_fallback_keeps_a_stable_event_identity(missing: str) -> None:
    hit = _hit(1)
    del hit[missing]
    event = _connector().normalize(hit)
    assert event["external_id"] == event["alert_id"]
    assert event["external_id"] != event["rule_id"]


def _page(hits: list[dict[str, Any]], cursor: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "_scroll_id": cursor,
            "timed_out": False,
            "_shards": {"total": 2, "successful": 2, "failed": 0},
            "hits": {"total": {"value": 1001, "relation": "eq"}, "hits": hits},
        },
    )


@pytest.mark.asyncio
async def test_paginated_documents_reach_ingest_with_distinct_external_ids(respx_mock: Any) -> None:
    hits = [_hit(number) for number in range(1001)]
    respx_mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_page(hits[:1000], "first"))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=[_page(hits[1000:], "second"), _page([], "last")])
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    submitted: list[dict[str, Any]] = []

    def accept(request: httpx.Request) -> httpx.Response:
        events = json.loads(request.content)["events"]
        submitted.extend(events)
        return httpx.Response(200, json={"accepted": len(events), "rejected": 0})

    sink = respx_mock.post(f"{INGEST}/v1/ingest/batch").mock(side_effect=accept)
    events = await _connector().fetch_alerts()
    client = IngestClient(INGEST, service_token="fixture-token")
    try:
        result = await client.push_events(
            tenant_id="11111111-1111-4111-8111-111111111111",
            connector_id="22222222-2222-4222-8222-222222222222",
            connector_type="wazuh",
            events=events,
        )
    finally:
        await client.aclose()

    assert sink.call_count == 2
    assert result == {"accepted": 1001, "rejected": 0}
    assert len({event["external_id"] for event in submitted}) == 1001
    assert {event["rule_id"] for event in submitted} == {"100100"}
    assert [event["external_id"] for event in submitted] == [event["external_id"] for event in events]
