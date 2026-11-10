"""
Unit tests for the Wazuh connector.

Pattern mirrors ``test_osquery_connectors.py``:

  1. Schema sanity — wizard form has the fields the docs promise and
     the secret-typed fields are masked.
  2. ``normalize()`` produces the canonical AiSOC alert shape and applies
     the four-tier severity collapse exactly as documented.
  3. HTTP routing through ``respx`` exercises the real ``httpx`` paths
     and proves we hit the documented Wazuh indexer endpoints.

These are synthetic protocol tests. They do not establish live Wazuh
compatibility or production acceptance.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import httpx
import pytest
import respx
from app.connectors.base import Capability
from app.connectors.wazuh import WazuhConnector, _severity_from_level

INDEXER = "https://wazuh.test.local:9200"
USERNAME = "admin"
PASSWORD = "wazuh-fake-password"
INDEX_PATTERN = "wazuh-alerts-*"


# ---------------------------------------------------------------------------
# Schema + capability surface
# ---------------------------------------------------------------------------


def test_wazuh_schema_has_required_fields():
    schema = WazuhConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"indexer_url", "username", "password", "index_pattern", "min_rule_level", "verify_tls"} <= names
    assert schema.category == "siem"
    pwd = next(f for f in schema.fields if f.name == "password")
    assert pwd.type == "secret"


def test_wazuh_capabilities_cover_pull_query_search_pivot():
    caps = set(WazuhConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.QUERY_LOGS in caps
    assert Capability.SEARCH_SIEM in caps
    assert Capability.PIVOT_HOST in caps


# ---------------------------------------------------------------------------
# Severity collapse: 0-15 → info | low | medium | high
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "level,expected",
    [
        (0, "info"),
        (3, "info"),
        (4, "low"),
        (7, "low"),
        (8, "medium"),
        (11, "medium"),
        (12, "high"),
        (14, "high"),
        # Wazuh level 15 is the maximum band and represents the most
        # severe attack signatures — it now maps to AiSOC's ``critical``
        # (P1, 15-minute MTTD SLA) so it lands in the top lane.
        (15, "critical"),
        # Out-of-band / weird inputs — must not raise.
        (None, "info"),
        ("not-a-number", "info"),
        ("9", "medium"),
        (-3, "info"),
        # Values above 15 are clamped to the top tier (``critical``).
        (99, "critical"),
    ],
)
def test_severity_band_collapse(level, expected):
    assert _severity_from_level(level) == expected


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


def _hit(level: int = 12, **rule_extra) -> dict:
    """Minimal indexer hit envelope mimicking a real Wazuh alert."""
    return {
        "_id": "doc-abc",
        "_index": "wazuh-alerts-4.x-2026.05.12",
        "_source": {
            "@timestamp": "2026-05-12T08:00:00.000Z",
            "agent": {"id": "001", "name": "web-01.corp", "ip": "10.0.0.5"},
            "rule": {
                "id": "100100",
                "level": level,
                "description": "Possible rootkit installation",
                "groups": ["rootcheck", "intrusion_attempt"],
                "mitre": {"id": ["T1547"], "tactic": ["Persistence"]},
                **rule_extra,
            },
            "data": {"command": "modprobe evil"},
            "decoder": {"name": "rootcheck"},
            "full_log": "rootcheck: detected suspicious kernel module",
        },
    }


def test_normalize_high_severity_rule_maps_to_high():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    normalized = connector.normalize(_hit(level=14))
    assert normalized["source"] == "wazuh"
    assert normalized["category"] == "siem"
    assert normalized["event_type"] == "wazuh_alert"
    assert normalized["severity"] == "high"
    assert normalized["title"] == "Possible rootkit installation"
    assert normalized["hostname"] == "web-01.corp"
    assert normalized["host"] == "web-01.corp"
    assert normalized["agent_id"] == "001"
    assert normalized["agent_ip"] == "10.0.0.5"
    assert normalized["rule_id"] == "100100"
    assert normalized["rule_level"] == 14
    assert normalized["mitre_techniques"] == ["T1547"]
    assert normalized["mitre_tactics"] == ["Persistence"]
    assert normalized["alert_id"] == "doc-abc"
    # raw_event must be the original _source so rule authors can pivot
    # into vendor-specific fields the canonical shape doesn't expose.
    assert normalized["raw_event"]["decoder"]["name"] == "rootcheck"


def test_normalize_low_signal_rule_maps_to_low():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    normalized = connector.normalize(_hit(level=5, description="sshd: failed password"))
    assert normalized["severity"] == "low"
    assert normalized["title"] == "sshd: failed password"


def test_normalize_synthesises_alert_id_when_doc_id_missing():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    raw = _hit(level=8)
    raw.pop("_id")
    normalized = connector.normalize(raw)
    # Composite fallback must include rule + agent + timestamp so retries
    # de-duplicate without the indexer doc id.
    assert "100100" in normalized["alert_id"]
    assert "001" in normalized["alert_id"]


def test_normalize_handles_missing_mitre_block():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    raw = _hit(level=8)
    del raw["_source"]["rule"]["mitre"]
    normalized = connector.normalize(raw)
    assert normalized["mitre_techniques"] == []
    assert normalized["mitre_tactics"] == []


# ---------------------------------------------------------------------------
# test_connection — auth, network, success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_success(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(return_value=httpx.Response(200, json={"status": "green"}))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result == {"success": True, "connector": "wazuh"}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_auth_failure(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(return_value=httpx.Response(401))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "auth" in result["error"].lower()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_network_error(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(side_effect=httpx.ConnectError("dns"))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "network" in result["error"].lower()


# ---------------------------------------------------------------------------
# fetch_alerts — wires through to OpenSearch search + applies the threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_returns_normalized_events(respx_mock):
    hits = [_hit(level=12), {**_hit(level=8), "_id": "doc-other"}]
    route = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(hits, total=2))
    _finish_scroll(respx_mock, total=2)
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 2
    # Must have routed through the search API
    assert route.called
    # Severity collapse must run on the way out
    assert {e["severity"] for e in events} == {"high", "medium"}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_raises_on_5xx(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(503))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    with pytest.raises(RuntimeError, match="503") as raised:
        await connector.fetch_alerts(since_seconds=300)
    assert type(raised.value).__name__ == "WazuhSearchError"


def _search_payload(hits: list[dict], scroll_id: str = "cursor", *, total: int | None = None, **extra) -> dict:
    return {
        "_scroll_id": scroll_id,
        "timed_out": False,
        "_shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": len(hits) if total is None else total, "relation": "eq"}, "hits": hits},
        **extra,
    }


def _search_page(hits: list[dict], scroll_id: str = "cursor", *, total: int | None = None, **extra) -> httpx.Response:
    return httpx.Response(200, json=_search_payload(hits, scroll_id, total=total, **extra))


def _finish_scroll(router, *, total: int):
    router.post(f"{INDEXER}/_search/scroll").mock(return_value=_search_page([], total=total))
    return router.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))


def _numbered_hits(count: int) -> list[dict]:
    # Every timestamp ties, including each page boundary. The cursor must
    # keep every document without assuming a unique timestamp sort key.
    return [{**_hit(), "_id": f"doc-{i}", "_index": f"wazuh-alerts-{i % 2}"} for i in range(count)]


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _requested_window(route, call: int = 0) -> dict:
    query = json.loads(route.calls[call].request.content)
    return query["query"]["bool"]["must"][0]["range"]["@timestamp"]


def _checkpoint(alerts: datetime, vulnerabilities: datetime | None = None) -> dict:
    return {
        "wazuh_poll": {
            "version": 1,
            "alerts_through": alerts.isoformat(),
            "vulnerabilities_through": (vulnerabilities or alerts).isoformat(),
        }
    }


def test_search_result_limit_is_visible_in_schema():
    field = next(field for field in WazuhConnector.schema().fields if field.name == "max_search_results")
    assert field.default == 100_000


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1000, 1001, 2501, 10001])
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_drains_all_pages_and_clears_latest_cursor(respx_mock, count):
    hits = _numbered_hits(count)
    pages = [hits[start : start + 1000] for start in range(0, count, 1000)] + [[]]
    responses = [_search_page(page, f"cursor-{i}", total=count) for i, page in enumerate(pages)]
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=responses[0])
    continuation = None
    if len(responses) > 1:
        continuation = respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=responses[1:])
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))

    before = datetime.now(UTC)
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    events = await connector.fetch_alerts(since_seconds=86400)
    after = datetime.now(UTC)

    assert [event["alert_id"] for event in events] == [hit["_id"] for hit in hits]
    request = initial.calls[0].request
    assert request.url.params["scroll"]
    assert request.url.params["allow_partial_search_results"] == "false"
    query = json.loads(request.content)
    assert query["size"] == 1000
    assert query["track_total_hits"] is True
    window = _requested_window(initial)
    assert before <= _datetime(window["lte"]) <= after
    # The bootstrap floor preserves the requested day; the polling
    # overlap also covers documents indexed shortly after that boundary.
    assert _datetime(window["lte"]) - _datetime(window["gte"]) == timedelta(days=1, seconds=60)
    if continuation is not None:
        assert [json.loads(call.request.content)["scroll_id"] for call in continuation.calls] == [
            f"cursor-{i}" for i in range(len(pages) - 1)
        ]
        for call in continuation.calls:
            assert json.loads(call.request.content)["scroll"] == request.url.params["scroll"]
            assert call.request.headers["Authorization"] == request.headers["Authorization"]
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": [f"cursor-{len(pages) - 1}"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_short_page_and_reused_cursor_do_not_end_scroll(respx_mock):
    hits = _numbered_hits(3)
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(hits[:1], total=3))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=[_search_page(hits[1:], total=3), _search_page([], total=3)])
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    events = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert [event["alert_id"] for event in events] == ["doc-0", "doc-1", "doc-2"]


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_same_document_id_in_different_indexes_is_not_a_duplicate_page(respx_mock):
    first = _hit()
    second = {**_hit(), "_index": "wazuh-alerts-another-day"}
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page([first], total=2))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=[_search_page([second], total=2), _search_page([], total=2)])
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    events = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert len(events) == 2
    assert {event["raw"]["_index"] for event in events} == {first["_index"], second["_index"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 500])
@respx.mock(assert_all_called=True)
async def test_search_http_errors_are_sanitized(respx_mock, status):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(status, text=PASSWORD))
    with pytest.raises(RuntimeError, match=str(status)) as raised:
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert PASSWORD not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout])
@respx.mock(assert_all_called=True)
async def test_search_transport_error_is_not_an_empty_success(respx_mock, error_type):
    route = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(side_effect=error_type("unavailable"))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert route.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [None, [], {}, {"error": "unavailable"}, {"hits": None}, {"hits": {}}, {"hits": {"hits": None}}],
)
@respx.mock(assert_all_called=True)
async def test_malformed_search_response_cannot_be_empty_success(respx_mock, payload):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, content=json.dumps(payload)))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,replacement",
    [
        ("timed_out", None),
        ("timed_out", "false"),
        ("_shards", None),
        ("_shards", {}),
        ("_shards", {"total": 2, "successful": 2}),
        ("_shards", {"total": True, "successful": True, "failed": False}),
        ("_shards", {"total": 2, "successful": "2", "failed": 0}),
        ("hits", {"total": {"value": 0, "relation": "eq"}, "hits": [None]}),
        ("hits", {"hits": []}),
        ("hits", {"total": {"value": 10000, "relation": "gte"}, "hits": []}),
        ("hits", {"total": {"value": -1, "relation": "eq"}, "hits": []}),
        ("hits", {"total": {"value": True, "relation": "eq"}, "hits": []}),
    ],
)
@respx.mock(assert_all_called=True)
async def test_incomplete_success_metadata_is_rejected(respx_mock, field, replacement):
    payload = _search_payload([], total=0)
    payload.pop("_scroll_id")
    if replacement is None:
        payload.pop(field)
    else:
        payload[field] = replacement
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_non_json_response_is_not_an_empty_success(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, text="<html>proxy error</html>"))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize(
    "extra",
    [
        {"timed_out": True},
        {"terminated_early": True},
        {"error": {"type": "search_phase_execution_exception"}},
        {"_shards": {"total": 2, "successful": 1, "skipped": 0, "failed": 1}},
        {"_shards": {"total": 2, "successful": 1, "skipped": 1, "failed": 0}},
    ],
)
@respx.mock(assert_all_called=True)
async def test_partial_search_cannot_return_hits_and_clears_context(respx_mock, extra, later_page):
    hits = _numbered_hits(2)
    failure = _search_page(hits[1:], "partial", total=2, **extra)
    initial = _search_page(hits[:1], "first", total=2) if later_page else failure
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=initial)
    if later_page:
        respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=failure)
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": ["partial"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_skipped_shards_are_already_successful_and_do_not_cause_false_failure(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(
        return_value=_search_page([], total=0, _shards={"total": 2, "successful": 2, "skipped": 1, "failed": 0})
    )
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    assert await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("scroll_id", [None, "", 7])
@respx.mock(assert_all_called=True)
async def test_nonempty_response_without_cursor_cannot_truncate_poll(respx_mock, scroll_id):
    payload = _search_payload(_numbered_hits(1), total=1)
    if scroll_id is None:
        payload.pop("_scroll_id")
    else:
        payload["_scroll_id"] = scroll_id
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_status", [200, 404, 503])
@respx.mock(assert_all_called=True)
async def test_later_page_error_never_returns_partial_batch(respx_mock, cleanup_status):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1000), "first", total=1001))
    continuation = respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(502))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(cleanup_status))
    with pytest.raises(RuntimeError, match="502"):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert continuation.call_count == 1
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": ["first"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_ambiguous_continuation_timeout_restarts_from_initial_query(respx_mock):
    hits = _numbered_hits(1001)
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(
        side_effect=[_search_page(hits[:1000], "failed-first", total=1001), _search_page(hits[:1000], "retry-first", total=1001)]
    )
    continuation = respx_mock.post(f"{INDEXER}/_search/scroll").mock(
        side_effect=[
            httpx.ReadTimeout("response lost after cursor advanced"),
            _search_page(hits[1000:], "retry-last", total=1001),
            _search_page([], "done", total=1001),
        ]
    )
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    with pytest.raises(RuntimeError):
        await connector.fetch_alerts()
    assert initial.call_count == continuation.call_count == 1

    events = await connector.fetch_alerts()
    assert len(events) == 1001
    assert initial.call_count == 2
    assert [json.loads(call.request.content)["scroll_id"] for call in continuation.calls] == ["failed-first", "retry-first", "retry-last"]
    assert [json.loads(call.request.content)["scroll_id"] for call in clear.calls] == [["failed-first"], ["done"]]


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_duplicate_page_cannot_report_complete_fetch(respx_mock):
    page = _numbered_hits(1)
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(page, total=2))
    continuation = respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=_search_page(page, "duplicate", total=2))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert continuation.call_count == 1
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": ["duplicate"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_exhausted_scroll_with_missing_hits_is_a_failure(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), total=2))
    _finish_scroll(respx_mock, total=2)
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_valid_empty_search_without_cursor_accepts_legacy_integer_total(respx_mock):
    payload = _search_payload([], total=0)
    payload.pop("_scroll_id")
    payload["hits"]["total"] = 0
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    assert await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["_index", "_id", "_source"])
@respx.mock(assert_all_called=True)
async def test_incomplete_document_envelope_cannot_be_silently_skipped(respx_mock, field):
    hit = _hit()
    hit.pop(field)
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page([hit], total=1))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert clear.called


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fetch_at_exact_result_limit_completes(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(2), total=2))
    _finish_scroll(respx_mock, total=2)
    events = await WazuhConnector(INDEXER, USERNAME, PASSWORD, max_search_results=2).fetch_alerts()
    assert len(events) == 2


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_result_limit_raises_instead_of_truncating(respx_mock):
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), total=2))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=_search_page(_numbered_hits(2)[1:], total=2))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD, max_search_results=1).fetch_alerts()
    assert initial.called and clear.called


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_page_limit_raises_instead_of_returning_partial_batch(respx_mock, monkeypatch):
    monkeypatch.setattr(WazuhConnector, "_MAX_SEARCH_PAGES", 1)
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), total=2))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=_search_page(_numbered_hits(2)[1:], total=2))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert initial.called and clear.called


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_whole_search_deadline_clears_context(respx_mock, monkeypatch):
    monkeypatch.setattr(WazuhConnector, "_SEARCH_TIMEOUT_SECONDS", 0.05)
    requested = asyncio.Event()

    async def blocked_page(request):
        requested.set()
        await asyncio.Future()

    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), total=2))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=blocked_page)
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await asyncio.wait_for(WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts(), timeout=2)
    assert requested.is_set()
    assert clear.called


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_cleanup_network_error_preserves_successful_empty_result(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page([], "empty", total=0))
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(side_effect=httpx.ConnectError("connection refused"))
    assert await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts() == []


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_cancelled_poll_clears_context_and_propagates_cancellation(respx_mock):
    cancelled = asyncio.Event()

    async def cancel_request(request):
        # respx does not record a call when its handler raises BaseException.
        cancelled.set()
        raise asyncio.CancelledError

    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), "first", total=2))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=cancel_request)
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200))
    with pytest.raises(asyncio.CancelledError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert initial.called
    assert cancelled.is_set()
    assert clear.called


def test_prepare_poll_persists_bootstrap_floor_before_first_fetch():
    now = datetime(2026, 11, 4, 9, tzinfo=UTC)
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    assert connector.checkpoints()
    floor = connector.prepare_poll(since_seconds=300, last_sync=None, started_at=now)
    state = floor["wazuh_poll"]
    assert state["version"] == 1
    assert _datetime(state["alerts_through"]) == now - timedelta(seconds=300)
    assert _datetime(state["vulnerabilities_through"]) == now - timedelta(seconds=3600)


@pytest.mark.asyncio
@pytest.mark.parametrize("fetch_method", ["fetch_alerts", "fetch_vulnerability_findings"])
@respx.mock(assert_all_called=True)
async def test_reused_standalone_connector_refreshes_its_time_window(respx_mock, fetch_method):
    first = datetime(2026, 11, 4, 9, tzinfo=UTC)
    second = first + timedelta(minutes=10)
    payload = _search_payload([], total=0)
    payload.pop("_scroll_id")
    route = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)

    with patch("app.connectors.wazuh.datetime") as clock:
        clock.now.side_effect = [first, second]
        assert await getattr(connector, fetch_method)() == []
        assert await getattr(connector, fetch_method)() == []

    assert route.call_count == 2
    assert _datetime(_requested_window(route, 0)["lte"]) == first
    assert _datetime(_requested_window(route, 1)["lte"]) == second
    # Refreshing the end must not lose the original lower boundary on a
    # caller-driven retry without a durable scheduler checkpoint.
    assert _datetime(_requested_window(route, 1)["gte"]) <= _datetime(_requested_window(route, 0)["gte"])


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_restart_uses_durable_stream_checkpoints_after_long_outage(respx_mock):
    alerts_through = datetime(2026, 11, 3, 9, tzinfo=UTC)
    vulnerabilities_through = alerts_through - timedelta(hours=2)
    now = alerts_through + timedelta(days=1)
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    connector.set_checkpoint(_checkpoint(alerts_through, vulnerabilities_through))
    connector.prepare_poll(since_seconds=300, last_sync=alerts_through, started_at=now)
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page([], total=0))
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))

    assert await connector.fetch_alerts() == []
    assert await connector.fetch_vulnerability_findings() == []

    alert_window = _requested_window(initial, 0)
    vuln_window = _requested_window(initial, 1)
    assert _datetime(alert_window["gte"]) == alerts_through - timedelta(seconds=60)
    assert _datetime(vuln_window["gte"]) == vulnerabilities_through - timedelta(seconds=60)
    assert _datetime(alert_window["lte"]) == _datetime(vuln_window["lte"]) == now
    state = connector.get_checkpoint()["wazuh_poll"]
    assert _datetime(state["alerts_through"]) == _datetime(state["vulnerabilities_through"]) == now


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_inventory_failure_does_not_expose_an_advanced_checkpoint(respx_mock):
    previous = datetime(2026, 11, 3, 9, tzinfo=UTC)
    checkpoint = _checkpoint(previous)
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    connector.set_checkpoint(checkpoint)
    connector.prepare_poll(since_seconds=300, last_sync=previous, started_at=previous + timedelta(hours=2))
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(side_effect=[_search_page([], total=0), httpx.Response(503)])
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    assert await connector.fetch_alerts() == []
    assert connector.get_checkpoint() in (None, checkpoint)
    with pytest.raises(RuntimeError):
        await connector.fetch_vulnerability_findings()
    assert connector.get_checkpoint() in (None, checkpoint)
