"""
Unit tests for the Wazuh connector.

Pattern mirrors ``test_osquery_connectors.py``:

  1. Schema sanity — wizard form has the fields the docs promise and
     the secret-typed fields are masked.
  2. ``normalize()`` produces the canonical AiSOC alert shape and applies
     the four-tier severity collapse exactly as documented.
  3. HTTP routing through ``respx`` exercises the real ``httpx`` paths
     and proves we hit the documented Wazuh indexer endpoints.

We intentionally do not test against a live Wazuh stack here — that is
covered by integration smoke tests in the docker-compose harness.
"""

from __future__ import annotations

import asyncio
import json

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
    payload = {
        "_scroll_id": "page-1",
        "hits": {
            "hits": [
                _hit(level=12),
                _hit(level=8),
            ]
        },
    }
    route = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=_search_page([], "page-2"))
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
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
    with pytest.raises(RuntimeError, match="503"):
        await connector.fetch_alerts(since_seconds=300)


def _search_page(hits: list[dict], scroll_id: str = "cursor", **extra) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "_scroll_id": scroll_id,
            "timed_out": False,
            "_shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
            "hits": {"hits": hits},
            **extra,
        },
    )


def _numbered_hits(count: int) -> list[dict]:
    # Every timestamp ties, including the page boundary. A scroll cursor,
    # rather than timestamp-only search_after, must keep every document.
    return [{**_hit(), "_id": f"doc-{i}", "_index": f"wazuh-alerts-{i % 2}"} for i in range(count)]


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1000, 1001, 2501])
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_drains_all_pages_and_clears_latest_cursor(respx_mock, count):
    hits = _numbered_hits(count)
    pages = [hits[start : start + 1000] for start in range(0, count, 1000)] + [[]]
    responses = [_search_page(page, f"cursor-{i}") for i, page in enumerate(pages)]
    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=responses[0])
    continuation = None
    if len(responses) > 1:
        continuation = respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=responses[1:])
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))

    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    events = await connector.fetch_alerts(since_seconds=86400)

    assert [event["alert_id"] for event in events] == [hit["_id"] for hit in hits]
    request = initial.calls[0].request
    assert request.url.params["scroll"] == "1m"
    assert request.url.params["allow_partial_search_results"] == "false"
    query = json.loads(request.content)
    assert query["size"] == 1000
    assert query["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"] == "now-86400s"
    if continuation is not None:
        assert [json.loads(call.request.content)["scroll_id"] for call in continuation.calls] == [
            f"cursor-{i}" for i in range(len(pages) - 1)
        ]
        for call in continuation.calls:
            assert json.loads(call.request.content)["scroll"] == "1m"
            assert call.request.headers["Authorization"] == request.headers["Authorization"]
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": [f"cursor-{len(pages) - 1}"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_short_page_does_not_end_scroll(respx_mock):
    hits = _numbered_hits(3)
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(hits[:1], "first"))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=[_search_page(hits[1:], "second"), _search_page([], "last")])
    respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    events = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert [event["alert_id"] for event in events] == ["doc-0", "doc-1", "doc-2"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 500])
@respx.mock(assert_all_called=True)
async def test_search_http_errors_are_sanitized(respx_mock, status):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(status, text=PASSWORD))
    with pytest.raises(RuntimeError, match=str(status)) as raised:
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert PASSWORD not in str(raised.value)


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_search_network_error_is_not_an_empty_success(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(side_effect=httpx.ConnectError("connection refused"))
    with pytest.raises(RuntimeError, match="request failed"):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"error": "unavailable"},
        {"error": "unavailable", "hits": {"hits": []}},
        {"hits": None},
        {"hits": {}},
        {"hits": {"hits": None}},
        {"hits": {"hits": {}}},
        {"hits": {"hits": [None]}},
        {"_shards": {}, "hits": {"hits": []}},
        {"_shards": {"failed": 0}, "hits": {"hits": []}},
    ],
)
@respx.mock(assert_all_called=True)
async def test_malformed_search_response_cannot_be_empty_success(respx_mock, payload):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, content=json.dumps(payload)))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_non_json_response_is_not_an_empty_success(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, text="<html>proxy error</html>"))
    with pytest.raises(RuntimeError, match="JSON"):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize(
    "extra",
    [
        {"timed_out": True},
        {"_shards": {"total": 2, "successful": 1, "skipped": 0, "failed": 1}},
        {"_shards": {"total": 2, "successful": 1, "skipped": 0, "failed": 0}},
    ],
)
@respx.mock(assert_all_called=True)
async def test_partial_search_cannot_return_hits_and_clears_context(respx_mock, extra, later_page):
    failure = _search_page(_numbered_hits(1), "partial", **extra)
    initial = _search_page(_numbered_hits(1), "first") if later_page else failure
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=initial)
    if later_page:
        respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=failure)
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200, json={"succeeded": True}))
    with pytest.raises(RuntimeError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": ["partial"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_nonempty_response_without_cursor_cannot_truncate_poll(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"hits": _numbered_hits(1000)}})
    )
    with pytest.raises(RuntimeError, match="scroll"):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_status", [200, 404, 503])
@respx.mock(assert_all_called=True)
async def test_later_page_error_never_returns_partial_batch(respx_mock, cleanup_status):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1000), "first"))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(502))
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(cleanup_status))
    with pytest.raises(RuntimeError, match="502"):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert json.loads(clear.calls[0].request.content) == {"scroll_id": ["first"]}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_cleanup_network_error_preserves_successful_empty_result(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page([], "empty"))
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

    initial = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=_search_page(_numbered_hits(1), "first"))
    respx_mock.post(f"{INDEXER}/_search/scroll").mock(side_effect=cancel_request)
    clear = respx_mock.delete(f"{INDEXER}/_search/scroll").mock(return_value=httpx.Response(200))
    with pytest.raises(asyncio.CancelledError):
        await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_alerts()
    assert initial.called
    assert cancelled.is_set()
    assert clear.called
