"""Complete polls must fit the count and body limits of the ingest API."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import httpx
import pytest
from app.ingest_client import IngestClient, IngestClientError

TENANT = "11111111-1111-4111-8111-111111111111"
CONNECTOR = "22222222-2222-4222-8222-222222222222"
TOKEN = "fixture-service-token"
BASE_URL = "http://ingest-worker:8080"


@asynccontextmanager
async def _client(handler, **kwargs):
    client = IngestClient(BASE_URL, service_token=TOKEN, **kwargs)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        yield client
    finally:
        await client.aclose()


async def _push(client, events):
    return await client.push_events(tenant_id=TENANT, connector_id=CONNECTOR, connector_type="wazuh", events=events)


def _body_size(events):
    payload = {
        "connector_id": CONNECTOR,
        "connector_type": "wazuh",
        "source_format": "raw_json",
        "events": events,
    }
    return len(httpx.Request("POST", BASE_URL, json=payload).content)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1, 1000, 1001, 2501])
async def test_complete_poll_respects_ingest_default_count_limit(count):
    received = []

    def handler(request):
        payload = json.loads(request.content)
        events = payload["events"]
        # The production Go handler refuses an entire oversized request.
        if len(events) > 1000:
            return httpx.Response(413, json={"error": "batch size exceeds maximum of 1000"})
        assert len(request.content) <= 10 * 1024 * 1024
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["x-tenant-id"] == TENANT
        assert payload["connector_id"] == CONNECTOR
        assert payload["connector_type"] == "wazuh"
        assert payload["source_format"] == "raw_json"
        received.append(events)
        return httpx.Response(200, json={"accepted": len(events), "rejected": 0, "request_id": f"request-{len(received)}"})

    events = [{"alert_id": f"alert-{i}"} for i in range(count)]
    async with _client(handler) as client:
        result = await _push(client, events)
    assert [event for batch in received for event in batch] == events
    assert len(received) == (count + 999) // 1000
    assert result["accepted"] == count
    assert result["rejected"] == 0
    if 0 < count <= 1000:
        assert result == {"accepted": count, "rejected": 0, "request_id": "request-1"}
    elif count > 1000:
        assert result["request_ids"] == [f"request-{i + 1}" for i in range(len(received))]


@pytest.mark.asyncio
async def test_body_limit_includes_envelope_and_escaped_event_bytes():
    event = {"message": '臺灣\n"' * 20}
    limit = _body_size([event])
    received = []

    def handler(request):
        assert len(request.content) == limit
        events = json.loads(request.content)["events"]
        received.extend(events)
        return httpx.Response(200, json={"accepted": len(events), "rejected": 0})

    async with _client(handler, max_body_bytes=limit) as client:
        result = await _push(client, [event] * 3)
    assert received == [event] * 3
    assert result["accepted"] == 3


@pytest.mark.asyncio
async def test_single_oversized_event_fails_without_sending_it():
    event = {"message": "x" * 100}
    called = False

    def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    async with _client(handler, max_body_bytes=_body_size([event]) - 1) as client:
        with pytest.raises(IngestClientError, match="single event"):
            await _push(client, [event])
    assert not called


@pytest.mark.asyncio
async def test_excessive_nesting_is_an_ingest_error():
    event = {}
    nested = event
    for _ in range(1100):
        nested["child"] = {}
        nested = nested["child"]

    def handler(request):
        pytest.fail("an unencodable event must not reach ingest")

    async with _client(handler) as client:
        with pytest.raises(IngestClientError, match="JSON encoded"):
            await _push(client, [event])


@pytest.mark.asyncio
async def test_counts_and_errors_are_aggregated_without_hiding_rejections():
    replies = [
        {"accepted": 1, "rejected": 1, "errors": ["event rejected"], "request_id": "first"},
        {"accepted": 1, "rejected": 0, "request_id": "last"},
    ]

    def handler(request):
        return httpx.Response(200, json=replies.pop(0))

    async with _client(handler, max_batch_size=2) as client:
        result = await _push(client, [{"id": i} for i in range(3)])
    assert result == {"accepted": 2, "rejected": 1, "errors": ["event rejected"], "request_ids": ["first", "last"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["http", "network"])
async def test_later_batch_failure_raises_without_a_partial_success(failure):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 2:
            if failure == "network":
                raise httpx.ReadTimeout("fixture timeout", request=request)
            return httpx.Response(503, json={"error": "unavailable"})
        return httpx.Response(200, json={"accepted": len(json.loads(request.content)["events"]), "rejected": 0})

    async with _client(handler) as client:
        with pytest.raises(IngestClientError):
            await _push(client, [{"id": i} for i in range(2501)])
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"accepted": 2},
        {"accepted": True, "rejected": 1},
        {"accepted": -1, "rejected": 3},
        {"accepted": 1, "rejected": 0},
        {"accepted": 3, "rejected": 0},
    ],
)
async def test_invalid_chunk_counts_cannot_cancel_out_in_the_total(response):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=json.dumps(response))

    async with _client(handler, max_batch_size=2) as client:
        with pytest.raises(IngestClientError, match="counts"):
            await _push(client, [{"id": i} for i in range(3)])
    assert calls == 1


@pytest.mark.asyncio
async def test_from_env_honors_ingest_count_and_body_limits(monkeypatch):
    monkeypatch.setenv("MAX_BATCH_SIZE", "2")
    monkeypatch.setenv("INGEST_MAX_BODY_BYTES", "1000")
    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", TOKEN)
    sizes = []

    def handler(request):
        assert len(request.content) <= 1000
        count = len(json.loads(request.content)["events"])
        sizes.append(count)
        return httpx.Response(200, json={"accepted": count, "rejected": 0})

    client = IngestClient.from_env()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        result = await _push(client, [{"id": i} for i in range(5)])
    finally:
        await client.aclose()
    assert sizes == [2, 2, 1]
    assert result["accepted"] == 5


@pytest.mark.parametrize("name", ["max_batch_size", "max_body_bytes"])
@pytest.mark.parametrize("value", [0, -1, True])
def test_invalid_limits_are_refused(name, value):
    with pytest.raises(ValueError):
        IngestClient(BASE_URL, **{name: value})
