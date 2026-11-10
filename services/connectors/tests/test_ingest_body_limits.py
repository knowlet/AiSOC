"""Large polls respect the Go ingest request limits and acceptance contract."""

from __future__ import annotations

import json
import math
import re
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from app.ingest_client import MAX_BODY_BYTES, IngestClient, IngestClientError, resolve_max_body_bytes

TENANT = "11111111-1111-4111-8111-111111111111"
CONNECTOR = "22222222-2222-4222-8222-222222222222"


@pytest_asyncio.fixture
async def clients() -> AsyncIterator[Callable[..., IngestClient]]:
    created: list[IngestClient] = []

    def build(handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> IngestClient:
        client = IngestClient("http://ingest.test", service_token="fixture-token", **kwargs)
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        created.append(client)
        return client

    yield build
    for client in created:
        await client.aclose()


async def _push(client: IngestClient, events: list[dict[str, Any]]) -> dict[str, Any]:
    return await client.push_events(tenant_id=TENANT, connector_id=CONNECTOR, connector_type="wazuh", events=events)


def test_body_limit_matches_the_go_service_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INGEST_MAX_BODY_BYTES", raising=False)
    assert resolve_max_body_bytes() == MAX_BODY_BYTES
    config = Path(__file__).resolve().parents[3] / "services/ingest/internal/config/config.go"
    match = re.search(r'mustGetEnvInt\(\s*"INGEST_MAX_BODY_BYTES"\s*,\s*([\d\s*]+)\)', config.read_text(encoding="utf-8"))
    assert match is not None, "could not locate the Go ingest body limit"
    assert math.prod(int(factor.strip()) for factor in match.group(1).split("*")) == MAX_BODY_BYTES


def test_body_limit_uses_the_same_environment_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INGEST_MAX_BODY_BYTES", "2048")
    assert resolve_max_body_bytes() == 2048
    for value in ("", "0", "-1", "bad", "1.5"):
        monkeypatch.setenv("INGEST_MAX_BODY_BYTES", value)
        assert resolve_max_body_bytes() == MAX_BODY_BYTES


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, "1024"])
def test_invalid_explicit_byte_limits_are_rejected(limit: Any) -> None:
    with pytest.raises(ValueError, match="max_body_bytes"):
        IngestClient("http://ingest.test", service_token="fixture-token", max_body_bytes=limit)


@pytest.mark.asyncio
async def test_large_unicode_events_split_by_actual_body_bytes(clients: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    events = [{"id": number, "raw_event": {"message": '中文🙂"\\\n' * 200}} for number in range(7)]
    received: list[httpx.Request] = []

    def measure(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200, json={"accepted": len(json.loads(request.content)["events"]), "rejected": 0})

    # Measure the real transport bytes, including JSON escaping, framing and
    # metadata. The subsequent server refuses a request one byte over that.
    await _push(clients(measure), events[:2])
    byte_limit = len(received.pop().content)
    monkeypatch.setenv("INGEST_MAX_BODY_BYTES", str(byte_limit))

    def bounded(request: httpx.Request) -> httpx.Response:
        received.append(request)
        if len(request.content) > byte_limit:
            return httpx.Response(413, text="body too large")
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert request.headers["x-tenant-id"] == TENANT
        return httpx.Response(200, json={"accepted": len(json.loads(request.content)["events"]), "rejected": 0})

    result = await _push(clients(bounded, max_batch_size=3), events)

    bodies = [json.loads(request.content) for request in received]
    assert [len(body["events"]) for body in bodies] == [2, 2, 2, 1]
    assert [event for body in bodies for event in body["events"]] == events
    assert all(len(request.content) <= byte_limit for request in received)
    assert result == {"accepted": 7, "rejected": 0}


@pytest.mark.asyncio
async def test_exact_byte_boundary_is_accepted_and_one_byte_less_is_not(clients: Any) -> None:
    event = {"raw_event": {"message": '單一事件🙂"\\\n' * 10}}
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    await _push(clients(handler), [event])
    length = len(bodies[0])
    assert await _push(clients(handler, max_body_bytes=length), [event]) == {"accepted": 1, "rejected": 0}
    assert bodies[0] == bodies[1]
    with pytest.raises(IngestClientError, match="single event exceeds"):
        await _push(clients(handler, max_body_bytes=length - 1), [event])
    assert len(bodies) == 2, "an oversized event must fail before any HTTP request"


@pytest.mark.asyncio
async def test_oversized_tail_event_fails_before_sending_any_chunk(clients: Any) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    client = clients(handler, max_batch_size=1, max_body_bytes=512)
    with pytest.raises(IngestClientError, match="single event exceeds"):
        await _push(client, [{"id": 1}, {"id": 2}, {"raw_event": {"message": "x" * 1024}}])
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [object(), float("nan"), float("inf")])
async def test_unencodable_tail_event_fails_before_sending_any_chunk(clients: Any, value: Any) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    with pytest.raises(IngestClientError, match="cannot be JSON encoded"):
        await _push(clients(handler, max_batch_size=1), [{"id": 1}, {"invalid": value}])
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {},
        [],
        {"accepted": 1},
        {"accepted": "1", "rejected": 0},
        {"accepted": True, "rejected": 0},
        {"accepted": 1.0, "rejected": 0},
        {"accepted": -1, "rejected": 2},
        {"accepted": 0, "rejected": 0},
        {"accepted": 2, "rejected": 0},
    ],
)
async def test_malformed_chunk_counts_cannot_be_hidden_by_aggregation(clients: Any, response: Any) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=response if calls == 1 else {"accepted": 0, "rejected": 0})

    with pytest.raises(IngestClientError, match="invalid acceptance counts"):
        await _push(clients(handler, max_batch_size=1), [{"id": 1}, {"id": 2}])
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [503, 429, "timeout", "json"])
async def test_later_chunk_failure_stops_and_a_new_poll_can_replay(clients: Any, failure: Any) -> None:
    requests: list[list[dict[str, Any]]] = []
    fail = True

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content)["events"])
        if fail and len(requests) == 2:
            if failure == "timeout":
                raise httpx.ReadTimeout("synthetic timeout", request=request)
            if failure == "json":
                return httpx.Response(200, text="not-json")
            return httpx.Response(failure, text="synthetic refusal")
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    client = clients(handler, max_batch_size=1)
    events = [{"id": 1}, {"id": 2}, {"id": 3}]
    with pytest.raises(IngestClientError):
        await _push(client, events)
    assert requests == [[events[0]], [events[1]]], "failed chunks must not be retried locally or skipped"
    fail = False
    assert await _push(client, events) == {"accepted": 3, "rejected": 0}
    assert requests[2:] == [[event] for event in events]


@pytest.mark.asyncio
async def test_redirect_is_not_an_ingest_acknowledgement(clients: Any) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, json={"accepted": 1, "rejected": 0})

    with pytest.raises(IngestClientError, match="302"):
        await _push(clients(handler), [{"id": 1}])
