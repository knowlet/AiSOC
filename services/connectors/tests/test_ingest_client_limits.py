"""A complete source page fits ingest by encoded bytes as well as row count.

These tests drive the deployed HTTP client through a transport that enforces
the server's body ceiling. No ingest service or Kafka broker runs here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.ingest_client import MAX_BODY_BYTES, IngestClient, IngestClientError, resolve_max_body_bytes

_TENANT = "11111111-1111-4111-8111-111111111111"
_CONNECTOR = "22222222-2222-4222-8222-222222222222"


@pytest.mark.asyncio
async def test_full_log_pages_are_split_under_the_default_body_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three valid large records fit the count cap but exceed 10 MiB."""
    body_limit = 10 * 1024 * 1024
    events = [{"external_id": f"fixture-{i}", "full_log": "x" * (4 * 1024 * 1024)} for i in range(3)]
    sizes: list[int] = []
    accepted_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sizes.append(len(request.content))
        if sizes[-1] > body_limit:
            return httpx.Response(413, text="synthetic ingest body limit")
        payload = json.loads(request.content)
        accepted_ids.extend(event["external_id"] for event in payload["events"])
        return httpx.Response(200, json={"accepted": len(payload["events"]), "rejected": 0})

    monkeypatch.delenv("INGEST_MAX_BODY_BYTES", raising=False)
    client = IngestClient("http://ingest.test", service_token="fixture-token")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client._client = transport
        result = await client.push_events(tenant_id=_TENANT, connector_id=_CONNECTOR, connector_type="wazuh", events=events)

    assert result == {"accepted": 3, "rejected": 0}
    assert accepted_ids == ["fixture-0", "fixture-1", "fixture-2"]
    assert len(sizes) == 2
    assert max(sizes) <= body_limit


@pytest.mark.asyncio
async def test_per_request_accounting_cannot_cancel_out_between_chunks() -> None:
    """Wrong counts must not add up to an apparently fully accepted poll."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert len(json.loads(request.content)["events"]) == 2
        return httpx.Response(200, json={"accepted": 3 if calls == 1 else 1, "rejected": 0})

    client = IngestClient("http://ingest.test", service_token="fixture-token", max_batch_size=2)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client._client = transport
        with pytest.raises(IngestClientError, match="invalid acceptance counts"):
            await client.push_events(
                tenant_id=_TENANT,
                connector_id=_CONNECTOR,
                connector_type="wazuh",
                events=[{"external_id": str(i)} for i in range(4)],
            )

    assert calls == 1


@pytest.mark.asyncio
async def test_body_boundary_includes_envelope_escaping_and_event_separators() -> None:
    events = [{"external_id": str(i), "full_log": '警示: "quoted"\\path\n' * 20} for i in range(3)]
    metadata = {"connector_id": _CONNECTOR, "connector_type": "wazuh", "source_format": "raw_json"}
    # An independently constructed request measures the real locked HTTP
    # client's encoding, including Unicode escapes and JSON punctuation.
    exactly_two = httpx.Request("POST", "http://ingest.test", json={**metadata, "events": events[:2]}).content
    limit = len(exactly_two)
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        if len(request.content) > limit:
            return httpx.Response(413, text="synthetic byte ceiling")
        assert request.headers["content-type"] == "application/json"
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert request.headers["x-tenant-id"] == _TENANT
        count = len(json.loads(request.content)["events"])
        return httpx.Response(200, json={"accepted": count, "rejected": 0})

    client = IngestClient("http://ingest.test", service_token="fixture-token", max_body_bytes=limit)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client._client = transport
        result = await client.push_events(tenant_id=_TENANT, **metadata, events=events)

    assert result == {"accepted": 3, "rejected": 0}
    assert len(bodies) == 2
    assert bodies[0] == exactly_two
    assert [event for body in bodies for event in json.loads(body)["events"]] == events


@pytest.mark.asyncio
async def test_one_oversized_event_raises_without_truncating_or_sending_it() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    client = IngestClient("http://ingest.test", service_token="fixture-token", max_body_bytes=256)
    event = {"full_log": "synthetic-" * 256}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client._client = transport
        with pytest.raises(IngestClientError, match="single event exceeds ingest body limit"):
            await client.push_events(tenant_id=_TENANT, connector_id=_CONNECTOR, connector_type="wazuh", events=[event])

    assert calls == 0
    assert event["full_log"] == "synthetic-" * 256


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {"accepted": 1},
        {"accepted": True, "rejected": 0},
        {"accepted": "1", "rejected": 0},
        {"accepted": 2, "rejected": -1},
        {"accepted": 0, "rejected": 0},
        [],
    ],
    ids=["missing-count", "boolean-count", "string-count", "negative-count", "short-count", "non-object"],
)
async def test_invalid_response_counts_are_never_synthesized_as_success(response: Any) -> None:
    client = IngestClient("http://ingest.test", service_token="fixture-token")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=response))) as transport:
        client._client = transport
        with pytest.raises(IngestClientError, match="invalid acceptance counts"):
            await client.push_events(tenant_id=_TENANT, connector_id=_CONNECTOR, connector_type="wazuh", events=[{"id": "fixture"}])


def test_body_ceiling_matches_the_ingest_service_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INGEST_MAX_BODY_BYTES", raising=False)
    assert resolve_max_body_bytes() == MAX_BODY_BYTES
    go_config = Path(__file__).resolve().parents[3] / "services" / "ingest" / "internal" / "config" / "config.go"
    match = re.search(r'mustGetEnvInt\(\s*"INGEST_MAX_BODY_BYTES"\s*,\s*(\d+)\s*\*\s*(\d+)\s*\*\s*(\d+)\s*\)', go_config.read_text())
    assert match is not None, "the Go ingest body limit must be checked against its deployed configuration"
    assert int(match.group(1)) * int(match.group(2)) * int(match.group(3)) == MAX_BODY_BYTES
    monkeypatch.setenv("INGEST_MAX_BODY_BYTES", "512")
    assert resolve_max_body_bytes() == 512
    assert IngestClient("http://ingest.test", service_token="fixture-token")._max_body_bytes == 512
    for bad in ("", "not-an-integer", "0", "-1"):
        monkeypatch.setenv("INGEST_MAX_BODY_BYTES", bad)
        assert resolve_max_body_bytes() == MAX_BODY_BYTES
