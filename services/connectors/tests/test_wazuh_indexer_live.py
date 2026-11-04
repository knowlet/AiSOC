"""Opt-in Wazuh queries against a disposable, real OpenSearch node.

Set WAZUH_TEST_OPENSEARCH_URL to an unauthenticated loopback test node. Every
test creates unique synthetic indices and deletes only those exact names.
This verifies the real search/scroll protocol and query mappings, not the
Wazuh Security plugin, production alert templates or a multi-node cluster.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from app.connectors.wazuh import WazuhConnector

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("WAZUH_TEST_OPENSEARCH_URL", "").strip(),
        reason="WAZUH_TEST_OPENSEARCH_URL is not set; this suite requires a disposable real indexer",
    ),
]


def _local_url() -> str:
    url = os.environ["WAZUH_TEST_OPENSEARCH_URL"].strip().rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("the destructive test fixture requires an unauthenticated literal-loopback URL with no path")
    return url


_MAPPING = {
    "settings": {"number_of_shards": 2, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"ingested": {"type": "date"}}},
            "rule": {
                "properties": {
                    "id": {"type": "keyword"},
                    "level": {"type": "integer"},
                    "groups": {"type": "keyword"},
                    "description": {"type": "text"},
                }
            },
            "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
            "full_log": {"type": "text"},
        }
    },
}


@pytest_asyncio.fixture
async def indexer(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[dict[str, Any]]:
    url = _local_url()
    host = urlsplit(url).hostname
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", str(host))
    # The product HTTP client stays intact. Its exact loopback destination
    # must not be sent through an unrelated developer proxy.
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", str(host))
    monkeypatch.setenv("no_proxy", str(host))
    namespace = f"aisoc-wazuh-test-{uuid.uuid4().hex}"
    names = [f"{namespace}-a", f"{namespace}-b"]
    created: list[str] = []
    async with httpx.AsyncClient(base_url=url, timeout=30, trust_env=False) as client:
        try:
            for name in names:
                response = await client.put(f"/{name}", json=_MAPPING)
                response.raise_for_status()
                assert response.json().get("acknowledged") is True
                created.append(name)
            yield {"url": url, "client": client, "indices": names}
        finally:
            for name in created:
                response = await client.delete(f"/{name}")
                assert response.status_code in {200, 404}, f"failed to remove synthetic test index {name}"


def _source(
    number: int,
    *,
    timestamp: datetime | None = None,
    rule_id: str = "110100",
    level: int = 12,
) -> dict[str, Any]:
    return {
        "@timestamp": (timestamp or datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        "agent": {"id": "001", "name": "synthetic-indexer-host"},
        "rule": {"id": rule_id, "level": level, "description": "Synthetic indexer regression event"},
        "full_log": f"Synthetic indexer log {number}",
    }


async def _put(indexer: dict[str, Any], documents: list[tuple[str, str, dict[str, Any]]]) -> None:
    lines: list[str] = []
    for index, document_id, source in documents:
        assert index in indexer["indices"], "only the fixture's unique indices may be written"
        lines.extend([json.dumps({"index": {"_index": index, "_id": document_id}}), json.dumps(source)])
    response = await indexer["client"].post(
        "/_bulk",
        params={"refresh": "wait_for"},
        content="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    response.raise_for_status()
    body = response.json()
    assert body["errors"] is False, body
    assert len(body["items"]) == len(documents)


def _connector(indexer: dict[str, Any], **kwargs: Any) -> WazuhConnector:
    return WazuhConnector(
        indexer_url=indexer["url"],
        username="fixture-user",
        password="fixture-password",
        index_pattern=kwargs.pop("index_pattern", indexer["indices"][0]),
        vuln_mode=kwargs.pop("vuln_mode", "alerts"),
        **kwargs,
    )


async def test_real_scroll_reads_2501_equal_timestamp_documents(indexer: dict[str, Any]) -> None:
    timestamp = datetime.now(UTC) - timedelta(seconds=1)
    index = indexer["indices"][0]
    await _put(indexer, [(index, f"document-{number}", _source(number, timestamp=timestamp)) for number in range(2501)])
    connector = _connector(indexer)

    events = await connector.fetch_alerts(since_seconds=300)

    assert len(events) == 2501
    assert len({event["alert_id"] for event in events}) == 2501
    assert len({event["external_id"] for event in events}) == 2501
    assert {event["description"] for event in events} == {f"Synthetic indexer log {number}" for number in range(2501)}
    assert {event["rule_id"] for event in events} == {"110100"}
    checkpoint = connector.get_checkpoint()
    assert checkpoint is not None
    restarted = _connector(indexer)
    restarted.set_checkpoint(checkpoint)
    assert await restarted.fetch_alerts(since_seconds=300) == []


async def test_real_indexer_returns_a_ten_minute_late_document_after_a_newer_one(indexer: dict[str, Any]) -> None:
    index = indexer["indices"][0]
    await _put(indexer, [(index, "newer", _source(1))])
    connector = _connector(indexer)
    first = await connector.fetch_alerts(since_seconds=300)
    assert len(first) == 1
    checkpoint = connector.get_checkpoint()
    # This document becomes visible only after the first poll, while its
    # event timestamp sorts before the already accepted document.
    await _put(indexer, [(index, "late", _source(2, timestamp=datetime.now(UTC) - timedelta(minutes=10)))])
    restarted = _connector(indexer)
    restarted.set_checkpoint(checkpoint)

    late = await restarted.fetch_alerts(since_seconds=300)

    assert len(late) == 1
    assert late[0]["description"] == "Synthetic indexer log 2"
    assert late[0]["external_id"] != first[0]["external_id"]


async def test_same_document_id_in_different_indices_keeps_both_source_identities(indexer: dict[str, Any]) -> None:
    first_index, second_index = indexer["indices"]
    await _put(indexer, [(first_index, "same-id", _source(1)), (second_index, "same-id", _source(2))])

    events = await _connector(indexer, index_pattern=",".join(indexer["indices"])).fetch_alerts()

    assert len(events) == 2
    assert len({event["external_id"] for event in events}) == 2
    assert len({event["alert_id"] for event in events}) == 2
    assert {event["rule_id"] for event in events} == {"110100"}


async def test_real_query_keeps_low_level_custom_rules_and_excludes_only_named_rules(indexer: dict[str, Any]) -> None:
    index = indexer["indices"][0]
    fixtures = [
        ("below-threshold", _source(1, rule_id="110001", level=2)),
        ("custom-three", _source(2, rule_id="110114", level=3)),
        ("custom-six", _source(3, rule_id="110125", level=6)),
        ("custom-seven", _source(4, rule_id="110190", level=7)),
        ("excluded-three", _source(5, rule_id="19008", level=3)),
        ("excluded-seven", _source(6, rule_id="19009", level=7)),
    ]
    await _put(indexer, [(index, document_id, source) for document_id, source in fixtures])
    defaults = await _connector(indexer).fetch_alerts()
    assert {event["rule_id"] for event in defaults} == {"110190", "19009"}

    selected = await _connector(indexer, min_rule_level=3, excluded_rule_ids="19008,19009").fetch_alerts()

    assert {event["rule_id"] for event in selected} == {"110114", "110125", "110190"}


async def test_real_query_can_use_an_operator_provided_ingestion_timestamp(indexer: dict[str, Any]) -> None:
    index = indexer["indices"][0]
    source = _source(1, timestamp=datetime.now(UTC) - timedelta(days=1))
    source["event"] = {"ingested": datetime.now(UTC).isoformat()}
    await _put(indexer, [(index, "old-event-new-ingestion", source)])
    assert await _connector(indexer).fetch_alerts() == []

    events = await _connector(indexer, timestamp_field="event.ingested").fetch_alerts()

    assert len(events) == 1
    assert events[0]["timestamp"] == source["@timestamp"], "querying by arrival time must not replace the original event time"


async def test_real_scroll_reads_every_vulnerability_finding(indexer: dict[str, Any]) -> None:
    index = indexer["indices"][0]
    documents = []
    timestamp = datetime.now(UTC) - timedelta(seconds=1)
    for number in range(1001):
        source = _source(number, timestamp=timestamp)
        source["rule"]["groups"] = ["vulnerability-detector"]
        source["data"] = {"vulnerability": {"cve": f"CVE-2026-{10000 + number}", "severity": "High"}}
        documents.append((index, f"finding-{number}", source))
    await _put(indexer, documents)

    connector = _connector(indexer, vuln_mode="inventory")
    assert await connector.fetch_alerts() == []
    findings = await connector.fetch_vulnerability_findings()

    assert len(findings) == 1001
    assert {finding["cve_id"] for finding in findings} == {f"CVE-2026-{10000 + number}" for number in range(1001)}


async def test_failed_primary_can_recover_from_the_real_indexer(indexer: dict[str, Any]) -> None:
    class Unavailable(BaseHTTPRequestHandler):
        requests = 0

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            type(self).requests += 1
            body = b'{"error":"synthetic unavailable primary"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:  # noqa: ANN002
            """Quiet synthetic failure endpoint."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Unavailable)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        await _put(indexer, [(indexer["indices"][0], "recovered", _source(1))])
        connector = WazuhConnector(
            indexer_url=f"http://127.0.0.1:{server.server_port}",
            indexer_urls=indexer["url"],
            username="fixture-user",
            password="fixture-password",
            index_pattern=indexer["indices"][0],
            vuln_mode="alerts",
        )
        events = await connector.fetch_alerts()
        assert len(events) == 1
        assert events[0]["description"] == "Synthetic indexer log 1"
        assert Unavailable.requests == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
