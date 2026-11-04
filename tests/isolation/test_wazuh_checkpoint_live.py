"""Wazuh recovery through HTTP sockets and durable PostgreSQL checkpoints.

The vendor and ingest endpoints are local protocol fixtures, not a running
Wazuh cluster or the Go ingest service. The connector, scheduler, vault,
HTTP clients and inventory/checkpoint SQL writers are the deployed code.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live PostgreSQL",
    ),
]


def _hit(identifier: str, timestamp: datetime, *, cve: str | None = None) -> dict[str, Any]:
    source: dict[str, Any] = {
        "@timestamp": timestamp.isoformat(),
        "agent": {"id": "001", "name": "checkpoint-fixture-host"},
        "rule": {"id": "100100", "level": 12, "description": "Synthetic checkpoint fixture"},
        "full_log": f"Synthetic record {identifier}",
    }
    if cve is not None:
        source["rule"]["groups"] = ["vulnerability-detector"]
        source["data"] = {"vulnerability": {"cve": cve, "severity": "High"}}
    return {"_index": "wazuh-alerts-fixture", "_id": identifier, "_source": source}


class _JSONHandler(BaseHTTPRequestHandler):
    def _reply(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet local fixtures."""


class _Indexer(_JSONHandler):
    alerts: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    failure: str | None = None
    searches: list[dict[str, Any]] = []
    cursors: dict[str, list[dict[str, Any]]] = {}
    cleared: list[str] = []

    @staticmethod
    def _time(value: str) -> datetime:
        if value == "now":
            return datetime.now(UTC)
        if value.startswith("now-") and value.endswith("s"):
            return datetime.now(UTC) - timedelta(seconds=int(value[4:-1]))
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def do_POST(self) -> None:  # noqa: N802
        expected = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()
        if self.headers.get("Authorization") != expected:
            self._reply({"error": "fixture authentication failed"}, status=401)
            return
        body = self._body()
        path = urlsplit(self.path).path
        state = type(self)
        if path == "/wazuh-alerts-*/_search":
            filters = body["query"]["bool"]["must"]
            inventory = any("rule.groups" in item.get("term", {}) for item in filters)
            stream = "vulnerabilities" if inventory else "alerts"
            window = next(item["range"]["@timestamp"] for item in filters if "@timestamp" in item.get("range", {}))
            state.searches.append({"stream": stream, "range": window})
            if state.failure == stream:
                self._reply({"error": "synthetic source failure"}, status=503)
                return
            start, end = self._time(window["gte"]), self._time(window["lte"])
            rows = state.vulnerabilities if inventory else state.alerts
            matched = [row for row in rows if start <= self._time(row["_source"]["@timestamp"]) <= end]
            cursor = uuid.uuid4().hex
            state.cursors[cursor] = matched
        elif path == "/_search/scroll":
            requested_cursor = body.get("scroll_id")
            if not isinstance(requested_cursor, str) or requested_cursor not in state.cursors:
                self._reply({"error": "unknown fixture cursor"}, status=404)
                return
            cursor = requested_cursor
        else:
            self._reply({}, status=404)
            return
        # Match the connector's per-request page size, including the final
        # empty page that proves the snapshot has been drained.
        page = state.cursors[cursor][:1000]
        state.cursors[cursor] = state.cursors[cursor][1000:]
        self._reply(
            {
                "_scroll_id": cursor,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "hits": {"hits": page},
            }
        )

    def do_DELETE(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/_search/scroll":
            self._reply({}, status=404)
            return
        cursors = self._body()["scroll_id"]
        if isinstance(cursors, str):
            cursors = [cursors]
        for cursor in cursors:
            type(self).cursors.pop(cursor, None)
            type(self).cleared.append(cursor)
        self._reply({"succeeded": True, "num_freed": len(cursors)})


class _Ingest(_JSONHandler):
    events: list[dict[str, Any]] = []
    failure: str | None = None

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/ingest/batch":
            self._reply({}, status=404)
            return
        events = self._body()["events"]
        if len(events) > 1000:
            self._reply({"error": "fixture batch limit"}, status=413)
            return
        type(self).events.extend(events)
        if self.failure == "http":
            self._reply({"error": "synthetic publish failure"}, status=503)
        elif self.failure == "partial":
            self._reply({"accepted": len(events) - 1, "rejected": 1})
        elif self.failure == "mismatch":
            self._reply({"accepted": len(events) - 1, "rejected": 0})
        else:
            self._reply({"accepted": len(events), "rejected": 0})


@pytest.fixture(scope="module")
def endpoints():
    running: list[tuple[HTTPServer, threading.Thread]] = []
    urls = []
    for handler in (_Indexer, _Ingest):
        server = HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        running.append((server, thread))
        urls.append(f"http://127.0.0.1:{server.server_port}")
    yield tuple(urls)
    for server, thread in running:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def reset_endpoints(monkeypatch):  # noqa: ANN001
    _Indexer.alerts, _Indexer.vulnerabilities = [], []
    _Indexer.failure = None
    _Indexer.searches, _Indexer.cleared = [], []
    _Indexer.cursors = {}
    _Ingest.events = []
    _Ingest.failure = None
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    instance = create_async_engine(os.environ["ISOLATION_CONNECTOR_DSN"], future=True)
    async with instance.connect() as conn:
        role = (await conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
        assert not role.rolsuper and not role.rolbypassrls, "the live proof must run as the DML-only runtime role"
    yield instance
    await instance.dispose()


@pytest.fixture(scope="module")
def vault():
    from app.security.credential_vault import CredentialVault
    from cryptography.fernet import Fernet

    return CredentialVault(Fernet.generate_key())


@pytest_asyncio.fixture(loop_scope="module")
async def connector_row(engine, endpoints, vault):  # noqa: ANN001
    import sqlalchemy

    tenant_id, connector_id = uuid.uuid4(), uuid.uuid4()
    checkpoint = {
        "version": 1,
        "completed_through": {stream: (datetime.now(UTC) - timedelta(hours=3)).isoformat() for stream in ("alerts", "vulnerabilities")},
        "seen": [],
    }
    config = {"indexer_url": endpoints[0], "vuln_mode": "alerts", "poll_interval_seconds": 300, "checkpoint": checkpoint}
    auth = vault.encrypt_dict({"username": "fixture-user", "password": "fixture-password"})
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": "Wazuh checkpoint fixture", "s": f"checkpoint-{tenant_id.hex}"},
        )
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO connectors (id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'wazuh', 'checkpoint-fixture', true, CAST(:a AS jsonb), CAST(:c AS jsonb))"
            ),
            {"i": connector_id, "t": tenant_id, "a": json.dumps(auth), "c": json.dumps(config)},
        )
    yield {"id": connector_id, "tenant_id": tenant_id, "checkpoint": checkpoint}
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DELETE FROM connectors WHERE id = :i"), {"i": connector_id})
        await conn.execute(sqlalchemy.text("DELETE FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": tenant_id})
        await conn.execute(sqlalchemy.text("DELETE FROM assets WHERE tenant_id = :t"), {"t": tenant_id})
        await conn.execute(sqlalchemy.text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})


async def _poll(engine, endpoints, vault, connector_id: uuid.UUID) -> None:  # noqa: ANN001
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler

    # Each call recreates both scheduler and connector. Progress can only
    # survive through the row that the scheduler reads from PostgreSQL.
    client = IngestClient(base_url=endpoints[1], service_token="fixture-service-token")
    try:
        await ConnectorScheduler(engine=engine, ingest_client=client, vault=vault)._poll_one(connector_id=connector_id)
    finally:
        await client.aclose()


async def _checkpoint(engine, connector_id: uuid.UUID) -> dict[str, Any]:  # noqa: ANN001
    import sqlalchemy

    async with engine.connect() as conn:
        result = await conn.execute(
            sqlalchemy.text("SELECT connector_config -> 'checkpoint' FROM connectors WHERE id = :i"),
            {"i": connector_id},
        )
        return result.scalar_one()


async def _inventory_mode(engine, connector_id: uuid.UUID) -> None:  # noqa: ANN001
    import sqlalchemy

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                'UPDATE connectors SET connector_config = connector_config || \'{"vuln_mode": "inventory"}\'::jsonb WHERE id = :i'
            ),
            {"i": connector_id},
        )


async def _inventory_count(engine, tenant_id: uuid.UUID) -> int:  # noqa: ANN001
    import sqlalchemy

    async with engine.connect() as conn:
        result = await conn.execute(
            sqlalchemy.text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        return result.scalar_one()


async def test_restart_recovers_the_backlog_and_keeps_late_same_time_ids(engine, endpoints, vault, connector_row) -> None:  # noqa: ANN001
    now = datetime.now(UTC)
    timestamp = now - timedelta(minutes=1)
    _Indexer.alerts = [_hit("backlog", now - timedelta(hours=2)), _hit("id-z", timestamp)]

    await _poll(engine, endpoints, vault, connector_row["id"])

    assert [event["alert_id"] for event in _Ingest.events] == ["backlog", "id-z"]
    saved = await _checkpoint(engine, connector_row["id"])
    assert datetime.fromisoformat(saved["completed_through"]["alerts"]) >= now
    assert len(saved["seen"]) == 2
    _Ingest.events = []
    _Indexer.alerts.extend([_hit("id-a", timestamp), _hit("older-late", timestamp - timedelta(seconds=30))])

    await _poll(engine, endpoints, vault, connector_row["id"])

    assert [event["alert_id"] for event in _Ingest.events] == ["id-a", "older-late"]
    assert len({event["external_id"] for event in _Ingest.events}) == 2


@pytest.mark.parametrize("failure", ["http", "partial", "mismatch"])
async def test_ingest_failure_does_not_persist_a_read_cursor(engine, endpoints, vault, connector_row, failure: str) -> None:  # noqa: ANN001
    _Indexer.alerts = [_hit("retry-me", datetime.now(UTC) - timedelta(seconds=30))]
    _Ingest.failure = failure

    await _poll(engine, endpoints, vault, connector_row["id"])

    assert await _checkpoint(engine, connector_row["id"]) == connector_row["checkpoint"]
    _Ingest.events, _Ingest.failure = [], None
    await _poll(engine, endpoints, vault, connector_row["id"])
    assert [event["alert_id"] for event in _Ingest.events] == ["retry-me"]
    assert await _checkpoint(engine, connector_row["id"]) != connector_row["checkpoint"]


async def test_empty_alert_and_inventory_windows_can_advance_independently(engine, endpoints, vault, connector_row) -> None:  # noqa: ANN001
    await _inventory_mode(engine, connector_row["id"])
    before = datetime.now(UTC)

    await _poll(engine, endpoints, vault, connector_row["id"])

    saved = await _checkpoint(engine, connector_row["id"])
    assert all(datetime.fromisoformat(saved["completed_through"][stream]) >= before for stream in ("alerts", "vulnerabilities"))
    assert _Ingest.events == []


async def test_inventory_fetch_failure_keeps_its_cursor_while_alerts_advance(engine, endpoints, vault, connector_row) -> None:  # noqa: ANN001
    await _inventory_mode(engine, connector_row["id"])
    _Indexer.alerts = [_hit("new-alert", datetime.now(UTC) - timedelta(seconds=30))]
    _Indexer.vulnerabilities = [_hit("old-inventory", datetime.now(UTC) - timedelta(hours=2), cve="CVE-2026-10001")]
    _Indexer.failure = "vulnerabilities"

    await _poll(engine, endpoints, vault, connector_row["id"])

    saved = await _checkpoint(engine, connector_row["id"])
    assert saved["completed_through"]["alerts"] != connector_row["checkpoint"]["completed_through"]["alerts"]
    assert saved["completed_through"]["vulnerabilities"] == connector_row["checkpoint"]["completed_through"]["vulnerabilities"]
    assert await _inventory_count(engine, connector_row["tenant_id"]) == 0
    _Indexer.failure = None

    await _poll(engine, endpoints, vault, connector_row["id"])

    recovered = await _checkpoint(engine, connector_row["id"])
    assert recovered["completed_through"]["vulnerabilities"] != saved["completed_through"]["vulnerabilities"]
    assert await _inventory_count(engine, connector_row["tenant_id"]) == 1


async def test_later_inventory_transaction_failure_keeps_the_cursor_and_replays_committed_chunks(
    engine, endpoints, vault, connector_row
) -> None:  # noqa: ANN001
    from app.vulnerabilities import MAX_FINDINGS_PER_SYNC

    await _inventory_mode(engine, connector_row["id"])
    timestamp = datetime.now(UTC) - timedelta(hours=2)
    _Indexer.vulnerabilities = [_hit(f"vuln-{i}", timestamp, cve=f"CVE-2026-{i + 10000}") for i in range(MAX_FINDINGS_PER_SYNC + 1)]
    # PostgreSQL TEXT refuses NUL. This fails the second real transaction,
    # after the first 2,000 findings committed, without mocking the writer.
    _Indexer.vulnerabilities[-1]["_source"]["rule"]["description"] = "synthetic\x00invalid-text"

    await _poll(engine, endpoints, vault, connector_row["id"])

    saved = await _checkpoint(engine, connector_row["id"])
    assert saved["completed_through"]["vulnerabilities"] == connector_row["checkpoint"]["completed_through"]["vulnerabilities"]
    assert await _inventory_count(engine, connector_row["tenant_id"]) == MAX_FINDINGS_PER_SYNC
    _Indexer.vulnerabilities[-1]["_source"]["rule"]["description"] = "corrected synthetic finding"

    await _poll(engine, endpoints, vault, connector_row["id"])

    recovered = await _checkpoint(engine, connector_row["id"])
    assert recovered["completed_through"]["vulnerabilities"] != saved["completed_through"]["vulnerabilities"]
    assert await _inventory_count(engine, connector_row["tenant_id"]) == MAX_FINDINGS_PER_SYNC + 1
