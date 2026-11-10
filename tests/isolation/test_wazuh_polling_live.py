"""Wazuh polling through real HTTP clients, scheduler and PostgreSQL writes.

The indexer and ingest endpoints are local socket fixtures. They exercise
the actual request/response path, but are not a live OpenSearch cluster or
the Go ingest service. The database is the same migrated PostgreSQL used
by the other connector isolation suites.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]


def _hit(number: int, timestamp: str) -> dict[str, Any]:
    return {
        "_id": f"alert-{number}",
        "_index": "wazuh-alerts-test",
        "_source": {
            # Identical timestamps across the page boundary must not drop hits.
            "@timestamp": timestamp,
            "agent": {"id": "001", "name": "fixture-host"},
            "rule": {"id": "100100", "level": 12, "description": "Synthetic polling regression event"},
        },
    }


def _vulnerability_hit(number: int, timestamp: str) -> dict[str, Any]:
    hit = _hit(number, timestamp)
    hit["_id"] = f"finding-{number}"
    hit["_source"]["rule"]["groups"] = ["vulnerability-detector"]
    hit["_source"]["data"] = {
        "vulnerability": {
            "cve": f"CVE-2026-{10000 + number}",
            "title": "Synthetic polling regression finding",
            "severity": "High",
            "status": "Active",
        }
    }
    return hit


class _Clock(datetime):
    """Only the application clock moves; HTTP and database paths stay real."""

    current: datetime

    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        return cls.current.astimezone(tz) if tz is not None else cls.current.replace(tzinfo=None)


def _query_time(value: str) -> datetime:
    # Model the original connector's relative query too, for the negative
    # control: a fixture that ignores its range cannot prove replay safety.
    if value == "now":
        return _Clock.current
    if value.startswith("now-") and value.endswith("s"):
        return _Clock.current - timedelta(seconds=int(value[4:-1]))
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _JSONHandler(BaseHTTPRequestHandler):
    def _reply(self, payload: Any, status: int = 200) -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The real timeout test has already closed its client socket.
            pass

    def _body(self) -> dict[str, Any]:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Keep the test output quiet."""


class _Indexer(_JSONHandler):
    total = 0
    vulnerability_total = 0
    failure: int | str | None = None
    fail_page = 1
    fail_stream = "alerts"
    page = 0
    offset = 0
    page_size = 1000
    scroll_id: str | None = None
    timestamp = ""
    drained = False
    stream = "alerts"
    matched: list[dict[str, Any]] = []
    requests: list[str] = []
    cleared: list[str] = []
    searches: list[dict[str, Any]] = []
    release_response = threading.Event()

    @classmethod
    def reset(cls) -> None:
        cls.total = 0
        cls.vulnerability_total = 0
        cls.failure = None
        cls.fail_page = 1
        cls.fail_stream = "alerts"
        cls.page = 0
        cls.offset = 0
        cls.scroll_id = None
        cls.timestamp = (_Clock.current - timedelta(seconds=1)).isoformat()
        cls.drained = False
        cls.stream = "alerts"
        cls.matched = []
        cls.requests = []
        cls.cleared = []
        cls.searches = []
        cls.release_response.clear()

    def do_POST(self) -> None:  # noqa: N802
        state = type(self)
        path = urlsplit(self.path).path
        state.requests.append(path)
        expected_auth = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()
        if self.headers.get("Authorization") != expected_auth:
            self._reply({}, status=401)
            return
        body = self._body()
        if path == "/wazuh-alerts-*/_search":
            state.page = 0
            state.offset = 0
            state.drained = False
            state.page_size = body["size"]
            clauses = body["query"]["bool"]["must"]
            state.stream = "vulnerabilities" if any("term" in clause for clause in clauses) else "alerts"
            window = next(clause["range"]["@timestamp"] for clause in clauses if "@timestamp" in clause.get("range", {}))
            state.searches.append({"stream": state.stream, "window": window, "params": parse_qs(urlsplit(self.path).query)})
            lower = _query_time(window["gte"])
            upper = _query_time(window.get("lte", "now"))
            timestamp = datetime.fromisoformat(state.timestamp)
            count = state.vulnerability_total if state.stream == "vulnerabilities" else state.total
            factory = _vulnerability_hit if state.stream == "vulnerabilities" else _hit
            state.matched = [factory(number, state.timestamp) for number in range(count)] if lower <= timestamp <= upper else []
        elif path == "/_search/scroll":
            if body.get("scroll_id") != state.scroll_id:
                self._reply({"error": "unknown scroll context"}, status=404)
                return
        else:
            self._reply({}, status=404)
            return

        state.page += 1
        if state.page == state.fail_page and state.stream == state.fail_stream:
            if isinstance(state.failure, int):
                self._reply({"error": "synthetic indexer failure"}, status=state.failure)
                return
            if state.failure == "disconnect":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            if state.failure == "json":
                self._reply(b"not-json")
                return
            if state.failure == "schema":
                self._reply({"hits": {"hits": None}})
                return
            if state.failure == "socket_timeout":
                # httpx has its real 30-second request timeout. Do not replace
                # the HTTP client or turn a simulated exception into live proof.
                state.release_response.wait(timeout=35)
                self._reply({"error": "held response"}, status=503)
                return

        end = min(state.offset + state.page_size, len(state.matched))
        hits = state.matched[state.offset : end]
        state.offset = end
        state.drained = not hits
        state.scroll_id = f"fixture-scroll-{state.stream}-{state.page}"
        payload: dict[str, Any] = {
            "_scroll_id": state.scroll_id,
            "timed_out": state.failure == "timeout" and state.page == state.fail_page and state.stream == state.fail_stream,
            "_shards": {"total": 2, "successful": 2, "failed": 0},
            "hits": {"hits": hits, "total": {"value": len(state.matched), "relation": "eq"}},
        }
        if state.failure == "shards" and state.page == state.fail_page and state.stream == state.fail_stream:
            payload["_shards"] = {"total": 2, "successful": 1, "failed": 1}
        if state.failure == "total" and state.page == state.fail_page and state.stream == state.fail_stream:
            payload["hits"]["total"]["relation"] = "gte"
        self._reply(payload)

    def do_DELETE(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/_search/scroll":
            self._reply({}, status=404)
            return
        ids = self._body().get("scroll_id")
        if isinstance(ids, str):
            type(self).cleared.append(ids)
        elif isinstance(ids, list) and all(isinstance(value, str) for value in ids):
            type(self).cleared.extend(ids)
        else:
            self._reply({}, status=400)
            return
        self._reply({"succeeded": True, "num_freed": 1})


class _Ingest(_JSONHandler):
    received: list[dict[str, Any]] = []
    request_count = 0
    fail_request: int | None = None
    reject_request: int | None = None

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/ingest/batch":
            self._reply({}, status=404)
            return
        state = type(self)
        state.request_count += 1
        if int(self.headers.get("Content-Length", "0")) > 10 * 1024 * 1024:
            self.close_connection = True
            self._reply({"error": "request body exceeds maximum allowed"}, status=413)
            return
        body = self._body()
        # Match services/ingest's default MAX_BATCH_SIZE. An unlimited
        # fixture would hide a paginated poll that the real sink rejects.
        if len(body["events"]) > 1000:
            self._reply({"error": "batch size exceeds maximum allowed"}, status=413)
            return
        if state.request_count == state.fail_request:
            self._reply({"error": "synthetic publish failure"}, status=503)
            return
        if state.request_count == state.reject_request:
            self._reply({"accepted": len(body["events"]) - 1, "rejected": 1})
            return
        state.received.append({"tenant": self.headers.get("X-Tenant-ID"), "body": body, "source_drained": _Indexer.drained})
        self._reply({"accepted": len(body["events"]), "rejected": 0})


def _serve(handler):  # noqa: ANN001
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="module")
def endpoints():
    vendor, vendor_thread, vendor_url = _serve(_Indexer)
    ingest, ingest_thread, ingest_url = _serve(_Ingest)
    yield vendor_url, ingest_url
    for server, thread in ((vendor, vendor_thread), (ingest, ingest_thread)):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def reset_endpoints(monkeypatch):  # noqa: ANN001
    from app import scheduler as scheduler_module
    from app.connectors import wazuh

    _Clock.current = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(scheduler_module, "datetime", _Clock)
    # The pre-fix connector used relative OpenSearch date math and did not
    # import datetime; allow the same fixture to run as a negative control.
    monkeypatch.setattr(wazuh, "datetime", _Clock, raising=False)
    _Indexer.reset()
    _Ingest.received = []
    _Ingest.request_count = 0
    _Ingest.fail_request = None
    _Ingest.reject_request = None
    # The documented, exact-host exception; the real SSRF guard still runs.
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    # These fixtures communicate only over loopback. A developer's outbound
    # SOCKS proxy must not replace their real local sockets (the locked HTTP
    # client also predates the socks5h proxy scheme).
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    yield
    _Indexer.release_response.set()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(
        os.environ["ISOLATION_CONNECTOR_DSN"], future=True, pool_size=1, max_overflow=0, connect_args={"command_timeout": 15}
    )
    async with created.connect() as conn:
        role = (await conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
        assert role == (False, False), "integration tests must use the unprivileged runtime role"
    yield created
    await created.dispose()


@pytest.fixture(scope="module")
def vault():
    from app.security.credential_vault import CredentialVault
    from cryptography.fernet import Fernet

    return CredentialVault(Fernet.generate_key())


@pytest_asyncio.fixture(loop_scope="module")
async def connector_row(engine, endpoints, vault):  # noqa: ANN001
    import sqlalchemy

    tenant_id, connector_id = uuid.uuid4(), uuid.uuid4()
    last_sync = _Clock.current - timedelta(minutes=10)
    checkpoint = {
        "wazuh_poll": {
            "version": 1,
            "alerts_through": last_sync.isoformat(),
            "vulnerabilities_through": (_Clock.current - timedelta(hours=1)).isoformat(),
        }
    }
    auth = vault.encrypt_dict({"username": "fixture-user", "password": "fixture-password"})
    config = {
        "indexer_url": endpoints[0],
        "poll_interval_seconds": 300,
        # Isolate the alert path from the optional inventory sync.
        "vuln_mode": "alerts",
        "checkpoint": checkpoint,
    }
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": "Wazuh polling fixture", "s": f"wazuh-{tenant_id.hex}"},
        )
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config, "
                "health_status, last_sync, events_ingested, error_count) "
                "VALUES (:i, :t, 'wazuh', 'live-wazuh-poll', true, CAST(:a AS jsonb), CAST(:c AS jsonb), "
                "'healthy', :s, 7, 0)"
            ),
            {"i": connector_id, "t": tenant_id, "a": json.dumps(auth), "c": json.dumps(config), "s": last_sync},
        )
    yield {"id": connector_id, "tenant_id": tenant_id, "last_sync": last_sync, "checkpoint": checkpoint}
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DELETE FROM connectors WHERE id = :i"), {"i": connector_id})
        await conn.execute(sqlalchemy.text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})


@pytest_asyncio.fixture(loop_scope="module")
async def scheduler(engine, endpoints, vault):  # noqa: ANN001
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler

    ingest = IngestClient(base_url=endpoints[1], service_token="fixture-service-token")
    yield ConnectorScheduler(engine=engine, ingest_client=ingest, vault=vault)
    await ingest.aclose()


async def _stored(engine, connector_id: uuid.UUID) -> dict[str, Any]:  # noqa: ANN001
    import sqlalchemy

    async with engine.connect() as conn:
        result = await conn.execute(
            sqlalchemy.text(
                "SELECT health_status, last_sync, error_count, last_outage_at, events_ingested, "
                "connector_config -> 'checkpoint' AS checkpoint FROM connectors WHERE id = :i"
            ),
            {"i": connector_id},
        )
        return dict(result.mappings().one())


@pytest.mark.parametrize("failure", [401, 403, 429, 503, "disconnect", "json", "schema", "timeout", "shards", "total"])
async def test_failed_search_is_unhealthy_and_preserves_last_success(scheduler, engine, connector_row, failure) -> None:  # noqa: ANN001
    _Indexer.failure = failure

    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row["id"])
    assert _Indexer.requests, "the actual Wazuh HTTP client must reach the indexer fixture"
    assert row["health_status"] == "unhealthy"
    assert row["error_count"] == 1
    assert row["last_sync"] == connector_row["last_sync"]
    assert row["checkpoint"] == connector_row["checkpoint"]
    assert row["events_ingested"] == 7
    assert row["last_outage_at"] is not None
    assert _Ingest.received == []

    # Repeated failure retains the first outage timestamp, so recovery can
    # calculate its duration instead of moving the start forward each poll.
    await scheduler._poll_one(connector_id=connector_row["id"])
    repeated = await _stored(engine, connector_row["id"])
    assert repeated["error_count"] == 2
    assert repeated["last_outage_at"] == row["last_outage_at"]
    assert repeated["last_sync"] == row["last_sync"]


async def test_a_genuine_empty_result_is_a_success(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row["id"])
    assert row["health_status"] == "healthy"
    assert row["error_count"] == 0
    assert row["last_sync"] > connector_row["last_sync"]
    assert row["events_ingested"] == 7
    assert row["last_outage_at"] is None
    assert _Ingest.received == []
    assert row["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()
    assert (
        row["checkpoint"]["wazuh_poll"]["vulnerabilities_through"] == connector_row["checkpoint"]["wazuh_poll"]["vulnerabilities_through"]
    )


@pytest.mark.parametrize("total", [1001, 2501])
async def test_every_page_reaches_ingest_once(scheduler, engine, connector_row, total) -> None:  # noqa: ANN001
    _Indexer.total = total

    await scheduler._poll_one(connector_id=connector_row["id"])

    assert len(_Ingest.received) == (total + 999) // 1000
    assert all(submitted["tenant"] == str(connector_row["tenant_id"]) for submitted in _Ingest.received)
    assert all(len(submitted["body"]["events"]) <= 1000 for submitted in _Ingest.received)
    assert all(submitted["source_drained"] for submitted in _Ingest.received)
    events = [event for submitted in _Ingest.received for event in submitted["body"]["events"]]
    assert [event["alert_id"] for event in events] == [f"alert-{number}" for number in range(total)]
    row = await _stored(engine, connector_row["id"])
    assert row["health_status"] == "healthy"
    assert row["events_ingested"] == 7 + total
    assert _Indexer.cleared == [_Indexer.scroll_id]
    assert row["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()


async def test_later_page_failure_ingests_nothing_and_next_poll_can_recover(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    _Indexer.total = 1001
    _Indexer.failure = 503
    _Indexer.fail_page = 2

    await scheduler._poll_one(connector_id=connector_row["id"])

    failed = await _stored(engine, connector_row["id"])
    assert failed["health_status"] == "unhealthy"
    assert failed["last_sync"] == connector_row["last_sync"]
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert failed["events_ingested"] == 7
    assert _Ingest.received == []
    assert _Indexer.cleared == [_Indexer.scroll_id]

    first_window = _Indexer.searches[0]["window"]
    _Clock.current += timedelta(minutes=40)
    _Indexer.failure = None
    await scheduler._poll_one(connector_id=connector_row["id"])

    recovered = await _stored(engine, connector_row["id"])
    assert recovered["health_status"] == "healthy"
    assert recovered["last_sync"] > connector_row["last_sync"]
    assert recovered["last_outage_at"] is None
    assert recovered["events_ingested"] == 1008
    assert recovered["error_count"] == 1
    assert len(_Ingest.received) == 2
    assert all(len(submitted["body"]["events"]) <= 1000 for submitted in _Ingest.received)
    assert all(submitted["source_drained"] for submitted in _Ingest.received)
    events = [event for submitted in _Ingest.received for event in submitted["body"]["events"]]
    assert [event["alert_id"] for event in events] == [f"alert-{number}" for number in range(1001)]
    assert _Indexer.searches[-1]["window"]["gte"] == first_window["gte"]
    assert _Indexer.searches[-1]["window"]["lte"] == _Clock.current.isoformat()
    assert recovered["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()


@pytest.mark.parametrize("failure_kind", ["http", "rejection"])
async def test_later_ingest_failure_preserves_last_success_and_allows_replay(scheduler, engine, connector_row, failure_kind) -> None:  # noqa: ANN001
    _Indexer.total = 1001
    if failure_kind == "http":
        _Ingest.fail_request = 2
    else:
        _Ingest.reject_request = 2

    await scheduler._poll_one(connector_id=connector_row["id"])

    failed = await _stored(engine, connector_row["id"])
    assert failed["health_status"] == "unhealthy"
    assert failed["error_count"] == 1
    assert failed["last_sync"] == connector_row["last_sync"]
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert failed["last_outage_at"] is not None
    assert len(_Ingest.received) == 1
    assert len(_Ingest.received[0]["body"]["events"]) == 1000
    assert _Ingest.received[0]["source_drained"]

    # Earlier chunks may already be durable. Retrying the still-overlapping
    # window deliberately allows replay instead of advancing past the failed
    # chunk; this is an at-least-once assertion, not an exactly-once claim.
    _Ingest.received = []
    _Ingest.fail_request = None
    _Ingest.reject_request = None
    _Clock.current += timedelta(hours=2)
    await scheduler._poll_one(connector_id=connector_row["id"])

    recovered = await _stored(engine, connector_row["id"])
    assert recovered["health_status"] == "healthy"
    assert recovered["last_sync"] > connector_row["last_sync"]
    assert recovered["last_outage_at"] is None
    assert recovered["events_ingested"] == 1008
    assert recovered["error_count"] == 1
    events = [event for submitted in _Ingest.received for event in submitted["body"]["events"]]
    assert [event["alert_id"] for event in events] == [f"alert-{number}" for number in range(1001)]
    assert recovered["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()


async def test_first_failed_poll_persists_a_replay_floor_across_scheduler_restart(
    scheduler, engine, connector_row, endpoints, vault
) -> None:  # noqa: ANN001
    import sqlalchemy
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("UPDATE connectors SET last_sync = NULL, connector_config = connector_config - 'checkpoint' WHERE id = :i"),
            {"i": connector_row["id"]},
        )
    first_started = _Clock.current
    _Indexer.total = 1001
    _Indexer.failure = 503
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row["id"])
    assert failed["last_sync"] is None
    assert failed["checkpoint"]["wazuh_poll"]["alerts_through"] == (first_started - timedelta(minutes=5)).isoformat()
    assert failed["checkpoint"]["wazuh_poll"]["vulnerabilities_through"] == (first_started - timedelta(hours=1)).isoformat()

    _Clock.current += timedelta(hours=5)
    # Reconstruct the scheduler and client: the only available replay state
    # must be the JSONB read from the connector row, not an object cache.
    ingest = IngestClient(base_url=endpoints[1], service_token="fixture-service-token")
    restarted = ConnectorScheduler(engine=engine, ingest_client=ingest, vault=vault)
    try:
        await restarted._poll_one(connector_id=connector_row["id"])
        failed_again = await _stored(engine, connector_row["id"])
        assert failed_again["checkpoint"] == failed["checkpoint"]
        assert failed_again["last_sync"] is None
        _Indexer.failure = None
        await restarted._poll_one(connector_id=connector_row["id"])
    finally:
        await ingest.aclose()
    recovered = await _stored(engine, connector_row["id"])
    events = [event for submitted in _Ingest.received for event in submitted["body"]["events"]]
    assert len(events) == 1001
    assert recovered["health_status"] == "healthy"
    assert recovered["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()
    assert recovered["events_ingested"] == 1008


async def test_real_http_timeout_preserves_the_window_for_retry(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    _Indexer.total = 1001
    _Indexer.failure = "socket_timeout"
    _Indexer.fail_page = 2
    try:
        await scheduler._poll_one(connector_id=connector_row["id"])
    finally:
        _Indexer.release_response.set()
    failed = await _stored(engine, connector_row["id"])
    assert failed["health_status"] == "unhealthy"
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert failed["last_sync"] == connector_row["last_sync"]
    assert _Ingest.received == []
    assert len(_Indexer.requests) == 2, "a timed-out continuation must not be retried against an advanced cursor"
    _Clock.current += timedelta(minutes=20)
    _Indexer.failure = None
    await scheduler._poll_one(connector_id=connector_row["id"])
    recovered = await _stored(engine, connector_row["id"])
    assert recovered["health_status"] == "healthy"
    assert recovered["events_ingested"] == 1008


async def test_result_limit_fails_closed_then_can_replay_with_a_larger_limit(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    import sqlalchemy

    _Indexer.total = 1001
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "UPDATE connectors SET connector_config = connector_config || '{\"max_search_results\": 1000}'::jsonb WHERE id = :i"
            ),
            {"i": connector_row["id"]},
        )
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row["id"])
    assert failed["health_status"] == "unhealthy"
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert _Ingest.received == []
    _Clock.current += timedelta(minutes=20)
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "UPDATE connectors SET connector_config = connector_config || '{\"max_search_results\": 2000}'::jsonb WHERE id = :i"
            ),
            {"i": connector_row["id"]},
        )
    await scheduler._poll_one(connector_id=connector_row["id"])
    recovered = await _stored(engine, connector_row["id"])
    assert recovered["health_status"] == "healthy"
    assert recovered["events_ingested"] == 1008


async def test_inventory_over_2000_findings_and_alerts_share_a_confirmed_boundary(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    import sqlalchemy

    _Indexer.total = 1
    _Indexer.vulnerability_total = 2001
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                'UPDATE connectors SET connector_config = connector_config || \'{"vuln_mode": "inventory"}\'::jsonb WHERE id = :i'
            ),
            {"i": connector_row["id"]},
        )
    await scheduler._poll_one(connector_id=connector_row["id"])
    row = await _stored(engine, connector_row["id"])
    assert row["health_status"] == "healthy"
    assert row["events_ingested"] == 8
    assert row["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()
    assert row["checkpoint"]["wazuh_poll"]["vulnerabilities_through"] == _Clock.current.isoformat()
    async with engine.connect() as conn:
        count = await conn.scalar(
            sqlalchemy.text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"),
            {"t": connector_row["tenant_id"]},
        )
    assert count == 2001, "a complete source snapshot must also pass the 2000-finding writer boundary"


async def test_inventory_page_failure_retains_both_streams_for_a_later_poll(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    import sqlalchemy

    _Indexer.total = 1
    _Indexer.vulnerability_total = 1001
    _Indexer.fail_stream = "vulnerabilities"
    _Indexer.fail_page = 2
    _Indexer.failure = 503
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                'UPDATE connectors SET connector_config = connector_config || \'{"vuln_mode": "inventory"}\'::jsonb WHERE id = :i'
            ),
            {"i": connector_row["id"]},
        )
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row["id"])
    assert failed["health_status"] == "unhealthy"
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert failed["last_sync"] == connector_row["last_sync"]
    async with engine.connect() as conn:
        assert (
            await conn.scalar(
                sqlalchemy.text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"),
                {"t": connector_row["tenant_id"]},
            )
            == 0
        )
    _Clock.current += timedelta(hours=2)
    _Indexer.failure = None
    await scheduler._poll_one(connector_id=connector_row["id"])
    recovered = await _stored(engine, connector_row["id"])
    assert recovered["health_status"] == "healthy"
    assert recovered["checkpoint"]["wazuh_poll"]["alerts_through"] == _Clock.current.isoformat()
    assert recovered["checkpoint"]["wazuh_poll"]["vulnerabilities_through"] == _Clock.current.isoformat()
    async with engine.connect() as conn:
        assert (
            await conn.scalar(
                sqlalchemy.text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"),
                {"t": connector_row["tenant_id"]},
            )
            == 1001
        )
