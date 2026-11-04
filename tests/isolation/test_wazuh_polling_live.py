"""Wazuh polling through HTTP sockets and persisted PostgreSQL checkpoints.

The local indexer and ingest servers implement only the protocol used by these
regressions; they are synthetic fixtures, not a Wazuh cluster or the Go ingest
service. The scheduler, HTTP clients, credential vault and database writes are
real. Native indexer behavior has its own opt-in connector test suite.
"""

from __future__ import annotations

import base64
import copy
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


class _Clock(datetime):
    """Move application time without replacing HTTP clients or database code."""

    current: datetime

    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        return cls.current.astimezone(tz) if tz is not None else cls.current.replace(tzinfo=None)


def _hit(number: int, timestamp: str, *, vulnerability: bool = False) -> dict[str, Any]:
    hit: dict[str, Any] = {
        "_id": f"{'finding' if vulnerability else 'alert'}-{number}",
        "_index": "wazuh-alerts-fixture",
        "_source": {
            "@timestamp": timestamp,
            "agent": {"id": "001", "name": "synthetic-host"},
            "rule": {"id": "100100", "level": 12, "description": "Synthetic polling regression event"},
            "full_log": f"Synthetic log record {number}",
        },
    }
    if vulnerability:
        hit["_source"]["rule"]["groups"] = ["vulnerability-detector"]
        hit["_source"]["data"] = {"vulnerability": {"cve": f"CVE-2026-{10000 + number}", "severity": "High"}}
    return hit


def _query_time(value: str) -> datetime:
    # The negative control uses the original relative date math. Ignoring
    # the actual range would let a broken rolling-window query pass.
    if value == "now":
        return _Clock.current
    if value.startswith("now-") and value.endswith("s"):
        return _Clock.current - timedelta(seconds=int(value[4:-1]))
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _field(source: dict[str, Any], name: str) -> Any:
    value: Any = source
    for part in name.removesuffix(".keyword").split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def _matches(query: dict[str, Any], source: dict[str, Any]) -> bool:
    """Evaluate the small documented DSL subset used by the real requests."""
    if "bool" in query:
        clauses = query["bool"]
        must = clauses.get("must", []) + clauses.get("filter", [])
        should = clauses.get("should", [])
        minimum = int(clauses.get("minimum_should_match", 0 if must else bool(should)))
        return (
            all(_matches(clause, source) for clause in must)
            and not any(_matches(clause, source) for clause in clauses.get("must_not", []))
            and sum(_matches(clause, source) for clause in should) >= minimum
        )
    if "range" in query:
        for name, bounds in query["range"].items():
            value = _field(source, name)
            if value is None:
                return False
            is_time = isinstance(value, str) and "T" in value
            value = _query_time(value) if is_time else value
            for operator, limit in bounds.items():
                limit = _query_time(limit) if is_time else limit
                if operator == "gte" and value < limit or operator == "lte" and value > limit:
                    return False
                if operator not in {"gte", "lte"}:
                    raise AssertionError(f"unsupported fixture range operator: {operator}")
        return True
    for operator in ("term", "terms"):
        if operator in query:
            for name, expected in query[operator].items():
                values = _field(source, name)
                values = values if isinstance(values, list) else [values]
                expected = expected if operator == "terms" else [expected]
                if not any(value in expected for value in values):
                    return False
            return True
    if "exists" in query:
        return _field(source, query["exists"]["field"]) is not None
    raise AssertionError(f"unsupported fixture query: {query}")


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
            pass

    def _body(self) -> dict[str, Any]:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Keep synthetic request bodies out of test logs."""


class _Indexer(_JSONHandler):
    label = "indexer"
    documents: list[dict[str, Any]]
    failure: int | str | None
    fail_page: int
    fail_stream: str
    requests: list[dict[str, Any]]
    searches: list[dict[str, Any]]
    cleared: list[str]
    drained: dict[str, bool]
    scroll_id: str | None
    release_response: threading.Event
    page: int
    offset: int
    page_size: int
    stream: str
    matched: list[dict[str, Any]]

    @classmethod
    def reset(cls) -> None:
        cls.documents = []
        cls.failure = None
        cls.fail_page = 1
        cls.fail_stream = "alerts"
        cls.requests = []
        cls.searches = []
        cls.cleared = []
        cls.drained = {}
        cls.scroll_id = None
        cls.release_response = threading.Event()
        cls.page = 0
        cls.offset = 0
        cls.page_size = 1000
        cls.stream = "alerts"
        cls.matched = []

    def do_POST(self) -> None:  # noqa: N802
        state = type(self)
        path = urlsplit(self.path).path
        body = self._body()
        state.requests.append({"path": path, "body": copy.deepcopy(body)})
        expected = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()
        if self.headers.get("Authorization") != expected:
            self._reply({}, status=401)
            return
        if path == "/wazuh-alerts-*/_search":
            state.page = 0
            state.offset = 0
            state.page_size = body["size"]
            must = body["query"]["bool"].get("must", [])
            state.stream = "vulnerabilities" if "vulnerability" in json.dumps(must) else "alerts"
            state.drained[state.stream] = False
            state.searches.append({"stream": state.stream, "body": copy.deepcopy(body), "params": parse_qs(urlsplit(self.path).query)})
            state.matched = [copy.deepcopy(hit) for hit in state.documents if _matches(body["query"], hit["_source"])]
        elif path == "/_search/scroll":
            if body.get("scroll_id") != state.scroll_id:
                self._reply({"error": "unknown scroll context"}, status=404)
                return
        else:
            self._reply({}, status=404)
            return

        state.page += 1
        failing = state.page == state.fail_page and state.stream == state.fail_stream
        if failing:
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
                state.release_response.wait(timeout=35)
                self._reply({"error": "held response"}, status=503)
                return

        hits = state.matched[state.offset : state.offset + state.page_size]
        state.offset += len(hits)
        state.drained[state.stream] = not hits
        state.scroll_id = f"fixture-{state.label}-{len(state.searches)}-{state.page}"
        payload: dict[str, Any] = {
            "_scroll_id": state.scroll_id,
            "timed_out": state.failure == "timeout" and failing,
            "_shards": {"total": 2, "successful": 2, "failed": 0},
            "hits": {"hits": hits, "total": {"value": len(state.matched), "relation": "eq"}},
        }
        if state.failure == "shards" and failing:
            payload["_shards"] = {"total": 2, "successful": 1, "failed": 1}
        self._reply(payload)

    def do_DELETE(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/_search/scroll":
            self._reply({}, status=404)
            return
        identities = self._body().get("scroll_id")
        if isinstance(identities, str):
            identities = [identities]
        if not isinstance(identities, list) or not all(isinstance(value, str) for value in identities):
            self._reply({}, status=400)
            return
        type(self).cleared.extend(identities)
        self._reply({"succeeded": True, "num_freed": 1})


class _Primary(_Indexer):
    label = "primary"


class _Secondary(_Indexer):
    label = "secondary"


class _Ingest(_JSONHandler):
    received: list[dict[str, Any]] = []
    request_count = 0
    fail_request: int | None = None
    reject_request: int | None = None

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/ingest/batch":
            self._reply({}, status=404)
            return
        if self.headers.get("Authorization") != "Bearer fixture-service-token":
            self._reply({}, status=401)
            return
        state = type(self)
        state.request_count += 1
        if int(self.headers.get("Content-Length", "0")) > 10 * 1024 * 1024:
            self.close_connection = True
            self._reply({"error": "request body exceeds maximum allowed"}, status=413)
            return
        body = self._body()
        if len(body["events"]) > 1000:
            self._reply({"error": "batch size exceeds maximum allowed"}, status=413)
            return
        if state.request_count == state.fail_request:
            self._reply({"error": "synthetic publish failure"}, status=503)
            return
        rejected = int(state.request_count == state.reject_request)
        accepted = len(body["events"]) - rejected
        state.received.append(
            {
                "tenant": self.headers.get("X-Tenant-ID"),
                "events": body["events"][:accepted],
                "submitted": len(body["events"]),
                "source_drained": _Primary.drained.get("alerts", False) or _Secondary.drained.get("alerts", False),
            }
        )
        self._reply({"accepted": accepted, "rejected": rejected})


def _serve(handler):  # noqa: ANN001
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="module")
def endpoints():
    running = [_serve(handler) for handler in (_Primary, _Secondary, _Ingest)]
    yield {"primary": running[0][2], "secondary": running[1][2], "ingest": running[2][2]}
    for server, thread, _url in running:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def reset_endpoints(monkeypatch):  # noqa: ANN001
    from app import scheduler as scheduler_module
    from app.connectors import wazuh

    _Clock.current = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(scheduler_module, "datetime", _Clock)
    monkeypatch.setattr(wazuh, "datetime", _Clock, raising=False)
    try:
        from app.connectors import wazuh_checkpoint
    except ImportError:
        # The unfixed main branch has no helper; the same socket fixture must
        # exercise its relative query as a behavioral negative control.
        pass
    else:
        monkeypatch.setattr(wazuh_checkpoint, "datetime", _Clock)
    _Primary.reset()
    _Secondary.reset()
    _Ingest.received = []
    _Ingest.request_count = 0
    _Ingest.fail_request = None
    _Ingest.reject_request = None
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    yield
    _Primary.release_response.set()
    _Secondary.release_response.set()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(
        os.environ["ISOLATION_CONNECTOR_DSN"], future=True, pool_size=1, max_overflow=0, connect_args={"command_timeout": 15}
    )
    async with created.connect() as conn:
        role = (await conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
        assert role == (False, False), "exercise the actual non-superuser runtime role"
    yield created
    await created.dispose()


@pytest.fixture(scope="module")
def vault():
    from app.security.credential_vault import CredentialVault
    from cryptography.fernet import Fernet

    return CredentialVault(Fernet.generate_key())


@pytest_asyncio.fixture(loop_scope="module")
async def connector_row(engine, endpoints, vault):  # noqa: ANN001
    from sqlalchemy import text

    tenant_id, connector_id = uuid.uuid4(), uuid.uuid4()
    last_sync = _Clock.current - timedelta(minutes=10)
    checkpoint = {
        "version": 1,
        "completed_through": {
            "alerts": last_sync.isoformat(),
            "vulnerabilities": (_Clock.current - timedelta(hours=1)).isoformat(),
        },
        "seen": [],
    }
    config = {"indexer_url": endpoints["primary"], "poll_interval_seconds": 300, "vuln_mode": "alerts", "checkpoint": checkpoint}
    auth = vault.encrypt_dict({"username": "fixture-user", "password": "fixture-password"})
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": "Synthetic Wazuh polling tenant", "s": f"wazuh-{tenant_id.hex}"},
        )
        await conn.execute(
            text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config, "
                "health_status, last_sync, events_ingested, error_count) "
                "VALUES (:i, :t, 'wazuh', 'synthetic-wazuh-poll', true, CAST(:a AS jsonb), CAST(:c AS jsonb), "
                "'healthy', :s, 7, 0)"
            ),
            {"i": connector_id, "t": tenant_id, "a": json.dumps(auth), "c": json.dumps(config), "s": last_sync},
        )
    yield {"id": connector_id, "tenant_id": tenant_id, "last_sync": last_sync, "checkpoint": checkpoint}
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM connectors WHERE id = :i AND tenant_id = :t"), {"i": connector_id, "t": tenant_id})
        await conn.execute(text("DELETE FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": tenant_id})
        await conn.execute(text("DELETE FROM assets WHERE tenant_id = :t"), {"t": tenant_id})
        await conn.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})


@pytest_asyncio.fixture(loop_scope="module")
async def scheduler(engine, endpoints, vault):  # noqa: ANN001
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler

    ingest = IngestClient(base_url=endpoints["ingest"], service_token="fixture-service-token")
    yield ConnectorScheduler(engine=engine, ingest_client=ingest, vault=vault)
    await ingest.aclose()


async def _stored(engine, row: dict[str, Any]) -> dict[str, Any]:  # noqa: ANN001
    from sqlalchemy import text

    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT health_status, last_sync, error_count, last_outage_at, events_ingested, "
                "connector_config -> 'checkpoint' AS checkpoint FROM connectors WHERE id = :i AND tenant_id = :t"
            ),
            {"i": row["id"], "t": row["tenant_id"]},
        )
        return dict(result.mappings().one())


async def _configure(engine, row: dict[str, Any], **values: Any) -> None:  # noqa: ANN001
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE connectors SET connector_config = connector_config || CAST(:c AS jsonb) WHERE id = :i AND tenant_id = :t"),
            {"i": row["id"], "t": row["tenant_id"], "c": json.dumps(values)},
        )


def _received() -> list[dict[str, Any]]:
    return [event for request in _Ingest.received for event in request["events"]]


def _seed(total: int, *, vulnerability_total: int = 0) -> None:
    stamp = (_Clock.current - timedelta(seconds=1)).isoformat()
    _Primary.documents = [_hit(number, stamp) for number in range(total)]
    _Primary.documents += [_hit(number, stamp, vulnerability=True) for number in range(vulnerability_total)]


@pytest.mark.parametrize("failure", [401, 403, 429, 503, "disconnect", "json", "schema", "timeout", "shards"])
async def test_failed_search_is_unhealthy_and_preserves_durable_progress(scheduler, engine, connector_row, failure) -> None:  # noqa: ANN001
    _Primary.failure = failure

    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row)
    assert _Primary.requests, "the real HTTP client must reach the local indexer"
    assert row["health_status"] == "unhealthy"
    assert row["error_count"] == 1
    assert row["last_sync"] == connector_row["last_sync"]
    assert row["checkpoint"] == connector_row["checkpoint"]
    assert row["last_outage_at"] is not None
    assert row["events_ingested"] == 7
    assert _received() == []


async def test_complete_empty_search_advances_only_the_completed_stream(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row)
    assert row["health_status"] == "healthy"
    assert row["last_sync"] > connector_row["last_sync"]
    assert row["events_ingested"] == 7
    assert row["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()
    assert row["checkpoint"]["completed_through"]["vulnerabilities"] == connector_row["checkpoint"]["completed_through"]["vulnerabilities"]
    assert _received() == []


@pytest.mark.parametrize("total", [1001, 2501])
async def test_every_page_and_same_rule_document_reaches_ingest(scheduler, engine, connector_row, total) -> None:  # noqa: ANN001
    _seed(total)
    await scheduler._poll_one(connector_id=connector_row["id"])

    events = _received()
    assert len(events) == total
    assert len({event["external_id"] for event in events}) == total, "the rule id is not a source-document identity"
    assert {event["rule_id"] for event in events} == {"100100"}
    assert {event["description"] for event in events} == {f"Synthetic log record {number}" for number in range(total)}
    assert len(_Ingest.received) == (total + 999) // 1000
    assert all(request["submitted"] <= 1000 and request["source_drained"] for request in _Ingest.received)
    assert all(request["tenant"] == str(connector_row["tenant_id"]) for request in _Ingest.received)
    assert _Primary.cleared == [_Primary.scroll_id]
    row = await _stored(engine, connector_row)
    assert row["events_ingested"] == 7 + total
    assert row["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()


async def test_later_page_failure_discards_partial_results_and_recovers_after_an_outage(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    _seed(1001)
    _Primary.failure, _Primary.fail_page = 503, 2
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row)
    assert failed["health_status"] == "unhealthy"
    assert failed["checkpoint"] == connector_row["checkpoint"]
    assert _received() == []
    assert _Primary.cleared == [_Primary.scroll_id]

    _Clock.current += timedelta(hours=2)
    _Primary.failure = None
    await scheduler._poll_one(connector_id=connector_row["id"])
    recovered = await _stored(engine, connector_row)
    assert len(_received()) == 1001
    assert len({event["external_id"] for event in _received()}) == 1001
    assert recovered["health_status"] == "healthy"
    assert recovered["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()


@pytest.mark.parametrize("failure_kind", ["http", "partial"])
async def test_ingest_failure_withholds_checkpoint_and_replays_every_unconfirmed_document(
    scheduler, engine, connector_row, failure_kind
) -> None:  # noqa: ANN001
    _seed(1001)
    if failure_kind == "http":
        _Ingest.fail_request = 2
    else:
        _Ingest.reject_request = 2
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row)
    assert len(_received()) == 1000
    assert failed["checkpoint"] == connector_row["checkpoint"], "partial acceptance cannot authorize a source checkpoint"

    # Accepted earlier chunks may replay. This is an at-least-once contract;
    # the important property is that the last, unaccepted document returns.
    _Clock.current += timedelta(hours=2)
    _Ingest.fail_request = _Ingest.reject_request = None
    _Ingest.received = []
    await scheduler._poll_one(connector_id=connector_row["id"])
    assert len(_received()) == 1001
    assert len({event["external_id"] for event in _received()}) == 1001
    recovered = await _stored(engine, connector_row)
    assert recovered["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()


async def test_restart_recovers_events_older_than_the_normal_poll_window(scheduler, engine, connector_row, endpoints, vault) -> None:  # noqa: ANN001
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler

    await scheduler._poll_one(connector_id=connector_row["id"])
    stopped_at = _Clock.current
    _Primary.documents = [_hit(1, (stopped_at + timedelta(minutes=10)).isoformat())]
    _Clock.current += timedelta(hours=2)
    ingest = IngestClient(endpoints["ingest"], service_token="fixture-service-token")
    try:
        restarted = ConnectorScheduler(engine=engine, ingest_client=ingest, vault=vault)
        await restarted._poll_one(connector_id=connector_row["id"])
    finally:
        await ingest.aclose()
    assert len(_received()) == 1, "a new scheduler must recover from JSONB, without an in-memory cursor"
    assert _received()[0]["description"] == "Synthetic log record 1"
    assert (await _stored(engine, connector_row))["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()


async def test_ten_minute_late_document_survives_a_previous_newer_document(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    _seed(1)
    await scheduler._poll_one(connector_id=connector_row["id"])
    assert len(_received()) == 1
    _Ingest.received = []
    _Clock.current += timedelta(minutes=5)
    _Primary.documents.append(_hit(2, (_Clock.current - timedelta(minutes=10)).isoformat()))

    await scheduler._poll_one(connector_id=connector_row["id"])

    assert len(_received()) == 1
    assert _received()[0]["description"] == "Synthetic log record 2"
    assert (await _stored(engine, connector_row))["events_ingested"] == 9


async def test_first_failed_poll_persists_an_uncompleted_window_across_restart(scheduler, engine, connector_row, endpoints, vault) -> None:  # noqa: ANN001
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE connectors SET last_sync = NULL, connector_config = connector_config - 'checkpoint' "
                "WHERE id = :i AND tenant_id = :t"
            ),
            {"i": connector_row["id"], "t": connector_row["tenant_id"]},
        )
    _Primary.documents = [_hit(1, (_Clock.current - timedelta(minutes=4)).isoformat())]
    _Primary.failure = 503
    await scheduler._poll_one(connector_id=connector_row["id"])
    failed = await _stored(engine, connector_row)
    assert failed["last_sync"] is None
    assert failed["checkpoint"]["completed_through"] == {}, "a failed search must never be labelled completed"
    assert _query_time(failed["checkpoint"]["pending_from"]["alerts"]) <= _query_time(_Primary.documents[0]["_source"]["@timestamp"])

    # Twenty minutes is below the scheduler's existing 30-minute outage
    # backfill trigger and outside a fresh 5-minute query plus 15-minute overlap.
    _Clock.current += timedelta(minutes=20)
    _Primary.failure = None
    ingest = IngestClient(endpoints["ingest"], service_token="fixture-service-token")
    try:
        restarted = ConnectorScheduler(engine=engine, ingest_client=ingest, vault=vault)
        await restarted._poll_one(connector_id=connector_row["id"])
    finally:
        await ingest.aclose()
    assert len(_received()) == 1
    recovered = await _stored(engine, connector_row)
    assert recovered["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()
    assert "alerts" not in recovered["checkpoint"]["pending_from"]


async def test_failover_restarts_the_same_window_without_mixing_partial_pages(scheduler, engine, connector_row, endpoints) -> None:  # noqa: ANN001
    _seed(1001)
    _Secondary.documents = copy.deepcopy(_Primary.documents)
    _Primary.failure, _Primary.fail_page = 503, 2
    await _configure(engine, connector_row, indexer_urls=endpoints["secondary"])

    await scheduler._poll_one(connector_id=connector_row["id"])

    assert len(_received()) == 1001
    assert len({event["external_id"] for event in _received()}) == 1001
    assert _Primary.searches[0]["body"] == _Secondary.searches[0]["body"]
    assert _Secondary.requests[0]["path"] == "/wazuh-alerts-*/_search", "a cursor cannot be resumed on a different endpoint"
    assert _Primary.cleared == [_Primary.scroll_id]
    assert _Secondary.cleared == [_Secondary.scroll_id]
    assert (await _stored(engine, connector_row))["health_status"] == "healthy"


async def test_authentication_failure_does_not_probe_another_endpoint(scheduler, engine, connector_row, endpoints) -> None:  # noqa: ANN001
    _seed(1)
    _Secondary.documents = copy.deepcopy(_Primary.documents)
    _Primary.failure = 401
    await _configure(engine, connector_row, indexer_urls=endpoints["secondary"])
    await scheduler._poll_one(connector_id=connector_row["id"])
    assert _Secondary.requests == []
    assert _received() == []
    assert (await _stored(engine, connector_row))["health_status"] == "unhealthy"


async def test_inventory_beyond_the_writer_cap_is_completely_persisted(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    from sqlalchemy import text

    _seed(1, vulnerability_total=2001)
    await _configure(engine, connector_row, vuln_mode="inventory")
    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row)
    assert row["events_ingested"] == 8
    assert row["checkpoint"]["completed_through"] == {"alerts": _Clock.current.isoformat(), "vulnerabilities": _Clock.current.isoformat()}
    async with engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": connector_row["tenant_id"]}
        )
    assert count == 2001, "pagination must not move loss to the writer's 2000-finding transaction cap"


async def test_inventory_page_failure_does_not_inherit_alert_progress(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    from sqlalchemy import text

    _seed(1, vulnerability_total=1001)
    await _configure(engine, connector_row, vuln_mode="inventory")
    _Primary.failure, _Primary.fail_page, _Primary.fail_stream = 503, 2, "vulnerabilities"
    await scheduler._poll_one(connector_id=connector_row["id"])

    row = await _stored(engine, connector_row)
    assert len(_received()) == 1, "inventory failure is isolated from the successful alert stream"
    assert row["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()
    assert row["checkpoint"]["completed_through"]["vulnerabilities"] == connector_row["checkpoint"]["completed_through"]["vulnerabilities"]
    async with engine.connect() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": connector_row["tenant_id"]})
            == 0
        )
    _Primary.failure = None
    _Clock.current += timedelta(hours=2)
    await scheduler._poll_one(connector_id=connector_row["id"])
    async with engine.connect() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": connector_row["tenant_id"]})
            == 1001
        )
    assert (await _stored(engine, connector_row))["checkpoint"]["completed_through"]["vulnerabilities"] == _Clock.current.isoformat()


async def test_inventory_database_rejection_keeps_its_checkpoint_until_every_chunk_commits(scheduler, engine, connector_row) -> None:  # noqa: ANN001
    from sqlalchemy import text

    _seed(1, vulnerability_total=2001)
    # JSON can carry this string, but PostgreSQL TEXT cannot store a NUL.
    # The last transaction really fails at the database; sync_findings is
    # neither patched nor replaced by a mock reporting success.
    broken = _Primary.documents[-1]["_source"]["data"]["vulnerability"]
    real_cve = broken["cve"]
    broken["cve"] = "CVE-2026-\x00invalid"
    await _configure(engine, connector_row, vuln_mode="inventory")
    await scheduler._poll_one(connector_id=connector_row["id"])
    row = await _stored(engine, connector_row)
    assert row["checkpoint"]["completed_through"]["alerts"] == _Clock.current.isoformat()
    assert row["checkpoint"]["completed_through"]["vulnerabilities"] == connector_row["checkpoint"]["completed_through"]["vulnerabilities"]
    async with engine.connect() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": connector_row["tenant_id"]})
            == 2000
        )

    broken["cve"] = real_cve
    _Clock.current += timedelta(hours=2)
    await scheduler._poll_one(connector_id=connector_row["id"])
    async with engine.connect() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"), {"t": connector_row["tenant_id"]})
            == 2001
        )
    assert (await _stored(engine, connector_row))["checkpoint"]["completed_through"]["vulnerabilities"] == _Clock.current.isoformat()
