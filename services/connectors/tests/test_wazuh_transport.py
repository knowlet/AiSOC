"""Real HTTP/TLS sockets with synthetic OpenSearch protocol fixtures.

These tests exercise httpx, page bodies, credentials and node changes. They
do not claim a live Wazuh or OpenSearch integration result.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from app.connectors.wazuh import WazuhConnector

_AUTH = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()


def _hits(count: int) -> list[dict[str, Any]]:
    timestamp = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
    return [
        {
            "_id": f"document-{number}",
            "_index": "wazuh-alerts-protocol-fixture",
            "_source": {
                "@timestamp": timestamp,
                "rule": {"id": "100100", "level": 12, "description": "Synthetic transport event"},
                "agent": {"id": "001", "name": "fixture-host"},
                "full_log": f"Synthetic transport record {number}",
            },
        }
        for number in range(count)
    ]


@dataclass
class _Node:
    rows: list[dict[str, Any]]
    failure: int | str | None = None
    url: str = ""
    requests: list[dict[str, Any]] = field(default_factory=list)
    cleared: list[str] = field(default_factory=list)
    cursor: str | None = None
    offset: int = 0
    page_number: int = 0


@contextmanager
def _node(rows: list[dict[str, Any]], *, failure: int | str | None = None, tls: ssl.SSLContext | None = None) -> Iterator[_Node]:
    state = _Node(rows=rows, failure=failure)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def _reply(self, payload: dict[str, Any], status: int = 200) -> None:
            content = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _request(self) -> tuple[str, dict[str, Any]]:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            url = urlsplit(self.path)
            state.requests.append(
                {
                    "method": self.command,
                    "path": url.path,
                    "params": parse_qs(url.query),
                    "body": body,
                    "auth": self.headers.get("Authorization"),
                }
            )
            return url.path, body

        def do_POST(self) -> None:  # noqa: N802
            path, body = self._request()
            if self.headers.get("Authorization") != _AUTH:
                self._reply({"error": "synthetic authentication failure"}, 401)
                return
            if path == "/wazuh-alerts-*/_search":
                state.offset = 0
                state.page_number = 0
            elif path == "/_search/scroll":
                if body.get("scroll_id") != state.cursor:
                    self._reply({"error": "unknown synthetic cursor"}, 404)
                    return
                if state.failure == "disconnect":
                    self.close_connection = True
                    return
                if isinstance(state.failure, int):
                    self._reply({"error": "synthetic page failure"}, state.failure)
                    return
            else:
                self._reply({"error": "unknown fixture path"}, 404)
                return
            page = state.rows[state.offset : state.offset + 1000]
            state.offset += len(page)
            state.page_number += 1
            state.cursor = f"cursor-{state.page_number}"
            self._reply(
                {
                    "_scroll_id": state.cursor,
                    "timed_out": False,
                    "_shards": {"total": 2, "successful": 2, "skipped": 1, "failed": 0},
                    "hits": {"hits": page},
                }
            )

        def do_DELETE(self) -> None:  # noqa: N802
            path, body = self._request()
            if self.headers.get("Authorization") != _AUTH:
                self._reply({"error": "synthetic authentication failure"}, 401)
                return
            cursor = state.cursor
            if path != "/_search/scroll" or cursor is None or body.get("scroll_id") != [cursor]:
                self._reply({"error": "unknown synthetic cursor"}, 404)
                return
            state.cleared.append(cursor)
            state.cursor = None
            self._reply({"succeeded": True, "num_freed": 1})

        def do_GET(self) -> None:  # noqa: N802
            self._request()
            self._reply({"status": "green"})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    state.url = f"{'https' if tls is not None else 'http'}://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture(autouse=True)
def allow_fixture_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exact host exception for this process's local protocol fixtures.
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1001, 2501])
async def test_socket_poll_drains_tied_timestamp_pages_and_clears_latest_cursor(count: int) -> None:
    rows = _hits(count)
    with _node(rows) as node:
        connector = WazuhConnector(node.url, "fixture-user", "fixture-password", vuln_mode="alerts")
        events = await connector.fetch_alerts()

    assert [event["alert_id"] for event in events] == [row["_id"] for row in rows]
    assert len({event["external_id"] for event in events}) == count
    assert all(request["auth"] == _AUTH for request in node.requests)
    assert node.requests[0]["params"] == {"scroll": ["1m"], "allow_partial_search_results": ["false"]}
    assert node.cleared == [f"cursor-{(count + 999) // 1000 + 1}"]
    assert node.cursor is None
    checkpoint = connector.get_checkpoint()
    assert checkpoint is not None
    assert checkpoint["completed_through"]["alerts"] == node.requests[0]["body"]["query"]["bool"]["must"][0]["range"]["@timestamp"]["lte"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [503, "disconnect"])
async def test_socket_failover_restarts_the_same_window_without_partial_duplicates(failure: int | str) -> None:
    rows = _hits(1001)
    with _node(rows, failure=failure) as primary, _node(rows) as secondary:
        connector = WazuhConnector(primary.url, "fixture-user", "fixture-password", indexer_urls=secondary.url, vuln_mode="alerts")
        events = await connector.fetch_alerts()

    assert len(events) == 1001
    assert len({event["external_id"] for event in events}) == 1001
    assert primary.requests[0]["body"] == secondary.requests[0]["body"]
    assert primary.cleared == ["cursor-1"]
    assert secondary.cleared == ["cursor-3"]
    assert all(request["auth"] == _AUTH for request in primary.requests + secondary.requests)


@pytest.mark.asyncio
async def test_socket_later_page_failure_preserves_checkpoint_and_clears_context() -> None:
    with _node(_hits(1001), failure=503) as node:
        connector = WazuhConnector(node.url, "fixture-user", "fixture-password", vuln_mode="alerts")
        with pytest.raises(RuntimeError, match="503"):
            await connector.fetch_alerts()

    assert connector.get_checkpoint() is None
    assert node.cleared == ["cursor-1"]


def _untrusted_certificate(tmp_path: Path) -> ssl.SSLContext:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Indexer fixture")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path, key_path = tmp_path / "fixture.pem", tmp_path / "fixture-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    return context


@pytest.mark.asyncio
async def test_real_certificate_validation_failure_is_not_bypassed_by_failover(tmp_path: Path) -> None:
    with _node([], tls=_untrusted_certificate(tmp_path)) as primary, _node([]) as secondary:
        connector = WazuhConnector(primary.url, "fixture-user", "fixture-password", indexer_urls=secondary.url)
        with pytest.raises(RuntimeError, match="TLS certificate validation"):
            await connector.fetch_alerts()
        result = await connector.test_connection()

    assert result["success"] is False
    assert "TLS certificate validation" in result["error"]
    assert secondary.requests == []
    assert connector.get_checkpoint() is None
