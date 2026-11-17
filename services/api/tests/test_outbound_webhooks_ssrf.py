"""Outbound webhook destinations may not point inside the deployment.

GHSA-898c-wxrw-hx6c (part 2). The delivery worker POSTs the alert payload to
the stored URL and records ``last_status_code`` / ``last_error``, so an
internal destination (cloud metadata, loopback, the compose service names,
RFC 1918) makes the API a request proxy into its own network with a response
oracle. The create model checked only the scheme, the update model checked
nothing at all (a destination saved as ``https://partner`` could be edited to
``file://`` or to 169.254.169.254 afterwards), and delivery never re-checked —
so a hostname that resolved publicly at registration could rebind to an
internal address at send time.

The API already vendors ``app._vendor.ssrf_guard.validate_outbound_url``; this
suite pins that both request models and the delivery path use it. Private
ranges stay refused unless ``AISOC_SSRF_ALLOW_PRIVATE`` says otherwise, for an
on-prem receiver — the same posture ``destinations.py`` already takes.
"""

from __future__ import annotations

import socket
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1.endpoints.outbound_webhooks import WebhookCreate, WebhookUpdate
from app.services import outbound_webhooks as svc
from pydantic import ValidationError

INTERNAL = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:5432/",
    "http://localhost:8000/api/v1/admin/users",
    "http://[::1]:8000/",
    "http://0.0.0.0:8000/",
    "http://2130706433/",
    "http://10.0.0.5/",
]


@pytest.fixture
def webhook_dns(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> list[str]:
    """Control DNS answers without bypassing either request model's SSRF guard."""
    addresses: tuple[str, ...] | None = getattr(request, "param", ("93.184.216.34", "2606:4700:4700::1111"))
    resolved: list[str] = []

    def resolve(host: str, port: int | None, *, type: int) -> list[tuple[Any, ...]]:
        assert host == "example.com", f"unexpected test DNS host: {host!r}"
        assert port is None and type == socket.SOCK_STREAM
        resolved.append(host)
        if addresses is None:
            raise socket.gaierror(socket.EAI_NONAME, "fixture hostname has no DNS records")
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0, 0, 0))
            if ":" in address
            else (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))
            for address in addresses
        ]

    monkeypatch.delenv("AISOC_SSRF_ALLOW_PRIVATE", raising=False)
    monkeypatch.delenv("AISOC_SSRF_ALLOW_HOSTS", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    return resolved


@pytest.mark.parametrize("url", INTERNAL)
def test_create_refuses_internal_destinations(url: str) -> None:
    with pytest.raises(ValidationError):
        WebhookCreate(name="x", url=url, event_types=["alert.created"])


@pytest.mark.parametrize("url", [*INTERNAL, "file:///etc/passwd"])
def test_update_refuses_what_create_refuses(url: str) -> None:
    with pytest.raises(ValidationError):
        WebhookUpdate(url=url)


def test_update_without_a_url_is_fine() -> None:
    assert WebhookUpdate(name="renamed").url is None


@pytest.mark.parametrize("model", [WebhookCreate, WebhookUpdate], ids=["create", "update"])
def test_a_public_destination_is_still_accepted(webhook_dns: list[str], model: type[WebhookCreate] | type[WebhookUpdate]) -> None:
    """The guard must not refuse the legitimate case, or the feature is dead."""
    created = model(name="partner", url="https://example.com/hook", event_types=["alert.created"])
    assert created.url == "https://example.com/hook"
    assert webhook_dns == ["example.com"]


@pytest.mark.parametrize("model", [WebhookCreate, WebhookUpdate], ids=["create", "update"])
@pytest.mark.parametrize(
    ("webhook_dns", "reason"),
    [
        pytest.param(("10.0.0.5",), "blocked address", id="private-ipv4"),
        pytest.param(("93.184.216.34", "10.0.0.5"), "blocked address", id="mixed-ipv4"),
        pytest.param(("fd00::1",), "blocked address", id="private-ipv6"),
        pytest.param(("93.184.216.34", "fd00::1"), "blocked address", id="mixed-ipv6"),
        pytest.param((), "no usable addresses", id="no-addresses"),
        pytest.param(None, "could not resolve hostname", id="unresolvable"),
    ],
    indirect=["webhook_dns"],
)
def test_dns_answers_still_pass_through_the_guard(
    webhook_dns: list[str], reason: str, model: type[WebhookCreate] | type[WebhookUpdate]
) -> None:
    with pytest.raises(ValidationError, match=reason):
        model(name="partner", url="https://example.com/hook", event_types=["alert.created"])
    assert webhook_dns == ["example.com"]


@pytest.mark.asyncio
async def test_delivery_refuses_an_internal_destination_without_sending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checked again at send time, not only at registration: DNS rebinding,
    and rows written before the registration check existed."""
    sent: list[str] = []

    class _Client:
        async def post(self, url: str, **_: object) -> None:
            sent.append(url)
            raise AssertionError("must not send")

    delivery = SimpleNamespace(
        id=uuid.uuid4(),
        attempts=0,
        status="pending",
        next_attempt_at=None,
        last_error="",
        last_status_code=None,
        event_type="alert.created",
        payload={},
    )
    webhook = SimpleNamespace(url="http://169.254.169.254/latest/meta-data/", secret=None)
    monkeypatch.setattr(svc, "_secret_for", lambda _w: "")
    monkeypatch.setattr(svc, "_body", lambda _d: b"{}")
    out = await svc.attempt_delivery(delivery, webhook, client=_Client())  # type: ignore[arg-type]
    assert sent == [], "the internal destination was contacted"
    assert out.status == "dead"
    assert "refused" in (out.last_error or "")
