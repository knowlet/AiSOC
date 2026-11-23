"""Triage and explain refuse loopback, link-local and metadata before the call.

``safe_ainvoke`` is the path automatic triage uses. ``safe_chat_completions_request``
is the path agents explain uses. Both have to apply the same outbound
policy as the credential probe, including names that resolve to a
blocked address.
"""

from __future__ import annotations

import socket

import pytest
from app.llm.contract import safe_ainvoke, safe_chat_completions_request
from app.playbook.ssrf_guard import SSRFError


class _Model:
    def __init__(self, base: str) -> None:
        self.openai_api_base = base
        self.model_name = "tenant-model"
        self.calls = 0

    async def ainvoke(self, _messages, **_kwargs):  # noqa: ANN001
        self.calls += 1
        return type("Reply", (), {"content": "ok"})()


def _resolve_as(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, str]) -> None:
    def getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[object]:
        ip = mapping[host]
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr("app.playbook.ssrf_guard.socket.getaddrinfo", getaddrinfo)


@pytest.fixture(autouse=True)
def _clear_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_SSRF_ALLOW_HOSTS", raising=False)
    monkeypatch.delenv("AISOC_SSRF_EXTRA_BLOCKED_HOSTS", raising=False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base",
    [
        "http://127.0.0.1:9/v1",
        "http://[::1]/v1",
        "http://169.254.1.1/latest",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
async def test_triage_does_not_call_a_blocked_base(base: str) -> None:
    model = _Model(base)
    with pytest.raises(SSRFError):
        await safe_ainvoke(model, [{"role": "user", "content": "Summarise this alert title."}])
    assert model.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "ip"),
    [
        ("loop.example", "127.0.0.1"),
        ("link.example", "169.254.1.1"),
        ("meta.example", "169.254.169.254"),
    ],
)
async def test_triage_does_not_call_a_name_that_resolves_to_a_blocked_address(name: str, ip: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_as(monkeypatch, {name: ip})
    model = _Model(f"http://{name}/v1")
    with pytest.raises(SSRFError):
        await safe_ainvoke(model, [{"role": "user", "content": "Summarise this alert title."}])
    assert model.calls == 0


@pytest.mark.asyncio
async def test_a_private_model_host_is_still_called() -> None:
    model = _Model("http://10.1.2.3/v1")
    await safe_ainvoke(model, [{"role": "user", "content": "Summarise this alert title."}])
    assert model.calls == 1


@pytest.mark.asyncio
async def test_explain_http_refuses_metadata_before_post(monkeypatch: pytest.MonkeyPatch) -> None:
    posts: list[str] = []

    class _Client:
        def __init__(self, *_a: object, **_k: object) -> None:
            return None

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_a: object) -> bool:
            return False

        async def post(self, url: str, **_kwargs: object) -> object:
            posts.append(url)
            raise AssertionError("posted")

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="m",
            messages=[{"role": "user", "content": "Summarise this alert title."}],
            url="http://169.254.169.254/latest/meta-data/",
        )
    assert posts == []
