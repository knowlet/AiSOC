"""Agents runtime calls use the same outbound guard as the API explain path."""

from __future__ import annotations

import socket

import pytest
from app.llm.contract import safe_ainvoke, safe_chat_completions_request
from app.llm.factory import completions_url_for_base, sdk_base_url_for
from app.playbook.ssrf_guard import SSRFError, guard_runtime_llm_url
from langchain_core.messages import HumanMessage

_OPERATOR_BASE_ENV = ("OPENAI_BASE_URL", "LLM_BASE_URL", "LLM_GATEWAY_URL")


@pytest.fixture(autouse=True)
def _no_operator_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each case states the deployment endpoint it needs, starting from none."""
    for name in _OPERATOR_BASE_ENV:
        monkeypatch.delenv(name, raising=False)


def _resolve_as(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    def fake(_host: str, *_args: object, **_kwargs: object) -> list:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, 0, 0, 0) if family is socket.AF_INET6 else (address, 0)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    monkeypatch.setattr("app.playbook.ssrf_guard.socket.getaddrinfo", fake)


class _Model:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.calls = 0

    async def ainvoke(self, *_args: object, **_kwargs: object) -> object:
        self.calls += 1
        return object()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:11434/v1",
        "http://[::1]/v1",
        "http://169.254.169.254/v1",
        "http://169.254.1.1/v1",
        "http://metadata.google.internal/computeMetadata/v1",
    ],
)
async def test_langchain_calls_do_not_reach_a_blocked_base(base_url: str) -> None:
    model = _Model(base_url)
    with pytest.raises(SSRFError):
        await safe_ainvoke(model, [HumanMessage(content="Explain this alert.")])
    assert model.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "fe80::1", "fd00:ec2::254", "100.100.100.200"])
async def test_a_dns_name_resolving_to_a_blocked_address_is_refused(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    _resolve_as(monkeypatch, address)
    model = _Model("http://evil.example/v1")
    with pytest.raises(SSRFError):
        await safe_ainvoke(model, [HumanMessage(content="Explain this alert.")])
    assert model.calls == 0


@pytest.mark.asyncio
async def test_allowlisted_metadata_resolution_is_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "evil.example")
    _resolve_as(monkeypatch, "169.254.169.254")
    model = _Model("http://evil.example/api")
    with pytest.raises(SSRFError):
        await safe_ainvoke(model, [HumanMessage(content="Explain this alert.")])
    assert model.calls == 0


@pytest.mark.asyncio
async def test_raw_http_completions_use_the_same_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    posts: list[str] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def post(self, url: str, **_kwargs: object) -> object:
            posts.append(url)
            raise AssertionError(url)

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="local",
            messages=[{"role": "user", "content": "Explain this alert."}],
            url="http://169.254.169.254/v1/chat/completions",
        )
    assert posts == []


def test_an_api_base_matches_the_sdk_builder() -> None:
    base = "https://gateway.example/api"
    assert completions_url_for_base(base) == "https://gateway.example/api/chat/completions"
    assert sdk_base_url_for(base).rstrip("/") + "/chat/completions" == completions_url_for_base(base)
    assert "/v1" not in completions_url_for_base(base)
    assert sdk_base_url_for("http://litellm:4000/v1") == "http://litellm:4000/v1"


# ---------------------------------------------------------------------------
# The deployment's own endpoint is configuration, not a tenant destination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("env_name", _OPERATOR_BASE_ENV)
async def test_the_deployments_own_loopback_endpoint_is_still_called(monkeypatch: pytest.MonkeyPatch, env_name: str) -> None:
    # The live smoke run and the recorded replay gateway both point the
    # deployment at a loopback model server through these variables.
    monkeypatch.setenv(env_name, "http://127.0.0.1:11434/v1")
    model = _Model("http://127.0.0.1:11434/v1")
    await safe_ainvoke(model, [HumanMessage(content="Explain this alert.")])
    assert model.calls == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:4000/v1/chat/completions",
        "http://localhost:4000/v1",
        "https://127.0.0.1:11434/v1",
        "http://[::1]:11434/v1",
    ],
)
def test_another_loopback_origin_is_refused_beside_a_loopback_deployment(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    # Only the configured scheme, host and port are exempt. A tenant route to
    # a different service on the same host is what the guard exists to stop.
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
    with pytest.raises(SSRFError):
        guard_runtime_llm_url(url)


def test_a_metadata_deployment_endpoint_is_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://169.254.169.254/v1")
    with pytest.raises(SSRFError):
        guard_runtime_llm_url("http://169.254.169.254/v1/chat/completions")


@pytest.mark.parametrize("address", ["169.254.169.254", "fd00:ec2::254", "100.100.100.200"])
def test_a_deployment_endpoint_name_resolving_to_metadata_is_refused(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    # The exemption skips the shared classification, and with it the lookup.
    # A configured name must still be resolved and checked for metadata.
    monkeypatch.setenv("LLM_BASE_URL", "http://models.internal:8000/v1")
    _resolve_as(monkeypatch, address)
    with pytest.raises(SSRFError):
        guard_runtime_llm_url("http://models.internal:8000/v1/chat/completions")


@pytest.mark.asyncio
async def test_the_guard_does_not_run_on_the_event_loop_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    # The guard calls getaddrinfo. On the loop thread a slow lookup stalls
    # every other task on the worker until DNS answers.
    import threading

    from app.llm import contract

    seen: list[int] = []

    def record(url: str) -> str:
        seen.append(threading.get_ident())
        return url

    monkeypatch.setattr(contract, "guard_runtime_llm_url", record)
    model = _Model("http://10.0.0.5:8000/v1")
    await safe_ainvoke(model, [HumanMessage(content="Explain this alert.")])
    assert model.calls == 1
    assert seen and threading.get_ident() not in seen
