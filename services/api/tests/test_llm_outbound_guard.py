"""Runtime LLM calls refuse loopback, link-local and metadata destinations.

Saving a credential checks URL shape. The connection probe then applies
``validate_outbound_url(allow_private=True)``. Explain used to skip that
check, so a keyless local or custom route could POST alert JSON to
``169.254.169.254``. The guard now runs inside the one function every
runtime completion uses.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from app._vendor.ssrf_guard import SSRFError
from app.models.alert import Alert
from app.services.alert_explain import HistoricalFpRate, RuleLineage, _call_llm_for_summary
from app.services.llm_resolver import LlmConfig
from app.services.llm_safety import safe_chat_completions_request


def _alert() -> Alert:
    return cast(
        Alert,
        SimpleNamespace(
            title="Suspicious sign-in",
            severity="high",
            category="identity",
            connector_type="okta",
            description="A user signed in from a new country.",
            tags=["login"],
        ),
    )


def _lineage() -> RuleLineage:
    return RuleLineage(
        rule_id=None,
        rule_name=None,
        rule_description=None,
        rule_status=None,
        rule_severity=None,
        rule_confidence=None,
        rule_language=None,
        is_builtin=False,
        confidence="low",
        match_method="none",
    )


def _fp() -> HistoricalFpRate:
    return HistoricalFpRate(fp_rate=0.0, sample_size=0, false_positives=0, lookback_days=30, scope="rule", notes="")


class _RecordingClient:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.posts: list[str] = []

    async def __aenter__(self) -> _RecordingClient:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def post(self, url: str, **_kwargs: object) -> httpx.Response:
        self.posts.append(url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "should not be sent"}}], "usage": {}},
            request=httpx.Request("POST", url),
        )


def _resolve_as(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    def fake(_host: str, *_args: object, **_kwargs: object) -> list:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, 0, 0, 0) if family is socket.AF_INET6 else (address, 0)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    monkeypatch.setattr("app._vendor.ssrf_guard.socket.getaddrinfo", fake)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    posts: list[str] = []

    class _Client(_RecordingClient):
        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            posts.append(url)
            return await super().post(url, **kwargs)

    monkeypatch.setattr("app.services.llm_safety.httpx.AsyncClient", _Client)
    return posts


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1/v1",
        "http://127.0.0.1:11434",
        "http://[::1]/v1",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/v1",
        "http://169.254.1.1/v1",
        "http://169.254.170.2/v1",
        "http://metadata.google.internal/v1",
        "http://metadata.azure.com/v1",
    ],
)
async def test_literal_loopback_link_local_and_metadata_are_not_called(recorder: list[str], base_url: str) -> None:
    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="local",
            messages=[{"role": "user", "content": "Explain this alert."}],
            url=base_url + "/chat/completions",
        )
    assert recorder == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "::1", "169.254.169.254", "169.254.1.1", "fe80::1"],
)
async def test_a_dns_name_resolving_to_a_blocked_address_is_not_called(
    monkeypatch: pytest.MonkeyPatch, recorder: list[str], address: str
) -> None:
    _resolve_as(monkeypatch, address)
    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="local",
            messages=[{"role": "user", "content": "Explain this alert."}],
            url="http://evil.example/v1/chat/completions",
        )
    assert recorder == []


@pytest.mark.asyncio
async def test_an_allowlisted_name_that_resolves_to_metadata_is_still_refused(monkeypatch: pytest.MonkeyPatch, recorder: list[str]) -> None:
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "evil.example")
    _resolve_as(monkeypatch, "169.254.169.254")
    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="local",
            messages=[{"role": "user", "content": "Explain this alert."}],
            url="http://evil.example/v1/chat/completions",
        )
    assert recorder == []


@pytest.mark.asyncio
async def test_a_private_lan_host_is_still_called(recorder: list[str]) -> None:
    await safe_chat_completions_request(
        api_key="aisoc-no-auth",
        model="local",
        messages=[{"role": "user", "content": "Explain this alert."}],
        url="http://10.1.2.3:11434/v1/chat/completions",
    )
    assert recorder == ["http://10.1.2.3:11434/v1/chat/completions"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:9",
        "http://169.254.169.254",
        "http://169.254.1.1/v1",
        "http://[::1]:11434/v1",
    ],
)
async def test_explain_does_not_post_alert_json(monkeypatch: pytest.MonkeyPatch, recorder: list[str], base_url: str) -> None:
    result = await _call_llm_for_summary(
        alert=_alert(),
        rule_lineage=_lineage(),
        mitre_techniques=[],
        fp=_fp(),
        llm_config=LlmConfig(
            allowed=True,
            base_url=base_url,
            model="local",
            api_key=None,
            source="tenant",
            reason="",
        ),
    )
    assert result.text is None
    assert result.error
    assert recorder == []
    assert "should not be sent" not in (result.error or "")


@pytest.mark.asyncio
async def test_explain_does_not_post_when_the_name_resolves_to_metadata(monkeypatch: pytest.MonkeyPatch, recorder: list[str]) -> None:
    _resolve_as(monkeypatch, "169.254.169.254")
    result = await _call_llm_for_summary(
        alert=_alert(),
        rule_lineage=_lineage(),
        mitre_techniques=[],
        fp=_fp(),
        llm_config=LlmConfig(
            allowed=True,
            base_url="http://metadata.evil.example/v1",
            model="local",
            api_key=None,
            source="tenant",
            reason="",
        ),
    )
    assert result.text is None
    assert recorder == []


def test_the_guard_is_inside_the_shared_request_function() -> None:
    """A caller that builds the URL itself still passes through the guard."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "app/services/llm_safety.py").read_text(encoding="utf-8")
    guard = source.index("guard_runtime_llm_url(url)")
    post = source.index(".post(")
    assert guard < post
    explain = (Path(__file__).resolve().parents[1] / "app/services/alert_explain.py").read_text(encoding="utf-8")
    assert "safe_chat_completions_request" in explain
