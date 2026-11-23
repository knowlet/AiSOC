"""Runtime LLM calls refuse loopback, link-local and metadata, including DNS.

Saving a credential checks URL shape. The connection probe checks the
outbound guard. Explain used to skip that guard, so a keyless local or
custom route could POST alert JSON at 127.0.0.1, 169.254.169.254, or a
name that resolves there. The guard now runs inside the shared
completions request, which is the call explain makes.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from app.services.llm_resolver import LlmConfig
from app.services.llm_safety import safe_chat_completions_request


class _Recorder:
    def __init__(self) -> None:
        self.posts: list[str] = []

    async def __aenter__(self) -> _Recorder:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def post(self, url: str, **_kwargs: object) -> httpx.Response:
        self.posts.append(url)
        body = {
            "choices": [{"message": {"content": "summary"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))


def _config(base: str) -> LlmConfig:
    return LlmConfig(
        allowed=True,
        base_url=base,
        model="local",
        api_key=None,
        source="tenant",
        reason="",
    )


def _alert() -> Any:
    return SimpleNamespace(
        title="Suspicious sign-in",
        severity="high",
        category="identity",
        connector_type="okta",
        description="A user signed in from an unfamiliar network.",
        tags=["signin"],
    )


def _resolve_as(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, str]) -> None:
    def getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[object]:
        ip = mapping[host]
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr("app._vendor.ssrf_guard.socket.getaddrinfo", getaddrinfo)


@pytest.fixture
def posts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    recorder = _Recorder()
    monkeypatch.setattr("app.services.llm_safety.httpx.AsyncClient", lambda *a, **k: recorder)
    monkeypatch.delenv("AISOC_SSRF_ALLOW_HOSTS", raising=False)
    monkeypatch.delenv("AISOC_SSRF_EXTRA_BLOCKED_HOSTS", raising=False)
    return recorder.posts


_BLOCKED = [
    "http://127.0.0.1:9/v1",
    "http://[::1]/v1",
    "http://169.254.1.1/latest",
    "http://169.254.169.254/latest/meta-data/",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("base", _BLOCKED)
async def test_explain_does_not_post_alert_json_at_a_blocked_address(base: str, posts: list[str]) -> None:
    from app.services.alert_explain import _call_llm_for_summary

    # Attribute bags, not ORM rows: the call only reads fields, and building
    # an Alert needs a session this test does not open.
    explain = cast(Any, _call_llm_for_summary)
    result = await explain(
        alert=_alert(),
        rule_lineage=SimpleNamespace(rule_name=None),
        mitre_techniques=[],
        fp=SimpleNamespace(fp_rate=0.0, sample_size=0, lookback_days=30, scope="rule"),
        llm_config=_config(base),
    )

    assert posts == []
    assert result.text is None
    assert result.error
    assert "llm_contract" not in result.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "ip"),
    [
        ("loop.example", "127.0.0.1"),
        ("link.example", "169.254.1.1"),
        ("meta.example", "169.254.169.254"),
    ],
)
async def test_explain_does_not_post_when_the_name_resolves_to_a_blocked_address(
    name: str,
    ip: str,
    monkeypatch: pytest.MonkeyPatch,
    posts: list[str],
) -> None:
    from app.services.alert_explain import _call_llm_for_summary

    _resolve_as(monkeypatch, {name: ip})
    explain = cast(Any, _call_llm_for_summary)
    result = await explain(
        alert=_alert(),
        rule_lineage=SimpleNamespace(rule_name=None),
        mitre_techniques=[],
        fp=SimpleNamespace(fp_rate=0.0, sample_size=0, lookback_days=30, scope="rule"),
        llm_config=_config(f"http://{name}/v1"),
    )

    assert posts == []
    assert result.text is None
    assert result.error
    assert "llm_contract" not in result.error


@pytest.mark.asyncio
async def test_a_private_model_host_is_still_called(posts: list[str]) -> None:
    """RFC1918 stays allowed. The webhook guard, which refuses it, is the wrong policy."""
    from app.services.alert_explain import _call_llm_for_summary

    explain = cast(Any, _call_llm_for_summary)
    result = await explain(
        alert=_alert(),
        rule_lineage=SimpleNamespace(rule_name=None),
        mitre_techniques=[],
        fp=SimpleNamespace(fp_rate=0.0, sample_size=0, lookback_days=30, scope="rule"),
        llm_config=_config("http://10.1.2.3/v1"),
    )

    assert posts == ["http://10.1.2.3/v1/chat/completions"]
    assert result.text == "summary"


@pytest.mark.asyncio
async def test_the_shared_request_refuses_before_its_client_posts(posts: list[str]) -> None:
    from app._vendor.ssrf_guard import SSRFError

    with pytest.raises(SSRFError):
        await safe_chat_completions_request(
            api_key="aisoc-no-auth",
            model="m",
            messages=[{"role": "user", "content": "Summarise this alert."}],
            url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        )
    assert posts == []
