"""Investigator accounting through the real SDK and a loopback HTTP fixture.

The responses below are synthetic protocol fixtures, not provider invoices.
The investigator, safe invocation wrapper, SDK, HTTP transport and tracker are
real. One received completion must produce one booked call even though its
cost also appears in a stage's audit event.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from app.core.cost_telemetry import CostTracker
from app.investigator.forensic_agent import _llm_forensic
from app.investigator.recon_agent import _llm_recon
from app.investigator.report_writer_agent import run_report_writer
from app.investigator.responder_agent import _llm_responder
from app.investigator.state import InvestigatorState, StepKind
from app.llm import contract
from app.llm.factory import llm_override

PROMPT_TOKENS = 1_200
COMPLETION_TOKENS = 30
CACHE_READ_TOKENS = 700
CACHE_CREATION_TOKENS = 400
RESPONSE_COST = 0.0123
CACHE_READ_COST = 0.001
CACHE_CREATION_COST = 0.004
SERVING_MODEL = "anthropic/claude-3-5-sonnet-20241022"


@dataclass
class SyntheticGateway:
    base_url: str = ""
    requests: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(
        default_factory=lambda: {
            "x-litellm-model-name": SERVING_MODEL,
            "x-litellm-response-cost": str(RESPONSE_COST),
            "x-litellm-response-cost-original": str(RESPONSE_COST),
            "x-litellm-response-cost-input": "0.002",
            "x-litellm-response-cost-output": "0.0053",
            "x-litellm-response-cost-cache-read": str(CACHE_READ_COST),
            "x-litellm-response-cost-cache-creation": str(CACHE_CREATION_COST),
        }
    )


@pytest.fixture
def synthetic_gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[SyntheticGateway]:
    gateway = SyntheticGateway()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — standard HTTP handler method
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            gateway.requests.append(payload)
            sequence = len(gateway.requests)
            body = json.dumps(
                {
                    "id": f"chatcmpl-synthetic-cost-{sequence}",
                    "object": "chat.completion",
                    "created": 1,
                    "model": SERVING_MODEL,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": '{"summary": "Synthetic accounting fixture."}'},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": PROMPT_TOKENS,
                        "completion_tokens": COMPLETION_TOKENS,
                        "total_tokens": PROMPT_TOKENS + COMPLETION_TOKENS,
                        "cache_read_input_tokens": CACHE_READ_TOKENS,
                        "cache_creation_input_tokens": CACHE_CREATION_TOKENS,
                        "prompt_tokens_details": {
                            "cached_tokens": CACHE_READ_TOKENS,
                            "cache_creation_tokens": CACHE_CREATION_TOKENS,
                            "cache_creation_token_details": {
                                "ephemeral_5m_input_tokens": 300,
                                "ephemeral_1h_input_tokens": 100,
                            },
                        },
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-litellm-call-id", f"synthetic-call-{sequence}")
            for name, value in gateway.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    gateway.base_url = f"http://127.0.0.1:{server.server_port}/v1"
    # All requests in this fixture target loopback. An ambient SOCKS proxy
    # must not turn a local transport test into an external network request.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    for role in ("RECON", "INVESTIGATION", "REPORT"):
        monkeypatch.delenv(f"AISOC_MODEL_PIN_{role}", raising=False)
    monkeypatch.setenv("LLM_GATEWAY_URL", gateway.base_url)
    monkeypatch.setenv("OPENAI_BASE_URL", gateway.base_url)
    monkeypatch.setenv("LITELLM_MASTER_KEY", "synthetic-test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    monkeypatch.setattr(contract, "_RESPONSE_CACHE_ENABLED", True)
    try:
        yield gateway
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive(), "loopback provider fixture did not stop"


async def run_stage(stage: str, state: InvestigatorState) -> InvestigatorState:
    if stage == "report":
        return InvestigatorState.from_dict(await run_report_writer(state.to_dict()))
    invoke = {"recon": _llm_recon, "forensic": _llm_forensic, "responder": _llm_responder}[stage]
    result = await invoke(state)
    assert result.get("summary") == "Synthetic accounting fixture."
    return state


@pytest.mark.parametrize("stage", ["recon", "forensic", "responder", "report"])
async def test_each_stage_books_one_call_per_http_response(synthetic_gateway: SyntheticGateway, stage: str) -> None:
    state = InvestigatorState(case_id=f"synthetic-cost-{stage}", alert_summary="Synthetic cost-accounting test.")
    async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
        state = await run_stage(stage, state)

    responses = [entry for entry in state.audit_log if entry.kind == StepKind.LLM_RESPONSE]
    assert len(synthetic_gateway.requests) == len(responses) == 1
    assert not [entry for entry in state.audit_log if entry.kind == StepKind.ERROR]
    assert responses[0].metadata["cost_usd"] == pytest.approx(RESPONSE_COST)
    assert responses[0].metadata["cost_source"] == "gateway"
    assert tracker.calls_made == 1, "the wrapper and stage audit must not book the same completion twice"
    assert tracker.prompt_tokens == PROMPT_TOKENS
    assert tracker.completion_tokens == COMPLETION_TOKENS
    assert tracker.measured_call_count == 1
    assert tracker.measured_cost_usd == pytest.approx(RESPONSE_COST)


async def test_sdk_cache_details_reach_the_tracker_without_increasing_prompt_total(synthetic_gateway: SyntheticGateway) -> None:
    state = InvestigatorState(case_id="synthetic-cache-cost", alert_summary="Synthetic cache-accounting test.")
    async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
        await run_stage("recon", state)

    assert len(synthetic_gateway.requests) == 1
    summary = tracker.summary()
    assert summary["prompt_tokens"] == PROMPT_TOKENS
    assert summary["cache_read_tokens"] == CACHE_READ_TOKENS
    assert summary["cache_creation_tokens"] == CACHE_CREATION_TOKENS
    assert summary["cache_read_cost_usd"] == pytest.approx(CACHE_READ_COST)
    assert summary["cache_creation_cost_usd"] == pytest.approx(CACHE_CREATION_COST)
    assert summary["measured_cost_usd"] == pytest.approx(RESPONSE_COST), "cache components are already inside the total"
    assert tracker._records[0].cache_creation_5m_tokens == 300
    assert tracker._records[0].cache_creation_1h_tokens == 100


async def test_local_response_cache_does_not_book_another_provider_call(synthetic_gateway: SyntheticGateway) -> None:
    state = InvestigatorState(case_id="synthetic-response-cache", alert_summary="Synthetic repeated request.")
    async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
        await run_stage("recon", state)
        await run_stage("recon", state)

    assert len(synthetic_gateway.requests) == 1, "the second identical request must be served by the local response cache"
    assert tracker.calls_made == tracker.measured_call_count == 1
    assert tracker.unpriced_call_count == 0, "a cache hit did not place an unpriced provider call"
    assert tracker.total_tokens == PROMPT_TOKENS + COMPLETION_TOKENS
    assert tracker.measured_cost_usd == pytest.approx(RESPONSE_COST)


async def test_two_uncached_report_requests_are_both_booked(synthetic_gateway: SyntheticGateway) -> None:
    state = InvestigatorState(case_id="synthetic-report-retry", alert_summary="Synthetic repeated report request.")
    async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
        await run_stage("report", state)
        await run_stage("report", state)

    assert len(synthetic_gateway.requests) == 2, "report requests bypass the local text-only cache"
    assert tracker.calls_made == tracker.measured_call_count == 2
    assert tracker.total_tokens == 2 * (PROMPT_TOKENS + COMPLETION_TOKENS)
    assert tracker.measured_cost_usd == pytest.approx(2 * RESPONSE_COST)


async def test_missing_cache_cost_headers_are_not_reported_as_zero(synthetic_gateway: SyntheticGateway) -> None:
    synthetic_gateway.headers.pop("x-litellm-response-cost-cache-read")
    synthetic_gateway.headers.pop("x-litellm-response-cost-cache-creation")
    state = InvestigatorState(case_id="synthetic-missing-cost", alert_summary="Synthetic incomplete cost breakdown.")
    async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
        await run_stage("recon", state)

    assert len(synthetic_gateway.requests) == 1
    summary = tracker.summary()
    assert summary["cache_read_token_call_count"] == summary["cache_creation_token_call_count"] == 1
    assert summary["cache_read_cost_call_count"] == summary["cache_creation_cost_call_count"] == 0
    assert summary["cache_read_cost_usd"] is None
    assert summary["cache_creation_cost_usd"] is None
    assert summary["measured_cost_usd"] == pytest.approx(RESPONSE_COST)


async def test_byok_call_is_not_booked_again_under_the_role_alias(synthetic_gateway: SyntheticGateway) -> None:
    state = InvestigatorState(case_id="synthetic-byok-cost", alert_summary="Synthetic tenant override.")
    with llm_override(api_key="synthetic-tenant-key", base_url=synthetic_gateway.base_url, model="tenant-selected-model"):
        async with CostTracker(run_id=str(state.run_id), tenant_id="synthetic-tenant", persist=False) as tracker:
            await run_stage("recon", state)

    assert len(synthetic_gateway.requests) == 1
    assert synthetic_gateway.requests[0]["model"] == "tenant-selected-model"
    assert tracker.summary()["models"] == ["tenant-selected-model"]
    assert tracker.measured_call_count == 1
    assert tracker.measured_cost_usd == pytest.approx(RESPONSE_COST)
