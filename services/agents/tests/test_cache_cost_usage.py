"""Cache arithmetic and missing-data boundaries for investigation accounting."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.core.cost_telemetry import GATEWAY, LIST_PRICE_ESTIMATE, UNPRICED, CallRecord, _estimate_cost, describe_llm_call
from app.core.gateway_cost import extract_gateway_cost
from app.core.token_usage import extract_token_usage


def response(*, normalized=None, raw=None, headers=None, **metadata):
    return SimpleNamespace(
        usage_metadata=normalized,
        response_metadata={"token_usage": raw, "headers": headers, **metadata},
    )


def test_cache_read_discount_applies_only_to_the_cached_input_partition():
    # 2k input tokens include 1.5k cached tokens; the 10 output tokens are
    # separate. Standard GPT-4o mini list rates are USD/1k: .00015/.000075/.0006.
    assert _estimate_cost("openai/gpt-4o-mini", 2_000, 10, cache_read_tokens=1_500) == pytest.approx(0.0001935)
    assert _estimate_cost("gpt-4o", 1_000, 1_000) == pytest.approx(0.0125)


def test_cache_writes_use_the_reported_ttl_without_pricing_them_twice():
    rec = CallRecord(
        model="anthropic/claude-sonnet-4-6",
        prompt_tokens=1_200,
        completion_tokens=30,
        latency_ms=1,
        cache_read_tokens=700,
        cache_creation_tokens=400,
        cache_creation_5m_tokens=300,
        cache_creation_1h_tokens=100,
    )
    # 100 uncached, 700 read, 300 five-minute write, 100 one-hour write, 30 output.
    assert rec.cost_usd == pytest.approx(0.002685)
    assert rec.cost_source == LIST_PRICE_ESTIMATE
    # Estimated total must not masquerade as gateway-reported components.
    assert rec.cache_read_cost_usd is None and rec.cache_creation_cost_usd is None


@pytest.mark.parametrize(
    "model,details",
    [
        ("claude-3-5-sonnet-20241022", {"cache_read_tokens": 700}),
        ("claude-sonnet-4-6", {"cache_creation_tokens": 400}),
        ("claude-sonnet-4-6", {"cache_creation_tokens": 400, "cache_creation_5m_tokens": 400, "cache_creation_1h_tokens": 400}),
        ("gpt-4o-mini", {"cache_creation_tokens": 400, "cache_creation_5m_tokens": 400, "cache_creation_1h_tokens": 0}),
        ("gpt-4o-mini", {"cache_read_tokens": 1_300}),
        ("gpt-4o-mini", {"cache_read_tokens": -1}),
    ],
)
def test_unsupported_or_inconsistent_cache_rates_are_unpriced(model, details):
    assert _estimate_cost(model, 1_200, 30, **details) is None


@pytest.mark.parametrize("model", ["ollama/gpt-4o-mini", "bedrock/gpt-4o-mini", "azure/gpt-4o-mini", "vertex_ai/claude-sonnet-4-6"])
def test_other_platforms_do_not_inherit_direct_provider_prices(model):
    assert _estimate_cost(model, 1_000, 100) is None


def test_unknown_serving_model_does_not_fall_back_to_the_requested_models_price():
    rec = CallRecord(model="gpt-4o-mini", resolved_model="unpriced-serving-model", prompt_tokens=1_000, completion_tokens=100, latency_ms=1)
    assert rec.cost_source == UNPRICED and rec.cost_usd is None


def test_raw_cache_writes_survive_normalized_usage_and_reasoning_is_not_added():
    usage = extract_token_usage(
        response(
            normalized={"input_tokens": 1_200, "output_tokens": 30, "input_token_details": {"cache_read": 700}},
            raw={
                "prompt_tokens": 1_200,
                "completion_tokens": 30,
                "cache_creation_input_tokens": 400,
                "cache_read_input_tokens": 700,
                "completion_tokens_details": {"reasoning_tokens": 20},
                "prompt_tokens_details": {
                    "cached_tokens": 700,
                    "cache_creation_tokens": 400,
                    "cache_creation_token_details": {"ephemeral_5m_input_tokens": 300, "ephemeral_1h_input_tokens": 100},
                },
            },
        )
    )
    assert (usage.prompt_tokens, usage.completion_tokens) == (1_200, 30)
    assert (usage.cache_read_tokens, usage.cache_creation_tokens) == (700, 400)
    assert (usage.cache_creation_5m_tokens, usage.cache_creation_1h_tokens) == (300, 100)
    assert usage.supports_estimate


def test_missing_and_reported_zero_cache_usage_remain_distinct():
    missing = extract_token_usage(response(normalized={"input_tokens": 50, "output_tokens": 10}))
    zero = extract_token_usage(response(normalized={"input_tokens": 50, "output_tokens": 10, "input_token_details": {"cache_read": 0}}))
    assert missing.cache_read_tokens is None
    assert zero.cache_read_tokens == 0
    assert zero.cache_creation_tokens is None


@pytest.mark.parametrize("bad", [-1, "NaN", "Infinity", "not-a-count", True, [], {}, pytest.param("9" * 5_000, id="oversized-count")])
def test_bad_cache_counts_never_break_a_reply_or_create_a_full_price_estimate(bad):
    rec = describe_llm_call(
        response(raw={"prompt_tokens": 1_200, "completion_tokens": 30, "prompt_tokens_details": {"cached_tokens": bad}}),
        model="gpt-4o-mini",
        latency_ms=1,
    )
    assert rec is not None
    assert rec.cost_source == UNPRICED and rec.cost_usd is None


def test_impossible_cache_partition_keeps_gateway_total_but_rejects_bad_details():
    rec = describe_llm_call(
        response(
            raw={"prompt_tokens": 1_200, "completion_tokens": 30, "prompt_tokens_details": {"cached_tokens": 1_500}},
            headers={"x-litellm-response-cost": "0.02"},
        ),
        model="gpt-4o-mini",
        latency_ms=1,
    )
    assert rec is not None
    assert rec.cost_source == GATEWAY and rec.cost_usd == 0.02
    assert rec.cache_read_tokens is None


@pytest.mark.parametrize("raw", [{}, {"total_tokens": 100}, {"prompt_tokens": "bad", "completion_tokens": 20}])
def test_missing_split_does_not_become_a_free_or_input_only_estimate(raw):
    rec = describe_llm_call(response(raw=raw), model="gpt-4o-mini", latency_ms=1)
    assert rec is not None
    assert rec.cost_source == UNPRICED and rec.cost_usd is None


def test_service_tier_pricing_requires_the_gateway():
    rec = describe_llm_call(
        response(raw={"prompt_tokens": 1_000, "completion_tokens": 100}, service_tier="priority"),
        model="gpt-4o-mini",
        latency_ms=1,
    )
    assert rec is not None
    assert rec.cost_source == UNPRICED


def test_partial_write_ttl_without_a_total_cannot_be_priced_as_ordinary_input():
    rec = describe_llm_call(
        response(
            raw={
                "prompt_tokens": 1_000,
                "completion_tokens": 20,
                "prompt_tokens_details": {"cache_creation_token_details": {"ephemeral_1h_input_tokens": 900}},
            }
        ),
        model="claude-sonnet-4-6",
        latency_ms=1,
    )
    assert rec is not None
    assert rec.cost_source == UNPRICED and rec.cost_usd is None


@pytest.mark.parametrize("side", ["input", "output"])
def test_audio_usage_does_not_inherit_text_token_prices(side):
    rec = describe_llm_call(
        response(normalized={"input_tokens": 1_000, "output_tokens": 100, f"{side}_token_details": {"audio": 100}}),
        model="gpt-4o",
        latency_ms=1,
    )
    assert rec is not None
    assert rec.cost_source == UNPRICED and rec.cost_usd is None


@pytest.mark.parametrize("bad", ["NaN", "inf", "-1", "bad"])
def test_invalid_cache_cost_headers_do_not_poison_a_valid_gateway_total(bad):
    cost = extract_gateway_cost(response(headers={"x-litellm-response-cost": "0.02", "x-litellm-response-cost-cache-read": bad}))
    assert cost is not None
    assert cost.cost_usd == 0.02
    assert cost.cache_read_cost_usd is None


def test_explicit_zero_cache_cost_header_is_a_reported_value():
    cost = extract_gateway_cost(response(headers={"x-litellm-response-cost-original": "0", "x-litellm-response-cost-cache-read": "0"}))
    assert cost is not None and cost.cost_usd == 0
    assert cost.cache_read_cost_usd == 0
    assert cost.cache_creation_cost_usd is None
