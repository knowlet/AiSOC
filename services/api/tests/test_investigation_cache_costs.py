"""Cache components describe the gateway total; they never increase it."""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.api.v1.endpoints.investigations import ModelCostBreakdown, _aggregate_row, _fetch_model_costs
from app.services.cost_dashboard import (
    _PUBLIC_PRICING,
    CostRow,
    DashboardInputs,
    _impute_public_cost,
    _imputed_for_row,
    build_dashboard_from_rows,
)


def test_dashboard_uncached_rates_match_tracker_and_verified_prices():
    # Parse the other deploy unit's literal table without importing its runtime.
    tracker = Path(__file__).resolve().parents[2] / "agents/app/core/cost_telemetry.py"
    table = next(
        node.value
        for node in ast.parse(tracker.read_text()).body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "_PRICING"
    )
    assert _PUBLIC_PRICING == ast.literal_eval(table)
    assert _impute_public_cost("gpt-4o", 1000, 1000) == 0.0125
    assert _impute_public_cost("claude-sonnet-4-6", 1000, 1000) == 0.018


@pytest.mark.parametrize("model", ["azure/gpt-4o", "bedrock/claude-sonnet-4-6", "custom/gpt-4o-mini", "openai/nested/gpt-4o"])
def test_dashboard_does_not_apply_direct_provider_prices_to_other_platforms(model):
    assert _impute_public_cost(model, 1000, 1000) is None


def test_dashboard_unknown_serving_model_does_not_use_requested_model_price():
    row = CostRow(
        run_id="routing-regression",
        case_id="routing-regression",
        model="gpt-4o",
        resolved_model="deployment/unknown-model",
        prompt_tokens=1000,
        completion_tokens=1000,
        measured_cost_usd=0.02,
        measured_call_count=1,
        latency_ms=100,
        call_count=1,
        started_at=datetime(2026, 11, 24, tzinfo=UTC),
    )
    assert _imputed_for_row(row) is None


def _row() -> dict:
    return {
        "model": "aisoc-investigation",
        "resolved_model": "openai/gpt-4o-mini",
        "runs": 1,
        "calls": 3,
        "call_count": 3,
        "total_prompt_tokens": 10000,
        "total_completion_tokens": 500,
        "measured_cost_usd": 0.02,
        "measured_call_count": 3,
        "estimated_cost_usd": 0.0,
        "estimated_call_count": 0,
        "unpriced_call_count": 0,
        "total_latency_ms": 120,
        "total_cache_read_tokens": 8000,
        "total_cache_creation_tokens": 1000,
        "cache_read_token_call_count": 3,
        "cache_creation_token_call_count": 2,
        "cache_read_cost_usd": 0.0006,
        "cache_creation_cost_usd": 0.001,
        "cache_read_cost_call_count": 2,
        "cache_creation_cost_call_count": 1,
    }


class _Rows:
    def mappings(self):
        return self

    def all(self):
        return [_row()]


class _Session:
    async def execute(self, _query, _params):
        return _Rows()


def _assert_cache_components(body: dict) -> None:
    for key, value in _row().items():
        if "cache" in key:
            assert body[key] == value
    assert body["total_cost_usd"] == 0.02


@pytest.mark.asyncio
async def test_model_cost_detail_preserves_cache_components_without_adding_them():
    rows = await _fetch_model_costs(_Session(), uuid.uuid4())
    _assert_cache_components(rows[0].model_dump())


def test_cost_aggregate_preserves_cache_components_and_coverage():
    row = _aggregate_row(_row())
    _assert_cache_components(row.model_dump())
    assert row.avg_cost_per_run == 0.02


def test_legacy_model_cost_has_unknown_cache_coverage():
    row = ModelCostBreakdown(
        model="legacy",
        total_prompt_tokens=100,
        total_completion_tokens=10,
        total_cost_usd=0.1,
        total_latency_ms=20,
        call_count=1,
    ).model_dump()
    assert row["cache_read_token_call_count"] == 0
    assert row["cache_creation_token_call_count"] == 0
    assert row["cache_read_cost_call_count"] == 0
    assert row["cache_creation_cost_call_count"] == 0


def test_dashboard_keeps_gateway_total_and_omits_unsupported_cached_imputation():
    cached = CostRow(
        run_id="cache-regression",
        case_id="cache-regression",
        model="gpt-4o-mini",
        prompt_tokens=10000,
        completion_tokens=500,
        measured_cost_usd=0.02,
        latency_ms=120,
        call_count=3,
        started_at=datetime(2026, 11, 24, tzinfo=UTC),
        measured_call_count=3,
        **{key: value for key, value in _row().items() if "cache" in key},
    )
    dashboard = build_dashboard_from_rows(
        DashboardInputs(
            tenant_id=uuid.uuid4(),
            period_start=datetime(2026, 11, 23, tzinfo=UTC),
            period_end=datetime(2026, 11, 25, tzinfo=UTC),
            cost_rows=[cached],
        )
    )
    model = dashboard.by_model[0]
    _assert_cache_components(model.model_dump())
    assert dashboard.headline.total_cost_usd == 0.02
    assert model.imputed_is_estimable is False
    assert model.unpriced_tokens == 10500
    assert dashboard.byok_savings.imputed_is_estimable is False
