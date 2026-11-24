"""Real SDK HTTP completions persist once in the real PostgreSQL cost ledger.

The loopback endpoint returns explicitly synthetic provider responses. No
hosted model is called. Set AISOC_TEST_POSTGRES to a disposable database.
"""

from __future__ import annotations

import os
import uuid

import asyncpg
import pytest
from app.core import cost_telemetry
from app.investigator.state import InvestigatorState

from tests import test_investigation_cost_accounting as accounting
from tests.test_investigation_cost_accounting import (
    CACHE_CREATION_COST,
    CACHE_CREATION_TOKENS,
    CACHE_READ_COST,
    CACHE_READ_TOKENS,
    COMPLETION_TOKENS,
    PROMPT_TOKENS,
    RESPONSE_COST,
    SyntheticGateway,
    run_stage,
)

synthetic_gateway = accounting.synthetic_gateway
DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip().replace("postgresql+asyncpg://", "postgresql://")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES to a disposable PostgreSQL database"),
]


async def test_four_stage_http_calls_persist_once_with_cache_breakdown(
    synthetic_gateway: SyntheticGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = str(uuid.uuid4())
    tenant_id = f"synthetic-cost-{uuid.uuid4()}"
    monkeypatch.setenv("DATABASE_URL", DSN)
    monkeypatch.setattr(cost_telemetry, "_POOL", None)
    connection = await asyncpg.connect(DSN, timeout=5)
    try:
        state = InvestigatorState(case_id=f"synthetic-case-{run_id}", alert_summary="Synthetic persisted accounting test.")
        async with cost_telemetry.CostTracker(run_id=run_id, tenant_id=tenant_id):
            for stage in ("recon", "forensic", "responder", "report"):
                state = await run_stage(stage, state)

        assert len(synthetic_gateway.requests) == 4
        rows = await connection.fetch(
            "SELECT * FROM aisoc_run_costs WHERE run_id = $1 AND tenant_id = $2 ORDER BY model", run_id, tenant_id
        )
        assert {row["model"]: row["call_count"] for row in rows} == {
            "aisoc-recon": 1,
            "aisoc-investigation": 2,
            "aisoc-report": 1,
        }
        assert sum(row["total_prompt_tokens"] for row in rows) == 4 * PROMPT_TOKENS
        assert sum(row["total_completion_tokens"] for row in rows) == 4 * COMPLETION_TOKENS
        assert sum(row["measured_call_count"] for row in rows) == 4
        assert sum(row["total_cost_usd"] for row in rows) == pytest.approx(4 * RESPONSE_COST)
        assert sum(row["total_cache_read_tokens"] for row in rows) == 4 * CACHE_READ_TOKENS
        assert sum(row["total_cache_creation_tokens"] for row in rows) == 4 * CACHE_CREATION_TOKENS
        assert sum(row["cache_read_token_call_count"] for row in rows) == 4
        assert sum(row["cache_creation_token_call_count"] for row in rows) == 4
        assert sum(row["cache_read_cost_usd"] for row in rows) == pytest.approx(4 * CACHE_READ_COST)
        assert sum(row["cache_creation_cost_usd"] for row in rows) == pytest.approx(4 * CACHE_CREATION_COST)
        assert sum(row["cache_read_cost_call_count"] for row in rows) == 4
        assert sum(row["cache_creation_cost_call_count"] for row in rows) == 4

        # A later tracker can append to the same run/model. Missing component
        # headers must not erase the earlier measured breakdown or invent
        # another call of cost coverage when the UPSERT adds the new totals.
        synthetic_gateway.headers.pop("x-litellm-response-cost-cache-read")
        synthetic_gateway.headers.pop("x-litellm-response-cost-cache-creation")
        async with cost_telemetry.CostTracker(run_id=run_id, tenant_id=tenant_id):
            await run_stage("report", state)
        assert len(synthetic_gateway.requests) == 5
        report = await connection.fetchrow(
            "SELECT * FROM aisoc_run_costs WHERE run_id = $1 AND tenant_id = $2 AND model = 'aisoc-report'", run_id, tenant_id
        )
        assert report is not None
        assert report["call_count"] == report["measured_call_count"] == 2
        assert report["total_cost_usd"] == pytest.approx(2 * RESPONSE_COST)
        assert report["total_cache_read_tokens"] == 2 * CACHE_READ_TOKENS
        assert report["total_cache_creation_tokens"] == 2 * CACHE_CREATION_TOKENS
        assert report["cache_read_token_call_count"] == report["cache_creation_token_call_count"] == 2
        assert report["cache_read_cost_usd"] == pytest.approx(CACHE_READ_COST)
        assert report["cache_creation_cost_usd"] == pytest.approx(CACHE_CREATION_COST)
        assert report["cache_read_cost_call_count"] == report["cache_creation_cost_call_count"] == 1

        # During a rolling upgrade a runtime role may be unable to add the
        # cache columns. The fallback must still persist the ordinary totals,
        # and cannot manufacture additional cache observation coverage.
        monkeypatch.setattr(cost_telemetry, "_CACHE_COLUMNS_AVAILABLE", False)
        async with cost_telemetry.CostTracker(run_id=run_id, tenant_id=tenant_id):
            await run_stage("report", state)
        assert len(synthetic_gateway.requests) == 6
        legacy = await connection.fetchrow(
            "SELECT * FROM aisoc_run_costs WHERE run_id = $1 AND tenant_id = $2 AND model = 'aisoc-report'", run_id, tenant_id
        )
        assert legacy is not None
        assert legacy["call_count"] == legacy["measured_call_count"] == 3
        assert legacy["total_prompt_tokens"] == 3 * PROMPT_TOKENS
        assert legacy["total_cost_usd"] == pytest.approx(3 * RESPONSE_COST)
        assert legacy["total_cache_read_tokens"] == 2 * CACHE_READ_TOKENS
        assert legacy["total_cache_creation_tokens"] == 2 * CACHE_CREATION_TOKENS
        assert legacy["cache_read_token_call_count"] == legacy["cache_creation_token_call_count"] == 2
        assert legacy["cache_read_cost_call_count"] == legacy["cache_creation_cost_call_count"] == 1
    finally:
        pool = cost_telemetry._POOL
        if pool is not None:
            await pool.close()
            cost_telemetry._POOL = None
        try:
            if await connection.fetchval("SELECT to_regclass('public.aisoc_run_costs')") is not None:
                await connection.execute("DELETE FROM aisoc_run_costs WHERE run_id = $1 AND tenant_id = $2", run_id, tenant_id)
        finally:
            await connection.close()
