"""Cache components survive actual SQL and the authenticated investigation API.

Requires PostgreSQL with the investigation, authentication and cost schema.
Set MSSP_ISOLATION_REQUIRED=1 to reject an unavailable database instead of
skipping the integration checks.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from app.core.security import create_access_token
from app.db.database import _normalize_async_pg_url, get_db
from app.db.rls import get_tenant_db
from app.main import create_application
from app.services.cost_dashboard import DashboardInputs, _fetch_cost_rows, build_dashboard_from_rows
from live_rls import bind_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@dataclass
class CacheAPI:
    client: httpx.AsyncClient
    db: AsyncSession
    tenant: uuid.UUID
    run: uuid.UUID
    other_run: uuid.UUID


@pytest_asyncio.fixture
async def cache_api(monkeypatch):
    dsn = os.environ.get("DATABASE_URL", "")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "").lower() not in ("", "0", "false")
    if "postgres" not in dsn:
        if required:
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires PostgreSQL with the investigation, authentication and cost schema")
    url, connect_args = _normalize_async_pg_url(dsn)
    engine = create_async_engine(url, connect_args=connect_args)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"PostgreSQL is required but unavailable: {type(exc).__name__}: {exc}")
        pytest.skip(f"PostgreSQL unavailable ({type(exc).__name__})")

    monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "0")
    tenant, other_tenant, user = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    run, legacy_run, other_run = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            for tid in (tenant, other_tenant):
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'Cache telemetry test', :slug)"),
                    {"id": tid, "slug": f"cache-{tid}"},
                )
            await bind_tenant(db, tenant)
            await db.execute(
                text("""INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
                    VALUES (:id, :tenant, :email, 'cache-test', '!test-only!', 'tenant_admin', TRUE)"""),
                {"id": user, "tenant": tenant, "email": f"cache-{user}@example.test"},
            )
            for rid, tid in ((run, tenant), (legacy_run, tenant), (other_run, other_tenant)):
                await bind_tenant(db, tid)
                await db.execute(
                    text("INSERT INTO investigation_runs (id, tenant_id, case_id) VALUES (:id, :tenant, :case)"),
                    {"id": rid, "tenant": tid, "case": f"cache-{rid}"},
                )
            await db.commit()
            for rid, tid, cost in ((run, tenant, 1.25), (other_run, other_tenant, 999.0)):
                await db.execute(
                    text("""INSERT INTO aisoc_run_costs
                        (run_id, tenant_id, model, total_prompt_tokens, total_completion_tokens,
                         measured_cost_usd, measured_call_count, call_count, total_cache_read_tokens,
                         total_cache_creation_tokens, cache_read_token_call_count,
                         cache_creation_token_call_count, cache_read_cost_usd, cache_creation_cost_usd,
                         cache_read_cost_call_count, cache_creation_cost_call_count)
                        VALUES (:run, :tenant, 'gpt-4o-mini', 10000, 500, :cost, 3, 3,
                                8000, 1000, 3, 2, 0.1, 0.2, 2, 1)"""),
                    {"run": str(rid), "tenant": f"alias-{tid}", "cost": cost},
                )
            # Legacy writer shape: none of the new metadata was reported.
            await db.execute(
                text("""INSERT INTO aisoc_run_costs
                    (run_id, tenant_id, model, total_prompt_tokens, total_completion_tokens,
                     measured_cost_usd, measured_call_count, call_count)
                    VALUES (:run, :tenant, 'gpt-4o-mini', 100, 10, 0.5, 1, 1)"""),
                {"run": str(legacy_run), "tenant": f"alias-{tenant}"},
            )
            await db.commit()
            app = create_application()

            async def session():
                # Unbound reads make missing query predicates observable
                # rather than allowing RLS to conceal them in this fixture.
                yield db

            app.dependency_overrides[get_db] = session
            app.dependency_overrides[get_tenant_db] = session
            token = create_access_token({"sub": str(user), "tenant_id": str(tenant), "role": "tenant_admin"})
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app, raise_app_exceptions=False),
                base_url="http://api.test",
                headers={"Authorization": f"Bearer {token}"},
                trust_env=False,
            ) as client:
                try:
                    yield CacheAPI(client, db, tenant, run, other_run)
                finally:
                    await db.rollback()
                    await db.execute(
                        text("DELETE FROM aisoc_run_costs WHERE run_id = ANY(CAST(:runs AS TEXT[]))"),
                        {"runs": [str(run), str(legacy_run), str(other_run)]},
                    )
                    for tid in (tenant, other_tenant):
                        await bind_tenant(db, tid)
                        await db.execute(text("DELETE FROM investigation_runs WHERE tenant_id = :tenant"), {"tenant": tid})
                        await db.execute(text("DELETE FROM users WHERE tenant_id = :tenant"), {"tenant": tid})
                        await db.execute(text("DELETE FROM tenants WHERE id = :tenant"), {"tenant": tid})
                    await db.commit()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_cache_components_reach_authenticated_run_detail(cache_api):
    response = await cache_api.client.get(f"/api/v1/investigations/{cache_api.run}")
    assert response.status_code == 200, response.text
    cost = response.json()["model_costs"][0]
    assert cost["total_prompt_tokens"] == 10000
    assert cost["total_cache_read_tokens"] == 8000
    assert cost["total_cache_creation_tokens"] == 1000
    assert cost["cache_read_token_call_count"] == 3
    assert cost["cache_creation_token_call_count"] == 2
    assert cost["cache_read_cost_usd"] == 0.1
    assert cost["cache_creation_cost_usd"] == 0.2
    assert cost["cache_read_cost_call_count"] == 2
    assert cost["cache_creation_cost_call_count"] == 1
    assert cost["total_cost_usd"] == 1.25
    denied = await cache_api.client.get(f"/api/v1/investigations/{cache_api.other_run}")
    assert denied.status_code == 404


@pytest.mark.asyncio
async def test_cache_aggregate_counts_legacy_coverage_without_other_tenant_cost(cache_api):
    response = await cache_api.client.get("/api/v1/investigations/costs/aggregate")
    assert response.status_code == 200, response.text
    for cost in (response.json()["totals"], response.json()["by_model"][0]):
        assert cost["runs"] == 2
        assert cost["calls"] == 4
        assert cost["total_cost_usd"] == 1.75
        assert cost["total_cache_read_tokens"] == 8000
        assert cost["cache_read_token_call_count"] == 3
        assert cost["cache_creation_token_call_count"] == 2
        assert cost["cache_read_cost_usd"] == 0.1
        assert cost["cache_creation_cost_usd"] == 0.2
        assert cost["cache_read_cost_call_count"] == 2
        assert cost["cache_creation_cost_call_count"] == 1


@pytest.mark.asyncio
async def test_dashboard_sql_preserves_cache_parts_without_invented_cache_savings(cache_api):
    now = datetime.now(UTC)
    rows = await _fetch_cost_rows(cache_api.db, cache_api.tenant, now - timedelta(days=1), now + timedelta(days=1))
    dashboard = build_dashboard_from_rows(
        DashboardInputs(
            tenant_id=cache_api.tenant,
            period_start=now - timedelta(days=1),
            period_end=now + timedelta(days=1),
            cost_rows=rows,
        )
    )
    assert dashboard.headline.total_cost_usd == 1.75
    model = dashboard.by_model[0]
    assert model.total_cache_read_tokens == 8000
    assert model.cache_read_cost_usd == 0.1
    assert model.cache_creation_cost_usd == 0.2
    assert model.cache_read_cost_call_count == 2
    assert model.cache_creation_cost_call_count == 1
    assert model.unpriced_tokens == 10500
