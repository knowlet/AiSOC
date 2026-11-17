"""Copilot queue contracts through HTTP and the migrated PostgreSQL schema.

Only the authenticated identity is supplied by the fixture. Permission checks,
query validation, SQL, pagination and response serialization are production code.
The read sessions intentionally remain unbound so RLS cannot mask a missing
tenant predicate in either queue.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import approvals, cases
from app.db.database import get_db
from app.db.rls import get_tenant_db
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def queues():
    dsn = os.environ.get("DATABASE_MIGRATION_URL") or os.environ.get("DATABASE_URL", "")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "") not in ("", "0", "false")
    if "postgres" not in dsn:
        if required:
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires live PostgreSQL with the API migration chain")
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"live PostgreSQL is unavailable: {type(exc).__name__}")
        pytest.skip(f"no PostgreSQL connection ({type(exc).__name__})")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    tenant_a, tenant_b, user_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    async with factory() as db:
        try:
            for tenant in (tenant_a, tenant_b):
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'Copilot queue test', :slug)"),
                    {"id": tenant, "slug": f"queue-{tenant}"},
                )
            await db.execute(
                text("""INSERT INTO users (id, tenant_id, email, username, hashed_password)
                        VALUES (:id, :tenant, :email, 'queue-reader', 'test-only-not-a-password-hash')"""),
                {"id": user_id, "tenant": tenant_a, "email": f"{user_id}@example.test"},
            )

            async def add_case(title, *, description=None, case_number=None, severity="high", status="new", tenant=None, identifier=None):
                identifier = identifier or uuid.uuid4()
                await db.execute(
                    text("""INSERT INTO aisoc_cases
                        (id, tenant_id, title, description, case_number, severity, status, opened_at, created_at, updated_at)
                        VALUES (:id, :tenant, :title, :description, :number, :severity, :status, :now, :now, :now)"""),
                    {
                        "id": identifier,
                        "tenant": tenant or tenant_a,
                        "title": title,
                        "description": description,
                        "number": case_number,
                        "severity": severity,
                        "status": status,
                        "now": now,
                    },
                )
                await db.commit()
                return str(identifier)

            async def add_approval(title, *, status="pending", risk="high", mine=False, tenant=None):
                identifier = uuid.uuid4()
                await db.execute(
                    text("""INSERT INTO agent_approvals
                        (id, tenant_id, title, summary, status, risk_level, required_user_id, action, created_at, updated_at)
                        VALUES (:id, :tenant, :title, 'Review 203.0.113.8', :status, :risk, :user, '{}'::jsonb, :now, :now)"""),
                    {
                        "id": identifier,
                        "tenant": tenant or tenant_a,
                        "title": title,
                        "status": status,
                        "risk": risk,
                        "user": user_id if mine else None,
                        "now": now,
                    },
                )
                await db.commit()
                return str(identifier)

            principal = CurrentUser(
                user_id=user_id,
                tenant_id=tenant_a,
                role="analyst",
                email=f"{user_id}@example.test",
                resolved_permissions=frozenset({"cases:read"}),
            )
            app = FastAPI()
            app.include_router(cases.router, prefix="/api/v1")
            app.include_router(approvals.router, prefix="/api/v1")
            app.dependency_overrides[get_current_user] = lambda: principal

            async def session():
                yield db

            app.dependency_overrides[get_db] = session
            app.dependency_overrides[get_tenant_db] = session
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
                yield SimpleNamespace(
                    client=client,
                    principal=principal,
                    tenant_b=tenant_b,
                    add_case=add_case,
                    add_approval=add_approval,
                    db=db,
                )
        finally:
            await db.rollback()
            for tenant in (tenant_a, tenant_b):
                for table in ("agent_approvals", "aisoc_cases", "users"):
                    await db.execute(text(f"DELETE FROM {table} WHERE tenant_id=:tenant"), {"tenant": tenant})
                await db.execute(text("DELETE FROM tenants WHERE id=:tenant"), {"tenant": tenant})
            await db.commit()
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["ransomware", "workstation-42", "inc-cop-042"])
async def test_case_search_matches_title_description_or_number_within_tenant(queues, query):
    expected = await queues.add_case("Ransomware investigation", description="Workstation-42", case_number="INC-COP-042")
    await queues.add_case("Unrelated incident")
    await queues.add_case("Ransomware investigation", description="Workstation-42", case_number="INC-COP-042", tenant=queues.tenant_b)
    response = await queues.client.get("/api/v1/cases", params={"query": query})
    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()] == [expected]


@pytest.mark.asyncio
async def test_search_combines_existing_filters_and_preserves_list_contract(queues):
    expected = await queues.add_case("Malware investigation", status="investigating")
    await queues.add_case("Malware closed", status="closed")
    await queues.add_case("Malware low", status="investigating", severity="low")
    response = await queues.client.get("/api/v1/cases", params={"query": " malware ", "status": "investigating", "severity": "high"})
    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()] == [expected]
    unfiltered = await queues.client.get("/api/v1/cases")
    assert unfiltered.status_code == 200 and len(unfiltered.json()) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["100%", "agent_42", "path\\file", "' OR true --"])
async def test_case_query_is_literal_and_parameterized(queues, query):
    expected = await queues.add_case(f"Investigate {query}")
    await queues.add_case("Investigate 100 percent agentX42 path/file")
    response = await queues.client.get("/api/v1/cases", params={"query": query})
    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()] == [expected]


@pytest.mark.asyncio
async def test_case_paging_has_stable_tie_order_and_a_lookahead_row(queues):
    identifiers = sorted(str(uuid.uuid4()) for _ in range(23))
    for identifier in reversed(identifiers):
        await queues.add_case("Queue page", identifier=uuid.UUID(identifier))
    first = await queues.client.get("/api/v1/cases", params={"query": "Queue", "limit": 21, "offset": 0})
    second = await queues.client.get("/api/v1/cases", params={"query": "Queue", "limit": 21, "offset": 20})
    assert first.status_code == second.status_code == 200
    assert [row["id"] for row in first.json()] == identifiers[:21]
    assert [row["id"] for row in second.json()] == identifiers[20:]


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["", "   ", "x" * 201])
async def test_invalid_query_is_refused(queues, query):
    response = await queues.client.get("/api/v1/cases", params={"query": query})
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_case_read_permission_is_required_and_empty_is_distinct(queues):
    assert (await queues.client.get("/api/v1/cases", params={"query": "missing"})).json() == []
    queues.principal.resolved_permissions = frozenset()
    response = await queues.client.get("/api/v1/cases", params={"query": "missing"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_pending_approval_scope_mine_risk_and_read_only_contract(queues):
    expected = await queues.add_approval("Mine", mine=True)
    unassigned = await queues.add_approval("Unassigned")
    low_risk = await queues.add_approval("Low risk", mine=True, risk="low")
    await queues.add_approval("Already approved", mine=True, status="approved")
    await queues.add_approval("Foreign pending", tenant=queues.tenant_b)
    response = await queues.client.get("/api/v1/approvals", params={"status": "pending", "mine": "true", "risk_level": "high"})
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert [row["id"] for row in response.json()["items"]] == [expected]
    all_pending = await queues.client.get("/api/v1/approvals", params={"status": "pending", "page_size": 1})
    assert all_pending.json()["total"] == 3 and all_pending.json()["pages"] == 3
    ids = []
    for page in range(1, 4):
        paged = await queues.client.get("/api/v1/approvals", params={"status": "pending", "page_size": 1, "page": page})
        ids.extend(row["id"] for row in paged.json()["items"])
    assert ids == sorted([expected, unassigned, low_risk])
    row = (
        await queues.db.execute(
            text("SELECT status, decided_at FROM agent_approvals WHERE id=:id AND tenant_id=:tenant"),
            {"id": uuid.UUID(expected), "tenant": queues.principal.tenant_id},
        )
    ).one()
    assert row.status == "pending" and row.decided_at is None
