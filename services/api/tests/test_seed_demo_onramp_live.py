"""The documented showcase seed against the migrated PostgreSQL schema.

The seed is an administrative operation; these tests use the owner connection,
not the runtime RLS role. Each random tenant and its rows live in a transaction
that is rolled back, including immutable ledger events. No database or seed
helper is replaced. The Golden pipeline covers the authenticated browser path.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

if TYPE_CHECKING:
    from app.models.tenant import Tenant


@pytest_asyncio.fixture
async def seeded_tenant() -> AsyncIterator[tuple[AsyncSession, Tenant]]:
    required = os.getenv("AISOC_DEMO_ONRAMP_REQUIRED", "").lower() not in {"", "0", "false"}
    dsn = os.getenv("DATABASE_MIGRATION_URL") or os.getenv("DATABASE_URL") or ""
    if not dsn.startswith("postgresql"):
        if required:
            pytest.fail("Showcase live tests require a migrated PostgreSQL owner URL")
        pytest.skip("requires migrated PostgreSQL (integration.yml)")

    from app.models.tenant import Tenant
    from app.scripts import seed_demo  # noqa: F401 — registers the seed's ORM models

    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT case_number, tags FROM aisoc_cases LIMIT 0"))
            await connection.execute(text("SELECT case_id FROM investigation_runs LIMIT 0"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"Showcase live prerequisites failed: {type(exc).__name__}: {exc}")
        pytest.skip(f"requires migrated PostgreSQL ({type(exc).__name__})")

    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                async with AsyncSession(bind=connection, expire_on_commit=False) as session:
                    tenant = Tenant(id=uuid.uuid4(), name="Synthetic onramp test", slug="onramp-" + str(uuid.uuid4()))
                    session.add(tenant)
                    await session.flush()
                    yield session, tenant
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_showcase_seed_uses_console_case_uuid(seeded_tenant: tuple[AsyncSession, Tenant]) -> None:
    from app.models.case import Case
    from app.models.investigation import InvestigationRun
    from app.scripts.seed_demo import _mirror_cases_to_aisoc, _seed_in_flight_investigation, _seed_realistic_incidents, _tags_to_object

    session, tenant = seeded_tenant
    await _seed_realistic_incidents(session, tenant)
    assert await _seed_in_flight_investigation(session, tenant) == 1
    await _mirror_cases_to_aisoc(session, tenant)
    case = (await session.execute(select(Case).where(Case.tenant_id == tenant.id, Case.case_number == "INC-RT-001"))).scalar_one()
    # This is the same tenant/UUID filter used by the real console ledger.
    runs = (
        (
            await session.execute(
                select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id, InvestigationRun.case_id == str(case.id))
            )
        )
        .scalars()
        .all()
    )
    assert len(runs) == 1, "showcase seed must be retrievable by the console's canonical case UUID"
    stored_tags = (await session.execute(text("SELECT tags FROM aisoc_cases WHERE id = :id"), {"id": case.id})).scalar_one()
    assert "synthetic" in _tags_to_object(stored_tags)["labels"], "showcase provenance must reach the persisted console case"


@pytest.mark.asyncio
@pytest.mark.parametrize("object_tags", [False, True])
async def test_reseed_repairs_legacy_without_losing_events(seeded_tenant: tuple[AsyncSession, Tenant], object_tags: bool) -> None:
    from app.models.case import Case
    from app.models.investigation import InvestigationArtifact, InvestigationEvent, InvestigationRun
    from app.scripts.seed_demo import (
        _REALISTIC_INCIDENTS,
        _make_realistic_case,
        _mirror_cases_to_aisoc,
        _seed_in_flight_investigation,
        _seed_realistic_incidents,
        _tags_to_object,
    )

    session, tenant = seeded_tenant
    await _seed_realistic_incidents(session, tenant)
    await _seed_in_flight_investigation(session, tenant)
    cases = (await session.execute(select(Case).where(Case.tenant_id == tenant.id))).scalars().all()
    case = next(c for c in cases if c.case_number == "INC-RT-001")
    edited = next(c for c in cases if c.case_number == "INC-RT-002")
    labels = [label for label in _tags_to_object(case.tags)["labels"] if label != "synthetic"]
    legacy_tags = {"labels": labels, "operator_note": "keep this metadata"} if object_tags else labels
    await session.execute(update(Case).where(Case.id == case.id).values(tags=legacy_tags))
    # A catalogue identifier alone does not establish seed ownership.
    edited.title = "Operator-authored incident with a reused catalogue number"
    edited.tags = ["realistic", "keep-this-label"]
    unrelated = _make_realistic_case(
        tenant.id,
        {**_REALISTIC_INCIDENTS[0], "key": "INC-RT-UNRELATED", "title": "Operator incident"},
        when=datetime.now(UTC),
        alert_ids=[],
    )
    unrelated.tags = ["realistic", "keep-this-label"]
    session.add(unrelated)

    run = (await session.execute(select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id))).scalar_one()
    run.case_id = "INC-RT-001"
    canonical = InvestigationRun(tenant_id=tenant.id, case_id=str(case.id), alert_summary="An existing canonical run")
    session.add(canonical)
    await session.flush()
    expected_run_ids = {run.id, canonical.id}
    before_events = (
        await session.execute(
            select(InvestigationEvent.id, InvestigationEvent.run_id, InvestigationEvent.summary).where(
                InvestigationEvent.tenant_id == tenant.id
            )
        )
    ).all()
    before_artifacts = (
        await session.execute(
            select(InvestigationArtifact.id, InvestigationArtifact.run_id, InvestigationArtifact.sha256).where(
                InvestigationArtifact.tenant_id == tenant.id
            )
        )
    ).all()
    assert before_events and before_artifacts

    for _ in range(2):
        assert await _seed_realistic_incidents(session, tenant) == (0, 0, 0)
        assert await _seed_in_flight_investigation(session, tenant) == 0
        await _mirror_cases_to_aisoc(session, tenant)
        runs = (await session.execute(select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id))).scalars().all()
        assert {r.id for r in runs} == expected_run_ids, "re-seeding must preserve both legacy and canonical run IDs"
        assert all(r.case_id == str(case.id) for r in runs), "legacy runs must be repaired to the same tenant's case UUID"
        stored = (await session.execute(text("SELECT tags FROM aisoc_cases WHERE id = :id"), {"id": case.id})).scalar_one()
        assert _tags_to_object(stored)["labels"].count("synthetic") == 1
        if object_tags:
            assert stored["operator_note"] == "keep this metadata"

    after_events = (
        await session.execute(
            select(InvestigationEvent.id, InvestigationEvent.run_id, InvestigationEvent.summary).where(
                InvestigationEvent.tenant_id == tenant.id
            )
        )
    ).all()
    after_artifacts = (
        await session.execute(
            select(InvestigationArtifact.id, InvestigationArtifact.run_id, InvestigationArtifact.sha256).where(
                InvestigationArtifact.tenant_id == tenant.id
            )
        )
    ).all()
    assert set(after_events) == set(before_events), "legacy repair must not replace immutable ledger events"
    assert set(after_artifacts) == set(before_artifacts), "legacy repair must preserve attached artifacts"
    for untouched in (edited, unrelated):
        stored = (await session.execute(text("SELECT tags FROM aisoc_cases WHERE id = :id"), {"id": untouched.id})).scalar_one()
        assert _tags_to_object(stored)["labels"] == ["realistic", "keep-this-label"]


@pytest.mark.asyncio
async def test_existing_operator_run_is_never_published_as_the_demo(seeded_tenant: tuple[AsyncSession, Tenant]) -> None:
    from app.models.case import Case
    from app.models.investigation import InvestigationEvent, InvestigationRun
    from app.models.published_replay import PublishedReplay
    from app.scripts.seed_demo import CANONICAL_REPLAY_SLUG, _seed_in_flight_investigation, _seed_realistic_incidents

    session, tenant = seeded_tenant
    await _seed_realistic_incidents(session, tenant)
    case = (await session.execute(select(Case).where(Case.tenant_id == tenant.id, Case.case_number == "INC-RT-001"))).scalar_one()
    # A pre-existing fixture replay would hide the publication branch. This
    # deletion and all new rows roll back together with the outer transaction.
    await session.execute(delete(PublishedReplay).where(PublishedReplay.slug == CANONICAL_REPLAY_SLUG))
    assert not (await session.execute(select(PublishedReplay).where(PublishedReplay.slug == CANONICAL_REPLAY_SLUG))).scalars().all()
    private_marker = "operator-only-evidence-" + str(uuid.uuid4())
    operator_run = InvestigationRun(
        tenant_id=tenant.id,
        case_id=str(case.id),
        alert_summary="An operator's private investigation",
        raw_alert={"incident_key": "operator-incident", "evidence": private_marker},
        model_used="operator-model",
        status="completed",
        started_at=datetime.now(UTC) - timedelta(days=1),
    )
    session.add(operator_run)
    await session.flush()
    operator_event = InvestigationEvent(
        tenant_id=tenant.id,
        run_id=operator_run.id,
        seq=1,
        kind="recon",
        agent="Operator",
        summary=private_marker,
    )
    session.add(operator_event)
    await session.flush()

    assert await _seed_in_flight_investigation(session, tenant) == 1, "an unrelated canonical run must not suppress the synthetic seed"
    replay = (await session.execute(select(PublishedReplay).where(PublishedReplay.slug == CANONICAL_REPLAY_SLUG))).scalar_one()
    assert replay.run_id != operator_run.id, "the public demo must never publish an operator investigation"
    assert private_marker not in json.dumps(replay.snapshot), "operator evidence must not enter the public demo snapshot"
    seeded_run = await session.get(InvestigationRun, replay.run_id)
    assert seeded_run is not None and seeded_run.raw_alert is not None
    assert seeded_run.raw_alert["incident_key"] == "INC-RT-001"
    assert seeded_run.model_used == "aisoc-investigator-v1"
    assert await _seed_in_flight_investigation(session, tenant) == 0
    await session.refresh(operator_run)
    await session.refresh(operator_event)
    assert operator_run.case_id == str(case.id)
    assert operator_run.raw_alert == {"incident_key": "operator-incident", "evidence": private_marker}
    assert operator_event.summary == private_marker and operator_event.run_id == operator_run.id
    runs = (await session.execute(select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id))).scalars().all()
    assert {run.id for run in runs} == {operator_run.id, seeded_run.id}


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_tenant", [False, True])
async def test_unowned_showcase_cannot_create_an_orphan(seeded_tenant: tuple[AsyncSession, Tenant], wrong_tenant: bool) -> None:
    from app.models.investigation import InvestigationRun
    from app.models.tenant import Tenant
    from app.scripts.seed_demo import _REALISTIC_INCIDENTS, _make_realistic_case, _seed_in_flight_investigation

    session, tenant = seeded_tenant
    owner = tenant
    if wrong_tenant:
        owner = Tenant(id=uuid.uuid4(), name="Other synthetic tenant", slug="onramp-other-" + str(uuid.uuid4()))
        session.add(owner)
        await session.flush()
    incident = dict(_REALISTIC_INCIDENTS[0])
    if not wrong_tenant:
        incident["title"] = "An operator's unrelated case"
    case = _make_realistic_case(owner.id, incident, when=datetime.now(UTC), alert_ids=[])
    session.add(case)
    await session.flush()
    reason = "missing from tenant" if wrong_tenant else "not the seeded showcase"
    with pytest.raises(RuntimeError, match=reason):
        await _seed_in_flight_investigation(session, tenant)
    assert not (await session.execute(select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id))).scalars().all()
