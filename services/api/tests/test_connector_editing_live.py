"""Connector edits through HTTP and real Postgres JSONB writes.

Set CONNECTOR_EDIT_DATABASE_URL to a disposable Postgres database. Each test
creates and drops its own schema; the two tables use the shipped ORM metadata.
This checks database updates, not the full migration chain or vendor access.
Authentication resolves to a supplied principal; route RBAC remains real.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import connectors
from app.db.database import Base, get_db
from app.models.connector import Connector
from app.models.tenant import Tenant
from app.security.credential_vault import CredentialVault
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("CONNECTOR_EDIT_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DSN, reason="CONNECTOR_EDIT_DATABASE_URL is not set; needs disposable Postgres")


@pytest_asyncio.fixture
async def live_editing(monkeypatch):
    schema = f"connector_edit_{uuid.uuid4().hex}"
    admin_engine = create_async_engine(DSN)
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))  # noqa: S608 — generated hex identifier
    engine = create_async_engine(DSN, connect_args={"server_settings": {"search_path": schema}})
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[Tenant.__table__, Connector.__table__]))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    tenant, other_tenant, connector_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    vault = CredentialVault(Fernet.generate_key())
    auth = {"username": "legacy-reader", "password": "original-password", "refresh_token": "retain-refresh-token"}
    config = {
        "indexer_url": "https://93.184.216.34:9200",
        "verify_tls": True,
        "min_rule_level": 7,
        "checkpoint": {"cursor": "latest"},
        "future_runtime_key": 42,
    }
    async with factory() as db:
        db.add_all([Tenant(id=tenant, name="Edit A", slug=f"a-{tenant}"), Tenant(id=other_tenant, name="Edit B", slug=f"b-{other_tenant}")])
        await db.flush()
        db.add(
            Connector(
                id=connector_id,
                tenant_id=tenant,
                name="Wazuh before edit",
                connector_type="wazuh",
                category="siem",
                auth_config=vault.encrypt_dict(auth),
                connector_config=config,
                health_status="healthy",
                last_health_check=datetime(2026, 11, 11, tzinfo=UTC),
                events_ingested=37,
                oauth_provisioned=True,
            )
        )
        await db.commit()

    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role="tenant_admin", email="editor@example.test")
    app = FastAPI()
    app.include_router(connectors.router, prefix="/api/v1")

    async def db_dependency():
        async with factory() as db:
            yield db

    app.dependency_overrides[get_db] = db_dependency
    app.dependency_overrides[get_current_user] = lambda: user
    monkeypatch.setattr(connectors, "get_vault", lambda: vault)
    # Use this build's real schema while keeping this suite independent of
    # the separate connectors-service deployment.
    monkeypatch.setattr(connectors.settings, "CONNECTORS_SERVICE_URL", "")
    proxy = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(connectors, "_proxy_test_connection", proxy)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api.test") as client:
            yield client, factory, user, connector_id, other_tenant, vault, proxy
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))  # noqa: S608 — this fixture's schema only
        await admin_engine.dispose()


@pytest.mark.asyncio
async def test_edit_round_trip_keeps_id_counters_credentials_and_unknown_runtime_keys(live_editing):
    client, factory, _user, connector_id, _other, vault, _proxy = live_editing
    before = await client.get(f"/api/v1/connectors/{connector_id}/edit_config")
    assert before.status_code == 200
    assert before.json()["values"]["username"] == "legacy-reader"
    assert before.json()["configured_secret_fields"] == ["password"]
    assert before.json()["connector"]["oauth_provisioned"] is True
    response = await client.patch(
        f"/api/v1/connectors/{connector_id}",
        json={
            "name": "Wazuh after edit",
            "auth_config_patch": {"password": ""},
            "connector_config_patch": {"verify_tls": False, "min_rule_level": 0},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(connector_id)
    assert response.json()["events_ingested"] == 37
    assert response.json()["health_status"] == "unknown"
    assert response.json()["last_health_check"] is None
    assert "original-password" not in response.text
    async with factory() as db:
        row = await db.get(Connector, connector_id)
        assert row.name == "Wazuh after edit"
        assert vault.decrypt_dict(row.auth_config) == {
            "username": "legacy-reader",
            "password": "original-password",
            "refresh_token": "retain-refresh-token",
        }
        assert row.connector_config == {
            "indexer_url": "https://93.184.216.34:9200",
            "verify_tls": False,
            "min_rule_level": 0,
            "checkpoint": {"cursor": "latest"},
            "future_runtime_key": 42,
        }
        assert row.oauth_provisioned is True


@pytest.mark.asyncio
async def test_rotating_one_secret_keeps_other_ciphertexts_and_invalidates_health(live_editing):
    client, factory, _user, connector_id, _other, vault, _proxy = live_editing
    async with factory() as db:
        before = (await db.get(Connector, connector_id)).auth_config.copy()
    response = await client.patch(f"/api/v1/connectors/{connector_id}", json={"auth_config_patch": {"password": "replacement-password"}})
    assert response.status_code == 200, response.text
    assert response.json()["health_status"] == "unknown"
    async with factory() as db:
        row = await db.get(Connector, connector_id)
        assert vault.decrypt_dict(row.auth_config)["password"] == "replacement-password"
        assert row.auth_config["password"].startswith("vault:")
        assert row.auth_config["refresh_token"] == before["refresh_token"]
        assert row.auth_config["username"] == before["username"]


@pytest.mark.asyncio
async def test_legacy_config_secret_is_hidden_and_cannot_shadow_rotation(live_editing):
    client, factory, _user, connector_id, _other, vault, proxy = live_editing
    async with factory() as db:
        row = await db.get(Connector, connector_id)
        row.connector_config = {**row.connector_config, "password": "legacy-misfiled-password"}
        await db.commit()
    edit = await client.get(f"/api/v1/connectors/{connector_id}/edit_config")
    assert edit.status_code == 200
    assert "legacy-misfiled-password" not in edit.text
    assert "password" not in edit.json()["connector"]["connector_config"]
    proxy.return_value = {"success": False, "error": "Rejected legacy-misfiled-password"}
    preview = await client.post(f"/api/v1/connectors/{connector_id}/test", json={})
    assert "legacy-misfiled-password" not in preview.text
    response = await client.patch(f"/api/v1/connectors/{connector_id}", json={"auth_config_patch": {"password": "replacement"}})
    assert response.status_code == 200, response.text
    async with factory() as db:
        row = await db.get(Connector, connector_id)
        assert "password" not in row.connector_config
        assert vault.decrypt_dict(row.auth_config)["password"] == "replacement"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        {"name": "Renamed", "connector_config_patch": {}},
        {"connector_config_patch": {"verify_tls": True}},
        {"auth_config_patch": {"password": "original-password"}},
    ],
)
async def test_metadata_or_unchanged_connection_does_not_invalidate_health(live_editing, patch):
    client, _factory, _user, connector_id, _other, _vault, _proxy = live_editing
    response = await client.patch(f"/api/v1/connectors/{connector_id}", json=patch)
    assert response.status_code == 200, response.text
    assert response.json()["health_status"] == "healthy"
    assert response.json()["last_health_check"] is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,suffix,payload",
    [("GET", "/edit_config", None), ("PATCH", "", {"auth_config_patch": {"password": "intruder"}}), ("POST", "/test", {})],
)
async def test_another_tenants_connector_is_not_found(live_editing, method, suffix, payload):
    client, factory, user, connector_id, other, vault, proxy = live_editing
    user.tenant_id = other
    response = await client.request(
        method, f"/api/v1/connectors/{connector_id}{suffix}", **({"json": payload} if payload is not None else {})
    )
    missing = await client.request(
        method, f"/api/v1/connectors/{uuid.uuid4()}{suffix}", **({"json": payload} if payload is not None else {})
    )
    assert response.status_code == missing.status_code == 404
    assert response.content == missing.content
    proxy.assert_not_awaited()
    async with factory() as db:
        assert vault.decrypt_dict((await db.get(Connector, connector_id)).auth_config)["password"] == "original-password"


@pytest.mark.asyncio
async def test_preview_does_not_write_config_or_health(live_editing):
    client, factory, _user, connector_id, _other, vault, proxy = live_editing
    response = await client.post(
        f"/api/v1/connectors/{connector_id}/test",
        json={"auth_config_patch": {"password": "preview-only"}, "connector_config_patch": {"verify_tls": False}},
    )
    assert response.status_code == 200
    assert proxy.await_args.args[1]["password"] == "preview-only"
    assert proxy.await_args.args[2]["verify_tls"] is False
    async with factory() as db:
        row = await db.get(Connector, connector_id)
        assert vault.decrypt_dict(row.auth_config)["password"] == "original-password"
        assert row.connector_config["verify_tls"] is True
        assert row.health_status == "healthy"
        assert row.last_health_check == datetime(2026, 11, 11, tzinfo=UTC)


@pytest.mark.asyncio
async def test_old_whole_object_replacement_still_supports_clearing_secrets(live_editing):
    client, factory, _user, connector_id, _other, _vault, _proxy = live_editing
    response = await client.patch(f"/api/v1/connectors/{connector_id}", json={"auth_config": {}})
    assert response.status_code == 200
    async with factory() as db:
        assert (await db.get(Connector, connector_id)).auth_config == {}
