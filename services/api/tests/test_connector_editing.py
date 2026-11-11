"""Editing routes preserve stored secrets and test unsaved values safely.

These tests drive the real FastAPI router and permission dependency with a
real credential vault. The database and connectors-service proxy are test
doubles; durable JSONB updates and tenant predicates are covered separately
by test_connector_editing_live.py against Postgres.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import connectors
from app.db.database import get_db
from app.models.connector import Connector
from app.security.credential_vault import CredentialVault
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException

TENANT = uuid.UUID("c0e00000-0000-0000-0000-000000000001")
CONNECTOR = uuid.UUID("c0e00000-0000-0000-0000-000000000002")
NOW = datetime(2026, 11, 11, tzinfo=UTC)
SCHEMA = {
    "connector_id": "wazuh",
    "fields": [
        {"name": "indexer_url", "type": "string", "required": True},
        {"name": "username", "type": "string", "required": True},
        {"name": "password", "type": "secret", "required": True},
        {"name": "optional_token", "type": "secret", "required": False},
        {"name": "verify_tls", "type": "boolean"},
        {"name": "min_rule_level", "type": "number"},
    ],
}


@pytest_asyncio.fixture
async def editing(monkeypatch):
    vault = CredentialVault(Fernet.generate_key())
    row = Connector(
        id=CONNECTOR,
        tenant_id=TENANT,
        name="Wazuh production",
        connector_type="wazuh",
        category="siem",
        is_enabled=True,
        auth_config=vault.encrypt_dict(
            {"password": "stored-password", "username": "legacy-user", "refresh_token": "private-refresh", "optional_token": ""}
        ),
        connector_config={
            "indexer_url": "https://93.184.216.34:9200",
            "verify_tls": False,
            "min_rule_level": 0,
            "checkpoint": {"cursor": "saved"},
        },
        health_status="healthy",
        last_health_check=NOW,
        events_ingested=42,
        events_dropped=0,
        error_count=0,
        oauth_provisioned=False,
        tags=[],
        created_at=NOW,
        updated_at=NOW,
    )
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db.execute.return_value = result
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="tenant_admin", email="admin@example.test")
    catalog = AsyncMock(return_value=SCHEMA)
    proxy = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(connectors, "get_vault", lambda: vault)
    monkeypatch.setattr(connectors, "_validate_connector_type", catalog)
    monkeypatch.setattr(connectors, "_proxy_test_connection", proxy)
    app = FastAPI()
    app.include_router(connectors.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api.test") as client:
        yield client, row, db, user, catalog, proxy, vault


@pytest.mark.asyncio
async def test_edit_config_prefills_allowlisted_values_without_returning_secrets(editing):
    client, row, _db, _user, _catalog, _proxy, _vault = editing
    response = await client.get(f"/api/v1/connectors/{CONNECTOR}/edit_config")
    assert response.status_code == 200
    body = response.json()
    assert body["values"] == {
        "username": "legacy-user",
        "indexer_url": "https://93.184.216.34:9200",
        "verify_tls": False,
        "min_rule_level": 0,
    }
    assert body["configured_secret_fields"] == ["password"]
    assert body["connector"]["id"] == str(row.id)
    assert "auth_config" not in body["connector"]
    for secret in ("stored-password", "private-refresh", "refresh_token", "vault:v1:"):
        assert secret not in response.text


@pytest.mark.asyncio
async def test_edit_config_requires_a_schema_before_decrypting_auth(editing):
    client, _row, _db, _user, catalog, _proxy, _vault = editing
    catalog.side_effect = HTTPException(status_code=503, detail="catalog unavailable")
    response = await client.get(f"/api/v1/connectors/{CONNECTOR}/edit_config")
    assert response.status_code == 503
    assert "private-refresh" not in response.text


@pytest.mark.asyncio
async def test_metadata_only_update_does_not_echo_a_legacy_config_secret(editing):
    client, row, _db, _user, _catalog, _proxy, _vault = editing
    row.connector_config = {**row.connector_config, "password": "legacy-misfiled-password"}
    response = await client.patch(f"/api/v1/connectors/{CONNECTOR}", json={"name": "Renamed"})
    assert response.status_code == 200
    assert "legacy-misfiled-password" not in response.text
    assert "password" not in response.json()["connector_config"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,suffix,payload", [("GET", "/edit_config", None), ("PATCH", "", {"name": "Changed"}), ("POST", "/test", {})]
)
async def test_edit_routes_refuse_a_read_only_principal(editing, method, suffix, payload):
    client, _row, db, user, _catalog, proxy, _vault = editing
    user.role = "viewer"
    response = await client.request(method, f"/api/v1/connectors/{CONNECTOR}{suffix}", **({"json": payload} if payload is not None else {}))
    assert response.status_code == 403
    db.execute.assert_not_awaited()
    proxy.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["auth_config", "connector_config"])
@pytest.mark.parametrize("patch_field", ["auth_config_patch", "connector_config_patch"])
async def test_replace_and_patch_are_mutually_exclusive(editing, field, patch_field):
    client, _row, db, _user, _catalog, _proxy, _vault = editing
    response = await client.patch(f"/api/v1/connectors/{CONNECTOR}", json={field: {}, patch_field: {}})
    assert response.status_code == 422
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["auth_config", "connector_config"])
async def test_preview_refuses_whole_config_replacements_instead_of_ignoring_them(editing, field):
    client, _row, db, _user, _catalog, proxy, _vault = editing
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test", json={field: {}, "connector_config_patch": {}})
    assert response.status_code == 422
    db.execute.assert_not_awaited()
    proxy.assert_not_awaited()


@pytest.mark.asyncio
async def test_unsaved_test_uses_existing_secrets_and_overrides_without_persisting(editing):
    client, row, db, _user, _catalog, proxy, _vault = editing
    original_auth = row.auth_config.copy()
    response = await client.post(
        f"/api/v1/connectors/{CONNECTOR}/test",
        json={"auth_config_patch": {"password": "  "}, "connector_config_patch": {"username": "new-user", "min_rule_level": 3}},
    )
    assert response.status_code == 200
    args = proxy.await_args.args
    assert args[1]["password"] == "stored-password"
    assert args[1]["refresh_token"] == "private-refresh"
    assert args[2]["username"] == "new-user"
    assert args[2]["min_rule_level"] == 3
    assert args[2]["checkpoint"] == {"cursor": "saved"}
    assert row.auth_config == original_auth
    assert row.last_health_check == NOW
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_empty_preview_body_does_not_change_saved_health(editing):
    client, _row, db, _user, _catalog, _proxy, _vault = editing
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test", json={})
    assert response.status_code == 200
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_body_keeps_existing_saved_test_behavior(editing):
    client, _row, db, _user, _catalog, _proxy, _vault = editing
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test")
    assert response.status_code == 200
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_preview_refuses_internal_destinations_before_contacting_service(editing):
    client, _row, db, _user, _catalog, proxy, _vault = editing
    response = await client.post(
        f"/api/v1/connectors/{CONNECTOR}/test", json={"connector_config_patch": {"indexer_url": "http://169.254.169.254/latest/meta-data/"}}
    )
    assert response.status_code == 422
    proxy.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("raised", [False, True])
async def test_preview_does_not_echo_stored_or_replacement_credentials(editing, raised):
    client, _row, _db, _user, _catalog, proxy, _vault = editing
    if raised:
        proxy.side_effect = HTTPException(status_code=422, detail="Rejected new-password / private-refresh")
    else:
        proxy.return_value = {"success": False, "error": "Rejected new-password", "details": {"trace": ["private-refresh"]}}
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test", json={"auth_config_patch": {"password": "new-password"}})
    assert response.status_code == (422 if raised else 200)
    assert "new-password" not in response.text
    assert "private-refresh" not in response.text


@pytest.mark.asyncio
async def test_redaction_preserves_protocol_keys_and_the_success_verdict(editing):
    client, row, db, _user, _catalog, proxy, vault = editing
    row.auth_config = vault.encrypt_dict({"username": "a", "password": "success"})
    proxy.return_value = {"success": True, "message": "Connection successful", "latency_ms": 10, "details": {"trace": "success"}}
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test")
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["latency_ms"] == 10
    assert "message" in response.json()
    assert "details" in response.json()
    assert db.execute.await_args.args[0].compile().params["health_status"] == "healthy"


@pytest.mark.asyncio
async def test_redaction_is_single_pass_and_keeps_public_diagnostics(editing):
    client, row, _db, _user, _catalog, proxy, vault = editing
    row.auth_config = vault.encrypt_dict({"password": "x", "refresh_token": "e", "username": "a"})
    proxy.return_value = {"success": False, "error": "x e", "details": {"url": "https://93.184.216.34:9200", "who": "a"}}
    response = await client.post(f"/api/v1/connectors/{CONNECTOR}/test", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["error"] == "[redacted] [redacted]"
    assert body["details"]["url"] == "https://93.184.216.34:9200"
    assert body["details"]["who"] == "a"
