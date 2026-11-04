"""Wazuh rule and log context survives the production alert-store write.

Requires a migrated, disposable loopback PostgreSQL database. The runtime
DSN must use a non-superuser, non-BYPASSRLS role; the fixture DSN may use the
schema owner to create and clean up one synthetic tenant. This exercises
the actual promoter, asyncpg transport, and AlertSink SQL. It does not run
Kafka, a Wazuh Indexer, or a model.
"""

from __future__ import annotations

import json
import os
import uuid
from urllib.parse import urlsplit

import asyncpg
import pytest
from app.models.alert import FusedAlert, FusionDecision
from app.services.alert_sink import AlertSink, PersistOutcome
from app.services.promoter import promote_normalized_event

DSN = os.getenv("WAZUH_CONTEXT_TEST_POSTGRES", "").strip()
FIXTURE_DSN = os.getenv("WAZUH_CONTEXT_TEST_POSTGRES_ADMIN", "").strip()
pytestmark = pytest.mark.skipif(
    not DSN or not FIXTURE_DSN,
    reason="set WAZUH_CONTEXT_TEST_POSTGRES and WAZUH_CONTEXT_TEST_POSTGRES_ADMIN to run the live store proof",
)


def _loopback_dsn(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgresql", "postgres"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Wazuh context tests require a disposable loopback PostgreSQL database")
    return value


@pytest.mark.asyncio
async def test_wazuh_context_survives_the_alert_store() -> None:
    fixture_dsn = _loopback_dsn(FIXTURE_DSN)
    runtime_dsn = _loopback_dsn(DSN)
    tenant = uuid.uuid4()
    fixture = await asyncpg.connect(fixture_dsn, timeout=10, command_timeout=10)
    try:
        await fixture.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant,
            "Synthetic Wazuh context fixture",
            f"wazuh-context-{tenant.hex}",
        )
    finally:
        await fixture.close()

    sink = AlertSink(runtime_dsn, pool_size=1)
    try:
        rule_name = "sshd: Attempt to login using a non-existent user."
        log_line = "sshd[1742]: Failed password for invalid user fixture from 192.0.2.31 port 45512 ssh2"
        external_id = f"wazuh-alerts-4.x-2026.11.04:fixture-{tenant.hex}"
        payload = {
            "source": "wazuh",
            "external_id": external_id,
            "rule_id": "5710",
            "rule_name": rule_name,
            "description": log_line,
            "raw_event": {"rule": {"id": "5710"}, "full_log": log_line},
        }
        message = {
            "tenant_id": str(tenant),
            "connector_type": "wazuh",
            "ocsf_event": {
                "class_uid": 2001,
                "severity_id": 4,
                "message": rule_name,
                "metadata": {"product": {"name": "wazuh", "vendor_name": "wazuh"}},
                "finding": {"uid": external_id},
                "device": {"name": "synthetic-wazuh-host"},
                "raw_data": json.dumps(payload),
            },
        }
        alert = promote_normalized_event(message)
        assert alert is not None
        alert.id = alert.deterministic_id()
        fused = FusedAlert(id=alert.id, tenant_id=tenant, fusion_decision=FusionDecision.NEW_ALERT, alert=alert)

        result = await sink.persist(fused)
        await sink.stop()

        assert result.outcome is PersistOutcome.INSERTED
        runtime = await asyncpg.connect(runtime_dsn, timeout=10, command_timeout=10)
        try:
            role = await runtime.fetchrow("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            assert role is not None and not role["rolsuper"] and not role["rolbypassrls"]
            row = await runtime.fetchrow(
                "SELECT rule_id, rule_name, external_id, description, raw_event FROM alerts WHERE id = $1 AND tenant_id = $2",
                alert.id,
                tenant,
            )
        finally:
            await runtime.close()
        assert row is not None
        assert row["rule_id"] == "5710"
        assert row["rule_name"] == rule_name
        assert row["external_id"] == external_id
        assert row["description"] == log_line
        raw_event = json.loads(row["raw_event"]) if isinstance(row["raw_event"], str) else row["raw_event"]
        assert json.loads(raw_event["raw_data"])["raw_event"]["full_log"] == log_line
    finally:
        await sink.stop()
        fixture = await asyncpg.connect(fixture_dsn, timeout=10, command_timeout=10)
        try:
            await fixture.execute("DELETE FROM tenants WHERE id = $1", tenant)
        finally:
            await fixture.close()
