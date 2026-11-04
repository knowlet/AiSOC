"""Canonical rule metadata survives the ingest-to-promotion boundary.

These tests use the serialized ``raw_data`` shape the Go ingest service
publishes. They exercise promotion, not a live Indexer or a running spine.
"""

from __future__ import annotations

import json

import pytest
from app.services.promoter import promote_normalized_event

TENANT = "11111111-1111-1111-1111-111111111111"
CONNECTOR = "22222222-2222-2222-2222-222222222222"
LOG_LINE = "sshd[1742]: Failed password for invalid user operator from 192.0.2.31 port 45512 ssh2"


def _message(raw_data: object) -> dict:
    return {
        "tenant_id": TENANT,
        "connector_id": CONNECTOR,
        "connector_type": "wazuh",
        "ocsf_event": {
            "class_uid": 2001,
            "severity_id": 4,
            "message": "sshd: Attempt to login using a non-existent user.",
            "metadata": {"product": {"name": "wazuh", "vendor_name": "wazuh"}},
            "finding": {"uid": "wazuh-alerts-4.x-2026.11.04:doc-1"},
            "device": {"name": "test-web-01"},
            "raw_data": raw_data,
        },
    }


@pytest.mark.parametrize("serialized", [True, False], ids=["ingest-json-string", "direct-object"])
def test_promotion_preserves_declared_rule_and_log_context(serialized: bool) -> None:
    payload = {
        "source": "wazuh",
        "external_id": "wazuh-alerts-4.x-2026.11.04:doc-1",
        "rule_id": "5710",
        "rule_name": "sshd: Attempt to login using a non-existent user.",
        "description": LOG_LINE,
        "raw_event": {"rule": {"id": "5710"}, "full_log": LOG_LINE},
    }
    message = _message(json.dumps(payload) if serialized else payload)
    alert = promote_normalized_event(message)

    assert alert is not None
    assert alert.rule_id == "5710"
    assert alert.rule_name == payload["rule_name"]
    assert alert.external_id == payload["external_id"]
    assert alert.description == LOG_LINE
    assert alert.raw_event == message["ocsf_event"]


def test_document_identity_is_not_inferred_to_be_a_rule() -> None:
    alert = promote_normalized_event(_message(json.dumps({"external_id": "doc-1", "title": "An alert"})))

    assert alert is not None
    assert alert.external_id == "wazuh-alerts-4.x-2026.11.04:doc-1"
    assert alert.rule_id is None
    assert alert.rule_name is None


def test_numeric_rule_id_keeps_its_identity() -> None:
    alert = promote_normalized_event(_message(json.dumps({"rule_id": 5710, "rule_name": "  SSH rule  "})))

    assert alert is not None
    assert alert.rule_id == "5710"
    assert alert.rule_name == "SSH rule"


@pytest.mark.parametrize("raw_data", ['{"rule_id":', "[]", None, {"rule_id": {}, "rule_name": []}, {"rule_id": True}])
def test_malformed_rule_metadata_does_not_break_promotion(raw_data: object) -> None:
    alert = promote_normalized_event(_message(raw_data))

    assert alert is not None
    assert alert.rule_id is None
    assert alert.rule_name is None
