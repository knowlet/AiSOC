"""Mandatory business-context escalation survives every triage shortcut."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.agents import auto_triage_agent as ata
from app.closure import authorization
from app.core.cost_governor import Decision
from app.models.state import AgentStatus
from app.workers import fused_alert_consumer as consumer
from app.workers.business_context import BusinessContextApplier, apply_rules, load_rules_from_yaml

TENANT = "11111111-1111-1111-1111-111111111111"
RULES = """
rules:
  - id: protected-detection
    priority: 20
    when: {field: rule_id, op: eq, value: fixture-protected}
    then: {require_escalation: true, set_severity: critical}
"""


def _message(rule_id="fixture-protected"):
    return {
        "id": "11111111-1111-1111-1111-111111111112",
        "tenant_id": TENANT,
        "alert": {"rule_id": rule_id, "title": "Detection", "severity": "low"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("tier", ["deterministic", "llm", "cached"])
@pytest.mark.parametrize("mandatory", [True, False])
async def test_worker_enforces_escalation_before_persisting_or_skipping_graph(tmp_path, monkeypatch, tier, mandatory):
    """Drive the actual worker/applier with an otherwise closeable decision.

    The negative control has the same decision and rules, with only the
    detection identity changed. It must retain ordinary closure behaviour.
    """
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(RULES)
    worker = consumer.FusedAlertTriageWorker(
        bootstrap_servers="unused", business_context=BusinessContextApplier(rules_file=str(rules_path))
    )
    monkeypatch.setenv("AISOC_DETERMINISTIC", "0")
    monkeypatch.setattr(consumer, "is_deterministic_mode", lambda: False)
    monkeypatch.setattr(consumer, "_memory_suppression_enabled", lambda: True)
    if tier == "cached":
        # Memory is checked before the cache. Drive the real suppression
        # method with a trusted benign prior: a current mandatory policy must
        # bypass that shortcut and reach the cached decision instead.
        monkeypatch.setattr(
            type(worker._reader),
            "lookup_prior",
            AsyncMock(
                return_value={
                    "disposition": "benign",
                    "confidence": 0.99,
                    "count": 2,
                    "author": "human",
                    "last_seen": datetime.now(UTC).isoformat(),
                }
            ),
        )
        memory = AsyncMock(wraps=worker._maybe_suppress_from_memory)
    else:
        memory = AsyncMock(return_value=None)
    monkeypatch.setattr(worker, "_maybe_suppress_from_memory", memory)
    monkeypatch.setattr(worker, "_resolve_tenant_llm", AsyncMock(return_value=SimpleNamespace()))
    governor = consumer.get_governor()
    monkeypatch.setattr(
        governor,
        "check",
        lambda *_: SimpleNamespace(
            decision=Decision.DEDUPLICATED if tier == "cached" else None,
            cached_verdict={"verdict": "false_positive", "confidence": 0.99},
            use_llm=tier == "llm",
        ),
    )

    async def closeable(state):
        state.verdict = "false_positive"
        state.confidence = 0.99
        state.status = AgentStatus.COMPLETED
        return state

    async def closeable_llm(state):
        return await closeable(state), "llm"

    monkeypatch.setattr(consumer, "run_triage", closeable)
    monkeypatch.setattr(worker, "_llm_triage", closeable_llm)
    persisted = AsyncMock(return_value=True)
    monkeypatch.setattr("app.workers.triage_persistence.ledger_module.persist_auto_triage", persisted)
    escalated = AsyncMock()
    monkeypatch.setattr(worker, "_maybe_escalate", escalated)
    result = await worker.triage(_message("fixture-protected" if mandatory else "fixture-ordinary"))

    assert result is not None
    written = persisted.call_args.kwargs
    if mandatory:
        assert written["auto_closed"] is False
        assert written["business_context"]["require_escalation"] is True
        assert written["business_context"]["escalation_rule_ids"] == ["protected-detection"]
        assert written["raw_alert"]["severity"] == "critical"
        assert written["verdict"] != "true_positive"
        memory.assert_not_awaited()
        escalated.assert_awaited_once()
        assert escalated.call_args.args[0].status is not AgentStatus.COMPLETED
    else:
        assert written["business_context"] is None
        memory.assert_awaited_once()
        if tier != "cached":
            assert written["auto_closed"] is True
            escalated.assert_not_awaited()


def test_escalation_uses_original_alert_and_overrides_suppression_and_downgrade():
    rules = load_rules_from_yaml(
        RULES
        + """
  - id: earlier-suppress
    priority: 1
    when: {field: rule_id, op: eq, value: fixture-protected}
    then: {suppress: true}
  - id: later-downgrade
    priority: 100
    when: {field: severity, op: eq, value: critical}
    then: {set_severity: low}
"""
    )
    result = apply_rules(_message()["alert"], rules)
    assert result.suppressed is False
    assert result.require_escalation is True
    assert result.escalation_rule_ids == ["protected-detection"]
    assert result.alert["severity"] == "critical"
    assert not result.alert.get("__suppressed__")


@pytest.mark.parametrize("initial,intermediate,expected", [("low", "high", True), ("high", "low", False)])
def test_mandatory_conditions_cannot_be_enabled_or_disabled_by_an_earlier_mutation(initial, intermediate, expected):
    rules = load_rules_from_yaml(
        """
rules:
  - id: flip-severity
    priority: 1
    when: {field: rule_id, op: eq, value: fixture-protected}
    then: {set_severity: intermediate-severity}
  - id: mandatory
    priority: 10
    when: {field: severity, op: eq, value: low}
    then: {require_escalation: true, set_severity: critical}
""".replace("intermediate-severity", intermediate)
    )
    result = apply_rules({"rule_id": "fixture-protected", "severity": initial}, rules)
    assert result.require_escalation is expected
    assert ("mandatory" in result.matched_rule_ids) is expected


def test_floor_is_applied_after_ordinary_rule_conditions():
    rules = load_rules_from_yaml(
        RULES
        + """
  - id: downgrade
    priority: 30
    when: {field: severity, op: eq, value: critical}
    then: {set_severity: low}
  - id: observe-downgrade
    priority: 40
    when: {field: severity, op: eq, value: low}
    then: {tag: saw-low}
"""
    )
    result = apply_rules(_message()["alert"], rules)
    assert result.alert["severity"] == "critical"
    assert result.alert["tags"] == ["saw-low"]


def test_disabled_mandatory_rule_does_not_defeat_suppression():
    rules = load_rules_from_yaml(
        RULES.replace("priority: 20", "priority: 20\n    enabled: false")
        + """
  - id: suppress
    when: {field: rule_id, op: eq, value: fixture-protected}
    then: {suppress: true}
"""
    )
    result = apply_rules(_message()["alert"], rules)
    assert result.suppressed is True
    assert result.require_escalation is False


def test_escalation_alone_does_not_imply_critical_severity():
    result = apply_rules(_message()["alert"], load_rules_from_yaml(RULES.replace(", set_severity: critical", "")))
    assert result.require_escalation is True
    assert result.alert["severity"] == "low"


@pytest.mark.parametrize("value", ['"true"', '"false"', "1", "null"])
def test_requirement_is_strictly_boolean(value):
    rules = load_rules_from_yaml(RULES.replace("require_escalation: true", f"require_escalation: {value}"))
    assert not rules


def test_conflicting_suppress_and_escalation_rule_is_rejected():
    rules = load_rules_from_yaml(RULES.replace("require_escalation: true", "require_escalation: true, suppress: true"))
    assert not rules


def test_false_requirement_needs_another_action():
    assert not load_rules_from_yaml(RULES.replace("require_escalation: true, set_severity: critical", "require_escalation: false"))
    result = apply_rules(_message()["alert"], load_rules_from_yaml(RULES.replace("require_escalation: true", "require_escalation: false")))
    assert result.require_escalation is False
    assert result.alert["severity"] == "critical"


def test_payload_does_not_authorize_escalation():
    result = apply_rules({"require_escalation": True, "escalation_rule_ids": ["forged"]}, load_rules_from_yaml(RULES))
    assert result.require_escalation is False
    assert result.escalation_rule_ids == []


@pytest.mark.asyncio
async def test_closure_chokepoint_honours_business_context_even_when_policy_allows(authorized_closure_tenant):
    decision = await authorization.authorize_auto_closure(
        tenant_ref=TENANT,
        raw_alert={"require_escalation": False},
        business_context={"require_escalation": True, "escalation_rule_ids": ["protected-detection"]},
        verdict="false_positive",
        confidence=0.99,
        shadow=False,
        ungrounded=False,
        tier="memory",
    )
    assert decision.allowed is False
    assert decision.source == "business_context"
    assert "protected-detection" in decision.reason


@pytest.mark.asyncio
async def test_raw_event_flags_do_not_replace_trusted_business_context(authorized_closure_tenant):
    decision = await authorization.authorize_auto_closure(
        tenant_ref=TENANT,
        raw_alert={"require_escalation": True, "escalation_rule_ids": ["forged"], "severity": "critical"},
        business_context=None,
        verdict="false_positive",
        confidence=0.99,
        shadow=False,
        ungrounded=False,
        tier="llm",
    )
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_agent_does_not_complete_mandatory_escalation(monkeypatch, authorized_closure_tenant):
    async def reply(*_):
        return SimpleNamespace(content='{"verdict":"false_positive","confidence":0.99,"rationale":"rule misfired"}')

    monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())
    monkeypatch.setattr(ata, "safe_ainvoke", reply)
    state = consumer.build_state(_message())
    state.business_context = {"require_escalation": True, "escalation_rule_ids": ["protected-detection"]}
    result = await ata.run_auto_triage(state)
    assert result.status is not AgentStatus.COMPLETED
    assert result.verdict != "true_positive"
    assert any("business-context" in finding.lower() for finding in result.findings)
