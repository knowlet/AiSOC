"""Queue discovery stays caller-scoped, bounded and read-only at the tool boundary."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from app.api.copilot_grounding import ground_answer
from app.prompting.tool_results import MAX_TOOL_MESSAGE_CHARS, render_tool_message
from app.security.agent_identity import issue_identity
from app.tools.copilot import MAX_EVIDENCE_BYTES, MAX_RECORDS, CopilotReads

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")
RECORD = "00000000-0000-0000-0000-000000000222"
TOOLS = ("copilot_cases", "copilot_pending_approvals")


def case_row(**values):
    return {
        "id": RECORD,
        "case_number": "INC-42",
        "title": "Investigate 198.51.100.42",
        "description": "Suspicious host activity",
        "severity": "high",
        "status": "investigating",
        **values,
    }


def approval_row(**values):
    return {
        "id": RECORD,
        "title": "Review containment of 198.51.100.42",
        "summary": "Analyst confirmation required",
        "risk_level": "high",
        "status": "pending",
        "expires_at": "2026-11-17T00:00:00Z",
        **values,
    }


def approval_page(rows=None, **values):
    rows = [approval_row()] if rows is None else rows
    return {"items": rows, "total": len(rows), "page": 1, "page_size": MAX_RECORDS, "pages": 1, **values}


@pytest.fixture
def api(monkeypatch):
    calls, answer = [], {"response": httpx.Response(200, json=[])}
    real_client = httpx.AsyncClient

    async def handle(request):
        calls.append(request)
        return answer["response"]

    class Client(real_client):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("transport", httpx.MockTransport(handle))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    monkeypatch.setenv("AISOC_API_URL", "http://api.test")
    return calls, answer


async def execute(reads, name, args=None):
    return await reads.registry().execute(name, args or {}, identity=issue_identity("copilot", run_id="queue-test"))


@pytest.mark.asyncio
async def test_case_search_uses_lookahead_without_fabricating_a_total(api):
    calls, answer = api
    rows = [case_row(id=str(uuid.UUID(int=i + 1))) for i in range(MAX_RECORDS + 1)]
    answer["response"] = httpx.Response(200, json=rows)
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, "copilot_cases", {"status": "investigating", "severity": "high", "query": "INC-42", "page": 2})
    assert result.get("available") is True, result
    assert result["page"] == 2 and result["next_page"] == 3 and result["has_more"] is True
    assert "total" not in result
    assert 0 < len(result["records"]) == len(reads.sources) <= MAX_RECORDS
    assert result["records"][0]["ref"] == "case:" + rows[0]["id"]
    assert all(source.ref != "case:" + rows[-1]["id"] for source in reads.sources)
    assert json.loads(render_tool_message(result)) == result
    assert result["records"][0]["case_number"] == "INC-42"
    request = calls[0]
    assert request.method == "GET" and request.url.path == "/api/v1/cases"
    assert dict(request.url.params) == {"limit": "21", "offset": "20", "status": "investigating", "severity": "high", "query": "INC-42"}
    assert request.headers["authorization"] == "Bearer analyst-token"
    assert request.headers["x-aisoc-tenant-id"] == str(TENANT)


@pytest.mark.asyncio
async def test_pending_approval_read_keeps_metadata_and_discards_the_action_payload(api):
    calls, answer = api
    answer["response"] = httpx.Response(
        200,
        json=approval_page([approval_row(action={"api_token": "SECRET", "host": "203.0.113.99"}, decision_comment="SECRET")], total=21),
    )
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, "copilot_pending_approvals", {"mine": True, "risk_level": "high"})
    assert result["available"] is True, result
    assert result["total"] == 21 and result["next_page"] == 2 and result["has_more"] is True
    assert result["records"][0]["ref"] == f"approval:{RECORD}"
    assert result["records"][0]["expires_at"] == "2026-11-17T00:00:00Z"
    assert "expires_at" in result["coverage"] and "No approval decision" in result["coverage"]
    for value in (json.dumps(result), " ".join(source.text for source in reads.sources)):
        assert "SECRET" not in value and "203.0.113.99" not in value
    request = calls[0]
    assert request.method == "GET" and request.url.path == "/api/v1/approvals"
    assert dict(request.url.params) == {"status": "pending", "mine": "true", "risk_level": "high", "page": "1", "page_size": "20"}
    assert request.headers["authorization"] == "Bearer analyst-token"
    assert request.headers["x-aisoc-tenant-id"] == str(TENANT)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TOOLS)
async def test_last_allowed_page_still_discloses_more_results(api, name):
    _, answer = api
    payload = [case_row(id=str(uuid.UUID(int=i + 1))) for i in range(MAX_RECORDS + 1)]
    if name == "copilot_pending_approvals":
        payload = approval_page(total=201, page=10, pages=11)
    answer["response"] = httpx.Response(200, json=payload)
    result = await execute(CopilotReads("Bearer analyst-token", TENANT), name, {"page": 10})
    assert result["available"] is True, result
    assert result["has_more"] is True and result["next_page"] is None
    assert "10 pages" in result["coverage"]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TOOLS)
async def test_empty_queue_is_a_success_but_not_an_upstream_search(api, name):
    _, answer = api
    answer["response"] = httpx.Response(200, json=[] if name == "copilot_cases" else approval_page([]))
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, name)
    assert result["available"] is True and result["records"] == []
    assert result["has_more"] is False and result["next_page"] is None
    assert reads.sources == [] and reads.calls[0]["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TOOLS)
@pytest.mark.parametrize("status", [301, 401, 403, 503])
async def test_queue_refusal_never_becomes_empty_success_or_leaks_response_body(api, name, status):
    calls, answer = api
    answer["response"] = httpx.Response(status, headers={"Location": "https://attacker.invalid"}, text="SECRET")
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, name)
    assert result["available"] is False, result
    assert "records" not in result and "SECRET" not in json.dumps(result)
    assert reads.sources == [] and reads.calls[0]["status"] == "could_not_check"
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,payload",
    [
        ("copilot_cases", {"items": []}),
        ("copilot_cases", [None]),
        ("copilot_cases", [case_row(id="../../secrets")]),
        ("copilot_cases", [case_row(title=None)]),
        ("copilot_cases", [case_row()] * (MAX_RECORDS + 2)),
        ("copilot_pending_approvals", []),
        ("copilot_pending_approvals", {"items": [], "total": 0}),
        ("copilot_pending_approvals", approval_page([approval_row(status="approved")])),
        ("copilot_pending_approvals", approval_page(total=True)),
        ("copilot_pending_approvals", approval_page(total=-1)),
        ("copilot_pending_approvals", approval_page(page=2)),
        ("copilot_pending_approvals", approval_page([approval_row(id="not-a-uuid")])),
    ],
)
async def test_malformed_queue_contracts_are_not_evidence(api, name, payload):
    _, answer = api
    answer["response"] = httpx.Response(200, json=payload)
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, name)
    assert result["available"] is False, result
    assert reads.sources == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TOOLS)
async def test_queue_reads_require_caller_credential_and_copilot_scope(api, monkeypatch, name):
    calls, _ = api
    monkeypatch.setenv("AISOC_AGENTS_API_KEY", "privileged-service-credential")
    result = await execute(CopilotReads(None, TENANT), name)
    assert result["available"] is False, result
    registry = CopilotReads("Bearer analyst-token", TENANT).registry()
    denied = await registry.execute(name, {}, identity=issue_identity("triage", run_id="triage"))
    assert "scope" in denied["error"]
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,args",
    [
        ("copilot_cases", {"tenant_id": str(uuid.uuid4())}),
        ("copilot_cases", {"query": "x" * 201}),
        ("copilot_cases", {"query": ""}),
        ("copilot_cases", {"page": 11}),
        ("copilot_cases", {"page": 0}),
        ("copilot_pending_approvals", {"url": "https://attacker.invalid"}),
        ("copilot_pending_approvals", {"status": "approved"}),
        ("copilot_pending_approvals", {"mine": "true"}),
        ("copilot_pending_approvals", {"risk_level": "invalid"}),
        ("copilot_pending_approvals", {"page": 11}),
        ("approve_review", {"id": RECORD}),
    ],
)
async def test_model_cannot_supply_credentials_tenants_routes_or_writes(api, name, args):
    calls, _ = api
    result = await execute(CopilotReads("Bearer analyst-token", TENANT), name, args)
    assert "error" in result, result
    assert calls == []


@pytest.mark.asyncio
async def test_queue_metadata_obeys_the_shared_evidence_budget(api):
    _, answer = api
    answer["response"] = httpx.Response(
        200,
        json=approval_page([approval_row(id=str(uuid.UUID(int=i + 1)), title="x" * 2000, summary="y" * 2000) for i in range(20)]),
    )
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, "copilot_pending_approvals")
    assert result["truncated"] is True and len(result["records"]) < 20
    assert result["total"] == 20
    assert len(reads.sources) == len(result["records"])
    assert reads._evidence_bytes <= MAX_EVIDENCE_BYTES


def test_tool_envelope_keeps_pagination_and_only_cites_records_the_model_received():
    reads = CopilotReads()
    result = reads._records(
        "copilot_cases",
        "case",
        [
            case_row(title="Check 198.51.100.42"),
            case_row(id=str(uuid.uuid4()), description="調查" * 400 + " 203.0.113.99"),
        ],
        page=1,
        has_more=True,
        next_page=2,
        coverage="Matching cases only; no total count.",
    )
    encoded = render_tool_message(result)
    assert len(encoded) <= MAX_TOOL_MESSAGE_CHARS
    decoded = json.loads(encoded)
    assert decoded["has_more"] is True and decoded["next_page"] == 2
    assert decoded["coverage"] == "Matching cases only; no total count."
    assert decoded["truncated"] is True and "omitted records" in decoded["truncation_notice"]
    assert len(decoded["records"]) == len(reads.sources) == 1
    assert "203.0.113.99" not in encoded
    grounded = ground_answer("198.51.100.42 and 203.0.113.99 need review.", reads.sources)
    assert grounded.uncited == ("203.0.113.99",)
    assert grounded.citations[0].refs == (f"case:{RECORD}",)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["case_queue", "case", "alert", "approval"])
async def test_oversized_first_record_keeps_a_citable_summary_and_a_path_to_details(api, kind):
    _, answer = api
    prose = "調查" * 400 + " 203.0.113.99"
    row = case_row(title="Review 198.51.100.42", description=prose, raw_event={"full_log": prose})
    name, args = "copilot_record", {"kind": kind, "record_id": RECORD}
    payload = row
    if kind == "case_queue":
        name, args, payload = "copilot_cases", {}, [row]
    elif kind == "approval":
        name, args = "copilot_pending_approvals", {}
        row = approval_row(title="Review 198.51.100.42", summary=prose)
        payload = approval_page([row])
    answer["response"] = httpx.Response(200, json=payload)
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await execute(reads, name, args)
    assert result["available"] is True, result
    decoded = json.loads(render_tool_message(result))
    assert decoded["truncated"] is True
    assert len(decoded["records"]) == len(reads.sources) == 1
    assert "fields" in decoded["truncation_notice"] and "console" in decoded["truncation_notice"]
    record = decoded["records"][0]
    expected_kind = "case" if kind == "case_queue" else kind
    assert record["id"] == RECORD and record["ref"] == f"{expected_kind}:{RECORD}"
    assert record["title"] == row["title"] and record["status"] == row["status"]
    if kind == "approval":
        assert record["expires_at"] == row["expires_at"] and record["risk_level"] == row["risk_level"]
    else:
        assert record["severity"] == row["severity"]
    assert "description" not in record and "raw_event" not in record and "summary" not in record
    grounded = ground_answer("198.51.100.42 and 203.0.113.99 need review.", reads.sources)
    assert grounded.uncited == ("203.0.113.99",)
    assert grounded.citations[0].refs == (f"{expected_kind}:{RECORD}",)


@pytest.mark.asyncio
async def test_summary_fallback_does_not_bypass_the_cumulative_evidence_budget(api):
    _, answer = api
    answer["response"] = httpx.Response(200, json=[case_row(description="調查" * 400)])
    reads = CopilotReads("Bearer analyst-token", TENANT)
    reads._evidence_bytes = MAX_EVIDENCE_BYTES
    result = await execute(reads, "copilot_cases")
    assert result["truncated"] is True and result["records"] == []
    assert reads.sources == [] and reads._evidence_bytes == MAX_EVIDENCE_BYTES
