"""Read-only console tools, using the caller's credential rather than a service grant.

The core API remains the authority for tenant and resource permissions. Neither
an LLM argument nor page context can choose a URL, credential or tenant. Results
are bounded before becoming both model context and citable evidence.
"""

from __future__ import annotations

import json
import math
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.api.copilot_grounding import EvidenceSource
from app.prompting.tool_results import MAX_TOOL_MESSAGE_CHARS
from app.tools.registry import Tool, ToolRegistry

MAX_RESPONSE_BYTES = 256_000
MAX_EVIDENCE_BYTES = 24_000
MAX_RECORDS = 20
_RECORD_KEYS = (
    "id",
    "title",
    "description",
    "severity",
    "status",
    "priority",
    "created_at",
    "event_time",
    "first_seen",
    "last_seen",
    "rule_id",
    "rule_name",
    "connector_type",
    "entities",
    "affected_hosts",
    "affected_ips",
    "affected_users",
    "mitre_techniques",
    "ai_summary",
    "raw_event",
    "summary",
    "entity_type",
    "entity_value",
    "score",
    "alert_count",
    "contributing_alerts",
    "severities",
    "contributors",
)
_CASE_KEYS = (
    "id",
    "case_number",
    "title",
    "description",
    "severity",
    "status",
    "assignee",
    "created_at",
    "updated_at",
    "opened_at",
    "sla_due_at",
    "mitre_techniques",
    "alert_ids",
)
_APPROVAL_KEYS = (
    "id",
    "title",
    "summary",
    "status",
    "risk_level",
    "requested_by",
    "case_id",
    "alert_id",
    "created_at",
    "expires_at",
)
_SUMMARY_KEYS = (
    "title",
    "case_number",
    "status",
    "severity",
    "risk_level",
    "expires_at",
    "score",
    "entity_type",
    "entity_value",
    "priority",
    "case_id",
    "alert_id",
    "rule_id",
    "rule_name",
    "connector_type",
    "created_at",
    "event_time",
    "first_seen",
    "last_seen",
)
_TRUNCATION_NOTICE = (
    "Records or fields may be omitted to fit the model context. Open the record in the console for full details; "
    "narrow filters for omitted records. next_page advances the API page and does not recover omitted records."
)


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return "[truncated]"
    if isinstance(value, str):
        return value[:2000] + (" [truncated]" if len(value) > 2000 else "")
    if isinstance(value, list):
        return [_bounded(v, depth + 1) for v in value[:MAX_RECORDS]]
    if isinstance(value, dict):
        return {str(k): _bounded(v, depth + 1) for k, v in list(value.items())[:30]}
    return value


class CopilotReads:
    """A single request's HTTP reads, evidence and provenance; never shared state."""

    def __init__(self, authorization: str | None = None, tenant_id: uuid.UUID | None = None) -> None:
        self._authorization = authorization
        self._tenant_id = tenant_id
        self._now = datetime.now(UTC)
        self._evidence_bytes = 0
        self.sources: list[EvidenceSource] = []
        self.calls: list[dict[str, Any]] = []

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self._tenant_id

    def registry(self) -> ToolRegistry:
        return ToolRegistry(
            [
                Tool(
                    name="copilot_alerts",
                    description=(
                        "Read alerts already ingested into AiSOC from any connected source. Filter by event-time window, "
                        "severity or exact hostname. Results are one bounded page, not the complete estate. "
                        "Use next_page when supplied. This does not query the upstream SIEM or EDR."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "hours": {"type": "integer", "minimum": 1, "maximum": 168},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "hostname": {"type": "string", "minLength": 1, "maxLength": 255},
                            "page": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                    },
                    fn=self.alerts,
                ),
                Tool(
                    name="copilot_cases",
                    description=(
                        "Find cases without knowing their UUIDs. Filter by status, severity, or a literal text substring "
                        "in the case number, title or description. Results are newest first and limited to one page of 20. "
                        "Use next_page when supplied; the API does not report a total. "
                        "Use copilot_record with a returned case UUID for details."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "status": {"type": "string", "enum": ["new", "triaged", "investigating", "contained", "resolved", "closed"]},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "query": {"type": "string", "minLength": 1, "maxLength": 200},
                            "page": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                    },
                    fn=self.cases,
                ),
                Tool(
                    name="copilot_pending_approvals",
                    description=(
                        "Read pending response approvals for this tenant, optionally only those assigned specifically "
                        "to the current analyst or at a risk level. Results are bounded queue metadata, newest first. "
                        "This never approves, denies or executes an action. Use next_page when supplied."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "mine": {"type": "boolean"},
                            "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                            "page": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                    },
                    fn=self.pending_approvals,
                ),
                Tool(
                    name="copilot_record",
                    description=(
                        "Read one tenant-authorized alert or case by its UUID. Cite the returned ref, not a client-supplied snapshot."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "kind": {"type": "string", "enum": ["alert", "case"]},
                            "record_id": {"type": "string", "format": "uuid", "maxLength": 36},
                        },
                        "required": ["kind", "record_id"],
                    },
                    fn=self.record,
                ),
                Tool(
                    name="copilot_entity_risk",
                    description=(
                        "Read Fusion risk for an entity, or the highest-scored observed entities of a type (host by default). "
                        "Queue coverage is bounded to Fusion's top 200 entities, not all assets. Risk is not proof of compromise. "
                        "Use contributing_alerts with copilot_record to investigate the evidence."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "entity_type": {"type": "string", "enum": ["host", "user", "src_ip", "domain"]},
                            "entity_value": {"type": "string", "minLength": 1, "maxLength": 255},
                        },
                    },
                    fn=self.entity_risk,
                ),
            ]
        )

    def _unavailable(self, operation: str, reason: str) -> dict[str, Any]:
        self.calls.append({"tool": operation, "status": "could_not_check", "reason": reason})
        return {
            "available": False,
            "outcome": "could_not_check",
            "reason": reason,
            "notice": "This lookup did not complete. It is not evidence of an empty queue, no alerts or no risk.",
        }

    async def _get(
        self,
        operation: str,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        list_response: bool = False,
    ) -> dict[str, Any]:
        if not self._authorization or not self._tenant_id:
            return self._unavailable(operation, "No caller credential is available for this read.")
        headers = {"Authorization": self._authorization, "X-AiSOC-Tenant-ID": str(self._tenant_id)}
        # A fixed deployment target and fixed route families. Never follow a
        # redirect with the console bearer, or substitute a stronger credential.
        url = os.getenv("AISOC_API_URL", "http://api:8000").rstrip("/") + path
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                async with client.stream("GET", url, params=params, headers=headers) as response:
                    if response.status_code != 200:
                        return self._unavailable(operation, f"The core API returned HTTP {response.status_code}.")
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_RESPONSE_BYTES:
                            return self._unavailable(operation, "The API response exceeded the safe read limit.")
            body = json.loads(data)
            if list_response:
                if not isinstance(body, list):
                    raise ValueError("expected list")
                return {"items": body}
            if not isinstance(body, dict):
                raise ValueError("expected object")
            return body
        except (httpx.HTTPError, ValueError):
            # Do not put upstream bodies, URLs with credentials, or exception
            # strings into the prompt. The HTTP status is enough to diagnose.
            return self._unavailable(operation, "The core API did not return a readable response.")

    def _records(
        self,
        operation: str,
        kind: str,
        rows: list[dict[str, Any]],
        *,
        fields: tuple[str, ...] = _RECORD_KEYS,
        **coverage: Any,
    ) -> dict[str, Any]:
        result: list[dict[str, Any]] = []
        sources: list[EvidenceSource] = []
        truncated = len(rows) > MAX_RECORDS
        retained_bytes = 0
        envelope = {
            "available": True,
            "outcome": "ok",
            "retrieved_at": datetime.now(UTC).isoformat(),
            **coverage,
        }

        def fits(entry: dict[str, Any]) -> bool:
            candidate = {
                **envelope,
                "truncated": True,
                "truncation_notice": _TRUNCATION_NOTICE,
                "records": [*result, entry],
            }
            return (
                self._evidence_bytes + retained_bytes + len(json.dumps(entry, ensure_ascii=False).encode()) <= MAX_EVIDENCE_BYTES
                and len(json.dumps(candidate, default=str)) <= MAX_TOOL_MESSAGE_CHARS
            )

        for row in rows[:MAX_RECORDS]:
            projected = {key: _bounded(row[key]) for key in fields if key in row}
            truncated |= any(projected[k] != row[k] for k in projected)
            identifier = row.get("id") if kind != "entity_risk" else f"{row.get('entity_type')}:{row.get('entity_value')}"
            if not identifier:
                return self._unavailable(operation, "The API returned a record without an identifier.")
            ref = f"{kind}:{identifier}"
            entry = {"ref": ref, **projected}
            # Match the actual tool-message renderer, including JSON's default
            # Unicode escaping. Reserve room for the truncation notice before
            # accepting a record, so metadata and citations cannot outlive the
            # complete JSON that reaches the model.
            if not fits(entry):
                truncated = True
                if result:
                    break
                # A long description or raw event must not erase the first
                # matching record. Keep its identity and bounded metadata so
                # the analyst can open it, without citing omitted prose.
                summary = {"id": projected["id"]} if "id" in projected else {}
                if not fits({"ref": ref, **summary}):
                    break
                for key in _SUMMARY_KEYS:
                    if key not in projected:
                        continue
                    value = projected[key]
                    if isinstance(value, str):
                        value = value[:160] + (" [truncated]" if len(value) > 160 else "")
                    elif value is not None and not isinstance(value, bool | int | float):
                        continue
                    if fits({"ref": ref, **summary, key: value}):
                        summary[key] = value
                projected = summary
                entry = {"ref": ref, **projected}
            retained_bytes += len(json.dumps(entry, ensure_ascii=False).encode())
            result.append(entry)
            sources.append(EvidenceSource(ref=ref, kind=kind, text=json.dumps(projected), label=str(projected.get("title") or identifier)))
        self._evidence_bytes += retained_bytes
        self.sources.extend(sources)
        self.calls.append({"tool": operation, "status": "ok", "records": len(result), "truncated": truncated})
        return {
            **envelope,
            "truncated": truncated,
            **({"truncation_notice": _TRUNCATION_NOTICE} if truncated else {}),
            "records": result,
        }

    async def alerts(self, hours: int = 24, severity: str | None = None, hostname: str | None = None, page: int = 1) -> dict[str, Any]:
        now = self._now
        params: dict[str, Any] = {
            "page": page,
            "page_size": MAX_RECORDS,
            "sort": "priority",
            "event_since": (now - timedelta(hours=hours)).isoformat(),
            "event_until": now.isoformat(),
        }
        if severity:
            params["severity"] = severity
        if hostname:
            params["hostname"] = hostname
        body = await self._get("copilot_alerts", "/api/v1/alerts", params)
        if body.get("available") is False:
            return body
        rows, total = body.get("items"), body.get("total")
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows) or not isinstance(total, int):
            return self._unavailable("copilot_alerts", "The alert list response did not match its contract.")
        return self._records(
            "copilot_alerts",
            "alert",
            rows,
            total=total,
            page=page,
            next_page=page + 1 if page * MAX_RECORDS < total and page < 10 else None,
            window={"field": "event_time", "since": params["event_since"], "until": params["event_until"]},
            coverage="Ingested AiSOC alerts only; missing upstream telemetry was not searched.",
        )

    async def cases(
        self,
        status: str | None = None,
        severity: str | None = None,
        query: str | None = None,
        page: int = 1,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": MAX_RECORDS + 1, "offset": (page - 1) * MAX_RECORDS}
        for key, value in (("status", status), ("severity", severity), ("query", query)):
            if value is not None:
                params[key] = value
        body = await self._get("copilot_cases", "/api/v1/cases", params, list_response=True)
        if body.get("available") is False:
            return body
        rows = body["items"]
        if len(rows) > MAX_RECORDS + 1 or not self._queue_records_valid(rows):
            return self._unavailable("copilot_cases", "The case list response did not match its contract.")
        has_more = len(rows) > MAX_RECORDS
        return self._records(
            "copilot_cases",
            "case",
            rows[:MAX_RECORDS],
            fields=_CASE_KEYS,
            page=page,
            has_more=has_more,
            next_page=page + 1 if has_more and page < 10 else None,
            coverage="Matching AiSOC cases only, newest first; at most 10 pages. The API does not supply a total count.",
        )

    async def pending_approvals(self, mine: bool = False, risk_level: str | None = None, page: int = 1) -> dict[str, Any]:
        params: dict[str, Any] = {"status": "pending", "mine": mine, "page": page, "page_size": MAX_RECORDS}
        if risk_level is not None:
            params["risk_level"] = risk_level
        body = await self._get("copilot_pending_approvals", "/api/v1/approvals", params)
        if body.get("available") is False:
            return body
        rows, total = body.get("items"), body.get("total")
        if (
            not isinstance(rows, list)
            or len(rows) > MAX_RECORDS
            or not self._queue_records_valid(rows)
            or any(row.get("status") != "pending" for row in rows)
            or type(total) is not int
            or total < len(rows)
            or body.get("page") != page
            or body.get("page_size") != MAX_RECORDS
        ):
            return self._unavailable("copilot_pending_approvals", "The approval list response did not match its contract.")
        has_more = page * MAX_RECORDS < total
        return self._records(
            "copilot_pending_approvals",
            "approval",
            rows,
            fields=_APPROVAL_KEYS,
            total=total,
            page=page,
            has_more=has_more,
            next_page=page + 1 if has_more and page < 10 else None,
            coverage=(
                "Pending AiSOC response approvals only; at most 10 pages. "
                "mine=true means explicitly assigned to this analyst, not every action they may approve. "
                "Pending rows can be past expires_at; check expiry before suggesting review. "
                "Action payloads are omitted. No approval decision or response action was performed."
            ),
        )

    @staticmethod
    def _queue_records_valid(rows: list[Any]) -> bool:
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("title"), str):
                return False
            try:
                if not isinstance(row.get("id"), str) or str(uuid.UUID(row["id"])) != row["id"]:
                    return False
            except ValueError:
                return False
        return True

    async def record(self, kind: str, record_id: str) -> dict[str, Any]:
        if kind not in {"alert", "case"}:
            return self._unavailable("copilot_record", "Unsupported record type.")
        try:
            identifier = str(uuid.UUID(record_id))
        except ValueError:
            return self._unavailable("copilot_record", "A record UUID is required.")
        body = await self._get("copilot_record", f"/api/v1/{kind}s/{identifier}")
        if body.get("available") is False:
            return body
        if str(body.get("id")) != identifier:
            return self._unavailable("copilot_record", "The returned record did not match the requested UUID.")
        return self._records("copilot_record", kind, [body], fields=_CASE_KEYS if kind == "case" else _RECORD_KEYS)

    async def entity_risk(self, entity_type: str = "host", entity_value: str | None = None) -> dict[str, Any]:
        if entity_value is not None:
            path = f"/api/v1/fusion/entity-risk/{quote(entity_type, safe='')}/{quote(entity_value, safe='')}"
            body = await self._get("copilot_entity_risk", path)
            if body.get("available") is False:
                return body
            rows = [body]
        else:
            body = await self._get("copilot_entity_risk", "/api/v1/fusion/entity-risk/queue", {"limit": 200})
            if body.get("available") is False:
                return body
            if not isinstance(body.get("entities"), list) or not all(isinstance(r, dict) for r in body["entities"]):
                return self._unavailable("copilot_entity_risk", "The risk queue response did not match its contract.")
            rows = [r for r in body["entities"] if r.get("entity_type") == entity_type]
        if not all(
            r.get("entity_type") == entity_type
            and isinstance(r.get("entity_value"), str)
            and isinstance(r.get("score"), int | float)
            and math.isfinite(r["score"])
            and (entity_value is None or r["entity_value"] == entity_value)
            for r in rows
        ):
            return self._unavailable("copilot_entity_risk", "The risk records did not match their contract.")
        rows.sort(key=lambda r: r["score"], reverse=True)
        return self._records(
            "copilot_entity_risk",
            "entity_risk",
            rows,
            coverage="Fusion's observed risk records; queue reads cover at most its top 200 entities, not the whole estate.",
        )
