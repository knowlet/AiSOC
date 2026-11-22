"""PR2: vulnerability findings are inventory with patch windows, not alerts.

Covers docs/cve-patch-policy.md end to end at the unit level:

* the calendar math (Patch Tuesday -> TEST Wednesday -> PROD +7d),
* the Wazuh stream split (detector events leave ``fetch_alerts`` and arrive
  on ``fetch_vulnerability_findings``),
* the inventory write (due date minted once, fail-closed environment),
* the promotion contract (one grouped alert per CVE, exception-path only).

HTTP routing uses ``respx`` exactly like ``test_wazuh_connector.py``.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime

import httpx
import pytest
import respx
import structlog
from app.connectors.base import Capability
from app.connectors.wazuh import WazuhConnector, is_vulnerability_source
from app.patch_calendar import (
    classify_environment,
    patch_due_for,
    patch_tuesday,
)
from app.patch_calendar import prod_patch_due_for as _prod_patch_due_for
from app.patch_calendar import test_patch_due_for as _test_patch_due_for

INDEXER = "https://wazuh.test.local:9200"
USERNAME = "admin"
PASSWORD = "wazuh-fake-password"


def _detector_hit(cve: str = "CVE-2024-0001", host: str = "prod-tmc-01", cvss=9.8) -> dict:
    return {
        "_id": "doc-vuln",
        "_index": "wazuh-alerts-4.x-2026.10.06",
        "_source": {
            "@timestamp": "2026-10-06T06:00:00.000Z",
            "agent": {"id": "002", "name": host, "ip": "10.0.0.5"},
            "rule": {
                "id": "20570",
                "level": 7,
                "description": f"{cve} affects linux-aws on {host}",
                "groups": ["vulnerability-detector", "vulnerability"],
            },
            "data": {
                "vulnerability": {
                    "cve": cve,
                    "severity": "Critical",
                    "cvss": {"cvss3": {"base_score": cvss}},
                }
            },
        },
    }


def _real_alert_hit() -> dict:
    return {
        "_id": "doc-alert",
        "_index": "wazuh-alerts-4.x-2026.10.06",
        "_source": {
            "@timestamp": "2026-10-06T06:05:00.000Z",
            "agent": {"id": "002", "name": "prod-tmc-01", "ip": "10.0.0.5"},
            "rule": {
                "id": "100100",
                "level": 12,
                "description": "Possible rootkit installation",
                "groups": ["rootcheck", "intrusion_attempt"],
            },
            "data": {"command": "modprobe evil"},
        },
    }


def _hits_response(hits: list[dict]):
    return httpx.Response(200, json={"hits": {"hits": hits}})


def _page_timestamp(hour: int, offset_seconds: int) -> str:
    minute, second = divmod(offset_seconds, 60)
    return f"2026-10-06T{hour:02d}:{minute:02d}:{second:02d}.000Z"


def _cve_page_hit(doc_id: str, timestamp: str, *, finding: bool) -> dict:
    if finding:
        groups = ["vulnerability-detector"]
        data = {"vulnerability": {"cve": "CVE-2024-9999", "severity": "High"}}
        rule_id = "20570"
        description = "CVE-2024-9999 on prod-tmc-01"
    else:
        groups = ["exploit_attempt"]
        data = {"cve": "CVE-2024-0001"}
        rule_id = "100200"
        description = "exploit attempt citing CVE-2024-0001"
    return {
        "_id": doc_id,
        "_index": "wazuh-alerts-4.x-2026.10.06",
        "_source": {
            "@timestamp": timestamp,
            "id": doc_id,
            "agent": {"id": "002", "name": "prod-tmc-01", "ip": "10.0.0.5"},
            "rule": {"id": rule_id, "level": 10, "description": description, "groups": groups},
            "data": data,
        },
    }


def _dig(node: object, field: str) -> object:
    current = node
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _indexed(node: object) -> bool:
    """True when OpenSearch would have an indexed value at this node.

    An empty object has no leaves, so ``exists`` does not match it. A
    dict matches when any descendant does.
    """
    if node is None or node in ("", {}, []):
        return False
    if isinstance(node, dict):
        return any(_indexed(value) for value in node.values())
    if isinstance(node, list):
        return any(_indexed(value) for value in node)
    return True


def _clause_matches(source: dict, clause: dict) -> bool:
    if "terms" in clause:
        field, values = next(iter(clause["terms"].items()))
        got = _dig(source, field)
        if isinstance(got, list):
            return any(value in got for value in values)
        return got in values
    if "exists" in clause:
        return _indexed(_dig(source, clause["exists"]["field"]))
    if "range" in clause:
        # The connector's window is ``now-...``; every fixture is inside it.
        return True
    if "bool" in clause:
        return _bool_matches(source, clause["bool"])
    return False


def _bool_matches(source: dict, boolean: dict) -> bool:
    if any(_clause_matches(source, clause) for clause in boolean.get("must_not", [])):
        return False
    if not all(_clause_matches(source, clause) for clause in boolean.get("must", [])):
        return False
    should = boolean.get("should", [])
    if not should:
        return True
    matched = sum(_clause_matches(source, clause) for clause in should)
    return matched >= boolean.get("minimum_should_match", 1)


def _sort_values(source: dict, spec: list[dict]) -> list:
    values = []
    for item in spec:
        field = next(iter(item))
        values.append(source.get(field))
    return values


def _after_cursor(values: list, cursor: list, spec: list[dict]) -> bool:
    """True when ``values`` sorts strictly after ``cursor`` under ``spec``."""
    for value, previous, item in zip(values, cursor, spec, strict=False):
        options = next(iter(item.values()))
        order = options.get("order", "asc") if isinstance(options, dict) else options
        if value == previous:
            continue
        if value is None or previous is None:
            # ``missing: _last`` — a missing value sorts after every present one.
            if value is None:
                return False
            return True
        later = value < previous if order == "desc" else value > previous
        return later
    return False


def _page_response(corpus: list[dict], request: httpx.Request) -> httpx.Response:
    """Apply size, sort, search_after and the bool query the way the indexer does."""
    body = json.loads(request.content)
    query = body.get("query") or {}
    matched = [hit for hit in corpus if _bool_matches(hit["_source"], query.get("bool", {}))]
    spec = body.get("sort") or []

    def ordering(hit: dict) -> tuple:
        key = []
        for value, item in zip(_sort_values(hit["_source"], spec), spec, strict=False):
            options = next(iter(item.values()))
            order = options.get("order", "asc") if isinstance(options, dict) else options
            # Missing sorts last in either direction.
            if value is None:
                key.append((1, ""))
            elif order == "desc":
                key.append((0, Reverse(value)))
            else:
                key.append((0, value))
        return tuple(key)

    matched.sort(key=ordering)
    cursor = body.get("search_after")
    if isinstance(cursor, list) and spec:
        matched = [hit for hit in matched if _after_cursor(_sort_values(hit["_source"], spec), cursor, spec)]
    size = body.get("size", len(matched))
    page = []
    for hit in matched[:size]:
        served = dict(hit)
        served["sort"] = _sort_values(hit["_source"], spec)
        page.append(served)
    return _hits_response(page)


class Reverse:
    """Sort key that reverses comparison for one field."""

    def __init__(self, value: object):
        self.value = value

    def __lt__(self, other: object) -> bool:
        return isinstance(other, Reverse) and self.value > other.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Reverse) and self.value == other.value


class TestTheCalendar:
    """The policy doc's concrete dates are the contract."""

    def test_patch_tuesdays_2026(self):
        assert patch_tuesday(2026, 10) == date(2026, 10, 13)
        assert patch_tuesday(2026, 11) == date(2026, 11, 10)
        assert patch_tuesday(2026, 12) == date(2026, 12, 8)

    def test_windows_match_the_policy_doc(self):
        # TEST: Oct 14, Nov 11, Dec 9 — PROD one week later.
        assert _test_patch_due_for(date(2026, 10, 1)) == date(2026, 10, 14)
        assert _test_patch_due_for(date(2026, 11, 1)) == date(2026, 11, 11)
        assert _test_patch_due_for(date(2026, 12, 1)) == date(2026, 12, 9)
        assert _prod_patch_due_for(date(2026, 10, 14)) == date(2026, 10, 21)
        assert _prod_patch_due_for(date(2026, 11, 11)) == date(2026, 11, 18)
        assert _prod_patch_due_for(date(2026, 12, 9)) == date(2026, 12, 16)

    def test_a_window_never_opens_in_the_past(self):
        # Found after October's window closed -> due in November's window.
        assert _test_patch_due_for(date(2026, 10, 20)) == date(2026, 11, 11)
        # December rolls the year.
        assert _test_patch_due_for(date(2026, 12, 20)) == date(2027, 1, 13)

    def test_environment_classification_fails_closed(self):
        assert classify_environment("dev-tmc-01") == "test"
        assert classify_environment("UAT-app-2") == "test"
        assert classify_environment("cbs-euw1-tmc-01") == "prod"
        assert classify_environment("mgi-tmc-02") == "prod"
        assert classify_environment(None) == "prod"

    def test_due_date_dispatches_by_environment(self):
        found = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
        assert patch_due_for(found, "test") == date(2026, 10, 14)
        assert patch_due_for(found, "prod") == date(2026, 10, 21)
        # unknown environment string behaves like prod (fail closed)
        assert patch_due_for(found, "garbage") == date(2026, 10, 21)


class TestTheStreamSplit:
    def test_wazuh_declares_the_vulnerability_capability(self):
        assert Capability.PULL_VULNERABILITIES in WazuhConnector.capabilities()

    def test_schema_offers_the_mode_knob(self):
        schema = WazuhConnector.schema()
        field = next((f for f in schema.fields if f.name == "vuln_mode"), None)
        assert field is not None, "operators have no way to see or set the mode"
        assert field.default == "inventory"

    def test_detector_events_are_recognised(self):
        assert is_vulnerability_source(_detector_hit()["_source"])
        assert not is_vulnerability_source(_real_alert_hit()["_source"])

    @pytest.mark.asyncio
    @respx.mock
    async def test_detector_events_leave_the_alert_stream(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([_detector_hit(), _real_alert_hit()]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
        events = await connector.fetch_alerts(since_seconds=300)

        assert route.called
        # The syscheck alert survives; the detector event does not.
        assert len(events) == 1
        assert events[0]["title"] == "Possible rootkit installation"
        # and the query itself asked the indexer to exclude the group, so
        # the 1000-hit page cap can't smuggle scan noise back in.
        body = route.calls.last.request.content.decode()
        assert "vulnerability-detector" in body

    @pytest.mark.asyncio
    @respx.mock
    async def test_legacy_mode_keeps_the_old_behaviour(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([_detector_hit(), _real_alert_hit()]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, vuln_mode="alerts")
        events = await connector.fetch_alerts(since_seconds=300)

        assert len(events) == 2
        # ...and the findings path stays empty so nothing double-writes.
        assert await connector.fetch_vulnerability_findings() == []
        # the legacy query has no must_not — that's the point of the mode.
        body = route.calls[0].request.content.decode()
        assert "must_not" not in body

    @pytest.mark.asyncio
    @respx.mock
    async def test_findings_fetch_names_cve_host_and_cvss(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=_hits_response([_detector_hit(cve="CVE-2021-44228", host="dev-tmc-01")])
        )
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
        findings = await connector.fetch_vulnerability_findings()

        assert route.called
        assert len(findings) == 1
        f = findings[0]
        assert f["cve_id"] == "CVE-2021-44228"
        assert f["hostname"] == "dev-tmc-01"
        assert f["cvss_score"] == pytest.approx(9.8)
        assert f["severity"] == "critical"
        assert f["source"] == "wazuh"

    @pytest.mark.asyncio
    @respx.mock
    async def test_inventory_query_covers_custom_markers_without_claiming_exploits(self):
        custom = _detector_hit()
        custom["_source"]["rule"]["groups"] = ["custom-detector"]
        exploit = _real_alert_hit()
        exploit["_source"]["data"]["cve"] = "CVE-2024-0001"
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([custom, exploit]))
        findings = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_vulnerability_findings()

        assert [finding["external_id"] for finding in findings] == ["doc-vuln"]
        query = json.loads(route.calls.last.request.content)
        selector = query["query"]["bool"]["must"][1]["bool"]
        assert selector["minimum_should_match"] == 1
        assert {"terms": {"rule.groups": ["vulnerability-detector", "vulnerability"]}} in selector["should"]
        assert {"exists": {"field": "data.vulnerability.cve"}} in selector["should"]
        assert {"exists": {"field": "data.cve"}} in selector["should"]
        # Newest candidate first. An oldest-first page is what let older
        # non-matches hide every finding.
        assert query["sort"][0]["@timestamp"]["order"] == "desc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_older_nonmatching_cve_alerts_cannot_hide_findings(self):
        """A page of non-matching ``data.cve`` alerts is not the whole window.

        The indexer applies ``size`` before ``is_vulnerability_source``.
        The corpus is 1,001 older exploit alerts that carry ``data.cve``,
        one real detector finding, and 1,001 newer exploit alerts. One
        1,000-hit page — oldest-first or newest-first — is entirely
        exploits, and the old reader returned no findings. The finding is
        in the middle so a sort flip without paging or a tighter query
        still misses it.
        """
        finding = _cve_page_hit("finding", _page_timestamp(12, 0), finding=True)
        older = [_cve_page_hit(f"old-{i:04d}", _page_timestamp(6, i), finding=False) for i in range(1001)]
        newer = [_cve_page_hit(f"new-{i:04d}", _page_timestamp(18, i), finding=False) for i in range(1001)]
        corpus = [*older, finding, *newer]
        assert len(older) > 1000
        assert is_vulnerability_source(finding["_source"])
        assert not is_vulnerability_source(older[0]["_source"])

        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(side_effect=lambda request: _page_response(corpus, request))
        findings = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_vulnerability_findings()

        assert [item["external_id"] for item in findings] == ["finding"]
        assert findings[0]["cve_id"] == "CVE-2024-9999"
        bodies = [json.loads(call.request.content) for call in route.calls]
        assert bodies
        assert all(body["sort"][0]["@timestamp"]["order"] == "desc" for body in bodies)
        selector = bodies[0]["query"]["bool"]["must"][1]["bool"]["should"]
        paged = any("search_after" in body for body in bodies)
        bare_cve = {"exists": {"field": "data.cve"}} in selector
        # Either the query no longer admits exploit ``data.cve`` hits, or
        # the read continued past the first page of them.
        assert paged or not bare_cve

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_findings_walk_stops_at_the_page_cap(self, monkeypatch):
        monkeypatch.setattr("app.connectors.wazuh.DEFAULT_MAX_PAGES", 2)
        finding = _cve_page_hit("finding", _page_timestamp(6, 0), finding=True)
        newer = [_cve_page_hit(f"new-{i:04d}", _page_timestamp(18, i), finding=False) for i in range(2000)]
        corpus = [*newer, finding]
        respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(side_effect=lambda request: _page_response(corpus, request))

        with structlog.testing.capture_logs() as logs:
            findings = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_vulnerability_findings()

        assert findings == []
        assert [log["event"] for log in logs].count("wazuh.vulnerability_findings.page_cap_reached") == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_findings_sort_falls_back_when_the_id_tiebreak_is_rejected(self):
        def respond(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            fields = [next(iter(item)) for item in body["sort"]]
            if "id" in fields:
                return httpx.Response(400, json={"error": {"type": "illegal_argument_exception"}})
            return _hits_response([_detector_hit(cve="CVE-2021-44228", host="dev-tmc-01")])

        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(side_effect=respond)
        findings = await WazuhConnector(INDEXER, USERNAME, PASSWORD).fetch_vulnerability_findings()

        assert [item["cve_id"] for item in findings] == ["CVE-2021-44228"]
        last = json.loads(route.calls.last.request.content)
        assert [next(iter(item)) for item in last["sort"]] == ["@timestamp"]
        assert "search_after" not in last

    @pytest.mark.asyncio
    @respx.mock
    async def test_anonymous_events_are_skipped_not_guessed(self):
        hit = _detector_hit()
        del hit["_source"]["data"]["vulnerability"]["cve"]
        hit["_source"]["agent"] = {}
        respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([hit]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)

        assert await connector.fetch_vulnerability_findings() == []


class TestThePromotionContract:
    def test_sql_is_fail_closed_and_scoped(self):
        from app.vuln_promotion_sql import (
            MARK_OVERDUE_SQL,
            PROMOTE_CANDIDATES_SQL,
            UPSERT_ALERT_SQL,
        )

        for sql in (MARK_OVERDUE_SQL, PROMOTE_CANDIDATES_SQL, UPSERT_ALERT_SQL):
            assert "tenant_id" in sql, "every statement is tenant-scoped"
        # The exception path is spelled in the candidate query, not in a
        # prompt: overdue OR CVSS>9 OR exploited OR KEV.
        assert "patch_status IN ('overdue', 'promoted')" in PROMOTE_CANDIDATES_SQL
        assert "cvss_score > 9" in PROMOTE_CANDIDATES_SQL
        assert "is_exploited" in PROMOTE_CANDIDATES_SQL
        assert "threat_intel_iocs" in PROMOTE_CANDIDATES_SQL
        # one grouped alert per CVE via the idempotency key
        assert "ON CONFLICT (tenant_id, idempotency_key)" in UPSERT_ALERT_SQL
        assert "GROUP BY v.cve_id" in PROMOTE_CANDIDATES_SQL

    def test_no_statement_uses_the_colon_cast_spelling(self):
        """``:name::type`` is never substituted and reaches the driver verbatim.

        The assertions above are substring checks on the SQL text, and that is
        the whole reason ``UPSERT_ALERT_SQL`` could carry
        ``:affected_hosts::jsonb`` for its entire life while every test passed:
        the substring was present and correct, and the statement answered
        ``syntax error at or near ":"`` on every execution. This is the one
        property a text assertion *can* decide, so it is asserted here, and
        ``tests/test_vuln_promotion_live.py`` runs the statements for real.
        """
        from app import vuln_promotion_sql

        for name in vuln_promotion_sql.__all__:
            sql = getattr(vuln_promotion_sql, name)
            offenders = re.findall(r"(?<![:\w\\]):(\w+)::", sql)
            assert not offenders, f"{name}: {offenders} are written `:name::type`; use CAST(:name AS type)"

    @pytest.mark.asyncio
    async def test_the_scheduler_actually_registers_the_promotion_job(self):
        """Read off a real APScheduler after a real ``start()``.

        This asserted ``"_vuln_promotion_loop" in inspect.getsource(...)``,
        which proves the identifier appears in the file and nothing about
        whether a job exists. Driving ``start()`` is what makes the six-hour
        interval and the bound coroutine assertable.
        """
        import os

        from app.scheduler import ConnectorScheduler

        os.environ.pop("AISOC_CONNECTORS_LEADER_ELECTION", None)
        scheduler = ConnectorScheduler(
            engine=_NoRowsEngine(),
            ingest_client=_ClosableClient(),
            vault=object(),
        )
        await scheduler.start()
        try:
            job = scheduler._scheduler.get_job("_vuln_promotion_loop")  # noqa: SLF001
            assert job is not None, "the promotion sweep is not scheduled at all"
            assert job.func == scheduler._promote_overdue_findings  # noqa: SLF001
            assert job.trigger.interval.total_seconds() == 6 * 3600.0
        finally:
            await scheduler.stop()

    def test_inventory_insert_mints_the_window_once(self):
        from app.vulnerabilities import _INSERT_VULN, _TOUCH_VULN

        ins = str(_INSERT_VULN)
        assert "patch_due_date" in ins and "environment" in ins and "patch_status" in ins
        touch = str(_TOUCH_VULN)
        # A re-poll must never move the promised date or un-overdue a row.
        assert "patch_due_date" not in touch
        assert "patch_status" not in touch


class _NoRowsEngine:
    """An engine whose reads return nothing, so ``start()`` can run with no DB.

    Only the reload loop reads through it during startup; the promotion job
    this test is about is registered unconditionally.
    """

    def connect(self):  # noqa: ANN201
        return _NoRowsCtx()

    def begin(self):  # noqa: ANN201
        return _NoRowsCtx()


class _NoRowsCtx:
    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *exc) -> bool:  # noqa: ANN002
        return False

    async def execute(self, *_args, **_kwargs):  # noqa: ANN202
        return self

    def scalars(self):  # noqa: ANN202
        return self

    def fetchall(self):  # noqa: ANN202
        return []

    def all(self):  # noqa: ANN202
        return []

    def mappings(self):  # noqa: ANN202
        return self


class _ClosableClient:
    """Enough of IngestClient for ``stop()`` to drain cleanly."""

    async def aclose(self) -> None:
        return None
