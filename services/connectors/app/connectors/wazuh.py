"""
Wazuh connector — open-source XDR/SIEM.

Wazuh splits cleanly across three services:

* **Wazuh Manager** — agents check in here; exposes a JWT-auth REST API on
  port ``55000`` for *operational* management (add agent, get config).
* **Wazuh Indexer** — a hardened OpenSearch fork on port ``9200`` where
  alerts and archives actually live. Index pattern: ``wazuh-alerts-*``.
* **Wazuh Dashboard** — read-only UI on top of the indexer.

We poll the **indexer** (not the manager) because that is where the rolling
alert stream lives and because the indexer's basic-auth + DSL surface is
the same one ``ElasticConnector`` already speaks. The manager API is a
better fit for kinetic actions and is intentionally out-of-scope for this
read-path connector — a future ``WazuhActionClient`` can layer on top.

Severity ladder
---------------

Wazuh rules carry a 0-15 ``level``; the official guidance maps roughly to:

* 0-3   — informational / system noise (login successes, decoder hits)
* 4-7   — low signal (failed sshd, non-malicious anomalies)
* 8-11  — suspicious (privilege change, unusual exec, FIM writes)
* 12-14 — high (rootkit, exploit, IOC hit)
* 15    — critical / attack (multi-stage attack, severe exploit)

We map that to AiSOC's 5-tier ladder (info | low | medium | high | critical)
so Wazuh's hardest P1 alerts (level 15 — the only level Wazuh explicitly
documents as "critical") keep their original priority rather than getting
silently downgraded into ``high``.

API references
--------------

* Wazuh indexer alerts schema:
  https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html
* Wazuh indexer search API (OpenSearch-compatible):
  https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html
* Rule level taxonomy:
  https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
"""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import (
    BaseConnector,
    Capability,
    ConnectorSchema,
    Field,
)

logger = structlog.get_logger()


class WazuhSearchError(RuntimeError):
    """The indexer did not return a complete, successful search result."""


# ---------------------------------------------------------------------------
# Severity mapping
#
# Map the 0-15 Wazuh ladder into AiSOC's 5-tier
# ``info | low | medium | high | critical`` ladder. Level 15 is the only
# tier Wazuh explicitly documents as "critical / attack" so we surface it
# at the AiSOC ``critical`` band; levels 12-14 stay at ``high``. The
# matching operator-facing table lives in ``apps/docs/docs/connectors/wazuh.md``
# so SOC analysts can predict what they will see. Boundaries are inclusive
# on the lower end.
# ---------------------------------------------------------------------------

_SEVERITY_BANDS: tuple[tuple[int, str], ...] = (
    (15, "critical"),  # 15
    (12, "high"),  # 12-14
    (8, "medium"),  # 8-11
    (4, "low"),  # 4-7
    (0, "info"),  # 0-3
)


#: Rule groups the Wazuh vulnerability-detector stamps on its CVE scan
#: events. A hit in one of these groups is *inventory state* ("host X runs
#: a package with CVE-Y"), not an incident. docs/cve-patch-policy.md routes
#: them to ``asset_vulnerabilities`` with a patch due date instead of the
#: alert queue — a full re-scan of four agents produced ~3,900 alert rows in
#: one hour on the live stack, which no analyst can triage and which buried
#: every real detection that landed in the same window.
_VULN_RULE_GROUPS: tuple[str, ...] = ("vulnerability-detector", "vulnerability")


def is_vulnerability_source(source: dict[str, Any]) -> bool:
    """True if an indexer ``_source`` document is a vulnerability-detector event.

    Two structural markers, in order of authority:

    * ``rule.groups`` contains the detector group — the canonical stamp the
      stock ``ossec-github``/vulnerability-detection ruleset puts on every
      scan event.
    * ``data.vulnerability`` is an object — the payload shape the detector
      itself writes, which custom rule packs keep even when they re-home the
      event under a different rule.

    Deliberately *not* a CVE mention in the description: legitimate
    exploit-attempt detections cite CVEs in their rule descriptions too, and
    swallowing one of those would hide a real incident. Fail open toward the
    alert queue, which is where visible-but-noisy beats invisible.
    """
    rule = source.get("rule") or {}
    groups = rule.get("groups")
    if isinstance(groups, list) and any(g in _VULN_RULE_GROUPS for g in groups):
        return True
    data = source.get("data")
    return isinstance(data, dict) and isinstance(data.get("vulnerability"), dict)


def _severity_from_level(level: int | float | str | None) -> str:
    """Map a Wazuh rule level (0-15) to an AiSOC severity tier.

    Defensive against non-int levels because Wazuh ships rule packs from
    third parties that occasionally store ``level`` as a string. We fall
    back to ``info`` rather than raising so a single malformed rule does
    not poison the whole batch.
    """
    try:
        lvl = int(float(level)) if level is not None else 0
    except (TypeError, ValueError):
        return "info"
    for threshold, label in _SEVERITY_BANDS:
        if lvl >= threshold:
            return label
    return "info"


#: Wazuh detector severity strings → AiSOC tiers. The detector uses the
#: NVD adjectival ladder ("Low", "Medium", "High", "Critical") plus the
#: odd vendor variants; anything unrecognised conservatively maps to
#: ``medium`` so an unknown label still lands above ``info`` in the
#: inventory without screaming critical.
_DETECTOR_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "severe": "critical",  # Wazuh's own word for the top band
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "info",
    "none": "info",
    "informational": "info",
}


def _severity_from_detector(severity: str | None) -> str:
    text = (severity or "").strip().lower()
    return _DETECTOR_SEVERITY_MAP.get(text, "medium")


class WazuhConnector(BaseConnector):
    """Wazuh — open-source XDR/SIEM.

    Polls the Wazuh indexer (OpenSearch-compatible) for alerts above a
    configurable rule-level threshold and normalizes them into the AiSOC
    canonical alert shape.
    """

    connector_id = "wazuh"
    connector_name = "Wazuh"
    connector_category = "siem"
    requires_complete_poll = True

    _MAX_SEARCH_PAGES = 1000
    _SEARCH_TIMEOUT_SECONDS = 300.0
    _OVERLAP_SECONDS = 60

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Wazuh is *both* an EDR (host-agent telemetry) and a SIEM (alert
        # store). For the connector platform we treat it as a SIEM because
        # the read-surface we expose is the indexer; the agent-side
        # response actions belong in a future kinetic plugin.
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_VULNERABILITIES,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.PIVOT_HOST,
        )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Wazuh — open-source XDR/SIEM. Pulls alerts from the "
                "Wazuh indexer (OpenSearch-compatible) and maps the "
                "0-15 rule level onto the AiSOC severity ladder."
            ),
            docs_url="/docs/connectors/wazuh",
            fields=[
                Field(
                    "indexer_url",
                    "string",
                    "Wazuh Indexer URL",
                    placeholder="https://wazuh.example.com:9200",
                    help_text=("Base URL of the Wazuh indexer (NOT the dashboard or manager). Default port is 9200."),
                ),
                Field(
                    "username",
                    "string",
                    "Indexer Username",
                    help_text=("Indexer user with read access to wazuh-alerts-*. Create a dedicated read-only role in production."),
                ),
                Field(
                    "password",
                    "secret",
                    "Indexer Password",
                ),
                Field(
                    "index_pattern",
                    "string",
                    "Alert Index Pattern",
                    required=False,
                    default="wazuh-alerts-*",
                    help_text=("Override only if you have re-templated the default Wazuh index naming."),
                ),
                Field(
                    "min_rule_level",
                    "number",
                    "Minimum Rule Level",
                    required=False,
                    default=7,
                    help_text=(
                        "Drop alerts with rule.level below this value at "
                        "ingest. Default 7 keeps low-signal noise out of "
                        "the lake; lower to 3 for full audit coverage."
                    ),
                ),
                Field(
                    "max_search_results",
                    "number",
                    "Maximum Results per Search",
                    required=False,
                    default=100_000,
                    help_text=(
                        "Safety limit for one complete alert or inventory search. "
                        "Exceeding it fails the poll and preserves its retry window; no results are silently dropped."
                    ),
                ),
                Field(
                    "verify_tls",
                    "boolean",
                    "Verify TLS Certificate",
                    required=False,
                    default=True,
                    help_text=("Disable only for self-signed lab clusters. Production deployments must install the CA chain."),
                ),
                Field(
                    "vuln_mode",
                    "select",
                    "Vulnerability Events",
                    required=False,
                    default="inventory",
                    help_text=(
                        "Where vulnerability-detector events go. 'inventory' "
                        "(default) routes them to the asset vulnerability "
                        "inventory with patch-window due dates per "
                        "docs/cve-patch-policy.md; only CVSS>9, KEV, or "
                        "overdue findings raise alerts. 'alerts' keeps the "
                        "legacy behaviour of one alert per scan finding."
                    ),
                    options=[
                        {"value": "inventory", "label": "Inventory + patch windows (recommended)"},
                        {"value": "alerts", "label": "Alert per finding (legacy)"},
                    ],
                ),
            ],
        )

    def __init__(
        self,
        indexer_url: str,
        username: str,
        password: str,
        index_pattern: str = "wazuh-alerts-*",
        min_rule_level: int = 7,
        verify_tls: bool = True,
        vuln_mode: str = "inventory",
        max_search_results: int = 100_000,
    ):
        # Strip trailing slash so URL composition is predictable.
        self._base_url = indexer_url.rstrip("/")
        self._username = username
        self._password = password
        self._index_pattern = index_pattern or "wazuh-alerts-*"
        try:
            self._min_rule_level = max(0, min(15, int(min_rule_level)))
        except (TypeError, ValueError):
            self._min_rule_level = 7
        self._verify_tls = bool(verify_tls)
        # "inventory" (default): detector events become asset_vulnerabilities
        # rows, not alerts. "alerts": legacy behaviour, detector events flow
        # into the alert stream as they always did. Anything unrecognised
        # collapses to the legacy mode — the operator asked for it by
        # setting a value we don't honour, and silently switching an
        # established pipeline is worse than not switching it.
        self._vuln_mode = vuln_mode if vuln_mode in ("inventory", "alerts") else "alerts"
        if isinstance(max_search_results, bool):
            raise ValueError("max_search_results must be a positive integer")
        try:
            self._max_search_results = int(max_search_results)
        except (TypeError, ValueError):
            raise ValueError("max_search_results must be a positive integer") from None
        if self._max_search_results < 1 or str(self._max_search_results) != str(max_search_results):
            raise ValueError("max_search_results must be a positive integer")
        self._window_checkpoint: dict[str, datetime] | None = None
        self._poll_end: datetime | None = None
        self._poll_prepared = False
        self._completed_streams: set[str] = set()

    @classmethod
    def checkpoints(cls) -> bool:
        """Resume complete windows; never discard rows by timestamp alone."""
        return True

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        self._window_checkpoint = None
        self._poll_end = None
        self._poll_prepared = False
        self._completed_streams = set()
        # Older versions did not implement a Wazuh checkpoint. A legacy
        # generic {time, id} is not evidence that either stream completed.
        if not isinstance(checkpoint, dict) or "wazuh_poll" not in checkpoint:
            return
        window = checkpoint["wazuh_poll"]
        if not isinstance(window, dict) or type(window.get("version")) is not int or window["version"] != 1:
            raise WazuhSearchError("Wazuh polling checkpoint has an unsupported format")
        parsed: dict[str, datetime] = {}
        for key in ("alerts_through", "vulnerabilities_through"):
            try:
                value = datetime.fromisoformat(window[key])
                if value.tzinfo is None:
                    raise ValueError("timezone required")
                parsed[key] = value.astimezone(UTC)
            except (KeyError, TypeError, ValueError):
                raise WazuhSearchError("Wazuh polling checkpoint has an invalid time boundary") from None
        self._window_checkpoint = parsed

    @staticmethod
    def _encode_checkpoint(window: dict[str, datetime]) -> dict[str, Any]:
        return {"wazuh_poll": {"version": 1, **{key: value.isoformat() for key, value in window.items()}}}

    def prepare_poll(self, *, since_seconds: int, last_sync: datetime | None, started_at: datetime) -> dict[str, Any] | None:
        self._poll_end = started_at.astimezone(UTC)
        self._poll_prepared = True
        self._completed_streams = set()
        if self._window_checkpoint is not None:
            if any(value > self._poll_end for value in self._window_checkpoint.values()):
                raise WazuhSearchError("Wazuh polling checkpoint is ahead of the current clock")
            return None
        # Persist these floors BEFORE the first source request. Otherwise a
        # failed initial poll with no prior cursor moves its relative window
        # on every retry and cannot recover after a process restart.
        prior = last_sync.replace(tzinfo=UTC) if last_sync is not None and last_sync.tzinfo is None else last_sync
        self._window_checkpoint = {
            "alerts_through": min(self._poll_end - timedelta(seconds=max(int(since_seconds), 0)), prior or self._poll_end),
            "vulnerabilities_through": min(self._poll_end - timedelta(hours=1), prior or self._poll_end),
        }
        return self._encode_checkpoint(self._window_checkpoint)

    def _window(self, stream: str, since_seconds: int) -> dict[str, str]:
        if not self._poll_prepared:
            self.prepare_poll(since_seconds=since_seconds, last_sync=None, started_at=datetime.now(UTC))
            # Public fetch methods can also be called without the scheduler.
            # Only explicit prepare_poll pins both streams to one poll end.
            self._poll_prepared = False
        assert self._poll_end is not None and self._window_checkpoint is not None
        start = min(
            self._window_checkpoint[stream] - timedelta(seconds=self._OVERLAP_SECONDS),
            self._poll_end - timedelta(seconds=max(int(since_seconds), 0)),
        )
        return {"gte": start.isoformat(), "lte": self._poll_end.isoformat()}

    def get_checkpoint(self) -> dict[str, Any] | None:
        required = {"alerts_through"}
        if self._vuln_mode == "inventory":
            required.add("vulnerabilities_through")
        if not required <= self._completed_streams or self._window_checkpoint is None or self._poll_end is None:
            return None
        window = dict(self._window_checkpoint)
        for key in required:
            window[key] = self._poll_end
        return self._encode_checkpoint(window)

    # ---- helpers ------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode("ascii")
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AiSOC/connectors-wazuh",
        }

    # ---- runtime ------------------------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        """Hit the indexer's cluster-health endpoint to validate auth + reachability."""
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify_tls) as client:
                resp = await client.get(
                    f"{self._base_url}/_cluster/health",
                    headers=self._headers(),
                )
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            if resp.status_code in (401, 403):
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": "authentication failed; check username/password",
                }
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"unexpected status {resp.status_code}",
            }
        except httpx.RequestError as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"network error: {exc}",
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Pull recent Wazuh alerts above the configured rule-level threshold.

        Uses the OpenSearch ``_search`` API on ``wazuh-alerts-*`` with a
        time-window filter and a scroll snapshot. Each page contains up
        to 1000 hits; the entire matching window is drained before any
        alerts are returned to the scheduler.

        In ``vuln_mode=inventory`` (the default) vulnerability-detector hits
        are excluded here and returned by
        :meth:`fetch_vulnerability_findings` instead. Excluding at the
        source — not via a downstream filter rule — is deliberate: the
        scheduler's ``filter_rules`` are tenant-controlled and evaluated
        after normalization, so dropping here is the only place the two
        streams provably cannot both claim the same event.
        """
        self._completed_streams.discard("alerts_through")
        query: dict[str, Any] = {
            "size": 1000,
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": self._window("alerts_through", since_seconds)}},
                        {"range": {"rule.level": {"gte": self._min_rule_level}}},
                    ]
                }
            },
        }
        if self._vuln_mode == "inventory":
            # Annotated at the literal rather than indexed through `object`:
            # without it mypy infers the nested dict's values as `object`,
            # which is not indexable, and the chained subscript below is
            # unchecked.
            query["query"]["bool"]["must_not"] = [
                {"terms": {"rule.groups": list(_VULN_RULE_GROUPS)}},
            ]

        hits = await self._search(query)
        if self._vuln_mode != "inventory":
            alerts = [self.normalize(hit) for hit in hits]
        else:
            alerts = [self.normalize(hit) for hit in hits if not is_vulnerability_source(hit.get("_source") or {})]
        # belt-and-braces: the must_not above misses custom rule packs that
        # re-home detector events under a different group, so re-check the
        # document shape itself before anything reaches the alert stream.
        self._completed_streams.add("alerts_through")
        return alerts

    async def fetch_vulnerability_findings(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Pull recent vulnerability-detector events as inventory findings.

        Called by the scheduler's vulnerability-sync gate (it detects this
        method's presence), which feeds :func:`app.vulnerabilities.sync_findings`
        → ``asset_vulnerabilities``. One finding per (CVE, host) as the
        detector reported it; the sync side keys inventory by
        ``(tenant, asset, cve, source)`` so repeat scans touch ``last_found``
        instead of multiplying rows.

        The window is wider than the alert poll (1h vs 5min) and drained in
        1000-hit pages: the detector's own scan interval is hourly,
        so a narrow window would drop findings between polls if the
        connector was down, and re-scans are idempotent anyway.

        In ``vuln_mode=alerts`` this returns nothing: that mode puts
        detector events in the alert stream (legacy behaviour), and the
        scheduler gate below would otherwise double-write every finding —
        once as an alert, once as inventory.
        """
        self._completed_streams.discard("vulnerabilities_through")
        if self._vuln_mode != "inventory":
            return []
        query = {
            "size": 1000,
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": self._window("vulnerabilities_through", since_seconds)}},
                        {"term": {"rule.groups": "vulnerability-detector"}},
                    ]
                }
            },
        }

        hits = await self._search(query)
        findings: list[dict[str, Any]] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            finding = self.normalize_vulnerability(hit)
            if finding is not None:
                findings.append(finding)
        self._completed_streams.add("vulnerabilities_through")
        logger.info(
            "wazuh.vulnerability_findings",
            fetched=len(hits),
            findings=len(findings),
            window_seconds=since_seconds,
        )
        return findings

    async def _search(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Drain a scroll snapshot, or raise without returning a partial batch.

        Scroll keeps the index view and shard cursors fixed across pages,
        including documents that share a timestamp. It works on indexers
        predating the PIT API and requires no sortable document-ID field.
        The scheduler records an exception as a failed poll; ``[]`` is
        reserved for a complete search with no matching documents.
        """
        scroll_id: str | None = None
        hits: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        expected_total: int | None = None
        headers = self._headers()
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            try:
                async with asyncio.timeout(self._SEARCH_TIMEOUT_SECONDS):
                    resp = await client.post(
                        f"{self._base_url}/{self._index_pattern}/_search",
                        headers=headers,
                        params={"scroll": "1m", "allow_partial_search_results": "false"},
                        json=query,
                    )
                    for _page_number in range(self._MAX_SEARCH_PAGES):
                        if resp.status_code != 200:
                            raise WazuhSearchError(f"Wazuh indexer search failed (HTTP {resp.status_code})")
                        try:
                            payload = resp.json()
                        except ValueError:
                            raise WazuhSearchError("Wazuh indexer returned invalid JSON") from None
                        if not isinstance(payload, dict):
                            raise WazuhSearchError("Wazuh indexer returned an invalid search response")

                        # A failed page may still return a new context ID.
                        page_scroll_id = payload.get("_scroll_id")
                        if isinstance(page_scroll_id, str) and page_scroll_id:
                            scroll_id = page_scroll_id
                        page = self._search_hits(payload)
                        if expected_total is None:
                            expected_total = self._search_total(payload)
                            if expected_total > self._max_search_results:
                                raise WazuhSearchError("Wazuh search exceeds max_search_results; retry window retained")
                        elif "total" in payload["hits"] and self._search_total(payload) != expected_total:
                            raise WazuhSearchError("Wazuh indexer changed the snapshot total")
                        if not page:
                            if len(hits) != expected_total:
                                raise WazuhSearchError("Wazuh indexer ended the snapshot before all hits were read")
                            return hits
                        if not isinstance(page_scroll_id, str) or not page_scroll_id:
                            raise WazuhSearchError("Wazuh indexer omitted the scroll cursor")
                        if len(hits) + len(page) > self._max_search_results:
                            raise WazuhSearchError("Wazuh search exceeds max_search_results; retry window retained")
                        for hit in page:
                            identity = (hit["_index"], hit["_id"])
                            if identity in seen:
                                raise WazuhSearchError("Wazuh indexer repeated a document in the scroll snapshot")
                            seen.add(identity)
                        hits.extend(page)
                        if len(hits) > expected_total:
                            raise WazuhSearchError("Wazuh indexer returned more hits than its snapshot total")
                        if _page_number + 1 >= self._MAX_SEARCH_PAGES:
                            raise WazuhSearchError("Wazuh search exceeded its page limit; retry window retained")
                        # A short page is not an end marker. Only an empty
                        # hits array with the exact total proves completion.
                        # Do not retry this continuation after a timeout: it
                        # may already have advanced the server-side cursor.
                        resp = await client.post(
                            f"{self._base_url}/_search/scroll",
                            headers=headers,
                            json={"scroll": "1m", "scroll_id": scroll_id},
                        )
                    raise WazuhSearchError("Wazuh search exceeded its page limit; retry window retained")
            except TimeoutError:
                raise WazuhSearchError("Wazuh search exceeded its time limit; retry window retained") from None
            except httpx.RequestError as exc:
                # Do not leak response bodies, credentials or query data
                # into the scheduler's exception log.
                raise WazuhSearchError(f"Wazuh indexer request failed ({type(exc).__name__})") from None
            finally:
                if scroll_id:
                    try:
                        cleared = await client.request(
                            "DELETE",
                            f"{self._base_url}/_search/scroll",
                            headers=headers,
                            json={"scroll_id": [scroll_id]},
                            timeout=5.0,
                        )
                        if cleared.status_code not in (200, 404):
                            logger.warning("wazuh.scroll_cleanup_failed", status=cleared.status_code)
                    except httpx.RequestError as exc:
                        # Cleanup must not hide the original error or
                        # cancellation. The one-minute lease also expires.
                        logger.warning("wazuh.scroll_cleanup_failed", error_type=type(exc).__name__)

    @staticmethod
    def _search_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Reject partial or malformed pages, including HTTP-200 failures."""
        if "error" in payload:
            raise WazuhSearchError("Wazuh indexer returned a search error")
        if payload.get("timed_out") is not False:
            raise WazuhSearchError("Wazuh indexer search timed out")
        if payload.get("terminated_early", False) is not False:
            raise WazuhSearchError("Wazuh indexer terminated the search early")
        shards = payload.get("_shards")
        if not isinstance(shards, dict) or not {"total", "successful", "failed"} <= shards.keys():
            raise WazuhSearchError("Wazuh indexer returned invalid shard metadata")
        counts = [shards.get(field, 0) for field in ("total", "successful", "skipped", "failed")]
        if any(type(count) is not int or count < 0 for count in counts):
            raise WazuhSearchError("Wazuh indexer returned invalid shard metadata")
        total, successful, skipped, failed = counts
        # Skipped shards already contribute to successful in OpenSearch.
        if failed or successful != total or skipped > successful:
            raise WazuhSearchError("Wazuh indexer search returned incomplete shard results")
        result = payload.get("hits")
        page = result.get("hits") if isinstance(result, dict) else None
        if not isinstance(page, list) or any(not isinstance(hit, dict) for hit in page):
            raise WazuhSearchError("Wazuh indexer returned invalid search hits")
        for hit in page:
            if (
                not isinstance(hit.get("_index"), str)
                or not hit["_index"]
                or not isinstance(hit.get("_id"), str)
                or not hit["_id"]
                or not isinstance(hit.get("_source"), dict)
            ):
                raise WazuhSearchError("Wazuh indexer returned an invalid document envelope")
        return page

    @staticmethod
    def _search_total(payload: dict[str, Any]) -> int:
        total = payload["hits"].get("total")
        if isinstance(total, dict) and total.get("relation") == "eq":
            total = total.get("value")
        if type(total) is not int or total < 0:
            raise WazuhSearchError("Wazuh indexer did not return an exact hit total")
        return total

    def normalize_vulnerability(self, hit: dict[str, Any]) -> dict[str, Any] | None:
        """Project a detector hit into the ``sync_findings`` finding shape.

        Returns ``None`` for events without a CVE or a host — the same two
        fields ``sync_findings`` would skip on — so they are counted here
        rather than silently dropped downstream.
        """
        source = hit.get("_source") or {}
        data = source.get("data") or {}
        vuln = data.get("vulnerability") or {}
        agent = source.get("agent") or {}

        cve = str(vuln.get("cve") or data.get("cve") or "").strip().upper()
        hostname = agent.get("name") or agent.get("ip")
        if not cve.startswith("CVE-") or not hostname:
            return None

        cvss = vuln.get("cvss") or {}
        # Wazuh nests v3 under cvss.cvss3 and v2 under cvss.cvss (yes,
        # literally the key "cvss" inside "cvss"). Prefer v3 base score.
        cvss3 = cvss.get("cvss3") or {}
        cvss2 = cvss.get("cvss") or {}
        score = cvss3.get("base_score")
        if score is None:
            score = cvss2.get("base_score")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        return {
            "cve_id": cve,
            "hostname": hostname,
            "ip_address": agent.get("ip"),
            # The detector's own severity ("Severe", "High", ...) is
            # free-form; sync_findings re-derives nothing, so collapse the
            # Wazuh text onto our five tiers conservatively.
            "severity": _severity_from_detector(vuln.get("severity")),
            "cvss_score": score,
            "title": (source.get("rule") or {}).get("description") or cve,
            "source": "wazuh",
            "external_id": hit.get("_id"),
            # KEV: the detector reports what it knowsvia the rule hit —
            # is_exploited stays False here and is owned by the KEV worker
            # (retro_hunt/kev_exposure.py), which flips it from the CISA
            # feed. The connector must not invent exploited status.
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Project a Wazuh indexer hit into the AiSOC canonical alert shape.

        ``raw`` is the full OpenSearch hit envelope (``_id``, ``_index``,
        ``_source``). We pull the meaningful fields out of ``_source`` and
        leave the original under ``raw_event`` so detection rules can
        still pivot on vendor-specific keys.
        """
        source = raw.get("_source") or {}
        rule = source.get("rule") or {}
        agent = source.get("agent") or {}
        data = source.get("data") or {}

        rule_level = rule.get("level", 0)
        rule_id = rule.get("id")
        rule_desc = rule.get("description") or "Wazuh alert"
        mitre = rule.get("mitre") or {}

        # MITRE technique IDs come as a list under ``rule.mitre.id`` in
        # modern Wazuh; older builds put them under ``rule.mitre.tactic``.
        mitre_techniques = mitre.get("id") if isinstance(mitre.get("id"), list) else []
        mitre_tactics = mitre.get("tactic") if isinstance(mitre.get("tactic"), list) else []

        hostname = agent.get("name") or agent.get("ip")
        agent_id = agent.get("id")
        timestamp = source.get("@timestamp") or source.get("timestamp")

        # Stable alert_id: prefer the indexer doc id, fall back to a
        # composite of rule + agent + timestamp so retries de-duplicate.
        alert_id = raw.get("_id") or f"{rule_id or 'unknown'}::{agent_id or 'na'}::{timestamp or ''}"
        # Ingest derives its canonical event ID from external_id. A rule ID
        # identifies a detection rule, not an event: using it would collapse
        # every document for that rule. Document IDs are scoped to an index.
        external_id = f"{raw['_index']}::{raw['_id']}" if raw.get("_index") and raw.get("_id") else alert_id

        return {
            "source": self.connector_id,
            "category": "siem",
            "event_type": "wazuh_alert",
            "severity": _severity_from_level(rule_level),
            "title": rule_desc,
            "description": (source.get("full_log") or rule_desc)[:1000],
            "alert_id": alert_id,
            "external_id": external_id,
            "rule_level": rule_level,
            "rule_id": rule_id,
            "rule_groups": rule.get("groups") or [],
            "hostname": hostname,
            "host": hostname,
            "agent_id": agent_id,
            "agent_ip": agent.get("ip"),
            "timestamp": timestamp,
            "mitre_techniques": mitre_techniques,
            "mitre_tactics": mitre_tactics,
            "decoder": (source.get("decoder") or {}).get("name"),
            "data": data,
            "raw_event": source,
            "raw": raw,
        }
