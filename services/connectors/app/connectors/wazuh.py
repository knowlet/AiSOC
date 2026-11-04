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

import base64
import hashlib
import json
import re
import ssl
from typing import Any

import httpx
import structlog

from app.connectors.base import (
    BaseConnector,
    Capability,
    ConnectorSchema,
    Field,
)
from app.connectors.wazuh_checkpoint import WazuhCheckpoint
from app.security.egress import EgressRefused, refuse_internal_destinations

logger = structlog.get_logger()

_FAILOVER_STATUSES = frozenset({429, 502, 503, 504})


class WazuhSearchError(RuntimeError):
    """The indexer did not return a complete, successful search result."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def _certificate_error(exc: BaseException) -> bool:
    """HTTP transports may retain a certificate failure only in its cause."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        message = str(current).lower().replace("_", " ")
        if (
            isinstance(current, ssl.SSLCertVerificationError)
            or "certificate verify failed" in message
            or "certificate verification failed" in message
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


def _request_error(exc: httpx.RequestError) -> WazuhSearchError:
    if _certificate_error(exc):
        return WazuhSearchError("Wazuh indexer TLS certificate validation failed")
    retryable = isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, httpx.ProxyError))
    return WazuhSearchError(f"Wazuh indexer request failed ({type(exc).__name__})", retryable=retryable)


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
    # Indexed arrival can lag event time. Deduplicate document identities
    # within the checkpoint's replay window, not a timestamp/ID ordering.
    dedup_identity_field = ("external_id",)

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
                    "indexer_urls",
                    "string",
                    "Additional Indexer URLs",
                    required=False,
                    default="",
                    help_text=(
                        "Comma- or newline-separated fallback nodes in the same Indexer cluster. "
                        "The primary URL is tried first; every node uses the same credentials and TLS policy."
                    ),
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
                    "checkpoint_overlap_seconds",
                    "number",
                    "Checkpoint Replay Overlap (seconds)",
                    required=False,
                    default=300,
                    help_text=(
                        "Replay this much time before the last completed window to catch late indexed events. "
                        "Already seen document identities are deduplicated. Default 300."
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
        indexer_urls: str = "",
        checkpoint_overlap_seconds: int = 300,
    ):
        if not isinstance(indexer_urls, str):
            raise ValueError("Additional Wazuh Indexer URLs must be a comma- or newline-separated string")
        nodes = [indexer_url, *re.split(r"[,\n]", indexer_urls)]
        urls: list[str] = []
        for node in nodes:
            candidate = node.strip().rstrip("/")
            if not candidate:
                continue
            try:
                url = httpx.URL(candidate)
            except httpx.InvalidURL:
                raise ValueError("Wazuh Indexer URLs must be valid HTTP or HTTPS base URLs") from None
            if url.scheme not in ("http", "https") or not url.host or url.username or url.password or url.query or url.fragment:
                raise ValueError("Wazuh Indexer URLs must be HTTP or HTTPS base URLs without credentials, query or fragment")
            if candidate not in urls:
                urls.append(candidate)
        if not urls:
            raise ValueError("A Wazuh Indexer URL is required")
        self._indexer_urls = tuple(urls)
        self._base_url = urls[0]
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
        self._windows = WazuhCheckpoint(overlap_seconds=checkpoint_overlap_seconds)
        self.set_checkpoint(None)

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

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        super().set_checkpoint(checkpoint)
        self._next_checkpoint = None
        self._windows.load(checkpoint)

    def get_checkpoint(self) -> dict[str, Any] | None:
        dedup = super().get_checkpoint()
        seen = dedup["seen"] if dedup is not None else self._incoming_seen
        return self._windows.snapshot(seen)

    def confirm_vulnerability_sync(self) -> None:
        self._windows.confirm_vulnerability_sync()

    async def test_connection(self) -> dict[str, Any]:
        """Hit the indexer's cluster-health endpoint to validate auth + reachability."""
        error = "no reachable Wazuh indexer"
        async with httpx.AsyncClient(timeout=15.0, verify=self._verify_tls) as client:
            for base_url in self._indexer_urls:
                try:
                    refuse_internal_destinations({"indexer_url": base_url})
                    resp = await client.get(f"{base_url}/_cluster/health", headers=self._headers())
                except EgressRefused as exc:
                    error = str(exc)
                    break
                except httpx.RequestError as exc:
                    failure = _request_error(exc)
                    error = f"network error: {failure}"
                    if failure.retryable:
                        continue
                    break
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id}
                if resp.status_code in (401, 403):
                    error = "authentication failed; check username/password and role permissions"
                    break
                error = f"unexpected status {resp.status_code}"
                if resp.status_code not in _FAILOVER_STATUSES:
                    break
        return {"success": False, "connector": self.connector_id, "error": error}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Pull recent Wazuh alerts above the configured rule-level threshold.

        Drains a fixed query window through 1000-hit scroll pages. A saved
        completed window expands the lookback after downtime; the bounded
        replay overlap catches late indexed documents without dropping
        events that share a timestamp.

        In ``vuln_mode=inventory`` (the default) vulnerability-detector hits
        are excluded here and returned by
        :meth:`fetch_vulnerability_findings` instead. Excluding at the
        source — not via a downstream filter rule — is deliberate: the
        scheduler's ``filter_rules`` are tenant-controlled and evaluated
        after normalization, so dropping here is the only place the two
        streams provably cannot both claim the same event.
        """
        window = self._windows.query_range("alerts", since_seconds)
        query: dict[str, Any] = {
            "size": 1000,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": window}},
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
        # belt-and-braces: the must_not above misses custom rule packs that
        # re-home detector events under a different group, so re-check the
        # document shape itself before anything reaches the alert stream.
        events = [
            self.normalize(hit) for hit in hits if self._vuln_mode != "inventory" or not is_vulnerability_source(hit.get("_source") or {})
        ]
        events = self.apply_checkpoint(events)
        self._windows.stage("alerts", window["lte"])
        return events

    async def fetch_vulnerability_findings(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Pull recent vulnerability-detector events as inventory findings.

        Called by the scheduler's vulnerability-sync gate (it detects this
        method's presence), which feeds :func:`app.vulnerabilities.sync_findings`
        → ``asset_vulnerabilities``. One finding per (CVE, host) as the
        detector reported it; the sync side keys inventory by
        ``(tenant, asset, cve, source)`` so repeat scans touch ``last_found``
        instead of multiplying rows.

        The initial window is wider than the alert poll (1h vs 5min).
        Subsequent polls resume the separately confirmed inventory window
        and drain every page. Re-scans are idempotent in the inventory sink.

        In ``vuln_mode=alerts`` this returns nothing: that mode puts
        detector events in the alert stream (legacy behaviour), and the
        scheduler gate below would otherwise double-write every finding —
        once as an alert, once as inventory.
        """
        if self._vuln_mode != "inventory":
            return []
        window = self._windows.query_range("vulnerabilities", since_seconds)
        query = {
            "size": 1000,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": window}},
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
        logger.info(
            "wazuh.vulnerability_findings",
            fetched=len(hits),
            findings=len(findings),
            window_seconds=since_seconds,
        )
        self._windows.stage("vulnerabilities", window["lte"])
        return findings

    async def _search(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Drain a complete snapshot, retrying the same window on another node.

        A scroll cursor belongs to its search context. Failover starts a
        fresh search and discards the failed attempt's hits; no cursor or
        partial batch crosses to the next node. All nodes must serve the
        same cluster. Exceptions let the scheduler preserve its checkpoint
        and record a failed poll; ``[]`` means a complete empty search.
        """
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            for attempt, base_url in enumerate(self._indexer_urls):
                try:
                    return await self._search_node(client, base_url, query)
                except WazuhSearchError as exc:
                    if not exc.retryable or attempt == len(self._indexer_urls) - 1:
                        raise
                    logger.warning("wazuh.indexer_failover", attempt=attempt + 1, reason=str(exc))
        raise WazuhSearchError("Wazuh indexer search exhausted all nodes")

    async def _search_node(self, client: httpx.AsyncClient, base_url: str, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Drain one scroll snapshot without ever returning a partial result."""
        # Apply the existing egress policy to the actual selected endpoint,
        # including fallback nodes and direct callers outside the scheduler.
        refuse_internal_destinations({"indexer_url": base_url})
        scroll_id: str | None = None
        hits: list[dict[str, Any]] = []
        headers = self._headers()
        try:
            resp = await client.post(
                f"{base_url}/{self._index_pattern}/_search",
                headers=headers,
                params={"scroll": "1m", "allow_partial_search_results": "false"},
                json=query,
            )
            while True:
                if resp.status_code != 200:
                    raise WazuhSearchError(
                        f"Wazuh indexer search failed (HTTP {resp.status_code})",
                        retryable=resp.status_code in _FAILOVER_STATUSES,
                    )
                try:
                    payload = resp.json()
                except ValueError:
                    raise WazuhSearchError("Wazuh indexer returned invalid JSON") from None
                if not isinstance(payload, dict):
                    raise WazuhSearchError("Wazuh indexer returned an invalid search response")

                # Retain even a failed page's newest cursor for cleanup.
                page_scroll_id = payload.get("_scroll_id")
                if isinstance(page_scroll_id, str) and page_scroll_id:
                    scroll_id = page_scroll_id
                page = self._search_hits(payload)
                if not page:
                    return hits
                if not isinstance(page_scroll_id, str) or not page_scroll_id:
                    raise WazuhSearchError("Wazuh indexer omitted the scroll cursor")
                hits.extend(page)
                # A short page is not an end marker. Only an empty hits
                # array proves that this snapshot was fully drained.
                resp = await client.post(
                    f"{base_url}/_search/scroll",
                    headers=headers,
                    json={"scroll": "1m", "scroll_id": scroll_id},
                )
        except httpx.RequestError as exc:
            # Never log response bodies, URLs, credentials or query data.
            raise _request_error(exc) from None
        finally:
            if scroll_id:
                try:
                    cleared = await client.request(
                        "DELETE",
                        f"{base_url}/_search/scroll",
                        headers=headers,
                        json={"scroll_id": [scroll_id]},
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
        if type(payload.get("timed_out")) is not bool:
            raise WazuhSearchError("Wazuh indexer returned invalid timeout metadata")
        if payload["timed_out"]:
            raise WazuhSearchError("Wazuh indexer search timed out", retryable=True)
        shards = payload.get("_shards")
        if not isinstance(shards, dict) or not {"total", "successful", "failed"} <= shards.keys():
            raise WazuhSearchError("Wazuh indexer returned invalid shard metadata")
        counts = [shards.get(field, 0) for field in ("total", "successful", "skipped", "failed")]
        if any(type(count) is not int or count < 0 for count in counts):
            raise WazuhSearchError("Wazuh indexer returned invalid shard metadata")
        total, successful, skipped, failed = counts
        if successful + failed > total or skipped > successful:
            raise WazuhSearchError("Wazuh indexer returned invalid shard metadata")
        # OpenSearch counts skipped shards as successful already. Adding
        # them again would hide an unavailable shard and advance the cursor.
        if failed or successful != total:
            raise WazuhSearchError("Wazuh indexer search returned incomplete shard results", retryable=True)
        result = payload.get("hits")
        page = result.get("hits") if isinstance(result, dict) else None
        if not isinstance(page, list) or any(not isinstance(hit, dict) for hit in page):
            raise WazuhSearchError("Wazuh indexer returned invalid search hits")
        return page

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

        # Keep the display/pivot alert_id compatible. Ingest event identity
        # instead uses the index-scoped document ID, never the repeated
        # Wazuh rule ID. If the document ID is absent, include all source
        # content so different log lines with the same rule/time stay distinct.
        alert_id = raw.get("_id") or f"{rule_id or 'unknown'}::{agent_id or 'na'}::{timestamp or ''}"
        index = raw.get("_index") or self._index_pattern
        document_id = raw.get("_id")
        if document_id is not None and str(document_id):
            external_id = json.dumps([index, str(document_id)], separators=(",", ":"), ensure_ascii=False)
        else:
            content = json.dumps([index, source], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            external_id = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

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
            "rule_name": rule_desc,
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
