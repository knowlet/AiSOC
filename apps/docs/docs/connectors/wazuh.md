---
sidebar_position: 15
title: Wazuh
description: Pull alerts from a Wazuh indexer (OpenSearch-compatible) into AiSOC for SIEM and HIDS coverage.
---

# Wazuh

[Wazuh](https://wazuh.com/) is an open-source XDR/SIEM platform that combines
host-based intrusion detection (HIDS), file-integrity monitoring (FIM),
log analytics, and rule-based alerting on top of an OpenSearch-compatible
indexer. The Wazuh connector polls the **indexer** directly for alerts that
exceed a configurable rule-level threshold and normalizes them into AiSOC's
canonical event shape.

This is a read-path connector — it does not modify Wazuh state. Live response
actions ("isolate this agent", "kill this PID") are tracked separately under
the generic `live_action` capability so the platform stays vendor-neutral.

## What you get

| Source | Wazuh endpoint | Notes |
|---|---|---|
| Alerts | `POST /{index_pattern}/_search?scroll=1m`, then `POST /_search/scroll` | One AiSOC event per alert document; reads all pages in the query window |
| Scroll cleanup | `DELETE /_search/scroll` | Releases this poll's search context after completion or failure |
| Cluster health probe | `GET /_cluster/health` | Used by **Test connection** |

Events are normalized with `category: siem` and the originating Wazuh rule
is preserved as `rule_id`, `rule_level`, and `raw_event` for downstream
routing and pivoting.

## Why we hit the indexer, not the manager

Wazuh exposes two HTTP surfaces:

- The **manager API** on port 55000 — used for agent management, rule deployment,
  and active-response orchestration. JWT-auth.
- The **indexer** on port 9200 — an OpenSearch fork that holds the actual
  alert documents in `wazuh-alerts-*`. Basic-auth.

For ingest we want the alert stream itself, which lives in the indexer. The
manager API is the right surface for live response actions and is documented
separately under [agent capabilities](/docs/concepts/capabilities).

## Prerequisites

- A reachable **Wazuh indexer** (default `https://wazuh.example.com:9200`).
- A read-only **indexer user** with permission to search `wazuh-alerts-*`,
  continue and clear scroll searches, and read cluster health for the connection probe.
  See the Wazuh docs for [creating indexer roles and users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
- Optional: the CA chain for the indexer's TLS certificate.

## Setup walkthrough

### 1. Create a read-only indexer user

In the Wazuh dashboard, go to **Security → Roles** and create a role with:

- Index permissions on `wazuh-alerts-*`: `read`, including search, scroll and
  scroll cleanup. If assigning individual actions, include
  `indices:data/read/search*`, `indices:data/read/scroll`, and
  `indices:data/read/scroll/clear`.
- Cluster permissions: `indices:data/read/scroll`,
  `indices:data/read/scroll/clear`, and `cluster:monitor/health`.

OpenSearch requires the scroll and clear-scroll actions at both cluster and
index scope; see its [permission reference](https://docs.opensearch.org/latest/security/access-control/permissions/).
Keep index access restricted to the configured alert pattern. These permissions
do not grant document writes or index administration.

Then **Security → Internal users** → create a user (e.g. `aisoc-reader`)
and map it to that role. Save the password — you will paste it into the AiSOC
connector form.

Reusing the built-in `admin` or `kibanaserver` accounts works for a lab but
must not be used in production.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Wazuh**.
2. Fill in:
   - `indexer_url`: full URL including port (e.g. `https://wazuh.corp.example.com:9200`).
   - `username` / `password`: the read-only user from step 1.
   - `index_pattern`: leave as `wazuh-alerts-*` unless you have re-templated indices.
   - `min_rule_level`: default `7` keeps low-signal noise out of the lake; set lower for full audit coverage.
   - `verify_tls`: leave **enabled** in production; install the CA chain rather than disabling.
3. **Test connection** — calls `GET /_cluster/health` against the indexer.
4. **Save**.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- The connector queries the indexer with a `range` filter on `@timestamp` so the
  manager-side processing pipeline is not impacted.
- Each page contains up to **1,000 hits**. The connector continues through the
  [Scroll API](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/)
  until the indexer returns an empty page, for both alerts and vulnerability
  inventory findings. A short page does not stop the search.
- A scroll keeps the initial query's snapshot, including its time window, while
  the pages are read. Each request renews the context for one minute, and the
  connector releases its latest scroll ID on completion or failure.
- HTTP and network errors, malformed responses, search timeouts and partial
  shard failures raise a fetch error. A failed alert fetch marks the connector
  unhealthy, increments its error count and preserves `last_sync`. If a later
  page fails, none of that incomplete alert batch is sent to ingest. A valid
  empty search remains a successful poll with zero events.
- After the complete search succeeds, the ingest client splits the result into
  requests within the ingest service's default limits of **1,000 events** and
  **10 MiB per request**, including the JSON envelope. If you customize
  `MAX_BATCH_SIZE` or `INGEST_MAX_BODY_BYTES`, set matching values on the
  connectors and ingest services. An individual event that cannot fit is
  reported as an ingest error.
- If a later ingest request fails, the poll remains failed and `last_sync` is
  preserved. Earlier requests may already have been accepted: replay can
  therefore include previously delivered events. This is not an atomic or
  exactly-once delivery guarantee.
- The existing interface returns a complete list, so a large query window uses
  memory proportional to its results. Pagination does not add a persistent
  source checkpoint: normal polling and the scheduler's existing outage
  backfill policy still determine which time windows are queried. Vulnerability
  inventory sync has its own failure log and does not determine alert-poll health.

## Severity mapping

Wazuh emits a 0-15 numeric `rule.level`. AiSOC collapses that ladder onto its
four-tier severity taxonomy so detection logic and fusion rules stay
vendor-agnostic:

| Wazuh rule level | AiSOC severity |
|---|---|
| 0 – 3 | `info` |
| 4 – 7 | `low` |
| 8 – 11 | `medium` |
| 12 – 15 | `high` |

The original `rule.level` is preserved on every event as `rule_level` so
detection rules can still pivot on the exact Wazuh value when they need to.

## Troubleshooting

**`auth failure 401`** — the indexer rejected basic auth. Check the username and
password against the **indexer** dashboard (not the Wazuh manager UI — they are
separate user stores by default).

**`network error` on Test connection** — verify the URL points at port 9200, not
55000 (manager) or 5601 (dashboard). The manager API uses JWT, not basic auth,
and will reject the connector's requests.

**`no events_added`** — confirm `wazuh-alerts-*` indices actually exist in the
target cluster. Some Wazuh installations re-template the index name; if so,
override `index_pattern` to match.

**A poll fails after its first page** — check that the reader role has scroll
and clear-scroll permissions at both cluster and index scope, and that any
proxy permits `POST` and `DELETE` on `/_search/scroll`. An expired context or a
failed shard is reported as a failed fetch instead of accepting a partial batch.

**`wazuh.scroll_cleanup_failed`** — the search context could not be released.
Check clear-scroll permissions and connectivity. The cleanup warning does not
replace the original fetch error; the context also has a one-minute expiry.

**TLS handshake errors** — set `verify_tls: false` only when you are deliberately
running a self-signed lab cluster. In production, install the root CA so the
connector trusts the indexer's certificate.

## Related

- [osctrl](/docs/connectors/osctrl) and [FleetDM](/docs/connectors/fleetdm) — osquery-based fleet managers if you want host telemetry without Wazuh's full agent stack.
- [Detection coverage](/docs/detections/coverage) — SIEM rules that fire on Wazuh alerts via the canonical event shape.
- [Credentials vault](/docs/operations/credentials) — how the indexer password is encrypted at rest.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `indexer_url` | Wazuh Indexer URL | string | yes | — | Base URL of the Wazuh indexer (NOT the dashboard or manager). Default port is 9200. |
| `username` | Indexer Username | string | yes | — | Indexer user with read access to wazuh-alerts-*. Create a dedicated read-only role in production. |
| `password` | Indexer Password | secret | yes | — | **encrypted at rest** |
| `index_pattern` | Alert Index Pattern | string | no | `wazuh-alerts-*` | Override only if you have re-templated the default Wazuh index naming. |
| `min_rule_level` | Minimum Rule Level | number | no | `7` | Drop alerts with rule.level below this value at ingest. Default 7 keeps low-signal noise out of the lake; lower to 3 for full audit coverage. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | Disable only for self-signed lab clusters. Production deployments must install the CA chain. |
| `vuln_mode` | Vulnerability Events | select | no | `inventory` | Where vulnerability-detector events go. 'inventory' (default) routes them to the asset vulnerability inventory with patch-window due dates per docs/cve-patch-policy.md; only CVSS>9, KEV, or overdue findings raise alerts. 'alerts' keeps the legacy behaviour of one alert per scan finding. · one of: `inventory`, `alerts` |

:::note Credential handling
`password` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
