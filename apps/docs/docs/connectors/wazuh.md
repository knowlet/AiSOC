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

This is a read-path connector — it does not modify indexed documents. It opens
and clears temporary scroll search contexts. Live response
actions ("isolate this agent", "kill this PID") are tracked separately under
the generic `live_action` capability so the platform stays vendor-neutral.

## What you get

| Source | Wazuh endpoint | Notes |
|---|---|---|
| Alerts and vulnerability findings | `POST /{index_pattern}/_search?scroll=1m` against the indexer | Complete snapshot, in pages of up to 1,000 documents |
| Continue / clear a search | `POST /_search/scroll`, `DELETE /_search/scroll` | Uses only this poll's latest scroll ID |
| Cluster health probe | `GET /_cluster/health` | Used by **Test connection** |

Events are normalized with `category: siem` and the originating Wazuh rule
is preserved as `rule_id`, `rule_level`, and `raw_event` for downstream
routing and pivoting.

`external_id` is the index-scoped document identity (`_index::_id`), which the
ingest service uses to distinguish alerts and recognize replays. `rule_id`
remains the rule identifier. Older connector versions used `rule_id` as
`external_id`, causing different alerts from one rule to share an event ID.
Existing stored IDs are not rewritten; historical replay after this correction
can create new IDs for previously ingested records.

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
- A read-only **indexer user** with permission to search `wazuh-alerts-*`
  and continue/clear its scroll contexts.
  See the Wazuh docs for [creating indexer roles and users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
- Optional: the CA chain for the indexer's TLS certificate.

## Setup walkthrough

### 1. Create a read-only indexer user

In the Wazuh dashboard, go to **Security → Roles** and create a role with:

- Index permissions scoped to `wazuh-alerts-*`: `read`, `search`, and
  `indices:data/read/search*`.
- Scroll permissions: `indices:data/read/scroll` and
  `indices:data/read/scroll/clear`. The continuation URLs carry no index, so
  the Security plugin also checks these actions at cluster scope. Include
  them at both scopes when defining a custom role.
- `cluster:monitor/health` for the existing **Test connection** probe.

These are search-context and monitoring permissions, not document-write or
cluster-administration privileges. Check the effective role on the deployed
Indexer version before rollout. A passing health probe alone does not prove
that search, continuation and cleanup are authorized.

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
   - `max_search_results`: default `100000` is the complete-result safety limit
     for each alert or inventory search, not a truncation threshold.
3. **Test connection** — calls `GET /_cluster/health` against the indexer.
4. **Save**.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- The connector queries `@timestamp` using an absolute time range fixed before
  the poll starts. The Manager API is not involved.
- A scroll snapshot keeps the source view and shard cursors stable, including
  documents with the same timestamp. The connector continues after short pages
  until an explicit empty page and checks the exact total before returning.
- The first poll saves its replay floor in `connector_config.checkpoint` before
  source I/O. Subsequent polls resume the last fully completed alert and
  vulnerability windows. A failure or process restart does not replace that
  floor with `now - polling interval`.
- A successful window keeps at least 60 seconds of overlap, or the requested
  lookback if wider (normally five minutes for alerts and one hour for findings).
  Empty completed windows also advance. No event-time/ID filter drops the
  overlap, so late-indexed documents within it remain eligible.
- In inventory mode the checkpoint advances only when both source searches,
  inventory writes, and every alert-ingest batch succeed. Inventory is written
  in chunks of at most 2,000 findings. A failed inventory sync may coexist with
  delivered alerts; those alerts can be replayed on retry.
- HTTP failures, transport timeouts, invalid JSON, incomplete shards, early
  termination, count mismatches, duplicate pages and missing cursors fail the
  poll. A legitimate empty search succeeds. Failed scroll continuations are
  never retried in place: the next scheduled poll opens a fresh snapshot from
  the preserved floor.
- Each search is bounded by `max_search_results`, 1,000 response pages and a
  300-second deadline; individual requests time out after 30 seconds. Exceeding
  any limit reports failure and retains the checkpoint. It never returns a
  truncated successful batch. Cleanup uses a five-second timeout; an unknown
  or uncleared context expires after its one-minute lease.
- Completed results are held in memory before ingest. Alert batches respect
  both `MAX_BATCH_SIZE` (default 1,000) and `INGEST_MAX_BODY_BYTES` (default
  10 MiB); configure these consistently on connectors and ingest. A single
  oversized event fails explicitly.

Delivery is **at least once**: a later sink failure or a checkpoint write failure
can replay earlier accepted batches. This is not a distributed transaction or
an exactly-once guarantee. Source retention and indexing delays longer than the
overlap can still require an explicit historical backfill. Existing gaps from
older connector versions are not reconstructed automatically. In legacy
`vuln_mode=alerts`, the independent inventory boundary stays unchanged.

Inventory selection retains the existing `rule.groups = vulnerability-detector`
query and requires a CVE and host for normalization. Custom vulnerability rule
groups are not covered by this polling repair and need a separate mapping
review; the alert-side vulnerability filter is broader than that query.

## Severity mapping

Wazuh emits a 0-15 numeric `rule.level`. AiSOC collapses that ladder onto its
five-tier severity taxonomy so detection logic and fusion rules stay
vendor-agnostic:

| Wazuh rule level | AiSOC severity |
|---|---|
| 0 – 3 | `info` |
| 4 – 7 | `low` |
| 8 – 11 | `medium` |
| 12 – 14 | `high` |
| 15 | `critical` |

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

**Search limit exceeded** — inspect volume and available poller memory before
raising `max_search_results`. The saved retry window remains intact. Changing
the rule threshold excludes data and is not a recovery mechanism. A deadline or
page-limit failure may require reducing source query cost or an explicitly
planned historical backfill; do not advance the checkpoint to hide the error.

**HTTP 403 on scroll / cleanup** — check the scroll permissions at both index
and cluster scope. Index search access alone can pass the first page and fail
the continuation. Cleanup failures are logged without replacing the original
search error.

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
| `max_search_results` | Maximum Results per Search | number | no | `100000` | Safety limit for one complete alert or inventory search. Exceeding it fails the poll and preserves its retry window; no results are silently dropped. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | Disable only for self-signed lab clusters. Production deployments must install the CA chain. |
| `vuln_mode` | Vulnerability Events | select | no | `inventory` | Where vulnerability-detector events go. 'inventory' (default) routes them to the asset vulnerability inventory with patch-window due dates per docs/cve-patch-policy.md; only CVSS>9, KEV, or overdue findings raise alerts. 'alerts' keeps the legacy behaviour of one alert per scan finding. · one of: `inventory`, `alerts` |

:::note Credential handling
`password` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
