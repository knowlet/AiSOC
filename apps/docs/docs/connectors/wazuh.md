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
| Alerts | `POST /{index_pattern}/_search` against the indexer | One AiSOC event per alert document |
| Complete result pages | `POST /_search/scroll`, `DELETE /_search/scroll` | Drain and release the current search snapshot |
| Cluster health probe | `GET /_cluster/health` | Used by **Test connection** |

Events are normalized with `category: siem`. The originating rule is preserved
as `rule_id`, `rule_name` and `rule_level`; the Indexer document identity is
`alert_id` / `external_id`. These are different identities: many documents can
match the same rule. The original payload remains in `raw_event`, and up to
1,000 characters of `full_log` become the description. Fusion and triage carry
the rule and description explicitly; triage sanitizes and bounds the excerpt
inside its untrusted telemetry section, under the existing model-input checks.

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
- A read-only **indexer user** with permission to search `wazuh-alerts-*`.
  See the Wazuh docs for [creating indexer roles and users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
- Optional: the CA chain for the indexer's TLS certificate.

## Setup walkthrough

### 1. Create a read-only indexer user

In the Wazuh dashboard, go to **Security → Roles** and create a role with:

- Index permissions on `wazuh-alerts-*`: `read` (including search, scroll and
  scroll-clear read actions).
- Cluster permissions: `cluster:monitor/health`, `indices:data/read/scroll`
  and `indices:data/read/scroll/clear`.

The health permission is required by **Test connection**. OpenSearch requires
the scroll and clear permissions at both cluster and index scope; granting
only index search permission is insufficient. See the
[OpenSearch permission reference](https://docs.opensearch.org/latest/security/access-control/permissions/).
No index writes, role administration or `all_access` permission are needed.

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
   - `min_rule_level`: default `7` selects levels 7–15. Set `3` to include
     levels 3–15 when custom security rules use lower levels; it still omits
     levels 0–2. Severity is a rule-author choice, not proof that a lower-level
     event is harmless.
   - `excluded_rule_ids`: optional explicit rule IDs to omit, separated by
     commas or newlines. For example, `19008,19009` omits those SCA rules if
     that matches your collection policy. No rule IDs are excluded by default.
   - `indexer_urls`: optional fallback URLs from the **same cluster**, separated
     by commas or newlines. The existing `indexer_url` remains the first choice.
   - `overlap_seconds`: default `900` (15 minutes) for delayed indexing.
   - `timestamp_field`: default `@timestamp`; change only when the Indexer has
     a deliberately configured and mapped arrival-time field (see below).
   - `verify_tls`: leave **enabled** in production; install the CA chain rather than disabling.
3. **Test connection** — calls `GET /_cluster/health` against the indexer.
   This proves the health endpoint is reachable with these credentials; a
   successful poll also requires index search and scroll permissions.
4. **Save**.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- Each poll freezes absolute lower and upper time bounds and drains a scroll
  snapshot in 1,000-hit pages until the Indexer returns an empty page. The page
  size is not a total-result limit, including when documents share timestamps.
- HTTP, network, malformed-response, timeout and failed-shard responses fail
  the poll. HTTP 200 with incomplete shard results is not a successful poll.
  An unsuccessful attempt returns no partial batch and stages no progress.
- A checkpoint records the completed query boundary and a bounded set of
  document identities. The scheduler persists it only after all submitted
  alerts are accepted by ingest. Successful empty windows establish progress
  too. A restart resumes from that persisted boundary, subject to Indexer
  retention; a failed read or delivery leaves it unchanged.
- Before the first source request, the scheduler persists an unfinished query
  lower bound. A failed first poll or a crash before any accepted batch can
  then resume that original window. This anchor does not claim completion;
  if it cannot be stored, the poll fails before querying the source.
- Queries overlap by `overlap_seconds`. A newly indexed older document is
  accepted based on its identity, rather than rejected because its event time
  precedes the previous poll's newest event. Identity-cache eviction can cause
  replay, not a gap; stable document IDs support downstream deduplication.
- Alerts and vulnerability inventory have separate completed boundaries.
  Inventory progress is confirmed only after all sink-sized transactions
  complete; a failed inventory sync cannot inherit the alerts' progress.
- On a transient node failure, failover restarts the **entire fixed window**
  on the next configured Indexer. A scroll continuation is never retried on a
  different node: the failed request may already have advanced its cursor.
  Failover does not replace unavailable shards or query independent clusters.

### Late documents and recovery limits

Wazuh's default Filebeat pipeline derives `@timestamp` from the Manager's
event timestamp. A successful search cannot see a document that has not been
indexed yet. The overlap covers a bounded lateness window, including a
ten-minute delay with the default setting; it is not an arbitrary-delay
guarantee. Increase the overlap for the observed forwarding delay, or run a
backfill when a delay exceeds it. Initial collection starts at the bootstrap
lookback plus overlap; documents already older than that at setup require an
explicit backfill. Once saved, the initial lower bound survives failed first
polls and restarts, separately for alerts and inventory.

An Indexer-assigned arrival-time field can decouple collection from Filebeat
delay. It must be a date field populated for every incoming alert, with its
processor placed after any processor that removes that field. It is **not**
present by default: the stock Wazuh pipeline removes `event`, so merely setting
`timestamp_field=event.ingested` does not create a working ingestion clock.
Preserve the original event time for investigation. Changing the collection
field requires an explicit backfill or checkpoint reset and validation of the
new field on existing documents.

Completed batches are returned as lists, so memory grows with the queried
window. A long outage can require a large recovery batch. Source retention,
late writes outside the overlap and permanently rejected downstream events
remain operational recovery conditions; they are not reported as lossless
end-to-end delivery.

### Event-identity upgrade

`external_id` now identifies the Indexer document (`_index::_id` when the index
is present), and `rule_id` identifies the rule. Older versions used the rule
ID as `external_id`, which could collapse distinct same-rule documents in
ingest. Existing stored alerts are not rewritten. Replaying an old window may
therefore create newly distinct alerts; use a deliberate backfill to recover
historical documents still retained by the Indexer.

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

**`403` or missing permission** — check the dedicated role. The health probe
requires `cluster:monitor/health`; a poll also needs the search/scroll grants
above. Changing the password does not repair a missing privilege.

**Failed shard, timeout or scroll error** — check Indexer shard availability
and the configured endpoints. The poll retains its checkpoint for retry;
an HTTP-200 partial result is deliberately rejected.

**`network error` on Test connection** — verify the URL points at port 9200, not
55000 (manager) or 5601 (dashboard). The manager API uses JWT, not basic auth,
and will reject the connector's requests.

**`no events_added`** — confirm `wazuh-alerts-*` indices actually exist in the
target cluster. Some Wazuh installations re-template the index name; if so,
override `index_pattern` to match.

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
| `indexer_urls` | Fallback Indexer URLs | textarea | no | — | Additional nodes in the same Indexer cluster, separated by commas or newlines. Tried in order after transient failures. |
| `username` | Indexer Username | string | yes | — | Indexer user with read access to wazuh-alerts-*. Create a dedicated read-only role in production. |
| `password` | Indexer Password | secret | yes | — | **encrypted at rest** |
| `index_pattern` | Alert Index Pattern | string | no | `wazuh-alerts-*` | Override only if you have re-templated the default Wazuh index naming. |
| `min_rule_level` | Minimum Rule Level | number | no | `7` | Only ingest alerts at or above this level. Default 7 excludes levels 0–6, including any custom security rules there. Set 3 to include levels 3–15 and use explicit rule exclusions for unwanted events. |
| `excluded_rule_ids` | Excluded Rule IDs | textarea | no | — | Optional alert rule IDs to exclude, separated by commas or newlines. Empty excludes no rules. |
| `overlap_seconds` | Late Arrival Overlap (seconds) | number | no | `900` | Replay this much event time before the last completed window. Delivery delays beyond this overlap require backfill. |
| `timestamp_field` | Query Timestamp Field | string | no | `@timestamp` | Default is the Manager event time. An ingestion-time field works only after you configure and map it in the Indexer pipeline. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | Disable only for self-signed lab clusters. Production deployments must install the CA chain. |
| `vuln_mode` | Vulnerability Events | select | no | `inventory` | Where vulnerability-detector events go. 'inventory' (default) routes them to the asset vulnerability inventory with patch-window due dates per docs/cve-patch-policy.md; only CVSS>9, KEV, or overdue findings raise alerts. 'alerts' keeps the legacy behaviour of one alert per scan finding. · one of: `inventory`, `alerts` |

:::note Credential handling
`password` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
