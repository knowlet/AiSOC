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
| Alerts | `POST /{index_pattern}/_search` and `POST /_search/scroll` | Read the complete query window in pages |
| Vulnerability inventory | The same search endpoints in `vuln_mode=inventory` | Detector findings are written to the asset inventory |
| Cluster health probe | `GET /_cluster/health` | Used by **Test connection** |

Inventory collection reads `vulnerability-detector` events from the configured
alert index.

Events are normalized with `category: siem`. The originating rule is retained
as `rule_id`, `rule_name`, and `rule_level`; `external_id` identifies the
Indexer document, not the rule. Different documents that match the same rule
must remain different events. The original source remains under `raw_event`.

Promotion preserves the rule metadata, and triage receives explicit rule
fields and a sanitized `description` containing up to 1,000 characters of
`full_log` (or the rule description when no log is present). The excerpt is
rendered as untrusted evidence within the prompt; it is not an instruction to
the model. The full original source is retained separately. These fields
being present does not by itself establish verdict accuracy.

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

- Index permissions on the configured pattern: `indices:data/read/search*`,
  `indices:data/read/scroll`, and `indices:data/read/scroll/clear`.
- Cluster permissions: `cluster:monitor/health`, `indices:data/read/scroll`,
  and `indices:data/read/scroll/clear`.

OpenSearch requires the scroll and clear-scroll actions at both cluster and
index scope. Clearing a scroll frees this connector's search context; it
does not delete indexed documents. The health permission is needed by
**Test connection**. Verify the role against your deployed Security plugin
version; see [OpenSearch permissions](https://docs.opensearch.org/latest/security/access-control/permissions/).

Then **Security → Internal users** → create a user (e.g. `aisoc-reader`)
and map it to that role. Save the password — you will paste it into the AiSOC
connector form.

Reusing the built-in `admin` or `kibanaserver` accounts works for a lab but
must not be used in production.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Wazuh**.
2. Fill in:
   - `indexer_url`: full URL including port (e.g. `https://wazuh.corp.example.com:9200`).
   - `indexer_urls`: optional additional nodes, separated by commas or newlines,
     from the **same Indexer cluster**. The primary URL is tried first.
   - `username` / `password`: the read-only user from step 1.
   - `index_pattern`: leave as `wazuh-alerts-*` unless you have re-templated indices.
   - `min_rule_level`: default `7` keeps low-signal noise out of the lake; set lower for full audit coverage.
   - `checkpoint_overlap_seconds`: default `300`; increase this if documents
     routinely become searchable more than five minutes after their timestamp.
   - `verify_tls`: leave **enabled** in production; install the CA chain rather than disabling.
3. **Test connection** — calls `GET /_cluster/health`, trying fallback nodes
   after retryable availability failures.
4. **Save**.

### Multiple Indexer nodes

Keep the primary node in `indexer_url` and list the other nodes' base URLs
in `indexer_urls`. All nodes use the same credentials, index pattern, and
TLS verification policy.
These URLs are replicas of one source cluster; use separate connector
instances to collect from independent clusters.

Connection failures, timeouts, incomplete shard searches, and HTTP 429, 502,
503, or 504 can move a read to the next node. A failure on a later page
restarts the entire frozen query window there; partial results from one
node are discarded. Authentication, query, and certificate-validation
failures remain errors so a fallback cannot conceal a configuration problem.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- The connector queries the indexer with a `range` filter on `@timestamp` so the
  manager-side processing pipeline is not impacted.
- Each page contains up to 1,000 hits. The connector follows the Scroll
  context until an empty page, then clears it. A short page is not treated
  as the end of the results.
- HTTP errors, invalid JSON, timed-out searches, and incomplete shard results
  invalidate the read attempt. Retryable failures can trigger failover;
  permanent failures or exhausted nodes fail the poll. These failures are
  not reported as a successful empty window, and partially read pages are
  not submitted to ingest.
- Alerts and vulnerability inventory have separate durable completed-window
  positions in the existing `connector_config.checkpoint`. Restarted polls
  extend their lookback to the saved position and replay an overlap for
  documents indexed late. Alert replay is deduplicated by document identity,
  not by rule ID or a timestamp ordering that can hide a new older event.
  The identity history retains at most 10,000 entries; a busy overlap can
  replay older identities that have fallen out of that history.
- Progress advances only after a complete read and confirmed downstream
  acceptance. Inventory advances only after all inventory chunks commit;
  a failed inventory sync retains its old position even if alerts succeed.
  Ingest requests respect both event-count and encoded-body limits (defaults:
  1,000 events and 10 MiB); inventory transactions contain at most 2,000
  findings. Configure `MAX_BATCH_SIZE` and `INGEST_MAX_BODY_BYTES` consistently
  on the connectors and ingest services when overriding those ingest limits.
- Delivery is at least once. A crash or later-chunk failure can replay
  already accepted data. Before a stream has its first saved checkpoint,
  alerts use the poll interval as their lookback (default five minutes),
  while inventory uses one hour. There is no earlier durable checkpoint
  for that stream to recover. Documents arriving
  outside the replay overlap or already removed by Indexer retention are
  not guaranteed to be recovered.
- The current fetch interface collects a completed window in memory. Large
  outage backlogs therefore need memory proportional to the result count.

After upgrading from the rule-ID-based event identity, newly ingested events
use the Indexer document's index and ID. Existing stored events are not
rewritten, and replaying the upgrade's overlap can create new event identities
for documents previously ingested under the old identity. Fusion can still
group related events; distinct source event IDs do not imply one alert row
per document.

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

**`403` during polling** — verify both the index and cluster scroll permissions
above. A successful health probe alone does not prove search authorization.

**A failed poll after some data was accepted** — the checkpoint is withheld
for replay. Do not clear it merely to make the error disappear: inspect the
failed Indexer response or downstream rejection so the missed window can be
retried.

**`single event exceeds ingest body limit`** — one event plus its request
envelope exceeds `INGEST_MAX_BODY_BYTES`. The connector fails the poll and
keeps the checkpoint for retry; it does not truncate or discard the source
log to fit. Review the event and, if appropriate, raise the limit consistently
on both services before retrying.

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
| `indexer_urls` | Additional Indexer URLs | string | no | — | Comma- or newline-separated fallback nodes in the same Indexer cluster. The primary URL is tried first; every node uses the same credentials and TLS policy. |
| `username` | Indexer Username | string | yes | — | Indexer user with read access to wazuh-alerts-*. Create a dedicated read-only role in production. |
| `password` | Indexer Password | secret | yes | — | **encrypted at rest** |
| `index_pattern` | Alert Index Pattern | string | no | `wazuh-alerts-*` | Override only if you have re-templated the default Wazuh index naming. |
| `min_rule_level` | Minimum Rule Level | number | no | `7` | Drop alerts with rule.level below this value at ingest. Default 7 keeps low-signal noise out of the lake; lower to 3 for full audit coverage. |
| `checkpoint_overlap_seconds` | Checkpoint Replay Overlap (seconds) | number | no | `300` | Replay this much time before the last completed window to catch late indexed events. Already seen document identities are deduplicated. Default 300. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | Disable only for self-signed lab clusters. Production deployments must install the CA chain. |
| `vuln_mode` | Vulnerability Events | select | no | `inventory` | Where vulnerability-detector events go. 'inventory' (default) routes them to the asset vulnerability inventory with patch-window due dates per docs/cve-patch-policy.md; only CVSS>9, KEV, or overdue findings raise alerts. 'alerts' keeps the legacy behaviour of one alert per scan finding. · one of: `inventory`, `alerts` |

:::note Credential handling
`password` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
