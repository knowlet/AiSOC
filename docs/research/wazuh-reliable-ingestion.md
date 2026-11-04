# Reliable Wazuh polling and triage evidence

## Scope and decision

Reviewed on 2026-11-04 against
`8a280520ccf18826c68b31c07adef6b1fae57622`. Extend the existing HTTPX connector,
Postgres checkpoint storage, ingest acceptance gate, and sanitized triage
projection. No additional client dependency or queue is needed.

The connector's current normalization already emits `rule_id` and a bounded
`description` from `full_log`; the missing context is in the subsequent
fusion/triage projections. Its `external_id` currently contains the rule ID,
but ingest uses that field as the event's stable identity. Different alert
documents from the same rule therefore need distinct external identities.

The scheduler already persists checkpoints after full ingest acceptance and
has an outage-backfill worker. Wazuh does not implement the checkpoint
contract, and its empty-list error fallback hides an outage from that worker.
The current fixed event-time window also excludes sufficiently late writes.

## References consulted before implementation

| Reference | Mechanism examined | License | Decision |
| --- | --- | --- | --- |
| OpenSearch Python client, `edf9dace73a5366d260c3ccc0c2348cba0bd2bf2` | `scan`, asynchronous transport: scroll lifecycle, shard validation, transport failure classification | Apache-2.0 | Reference the protocol; retain HTTPX and the existing complete-batch return contract |
| Logstash search input, `06f70e4a37181313adc2d232777f3c6ff6bb6baa` | `paginated_search.rb`, `cursor_tracker.rb`: fixed searches, scroll/PIT, persisted progress | Apache-2.0 | Reference the design only; its queue acceptance differs from this scheduler's ingest acknowledgement |
| OpenSearch Go client, `731076cb82ffab90f56f8fbe6d24f21983331d1a` | `PartialSearchError`, explicit partial-search parameter | Apache-2.0 | Reference explicit HTTP-200 failure handling; no cross-language dependency |

Sources:

- [Python scroll implementation](https://github.com/opensearch-project/opensearch-py/blob/edf9dace73a5366d260c3ccc0c2348cba0bd2bf2/opensearchpy/helpers/actions.py).
- [Search input pagination](https://github.com/logstash-plugins/logstash-input-elasticsearch/blob/06f70e4a37181313adc2d232777f3c6ff6bb6baa/lib/logstash/inputs/elasticsearch/paginated_search.rb).
- [Go partial-search errors](https://github.com/opensearch-project/opensearch-go/blob/731076cb82ffab90f56f8fbe6d24f21983331d1a/opensearchapi/errors.go).
- [OpenSearch scroll protocol](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/).
- [OpenSearch permissions](https://docs.opensearch.org/latest/security/access-control/permissions/).
- [Wazuh Filebeat pipeline](https://github.com/wazuh/wazuh/blob/bed556db3f4f535cb3a585f3d9e7f35a6acf0f58/extensions/filebeat/7.x/wazuh-module/alerts/ingest/pipeline.json).

The Wazuh pipeline assigns the source `timestamp` to `@timestamp`; it is not
an Indexer arrival time. That pipeline also removes `event`, so an optional
arrival-time field requires an operator-configured ingest processor and date
mapping. There is no assumed built-in `event.ingested` field.

The earlier fork branch `fix/wazuh-complete-polling` at
`9b0d6895a060d275890d43b86ba1d3435255d4e7` supplies prior pagination and
error-handling work. Its downstream client changes must not replace newer
main-branch batching. Reuse is selective and validated against this base.

## Implementation constraints

1. Drain a fixed scroll snapshot until an empty page. Validate every page
   before exposing any batch. HTTP errors, malformed JSON, timeouts and
   failed shards are failures, never successful empty polls.
2. Pin each scroll attempt to one Indexer. A failed continuation can advance
   server state, so failover restarts the entire same absolute query window
   and discards the abandoned attempt. Always clear its most recent cursor.
3. Save the completed query boundary, not the newest event timestamp.
   Re-query a configurable overlap and deduplicate document identities.
   A bounded identity cache may replay old documents after eviction; it must
   never discard a first arrival merely because its event time is older.
   Persist an unfinished first-query lower bound before source I/O so a
   failure before any accepted batch cannot move the bootstrap window forward.
4. Keep alert and vulnerability progress separate. Confirm inventory progress
   only after all of its sink transactions succeed. The existing full-alert-
   acceptance gate owns the final durable checkpoint write.
5. Preserve single-URL configuration, validate every fallback destination,
   retain TLS verification, and expose authentication/permission failures
   without logging credentials, query contents or response bodies.
6. Retain the existing minimum-level default for compatibility. Document
   lower-level custom detections and optional explicit rule-ID exclusions;
   do not hard-code a private deployment's rule pack or silently drop SCA.
7. Keep vendor log content inside the existing bounded, sanitized untrusted
   evidence projection. Rule identity and event identity remain distinct.

## Verification boundaries

Regressions cover page boundaries and equal timestamps, incomplete responses,
later-page failures, complete-window failover, delayed insertion, restart
recovery, downstream rejection, independent inventory progress and triage
projection. Negative controls run the same regressions against the original
production code. Synthetic HTTP protocol fixtures, a real search index, a
real database and an actual deployed multi-node Wazuh cluster are distinct
verification layers and must be reported separately.

Checkpoint recovery is limited by source retention. Initial collection starts
at the configured bootstrap window; older history requires explicit backfill.
A persisted unfinished lower bound keeps that initial window available across
failed first polls. Event-time overlap covers bounded delivery
lateness, not arbitrary Filebeat delays; longer delays need a larger window,
backfill, or an Indexer-assigned arrival-time field. A list-returning fetch
still consumes memory proportional to the completed window.

## Validation record (2026-11-04)

The local service environments use Python 3.11.17 and the applicable packages
from each service's current lockfile. The connector suite completed with
**1,445 passed, 12 skipped**, and 73.88% coverage (required: 66%). Seven skips
are the explicitly opt-in real-Indexer cases; the others require a separate
live database or non-root filesystem permission enforcement.

`tests/isolation/test_wazuh_polling_live.py` completed with **23 passed**.
Its source and ingest endpoints are real HTTP sockets with synthetic protocol
fixtures; the source fixture evaluates the submitted query rather than
returning every document unconditionally. SQL and JSONB checkpoint writes use
the production scheduler, vault, HTTP client and database code. The database
is PostgreSQL 18.6 compiled to WASM (PGlite 0.5.15), with all 155 migrations
applied unchanged and a runtime role verified as neither superuser nor
BYPASSRLS. A harness-only loopback adapter closes TCP on PostgreSQL Terminate
to work around the socket wrapper's missing session-close behavior; SQL and
database replies are forwarded unchanged.

The same 15 applicable regressions fail against the original production
source at the base commit above, pass against the fix, and fail again when
replayed against that original source. Failures reproduce truncation at
1,000 documents, missing late arrivals and restart history, and failed
searches being recorded as successful. The fixed suite additionally checks
independent inventory progress, including a real second-transaction database
rejection after the first 2,000 findings have committed.

The live fusion store regression passes after the fix and fails against
the original source: both executions insert and read a real alert row, but
the original row's `rule_id` is null. The same database environment is used.
The new triage tests also exercise the production model client against a
local HTTP endpoint; they do not call a paid or live inference service.

After rebasing onto upstream `a6061839f8acd04e297f860edd4bb9496a2c10b0`,
the full fusion suite completed with **1,210 passed, 29 skipped**; the
opt-in live store test separately passed. The full agents unit suite completed
with **2,522 passed, 3 failed, 3 skipped, 16 deselected**. All three failures are
unchanged DNS failures in `test_hunt_from_report.py`, reproduced against the
current base source (**2,515 passed, 10 failed** with the same new tests);
seven additional failures from the new context tests occur only on that base.
Both before/after offline eval runs pass all 11 axes, with
identical values and non-duration details under `PYTHONHASHSEED=0`.

The rebase adds one upstream migration. The scheduler's 23 regressions and
the live fusion store proof both pass again with all **156 migrations**
applied unchanged, under the same restricted runtime role. The connector
suite also passes again with the same 1,445/12 result. The original
155-migration negative-control evidence is retained separately.

The live scheduler workflow now runs the same database regressions against
native PostgreSQL and seven additional cases against the official OpenSearch
2.19.4 service. Those native services, a deployed multi-node Wazuh cluster,
and the full Compose smoke test were not available locally. A locally passing
protocol fixture is not evidence that those deployment checks have passed.
