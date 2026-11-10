# Complete Wazuh polling and replayable failures

## Scope and decision

Reviewed on 2026-11-04 against upstream
`2627090dc65938a69fa32f5dac3ef015bdd963e3`. The earlier fork change
`9b0d6895a060d275890d43b86ba1d3435255d4e7` is a reference, not evidence that
the current tree has passed its recorded tests.

Both Wazuh fetch paths stop after one 1,000-hit response. The shared search
helper returns an empty list on errors, which the scheduler treats as success.
Raising alone is insufficient: a relative time window moves past unread data
after an outage. The optional inventory sync also suppresses failures and its
writer truncates each call to 2,000 findings. Upstream already chunks alert
ingest by event count; retain that implementation.

Keep the existing HTTP client and list-returning interface. Drain a scroll
snapshot before returning any rows. Save an initial replay floor before source
I/O, then advance the Wazuh window checkpoint only when both required streams
and every downstream batch complete. Bounded resource limits raise an error;
they never turn a partial read into success. Replaying accepted rows is allowed.

## References inspected before implementation

| Candidate | License and source | Decision |
| --- | --- | --- |
| OpenSearch scroll / opensearch-py async_scan | Apache-2.0, `edf9dace73a5366d260c3ccc0c2348cba0bd2bf2` | Reference lifecycle only; keep httpx |
| PIT / elasticsearch-py AsyncSearch.iterate | Apache-2.0, `3cf07475a8b7626f0cd72cdbe0c80fd2903055bf` | Different tie-breaker/version assumptions; do not adopt |
| opensearch-dsl-py Search.scan | Apache-2.0, `d570c6dbd48999ee2af6dfc8fb2c884e820c212c` | Delegates to the same helper; no additional dependency |

Actual source and protocol evidence:

- [OpenSearch pagination](https://docs.opensearch.org/latest/search-plugins/searching-data/paginate/)
- [PIT and ambiguous scroll retries](https://docs.opensearch.org/latest/search-plugins/searching-data/point-in-time/)
- [Async scan lifecycle](https://github.com/opensearch-project/opensearch-py/blob/edf9dace73a5366d260c3ccc0c2348cba0bd2bf2/opensearchpy/_async/helpers/actions.py)
- [OpenSearch 2.19 shard accounting](https://github.com/opensearch-project/OpenSearch/blob/fd9a9d90df25bea1af2c6a85039692e815b894f5/server/src/main/java/org/opensearch/action/search/AbstractSearchAsyncAction.java)
- [OpenSearch 3.3 tie-breaker addition](https://github.com/opensearch-project/OpenSearch/blob/e972d15408320e6be84c64bb0fdc076ca7696ea2/release-notes/opensearch.release-notes-3.3.0.md)

Scroll fixes the source view and shard cursors, including identical timestamps,
without assuming a sortable document-ID field. Use the latest scroll ID and
clear it in finally. A timeout may occur after a continuation advanced server
state: never retry that continuation in place. Restart from the persisted time
floor in the next scheduled poll. An unchanged scroll ID is normal.

Validate pages before accepting any hits. OpenSearch's skipped shards already
count as successful; require successful == total and failed == 0. Request exact
total hits, validate completion against it, reject duplicate document identities,
and continue to an explicit empty page even after a short page. This implementation
references protocol design; it does not copy another client's source.

## Checkpoint and downstream contract

The Wazuh-specific checkpoint carries separate alert and inventory boundaries.
They are completed query-window boundaries, not the largest event timestamp;
no timestamp/ID filter may discard late arrivals within the overlap. Capture an
absolute end before source I/O. On first use, persist the historical start before
fetching, so an initial failure can survive a restart. Existing last_sync helps
bootstrap older connector rows but cannot repair data already lost historically.

The required inventory sync must return a success/failure result and feed all
findings to its existing writer in bounded chunks. Any failed source page, sink
batch, partial acceptance, or checkpoint write preserves the previous replay
boundary and reports a failed poll. Alert delivery may precede inventory failure
reporting; those alerts may be replayed. This is at-least-once delivery, not an
atomic transaction across the source, inventory, ingest, and checkpoint.

The final sink-path review also found that Wazuh used its rule ID as
`external_id`. The Go normalizer's `generateEventID()` prioritizes that field,
so distinct alerts from the same rule collided. Keep `rule_id` and the existing
`alert_id`, but supply an index-scoped document identity as `external_id`.
Retries of one document then retain an identity while distinct documents and
daily indexes remain distinct. Historical IDs are not rewritten; replaying old
data after this correction can produce new IDs for previously ingested records.

Preserve the upstream event-count batching and extend it with the ingest
server's byte limit. Preflight the exact serialized envelope before sending
anything, reject a single oversized event, and validate each response's counts
before aggregation. A malformed count in one chunk cannot cancel another
chunk's discrepancy into a false whole-poll success.

## Verification plan and limits

Exercise both entry points above 1,000 and 10,000 documents, tied timestamps,
short pages, true empty results, every failure mode, caps, cleanup, and delayed
recovery. Use the service lockfile, real HTTP sockets and a temporary migrated
PostgreSQL database. Run a negative control against the original source.

Synthetic sockets do not validate an actual Wazuh/OpenSearch server, cluster
failover, Security-plugin roles, or production connectivity. Source retention and
arbitrarily late indexing remain external limits. The list interface retains a
complete bounded result in memory; hitting a cap keeps the poll unhealthy until
the operator increases the bound or arranges an explicit historical backfill.

Existing vulnerability classification is outside this fix: the inventory query
selects `rule.groups = vulnerability-detector`; events using only custom groups
can be excluded by the alert-side filter without matching that query. Findings
without a CVE or host remain excluded by normalization. Snapshot completeness
therefore means every document matching each existing query, not every possible
vulnerability event in a customized deployment.

## Validation record

Environment: Linux x86_64, CPython 3.11.17, all 51 applicable distributions
installed at the connector lockfile versions; Ruff 0.16.10 and mypy 2.4.1 in a
separate environment. No dependency manifests or locks changed. The official
Go 1.26.10 archive checksum matched its published metadata.

| Check | Observed result |
| --- | --- |
| Unchanged upstream connectors tests, same Python/dependencies | 1,337 passed, 5 skipped |
| Changed connectors tests with the existing coverage gate | 1,456 passed, 5 skipped; 73.94% coverage against the unchanged 66% floor |
| Wazuh HTTP socket / database regressions | 21 passed, no skips |
| Existing scheduler / queue acknowledgement / vulnerability promotion regressions | 19 passed, no skips |
| Selected source regressions against unchanged upstream Wazuh/Base | 10 failures for the expected truncation / swallowed-error behavior |
| Selected socket/database regressions against unchanged upstream | 7 expected behavior-assertion failures |
| Existing native Go normalizer / identity cases | 4 passed, module mode readonly |
| Actual Python Wazuh output through the native Go normalizer | 1,002 distinct events produced 1,002 distinct canonical IDs; every replay retained its ID |
| Same Go harness with original Python output | Expected collision at the second distinct document |

The database runs use real SQLAlchemy/asyncpg connections to PostgreSQL 18.6
compiled to WASM, provided by PGlite 0.5.15 and its socket adapter. All 154 SQL
migrations were applied unchanged. The runtime connection is checked as
`aisoc_app`, with neither superuser nor BYPASSRLS privileges. The fixtures honor
the query's actual time bounds; recovery tests advance the application clock
beyond the original interval. One test stalls a real local response to exercise
the actual 30-second HTTP read timeout.

This is not native PostgreSQL 16 validation. The environment has no Docker and
only a root UID mapping, which cannot start native PostgreSQL through its
supported entry point. PGlite has one underlying backend and different socket
termination behavior, so these tests do not establish native multibackend
concurrency. The existing PostgreSQL CI workflow now includes the new suite;
that remote workflow has not run for this branch yet.

The five ordinary unit-suite skips are two root/chmod tests and three optional
database promotion tests. Those three promotion tests passed separately in the
19-case database run. The full Wazuh/OpenSearch service, Security-plugin roles,
native Go HTTP ingest server, Kafka, and the CORE deployment were not exercised.
No production Wazuh environment was contacted.

Reproduction with the service's locked environment:

```sh
cd services/connectors
python -m pytest tests/ --cov-config=pyproject.toml --cov=app -q --tb=short -rs
# Set both test DSNs to an isolated migrated database before these tests.
python -m pytest ../../tests/isolation/test_wazuh_polling_live.py \
  ../../tests/isolation/test_connector_scheduler_live.py \
  ../../tests/isolation/test_queue_acknowledgement_live.py \
  tests/test_vuln_promotion_live.py -q --tb=short -rs
```

Static checks use the repository's unmodified Ruff, mypy-baseline, test-discovery,
generated connector-doc, conformance, attribution and integration-name gates.
The source and test files are included in the existing CI paths; no check or
coverage threshold was weakened.
