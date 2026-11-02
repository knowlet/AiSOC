# Complete Wazuh polling and visible fetch failures

## Scope and evidence

Reviewed on 2026-11-02 against AiSOC
`f61942f309650dd219631b19df7d1af87a6ac67a`.

Both `WazuhConnector.fetch_alerts()` and `fetch_vulnerability_findings()`
request `size: 1000`, and `_search()` returns only that response's hits.
The same helper converts HTTP, transport and JSON errors to an empty list.
`ConnectorScheduler._poll_one()` already catches fetch exceptions and records
failure, but an empty list takes its success path. The helper's comment
describing a required never-raise contract contradicts its actual caller.

The fix keeps the existing async HTTP client, normalized envelopes, time-window
filters and list-returning interface. Scheduler failure bookkeeping needs no
behavior changes.

Reviewing the downstream transport exposed a second 1,000-event boundary:
`services/ingest/internal/handler/handler.go` rejects requests exceeding
`MaxBatchSize`, and `internal/config/config.go` defaults that setting to 1,000
and the request body limit to 10 MiB. The existing Python `IngestClient` sends
the entire list in one request. Fixing source pagination alone therefore
turns large polls into HTTP 413 failures. The integration fixture must enforce
these real server limits; accepting arbitrary lists would conceal this defect.
The ingest client will split a fully fetched result within both limits,
preserve order and tenant/auth headers, and aggregate confirmed counts. This
uses the existing JSON/HTTP stack, with no new buffering service or dependency.

## Reference comparison

| Candidate | Evidence | Decision |
| --- | --- | --- |
| OpenSearch Scroll with the existing `httpx` client | Official Scroll API, available since OpenSearch 1.0; fixed initial search snapshot and sequential batches | Adopt the protocol for batch ingestion; no new dependency |
| `opensearch-py` `async_scan()` | Apache-2.0 implementation at `edf9dace73a5366d260c3ccc0c2348cba0bd2bf2` | Reference its lifecycle and failure behavior; do not copy source or add the client package |
| PIT with `search_after` | Official PIT API, available since OpenSearch 2.4; snapshot plus explicit pagination sort | Valid alternative, but adds a newer API requirement and another context/permission contract to this focused fix |

Sources read before implementation:

- [OpenSearch Scroll API](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/).
- [OpenSearch Search API](https://docs.opensearch.org/latest/api-reference/search-apis/search/).
- [OpenSearch PIT API](https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/).
- [OpenSearch permissions](https://docs.opensearch.org/latest/security/access-control/permissions/).
- [Pinned `async_scan()` implementation](https://raw.githubusercontent.com/opensearch-project/opensearch-py/edf9dace73a5366d260c3ccc0c2348cba0bd2bf2/opensearchpy/_async/helpers/actions.py).
- [Pinned upstream license](https://raw.githubusercontent.com/opensearch-project/opensearch-py/edf9dace73a5366d260c3ccc0c2348cba0bd2bf2/LICENSE.txt).

The upstream helper starts a scroll search, follows the newest returned ID,
checks shard completion and clears its context in `finally`. This patch uses
that protocol design within the current helper. Unlike a streaming iterator,
the existing AiSOC fetch contract must collect the complete result before
returning; otherwise a later-page failure could masquerade as a successful
partial poll.

## Required behavior

1. Keep 1,000 as a page size, not a total-result limit. Continue until an empty
   hits array, including after a short page. Both Wazuh fetch paths share it.
2. Use the latest scroll ID on every continuation and cleanup, with the existing
   authentication and TLS settings. Clear only this query's context.
3. Disable partial results on the initial search and reject timeout, failed or
   incomplete shard responses, invalid JSON, malformed envelopes and unusable
   cursors. HTTP 200 alone does not prove completeness.
4. Raise a sanitized fetch error rather than returning empty or partial data.
   Preserve the original failure if best-effort cleanup also fails.
5. Leave genuine empty results as success. The scheduler records a failed alert
   fetch without ingesting its partial pages or advancing `last_sync`.
6. Document scroll/clear permissions at both cluster and index scope and the
   cluster-health permission used by the existing connection probe.
7. Send completed windows in bounded ingest requests, respecting both event
   count and encoded JSON body bytes. Do not increase server limits. Fail the
   poll if any request fails; prior requests may already have been accepted,
   so replay remains at-least-once rather than atomic delivery.

## Verification and limits

Regression tests must distinguish the old and new behavior for 1,001 or more
documents, exact page boundaries, identical timestamps, changing scroll IDs,
valid empty results, transport/HTTP/JSON failures, partial shards and cleanup.
Both alert and vulnerability-fetch entry points are covered.

The scheduler regression uses real HTTP sockets and the service's locked
dependencies against a migrated PostgreSQL database with the runtime role.
It checks persisted health/error/outage/`last_sync` state, no ingest after a
later-page failure, and recovery. Re-running the regression against the
original connector is the negative control.

Socket fixtures are synthetic indexer and ingest servers. They do not verify
an actual Wazuh/OpenSearch cluster, replica failover or its Security plugin.
Scroll fixes the completeness of each queried snapshot; it does not implement
a durable source checkpoint or change the scheduler's outage-backfill policy.
The optional vulnerability sync retains its separate failure logging policy.
Result memory remains proportional to the completed window's document count.

## Validation record

Environment: Linux x86_64, Python 3.11.17, all 51 applicable distributions
installed exactly from the connector service's lockfile, PostgreSQL 16.15
with all 147 repository migrations applied. Database tests used `aisoc_app`
with `NOSUPERUSER` and `NOBYPASSRLS`. Ruff 0.16.10 and mypy 2.4.1 ran in a
separate tools environment.

| Check | Result |
| --- | --- |
| From `services/connectors`: `python -m pytest tests/ --cov-config=pyproject.toml --cov=app --cov-report=term -q --tb=short -rs` | Exit 0: 1,339 passed, 2 skipped; 72.67% coverage, above the unchanged 66% floor |
| Same environment, `ISOLATION_CONNECTOR_DSN` pointing to the temporary database: `python -m pytest ../../tests/isolation/test_wazuh_polling_live.py -q --tb=short` | Exit 0: 13 passed |
| Same final live test file against an isolated copy of the original connector and ingest client | Exit 1 as required: 12 failed, 1 passed; the legitimate empty-result case still passes |
| Three focused source regressions before the fix, then with the original connector restored only in an isolated copy | All three fail as expected: 1,001 alerts truncate, 1,001 vulnerability findings truncate, HTTP 503 does not raise |
| Default ingest-size regression against the original client | 1,001- and 2,501-event cases fail with HTTP 413; 0-, 1- and 1,000-event cases pass |
| `ruff check services/ scripts/ tests/ tools/` and `ruff format --check .` | Exit 0; all 2,771 Python files formatted |
| `python scripts/check_mypy_baseline.py`, with a fresh temporary `MYPY_CACHE_DIR` | Exit 0: the existing 964 findings are unchanged; no new findings in any configured or unmanaged tree |
| `python scripts/check_test_discovery.py` | Exit 0: all 865 test files reached by CI invocations |
| `python scripts/check_competitor_names.py` | Exit 0; exact integration-path exceptions cover this research record and the new live test |

The two skipped unit tests exercise `chmod 000`; the test process runs as root,
so that permission-denial scenario cannot be asserted in this environment.
There are no skipped cases in the new live regression. The source fixtures use
synthetic events; no production credentials, alerts or cluster were accessed.

The pre-push workflow review found no checked-in push trigger matching
`fix/wazuh-complete-polling`. Main-branch image publishing, documentation
deployment and release automation do not run for that feature-branch push.
Local verification is not a GitHub Actions result.
