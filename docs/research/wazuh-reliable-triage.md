# Reliable Wazuh polling and triage context

## Scope and baseline

Investigated on 2026-11-04 against upstream commit
`8a280520ccf18826c68b31c07adef6b1fae57622`. The fork's earlier polling
commit `9b0d6895a060d275890d43b86ba1d3435255d4e7` provides existing Scroll
research and regression cases. Its ingest batching changes must not replace
the newer batching already present on main.

The connector already emits `rule_id`, a `description` containing at most
1,000 characters of `full_log`, and the original source under `raw_event`.
The missing context is downstream: promotion omits the canonical rule
metadata, the fused-alert consumer omits the description, and the prompt's
generic extra-field budget can omit nested source evidence. Separately,
`external_id` contains the rule ID, although ingest uses that field as an
event identity. Distinct documents produced by one rule can therefore share
the same normalized event ID.

At that baseline, both alert and vulnerability queries stop after 1,000 hits.
Search errors become empty results. Wazuh does not adopt the existing
persistent checkpoint contract or recover time windows missed during an outage.

Duplicate searches found no Wazuh-specific issue or pull request covering
these remaining gaps. Related upstream work already supplies the checkpoint
contract (#1039), the full-ingest acceptance gate (#1441), and count-based
ingest chunking (#1653). Earlier rule-aware triage work (#665) and the closed
normalization issue #1244 do not carry these canonical rule/log fields through
the complete path. The fork's separate custom-inventory-selector pull request
is outside this change.

## Design before implementation

| Existing mechanism or candidate | Use and limits |
| --- | --- |
| AiSOC's MIT-licensed normalization, promotion, prompt sanitization, and checkpoint persistence | Extend the existing paths without changing the schema or replacing other connectors' cursor policies. |
| OpenSearch Scroll over the existing HTTP client | Drain a stable query snapshot, including short pages, and clear its context. Retry the complete frozen window on another configured node after a retryable failure. |
| `opensearch-py` asynchronous scan helper, Apache-2.0 | Reference lifecycle, failed-shard checks, and cleanup; no code copied and no new dependency. Existing research pins `edf9dace73a5366d260c3ccc0c2348cba0bd2bf2`. |
| Point in time with `search_after` | A valid alternative, but adds newer API and permission requirements to this connector; retain the already-researched Scroll approach. |

Use a stable per-document `external_id`, keeping detection identity in
`rule_id`. Propagate canonical rule metadata through promotion and explicitly
render the sanitized, bounded vendor log excerpt inside the existing
untrusted-evidence prompt boundary.

Checkpoint state is specific to this connector: independent completed-window
ends for alerts and vulnerability inventory, plus bounded replay deduplication
for alert document identities. Freeze each query's upper bound, replay an
overlap, and extend the lower bound to the saved position after an outage.
Stage progress only after complete reads. Inventory progress requires a
successful database sync; the existing scheduler's full-ingest acceptance
gate controls durable checkpoint persistence. An unconfirmed write may replay
but must not skip data.

Failover URLs refer to nodes of the same Indexer cluster. A node failure must
not produce an empty success or combine partial snapshots. Auth, malformed
query, and TLS validation failures must remain visible. Preserve certificate
verification, sanitize diagnostics, and close owned search contexts.

## Verification plan and limits

Use each service's locked dependencies with Python 3.11. Prove regressions
for complete pagination, tied timestamps, node failures, partial responses,
restart catch-up, rejected ingest, independent inventory retries, and rule/log
context reaching the actual prompt builder. Use real local HTTP transport
and PostgreSQL where available, and distinguish these from a real Indexer
cluster or the full Compose pipeline. Run the required agent eval harness
before and after changes. Record baseline failures and negative controls
without weakening existing gates.

This change does not promise exactly-once delivery, unlimited late-event
recovery, or recovery of documents already deleted by source retention.
The first poll uses its configured lookback. Result memory remains
proportional to a completed query window under the existing list interface.

## Validation record

The final service suites and paired evals were rerun after rebasing onto
upstream `b9a66f96d9bc7de1ac5f269bf9783da796571926`. Its three security
commits do not overlap this patch; their route, query-scope, and vendored
authentication checks also pass.

### Executed application paths

All Python service tests used Python 3.11 and each service's committed
dependency lock in a separate environment. Tooling was isolated from those
environments. Tests used synthetic records; no production data was invented
or measured.

| Check | Observed result |
| --- | --- |
| Complete connectors suite | 1,437 passed, 5 skipped. |
| Complete fusion suite | 1,210 passed, 28 skipped. |
| Complete agents suite | 2,519 passed, 19 skipped, 219 subtests passed; three existing DNS failures also occur on the unchanged base. |
| Real HTTP/TLS protocol fixtures | Six cases passed, including 1,001 and 2,501 tied-timestamp documents, late-page failures, whole-window failover, cleanup, and an untrusted certificate that stops fallback. These are not a running Indexer cluster. |
| Agent eval harness | All 11 suites passed before and after, with equal scored values under `PYTHONHASHSEED=0`; 200 synthetic cases, no model call. |

The three agents-suite failures are in `test_hunt_from_report.py`: its URL
guard resolves `example.com` before reaching the mocked HTTP transport, and
that lookup is unavailable in the local test environment. The base produces
the same three failures. Local fixture runs removed inherited proxy settings
only in the test process and disallowed non-loopback socket connections;
production HTTP-client proxy behavior is unchanged.

An additional cross-service experiment used the actual Go normalizer and
four synthetic deliveries: three source documents, including reused IDs in
different indices, plus one replay. The base generated one canonical event
ID; the patch generated three, with the replay retaining its original ID.
Actual normalized output then passed through `FusionWorker`, the real
`FusionEngine`, the sink's SQL argument construction, fused serialization,
`build_state`, and the prompt builder. Rule `5710`, the document identity,
and a 536-character log including evidence after character 400 survived.
That experiment used the repository's Kafka producer double and Redis's
unavailable fallback; it did not write PostgreSQL or call a model.

### Regressions and controls

New tests were observed failing before the relevant production fixes.
Isolated copies with the corresponding fix removed reproduced failures for
pagination, rule/log propagation, checkpoint resume, inventory confirmation,
inventory transaction chunking, request byte limits, and per-request accepted
counts. The original connector fails all six real HTTP/TLS protocol cases.
Additional controls cover invalid checkpoint timestamps and constructor
validation being recorded as a failed poll.

Full pagination exposed two downstream limits that must remain enforced:
the inventory writer truncates a call above 2,000 findings, and ingest limits
both event count and encoded body bytes. The scheduler now splits inventory
transactions; ingest requests preserve the existing configurable count limit
and also fit the configured body limit. Three synthetic 4 MiB records
reproduced the old HTTP 413 despite a batch count of only three. Counts are
checked per response so an overcount and undercount cannot cancel out across
requests and authorize an incorrect checkpoint.

Independent review also corrected shard accounting: OpenSearch's `skipped`
count is included in `successful`. Completion therefore requires
`successful == total`, zero failures, and explicit valid response metadata,
including on the final empty page. Missing metadata is not proof of success.

### Database and deployment limits

Seven PostgreSQL checkpoint/inventory cases are wired into the existing
connector-scheduler live workflow. A further case in the existing alert
occurrences suite writes and reads the rule, excerpt, event identity, and
original raw log through the actual alert sink. The fixtures assert/use the
existing DML runtime role and migrated schema.

Those database assertions were not executed locally: PostgreSQL and Docker
were unavailable. Likewise, a real Wazuh cluster, Kafka-backed CORE smoke, and
live model verdict accuracy were not tested. The CI jobs must supply the
database evidence; local protocol and serialization passes do not substitute
for it. Delivery remains at least once, with a finite overlap and a bounded
10,000-identity history. Fusion may aggregate distinct source events into one
alert row.

### Primary protocol references

- [OpenSearch Scroll API](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/)
- [OpenSearch search response](https://docs.opensearch.org/latest/api-reference/search-apis/search/)
- [OpenSearch permissions](https://docs.opensearch.org/latest/security/access-control/permissions/)
- [Search shard accounting](https://github.com/opensearch-project/OpenSearch/blob/main/server/src/main/java/org/opensearch/action/search/AbstractSearchAsyncAction.java)

These references were fetched successfully during review. No third-party
implementation was copied and no dependency was added.
