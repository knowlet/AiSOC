---
sidebar_position: 1
---

# Cases

A **Case** is the central unit of work in AiSOC. Every security incident, alert,
or investigation is tracked as a Case.

## Case States

Six states, and the machine is **forward-only**:

```
new → triaged → investigating → contained → resolved → closed
                      │
                      └──────────────────► resolved
```

`investigating` can go straight to `resolved` when there was nothing to
contain. Every other move is one step along the chain, and `PATCH /cases/{id}`
refuses anything else with a `422` naming the transitions that *are* allowed.

Two states are easy to misread:

- **`resolved` is not terminal.** It means the case has an outcome, not that
  it has been closed out. It is still on somebody's queue, and treating it as
  finished is what made "cases closed this week" count the wrong rows. Only
  `closed` writes `closed_at`, which every duration metric reads.
- **`open` and `in_progress` are not states.** They belonged to a
  pre-consolidation vocabulary and the `aisoc_cases` CHECK constraint rejects
  both. A query filtering on either returns nothing — not an error, just a
  structurally empty result, which is why these lingered.

### Reopening

Forward-only is what makes "this case was closed" mean something, so there is
no backward edge in the state machine — a title edit that happened to carry a
status must not be able to walk a case backwards silently.

"Closed in error" and "it came back" are still real, so reopening is its own
deliberate act:

```
POST /api/v1/cases/{id}/reopen
{ "reason": "The indicator reappeared on two more hosts overnight.",
  "status": "investigating" }
```

It needs `cases:write`, requires a reason of at least 8 characters, increments
`reopen_count`, records `reopened_at`, and clears `closed_at` / `resolved_at`
so the case is not counted as terminal and active at once. Only `closed` can
be reopened; `resolved` still has a forward edge, so the route answers `409`
and tells you to use `PATCH`.

Reading is permissioned too: every cases `GET` route requires `cases:read`
(v20.0.0), so an API key scoped to `alerts:read` alone cannot list cases or
read their comments, timeline and evidence chain. Case comments carry an
`is_system` flag in responses, but it is server-assigned only — the create
request stopped accepting it in v20.0.0, because a caller-supplied value let
any `cases:write` holder author a comment the console renders as an
unattributed "System note".

`reopen_count` exists because `reopened_at` is overwritten each time: a case
reopened four times is a different conversation from one reopened once, and a
single timestamp cannot tell them apart.

## Case Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier |
| `title` | string | Short description |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `status` | enum | `new`, `triaged`, `investigating`, `contained`, `resolved`, `closed` |
| `reopened_at` | timestamp? | When last reopened. `null` means never — not zero |
| `reopen_count` | int | How many times. `0` is a real measurement here, unlike the timestamp |
| `reopen_reason` | string? | Why it was last reopened |
| `mitre_tactics` | string[] | Associated ATT&CK tactics |
| `indicators` | Indicator[] | IOCs linked to the case |
| `playbook_runs` | PlaybookRun[] | Automation runs |
| `ledger_entries` | LedgerEntry[] | Replayable agent decisions (see below) |

## AI Investigation

Click **Investigate with AI** to launch the multi-agent investigation pipeline:

1. **OrchestratorAgent** — plans the investigation graph and routes work
2. **ReconAgent** — collects case context, threat intel, environmental fit
3. **ForensicAgent** — deep-dives indicators, timeline, attack-graph paths
4. **ResponderAgent** — proposes (dry-run by default) containment steps
5. **ReportWriterAgent** — generates the PDF / Markdown executive report

The full graph lives under
[`services/agents/app/investigator/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/investigator).

## Investigation Ledger

The **Investigation Ledger** is the structural moat that separates AiSOC from
closed-source AI SOC vendors: every prompt sent to an LLM, every response
received, every tool invocation, every evidence citation, and every decision
branch is appended to a tenant-scoped, append-only ledger and rendered as a
scrubbable timeline on the case workspace.

### What gets logged

For every agent step, the ledger captures:

- `agent_id` — which agent emitted the step (`orchestrator`, `recon`, …)
- `step_kind` — `prompt`, `response`, `tool_call`, `tool_result`,
  `decision`, `evidence_citation`, `plan_update`
- `model` — the model name and provider used for the step
- `prompt_hash` — SHA-256 of the prompt (so you can prove what was asked
  without storing every byte twice)
- `payload` — the structured content of the step (redacted per tenant
  config)
- `started_at` / `completed_at` / `latency_ms`
- `tool_name` and `tool_input_hash` for tool calls
- `evidence_uris` — links into PostgreSQL / OpenSearch / Neo4j / Qdrant
  for every cited piece of evidence

### Why it matters

- **Auditability** — every claim the agent makes on a case is backed by
  a logged tool call and evidence citation, scoped to a tenant.
- **Replayability** — analysts can scrub the timeline and replay the
  exact sequence the agent followed, including failed tool calls.
- **Compliance** — feeds the SOC 2 / ISO 27001 / NIST CSF dashboards
  with concrete, human-readable evidence of automated decisions.
- **Debugging** — when an investigation goes wrong, the ledger is the
  first place to look; you can see the exact prompt, response, and
  tool input that produced the bad output.

### Where it lives

- Schema:
  [`services/api/migrations/008_investigation_ledger.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/008_investigation_ledger.sql)
- Model:
  [`services/api/app/models/investigation.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/models/investigation.py)
- API endpoints:
  [`services/api/app/api/v1/endpoints/investigations.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/investigations.py)
- Agent-side writer:
  [`services/agents/app/investigator/ledger.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/app/investigator/ledger.py)
- UI:
  [`apps/web/src/components/cases/InvestigationLedger.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/cases/InvestigationLedger.tsx)

### REST surface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/cases/{case_id}/investigations` | List ledger entries for a case |
| `GET` | `/api/v1/investigations/{id}` | Get a single ledger entry with full payload |
| `POST` | `/api/v1/cases/{case_id}/investigations:replay` | Replay an investigation deterministically |

The ledger is also surfaced through the [MCP server](../integrations/mcp), so
analysts can replay agent decisions directly from Claude / Cursor / Continue
/ Cody.

## Ambient Copilot

### Finding cases and pending approvals

Copilot can discover work before you know its UUID. For example:

- "Find high-severity cases about workstation-42."
- "Find INC-042 and summarize the case evidence."
- "Which high-risk approvals are assigned to me?"

`copilot_cases` searches case titles, descriptions and case numbers using a
case-insensitive **literal substring**; `%`, `_` and backslashes have no wildcard
meaning. The query is trimmed, must contain a non-whitespace character, and is
limited to 200 characters. Optional status and severity filters combine with
the query. Statuses use the six case states above; `resolved` remains separate
from `closed`. Returned `case:<uuid>` references can be used with
`copilot_record` for a follow-up read. The underlying
`GET /api/v1/cases?query=...` retains its existing list response and requires
`cases:read`.

`copilot_pending_approvals` reads the authenticated tenant's existing approval
queue with `status=pending`. `mine=true` means **explicitly assigned to the
current user**, not every unassigned approval that the user might be able to
review. It can also filter by `low`, `medium`, `high` or `critical` risk. The
returned `approval:<uuid>` references identify queue records; an analyst still
reviews and decides them in the responder approval queue. Copilot receives
summary metadata, linked case/alert identifiers and expiry times, never the
action execution payload. A pending record may already be past its expiry;
the returned status alone is not proof that it can still be approved.

Both reads forward the current caller's credentials and tenant context to the
core API. They cannot choose another tenant, replace the caller with a service
credential, approve a request or execute an action. A denied or failed read is
reported as `could_not_check`, not as an empty queue.

Results use server pages of at most 20 records and stop at page 10. Case reads
use one additional row to determine `has_more`; they do not invent a total
count. Approval reads retain the API's filtered total. Records are ordered by
creation time descending with UUID as the tie-breaker. Per-response and
cumulative evidence limits may retain fewer records than a server page;
`truncated` identifies that loss and only retained records become citation
sources. An oversized first record retains a bounded metadata summary when
space permits; omitted descriptions and raw evidence do not support citations.
Narrow the query for omitted rows, or open the record in the console for omitted
fields. An empty page, the final
permitted page, or a cited answer is not evidence that every case or upstream
security event was searched.

### Contextual suggestions

The case workspace is **copilot-aware**: the Ambient Copilot panel proposes
the next concrete action based on the current state of the case (e.g.
"contain host", "open jira ticket", "add indicator to threat intel feed").
Each suggestion is one click away from running the right agent tool with
the right payload, and every accepted suggestion is recorded in the
ledger.
