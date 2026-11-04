---
title: What triage reads
sidebar_label: Triage context
---

# What triage reads

Auto-triage does not judge an alert on the alert alone. Before the model is
asked for a verdict it is given what this organisation already knows, and this
page is the complete list of what that is, where each part comes from, and
what it is allowed to do to a verdict.

Two rules hold for every source on the list.

**Prompt context is advisory.** Each prose block gives the model evidence to
consider. Tenant skills and runbooks do not enforce a disposition. Authored
business-context actions also run in deterministic code; the explicit
`require_escalation` action below is enforced outside the model.

**Context is point-in-time during a replay.** When you evaluate AiSOC against
your own closed findings, every source below is held at the split point, so
the test window cannot be judged using knowledge that did not exist yet. How
that is done differs by source and is described under
[Freezing](#freezing-context-for-a-replay).

## The sources

| Source | Where it comes from | What it contributes |
|---|---|---|
| Organisation memory | Compiled from tagged analyst disagreement (`/feedback`) | Durable statements about what is normal in your estate |
| Outcome priors | Every durable verdict, per evidence signature | A repeat alert matching a trusted prior benign disposition is closed without re-triage |
| Tenant skills | Authored over the [tenant-skills API](./tenant-skills.md), backtested, activated — there is no console editor yet | Your own investigation approach for alerts of a given shape |
| Knowledge-base runbooks | Documents you ingested at `/kb` | Excerpts from your runbooks that mention something this alert mentions, with citations |
| Business-context rules | Authored on `/settings/business-context`, applied post-fusion → pre-triage | The prompt names which of your rules fired and what they changed (for example `severity medium → critical`), so the model never reasons over a severity nobody chose in the evidence |

## Mandatory escalation

Use `require_escalation: true` when a matching alert must remain available for
human review. Pair it with `set_severity: critical` when the same rule should
also raise the alert's severity. Severity alone does not prohibit closure.

The two actions have separate meanings:

- `set_severity` changes the alert's severity. Ordinary severity actions keep
  their existing last-matching-rule behavior.
- `require_escalation` prohibits automatic suppression and closure. A model
  can still assess the evidence, but a benign verdict or a remembered benign
  prior cannot cancel the requirement. The matched rule IDs travel with the
  verdict, and the durable closure check refuses to resolve the alert.

Mandatory rules match against the **original alert**, before any ordinary
rule changes it. When one matches, suppression is refused regardless of rule
priority. A severity supplied by a matching mandatory rule is a floor on the
final result; another rule cannot reduce it. The live alert row is raised to
that severity without lowering a more severe existing value. Shadow runs
still leave the operational alert columns unchanged.

The action must be a YAML boolean, not a quoted string or a number. A rule
cannot combine `require_escalation: true` and `suppress: true`; the API rejects
that contradiction. Rules with the action set to `false`, disabled rules,
and nonmatching rules do not add a restriction. Preview uses the same
original-alert matching and conflict behavior as the worker.

### Wazuh rule identities

Scope an ID list to `connector_type: wazuh` so an identically numbered
detection from another source is not included. Inspect a fused alert before
choosing the ID field. In the current connector, Wazuh's rule ID is emitted as
`external_id`; ingest projects it to OCSF `finding.uid`, available to
business-context as `raw_event.finding.uid`. The top-level fused `rule_id`
must not be assumed to carry the Wazuh rule ID. A connector version that
changes its external finding identity needs its matching field verified
again.

This template is deliberately disabled. Replace the placeholder with the
verified, quoted Wazuh rule IDs, preview it against matching and nonmatching
alerts, then enable it. It does not contain a recommended or preconfigured
production ID list.

```yaml
rules:
  - id: wazuh-mandatory-review
    enabled: false
    when:
      all:
        - {field: connector_type, op: eq, value: wazuh}
        - field: raw_event.finding.uid
          op: in
          value: ["REPLACE_WITH_VERIFIED_RULE_ID"]
    then:
      set_severity: critical
      require_escalation: true
```

Saving this YAML through `/settings/business-context` or
`POST /v1/business-context/rules` replaces the tenant's whole rule set, so
retain its other rules in the document. Tenant rules are cached by the worker
for up to 30 seconds. A deployment-wide rules file applies to every tenant;
use the tenant-scoped editor for an environment-specific ID list.

Automatic closure remains default-deny. Do not enable a closure policy just
to use mandatory escalation. The feature requires both API and agents to
support the action; an older parser can ignore an unknown action. It applies
when the worker has loaded and matched the rule set: the existing loader is
fail-soft on a missing or invalid file, or a first database read failure.
Verify a real alert's matched rules after rollout. This action does not repair
connector polling or bring back alerts that never reached triage, and it
does not authorize a response action.

## Business impact, cited or absent

When one of your business-context rules fired on the alert, the prompt invites
the model to add one optional element to its verdict: a one-sentence
`business_impact` statement whose `citations` must name the rule ids that
fired. The same discipline as runbook citations, pointing the other way:

- A statement citing a rule that did not fire on this alert is dropped and
  counted (`business_impact_uncited`), never rendered.
- When no rule fired, the instruction is never injected — a model with no
  business context never sees the element's name, so it cannot be invited to
  invent an impact.
- The surviving statement appears in the Investigation Rail's **Business
  context** section, beside the rules that fired and the severity mutation
  they made. No rule fired means the section does not render — absence is
  honest absence, not a measurement of zero.

## Knowledge-base runbooks

AiSOC has held a knowledge base since runbook ingest shipped, and until this
release nothing in the agent read it. A SOC that had written down how it
handles a password-spray alert still got a verdict produced in ignorance of
that document.

### What is retrieved

For each alert, the agent builds a query from the alert summary and the rule
name, and asks the API for the best-matching chunks of your `runbook`,
`playbook` and `sop` documents. Policies and wiki pages are excluded: every
chunk in the prompt is budget the evidence does not get, and those kinds
rarely say what to do about an alert.

Retrieval is the same full-text search and the same ranking that `/kb/query`
runs for an analyst, so a chunk triage was given is a chunk you would have
found by searching for the same thing by hand.

Up to three chunks reach the prompt. Set `AISOC_TRIAGE_KB_TOP_K` to change
that, and `AISOC_TRIAGE_KB_ENABLED=0` to turn the source off entirely.

### Citations

Each chunk in the prompt carries a marker, `[KB1]`, `[KB2]`, `[KB3]`, and the
prompt asks the model to cite the marker when a runbook informs its reasoning.
The verdict's confidence basis then records, for each marker, the document id,
the title and which chunk of that document it was.

That last part is what makes a citation worth having. A marker exists so that
you can open the document and check whether it says what the model claimed, so
the record has to resolve to a chunk rather than to a document with forty of
them.

If a rationale cites a marker no retrieved chunk carries, the basis says so
explicitly. An invented `[KB7]` reads exactly like a citation that resolves,
and a reader would otherwise only discover the difference by going to look for
a seventh runbook.

### How runbook text is contained

Runbook text is treated as untrusted, and more carefully than a tenant skill
is. A skill is written by one person holding `settings:write`, into fields
that are individually parsed and capped. A knowledge-base article
is longer, is often imported in bulk from a wiki or a vendor advisory, is
edited by more people over more time, and reaches the prompt as prose. An
advisory pasted into a runbook routinely quotes attacker output verbatim,
which is exactly the shape an injected instruction hides in.

So a retrieved chunk gets the containment an MCP reply gets, in this order:

1. **Capped**, per chunk and across the block.
2. **Fenced** inside the run's cryptographic nonce, whose delimiter nobody
   could have known when the document was written, so fenced text cannot forge
   its own closing marker.
3. **Labelled inline**, beside the fence, saying that what follows is data
   from a document rather than an instruction. The standing system rule says
   this once per run; a retrieved document can sit many turns away from it.
4. **Scanned** by the prompt-injection guard. A chunk the guard calls high
   severity is dropped and never reaches the prompt.

The order matters and the obvious order is wrong. The scan runs on the text as
stored, before sanitising, because the sanitiser rewrites the loudest payloads
to a redaction marker and a guard run afterwards would see a clean string.

Be clear about how much the fourth step is worth. Against 28 payloads authored
after the guard's last hardening it detects 2. It scores far better against
the corpus it was tuned on, but a document ingested last week is held-out data
by definition. The fence and the standing rule are what hold when the guard
misses; the scan is what makes a miss visible afterwards.

A flagged chunk is dropped rather than demoting the alert to manual review.
Auto-triage does demote a case when the *alert's own evidence* looks like an
injection attempt, because that evidence is what the verdict rests on. A
poisoned library document is not evidence about this alert, and demoting on
one would hand anybody who can write a runbook a way to switch off auto-close
across the whole tenant. Refusing the chunk costs the model some guidance and
costs you nothing else, and the count of refusals is published on the verdict
and as the `runbooks_refused_for_injection` metric so a poisoned library is
something you find out about.

## Freezing context for a replay

[Replay evaluation](../evaluation/replay.md) measures AiSOC against your
analysts' own past decisions. That number only means something if the agent
judging an alert from last May could not see anything recorded after last May.
There are two ways AiSOC holds a source still, and which one applies depends
on how big the source is.

**Captured.** Organisation memory, outcome priors and tenant skills are small
enough to read once, before the test window is replayed. Rows recorded after
the split are dropped from the captured set, and the report's method section
publishes how many were kept, how many were dropped, and how many carried no
timestamp to test.

**Cut off.** The knowledge base is queried per alert against a corpus that can
hold every document you have ever written, so there is nothing sensible to
capture up front. Instead the replay passes the split instant to the API,
which refuses any chunk created after it, and reports how many it refused. The
report publishes the same three figures under `cutoff_context`.

The refused count is the part that makes the claim checkable. A cutoff that
matched nothing and a cutoff that threw away fifty documents return the same
empty list, so without the count you could not tell a working freeze from an
inert one.

A runbook is usually written *after* the incident that prompted it, which
makes this the most natural way a replay could flatter itself: a document that
describes the answer to the alerts being graded. It is also why the freeze is
tested with a sensitivity half that runs the unprotected configuration and
asserts it does leak.

If the API ever answers without naming the instant it cut off at, the replay
records `runbooks_cutoff_not_honoured` rather than counting those rows as
frozen. A store that ignores the parameter returns a perfectly well-formed
reply, so the echo is the only evidence, and its absence has to be reported
rather than rounded down to a clean read.
