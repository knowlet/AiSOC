# Deterministic escalation from business-context rules

## Evidence and scope

Reviewed on 2026-11-04 against commit
`8a280520ccf18826c68b31c07adef6b1fae57622`.

The API authoring engine and the agents worker both support severity, routing,
tags and suppression. They do not express a mandatory escalation. A
`set_severity: critical` action changes alert evidence; it does not authorize
or prohibit an automatic closure. The closure policy already defaults to
denial, and `persist_auto_triage` checks that policy before resolving an alert.
Those protections are retained.

Relevant existing components:

- `services/api/app/services/business_context/models.py` and `engine.py`:
  parsed YAML actions, deterministic evaluation, and preview.
- `services/agents/app/workers/business_context.py`: tenant-scoped live rules
  and deployment-file rules.
- `services/agents/app/workers/fused_alert_consumer.py`: applies rules before
  memory suppression and triage.
- `services/agents/app/agents/auto_triage_agent.py`: model verdict and
  automatic-closure precheck.
- `services/agents/app/closure/authorization.py` and
  `services/agents/app/investigator/ledger.py`: authorization at the write.

An external Apache-2.0 executor was also inspected at commit
`ad7d50f94fea29c4f12700f907edbde414fb7234`: its guard ranks dispositions and
its terminal floor vetoes closure. Only the design principle is used here:
an enforced restriction can remove permission to close, never grant it.
No external code or dependency is incorporated. The implementation extends
AiSOC's existing MIT-licensed rule engines and closure authorization.

## Decision

Add an explicit boolean action, `require_escalation`, rather than redefining
every vendor's critical severity as a closure prohibition. A matching
mandatory rule is evaluated against the original alert so an earlier
suppression or severity rewrite cannot hide its match. Its escalation
requirement is monotonic, and any severity it specifies is a floor. Ordinary
rules retain their existing order and behavior when no mandatory rule matches.
The authoring preview and the live worker must agree.

Rules with both `suppress: true` and `require_escalation: true` are invalid.
The new action accepts a real YAML boolean only. An alert payload cannot
declare that a trusted rule matched; the evaluator derives that evidence.

The worker carries the matched rule identities into triage and the ledger.
Memory reuse and a model's benign verdict must not terminate the required
escalation. The durable closure check also refuses a closure carrying that
requirement. A required review does not assert that the alert is malicious,
and does not authorize a response action.

## Configuration boundary

The requested tenant-specific set of 17 vendor rule IDs was not present in the
request or the inspected repository/history evidence. No production ID list
is inferred from an ID range or from unrelated examples. Rules must be scoped
to the intended connector and use the vendor rule identity actually present in the fused
payload, not an unrelated internal detection identifier or document ID.

This change does not modify a running tenant, enable automatic closure, or
deploy a new rule set. API and agents must both support the new action before
an operator uses it; an older parser may ignore an unknown action.

## Validation plan

- Reproduce the missing enforcement through the worker, using a permissive
  closure policy and a benign model result so the default denial cannot hide
  the defect.
- Test rule conflicts, disabled/nonmatching rules, strict booleans, tenant
  isolation, and API serialization/preview parity.
- Check the durable refusal with a real database where available.
- Run the relevant service tests with Python 3.11 and each service's lockfile.
- Compare the repository's offline eval report before and after the change.
- Remove the fix in an isolated negative-control checkout and require the new
  regression cases to fail again.

## Local validation

The new worker regression has six parameter cases: three matching mandatory
rules and three nonmatching controls. On the base implementation, the three
matching cases incorrectly reach persistence with `auto_closed=True`; the
three controls pass. The cached configuration is intercepted by the real
memory-suppression shortcut before it can use the cache. The fixed worker
skips that shortcut and reaches the cached path. Repeating the tests against
an isolated base archive reproduces all three failures. The complete new
agents test file passes 22 cases.

The API regression adds 24 cases. They fail against the base implementation
and pass with the fix; the related API suites pass 102 cases in total.
The full agents suite passes 2,508 cases with the change and 2,486 on the
base commit, with the same 19 skips and three failures in both runs. Those
failures require DNS resolution of `example.com`, unavailable in the local
environment. The offline runner removes incompatible proxy environment
settings and refuses non-loopback socket connections; service dependencies
remain exactly as locked.

The offline eval harness passes all 11 suites before and after. Its calibration
fixture uses Python's randomized `hash()`, so the comparison was repeated
with `PYTHONHASHSEED=0` in separate complete base and modified worktrees.
All suite metrics then match, excluding execution durations. This harness
uses synthetic deterministic fixtures; it does not measure a deployed model
or a live connector installation.

The current local environment has no Docker or PostgreSQL executable. Five
new live database cases are collected by the existing closure-authorization
suite and its existing CI workflow. They cover saved tenant rules, the actual
worker, an otherwise permissive closure policy, three closure tiers, durable
severity and tenant separation. Database and full-stack checks require a
separately available runner and are not local passes.
