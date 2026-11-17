# Copilot queue transport test

This harness starts the production API and agents ASGI applications on loopback,
then submits authenticated Copilot chat requests. The selected tools call the
real API over HTTP, query real PostgreSQL tables, and persist conversations. A
local OpenAI-compatible HTTP endpoint chooses deterministic tool calls and
answers; this verifies the application transport and evidence handling, not a
model's investigation quality.

Use separate environments installed from each service's locked requirements.
Provide a freshly migrated, disposable PostgreSQL database. The application role
must be a non-superuser with `NOBYPASSRLS`; the migration connection inserts
synthetic test fixtures. The harness refuses to run without an explicit
`--disposable-database` flag. It never contacts a paid model provider.

```bash
export DATABASE_URL='postgresql+asyncpg://aisoc_app:password@127.0.0.1:5432/copilot_test'
export DATABASE_MIGRATION_URL='postgresql+asyncpg://migration_owner:password@127.0.0.1:5432/copilot_test'
export SECRET_KEY='a-test-only-signing-secret-with-at-least-32-characters'
services/api/.venv/bin/python tests/e2e/copilot_queues/run_copilot_queues.py \
  --agents-python services/agents/.venv/bin/python \
  --disposable-database
```

The checks cover literal case search, status/severity filtering, pending and
personal approvals, tenant isolation, case permission denial versus empty
results, citations through JSON and NDJSON chat, conversation persistence,
bounded pagination, and unchanged case/approval/action state. HTTP traces also
verify that the Copilot's API calls are bounded GET requests.

Unrelated background workers and external corpus loading are omitted by running
with ASGI lifespan disabled. The agents service's production session-revocation
check is registered explicitly, and both services retain their production
authentication and authorization dependencies. This is a focused transport test,
not the full ingest/fusion smoke test.

For a negative control, point `--repo` at a clean checkout before the queue tools
and case query were added, while running this same harness against a new test
database. It must fail because the model request does not advertise
`copilot_cases`; a passing baseline is not evidence for this feature.
