# Dependency and infrastructure modernization (2026-11-11)

Branch `cursor/dependency-modernization-110d` on **`knowlet/AiSOC`** (draft
PR #6). **No upstream merge / not production-ready** until CI and operator
rehearsal gaps below are closed.

Regenerate inventory:

```bash
python3 scripts/generate_dependency_inventory.py
python3 scripts/generate_dependency_inventory.py --check
```

Machine-readable: [`dependency-inventory.json`](dependency-inventory.json).
Stateful rehearsal log: [`STATEFUL_MIGRATION_EVIDENCE.md`](STATEFUL_MIGRATION_EVIDENCE.md).

---

## Official version sources (fetched 2026-11-11)

| Component | Selected pin | Source (date) | Rationale |
|-----------|--------------|---------------|-----------|
| ClickHouse | `clickhouse/clickhouse-server:26.8` | [endoflife.date/clickhouse](https://endoflife.date/clickhouse) (2026-10-30); [GitHub releases](https://github.com/ClickHouse/ClickHouse/releases) | **26.8 LTS** through 2027-08-27; not bleeding 26.10 |
| Confluent Kafka/ZK | `confluentinc/cp-kafka:7.8.12`, `cp-zookeeper:7.8.12` | [Confluent release notes](https://docs.confluent.io/platform/current/release-notes/index.html) (2026-11-09 security) | Stay on supported 7.8 patch, not 7.5/7.7 |
| OpenSearch | `opensearchproject/opensearch:2.19.7` | [OpenSearch releases](https://github.com/opensearch-project/OpenSearch/releases) (2026-10-20) | Latest **2.x**; 3.x is separate major |
| Qdrant | `qdrant/qdrant:v1.20.0` | [Qdrant releases](https://github.com/qdrant/qdrant/releases) (2026-10-22) | Server/client bump coordinated in Poetry locks |
| Neo4j | `neo4j:5.26.0-community` | [Neo4j releases](https://github.com/neo4j/neo4j/releases) | 5.x minor within community line |
| Prometheus | `prom/prometheus:v3.13.5` | [prometheus.io/download](https://prometheus.io/download/) (2026-11 LTS) | **3.x LTS**; 2.55.x EOL |
| Alertmanager | `prom/alertmanager:v0.28.1` | [Docker Hub prom/alertmanager](https://hub.docker.com/r/prom/alertmanager/tags) | Current 0.28 patch |
| Grafana | `grafana/grafana:13.3.1` | [Grafana download](https://grafana.com/grafana/download) / [GitHub](https://github.com/grafana/grafana/releases) (2026-11-10) | Security fixes; re-check provisioned dashboards |
| Tempo | `grafana/tempo:2.7.2` | [Docker Hub grafana/tempo](https://hub.docker.com/r/grafana/tempo/tags) | Observability profile |
| OTel Collector | `otel/opentelemetry-collector-contrib:0.121.0` | [Docker Hub otel contrib](https://hub.docker.com/r/otel/opentelemetry-collector-contrib/tags) | |
| Go service bases | `alpine:3.23` | [Alpine releases](https://alpinelinux.org/releases/) — 3.21 support ended ~2026-11-01 | ingest/enrichment static binaries |
| Python services | `python:3.13-slim` | [python.org](https://www.python.org/downloads/) — 3.13 security branch | Coordinated with CI + `mypy-unmanaged.toml` |
| Ollama | `ollama/ollama:0.40.16` | [GitHub releases](https://github.com/ollama/ollama/releases) (2026-11-09) | Contract tests updated; models not re-pulled in CI |
| LiteLLM | `ghcr.io/berriai/litellm:v1.108.5` | [LiteLLM releases](https://github.com/BerriAI/litellm/releases) (2026-11-10 LTS) | Airgap config comments synced |
| Kafka UI | `provectuslabs/kafka-ui:v0.7.2` | [Docker Hub](https://hub.docker.com/r/provectuslabs/kafka-ui/tags) | Stop `latest` float |

Unchanged (still appropriate):

| Component | Pin | Notes |
|-----------|-----|-------|
| PostgreSQL | `postgres:16-alpine` | App migrations unchanged |
| Redis | `redis:7-alpine` | Supported 7.x |

**Intentional holds** (still in repo policy, not removed):

| Hold | Where | Why |
|------|-------|-----|
| TypeScript 6 / ESLint 10 | `.github/dependabot.yml` ignores | Prior compatibility gate |
| pnpm 8.15.1 | `package.json` `packageManager` | Store + CI agreement |
| Helm KRaft Kafka `apache/kafka:3.9.1` | `infra/helm/aisoc/values.yaml` | Production chart path ≠ Confluent compose |

---

## Before → after (compose canonical)

| Component | Prior PR snapshot | This continuation |
|-----------|-------------------|-------------------|
| ClickHouse | 24.8 | **26.8** (LTS) |
| Kafka/ZK | 7.7.1 | **7.8.12** |
| OpenSearch | 2.19.0 | **2.19.7** |
| Qdrant | v1.12.5 | **v1.20.0** |
| Prometheus | v2.55.1 | **v3.13.5** (major) |
| Grafana | 11.5.2 | **13.3.1** (major) |
| Alpine (Go images) | 3.21 | **3.23** |
| Python (13 services + CI) | 3.11 | **3.13** |
| Ollama / LiteLLM | 0.6.7 / v1.102.1 | **0.40.16 / v1.108.5** |

---

## Application dependencies (this PR)

| Surface | Action |
|---------|--------|
| Poetry (`services/*`, `packages/*`) | All **14 service** `poetry.lock` files refreshed with **Python 3.13** (`poetry lock` on host 3.13.18) |
| pnpm | Not mass-bumped here; root lock unchanged unless CI requires |

### pnpm advisory: `deepmerge` (documented, not overridden)

| Field | Value |
|-------|--------|
| Severity | **low** (prototype pollution in `mergeObject`) |
| Advisory | `pnpm audit` — patched versions listed as `<0.0.0` (no fixed release on advisory) |
| Exposure | **dev-only**: `apps/web` via `@storybook/test-runner` → `jest` → `jest-config`; `apps/docs` via `@docusaurus/*` → `@svgr/webpack` → `deepmerge@4.3.1` |
| Runtime | Production web bundle does not ship Jest/Storybook test-runner paths |
| Mitigation | No bogus `pnpm.overrides` invented; re-audit when upstream publishes a fix; Storybook/Docusaurus bumps tracked separately |
| Go | `go 1.26` unchanged |

Run local audit: `python3 scripts/security_audit.py` (workflow also on push).

---

## Rollout / rollback

1. Backup Postgres and datastore volumes (`make doctor` + [`MIGRATION.md`](MIGRATION.md)).
2. Pull new tags; recreate or migrate stateful volumes per component table.
3. `make smoke` when Docker/resources allow.

**Rollback:** Git revert + `docker compose pull` old tags + **restore volumes** for
ClickHouse/OpenSearch/Kafka if forward upgrade mutated on-disk format (see evidence doc).

---

## Testing executed on this branch (agent VM, 2026-11-11)

| Check | Result |
|-------|--------|
| `ruff check` (inventory script) | Pass |
| `generate_dependency_inventory.py --self-test` / `--check` | Pass |
| `check_toolchain_pins.py` | Pass |
| `tests/test_toolchain_pin_gate.py` | **64 passed** |
| `check_mypy_baseline.py` (container **Python 3.13**) | Pass — baseline file still recorded on 3.11; script notes PEP 701 line split (~2 findings in `run_evals.py` only) |
| Poetry lock refresh | 14 service locks updated |
| ClickHouse 23.8→26.8 disposable volume | Pass query; rollback **failed** (documented) |
| `make smoke` / full Playwright / compose nightly | **Not run** in VM (resource/time); rely on CI push |
| Live paid LLM providers | **Not exercised**; fixture/airgap contracts only |

---

## Deployability (go / no-go)

Authoritative rehearsal table: [`STATEFUL_MIGRATION_EVIDENCE.md`](STATEFUL_MIGRATION_EVIDENCE.md).

| Area | Verdict |
|------|---------|
| ClickHouse 26.8 | **Conditional GO** — in-place upgrade + `BACKUP`/`RESTORE` proved; down-grade without restore **no** |
| Qdrant v1.20.0 | **NO-GO** raw v1.7 volume / v1.7 snapshots; **GO** via consecutive-minor ladder + post-migration snapshot (`qdrant_migration_evidence.sh`) |
| Kafka 7.8.12 | **Conditional GO** — paired-volume rehearsal with compose-aligned listeners |
| OpenSearch 2.19.7 | **Open** — index store not rehearsed |
| Python 3.13 toolchain | **GO** for locked unit suites exercised (actions/agents); full matrix pending green lint job |
| Grafana 13 / Prometheus 3 | **Conditional GO** — health + config mount only |

Draft PR **must not merge** until compose smoke, integration upgrade paths, and Qdrant migration plan are green in your environment.

## Remaining risks / open items

- **Mypy baseline file** still numerically from the 3.11 era — consider a deliberate baseline refresh on 3.13 in a follow-up commit (not hidden edits).
- **Grafana 13** / **Prometheus 3** dashboard and scrape validation under `infra/docker/`.
- **OpenSearch** index backup/restore still **open**; Qdrant + Kafka disposable paths documented in [`STATEFUL_MIGRATION_EVIDENCE.md`](STATEFUL_MIGRATION_EVIDENCE.md).
- **Fork Helm CI** may need release tags visible to `check_chart_version.py` (investigate if red on push).
- **sdk-py** keeps wider `requires-python >=3.10` for downstream consumers — intentional.
