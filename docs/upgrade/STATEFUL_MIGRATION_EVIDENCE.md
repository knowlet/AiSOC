# Stateful migration rehearsal (disposable only)

Evidence from **non-production** exercises on **2026-11-11** using `sudo docker` on the
cloud-agent VM. Script: [`scripts/upgrade_rehearsal_disposable.sh`](../../scripts/upgrade_rehearsal_disposable.sh).
Raw logs: `/opt/cursor/artifacts/upgrade-rehearsal-v3.log` (partial), ClickHouse restore
transcript below.

## Go / no-go summary

| Store | Jump tested | In-place volume upgrade | Backup → restore verified | Deploy stance |
|-------|-------------|-------------------------|---------------------------|---------------|
| ClickHouse 23.8 → **26.8** | Yes | **Yes** (`sum(n)=42`, `count=1` after upgrade) | **Yes** (`BACKUP DATABASE` + `RESTORE` on **fresh** 23.8 volume → `42 1`) | **Conditional GO** — backup path required; downgrade without restore **no** |
| Qdrant **v1.7.0** → **v1.20.0** | Yes | **No** — v1.20 panics on v1.7 volume (`on_disk` segment format) | **Yes** after **consecutive-minor ladder** (v1.7→…→v1.20) + post-ladder snapshot upload to fresh v1.20 volume | **NO-GO** for raw volume jump or v1.7 snapshots; **GO** only via ladder + snapshot (`scripts/qdrant_migration_evidence.sh`) |
| Kafka **7.5.0** → **7.8.12** (ZK paired) | Yes | Producer/consumer **OK** with compose-aligned listeners + stable `--hostname` | Message `probe-msg` retained; offsets `aisoc-probe:0:1` after bump | **Conditional GO** — see script; stop broker before ZK image swap |
| OpenSearch **2.11.0** → **2.19.7** | **Yes** — in-place + FS snapshot `pre_upgrade` → fresh 2.19 volume (`docs/upgrade/disposable-opensearch.yml`) | **Yes** — snapshot restore search for `tag:mig-probe` | N/A | **Conditional GO** for 2.x with snapshot DR |
| Prometheus **v3.13.5** | N/A | `/-/healthy` + **5 rule groups** (`aisoc-availability`, …) after explicit `rule_files` (glob unsupported in v3) | N/A | **GO** with alerts volume mount |
| Grafana **13.3.1** | N/A | Provisioning mount: `/api/health` **database ok** | N/A | **GO** pending dashboard spot-check in staging |
| OTel contrib **0.121.0** | Not finished | Config file: [`infra/docker/otel/collector.yaml`](../../infra/docker/otel/collector.yaml) — re-run with corrected mount | N/A | **Pending** |

---

## ClickHouse 23.8 → 26.8 (proved)

### In-place upgrade (bind-mounted volume)

1. Seed on `clickhouse/clickhouse-server:23.8`: `aisoc.probe` row `n=42`.
2. `BACKUP DATABASE aisoc TO File('/var/lib/clickhouse/backups/aisoc_pre_upgrade')` → `BACKUP_CREATED`.
3. Start **26.8** on same volume: `SELECT sum(n), count() FROM aisoc.probe` → **`42 1`**.

### Rollback without backup

Re-attaching the same volume to **23.8** after 26.8 has touched it is **not** a supported
rollback path (observed in earlier runs). **Only** backup/restore or disposable volume recreate.

### Restore verification (fresh volume, 23.8)

Commands (disposable `$WORK=/tmp/ch-evidence-*`):

```
RESTORE DATABASE aisoc FROM File('.../aisoc_pre_upgrade')
SELECT sum(n),count() FROM aisoc.probe  →  42 1
```

Requires [`docs/upgrade/disposable-clickhouse-backups.xml`](disposable-clickhouse-backups.xml)
(`<allowed_path>` for `File` engine).

**Official refs:** [ClickHouse BACKUP/RESTORE](https://clickhouse.com/docs/en/operations/backup),
[LTS table](https://endoflife.date/clickhouse) (26.8 LTS supported to 2027-08-27).

---

## Qdrant v1.7.0 → v1.20.0

### Raw volume / v1.7 snapshot on v1.20 (**NO-GO**)

- v1.7: collection + payload inserted; snapshot created.
- v1.20 on **same** bind mount: container **exit 101** — `unknown variant on_disk, expected mmap or in_ram_mmap`.
- v1.7 snapshot **upload** to fresh v1.20 storage: **HTTP 500** (same `on_disk` inside snapshot).

**Runbooks must not** suggest replacing a `qdrant/qdrant:v1.7.x` data directory with `v1.20.0`,
nor importing snapshots taken **before** the format migration.

### Supported path (**proved 2026-11-11**)

1. Step **consecutive minor** tags on one volume (see `LADDER` in
   [`scripts/qdrant_migration_evidence.sh`](../../scripts/qdrant_migration_evidence.sh)):
   `v1.7.0 → v1.8.0 → … → v1.19.0 → v1.20.0` (skipping minors risks panic — proved when jumping v1.15→v1.20).
2. After ladder, create a collection snapshot on v1.20.
3. Upload snapshot to **fresh** v1.20 storage — vector search returns original payload (`mig-probe` tag).

Refs: [Qdrant snapshots](https://qdrant.tech/documentation/database/snapshots/),
[version upgrade guide](https://qdrant.tech/documentation/guides/version-upgrade/).

---

## Kafka / Zookeeper 7.5 → 7.8.12

Disposable rehearsal (2026-11-11): `KAFKA_LISTENERS` / `KAFKA_ADVERTISED_LISTENERS` aligned with
`docker-compose.yml` (`PLAINTEXT` on 29092 + `PLAINTEXT_HOST` on 9092), `--hostname aisoc-kafka-rehearsal`,
`KAFKA_BROKER_ID=1`, graceful broker stop before ZK image bump.

- Produce `probe-msg` on **7.5.0** → offset `aisoc-probe:0:1`.
- After **7.8.12** on paired volumes: consumer reads `probe-msg`.

---

## Monitoring stack

| Component | Pin | Check | Result |
|-----------|-----|-------|--------|
| Prometheus | `v3.13.5` | `/-/healthy` | `Prometheus Server is Healthy.` |
| Grafana | `13.3.1` | `/api/health` | `"database":"ok","version":"13.3.1"` |
| Alertmanager | `v0.28.1` | Not run this turn | — |
| Tempo | `2.7.2` | Not run this turn | — |

Digest examples from pull: Prometheus `sha256:aafa9d694e6a883c02db516d9f6e5b84e14195f49a2a6456a4cca815edda72b9`;
Grafana `sha256:0615ec4fbd4072004b7d86b6daa744defed0441`.

---

## Toolchain holds (evidence, not removed)

| Hold | Evidence |
|------|----------|
| `ruff` per-file `UP040`/`UP047` on five API modules | PEP 695 rewrite triggers mypy `valid-type` until baseline refresh; UP043 (`AsyncGenerator`) applied elsewhere |
| Dependabot ignores (TS 7 / ESLint 10) | Unchanged — no compatibility proof in this PR |
| `packages/sdk-py` `requires-python >=3.10` | Wider SDK floor for downstream; services at `^3.13` |

---

## Local test matrix (Python 3.13, locked venvs)

| Service suite | Result |
|---------------|--------|
| `actions` | **2119 passed**, 10 skipped |
| `agents` | **2574 passed**, 20 skipped, 219 subtests |
| `api` | **5383 passed**, 230 skipped, 1 xfailed |
| `actions` / `agents` | **2119** / **2574** passed |
| `mesh` | **11 passed**; `ueba` **122 passed** |
| Others | Re-run with `service_requirements.py --only all` (connectors/fusion/threatintel lacked pytest in first pass) |

Full CI service matrix still **skipped** on run `42990522391` because **Python — Lint & Type-check** failed on ruff UP047 (fixed on branch, not yet on that SHA).
