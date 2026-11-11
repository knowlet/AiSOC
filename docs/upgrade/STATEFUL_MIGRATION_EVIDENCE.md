# Stateful migration rehearsal (disposable only)

Evidence from **non-production** exercises on **2026-11-11** using `sudo docker` on the
cloud-agent VM. Script: [`scripts/upgrade_rehearsal_disposable.sh`](../../scripts/upgrade_rehearsal_disposable.sh).
Raw logs: `/opt/cursor/artifacts/upgrade-rehearsal-v3.log` (partial), ClickHouse restore
transcript below.

## Go / no-go summary

| Store | Jump tested | In-place volume upgrade | Backup → restore verified | Deploy stance |
|-------|-------------|-------------------------|---------------------------|---------------|
| ClickHouse 23.8 → **26.8** | Yes | **Yes** (`sum(n)=42`, `count=1` after upgrade) | **Yes** (`BACKUP DATABASE` + `RESTORE` on **fresh** 23.8 volume → `42 1`) | **Conditional GO** — backup path required; downgrade without restore **no** |
| Qdrant **v1.7.0** → **v1.20.0** | Yes | **No** — v1.20 panics loading v1.7 segments (`unknown variant on_disk`) | Snapshot created on v1.7; **not** re-loaded on v1.20 in this run | **NO-GO** for raw volume jump; use **snapshot / reindex** per [Qdrant upgrades](https://qdrant.tech/documentation/guides/version-upgrade/) |
| Kafka **7.5.0** → **7.8.12** (ZK paired) | Partial | Consumer from host **failed** (advertised listeners); not a format proof | N/A | **Rehearse in CI** `Upgrade test` / operator lab before GO |
| OpenSearch **2.11.0** → **2.19.7** | Script bug (Java opts quoting) fixed on branch; **not re-run to completion** | Not measured | N/A | **NO-GO** until index-level rehearsal completes |
| Prometheus **v3.13.5** | N/A | Config load: `/-/healthy` **OK** | N/A | **GO** for scrape config mount |
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

## Qdrant v1.7.0 → v1.20.0 (in-place **rejected**)

- v1.7: collection `probe` created, point inserted, **snapshot OK**.
- v1.20 on **same** `qdrant_data`: container **exit 101**, log:
  `unknown variant on_disk, expected mmap or in_ram_mmap` in `segment.json`.

**Implication:** Compose jump from legacy **v1.7.0** disks to **v1.20.0** is **not** deployable
without migration tooling. Staged path: intermediate versions and/or snapshot export-import
documented by Qdrant — **not** exercised end-to-end in this run.

---

## Kafka / Zookeeper 7.5 → 7.8.12

- Images pulled and paired volumes started (see rehearsal log).
- Host-side `kafka-console-consumer` → **FAIL** (listener/advertised address mismatch in disposable script).
- **Does not** disprove broker log compatibility; **does** mean this agent run did not prove
  offset retention across the bump. Treat as **open** until CI upgrade job or fixed script passes.

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
| `ruff` `ignore = UP040, UP047` with `target-version = "py313"` | Enabling UP047 triggered mypy `valid-type` regressions; UP043 (`AsyncGenerator` defaults) applied; PEP 695 generic syntax deferred until baseline refresh |
| Dependabot ignores (TS 7 / ESLint 10) | Unchanged — no compatibility proof in this PR |
| `packages/sdk-py` `requires-python >=3.10` | Wider SDK floor for downstream; services at `^3.13` |

---

## Local test matrix (Python 3.13, locked venvs)

| Service suite | Result |
|---------------|--------|
| `actions` | **2119 passed**, 10 skipped |
| `agents` | **2574 passed**, 20 skipped, 219 subtests |
| `api` | **In progress** at capture (large lock install) |
| `mesh` | **11 passed** (spot check) |

Full CI service matrix still **skipped** on run `42990522391` because **Python — Lint & Type-check** failed on ruff UP047 (fixed on branch, not yet on that SHA).
