# Stateful migration rehearsal (disposable volumes only)

Evidence from **non-production** upgrade exercises run on 2026-11-11 in a
cloud-agent VM with `sudo docker`. No operator volumes or remote clusters were
touched.

## ClickHouse 23.8 → 26.8

| Step | Image | Result |
|------|-------|--------|
| Seed | `clickhouse/clickhouse-server:23.8` | Created DB `aisoc`, table `probe`, row `(1)` |
| Upgrade | `clickhouse/clickhouse-server:26.8` (same bind-mounted volume) | `SELECT * FROM aisoc.probe` → **1** |
| Rollback | `clickhouse/clickhouse-server:23.8` (same volume after 26.8) | Container failed to become queryable; **downgrade not supported without backup restore** |

**Deploy stance:** Jumping production `clickhouse_data` from 23.x/24.x to **26.8**
is a proposal until your environment repeats this rehearsal (or uses ClickHouse
`BACKUP`/`RESTORE` per [ClickHouse docs](https://clickhouse.com/docs/en/operations/backup)).

**Version choice:** Compose pin `26.8` tracks the **LTS** line (supported until
2027-08-27 per [endoflife.date ClickHouse](https://endoflife.date/clickhouse),
latest patch 26.8.34.13 as of 2026-10-22). Newer 26.10 exists; 26.8 was chosen
for LTS support window, not “latest major”.

## OpenSearch 2.11 → 2.19.7

**Not exercised** on disk in this run (no disposable `opensearch_data` rehearsal).
Treat forward upgrade as **deploy after backup**; index-store format changes may
require reindex. Pin `2.19.7` is latest **2.x** patch per
[OpenSearch releases](https://github.com/opensearch-project/OpenSearch/releases)
(2026-10-20).

## Kafka / Zookeeper 7.5 → 7.8.12

**Not exercised** with retained `kafka_data` in this run. Tag `7.8.12` is the
current Confluent Platform 7.8 patch line (security release notes 2026-11-09:
[CP 7.8.12](https://docs.confluent.io/platform/current/release-notes/index.html)).

## Qdrant v1.7 → v1.20.0

**Not exercised** with a populated `qdrant_data` volume. Server pin matches
[Qdrant v1.20.0](https://github.com/qdrant/qdrant/releases) (2026-10-22).
Poetry locks refreshed under Python 3.13; validate `qdrant-client` against your
collections in staging.
