#!/usr/bin/env bash
# Disposable datastore upgrade rehearsal — never touches named production volumes.
# Run from repo root: bash scripts/upgrade_rehearsal_disposable.sh 2>&1 | tee /tmp/upgrade-rehearsal.log
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/aisoc-upgrade-rehearsal-$$"
mkdir -p "$WORK"
LOG="$WORK/summary.jsonl"
touch "$LOG"

log() { echo "$1" | tee -a "$LOG"; }

need() {
  command -v "$1" >/dev/null || { log "BLOCKER: $1 not found"; exit 2; }
}

need docker

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    log "BLOCKER: docker daemon not reachable"
    exit 2
  fi
fi

CH_NEW="clickhouse/clickhouse-server:26.8"
CH_OLD="clickhouse/clickhouse-server:23.8"
CH_VOL="$WORK/ch_data"
CH_BACKUP="$WORK/ch_backup"
CH_BK_CFG="$ROOT/docs/upgrade/disposable-clickhouse-backups.xml"
mkdir -p "$CH_VOL" "$CH_BACKUP"
mkdir -p "$CH_VOL/backups"

log "=== ClickHouse staged backup/restore (23.8 -> 26.8 -> restore on fresh 23.8 vol) ==="

"${DOCKER[@]}" rm -f aisoc-ch-rehearsal-old aisoc-ch-rehearsal-new aisoc-ch-rehearsal-rb 2>/dev/null || true

"${DOCKER[@]}" run -d --name aisoc-ch-rehearsal-old \
  -v "$CH_VOL:/var/lib/clickhouse" \
  -v "$ROOT/services/api/clickhouse:/docker-entrypoint-initdb.d:ro" \
  -v "$CH_BK_CFG:/etc/clickhouse-server/config.d/backups.xml:ro" \
  "$CH_OLD" >/dev/null

for i in $(seq 1 60); do
  if "${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q "SELECT 1" 2>/dev/null; then break; fi
  sleep 2
done

"${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q \
  "CREATE TABLE IF NOT EXISTS aisoc.probe (n UInt8) ENGINE=MergeTree ORDER BY n"
"${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q "TRUNCATE TABLE IF EXISTS aisoc.probe"
"${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q "INSERT INTO aisoc.probe VALUES (42)"
CHK=$("${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q "SELECT sum(n), count() FROM aisoc.probe")
log "CH23.8 seeded checksum: sum_n=$CHK"

"${DOCKER[@]}" exec aisoc-ch-rehearsal-old clickhouse-client -q \
  "BACKUP DATABASE aisoc TO File('/var/lib/clickhouse/backups/aisoc_pre_upgrade')"

"${DOCKER[@]}" stop aisoc-ch-rehearsal-old >/dev/null

"${DOCKER[@]}" run -d --name aisoc-ch-rehearsal-new \
  -v "$CH_VOL:/var/lib/clickhouse" \
  "$CH_NEW" >/dev/null
for i in $(seq 1 90); do
  if "${DOCKER[@]}" exec aisoc-ch-rehearsal-new clickhouse-client -q "SELECT 1" 2>/dev/null; then break; fi
  sleep 2
done
UP=$("${DOCKER[@]}" exec aisoc-ch-rehearsal-new clickhouse-client -q "SELECT sum(n), count() FROM aisoc.probe" 2>/dev/null || echo FAIL)
log "CH26.8 in-place upgrade read: $UP"

# Restore path: fresh volume + backup (when BACKUP DATABASE succeeded)
CH_VOL2="$WORK/ch_data_fresh"
mkdir -p "$CH_VOL2" "$CH_BACKUP"
"${DOCKER[@]}" stop aisoc-ch-rehearsal-new 2>/dev/null || true

if [[ -d "$CH_VOL/backups/aisoc_pre_upgrade" ]]; then
  chmod -R a+rX "$CH_VOL/backups" 2>/dev/null || sudo chmod -R a+rX "$CH_VOL/backups" 2>/dev/null || true
  mkdir -p "$CH_VOL2/backups"
  cp -a "$CH_VOL/backups/." "$CH_VOL2/backups/" 2>/dev/null || true
  "${DOCKER[@]}" run -d --name aisoc-ch-rehearsal-rb \
    -v "$CH_VOL2:/var/lib/clickhouse" \
    -v "$CH_BK_CFG:/etc/clickhouse-server/config.d/backups.xml:ro" \
    "$CH_OLD" >/dev/null
  for i in $(seq 1 60); do
    if "${DOCKER[@]}" exec aisoc-ch-rehearsal-rb clickhouse-client -q "SELECT 1" 2>/dev/null; then break; fi
    sleep 2
  done
  if "${DOCKER[@]}" exec aisoc-ch-rehearsal-rb clickhouse-client -q \
    "RESTORE DATABASE aisoc FROM File('/var/lib/clickhouse/backups/aisoc_pre_upgrade')" 2>/dev/null; then
    RB=$("${DOCKER[@]}" exec aisoc-ch-rehearsal-rb clickhouse-client -q "SELECT sum(n), count() FROM aisoc.probe")
    log "CH23.8 restore verification: $RB"
  else
    log "CH restore: RESTORE failed (note exact ClickHouse BACKUP/RESTORE edition requirements)"
  fi
else
  log "CH restore: skipped — no backup artifact (use clickhouse-backup or object storage in operator runbook)"
fi

log "=== Qdrant v1.7.0 -> v1.20.0 ==="
QD_VOL="$WORK/qdrant_data"
mkdir -p "$QD_VOL"
"${DOCKER[@]}" rm -f aisoc-qdrant-r1 aisoc-qdrant-r2 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-qdrant-r1 -p 16333:6333 -v "$QD_VOL:/qdrant/storage" qdrant/qdrant:v1.7.0
sleep 5
POINT='{"points":[{"id":1,"vector":[0.1,0.2,0.3,0.4],"payload":{"tenant":"t1"}}]}'
curl -fsS -X PUT "http://127.0.0.1:16333/collections/probe" \
  -H 'Content-Type: application/json' \
  -d '{"vectors":{"size":4,"distance":"Cosine"}}' >/dev/null || true
curl -fsS -X PUT "http://127.0.0.1:16333/collections/probe/points" \
  -H 'Content-Type: application/json' \
  -d "$POINT" >/dev/null
SNAP=$(curl -fsS -X POST "http://127.0.0.1:16333/collections/probe/snapshots" 2>/dev/null | head -c 200 || echo none)
log "Qdrant v1.7 snapshot: $SNAP"
"${DOCKER[@]}" stop aisoc-qdrant-r1 >/dev/null
"${DOCKER[@]}" run -d --name aisoc-qdrant-r2 -p 16334:6333 -v "$QD_VOL:/qdrant/storage" qdrant/qdrant:v1.20.0
sleep 5
SEARCH=$(curl -fsS -X POST "http://127.0.0.1:16334/collections/probe/points/search" \
  -H 'Content-Type: application/json' \
  -d '{"vector":[0.1,0.2,0.3,0.4],"limit":1}' 2>/dev/null | head -c 300 || echo FAIL)
log "Qdrant v1.20 search: $SEARCH"

log "=== Kafka/ZK 7.5.0 -> 7.8.12 (paired volumes) ==="
KZK_VOL="$WORK/kafka_zk"
mkdir -p "$KZK_VOL/zk-data" "$KZK_VOL/zk-log" "$KZK_VOL/kafka"
"${DOCKER[@]}" rm -f aisoc-zk-r aisoc-kafka-r 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-zk-r \
  -e ZOOKEEPER_CLIENT_PORT=2181 \
  -v "$KZK_VOL/zk-data:/var/lib/zookeeper/data" \
  -v "$KZK_VOL/zk-log:/var/lib/zookeeper/log" \
  confluentinc/cp-zookeeper:7.5.0
sleep 8
"${DOCKER[@]}" run -d --name aisoc-kafka-r \
  --link aisoc-zk-r:zookeeper \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:19092 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -v "$KZK_VOL/kafka:/var/lib/kafka/data" \
  confluentinc/cp-kafka:7.5.0
sleep 15
echo "probe-msg" | "${DOCKER[@]}" exec -i aisoc-kafka-r kafka-console-producer \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null || \
  log "Kafka seed: producer failed (check broker readiness)"
OFF1=$("${DOCKER[@]}" exec aisoc-kafka-r kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null | head -3 || echo none)
log "Kafka 7.5 offsets before: $OFF1"
"${DOCKER[@]}" stop aisoc-kafka-r aisoc-zk-r >/dev/null
"${DOCKER[@]}" run -d --name aisoc-zk-r2 \
  -e ZOOKEEPER_CLIENT_PORT=2181 \
  -v "$KZK_VOL/zk-data:/var/lib/zookeeper/data" \
  -v "$KZK_VOL/zk-log:/var/lib/zookeeper/log" \
  confluentinc/cp-zookeeper:7.8.12
sleep 8
"${DOCKER[@]}" run -d --name aisoc-kafka-r2 \
  --link aisoc-zk-r2:zookeeper \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:19092 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -v "$KZK_VOL/kafka:/var/lib/kafka/data" \
  confluentinc/cp-kafka:7.8.12
sleep 20
CONS=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-console-consumer \
  --bootstrap-server localhost:9092 --topic aisoc-probe --from-beginning --timeout-ms 5000 --max-messages 1 2>/dev/null || echo FAIL)
log "Kafka 7.8 consume: $CONS"

log "=== OpenSearch 2.11.0 -> 2.19.7 ==="
OS_VOL="$WORK/opensearch"
mkdir -p "$OS_VOL"
"${DOCKER[@]}" rm -f aisoc-os-r1 aisoc-os-r2 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-os-r1 \
  -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  -v "$OS_VOL:/usr/share/opensearch/data" \
  -p 19200:9200 opensearchproject/opensearch:2.11.0
sleep 45
curl -fsS -X PUT "http://127.0.0.1:19200/aisoc-probe" -H 'Content-Type: application/json' \
  -d '{"settings":{"index.number_of_shards":1},"mappings":{"properties":{"n":{"type":"integer"}}}}' >/dev/null || true
curl -fsS -X POST "http://127.0.0.1:19200/aisoc-probe/_doc" -H 'Content-Type: application/json' \
  -d '{"n":7}' >/dev/null || true
curl -fsS "http://127.0.0.1:19200/aisoc-probe/_search?q=n:7" | head -c 200 | tee -a "$LOG" || true
"${DOCKER[@]}" stop aisoc-os-r1 >/dev/null
sleep 5
"${DOCKER[@]}" run -d --name aisoc-os-r2 \
  -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  -v "$OS_VOL:/usr/share/opensearch/data" \
  -p 19201:9200 opensearchproject/opensearch:2.19.7
sleep 60
OS2=$(curl -fsS "http://127.0.0.1:19201/aisoc-probe/_count" 2>/dev/null || echo FAIL)
log "OpenSearch 2.19.7 doc count: $OS2"

log "=== Monitoring stack config load (Prometheus 3 / Grafana 13 / OTel 0.121) ==="
MON="$WORK/monitoring"
mkdir -p "$MON/grafana" "$MON/prom"
"${DOCKER[@]}" rm -f aisoc-prom-r aisoc-graf-r aisoc-otel-r 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-prom-r \
  -v "$ROOT/infra/docker/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  -p 19090:9090 prom/prometheus:v3.13.5
sleep 5
PROM=$("${DOCKER[@]}" exec aisoc-prom-r wget -qO- http://localhost:9090/-/healthy 2>/dev/null || echo FAIL)
log "Prometheus healthy: $PROM"
"${DOCKER[@]}" run -d --name aisoc-graf-r \
  -v "$ROOT/infra/docker/grafana:/etc/grafana/provisioning:ro" \
  -p 13000:3000 grafana/grafana:13.3.1
sleep 10
GRAF=$("${DOCKER[@]}" exec aisoc-graf-r wget -qO- http://localhost:3000/api/health 2>/dev/null | head -c 120 || echo FAIL)
log "Grafana health: $GRAF"
"${DOCKER[@]}" run -d --name aisoc-otel-r \
  -v "$ROOT/infra/docker/otel/collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  otel/opentelemetry-collector-contrib:0.121.0 2>/dev/null || \
  log "OTel: config mount path may differ — check container logs"

log "WORK_DIR=$WORK"
log "DONE"
