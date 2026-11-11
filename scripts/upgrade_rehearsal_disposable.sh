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
KAFKA_LISTENER_COMMON=(
  -e KAFKA_BROKER_ID=1
  -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=true
  -e KAFKA_DEFAULT_REPLICATION_FACTOR=1
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
  -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:29092,PLAINTEXT_HOST://0.0.0.0:9092
  # Stable hostname across the image bump so log dirs + ZK broker entries match.
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://aisoc-kafka-rehearsal:29092,PLAINTEXT_HOST://127.0.0.1:9092
  -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT
)
"${DOCKER[@]}" run -d --name aisoc-kafka-r \
  --hostname aisoc-kafka-rehearsal \
  --link aisoc-zk-r:zookeeper \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  "${KAFKA_LISTENER_COMMON[@]}" \
  -v "$KZK_VOL/kafka:/var/lib/kafka/data" \
  confluentinc/cp-kafka:7.5.0
sleep 20
"${DOCKER[@]}" exec aisoc-kafka-r kafka-topics --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic aisoc-probe --partitions 1 --replication-factor 1 \
  >/dev/null 2>&1 || true
echo "probe-msg" | "${DOCKER[@]}" exec -i aisoc-kafka-r kafka-console-producer \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null || \
  log "Kafka seed: producer failed (check broker readiness)"
OFF1=$("${DOCKER[@]}" exec aisoc-kafka-r kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null | head -3 || echo none)
log "Kafka 7.5 offsets before: $OFF1"
# Commit consumer-group offsets before the image bump.
"${DOCKER[@]}" exec aisoc-kafka-r kafka-console-consumer \
  --bootstrap-server localhost:9092 --topic aisoc-probe \
  --group aisoc-rehearsal --from-beginning --timeout-ms 8000 --max-messages 1 \
  >/dev/null 2>&1 || true
CG1=$("${DOCKER[@]}" exec aisoc-kafka-r kafka-consumer-groups \
  --bootstrap-server localhost:9092 --describe --group aisoc-rehearsal 2>/dev/null | tail -1 || echo none)
log "Kafka 7.5 consumer group aisoc-rehearsal: $CG1"
# Second message for high-water mark after commit.
echo "probe-msg-2" | "${DOCKER[@]}" exec -i aisoc-kafka-r kafka-console-producer \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null || true
# Stop broker first so ZK ephemeral broker registration clears before the bump.
"${DOCKER[@]}" stop -t 30 aisoc-kafka-r >/dev/null
sleep 5
"${DOCKER[@]}" stop -t 15 aisoc-zk-r >/dev/null
sleep 3
"${DOCKER[@]}" rm -f aisoc-kafka-r aisoc-zk-r 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-zk-r \
  -e ZOOKEEPER_CLIENT_PORT=2181 \
  -v "$KZK_VOL/zk-data:/var/lib/zookeeper/data" \
  -v "$KZK_VOL/zk-log:/var/lib/zookeeper/log" \
  confluentinc/cp-zookeeper:7.8.12
sleep 10
KAFKA_LISTENER_UPGRADE=(
  -e KAFKA_BROKER_ID=1
  -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=true
  -e KAFKA_DEFAULT_REPLICATION_FACTOR=1
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
  -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:29092,PLAINTEXT_HOST://0.0.0.0:9092
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://aisoc-kafka-rehearsal:29092,PLAINTEXT_HOST://127.0.0.1:9092
  -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT
)
"${DOCKER[@]}" run -d --name aisoc-kafka-r2 \
  --hostname aisoc-kafka-rehearsal \
  --link aisoc-zk-r:zookeeper \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  "${KAFKA_LISTENER_UPGRADE[@]}" \
  -v "$KZK_VOL/kafka:/var/lib/kafka/data" \
  confluentinc/cp-kafka:7.8.12
sleep 25
OFF2=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null | head -3 || echo none)
log "Kafka 7.8.12 offsets after upgrade: $OFF2"
CONS=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-console-consumer \
  --bootstrap-server localhost:9092 --topic aisoc-probe --from-beginning --timeout-ms 8000 --max-messages 2 2>/dev/null || echo FAIL)
log "Kafka 7.8 consume (from-beginning): $CONS"
CG2=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-consumer-groups \
  --bootstrap-server localhost:9092 --describe --group aisoc-rehearsal 2>/dev/null | tail -1 || echo none)
log "Kafka 7.8 consumer group aisoc-rehearsal: $CG2"
RESUME=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-console-consumer \
  --bootstrap-server localhost:9092 --topic aisoc-probe --group aisoc-rehearsal \
  --timeout-ms 8000 --max-messages 2 2>/dev/null || echo FAIL)
log "Kafka 7.8 group resume: $RESUME"
OFF3=$("${DOCKER[@]}" exec aisoc-kafka-r2 kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic aisoc-probe 2>/dev/null | head -3 || echo none)
log "Kafka 7.8 offsets after upgrade: $OFF3"

log "=== OpenSearch 2.11.0 -> 2.19.7 (volume + snapshot restore) ==="
OS_VOL="$WORK/opensearch_data"
OS_SNAP="$WORK/opensearch_snapshots"
mkdir -p "$OS_VOL" "$OS_SNAP"
"${DOCKER[@]}" rm -f aisoc-os-r1 aisoc-os-r2 aisoc-os-restore 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-os-r1 \
  -e discovery.type=single-node \
  -e DISABLE_SECURITY_PLUGIN=true \
  -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
  -v "$OS_VOL:/usr/share/opensearch/data" \
  -v "$OS_SNAP:/usr/share/opensearch/snapshots" \
  -p 19200:9200 opensearchproject/opensearch:2.11.0
sleep 50
# path.repo must be on disk before the snapshot repository is registered; append and bounce once.
"${DOCKER[@]}" exec aisoc-os-r1 bash -c 'grep -q path.repo /usr/share/opensearch/config/opensearch.yml || echo "path.repo: [\"/usr/share/opensearch/snapshots\"]" >> /usr/share/opensearch/config/opensearch.yml'
"${DOCKER[@]}" restart aisoc-os-r1 >/dev/null
sleep 50
curl -fsS -X PUT "http://127.0.0.1:19200/aisoc-probe" -H 'Content-Type: application/json' \
  -d '{"settings":{"index.number_of_shards":1,"number_of_replicas":0},"mappings":{"properties":{"n":{"type":"integer"},"tag":{"type":"keyword"}}}}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19200/aisoc-probe/_doc/7" -H 'Content-Type: application/json' \
  -d '{"n":7,"tag":"mig-probe"}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19200/aisoc-probe/_refresh" >/dev/null
OS_SEARCH=$(curl -fsS "http://127.0.0.1:19200/aisoc-probe/_search" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"tag":"mig-probe"}}}')
log "OpenSearch 2.11 search: $(echo "$OS_SEARCH" | head -c 200)"
curl -fsS -X PUT "http://127.0.0.1:19200/_snapshot/aisoc_backup" -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}' >/dev/null
curl -fsS -X PUT "http://127.0.0.1:19200/_snapshot/aisoc_backup/pre_upgrade?wait_for_completion=true" >/dev/null
# Rollback proof: pre-upgrade snapshot → fresh 2.11 volume (same major line).
OS_VOL_RB211="$WORK/opensearch_rollback_211"
rm -rf "$OS_VOL_RB211"
mkdir -p "$OS_VOL_RB211"
"${DOCKER[@]}" run -d --name aisoc-os-rb211 \
  -e discovery.type=single-node \
  -e DISABLE_SECURITY_PLUGIN=true \
  -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
  -v "$OS_VOL_RB211:/usr/share/opensearch/data" \
  -v "$OS_SNAP:/usr/share/opensearch/snapshots" \
  -p 19203:9200 opensearchproject/opensearch:2.11.0
sleep 50
"${DOCKER[@]}" exec aisoc-os-rb211 bash -c 'grep -q path.repo /usr/share/opensearch/config/opensearch.yml || echo "path.repo: [\"/usr/share/opensearch/snapshots\"]" >> /usr/share/opensearch/config/opensearch.yml'
"${DOCKER[@]}" restart aisoc-os-rb211 >/dev/null
sleep 50
curl -fsS -X PUT "http://127.0.0.1:19203/_snapshot/aisoc_backup" -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19203/_snapshot/aisoc_backup/pre_upgrade/_restore?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"aisoc-probe"}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19203/aisoc-probe/_refresh" >/dev/null
OS_RB=$(curl -fsS "http://127.0.0.1:19203/aisoc-probe/_search" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"tag":"mig-probe"}}}')
log "OpenSearch 2.11 rollback restore (pre_upgrade snapshot): $(echo "$OS_RB" | head -c 250)"
"${DOCKER[@]}" stop aisoc-os-rb211 aisoc-os-r1 >/dev/null
sleep 5
# In-place minor upgrade on same data volume.
"${DOCKER[@]}" run -d --name aisoc-os-r2 \
  -e discovery.type=single-node \
  -e DISABLE_SECURITY_PLUGIN=true \
  -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
  -v "$OS_VOL:/usr/share/opensearch/data" \
  -v "$OS_SNAP:/usr/share/opensearch/snapshots" \
  -p 19201:9200 opensearchproject/opensearch:2.19.7
sleep 60
OS2=$(curl -fsS "http://127.0.0.1:19201/aisoc-probe/_count" 2>/dev/null || echo FAIL)
log "OpenSearch 2.19.7 in-place _count: $OS2"
# Snapshot restore onto a fresh data volume (DR / rollback rehearsal).
OS_VOL_FRESH="$WORK/opensearch_data_fresh"
rm -rf "$OS_VOL_FRESH"
mkdir -p "$OS_VOL_FRESH"
"${DOCKER[@]}" run -d --name aisoc-os-restore \
  -e discovery.type=single-node \
  -e DISABLE_SECURITY_PLUGIN=true \
  -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
  -v "$OS_VOL_FRESH:/usr/share/opensearch/data" \
  -v "$OS_SNAP:/usr/share/opensearch/snapshots" \
  -p 19202:9200 opensearchproject/opensearch:2.19.7
sleep 50
"${DOCKER[@]}" exec aisoc-os-restore bash -c 'grep -q path.repo /usr/share/opensearch/config/opensearch.yml || echo "path.repo: [\"/usr/share/opensearch/snapshots\"]" >> /usr/share/opensearch/config/opensearch.yml'
"${DOCKER[@]}" restart aisoc-os-restore >/dev/null
sleep 50
curl -fsS -X PUT "http://127.0.0.1:19202/_snapshot/aisoc_backup" -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19202/_snapshot/aisoc_backup/pre_upgrade/_restore?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"aisoc-probe"}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:19202/aisoc-probe/_refresh" >/dev/null
OS_RESTORE=$(curl -fsS "http://127.0.0.1:19202/aisoc-probe/_search" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"tag":"mig-probe"}}}')
log "OpenSearch 2.19 fresh volume restore search: $(echo "$OS_RESTORE" | head -c 250)"

log "=== Monitoring stack config load (Prometheus 3 / Grafana 13 / OTel 0.121) ==="
MON="$WORK/monitoring"
mkdir -p "$MON/grafana" "$MON/prom"
"${DOCKER[@]}" rm -f aisoc-prom-r aisoc-graf-r aisoc-otel-r 2>/dev/null || true
"${DOCKER[@]}" run -d --name aisoc-prom-r \
  -v "$ROOT/infra/docker/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  -v "$ROOT/infra/docker/alerts:/etc/prometheus/alerts:ro" \
  -p 19090:9090 prom/prometheus:v3.13.5 \
  --config.file=/etc/prometheus/prometheus.yml --web.enable-lifecycle
sleep 5
PROM=$("${DOCKER[@]}" exec aisoc-prom-r wget -qO- http://localhost:9090/-/healthy 2>/dev/null || echo FAIL)
log "Prometheus healthy: $PROM"
RULES=$("${DOCKER[@]}" exec aisoc-prom-r wget -qO- 'http://localhost:9090/api/v1/rules' 2>/dev/null | \
  python3 -c "import sys,json; g=json.load(sys.stdin)['data']['groups']; print(len(g), [x['name'] for x in g])" 2>/dev/null || echo FAIL)
log "Prometheus rule groups: $RULES"
"${DOCKER[@]}" run -d --name aisoc-graf-r \
  -v "$ROOT/infra/docker/grafana:/etc/grafana/provisioning:ro" \
  -p 13000:3000 grafana/grafana:13.3.1
sleep 10
GRAF=$("${DOCKER[@]}" exec aisoc-graf-r wget -qO- http://localhost:3000/api/health 2>/dev/null | head -c 120 || echo FAIL)
log "Grafana health: $GRAF"
if OTEL_EVIDENCE_TAG="rehearsal-$(date +%s)" bash "$ROOT/scripts/otel_tempo_trace_evidence.sh" >>"$LOG" 2>&1; then
  log "OTel→Tempo: GO (trace injected via collector, retrievable by trace ID)"
else
  log "OTel→Tempo: FAIL (see scripts/otel_tempo_trace_evidence.sh output above)"
fi

log "WORK_DIR=$WORK"
log "DONE"
