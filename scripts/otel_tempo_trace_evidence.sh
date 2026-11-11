#!/usr/bin/env bash
# Emit one OTLP span and prove Tempo indexed it by trace ID (disposable).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET="${OTEL_EVIDENCE_NET:-aisoc-rehearsal-mon}"
TRACE_TAG="${OTEL_EVIDENCE_TAG:-upgrade-rehearsal-$(date +%s)}"
TEMPO_HTTP_PORT="${OTEL_TEMPO_HTTP_PORT:-13200}"
TEMPO_OTLP_PORT="${OTEL_TEMPO_OTLP_PORT:-14397}"
COLLECTOR_GRPC_PORT="${OTEL_COLLECTOR_GRPC_PORT:-14317}"

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
fi

cleanup() {
  rm -f "${COLLECTOR_CFG:-}"
  "${DOCKER[@]}" rm -f aisoc-tempo-ev aisoc-otel-ev 2>/dev/null || true
}
trap cleanup EXIT

COLLECTOR_CFG="$(mktemp)"
chmod a+r "$COLLECTOR_CFG"
sed "s|endpoint: tempo:4317|endpoint: host.docker.internal:${TEMPO_OTLP_PORT}|" \
  "$ROOT/infra/docker/otel/collector.yaml" >"$COLLECTOR_CFG"

"${DOCKER[@]}" rm -f aisoc-tempo-ev aisoc-otel-ev 2>/dev/null || true
"${DOCKER[@]}" network create "$NET" 2>/dev/null || true
TEMPO_VOL="$(mktemp -d)"
"${DOCKER[@]}" run -d --name aisoc-tempo-ev --hostname tempo --network "$NET" \
  -p "${TEMPO_HTTP_PORT}:3200" -p "${TEMPO_OTLP_PORT}:4317" \
  --user 0:0 \
  -v "$ROOT/infra/docker/otel/tempo.yaml:/etc/tempo/tempo.yaml:ro" \
  -v "${TEMPO_VOL}:/var/tempo" \
  grafana/tempo:2.7.2 \
  -config.file=/etc/tempo/tempo.yaml

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${TEMPO_HTTP_PORT}/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -fsS "http://127.0.0.1:${TEMPO_HTTP_PORT}/ready" >/dev/null 2>&1; then
  echo "FAIL: Tempo not ready on :${TEMPO_HTTP_PORT}" >&2
  "${DOCKER[@]}" logs aisoc-tempo-ev 2>&1 | tail -20 >&2 || true
  exit 1
fi

"${DOCKER[@]}" run -d --name aisoc-otel-ev --network "$NET" \
  --add-host=host.docker.internal:host-gateway \
  -p "${COLLECTOR_GRPC_PORT}:4317" -p 14318:4318 \
  -v "${COLLECTOR_CFG}:/etc/otelcol-contrib/config.yaml:ro" \
  otel/opentelemetry-collector-contrib:0.121.0 \
  --config=/etc/otelcol-contrib/config.yaml
for _ in $(seq 1 30); do
  if (echo >/dev/tcp/127.0.0.1/"$COLLECTOR_GRPC_PORT") 2>/dev/null; then
    break
  fi
  sleep 1
done

V=/tmp/otel-ev-venv
python3.13 -m venv "$V"
"$V/bin/pip" -q install \
  opentelemetry-api opentelemetry-sdk \
  opentelemetry-exporter-otlp-proto-grpc
export TRACE_TAG OTEL_COLLECTOR_GRPC_PORT="$COLLECTOR_GRPC_PORT"
TRACE_ID="$("$V/bin/python" - <<'PY'
import os
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

resource = Resource.create({"service.name": "upgrade-evidence"})
provider = TracerProvider(resource=resource)
exporter = OTLPSpanExporter(endpoint=f"localhost:{os.environ['OTEL_COLLECTOR_GRPC_PORT']}", insecure=True)
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("scripts.otel_tempo_trace_evidence")
tag = os.environ.get("TRACE_TAG", "evidence")
with tracer.start_as_current_span("aisoc.disposable.trace_probe") as span:
    span.set_attribute("evidence.tag", tag)
    tid = format(span.get_span_context().trace_id, "032x")
provider.force_flush(timeout_millis=15000)
provider.shutdown()
print(tid)
PY
)"

found=0
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${TEMPO_HTTP_PORT}/api/traces/${TRACE_ID}" | grep -q "$TRACE_TAG"; then
    found=1
    break
  fi
  sleep 2
done

HITS=$(curl -fsS "http://127.0.0.1:${TEMPO_HTTP_PORT}/api/search?tags=evidence.tag%3D${TRACE_TAG}" 2>/dev/null | head -c 400 || echo FAIL)
echo "trace_id=$TRACE_ID"
echo "tempo_search=$HITS"
if [ "$found" -eq 1 ]; then
  echo "GO: span exported via OTel collector and trace retrievable from Tempo"
  exit 0
fi
echo "FAIL: trace $TRACE_ID not found in Tempo" >&2
exit 1
