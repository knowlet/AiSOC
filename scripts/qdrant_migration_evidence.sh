#!/usr/bin/env bash
# Qdrant migration evidence — disposable only.
#
# Proves:
#   (1) Raw v1.7.0 volume on v1.20.0 is unsafe (NO-GO).
#   (2) Snapshots taken on v1.7.0 do not recover on v1.20.0 (on_disk segment format).
#   (3) Official path: step consecutive minor releases on the same volume, then
#       snapshot/recover onto fresh v1.20.0 storage preserves vectors + payload.
#
# Qdrant documents storage compatibility between consecutive minor versions only;
# see https://qdrant.tech/documentation/database/snapshots/ and roadmap notes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/qdrant-mig-$$"
mkdir -p "$WORK"
LOG="$WORK/evidence.log"
log() { echo "$*" | tee -a "$LOG"; }

DOCKER=(docker)
command -v docker >/dev/null || exit 2
if ! docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
fi

VEC='[0.11,0.22,0.33,0.44]'
PAYLOAD='{"tenant":"evidence","tag":"mig-probe"}'

# Consecutive minors exercised on this VM (tags must exist on docker.io/qdrant/qdrant).
LADDER=(
  v1.7.0 v1.8.0 v1.9.0 v1.10.0 v1.11.0 v1.12.5 v1.13.0 v1.14.0
  v1.15.1 v1.16.0 v1.17.0 v1.18.0 v1.19.0 v1.20.0
)

log "=== Qdrant migration evidence ($(date -Iseconds)) ==="

QV="$WORK/qdrant_data"
rm -rf "$QV"
mkdir -p "$QV"
"${DOCKER[@]}" rm -f qdrant-mig-old qdrant-mig-new qdrant-mig-bad 2>/dev/null || true

"${DOCKER[@]}" run -d --name qdrant-mig-old -p 16335:6333 -v "$QV:/qdrant/storage" qdrant/qdrant:v1.7.0
sleep 4
curl -fsS -X PUT "http://127.0.0.1:16335/collections/mig_probe" \
  -H 'Content-Type: application/json' \
  -d '{"vectors":{"size":4,"distance":"Cosine"}}' >/dev/null
curl -fsS -X PUT "http://127.0.0.1:16335/collections/mig_probe/points" \
  -H 'Content-Type: application/json' \
  -d "{\"points\":[{\"id\":42,\"vector\":$VEC,\"payload\":$PAYLOAD}]}" >/dev/null
BEFORE=$(curl -fsS -X POST "http://127.0.0.1:16335/collections/mig_probe/points/search" \
  -H 'Content-Type: application/json' \
  -d "{\"vector\":$VEC,\"limit\":1,\"with_payload\":true}" )
log "v1.7.0 search: $(echo "$BEFORE" | head -c 400)"

SNAP_RAW=$(curl -fsS -X POST "http://127.0.0.1:16335/collections/mig_probe/snapshots")
SNAP_NAME=$(echo "$SNAP_RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['name'])")
log "v1.7.0 snapshot: $SNAP_NAME"
"${DOCKER[@]}" cp "qdrant-mig-old:/qdrant/snapshots/mig_probe/$SNAP_NAME" "$WORK/$SNAP_NAME"
chmod a+r "$WORK/$SNAP_NAME" 2>/dev/null || sudo chmod a+r "$WORK/$SNAP_NAME"
log "snapshot bytes: $(wc -c < "$WORK/$SNAP_NAME")"

# --- Rollback proof: pre-ladder v1.7 snapshot → fresh v1.7 storage ---
QV_RB="$WORK/qdrant_rollback"
rm -rf "$QV_RB"
mkdir -p "$QV_RB"
"${DOCKER[@]}" rm -f qdrant-rb 2>/dev/null || true
"${DOCKER[@]}" run -d --name qdrant-rb -p 16334:6333 -v "$QV_RB:/qdrant/storage" qdrant/qdrant:v1.7.0
sleep 4
curl -fsS -X POST "http://127.0.0.1:16334/collections/mig_probe/snapshots/upload?wait=true" \
  -F "snapshot=@$WORK/$SNAP_NAME" >/dev/null
RB=$(curl -fsS -X POST "http://127.0.0.1:16334/collections/mig_probe/points/search" \
  -H 'Content-Type: application/json' \
  -d "{\"vector\":$VEC,\"limit\":1,\"with_payload\":true}")
log "v1.7.0 rollback (pre-ladder snapshot → fresh v1.7): $(echo "$RB" | head -c 350)"
if ! echo "$RB" | grep -q '"tag":"mig-probe"'; then
  log "FAIL: pre-ladder snapshot did not restore on v1.7.0"
  exit 1
fi
log "GO: pre-ladder backup restores on v1.7.0 (rollback path before any forward ladder)"

# --- NO-GO: same v1.7 volume on v1.20.0 ---
"${DOCKER[@]}" stop qdrant-mig-old >/dev/null
if "${DOCKER[@]}" run -d --name qdrant-mig-bad -v "$QV:/qdrant/storage" qdrant/qdrant:v1.20.0 >/dev/null 2>&1; then
  sleep 3
  if "${DOCKER[@]}" ps --filter name=qdrant-mig-bad --filter status=running -q | grep -q .; then
    log "UNEXPECTED: v1.20 stayed up on v1.7 volume — re-check"
  else
    log "NO-GO: v1.20 does not run on v1.7.0 volume (segment on_disk vs mmap)"
  fi
  "${DOCKER[@]}" rm -f qdrant-mig-bad 2>/dev/null || true
else
  log "NO-GO: v1.20 container exit on v1.7.0 volume"
fi

# --- NO-GO: v1.7.0 snapshot upload on fresh v1.20 (format not forward-compatible) ---
QV_BAD="$WORK/qdrant_fresh_bad"
rm -rf "$QV_BAD"
mkdir -p "$QV_BAD"
"${DOCKER[@]}" run -d --name qdrant-mig-new -p 16336:6333 -v "$QV_BAD:/qdrant/storage" qdrant/qdrant:v1.20.0
sleep 5
if curl -fsS -X POST "http://127.0.0.1:16336/collections/mig_probe/snapshots/upload?wait=true" \
  -F "snapshot=@$WORK/$SNAP_NAME" >/dev/null 2>&1; then
  log "UNEXPECTED: v1.7 snapshot recovered on v1.20 without ladder"
else
  log "NO-GO: v1.7.0 snapshot does not recover on v1.20.0 (on_disk in snapshot payload)"
fi
"${DOCKER[@]}" rm -f qdrant-mig-new 2>/dev/null || true

# --- GO: consecutive minor ladder on shared volume ---
QV_LADDER="$WORK/qdrant_ladder"
rm -rf "$QV_LADDER"
mkdir -p "$QV_LADDER"
"${DOCKER[@]}" rm -f qdrant-ladder 2>/dev/null || true
"${DOCKER[@]}" run -d --name qdrant-ladder -p 16337:6333 -v "$QV_LADDER:/qdrant/storage" qdrant/qdrant:${LADDER[0]}
sleep 4
curl -fsS -X PUT "http://127.0.0.1:16337/collections/mig_probe" \
  -H 'Content-Type: application/json' \
  -d '{"vectors":{"size":4,"distance":"Cosine"}}' >/dev/null
curl -fsS -X PUT "http://127.0.0.1:16337/collections/mig_probe/points" \
  -H 'Content-Type: application/json' \
  -d "{\"points\":[{\"id\":42,\"vector\":$VEC,\"payload\":$PAYLOAD}]}" >/dev/null

for ((i = 1; i < ${#LADDER[@]}; i++)); do
  ver="${LADDER[$i]}"
  prev="${LADDER[$((i - 1))]}"
  "${DOCKER[@]}" stop qdrant-ladder >/dev/null
  "${DOCKER[@]}" rm qdrant-ladder >/dev/null
  "${DOCKER[@]}" run -d --name qdrant-ladder -p 16337:6333 \
    -v "$QV_LADDER:/qdrant/storage" "qdrant/qdrant:${ver}"
  sleep 6
  if ! curl -fsS -X POST "http://127.0.0.1:16337/collections/mig_probe/points/search" \
    -H 'Content-Type: application/json' \
    -d "{\"vector\":$VEC,\"limit\":1,\"with_payload\":true}" | grep -q mig-probe; then
    log "LADDER FAIL at $prev -> $ver"
    "${DOCKER[@]}" logs qdrant-ladder 2>&1 | tail -8 | tee -a "$LOG"
    exit 1
  fi
  log "LADDER OK $prev -> $ver"
done

AFTER_LADDER=$(curl -fsS -X POST "http://127.0.0.1:16337/collections/mig_probe/points/search" \
  -H 'Content-Type: application/json' \
  -d "{\"vector\":$VEC,\"limit\":1,\"with_payload\":true}")
log "v1.20.0 in-place search after ladder: $(echo "$AFTER_LADDER" | head -c 400)"

SNAP_OK=$(curl -fsS -X POST "http://127.0.0.1:16337/collections/mig_probe/snapshots")
SNAP_OK_NAME=$(echo "$SNAP_OK" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['name'])")
"${DOCKER[@]}" cp "qdrant-ladder:/qdrant/snapshots/mig_probe/$SNAP_OK_NAME" "$WORK/$SNAP_OK_NAME"
chmod a+r "$WORK/$SNAP_OK_NAME" 2>/dev/null || sudo chmod a+r "$WORK/$SNAP_OK_NAME"

QV_RESTORE="$WORK/qdrant_restore"
rm -rf "$QV_RESTORE"
mkdir -p "$QV_RESTORE"
"${DOCKER[@]}" stop qdrant-ladder >/dev/null
"${DOCKER[@]}" run -d --name qdrant-restore -p 16338:6333 -v "$QV_RESTORE:/qdrant/storage" qdrant/qdrant:v1.20.0
sleep 5
curl -fsS -X POST "http://127.0.0.1:16338/collections/mig_probe/snapshots/upload?wait=true" \
  -F "snapshot=@$WORK/$SNAP_OK_NAME" >/dev/null
RESTORED=$(curl -fsS -X POST "http://127.0.0.1:16338/collections/mig_probe/points/search" \
  -H 'Content-Type: application/json' \
  -d "{\"vector\":$VEC,\"limit\":1,\"with_payload\":true}")
log "v1.20.0 backup/restore search: $(echo "$RESTORED" | head -c 400)"

if echo "$RESTORED" | grep -q '"tag":"mig-probe"'; then
  log "GO: consecutive-minor ladder + snapshot recover preserves payload on v1.20.0"
else
  log "FAIL: restore search missing expected payload"
  exit 1
fi

log ""
log "RUNBOOK: Do not mount a v1.7.x data directory on qdrant/qdrant:v1.20.0."
log "RUNBOOK: Do not rely on snapshots created on v1.7.x for direct v1.20 import."
log "RUNBOOK: Step every consecutive minor (see LADDER in this script) on the same volume,"
log "          then use collection snapshots for backup/restore onto fresh v1.20 storage."
log "LOG=$LOG WORK=$WORK"
