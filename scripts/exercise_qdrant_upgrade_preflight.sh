#!/usr/bin/env bash
# Feed the Qdrant preflight a volume Qdrant itself wrote.
#
# A run with no storage version used to read the compose pin and report GO.
# This starts the upstream v1.7.0 and v1.19.0 binaries, creates a collection,
# and requires the preflight to refuse v1.7 and allow the consecutive minor.
# The readiness loop fails the job if the process never answers; it does not
# retry a failed preflight.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
pids=()

cleanup() {
  local pid
  for pid in "${pids[@]+"${pids[@]}"}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${pids[@]+"${pids[@]}"}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "qdrant preflight exercise needs the x86_64 release binary (this host is $(uname -m))" >&2
  exit 1
fi

fetch() {
  local version="$1" dest="$2"
  local url="https://github.com/qdrant/qdrant/releases/download/${version}/qdrant-x86_64-unknown-linux-gnu.tar.gz"
  curl -fsSL -o "$dest.tgz" -L "$url"
  mkdir -p "$dest"
  tar -xzf "$dest.tgz" -C "$dest"
  test -x "$dest/qdrant"
}

wait_ready() {
  local url="$1" log="$2" i
  for i in $(seq 1 50); do
    if curl -fsS "$url/readyz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "qdrant did not answer $url/readyz" >&2
  cat "$log" >&2 || true
  return 1
}

start_qdrant() {
  local bin="$1" storage="$2" http="$3" grpc="$4" log="$5"
  mkdir -p "$storage"
  # Qdrant writes .qdrant-initialized in the process cwd. Stay in $WORK so a
  # run from the repository does not leave that file in the tree.
  pushd "$WORK" >/dev/null
  QDRANT__STORAGE__STORAGE_PATH="$storage" \
    QDRANT__SERVICE__HTTP_PORT="$http" \
    QDRANT__SERVICE__GRPC_PORT="$grpc" \
    "$bin" --disable-telemetry >"$log" 2>&1 &
  last_pid=$!
  pids+=("$last_pid")
  popd >/dev/null
}

stop_pid() {
  local pid="$1" i
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
}

seed() {
  local url="$1"
  curl -fsS -X PUT "$url/collections/probe" \
    -H 'Content-Type: application/json' \
    -d '{"vectors":{"size":4,"distance":"Cosine"}}' >/dev/null
  curl -fsS -X PUT "$url/collections/probe/points" \
    -H 'Content-Type: application/json' \
    -d '{"points":[{"id":1,"vector":[0.1,0.2,0.3,0.4],"payload":{"tag":"mig-probe"}}]}' >/dev/null
}

# code_want storage url python-assertions
expect_report() {
  local want="$1" storage="$2" url="$3" check="$4" out code
  out="$WORK/report.json"
  set +e
  if [[ -n "$url" ]]; then
    python3 "$ROOT/scripts/check_qdrant_upgrade_preflight.py" --storage "$storage" --url "$url" >"$out"
  else
    python3 "$ROOT/scripts/check_qdrant_upgrade_preflight.py" --storage "$storage" >"$out"
  fi
  code=$?
  set -e
  python3 - "$out" "$want" "$code" "$check" <<'PY'
import json, sys
path, want, code, check = sys.argv[1:]
report = json.load(open(path, encoding="utf-8"))
if int(code) != int(want):
    raise SystemExit(f"exit {code}, wanted {want}: {json.dumps(report)}")
observed = report.get("storage_version_observed")
pin = report.get("compose_qdrant_pin")
if observed == pin and pin:
    raise SystemExit(f"observed version fell back to the compose pin {pin}: {json.dumps(report)}")
env = {"report": report, "observed": observed, "pin": pin}
exec(check, env)
if not env.get("ok", False):
    raise SystemExit(f"assertion failed: {check}\n{json.dumps(report, indent=2)}")
PY
}

echo "fetching qdrant v1.7.0 and v1.19.0"
fetch v1.7.0 "$WORK/v17"
fetch v1.19.0 "$WORK/v19"

STOR17="$WORK/storage17"
URL17="http://127.0.0.1:18171"
start_qdrant "$WORK/v17/qdrant" "$STOR17" 18171 18172 "$WORK/v17.log"
pid17=$last_pid
wait_ready "$URL17" "$WORK/v17.log"
seed "$URL17"
test -f "$STOR17/collections/probe/version.info"
crate="$(tr -d '[:space:]' < "$STOR17/collections/probe/version.info")"
if [[ "$crate" != "0.4.2" ]]; then
  echo "expected collection version.info 0.4.2 from the v1.7.0 binary, got $crate" >&2
  exit 1
fi

echo "v1.7 volume, server still open: NO-GO, version from the API"
expect_report 1 "$STOR17" "$URL17" 'ok = report["ok"] is False and observed == "v1.7.0" and report["storage_version_source"] == "api"'
if [[ "$(tr -d '[:space:]' < "$STOR17/aisoc-observed-version")" != "v1.7.0" ]]; then
  echo "preflight did not record the observed release into the volume" >&2
  exit 1
fi

stop_pid "$pid17"
echo "same volume, server stopped, marker in the storage: still NO-GO"
expect_report 1 "$STOR17" "" 'ok = report["ok"] is False and observed == "v1.7.0" and report["storage_version_source"] == "storage-marker"'

rm -f "$STOR17/aisoc-observed-version"
echo "same volume with only crate version.info: unknown is NO-GO"
expect_report 1 "$STOR17" "" 'ok = report["ok"] is False and observed is None and report["storage_version_source"] == "unknown" and report["legacy_on_disk_payload"] is True'

STOR19="$WORK/storage19"
URL19="http://127.0.0.1:18191"
start_qdrant "$WORK/v19/qdrant" "$STOR19" 18191 18192 "$WORK/v19.log"
pid19=$last_pid
wait_ready "$URL19" "$WORK/v19.log"
seed "$URL19"
echo "v1.19 volume: consecutive minor is GO"
expect_report 0 "$STOR19" "$URL19" 'ok = report["ok"] is True and observed == "v1.19.0" and report["storage_version_source"] == "api"'
stop_pid "$pid19"
echo "v1.19 marker left in the storage, server stopped: still GO"
expect_report 0 "$STOR19" "" 'ok = report["ok"] is True and observed == "v1.19.0" and report["storage_version_source"] == "storage-marker"'

echo "qdrant upgrade preflight exercise: GO and NO-GO both came from real volumes"
