#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# THE OTLP SUITE (busbar registry id `otlp`): busbar-export-otlp exports into the official
# OpenTelemetry Collector (contrib), pinned by digest; every span it sent must arrive intact.
#
#   CONTROL           telemetrygen (the OpenTelemetry project's own generator, pinned by digest)
#                     sends traces, metrics and logs over OTLP/HTTP and OTLP/gRPC to the collector;
#                     all of it must arrive well-formed.
#   NEGATIVE CONTROL  a corrupt protobuf body and a wrong content-type must be refused by the
#                     collector (and write nothing), and the intact-comparison must catch each of a
#                     set of planted losses (dropped attribute, shifted timestamp, changed id ...).
#   SUBJECT           the plugin's own request builder (driver/main.rs, built in its locked workspace)
#                     delivers the fixture batch; the collector's file output is compared with what
#                     the fixture says must arrive: ids, names, timestamps, attributes (typed),
#                     events, status, resource and scope.
#
# The plugin exports traces only (its `traces` stream); metrics and logs are covered by the control.
# Verdict: pass only when all three legs hold. Contract: testing/conformance/run.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${CONFORMANCE_OUT:?CONFORMANCE_OUT}"

# Harness completion only: the default is the existing collector readiness window. This does
# not change EXPORT_TIMEOUT_MS or any host/plugin delivery deadline. Slow image downloads can
# override it without changing the collector readiness, flush or graceful-stop intervals.
READINESS_TIMEOUT_SECONDS=60
READINESS_POLL_SECONDS=1
COLLECTOR_FLUSH_SECONDS=2
COLLECTOR_STOP_SECONDS=20
COMMAND_TIMEOUT_SECONDS="${OTLP_CONFORMANCE_COMMAND_TIMEOUT_SECONDS:-$READINESS_TIMEOUT_SECONDS}"

COLLECTOR_VERSION=0.163.2
COLLECTOR_IMAGE="otel/opentelemetry-collector-contrib@sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849"
TELEMETRYGEN_VERSION=0.163.0
TELEMETRYGEN_IMAGE="ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen@sha256:569b79a39f8313db839a727e8eac161c66b8a6c2e633f2da4ad352ce7b383c23"
PROTO_CRATE="opentelemetry-proto $(sed -n '/name = "opentelemetry-proto"/{n;s/version = "\(.*\)"/\1/p;}' "$ROOT/Cargo.lock" | head -1)"
SPEC="OpenTelemetry Collector contrib $COLLECTOR_VERSION; OTLP/1.x ($PROTO_CRATE); telemetrygen $TELEMETRYGEN_VERSION"

say() { printf 'otlp: %s\n' "$*" >&2; }
REASONS=()
note() { REASONS+=("$*"); say "FAIL: $*"; }

verdict() { # status armed reason
  python3 -I - "$OUT/verdict.json" "$1" "$2" "$3" "$SPEC" <<'PY'
import json, sys
path, status, armed, reason, spec = sys.argv[1:6]
json.dump({"suite": "otlp", "status": status, "armed": armed == "true",
           "standard": "OpenTelemetry Protocol (OTLP) 1.x",
           "plan": "busbar-export-otlp exporting into the official opentelemetry-collector-contrib; every span it sent arrives intact",
           "spec_version": spec, "reason": reason}, open(path, "w"), indent=2)
PY
}

NET="otlpconf-$$"
CONTAINERS=()
NETWORK_REGISTERED=0
RUNNING_TOOL=
run_tool() {
  python3 -I "$HERE/command.py" "$COMMAND_TIMEOUT_SECONDS" "$@" &
  RUNNING_TOOL=$!
  local status=0
  wait "$RUNNING_TOOL" || status=$?
  RUNNING_TOOL=
  return "$status"
}
cleanup() {
  local status=$? c failed=0 log names
  trap - EXIT
  trap '' INT TERM
  if [ -n "$RUNNING_TOOL" ]; then
    kill -TERM "$RUNNING_TOOL" 2>/dev/null || :
    wait "$RUNNING_TOOL" 2>/dev/null || :
    RUNNING_TOOL=
  fi
  for c in "${CONTAINERS[@]:-}"; do
    if [ -n "$c" ]; then
      log="$OUT/work/cleanup-$c.log"
      names="$OUT/work/cleanup-$c.names"
      if ! run_tool docker rm -f "$c" > "$log" 2>&1; then
        # telemetrygen's --rm may already have removed it. Only an affirmative successful
        # listing can establish absence; a daemon/timeout error is still a cleanup failure.
        if ! run_tool docker ps -a --filter "name=^/$c\$" --format '{{.Names}}' > "$names" 2>> "$log" \
          || [ -s "$names" ]; then
          cat "$log" >&2
          say "cleanup: could not remove container $c"
          failed=1
        fi
      fi
    fi
  done
  if [ "$NETWORK_REGISTERED" = 1 ]; then
    log="$OUT/work/cleanup-network.log"
    names="$OUT/work/cleanup-network.names"
    if ! run_tool docker network rm "$NET" > "$log" 2>&1; then
      if ! run_tool docker network ls --filter "name=^$NET\$" --format '{{.Name}}' > "$names" 2>> "$log" \
        || [ -s "$names" ]; then
        cat "$log" >&2
        say "cleanup: could not remove network $NET"
        failed=1
      fi
    fi
  fi
  if [ "$failed" = 1 ] && [ "$status" = 0 ]; then
    verdict fail true "the OTLP harness could not finish resource cleanup; see cleanup logs"
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
interrupted() {
  verdict fail true "the OTLP suite was interrupted by $1"
  exit "$2"
}
trap 'interrupted INT 130' INT
trap 'interrupted TERM 143' TERM

command -v docker >/dev/null || { verdict fail true "docker is absent; the collector cannot run"; exit 1; }
mkdir -p "$OUT/work" || exit 1
NETWORK_REGISTERED=1
run_tool docker network create "$NET" >/dev/null || { verdict fail true "docker network create failed"; exit 1; }

# collector_start <name>: a fresh collector; sets PORT (host-published OTLP/HTTP).
collector_start() {
  local name="otlpconf-$$-$1"
  CONTAINERS+=("$name")
  run_tool docker create --name "$name" --network "$NET" --network-alias collector --user 0:0 \
    -p 127.0.0.1::4318 "$COLLECTOR_IMAGE" --config /conf.yaml >/dev/null || return 1
  run_tool docker cp "$HERE/collector.yaml" "$name:/conf.yaml" || return 1
  run_tool docker start "$name" >/dev/null || return 1
  run_tool docker port "$name" 4318/tcp > "$OUT/work/$1.port" || return 1
  PORT="$(head -1 "$OUT/work/$1.port" | sed 's/.*://')"
  [ -n "$PORT" ] || return 1
  local deadline=$((SECONDS + READINESS_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -s --connect-timeout "$READINESS_POLL_SECONDS" --max-time "$READINESS_POLL_SECONDS" \
      -o /dev/null -X POST -H 'content-type: application/json' -d '{}' "http://127.0.0.1:$PORT/v1/traces"; then return 0; fi
    sleep "$READINESS_POLL_SECONDS"
  done
  run_tool docker logs "$name" > "$OUT/work/$1.start.log" 2>&1 || :
  tail -20 "$OUT/work/$1.start.log" >&2
  return 1
}

# collector_finish <name> <dir> <signals...>: stop gracefully, copy the required signal files out.
collector_finish() {
  local name="otlpconf-$$-$1" dir="$2" failed=0 f
  shift 2
  mkdir -p "$dir" || return 1
  sleep "$COLLECTOR_FLUSH_SECONDS"
  if ! run_tool docker stop -t "$COLLECTOR_STOP_SECONDS" "$name" > "$dir/stop.log" 2>&1; then
    cat "$dir/stop.log" >&2
    failed=1
  fi
  for f in "$@"; do
    if ! run_tool docker cp "$name:/$f.json" "$dir/$f.json" > "$dir/copy-$f.log" 2>&1; then
      cat "$dir/copy-$f.log" >&2
      : > "$dir/$f.json"
      failed=1
    fi
  done
  if ! run_tool docker logs "$name" > "$dir/collector.log" 2>&1; then
    cat "$dir/collector.log" >&2
    failed=1
  fi
  return "$failed"
}

CHECK=(python3 -I "$HERE/check.py")

# ---- CONTROL: telemetrygen -> collector, over HTTP and gRPC, all three signals -------------------
say "control: telemetrygen $TELEMETRYGEN_VERSION -> collector $COLLECTOR_VERSION"
if ! run_tool docker pull -q "$COLLECTOR_IMAGE" >/dev/null || ! run_tool docker pull -q "$TELEMETRYGEN_IMAGE" >/dev/null; then
  verdict fail true "the pinned collector or telemetrygen image could not be pulled"; exit 1
fi
if collector_start control; then
  for proto in http grpc; do
    flag=(--otlp-insecure)
    if [ "$proto" = grpc ]; then ep=collector:4317; else ep=collector:4318; flag+=(--otlp-http); fi
    for sig in traces metrics logs; do
      count=(--"$sig" 5)
      generator="otlpconf-$$-telemetrygen-$proto-$sig"
      CONTAINERS+=("$generator")
      run_tool docker run --rm --name "$generator" --network "$NET" "$TELEMETRYGEN_IMAGE" "$sig" --otlp-endpoint "$ep" "${flag[@]}" \
        --service "ctl-$proto" "${count[@]}" --rate 0 >"$OUT/work/telemetrygen-$proto-$sig.log" 2>&1 \
        || note "control: telemetrygen $sig over $proto failed ($(tail -1 "$OUT/work/telemetrygen-$proto-$sig.log"))"
    done
  done
  collector_finish control "$OUT/work/control" traces metrics logs || note "control: collector stop or output capture failed"
  for proto in http grpc; do
    for sig in traces metrics logs; do
      p="$("${CHECK[@]}" control "$OUT/work/control" "ctl-$proto" "$sig" 5)" || note "control ($proto $sig): $p"
    done
  done
else
  note "control: the collector did not start"
fi

# ---- SUBJECT build ------------------------------------------------------------------------------
say "subject: building the driver with the plugin workspace's lock and pinned contract"
# The example is an existing workspace package target, not a new generated package. Its logic,
# serde_json and contract dependencies already occur in the root lock, which stays unmodified.
BUILT=0
if cargo build --locked --release --manifest-path "$ROOT/Cargo.toml" -p busbar-export-otlp \
  --example otlp-conformance-driver >"$OUT/work/build.log" 2>&1; then
  BUILT=1
else
  tail -30 "$OUT/work/build.log" >&2
  note "subject: the driver does not build with the plugin's pinned dependencies"
fi
DRIVER="${CARGO_TARGET_DIR:-$ROOT/target}/release/examples/otlp-conformance-driver"

# ---- SUBJECT + NEGATIVE CONTROL ------------------------------------------------------------------
if [ "$BUILT" = 1 ]; then
  if collector_start subject; then
    URL="http://127.0.0.1:$PORT/v1/traces"
    say "subject: delivering the fixture batch to $URL"
    if ! run_tool "$DRIVER" send "$URL" "$HERE/fixture.jsonl" >"$OUT/work/send.log" 2>&1; then
      note "subject: the collector refused the plugin's export ($(head -1 "$OUT/work/send.log"))"
    fi
    # The body runs under the same deadline as every other tool; the negative controls built from
    # it run only when it was built, so a missing body is one reason, not three false ones.
    BODY=0
    if run_tool "$DRIVER" body "$HERE/fixture.jsonl" "$OUT/work/body.bin" && [ -s "$OUT/work/body.bin" ]; then
      BODY=1
    else
      note "subject: no body built"
    fi

    # negative controls on the wire: each MUST be refused with a 4xx.
    head -c 64 /dev/zero | tr '\0' '\377' > "$OUT/work/garbage.bin"
    neg() { # label content-type file
      local code
      if ! run_tool curl -sS --connect-timeout "$COMMAND_TIMEOUT_SECONDS" --max-time "$COMMAND_TIMEOUT_SECONDS" \
        -o /dev/null -w '%{http_code}' -X POST -H "content-type: $2" --data-binary "@$3" "$URL" > "$OUT/work/negative-status"; then
        note "negative control: $1 request failed"
        return
      fi
      code="$(cat "$OUT/work/negative-status")"
      case "$code" in 4??) say "negative control: $1 -> $code (refused)";; *) note "negative control: $1 was answered $code, not refused";; esac
    }
    neg "corrupt protobuf (garbage)" application/x-protobuf "$OUT/work/garbage.bin"
    if [ "$BODY" = 1 ]; then
      head -c 40 "$OUT/work/body.bin" > "$OUT/work/truncated.bin"
      neg "corrupt protobuf (truncated)" application/x-protobuf "$OUT/work/truncated.bin"
      neg "wrong content-type" text/plain "$OUT/work/body.bin"
      neg "no usable content-type" application/octet-stream "$OUT/work/body.bin"
    fi

    collector_finish subject "$OUT/work/subject" traces || note "subject: collector stop or output capture failed"
    p="$("${CHECK[@]}" compare "$HERE/fixture.jsonl" "$OUT/work/subject/traces.json")" || note "subject: $p"
    echo "$p" >&2
    # the refused payloads wrote nothing: the file holds exactly the one delivery's spans
    n="$(python3 -I -c 'import json,sys;print(sum(len(ss["spans"]) for l in open(sys.argv[1]) if l.strip() for rs in json.loads(l)["resourceSpans"] for ss in rs["scopeSpans"]))' "$OUT/work/subject/traces.json")"
    want="$(python3 -I -c 'import sys;sys.path.insert(0,sys.argv[1]);import check;print(len(check.expected(sys.argv[2])))' "$HERE" "$HERE/fixture.jsonl")"
    [ "$n" = "$want" ] || note "negative control: the collector holds $n spans, the one good delivery had $want"
    p="$("${CHECK[@]}" bites "$HERE/fixture.jsonl" "$OUT/work/subject/traces.json")" || note "negative control: $p"
    echo "$p" >&2
  else
    note "subject: the collector did not start"
  fi
fi

if [ "${#REASONS[@]}" -eq 0 ]; then
  verdict pass true "control (telemetrygen http+grpc, traces+metrics+logs) round-tripped; corrupt protobuf and wrong content-type refused; planted losses caught; every plugin span arrived intact"
  exit 0
fi
reason="$(printf '%s; ' "${REASONS[@]}")"
verdict fail true "${reason%; }"
exit 1
