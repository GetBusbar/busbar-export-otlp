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
#   SUBJECT           the plugin's own request builder (driver.rs, built against $BUSBAR_CHECKOUT)
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
CHECKOUT="${BUSBAR_CHECKOUT:?BUSBAR_CHECKOUT}"

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
cleanup() {
  for c in "${CONTAINERS[@]:-}"; do [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

command -v docker >/dev/null || { verdict fail true "docker is absent; the collector cannot run"; exit 1; }
mkdir -p "$OUT/work" || exit 1
docker network create "$NET" >/dev/null || { verdict fail true "docker network create failed"; exit 1; }

# collector_start <name>: a fresh collector; sets PORT (host-published OTLP/HTTP).
collector_start() {
  local name="otlpconf-$$-$1"
  CONTAINERS+=("$name")
  docker create --name "$name" --network "$NET" --network-alias collector --user 0:0 \
    -p 127.0.0.1::4318 "$COLLECTOR_IMAGE" --config /conf.yaml >/dev/null || return 1
  docker cp "$HERE/collector.yaml" "$name:/conf.yaml" || return 1
  docker start "$name" >/dev/null || return 1
  PORT="$(docker port "$name" 4318/tcp | head -1 | sed 's/.*://')"
  local i
  for i in $(seq 1 60); do
    if curl -s -o /dev/null -X POST -H 'content-type: application/json' -d '{}' "http://127.0.0.1:$PORT/v1/traces"; then return 0; fi
    sleep 1
  done
  docker logs "$name" 2>&1 | tail -20 >&2
  return 1
}

# collector_finish <name> <dir>: stop gracefully (flushes the file exporters), copy the files out.
collector_finish() {
  local name="otlpconf-$$-$1"
  sleep 2
  docker stop -t 20 "$name" >/dev/null 2>&1
  mkdir -p "$2"
  local f
  for f in traces metrics logs; do
    docker cp "$name:/$f.json" "$2/$f.json" >/dev/null 2>&1 || : > "$2/$f.json"
  done
  docker logs "$name" > "$2/collector.log" 2>&1
}

CHECK=(python3 -I "$HERE/check.py")

# ---- CONTROL: telemetrygen -> collector, over HTTP and gRPC, all three signals -------------------
say "control: telemetrygen $TELEMETRYGEN_VERSION -> collector $COLLECTOR_VERSION"
if ! docker pull -q "$COLLECTOR_IMAGE" >/dev/null || ! docker pull -q "$TELEMETRYGEN_IMAGE" >/dev/null; then
  verdict fail true "the pinned collector or telemetrygen image could not be pulled"; exit 1
fi
if collector_start control; then
  for proto in http grpc; do
    ep=collector:4318; flag=(--otlp-http); [ "$proto" = grpc ] && { ep=collector:4317; flag=(); }
    for sig in traces metrics logs; do
      count=(--"$sig" 5)
      docker run --rm --network "$NET" "$TELEMETRYGEN_IMAGE" "$sig" --otlp-endpoint "$ep" "${flag[@]}" \
        --otlp-insecure --service "ctl-$proto" "${count[@]}" --rate 0 >"$OUT/work/telemetrygen-$proto-$sig.log" 2>&1 \
        || note "control: telemetrygen $sig over $proto failed ($(tail -1 "$OUT/work/telemetrygen-$proto-$sig.log"))"
    done
  done
  collector_finish control "$OUT/work/control"
  for proto in http grpc; do
    for sig in traces metrics logs; do
      p="$("${CHECK[@]}" control "$OUT/work/control" "ctl-$proto" "$sig" 5)" || note "control ($proto $sig): $p"
    done
  done
else
  note "control: the collector did not start"
fi

# ---- SUBJECT build ------------------------------------------------------------------------------
say "subject: building the driver against $CHECKOUT"
DRV="$OUT/work/driver"
mkdir -p "$DRV/src"
cp "$HERE/driver/main.rs" "$DRV/src/main.rs"
cp "$ROOT/Cargo.lock" "$DRV/Cargo.lock"
cat > "$DRV/Cargo.toml" <<TOML
[package]
name = "otlp-conformance-driver"
version = "0.0.0"
edition = "2021"
publish = false
[[bin]]
name = "driver"
path = "src/main.rs"
[dependencies]
busbar-export-otlp = { path = "$ROOT/export-otlp" }
serde_json = "1"
[workspace]
[patch."https://github.com/GetBusbar/busbar"]
busbar-contract = { path = "$CHECKOUT/crates/busbar-contract" }
TOML
BUILT=0
if ( cd "$DRV" && cargo build --release --bin driver ) >"$OUT/work/build.log" 2>&1; then
  BUILT=1
else
  tail -30 "$OUT/work/build.log" >&2
  note "subject: the driver does not build against busbar $BUSBAR_PIN"
fi
DRIVER="$CARGO_TARGET_DIR/release/driver"
[ -n "${CARGO_TARGET_DIR:-}" ] || DRIVER="$DRV/target/release/driver"

# ---- SUBJECT + NEGATIVE CONTROL ------------------------------------------------------------------
if [ "$BUILT" = 1 ]; then
  if collector_start subject; then
    URL="http://127.0.0.1:$PORT/v1/traces"
    say "subject: delivering the fixture batch to $URL"
    if ! "$DRIVER" send "$URL" "$HERE/fixture.jsonl" >"$OUT/work/send.log" 2>&1; then
      note "subject: the collector refused the plugin's export ($(head -1 "$OUT/work/send.log"))"
    fi
    "$DRIVER" body "$HERE/fixture.jsonl" "$OUT/work/body.bin" || note "subject: no body built"

    # negative controls on the wire: each MUST be refused with a 4xx.
    head -c 40 "$OUT/work/body.bin" > "$OUT/work/truncated.bin"
    head -c 64 /dev/zero | tr '\0' '\377' > "$OUT/work/garbage.bin"
    neg() { # label content-type file
      local code
      code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "content-type: $2" --data-binary "@$3" "$URL")"
      case "$code" in 4??) say "negative control: $1 -> $code (refused)";; *) note "negative control: $1 was answered $code, not refused";; esac
    }
    neg "corrupt protobuf (garbage)" application/x-protobuf "$OUT/work/garbage.bin"
    neg "corrupt protobuf (truncated)" application/x-protobuf "$OUT/work/truncated.bin"
    neg "wrong content-type" text/plain "$OUT/work/body.bin"
    neg "no usable content-type" application/octet-stream "$OUT/work/body.bin"

    collector_finish subject "$OUT/work/subject"
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
