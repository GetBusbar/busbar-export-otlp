#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# THE otel-semconv-weaver SUITE: official Weaver checks on this invocation's real
# Collector-captured plugin spans (see README.md). The evaluation itself is the Rust rig
# testing/weaver-conformance/rig.rs, compiled into busbar-export-otlp's test target with the
# workspace's lock (like the collector driver) and run here as its one ignored test. It writes
# $CONFORMANCE_OUT/verdict.json and $CONFORMANCE_OUT/evidence/; this script only builds and runs it.
#
#   CONFORMANCE_OUT            an empty directory; the sibling ../otlp holds this invocation's
#                              passing OTLP verdict and its capture
#   CONFORMANCE_CAPABILITIES   present under protected native CI: the pinned Weaver inputs are the
#                              controller's read-only staging, and nothing is downloaded
#   CARGO_TARGET_DIR           this repo's target/ (the otlp suite already built the test target)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
: "${CONFORMANCE_OUT:?CONFORMANCE_OUT is the verdict directory}"
mkdir -p "$CONFORMANCE_OUT"
CONFORMANCE_OUT="$(cd "$CONFORMANCE_OUT" && pwd)"
export CONFORMANCE_OUT

rc=0
cargo test --locked --release --manifest-path "$ROOT/Cargo.toml" -p busbar-export-otlp --lib \
  -- --ignored --exact weaver_rig::weaver_conformance --nocapture --test-threads=1 || rc=$?

# The rig writes a verdict on every evaluation outcome. Only a rig that did not build, or could
# not create its evidence directories, leaves none; that is a failure with its own reason.
if [ ! -f "$CONFORMANCE_OUT/verdict.json" ]; then
  cat > "$CONFORMANCE_OUT/verdict.json" <<'JSON'
{
  "armed": true,
  "reason": "the Weaver rig did not build or could not run; see the job log",
  "status": "fail",
  "suite": "otel-semconv-weaver"
}
JSON
  [ "$rc" -ne 0 ] || rc=1
fi
exit "$rc"
