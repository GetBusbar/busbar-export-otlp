# OTLP collector conformance

Run through `testing/conformance/run.sh`, or invoke this suite's `run.sh` with
`CONFORMANCE_OUT` set to an output directory. Docker, Python and the workspace's
Rust toolchain must be available. The command helper uses Python's POSIX process
groups and wait-without-reaping support on the suite's Linux/macOS hosts.

The subject driver is the `otlp-conformance-driver` example of `busbar-export-otlp`.
The suite builds it with `cargo build --locked --release` from the existing plugin
workspace. It uses that workspace's unchanged `Cargo.lock` and Git-pinned contract;
it creates no standalone package, copied lock or local contract patch. The normal
conformance wrapper supplies the same core pin as the plugin's dependency manifests.

`OTLP_CONFORMANCE_COMMAND_TIMEOUT_SECONDS` sets the harness command deadline in
positive whole seconds. Its default is the existing 60-second collector readiness
window; slow image pulls can use a larger value. Docker operations, telemetrygen
and the subject's network send run under this deadline. Negative curl requests also
use its connection and total timeouts. Readiness keeps its 60-second window and
one-second polling interval; collector flushing still waits two seconds and Docker
still receives its existing 20-second graceful-stop interval. Product delivery
deadlines are unchanged.

A timed-out command exits 124 and keeps its stdout/stderr. INT or TERM stops the
helper's own command process group and reaps its direct child. The suite's EXIT
cleanup removes containers and the network only by the exact names registered
before their creation, with bounded Docker calls and visible cleanup failures.
Collector stop/copy failures remain failures, and their logs stay in the output
directory beside the intact comparison and negative-control evidence.

`test_command.py` contains normal Python unittest regressions for output/status
preservation, timeout and TERM cleanup. It is separate from the real-collector
suite and introduces no CI check or alternate conformance verdict.
