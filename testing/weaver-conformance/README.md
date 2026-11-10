# Official Weaver evaluation

`otel-semconv-weaver` runs after `otlp` in the native conformance job. It requires
that invocation's passing Collector round-trip verdict and nonempty actual plugin
span capture. It checks every captured resource, span, event and link attribute
with official Weaver v0.28.0 and OpenTelemetry semantic conventions v1.45.0.
Both archives are pinned by SHA-256; the registry also names its exact commit.

The positive control is the registry's `service.name` string. The negative control
changes only its type to integer and must produce the official `type_mismatch`
violation. The subject uses unmodified official policies and `--fail-on violation`.
Unknown/custom attributes are reported normally; no findings are suppressed and
no custom registry makes the subject pass. All improvements/information remain
in the retained report. Missing captures, failed prior OTLP checks, incomplete
reports, missing controls and actual violations exit nonzero and fail CI.

This is a sample-based trace semantic evaluation, not certification or full
instrumentation coverage. The exporter has no metrics/logs path. Weaver's JSON
sample form does not associate resources/scopes with individual spans; scope
attributes are therefore checked individually. This does not qualify semantic
requirements that depend on those associations. OTLP wire round-trip/field
preservation remains the separate `otlp` suite's responsibility.

Raw official reports, unchanged converted samples, source capture digest and the
assessment are written under `CONFORMANCE_OUT/evidence`. These are synthetic
fixture samples, not production telemetry. The full evaluation runs in CI.
Targeted local adapter tests: `python3 -B -I testing/weaver-conformance/test_run.py`.

Primary sources:
- https://github.com/open-telemetry/weaver/tree/v0.28.0
- https://github.com/open-telemetry/weaver/blob/v0.28.0/src/registry/live_check.rs
- https://github.com/open-telemetry/semantic-conventions/tree/fb30ca17193b551473b1f43c315482918ab6987c
