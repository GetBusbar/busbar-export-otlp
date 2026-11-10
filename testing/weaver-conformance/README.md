# Official Weaver evaluation

`otel-semconv-weaver` runs after `otlp` in the native conformance job. It requires
that invocation's passing Collector round-trip verdict and nonempty actual plugin
span capture. It checks every captured resource, span, event and link attribute
with official Weaver v0.28.0 and OpenTelemetry semantic conventions v1.45.0,
plus the separately declared Busbar custom registry in `registry/busbar.yaml`.
Both archives are pinned by SHA-256; the registry also names its exact commit.

The positive control is the registry's `service.name` string. The negative control
changes only its type to integer and must produce the official `type_mismatch`
violation. The subject uses unmodified official policies and `--fail-on violation`.
`--include-unreferenced` includes the official dependency's attribute definitions.
The combined-registry result validates Busbar's dynamic `busbar.*` metadata under
its explicit `template[any]` declaration; it does not establish standard OTel
semantics or a fixed value type for those custom fields. A separate base-only
official-registry report remains visible, including its custom-attribute findings.
No finding filters or severity overrides are used. All improvements/information
remain in the retained report. Missing captures, failed prior OTLP checks, incomplete
reports, missing controls and actual violations exit nonzero and fail CI.

This is a sample-based trace/extension evaluation, not certification or full
instrumentation coverage. The exporter has no metrics/logs path. Weaver's JSON
sample form does not associate resources/scopes with individual spans; scope
attributes are therefore checked individually. This does not qualify semantic
requirements that depend on those associations. OTLP wire round-trip/field
preservation remains the separate `otlp` suite's responsibility.

Raw official reports, unchanged converted samples, source capture digest and the
assessment are written under `CONFORMANCE_OUT/evidence`. These are synthetic
fixture samples, not production telemetry. The full evaluation runs in CI.
Targeted local adapter tests: `python3 -B -I testing/weaver-conformance/test_run.py`.

The exporter places bare projected/tracing attribute keys in `busbar.*`; qualified
standard/custom keys keep their names. All values retain their original types.
When a caller supplies both `pool` and `busbar.pool`, the bare key becomes
`busbar.original.706f6f6c` (UTF-8 hex of `pool`) instead of overwriting the other
attribute. Additional `.original` suffixes resolve an already occupied escape
name. This naming is part of the 1.6.0 exporter wire contract; OTLP round-trip
checks independently verify it for projected fields, full spans and events.

Primary sources:
- https://github.com/open-telemetry/weaver/tree/v0.28.0
- https://github.com/open-telemetry/weaver/blob/v0.28.0/src/registry/live_check.rs
- https://github.com/open-telemetry/semantic-conventions/tree/fb30ca17193b551473b1f43c315482918ab6987c
