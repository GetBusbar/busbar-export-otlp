<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-export-otlp

First-party signed kind:export plugin cdylib: the OTLP trace export sink (module: otlp), packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and name it from an export.<name>.module: otlp block.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `export` | `otlp` | `busbar-export-otlp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-export-otlp` is a `kind: export` busbar plugin.

## Config

Configured from an `export.<name>.module: otlp` block. Its `settings:` are:

- `url` (required): the OTLP/HTTP traces endpoint, e.g. `https://collector.example:4318/v1/traces`. It must be `https://`; plaintext `http://` is allowed only to a loopback collector. Userinfo in the url (`https://user:pass@collector/…`) is not sent in the url: it becomes an `Authorization: Basic` header, and every log line masks it. A url whose credential holds an unescaped `/`, `?` or `#` is refused as ambiguous; percent-encode it (`%2F`, `%3F`, `%23`).

One instance per config: a second `module: otlp` export is refused, because OTLP installs the one process-global tracer subscriber.

## Build

```bash
cargo build --release -p busbar-export-otlp-plugin --features dropped-in
```

## Tests

```bash
cargo test --workspace --locked
```

### Conformance

`bash testing/conformance/run.sh` runs every suite listed in `testing/conformance/suites.tsv` (here one, `otlp`) against busbar at the commit in `.busbar-ref`, and writes one verdict per suite to `target/conformance/verdicts/<id>.json`; it exits 0 only when every suite passed. `--selftest` checks the verdict judge against planted verdicts. It needs docker for the suite and fetches pinned `rust` and `node` toolchains (`testing/conformance/tools.sh`) when they are not on `PATH`.

`testing/otlp-conformance/run.sh` is the `otlp` suite: the plugin's request builder against the official OpenTelemetry Collector (contrib 0.163.2, pinned by image digest). Three legs, all of which must hold:

- control: `telemetrygen` (0.163.0, pinned by digest) sends traces, metrics and logs over OTLP/HTTP and OTLP/gRPC to the collector, and all of it must arrive well formed.
- negative control: a corrupt protobuf body (garbage and truncated) and a wrong or unusable content-type must be answered with a 4xx and write nothing, and the span comparison must catch each of a set of planted losses (a dropped attribute, a shifted timestamp, a changed id).
- subject: a driver built from this repo's `export-otlp` crate against busbar at the pin builds the request for `testing/otlp-conformance/fixture.jsonl` and POSTs it to the collector; the collector's file output is compared with what the fixture says must arrive (ids, names, timestamps, typed attributes, events, status, resource and scope).

The plugin exports traces only, so metrics and logs are covered by the control alone.

## License

Apache-2.0. See [LICENSE](LICENSE).
