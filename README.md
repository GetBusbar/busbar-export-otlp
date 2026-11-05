<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-export-otlp

First-party signed kind:export plugin cdylib: the OTLP trace export sink (module: otlp), packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and name it from an export.<name>.module: otlp block.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `export` | `otlp` | `busbar-export-otlp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-export-otlp` sends the `traces` stream to an OTLP/HTTP protobuf collector. Each batch
becomes one request with resource `service.name = busbar` and scope `busbar`. Full span records
preserve typed attributes, events, nanosecond timestamps and error status.

The host's exact one-member JSON markers `{"$busbar_f64":"NaN"}`,
`{"$busbar_f64":"inf"}` and `{"$busbar_f64":"-inf"}` become OTLP double values,
preserving non-finite attributes. Ordinary strings and other objects keep their existing encoding.

Exports are never retried. A connector refusal on the first delivery disables the run until
reload; a transport failure or non-2xx response drops that batch. `OTLP tracing enabled` means
the host admitted the connection, and can accompany a collector error status. Collector partial
rejections report the rejected count; collector warnings report their message. Malformed or
oversized 2xx replies warn that partial-success details are unavailable, without assuming the
whole batch was rejected.

Diagnostics are `BUSBAR-7140` (disabled), `7141` (non-2xx), `7142` (delivery failure), `7143`
(partial rejection), `7144` (skipped record), and `7145` (collector warning). Foreign error text is
scrubbed and quoted; collector messages are also capped after scrubbing.

## Config

Configured from an `export.<name>.module: otlp` block. Its `settings:` are:

- `url` (required): the OTLP/HTTP traces endpoint, e.g. `https://collector.example:4318/v1/traces`. It must be `https://`; plaintext `http://` is allowed only to a loopback collector. Userinfo in the url (`https://user:pass@collector/…`) is not sent in the url: it becomes an `Authorization: Basic` header, and every log line masks it. A url whose credential holds an unescaped `/`, `?` or `#` is refused as ambiguous; percent-encode it (`%2F`, `%3F`, `%23`).

Multiple named `module: otlp` exports can send traces to independent collectors. The host owns
one shared trace producer; each export instance has its own endpoint and delivery state.

## Differences from 1.5.5

- Multiple OTLP collector instances are supported. The old single-instance restriction belonged
  to the previous tracer setup and no longer applies to independent export sinks.

- A url whose username holds a `:` (written `%3A`, e.g. `https://us%3Aer:pass@collector/…`)
  cannot be an `Authorization: Basic` credential: RFC 7617 forbids a `:` in the user-id, since
  the collector would split the credential at it. busbar 1.5.5 sent `Basic base64(us:er:pass)`
  anyway, which a collector reads as user `us`. Now the userinfo is still cut from the url the
  host dials, no `Authorization` is sent, and opening the instance writes a warning (the userinfo
  masked) that its exports go without the credential.

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
