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

## License

Apache-2.0. See [LICENSE](LICENSE).
