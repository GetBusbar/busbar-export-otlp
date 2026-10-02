<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-export-otlp

First-party signed kind:export plugin cdylib: the OTLP trace export sink (module: otlp), packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and name it from an export.<name>.module: otlp block.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `export` | `otlp` | `busbar-export-otlp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | MIT |

[![ci](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-export-otlp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-export-otlp` is a `kind: export` busbar plugin.

## Config

Configured under the `otlp` module name.

## Build

```bash
cargo build --release -p busbar-export-otlp-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
