// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **otlp export sink as a droppable busbar plugin** — a `cdylib` that exports the neutral
//! six-symbol C ABI at `kind: export`. Build it, drop the resulting `.so`/`.dll`/`.dylib` into the
//! engine's plugins folder, and name it from an `export.<name>.module: otlp` config block; the
//! engine loads it in-process at boot.
//!
//! This crate is deliberately tiny: all the sink logic lives in the `busbar-export-otlp` `lib` crate. Here we
//! only adapt the engine's JSON config into a sink and hand the trait object to the SDK, which emits
//! the six extern-C symbols the loader resolves via [`busbar_plugin_sdk::export_export_plugin`].
//!
//! SCAFFOLD: [`open`] delegates to `busbar-export-otlp::open`, which reports `unimplemented` until the
//! byte-identical sink extraction from busbar-core lands (busbar 1.6.0 DECISIONS #3, oracle-gated).

use busbar_plugin_sdk::ExportHandler;

/// Construct the otlp export sink from the JSON config the engine passes through `open` (COLD/JSON
/// lane — serde_json, same posture as the store plugins). SCAFFOLD: delegates to the core crate,
/// which returns `unimplemented` until the sink logic is extracted.
fn open(cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    busbar_export_otlp::open(cfg)
}

busbar_plugin_sdk::export_export_plugin!(open);

#[cfg(test)]
mod tests;
