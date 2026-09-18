// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-export-otlp-plugin` cdylib, loaded the way a REAL operator loads a plugin —
//! pack the built cdylib into a signed tarball, drop it into a real `plugins.dir`, and run the REAL
//! `busbar --validate` binary against an `export.<name>.module: otlp` config (mirrors
//! `GetBusbar/store-sqlite`'s `store-sqlite-plugin/tests/e2e.rs`).
//!
//! SCAFFOLD: the real over-the-ABI e2e lands with the sink extraction (an `unimplemented` `open`
//! has nothing to exercise across the loader yet). Kept as an ignored placeholder so the harness and
//! its `busbar-plugin-loader` dev-dependency are wired from day one.

#[test]
#[ignore = "scaffold: real dlopen/--validate e2e lands with the byte-identical sink extraction"]
fn load_and_exercise_otlp_plugin_via_file_drop() {
    // TODO(extraction): pack -> drop into plugins.dir -> `busbar --validate` with
    // `export.<name>.module: otlp`, then assert the sink's real behavior/output byte-for-byte.
}
