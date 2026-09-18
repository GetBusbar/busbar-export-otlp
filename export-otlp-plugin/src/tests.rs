// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for THIS crate's own responsibility: adapting the engine's JSON config and delegating
//! to the core sink. SCAFFOLD — asserts the adapter surfaces the core crate's `unimplemented` cleanly
//! (never a panic across the seam). The real over-the-ABI dlopen coverage lives in `tests/e2e.rs`.

use super::open;
use busbar_plugin_sdk::ExportHandler;

/// `Box<dyn ExportHandler>` is not `Debug`, so unwrap the error arm by hand rather than `expect_err`.
fn expect_err(result: Result<Box<dyn ExportHandler>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn open_delegates_and_reports_unimplemented() {
    let err = expect_err(open("{}"));
    assert!(
        err.contains("unimplemented"),
        "adapter should relay the core scaffold error verbatim: {err}"
    );
}
