// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SCAFFOLD self-tests: assert the skeleton contract (`open` reports unimplemented rather than
//! silently succeeding, and the declared stream is stable). Replaced by the real behavioral suite
//! when the sink logic is extracted from busbar-core.

use super::*;

/// `Box<dyn ExportHandler>` is not `Debug`, so `Result::expect_err` can't be used on `open`'s
/// return; unwrap the error by hand instead.
fn expect_err(result: Result<Box<dyn ExportHandler>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn open_is_unimplemented_scaffold() {
    let err = expect_err(open("{}"));
    assert!(
        err.contains("unimplemented") && err.contains("otlp"),
        "error should name itself a scaffold for the otlp sink: {err}"
    );
}

#[test]
fn malformed_config_is_rejected_before_unimplemented() {
    let err = expect_err(open("{ not json"));
    assert!(
        err.contains("invalid otlp export plugin config"),
        "error should name the config as invalid: {err}"
    );
}

#[test]
fn declares_its_stream() {
    assert_eq!(Sink.streams(), vec![ExportStream::Traces]);
}
