// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's private pieces, tested where they are private.

use super::batch_body;

/// The messages logged while `f` runs on this thread.
fn logged(f: impl FnOnce()) -> Vec<String> {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Message(String);
    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().expect("lock").push(message.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(Arc::clone(&lines)), f);
    let lines = lines.lock().expect("lock").clone();
    lines
}

/// A line that is not JSON is logged as such, not as a record with no span identity; JSON without
/// ids keeps the identity line. RED before the fix: both lines said "no span identity".
#[test]
fn a_line_that_is_not_json_is_logged_as_not_json() {
    let batch = b"this is not json\n{\"name\":\"json without ids\"}\n";
    let lines = logged(|| {
        assert_eq!(batch_body(batch), None);
    });
    assert_eq!(
        lines,
        [
            "OTLP span export skipped a line that is not JSON",
            "OTLP span export skipped a record with no span identity",
        ]
    );
}
