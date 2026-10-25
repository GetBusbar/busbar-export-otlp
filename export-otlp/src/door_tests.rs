// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's private pieces, tested where they are private.

use super::{batch_body, ConnFailure, Endpoint, Otlp};
use std::sync::{PoisonError, RwLock};

/// The messages logged while `f` runs on this thread.
fn logged(f: impl FnOnce()) -> Vec<String> {
    captured(f)
        .into_iter()
        .map(|(message, _)| message)
        .collect()
}

/// The (message, ` key=value` fields) of every event logged while `f` runs on this thread.
fn captured(f: impl FnOnce()) -> Vec<(String, String)> {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<(String, String)>>>);
    struct Message(String, String);
    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            } else {
                self.1.push_str(&format!(" {}={value:?}", field.name()));
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
            let mut message = Message(String::new(), String::new());
            event.record(&mut message);
            self.0.lock().expect("lock").push((message.0, message.1));
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

/// A answer for a run a refresh replaced settles nothing and speaks only of that old run: the
/// connector's refusal of a parked delivery writes neither the "disabling OTLP trace export" line
/// nor the "OTLP tracing enabled" line, and the debug dropped-export line names the OLD endpoint.
#[test]
fn a_stale_refusal_writes_no_settling_line_and_names_the_old_endpoint() {
    let at = |url: &str| Endpoint {
        shown: url.into(),
        ..Endpoint::default()
    };
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(at("https://a.example/v1/traces"))),
    };
    let parked = otlp.run();
    *otlp.run.write().unwrap_or_else(PoisonError::into_inner) =
        Otlp::start(at("https://b.example/v1/traces"));

    let refusal = Err(ConnFailure::Refused("the egress class says no".into()));
    let lines = captured(|| otlp.settle(&parked, &refusal));
    assert_eq!(
        lines,
        [(
            "OTLP span export failed; this batch was dropped".to_string(),
            " endpoint=https://a.example/v1/traces error=the egress class says no".to_string()
        )],
        "a stale refusal is one debug line naming the old endpoint, with no settling line"
    );
    assert!(
        !lines
            .iter()
            .any(|(m, _)| m.contains("disabling OTLP trace export")
                || m.contains("OTLP tracing enabled")),
        "a stale answer must not write a settling line"
    );
    // Neither run was settled by it.
    assert_eq!(*parked.admitted.lock().expect("lock"), None);
    assert!(!otlp.run().refused());
}

// ── Credential-echo canaries (CREDENTIAL-LOCKDOWN H3) ────────────────────────────────────────────

const CANARY: &str = "CANARY5e81bc";

/// Every line logged while one instance's exports are carried, refused and dropped, for a target
/// whose query and path carry a key, with the host's text quoting the target back.
fn lines_for(url: &str) -> String {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let settings = crate::OtlpSettings {
        url: url.to_string(),
    };
    let reply = |status| {
        Ok(ExchangeResponse {
            status,
            ..ExchangeResponse::default()
        })
    };
    let echo = format!("error sending request for url ({url}): connection reset");
    let mut all = Vec::new();
    // One run admitted, then a non-2xx and a host failure that quotes the URL.
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(Endpoint::of(&settings))),
    };
    let run = otlp.run();
    all.extend(captured(|| {
        otlp.settle(&run, &reply(200));
        otlp.settle(&run, &reply(503));
        otlp.settle(&run, &Err(ConnFailure::Failed(echo.clone())));
    }));
    // A fresh run the host refuses, in words that quote the URL.
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(Endpoint::of(&settings))),
    };
    let run = otlp.run();
    all.extend(captured(|| {
        otlp.settle(&run, &Err(ConnFailure::Refused(echo.clone())));
    }));
    let mut text: String = all.iter().map(|(m, f)| format!("{m}{f}\n")).collect();
    text.push_str(&format!("{:?}\n{:?}\n", Endpoint::of(&settings), settings));
    text
}

/// H3: the endpoint every line names kept the target's path and query, and the host's failure text
/// was printed verbatim. A collector key in the query (`?api-key=`) or the path reached the log.
#[test]
fn no_log_line_or_debug_carries_a_key_in_the_targets_query_or_path() {
    for url in [
        format!("https://collector.example/v1/traces?api-key={CANARY}"),
        format!("https://collector.example/{CANARY}/v1/traces"),
        format!("https://u:{CANARY}@collector.example/v1/traces"),
    ] {
        let text = lines_for(&url);
        assert!(
            !text.contains(CANARY),
            "{url}: a line carried the key:\n{text}"
        );
        assert!(
            text.contains("collector.example"),
            "{url}: the host is kept:\n{text}"
        );
    }
}
