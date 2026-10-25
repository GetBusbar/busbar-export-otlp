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
/// nor the "OTLP tracing enabled" line, and the dropped-export line names the OLD endpoint.
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
        "a stale refusal is one line naming the old endpoint, with no settling line"
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

/// The (level, message) of every event logged while `f` runs on this thread.
fn levelled(f: impl FnOnce()) -> Vec<(tracing::Level, String)> {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<(tracing::Level, String)>>>);
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
            let level = *event.metadata().level();
            self.0.lock().expect("lock").push((level, message.0));
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(Arc::clone(&lines)), f);
    let lines = lines.lock().expect("lock").clone();
    lines
}

/// RED before: a failed or non-2xx export was logged at DEBUG, so at the default level a lost batch
/// said nothing. Every dropped export is a WARN line, as the request-log siblings warn theirs.
#[test]
fn a_dropped_export_is_a_warn_line() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(Endpoint {
            shown: "https://c.example/v1/traces".into(),
            ..Endpoint::default()
        })),
    };
    let run = otlp.run();
    // The first answer settles the run (admitted); the next two are drops.
    let ok = Ok(ExchangeResponse {
        status: 200,
        ..ExchangeResponse::default()
    });
    otlp.settle(&run, &ok);
    let non_2xx = Ok(ExchangeResponse {
        status: 503,
        ..ExchangeResponse::default()
    });
    let failed = Err(ConnFailure::Failed("connection reset".into()));
    let lines = levelled(|| {
        otlp.settle(&run, &non_2xx);
        otlp.settle(&run, &failed);
    });
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .all(|(level, _)| *level == tracing::Level::WARN),
        "{lines:?}"
    );
}

/// RED before: empty settings were refused as JSON that ended early ("EOF while parsing"), not for
/// the missing `url` — the SDK reads empty settings as `{}`, as the request-log siblings do.
#[test]
fn empty_settings_are_refused_for_the_missing_url() {
    use busbar_contract::abi::sdk::life::Life;
    let refusal = Otlp::validate(b"").expect_err("refused");
    assert_eq!(refusal.text(), Some("settings: missing field `url`"));
    assert!(Otlp::open(b"", &[], 1).is_err());
}

/// OWNER RULING 2026-10-24, RED before: a url that parses but reads its credential as host and
/// path (`https://tok/en@host`, `https://u:123/x@host`) was taken, so the credential was dialled as
/// a host and written into lines. It is refused at validate, open and refresh (a refused refresh
/// keeps the old endpoint), naming the problem, the credential cut from the url it shows.
#[test]
fn an_ambiguous_url_is_refused_without_its_credential() {
    use busbar_contract::abi::sdk::life::Life;
    for (url, secret) in [
        ("https://tok/en@collector.example/v1/traces", "tok/en"),
        ("https://u:123/x@collector.example/v1/traces", "u:123/x"),
        ("https://collector.example/v1/traces?k=a@b", "k=a"),
    ] {
        let settings = serde_json::json!({ "url": url }).to_string();
        let refusal = Otlp::validate(settings.as_bytes()).expect_err(url);
        let text = refusal.text().expect("a refusal says why");
        assert!(text.contains("is ambiguous"), "{text}");
        assert!(text.contains("%2F"), "{text}");
        assert!(!text.contains(secret), "{url}: {text}");
        assert!(Otlp::open(settings.as_bytes(), &[], 1).is_err(), "{url}");

        let otlp = Otlp::open(br#"{"url":"https://ok.example/v1/traces"}"#, &[], 1).expect("opens");
        assert!(otlp.refresh(settings.as_bytes(), &[], 2).is_err(), "{url}");
        assert_eq!(otlp.endpoint().shown, "https://ok.example/v1/traces");
    }
    // A credential written as the URL grammar wants it is taken.
    for url in [
        "https://u:p@collector.example/v1/traces",
        "https://tok%2Fen@collector.example/v1/traces",
        "http://127.0.0.1:4318/v1/traces",
        "https://collector.example/v1/%40traces",
    ] {
        let settings = serde_json::json!({ "url": url }).to_string();
        assert!(Otlp::validate(settings.as_bytes()).is_ok(), "{url}");
    }
}

/// RED before: `serve` answered a bare REFUSED. It now says why, in the words every export sibling
/// uses.
#[test]
fn every_refusal_names_its_cause_through_the_door() {
    use super::NO_ROUTE;
    use busbar_contract::abi::export::{slot as kind, Ops, ServeIn, ServeOut};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::test_support::reply::{call_in, close_in};
    use busbar_contract::abi::sdk::test_support::test_in::TestIn;
    use busbar_contract::abi::sdk::test_support::{zeroed, DoorView};

    let view = DoorView::of(super::MACRO_DOOR);
    let op =
        |pick: fn(&'static Ops) -> &'static Option<busbar_contract::abi::mechanism::call::Op>| {
            view.op::<Ops>(pick).expect("the slot is stated")
        };
    let head = || {
        let mut h: OutHead = zeroed();
        h.size = std::mem::size_of::<OutHead>() as u32;
        h
    };

    // `deliver` / `check` with no instance answer NO_INSTANCE; neither the host nor the test kit
    // enters a kind op on no instance (`reply::call_in` asserts it), so that arm is not driven.
    let mut opened = call_in(
        op(|t| &t.head.open),
        None,
        &TestIn::<OpenIn>::new()
            .set(|i| &i.head.op, slot::OPEN)
            .settings(br#"{"url":"https://c.example/v1/traces"}"#),
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("an instance");
    // `scrape` is driven over the loader (the plugin crate's conformance test): the test kit copies
    // no `ScrapeOut`.
    let c = call_in(
        op(|t| &t.serve),
        Some(&instance),
        &TestIn::<ServeIn>::new().set(|i| &i.head.op, kind::SERVE),
        zeroed::<ServeOut>(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(NO_ROUTE));
    let closed = close_in(
        op(|t| &t.head.close),
        instance,
        &TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE),
        head(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
}
