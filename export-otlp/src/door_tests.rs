// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's private pieces, tested where they are private.

use super::{batch_body, ConnFailure, Endpoint, Otlp};
use std::sync::{PoisonError, RwLock};

/// The messages logged while `f` runs on this thread.
fn logged(f: impl FnOnce()) -> Vec<String> {
    captured(f)
        .into_iter()
        .map(|(_, message, _)| message)
        .collect()
}

/// The (level, message, ` key=value` fields) of every event logged while `f` runs on this thread.
fn captured(f: impl FnOnce()) -> Vec<(tracing::Level, String, String)> {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<(tracing::Level, String, String)>>>);
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
            let level = *event.metadata().level();
            self.0
                .lock()
                .expect("lock")
                .push((level, message.0, message.1));
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
    let at = |url: &str| Endpoint::of(&crate::OtlpSettings { url: url.into() });
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
            tracing::Level::WARN,
            "OTLP span export failed; this batch was dropped".to_string(),
            " endpoint=https://a.example/v1/traces error=the egress class says no".to_string()
        )],
        "a stale refusal is one line naming the old endpoint, with no settling line"
    );
    assert!(
        !lines
            .iter()
            .any(|(_, m, _)| m.contains("disabling OTLP trace export")
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
    let mut text: String = all.iter().map(|(_, m, f)| format!("{m}{f}\n")).collect();
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

/// RED before: a failed or non-2xx export was logged at DEBUG, so at the default level a lost batch
/// said nothing. Every dropped export is a WARN line, as the request-log siblings warn theirs.
#[test]
fn a_dropped_export_is_a_warn_line() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(Endpoint::of(&crate::OtlpSettings {
            url: "https://c.example/v1/traces".into(),
        }))),
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
    let lines = captured(|| {
        otlp.settle(&run, &non_2xx);
        otlp.settle(&run, &failed);
    });
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .all(|(level, _, _)| *level == tracing::Level::WARN),
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

/// RED before: a url the parser cannot parse at all (`svc:pa` is no port) skipped the ambiguity
/// check, so a credential holding an unescaped `/` was silently dropped from the request. It is
/// refused, the credential cut from the words.
#[test]
fn an_unparseable_ambiguous_url_is_refused_without_its_credential() {
    use busbar_contract::abi::sdk::life::Life;
    let settings = br#"{"url":"https://svc:pa/ss@collector.example/v1/traces"}"#;
    let refusal = Otlp::validate(settings).expect_err("refused");
    let text = refusal.text().expect("a refusal says why");
    assert!(text.contains("is ambiguous"), "{text}");
    assert!(!text.contains("pa/ss") && !text.contains("svc:"), "{text}");
}

/// An `ExportTraceServiceResponse` body carrying `partial_success`, encoded by the OpenTelemetry
/// project's own types.
fn partial_success_body(rejected_spans: i64, error_message: &str) -> Vec<u8> {
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTracePartialSuccess, ExportTraceServiceResponse,
    };
    use prost::Message as _;
    ExportTraceServiceResponse {
        partial_success: Some(ExportTracePartialSuccess {
            rejected_spans,
            error_message: error_message.to_string(),
        }),
    }
    .encode_to_vec()
}

/// An admitted run at `url`, for the answers a 2xx carries.
fn admitted_run(url: &str) -> (Otlp, std::sync::Arc<super::Run>) {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let settings = crate::OtlpSettings { url: url.into() };
    let otlp = Otlp {
        run: RwLock::new(Otlp::start(Endpoint::of(&settings))),
    };
    let run = otlp.run();
    otlp.settle(
        &run,
        &Ok(ExchangeResponse {
            status: 200,
            ..ExchangeResponse::default()
        }),
    );
    (otlp, run)
}

/// RED before: a 2xx whose `partial_success` rejected spans dropped them without a word. It is one
/// warn line with the count and the collector's (scrubbed) message; an empty or undecodable 2xx
/// body stays a success with no line.
#[test]
fn a_partial_success_reply_is_a_warn_line_and_an_empty_one_is_silent() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let (otlp, run) = admitted_run("https://u:SECRETpw@c.example/v1/traces");
    let reply = |body: Vec<u8>| {
        Ok(ExchangeResponse {
            status: 200,
            body,
            ..ExchangeResponse::default()
        })
    };
    let lines = captured(|| {
        otlp.settle(&run, &reply(partial_success_body(3, "too old SECRETpw")));
    });
    assert_eq!(
        lines,
        [(
            tracing::Level::WARN,
            "OTLP collector rejected part of this batch: too old ***".to_string(),
            " endpoint=https://***@c.example/v1/traces rejected_spans=3".to_string()
        )]
    );
    // A count alone, with no message, is still a rejection.
    let lines = captured(|| otlp.settle(&run, &reply(partial_success_body(2, ""))));
    assert_eq!(lines.len(), 1, "{lines:?}");
    // Nothing rejected, an empty body, and a body that is no response: silent successes.
    for body in [
        partial_success_body(0, ""),
        Vec::new(),
        b"\xff\xff not protobuf".to_vec(),
    ] {
        let lines = captured(|| otlp.settle(&run, &reply(body.clone())));
        assert!(lines.is_empty(), "{body:?}: {lines:?}");
    }
}

/// A 2xx whose body passes the reply bound fails the exchange after its head; the batch was
/// delivered, so it is no dropped batch. A non-2xx head, or a failure with no head, stays a failure.
#[test]
fn a_2xx_reply_past_the_bound_is_still_delivered() {
    use super::{delivered_past_bound, REPLY_OVER_BOUND};
    let over = || Err(ConnFailure::Failed(REPLY_OVER_BOUND.to_string()));
    let ok = delivered_past_bound(over(), Some(200)).expect("delivered");
    assert_eq!((ok.status, ok.body.is_empty()), (200, true));
    assert!(delivered_past_bound(over(), Some(503)).is_err());
    assert!(delivered_past_bound(over(), None).is_err());
    let reset = Err(ConnFailure::Failed("connection reset".into()));
    assert!(delivered_past_bound(reset, Some(200)).is_err());
}

/// RED before: the two skipped-line notices were debug, so at the default level a dropped line said
/// nothing. A skipped line is a warn.
#[test]
fn a_skipped_line_is_a_warn_line() {
    let lines = captured(|| {
        assert_eq!(batch_body(b"not json\n{\"name\":\"no ids\"}\n"), None);
    });
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .all(|(level, _, _)| *level == tracing::Level::WARN),
        "{lines:?}"
    );
}

// ── batch_body (T1) ─────────────────────────────────────────────────────────────────────────────

/// A `traces` line for the span with id `n`.
fn line(n: u64) -> String {
    format!(
        r#"{{"trace_id":"{n:016x}","span_id":"{n:016x}","name":"s{n}","start":1,"duration_us":1}}"#
    )
}

/// The span ids (as numbers) the request `body` carries, in order.
fn span_ids(body: &[u8]) -> Vec<u64> {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message as _;
    let request = ExportTraceServiceRequest::decode(body).expect("a request");
    request.resource_spans[0].scope_spans[0]
        .spans
        .iter()
        .map(|s| u64::from_be_bytes(s.span_id.clone().try_into().expect("8 bytes")))
        .collect()
}

/// Two valid lines are two spans, in order; a valid line after a non-JSON one is still exported;
/// CRLF line endings, blank lines and a missing trailing newline change nothing.
#[test]
fn a_batch_is_split_into_its_span_lines() {
    let (a, b, c) = (line(1), line(2), line(3));
    let batches = [
        (format!("{a}\n{b}\n"), vec![1, 2]),
        (format!("{a}\n{b}"), vec![1, 2]),
        (format!("{a}\r\n{b}\r\n"), vec![1, 2]),
        (format!("{a}\r\n{b}"), vec![1, 2]),
        (format!("\n\n{a}\n\n   \n{b}\n\n"), vec![1, 2]),
        (format!("not json\n{a}\n"), vec![1]),
        (
            format!("{a}\n{{\"name\":\"no ids\"}}\nnot json\n{b}\n{c}"),
            vec![1, 2, 3],
        ),
    ];
    for (batch, want) in batches {
        let body = batch_body(batch.as_bytes()).unwrap_or_else(|| panic!("{batch:?}: no body"));
        assert_eq!(span_ids(&body), want, "{batch:?}");
    }
    assert_eq!(batch_body(b""), None);
    assert_eq!(batch_body(b"\n\r\n  \n"), None);
}

/// RED before: the collector's `partial_success` message was scrubbed with the url's parts alone, so
/// a collector echoing the request's `Authorization: Basic <token>` logged a reversible credential.
#[test]
fn a_partial_success_message_echoing_the_authorization_logs_no_token() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let (otlp, run) = admitted_run("https://opsuser:hunter2@c.example/v1/traces");
    let token = run
        .endpoint
        .target
        .authorization
        .clone()
        .and_then(|a| a.strip_prefix("Basic ").map(str::to_owned))
        .expect("a Basic authorization");
    for echo in [format!("Basic {token}"), token.clone()] {
        let reply = Ok(ExchangeResponse {
            status: 200,
            body: partial_success_body(1, &format!("bad header authorization: {echo}")),
            ..ExchangeResponse::default()
        });
        let lines = captured(|| otlp.settle(&run, &reply));
        assert_eq!(lines.len(), 1, "{lines:?}");
        let text = format!("{lines:?}");
        assert!(!text.contains(&token), "the token was logged: {text}");
    }
}

/// RED before: the collector's message was printed raw and whole (a newline forged a line, a long
/// one filled the log) and a message that is not UTF-8 made the whole answer undecodable, so the
/// rejected count was lost. The message is logged Debug-quoted and capped at 256 characters, and
/// the count is reported whatever the message bytes.
#[test]
fn a_partial_success_message_is_quoted_capped_and_need_not_be_utf8() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    let (otlp, run) = admitted_run("https://c.example/v1/traces");
    let reply = |body: Vec<u8>| {
        Ok(ExchangeResponse {
            status: 200,
            body,
            ..ExchangeResponse::default()
        })
    };
    let long = format!("a\nINJECTED{}", "x".repeat(400));
    let lines = captured(|| otlp.settle(&run, &reply(partial_success_body(1, &long))));
    assert_eq!(lines.len(), 1, "{lines:?}");
    let message = &lines[0].1;
    assert!(!message.contains('\n'), "{message:?}");
    assert!(message.contains("a\\nINJECTED"), "{message:?}");
    assert!(message.ends_with("…\""), "{message:?}");
    assert!(message.chars().count() < 256 + 80, "{message:?}");

    // `PartialSuccess { rejected_spans: 4, error_message: [0xff, 'a'] }`, by hand.
    let inner = [0x08, 0x04, 0x12, 0x02, 0xff, b'a'];
    let mut body = vec![0x0a, inner.len() as u8];
    body.extend_from_slice(&inner);
    let lines = captured(|| otlp.settle(&run, &reply(body)));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].2.contains("rejected_spans=4"), "{lines:?}");
}
