// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink's own suite: the OTLP encoding (checked against the OpenTelemetry project's generated

use super::*;
use busbar_contract::abi::sdk::exchange::Request;
use busbar_contract::abi::sdk::export::second_instances;
use busbar_contract::abi::sdk::life::{settings_as, Life};
use door::{Endpoint, Otlp};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{span::SpanKind, ResourceSpans, ScopeSpans, Span};
use prost::Message as _;
use serde_json::json;

#[test]
fn parseable_url_fragments_stay_out_of_diagnostics_even_when_echoed_separately() {
    let url = "https://collector.example/v1/traces#fragment%2Dcredential";
    assert!(ambiguous_url(url).is_none());
    assert_eq!(log_target(url), "https://collector.example/v1/traces");
    let endpoint = Endpoint::of(&OtlpSettings { url: url.into() });
    assert!(!format!("{endpoint:?}").contains("fragment"));
    let parts = secret_parts(url);
    assert_eq!(
        scrub("failure fragment%2Dcredential fragment-credential", &parts),
        "failure *** ***"
    );
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
        ..Default::default()
    }
}

/// The request the publisher's types say one span is.
fn expected(span: Span) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![kv("service.name", "busbar")],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "busbar".into(),
                    ..Default::default()
                }),
                spans: vec![span],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// Decode `bytes` with the OpenTelemetry project's own types, and require that re-encoding the
fn decoded(bytes: &[u8]) -> ExportTraceServiceRequest {
    let request = ExportTraceServiceRequest::decode(bytes).expect("an OTLP request");
    assert_eq!(request.encode_to_vec(), bytes, "the canonical encoding");
    request
}

/// A child span, every field the `traces` stream produces: each lands in its OTLP field.
#[test]
fn a_traces_record_is_one_otlp_span_every_field_in_its_place() {
    let record = json!({
        "trace_id": "000000000000002a", "span_id": "00000000000000ff",
        "parent_span_id": "000000000000002a", "name": "adhoc",
        "start": 1_700_000_000_123_456u64, "duration_us": 250,
        "pool": "p1", "ingress": "openai", "op": "chat", "lane": "l0",
        "provider": "mock", "model": "m1",
    });
    let bytes = proto::export_request([&record]).expect("a span");
    let mut trace_id = vec![0u8; 15];
    trace_id.push(0x2a);
    let span = Span {
        trace_id,
        span_id: vec![0, 0, 0, 0, 0, 0, 0, 0xff],
        parent_span_id: vec![0, 0, 0, 0, 0, 0, 0, 0x2a],
        name: "adhoc".into(),
        kind: SpanKind::Internal as i32,
        start_time_unix_nano: 1_700_000_000_123_456_000,
        end_time_unix_nano: 1_700_000_000_123_706_000,
        attributes: vec![
            kv("pool", "p1"),
            kv("ingress", "openai"),
            kv("op", "chat"),
            kv("lane", "l0"),
            kv("provider", "mock"),
            kv("model", "m1"),
        ],
        ..Default::default()
    };
    assert_eq!(decoded(&bytes), expected(span));
}

/// A root span carries no parent and only the attributes it has; an empty attribute value is
#[test]
fn a_root_span_has_no_parent_and_only_its_own_attributes() {
    let record = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000007", "name": "forward",
        "start": 5, "duration_us": 0, "pool": "", "op": "chat",
    });
    let bytes = proto::export_request([&record]).expect("a span");
    let request = decoded(&bytes);
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    assert!(span.parent_span_id.is_empty());
    assert_eq!(span.attributes, vec![kv("pool", ""), kv("op", "chat")]);
    assert_eq!(
        (span.start_time_unix_nano, span.end_time_unix_nano),
        (5000, 5000)
    );
}

#[test]
fn an_attribute_keeps_the_type_the_record_states() {
    let record = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000008", "name": "forward_once",
        "start": 5, "duration_us": 0, "pool": "p", "ingress": true, "op": 0.5, "lane": 3,
        "provider": 0, "model": -2,
    });
    let bytes = proto::export_request([&record]).expect("a span");
    let request = decoded(&bytes);
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    let typed = |key: &str, value: any_value::Value| KeyValue {
        key: key.into(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    };
    assert_eq!(
        span.attributes,
        vec![
            kv("pool", "p"),
            typed("ingress", any_value::Value::BoolValue(true)),
            typed("op", any_value::Value::DoubleValue(0.5)),
            typed("lane", any_value::Value::IntValue(3)),
            typed("provider", any_value::Value::IntValue(0)),
            typed("model", any_value::Value::IntValue(-2)),
        ]
    );
}

#[test]
fn a_full_span_record_is_the_span() {
    use opentelemetry_proto::tonic::common::v1::ArrayValue;
    use opentelemetry_proto::tonic::trace::v1::{span::Event, status::StatusCode, Status};
    let record = json!({
        "trace_id": "0000000000000001", "span_id": "0000000000000002", "name": "projected",
        "start": 1, "duration_us": 1, "pool": "projected",
        "span": {
            "trace_id": "0000000000000007", "span_id": "0000000000000008",
            "parent_span_id": "0000000000000007", "name": "forward",
            "start_ns": 1_000_000_123u64, "end_ns": 1_000_000_456u64,
            "attributes": [
                {"key": "thread.id", "value": 3},
                {"key": "target", "value": "busbar::proxy::engine"},
                {"key": "request_id", "value": "7"},
                {"key": "e.chain", "value": ["a", "b"]},
                {"key": "busy_ns", "value": 0}
            ],
            "events": [
                {"name": "broke", "time_ns": 1_000_000_200u64,
                 "attributes": [{"key": "level", "value": "ERROR"}]}
            ],
            "status": {"code": "error", "message": "boom"}
        }
    });
    let bytes = proto::export_request([&record]).expect("a span");
    let request = decoded(&bytes);
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    let typed = |key: &str, value: any_value::Value| KeyValue {
        key: key.into(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    };
    let text = |s: &str| AnyValue {
        value: Some(any_value::Value::StringValue(s.into())),
    };
    assert_eq!(span.name, "forward");
    assert_eq!(span.span_id, vec![0, 0, 0, 0, 0, 0, 0, 8]);
    assert_eq!(span.parent_span_id, vec![0, 0, 0, 0, 0, 0, 0, 7]);
    assert_eq!(
        (span.start_time_unix_nano, span.end_time_unix_nano),
        (1_000_000_123, 1_000_000_456)
    );
    assert_eq!(
        span.attributes,
        vec![
            typed("thread.id", any_value::Value::IntValue(3)),
            kv("target", "busbar::proxy::engine"),
            kv("request_id", "7"),
            typed(
                "e.chain",
                any_value::Value::ArrayValue(ArrayValue {
                    values: vec![text("a"), text("b")],
                }),
            ),
            typed("busy_ns", any_value::Value::IntValue(0)),
        ]
    );
    assert_eq!(
        span.events,
        vec![Event {
            time_unix_nano: 1_000_000_200,
            name: "broke".into(),
            attributes: vec![kv("level", "ERROR")],
            ..Default::default()
        }]
    );
    assert_eq!(
        span.status,
        Some(Status {
            message: "boom".into(),
            code: StatusCode::Error as i32,
        })
    );
}

#[test]
fn a_record_without_a_span_identity_encodes_to_nothing() {
    for record in [
        json!({"span_id": "0000000000000001", "name": "x"}),
        json!({"trace_id": "0000000000000001", "name": "x"}),
        json!({"trace_id": "0000000000000000", "span_id": "0000000000000001"}),
        json!({"trace_id": "not-hex", "span_id": "0000000000000001"}),
        json!({"trace_id": "00000000000000001", "span_id": "0000000000000001"}),
        json!({"trace_id": 1, "span_id": "0000000000000001"}),
        json!({"trace_id": "2a", "span_id": "0000000000000001"}),
        json!({"trace_id": "0000000000000001", "span_id": "ff"}),
        json!({"trace_id": "+00000000000002a", "span_id": "0000000000000001"}),
    ] {
        assert_eq!(proto::export_request([&record]), None, "{record}");
    }
}

/// A batch is ONE request: each record that is a span, in batch order; a record that is none adds
#[test]
fn a_batch_is_one_request_carrying_each_span_in_order() {
    let records = [
        json!({"trace_id": "0000000000000001", "span_id": "0000000000000002", "name": "a"}),
        json!({"name": "no identity"}),
        json!({"trace_id": "0000000000000001", "span_id": "0000000000000003", "name": "b"}),
    ];
    let request = decoded(&proto::export_request(&records).expect("two spans"));
    let spans = &request.resource_spans[0].scope_spans[0].spans;
    let names: Vec<_> = spans.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert!(!proto::is_span(&records[1]));

    assert_eq!(
        proto::export_request([&records[0]]),
        proto::export_request(&records[..1])
    );
}

/// The settings' shape refuses in the configuration grammar's words.
#[test]
fn settings_refuse_in_the_grammars_words() {
    let refusal = |s: &str| {
        Otlp::validate(s.as_bytes())
            .err()
            .map(|r| r.text().map(String::from))
    };
    assert_eq!(
        refusal(r#"{"url": "http://localhost:4318/v1/traces"}"#),
        None
    );
    assert_eq!(
        refusal(r#"{"url": "http://x/", "otlp_endpoint": "y"}"#),
        Some(Some(
            "settings: unknown field `otlp_endpoint`, expected `url`".to_string()
        ))
    );
    assert_eq!(
        refusal("{}"),
        Some(Some("settings: missing field `url`".to_string()))
    );
}

/// A delivery POSTs the batch's OTLP request — binary, to the endpoint's path, the userinfo riding
#[test]
fn a_delivery_posts_the_request_with_the_credential_moved_to_a_header() {
    let endpoint = Endpoint::of(
        &settings_as::<OtlpSettings>(
            br#"{"url":"https://us%40r:p%3Ass@collector.example:4318/v1/traces"}"#,
        )
        .expect("parses"),
    );
    assert_eq!(
        endpoint.shown,
        "https://***@collector.example:4318/v1/traces"
    );

    assert_eq!(
        endpoint.collector,
        "https://collector.example:4318/v1/traces"
    );
    let body = proto::export_request([&json!({"trace_id": "0000000000000001",
        "span_id": "0000000000000002", "name": "n", "start": 1, "duration_us": 1})])
    .expect("a span");
    let (request, sealed) = endpoint.parts(body.clone());
    assert_eq!(
        request,
        Request {
            method: b"POST".to_vec(),
            target: b"/v1/traces".to_vec(),
            // The `Authorization` rides sealed, after `content-type`.
            fields: vec![(b"content-type".to_vec(), b"application/x-protobuf".to_vec())],
            body,
            timeout_ms: 10_000,
        }
    );
    assert_eq!(sealed.len(), 1);
    assert_eq!(
        (sealed[0].0, sealed[0].1.as_slice()),
        (1, &b"authorization"[..])
    );

    assert!(endpoint
        .target
        .authorization
        .as_ref()
        .expect("held")
        .verify_eq(b"Basic dXNAcjpwOnNz"));
}

/// The request target is the endpoint's path and query.
#[test]
fn the_request_target_is_the_path_and_query() {
    for (endpoint, target) in [
        ("http://127.0.0.1:4318/v1/traces", "/v1/traces"),
        ("https://h/v1/traces?tenant=a", "/v1/traces?tenant=a"),
        ("http://localhost:4318", "/"),
        ("not a url", "/"),
    ] {
        assert_eq!(request_target(endpoint), target, "{endpoint}");
    }
}

#[test]
fn a_plus_after_percent_is_not_an_escape() {
    assert_eq!(percent_decode("ab%+41cd"), b"ab%+41cd");
    assert_eq!(
        split_credentials("https://u:ab%+41cd@collector.example/v1").1,
        Some(format!("Basic {}", base64(b"u:ab%+41cd")))
    );
}

#[test]
fn the_small_encoders_match_their_standards() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    assert_eq!(percent_decode("a%20b%zz%4"), b"a b%zz%4");
    assert_eq!(
        split_credentials("http://localhost:4318/v1/traces"),
        ("http://localhost:4318/v1/traces".into(), None)
    );
    assert_eq!(
        mask_url("https://u:p@collector.example/v1"),
        "https://***@collector.example/v1"
    );
    assert_eq!(mask_url("not a url"), "not a url");
    assert_eq!(
        mask_url("https://tok@collector.example/v1"),
        "https://***@collector.example/v1"
    );
    assert_eq!(
        mask_url("https://:p@collector.example/v1"),
        "https://***@collector.example/v1"
    );
}

/// The credential split (moved with the exporter from busbar's composition root, K9e-2): whatever
#[test]
fn every_shape_of_userinfo_leaves_the_url_for_a_basic_header() {
    let cases = [
        (
            "https://alice:s3cr3t@collector.example.com:4318/v1/traces",
            "https://collector.example.com:4318/v1/traces",
            Some("Basic YWxpY2U6czNjcjN0"),
        ),
        (
            "https://:topsecret@host:4318/v1/traces",
            "https://host:4318/v1/traces",
            Some("Basic OnRvcHNlY3JldA=="),
        ),
        (
            "https://tokenuser@host:4318/v1/traces",
            "https://host:4318/v1/traces",
            Some("Basic dG9rZW51c2VyOg=="),
        ),
        (
            "https://u:p%40ss%3Aword@host/v1/traces",
            "https://host/v1/traces",
            Some("Basic dTpwQHNzOndvcmQ="),
        ),
        (
            "https://collector.example.com:4318/v1/traces",
            "https://collector.example.com:4318/v1/traces",
            None,
        ),
        ("http://localhost:4318", "http://localhost:4318", None),
    ];
    for (endpoint, clean, authorization) in cases {
        let (got_clean, got_auth) = split_credentials(endpoint);
        assert_eq!(
            (got_clean.as_str(), got_auth.as_deref()),
            (clean, authorization),
            "{endpoint}"
        );
    }
    for (input, want) in [
        (&b"foob"[..], "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(input), want);
    }
}

/// A password with an unescaped `/`, `?` or `#` makes the url unparsable (the text before it reads as
#[test]
fn an_unescaped_delimiter_in_a_password_does_not_defeat_the_userinfo_cut() {
    for (url, secret) in [
        ("https://user:ab/cd==@collector.example/v1/traces", "ab/cd"),
        ("https://user:ab#cd==@collector.example/v1/traces", "ab#cd"),
        ("https://user:ab?cd==@collector.example/v1/traces", "ab?cd"),
    ] {
        assert!(url::Url::parse(url).is_err(), "{url} must be unparsable");
        let masked = mask_url(url);
        assert!(!masked.contains(secret), "mask_url leaked: {masked}");
        let (clean, auth) = split_credentials(url);
        assert!(!clean.contains(secret), "split_credentials leaked: {clean}");
        assert_eq!(auth, None);
        let debug = format!(
            "{:?}",
            config::OtlpSettings {
                url: url.to_string()
            }
        );
        assert!(!debug.contains(secret), "Debug leaked: {debug}");
    }
}

/// THE ONE-INSTANCE REFUSAL, byte for byte the line busbar 1.5.5's `--validate` printed for a second
#[test]
fn a_second_instance_is_refused_in_1_5_5_words() {
    let check_limits = |names: &[String]| second_instances(names, ALIAS, ONE_INSTANCE);
    assert!(check_limits(&[]).is_empty());
    assert!(check_limits(&["traces".to_string()]).is_empty());
    assert_eq!(
        check_limits(&["traces".to_string(), "again".to_string()]),
        vec![
            "export.again: a second `module: otlp` instance (already defined as 'traces'). OTLP \
             installs the ONE process-global tracer subscriber, so a second instance could only be \
             silently ignored — keep a single instance."
                .to_string()
        ]
    );
}

/// The sink states the `one_instance` mark, which is what makes the host ask its limits check while
#[test]
fn the_statement_marks_one_instance() {
    use busbar_contract::abi::mechanism::door::MARK_ONE_INSTANCE;
    assert_eq!(door::STATEMENT.marks & MARK_ONE_INSTANCE, MARK_ONE_INSTANCE);
}

#[test]
fn the_need_is_pinned_to_the_url_setting() {
    assert_eq!(door::NEEDS.len(), 1);

    let target = door::NEEDS[0].target_from;
    assert_eq!(door::TARGET_FROM, "settings.url");
    assert_eq!(target.len, door::TARGET_FROM.len());
    assert!(!target.ptr.is_null());
}

#[test]
fn no_collector_credential_renders_through_debug() {
    let raw = br#"{"url":"https://ops:hunter2@collector.example/v1/traces"}"#;
    let settings = settings_as::<OtlpSettings>(raw).expect("parses");
    let endpoint = crate::door::Endpoint::of(&settings);
    assert!(
        endpoint.target.authorization.is_some(),
        "the userinfo became an Authorization"
    );
    for text in [
        format!("{settings:?}"),
        format!("{settings:#?}"),
        format!("{endpoint:?}"),
        format!("{endpoint:#?}"),
    ] {
        assert!(!text.contains("hunter2"), "the password leaked: {text}");
        assert!(
            !text.contains("b3BzOmh1bnRlcjI"),
            "the Basic token leaked: {text}"
        );
        assert!(
            text.contains("collector.example"),
            "the host is kept: {text}"
        );
    }
}

#[test]
fn a_userinfos_escaped_octets_reach_the_collector_as_they_are() {
    let (clean, auth) = crate::split_credentials("https://u:p%FFw@collector.example/v1/traces");
    assert_eq!(clean, "https://collector.example/v1/traces");

    assert_eq!(auth.as_deref(), Some("Basic dTpw/3c="));
}

#[test]
fn an_unparsable_url_keeps_its_userinfo_out_of_lines_debug_and_the_target() {
    let url = "https://ops:hunter2@collector.example:99999/v1/traces";
    assert!(url::Url::parse(url).is_err(), "the fixture does not parse");
    assert_eq!(
        mask_url(url),
        "https://***@collector.example:99999/v1/traces"
    );
    let (collector, auth) = crate::split_credentials(url);
    assert!(!collector.contains("hunter2"), "{collector}");
    assert_eq!(auth, None);
    let raw = format!(r#"{{"url":"{url}"}}"#);
    let settings = settings_as::<OtlpSettings>(raw.as_bytes()).expect("parses");
    let endpoint = crate::door::Endpoint::of(&settings);
    for text in [format!("{endpoint:?}"), format!("{settings:?}")] {
        assert!(!text.contains("hunter2"), "{text}");
    }
}

/// A refresh that lands while a delivery is parked on the host must not let that delivery's answer
#[test]
fn a_parked_deliveries_answer_does_not_settle_a_refreshed_run() {
    use crate::abi_tests_support::{connector, host, OtlpDoor};
    use busbar_contract::abi::host::service::ServiceOut;
    use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome, FLAG_RESUME};
    use busbar_contract::abi::mechanism::ticket::HostCtx;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ESTABLISHES: AtomicUsize = AtomicUsize::new(0);
    #[allow(unsafe_code)]
    extern "C" fn establish(
        _: HostCtx,
        _: *const std::ffi::c_void,
        out: *mut ServiceOut,
    ) -> RawOutcome {
        let outcome = if ESTABLISHES.fetch_add(1, Ordering::SeqCst) == 0 {
            Outcome::Pending
        } else {
            Outcome::Refused
        };
        // SAFETY: the SDK lends the exclusively writable host service answer for this crossing.
        let out = unsafe { &mut *out };
        let error = "the test connector refuses this target";
        if outcome == Outcome::Refused {
            out.error = AbiStr {
                ptr: error.as_ptr(),
                len: error.len(),
            };
        }
        out.outcome = RawOutcome::of(outcome);
        out.outcome
    }
    let batch=br#"{"trace_id":"0000000000000001","span_id":"0000000000000002","name":"n","start":1,"duration_us":1}"#;
    let conns = connector(establish);
    let host = host(&conns);
    let instance = OtlpDoor::open(br#"{"url":"https://a.example/v1/traces"}"#, Some(&host));
    assert_eq!(instance.deliver(batch, 1, 0), Outcome::Pending);
    assert_eq!(
        instance
            .refresh(br#"{"url":"https://b.example/v1/traces"}"#)
            .outcome,
        Outcome::Ready
    );
    assert_eq!(instance.deliver(batch, 1, FLAG_RESUME), Outcome::Ready);
    assert_eq!(ESTABLISHES.load(Ordering::SeqCst), 2);
    let _ = instance.deliver(batch, 2, 0);
    assert_eq!(ESTABLISHES.load(Ordering::SeqCst),3,"a fresh delivery after the refresh reached the connector (the stale answer left the refreshed run open)");
}

/// Bad refresh settings leave the previous run active, proven by its next actual connector call.
#[test]
fn a_refresh_over_unparsable_settings_is_refused_and_changes_nothing() {
    use crate::abi_tests_support::{connector, host, OtlpDoor};
    use busbar_contract::abi::host::service::ServiceOut;
    use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::ticket::HostCtx;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ESTABLISHES: AtomicUsize = AtomicUsize::new(0);
    #[allow(unsafe_code)]
    extern "C" fn establish(
        _: HostCtx,
        _: *const std::ffi::c_void,
        out: *mut ServiceOut,
    ) -> RawOutcome {
        ESTABLISHES.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the SDK lends this exclusively writable host service answer.
        let out = unsafe { &mut *out };
        let error = "the test connector refuses this target";
        out.error = AbiStr {
            ptr: error.as_ptr(),
            len: error.len(),
        };
        out.outcome = RawOutcome::of(Outcome::Refused);
        out.outcome
    }
    let batch=br#"{"trace_id":"0000000000000001","span_id":"0000000000000002","name":"n","start":1,"duration_us":1}"#;
    let conns = connector(establish);
    let host = host(&conns);
    let instance = OtlpDoor::open(br#"{"url":"https://a.example/v1/traces"}"#, Some(&host));
    let refreshed = instance.refresh(b"{}");
    assert_eq!(
        refreshed.outcome,
        Outcome::Failed,
        "a refresh of bad settings"
    );
    assert_eq!(
        refreshed.error.as_deref(),
        Some("settings: missing field `url`")
    );
    assert_eq!(instance.deliver(batch, 1, 0), Outcome::Ready);
    assert_eq!(
        ESTABLISHES.load(Ordering::SeqCst),
        1,
        "the delivery after a refused refresh reached the connector"
    );
}

/// The `Span` the sink encodes `record` as, through the request it builds.
fn span_of(record: &serde_json::Value) -> Option<Span> {
    let bytes = proto::export_request([record])?;
    Some(decoded(&bytes).resource_spans[0].scope_spans[0].spans[0].clone())
}

fn full(extra: serde_json::Value) -> serde_json::Value {
    let mut span = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000008", "name": "n",
        "start_ns": 1, "end_ns": 2,
    });
    for (k, v) in extra.as_object().unwrap() {
        span[k] = v.clone();
    }
    json!({ "span": span })
}

/// A full span record's status: absent and `unset` are the empty status (code 0, no message); an
#[test]
fn a_full_span_records_status_is_empty_unless_it_is_an_error() {
    let status =
        |extra: serde_json::Value| span_of(&full(extra)).unwrap().status.unwrap_or_default();
    for unset in [json!({}), json!({"status": {"code": "unset"}})] {
        let s = status(unset);
        assert_eq!((s.code, s.message.as_str()), (0, ""), "{s:?}");
    }
    let s = status(json!({"status": {"code": "error"}}));
    assert_eq!((s.code, s.message.as_str()), (2, ""), "{s:?}");
    let s = status(json!({"status": {"code": "error", "message": "boom"}}));
    assert_eq!((s.code, s.message.as_str()), (2, "boom"), "{s:?}");
}

/// Real ids are high-entropy: the 16 hex digits are the exact 8 big-endian bytes (the trace id
#[test]
fn high_entropy_ids_encode_to_their_exact_bytes() {
    let tail = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    let mut trace = vec![0u8; 8];
    trace.extend_from_slice(&tail);
    let parent = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let ids = json!({
        "trace_id": "a1b2c3d4e5f60718", "span_id": "fedcba9876543210",
        "parent_span_id": "fedcba9876543210",
    });
    let mut projected = json!({"name": "n"});
    for (k, v) in ids.as_object().unwrap() {
        projected[k] = v.clone();
    }
    let spanned = json!({"span": {"name": "n", "trace_id": ids["trace_id"], "span_id": ids["span_id"],
        "parent_span_id": ids["parent_span_id"]}});
    for record in [projected, spanned] {
        let span = span_of(&record).expect("a span");
        assert_eq!(span.trace_id, trace);
        assert_eq!(span.span_id, parent);
        assert_eq!(span.parent_span_id, parent);
    }
}

/// Projected-attribute edges: a JSON null is no attribute; an integer past `i64::MAX` is an
#[test]
fn projected_attribute_and_time_edges() {
    let record = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000008", "name": "n",
        "start": u64::MAX, "duration_us": u64::MAX,
        "pool": null, "ingress": "i", "op": 18446744073709551615u64,
    });
    let span = span_of(&record).expect("a span");
    assert_eq!(
        span.attributes,
        vec![
            kv("ingress", "i"),
            KeyValue {
                key: "op".into(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::IntValue(-1)),
                }),
                ..Default::default()
            },
        ]
    );
    assert_eq!(span.start_time_unix_nano, u64::MAX);
    assert_eq!(span.end_time_unix_nano, u64::MAX);
}

/// The `span` member wins: malformed ids in it are no span even beside valid projected ids; with
#[test]
fn the_span_member_wins_over_projected_fields() {
    let bad = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000008", "name": "projected",
        "span": {"trace_id": "nothex", "span_id": "0000000000000009", "name": "full"},
    });
    assert!(span_of(&bad).is_none());
    assert!(!proto::is_span(&bad));
    assert!(proto::export_request([&bad]).is_none());
    let both = json!({
        "trace_id": "0000000000000007", "span_id": "0000000000000008", "name": "projected",
        "span": {"trace_id": "0000000000000007", "span_id": "0000000000000009", "name": "full"},
    });
    assert_eq!(span_of(&both).unwrap().name, "full");
}

#[test]
fn a_null_attribute_is_omitted_and_a_null_array_item_is_an_empty_any_value() {
    let span = span_of(&full(json!({
        "attributes": [
            {"key": "x", "value": null},
            {"key": "kept", "value": "v"},
            {"key": "arr", "value": [1, null]},
        ],
        "events": [{"name": "e", "time_ns": 1, "attributes": [{"key": "y", "value": null}]}],
    })))
    .unwrap();
    let keys: Vec<&str> = span.attributes.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys, ["kept", "arr"], "{:?}", span.attributes);
    let Some(any_value::Value::ArrayValue(array)) = span.attributes[1].value.clone().unwrap().value
    else {
        panic!("an array value");
    };
    assert_eq!(array.values.len(), 2);
    assert_eq!(array.values[0].value, Some(any_value::Value::IntValue(1)));
    assert_eq!(array.values[1].value, None);
    assert!(span.events[0].attributes.is_empty(), "{:?}", span.events);
}

#[test]
fn log_target_masks_a_credential_in_its_fall_through_branches() {
    const KEY: &str = "CANARYfall7";

    for text in [KEY.to_string(), format!("//user:{KEY}@host/v1/traces")] {
        let shown = log_target(&text);
        assert!(!shown.contains(KEY), "{text}: {shown}");
        assert_eq!(shown, "***", "{text}");
    }

    for text in [
        format!("data:text/plain,{KEY}"),
        format!("mailto:ops:{KEY}@x"),
    ] {
        assert!(url::Url::parse(&text).is_ok(), "{text} parses");
        let shown = log_target(&text);
        assert!(!shown.contains(KEY), "{text}: {shown}");

        assert!(
            shown.ends_with(":***") || (text.contains('@') && shown == "***"),
            "{text}: {shown}"
        );
    }

    let shown = log_target(&format!("https://user:{KEY}/x@host:99999/p/{KEY}"));
    assert!(!shown.contains(KEY), "{shown}");
}

#[test]
fn a_percent_encoded_credential_is_scrubbed_in_both_forms() {
    let url = "https://opsuser:CANARY%40pw9@collector.example/v1/traces";
    let parts = secret_parts(url);
    for text in [
        "error sending request for url (https://opsuser:CANARY%40pw9@collector.example/v1/traces)",
        "bad credential CANARY@pw9 for the collector",
        "bad credential CANARY%40pw9 for the collector",
    ] {
        let out = scrub(text, &parts);
        assert!(
            !out.contains("CANARY") && !out.contains("pw9"),
            "{text} -> {out}"
        );
    }
}

#[test]
fn identity_validation_preserves_uppercase_ids_and_omits_invalid_parents() {
    for full in [false, true] {
        for parent in ["0000000000000000", "short", "nothexnothexnotx", ""] {
            let source = json!({
                "trace_id": "00000000000000AB", "span_id": "00000000000000CD",
                "parent_span_id": parent, "name": "identity"
            });
            let record = if full {
                json!({"span": source})
            } else {
                source
            };
            let request =
                decoded(&proto::export_request([&record]).expect("span survives invalid parent"));
            let span = &request.resource_spans[0].scope_spans[0].spans[0];
            assert_eq!(span.trace_id, [vec![0; 15], vec![0xab]].concat());
            assert_eq!(span.span_id, [0, 0, 0, 0, 0, 0, 0, 0xcd]);
            assert!(span.parent_span_id.is_empty());
        }
        let zero = json!({"trace_id":"00000000000000ab", "span_id":"0000000000000000"});
        let zero = if full { json!({"span": zero}) } else { zero };
        assert_eq!(proto::export_request([&zero]), None);
    }
}
