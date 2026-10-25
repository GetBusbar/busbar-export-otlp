// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink's own suite: the OTLP encoding (checked against the OpenTelemetry project's generated
//! types), the settings refusals, and the request each delivery sends. The same crate through both
//! doors is proven by `busbar-export-otlp-plugin`'s conformance test.

use super::*;
use busbar_contract::abi::sdk::exchange::Request;
use busbar_contract::abi::sdk::life::Life;
use door::{Endpoint, Otlp};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{span::SpanKind, ResourceSpans, ScopeSpans, Span};
use prost::Message as _;
use serde_json::json;

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
/// decoded message reproduces them BYTE FOR BYTE — so the encoding is the proto's canonical one,
/// not merely one a lenient decoder accepts.
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
/// still the attribute (its `oneof` member is set).
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

/// AN ATTRIBUTE KEEPS ITS TYPE (busbar status row 173): a record's integer is an `int_value`
/// (1.5.5's exporter wrote `forward_once`'s `lane = i` so), its boolean a `bool_value`, its float a
/// `double_value`, each written even at its default; a string stays a `string_value`. RED before the
/// sink typed them: every value was its text.
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

/// THE FULL SPAN RECORD (busbar status row 173): a line carrying the host's `span` member is
/// encoded from it alone: its ns start and end, its attributes in its order and types (an array an
/// `array_value`), its events and its status, whatever projected fields the line also carries.
/// RED before the sink read it: the span was the projected fields' (µs times, string attributes,
/// no events, no status).
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

/// RED ARM: a record without a usable span identity is no span — nothing is encoded.
#[test]
fn a_record_without_a_span_identity_encodes_to_nothing() {
    for record in [
        json!({"span_id": "0000000000000001", "name": "x"}),
        json!({"trace_id": "0000000000000001", "name": "x"}),
        json!({"trace_id": "0000000000000000", "span_id": "0000000000000001"}),
        json!({"trace_id": "not-hex", "span_id": "0000000000000001"}),
        json!({"trace_id": "00000000000000001", "span_id": "0000000000000001"}),
        json!({"trace_id": 1, "span_id": "0000000000000001"}),
        // Not EXACTLY 16 hex digits (Q128 export-otlp NIT, reader r61): short, and a leading `+`.
        json!({"trace_id": "2a", "span_id": "0000000000000001"}),
        json!({"trace_id": "0000000000000001", "span_id": "ff"}),
        json!({"trace_id": "+00000000000002a", "span_id": "0000000000000001"}),
    ] {
        assert_eq!(proto::export_request([&record]), None, "{record}");
    }
}

/// A batch is ONE request: each record that is a span, in batch order; a record that is none adds
/// nothing.
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
    // One record encodes exactly as a batch of one.
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
/// as `Authorization: Basic` instead; every line names the endpoint masked.
#[test]
fn a_delivery_posts_the_request_with_the_credential_moved_to_a_header() {
    let endpoint = Endpoint::of(
        &OtlpSettings::parse(
            br#"{"url":"https://us%40r:p%3Ass@collector.example:4318/v1/traces"}"#,
        )
        .expect("parses"),
    );
    assert_eq!(
        endpoint.shown,
        "https://***@collector.example:4318/v1/traces"
    );
    // The collector the host dials carries no userinfo: the credential is only the header's.
    assert_eq!(
        endpoint.collector.as_deref(),
        Some("https://collector.example:4318/v1/traces")
    );
    let body = proto::export_request([&json!({"trace_id": "0000000000000001",
        "span_id": "0000000000000002", "name": "n", "start": 1, "duration_us": 1})])
    .expect("a span");
    assert_eq!(
        endpoint.request(body.clone()),
        Some(Request {
            method: b"POST".to_vec(),
            target: b"/v1/traces".to_vec(),
            fields: vec![
                (b"content-type".to_vec(), b"application/x-protobuf".to_vec()),
                // base64("us@r:p:ss")
                (b"authorization".to_vec(), b"Basic dXNAcjpwOnNz".to_vec()),
            ],
            body,
            timeout_ms: 10_000,
        })
    );
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

/// EOTLP-1: `from_str_radix` accepts a leading `+`, so `%+4` must stay literal (1.5.5 bytes).
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
        mask_userinfo("https://u:p@collector.example/v1"),
        "https://***@collector.example/v1"
    );
    assert_eq!(mask_userinfo("not a url"), "not a url");
    assert_eq!(
        mask_userinfo("https://tok@collector.example/v1"),
        "https://***@collector.example/v1"
    );
    assert_eq!(
        mask_userinfo("https://:p@collector.example/v1"),
        "https://***@collector.example/v1"
    );
}

/// The credential split (moved with the exporter from busbar's composition root, K9e-2): whatever
/// userinfo the endpoint carries — both halves, the password alone, the user alone, percent-encoded
/// — leaves the URL and becomes `Authorization: Basic base64(user:pass)`; an endpoint with none is
/// untouched and authenticates with nothing.
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
/// a port) and ends a first-delimiter "authority" inside the password: the userinfo cut must still
/// remove the whole password from the log form, the dial target and the settings Debug.
#[test]
fn an_unescaped_delimiter_in_a_password_does_not_defeat_the_userinfo_cut() {
    for (url, secret) in [
        ("https://user:ab/cd==@collector.example/v1/traces", "ab/cd"),
        ("https://user:ab#cd==@collector.example/v1/traces", "ab#cd"),
        ("https://user:ab?cd==@collector.example/v1/traces", "ab?cd"),
    ] {
        assert!(url::Url::parse(url).is_err(), "{url} must be unparsable");
        let masked = mask_userinfo(url);
        assert!(!masked.contains(secret), "mask_userinfo leaked: {masked}");
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
/// `module: otlp` instance (busbar `tests/v1.5.5-validate/refusals.txt`): one line per instance after
/// the first, naming the first; one instance, or none, is no finding.
#[test]
fn a_second_instance_is_refused_in_1_5_5_words() {
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
/// the configuration is resolved.
#[test]
fn the_statement_marks_one_instance() {
    use busbar_contract::abi::mechanism::door::MARK_ONE_INSTANCE;
    assert_eq!(door::STATEMENT.marks & MARK_ONE_INSTANCE, MARK_ONE_INSTANCE);
}

/// THE NEED IS HELD TO THE OPERATOR'S COLLECTOR (THE DESIGN §5, PB-100: "Every declared need is held
/// to its configured target: the loader's connection-table fill resolves a need's `target_from`
/// against the instance's validated settings at open and refresh and declares the need pinned to
/// that target"). The need names the `url` setting, so the host pins it to the collector the
/// operator configured (its userinfo left out by the connector) and refuses a dial to any other
/// host; a need with no `target_from` let the sink name its own dial target on every export.
#[test]
fn the_need_is_pinned_to_the_url_setting() {
    assert_eq!(door::NEEDS.len(), 1);
    assert_eq!(
        door::NEEDS[0].target_from.len,
        "settings.url".len(),
        "the collector need names no configured target"
    );
}

/// NO COLLECTOR CREDENTIAL RENDERS THROUGH `Debug` (Q128 export-otlp LOW, reader r82 on ba8cf38):
/// the settings' url, the endpoint and the instance holding it mask the url's userinfo and redact
/// the `Authorization` it became. RED before the fix: `Debug` was derived over the raw url and the
/// decoded Basic token.
#[test]
fn no_collector_credential_renders_through_debug() {
    let raw = br#"{"url":"https://ops:hunter2@collector.example/v1/traces"}"#;
    let settings = crate::config::OtlpSettings::parse(raw).expect("parses");
    let endpoint = crate::door::Endpoint::of(&settings);
    assert!(
        endpoint.target.as_ref().is_some_and(|(_, a)| a.is_some()),
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

/// A USERINFO's PERCENT-ESCAPED OCTETS REACH THE COLLECTOR AS THEY ARE (Q128 export-otlp LOW, reader
/// r91 on a776bd3; RFC 7617: the user-pass is an octet sequence; RFC 3986 percent-escapes encode
/// octets): `p%FFw` is the bytes `p 0xFF w`, base64ed as written. RED before the fix: the octets
/// went through a lossy UTF-8 reading, and `0xFF` reached the collector as `EF BF BD`.
#[test]
fn a_userinfos_escaped_octets_reach_the_collector_as_they_are() {
    let (clean, auth) = crate::split_credentials("https://u:p%FFw@collector.example/v1/traces");
    assert_eq!(clean, "https://collector.example/v1/traces");
    // base64("u:p\xFFw") = "dTpw/3c=".
    assert_eq!(auth.as_deref(), Some("Basic dTpw/3c="));
}

/// A URL THAT DOES NOT PARSE STILL KEEPS ITS USERINFO OUT OF EVERY LINE AND THE DIAL TARGET (Q128
/// export-otlp LOW, reader r131 on d26b358): 1.5.5 accepted any string as the url, so one that
/// carries `user:pass` but fails to parse (an out-of-range port) is masked by cutting at the
/// authority's last `@`, in the lines, in `Debug` and in the collector handed to the host. RED
/// before the fix: the password rode all three.
#[test]
fn an_unparsable_url_keeps_its_userinfo_out_of_lines_debug_and_the_target() {
    let url = "https://ops:hunter2@collector.example:99999/v1/traces";
    assert!(url::Url::parse(url).is_err(), "the fixture does not parse");
    assert_eq!(
        crate::mask_userinfo(url),
        "https://***@collector.example:99999/v1/traces"
    );
    let (collector, auth) = crate::split_credentials(url);
    assert!(!collector.contains("hunter2"), "{collector}");
    assert_eq!(auth, None);
    let raw = format!(r#"{{"url":"{url}"}}"#);
    let settings = crate::config::OtlpSettings::parse(raw.as_bytes()).expect("parses");
    let endpoint = crate::door::Endpoint::of(&settings);
    for text in [format!("{endpoint:?}"), format!("{settings:?}")] {
        assert!(!text.contains("hunter2"), "{text}");
    }
}

/// A refresh that lands while a delivery is parked on the host must not let that delivery's answer
/// settle the NEW run (design A). The connector double pends the first ESTABLISH and refuses the
/// resume of it; after a refresh to another collector, a fresh delivery must still reach the
/// connector. RED before the fix: the stale refusal disabled the refreshed run, so no ESTABLISH.
#[test]
fn a_parked_deliveries_answer_does_not_settle_a_refreshed_run() {
    use busbar_contract::abi::export::{DeliverIn, Ops};
    use busbar_contract::abi::host::conn::connector::EstablishIn;
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, BLOB_JSONL, FLAG_RESUME};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use busbar_contract::abi::sdk::test_support::reply::{call_hosted_in, call_in};
    use busbar_contract::abi::sdk::test_support::test_in::TestIn;
    use busbar_contract::abi::sdk::test_support::{zeroed, DoorView};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ESTABLISHES: AtomicUsize = AtomicUsize::new(0);

    /// The connector: the first ESTABLISH pends, every later one (the resume's included) is refused.
    struct Connector;
    impl FakeService for Connector {
        type In = EstablishIn;
        fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
            if ESTABLISHES.fetch_add(1, Ordering::SeqCst) == 0 {
                return Outcome::Pending;
            }
            call.set_error("the test connector refuses this target");
            Outcome::Refused
        }
    }

    let batch = br#"{"trace_id":"0000000000000001","span_id":"0000000000000002","name":"n","start":1,"duration_us":1}"#;
    let view = DoorView::of(door::MACRO_DOOR);
    let op =
        |pick: fn(&'static Ops) -> &'static Option<busbar_contract::abi::mechanism::call::Op>| {
            view.op::<Ops>(pick).expect("the door states the slot")
        };
    let host = FakeHost::new().serve(fake::conn::ESTABLISH, Connector);

    let a = br#"{"url":"https://a.example/v1/traces"}"#;
    let open_in = TestIn::<OpenIn>::new()
        .set(|i| &i.head.op, slot::OPEN)
        .settings(a);
    let mut opened = call_hosted_in(
        op(|t| &t.head.open),
        None,
        &host.lend_in(open_in),
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("open answered an instance");

    let deliver_slot = op(|t| &t.deliver).index();
    let deliver = |ticket: u32, flags: u32| {
        let input = TestIn::<DeliverIn>::new()
            .set(|i| &i.head.op, deliver_slot)
            .set(|i| &i.head.flags, flags)
            .set(
                |i| &i.head.ticket,
                Ticket {
                    slot: ticket,
                    generation: 1,
                },
            )
            .blob(|i| &i.batch, batch, BLOB_JSONL);
        call_in(
            op(|t| &t.deliver),
            Some(&instance),
            &input,
            zeroed::<OutHead>(),
        )
        .outcome
    };

    // Delivery 1 parks on the host (the first ESTABLISH pends) ...
    assert_eq!(deliver(1, 0), Outcome::Pending);
    // ... a refresh moves the collector while it is parked ...
    let b = br#"{"url":"https://b.example/v1/traces"}"#;
    let refresh_in = TestIn::<RefreshIn>::new()
        .set(|i| &i.head.op, slot::REFRESH)
        .settings(b);
    let refreshed = call_in(
        op(|t| &t.head.refresh),
        Some(&instance),
        &refresh_in,
        zeroed::<OutHead>(),
    );
    assert_eq!(refreshed.outcome, Outcome::Ready);
    // ... and the host resumes delivery 1: its connector refuses it.
    assert_eq!(deliver(1, FLAG_RESUME), Outcome::Ready);
    assert_eq!(ESTABLISHES.load(Ordering::SeqCst), 2);

    // The refresh made a new run: a fresh delivery reaches the connector again.
    let _ = deliver(2, 0);
    assert_eq!(
        ESTABLISHES.load(Ordering::SeqCst),
        3,
        "a fresh delivery after the refresh reached the connector (the stale answer left the refreshed run open)"
    );
}

/// A refresh over settings that do not parse is refused in `validate`'s words and leaves the
/// instance as it was (design B). RED before the fix: the refresh answered READY and replaced the
/// working endpoint with one that sends nothing, so no later delivery reached the connector.
#[test]
fn a_refresh_over_unparsable_settings_is_refused_and_changes_nothing() {
    use busbar_contract::abi::export::{DeliverIn, Ops};
    use busbar_contract::abi::host::conn::connector::EstablishIn;
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, BLOB_JSONL};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use busbar_contract::abi::sdk::test_support::reply::{call_hosted_in, call_in};
    use busbar_contract::abi::sdk::test_support::test_in::TestIn;
    use busbar_contract::abi::sdk::test_support::{zeroed, DoorView};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ESTABLISHES: AtomicUsize = AtomicUsize::new(0);

    /// The connector: counts the dials it is asked for, refusing each.
    struct Connector;
    impl FakeService for Connector {
        type In = EstablishIn;
        fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
            ESTABLISHES.fetch_add(1, Ordering::SeqCst);
            call.set_error("the test connector refuses this target");
            Outcome::Refused
        }
    }

    let batch = br#"{"trace_id":"0000000000000001","span_id":"0000000000000002","name":"n","start":1,"duration_us":1}"#;
    let view = DoorView::of(door::MACRO_DOOR);
    let host = FakeHost::new().serve(fake::conn::ESTABLISH, Connector);
    let good = br#"{"url":"https://a.example/v1/traces"}"#;
    let open_in = TestIn::<OpenIn>::new()
        .set(|i| &i.head.op, slot::OPEN)
        .settings(good);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let mut opened = call_hosted_in(open, None, &host.lend_in(open_in), zeroed::<OpenOut>());
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("an instance");

    let refresh = view.op::<Ops>(|t| &t.head.refresh).expect("refresh");
    let refresh_in = TestIn::<RefreshIn>::new()
        .set(|i| &i.head.op, slot::REFRESH)
        .settings(b"{}");
    let refreshed = call_in(refresh, Some(&instance), &refresh_in, zeroed::<OutHead>());
    assert_eq!(
        refreshed.outcome,
        Outcome::Failed,
        "a refresh of bad settings"
    );
    assert_eq!(
        refreshed.error.as_deref(),
        Some("settings: missing field `url`")
    );

    // The instance still serves the settings it held: a delivery is carried to the connector.
    let deliver = view.op::<Ops>(|t| &t.deliver).expect("deliver");
    let deliver_in = TestIn::<DeliverIn>::new()
        .set(|i| &i.head.op, deliver.index())
        .set(
            |i| &i.head.ticket,
            Ticket {
                slot: 1,
                generation: 1,
            },
        )
        .blob(|i| &i.batch, batch, BLOB_JSONL);
    let delivered = call_in(deliver, Some(&instance), &deliver_in, zeroed::<OutHead>());
    assert_eq!(delivered.outcome, Outcome::Ready);
    assert_eq!(
        ESTABLISHES.load(Ordering::SeqCst),
        1,
        "the delivery after a refused refresh reached the connector"
    );
}
