// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink's own suite: the OTLP encoding (checked against the OpenTelemetry project's generated
//! types), the settings and check refusals, and the host ops each call asks for. The same crate
//! through both doors is proven by `busbar-export-otlp-plugin`'s conformance test.

use super::*;
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
    let bytes = proto::export_request(&record).expect("a span");
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
    let bytes = proto::export_request(&record).expect("a span");
    let request = decoded(&bytes);
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    assert!(span.parent_span_id.is_empty());
    assert_eq!(span.attributes, vec![kv("pool", ""), kv("op", "chat")]);
    assert_eq!(
        (span.start_time_unix_nano, span.end_time_unix_nano),
        (5000, 5000)
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
    ] {
        assert_eq!(proto::export_request(&record), None, "{record}");
    }
}

/// The settings' shape refuses in the configuration grammar's words.
#[test]
fn settings_refuse_in_the_grammars_words() {
    let sink = open("{}").expect("opens");
    assert!(sink
        .validate("t", &json!({"url": "http://localhost:4318/v1/traces"}))
        .is_empty());
    assert_eq!(
        sink.validate("t", &json!({"url": "http://x/", "otlp_endpoint": "y"})),
        vec!["export.t.settings: unknown field `otlp_endpoint`, expected `url`".to_string()]
    );
    assert_eq!(
        sink.validate("t", &json!({})),
        vec!["export.t.settings: missing field `url`".to_string()]
    );
}

/// A second instance is refused, naming the first, in 1.5.x's words; one instance, and the limits
/// phase, report nothing.
#[test]
fn a_second_instance_is_refused_in_the_words_it_always_was() {
    let url = json!({"url": "http://localhost:4318/v1/traces"});
    let one = [("traces".to_string(), url.clone())];
    assert!(check(CheckPhase::Instances, &one).is_empty());
    let two = [one[0].clone(), ("more".to_string(), url)];
    assert!(check(CheckPhase::Limits, &two).is_empty());
    assert_eq!(
        check(CheckPhase::Instances, &two),
        vec![
            "export.more: a second `module: otlp` instance (already defined as 'traces'). OTLP \
             installs the ONE process-global tracer subscriber, so a second instance could only \
             be silently ignored — keep a single instance."
                .to_string()
        ]
    );
}

/// Start asks the host's policy about the endpoint AS WRITTEN (its refusal names it masked); the
/// answer decides whether the sink takes spans this run.
#[test]
fn start_asks_the_policy_and_its_answer_decides() {
    let sink = open(r#"{"url":"https://u:p@collector.example/v1/traces"}"#).expect("opens");
    assert_eq!(
        sink.start(),
        HostStep::Host {
            token: 0,
            ops: vec![HostOp::Admit {
                url: "https://u:p@collector.example/v1/traces".into()
            }],
        }
    );
    assert_eq!(
        sink.resume(0, vec![HostResult::Done { rotation: None }]),
        started(true)
    );
    let refused = HostResult::Failed {
        step: "refused".into(),
        error: "no".into(),
        rotation: None,
    };
    assert_eq!(sink.resume(0, vec![refused]), started(false));
    // Settings that did not parse (the configuration refused them) take nothing.
    assert_eq!(open("{}").expect("opens").start(), started(false));
}

/// A delivery asks the host to POST the span's OTLP request — binary, to the endpoint without its
/// userinfo, which rides as `Authorization: Basic` instead.
#[test]
fn a_delivery_asks_the_host_to_post_the_request_with_the_credential_moved_to_a_header() {
    let sink =
        open(r#"{"url":"https://us%40r:p%3Ass@collector.example:4318/v1/traces"}"#).expect("opens");
    let record = json!({"trace_id": "0000000000000001", "span_id": "0000000000000002",
        "name": "n", "start": 1, "duration_us": 1});
    let HostStep::Host { token, ops } = sink.deliver_via_host(ExportStream::Traces, &record) else {
        panic!("a delivery asks the host to act");
    };
    assert_eq!(token, 1);
    assert_eq!(
        ops,
        vec![HostOp::HttpBinary(HttpRequest {
            method: "POST".into(),
            url: "https://collector.example:4318/v1/traces".into(),
            headers: vec![
                ("content-type".into(), "application/x-protobuf".into()),
                // base64("us@r:p:ss")
                ("authorization".into(), "Basic dXNAcjpwOnNz".into()),
            ],
            body: hex(&proto::export_request(&record).expect("a span")),
            timeout_ms: 10_000,
        })]
    );
    // The answer: fire and forget, whatever it was.
    let failed = HostResult::Failed {
        step: "request".into(),
        error: "reset".into(),
        rotation: None,
    };
    assert_eq!(sink.resume(token, vec![failed]), HostStep::Done);
    // A record that is no span asks nothing.
    assert_eq!(
        sink.deliver_via_host(ExportStream::Traces, &json!({"name": "x"})),
        HostStep::Done
    );
}

#[test]
fn the_small_encoders_match_their_standards() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    assert_eq!(hex(&[0x00, 0x0a, 0xff]), "000aff");
    assert_eq!(percent_decode("a%20b%zz%4"), "a b%zz%4");
    assert_eq!(
        split_credentials("http://localhost:4318/v1/traces"),
        ("http://localhost:4318/v1/traces".into(), None)
    );
    assert_eq!(
        mask_userinfo("https://u:p@collector.example/v1"),
        "https://***@collector.example/v1"
    );
    assert_eq!(mask_userinfo("not a url"), "not a url");
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
