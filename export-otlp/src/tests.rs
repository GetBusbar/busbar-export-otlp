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
    let endpoint =
        Endpoint::of(br#"{"url":"https://us%40r:p%3Ass@collector.example:4318/v1/traces"}"#);
    assert_eq!(
        endpoint.shown,
        "https://***@collector.example:4318/v1/traces"
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
    // Settings that did not parse (the configuration refused them) send nothing.
    assert_eq!(Endpoint::of(b"{}").request(vec![1]), None);
    assert_eq!(Endpoint::of(b"").request(vec![1]), None);
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
    assert_eq!(percent_decode("ab%+41cd"), "ab%+41cd");
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
