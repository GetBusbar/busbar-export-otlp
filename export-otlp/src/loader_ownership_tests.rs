// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn loader_owned_trace_shape_and_stream_contract() {
    assert!(Otlp::validate(br#"{"url":"http://127.0.0.1:4318/v1/traces"}"#).is_ok());
    assert_eq!(
        Otlp::validate(br#"{"url":"http://127.0.0.1:4318","bogus":1}"#)
            .unwrap_err()
            .text(),
        Some("settings: unknown field `bogus`, expected `url`")
    );
}

#[test]
fn loader_owned_closed_span_has_the_otlp_wire_contract() {
    let span = json!({"trace_id":"4bf92f3577b34da6", "span_id":"00f067aa0ba902b7", "name":"busbar.request", "start":1_700_000_000_000_000_u64,"duration_us":1500});
    let body = export_request([&span]).unwrap();
    let endpoint = Endpoint::of(
        &settings_as::<OtlpSettings>(br#"{"url":"http://127.0.0.1:4318/v1/traces"}"#).unwrap(),
    );
    let (request, _) = endpoint.parts(body);
    assert_eq!(request.method, b"POST");
    assert_eq!(request.target, b"/v1/traces");
    assert!(request
        .fields
        .contains(&(b"content-type".to_vec(), b"application/x-protobuf".to_vec())));
    let decoded = decoded(&request.body);
    let actual = &decoded.resource_spans[0].scope_spans[0].spans[0];
    assert_eq!(actual.name, "busbar.request");
    assert_eq!(
        actual.trace_id,
        vec![0, 0, 0, 0, 0, 0, 0, 0, 0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6]
    );
}
