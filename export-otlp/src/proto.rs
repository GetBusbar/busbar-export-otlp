// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE `traces` BATCH → ONE OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! (`opentelemetry/proto/collector/trace/v1/trace_service.proto`, OTLP 1.x), encoded here by hand:
//! the handful of messages it takes do not justify a code generator in the binary.
//!
//! The request is `resource_spans[1]`: `resource.attributes = [service.name = "busbar"]`, one
//! `scope_spans` whose `scope.name` is `busbar`, and one `Span` per record, in batch order:
//!
//! | record field | `Span` field |
//! |---|---|
//! | `trace_id` (16 hex digits) | `trace_id` (1): 16 bytes, the id's 8 big-endian bytes after 8 zero bytes |
//! | `span_id` | `span_id` (2): its 8 big-endian bytes |
//! | `parent_span_id` | `parent_span_id` (4), when present |
//! | `name` | `name` (5) |
//! | — | `kind` (6): `SPAN_KIND_INTERNAL` |
//! | `start` (epoch µs) | `start_time_unix_nano` (7) |
//! | `start` + `duration_us` | `end_time_unix_nano` (8) |
//! | `pool` `ingress` `op` `lane` `provider` `model` | `attributes` (9), in that order, typed as the record states them: a string a `string_value`, an integer an `int_value`, a boolean a `bool_value`, a float a `double_value` |
//!
//! Proto3 rules, as every conforming encoder writes them: fields in field-number order, a field at
//! its default (empty, zero) left off, a `oneof` member written whenever it is set. A record with no
//! usable `trace_id` or `span_id` is no span; a batch with no span encodes to nothing.

use serde_json::Value;

/// The OTLP resource's `service.name`, and the instrumentation scope's name.
pub const SERVICE: &str = "busbar";
/// The record fields that become span attributes, in the order they are written.
pub const ATTRIBUTES: [&str; 6] = ["pool", "ingress", "op", "lane", "provider", "model"];
/// `SPAN_KIND_INTERNAL`.
const SPAN_KIND_INTERNAL: u64 = 1;

/// Protobuf wire types.
const VARINT: u32 = 0;
const FIXED64: u32 = 1;
const LEN: u32 = 2;

/// The encoded `ExportTraceServiceRequest` carrying each of `records` that is a span, in order, or
/// `None` when none of them carries a usable span identity.
pub fn export_request<'a>(records: impl IntoIterator<Item = &'a Value>) -> Option<Vec<u8>> {
    let mut scope = Vec::new();
    string(&mut scope, 1, SERVICE);
    let mut scope_spans = Vec::new();
    message(&mut scope_spans, 1, &scope);
    let mut spans = 0usize;
    for span in records.into_iter().filter_map(span) {
        message(&mut scope_spans, 2, &span);
        spans += 1;
    }
    if spans == 0 {
        return None;
    }
    let mut resource = Vec::new();
    message(&mut resource, 1, &key_value("service.name", SERVICE));
    let mut resource_spans = Vec::new();
    message(&mut resource_spans, 1, &resource);
    message(&mut resource_spans, 2, &scope_spans);
    let mut request = Vec::new();
    message(&mut request, 1, &resource_spans);
    Some(request)
}

/// Whether `record` carries a usable span identity (it is a span [`export_request`] encodes).
pub fn is_span(record: &Value) -> bool {
    span(record).is_some()
}

/// The record's `Span` message: from its full span record where the host handed one (its `span`
/// member, [`full_span`]), else from its projected fields.
fn span(record: &Value) -> Option<Vec<u8>> {
    if let Some(full) = record.get(SPAN_MEMBER).filter(|v| v.is_object()) {
        return full_span(full);
    }
    let trace_id = id(record.get("trace_id")?)?;
    let span_id = id(record.get("span_id")?)?;
    let parent = record.get("parent_span_id").and_then(id);
    let text = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or_default();
    let micros = |key: &str| record.get(key).and_then(Value::as_u64).unwrap_or_default();
    let start = micros("start").saturating_mul(1000);
    let end = start.saturating_add(micros("duration_us").saturating_mul(1000));

    let mut out = Vec::new();
    let mut trace = [0u8; 16];
    trace[8..].copy_from_slice(&trace_id);
    bytes(&mut out, 1, &trace);
    bytes(&mut out, 2, &span_id);
    if let Some(parent) = parent {
        bytes(&mut out, 4, &parent);
    }
    string(&mut out, 5, text("name"));
    varint_field(&mut out, 6, SPAN_KIND_INTERNAL);
    fixed64(&mut out, 7, start);
    fixed64(&mut out, 8, end);
    for key in ATTRIBUTES {
        let value = match record.get(key) {
            None | Some(Value::Null) => continue,
            Some(value) => any_value(value),
        };
        message(&mut out, 9, &key_value_any(key, &value));
    }
    Some(out)
}

/// The reserved member of a `traces` line carrying the full span record (the host hands it to a
/// sink that takes span records).
pub const SPAN_MEMBER: &str = "span";

/// `Status.code` `STATUS_CODE_ERROR`.
const STATUS_CODE_ERROR: u64 = 2;

/// THE FULL SPAN RECORD as its `Span` (busbar status row 173): its ids and name, its start and end
/// in nanoseconds, its attributes in the order and types the host states them (an array an
/// `array_value`), its events (each its time, name and attributes), and its status (an error with
/// its message; unset the empty status). Everything the previous release's exporter sent for a span,
/// whatever `fields:` selected.
fn full_span(full: &Value) -> Option<Vec<u8>> {
    let trace_id = id(full.get("trace_id")?)?;
    let span_id = id(full.get("span_id")?)?;
    let parent = full.get("parent_span_id").and_then(id);
    let ns = |key: &str| full.get(key).and_then(Value::as_u64).unwrap_or_default();
    let mut out = Vec::new();
    let mut trace = [0u8; 16];
    trace[8..].copy_from_slice(&trace_id);
    bytes(&mut out, 1, &trace);
    bytes(&mut out, 2, &span_id);
    if let Some(parent) = parent {
        bytes(&mut out, 4, &parent);
    }
    string(
        &mut out,
        5,
        full.get("name").and_then(Value::as_str).unwrap_or_default(),
    );
    varint_field(&mut out, 6, SPAN_KIND_INTERNAL);
    fixed64(&mut out, 7, ns("start_ns"));
    fixed64(&mut out, 8, ns("end_ns"));
    for kv in key_values(full.get("attributes")) {
        message(&mut out, 9, &kv);
    }
    for event in full
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mut e = Vec::new();
        fixed64(
            &mut e,
            1,
            event
                .get("time_ns")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        );
        string(
            &mut e,
            2,
            event
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        for kv in key_values(event.get("attributes")) {
            message(&mut e, 3, &kv);
        }
        message(&mut out, 11, &e);
    }
    // The status is always set, as the previous release's exporter set it: unset is the empty
    // message; an error carries its message and `STATUS_CODE_ERROR`.
    let status = full.get("status");
    let mut st = Vec::new();
    if status.and_then(|s| s.get("code")).and_then(Value::as_str) == Some("error") {
        string(
            &mut st,
            2,
            status
                .and_then(|s| s.get("message"))
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        varint_field(&mut st, 3, STATUS_CODE_ERROR);
    }
    message(&mut out, 15, &st);
    Some(out)
}

/// `[{key, value}, …]` as encoded `KeyValue`s, in order.
fn key_values(list: Option<&Value>) -> Vec<Vec<u8>> {
    list.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|kv| {
            let key = kv.get("key")?.as_str()?;
            let value = kv.get("value")?;
            Some(key_value_any(key, &any_value(value)))
        })
        .collect()
}

/// A record's span id — 16 hex digits — as its 8 big-endian bytes; `None` when it is not one, or
/// is zero (the invalid id in OTLP).
fn id(value: &Value) -> Option<[u8; 8]> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    let n = u64::from_str_radix(text, 16).ok().filter(|n| *n != 0)?;
    Some(n.to_be_bytes())
}

/// A `KeyValue { key, value: AnyValue { string_value } }`.
fn key_value(key: &str, value: &str) -> Vec<u8> {
    key_value_any(key, &any_value(&Value::from(value)))
}

/// A `KeyValue { key, value }` over an encoded `AnyValue`.
fn key_value_any(key: &str, any: &[u8]) -> Vec<u8> {
    let mut kv = Vec::new();
    string(&mut kv, 1, key);
    message(&mut kv, 2, any);
    kv
}

/// A record value as its `AnyValue`, typed as the record states it (as the previous release's
/// exporter typed a span's fields): a string its `string_value` (1), a boolean its `bool_value`
/// (2), an integer its `int_value` (3, an `int64`), any other number its `double_value` (4), an
/// array its `array_value` (5); an object its JSON text. `AnyValue.value` is a oneof: its member is
/// written even at its default (the empty string, `false`, `0`).
fn any_value(value: &Value) -> Vec<u8> {
    let mut any = Vec::new();
    match value {
        Value::Bool(b) => {
            tag(&mut any, 2, VARINT);
            varint(&mut any, u64::from(*b));
        }
        Value::Number(n) if n.as_i64().is_some() || n.as_u64().is_some() => {
            // An `int64` on the wire is its two's-complement bits as a varint; a `u64` past
            // `i64::MAX` keeps its bits.
            let bits = n
                .as_i64()
                .map_or_else(|| n.as_u64().unwrap_or_default(), |i| i as u64);
            tag(&mut any, 3, VARINT);
            varint(&mut any, bits);
        }
        Value::Number(n) => {
            tag(&mut any, 4, FIXED64);
            any.extend_from_slice(&n.as_f64().unwrap_or_default().to_bits().to_le_bytes());
        }
        Value::String(s) => {
            tag(&mut any, 1, LEN);
            varint(&mut any, s.len() as u64);
            any.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            // `array_value` (5): an `ArrayValue { values: repeated AnyValue }`.
            let mut array = Vec::new();
            for item in items {
                message(&mut array, 1, &any_value(item));
            }
            message(&mut any, 5, &array);
        }
        other => {
            let text = other.to_string();
            tag(&mut any, 1, LEN);
            varint(&mut any, text.len() as u64);
            any.extend_from_slice(text.as_bytes());
        }
    }
    any
}

fn tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    varint(out, u64::from((field << 3) | wire));
}

fn varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn varint_field(out: &mut Vec<u8>, field: u32, n: u64) {
    if n != 0 {
        tag(out, field, VARINT);
        varint(out, n);
    }
}

fn fixed64(out: &mut Vec<u8>, field: u32, n: u64) {
    if n != 0 {
        tag(out, field, FIXED64);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    if !b.is_empty() {
        tag(out, field, LEN);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }
}

fn string(out: &mut Vec<u8>, field: u32, s: &str) {
    bytes(out, field, s.as_bytes());
}

/// An embedded message — written even when empty, as a set message field is.
fn message(out: &mut Vec<u8>, field: u32, encoded: &[u8]) {
    tag(out, field, LEN);
    varint(out, encoded.len() as u64);
    out.extend_from_slice(encoded);
}
