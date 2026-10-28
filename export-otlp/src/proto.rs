// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE `traces` BATCH → ONE OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! (`opentelemetry/proto/collector/trace/v1/trace_service.proto`, OTLP 1.x), encoded by `prost`
//! (the fleet's protobuf library) over the eleven messages it takes, declared here with their
//! `.proto` field numbers. Not through `opentelemetry-proto`: that crate depends on `opentelemetry`
//! and `opentelemetry_sdk` unconditionally (its `trace` feature turns on `opentelemetry_sdk/trace`),
//! which would link the OpenTelemetry SDK, a tracer runtime this sink does not run, into the
//! shipped plugin. Its generated types stay the ORACLE: every request the suite builds is decoded
//! with `opentelemetry-proto` and compared field by field.
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

use prost::Message as _;
use serde_json::Value;

/// The OTLP resource's `service.name`, and the instrumentation scope's name.
pub const SERVICE: &str = "busbar";
/// The record fields that become span attributes, in the order they are written.
pub const ATTRIBUTES: [&str; 6] = ["pool", "ingress", "op", "lane", "provider", "model"];
/// `SPAN_KIND_INTERNAL`.
const SPAN_KIND_INTERNAL: i32 = 1;

/// `ExportTraceServiceRequest` (collector/trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct ExportTraceServiceRequest {
    #[prost(message, repeated, tag = "1")]
    resource_spans: Vec<ResourceSpans>,
}

/// `ResourceSpans` (trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct ResourceSpans {
    #[prost(message, optional, tag = "1")]
    resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    scope_spans: Vec<ScopeSpans>,
}

/// `Resource` (resource/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct Resource {
    #[prost(message, repeated, tag = "1")]
    attributes: Vec<KeyValue>,
}

/// `ScopeSpans` (trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct ScopeSpans {
    #[prost(message, optional, tag = "1")]
    scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    spans: Vec<Span>,
}

/// `InstrumentationScope` (common/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct InstrumentationScope {
    #[prost(string, tag = "1")]
    name: String,
}

/// `Span` (trace/v1): the fields this sink fills.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Span {
    #[prost(bytes = "vec", tag = "1")]
    trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    span_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    parent_span_id: Vec<u8>,
    #[prost(string, tag = "5")]
    name: String,
    #[prost(int32, tag = "6")]
    kind: i32,
    #[prost(fixed64, tag = "7")]
    start_time_unix_nano: u64,
    #[prost(fixed64, tag = "8")]
    end_time_unix_nano: u64,
    #[prost(message, repeated, tag = "9")]
    attributes: Vec<KeyValue>,
    #[prost(message, repeated, tag = "11")]
    events: Vec<Event>,
    #[prost(message, optional, tag = "15")]
    status: Option<Status>,
}

/// `Span.Event` (trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct Event {
    #[prost(fixed64, tag = "1")]
    time_unix_nano: u64,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(message, repeated, tag = "3")]
    attributes: Vec<KeyValue>,
}

/// `Status` (trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct Status {
    #[prost(string, tag = "2")]
    message: String,
    #[prost(int32, tag = "3")]
    code: i32,
}

/// `Status.code` `STATUS_CODE_ERROR`.
const STATUS_CODE_ERROR: i32 = 2;

/// The reserved member of a `traces` line carrying the full span record (the host hands it to a
/// sink that takes span records).
pub const SPAN_MEMBER: &str = "span";

/// `ArrayValue` (common/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct ArrayValue {
    #[prost(message, repeated, tag = "1")]
    values: Vec<AnyValue>,
}

/// `KeyValue` (common/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct KeyValue {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(message, optional, tag = "2")]
    value: Option<AnyValue>,
}

/// `AnyValue` (common/v1): its `string_value`, `bool_value`, `int_value`, `double_value` and
/// `array_value` members, the ones this sink writes.
#[derive(Clone, PartialEq, prost::Message)]
struct AnyValue {
    #[prost(oneof = "AnyValueKind", tags = "1, 2, 3, 4, 5")]
    value: Option<AnyValueKind>,
}

/// `AnyValue.value`: `string_value` (1), `bool_value` (2), `int_value` (3), `double_value` (4),
/// `array_value` (5).
#[derive(Clone, PartialEq, prost::Oneof)]
enum AnyValueKind {
    #[prost(string, tag = "1")]
    Text(String),
    #[prost(bool, tag = "2")]
    Bool(bool),
    #[prost(int64, tag = "3")]
    Int(i64),
    #[prost(double, tag = "4")]
    Double(f64),
    #[prost(message, tag = "5")]
    Array(ArrayValue),
}

/// A `KeyValue { key, value: AnyValue { string_value } }`.
fn key_value(key: &str, value: &str) -> KeyValue {
    key_value_of(key, AnyValueKind::Text(value.to_string()))
}

/// A `KeyValue { key, value: AnyValue { value } }`.
fn key_value_of(key: &str, value: AnyValueKind) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue { value: Some(value) }),
    }
}

/// A record value as its `AnyValue` member, typed as the record states it (as the previous
/// release's exporter typed a span's fields): a string its `string_value`, a boolean its
/// `bool_value`, an integer its `int_value` (a `u64` past `i64::MAX` keeps its bits), any other
/// number its `double_value`, an array its `array_value`; an object its JSON text.
fn any_value(value: &Value) -> AnyValueKind {
    match value {
        Value::String(s) => AnyValueKind::Text(s.clone()),
        Value::Bool(b) => AnyValueKind::Bool(*b),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => AnyValueKind::Int(i),
            (None, Some(u)) => AnyValueKind::Int(u as i64),
            (None, None) => AnyValueKind::Double(n.as_f64().unwrap_or_default()),
        },
        Value::Array(items) => AnyValueKind::Array(ArrayValue {
            values: items
                .iter()
                .map(|item| AnyValue {
                    value: Some(any_value(item)),
                })
                .collect(),
        }),
        other => AnyValueKind::Text(other.to_string()),
    }
}

/// `[{key, value}, …]` as `KeyValue`s, in order.
fn key_values(list: Option<&Value>) -> Vec<KeyValue> {
    list.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|kv| {
            let key = kv.get("key")?.as_str()?;
            Some(key_value_of(key, any_value(kv.get("value")?)))
        })
        .collect()
}

/// THE FULL SPAN RECORD as its `Span` (busbar status row 173): its ids and name, its start and end
/// in nanoseconds, its attributes in the order and types the host states them (an array an
/// `array_value`), its events (each its time, name and attributes), and its status (an error with
/// its message; unset the empty status). Everything the previous release's exporter sent for a
/// span, whatever `fields:` selected.
fn full_span(full: &Value) -> Option<Span> {
    let trace_id = id(full.get("trace_id")?)?;
    let span_id = id(full.get("span_id")?)?;
    let parent = full.get("parent_span_id").and_then(id);
    let ns = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64).unwrap_or_default();
    let text = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut trace = vec![0u8; 16];
    trace[8..].copy_from_slice(&trace_id);
    let events = full
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| Event {
            time_unix_nano: ns(e, "time_ns"),
            name: text(e, "name"),
            attributes: key_values(e.get("attributes")),
        })
        .collect();
    let status = full.get("status");
    let error = status.and_then(|s| s.get("code")).and_then(Value::as_str) == Some("error");
    let status = if error {
        Status {
            message: status.map(|s| text(s, "message")).unwrap_or_default(),
            code: STATUS_CODE_ERROR,
        }
    } else {
        Status::default()
    };
    Some(Span {
        trace_id: trace,
        span_id: span_id.to_vec(),
        parent_span_id: parent.map(|p| p.to_vec()).unwrap_or_default(),
        name: text(full, "name"),
        kind: SPAN_KIND_INTERNAL,
        start_time_unix_nano: ns(full, "start_ns"),
        end_time_unix_nano: ns(full, "end_ns"),
        attributes: key_values(full.get("attributes")),
        events,
        status: Some(status),
    })
}

/// The encoded `ExportTraceServiceRequest` carrying each of `records` that is a span, in order, or
/// `None` when none of them carries a usable span identity.
pub fn export_request<'a>(records: impl IntoIterator<Item = &'a Value>) -> Option<Vec<u8>> {
    encode(records.into_iter().filter_map(span).collect())
}

/// The encoded `ExportTraceServiceRequest` carrying `spans` (each built once by [`span`]), or `None`
/// when there are none.
pub(crate) fn encode(spans: Vec<Span>) -> Option<Vec<u8>> {
    if spans.is_empty() {
        return None;
    }
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![key_value("service.name", SERVICE)],
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: SERVICE.to_string(),
                }),
                spans,
            }],
        }],
    };
    Some(request.encode_to_vec())
}

/// Whether `record` carries a usable span identity (it is a span [`export_request`] encodes).
pub fn is_span(record: &Value) -> bool {
    span(record).is_some()
}

/// The record's `Span` message: from its full span record where the host handed one (its `span`
/// member, [`full_span`]), else from its projected fields.
pub(crate) fn span(record: &Value) -> Option<Span> {
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
    let mut trace = vec![0u8; 16];
    trace[8..].copy_from_slice(&trace_id);
    let attributes = ATTRIBUTES
        .iter()
        .filter_map(|key| match record.get(*key) {
            None | Some(Value::Null) => None,
            Some(value) => Some(key_value_of(key, any_value(value))),
        })
        .collect();
    Some(Span {
        trace_id: trace,
        span_id: span_id.to_vec(),
        parent_span_id: parent.map(|p| p.to_vec()).unwrap_or_default(),
        name: text("name").to_string(),
        kind: SPAN_KIND_INTERNAL,
        start_time_unix_nano: start,
        end_time_unix_nano: end,
        attributes,
        events: Vec::new(),
        status: None,
    })
}

/// A record's span id — 16 hex digits — as its 8 big-endian bytes; `None` when it is not one, or
/// is zero (the invalid id in OTLP).
fn id(value: &Value) -> Option<[u8; 8]> {
    let text = value.as_str()?;
    if text.len() != 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let n = u64::from_str_radix(text, 16).ok().filter(|n| *n != 0)?;
    Some(n.to_be_bytes())
}
