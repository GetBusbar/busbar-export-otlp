// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE `traces` BATCH → ONE OTLP/HTTP protobuf `ExportTraceServiceRequest`

use busbar_contract::abi::export::ExportField;
use prost::Message as _;
use serde_json::Value;

/// The OTLP resource's `service.name`, and the instrumentation scope's name.
pub const SERVICE: &str = "busbar";
/// The record fields that become span attributes, in the order they are written.
pub const ATTRIBUTES: [&str; 6] = [
    ExportField::Pool.as_token(),
    ExportField::Ingress.as_token(),
    ExportField::Op.as_token(),
    ExportField::Lane.as_token(),
    ExportField::Provider.as_token(),
    ExportField::Model.as_token(),
];

/// OpenTelemetry semantic conventions: the resource's service identity attribute.
const SERVICE_NAME_ATTRIBUTE: &str = "service.name";
/// SI conversion from the host's projected epoch microseconds to OTLP nanoseconds.
const NANOS_PER_MICROSECOND: u64 = 1_000;
/// OTLP trace/v1 TraceId width. The host's u64 identity occupies its trailing bytes.
const TRACE_ID_BYTES: usize = 16;
/// Host span identities are u64 values written as fixed-width hexadecimal text.
const RECORD_ID_BYTES: usize = std::mem::size_of::<u64>();
const RECORD_ID_HEX_DIGITS: usize = RECORD_ID_BYTES * 2;
const HEX_RADIX: u32 = 16;
/// OTLP trace/v1 reserves an all-zero trace or span identity as invalid.
const INVALID_RECORD_ID: u64 = 0;

/// Full-span JSON vocabulary emitted by busbar-kernel's export/traces.rs

mod span_record {
    pub(super) const KEY: &str = "key";
    pub(super) const VALUE: &str = "value";
    pub(super) const ATTRIBUTES: &str = "attributes";
    pub(super) const EVENTS: &str = "events";
    pub(super) const TIME_NS: &str = "time_ns";
    pub(super) const CODE: &str = "code";
    pub(super) const STATUS: &str = "status";
    pub(super) const MESSAGE: &str = "message";
    pub(super) const ERROR: &str = "error";
    pub(super) const START_NS: &str = "start_ns";
    pub(super) const END_NS: &str = "end_ns";
}

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

/// `ExportTraceServiceResponse` (collector/trace/v1): a collector's 2xx answer.
#[derive(Clone, PartialEq, prost::Message)]
struct ExportTraceServiceResponse {
    #[prost(message, optional, tag = "1")]
    partial_success: Option<ExportTracePartialSuccess>,
}

/// `ExportTracePartialSuccess` (collector/trace/v1).
#[derive(Clone, PartialEq, prost::Message)]
struct ExportTracePartialSuccess {
    #[prost(int64, tag = "1")]
    rejected_spans: i64,
    /// Bytes on the wire as a string is: a message that is not UTF-8 must not lose the count.
    #[prost(bytes = "vec", tag = "2")]
    error_message: Vec<u8>,
}

/// What a collector's 2xx body says it rejected: `Some((rejected_spans, error_message))` when its

pub fn rejected(body: &[u8]) -> Option<(i64, String)> {
    collector_response(body).ok().flatten()
}

/// Decode the response without treating malformed protobuf as a fully accepted batch.
pub(crate) fn collector_response(body: &[u8]) -> Result<Option<(i64, String)>, prost::DecodeError> {
    let Some(partial) = ExportTraceServiceResponse::decode(body)?.partial_success else {
        return Ok(None);
    };
    Ok(
        (partial.rejected_spans > 0 || !partial.error_message.is_empty()).then(|| {
            (
                partial.rejected_spans,
                String::from_utf8_lossy(&partial.error_message).into_owned(),
            )
        }),
    )
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

fn any_value(value: &Value) -> Option<AnyValueKind> {
    Some(match value {
        Value::Null => return None,
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
                    value: any_value(item),
                })
                .collect(),
        }),
        other => AnyValueKind::Text(other.to_string()),
    })
}

/// `[{key, value}, …]` as `KeyValue`s, in order.
fn key_values(list: Option<&Value>) -> Vec<KeyValue> {
    list.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|kv| {
            let key = kv.get(span_record::KEY)?.as_str()?;
            Some(key_value_of(key, any_value(kv.get(span_record::VALUE)?)?))
        })
        .collect()
}

/// The one `Span` builder: the ids a record (or a full span record) states, as `source` carries

fn build(source: &Value, fill: impl FnOnce(&mut Span)) -> Option<Span> {
    let trace_id = id(source.get(ExportField::TraceId.as_token())?)?;
    let span_id = id(source.get(ExportField::SpanId.as_token())?)?;
    let parent = source
        .get(ExportField::ParentSpanId.as_token())
        .and_then(id);
    let mut trace = vec![0u8; TRACE_ID_BYTES];
    trace[TRACE_ID_BYTES - RECORD_ID_BYTES..].copy_from_slice(&trace_id);
    let mut span = Span {
        trace_id: trace,
        span_id: span_id.to_vec(),
        parent_span_id: parent.map(|p| p.to_vec()).unwrap_or_default(),
        kind: SPAN_KIND_INTERNAL,
        ..Span::default()
    };
    fill(&mut span);
    Some(span)
}

/// The full span record as its `Span`: its ids and name, its start and end

fn full_span(full: &Value) -> Option<Span> {
    let ns = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64).unwrap_or_default();
    let text = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    build(full, |span| {
        span.events = full
            .get(span_record::EVENTS)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|e| Event {
                time_unix_nano: ns(e, span_record::TIME_NS),
                name: text(e, ExportField::Name.as_token()),
                attributes: key_values(e.get(span_record::ATTRIBUTES)),
            })
            .collect();
        let status = full.get(span_record::STATUS);
        let error = status
            .and_then(|s| s.get(span_record::CODE))
            .and_then(Value::as_str)
            == Some(span_record::ERROR);
        span.status = Some(if error {
            Status {
                message: status
                    .map(|s| text(s, span_record::MESSAGE))
                    .unwrap_or_default(),
                code: STATUS_CODE_ERROR,
            }
        } else {
            Status::default()
        });
        span.name = text(full, ExportField::Name.as_token());
        span.start_time_unix_nano = ns(full, span_record::START_NS);
        span.end_time_unix_nano = ns(full, span_record::END_NS);
        span.attributes = key_values(full.get(span_record::ATTRIBUTES));
    })
}

/// The encoded `ExportTraceServiceRequest` carrying each of `records` that is a span, in order, or

pub fn export_request<'a>(records: impl IntoIterator<Item = &'a Value>) -> Option<Vec<u8>> {
    encode(records.into_iter().filter_map(span).collect())
}

/// The encoded `ExportTraceServiceRequest` carrying `spans` (each built once by [`span`]), or `None`

pub(crate) fn encode(spans: Vec<Span>) -> Option<Vec<u8>> {
    if spans.is_empty() {
        return None;
    }
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![key_value(SERVICE_NAME_ATTRIBUTE, SERVICE)],
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

pub(crate) fn span(record: &Value) -> Option<Span> {
    if let Some(full) = record.get(SPAN_MEMBER).filter(|v| v.is_object()) {
        return full_span(full);
    }
    let micros = |key: &str| record.get(key).and_then(Value::as_u64).unwrap_or_default();
    build(record, |span| {
        let start = micros(ExportField::Start.as_token()).saturating_mul(NANOS_PER_MICROSECOND);
        span.name = record
            .get(ExportField::Name.as_token())
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        span.start_time_unix_nano = start;
        span.end_time_unix_nano = start.saturating_add(
            micros(ExportField::DurationUs.as_token()).saturating_mul(NANOS_PER_MICROSECOND),
        );
        span.attributes = ATTRIBUTES
            .iter()
            .filter_map(|key| Some(key_value_of(key, any_value(record.get(*key)?)?)))
            .collect();
    })
}

/// A record's span id — 16 hex digits — as its 8 big-endian bytes; `None` when it is not one, or

fn id(value: &Value) -> Option<[u8; RECORD_ID_BYTES]> {
    let text = value.as_str()?;
    if text.len() != RECORD_ID_HEX_DIGITS || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let n = u64::from_str_radix(text, HEX_RADIX)
        .ok()
        .filter(|n| *n != INVALID_RECORD_ID)?;
    Some(n.to_be_bytes())
}
