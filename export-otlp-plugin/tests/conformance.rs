// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE OTLP TRACE SINK, BOTH DOORS, ONE TABLE** — the sink's linked + dropped-in conformance on

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::export::{
    self, CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut,
};
use busbar_contract::abi::host::conn::connector::EGRESS_LOOPBACK_ALLOWED;
use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, InHead, OutHead, BLOB_JSON, BLOB_JSONL, DIAG_LOG,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::{ReadNeed, RENDERING_MAGIC};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, Called, ConnTable, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, LoadError, Metric, Plugin,
    NO_BLOB,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use prost::Message as _;
use serde_json::{json, Value};

const COLLECTOR: &str = r#"{"url":"http://127.0.0.1:4318/v1/traces"}"#;
const FAILING: &str = r#"{"url":"https://u:p@collector.example/fail"}"#;
const INTERNAL: &str = r#"{"url":"https://collector.internal.example/v1/traces"}"#;
const PLAINTEXT: &str = r#"{"url":"http://collector.example/v1/traces"}"#;
const MOVED: &str = r#"{"url":"http://127.0.0.1:4318/v2/traces"}"#;

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a

fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_export_otlp_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-export-otlp-plugin cdylib ({file}) is not built"))
}

/// The row a busbar build that links the sink states.
fn row() -> LinkedRow {
    LinkedRow::of(busbar_export_otlp::door::door).expect("the linked door renders")
}

/// One declared need: its egress class and the target it was declared at, if any.
type Declared = (u32, Option<String>);

/// The collector behind the host's connection table: what each need was declared at and judged,
/// every request it was handed, and the reply each connection reads.
#[derive(Default)]
struct Collector {
    slab: ConnSlab<()>,
    /// Per `(instance, need)`: its egress class and declared target.
    declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    carried: Mutex<Vec<Value>>,
    replies: Mutex<HashMap<ConnId, VecDeque<Piece>>>,
    /// The body bytes each connection's `Body` pieces fill the read buffer with, in order.
    bodies: Mutex<HashMap<ConnId, VecDeque<Vec<u8>>>>,
}

/// The egress verdict on `target` under `class`.
fn judge(class: u32, target: Option<&str>) -> Result<(), ConnError> {
    match target {
        Some(u) if u.contains(".internal.example") => Err(ConnError::Refused),
        Some(u) if u.starts_with("https://") => Ok(()),
        Some(u) if class == EGRESS_LOOPBACK_ALLOWED && u.starts_with("http://127.0.0.1") => Ok(()),
        _ => Err(ConnError::Refused),
    }
}

fn piece(kind: PieceKind, code: Option<u32>) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len: 0,
        end: true,
        status: None,
        status_code: code,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

fn hex(octets: &[u8]) -> String {
    octets.iter().map(|b| format!("{b:02x}")).collect()
}

impl DeclaredConns for Collector {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.slab.declare(owner, need);
        self.declared
            .lock()
            .unwrap()
            .insert((owner, need), (spec.egress_class, target.map(String::from)));
        target.map_or(Ok(()), |t| judge(spec.egress_class, Some(t)))
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.declared
            .lock()
            .unwrap()
            .get(&(owner, need))
            .map(|(class, target)| target.as_deref().map_or(Ok(()), |t| judge(*class, Some(t))))
    }

    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }

    /// The collector's need is the host's `http` framer (Part 2 #50's boot scheme match).
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
}

impl Conns for Collector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let (class, declared) = self
            .declared
            .lock()
            .unwrap()
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::UndeclaredNeed)?;

        let target = if desc.target.is_empty() {
            declared.unwrap_or_default()
        } else {
            desc.target.to_owned()
        };
        judge(class, Some(&target))?;
        self.carried.lock().unwrap().push(json!({
            "need": need.0,
            "target": target,
            "method": String::from_utf8_lossy(desc.method),
            "head_target": String::from_utf8_lossy(desc.head_target),
            "fields": desc.fields.iter()
                .map(|(n, v)| [(*n).to_owned(), String::from_utf8_lossy(v).into_owned()])
                .collect::<Vec<_>>(),
            "timeout_ms": desc.timeout_ms,
            "body": hex(&desc.body),
        }));
        let id = self.slab.insert(caller, need, ())?;
        let code =
            if desc.head_target.ends_with(b"/fail") || desc.head_target.ends_with(b"/bigfail") {
                503
            } else {
                200
            };
        let mut pieces = VecDeque::from([piece(PieceKind::Fields, Some(code))]);
        if desc.head_target.ends_with(b"/big") || desc.head_target.ends_with(b"/bigfail") {
            let mut body = ExportTraceServiceResponse {
                partial_success: Some(ExportTracePartialSuccess {
                    rejected_spans: 5,
                    error_message: "too big".into(),
                }),
            }
            .encode_to_vec();
            body.extend_from_slice(&[0x7a, 0x80, 0xf1, 0x04]);
            body.resize(body.len() + 80_000, 0);
            let chunks: VecDeque<Vec<u8>> = body.chunks(8192).map(<[u8]>::to_vec).collect();
            for _ in &chunks {
                pieces.push_back(piece(PieceKind::Body, None));
            }
            self.bodies.lock().unwrap().insert(id, chunks);
        }
        pieces.push_back(piece(PieceKind::Completion, None));
        self.replies.lock().unwrap().insert(id, pieces);
        Ok(id)
    }

    fn write(
        &self,
        c: InstanceId,
        id: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(c, id)?;
        Ok(b.len())
    }

    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let mut piece = self
            .replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .ok_or(ConnError::Closed)?;
        if piece.kind == PieceKind::Body {
            let chunk = self
                .bodies
                .lock()
                .unwrap()
                .get_mut(&id)
                .and_then(VecDeque::pop_front)
                .ok_or(ConnError::Closed)?;
            buf[..chunk.len()].copy_from_slice(&chunk);
            piece.len = chunk.len();
        }
        Ok(piece)
    }

    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }

    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }

    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.replies.lock().unwrap().remove(&id);
        self.slab.remove(c, id).map(|_| ())
    }
}

/// The instance's log, as the host receives it: every log record of every reply's envelope.
#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl EnvelopeSink for Lines {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, d: Diagnostic<'_>) {
        if d.id == DIAG_LOG {
            let text = String::from_utf8_lossy(d.text);
            self.0
                .lock()
                .unwrap()
                .push(format!("{} {text}", d.severity));
        }
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

/// One door's host: its dispatcher, collector and log.
struct Host {
    d: Arc<Dispatcher>,
    collector: Arc<Collector>,
    lines: Arc<Lines>,
}

impl Host {
    fn new() -> Self {
        Self {
            d: Arc::new(Dispatcher::new(DispatchConfig {
                workers: 2,
                watchdog_period: Duration::from_millis(20),
                ..DispatchConfig::default()
            })),
            collector: Arc::default(),
            lines: Arc::default(),
        }
    }

    fn bind(&self) -> Bind {
        let conns: Arc<dyn DeclaredConns> = self.collector.clone();
        let sink: Arc<dyn EnvelopeSink> = self.lines.clone();
        Bind {
            instance: Arc::from("traces"),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.d.adopter(),
            conns: ConnTable::Host(conns),
        }
    }
}

/// The door, linked or dropped in, bound to `host`.
fn load(host: &Host, dropped: bool) -> Plugin<Export> {
    if dropped {
        load_dropped::<Export>(&cdylib(), &row().statement, host.bind())
            .expect("the dropped-in door loads")
    } else {
        load_linked::<Export>(&row(), host.bind()).expect("the linked door loads")
    }
}

fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} {text}", c.outcome)
}

fn validate(p: &Plugin<Export>, settings: &str) -> String {
    let mut input: ValidateIn = blank_in();
    input.head = in_head();
    input.settings = blob(settings.as_bytes(), BLOB_JSON);
    spelled(&p.call(lc::VALIDATE, &mut Frame::new(input, out_head())))
}

fn open(p: &Plugin<Export>, settings: &str) -> String {
    let mut input: OpenIn = blank_in();
    input.head = in_head();
    input.settings = blob(settings.as_bytes(), BLOB_JSON);
    input.generation = 1;
    let mut out: OpenOut = blank_out();
    out.head = out_head();
    spelled(&p.call(lc::OPEN, &mut Frame::new(input, out)))
}

fn refresh(p: &Plugin<Export>, settings: &str) -> String {
    let mut input: RefreshIn = blank_in();
    input.head = in_head();
    input.settings = blob(settings.as_bytes(), BLOB_JSON);
    input.generation = 2;
    spelled(&p.call(lc::REFRESH, &mut Frame::new(input, out_head())))
}

fn close(p: &Plugin<Export>) -> String {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    spelled(&p.call(lc::CLOSE, &mut f))
}

/// The kind's four non-delivery answers.
fn kind_answers(p: &Plugin<Export>) -> Value {
    let mut scrape: ScrapeIn = blank_in();
    scrape.head = in_head();
    let mut scrape_out: ScrapeOut = blank_out();
    scrape_out.head = out_head();
    let status = StatusOut {
        head: out_head(),
        status: NO_BLOB,
    };
    let mut check: CheckIn = blank_in();
    check.head = in_head();
    check.phase = export::CHECK_PHASE_INSTANCES;
    let check_out = CheckOut {
        head: out_head(),
        findings: NO_BLOB,
    };
    let mut serve: ServeIn = blank_in();
    serve.head = in_head();
    let mut serve_out: ServeOut = blank_out();
    serve_out.head = out_head();
    json!({
        "scrape": spelled(&p.call(export::slot::SCRAPE, &mut Frame::new(scrape, scrape_out))),
        "status": spelled(&p.call(export::slot::STATUS, &mut Frame::new(in_head(), status))),
        "check": spelled(&p.call(export::slot::CHECK, &mut Frame::new(check, check_out))),
        "serve": spelled(&p.call(export::slot::SERVE, &mut Frame::new(serve, serve_out))),
    })
}

/// A `traces` record as the host's producer builds it.
fn record(span: &str, parent: Option<&str>) -> Value {
    let mut r = json!({
        "trace_id": "0000000000000011", "span_id": span, "name": "forward",
        "start": 1_700_000_000_000_000u64, "duration_us": 42,
        "pool": "p1", "ingress": "openai", "op": "chat",
    });
    if let Some(parent) = parent {
        r["parent_span_id"] = json!(parent);
    }
    r
}

/// `records` as the JSON-lines batch the host hands `deliver`.
fn jsonl(records: &[Value]) -> Vec<u8> {
    records
        .iter()
        .map(|r| format!("{r}\n"))
        .collect::<String>()
        .into_bytes()
}

/// `deliver` of `records` on a request ticket, as the host's delivery runs it.
fn deliver(host: &Host, p: &Plugin<Export>, records: &[Value]) -> String {
    let batch = jsonl(records);
    let mut input: DeliverIn = blank_in();
    input.head = in_head();
    input.stream = ExportStream::Traces as u8;
    input.batch = blob(&batch, BLOB_JSONL);
    let ticket = host.d.mint(0).expect("a ticket");
    let reply = host.d.submit(
        p,
        ticket,
        export::slot::DELIVER,
        Frame::new(input, out_head()),
        DeadlineClass::WriteBehind,
        now_ns() + 10_000_000_000,
    );
    let done = reply
        .wait(Duration::from_secs(10))
        .expect("the delivery completes");
    host.d.recycle(ticket);
    drop(batch);
    let text = done
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} {text}", done.outcome)
}

/// `deliver` with no ticket: it may not pend, so the connector is not reachable.
fn deliver_ticketless(p: &Plugin<Export>) -> String {
    let batch = jsonl(&[record("0000000000000019", None)]);
    let mut input: DeliverIn = blank_in();
    input.head = in_head();
    input.stream = ExportStream::Traces as u8;
    input.batch = blob(&batch, BLOB_JSONL);
    spelled(&p.call(export::slot::DELIVER, &mut Frame::new(input, out_head())))
}

/// One door's whole script, as one comparable transcript.
fn transcript(dropped: bool, settings: &str) -> Value {
    let host = Host::new();
    let live = load(&host, dropped);
    let validated: Vec<String> = [
        "",
        "{}",
        r#"{"url":"http://x/","otlp_endpoint":1}"#,
        "[1]",
        settings,
    ]
    .iter()
    .map(|s| validate(&live, s))
    .collect();
    let opened = open(&live, settings);
    let answers = kind_answers(&live);
    let delivered = [
        deliver(
            &host,
            &live,
            &[
                record("0000000000000011", None),
                json!({"name": "no identity"}),
            ],
        ),
        deliver(&host, &live, &[json!({"name": "no identity"})]),
        deliver(
            &host,
            &live,
            &[record("0000000000000012", Some("0000000000000011"))],
        ),
        deliver_ticketless(&live),
    ];
    let refreshed = refresh(&live, MOVED);
    let moved = deliver(&host, &live, &[record("0000000000000013", None)]);
    let closed = close(&live);

    let others: Vec<Value> = [FAILING, INTERNAL, PLAINTEXT]
        .iter()
        .map(|s| {
            let p = load(&host, dropped);
            let opened = open(&p, s);
            let first = deliver(&host, &p, &[record("0000000000000021", None)]);
            let again = deliver(&host, &p, &[record("0000000000000022", None)]);
            json!([opened, first, again, close(&p)])
        })
        .collect();

    json!({
        "name": live.name(),
        "kind": format!("{:?}", live.kind()),
        "max_inflight": live.max_inflight(),
        "validate": validated,
        "open": opened,
        "answers": answers,
        "deliver": delivered,
        "refresh": refreshed,
        "moved": moved,
        "close": closed,
        "others": others,
        "carried": host.collector.carried.lock().unwrap().clone(),
        "lines": host.lines.0.lock().unwrap().clone(),
    })
}

/// Every body the collector was handed, decoded by the publisher's types — and re-encoded to the

fn otlp_bodies(run: &Value) -> Vec<ExportTraceServiceRequest> {
    run["carried"]
        .as_array()
        .expect("carried")
        .iter()
        .map(|c| {
            let hex = c["body"].as_str().expect("a body");
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect();
            let request = ExportTraceServiceRequest::decode(&bytes[..]).expect("an OTLP request");
            assert_eq!(request.encode_to_vec(), bytes, "the canonical encoding");
            request
        })
        .collect()
}

/// Follow the host's parsed capability through the real export-instance queue, each door and the

#[test]
fn full_span_records_reach_the_collector_through_both_export_instances() {
    use busbar_contract::export_calls::{Delivered, ExportCalls};
    use busbar_plugin_loader::export_door::ExportInstance;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

    struct Completed(std::sync::mpsc::Sender<()>);
    impl Drop for Completed {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let full = json!({
        "trace_id": "0000000000000011",
        "span_id": "0000000000000012",
        "parent_span_id": "0000000000000010",
        "name": "forward",
        "start_ns": 1_700_000_000_000_000_001u64,
        "end_ns": 1_700_000_000_000_042_002u64,
        "attributes": [
            {"key": "pool", "value": "p1"},
            {"key": "request_id", "value": "9007199254740993"},
            {"key": "attempt", "value": 2},
            {"key": "cached", "value": false},
            {"key": "latency", "value": 1.25},
            {"key": "retries", "value": ["a", "b"]}
        ],
        "events": [{
            "name": "upstream refused",
            "time_ns": 1_700_000_000_000_041_003u64,
            "attributes": [{"key": "level", "value": "ERROR"}, {"key": "code", "value": 503}]
        }],
        "status": {"code": "error", "message": "upstream refused"}
    });
    let mut requests = Vec::new();
    for dropped in [false, true] {
        let host = Host::new();
        let instance =
            ExportInstance::open(load(&host, dropped), host.d.clone(), COLLECTOR.as_bytes())
                .expect("open the real export instance");
        assert!(
            instance.takes_span_records(),
            "the producer must receive the loaded door's full-span capability; dropped={dropped}"
        );

        let line = serde_json::to_vec(&json!({"span": full})).unwrap();
        let (done, completed) = std::sync::mpsc::channel();
        assert!(matches!(
            instance.deliver(ExportStream::Traces as u8, line, Box::new(Completed(done))),
            Delivered::Queued
        ));
        completed
            .recv_timeout(Duration::from_secs(10))
            .expect("the queued batch answers");
        let carried = host.collector.carried.lock().unwrap().clone();
        let decoded = otlp_bodies(&json!({"carried": carried}));
        assert_eq!(decoded.len(), 1, "one request; dropped={dropped}");
        let request = &decoded[0];
        let resource = &request.resource_spans[0];
        assert_eq!(
            resource.resource.as_ref().unwrap().attributes[0].key,
            "service.name"
        );
        assert_eq!(
            resource.resource.as_ref().unwrap().attributes[0]
                .value
                .as_ref()
                .unwrap()
                .value,
            Some(AnyValue::StringValue("busbar".into()))
        );
        assert_eq!(
            resource.scope_spans[0].scope.as_ref().unwrap().name,
            "busbar"
        );
        let spans = &resource.scope_spans[0].spans;
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(hex(&span.trace_id), "00000000000000000000000000000011");
        assert_eq!(hex(&span.span_id), "0000000000000012");
        assert_eq!(hex(&span.parent_span_id), "0000000000000010");
        assert_eq!(span.name, "forward");
        assert_eq!(span.kind, 1);
        assert_eq!(
            span.start_time_unix_nano,
            full["start_ns"].as_u64().unwrap()
        );
        assert_eq!(span.end_time_unix_nano, full["end_ns"].as_u64().unwrap());
        let attributes: Vec<_> = span
            .attributes
            .iter()
            .map(|kv| {
                (
                    kv.key.as_str(),
                    kv.value.as_ref().unwrap().value.clone().unwrap(),
                )
            })
            .collect();
        assert_eq!(attributes.len(), 6);
        assert_eq!(
            attributes[..5],
            [
                ("pool", AnyValue::StringValue("p1".into())),
                (
                    "request_id",
                    AnyValue::StringValue("9007199254740993".into())
                ),
                ("attempt", AnyValue::IntValue(2)),
                ("cached", AnyValue::BoolValue(false)),
                ("latency", AnyValue::DoubleValue(1.25)),
            ]
        );
        match &attributes[5].1 {
            AnyValue::ArrayValue(values) => assert_eq!(
                values
                    .values
                    .iter()
                    .map(|v| v.value.clone().unwrap())
                    .collect::<Vec<_>>(),
                [
                    AnyValue::StringValue("a".into()),
                    AnyValue::StringValue("b".into())
                ]
            ),
            value => panic!("the array attribute changed type: {value:?}"),
        }
        assert_eq!(span.events.len(), 1);
        let event = &span.events[0];
        assert_eq!(event.name, "upstream refused");
        assert_eq!(
            event.time_unix_nano,
            full["events"][0]["time_ns"].as_u64().unwrap()
        );
        assert_eq!(event.attributes.len(), 2);
        assert_eq!(event.attributes[0].key, "level");
        assert_eq!(event.attributes[1].key, "code");
        assert_eq!(
            event.attributes[0].value.as_ref().unwrap().value,
            Some(AnyValue::StringValue("ERROR".into()))
        );
        assert_eq!(
            event.attributes[1].value.as_ref().unwrap().value,
            Some(AnyValue::IntValue(503))
        );
        assert_eq!(span.status.as_ref().unwrap().code, 2);
        assert_eq!(span.status.as_ref().unwrap().message, "upstream refused");
        requests.push(request.clone());
        drop(instance);
    }
    assert_eq!(
        requests[0], requests[1],
        "linked and dropped doors preserve the same full record"
    );
}

/// The linked and the dropped-in OTLP sink are ONE plugin: the same answers, the same requests to

#[test]
fn the_linked_and_the_dropped_in_otlp_sink_are_one_plugin() {
    let linked = transcript(false, COLLECTOR);
    let dropped_in = transcript(true, COLLECTOR);
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    assert_eq!(linked["name"], "busbar-export-otlp");
    assert_eq!(linked["kind"], "Export");
    assert_eq!(linked["max_inflight"], 64);
    let validate = linked["validate"].as_array().unwrap();

    assert_eq!(
        validate[0], "Failed settings: missing field `url`",
        "{validate:?}"
    );
    assert_eq!(validate[1], "Failed settings: missing field `url`");
    assert_eq!(
        validate[2],
        "Failed settings: unknown field `otlp_endpoint`, expected `url`"
    );
    assert!(
        validate[3]
            .as_str()
            .unwrap()
            .starts_with("Failed settings: invalid type: "),
        "{validate:?}"
    );
    assert_eq!(validate[4], "Ready ");
    assert_eq!(linked["open"], "Ready ");
    assert_eq!(
        linked["answers"],
        json!({
            "scrape": format!("Refused {}", busbar_export_otlp::door::NO_EXPOSITION),
            "status": "Ready ",
            "check": "Ready ",
            "serve": format!("Refused {}", busbar_export_otlp::door::NO_ROUTE),
        })
    );
    assert_eq!(
        linked["deliver"],
        json!(["Ready ", "Ready ", "Ready ", "Ready "])
    );
    assert_eq!(linked["refresh"], "Ready ");
    assert_eq!(linked["moved"], "Ready ");
    assert_eq!(linked["close"], "Ready ");

    let carried = linked["carried"].as_array().unwrap();
    let route = |c: &Value| {
        (
            c["target"].as_str().unwrap().to_owned(),
            c["head_target"].as_str().unwrap().to_owned(),
        )
    };
    assert_eq!(
        carried.iter().map(route).collect::<Vec<_>>(),
        [
            ("http://127.0.0.1:4318/v1/traces", "/v1/traces"),
            ("http://127.0.0.1:4318/v1/traces", "/v1/traces"),
            ("http://127.0.0.1:4318/v2/traces", "/v2/traces"),
            ("https://collector.example/fail", "/fail"),
            ("https://collector.example/fail", "/fail"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
    );
    for c in carried {
        assert!(
            !c["target"].as_str().unwrap().contains('@'),
            "the target the host dials carries no userinfo: {c}"
        );
        assert_eq!(c["need"], 0);
        assert_eq!(c["method"], "POST");
        assert_eq!(c["timeout_ms"], 10_000);
        assert_eq!(
            c["fields"][0],
            json!(["content-type", "application/x-protobuf"])
        );
    }
    assert_eq!(carried[0]["fields"].as_array().unwrap().len(), 1);
    assert_eq!(
        carried[3]["fields"][1],
        json!(["authorization", "Basic dTpw"]),
        "the userinfo rides as a Basic header"
    );

    let bodies = otlp_bodies(&linked);
    let spans: Vec<_> = bodies
        .iter()
        .map(|r| &r.resource_spans[0].scope_spans[0].spans)
        .collect();
    assert_eq!(spans[0].len(), 1, "the record that is no span adds nothing");
    assert_eq!(spans[0][0].span_id, vec![0, 0, 0, 0, 0, 0, 0, 0x11]);
    assert!(spans[0][0].parent_span_id.is_empty());
    assert_eq!(spans[1][0].parent_span_id, spans[0][0].span_id);
    assert_eq!(spans[1][0].trace_id, spans[0][0].trace_id);
    assert_eq!(
        spans[0][0].end_time_unix_nano - spans[0][0].start_time_unix_nano,
        42_000
    );

    let lines: Vec<String> = linked["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    let all = lines.join("\n");
    assert!(
        !all.contains("u:p@"),
        "a line carries the credential: {all}"
    );
    let count = |needle: &str| lines.iter().filter(|l| l.contains(needle)).count();
    assert_eq!(count("OTLP tracing enabled"), 3, "{all}");
    assert_eq!(
        count("OTLP tracing enabled endpoint=http://127.0.0.1:4318/v1/traces"),
        1,
        "{all}"
    );
    assert_eq!(
        count("OTLP tracing enabled endpoint=http://127.0.0.1:4318/***"),
        1,
        "{all}"
    );
    assert_eq!(
        count("OTLP tracing enabled endpoint=https://***@collector.example/***"),
        1,
        "{all}"
    );
    assert_eq!(count("skipped a record with no span identity"), 2, "{all}");
    assert_eq!(count("returned a non-2xx status"), 2, "{all}");
    assert_eq!(count("status=503"), 2, "{all}");
    assert_eq!(count("; disabling OTLP trace export"), 2, "{all}");
    assert_eq!(
        count("OTLP span export failed"),
        1,
        "the ticketless delivery: {all}"
    );
    assert!(
        lines
            .iter()
            .filter(|l| l.contains("disabling"))
            .all(|l| l.starts_with("2 ")),
        "a refusal is an error line: {all}"
    );

    for (needle, severity) in [
        ("OTLP tracing enabled", "0 "),
        ("returned a non-2xx status", "1 "),
        ("OTLP span export failed", "1 "),
    ] {
        assert!(
            lines
                .iter()
                .filter(|l| l.contains(needle))
                .all(|l| l.starts_with(severity)),
            "`{needle}` lines must carry severity {severity:?}: {all}"
        );
    }

    let other = transcript(true, PLAINTEXT);
    assert_ne!(
        other, linked,
        "a door over another config must not compare equal"
    );
}

/// THE REPLY BOUND, end to end through the host's connector: a 2xx reply whose 80 KB body (read

#[test]
fn a_reply_past_the_bound_is_delivered_on_2xx_and_a_non_2xx_drop_otherwise() {
    for dropped in [false, true] {
        let host = Host::new();
        let p = load(&host, dropped);
        open(&p, r#"{"url":"https://collector.example/big"}"#);
        deliver(&host, &p, &[record("0000000000000031", None)]);
        let lines = host.lines.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("OTLP tracing enabled")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("1 ")
                    && l.contains("partial-success details are unavailable")),
            "{lines:?}"
        );

        let q = load(&host, dropped);
        open(&q, r#"{"url":"https://collector.example/bigfail"}"#);
        deliver(&host, &q, &[record("0000000000000032", None)]);
        let lines = host.lines.0.lock().unwrap().clone();
        let non_2xx: Vec<_> = lines
            .iter()
            .filter(|l| l.contains("returned a non-2xx status"))
            .collect();
        assert_eq!(non_2xx.len(), 1, "{lines:?}");
        assert!(non_2xx[0].contains("status=503"), "{lines:?}");
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("rejected part") || l.contains("export failed")),
            "{lines:?}"
        );
    }
}

/// RED: the door asked for as another kind is refused, by either origin, before any slot runs.
#[test]
fn a_wrong_kind_is_refused() {
    use busbar_contract::abi::mechanism::KindCode;

    let host = Host::new();
    let expected = LoadError::ManifestKind {
        stated: KindCode::Export,
        want: KindCode::Secret,
    };
    let err = load_linked::<Secret>(&row(), host.bind())
        .expect_err("an export door is not a secret door");
    assert_eq!(
        err, expected,
        "the linked rendering is rejected before entry"
    );
    let err = load_dropped::<Secret>(&cdylib(), &row().statement, host.bind())
        .expect_err("the dropped-in export door is not a secret door");
    assert_eq!(
        err, expected,
        "the dropped rendering is rejected before entry"
    );
}

/// RED: a manifest stating 1.5.5's export ABI (2) is refused before `dlopen` (THE DESIGN §11.8).
#[test]
fn a_manifest_stating_the_1_5_5_export_abi_is_refused() {
    let mut stated = row().statement;
    let at = RENDERING_MAGIC.len() + 8;
    assert_eq!(
        u32::from_le_bytes(stated[at..at + 4].try_into().unwrap()),
        export::ABI_VERSION
    );
    stated[at..at + 4].copy_from_slice(&(export::ABI_VERSION - 1).to_le_bytes());
    let err = load_dropped::<Export>(&cdylib(), &stated, Host::new().bind())
        .expect_err("1.5.5's export ABI is refused");
    assert!(matches!(err, LoadError::ManifestKindAbi { .. }), "{err:?}");
}

/// `check` at `phase` over instances named `names`, through the slot: the call's outcome and the

fn check_through_the_door(
    p: &Plugin<Export>,
    phase: u32,
    names: &[&'static str],
) -> (String, Option<String>) {
    let instances: Vec<export::CheckInstance> = names
        .iter()
        .map(|n| export::CheckInstance {
            name: busbar_contract::abi::mechanism::call::AbiStr::of(n),
            settings: Blob::ABSENT,
        })
        .collect();
    let mut check: CheckIn = blank_in();
    check.head = in_head();
    check.phase = phase;
    check.instances = instances.as_ptr();
    check.instances_len = instances.len();
    let check_out = CheckOut {
        head: out_head(),
        findings: NO_BLOB,
    };
    let mut frame = Frame::new(check, check_out);
    let called = p.call(export::slot::CHECK, &mut frame);
    let findings = frame.out.findings;
    // SAFETY: the sink's findings are a plugin-owned result live under the call's lease, which this
    // test does not release before it has copied the bytes.
    let text = (!findings.ptr.is_null())
        .then(|| String::from_utf8(unsafe { findings.bytes() }.to_vec()).expect("UTF-8 findings"));
    (spelled(&called), text)
}

/// THE LIMITS-PHASE CHECK, DRIVEN THROUGH THE DOOR: with two instances at the limits phase the sink

#[test]
fn the_limits_check_refuses_a_second_instance_through_the_door() {
    let expected = serde_json::to_string(&busbar_contract::abi::sdk::export::second_instances(
        &["first".to_string(), "second".to_string()],
        busbar_export_otlp::ALIAS,
        busbar_export_otlp::ONE_INSTANCE,
    ))
    .unwrap();
    assert!(
        expected.contains("export.second") && expected.contains("'first'"),
        "{expected}"
    );
    for dropped in [false, true] {
        let host = Host::new();
        let p = load(&host, dropped);
        assert_eq!(open(&p, COLLECTOR), "Ready ");
        let (outcome, findings) =
            check_through_the_door(&p, export::CHECK_PHASE_LIMITS, &["first", "second"]);
        assert_eq!(outcome, "Ready ", "dropped={dropped}");
        assert_eq!(
            findings.as_deref(),
            Some(expected.as_str()),
            "dropped={dropped}"
        );
        let (outcome, findings) =
            check_through_the_door(&p, export::CHECK_PHASE_INSTANCES, &["first", "second"]);
        assert_eq!(outcome, "Ready ", "dropped={dropped}");
        assert_eq!(findings, None, "no finding at the instances phase");
        let (_, findings) = check_through_the_door(&p, export::CHECK_PHASE_LIMITS, &["first"]);
        assert_eq!(findings, None, "one instance is no finding");
        close(&p);
    }
}

/// THE NEED IS PINNED TO THE `url` SETTING, read from the Statement the door states: the target

#[test]
fn the_statement_need_names_the_url_setting_and_the_loopback_http_collector() {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, KEEP_NAMED};
    let st = busbar_export_otlp::door::STATEMENT;
    assert_eq!(st.needs_len, 1);
    // SAFETY: the Statement's needs are a `'static` list of `needs_len` entries.
    let need = unsafe { std::slice::from_raw_parts(st.needs, st.needs_len) }[0];
    // SAFETY: the Statement's strings are `'static`.
    let (target, transport) = unsafe { (need.target_from.bytes(), need.transport.bytes()) };
    assert_eq!(target, b"settings.url");
    assert_eq!(transport, b"http");
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_LOOPBACK_ALLOWED);
    assert_eq!(need.timeout_ms, busbar_export_otlp::EXPORT_TIMEOUT_MS);
    assert_eq!(need.keep_mode, KEEP_NAMED);
}

/// THE STATEMENT STATES THE ALIAS REWRITE: one rewrite, of the alias class, from the module name

#[test]
fn the_statement_states_the_otlp_alias_rewrite() {
    use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
    let st = busbar_export_otlp::door::STATEMENT;
    assert_eq!(st.rewrites_len, 1);
    // SAFETY: the Statement's rewrites are a `'static` list of `rewrites_len` entries.
    let rewrite = unsafe { std::slice::from_raw_parts(st.rewrites, st.rewrites_len) }[0];
    assert_eq!(rewrite.class, REWRITE_ALIAS);
    // SAFETY: the Statement's strings are `'static`.
    assert_eq!(unsafe { rewrite.from.bytes() }, b"otlp");
}

#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The collector's answer: an HTTP/1.1 `200` (an empty OTLP response) once a whole request (its

fn collected(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (seen.len() >= end + body).then(|| {
        b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n"
            .to_vec()
    })
}

/// The host the suite binds the sink over, with the collector its settings name already listening.
fn suite_host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn DeclaredConns> {
    conformance_host::far_end(collected);
    conformance_host::host(wake, anchors)
}

busbar_test_kit::conformance_suite! {
    door: busbar_export_otlp::door::door,
    cdylib: "busbar_export_otlp_plugin",
    inputs: include_str!("conformance.json"),
    host: suite_host,
    tls: conformance_host::anchors(),
}

/// The sink's declared secret fields, as the kernel resolves them (busbar #1699; OWNER RULING,

mod declared_secrets {
    use std::sync::Arc;

    use busbar_plugin_loader::dispatch::kinds::export::Export;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
    };
    use busbar_test_kit::conformance::settings_as_the_kernel_resolves;
    use serde_json::{json, Value};

    fn load() -> Plugin<Export> {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        load_linked::<Export>(
            &LinkedRow::of(busbar_export_otlp::door::door).expect("the linked door renders"),
            Bind {
                instance: Arc::from("declared"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::Host(super::conformance_host::host(Arc::new(|_, _| {}), None)),
            },
        )
        .expect("the linked door loads")
    }

    fn resolved(_: &str, _: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
        Ok("resolved-value".to_string())
    }

    #[test]
    fn a_reference_at_each_declared_field_resolves_in_place() {
        let out = settings_as_the_kernel_resolves(&load(), br#"{"url":{"env":"X"}}"#, resolved)
            .expect("the declared fields take a reference");
        let v: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(v["url"], json!("resolved-value"), "{v}");
    }

    #[test]
    fn a_reference_at_an_undeclared_field_is_refused() {
        let e = settings_as_the_kernel_resolves(
            &load(),
            br#"{"url":"http://127.0.0.1:4318/v1/traces","nope":{"env":"X"}}"#,
            resolved,
        )
        .expect_err("an undeclared field takes no reference");
        assert!(e.contains("did not declare it as a secret"), "{e}");
    }
}
