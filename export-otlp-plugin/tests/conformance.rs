// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE OTLP TRACE SINK, BOTH DOORS, ONE TABLE** — the sink's linked + dropped-in conformance on
//! the export kind's memory ABI (THE DESIGN §11.4), run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The sink is held two ways at once: LINKED (the logic crate's `door::door`, through the loader's
//! `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the loader's
//! `load_dropped`, which resolves `busbar_plugin_door` and compares its Statement with the linked
//! row's, byte for byte). Each is bound to a real dispatcher and to a stand-in for the host's
//! connection table — a collector that judges each target it is asked to dial under the need's
//! egress class (`https://`, or plaintext to `127.0.0.1` under `loopback-allowed`;
//! `*.internal.example` never)
//! and answers 503 on a path ending `/fail`, 200 otherwise — and driven over one script: validate,
//! open, the kind's answers, deliveries on request tickets (spans, a record that is no span), a
//! failing collector, refused targets, a refresh that moves the target, close. Everything the host
//! sees — the answers, every request the connector was handed (octets included) and every line the
//! sink logged through the door's call capture — must be identical between the doors, and every
//! body must be an OTLP `ExportTraceServiceRequest` by the OpenTelemetry project's own types,
//! re-encoding to the same bytes.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused, by either origin; a
//! manifest stating 1.5.5's export ABI (2) is refused before `dlopen`; a refused target carries
//! nothing and disables the run, saying so; the same image over another config answers another
//! transcript. A missing cdylib PANICS — this test IS the dropped-in door's proof, and never skips.

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
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, Called, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, LoadError, Metric, Plugin, NO_BLOB,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message as _;
use serde_json::{json, Value};

const COLLECTOR: &str = r#"{"url":"http://127.0.0.1:4318/v1/traces"}"#;
const FAILING: &str = r#"{"url":"https://u:p@collector.example/fail"}"#;
const INTERNAL: &str = r#"{"url":"https://collector.internal.example/v1/traces"}"#;
const PLAINTEXT: &str = r#"{"url":"http://collector.example/v1/traces"}"#;
const MOVED: &str = r#"{"url":"http://127.0.0.1:4318/v2/traces"}"#;

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
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

// ── the host's stand-ins ─────────────────────────────────────────────────────────────────────────

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
        reason: None,
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
        // The target the plugin named at establish, else the one the need was declared at.
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
            "body": hex(desc.body),
        }));
        let id = self.slab.insert(caller, need, ())?;
        let code = if desc.head_target.ends_with(b"/fail") {
            503
        } else {
            200
        };
        self.replies.lock().unwrap().insert(
            id,
            VecDeque::from([
                piece(PieceKind::Fields, Some(code)),
                piece(PieceKind::Completion, None),
            ]),
        );
        Ok(id)
    }

    fn write(&self, c: InstanceId, id: ConnId, b: &[u8], _: bool) -> Result<usize, ConnError> {
        self.slab.get(c, id)?;
        Ok(b.len())
    }

    fn read(&self, c: InstanceId, id: ConnId, _: u64, _: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        self.replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .ok_or(ConnError::Closed)
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
            conns: Some(conns),
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

// ── the script ───────────────────────────────────────────────────────────────────────────────────

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
/// very same bytes.
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

/// The linked and the dropped-in OTLP sink are ONE plugin: the same answers, the same requests to
/// the collector, the same log — and the same image over another config is not (RED).
#[test]
fn the_linked_and_the_dropped_in_otlp_sink_are_one_plugin() {
    let linked = transcript(false, COLLECTOR);
    let dropped_in = transcript(true, COLLECTOR);
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    assert_eq!(linked["name"], "busbar-export-otlp");
    assert_eq!(linked["kind"], "Export");
    assert_eq!(linked["max_inflight"], 64);
    let validate = linked["validate"].as_array().unwrap();
    assert!(
        validate[0]
            .as_str()
            .unwrap()
            .starts_with("Failed settings: EOF while parsing"),
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
        json!({"scrape": "Refused ", "status": "Ready ", "check": "Ready ", "serve": "Refused "})
    );
    assert_eq!(
        linked["deliver"],
        json!(["Ready ", "Ready ", "Ready ", "Ready "])
    );
    assert_eq!(linked["refresh"], "Ready ");
    assert_eq!(linked["moved"], "Ready ");
    assert_eq!(linked["close"], "Ready ");

    // What the collector was handed: the two span batches (the record with no identity asked for
    // nothing), the moved target's, and the failing collector's two; nothing for a refused target.
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

    // The log: enabled on the first carried export of each instance and again after the refresh
    // that moved its target (the need is re-declared), the record that is no span
    // and every dropped export at debug, the endpoint always masked; a refused target disabled.
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
        count("OTLP tracing enabled endpoint=http://127.0.0.1:4318/v2/traces"),
        1,
        "{all}"
    );
    assert_eq!(
        count("OTLP tracing enabled endpoint=https://***@collector.example/fail"),
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

    // RED: the same image over another config answers another transcript.
    let other = transcript(true, PLAINTEXT);
    assert_ne!(
        other, linked,
        "a door over another config must not compare equal"
    );
}

/// RED: the door asked for as another kind is refused, by either origin, before any slot runs.
#[test]
fn a_wrong_kind_is_refused() {
    let host = Host::new();
    let err = load_linked::<Secret>(&row(), host.bind())
        .expect_err("an export door is not a secret door");
    assert!(
        matches!(
            err,
            LoadError::WrongKind { .. } | LoadError::StatementMismatch
        ),
        "{err:?}"
    );
    let err = load_dropped::<Secret>(&cdylib(), &row().statement, host.bind())
        .expect_err("the dropped-in export door is not a secret door");
    assert!(matches!(err, LoadError::ManifestKind { .. }), "{err:?}");
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

// THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN (busbar's loader, at the commit this repo pins):
// the sink driven two ways through the one loader over the export kind's script with the inputs in
// `conformance.json`, every step's crossings exactly at the script's pin, the two folds equal, and
// the suite's RED arms kept.
busbar_plugin_loader::conformance_suite! {
    door: busbar_export_otlp::door::door,
    cdylib: "busbar_export_otlp_plugin",
    inputs: include_str!("conformance.json"),
}
