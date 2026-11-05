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
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, OpenIn, OpenOut, ValidateIn};
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

/// CI builds this repository's actual cdylib before invoking these tests.
fn cdylib() -> PathBuf {
    let path = match std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        }
        None => {
            let exe = std::env::current_exe().expect("the test binary has a path");
            exe.parent()
                .and_then(|d| d.parent())
                .expect("target/<profile>")
                .join(busbar_plugin_loader::plugin_library_filename(
                    "busbar_export_otlp_plugin",
                ))
        }
    };
    assert!(
        path.is_file(),
        "build the actual busbar-export-otlp-plugin cdylib before testing: {}",
        path.display()
    );
    path
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
    slab: ConnSlab<Mutex<Prepared>>,
    profile: CarrierProfile,
    /// Per `(instance, need)`: its egress class and declared target.
    declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    carried: Mutex<Vec<Value>>,
    replies: Mutex<HashMap<ConnId, VecDeque<Piece>>>,
    /// The body bytes each connection's `Body` pieces fill the read buffer with, in order.
    bodies: Mutex<HashMap<ConnId, VecDeque<Vec<u8>>>>,
}

/// Scripted established carrier evidence, deliberately independent of the target URL.
#[derive(Clone, Copy, Default)]
enum CarrierProfile {
    #[default]
    Clear,
    Missing,
    Secure,
}

struct Prepared {
    need: NeedId,
    target: String,
    committed: bool,
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
        status_namespace: code.map(|_| "http".to_owned()),
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
    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        _: u64,
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
        self.slab.insert(
            caller,
            need,
            Mutex::new(Prepared {
                need,
                target,
                committed: false,
            }),
        )
    }

    fn commit_request(
        &self,
        caller: InstanceId,
        conn: ConnId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), ConnError> {
        let (_, entry) = self.slab.get(caller, conn)?;
        let mut prepared = entry.lock().unwrap();
        if prepared.committed || (!desc.target.is_empty() && desc.target != prepared.target) {
            return Err(ConnError::Refused);
        }
        if require_secure && !matches!(self.profile, CarrierProfile::Secure) {
            return Err(ConnError::AuthRefused);
        }
        prepared.committed = true;
        self.capture(conn, prepared.need, &prepared.target, desc);
        Ok(())
    }

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

impl Collector {
    fn capture(&self, id: ConnId, need: NeedId, target: &str, desc: &OpenDesc<'_>) {
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
    }
}

impl Conns for Collector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let id = self.prepare_request(caller, need, desc, desc.timeout_ms)?;
        self.commit_request(caller, id, desc, false)?;
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

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        match self.profile {
            CarrierProfile::Missing => Err(ConnError::Closed),
            CarrierProfile::Clear => Ok(ConnFacts::default()),
            CarrierProfile::Secure => Ok(ConnFacts {
                peer_cert: Some(busbar_contract::transport::wire::CertFacts {
                    subject: "scripted collector".into(),
                    issuer: "scripted fixture".into(),
                    fingerprint: "ab".repeat(32),
                }),
                ..ConnFacts::default()
            }),
        }
    }

    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.slab.remove(c, id)?;
        self.replies.lock().unwrap().remove(&id);
        self.bodies.lock().unwrap().remove(&id);
        Ok(())
    }
}

#[test]
fn prepared_collector_commits_once_on_the_owned_connection() {
    let collector = Collector {
        profile: CarrierProfile::Secure,
        ..Collector::default()
    };
    let owner = InstanceId(1);
    let need = NeedId(0);
    collector.slab.declare(owner, need);
    collector
        .declared
        .lock()
        .unwrap()
        .insert((owner, need), (EGRESS_LOOPBACK_ALLOWED, None));
    let desc = OpenDesc {
        target: "https://collector.example/v1/traces",
        ..OpenDesc::default()
    };
    let conn = collector.prepare_request(owner, need, &desc, 0).unwrap();
    assert!(collector.carried.lock().unwrap().is_empty());
    assert!(collector.facts(owner, conn).unwrap().peer_cert.is_some());
    assert!(matches!(
        collector.facts(InstanceId(2), conn),
        Err(ConnError::NotOwner)
    ));
    assert!(matches!(
        collector.commit_request(InstanceId(2), conn, &desc, true),
        Err(ConnError::NotOwner)
    ));
    let changed = OpenDesc {
        target: "https://other.example/",
        ..desc.clone()
    };
    assert!(matches!(
        collector.commit_request(owner, conn, &changed, true),
        Err(ConnError::Refused)
    ));
    assert!(collector.carried.lock().unwrap().is_empty());
    collector.commit_request(owner, conn, &desc, true).unwrap();
    assert!(collector.replies.lock().unwrap().contains_key(&conn));
    assert!(matches!(
        collector.commit_request(owner, conn, &desc, true),
        Err(ConnError::Refused)
    ));
    assert_eq!(collector.carried.lock().unwrap().len(), 1);
    collector.close(owner, conn).unwrap();
    assert!(matches!(
        collector.facts(owner, conn),
        Err(ConnError::Closed)
    ));
}

#[test]
fn protected_collector_requests_require_explicit_carrier_evidence() {
    for profile in [CarrierProfile::Clear, CarrierProfile::Missing] {
        let collector = Collector {
            profile,
            ..Collector::default()
        };
        let owner = InstanceId(1);
        let need = NeedId(0);
        collector.slab.declare(owner, need);
        collector
            .declared
            .lock()
            .unwrap()
            .insert((owner, need), (EGRESS_LOOPBACK_ALLOWED, None));
        let desc = OpenDesc {
            target: "https://collector.example/v1/traces",
            ..OpenDesc::default()
        };
        let conn = collector.prepare_request(owner, need, &desc, 0).unwrap();
        assert!(!collector
            .facts(owner, conn)
            .is_ok_and(|f| f.peer_cert.is_some()));
        assert!(matches!(
            collector.commit_request(owner, conn, &desc, true),
            Err(ConnError::AuthRefused)
        ));
        assert!(collector.carried.lock().unwrap().is_empty());
        assert!(collector.replies.lock().unwrap().is_empty());
    }
}

#[test]
fn protected_otlp_never_reaches_an_unproven_collector_through_either_door() {
    for dropped in [false, true] {
        for profile in [CarrierProfile::Clear, CarrierProfile::Missing] {
            let host = Host::with_profile(profile);
            let plugin = load(&host, dropped);
            open(&plugin, FAILING);
            deliver(&host, &plugin, &[record("0000000000000021", None)]);
            assert!(host.collector.carried.lock().unwrap().is_empty());
            close(&plugin);
        }
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
        Self::with_profile(CarrierProfile::Clear)
    }

    fn with_profile(profile: CarrierProfile) -> Self {
        Self {
            d: Arc::new(Dispatcher::new(DispatchConfig {
                workers: 2,
                watchdog_period: Duration::from_millis(20),
                ..DispatchConfig::default()
            })),
            collector: Arc::new(Collector {
                profile,
                ..Collector::default()
            }),
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
    let host = Host::with_profile(CarrierProfile::Secure);
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
    let refreshed = spelled(&calls::refresh(&live, &host.d, MOVED.as_bytes()));
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

/// Follow the host's parsed capability through the real export-instance queue, each door and the
/// collector. The supplied full record is a protocol fixture; actual kernel tracing production
/// additionally requires an assembled-product test.
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
/// whole it says `partial_success` rejected 5 spans) passes the sink's 64 KiB bound is a delivered
/// batch, with no rejection line and no dropped-export line; the same body on a 503 is the usual
/// non-2xx drop with its status. Without `reply_limit` the first would log the rejection; without
/// the past-bound rewrite it would log a failed export.
#[test]
fn a_reply_past_the_bound_is_delivered_on_2xx_and_a_non_2xx_drop_otherwise() {
    for dropped in [false, true] {
        let host = Host::with_profile(CarrierProfile::Secure);
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
/// findings the sink leased (the JSON text), if it wrote any.
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
/// leases `second_instances`' one refusal (naming the second and the first); at the instances phase it
/// has nothing to say whatever the instances. Both doors.
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
/// is the setting's name (its bytes, not just its length) and the rest of the declaration is the
/// collector's.
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
/// `otlp` (its bytes, read from the Statement the door states).
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
/// head, then the `content-length` body it states) has been read.
static RECEIVED: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

fn collected(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (seen.len() >= end + body).then(|| {
        RECEIVED.lock().unwrap().push(seen[..end + body].to_vec());
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

#[path = "support/calls.rs"]
mod calls;
#[path = "support/settings.rs"]
mod settings;

#[test]
fn the_linked_and_freshly_built_dropped_otlp_obey_the_export_contract() {
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    use busbar_contract::abi::{
        export::{self, CheckIn, CheckInstance, CheckOut, DeliverIn, ServeIn, ServeOut, StatusOut},
        mechanism::{
            call::{AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSONL},
            lifecycle::{self, ReleaseIn, TickIn, TickOut, ValidateIn},
        },
    };
    use busbar_plugin_loader::dispatch::kinds::export::Export;
    use busbar_plugin_loader::dispatch::{load_dropped, load_linked, ConnTable, Frame, LinkedRow};
    use std::sync::Arc;
    let mut inputs: serde_json::Value =
        serde_json::from_str(include_str!("conformance.json")).unwrap();
    let port = conformance_host::far_end(collected);
    inputs["settings"]["url"] = format!("https://localhost:{port}/v1/traces").into();
    let settings = inputs["settings"].to_string().into_bytes();
    let row = LinkedRow::of(busbar_export_otlp::door::door).expect("actual linked statement");
    let mut answers = Vec::new();
    for dropped in [false, true] {
        RECEIVED.lock().unwrap().clear();
        let d = calls::dispatcher();
        let tape = Arc::new(calls::Observed::default());
        let bind = busbar_plugin_loader::dispatch::Bind {
            sink: tape.clone(),
            conns: ConnTable::Host(suite_host(
                d.conn_waker(),
                Some(conformance_host::anchors()),
            )),
            ..calls::bind(&d, "conformance")
        };
        let p = if dropped {
            load_dropped::<Export>(&cdylib(), &row.statement, bind)
        } else {
            load_linked::<Export>(&row, bind)
        }
        .expect("actual OTLP loads");
        let mut observed = vec![format!(
            "{} {:?} {:?}",
            p.name(),
            p.secret_refs(),
            p.reference_fields()
        )];
        use std::sync::atomic::Ordering;
        let mut prior_crossings = p.inner.crossings.load(Ordering::SeqCst);
        let mut prior_resumes = p.inner.resumes.load(Ordering::SeqCst);
        let mut counts = Vec::new();
        let mut pin = |label: &str, first: u64| {
            let crossings = p.inner.crossings.load(Ordering::SeqCst);
            let resumes = p.inner.resumes.load(Ordering::SeqCst);
            let resumed = resumes - prior_resumes;
            assert_eq!(
                crossings - prior_crossings - resumed,
                first,
                "{label}: first invocations"
            );
            counts.push((label.to_owned(), first, tape.take()));
            eprintln!("{label}: first={first} resumes={resumed}");
            prior_crossings = crossings;
            prior_resumes = resumes;
        };
        assert_eq!(p.kind(), busbar_contract::abi::mechanism::KindCode::Export);
        assert_eq!(p.name(), "busbar-export-otlp");
        assert_eq!(p.max_inflight(), 64);
        pin("facts", 0);
        for (index, case) in inputs["export"]["bad_settings"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let bytes = case["settings"].to_string().into_bytes();
            let mut i: ValidateIn = blank_in();
            i.settings = calls::json(&bytes);
            let mut error = [0u8; 1024];
            i.err_buf = error.as_mut_ptr();
            i.err_cap = error.len();
            let c = p.call(
                lifecycle::slot::VALIDATE,
                &mut Frame::new(i, blank_out::<OutHead>()),
            );
            let route = if dropped { "dropped-in" } else { "linked" };
            let expected = case["refusal"].as_str().expect("fixture refusal text");
            assert_eq!(
                c.outcome,
                Outcome::Failed,
                "{route} bad settings #{index}: {}",
                calls::called(&c)
            );
            assert_eq!(
                c.lease,
                0,
                "{route} bad settings #{index}: {}",
                calls::called(&c)
            );
            let actual = String::from_utf8_lossy(c.error.as_ref().unwrap_or_else(|| {
                panic!("{route} bad settings #{index}: missing refusal text; expected {expected:?}")
            }));
            assert!(actual.contains(expected),
                "{route} bad settings #{index}: expected refusal substring {expected:?}, actual {actual:?}");
            observed.push(calls::called(&c));
            pin("validate bad", 1);
        }
        let batch = Arc::new(
            inputs["export"]["deliver"][0]["batch"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        let deliver = || {
            let mut i: DeliverIn = blank_in();
            i.stream = export::ExportStream::Traces as u8;
            i.op_id = [1; 16];
            i.batch = Blob {
                fmt: BLOB_JSONL,
                ..calls::json(&batch)
            };
            calls::on_ticket(
                &p,
                &d,
                export::slot::DELIVER,
                Frame::new(i, blank_out::<OutHead>()),
                DeadlineClass::WriteBehind,
                0,
                batch.clone(),
            )
        };
        assert_ne!(
            deliver().outcome,
            Outcome::Ready,
            "unopened exporter delivers nothing"
        );
        pin("deliver unopened", 0);
        let mut i: ValidateIn = blank_in();
        i.settings = calls::json(&settings);
        assert_eq!(
            p.call(
                lifecycle::slot::VALIDATE,
                &mut Frame::new(i, blank_out::<OutHead>())
            )
            .outcome,
            Outcome::Ready
        );
        pin("validate", 1);
        assert_eq!(
            calls::open_resumed(&p, &d, &settings).outcome,
            Outcome::Ready
        );
        pin("open", 1);
        p.ready(&d, std::time::Duration::from_secs(10))
            .expect("OTLP ready");
        pin("ready", u64::from(p.has_ready()));
        let c = deliver();
        assert_eq!(c.outcome, Outcome::Ready);
        assert_eq!(c.lease, 0);
        observed.push(calls::called(&c));
        pin("deliver #0", 1);
        let mut leases = Vec::new();
        let mut status = Frame::new(blank_in::<InHead>(), blank_out::<StatusOut>());
        let c = p.call(export::slot::STATUS, &mut status);
        assert_eq!(c.outcome, Outcome::Ready);
        pin("status", 1);
        // SAFETY: the loader judged the returned blob; its result lease is still live.
        let bytes = if status.out.status.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(status.out.status.ptr, status.out.status.len) }
                .to_vec()
        };
        observed.push(format!("status {:?}", bytes));
        if c.lease != 0 {
            leases.push(c.lease);
        }
        let rows = [CheckInstance {
            name: AbiStr::of("conformance"),
            settings: calls::json(&settings),
        }];
        for phase in [export::CHECK_PHASE_LIMITS, export::CHECK_PHASE_INSTANCES] {
            let mut i: CheckIn = blank_in();
            i.phase = phase;
            i.instances = rows.as_ptr();
            i.instances_len = rows.len();
            let mut f = Frame::new(i, blank_out::<CheckOut>());
            let c = p.call(export::slot::CHECK, &mut f);
            assert_eq!(c.outcome, Outcome::Ready);
            pin("check phase", 1);
            // SAFETY: the loader judged the findings blob; its result lease is still live.
            let bytes = if f.out.findings.len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(f.out.findings.ptr, f.out.findings.len) }
                    .to_vec()
            };
            observed.push(format!("check {phase} {:?}", bytes));
            if c.lease != 0 {
                leases.push(c.lease);
            }
        }
        let mut i: ServeIn = blank_in();
        i.method = AbiStr::of("GET");
        i.path = AbiStr::of("/exports/tail/x");
        let c = p.call(
            export::slot::SERVE,
            &mut Frame::new(i, blank_out::<ServeOut>()),
        );
        assert_eq!(c.outcome, Outcome::Refused);
        pin("serve #0", 1);
        observed.push(calls::called(&c));
        if c.lease != 0 {
            leases.push(c.lease);
        }
        let unique: std::collections::BTreeSet<_> = leases.iter().collect();
        assert_eq!(unique.len(), leases.len());
        pin("own leases", 0);
        let release = |lease| {
            let mut i: ReleaseIn = blank_in();
            i.lease = lease;
            p.call(
                lifecycle::slot::RELEASE,
                &mut Frame::new(i, blank_out::<OutHead>()),
            )
        };
        for &lease in &leases {
            assert_eq!(release(lease).outcome, Outcome::Ready);
            pin("release", 1);
        }
        if let Some(&lease) = leases.first() {
            assert_eq!(release(lease).outcome, Outcome::Refused);
            pin("release again", 1);
        }
        let mut tick = Frame::new(blank_in::<TickIn>(), blank_out::<TickOut>());
        assert_eq!(
            p.call(lifecycle::slot::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        pin("tick", 1);
        let bad = inputs["export"]["bad_settings"][0]["settings"].to_string();
        assert_eq!(
            calls::refresh(&p, &d, bad.as_bytes()).outcome,
            Outcome::Failed
        );
        pin("refresh bad", 1);
        assert_eq!(calls::refresh(&p, &d, &settings).outcome, Outcome::Ready);
        pin("refresh", 1);
        assert_eq!(deliver().outcome, Outcome::Ready);
        pin("deliver after refresh", 1);
        assert_eq!(
            p.call(
                lifecycle::slot::CLOSE,
                &mut Frame::new(blank_in::<InHead>(), blank_out::<OutHead>())
            )
            .outcome,
            Outcome::Ready
        );
        pin("close", 1);
        assert_ne!(
            deliver().outcome,
            Outcome::Ready,
            "closed exporter delivers nothing"
        );
        pin("deliver after close", 0);
        let received = std::mem::take(&mut *RECEIVED.lock().unwrap());
        assert_eq!(
            received.len(),
            2,
            "one actual OTLP POST before and after refresh"
        );
        for request in received {
            let split = request
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert!(request.starts_with(b"POST /v1/traces HTTP/1.1\r\n"));
            let decoded = ExportTraceServiceRequest::decode(&request[split..])
                .expect("actual OTLP protobuf request");
            let spans: Vec<_> = decoded
                .resource_spans
                .iter()
                .flat_map(|resource| &resource.scope_spans)
                .flat_map(|scope| &scope.spans)
                .collect();
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].name, "forward");
        }
        answers.push((observed, counts));
    }
    assert_eq!(
        answers[0], answers[1],
        "linked and dropped actual plugin results"
    );
}

/// The kernel resolves references at declared secret fields in place and refuses undeclared ones.
mod declared_secrets {
    use std::sync::Arc;

    use super::settings::settings_as_the_kernel_resolves;
    use busbar_plugin_loader::dispatch::kinds::export::Export;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
    };
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

#[test]
fn the_declared_needs_are_the_statements() {
    let row = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_export_otlp::door::door)
        .expect("actual statement");
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("statement renders");
    let actual: std::collections::BTreeSet<_> = statement
        .needs
        .iter()
        .filter(|need| !need.transport.is_empty())
        .map(|need| need.transport.as_str())
        .collect();
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../export-otlp/declares.json"))
            .expect("declared needs JSON");
    let expected: std::collections::BTreeSet<_> = declared["needs"]
        .as_array()
        .expect("declared needs list")
        .iter()
        .map(|value| value.as_str().expect("transport scheme"))
        .collect();
    assert_eq!(actual, expected);
}
#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE requires --release"
    );
}
