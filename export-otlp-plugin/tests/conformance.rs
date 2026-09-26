// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE OTLP TRACE SINK, BOTH WAYS** — the sink's linked + dropped-in conformance, run against the
//! busbar rev this repo pins (`.busbar-ref`).
//!
//! The sink is held two ways at once: LINKED (its `linked::EXPORT` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement — `declares` included, which is what
//! `busbar-plugin-pack --declares-file` embeds — into a temp `plugins/` directory and found by the
//! loader's scan). Each is registered through the plugin registry's one admission and opened through
//! its one `open_export`. One script runs against each: validate and check its settings, start it
//! (the host's collector policy asked of its target), deliver two spans (one the collector accepts,
//! one it answers 503) and a record that is no span. Everything the host sees — the answers, the
//! egress policy each request was judged under, and every request its carrier was asked to make,
//! octets included — must be byte-identical between the doors, and every body the collector was
//! handed must be an OTLP `ExportTraceServiceRequest` by the OpenTelemetry project's own types,
//! re-encoding to the same bytes.
//!
//! RED ARMS: a tarball packed WITHOUT the declaration the linked row states is judged under the open
//! web, which refuses a plaintext loopback collector, so it never starts and nothing is carried; the
//! declaration signed by a third party is refused at open, naming the policy; and without the linked
//! row the module is not on the axis at all.

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{
    EgressPolicy, ExportStream, HostResult, HttpRequest, HttpResponse, LinkedPlugin, PluginRegistry,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message as _;
use serde_json::{json, Value};
use std::sync::Mutex;

const ALIAS: &str = "otlp";

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The requests the host's carrier was asked to make during one script.
static CARRIED: Mutex<Vec<Value>> = Mutex::new(Vec::new());
/// One script at a time (the carrier is process-global).
static SERIAL: Mutex<()> = Mutex::new(());

/// The egress this test installs. Its OPEN-WEB policy takes `https://` only; its COLLECTOR policy
/// also takes plaintext `http://` to `127.0.0.1`, and refuses `*.internal.example` under either.
/// The far end answers 503 on a path ending `/fail` and 200 otherwise. It records every request it
/// carries, with the policy it was judged under and its octets.
struct Carrier;

fn judge(policy: EgressPolicy, url: &str) -> Result<(), String> {
    let loopback_http = url.starts_with("http://127.0.0.1");
    match (policy, url) {
        (_, u) if u.contains(".internal.example") => Err(format!("refused target '{u}'")),
        (_, u) if u.starts_with("https://") => Ok(()),
        (EgressPolicy::Collector, _) if loopback_http => Ok(()),
        (_, u) => Err(format!("plaintext target '{u}' refused")),
    }
}

impl busbar_plugin_loader::EgressCarrier for Carrier {
    fn carry(&self, request: &HttpRequest) -> HostResult {
        self.carry_under(EgressPolicy::OpenWeb, request, request.body.as_bytes())
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        judge(EgressPolicy::OpenWeb, url)
    }

    fn admit_under(&self, policy: EgressPolicy, url: &str) -> Result<(), String> {
        judge(policy, url)
    }

    fn carry_under(&self, policy: EgressPolicy, request: &HttpRequest, body: &[u8]) -> HostResult {
        if let Err(refusal) = judge(policy, &request.url) {
            return HostResult::Failed {
                step: "refused".into(),
                error: refusal,
                rotation: None,
            };
        }
        CARRIED.lock().unwrap().push(json!({
            "policy": policy.as_token(),
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "timeout_ms": request.timeout_ms,
            "body": busbar_export_otlp::hex(body),
        }));
        let status = if request.url.ends_with("/fail") {
            503
        } else {
            200
        };
        HostResult::Http(HttpResponse {
            status,
            body: String::new(),
        })
    }
}

fn installed() -> std::sync::MutexGuard<'static, ()> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // First-install-wins process global: if another test in this binary had installed its own,
        // every assertion below would read somebody else's record — refuse that loudly.
        assert!(busbar_plugin_loader::install_egress_carrier(&Carrier));
    });
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_export_otlp_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-export-otlp-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// THE LINKED DOOR: exactly the row busbar's composition root states for `linked::EXPORT`.
fn linked_door() -> PluginRegistry {
    let (name, alias, declares, entry) = busbar_export_otlp::linked::EXPORT;
    let abi = busbar_plugin_loader::supported_abi("export")
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    let manifest = Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "export".into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: serde_json::from_str(declares).expect("declares.json parses"),
    };
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(manifest, entry)])
        .expect("the linked door admits it")
}

/// The statement the linked row makes for `ALIAS` — what the tarball must state too.
fn statement(registry: &PluginRegistry) -> Manifest {
    registry
        .resolve(ALIAS)
        .expect("the otlp row")
        .manifest
        .clone()
}

/// THE DROPPED-IN DOOR: `lib` signed by `key` under `manifest` into a fresh `plugins/`, scanned
/// under a policy whose first-party key is the release key (`[9; 32]`) and that admits the
/// third-party key (`[5; 32]`) as publisher `acme`.
fn dropped_door(tag: &str, mut manifest: Manifest, lib: &[u8], key: [u8; 32]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("export-otlp-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[9u8; 32]);
    let signer = SigningKey::from_bytes(&key);
    manifest.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
    let signed = sign(&signer, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libotlp.so", lib).unwrap();
    std::fs::write(dir.join("otlp.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: [(
            "acme".to_string(),
            SigningKey::from_bytes(&[5u8; 32]).verifying_key(),
        )]
        .into_iter()
        .collect(),
        allow_unsigned: false,
        allow_third_party: true,
        min_versions: Default::default(),
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let _ = std::fs::remove_dir_all(&dir);
    registry
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

/// One script against the `otlp` row of `registry`: everything the host saw.
fn transcript(registry: &PluginRegistry) -> Value {
    CARRIED.lock().unwrap().clear();
    let collector = json!({"url": "http://127.0.0.1:4318/v1/traces"});
    let refused = json!({"url": "https://collector.internal.example/v1/traces"});
    let failing = json!({"url": "https://u:p@collector.example/fail"});
    let validated = (
        registry.validate_export(ALIAS, "t", &json!({"url": "http://x/", "otlp_endpoint": 1})),
        registry.check_export(
            ALIAS,
            busbar_plugin_loader::CheckPhase::Instances,
            &[
                ("traces".into(), collector.clone()),
                ("again".into(), collector.clone()),
            ],
        ),
    );
    let open = |settings: &Value| {
        registry
            .open_export(ALIAS, &settings.to_string())
            .expect("opens")
    };
    let live = open(&collector);
    let started = (live.start(), open(&refused).start());
    live.deliver(ExportStream::Traces, &record("0000000000000011", None))
        .unwrap();
    live.deliver(ExportStream::Traces, &json!({"name": "no identity"}))
        .unwrap();
    let failing = open(&failing);
    let _ = failing.start();
    failing
        .deliver(
            ExportStream::Traces,
            &record("0000000000000012", Some("0000000000000011")),
        )
        .unwrap();
    json!({
        "validated": format!("{validated:?}"),
        "started": format!("{started:?}"),
        "streams": format!("{:?}", live.streams()),
        "egress": live.egress().as_token(),
        "carried": CARRIED.lock().unwrap().clone(),
    })
}

/// Every body the carrier was handed, decoded by the publisher's types — and re-encoded to the
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

/// The linked and the dropped-in OTLP sink register one statement and hand the host byte-identical
/// transcripts — every request an OTLP export by the proto's own types; the RED arms diverge.
#[test]
fn the_linked_and_the_dropped_in_otlp_sink_are_one_plugin() {
    let _guard = installed();
    let linked = linked_door();
    let lib = cdylib();
    let dropped = dropped_door("both", statement(&linked), &lib, [9u8; 32]);
    let (a, b) = (statement(&linked), statement(&dropped));
    assert_eq!(
        (a.name.as_str(), a.alias.as_str()),
        ("busbar-export-otlp", "otlp")
    );
    assert_eq!(a.declares.egress, EgressPolicy::Collector);
    let same = |m: &Manifest| {
        (
            m.name.clone(),
            m.alias.clone(),
            m.kind.clone(),
            m.declares.clone(),
        )
    };
    assert_eq!(same(&a), same(&b), "both doors state the same plugin");

    let linked_run = transcript(&linked);
    let dropped_run = transcript(&dropped);
    // What the host sees, spelled out once so the equality below is about the right thing.
    let text = linked_run.to_string();
    for want in [
        r#""egress":"collector""#,
        r#""policy":"collector""#,
        r#""url":"http://127.0.0.1:4318/v1/traces""#,
        r#""url":"https://collector.example/fail""#,
        r#"["content-type","application/x-protobuf"]"#,
        r#"["authorization","Basic dTpw"]"#,
        r#""timeout_ms":10000"#,
        "Ok(Some((true, 0, \\\"\\\")))",
        "Ok(Some((false, 0, \\\"\\\")))",
        "unknown field `otlp_endpoint`, expected `url`",
        // The sink has no checks of its own: the host refuses a second instance while resolving.
        "\"]), Some([]))",
        "[Traces]",
    ] {
        assert!(
            text.contains(want),
            "linked transcript lacks {want}: {text}"
        );
    }
    assert_eq!(linked_run, dropped_run, "the two doors are one plugin");

    // Two spans carried (the record with no identity asked for nothing), each its own request.
    let bodies = otlp_bodies(&linked_run);
    assert_eq!(bodies.len(), 2, "{text}");
    let spans: Vec<_> = bodies
        .iter()
        .map(|r| &r.resource_spans[0].scope_spans[0].spans[0])
        .collect();
    assert_eq!(spans[0].span_id, vec![0, 0, 0, 0, 0, 0, 0, 0x11]);
    assert!(spans[0].parent_span_id.is_empty());
    assert_eq!(spans[1].parent_span_id, spans[0].span_id);
    assert_eq!(spans[1].trace_id, spans[0].trace_id);
    assert_eq!(
        spans[0].end_time_unix_nano - spans[0].start_time_unix_nano,
        42_000
    );

    // RED ARM 1: a tarball without the declaration the linked row states is judged under the open
    // web: the plaintext loopback collector is refused at start, and nothing is carried.
    let mut undeclared = statement(&linked);
    undeclared.name = "busbar-export-otlp-undeclared".into();
    undeclared.alias = "otlp-undeclared".into();
    undeclared.declares = Default::default();
    let bare = dropped_door("undeclared", undeclared, &lib, [9u8; 32]);
    let sink = bare
        .open_export(
            "otlp-undeclared",
            r#"{"url":"http://127.0.0.1:4318/v1/traces"}"#,
        )
        .expect("opens");
    assert_eq!(sink.egress(), EgressPolicy::OpenWeb);
    assert_eq!(sink.start(), Ok(Some((false, 0, String::new()))));
    CARRIED.lock().unwrap().clear();
    sink.deliver(ExportStream::Traces, &record("0000000000000013", None))
        .unwrap();
    assert!(
        CARRIED.lock().unwrap().is_empty(),
        "the open web carried a plaintext loopback export"
    );

    // RED ARM 2: the same declaration, signed by a third party, is refused at open.
    let mut third = statement(&linked);
    third.name = "busbar-export-otlp-acme".into();
    third.alias = "otlp-acme".into();
    third.publisher = "acme".into();
    let refused = dropped_door("third", third, &lib, [5u8; 32])
        .open_export("otlp-acme", r#"{"url":"http://127.0.0.1:4318/v1/traces"}"#)
        .expect_err("a third party is not granted the collector policy");
    assert!(
        refused.contains(
            "declares the `collector` egress policy, which the host grants to a \
             first-party plugin only"
        ),
        "{refused}"
    );

    // RED ARM 3: without the linked row the module is not on the axis.
    assert!(PluginRegistry::empty().resolve(ALIAS).is_none());
    assert!(PluginRegistry::empty()
        .validate_export(ALIAS, "t", &json!({}))
        .is_none());
}
