// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lines the sink writes when it starts — in a test binary of their own, because a `tracing`
//! callsite's interest is process-wide, and another test hitting it first with no subscriber would
//! leave it disabled for this one.

use busbar_contract::abi::sdk::{HostResult, HostStep};
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt as _;

/// Every event, rendered `LEVEL field=value …`.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Lines {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Render(String);
        impl tracing::field::Visit for Render {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={v:?}", f.name()));
            }
        }
        let mut r = Render(event.metadata().level().to_string());
        event.record(&mut r);
        self.0.lock().unwrap().push(r.0);
    }
}

fn started(live: bool) -> HostStep {
    HostStep::Started {
        live,
        inflight: 0,
        gate: String::new(),
    }
}

/// NO ADMISSION, NO "ENABLED" LINE (busbar item 570, carried with the exporter): the sink says
/// `OTLP tracing enabled` only when the host admitted its endpoint — the line a rollout check greps
/// for — and a refused endpoint says why and that export is disabled; the credential is masked.
#[test]
fn the_enabled_line_is_the_admissions_and_a_refusal_says_export_is_disabled() {
    let lines = Lines::default();
    let subscriber = tracing_subscriber::registry().with(lines.clone());
    tracing::subscriber::with_default(subscriber, || {
        let sink = busbar_export_otlp::open(r#"{"url":"https://u:p@collector.example/v1/traces"}"#)
            .expect("opens");
        let refused = HostResult::Failed {
            step: "refused".into(),
            error: "observability.otlp_endpoint must not target … got 'https://***@10.0.0.1/'"
                .into(),
            rotation: None,
        };
        assert_eq!(sink.resume(0, vec![refused]), started(false));
        let admitted = HostResult::Done { rotation: None };
        assert_eq!(sink.resume(0, vec![admitted]), started(true));
    });
    let got = lines.0.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![
            "ERROR message=observability.otlp_endpoint must not target … got \
             'https://***@10.0.0.1/'; disabling OTLP trace export"
                .to_string(),
            "INFO message=OTLP tracing enabled endpoint=https://***@collector.example/v1/traces"
                .to_string(),
        ]
    );
}
