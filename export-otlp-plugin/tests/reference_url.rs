// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The collector `url` accepts references resolved in place and literal URLs as non-secret settings.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};
fn settings_as_the_kernel_resolves(
    plugin: &Plugin<Export>,
    bytes: &[u8],
    resolve: impl FnMut(&str, &busbar_contract::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<Vec<u8>, String> {
    let mut value = serde_json::from_slice(bytes).map_err(|e| format!("settings JSON: {e}"))?;
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut value,
        plugin.secret_refs(),
        plugin.reference_fields(),
        plugin.name(),
        resolve,
    )?;
    serde_json::to_vec(&value).map_err(|e| e.to_string())
}

const URL: &str = "https://collector.example:4318/v1/traces";

fn linked() -> (Plugin<Export>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("reference-url"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(busbar_export_otlp::door::door).expect("the row renders");
    (
        load_linked::<Export>(&row, bind).expect("the door loads"),
        d,
    )
}

#[test]
fn the_url_is_not_declared_secret() {
    let (p, _d) = linked();
    assert!(
        !p.secret_refs().iter().any(|f| f == "url"),
        "{:?}",
        p.secret_refs()
    );
}

#[test]
fn a_reference_at_the_url_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    let out =
        settings_as_the_kernel_resolves(&p, br#"{"url":{"env":"REFCAP_URL_FOR_TEST"}}"#, |_, _| {
            Ok(URL.to_string())
        })
        .expect("a reference at the url resolves");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}

#[test]
fn a_literal_url_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"url":"{URL}"}}"#);
    let out = settings_as_the_kernel_resolves(&p, settings.as_bytes(), |_, _| {
        Err("a literal url resolves nothing".to_string())
    })
    .expect("a literal url passes as written");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}
