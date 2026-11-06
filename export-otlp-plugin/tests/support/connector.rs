// SPDX-License-Identifier: Apache-2.0
//! The real connector drives this repository's pinned TCP and HTTP transport doors.
use busbar_core_connector::registry::{Entry, Transports};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use rustls_pki_types::pem::PemObject;
use std::sync::{Arc, OnceLock};

fn runtime() -> tokio::runtime::Handle {
    static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("connector runtime");
            let handle = rt.handle().clone();
            std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));
            handle
        })
        .clone()
}
fn transport_dispatcher() -> Arc<Dispatcher> {
    static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    DISPATCHER
        .get_or_init(|| {
            // Request-head deadlines cross the transport ABI using its host clock.
            let dispatcher = Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(busbar_kernel::host_services::KernelServices::new()),
            );
            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            dispatcher.install_runtime(runtime());
            dispatcher.install_io(busbar_core_connector::hostio::process());
            Arc::new(dispatcher)
        })
        .clone()
}
pub fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    host_judged(wake, anchors, false)
}
#[allow(dead_code)] // The direct host-proof binary uses the production guard.
pub fn guarded_host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    host_judged(wake, anchors, true)
}
fn host_judged(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
    guarded: bool,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    use std::net::ToSocketAddrs;
    busbar_core_connector::io::install_process_reactor(runtime());
    let mut trust = busbar_contract::transport::EgressTrust::default();
    if let Some(pem) = anchors {
        trust.extra_anchors = rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
            .map(|v| v.expect("test certificate").to_vec())
            .collect();
    }
    let tls =
        busbar_core_connector::tls::client::build_client_config(&trust).expect("connector TLS");
    let doors = [
        ("tcp", busbar_transport_tcp::linked::MACRO_DOOR),
        ("http", busbar_transport_http::door::MACRO_DOOR),
    ];
    let entries = doors
        .into_iter()
        .map(|(name, door)| {
            let bind = Bind {
                instance: Arc::from(name),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: transport_dispatcher().adopter(),
                conns: ConnTable::NoNeeds,
            };
            let row = LinkedRow::of_macro(door).expect("transport statement");
            let plugin = busbar_plugin_loader::dispatch::load_linked::<Transport>(&row, bind)
                .expect("load transport");
            let opened = busbar_core_connector::doors::Dispatched::open_on(
                plugin,
                &busbar_contract::transport::TransportSettings::default(),
                transport_dispatcher(),
            )
            .expect("open actual transport on the host dispatcher");
            Entry {
                door: Arc::new(opened),
                alpn: Vec::new(),
            }
        })
        .collect();
    let loopback = Arc::new(|target: &str, _: u32, _: busbar_core_connector::Judged| {
        Some(
            target
                .to_socket_addrs()
                .ok()
                .and_then(|mut rows| rows.find(|row| row.ip().is_loopback()))
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    });
    let judge: Arc<dyn busbar_core_connector::DialJudge> = if guarded {
        let config = busbar_kernel::config::Destinations {
            block_private_addresses:
                busbar_kernel::config::sections::DEFAULT_BLOCK_PRIVATE_ADDRESSES,
            ..Default::default()
        };
        let guard = busbar_core_connector::process::dest_judge(&config)
            .expect("production default destination guard");
        busbar_core_connector::process::judge(guard, &[])
    } else {
        loopback
    };
    Arc::new(busbar_core_connector::Connector::serving(
        Transports::new(entries).expect("TCP+HTTP composition"),
        judge,
        Some(Arc::new(tls)),
        wake,
    ))
}
