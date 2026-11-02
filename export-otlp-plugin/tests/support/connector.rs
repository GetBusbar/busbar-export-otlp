// SPDX-License-Identifier: Apache-2.0
//! The real connector drives this repository's pinned TCP and HTTP transport doors.
use busbar_contract::abi::mechanism::lifecycle::{self, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::slot;
use busbar_core_connector::carrier::{Carry, Side};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::registry::{Entry, Transports};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{
    Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink, OutFrame,
    Plugin,
};
use rustls_pki_types::pem::PemObject;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
fn transport_dispatcher() -> &'static Dispatcher {
    static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();
    DISPATCHER.get_or_init(|| {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        dispatcher.install_runtime(runtime());
        dispatcher.install_io(busbar_core_connector::hostio::process());
        dispatcher
    })
}
struct LoadedTransport {
    plugin: Plugin<Transport>,
    facts: DoorFacts,
}
fn cross<I: InFrame, O: OutFrame>(
    p: &Plugin<Transport>,
    slot: u32,
    input: &mut I,
    output: &mut O,
    ticket: Option<(busbar_contract::abi::mechanism::ticket::Ticket, bool)>,
) -> Crossed {
    let mut frame = Frame::new(*input, *output);
    let result = match ticket {
        Some((id, resume)) => p.call_inline(id, resume, slot, &mut frame),
        None => p.call(slot, &mut frame),
    };
    *input = frame.input;
    *output = frame.out;
    Crossed {
        outcome: result.outcome,
        error: result.error,
    }
}
struct CarrierTicket(busbar_plugin_loader::dispatch::InlineTicket);
impl Side for CarrierTicket {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.0.ticket()
    }
    fn register(&self, waker: &std::task::Waker) {
        self.0.register(waker);
    }
}
impl FramerDoor for LoadedTransport {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        (self.facts.role == busbar_contract::abi::transport::ROLE_CARRIER)
            .then(|| transport_dispatcher().inline_ticket())
            .flatten()
            .map(|id| Box::new(CarrierTicket(id)) as Box<dyn Side>)
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        let ticket = Some((side.ticket(), resume));
        match call {
            Carry::Listen(i, o) => cross(&self.plugin, slot::LISTEN, i, o, ticket),
            Carry::Accept(i, o) => cross(&self.plugin, slot::ACCEPT, i, o, ticket),
            Carry::Dial(i, o) => cross(&self.plugin, slot::DIAL, i, o, ticket),
            Carry::Read(i, o) => cross(&self.plugin, slot::READ, i, o, ticket),
            Carry::Write(i, o) => cross(&self.plugin, slot::WRITE, i, o, ticket),
            Carry::Flush(i, o) => cross(&self.plugin, slot::FLUSH, i, o, ticket),
            Carry::Shut(i, o) => cross(&self.plugin, slot::SHUT, i, o, ticket),
            Carry::Cancel(i, o) => cross(&self.plugin, lifecycle::slot::CANCEL, i, o, None),
        }
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Locate(i, o) => cross(&self.plugin, slot::LOCATE, i, o, None),
            Call::Begin(i, o) => cross(&self.plugin, slot::BEGIN, i, o, None),
            Call::Ingest(i, o) => cross(&self.plugin, slot::INGEST, i, o, None),
            Call::Emit(i, o) => cross(&self.plugin, slot::EMIT, i, o, None),
            Call::Encode(i, o) => cross(&self.plugin, slot::ENCODE, i, o, None),
            Call::Refuse(i, o) => cross(&self.plugin, slot::REFUSE, i, o, None),
            Call::Finish(i, o) => cross(&self.plugin, slot::FINISH, i, o, None),
            Call::Detach(i, o) => cross(&self.plugin, slot::DETACH, i, o, None),
            Call::Adopt(i, o) => cross(&self.plugin, slot::ADOPT, i, o, None),
            Call::Timer(i, o) => cross(&self.plugin, slot::TIMER, i, o, None),
        }
    }
}
pub fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    host_judged(wake, anchors, false)
}
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
            let facts = plugin
                .context::<TransportFacts>()
                .expect("transport facts")
                .clone();
            let result = plugin.call(
                lifecycle::slot::OPEN,
                &mut Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>()),
            );
            assert_eq!(
                result.outcome,
                busbar_contract::abi::mechanism::call::Outcome::Ready
            );
            plugin
                .ready(transport_dispatcher(), Duration::from_secs(10))
                .expect("ready transport");
            Entry {
                door: Arc::new(LoadedTransport {
                    plugin,
                    facts: DoorFacts {
                        name: name.into(),
                        claims: facts.claims,
                        role: facts.role,
                        composes_over: facts.composes_over,
                        ported: facts.ported,
                        status_rows: facts.status_rows,
                        datagram: facts.datagram,
                        duplex: facts
                            .upgrades
                            .iter()
                            .chain(&facts.sessions)
                            .copied()
                            .collect(),
                    },
                }),
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
