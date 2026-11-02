// SPDX-License-Identifier: Apache-2.0
//! Webhook delivery submits owned JSONL bytes to the real dispatcher.
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{self, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    Bind, Called, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, Lent, NoSink, OutFrame,
    Plugin,
};
use std::sync::Arc;

pub fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}
pub fn bind(d: &Dispatcher, name: &str) -> Bind {
    Bind {
        instance: Arc::from(name),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    }
}
pub fn input<I: InFrame + busbar_contract::abi::sdk::door::AbiIn>() -> I {
    blank_in()
}
pub fn output<O: OutFrame + busbar_contract::abi::sdk::door::AbiOut>() -> O {
    blank_out()
}
pub fn called(c: &Called) -> String {
    format!(
        "{:?} lease={} {}",
        c.outcome,
        c.lease != 0,
        String::from_utf8_lossy(c.error.as_deref().unwrap_or_default())
    )
}
pub fn on_ticket<I: InFrame, O: OutFrame>(
    p: &Plugin<Export>,
    d: &Dispatcher,
    slot: u32,
    frame: Frame<I, O>,
    class: DeadlineClass,
    deadline: u64,
    bytes: Lent,
) -> Called {
    let ticket = d.mint(0).expect("delivery ticket");
    let done = d
        .submit_watched(
            p,
            ticket,
            slot,
            frame,
            class,
            deadline,
            bytes,
            std::time::Duration::ZERO,
        )
        .wait_done();
    d.recycle(ticket);
    Called {
        outcome: done.outcome,
        error: done.error,
        lease: done.lease,
        recall: None,
    }
}
pub fn open_resumed(p: &Plugin<Export>, d: &Dispatcher, settings: &[u8]) -> Called {
    let bytes = Arc::new(settings.to_vec());
    let mut i: OpenIn = blank_in();
    i.settings = Blob::json(&bytes);
    i.generation = 1;
    let deadline = busbar_plugin_loader::dispatch::now_ns().saturating_add(30_000_000_000);
    on_ticket(
        p,
        d,
        lifecycle::slot::OPEN,
        Frame::new(i, blank_out::<OpenOut>()),
        DeadlineClass::Call,
        deadline,
        bytes,
    )
}
pub fn refresh(p: &Plugin<Export>, settings: &[u8]) -> Called {
    let mut i: RefreshIn = blank_in();
    i.settings = Blob::json(settings);
    i.generation = 2;
    p.call(
        lifecycle::slot::REFRESH,
        &mut Frame::new(i, blank_out::<OutHead>()),
    )
}

/// Host-observed effects of the concrete export lifecycle, compared between the two doors.
#[derive(Default)]
pub struct Observed(std::sync::Mutex<Vec<String>>);
impl Observed {
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}
impl busbar_plugin_loader::dispatch::EnvelopeSink for Observed {
    fn metric(&self, m: busbar_plugin_loader::dispatch::Metric<'_>) {
        let labels: Vec<_> = m
            .labels
            .iter()
            .map(|label| String::from_utf8_lossy(label))
            .collect();
        self.0.lock().unwrap().push(format!(
            "metric {} {} {} {labels:?}",
            m.family, m.kind, m.value
        ));
    }
    fn diag(&self, d: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} {} {}",
            String::from_utf8_lossy(d.name),
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: busbar_plugin_loader::dispatch::Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}
