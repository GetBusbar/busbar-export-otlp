// SPDX-License-Identifier: Apache-2.0
//! Only the concrete OTLP lifecycle and deliver crossings used by its unit regressions.
use busbar_contract::abi::export::{self, DeliverIn, Ops, ServeIn, ServeOut};
use busbar_contract::abi::host::conn::connector::{ConnectorSlots, SERVICES};
use busbar_contract::abi::host::service::ServiceFn;
use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_JSONL,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use std::ffi::c_void;
use std::mem::size_of;

pub fn connector(establish: ServiceFn) -> ConnectorSlots {
    ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: SERVICES,
        establish: Some(establish),
        reject_endpoint: None,
        side_stream: None,
        read: None,
        write: None,
        upgrade_secure: None,
        facts: None,
        checkout: None,
        checkin: None,
        close: None,
        random: None,
        identity: None,
        read_reply: None,
        write_request: None,
    }
}
pub fn host(connector: &ConnectorSlots) -> HostTables {
    HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: connector,
        services: std::ptr::null(),
        io: std::ptr::null(),
    }
}
pub fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}
fn head() -> OutHead {
    let mut out: OutHead = blank_out();
    out.size = size_of::<OutHead>() as u32;
    out
}
fn ops() -> &'static Ops {
    // SAFETY: this actual linked OTLP door's export table is static program data.
    unsafe { &*Door::read_parts(crate::door::door()).ops.cast::<Ops>() }
}
pub struct Answer {
    pub outcome: Outcome,
    pub error: Option<String>,
}
fn answer(outcome: Outcome, out: OutHead) -> Answer {
    let error = if out.error.len == 0 {
        None
    } else {
        // SAFETY: call capture's error is copied before any next crossing.
        Some(
            String::from_utf8_lossy(unsafe {
                std::slice::from_raw_parts(out.error.ptr, out.error.len)
            })
            .into_owned(),
        )
    };
    Answer { outcome, error }
}
pub struct OtlpDoor<'a> {
    instance: *mut c_void,
    _host: std::marker::PhantomData<&'a HostTables>,
}
impl<'a> OtlpDoor<'a> {
    pub fn open(settings: &[u8], host: Option<&'a HostTables>) -> Self {
        let mut input: OpenIn = blank_in();
        input.head.op = slot::OPEN;
        input.head.size = size_of::<OpenIn>() as u32;
        input.settings = blob(settings, BLOB_JSON);
        input.generation = 1;
        input.host = host.map_or(std::ptr::null(), std::ptr::from_ref);
        let mut out: OpenOut = blank_out();
        out.head.size = size_of::<OpenOut>() as u32;
        // SAFETY: the actual door receives live, correctly sized open frames and host loan.
        let outcome = unsafe {
            ops().head.open.expect("open")(
                std::ptr::null_mut(),
                (&input as *const OpenIn).cast(),
                (&mut out as *mut OpenOut).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert!(!out.instance.is_null());
        Self {
            instance: out.instance,
            _host: std::marker::PhantomData,
        }
    }
    pub fn deliver(&self, batch: &[u8], ticket: u32, flags: u32) -> Outcome {
        let mut input: DeliverIn = blank_in();
        input.head.op = export::slot::DELIVER;
        input.head.size = size_of::<DeliverIn>() as u32;
        input.head.flags = flags;
        input.head.ticket = Ticket {
            slot: ticket,
            generation: 1,
        };
        input.batch = blob(batch, BLOB_JSONL);
        let mut out = head();
        // SAFETY: this instance and its typed batch/output loans remain live for the crossing.
        unsafe {
            ops().deliver.expect("deliver")(
                self.instance,
                (&input as *const DeliverIn).cast(),
                (&mut out as *mut OutHead).cast(),
            )
        }
        .outcome()
    }
    pub fn refresh(&self, settings: &[u8]) -> Answer {
        let mut input: RefreshIn = blank_in();
        input.head.op = slot::REFRESH;
        input.head.size = size_of::<RefreshIn>() as u32;
        input.settings = blob(settings, BLOB_JSON);
        let mut out = head();
        // SAFETY: the live instance receives correctly sized refresh and output frames.
        let outcome = unsafe {
            ops().head.refresh.expect("refresh")(
                self.instance,
                (&input as *const RefreshIn).cast(),
                (&mut out as *mut OutHead).cast(),
            )
        }
        .outcome();
        answer(outcome, out)
    }
    pub fn serve(&self) -> Answer {
        let mut input: ServeIn = blank_in();
        input.head.op = export::slot::SERVE;
        input.head.size = size_of::<ServeIn>() as u32;
        let mut out: ServeOut = blank_out();
        out.head.size = size_of::<ServeOut>() as u32;
        // SAFETY: the live instance receives correctly sized ServeIn/ServeOut records.
        let outcome = unsafe {
            ops().serve.expect("serve")(
                self.instance,
                (&input as *const ServeIn).cast(),
                (&mut out as *mut ServeOut).cast(),
            )
        }
        .outcome();
        answer(outcome, out.head)
    }
}
impl Drop for OtlpDoor<'_> {
    fn drop(&mut self) {
        let mut input: InHead = blank_in();
        input.op = slot::CLOSE;
        input.size = size_of::<InHead>() as u32;
        let mut out = head();
        assert_eq!(
            // SAFETY: this owner closes its actual door instance once with live typed frames.
            unsafe {
                ops().head.close.expect("close")(
                    self.instance,
                    (&input as *const InHead).cast(),
                    (&mut out as *mut OutHead).cast(),
                )
            }
            .outcome(),
            Outcome::Ready
        );
    }
}
