// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the OTLP sink on the export kind's table (`busbar_contract::abi::export`), its
//! lifecycle the SDK's generic one over [`Otlp`] (`abi::sdk::life`), every kind op a [`SafeSlot`].
//!
//! * `validate` — the settings parse as [`OtlpSettings`], refusing in serde's words.
//! * `open` / `refresh` — the settings become the endpoint (userinfo split into a Basic header).
//!   Settings that do not parse are refused in `validate`'s words; a refused `refresh` leaves the
//!   instance as it was.
//! * `deliver` — the batch's spans as one OTLP request, sent by `exchange()` over the declared need,
//!   PENDING while the host carries it; READY whatever became of it (a dropped export is logged at
//!   warn). The host's first answer settles the run: carried, `OTLP tracing enabled`; refused by
//!   the connector, `…; disabling OTLP trace export`, and no later batch is sent.
//! * `scrape` and `serve` — REFUSED, saying why: the sink carries no metrics and serves no route.
//! * `status` — READY with nothing to report.
//! * `check` — READY with nothing to report, except at the limits phase, where it returns the
//!   one-instance refusal findings ([`crate::check_limits`]).

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    cancel, CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, Tail, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement, MARK_ONE_INSTANCE};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use crate::{
    log_target, proto, request_target, scrub, secret_parts, split_credentials, OtlpSettings,
    CONTENT_TYPE, EXPORT_TIMEOUT_MS, NAME,
};

/// The one need's index in [`STATEMENT`]'s needs.
pub const NEED: u32 = 0;

/// The collector, reached through the host: framed `http`, under the `loopback-allowed` egress class
/// the exporter holds its endpoint to, its target the `url` setting: the
/// host declares the need pinned to the operator's collector, its userinfo left out, and refuses a
/// dial to any other host. Each export names the same collector ([`Endpoint::collector`], the URL
/// with its userinfo stripped), so no credential is ever part of what the host dials; the userinfo
/// travels only as the request's `Authorization`.
pub(crate) const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    auth: abi_str(""),
    target_from: abi_str("settings.url"),
    trust_from: abi_str(""),
    details: Blob::ABSENT,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: EXPORT_TIMEOUT_MS,
    // The collector's response head is not read: the named (empty) list, nothing denied beyond it.
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// The one stream the sink carries.
const STREAMS: &[u8] = &[ExportStream::Traces as u8];

const TAIL: Tail = Tail {
    head: KindTailHead {
        size: std::mem::size_of::<Tail>() as u32,
        _reserved: 0,
    },
    streams: STREAMS.as_ptr(),
    streams_len: STREAMS.len(),
    routes: std::ptr::null(),
    routes_len: 0,
};

/// The settings fields that may carry a credential, declared so the kernel resolves a
/// `{env:}`/`{file:}`/`{module:}` reference written there.
/// `url`: its userinfo becomes the `Authorization: Basic` header. The export host lends nothing;
/// the sink receives the resolved string.
const SECRET_REFS: &[AbiStr] = &[abi_str("url")];

/// This plugin's Statement: its name and version, the `traces` stream, and the collector need.
pub const STATEMENT: Statement = Statement {
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    // At most one instance: the host asks this sink's limits-phase check (`Check`), which words the
    // refusal of a second `module: otlp` sink (`crate::check_limits`).
    marks: MARK_ONE_INSTANCE,
    ..statement(NAME, env!("CARGO_PKG_VERSION"), 64)
};

const METHOD: &[u8] = b"POST";
const CONTENT_TYPE_FIELD: &[u8] = b"content-type";
const AUTHORIZATION_FIELD: &[u8] = b"authorization";

/// Where each export goes, as one instance's settings name it. Its `Debug` carries no credential:
/// the collector is named as every line names it, the request target and the `Authorization` the
/// url's userinfo became are redacted.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// The settings' URL as every line names it ([`log_target`]: userinfo, a non-OTLP path and the
    /// query masked).
    pub shown: String,
    /// The collector the host dials — the settings' URL without its userinfo; `None` only for the
    /// default endpoint, which names none.
    pub collector: Option<String>,
    /// The request target (path and query) and the `Authorization` the userinfo became; `None`
    /// only for the default endpoint, which names none.
    pub target: Option<(String, Option<String>)>,
    /// The parts of the settings' URL cut from the host's text before it is logged
    /// ([`secret_parts`]).
    pub secrets: Vec<String>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target = self
            .target
            .as_ref()
            .map(|(_, authorization)| ("<redacted>", authorization.as_ref().map(|_| "<redacted>")));
        f.debug_struct("Endpoint")
            .field("shown", &self.shown)
            .field("collector", &self.collector.as_deref().map(log_target))
            .field("target", &target)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// The endpoint `settings` name.
    #[must_use]
    pub fn of(settings: &OtlpSettings) -> Self {
        let (clean, authorization) = split_credentials(&settings.url);
        Self {
            shown: log_target(&settings.url),
            target: Some((request_target(&clean), authorization)),
            collector: Some(clean),
            secrets: secret_parts(&settings.url),
        }
    }

    /// The request carrying `body` to this endpoint; `None` when it names none.
    #[must_use]
    pub fn request(&self, body: Vec<u8>) -> Option<Request> {
        let (target, authorization) = self.target.as_ref()?;
        let mut fields = Vec::with_capacity(2);
        fields.push((
            CONTENT_TYPE_FIELD.to_vec(),
            CONTENT_TYPE.as_bytes().to_vec(),
        ));
        if let Some(value) = authorization {
            fields.push((AUTHORIZATION_FIELD.to_vec(), value.as_bytes().to_vec()));
        }
        Some(Request {
            method: METHOD.to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body,
            timeout_ms: EXPORT_TIMEOUT_MS,
        })
    }
}

/// One run of the sink: an endpoint and whether the host's first answer admitted it. A refresh
/// starts a new one, so an answer for the endpoint it replaced cannot settle it.
#[derive(Debug)]
struct Run {
    endpoint: Endpoint,
    /// Whether this run takes spans, once the host's first answer settled it.
    admitted: Mutex<Option<bool>>,
}

/// A delivery parked on the host: its exchange, and the run it was framed for, so its answer is
/// settled and logged as that run's even when a refresh lands while it is parked.
struct Parked {
    exchange: Exchange,
    run: Arc<Run>,
}

/// One opened instance.
#[derive(Debug)]
pub struct Otlp {
    run: RwLock<Arc<Run>>,
}

impl Otlp {
    fn start(endpoint: Endpoint) -> Arc<Run> {
        Arc::new(Run {
            endpoint,
            admitted: Mutex::new(None),
        })
    }

    /// The current run.
    fn run(&self) -> Arc<Run> {
        Arc::clone(&self.run.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The endpoint this instance sends to.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.run().endpoint.clone()
    }

    /// What became of one export framed for `run`. A refresh since then makes the answer a stale
    /// one: it settles nothing and says nothing of the current run. A stale failure or non-2xx
    /// answer is logged at warn as a dropped export; a stale success says nothing.
    fn settle(&self, run: &Arc<Run>, result: &Result<ExchangeResponse, ConnFailure>) {
        let stale = !Arc::ptr_eq(run, &self.run());
        run.settle(stale, result);
    }
}

impl Run {
    /// Whether the host refused this run's exports: its connector refused the first one (the
    /// egress class's verdict on the target, or no connector at all).
    fn refused(&self) -> bool {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) == Some(false)
    }

    /// What became of one export: the first answer the host gives settles whether this run takes
    /// spans (the line a rollout check greps for, or the refusal and that export is disabled); a
    /// non-2xx or failed export drops that batch, logged at warn. A `stale` answer (the run it was
    /// framed for was replaced by a refresh) settles nothing.
    fn settle(&self, stale: bool, result: &Result<ExchangeResponse, ConnFailure>) {
        let shown = self.endpoint.shown.as_str();
        let secrets = self.endpoint.secrets.as_slice();
        if !stale {
            let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
            match (result, *admitted) {
                (Err(e @ (ConnFailure::Refused(_) | ConnFailure::Unarmed)), None) => {
                    tracing::error!(
                        "{}; disabling OTLP trace export",
                        scrub(&e.to_string(), secrets)
                    );
                    *admitted = Some(false);
                    return;
                }
                (Ok(_), None) => {
                    tracing::info!(endpoint = %shown, "OTLP tracing enabled");
                    *admitted = Some(true);
                }
                _ => {}
            }
        }
        match result {
            Ok(reply) if (200..300).contains(&reply.status) => {}
            Ok(reply) => tracing::warn!(
                endpoint = %shown,
                status = reply.status,
                "OTLP span export returned a non-2xx status; this batch was dropped"
            ),
            Err(e) => dropped(shown, secrets, e),
        }
    }
}

/// The error texts of the door's REFUSED answers: one per cause, so the host's line names why
/// instead of a bare outcome.
pub const NO_INSTANCE: &str = "no opened otlp instance";
/// `scrape` on a push sink: it carries no `metrics` stream.
pub const NO_EXPOSITION: &str = "this sink carries no metrics stream, so it renders no exposition";
/// `serve` on a sink that declares no route.
pub const NO_ROUTE: &str = "this sink declares no route, so it serves no request";

/// The settings as [`OtlpSettings`], or the one refusal `validate`, `open` and `refresh` all give.
fn parsed(settings: &[u8]) -> Result<OtlpSettings, Refusal> {
    let settings =
        OtlpSettings::parse(settings).map_err(|e| Refusal::failed(format!("settings: {e}")))?;
    if let Some(refusal) = crate::ambiguous_url(&settings.url) {
        return Err(Refusal::failed(refusal));
    }
    Ok(settings)
}

impl Life for Otlp {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parsed(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            run: RwLock::new(Self::start(Endpoint::of(&parsed(settings)?))),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let endpoint = Endpoint::of(&parsed(settings)?);
        *self.run.write().unwrap_or_else(PoisonError::into_inner) = Self::start(endpoint);
        Ok(Refreshed::default())
    }
}

/// The OTLP request a JSON-lines batch makes, each line that is no span logged and skipped.
fn batch_body(batch: &[u8]) -> Option<Vec<u8>> {
    let mut spans = Vec::new();
    for line in batch
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        match serde_json::from_slice::<serde_json::Value>(line) {
            Ok(record) => match proto::span(&record) {
                Some(span) => spans.push(span),
                None => tracing::debug!("OTLP span export skipped a record with no span identity"),
            },
            Err(_) => tracing::debug!("OTLP span export skipped a line that is not JSON"),
        }
    }
    proto::encode(spans)
}

/// `deliver`: the batch as one OTLP request, exchanged over the need.
pub struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Otlp>;
    fn call(
        instance: Instance<'_, Held<Otlp>>,
        input: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        let (mut state, run) = match instance.resume::<Parked>() {
            Some(parked) => {
                let Parked { exchange, run } = *parked;
                (exchange, run)
            }
            None => {
                let run = held.life().run();
                if run.refused() {
                    return Outcome::Ready;
                }
                let endpoint = &run.endpoint;
                let Some(body) = batch_body(input.field(|i| &i.batch).bytes()) else {
                    return Outcome::Ready;
                };
                let Some(request) = endpoint.request(body) else {
                    return Outcome::Ready;
                };
                match Exchange::request(request) {
                    Ok(state) => (state, run),
                    Err(e) => {
                        dropped(&endpoint.shown, &endpoint.secrets, &e);
                        return Outcome::Ready;
                    }
                }
            }
        };
        let answer = match held.host() {
            Some(host) => exchange(
                &mut host.connector(instance.ticket()),
                &mut state,
                NEED,
                run.endpoint.collector.as_deref(),
            ),
            None => Poll::Ready(Err(ConnFailure::Unarmed)),
        };
        match answer {
            Poll::Pending => {
                instance.park(Parked {
                    exchange: state,
                    run,
                });
                Outcome::Pending
            }
            Poll::Ready(result) => {
                held.life().settle(&run, &result);
                Outcome::Ready
            }
        }
    }
}

/// The line an export that did not reach the collector writes, the host's text cut of the target's
/// credential-bearing parts.
fn dropped(shown: &str, secrets: &[String], error: &ConnFailure) {
    tracing::warn!(
        endpoint = %shown,
        error = %scrub(&error.to_string(), secrets),
        "OTLP span export failed; this batch was dropped"
    );
}

/// `scrape`: REFUSED, saying why — the sink carries no metrics.
pub struct Scrape;

impl SafeSlot for Scrape {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = Held<Otlp>;
    fn call(
        _: Instance<'_, Held<Otlp>>,
        _: Lent<'_, ScrapeIn>,
        mut out: Out<'_, ScrapeOut>,
    ) -> Outcome {
        out.fail(Refusal::refused(NO_EXPOSITION))
    }
}

/// `status`: nothing to report.
pub struct Status;

impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = Held<Otlp>;
    fn call(_: Instance<'_, Held<Otlp>>, _: Lent<'_, InHead>, _: Out<'_, StatusOut>) -> Outcome {
        Outcome::Ready
    }
}

/// `check`: at the limits phase, a refusal of every instance after the first
/// ([`crate::check_limits`]) — the sink states the `one_instance` mark, so the host asks it while
/// the configuration is resolved; READY with nothing otherwise.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Otlp>;
    fn call(
        instance: Instance<'_, Held<Otlp>>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return out.fail(Refusal::refused(NO_INSTANCE));
        };
        if input.phase != CHECK_PHASE_LIMITS {
            return Outcome::Ready;
        }
        let names: Vec<String> = input
            .instances()
            .iter()
            .map(|c| String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned())
            .collect();
        let lines = crate::check_limits(&names);
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

/// `serve`: REFUSED, saying why — the sink serves no route.
pub struct Serve;

impl SafeSlot for Serve {
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<Otlp>;
    fn call(
        _: Instance<'_, Held<Otlp>>,
        _: Lent<'_, ServeIn>,
        mut out: Out<'_, ServeOut>,
    ) -> Outcome {
        out.fail(Refusal::refused(NO_ROUTE))
    }
}

mod table {
    use super::{Check, Deliver, Otlp, Safe, Scrape, Serve, Status};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Otlp),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;

/// The door as the macro built it, for the contract's test support (`DoorView::of`).
#[cfg(test)]
pub(crate) use table::MACRO_DOOR;

#[cfg(test)]
#[path = "door_tests.rs"]
mod tests;
