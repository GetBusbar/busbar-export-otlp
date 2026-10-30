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
//!   one-instance refusal findings ([`second_instances`], [`crate::ONE_INSTANCE`]).

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    cancel, CheckIn, CheckOut, DeliverIn, ExportStream, Tail, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement, MARK_ONE_INSTANCE};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{
    exchange, Exchange, ExchangeResponse, Request, REPLY_OVER_BOUND,
};
use busbar_contract::abi::sdk::export::{instance_names, second_instances, tail};
pub use busbar_contract::abi::sdk::export::{NO_EXPOSITION, NO_ROUTE};
use busbar_contract::abi::sdk::life::{settings_as, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use crate::{
    log_target, proto, request_target, scrub, secret_parts, split_credentials, OtlpSettings, ALIAS,
    CONTENT_TYPE, EXPORT_TIMEOUT_MS, NAME, ONE_INSTANCE,
};

/// The settings path the need's target is read from.
pub(crate) const TARGET_FROM: &str = "settings.url";

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
    target_from: abi_str(TARGET_FROM),
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

const TAIL: Tail = tail(STREAMS, &[]);

// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in the
// Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/`{file:}`/
// `{module:}` reference written at `url` is resolved by the kernel IN PLACE to its string (a 1.5.5
// config's `url: {env: VAR}` keeps booting), and a literal url passes as written (never refused
// as a secret literal). The value is not a secret: it is never lent. The export host lends
// nothing; the sink receives the resolved string. (A plain comment: the macro takes no doc.)
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// The most deliveries one instance holds in flight; past it the host sheds the batch.
pub const MAX_INFLIGHT: u32 = 64;

/// This plugin's Statement: its name and version, the `traces` stream, and the collector need.
pub const STATEMENT: Statement = Statement {
    extensions: EXTENSIONS,
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    // At most one instance: the host asks this sink's limits-phase check (`Check`), which words the
    // refusal of a second `module: otlp` sink (`second_instances`).
    marks: MARK_ONE_INSTANCE,
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

/// The catalogue codes the sink's lines carry (`declares.json`): the exporter disabled because the
/// host refused its target, a non-2xx answer (batch dropped), a transport failure (batch dropped),
/// a collector's partial rejection, a record skipped (not JSON, or no span identity).
const DISABLED: &str = "BUSBAR-7140";
const NON_2XX: &str = "BUSBAR-7141";
const TRANSPORT_FAILURE: &str = "BUSBAR-7142";
const PARTIAL_REJECTION: &str = "BUSBAR-7143";
const SKIPPED_RECORD: &str = "BUSBAR-7144";

/// The most of a collector's reply body this sink buffers: the `partial_success` it reads is small.
const REPLY_LIMIT: usize = 64 * 1024;

const METHOD: &[u8] = b"POST";
const CONTENT_TYPE_FIELD: &[u8] = b"content-type";
const AUTHORIZATION_FIELD: &[u8] = b"authorization";

/// The request target and credential of an endpoint's exports.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    /// The request target: the settings' path and query.
    pub path: String,
    /// The `Authorization` the settings' userinfo became, if it carried one.
    pub authorization: Option<String>,
}

/// Where each export goes, as one instance's settings name it. Its `Debug` carries no credential:
/// the collector is named as every line names it, the request target and the `Authorization` the
/// url's userinfo became are redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The settings' URL as every line names it ([`log_target`]: userinfo, a non-OTLP path and the
    /// query masked).
    pub shown: String,
    /// The collector the host dials — the settings' URL without its userinfo.
    pub collector: String,
    /// What each request carries besides the body.
    pub target: Target,
    /// The parts of the settings' URL cut from the host's text before it is logged
    /// ([`secret_parts`]).
    pub secrets: Vec<String>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target = (
            "<redacted>",
            self.target.authorization.as_ref().map(|_| "<redacted>"),
        );
        f.debug_struct("Endpoint")
            .field("shown", &self.shown)
            .field("collector", &log_target(&self.collector))
            .field("target", &target)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// The endpoint `settings` name.
    #[must_use]
    pub fn of(settings: &OtlpSettings) -> Self {
        let (clean, authorization) = split_credentials(&settings.url);
        let mut secrets = secret_parts(&settings.url);
        // A collector may echo the request's `Authorization` back: the header value and its token.
        if let Some(value) = &authorization {
            secrets.extend(value.strip_prefix("Basic ").map(str::to_owned));
            secrets.push(value.clone());
        }
        Self {
            shown: log_target(&settings.url),
            target: Target {
                path: request_target(&clean),
                authorization,
            },
            collector: clean,
            secrets,
        }
    }

    /// The request carrying `body` to this endpoint.
    #[must_use]
    pub fn request(&self, body: Vec<u8>) -> Request {
        let Target {
            path: target,
            authorization,
        } = &self.target;
        let mut fields = Vec::with_capacity(2);
        fields.push((
            CONTENT_TYPE_FIELD.to_vec(),
            CONTENT_TYPE.as_bytes().to_vec(),
        ));
        if let Some(value) = authorization {
            fields.push((AUTHORIZATION_FIELD.to_vec(), value.as_bytes().to_vec()));
        }
        Request {
            method: METHOD.to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body,
            timeout_ms: EXPORT_TIMEOUT_MS,
        }
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
                        diag = %DISABLED,
                        endpoint = %shown,
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
            Ok(reply) if (200..300).contains(&reply.status) => {
                if let Some((rejected_spans, message)) = proto::rejected(&reply.body) {
                    tracing::warn!(
                        diag = %PARTIAL_REJECTION,
                        endpoint = %shown,
                        rejected_spans,
                        "OTLP collector rejected part of this batch: {:?}",
                        capped(&scrub(&message, secrets))
                    );
                }
            }
            Ok(reply) => tracing::warn!(
                diag = %NON_2XX,
                endpoint = %shown,
                status = reply.status,
                "OTLP span export returned a non-2xx status; this batch was dropped"
            ),
            Err(e) => dropped(shown, secrets, e),
        }
    }
}

/// The error text of the door's REFUSED answer to `deliver` or `check` on no opened instance, so
/// the host's line names why instead of a bare outcome.
pub const NO_INSTANCE: &str = "no opened otlp instance";

/// The settings as [`OtlpSettings`], or the one refusal `validate`, `open` and `refresh` all give.
fn parsed(settings: &[u8]) -> Result<OtlpSettings, Refusal> {
    let settings: OtlpSettings = settings_as(settings)?;
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

/// The OTLP request a JSON-lines batch makes, each line that is no span logged and skipped: the
/// one pipeline from a `traces` batch to its request, the door's delivery and the conformance
/// driver both (a record encodes through [`proto::span`] and [`proto::encode`], as
/// [`proto::export_request`] does for records already parsed).
pub fn batch_body(batch: &[u8]) -> Option<Vec<u8>> {
    let mut spans = Vec::new();
    for line in batch
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        match serde_json::from_slice::<serde_json::Value>(line) {
            Ok(record) => match proto::span(&record) {
                Some(span) => spans.push(span),
                None => tracing::warn!(diag = %SKIPPED_RECORD, "OTLP span export skipped a record with no span identity"),
            },
            Err(_) => tracing::warn!(diag = %SKIPPED_RECORD, "OTLP span export skipped a line that is not JSON"),
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
                match Exchange::request(endpoint.request(body)) {
                    // Only the collector's `partial_success` is read from the body: a small bound.
                    Ok(state) => (state.reply_limit(REPLY_LIMIT), run),
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
                Some(run.endpoint.collector.as_str()),
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
                let result = delivered_past_bound(result, state.head_status());
                held.life().settle(&run, &result);
                Outcome::Ready
            }
        }
    }
}

/// The most characters of a collector's message one line carries.
const MESSAGE_CAP: usize = 256;

/// `text` cut to [`MESSAGE_CAP`] characters, then `…`.
fn capped(text: &str) -> String {
    match text.char_indices().nth(MESSAGE_CAP) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// A reply whose body passed [`REPLY_LIMIT`] fails the exchange ([`REPLY_OVER_BOUND`]) after its
/// head was read. The batch reached the collector all the same: with a head status, the answer is
/// that status with no body (a 2xx is delivered, its `partial_success` unread; any other status is
/// the usual non-2xx drop, status named). Any other failure, or one with no head, stands.
fn delivered_past_bound(
    result: Result<ExchangeResponse, ConnFailure>,
    head_status: Option<u16>,
) -> Result<ExchangeResponse, ConnFailure> {
    match (&result, head_status) {
        (Err(ConnFailure::Failed(text)), Some(status)) if text == REPLY_OVER_BOUND => {
            Ok(ExchangeResponse {
                status,
                ..ExchangeResponse::default()
            })
        }
        _ => result,
    }
}

/// The line an export that did not reach the collector writes, the host's text cut of the target's
/// credential-bearing parts.
fn dropped(shown: &str, secrets: &[String], error: &ConnFailure) {
    tracing::warn!(
        diag = %TRANSPORT_FAILURE,
        endpoint = %shown,
        error = %scrub(&error.to_string(), secrets),
        "OTLP span export failed; this batch was dropped"
    );
}

/// `check`: at the limits phase, a refusal of every instance after the first
/// ([`second_instances`]) — the sink states the `one_instance` mark, so the host asks it while
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
        let lines = second_instances(&instance_names(input), ALIAS, ONE_INSTANCE);
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

mod table {
    use super::{Check, Deliver, Otlp, Safe};
    use busbar_contract::abi::sdk::export::{NoScrape, NoServe, Quiet};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Otlp),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<NoScrape<Otlp>>, status: Safe<Quiet<Otlp>>,
            check: Safe<Check>, serve: Safe<NoServe<Otlp>>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;

/// The door as the macro built it, for the contract's test support (`DoorView::of`).
#[cfg(test)]
pub use table::MACRO_DOOR;

#[cfg(test)]
#[path = "door_tests.rs"]
mod tests;
