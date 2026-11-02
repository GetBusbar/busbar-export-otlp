// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the OTLP sink on the export kind's table (`busbar_contract::abi::export`), its

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    cancel, CheckIn, CheckOut, DeliverIn, ExportStream, Tail, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement, MARK_ONE_INSTANCE};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::door::{abi_str, alias, statement};
use busbar_contract::abi::sdk::exchange::{
    exchange, Exchange, ExchangeResponse, Request, SealedField, REPLY_OVER_BOUND,
};
use busbar_contract::abi::sdk::export::{instance_names, second_instances, tail};
pub use busbar_contract::abi::sdk::export::{NO_EXPOSITION, NO_ROUTE};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
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

    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// The one stream the sink carries.
const STREAMS: &[u8] = &[ExportStream::Traces as u8];

const TAIL: Tail = tail(STREAMS, &[]);

busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
    (busbar_contract::abi::mechanism::extensions::EXT_SPAN_RECORDS, b"true"),
]);

/// The most deliveries one instance holds in flight; past it the host sheds the batch.
pub const MAX_INFLIGHT: u32 = 64;

/// The module name an operator writes, as the alias the registry holds beside [`NAME`].
const REWRITES: &[Rewrite] = &[alias(ALIAS)];

/// This plugin's Statement: its name and version, the `traces` stream, the alias and the collector need.
pub const STATEMENT: Statement = Statement {
    extensions: EXTENSIONS,
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),

    marks: MARK_ONE_INSTANCE,
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

/// The catalogue codes the sink's lines carry (`declares.json`): the exporter disabled because the
const DISABLED: &str = "BUSBAR-7140";
const NON_2XX: &str = "BUSBAR-7141";
const TRANSPORT_FAILURE: &str = "BUSBAR-7142";
const PARTIAL_REJECTION: &str = "BUSBAR-7143";
const SKIPPED_RECORD: &str = "BUSBAR-7144";
const PARTIAL_WARNING: &str = "BUSBAR-7145";

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
    /// The `Authorization` the settings' userinfo became, if it carried one, held as a `Cred` (it
    /// has no getter and no `Debug`): each request carries it sealed, so the SDK frames and wipes it.
    pub authorization: Option<Cred>,
}

impl Drop for Target {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.path);
    }
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

impl Drop for Endpoint {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.collector);
        zeroize::Zeroize::zeroize(&mut self.secrets);
    }
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

        if let Some(value) = &authorization {
            secrets.extend(value.strip_prefix("Basic ").map(str::to_owned));
            secrets.push(value.clone());
        }
        Self {
            shown: log_target(&settings.url),
            target: Target {
                path: request_target(&clean),
                authorization: authorization.map(|value| {
                    Cred::take(&mut serde_json::Value::String(value))
                        .unwrap_or_else(Cred::empty)
                        .secure_for(&clean)
                }),
            },
            collector: clean,
            secrets,
        }
    }

    /// The request carrying `body` to this endpoint, and the sealed fields it carries beside it
    #[must_use]
    pub fn parts(&self, body: Vec<u8>) -> (Request, Vec<SealedField>) {
        let request = Request {
            method: METHOD.to_vec(),
            target: self.target.path.as_bytes().to_vec(),
            fields: vec![(
                CONTENT_TYPE_FIELD.to_vec(),
                CONTENT_TYPE.as_bytes().to_vec(),
            )],
            body,
            timeout_ms: EXPORT_TIMEOUT_MS,
        };
        let sealed = self
            .target
            .authorization
            .iter()
            .map(|c| (1, AUTHORIZATION_FIELD.to_vec(), c.field()))
            .collect();
        (request, sealed)
    }
}

impl Endpoint {
    /// The exchange carrying `body` to this endpoint, framed.
    pub fn exchange(&self, body: Vec<u8>) -> Result<Exchange, ConnFailure> {
        let (request, sealed) = self.parts(body);
        Exchange::request_sealed(request, sealed)
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
    fn settle(&self, run: &Arc<Run>, result: &Result<ExchangeResponse, ConnFailure>) {
        let stale = !Arc::ptr_eq(run, &self.run());
        run.settle(stale, result);
    }
}

impl Run {
    /// Whether the host refused this run's exports: its connector refused the first one (the
    fn refused(&self) -> bool {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) == Some(false)
    }

    /// What became of one export: the first answer the host gives settles whether this run takes
    fn settle(&self, stale: bool, result: &Result<ExchangeResponse, ConnFailure>) {
        let shown = self.endpoint.shown.as_str();
        let secrets = self.endpoint.secrets.as_slice();
        let announcement = if !stale {
            let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
            match (result, *admitted) {
                (Err(ConnFailure::Refused(_) | ConnFailure::Unarmed), None) => {
                    *admitted = Some(false);
                    Some(false)
                }
                (Ok(_), None) => {
                    *admitted = Some(true);
                    Some(true)
                }
                _ => None,
            }
        } else {
            None
        };

        match announcement {
            Some(false) => {
                if let Err(error) = result {
                    tracing::error!(
                        diag = %DISABLED,
                        endpoint = %shown,
                        "{:?}; disabling OTLP trace export",
                        failure_text(error, secrets)
                    );
                }
                return;
            }
            Some(true) => tracing::info!(endpoint = %shown, "OTLP tracing enabled"),
            None => {}
        }
        match result {
            Ok(reply) if (200..300).contains(&reply.status) => {
                let partial = match proto::collector_response(&reply.body) {
                    Ok(partial) => partial,
                    Err(_) => {
                        tracing::warn!(
                            diag = %PARTIAL_WARNING,
                            endpoint = %shown,
                            status = reply.status,
                            "OTLP collector reply is not a valid protobuf response; partial-success details are unavailable"
                        );
                        return;
                    }
                };
                if let Some((rejected_spans, message)) = partial {
                    let message = capped(&scrub(&message, secrets));
                    if rejected_spans > 0 {
                        tracing::warn!(
                            diag = %PARTIAL_REJECTION,
                            endpoint = %shown,
                            rejected_spans,
                            "OTLP collector rejected part of this batch: {message:?}"
                        );
                    } else {
                        tracing::warn!(
                            diag = %PARTIAL_WARNING,
                            endpoint = %shown,
                            "OTLP collector warned about this batch: {message:?}"
                        );
                    }
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
pub const NO_INSTANCE: &str = "no opened otlp instance";

/// The settings as [`OtlpSettings`], or the one refusal `validate`, `open` and `refresh` all give.
fn parsed(settings: &[u8]) -> Result<OtlpSettings, Refusal> {
    let value =
        crate::owners::SettingsValue(busbar_contract::abi::sdk::life::settings_value(settings)?);
    #[cfg(test)]
    crate::ownership_tests::watch_settings_value(&value);
    let settings: OtlpSettings = serde::Deserialize::deserialize(&*value)
        .map_err(|e: serde_json::Error| Refusal::failed(format!("settings: {e}")))?;
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
pub fn batch_body(batch: &[u8]) -> Option<Vec<u8>> {
    let mut spans = Vec::new();
    for line in batch
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        match serde_json::from_slice::<serde_json::Value>(line) {
            Ok(record) => match proto::span(&record) {
                Some(span) => spans.push(span),
                None => {
                    tracing::warn!(diag = %SKIPPED_RECORD, "OTLP span export skipped a record with no span identity")
                }
            },
            Err(_) => {
                tracing::warn!(diag = %SKIPPED_RECORD, "OTLP span export skipped a line that is not JSON")
            }
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
                match endpoint.exchange(body) {
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
fn delivered_past_bound(
    result: Result<ExchangeResponse, ConnFailure>,
    head_status: Option<u16>,
) -> Result<ExchangeResponse, ConnFailure> {
    match (&result, head_status) {
        (Err(ConnFailure::Failed(text)), Some(status)) if text == REPLY_OVER_BOUND => {
            if (200..300).contains(&status) {
                tracing::warn!(
                    diag = %PARTIAL_WARNING,
                    status,
                    reply_limit = REPLY_LIMIT,
                    "OTLP collector reply exceeded the body limit; partial-success details are unavailable"
                );
            }
            Ok(ExchangeResponse {
                status,
                ..ExchangeResponse::default()
            })
        }
        _ => result,
    }
}

/// The line an export that did not reach the collector writes, the host's text cut of the target's
fn dropped(shown: &str, secrets: &[String], error: &ConnFailure) {
    let message = failure_text(error, secrets);
    if matches!(error, ConnFailure::Refused(_) | ConnFailure::Unarmed) {
        tracing::warn!(
            diag = %TRANSPORT_FAILURE,
            endpoint = %shown,
            error = ?message,
            "OTLP span export was refused; this batch was dropped"
        );
    } else {
        tracing::warn!(
            diag = %TRANSPORT_FAILURE,
            endpoint = %shown,
            error = ?message,
            "OTLP span export failed; this batch was dropped"
        );
    }
}

fn failure_text(error: &ConnFailure, secrets: &[String]) -> String {
    let raw = zeroize::Zeroizing::new(error.to_string());
    scrub(&raw, secrets)
}

/// `check`: at the limits phase, a refusal of every instance after the first
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
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "door_tests.rs"]
mod tests;
