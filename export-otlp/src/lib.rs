// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-otlp`** — the OTLP trace sink as a `kind: export` plugin (owner ruling Q75,
//! 2026-09-25: OTLP export never delivered in 1.5.5, and 1.6.0 fixes it): `export.<name>.module:
//! otlp`.
//!
//! **What it carries.** The `traces` stream: one record per closed span, built by the host's traces
//! producer (K9a S7) — the span's `trace_id`, `span_id`, `parent_span_id`, `name`, `start`,
//! `duration_us` and whichever of `pool` / `ingress` / `op` / `lane` / `provider` / `model` it
//! carries. Each record the host hands it becomes one OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! ([`proto`]): one resource (`service.name = busbar`), one scope (`busbar`), one span.
//!
//! **Who dials.** The HOST: a delivery answers [`HostOp::HttpBinary`] — `POST` to the instance's
//! `url`, `content-type: application/x-protobuf` — and the host's egress carrier makes the request
//! under the COLLECTOR policy this sink declares (`declares.egress`, granted to a first-party sink):
//! `https://`, or plaintext `http://` to a loopback collector only; link-local, private, CGNAT and
//! cloud-metadata targets refused. The sink never dials. Credentials the operator embedded in the
//! URL (`https://user:pass@collector/…`) never ride it: they move into an `Authorization: Basic`
//! header, and every line this sink writes masks them. A delivery is fire-and-forget and never
//! retried; a refused, failed or non-2xx export drops that one span, logged at debug.
//!
//! **Start.** When the host starts its sinks the sink asks the policy about its target
//! ([`HostOp::Admit`], the guard's full check, name resolution included): refused, it logs
//! `…; disabling OTLP trace export` and takes no span this run; admitted, it logs `OTLP tracing
//! enabled` and is fed at the host's default admission.
//!
//! **Settings** ([`OtlpSettings`]): `url`, required. At most one `module: otlp` instance: the host
//! refuses a second while it resolves its configuration, in the words and at the place 1.5.x did.
//!
//! The one registration both doors take states [`NAME`], [`ALIAS`] and [`DECLARES`] (the manifest
//! `declares` section its signed tarball carries: the collector egress policy) over its boundary —
//! [`linked::EXPORT`] for the linked door.

#![deny(unsafe_code)]

pub mod config;
pub mod proto;

use busbar_contract::abi::sdk::{
    ExportHandler, ExportStream, HostOp, HostResult, HostStep, HttpRequest,
};
pub use config::OtlpSettings;
use std::sync::atomic::{AtomicU64, Ordering};

/// The plugin's canonical name.
pub const NAME: &str = "busbar-export-otlp";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "otlp";
/// The manifest `declares` section both doors state (`--declares-file` for the signed tarball).
pub const DECLARES: &str = include_str!("../declares.json");

/// The token of the start-time admission ask ([`HostOp::Admit`]); deliveries count from 1.
const START: u64 = 0;
/// OTLP/HTTP's binary protobuf encoding.
pub const CONTENT_TYPE: &str = "application/x-protobuf";
/// Each export's end-to-end deadline: the ten seconds 1.5.x's exporter held its HTTP client to.
pub const EXPORT_TIMEOUT_MS: u64 = 10_000;
/// The HTTP Basic auth scheme prefix (RFC 7617), with its trailing space.
const BASIC: &str = "Basic ";

/// One opened instance.
struct Otlp {
    /// Its settings, when they parse (the host refused the configuration otherwise; a sink opened
    /// only to validate or check settings still opens).
    settings: Option<OtlpSettings>,
    /// Where each export goes — the URL with its userinfo removed — and the `Authorization`
    /// header that userinfo became, if it carried any.
    target: Option<(String, Option<String>)>,
    /// The next delivery's token.
    next: AtomicU64,
}

impl ExportHandler for Otlp {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Traces]
    }

    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match serde_json::from_value::<OtlpSettings>(settings.clone()) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("export.{instance}.settings: {e}")],
        }
    }

    fn start(&self) -> HostStep {
        match &self.settings {
            Some(s) => HostStep::Host {
                token: START,
                ops: vec![HostOp::Admit { url: s.url.clone() }],
            },
            None => started(false),
        }
    }

    fn deliver_via_host(&self, _stream: ExportStream, payload: &serde_json::Value) -> HostStep {
        let Some((url, authorization)) = &self.target else {
            return HostStep::Done;
        };
        let Some(body) = proto::export_request(payload) else {
            tracing::debug!("OTLP span export skipped a record with no span identity");
            return HostStep::Done;
        };
        let mut headers = vec![("content-type".to_string(), CONTENT_TYPE.to_string())];
        if let Some(value) = authorization {
            headers.push(("authorization".to_string(), value.clone()));
        }
        HostStep::Host {
            token: self.next.fetch_add(1, Ordering::Relaxed),
            ops: vec![HostOp::HttpBinary(HttpRequest {
                method: "POST".to_string(),
                url: url.clone(),
                headers,
                body: hex(&body),
                timeout_ms: EXPORT_TIMEOUT_MS,
            })],
        }
    }

    fn resume(&self, token: u64, results: Vec<HostResult>) -> HostStep {
        let outcome = results.into_iter().next();
        let shown = self
            .settings
            .as_ref()
            .map_or_else(String::new, |s| mask_userinfo(&s.url));
        if token == START {
            return match outcome {
                Some(HostResult::Done { .. }) => {
                    tracing::info!(endpoint = %shown, "OTLP tracing enabled");
                    started(true)
                }
                Some(HostResult::Failed { error, .. }) => {
                    tracing::error!("{error}; disabling OTLP trace export");
                    started(false)
                }
                _ => started(false),
            };
        }
        match outcome {
            Some(HostResult::Http(answer)) if (200..300).contains(&answer.status) => {}
            Some(HostResult::Http(answer)) => tracing::debug!(
                endpoint = %shown,
                status = answer.status,
                "OTLP span export returned a non-2xx status; this span was dropped"
            ),
            Some(HostResult::Failed { step, error, .. }) => tracing::debug!(
                endpoint = %shown,
                step = %step,
                error = %error,
                "OTLP span export failed; this span was dropped"
            ),
            _ => {}
        }
        HostStep::Done
    }
}

/// Started — taking spans this run, or not — at the host's default admission.
fn started(live: bool) -> HostStep {
    HostStep::Started {
        live,
        inflight: 0,
        gate: String::new(),
    }
}

/// `url` with any userinfo (`scheme://user:pass@host/…`) replaced by `***`, safe for a log line;
/// a URL with none, or a string that is not a URL, unchanged.
pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return url.to_string();
    }
    if parsed.set_password(None).is_err() || parsed.set_username("***").is_err() {
        let host = parsed.host_str().unwrap_or("");
        return match parsed.port() {
            Some(p) => format!("{}://***@{host}:{p}", parsed.scheme()),
            None => format!("{}://***@{host}", parsed.scheme()),
        };
    }
    parsed.into()
}

/// Split any userinfo OUT of `endpoint`: `(the endpoint without it, Some(Authorization: Basic
/// base64(user:pass)))` — RFC 7617, the userinfo percent-decoded — or `(endpoint, None)` when it
/// carries none or is not a URL. What the host is asked to POST to never carries the secret.
pub fn split_credentials(endpoint: &str) -> (String, Option<String>) {
    let Ok(mut parsed) = url::Url::parse(endpoint) else {
        return (endpoint.to_string(), None);
    };
    let username = parsed.username().to_string();
    let password = parsed.password().map(str::to_string);
    if username.is_empty() && password.is_none() {
        return (endpoint.to_string(), None);
    }
    let user = percent_decode(&username);
    let pass = percent_decode(password.as_deref().unwrap_or(""));
    let token = base64(format!("{user}:{pass}").as_bytes());
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    (clean, Some(format!("{BASIC}{token}")))
}

/// Percent-decode a URL userinfo component (`%XX` → the byte; anything else as written).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex_pair = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (
            bytes[i],
            hex_pair.and_then(|h| u8::from_str_radix(h, 16).ok()),
        ) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Standard base64 (RFC 4648 §4, `=`-padded).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The octets as lowercase hex — [`HostOp::HttpBinary`]'s body spelling.
pub fn hex(octets: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(octets.len() * 2);
    for b in octets {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Open an instance with its settings (JSON text). Never fails: settings that do not parse are the
/// configuration's refusal, reported by [`ExportHandler::validate`] — a sink opened only to answer
/// that must open.
pub fn open(cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    let settings: Option<OtlpSettings> = serde_json::from_str(cfg).ok();
    let target = settings.as_ref().map(|s| split_credentials(&s.url));
    Ok(Box::new(Otlp {
        settings,
        target,
        next: AtomicU64::new(START + 1),
    }))
}

busbar_contract::abi::sdk::export_export_plugin!(open);

/// THE COMPILED-IN ENTRY POINT — the same op-dispatch and envelope the `busbar_call` symbol runs.
pub fn dispatch_compiled_in(
    handler: &dyn ExportHandler,
    req: busbar_contract::abi::sdk::ExportRequest,
) -> busbar_contract::abi::sdk::Envelope<busbar_contract::abi::sdk::ExportResponse> {
    busbar_contract::abi::sdk::dispatch_export_enveloped(handler, req)
}

/// THE LINKED DOOR's entry: what the composition root's linked table registers through the one
/// registration a dropped-in tarball of this crate also takes.
pub mod linked {
    /// `(name, alias, declares, boundary)`.
    pub const EXPORT: (&str, &str, &str, &busbar_contract::abi::sdk::ColdEntry) = (
        super::NAME,
        super::ALIAS,
        super::DECLARES,
        &super::BUSBAR_COLD_ENTRY,
    );
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
