// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-otlp`** — the OTLP trace sink as a `kind: export` plugin:
//! `export.<name>.module: otlp`.
//!
//! **What it carries.** The `traces` stream: one record per closed span, built by the host's traces
//! producer — the span's `trace_id`, `span_id`, `parent_span_id`, `name`, `start`,
//! `duration_us` and whichever of `pool` / `ingress` / `op` / `lane` / `provider` / `model` it
//! carries. Each batch the host hands it becomes one OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! ([`proto`]): one resource (`service.name = busbar`), one scope (`busbar`), one span per record.
//!
//! **Who dials.** The HOST: the sink declares one outbound need ([`door::STATEMENT`]) — framed
//! `http`, pinned to the instance's `url` setting with the userinfo stripped, under the
//! `loopback-allowed` egress class (`https://`, or plaintext `http://` to a loopback collector
//! only) — and a delivery is one
//! `exchange()` over it: `POST`, `content-type: application/x-protobuf`. The sink never dials.
//! Credentials the operator embedded in the URL (`https://user:pass@collector/…`) never ride the
//! request: they move into an `Authorization: Basic` header, and every line this sink writes masks
//! them; a url whose credential would be misread as its host is refused ([`ambiguous_url`]). A
//! delivery is fire-and-forget and never retried; a refused, failed or non-2xx export drops that
//! batch, logged at warn.
//!
//! **Admission.** The host's connector judges every export against the need's egress class. Its
//! first answer settles the run: refused, the sink logs `…; disabling OTLP trace export` and sends
//! no later batch; carried, it logs `OTLP tracing enabled`.
//!
//! **Settings** ([`OtlpSettings`]): `url`, required.
//!
//! One door, both ways in: [`door::door`] is the row a busbar build links, and the sibling
//! `busbar-export-otlp-plugin` cdylib exports the same door as its one symbol.

#![forbid(unsafe_code)]

pub mod config;
pub mod door;
pub mod proto;

use busbar_contract::abi::sdk::mask::mask_url;
use busbar_contract::abi::sdk::url::{self as sdk_url, cut_userinfo, Userinfo};
pub use config::OtlpSettings;

/// Why a second instance is refused, the tail of the limits check's line
/// (`busbar_contract::abi::sdk::export::second_instances`): the sink states the `one_instance`
/// mark, so each extra instance is refused, naming the first.
pub const ONE_INSTANCE: &str =
    "OTLP installs the ONE process-global tracer subscriber, so a second \
     instance could only be silently ignored — keep a single instance.";

/// The plugin's canonical name.
pub const NAME: &str = "busbar-export-otlp";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "otlp";
/// The manifest `declares` section the signed tarball carries (`--declares-file`).
pub const DECLARES: &str = include_str!("../declares.json");

/// OTLP/HTTP's binary protobuf encoding.
pub const CONTENT_TYPE: &str = "application/x-protobuf";
/// Each export's end-to-end deadline.
pub const EXPORT_TIMEOUT_MS: u64 = 10_000;
/// The OTLP/HTTP traces path (the specification's default), kept in a log line: it is not a secret.
const OTLP_TRACES_PATH: &str = "/v1/traces";

/// `url` as a log line or `Debug` names it: scheme, a masked userinfo, host
/// and port. A path becomes `/***` unless it is `/` or OTLP's own `/v1/traces`, since a collector key
/// may ride in the path. A query becomes `?***` (`?api-key=`). A fragment is dropped. A string that
/// is not a URL keeps only its scheme and authority, userinfo cut.
pub fn log_target(url: &str) -> String {
    let Ok(u) = url::Url::parse(url) else {
        let cut = cut_userinfo(url, "***@");
        let Some((scheme, rest)) = cut.split_once("://") else {
            return "***".to_string();
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let tail = if end < rest.len() { "/***" } else { "" };
        return format!("{scheme}://{}{tail}", &rest[..end]);
    };
    let Some(host) = u.host_str() else {
        return format!("{}:***", u.scheme());
    };
    let mut out = format!("{}://", u.scheme());
    if !u.username().is_empty() || u.password().is_some() {
        out.push_str("***@");
    }
    out.push_str(host);
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    match u.path() {
        "" | "/" => {}
        OTLP_TRACES_PATH => out.push_str(OTLP_TRACES_PATH),
        _ => out.push_str("/***"),
    }
    if u.query().is_some() {
        out.push_str("?***");
    }
    out
}

/// The parts of `url` that can carry a credential, as [`scrub`] cuts them from foreign text: the URL
/// as written and masked (`busbar_contract::abi::sdk::mask::mask_url`), the URL without userinfo,
/// its path (unless OTLP's own), query and userinfo, each also percent-decoded; longest first.
pub fn secret_parts(url: &str) -> Vec<String> {
    let mut parts = vec![url.to_string(), mask_url(url), split_credentials(url).0];
    if let Ok(u) = url::Url::parse(url) {
        if !matches!(u.path(), "" | "/" | OTLP_TRACES_PATH) {
            parts.push(u.path().to_string());
        }
        if let Some(q) = u.query().filter(|q| !q.is_empty()) {
            parts.push(q.to_string());
        }
        if let Some(p) = u.password() {
            parts.push(p.to_string());
        }
        parts.push(u.username().to_string());
    }
    let mut parts = sdk_url::and_decoded(parts);
    parts.retain(|p| !p.is_empty());
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup();
    parts
}

/// `text` (the host's failure words, which may quote the target) with each of `parts`
/// ([`secret_parts`]) replaced by `***`: the SDK's `sdk::url::scrub`, unquoted.
#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    sdk_url::scrub(text, parts.to_vec(), false)
}

/// The ambiguous-URL refusal: `Some(the refusal)` when `url` parses but
/// carries an `@` after its host — `https://tok/en@collector/…` or `https://u:123/x@collector/…`,
/// a credential holding an unescaped `/`, `?` or `#`, which a URL parser reads as host `tok` (or
/// `u`, port `123`) and a path, so the credential would be dialled as a host and written into
/// lines. The refusal shows the url with everything before its last `@` cut, never the credential.
/// A url that does not parse, or has no `@` after its host, is not ambiguous here. The words are
/// the SDK's (`sdk::url::ambiguous_url`); this parser decides what the path is.
pub fn ambiguous_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    sdk_url::ambiguous_url(url, &parsed[url::Position::BeforePath..])
}

/// Split any userinfo OUT of `endpoint`: `(the endpoint without it, Some(Authorization: Basic
/// base64(user:pass)))` — RFC 7617, the userinfo percent-decoded — or `(endpoint, None)` when it
/// carries none or is not a URL. What the request carries never holds the secret in its target.
pub fn split_credentials(endpoint: &str) -> (String, Option<String>) {
    let Ok(mut parsed) = url::Url::parse(endpoint) else {
        // Not a URL the client can parse (any string is accepted as the url): no credential is
        // made of it, and its userinfo never reaches the host's dial target.
        return (cut_userinfo(endpoint, ""), None);
    };
    // The user-pass is an octet sequence (RFC 7617), and a userinfo escape encodes an octet (RFC
    // 3986): the decoded bytes are base64ed as they are, never read as text first.
    let Some(authorization) =
        sdk_url::basic_authorization(parsed.username(), parsed.password(), Userinfo::Octets)
    else {
        return (endpoint.to_string(), None);
    };
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    (clean, Some(authorization))
}

/// The request target `endpoint` names: its path and query (`/` when it has no path), or `/` when
/// it is not a URL.
pub fn request_target(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => {
            let target = &u[url::Position::BeforePath..url::Position::AfterQuery];
            if target.is_empty() { "/" } else { target }.to_string()
        }
        Err(_) => "/".to_string(),
    }
}

/// The suite's view of the SDK's percent-decoder (`sdk::url::percent_decode`), over text.
#[cfg(test)]
fn percent_decode(s: &str) -> Vec<u8> {
    sdk_url::percent_decode(s.as_bytes())
}

/// Standard base64 (RFC 4648 §4, `=`-padded) through the `base64` crate: the suite's independent
/// check of the Basic credential the SDK encodes.
#[cfg(test)]
fn base64(input: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(input)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
