// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-otlp`** — the OTLP trace sink as a `kind: export` plugin (owner ruling Q75,
//! 2026-09-25: OTLP export never delivered in 1.5.5, and 1.6.0 fixes it): `export.<name>.module:
//! otlp`.
//!
//! **What it carries.** The `traces` stream: one record per closed span, built by the host's traces
//! producer (K9a S7) — the span's `trace_id`, `span_id`, `parent_span_id`, `name`, `start`,
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

pub use config::OtlpSettings;

/// THE LIMITS CHECK across every configured instance of this sink, in configuration order: the sink
/// states the `one_instance` mark, so a second instance is refused in busbar 1.5.5's words, once per
/// extra instance, naming the first.
pub fn check_limits(instances: &[String]) -> Vec<String> {
    let Some((first, rest)) = instances.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {ALIAS}` instance (already defined as '{first}'). \
                 OTLP installs the ONE process-global tracer subscriber, so a second instance could \
                 only be silently ignored — keep a single instance."
            )
        })
        .collect()
}

/// The plugin's canonical name.
use busbar_contract::abi::sdk::cred::{Cred, PasswordAt, UserinfoUrl};

pub const NAME: &str = "busbar-export-otlp";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "otlp";
/// The manifest `declares` section the signed tarball carries (`--declares-file`).
pub const DECLARES: &str = include_str!("../declares.json");

/// OTLP/HTTP's binary protobuf encoding.
pub const CONTENT_TYPE: &str = "application/x-protobuf";
/// Each export's end-to-end deadline: the ten seconds 1.5.x's exporter held its HTTP client to.
pub const EXPORT_TIMEOUT_MS: u64 = 10_000;

/// `url` with any userinfo (`scheme://user:pass@host/…`) replaced by `***`, safe for a log line;
/// a URL with none unchanged. A string that is not a URL but carries `scheme://userinfo@…` has its
/// userinfo cut the same way (`cut_userinfo`); one without is unchanged.
pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return cut_userinfo(url, "***@");
    };
    // A userinfo whose password was sealed at parse keeps its `@` (`https://@h/` for `:pw@`).
    let at_in_authority = url.split_once("://").is_some_and(|(_, rest)| {
        rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())].contains('@')
    });
    if parsed.username().is_empty() && parsed.password().is_none() && !at_in_authority {
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

/// The OTLP/HTTP traces path (the specification's default), kept in a log line: it is not a secret.
const OTLP_TRACES_PATH: &str = "/v1/traces";

/// `url` as a log line or `Debug` names it (CREDENTIAL-LOCKDOWN H3): scheme, a masked userinfo, host
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
/// as written and userinfo-masked, the URL without userinfo, its path (unless OTLP's own), query and
/// userinfo, each also percent-decoded; longest first.
pub fn secret_parts(url: &str) -> Vec<String> {
    let mut parts = vec![url.to_string(), mask_userinfo(url), without_userinfo(url)];
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
    let decoded: Vec<String> = parts
        .iter()
        .map(|p| String::from_utf8_lossy(&percent_decode(p)).into_owned())
        .collect();
    parts.extend(decoded);
    parts.retain(|p| !p.is_empty());
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup();
    parts
}

/// `text` (the host's failure words, which may quote the target) with each of `parts`
/// ([`secret_parts`]) replaced by `***`.
#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    let mut out = text.to_string();
    for p in parts {
        if out.contains(p.as_str()) {
            out = out.replace(p.as_str(), "***");
        }
    }
    out
}

/// THE AMBIGUOUS-URL REFUSAL (owner ruling 2026-10-24): `Some(the refusal)` when `url` parses but
/// carries an `@` after its host — `https://tok/en@collector/…` or `https://u:123/x@collector/…`,
/// a credential holding an unescaped `/`, `?` or `#`, which a URL parser reads as host `tok` (or
/// `u`, port `123`) and a path, so the credential would be dialled as a host and written into
/// lines. The refusal shows the url with everything before its last `@` cut, never the credential.
/// A url that does not parse, or has no `@` after its host, is not ambiguous here.
pub fn ambiguous_url(url: &str, unencoded: bool) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if !unencoded && !parsed[url::Position::BeforePath..].contains('@') {
        return None;
    }
    Some(format!(
        "settings: url `{}` is ambiguous: it has an `@` after its host, so what comes before that \
         `@` would be read as the host and path, not as a credential. Percent-encode a `/`, `?` or \
         `#` inside the credential (`%2F`, `%3F`, `%23`), or write an `@` meant for the path as \
         `%40`",
        cut_userinfo(url, "***@")
    ))
}

/// Split any userinfo OUT of `endpoint`: `(the endpoint without it, Some((the user's octets, the
/// sealed password)))` for the `Authorization: Basic` (RFC 7617) the chip makes of them, or
/// `(endpoint, None)` when it carries none or is not a URL. What the request carries never holds
/// the secret in its target.
pub fn split_credentials(endpoint: &UserinfoUrl) -> (String, Option<(Vec<u8>, Cred)>) {
    let text = endpoint.public();
    // A password holding an unescaped `/`, `?` or `#` made 1.5.5's url unparsable: no credential.
    if endpoint.password_at() == Some(PasswordAt::UserinfoUnencoded) {
        return (cut_userinfo(text, ""), None);
    }
    let Ok(mut parsed) = url::Url::parse(text) else {
        // Not a URL the client can parse (1.5.5 accepted any string as the url): no credential is
        // made of it, and its userinfo never reaches the host's dial target.
        return (cut_userinfo(text, ""), None);
    };
    let username = parsed.username().to_string();
    let password = endpoint.password();
    if username.is_empty() && password.is_none() {
        return (text.to_string(), None);
    }
    // The user-pass is an octet sequence (RFC 7617), and a userinfo escape encodes an octet (RFC
    // 3986): the decoded user is passed as its octets, never read as text first.
    let user = percent_decode(&username);
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    (
        clean,
        Some((user, password.cloned().unwrap_or_else(Cred::empty))),
    )
}

/// `url` with its userinfo taken out (a string that is not a URL: cut as [`cut_userinfo`] cuts).
fn without_userinfo(url: &str) -> String {
    let Ok(mut u) = url::Url::parse(url) else {
        return cut_userinfo(url, "");
    };
    if u.set_username("").is_ok() && u.set_password(None).is_ok() {
        u.into()
    } else {
        cut_userinfo(url, "")
    }
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

/// A string `url::Url` refuses (an out-of-range port, an empty host) that still carries
/// `scheme://userinfo@…`: everything between `://` and the LAST `@` anywhere after `://` is replaced
/// by `with` (its `@` included) — a password may hold an unescaped `/`, `?` or `#`, so no delimiter
/// bounds the authority here. A string with an `@` in its path or query is over-cut: accepted, for
/// it is unparsable and leaking a secret is worse than a shortened line. A string with no `@` after
/// `://` is returned unchanged.
fn cut_userinfo(url: &str, with: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.rfind('@') {
        Some(at) => format!("{scheme}://{with}{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// Percent-decode a URL userinfo component to its octets (`%XX` → the byte; anything else as
/// written), through the `percent-encoding` crate.
fn percent_decode(s: &str) -> Vec<u8> {
    percent_encoding::percent_decode_str(s).collect()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
