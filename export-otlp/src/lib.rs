// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-otlp`** — the OTLP trace sink as a `kind: export` plugin:

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(unsafe_code)]

#[cfg(test)]
#[path = "tests/ownership_tests.rs"]
mod ownership_tests;
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/wipe_probe.rs"]
mod wipe_probe;

/// The parsed serialization is an owned allocation, separately from the settings text.
fn parsed_url(text: &str) -> Result<owners::ParsedUrl, url::ParseError> {
    let parsed = owners::ParsedUrl::parse(text)?;
    #[cfg(test)]
    crate::wipe_probe::watch("parsed url", parsed.as_str().as_bytes());
    Ok(parsed)
}

pub mod config;
pub mod door;
mod owners;
pub mod proto;

use busbar_contract::abi::sdk::mask::mask_url;
use busbar_contract::abi::sdk::url::{self as sdk_url, cut_userinfo, Userinfo};
pub use config::OtlpSettings;
use zeroize::{Zeroize, Zeroizing};

/// Why a second instance is refused, the tail of the limits check's line

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

pub fn log_target(url: &str) -> String {
    let Ok(u) = parsed_url(url) else {
        return unparsed_target(url);
    };

    if u[url::Position::BeforePath..].contains('@') {
        return unparsed_target(url);
    }
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

pub fn secret_parts(url: &str) -> Vec<String> {
    let (clean, mut unused_authorization) = split_credentials(url);
    unused_authorization.zeroize();
    let mut parts = Zeroizing::new(vec![url.to_string(), mask_url(url), clean]);
    if let Ok(u) = parsed_url(url) {
        if !matches!(u.path(), "" | "/" | OTLP_TRACES_PATH) {
            parts.push(u.path().to_string());
        }
        if let Some(q) = u.query().filter(|q| !q.is_empty()) {
            parts.push(q.to_string());
        }
        if let Some(fragment) = u.fragment().filter(|fragment| !fragment.is_empty()) {
            parts.push(fragment.to_string());
        }
        if let Some(p) = u.password() {
            parts.push(p.to_string());
        }
        parts.push(u.username().to_string());
    }
    let mut parts = Zeroizing::new(sdk_url::and_decoded(std::mem::take(&mut *parts)));
    parts.retain(|p| !p.is_empty());
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup_by(|removed, kept| {
        if removed == kept {
            removed.zeroize();
            true
        } else {
            false
        }
    });
    #[cfg(test)]
    for part in parts.iter() {
        crate::wipe_probe::watch("redaction part", part.as_bytes());
    }
    std::mem::take(&mut *parts)
}

/// `text` (the host's failure words, which may quote the target) with each of `parts`

#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    sdk_url::scrub(text, parts.to_vec(), false)
}

/// What a line shows of url text that does not parse: `<scheme>:***` when it opens with `http` or

fn unparsed_target(url: &str) -> String {
    let scheme = url
        .split_once(':')
        .map(|(s, _)| s)
        .filter(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"));
    scheme.map_or_else(|| "***".to_string(), |s| format!("{s}:***"))
}

/// The ambiguous-URL refusal: `Some(the refusal)` when `url` carries an `@` after its host —

pub fn ambiguous_url(url: &str) -> Option<String> {
    let from_path = Zeroizing::new(match parsed_url(url) {
        Ok(parsed) => parsed[url::Position::BeforePath..].to_string(),
        Err(_) if url.contains('@') => "@".to_string(),
        Err(_) => return None,
    });
    sdk_url::ambiguous_url(&unparsed_target(url), &from_path)
}

/// Split any userinfo OUT of `endpoint`: `(the endpoint without it, Some(Authorization: Basic

pub fn split_credentials(endpoint: &str) -> (String, Option<String>) {
    let Ok(parsed) = parsed_url(endpoint) else {
        return (cut_userinfo(endpoint, ""), None);
    };

    let Some(authorization) =
        sdk_url::basic_authorization(parsed.username(), parsed.password(), Userinfo::Octets)
    else {
        return (endpoint.to_string(), None);
    };
    #[cfg(test)]
    crate::wipe_probe::watch("Basic value", authorization.as_bytes());
    let clean = if parsed.host_str().is_none_or(str::is_empty) || parsed.scheme() == "file" {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        let prefix = &parsed[..url::Position::BeforeUsername];
        let suffix = &parsed[url::Position::BeforeHost..];
        let mut clean = String::with_capacity(prefix.len() + suffix.len());
        clean.push_str(prefix);
        clean.push_str(suffix);
        clean
    };
    (clean, Some(authorization))
}

/// The request target `endpoint` names: its path and query (`/` when it has no path), or `/` when

pub fn request_target(endpoint: &str) -> String {
    match parsed_url(endpoint) {
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

#[cfg(test)]
fn base64(input: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(input)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
