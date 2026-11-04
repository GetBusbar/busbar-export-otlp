// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` of an `export.<name>.module: otlp` instance. The same serde the host's
//! configuration grammar uses, so a settings error reads the same
//! (`export.<name>.settings: unknown field …` / `missing field `url``). The door reads them through
//! `busbar_contract::abi::sdk::life::settings_value` (empty settings are `{}`, so they are refused
//! for the missing `url`, not as JSON that ended early).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// `settings:` of an `export.<name>.module: otlp` instance. Its `Debug` names the url as every line
/// the sink writes names it ([`crate::log_target`]): userinfo, a non-OTLP path and the query masked.
#[derive(Deserialize, Serialize, Clone, PartialEq)]
#[serde(from = "ParsedSettings")]
pub struct OtlpSettings {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`) — REQUIRED. When an
    /// `otlp` export instance is present busbar exports its spans there.
    pub url: String,
}

#[derive(Deserialize)]
#[serde(rename = "OtlpSettings", deny_unknown_fields)]
struct ParsedSettings {
    #[serde(deserialize_with = "wiped_url")]
    url: Zeroizing<String>,
}

fn wiped_url<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    url_string(d).map(Zeroizing::new)
}

impl From<ParsedSettings> for OtlpSettings {
    fn from(mut parsed: ParsedSettings) -> Self {
        Self {
            url: std::mem::take(&mut *parsed.url),
        }
    }
}

impl Drop for OtlpSettings {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}

fn url_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let url = String::deserialize(d)?;
    crate::seams::watch("decoded settings url", url.as_bytes());
    Ok(url)
}

impl std::fmt::Debug for OtlpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpSettings")
            .field("url", &crate::log_target(&self.url))
            .finish()
    }
}
