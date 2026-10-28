// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` of an `export.<name>.module: otlp` instance. The same serde the host's
//! configuration grammar uses, so a settings error reads the same
//! (`export.<name>.settings: unknown field …` / `missing field `url``).

use serde::{Deserialize, Serialize};

/// `settings:` of an `export.<name>.module: otlp` instance. Its `Debug` names the url as every line
/// the sink writes names it ([`crate::log_target`]): userinfo, a non-OTLP path and the query masked.
#[derive(Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OtlpSettings {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`) — REQUIRED. When an
    /// `otlp` export instance is present busbar exports its spans there.
    pub url: String,
}

impl std::fmt::Debug for OtlpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpSettings")
            .field("url", &crate::log_target(&self.url))
            .finish()
    }
}

impl OtlpSettings {
    /// The settings `bytes` hold, refused in the configuration grammar's words (`unknown field …`,
    /// `missing field `url``).
    ///
    /// Empty settings read as `{}` (the SDK's `settings_object` rule), so they are refused for the
    /// missing `url`, not as JSON that ended early.
    ///
    /// # Errors
    /// The bytes are not JSON, or not this shape.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let bytes = if bytes.is_empty() { b"{}" } else { bytes };
        serde_json::from_value(serde_json::from_slice(bytes)?)
    }
}
