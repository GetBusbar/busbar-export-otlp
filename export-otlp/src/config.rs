// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` of an `export.<name>.module: otlp` instance. The same serde the host's
//! configuration grammar uses, so a settings error reads the same
//! (`export.<name>.settings: unknown field …` / `missing field `url``). The door reads them through
//! `busbar_contract::abi::sdk::life::settings_as` (empty settings are `{}`, so they are refused for
//! the missing `url`, not as JSON that ended early).

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
