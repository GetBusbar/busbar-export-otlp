// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test build's watchers behind the production seams (`crate::seams`): the wipe probe over each
//! buffer that holds a credential, and the settings ownership check over the parsed settings.

pub(super) use crate::ownership_tests::watch_settings_value;
pub(super) use crate::wipe_probe::watch;
