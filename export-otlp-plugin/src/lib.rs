// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OTLP trace export sink as a droppable busbar plugin** — the `cdylib` a signed tarball of
//! the sink carries (`kind: export`, alias `otlp`).
//!
//! All the sink lives in the `busbar-export-otlp` crate, including its one door registration
//! (`export_export_plugin!(open)`): the frozen symbols the loader looks up are the SDK's, defined
//! once, and they answer through that door. This crate re-exports the logic crate so the library it
//! builds carries exactly the code the busbar binary links — one source, both doors (DECISIONS #2
//! rule (1)). Pack it with `busbar-plugin-pack --kind export --alias otlp --declares-file
//! export-otlp/declares.json` (the declaration states the collector egress policy the sink needs).

#![deny(unsafe_code)]

pub use busbar_export_otlp::*;
