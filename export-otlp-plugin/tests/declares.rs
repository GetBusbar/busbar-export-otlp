// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's Statement states the whole `declares` document under `EXT_DECLARES` (BUSBAR-1.6.0.md
//! l.246), read back the way the host reads it.

#[test]
fn the_statement_carries_the_declares_document() {
    // SAFETY: `door` is this crate's own `plugin_door!` entry.
    #[allow(unused_unsafe)]
    let door =
        unsafe { busbar_plugin_loader::dispatch::LoadedDoor::from_raw(busbar_export_otlp::door) };
    let row = busbar_plugin_loader::dispatch::LinkedRow::of_loaded(door).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../export-otlp/declares.json")[..]),
    );
}
