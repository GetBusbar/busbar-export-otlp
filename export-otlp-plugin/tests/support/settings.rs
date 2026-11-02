// SPDX-License-Identifier: Apache-2.0
//! Settings resolution uses the production contract's resolver and the actual loaded declaration.
pub fn settings_as_the_kernel_resolves(
    plugin: &busbar_plugin_loader::dispatch::Plugin<
        busbar_plugin_loader::dispatch::kinds::export::Export,
    >,
    bytes: &[u8],
    resolve: impl FnMut(&str, &busbar_contract::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<Vec<u8>, String> {
    let mut value = serde_json::from_slice(bytes).map_err(|e| format!("settings JSON: {e}"))?;
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut value,
        plugin.secret_refs(),
        plugin.reference_fields(),
        plugin.name(),
        resolve,
    )?;
    serde_json::to_vec(&value).map_err(|e| e.to_string())
}
