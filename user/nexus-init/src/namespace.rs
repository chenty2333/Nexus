use alloc::string::String;
use alloc::vec::Vec;

use axle_types::status::{ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_FOUND};
use axle_types::{zx_handle_t, zx_status_t};
use nexus_component::{CapabilityKind, ComponentDecl, NamespaceEntry};
use nexus_io::{NamespaceTrie, normalize_namespace_path};

use crate::ECHO_PROTOCOL_NAME;

pub(crate) struct CapabilityRegistry {
    protocols: Vec<(String, zx_handle_t)>,
}

impl CapabilityRegistry {
    pub(crate) fn new() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }

    pub(crate) fn publish_protocol(&mut self, name: &str, handle: zx_handle_t) {
        self.protocols.push((String::from(name), handle));
    }

    pub(crate) fn take_protocol(&mut self, name: &str) -> Result<zx_handle_t, zx_status_t> {
        let index = self
            .protocols
            .iter()
            .position(|(protocol, _)| protocol == name)
            .ok_or(ZX_ERR_NOT_FOUND)?;
        Ok(self.protocols.remove(index).1)
    }
}

pub(crate) fn build_namespace_entries(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
) -> Result<Vec<NamespaceEntry>, zx_status_t> {
    let mut entries = Vec::new();
    let mut trie = NamespaceTrie::new();
    for use_decl in &decl.uses {
        match use_decl.kind {
            CapabilityKind::Protocol | CapabilityKind::Directory => {
                let Some(path) = &use_decl.target_path else {
                    return Err(ZX_ERR_INVALID_ARGS);
                };
                let handle = registry.take_protocol(&use_decl.source_name)?;
                let normalized = normalize_namespace_path(path)?;
                trie.insert(normalized.as_str(), handle)?;
                entries.push(NamespaceEntry {
                    path: normalized,
                    handle,
                });
            }
            CapabilityKind::Runner | CapabilityKind::Resolver => {}
        }
    }
    Ok(entries)
}

pub(crate) fn publish_protocols(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
    outgoing: zx_handle_t,
) {
    for expose in &decl.exposes {
        if expose.target_name == ECHO_PROTOCOL_NAME {
            registry.publish_protocol(&expose.target_name, outgoing);
            return;
        }
    }
}
