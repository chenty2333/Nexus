use alloc::format;
use alloc::sync::Arc;

use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NOT_FOUND,
    ZX_ERR_NOT_SUPPORTED,
};
use axle_types::zx_status_t;
use nexus_component::{CapabilityKind, ComponentDecl, ResolvedComponent, StartupMode, UseDecl};
use nexus_io::{FdOps, OpenFlags};

pub(crate) struct ResolverRegistry {
    boot_root: Arc<dyn FdOps>,
}

impl ResolverRegistry {
    pub(crate) fn new(boot_root: Arc<dyn FdOps>) -> Self {
        Self { boot_root }
    }

    pub(crate) fn resolve(
        &self,
        capability_name: &str,
        url: &str,
    ) -> Result<ResolvedComponent, zx_status_t> {
        if capability_name != "boot-resolver" {
            return Err(ZX_ERR_NOT_FOUND);
        }
        let path = boot_manifest_path(url)?;
        let manifest = self.boot_root.openat(path.as_str(), OpenFlags::READABLE)?;
        let mut bytes = [0u8; 4096];
        let actual = manifest.read(&mut bytes)?;
        if actual == 0 {
            return Err(ZX_ERR_BAD_STATE);
        }
        decode_resolved_component(&bytes[..actual])
    }
}

pub(crate) fn decode_resolved_component(bytes: &[u8]) -> Result<ResolvedComponent, zx_status_t> {
    let decl = ComponentDecl::decode_binary(bytes).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(ResolvedComponent {
        decl,
        package_dir: None,
        config_blob: None,
    })
}

pub(crate) fn lookup_use_decl<'a>(
    decl: &'a ComponentDecl,
    kind: CapabilityKind,
    source_name: Option<&str>,
) -> Result<&'a UseDecl, zx_status_t> {
    let use_decl = decl
        .uses
        .iter()
        .find(|use_decl| {
            use_decl.kind == kind
                && source_name.is_none_or(|name| use_decl.source_name.as_str() == name)
        })
        .ok_or(ZX_ERR_NOT_FOUND)?;
    match kind {
        CapabilityKind::Runner | CapabilityKind::Resolver => {
            if use_decl.target_path.is_some() {
                return Err(ZX_ERR_INVALID_ARGS);
            }
        }
        CapabilityKind::Protocol | CapabilityKind::Directory => {}
    }
    Ok(use_decl)
}

pub(crate) fn resolve_with_realm(
    realm: &ComponentDecl,
    resolvers: &ResolverRegistry,
    url: &str,
) -> Result<ResolvedComponent, zx_status_t> {
    let resolver = lookup_use_decl(realm, CapabilityKind::Resolver, None)?;
    resolvers.resolve(&resolver.source_name, url)
}

pub(crate) fn resolve_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    name: &str,
) -> Result<(ResolvedComponent, StartupMode), zx_status_t> {
    let child = root
        .decl
        .children
        .iter()
        .find(|child| child.name == name)
        .ok_or(ZX_ERR_NOT_FOUND)?;
    let resolved = resolve_with_realm(&root.decl, resolvers, &child.url)?;
    Ok((resolved, child.startup))
}

fn map_resolve_error(error: nexus_component::ResolveError) -> zx_status_t {
    match error {
        nexus_component::ResolveError::InvalidUrl => ZX_ERR_INVALID_ARGS,
        nexus_component::ResolveError::UnsupportedScheme => ZX_ERR_NOT_SUPPORTED,
        nexus_component::ResolveError::NotFound => ZX_ERR_NOT_FOUND,
    }
}

fn boot_manifest_path(url: &str) -> Result<alloc::string::String, zx_status_t> {
    let name = url
        .strip_prefix("boot://")
        .ok_or_else(|| map_resolve_error(nexus_component::ResolveError::UnsupportedScheme))?;
    if name.is_empty() || name.contains('/') {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(format!("manifests/{name}.nxcd"))
}
