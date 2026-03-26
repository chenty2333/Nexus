use super::super::*;

use alloc::vec::Vec;

use crate::services::BootstrapNamespace;
use crate::{push_starnix_manifest_assets, push_starnix_runtime_assets};

pub(super) fn build_starnix_namespace() -> Result<nexus_io::ProcessNamespace, zx_status_t> {
    let mut assets = Vec::new();
    push_starnix_runtime_assets(&mut assets);
    push_starnix_manifest_assets(&mut assets);
    let bootstrap = BootstrapNamespace::build(&assets)?;
    let mut mounts = bootstrap.namespace().mounts().clone();
    mounts.insert("/", bootstrap.boot_root())?;
    Ok(nexus_io::ProcessNamespace::new(mounts))
}
