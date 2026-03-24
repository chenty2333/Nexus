use super::*;

/// Maximum VMO size that can be created via syscall (4 GiB).
const MAX_VMO_CREATE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Return the bootstrap root VMAR handle seeded into the current process.
pub fn bootstrap_root_vmar_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| Ok(Some(registry.bootstrap_root_vmar_handle)))
    })
    .ok()
    .flatten()
}

/// Return the bootstrap current-process code-image VMO handle, if seeded.
pub fn bootstrap_self_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_self_code_vmo_handle != 0)
                .then_some(registry.bootstrap_self_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Return the bootstrap `echo-provider` code-image VMO handle, if seeded.
pub fn bootstrap_echo_provider_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_echo_provider_code_vmo_handle != 0)
                .then_some(registry.bootstrap_echo_provider_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Return the bootstrap `echo-client` code-image VMO handle, if seeded.
pub fn bootstrap_echo_client_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_echo_client_code_vmo_handle != 0)
                .then_some(registry.bootstrap_echo_client_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Return the bootstrap `controller-worker` code-image VMO handle, if seeded.
pub fn bootstrap_controller_worker_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_controller_worker_code_vmo_handle != 0)
                .then_some(registry.bootstrap_controller_worker_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Return the bootstrap `starnix-kernel` code-image VMO handle, if seeded.
pub fn bootstrap_starnix_kernel_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_starnix_kernel_code_vmo_handle != 0)
                .then_some(registry.bootstrap_starnix_kernel_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Return the bootstrap Linux `hello` image VMO handle, if seeded.
pub fn bootstrap_linux_hello_code_vmo_handle() -> Option<zx_handle_t> {
    with_state_mut(|state| {
        state.with_registry(|registry| {
            Ok((registry.bootstrap_linux_hello_code_vmo_handle != 0)
                .then_some(registry.bootstrap_linux_hello_code_vmo_handle))
        })
    })
    .ok()
    .flatten()
}

/// Create an anonymous VMO and return a handle.
pub fn create_vmo(size: u64, options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if size > MAX_VMO_CREATE_SIZE {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }

    with_state_mut(|state| {
        let object_id = state.alloc_object_id();
        let global_vmo_id = state.with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
        let (process_id, address_space_id) = state.with_core(|kernel| {
            let process = kernel.current_process_info()?;
            let address_space_id = kernel.process_address_space_id(process.process_id())?;
            Ok((process.process_id(), address_space_id))
        })?;
        let created = state.with_vm_mut(|vm| {
            vm.create_anonymous_vmo_for_address_space(
                process_id,
                address_space_id,
                size,
                global_vmo_id,
            )
        })?;
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Vmo(VmoObject {
                    creator_process_id: created.process_id(),
                    global_vmo_id: created.global_vmo_id(),
                    backing_scope: VmoBackingScope::LocalPrivate {
                        owner_address_space_id: created.address_space_id(),
                        local_vmo_id: created.vmo_id(),
                    },
                    kind: axle_mm::VmoKind::Anonymous,
                    size_bytes: created.size_bytes(),
                    image_layout: None,
                }),
            )?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(object_id, handle::vmo_default_rights()) {
            Ok(h) => Ok(h),
            Err(e) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(e)
            }
        }
    })
}

/// Create one public physical/MMIO-style VMO over an existing page-aligned span.
///
/// # Privilege
///
/// Physical VMO creation grants direct access to physical memory and is
/// restricted to processes that are direct children of the root job.
/// A proper Resource-handle capability gate should replace this check once
/// the Resource subsystem is implemented.
pub fn create_physical_vmo(
    base_paddr: u64,
    size: u64,
    options: u32,
) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        // Privilege gate: only processes that are direct children of the root
        // job may create physical VMOs.  This is a stop-gap until a full
        // Resource-handle authority is plumbed through the object system.
        // TODO(security): Replace with a proper root-resource handle check.
        let caller_job_id = state.with_core(|kernel| {
            let process = kernel.current_process_info()?;
            kernel.process_job_id(process.process_id())
        })?;
        let root_job_id = state.with_kernel(|kernel| Ok(kernel.root_job_id()))?;
        if caller_job_id != root_job_id {
            return Err(ZX_ERR_ACCESS_DENIED);
        }

        let object_id = state.alloc_object_id();
        let global_vmo_id = state.with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
        let process_id =
            state.with_core(|kernel| Ok(kernel.current_process_info()?.process_id()))?;
        let size_bytes = state
            .with_vm_mut(|vm| vm.create_physical_vmo_global(base_paddr, size, global_vmo_id))?;
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Vmo(VmoObject {
                    creator_process_id: process_id,
                    global_vmo_id,
                    backing_scope: VmoBackingScope::GlobalShared,
                    kind: axle_mm::VmoKind::Physical,
                    size_bytes,
                    image_layout: None,
                }),
            )?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(object_id, handle::vmo_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

/// Create one public contiguous, DMA-capable VMO and return a handle.
pub fn create_contiguous_vmo(size: u64, options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let object_id = state.alloc_object_id();
        let global_vmo_id = state.with_kernel_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
        let process_id =
            state.with_core(|kernel| Ok(kernel.current_process_info()?.process_id()))?;
        let size_bytes =
            state.with_vm_mut(|vm| vm.create_contiguous_vmo_global(size, global_vmo_id))?;
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Vmo(VmoObject {
                    creator_process_id: process_id,
                    global_vmo_id,
                    backing_scope: VmoBackingScope::GlobalShared,
                    kind: axle_mm::VmoKind::Contiguous,
                    size_bytes,
                    image_layout: None,
                }),
            )?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(object_id, handle::vmo_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

fn encode_vmo_kind(kind: axle_mm::VmoKind) -> u32 {
    match kind {
        axle_mm::VmoKind::Anonymous => axle_types::vmo::AX_VMO_KIND_ANONYMOUS,
        axle_mm::VmoKind::Physical => axle_types::vmo::AX_VMO_KIND_PHYSICAL,
        axle_mm::VmoKind::Contiguous => axle_types::vmo::AX_VMO_KIND_CONTIGUOUS,
        axle_mm::VmoKind::PagerBacked => axle_types::vmo::AX_VMO_KIND_PAGER_BACKED,
    }
}

fn encode_vmo_backing_scope(scope: VmoBackingScope) -> u32 {
    match scope {
        VmoBackingScope::LocalPrivate { .. } => axle_types::vmo::AX_VMO_BACKING_SCOPE_LOCAL_PRIVATE,
        VmoBackingScope::GlobalShared => axle_types::vmo::AX_VMO_BACKING_SCOPE_GLOBAL_SHARED,
    }
}

fn encode_vmo_flags(kind: axle_mm::VmoKind) -> u32 {
    let mut flags = 0u32;
    if kind.supports_kernel_read() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_KERNEL_READ;
    }
    if kind.supports_kernel_write() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_KERNEL_WRITE;
    }
    if kind.supports_resize() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_RESIZABLE;
    }
    if kind.supports_copy_on_write() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_COPY_ON_WRITE;
    }
    if kind.supports_page_loan() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_PAGE_LOAN;
    }
    if kind.requires_resident_frames() {
        flags |= axle_types::vmo::AX_VMO_INFO_FLAG_REQUIRES_RESIDENT_FRAMES;
    }
    flags
}

/// Read one narrow public VMO/object-model snapshot.
pub fn vmo_get_info(handle: zx_handle_t) -> Result<axle_types::vmo::ax_vmo_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::Vmo(vmo)) => Ok(axle_types::vmo::ax_vmo_info_t {
                size_bytes: vmo.size_bytes(),
                kind: encode_vmo_kind(vmo.kind()),
                backing_scope: encode_vmo_backing_scope(vmo.backing_scope()),
                flags: encode_vmo_flags(vmo.kind()),
                rights: resolved.rights().bits(),
            }),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

/// Create one object-level private clone from a shared COW-capable source VMO.
pub fn vmo_create_private_clone(handle: zx_handle_t) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::READ)?;
        let source = state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::Vmo(vmo)) => Ok(vmo.clone()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        if !matches!(source.backing_scope(), VmoBackingScope::GlobalShared)
            || !source.kind().supports_copy_on_write()
            || !source.kind().supports_kernel_read()
        {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let size = source.size_bytes();
        let global_vmo_id = state.with_core_mut(|kernel| Ok(kernel.allocate_global_vmo_id()))?;
        let created = match state
            .with_core_mut(|kernel| kernel.create_current_anonymous_vmo(size, global_vmo_id))
        {
            Ok(created) => created,
            Err(status) => return Err(status),
        };
        let object_id = state.alloc_object_id();
        let target_vmo = VmoObject {
            creator_process_id: created.process_id(),
            global_vmo_id: created.global_vmo_id(),
            backing_scope: VmoBackingScope::LocalPrivate {
                owner_address_space_id: created.address_space_id(),
                local_vmo_id: created.vmo_id(),
            },
            kind: axle_mm::VmoKind::Anonymous,
            size_bytes: created.size_bytes(),
            image_layout: None,
        };
        let source_bytes = state.with_core(|kernel| {
            kernel.vm_handle().read_vmo_bytes(
                &source,
                0,
                usize::try_from(size).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            )
        })?;
        state.with_vm_mut(|vm| vm.write_vmo_bytes(&target_vmo, 0, &source_bytes))?;
        state.with_objects_mut(|objects| {
            objects.insert(object_id, KernelObject::Vmo(target_vmo.clone()))?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(object_id, handle::vmo_default_rights()) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

/// Promote one local-private VMO object to the shared/global backing domain.
pub fn vmo_promote_shared(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let object_key = resolved.object_key();
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let promoted = state.with_vm_mut(|vm| vm.promote_vmo_object_to_shared(&vmo))?;
        if !promoted {
            return Ok(());
        }
        state.with_objects_mut(|objects| {
            let Some(KernelObject::Vmo(vmo_object)) = objects.get_mut(object_key) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            vmo_object.backing_scope = VmoBackingScope::GlobalShared;
            Ok(())
        })
    })
}

/// Pin one physical/contiguous VMO range and return a DMA region handle.
pub fn pin_vmo(
    handle: zx_handle_t,
    offset: u64,
    len: u64,
    options: u32,
) -> Result<zx_handle_t, zx_status_t> {
    let allowed =
        axle_types::dma::ZX_DMA_PERM_DEVICE_READ | axle_types::dma::ZX_DMA_PERM_DEVICE_WRITE;
    if (options & !allowed) != 0 || options == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::MAP)?;
        let object_key = resolved.object_key();
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(object_key) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let mut pin = Some(state.with_vm_mut(|vm| vm.pin_vmo_range(&vmo, offset, len))?);
        let region_object_id = state.alloc_object_id();
        let insert_result = state.with_objects_mut(|objects| {
            let region = DmaRegionObject {
                source_vmo_object: object_key,
                source_offset: offset,
                size_bytes: len,
                options,
                pin: pin.take().ok_or(ZX_ERR_BAD_STATE)?,
            };
            objects.insert(region_object_id, KernelObject::DmaRegion(region))?;
            Ok(())
        });
        if let Err(err) = insert_result {
            if let Some(pin) = pin.take() {
                state.with_frames_mut(|frames| pin.release(frames));
            }
            return Err(err);
        }

        match state.alloc_handle_for_object(region_object_id, handle::dma_region_default_rights()) {
            Ok(region_handle) => Ok(region_handle),
            Err(err) => {
                if let Some(KernelObject::DmaRegion(region)) =
                    state.with_objects_mut(|objects| Ok(objects.remove(region_object_id)))?
                {
                    state.with_frames_mut(|frames| region.release(frames));
                }
                Err(err)
            }
        }
    })
}

/// Return the physical address backing one offset inside a pinned DMA region.
pub fn lookup_dma_region_paddr(handle: zx_handle_t, offset: u64) -> Result<u64, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        Ok(
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::DmaRegion(region)) => region.lookup_paddr(offset),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })?,
        )
    })
}

/// Read one metadata snapshot from a pinned DMA region.
pub fn dma_region_get_info(
    handle: zx_handle_t,
) -> Result<axle_types::ax_dma_region_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::DmaRegion(region)) => region.info(),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

/// Read one segment metadata snapshot from a pinned DMA region.
pub fn dma_region_get_segment_info(
    handle: zx_handle_t,
    segment_index: u32,
) -> Result<axle_types::ax_dma_segment_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::DmaRegion(region)) => region.segment_info(segment_index),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })
    })
}

/// Return the device-visible IOVA backing one offset inside a pinned DMA region.
pub fn lookup_dma_region_iova(handle: zx_handle_t, offset: u64) -> Result<u64, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        Ok(
            state.with_objects(|objects| match objects.get(resolved.object_key()) {
                Some(KernelObject::DmaRegion(region)) => region.lookup_iova(offset),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })?,
        )
    })
}

/// Return the physical address backing one physical/contiguous VMO offset.
pub fn lookup_vmo_paddr(handle: zx_handle_t, offset: u64) -> Result<u64, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::READ)?;
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        state.with_vm_mut(|vm| vm.lookup_vmo_paddr(&vmo, offset))
    })
}

/// Read bytes from one VMO into a kernel-owned buffer.
pub fn vmo_read(handle: zx_handle_t, offset: u64, len: usize) -> Result<Vec<u8>, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        require_handle_rights(resolved, crate::task::HandleRights::READ)?;
        state.with_vm_mut(|vm| vm.read_vmo_bytes(&vmo, offset, len))
    })
}

/// Write bytes into one VMO from a kernel-owned buffer.
pub fn vmo_write(handle: zx_handle_t, offset: u64, bytes: &[u8]) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
        state.with_vm_mut(|vm| vm.write_vmo_bytes(&vmo, offset, bytes))
    })
}

/// Resize one VMO.
pub fn vmo_set_size(handle: zx_handle_t, size: u64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let object_id = resolved.object_key();
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(object_id) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
        let resized = state.with_vm_mut(|vm| vm.set_vmo_size(&vmo, size))?;
        state.retire_bootstrap_frames_after_quiescence(
            resized.barrier_address_spaces(),
            resized.retired_frames(),
        )?;
        state.with_objects_mut(|objects| {
            let Some(KernelObject::Vmo(vmo)) = objects.get_mut(object_id) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            vmo.size_bytes = resized.new_size();
            Ok(())
        })?;
        Ok(())
    })
}

/// Allocate one child VMAR from an existing parent VMAR.
#[allow(clippy::too_many_arguments)]
pub fn vmar_allocate(
    parent_vmar_handle: zx_handle_t,
    options: u32,
    offset: u64,
    len: u64,
) -> Result<(zx_handle_t, u64), zx_status_t> {
    let request = vmar_allocate_request_from_options(options, offset)?;

    with_state_mut(|state| {
        let resolved_parent =
            state.lookup_handle(parent_vmar_handle, crate::task::HandleRights::empty())?;
        let parent = state.with_objects(|objects| {
            Ok(match objects.get(resolved_parent.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        require_vmar_control_rights(resolved_parent)?;
        require_vmar_child_mapping_caps(parent.mapping_caps, request.mapping_caps)?;
        if (request.mode == VmarAllocMode::Specific || request.offset_is_upper_limit)
            && !parent.mapping_caps.can_map_specific
        {
            return Err(ZX_ERR_ACCESS_DENIED);
        }

        let cpu_id = crate::arch::apic::this_apic_id() as usize;
        let child = state.with_vm_mut(|vm| {
            vm.allocate_subvmar(
                parent.address_space_id,
                cpu_id,
                parent.vmar_id,
                offset,
                len,
                request.align,
                request.mode,
                request.offset_is_upper_limit,
                request.child_policy,
            )
        })?;
        let object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Vmar(VmarObject {
                    process_id: parent.process_id,
                    address_space_id: parent.address_space_id,
                    vmar_id: child.id(),
                    base: child.base(),
                    len: child.len(),
                    mapping_caps: request.mapping_caps,
                }),
            )?;
            Ok(())
        })?;

        let child_handle =
            match state.alloc_handle_for_object(object_id, handle::vmar_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                    let _ = state
                        .with_vm_mut(|vm| vm.destroy_vmar(parent.address_space_id, child.id()))
                        .map(|_| ());
                    return Err(err);
                }
            };

        Ok((child_handle, child.base()))
    })
}

/// Map a VMO into a VMAR at an exact offset.
#[allow(clippy::too_many_arguments)]
pub fn vmar_map(
    vmar_handle: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo_handle: zx_handle_t,
    vmo_offset: u64,
    len: u64,
) -> Result<u64, zx_status_t> {
    let request = mapping_request_from_options(options, vmar_offset)?;

    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let resolved_vmo = state.lookup_handle(vmo_handle, crate::task::HandleRights::empty())?;
        let vmar = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmar.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let vmo = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmo.object_key()) {
                Some(KernelObject::Vmo(vmo)) => vmo.clone(),
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        require_vm_mapping_rights(resolved_vmar, request.perms, false)?;
        require_vm_mapping_rights(
            resolved_vmo,
            request.perms,
            request.private_clone && vmo.kind.supports_copy_on_write(),
        )?;
        require_vmar_mapping_caps(vmar.mapping_caps, request.perms, request.specific)?;
        if request.cache_policy == axle_mm::MappingCachePolicy::DeviceMmio
            && !matches!(
                vmo.kind,
                axle_mm::VmoKind::Physical | axle_mm::VmoKind::Contiguous
            )
        {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut vmo = vmo;
        if let VmoBackingScope::LocalPrivate {
            owner_address_space_id,
            ..
        } = vmo.backing_scope
            && owner_address_space_id != vmar.address_space_id
        {
            let promoted = state.with_vm_mut(|vm| vm.promote_vmo_object_to_shared(&vmo))?;
            if promoted {
                state.with_objects_mut(|objects| {
                    let Some(KernelObject::Vmo(vmo_object)) =
                        objects.get_mut(resolved_vmo.object_key())
                    else {
                        return Err(ZX_ERR_BAD_STATE);
                    };
                    vmo_object.backing_scope = VmoBackingScope::GlobalShared;
                    Ok(())
                })?;
                vmo.backing_scope = VmoBackingScope::GlobalShared;
            }
        }
        let cpu_id = crate::arch::apic::this_apic_id() as usize;
        let (mapped_addr, tlb_commit) = state.with_vm_mut(|vm| {
            vm.map_vmo_object_into_vmar(
                vmar.address_space_id,
                cpu_id,
                vmar.vmar_id,
                &vmo,
                request.specific.then_some(vmar_offset),
                vmo_offset,
                len,
                request.perms,
                request.cache_policy,
                request.private_clone,
                request.clone_policy,
            )
        })?;
        state.apply_tlb_commit_reqs(&[tlb_commit])?;
        Ok(mapped_addr)
    })
}

/// Destroy one child VMAR and recursively unmap mappings inside it.
pub fn vmar_destroy(vmar_handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmar.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        require_vmar_control_rights(resolved_vmar)?;
        let tlb_commit =
            state.with_vm_mut(|vm| vm.destroy_vmar(vmar.address_space_id, vmar.vmar_id))?;
        state.apply_tlb_commit_reqs(&[tlb_commit])?;
        let _ = state.begin_logical_destroy(resolved_vmar.object_key())?;
        state.finish_logical_destroy(resolved_vmar.object_key());
        Ok(())
    })
}

/// Unmap a previously installed VMAR range.
pub fn vmar_unmap(vmar_handle: zx_handle_t, addr: u64, len: u64) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmar.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let _ = (vmar.process_id, vmar.base, vmar.len);
        require_handle_rights(resolved_vmar, crate::task::HandleRights::WRITE)?;
        let tlb_commit = state
            .with_vm_mut(|vm| vm.unmap_vmar(vmar.address_space_id, vmar.vmar_id, addr, len))?;
        state.apply_tlb_commit_reqs(&[tlb_commit])
    })
}

/// Change permissions on an existing VMAR range.
pub fn vmar_protect(
    vmar_handle: zx_handle_t,
    options: u32,
    addr: u64,
    len: u64,
) -> Result<(), zx_status_t> {
    let perms = mapping_perms_from_options(options, false)?;

    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmar.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;
        let _ = (vmar.process_id, vmar.base, vmar.len);
        require_vm_mapping_rights(resolved_vmar, perms, false)?;
        require_vmar_mapping_caps(vmar.mapping_caps, perms, false)?;
        let tlb_commit = state.with_vm_mut(|vm| {
            vm.protect_vmar(vmar.address_space_id, vmar.vmar_id, addr, len, perms)
        })?;
        state.apply_tlb_commit_reqs(&[tlb_commit])
    })
}

/// Clone all child-visible mappings from one VMAR into another.
pub fn vmar_clone_mappings(
    src_vmar_handle: zx_handle_t,
    dst_vmar_handle: zx_handle_t,
) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved_src =
            state.lookup_handle(src_vmar_handle, crate::task::HandleRights::empty())?;
        let resolved_dst =
            state.lookup_handle(dst_vmar_handle, crate::task::HandleRights::empty())?;
        let (src_vmar, dst_vmar) = state.with_objects(|objects| {
            let src = match objects.get(resolved_src.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            let dst = match objects.get(resolved_dst.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            Ok((src, dst))
        })?;

        require_vmar_control_rights(resolved_src)?;
        require_vmar_control_rights(resolved_dst)?;

        let tlb_commits = state.with_vm_mut(|vm| {
            vm.clone_vmar_mappings(
                src_vmar.address_space_id,
                src_vmar.vmar_id,
                dst_vmar.address_space_id,
                dst_vmar.vmar_id,
            )
        })?;
        state.apply_tlb_commit_reqs(&tlb_commits)
    })
}

/// Reify the current backing VMO of one child-visible mapping inside a VMAR.
pub fn vmar_get_mapping_vmo(
    vmar_handle: zx_handle_t,
    addr: u64,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved_vmar = state.lookup_handle(vmar_handle, crate::task::HandleRights::empty())?;
        let vmar = state.with_objects(|objects| {
            Ok(match objects.get(resolved_vmar.object_key()) {
                Some(KernelObject::Vmar(vmar)) => *vmar,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            })
        })?;

        require_vmar_control_rights(resolved_vmar)?;

        let (lookup, mapping_vmo) = state
            .with_vm_mut(|vm| Ok(vm.snapshot_mapping_vmo(vmar.address_space_id, addr, 1)))
            .and_then(|snapshot| snapshot.ok_or(ZX_ERR_NOT_FOUND))?;
        if lookup.vmar_id() != vmar.vmar_id {
            return Err(ZX_ERR_NOT_FOUND);
        }

        let process_id =
            state.with_core(|kernel| Ok(kernel.current_process_info()?.process_id()))?;
        let object_id = state.alloc_object_id();
        let backing_scope = if lookup.is_global_backed() {
            VmoBackingScope::GlobalShared
        } else {
            VmoBackingScope::LocalPrivate {
                owner_address_space_id: lookup.address_space_id().raw(),
                local_vmo_id: lookup.vmo_id(),
            }
        };
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::Vmo(VmoObject {
                    creator_process_id: process_id,
                    global_vmo_id: lookup.global_vmo_id(),
                    backing_scope,
                    kind: mapping_vmo.kind(),
                    size_bytes: mapping_vmo.size_bytes(),
                    image_layout: None,
                }),
            )?;
            Ok(())
        })?;

        match state.alloc_handle_for_object(
            object_id,
            mapping_vmo_capture_rights(lookup.perms(), mapping_vmo.kind()),
        ) {
            Ok(handle) => Ok(handle),
            Err(err) => {
                let _ = state.with_objects_mut(|objects| Ok(objects.remove(object_id)));
                Err(err)
            }
        }
    })
}

pub(super) fn root_vmar_mapping_caps() -> VmarMappingCaps {
    VmarMappingCaps {
        max_perms: MappingPerms::READ
            | MappingPerms::WRITE
            | MappingPerms::EXECUTE
            | MappingPerms::USER,
        can_map_specific: true,
    }
}

fn require_vm_mapping_rights(
    resolved: crate::task::ResolvedHandle,
    perms: MappingPerms,
    private_clone: bool,
) -> Result<(), zx_status_t> {
    require_handle_rights(resolved, crate::task::HandleRights::MAP)?;
    require_handle_rights(resolved, crate::task::HandleRights::READ)?;
    if perms.contains(MappingPerms::WRITE) && !private_clone {
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;
    }
    if perms.contains(MappingPerms::EXECUTE) {
        require_handle_rights(resolved, crate::task::HandleRights::EXECUTE)?;
    }
    Ok(())
}

fn require_vmar_control_rights(resolved: crate::task::ResolvedHandle) -> Result<(), zx_status_t> {
    require_handle_rights(resolved, crate::task::HandleRights::MAP)?;
    require_handle_rights(resolved, crate::task::HandleRights::WRITE)
}

fn mapping_vmo_capture_rights(
    perms: MappingPerms,
    kind: axle_mm::VmoKind,
) -> crate::task::HandleRights {
    let mut rights = crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MAP;
    if kind.supports_kernel_read() {
        rights |= crate::task::HandleRights::READ;
    }
    if perms.contains(MappingPerms::WRITE) && kind.supports_kernel_write() {
        rights |= crate::task::HandleRights::WRITE;
    }
    if perms.contains(MappingPerms::EXECUTE) {
        rights |= crate::task::HandleRights::EXECUTE;
    }
    rights
}

fn require_vmar_mapping_caps(
    caps: VmarMappingCaps,
    perms: MappingPerms,
    require_specific: bool,
) -> Result<(), zx_status_t> {
    if !caps.max_perms.contains(perms) {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    if require_specific && !caps.can_map_specific {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    Ok(())
}

fn require_vmar_child_mapping_caps(
    parent: VmarMappingCaps,
    requested: VmarMappingCaps,
) -> Result<(), zx_status_t> {
    if !parent.max_perms.contains(requested.max_perms) {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    if requested.can_map_specific && !parent.can_map_specific {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    Ok(())
}

fn mapping_request_from_options(
    options: u32,
    vmar_offset: u64,
) -> Result<VmarMappingRequest, zx_status_t> {
    let allowed = ZX_VM_PERM_READ
        | ZX_VM_PERM_WRITE
        | ZX_VM_PERM_EXECUTE
        | ZX_VM_MAP_MMIO
        | ZX_VM_CLONE_COW
        | ZX_VM_CLONE_SHARE
        | ZX_VM_PRIVATE_CLONE
        | ZX_VM_SPECIFIC;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let specific = (options & ZX_VM_SPECIFIC) != 0;
    let private_clone = (options & ZX_VM_PRIVATE_CLONE) != 0;
    let clone_cow = (options & ZX_VM_CLONE_COW) != 0;
    let clone_share = (options & ZX_VM_CLONE_SHARE) != 0;
    let cache_policy = if (options & ZX_VM_MAP_MMIO) != 0 {
        axle_mm::MappingCachePolicy::DeviceMmio
    } else {
        axle_mm::MappingCachePolicy::Cached
    };
    if !specific && vmar_offset != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let has_read = (options & ZX_VM_PERM_READ) != 0;
    let has_write = (options & ZX_VM_PERM_WRITE) != 0;
    let has_execute = (options & ZX_VM_PERM_EXECUTE) != 0;
    if !has_read {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if clone_cow && clone_share {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if private_clone && !has_write {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if clone_cow && !has_write {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if cache_policy == axle_mm::MappingCachePolicy::DeviceMmio
        && (private_clone || clone_cow || clone_share || has_execute)
    {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let clone_policy = if private_clone || clone_cow {
        axle_mm::MappingClonePolicy::PrivateCow
    } else if clone_share {
        axle_mm::MappingClonePolicy::SharedAlias
    } else {
        axle_mm::MappingClonePolicy::None
    };

    let mut perms = MappingPerms::READ | MappingPerms::USER;
    if has_write {
        perms |= MappingPerms::WRITE;
    }
    if has_execute {
        perms |= MappingPerms::EXECUTE;
    }
    Ok(VmarMappingRequest {
        perms,
        cache_policy,
        clone_policy,
        specific,
        private_clone,
    })
}

fn mapping_perms_from_options(
    options: u32,
    require_specific: bool,
) -> Result<MappingPerms, zx_status_t> {
    if (options & ZX_VM_MAP_MMIO) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !require_specific && (options & ZX_VM_SPECIFIC) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let request = mapping_request_from_options(options, if require_specific { 1 } else { 0 })?;
    if require_specific && !request.specific {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(request.perms)
}

fn vmar_mapping_caps_from_allocate_options(options: u32) -> Result<VmarMappingCaps, zx_status_t> {
    let allowed =
        ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_EXECUTE | ZX_VM_CAN_MAP_SPECIFIC;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let mut max_perms = MappingPerms::USER;
    if (options & ZX_VM_CAN_MAP_READ) != 0 {
        max_perms |= MappingPerms::READ;
    }
    if (options & ZX_VM_CAN_MAP_WRITE) != 0 {
        max_perms |= MappingPerms::WRITE;
    }
    if (options & ZX_VM_CAN_MAP_EXECUTE) != 0 {
        max_perms |= MappingPerms::EXECUTE;
    }

    Ok(VmarMappingCaps {
        max_perms,
        can_map_specific: (options & ZX_VM_CAN_MAP_SPECIFIC) != 0,
    })
}

fn vmar_allocate_request_from_options(
    options: u32,
    offset: u64,
) -> Result<VmarAllocateRequest, zx_status_t> {
    let align = vmar_allocate_align_from_options(options)?;
    let allowed = ZX_VM_CAN_MAP_READ
        | ZX_VM_CAN_MAP_WRITE
        | ZX_VM_CAN_MAP_EXECUTE
        | ZX_VM_CAN_MAP_SPECIFIC
        | ZX_VM_SPECIFIC
        | ZX_VM_OFFSET_IS_UPPER_LIMIT
        | ZX_VM_COMPACT
        | ZX_VM_ALIGN_MASK;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let specific = (options & ZX_VM_SPECIFIC) != 0;
    let offset_is_upper_limit = (options & ZX_VM_OFFSET_IS_UPPER_LIMIT) != 0;
    let compact = (options & ZX_VM_COMPACT) != 0;
    if specific && offset_is_upper_limit {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !specific && !offset_is_upper_limit && offset != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(VmarAllocateRequest {
        mapping_caps: vmar_mapping_caps_from_allocate_options(
            options
                & !(ZX_VM_SPECIFIC
                    | ZX_VM_OFFSET_IS_UPPER_LIMIT
                    | ZX_VM_COMPACT
                    | ZX_VM_ALIGN_MASK),
        )?,
        align,
        mode: if specific {
            VmarAllocMode::Specific
        } else {
            VmarAllocMode::Randomized
        },
        offset_is_upper_limit,
        child_policy: if compact {
            VmarPlacementPolicy::Compact
        } else {
            VmarPlacementPolicy::Randomized
        },
    })
}

fn vmar_allocate_align_from_options(options: u32) -> Result<u64, zx_status_t> {
    let encoded = (options & ZX_VM_ALIGN_MASK) >> ZX_VM_ALIGN_BASE;
    if encoded == 0 {
        return Ok(axle_mm::PAGE_SIZE);
    }
    let align = 1_u64.checked_shl(encoded).ok_or(ZX_ERR_INVALID_ARGS)?;
    Ok(core::cmp::max(axle_mm::PAGE_SIZE, align))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_request_allows_execute_permissions() {
        let request = mapping_request_from_options(ZX_VM_PERM_READ | ZX_VM_PERM_EXECUTE, 0)
            .expect("read+execute mapping request should decode");

        assert_eq!(
            request.perms,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER
        );
        assert!(!request.specific);
        assert!(!request.private_clone);
    }

    #[test]
    fn mapping_request_decodes_private_clone() {
        let request = mapping_request_from_options(
            ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | ZX_VM_PRIVATE_CLONE,
            0,
        )
        .expect("private-clone mapping request should decode");

        assert_eq!(
            request.perms,
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER
        );
        assert!(request.private_clone);
    }

    #[test]
    fn private_clone_requires_write_permission() {
        assert!(matches!(
            mapping_request_from_options(ZX_VM_PERM_READ | ZX_VM_PRIVATE_CLONE, 0),
            Err(ZX_ERR_INVALID_ARGS)
        ));
    }

    #[test]
    fn protect_decode_preserves_execute_permissions() {
        let perms = mapping_perms_from_options(ZX_VM_PERM_READ | ZX_VM_PERM_EXECUTE, false)
            .expect("protect decode should keep execute");

        assert_eq!(
            perms,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER
        );
    }

    #[test]
    fn child_vmar_caps_allow_execute() {
        let caps = vmar_mapping_caps_from_allocate_options(
            ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_EXECUTE | ZX_VM_CAN_MAP_SPECIFIC,
        )
        .expect("execute child caps should decode");

        assert_eq!(
            caps.max_perms,
            MappingPerms::READ | MappingPerms::EXECUTE | MappingPerms::USER
        );
        assert!(caps.can_map_specific);
    }

    #[test]
    fn execute_without_read_remains_invalid() {
        assert!(matches!(
            mapping_request_from_options(ZX_VM_PERM_EXECUTE, 0),
            Err(ZX_ERR_INVALID_ARGS)
        ));
    }
}
