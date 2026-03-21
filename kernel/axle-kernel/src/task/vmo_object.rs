use super::*;

impl VmDomain {
    pub(super) fn register_global_vmo_from_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        let snapshot = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.snapshot_vmo(global_vmo_id))
            .ok_or(ZX_ERR_BAD_STATE)?;
        self.global_vmos
            .lock()
            .register_snapshot(global_vmo_id, &snapshot)?;
        Ok(())
    }

    pub(super) fn register_empty_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_empty(global_vmo_id, kind, size_bytes)
    }

    pub(super) fn register_pager_backed_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        bytes: &'static [u8],
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_pager_read_only(global_vmo_id, bytes)
    }

    pub(super) fn register_pager_file_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
    ) -> Result<(), zx_status_t> {
        self.register_pager_source_handle(
            global_vmo_id,
            PagerSourceHandle::new(FilePagerSource {
                size_bytes,
                read_at,
            }),
        )
    }

    pub(super) fn register_pager_source_handle(
        &mut self,
        global_vmo_id: KernelVmoId,
        source: PagerSourceHandle,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .register_pager_source(global_vmo_id, source)
    }

    pub(super) fn bootstrap_user_runner_global_vmo_id(&self) -> Option<KernelVmoId> {
        self.bootstrap_user_runner_global_vmo_id
    }

    pub(super) fn import_global_vmo_into_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, zx_status_t> {
        let global_vmo = self.global_vmos.lock().snapshot(global_vmo_id)?;
        let address_space = self
            .address_spaces
            .get_mut(&address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let local_vmo_id = address_space
            .import_vmo_alias(global_vmo.kind(), global_vmo.size_bytes(), global_vmo_id)
            .map_err(map_address_space_error)?;
        for (page_index, frame_id) in global_vmo.frames().iter().copied().enumerate() {
            let Some(frame_id) = frame_id else {
                continue;
            };
            address_space
                .set_vmo_frame(
                    local_vmo_id,
                    (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                    frame_id,
                )
                .map_err(map_address_space_error)?;
        }
        Ok(local_vmo_id)
    }

    pub(super) fn promote_local_vmo_to_shared(
        &mut self,
        owner_address_space_id: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        self.register_global_vmo_from_address_space(owner_address_space_id, global_vmo_id)?;
        let (kind, size_bytes) = self
            .address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.snapshot_vmo(global_vmo_id))
            .map(|snapshot| (snapshot.kind(), snapshot.size_bytes()))
            .ok_or(ZX_ERR_BAD_STATE)?;
        let address_space = self
            .address_spaces
            .get_mut(&owner_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let _ = address_space
            .import_vmo_alias(kind, size_bytes, global_vmo_id)
            .map_err(map_address_space_error)?;
        Ok(())
    }

    pub(super) fn ensure_vmo_backing_for_mapping(
        &mut self,
        target_address_space_id: AddressSpaceId,
        vmo: &crate::object::VmoObject,
    ) -> Result<VmoId, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } if owner_address_space_id == target_address_space_id => Ok(local_vmo_id),
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                ..
            } => {
                self.promote_local_vmo_to_shared(owner_address_space_id, vmo.global_vmo_id())?;
                self.import_global_vmo_into_address_space(
                    target_address_space_id,
                    vmo.global_vmo_id(),
                )
            }
            crate::object::VmoBackingScope::GlobalShared => self
                .import_global_vmo_into_address_space(target_address_space_id, vmo.global_vmo_id()),
        }
    }

    pub(super) fn create_private_clone_local_vmo_for_mapping(
        &mut self,
        target_address_space_id: AddressSpaceId,
        vmo: &crate::object::VmoObject,
    ) -> Result<VmoId, zx_status_t> {
        if !matches!(
            vmo.backing_scope(),
            crate::object::VmoBackingScope::GlobalShared
        ) || !vmo.kind().supports_copy_on_write()
        {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let _ = self.ensure_vmo_backing_for_mapping(target_address_space_id, vmo)?;
        let global_vmo = self.global_vmos.lock().snapshot(vmo.global_vmo_id())?;
        let address_space = self
            .address_spaces
            .get_mut(&target_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        address_space
            .create_private_clone_vmo(
                global_vmo.kind(),
                global_vmo.size_bytes(),
                vmo.global_vmo_id(),
                global_vmo.frames(),
            )
            .map_err(map_address_space_error)
    }

    pub(super) fn promote_vmo_object_to_shared(
        &mut self,
        vmo: &crate::object::VmoObject,
    ) -> Result<bool, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                ..
            } => {
                self.promote_local_vmo_to_shared(owner_address_space_id, vmo.global_vmo_id())?;
                Ok(true)
            }
            crate::object::VmoBackingScope::GlobalShared => Ok(false),
        }
    }

    pub(super) fn update_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        self.global_vmos
            .lock()
            .update_frame(global_vmo_id, offset, frame_id)
    }

    pub(super) fn global_vmo_frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        self.global_vmos.lock().frame(global_vmo_id, offset)
    }

    pub(super) fn create_anonymous_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let local_vmo_id =
            self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                address_space
                    .create_anonymous_vmo(frames, size, global_vmo_id)
                    .map(|vmo| vmo.id())
                    .map_err(map_address_space_error)
            })?;
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
        })
    }

    pub(super) fn create_physical_vmo_global(
        &mut self,
        base_paddr: u64,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<u64, zx_status_t> {
        if base_paddr == 0
            || (base_paddr & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
            || size == 0
            || (size & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
        {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        self.register_empty_global_vmo(global_vmo_id, VmoKind::Physical, size)?;

        let created = {
            let mut frames = self.frames.lock();
            let mut global_vmos = self.global_vmos.lock();
            let page_count = usize::try_from(size / crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            for page_index in 0..page_count {
                let paddr = base_paddr + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
                let frame_id = if frames.contains(FrameId::from_raw(paddr).ok_or(ZX_ERR_BAD_STATE)?)
                {
                    FrameId::from_raw(paddr).ok_or(ZX_ERR_BAD_STATE)?
                } else {
                    frames
                        .register_existing(paddr)
                        .map_err(map_frame_table_error)?
                };
                global_vmos.update_frame(
                    global_vmo_id,
                    (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                    frame_id,
                )?;
            }
            Ok(())
        };

        if let Err(status) = created {
            let _ = self.global_vmos.lock().remove(global_vmo_id);
            return Err(status);
        }
        Ok(size)
    }

    pub(super) fn create_contiguous_vmo_global(
        &mut self,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<u64, zx_status_t> {
        if size == 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_size = crate::userspace::USER_PAGE_BYTES;
        let rounded_size = size
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let page_count =
            usize::try_from(rounded_size / page_size).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        self.register_empty_global_vmo(global_vmo_id, VmoKind::Contiguous, rounded_size)?;

        let Some(base_paddr) = crate::userspace::alloc_bootstrap_zeroed_pages(page_count) else {
            let _ = self.global_vmos.lock().remove(global_vmo_id);
            return Err(ZX_ERR_NO_MEMORY);
        };

        let created = {
            let mut frames = self.frames.lock();
            let mut global_vmos = self.global_vmos.lock();
            for page_index in 0..page_count {
                let paddr = base_paddr + (page_index as u64) * page_size;
                let frame_id = frames
                    .register_existing(paddr)
                    .map_err(map_frame_table_error)?;
                global_vmos.update_frame(
                    global_vmo_id,
                    (page_index as u64) * page_size,
                    frame_id,
                )?;
            }
            Ok(())
        };

        if let Err(status) = created {
            let _ = self.global_vmos.lock().remove(global_vmo_id);
            crate::userspace::free_bootstrap_pages(base_paddr, page_count);
            return Err(status);
        }
        Ok(rounded_size)
    }

    pub(super) fn create_pager_backed_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        bytes: &'static [u8],
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.register_pager_backed_global_vmo(global_vmo_id, bytes)?;
        let local_vmo_id =
            match self.import_global_vmo_into_address_space(address_space_id, global_vmo_id) {
                Ok(vmo_id) => vmo_id,
                Err(err) => {
                    let _ = self.global_vmos.lock().remove(global_vmo_id);
                    return Err(err);
                }
            };
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
        })
    }

    pub(super) fn create_pager_file_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        self.register_pager_file_global_vmo(global_vmo_id, size_bytes, read_at)?;
        let local_vmo_id =
            match self.import_global_vmo_into_address_space(address_space_id, global_vmo_id) {
                Ok(vmo_id) => vmo_id,
                Err(err) => {
                    let _ = self.global_vmos.lock().remove(global_vmo_id);
                    return Err(err);
                }
            };
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
        })
    }

    pub(super) fn import_bootstrap_user_runner_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let global_vmo_id = self
            .bootstrap_user_runner_global_vmo_id
            .ok_or(ZX_ERR_NOT_FOUND)?;
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
        })
    }

    pub(super) fn import_bootstrap_user_code_vmo_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let global_vmo_id = self
            .bootstrap_user_code_global_vmo_id
            .ok_or(ZX_ERR_NOT_FOUND)?;
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
        let vmo = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(CreatedVmo {
            process_id,
            address_space_id,
            vmo,
        })
    }

    pub(super) fn import_bootstrap_process_image_for_address_space(
        &mut self,
        process_id: ProcessId,
        address_space_id: AddressSpaceId,
    ) -> Result<ImportedProcessImage, zx_status_t> {
        let code_vmo =
            self.import_bootstrap_user_code_vmo_for_address_space(process_id, address_space_id)?;
        Ok(ImportedProcessImage {
            code_vmo,
            layout: crate::userspace::bootstrap_process_image_layout()
                .unwrap_or_else(ProcessImageLayout::bootstrap_conformance),
        })
    }
}

impl AddressSpace {
    pub(super) fn create_anonymous_vmo(
        &mut self,
        _frames: &mut FrameTable,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<Vmo, AddressSpaceError> {
        let vmo_id = self
            .vm
            .create_vmo(VmoKind::Anonymous, size, global_vmo_id)?;
        self.vm
            .vmo(vmo_id)
            .cloned()
            .ok_or(AddressSpaceError::InvalidVmo)
    }

    pub(super) fn import_vmo_alias(
        &mut self,
        kind: VmoKind,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, AddressSpaceError> {
        self.vm.import_vmo(kind, size, global_vmo_id)
    }

    pub(super) fn local_vmo_id(&self, global_vmo_id: KernelVmoId) -> Option<VmoId> {
        self.vm.vmo_id_by_global_id(global_vmo_id)
    }

    pub(super) fn validate_vmo_resize(
        &self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<(), AddressSpaceError> {
        let Some(vmo_id) = self.local_vmo_id(global_vmo_id) else {
            return Ok(());
        };
        self.vm.validate_vmo_resize(vmo_id, new_size)
    }

    pub(super) fn resize_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<Vec<FrameId>, AddressSpaceError> {
        let Some(vmo_id) = self.local_vmo_id(global_vmo_id) else {
            return Ok(Vec::new());
        };
        self.vm.resize_vmo(vmo_id, new_size)
    }

    pub(super) fn set_vmo_frame(
        &mut self,
        vmo_id: VmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), AddressSpaceError> {
        self.vm.set_vmo_frame(vmo_id, offset, frame_id)
    }

    pub(super) fn create_private_clone_vmo(
        &mut self,
        kind: VmoKind,
        size: u64,
        global_vmo_id: KernelVmoId,
        frames: &[Option<FrameId>],
    ) -> Result<VmoId, AddressSpaceError> {
        let vmo_id = self.vm.create_vmo(kind, size, global_vmo_id)?;
        for (page_index, frame_id) in frames.iter().copied().enumerate() {
            let Some(frame_id) = frame_id else {
                continue;
            };
            self.vm.set_vmo_frame(
                vmo_id,
                (page_index as u64) * crate::userspace::USER_PAGE_BYTES,
                frame_id,
            )?;
        }
        if !self.private_clone_vmos.contains(&vmo_id) {
            self.private_clone_vmos.push(vmo_id);
        }
        Ok(vmo_id)
    }

    pub(super) fn reclaim_unmapped_private_clone_vmos(&mut self) {
        let tracked = self.private_clone_vmos.clone();
        for vmo_id in tracked {
            match self.vm.remove_vmo_if_unmapped(vmo_id) {
                Ok(true) => {
                    self.private_clone_vmos
                        .retain(|candidate| *candidate != vmo_id);
                }
                Ok(false) | Err(_) => {}
            }
        }
    }

    pub(super) fn mapped_ranges_for_global_vmo(
        &self,
        global_vmo_id: KernelVmoId,
    ) -> Vec<(u64, u64)> {
        self.vm.mapped_ranges_for_global_vmo(global_vmo_id)
    }

    pub(super) fn imports_global_vmo(&self, global_vmo_id: KernelVmoId) -> bool {
        self.local_vmo_id(global_vmo_id).is_some()
    }
}

impl Kernel {
    pub(crate) fn create_kernel_vmo_backing(
        &mut self,
        size_bytes: u64,
    ) -> Result<KernelVmoBacking, zx_status_t> {
        if size_bytes == 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_size = crate::userspace::USER_PAGE_BYTES;
        let rounded_size = size_bytes
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let page_count =
            usize::try_from(rounded_size / page_size).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let global_vmo_id = self.allocate_global_vmo_id();
        self.register_empty_global_vmo(global_vmo_id, VmoKind::Anonymous, rounded_size)?;

        let Some(base_paddr) = crate::userspace::alloc_bootstrap_zeroed_pages(page_count) else {
            let _ = self.with_vm_mut(|vm| vm.global_vmos.lock().remove(global_vmo_id));
            return Err(ZX_ERR_NO_MEMORY);
        };

        let created = self.with_vm_mut(|vm| {
            let mut frames = vm.frames.lock();
            let mut global_vmos = vm.global_vmos.lock();
            let mut frame_ids = Vec::with_capacity(page_count);
            for page_index in 0..page_count {
                let paddr = base_paddr + (page_index as u64) * page_size;
                let frame_id = frames.register_existing(paddr).map_err(|err| match err {
                    axle_mm::FrameTableError::InvalidArgs => ZX_ERR_INVALID_ARGS,
                    axle_mm::FrameTableError::AlreadyExists => ZX_ERR_ALREADY_EXISTS,
                    axle_mm::FrameTableError::NotFound
                    | axle_mm::FrameTableError::CountOverflow
                    | axle_mm::FrameTableError::RefUnderflow
                    | axle_mm::FrameTableError::PinUnderflow
                    | axle_mm::FrameTableError::LoanUnderflow
                    | axle_mm::FrameTableError::MissingAnchor
                    | axle_mm::FrameTableError::Busy => ZX_ERR_BAD_STATE,
                })?;
                if let Err(status) = global_vmos.update_frame(
                    global_vmo_id,
                    (page_index as u64) * page_size,
                    frame_id,
                ) {
                    let _ = frames.unregister_existing(frame_id);
                    return Err(status);
                }
                frame_ids.push(frame_id);
            }
            Ok(frame_ids)
        });

        let frame_ids = match created {
            Ok(frame_ids) => frame_ids,
            Err(status) => {
                let _ = self.destroy_kernel_vmo_backing(KernelVmoBacking {
                    global_vmo_id,
                    base_paddr,
                    page_count,
                    frame_ids: Vec::new(),
                    size_bytes: rounded_size,
                });
                return Err(status);
            }
        };

        Ok(KernelVmoBacking {
            global_vmo_id,
            base_paddr,
            page_count,
            frame_ids,
            size_bytes: rounded_size,
        })
    }

    pub(crate) fn destroy_kernel_vmo_backing(
        &mut self,
        backing: KernelVmoBacking,
    ) -> Result<(), zx_status_t> {
        let retire_plan =
            self.with_vm(|vm| vm.build_required_frame_retire_plan(backing.frame_ids(), &[]))?;
        let _ = self.with_vm_mut(|vm| vm.global_vmos.lock().remove(backing.global_vmo_id()));
        self.retire_bootstrap_frames_after_quiescence_current(
            retire_plan.barrier_address_spaces(),
            retire_plan.retired_frames(),
        )?;
        Ok(())
    }

    pub(super) fn register_global_vmo_from_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| {
            vm.register_global_vmo_from_address_space(address_space_id, global_vmo_id)
        })
    }

    pub(super) fn register_empty_global_vmo(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.register_empty_global_vmo(global_vmo_id, kind, size_bytes))
    }

    pub(super) fn import_global_vmo_into_address_space(
        &mut self,
        address_space_id: AddressSpaceId,
        global_vmo_id: KernelVmoId,
    ) -> Result<VmoId, zx_status_t> {
        self.with_vm_mut(|vm| {
            vm.import_global_vmo_into_address_space(address_space_id, global_vmo_id)
        })
    }

    pub(super) fn update_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        self.with_vm_mut(|vm| vm.update_global_vmo_frame(global_vmo_id, offset, frame_id))
    }

    pub(super) fn global_vmo_frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        self.with_vm(|vm| vm.global_vmo_frame(global_vmo_id, offset))
    }

    pub(crate) fn create_current_anonymous_vmo(
        &mut self,
        size: u64,
        global_vmo_id: KernelVmoId,
    ) -> Result<CreatedVmo, zx_status_t> {
        let process_id = self.current_thread()?.process_id;
        let address_space_id = self.current_process()?.address_space_id;
        self.with_vm_mut(|vm| {
            vm.create_anonymous_vmo_for_address_space(
                process_id,
                address_space_id,
                size,
                global_vmo_id,
            )
        })
    }
}

impl VmDomain {
    pub(super) fn map_existing_local_vmo_fixed(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        local_vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
    ) -> Result<(), zx_status_t> {
        self.map_existing_local_vmo_fixed_with_clone_policy(
            address_space_id,
            vmar_id,
            base,
            len,
            local_vmo_id,
            vmo_offset,
            perms,
            perms,
            MappingClonePolicy::None,
        )
    }

    pub(super) fn map_existing_local_vmo_fixed_with_clone_policy(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        local_vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        clone_policy: MappingClonePolicy,
    ) -> Result<(), zx_status_t> {
        self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
            address_space
                .map_vmo_fixed_with_max_perms_and_mapping_policy(
                    frames,
                    vmar_id,
                    base,
                    len,
                    local_vmo_id,
                    vmo_offset,
                    perms,
                    max_perms,
                    MappingCachePolicy::Cached,
                    clone_policy,
                )
                .map_err(map_address_space_error)
        })?;
        self.install_mapping_pages(address_space_id, base, len)?;
        Ok(())
    }

    pub(crate) fn map_vmo_into_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        vmar_id: VmarId,
        global_vmo_id: KernelVmoId,
        fixed_vmar_offset: Option<u64>,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
        clone_policy: MappingClonePolicy,
    ) -> Result<(u64, TlbCommitReq), zx_status_t> {
        let local_vmo_id =
            self.import_global_vmo_into_address_space(address_space_id, global_vmo_id)?;
        let frames_handle = self.frame_table();
        let mapped_addr = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match fixed_vmar_offset {
                Some(vmar_offset) => {
                    let vmar = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mapped_addr = vmar
                        .base()
                        .checked_add(vmar_offset)
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
                    {
                        let mut frames = frames_handle.lock();
                        address_space
                            .map_vmo_fixed_with_mapping_policy(
                                &mut frames,
                                vmar_id,
                                mapped_addr,
                                len,
                                local_vmo_id,
                                vmo_offset,
                                perms,
                                MappingCachePolicy::Cached,
                                clone_policy,
                            )
                            .map_err(map_address_space_error)?;
                    }
                    mapped_addr
                }
                None => {
                    let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mut frames = frames_handle.lock();
                    address_space
                        .map_vmo_anywhere_with_mapping_policy(
                            &mut frames,
                            cpu_id,
                            vmar_id,
                            len,
                            local_vmo_id,
                            vmo_offset,
                            perms,
                            MappingCachePolicy::Cached,
                            clone_policy,
                        )
                        .map_err(map_address_space_error)?
                }
            }
        };
        self.install_mapping_pages(address_space_id, mapped_addr, len)?;
        Ok((
            mapped_addr,
            if perms.contains(MappingPerms::EXECUTE) {
                TlbCommitReq::strict(address_space_id)
            } else {
                TlbCommitReq::relaxed(address_space_id)
            },
        ))
    }

    pub(crate) fn map_vmo_object_into_vmar(
        &mut self,
        address_space_id: AddressSpaceId,
        cpu_id: usize,
        vmar_id: VmarId,
        vmo: &crate::object::VmoObject,
        fixed_vmar_offset: Option<u64>,
        vmo_offset: u64,
        len: u64,
        perms: MappingPerms,
        cache_policy: MappingCachePolicy,
        private_clone: bool,
        clone_policy: MappingClonePolicy,
    ) -> Result<(u64, TlbCommitReq), zx_status_t> {
        let local_vmo_id = if private_clone {
            self.create_private_clone_local_vmo_for_mapping(address_space_id, vmo)?
        } else {
            self.ensure_vmo_backing_for_mapping(address_space_id, vmo)?
        };
        let frames_handle = self.frame_table();
        let mapped_addr = {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match fixed_vmar_offset {
                Some(vmar_offset) => {
                    let vmar = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mapped_addr = vmar
                        .base()
                        .checked_add(vmar_offset)
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
                    {
                        let mut frames = frames_handle.lock();
                        address_space
                            .map_vmo_fixed_with_mapping_policy(
                                &mut frames,
                                vmar_id,
                                mapped_addr,
                                len,
                                local_vmo_id,
                                vmo_offset,
                                perms,
                                cache_policy,
                                clone_policy,
                            )
                            .map_err(map_address_space_error)?;
                    }
                    mapped_addr
                }
                None => {
                    let _ = address_space.vmar(vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
                    let mut frames = frames_handle.lock();
                    address_space
                        .map_vmo_anywhere_with_mapping_policy(
                            &mut frames,
                            cpu_id,
                            vmar_id,
                            len,
                            local_vmo_id,
                            vmo_offset,
                            perms,
                            cache_policy,
                            clone_policy,
                        )
                        .map_err(map_address_space_error)?
                }
            }
        };
        if private_clone {
            let address_space = self
                .address_spaces
                .get_mut(&address_space_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            address_space
                .arm_copy_on_write(mapped_addr, len)
                .map_err(map_address_space_error)?;
        }
        self.install_mapping_pages(address_space_id, mapped_addr, len)?;
        Ok((
            mapped_addr,
            if perms.contains(MappingPerms::EXECUTE) {
                TlbCommitReq::strict(address_space_id)
            } else {
                TlbCommitReq::relaxed(address_space_id)
            },
        ))
    }
}
