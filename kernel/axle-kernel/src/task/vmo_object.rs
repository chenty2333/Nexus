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
