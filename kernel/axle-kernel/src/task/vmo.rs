use super::*;

/// Result of resizing one VMO, including any frames that must be retired before reuse.
#[derive(Clone, Debug)]
pub(crate) struct VmoResizeResult {
    new_size: u64,
    retired_frames: Vec<RetiredFrame>,
    barrier_address_spaces: Vec<AddressSpaceId>,
}

impl VmoResizeResult {
    fn from_retire_plan(new_size: u64, plan: FrameRetirePlan) -> Self {
        Self {
            new_size,
            retired_frames: plan.retired_frames,
            barrier_address_spaces: plan.barrier_address_spaces,
        }
    }

    pub(crate) const fn new_size(&self) -> u64 {
        self.new_size
    }

    pub(crate) fn retired_frames(&self) -> &[RetiredFrame] {
        &self.retired_frames
    }

    pub(crate) fn barrier_address_spaces(&self) -> &[AddressSpaceId] {
        &self.barrier_address_spaces
    }
}

impl VmDomain {
    pub(super) fn read_shared_vmo_bytes(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.kind().supports_kernel_read() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        out.resize(len, 0);

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut copied = 0usize;
        while copied < len {
            let absolute = offset
                .checked_add(copied as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_index = usize::try_from(absolute / crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, len - copied);
            let dst = &mut out[copied..copied + chunk_len];
            match snapshot.frames().get(page_index).copied().flatten() {
                Some(frame_id) => {
                    crate::copy::read_bootstrap_frame_bytes(frame_id.raw(), page_byte_offset, dst)?;
                }
                None if snapshot.kind() == VmoKind::Anonymous => {
                    crate::copy::zero_fill(dst);
                }
                None => {
                    if !snapshot.read_bytes_into(absolute, dst)? {
                        return Err(ZX_ERR_BAD_STATE);
                    }
                }
            }
            copied += chunk_len;
        }

        Ok(out)
    }

    pub(super) fn read_local_vmo_bytes(
        &self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_kernel_read() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        out.resize(len, 0);

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut copied = 0usize;
        while copied < len {
            let absolute = offset
                .checked_add(copied as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_index = usize::try_from(absolute / crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, len - copied);
            let dst = &mut out[copied..copied + chunk_len];
            match snapshot.frames().get(page_index).copied().flatten() {
                Some(frame_id) => {
                    crate::copy::read_bootstrap_frame_bytes(frame_id.raw(), page_byte_offset, dst)?;
                }
                None if snapshot.kind() == VmoKind::Anonymous => crate::copy::zero_fill(dst),
                None => return Err(ZX_ERR_BAD_STATE),
            }
            copied += chunk_len;
        }

        Ok(out)
    }

    pub(crate) fn read_vmo_bytes(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.read_local_vmo_bytes(owner_address_space_id, local_vmo_id, offset, len),
            crate::object::VmoBackingScope::GlobalShared => {
                self.read_shared_vmo_bytes(vmo.global_vmo_id(), offset, len)
            }
        }
    }

    fn write_shared_vmo_bytes(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.kind().supports_kernel_write() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut written = 0usize;
        while written < bytes.len() {
            let absolute = offset
                .checked_add(written as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_offset = absolute
                .checked_sub(absolute % crate::userspace::USER_PAGE_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, bytes.len() - written);
            let frame_id = match self.global_vmo_frame(global_vmo_id, page_offset)? {
                Some(frame_id) => frame_id,
                None => match snapshot.kind() {
                    VmoKind::Anonymous => {
                        let mut prepared = PreparedFaultWork::NewPage {
                            paddr: crate::userspace::alloc_bootstrap_zeroed_page()
                                .ok_or(ZX_ERR_NO_MEMORY)?,
                        };
                        let frame_id = self.ensure_global_vmo_frame(
                            global_vmo_id,
                            page_offset,
                            &mut prepared,
                        )?;
                        prepared.release_unused();
                        self.attach_global_vmo_page_aliases(global_vmo_id, page_offset, frame_id)?;
                        frame_id
                    }
                    VmoKind::Physical | VmoKind::Contiguous | VmoKind::PagerBacked => {
                        return Err(ZX_ERR_BAD_STATE);
                    }
                },
            };
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_byte_offset,
                &bytes[written..written + chunk_len],
            )?;
            written += chunk_len;
        }

        Ok(())
    }

    pub(super) fn write_local_vmo_bytes(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_kernel_write() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }

        let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
        let mut written = 0usize;
        while written < bytes.len() {
            let absolute = offset
                .checked_add(written as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_offset = absolute
                .checked_sub(absolute % crate::userspace::USER_PAGE_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let page_byte_offset = usize::try_from(absolute % crate::userspace::USER_PAGE_BYTES)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
            let chunk_len = core::cmp::min(page_bytes - page_byte_offset, bytes.len() - written);
            let frame_id = match self
                .address_spaces
                .get(&owner_address_space_id)
                .and_then(|space| space.vm.vmo(local_vmo_id))
                .and_then(|vmo| vmo.frame_at_offset(page_offset))
            {
                Some(frame_id) => frame_id,
                None if snapshot.kind() == VmoKind::Anonymous => {
                    let frame_id = self.ensure_local_vmo_frame(
                        owner_address_space_id,
                        local_vmo_id,
                        page_offset,
                    )?;
                    self.attach_local_vmo_page_aliases(
                        owner_address_space_id,
                        local_vmo_id,
                        page_offset,
                        frame_id,
                    )?;
                    frame_id
                }
                None => return Err(ZX_ERR_BAD_STATE),
            };
            crate::copy::write_bootstrap_frame_bytes(
                frame_id.raw(),
                page_byte_offset,
                &bytes[written..written + chunk_len],
            )?;
            written += chunk_len;
        }

        Ok(())
    }

    pub(crate) fn write_vmo_bytes(
        &mut self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.write_local_vmo_bytes(owner_address_space_id, local_vmo_id, offset, bytes),
            crate::object::VmoBackingScope::GlobalShared => {
                self.write_shared_vmo_bytes(vmo.global_vmo_id(), offset, bytes)
            }
        }
    }

    fn set_shared_vmo_size(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        if new_size == 0 || (new_size & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !snapshot.kind().supports_resize() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if new_size == snapshot.size_bytes() {
            return Ok(VmoResizeResult {
                new_size,
                retired_frames: Vec::new(),
                barrier_address_spaces: Vec::new(),
            });
        }

        for address_space in self.address_spaces.values() {
            address_space
                .validate_vmo_resize(global_vmo_id, new_size)
                .map_err(map_address_space_error)?;
        }

        let dropped = self.global_vmos.lock().resize(global_vmo_id, new_size)?;
        for address_space in self.address_spaces.values_mut() {
            let _ = address_space
                .resize_vmo(global_vmo_id, new_size)
                .map_err(map_address_space_error)?;
        }
        let retire_plan = self.build_required_frame_retire_plan(&dropped, &[])?;
        Ok(VmoResizeResult::from_retire_plan(new_size, retire_plan))
    }

    fn set_local_vmo_size(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        if new_size == 0 || (new_size & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !snapshot.kind().supports_resize() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if new_size == snapshot.size_bytes() {
            return Ok(VmoResizeResult {
                new_size,
                retired_frames: Vec::new(),
                barrier_address_spaces: Vec::new(),
            });
        }

        let dropped = self.with_address_space_frames_mut(
            owner_address_space_id,
            |address_space, _frames| {
                address_space
                    .vm
                    .resize_vmo(local_vmo_id, new_size)
                    .map_err(map_address_space_error)
            },
        )?;
        let retire_plan = self.build_required_frame_retire_plan(&dropped, &[])?;
        Ok(VmoResizeResult::from_retire_plan(new_size, retire_plan))
    }

    pub(crate) fn set_vmo_size(
        &mut self,
        vmo: &crate::object::VmoObject,
        new_size: u64,
    ) -> Result<VmoResizeResult, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.set_local_vmo_size(owner_address_space_id, local_vmo_id, new_size),
            crate::object::VmoBackingScope::GlobalShared => {
                self.set_shared_vmo_size(vmo.global_vmo_id(), new_size)
            }
        }
    }

    fn lookup_shared_vmo_paddr(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !matches!(snapshot.kind(), VmoKind::Physical | VmoKind::Contiguous) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, 1)?;
        let page_offset = align_down_page(offset);
        let byte_offset = offset - page_offset;
        let frame_id = self
            .global_vmo_frame(global_vmo_id, page_offset)?
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(frame_id.raw() + byte_offset)
    }

    fn lookup_local_vmo_paddr(
        &self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !matches!(snapshot.kind(), VmoKind::Physical | VmoKind::Contiguous) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        validate_vmo_io_range(snapshot.size_bytes(), offset, 1)?;
        let page_offset = align_down_page(offset);
        let byte_offset = offset - page_offset;
        let frame_id = snapshot
            .frame_at_offset(page_offset)
            .ok_or(ZX_ERR_BAD_STATE)?;
        Ok(frame_id.raw() + byte_offset)
    }

    pub(crate) fn lookup_vmo_paddr(
        &self,
        vmo: &crate::object::VmoObject,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.lookup_local_vmo_paddr(owner_address_space_id, local_vmo_id, offset),
            crate::object::VmoBackingScope::GlobalShared => {
                self.lookup_shared_vmo_paddr(vmo.global_vmo_id(), offset)
            }
        }
    }

    fn pin_shared_vmo_range(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        len: u64,
    ) -> Result<axle_mm::PinToken, zx_status_t> {
        let snapshot = self.global_vmos.lock().snapshot(global_vmo_id)?;
        if !matches!(snapshot.kind(), VmoKind::Physical | VmoKind::Contiguous) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let len_usize = usize::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        validate_vmo_io_range(snapshot.size_bytes(), offset, len_usize)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let mut frame_ids = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_offset = offset + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let frame_id = self
                .global_vmo_frame(global_vmo_id, page_offset)?
                .ok_or(ZX_ERR_BAD_STATE)?;
            frame_ids.push(frame_id);
        }
        self.with_frames_mut(|frames| frames.pin_many(&frame_ids))
            .map_err(map_frame_table_error)
    }

    fn pin_local_vmo_range(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        offset: u64,
        len: u64,
    ) -> Result<axle_mm::PinToken, zx_status_t> {
        let snapshot = self.local_vmo_snapshot(owner_address_space_id, local_vmo_id)?;
        if !matches!(snapshot.kind(), VmoKind::Physical | VmoKind::Contiguous) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let len_usize = usize::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        validate_vmo_io_range(snapshot.size_bytes(), offset, len_usize)?;
        let page_count = usize::try_from(len / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let mut frame_ids = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_offset = offset + (page_index as u64) * crate::userspace::USER_PAGE_BYTES;
            let frame_id = snapshot
                .frame_at_offset(page_offset)
                .ok_or(ZX_ERR_BAD_STATE)?;
            frame_ids.push(frame_id);
        }
        self.with_frames_mut(|frames| frames.pin_many(&frame_ids))
            .map_err(map_frame_table_error)
    }

    pub(crate) fn pin_vmo_range(
        &mut self,
        vmo: &crate::object::VmoObject,
        offset: u64,
        len: u64,
    ) -> Result<axle_mm::PinToken, zx_status_t> {
        if len == 0
            || (offset & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
            || (len & (crate::userspace::USER_PAGE_BYTES - 1)) != 0
        {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        match vmo.backing_scope() {
            crate::object::VmoBackingScope::LocalPrivate {
                owner_address_space_id,
                local_vmo_id,
            } => self.pin_local_vmo_range(owner_address_space_id, local_vmo_id, offset, len),
            crate::object::VmoBackingScope::GlobalShared => {
                self.pin_shared_vmo_range(vmo.global_vmo_id(), offset, len)
            }
        }
    }

    pub(super) fn ensure_global_vmo_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        prepared: &mut PreparedFaultWork,
    ) -> Result<FrameId, zx_status_t> {
        if let Some(frame_id) = self.global_vmo_frame(global_vmo_id, page_offset)? {
            return Ok(frame_id);
        }
        let new_frame_paddr = prepared.take_page_paddr().ok_or(ZX_ERR_BAD_STATE)?;
        let new_frame_id = self.with_frames_mut(|frames| {
            frames
                .register_existing(new_frame_paddr)
                .map_err(|_| ZX_ERR_BAD_STATE)
        })?;
        self.update_global_vmo_frame(global_vmo_id, page_offset, new_frame_id)?;
        Ok(new_frame_id)
    }
}

impl VmDomain {
    pub(super) fn local_vmo_snapshot(
        &self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
    ) -> Result<Vmo, zx_status_t> {
        self.address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .cloned()
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(super) fn ensure_local_vmo_frame(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        page_offset: u64,
    ) -> Result<FrameId, zx_status_t> {
        if let Some(frame_id) = self
            .address_spaces
            .get(&owner_address_space_id)
            .and_then(|space| space.vm.vmo(local_vmo_id))
            .and_then(|vmo| vmo.frame_at_offset(page_offset))
        {
            return Ok(frame_id);
        }

        let new_frame_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(ZX_ERR_NO_MEMORY)?;
        let bound =
            self.with_address_space_frames_mut(owner_address_space_id, |address_space, frames| {
                if let Some(frame_id) = address_space
                    .vm
                    .vmo(local_vmo_id)
                    .and_then(|vmo| vmo.frame_at_offset(page_offset))
                {
                    return Ok((frame_id, false));
                }
                let new_frame_id = frames
                    .register_existing(new_frame_paddr)
                    .map_err(|_| ZX_ERR_BAD_STATE)?;
                address_space
                    .set_vmo_frame(local_vmo_id, page_offset, new_frame_id)
                    .map_err(map_address_space_error)?;
                Ok((new_frame_id, true))
            })?;
        if !bound.1 {
            crate::userspace::free_bootstrap_page(new_frame_paddr);
        }
        Ok(bound.0)
    }

    pub(super) fn attach_local_vmo_page_aliases(
        &mut self,
        owner_address_space_id: AddressSpaceId,
        local_vmo_id: VmoId,
        page_offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let page_bases =
            self.with_address_space_frames_mut(owner_address_space_id, |address_space, frames| {
                address_space
                    .vm
                    .materialize_vmo_page_aliases(frames, local_vmo_id, page_offset, frame_id)
                    .map_err(map_address_space_error)
            })?;
        for page_base in page_bases {
            self.sync_mapping_pages(
                owner_address_space_id,
                page_base,
                crate::userspace::USER_PAGE_BYTES,
            )?;
        }
        self.validate_frame_mapping_invariants(frame_id, "attach_local_vmo_page_aliases");
        Ok(())
    }

    pub(super) fn attach_global_vmo_page_aliases(
        &mut self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let address_space_ids = self.address_space_ids_importing_global_vmo(global_vmo_id);
        for address_space_id in address_space_ids {
            let Some(local_vmo_id) = self
                .address_spaces
                .get(&address_space_id)
                .and_then(|space| space.local_vmo_id(global_vmo_id))
            else {
                continue;
            };
            let page_bases =
                self.with_address_space_frames_mut(address_space_id, |address_space, frames| {
                    address_space
                        .vm
                        .materialize_vmo_page_aliases(frames, local_vmo_id, page_offset, frame_id)
                        .map_err(map_address_space_error)
                })?;
            for page_base in page_bases {
                self.sync_mapping_pages(
                    address_space_id,
                    page_base,
                    crate::userspace::USER_PAGE_BYTES,
                )?;
            }
        }
        self.validate_frame_mapping_invariants(frame_id, "attach_global_vmo_page_aliases");
        Ok(())
    }
}

fn validate_vmo_io_range(size_bytes: u64, offset: u64, len: usize) -> Result<(), zx_status_t> {
    let end = offset
        .checked_add(u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if end > size_bytes {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    Ok(())
}
