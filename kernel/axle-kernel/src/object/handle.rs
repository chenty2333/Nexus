use super::*;

impl KernelState {
    pub(super) fn alloc_handle_for_object(
        &mut self,
        object_id: u64,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let cap = Capability::new(object_id, rights.bits(), DEFAULT_OBJECT_GENERATION);
        let handle = self.with_core_mut(|kernel| kernel.alloc_handle_for_current_process(cap))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    pub(crate) fn lookup_handle(
        &self,
        raw: zx_handle_t,
        required_rights: crate::task::HandleRights,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        self.with_core(|kernel| kernel.lookup_current_handle(raw, required_rights))
    }

    pub(super) fn close_handle(&mut self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let object_id = self
            .lookup_handle(raw, crate::task::HandleRights::empty())?
            .object_id();
        self.with_core_mut(|kernel| kernel.close_current_handle(raw))?;
        self.decrement_object_handle_ref(object_id);
        Ok(())
    }

    pub(super) fn duplicate_handle(
        &mut self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_id = self
            .lookup_handle(raw, crate::task::HandleRights::empty())?
            .object_id();
        let handle = self.with_core_mut(|kernel| kernel.duplicate_current_handle(raw, rights))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    pub(super) fn replace_handle(
        &mut self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        self.with_core_mut(|kernel| kernel.replace_current_handle(raw, rights))
    }

    pub(super) fn snapshot_handle_for_transfer(
        &self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<TransferredCap, zx_status_t> {
        self.with_core(|kernel| kernel.snapshot_current_handle_for_transfer(raw, rights))
    }

    pub(super) fn install_transferred_handle(
        &mut self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_id = transferred.capability().object_id();
        let handle =
            self.with_core_mut(|kernel| kernel.install_handle_in_current_process(transferred))?;
        self.object_handle_refs
            .entry(object_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(handle)
    }

    pub(super) fn object_handle_count(&self, object_id: u64) -> usize {
        self.object_handle_refs
            .get(&object_id)
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn forget_object_handle_refs(&mut self, object_id: u64) {
        let _ = self.object_handle_refs.remove(&object_id);
    }

    pub(super) fn decrement_object_handle_ref(&mut self, object_id: u64) {
        match self.object_handle_refs.get_mut(&object_id) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                self.object_handle_refs.remove(&object_id);
            }
            None => {}
        }
    }
}

/// Duplicate one handle, optionally dropping rights.
pub fn duplicate_handle(
    handle: zx_handle_t,
    rights: zx_rights_t,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::DUPLICATE)?;
        let derived_rights = normalize_requested_rights(resolved, rights)?;
        state.duplicate_handle(handle, derived_rights)
    })
}

/// Replace one handle with a new handle that carries equal-or-fewer rights.
pub fn replace_handle(
    handle: zx_handle_t,
    rights: zx_rights_t,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::DUPLICATE)?;
        let derived_rights = normalize_requested_rights(resolved, rights)?;
        state.replace_handle(handle, derived_rights)
    })
}

pub(super) fn normalize_requested_rights(
    resolved: crate::task::ResolvedHandle,
    requested: zx_rights_t,
) -> Result<crate::task::HandleRights, zx_status_t> {
    if requested == ZX_RIGHT_SAME_RIGHTS {
        return Ok(resolved.rights());
    }
    if (requested & !ZX_RIGHTS_ALL) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if (requested & !resolved.rights().bits()) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(crate::task::HandleRights::from_zx_rights(requested))
}

pub(super) fn channel_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

pub(super) fn socket_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

pub(super) fn process_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MANAGE_PROCESS
        | crate::task::HandleRights::MANAGE_THREAD
}

pub(super) fn suspend_token_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::empty()
}

pub(super) fn eventpair_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::SIGNAL
        | crate::task::HandleRights::SIGNAL_PEER
}

pub(super) fn port_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

pub(super) fn timer_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::WRITE
}

pub(super) fn vmo_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
        | crate::task::HandleRights::MAP
}

pub(super) fn bootstrap_code_vmo_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::MAP
}

pub(super) fn vmar_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
        | crate::task::HandleRights::MAP
}

pub(super) fn thread_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MANAGE_THREAD
}
