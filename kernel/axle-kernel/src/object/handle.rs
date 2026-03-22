use super::*;

impl KernelState {
    fn current_process_id(&self) -> Result<u64, zx_status_t> {
        self.with_core(|kernel| {
            kernel
                .current_process_info()
                .map(|process| process.process_id())
        })
    }

    pub(super) fn resolve_handle_raw(
        &self,
        raw: zx_handle_t,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        let process_id = self.current_process_id()?;
        self.resolve_handle_raw_in_process(process_id, raw)
    }

    pub(super) fn resolve_handle_raw_in_process(
        &self,
        process_id: u64,
        raw: zx_handle_t,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        self.with_core(|kernel| {
            kernel.lookup_handle_in_process(process_id, raw, crate::task::HandleRights::empty())
        })
    }

    pub(super) fn alloc_handle_for_object(
        &self,
        object_key: ObjectKey,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let cap = self.capability_for_object(object_key, rights);
        let handle = self.with_core_mut(|kernel| kernel.alloc_handle_for_current_process(cap))?;
        self.with_registry_mut(|registry| registry.increment_handle_ref(object_key))?;
        Ok(handle)
    }

    pub(crate) fn lookup_handle(
        &self,
        raw: zx_handle_t,
        required_rights: crate::task::HandleRights,
    ) -> Result<crate::task::ResolvedHandle, zx_status_t> {
        let resolved = self.with_core(|kernel| {
            kernel.lookup_current_handle(raw, crate::task::HandleRights::empty())
        })?;
        self.with_registry(|registry| {
            if registry.get(resolved.object_key()).is_some() {
                Ok(())
            } else {
                Err(ZX_ERR_BAD_HANDLE)
            }
        })?;
        require_handle_rights(resolved, required_rights)?;
        Ok(resolved)
    }

    pub(super) fn close_handle(&self, raw: zx_handle_t) -> Result<(), zx_status_t> {
        let process_id = self.current_process_id()?;
        self.close_handle_in_process(process_id, raw)
    }

    pub(super) fn close_handle_in_process(
        &self,
        process_id: u64,
        raw: zx_handle_t,
    ) -> Result<(), zx_status_t> {
        let object_key = self
            .resolve_handle_raw_in_process(process_id, raw)?
            .object_key();
        self.with_core_mut(|kernel| kernel.close_handle_in_process(process_id, raw))?;
        self.decrement_object_handle_ref(object_key);
        Ok(())
    }

    pub(super) fn duplicate_handle(
        &self,
        raw: zx_handle_t,
        rights: crate::task::HandleRights,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_key = self
            .lookup_handle(raw, crate::task::HandleRights::empty())?
            .object_key();
        let handle = self.with_core_mut(|kernel| kernel.duplicate_current_handle(raw, rights))?;
        self.with_registry_mut(|registry| registry.increment_handle_ref(object_key))?;
        Ok(handle)
    }

    pub(super) fn replace_handle(
        &self,
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
        let _ = self.lookup_handle(raw, rights)?;
        self.with_core(|kernel| kernel.snapshot_current_handle_for_transfer(raw, rights))
    }

    pub(super) fn install_transferred_handle(
        &self,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let process_id = self.current_process_id()?;
        self.install_transferred_handle_in_process(process_id, transferred)
    }

    pub(super) fn install_transferred_handle_in_process(
        &self,
        process_id: u64,
        transferred: TransferredCap,
    ) -> Result<zx_handle_t, zx_status_t> {
        let object_key = transferred.capability().object_key();
        let vmo_to_promote = self.with_registry(|registry| {
            Ok(match registry.get(object_key) {
                Some(KernelObject::Vmo(vmo))
                    if matches!(vmo.backing_scope(), VmoBackingScope::LocalPrivate { .. })
                        && vmo.creator_process_id() != process_id =>
                {
                    Some(vmo.clone())
                }
                _ => None,
            })
        })?;
        if let Some(vmo) = vmo_to_promote {
            let promoted = self.with_vm_mut(|vm| vm.promote_vmo_object_to_shared(&vmo))?;
            if promoted {
                self.with_registry_mut(|registry| {
                    let Some(KernelObject::Vmo(vmo_object)) = registry.get_mut(object_key) else {
                        return Err(ZX_ERR_BAD_STATE);
                    };
                    vmo_object.backing_scope = VmoBackingScope::GlobalShared;
                    Ok(())
                })?;
            }
        }
        let handle =
            self.with_core_mut(|kernel| kernel.install_handle_in_process(process_id, transferred))?;
        self.with_registry_mut(|registry| registry.increment_handle_ref(object_key))?;
        Ok(handle)
    }

    pub(super) fn object_handle_count(&self, object_key: ObjectKey) -> usize {
        self.registry.lock().handle_refcount(object_key)
    }

    pub(super) fn forget_object_handle_refs(&self, _object_key: ObjectKey) {}

    pub(super) fn decrement_object_handle_ref(&self, object_key: ObjectKey) {
        self.registry.lock().decrement_handle_ref(object_key);
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

/// Duplicate one handle with reduced rights and bind the duplicate to one revocation group.
pub fn duplicate_handle_revocable(
    handle: zx_handle_t,
    rights: zx_rights_t,
    group_handle: zx_handle_t,
) -> Result<zx_handle_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::DUPLICATE)?;
        let derived_rights = normalize_requested_rights(resolved, rights)?;
        let group = state.lookup_handle(group_handle, crate::task::HandleRights::WRITE)?;
        let token = state.with_objects(|objects| match objects.get(group.object_key()) {
            Some(KernelObject::RevocationGroup(group)) => Ok(group.token()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        let object_key = resolved.object_key();
        let duplicated = state.with_core_mut(|kernel| {
            kernel.duplicate_current_handle_revocable(handle, derived_rights, token)
        })?;
        state.with_registry_mut(|registry| registry.increment_handle_ref(object_key))?;
        Ok(duplicated)
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

pub(super) fn guest_session_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
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
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
}

pub(super) fn timer_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::WRITE
}

pub(super) fn interrupt_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::WRITE
}

pub(super) fn dma_region_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::INSPECT
}

pub(super) fn pci_device_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::WRITE
}

pub(super) fn pci_config_vmo_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::MAP
}

pub(super) fn vmo_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
        | crate::task::HandleRights::EXECUTE
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MAP
}

pub(super) fn bootstrap_code_vmo_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::EXECUTE
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MAP
}

pub(super) fn vmar_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::READ
        | crate::task::HandleRights::WRITE
        | crate::task::HandleRights::EXECUTE
        | crate::task::HandleRights::MAP
}

pub(super) fn revocation_group_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::WRITE
}

pub(super) fn thread_default_rights() -> crate::task::HandleRights {
    crate::task::HandleRights::DUPLICATE
        | crate::task::HandleRights::TRANSFER
        | crate::task::HandleRights::WAIT
        | crate::task::HandleRights::INSPECT
        | crate::task::HandleRights::MANAGE_THREAD
}
