use super::*;

pub fn create_revocation_group(options: u32) -> Result<zx_handle_t, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let token = state.with_core_mut(|kernel| Ok(kernel.create_revocation_group()))?;
        let object_id = state.alloc_object_id();
        state.with_objects_mut(|objects| {
            objects.insert(
                object_id,
                KernelObject::RevocationGroup(RevocationGroupObject { token }),
            )?;
            Ok(())
        })?;
        state.alloc_handle_for_object(object_id, handle::revocation_group_default_rights())
    })
}

pub fn revocation_group_get_info(
    handle: zx_handle_t,
) -> Result<axle_types::ax_revocation_group_info_t, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::INSPECT)?;
        let token = state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::RevocationGroup(group)) => Ok(group.token()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        let epoch = state.with_core(|kernel| kernel.revocation_group_epoch(token))?;
        Ok(axle_types::ax_revocation_group_info_t {
            group_id: token.id().raw(),
            generation: token.generation(),
            epoch,
            reserved0: 0,
        })
    })
}

pub fn revocation_group_revoke(handle: zx_handle_t) -> Result<(), zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let token = state.with_objects(|objects| match objects.get(resolved.object_key()) {
            Some(KernelObject::RevocationGroup(group)) => Ok(group.token()),
            Some(_) => Err(ZX_ERR_WRONG_TYPE),
            None => Err(ZX_ERR_BAD_HANDLE),
        })?;
        state.with_core_mut(|kernel| kernel.revoke_group(token))
    })
}
