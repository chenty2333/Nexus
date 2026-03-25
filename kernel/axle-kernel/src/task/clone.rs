use super::*;

#[derive(Clone)]
struct VmarClonePlan {
    src_base: u64,
    dst_base: u64,
    len: u64,
    vmo_offset: u64,
    perms: MappingPerms,
    max_perms: MappingPerms,
    cache_policy: MappingCachePolicy,
    clone_policy: MappingClonePolicy,
    source_vmo_id: VmoId,
    source_kind: VmoKind,
    source_size_bytes: u64,
    source_global_vmo_id: KernelVmoId,
    source_frames: Vec<Option<FrameId>>,
}

impl VmDomain {
    pub(crate) fn clone_vmar_mappings(
        &mut self,
        src_address_space_id: AddressSpaceId,
        src_vmar_id: VmarId,
        dst_address_space_id: AddressSpaceId,
        dst_vmar_id: VmarId,
    ) -> Result<Vec<TlbCommitReq>, zx_status_t> {
        if src_address_space_id == dst_address_space_id {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let plans = self.collect_vmar_clone_plans(
            src_address_space_id,
            src_vmar_id,
            dst_address_space_id,
            dst_vmar_id,
        )?;
        if plans.is_empty() {
            return Ok(Vec::new());
        }

        for plan in plans.iter() {
            match plan.clone_policy {
                MappingClonePolicy::None => {}
                MappingClonePolicy::SharedAlias => self.apply_shared_alias_clone(
                    src_address_space_id,
                    src_vmar_id,
                    dst_address_space_id,
                    dst_vmar_id,
                    plan,
                )?,
                MappingClonePolicy::PrivateCow => self.apply_private_cow_clone(
                    src_address_space_id,
                    plan,
                    dst_address_space_id,
                    dst_vmar_id,
                )?,
            }
        }

        let mut reqs = Vec::with_capacity(2);
        reqs.push(TlbCommitReq::strict(src_address_space_id));
        reqs.push(TlbCommitReq::strict(dst_address_space_id));
        Ok(reqs)
    }

    fn collect_vmar_clone_plans(
        &self,
        src_address_space_id: AddressSpaceId,
        src_vmar_id: VmarId,
        dst_address_space_id: AddressSpaceId,
        dst_vmar_id: VmarId,
    ) -> Result<Vec<VmarClonePlan>, zx_status_t> {
        let src_space = self
            .address_spaces
            .get(&src_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let dst_space = self
            .address_spaces
            .get(&dst_address_space_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let src_vmar = src_space.vmar(src_vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;
        let dst_vmar = dst_space.vmar(dst_vmar_id).ok_or(ZX_ERR_NOT_FOUND)?;

        let mut plans = Vec::new();
        for vma in src_space
            .vm
            .vmas()
            .iter()
            .copied()
            .filter(|candidate| candidate.vmar_id() == src_vmar_id)
        {
            if vma.clone_policy() == MappingClonePolicy::None {
                continue;
            }
            let map_rec = src_space.map_record(vma.map_id()).ok_or(ZX_ERR_BAD_STATE)?;
            let source_vmo = src_space.vm.vmo(map_rec.vmo_id()).ok_or(ZX_ERR_BAD_STATE)?;
            let relative = vma
                .base()
                .checked_sub(src_vmar.base())
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let dst_base = dst_vmar
                .base()
                .checked_add(relative)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let dst_end = dst_base.checked_add(vma.len()).ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let dst_limit = dst_vmar
                .base()
                .checked_add(dst_vmar.len())
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if dst_base < dst_vmar.base() || dst_end > dst_limit {
                return Err(ZX_ERR_OUT_OF_RANGE);
            }
            plans.push(VmarClonePlan {
                src_base: vma.base(),
                dst_base,
                len: vma.len(),
                vmo_offset: map_rec.vmo_offset(),
                perms: vma.perms(),
                max_perms: map_rec.max_perms(),
                cache_policy: map_rec.cache_policy(),
                clone_policy: vma.clone_policy(),
                source_vmo_id: map_rec.vmo_id(),
                source_kind: source_vmo.kind(),
                source_size_bytes: source_vmo.size_bytes(),
                source_global_vmo_id: map_rec.global_vmo_id(),
                source_frames: source_vmo.frames().to_vec(),
            });
        }
        Ok(plans)
    }

    fn apply_shared_alias_clone(
        &mut self,
        src_address_space_id: AddressSpaceId,
        src_vmar_id: VmarId,
        dst_address_space_id: AddressSpaceId,
        dst_vmar_id: VmarId,
        plan: &VmarClonePlan,
    ) -> Result<(), zx_status_t> {
        let shared_src_vmo_id = if self
            .address_spaces
            .get(&src_address_space_id)
            .and_then(|space| space.local_vmo_id(plan.source_global_vmo_id))
            .is_some_and(|candidate| candidate != plan.source_vmo_id)
        {
            self.address_spaces
                .get(&src_address_space_id)
                .and_then(|space| space.local_vmo_id(plan.source_global_vmo_id))
                .ok_or(ZX_ERR_BAD_STATE)?
        } else {
            self.promote_local_vmo_to_shared(src_address_space_id, plan.source_global_vmo_id)?;
            self.address_spaces
                .get(&src_address_space_id)
                .and_then(|space| space.local_vmo_id(plan.source_global_vmo_id))
                .ok_or(ZX_ERR_BAD_STATE)?
        };
        let shared_dst_vmo_id = self.import_global_vmo_into_address_space(
            dst_address_space_id,
            plan.source_global_vmo_id,
        )?;

        if shared_src_vmo_id != plan.source_vmo_id {
            self.unmap_clone_target_if_present(
                src_address_space_id,
                src_vmar_id,
                plan.src_base,
                plan.len,
            )?;
            self.map_existing_local_vmo_fixed_with_clone_policy(
                src_address_space_id,
                src_vmar_id,
                plan.src_base,
                plan.len,
                shared_src_vmo_id,
                plan.vmo_offset,
                plan.perms,
                plan.max_perms,
                MappingClonePolicy::SharedAlias,
            )?;
        }

        self.unmap_clone_target_if_present(
            dst_address_space_id,
            dst_vmar_id,
            plan.dst_base,
            plan.len,
        )?;
        self.map_existing_local_vmo_fixed_with_clone_policy(
            dst_address_space_id,
            dst_vmar_id,
            plan.dst_base,
            plan.len,
            shared_dst_vmo_id,
            plan.vmo_offset,
            plan.perms,
            plan.max_perms,
            MappingClonePolicy::SharedAlias,
        )?;
        Ok(())
    }

    fn apply_private_cow_clone(
        &mut self,
        src_address_space_id: AddressSpaceId,
        plan: &VmarClonePlan,
        dst_address_space_id: AddressSpaceId,
        dst_vmar_id: VmarId,
    ) -> Result<(), zx_status_t> {
        self.unmap_clone_target_if_present(
            dst_address_space_id,
            dst_vmar_id,
            plan.dst_base,
            plan.len,
        )?;

        let dst_vmo_id =
            self.with_address_space_frames_mut(dst_address_space_id, |address_space, _frames| {
                address_space
                    .create_private_clone_vmo(
                        plan.source_kind,
                        plan.source_size_bytes,
                        plan.source_global_vmo_id,
                        &plan.source_frames,
                    )
                    .map_err(map_address_space_error)
            })?;
        self.map_existing_local_vmo_fixed_with_clone_policy(
            dst_address_space_id,
            dst_vmar_id,
            plan.dst_base,
            plan.len,
            dst_vmo_id,
            plan.vmo_offset,
            plan.perms,
            plan.max_perms,
            MappingClonePolicy::PrivateCow,
        )?;
        self.with_address_space_frames_mut(dst_address_space_id, |address_space, _frames| {
            address_space
                .arm_copy_on_write(plan.dst_base, plan.len)
                .map_err(map_address_space_error)
        })?;
        self.clear_private_cow_range(dst_address_space_id, plan.dst_base, plan.len);
        self.update_mapping_pages(dst_address_space_id, plan.dst_base, plan.len)?;

        let src_arm_result =
            self.with_address_space_frames_mut(src_address_space_id, |address_space, _frames| {
                address_space
                    .arm_copy_on_write(plan.src_base, plan.len)
                    .map_err(map_address_space_error)
            });
        if let Err(err) = src_arm_result {
            // Rollback: unmap the dst mapping and release the VMO we just created.
            let _ = self.unmap_clone_target_if_present(
                dst_address_space_id,
                dst_vmar_id,
                plan.dst_base,
                plan.len,
            );
            return Err(err);
        }
        self.clear_private_cow_range(src_address_space_id, plan.src_base, plan.len);
        self.update_mapping_pages(src_address_space_id, plan.src_base, plan.len)?;
        Ok(())
    }

    fn unmap_clone_target_if_present(
        &mut self,
        address_space_id: AddressSpaceId,
        vmar_id: VmarId,
        base: u64,
        len: u64,
    ) -> Result<(), zx_status_t> {
        let present = self
            .address_spaces
            .get(&address_space_id)
            .and_then(|space| space.lookup_user_mapping(base, 1))
            .is_some();
        if present {
            let _ = self.unmap_vmar(address_space_id, vmar_id, base, len)?;
        }
        Ok(())
    }
}
