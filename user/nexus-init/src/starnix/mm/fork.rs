use super::super::*;
use super::context::{LinuxMapBacking, LinuxMapEntry, LinuxMm};
use super::mmap::map_linux_prot_to_vm_options;

impl LinuxMm {
    pub(in crate::starnix) fn new(root_vmar: zx_handle_t) -> Result<Self, zx_status_t> {
        let (heap_vmar, heap_base) = allocate_child_vmar(
            root_vmar,
            ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_SPECIFIC | ZX_VM_COMPACT,
            LINUX_HEAP_REGION_BYTES,
        )?;
        let (mmap_vmar, mmap_base) = allocate_child_vmar(
            root_vmar,
            ZX_VM_CAN_MAP_READ
                | ZX_VM_CAN_MAP_WRITE
                | ZX_VM_CAN_MAP_EXECUTE
                | ZX_VM_CAN_MAP_SPECIFIC
                | ZX_VM_COMPACT,
            LINUX_MMAP_REGION_BYTES,
        )?;
        let mut heap_vmo = ZX_HANDLE_INVALID;
        let status = zx_vmo_create(LINUX_HEAP_VMO_BYTES, 0, &mut heap_vmo);
        if status != ZX_OK {
            let _ = zx_handle_close(heap_vmar);
            let _ = zx_handle_close(mmap_vmar);
            let _ = zx_handle_close(root_vmar);
            return Err(status);
        }
        Ok(Self {
            root_vmar,
            heap_vmar,
            heap_base,
            heap_limit: heap_base
                .checked_add(LINUX_HEAP_REGION_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            heap_vmo,
            heap_break: heap_base,
            heap_mapped_len: 0,
            mmap_vmar,
            mmap_base,
            exec_tree: BTreeMap::new(),
            map_tree: BTreeMap::new(),
        })
    }

    pub(in crate::starnix) fn fork_clone(
        &self,
        child_root_vmar: zx_handle_t,
        parent_session: zx_handle_t,
        child_session: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        let heap_options =
            ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_SPECIFIC | ZX_VM_SPECIFIC;
        let mmap_options = ZX_VM_CAN_MAP_READ
            | ZX_VM_CAN_MAP_WRITE
            | ZX_VM_CAN_MAP_EXECUTE
            | ZX_VM_CAN_MAP_SPECIFIC
            | ZX_VM_SPECIFIC;
        let heap_vmar = allocate_child_vmar_fixed(
            child_root_vmar,
            heap_options,
            self.heap_base,
            LINUX_HEAP_REGION_BYTES,
        )?;
        let mmap_vmar = allocate_child_vmar_fixed(
            child_root_vmar,
            mmap_options,
            self.mmap_base,
            LINUX_MMAP_REGION_BYTES,
        )?;
        let mut child_heap_vmo = ZX_HANDLE_INVALID;
        zx_status_result(zx_vmo_create(LINUX_HEAP_VMO_BYTES, 0, &mut child_heap_vmo))?;
        zx_status_result(ax_vmar_clone_mappings_local(
            self.root_vmar,
            child_root_vmar,
        ))?;
        if self.heap_mapped_len != 0 {
            let mut mapped_addr = 0u64;
            zx_status_result(zx_vmar_map_local(
                heap_vmar,
                ZX_VM_SPECIFIC | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
                0,
                child_heap_vmo,
                0,
                self.heap_mapped_len,
                &mut mapped_addr,
            ))?;
            copy_guest_region(
                parent_session,
                child_session,
                self.heap_base,
                self.heap_mapped_len,
            )?;
        }

        let exec_tree = self.exec_tree.clone();
        let mut map_tree = BTreeMap::new();
        for entry in self.map_tree.values() {
            match entry.backing {
                LinuxMapBacking::Anonymous { .. } => {
                    let mut child_vmo = ZX_HANDLE_INVALID;
                    zx_status_result(zx_vmo_create(entry.len, 0, &mut child_vmo))?;
                    let mut mapped_addr = 0u64;
                    zx_status_result(zx_vmar_map_local(
                        mmap_vmar,
                        map_linux_prot_to_vm_options(entry.prot)
                            .map_err(linux_status_from_errno)?
                            | ZX_VM_SPECIFIC,
                        entry
                            .base
                            .checked_sub(self.mmap_base)
                            .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                        child_vmo,
                        0,
                        entry.len,
                        &mut mapped_addr,
                    ))?;
                    copy_guest_region(parent_session, child_session, entry.base, entry.len)?;
                    map_tree.insert(
                        entry.base,
                        LinuxMapEntry {
                            base: entry.base,
                            len: entry.len,
                            prot: entry.prot,
                            flags: entry.flags,
                            backing: LinuxMapBacking::Anonymous { vmo: child_vmo },
                        },
                    );
                }
                LinuxMapBacking::File { vmo, offset } => {
                    if entry.is_private() {
                        let mut child_vmo = ZX_HANDLE_INVALID;
                        zx_status_result(zx_vmo_create(entry.len, 0, &mut child_vmo))?;
                        let mut mapped_addr = 0u64;
                        zx_status_result(zx_vmar_map_local(
                            mmap_vmar,
                            map_linux_prot_to_vm_options(entry.prot)
                                .map_err(linux_status_from_errno)?
                                | ZX_VM_SPECIFIC,
                            entry
                                .base
                                .checked_sub(self.mmap_base)
                                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                            child_vmo,
                            0,
                            entry.len,
                            &mut mapped_addr,
                        ))?;
                        copy_guest_region(parent_session, child_session, entry.base, entry.len)?;
                        map_tree.insert(
                            entry.base,
                            LinuxMapEntry {
                                base: entry.base,
                                len: entry.len,
                                prot: entry.prot,
                                flags: entry.flags,
                                backing: LinuxMapBacking::Anonymous { vmo: child_vmo },
                            },
                        );
                        continue;
                    }
                    let mut duplicated = ZX_HANDLE_INVALID;
                    zx_status_result(zx_handle_duplicate(
                        vmo,
                        ZX_RIGHT_SAME_RIGHTS,
                        &mut duplicated,
                    ))?;
                    let mut mapped_addr = 0u64;
                    zx_status_result(zx_vmar_map_local(
                        mmap_vmar,
                        map_linux_prot_to_vm_options(entry.prot)
                            .map_err(linux_status_from_errno)?
                            | ZX_VM_SPECIFIC,
                        entry
                            .base
                            .checked_sub(self.mmap_base)
                            .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                        duplicated,
                        offset,
                        entry.len,
                        &mut mapped_addr,
                    ))?;
                    map_tree.insert(
                        entry.base,
                        LinuxMapEntry {
                            base: entry.base,
                            len: entry.len,
                            prot: entry.prot,
                            flags: entry.flags,
                            backing: LinuxMapBacking::File {
                                vmo: duplicated,
                                offset,
                            },
                        },
                    );
                }
            }
        }

        Ok(Self {
            root_vmar: child_root_vmar,
            heap_vmar,
            heap_base: self.heap_base,
            heap_limit: self.heap_limit,
            heap_vmo: child_heap_vmo,
            heap_break: self.heap_break,
            heap_mapped_len: self.heap_mapped_len,
            mmap_vmar,
            mmap_base: self.mmap_base,
            exec_tree,
            map_tree,
        })
    }

    #[cfg(test)]
    pub(in crate::starnix) fn empty_for_tests() -> Self {
        Self {
            root_vmar: ZX_HANDLE_INVALID,
            heap_vmar: ZX_HANDLE_INVALID,
            heap_base: 0,
            heap_limit: 0,
            heap_vmo: ZX_HANDLE_INVALID,
            heap_break: 0,
            heap_mapped_len: 0,
            mmap_vmar: ZX_HANDLE_INVALID,
            mmap_base: 0,
            exec_tree: BTreeMap::new(),
            map_tree: BTreeMap::new(),
        }
    }
}

fn allocate_child_vmar(
    parent: zx_handle_t,
    options: u32,
    size: u64,
) -> Result<(zx_handle_t, u64), zx_status_t> {
    let mut child = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(parent, options, 0, size, &mut child, &mut child_addr);
    if status == ZX_OK {
        Ok((child, child_addr))
    } else {
        Err(status)
    }
}

fn allocate_child_vmar_fixed(
    parent: zx_handle_t,
    options: u32,
    addr: u64,
    size: u64,
) -> Result<zx_handle_t, zx_status_t> {
    let offset = addr.checked_sub(USER_CODE_VA).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut child = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(parent, options, offset, size, &mut child, &mut child_addr);
    if status != ZX_OK {
        return Err(status);
    }
    if child_addr != addr {
        let _ = zx_handle_close(child);
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(child)
}
