use super::super::*;
use super::context::{LinuxMapBacking, LinuxMapEntry, LinuxMm};

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
        zx_status_result(ax_vmar_clone_mappings_local(
            self.root_vmar,
            child_root_vmar,
        ))?;
        zx_status_result(ax_vmar_clone_mappings_local(self.heap_vmar, heap_vmar))?;
        zx_status_result(ax_vmar_clone_mappings_local(self.mmap_vmar, mmap_vmar))?;
        let child_heap_vmo = if self.heap_mapped_len == 0 {
            let mut child_heap_vmo = ZX_HANDLE_INVALID;
            zx_status_result(zx_vmo_create(LINUX_HEAP_VMO_BYTES, 0, &mut child_heap_vmo))?;
            child_heap_vmo
        } else {
            capture_mapping_vmo(heap_vmar, self.heap_base)?
        };

        let exec_tree = self.exec_tree.clone();
        let mut map_tree = BTreeMap::new();
        for entry in self.map_tree.values() {
            let child_vmo = capture_mapping_vmo(mmap_vmar, entry.base)?;
            let backing = match entry.backing {
                LinuxMapBacking::Anonymous { .. } => LinuxMapBacking::Anonymous { vmo: child_vmo },
                LinuxMapBacking::File { offset, .. } => LinuxMapBacking::File {
                    vmo: child_vmo,
                    offset,
                },
            };
            map_tree.insert(
                entry.base,
                LinuxMapEntry {
                    base: entry.base,
                    len: entry.len,
                    prot: entry.prot,
                    flags: entry.flags,
                    backing,
                },
            );
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

fn capture_mapping_vmo(vmar: zx_handle_t, addr: u64) -> Result<zx_handle_t, zx_status_t> {
    let mut vmo = ZX_HANDLE_INVALID;
    zx_status_result(ax_vmar_get_mapping_vmo_local(vmar, addr, &mut vmo))?;
    Ok(vmo)
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
