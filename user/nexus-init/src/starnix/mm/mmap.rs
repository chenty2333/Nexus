use super::super::*;

#[derive(Clone, Copy)]
pub(in crate::starnix) enum LinuxMapBacking {
    Anonymous { vmo: zx_handle_t },
    File { vmo: zx_handle_t, offset: u64 },
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxMapEntry {
    base: u64,
    len: u64,
    prot: u64,
    backing: LinuxMapBacking,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxProtectEntry {
    base: u64,
    len: u64,
    prot: u64,
}

pub(in crate::starnix) struct LinuxMm {
    root_vmar: zx_handle_t,
    heap_vmar: zx_handle_t,
    heap_base: u64,
    heap_limit: u64,
    heap_vmo: zx_handle_t,
    heap_break: u64,
    heap_mapped_len: u64,
    mmap_vmar: zx_handle_t,
    mmap_base: u64,
    exec_tree: BTreeMap<u64, LinuxProtectEntry>,
    map_tree: BTreeMap<u64, LinuxMapEntry>,
}

#[derive(Clone)]
pub(in crate::starnix) struct LinuxWritableRange {
    pub(in crate::starnix) base: u64,
    pub(in crate::starnix) len: u64,
}

impl ExecutiveState {
    pub(in crate::starnix) fn brk(&mut self, addr: u64) -> Result<u64, zx_status_t> {
        Ok(self.linux_mm.brk(addr))
    }

    pub(in crate::starnix) fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i32,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        self.linux_mm
            .mmap(&self.fd_table, addr, len, prot, flags, fd, offset)
    }

    pub(in crate::starnix) fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
        self.linux_mm.munmap(addr, len)
    }

    pub(in crate::starnix) fn mprotect(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, zx_status_t> {
        self.linux_mm.mprotect(addr, len, prot)
    }

    pub(in crate::starnix) fn map_private_anon(
        &mut self,
        len: u64,
        prot: u64,
    ) -> Result<u64, zx_status_t> {
        let mapped = self.linux_mm.mmap(
            &self.fd_table,
            0,
            len,
            prot,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            -1,
            0,
        )?;
        if (mapped as i64) < 0 {
            return Err(ZX_ERR_BAD_STATE);
        }
        Ok(mapped)
    }

    pub(in crate::starnix) fn install_exec_writable_ranges(
        &mut self,
        writable_ranges: &[LinuxWritableRange],
    ) -> Result<(), zx_status_t> {
        self.linux_mm.install_exec_writable_ranges(writable_ranges)
    }
}

impl Drop for LinuxMm {
    fn drop(&mut self) {
        for entry in self.map_tree.values() {
            let handle = match entry.backing {
                LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
            };
            if handle != ZX_HANDLE_INVALID {
                let _ = zx_handle_close(handle);
            }
        }
        for handle in [
            self.heap_vmo,
            self.heap_vmar,
            self.mmap_vmar,
            self.root_vmar,
        ] {
            if handle != ZX_HANDLE_INVALID {
                let _ = zx_handle_close(handle);
            }
        }
    }
}

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
                            backing: LinuxMapBacking::Anonymous { vmo: child_vmo },
                        },
                    );
                }
                LinuxMapBacking::File { vmo, offset } => {
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

    fn install_exec_writable_ranges(
        &mut self,
        writable_ranges: &[LinuxWritableRange],
    ) -> Result<(), zx_status_t> {
        self.exec_tree.clear();
        let mmap_end = self
            .mmap_base
            .checked_add(LINUX_MMAP_REGION_BYTES)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        for range in writable_ranges {
            let range_end = range
                .base
                .checked_add(range.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if range.base >= self.mmap_base && range_end <= mmap_end {
                continue;
            }
            self.exec_tree.insert(
                range.base,
                LinuxProtectEntry {
                    base: range.base,
                    len: range.len,
                    prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
                },
            );
        }
        Ok(())
    }

    fn brk(&mut self, requested: u64) -> u64 {
        if requested == 0 {
            return self.heap_break;
        }
        if requested < self.heap_base || requested > self.heap_limit {
            return self.heap_break;
        }
        let Some(target_mapped_len) =
            align_up_u64(requested.saturating_sub(self.heap_base), USER_PAGE_BYTES)
        else {
            return self.heap_break;
        };
        if target_mapped_len > LINUX_HEAP_VMO_BYTES {
            return self.heap_break;
        }

        if target_mapped_len > self.heap_mapped_len {
            let delta = target_mapped_len - self.heap_mapped_len;
            let heap_offset = self.heap_mapped_len;
            let map_options = ZX_VM_SPECIFIC | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE;
            let mut mapped_addr = 0u64;
            let status = zx_vmar_map_local(
                self.heap_vmar,
                map_options,
                heap_offset,
                self.heap_vmo,
                heap_offset,
                delta,
                &mut mapped_addr,
            );
            if status != ZX_OK {
                return self.heap_break;
            }
        } else if target_mapped_len < self.heap_mapped_len {
            let new_end = self.heap_base + target_mapped_len;
            let delta = self.heap_mapped_len - target_mapped_len;
            let status = zx_vmar_unmap_local(self.heap_vmar, new_end, delta);
            if status != ZX_OK {
                return self.heap_break;
            }
        }

        self.heap_mapped_len = target_mapped_len;
        self.heap_break = requested;
        requested
    }

    #[allow(clippy::too_many_arguments)]
    fn mmap(
        &mut self,
        fd_table: &FdTable,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i32,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        if len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_ENOMEM));
        };
        let map_options = match map_linux_prot_to_vm_options(prot) {
            Ok(options) => options,
            Err(errno) => return Ok(linux_errno(errno)),
        };
        let shared = (flags & LINUX_MAP_SHARED) != 0;
        let private = (flags & LINUX_MAP_PRIVATE) != 0;
        if shared == private {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let anonymous = (flags & LINUX_MAP_ANONYMOUS) != 0;
        let fixed = (flags & LINUX_MAP_FIXED) != 0;
        let end = addr.checked_add(aligned_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if fixed {
            if !addr.is_multiple_of(USER_PAGE_BYTES) {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            let mmap_end = self
                .mmap_base
                .checked_add(LINUX_MMAP_REGION_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if addr < self.mmap_base || end > mmap_end {
                return Ok(linux_errno(LINUX_ENOMEM));
            }
            if self.covered_mappings(addr, end)?.is_some() {
                let result = self.munmap(addr, aligned_len)?;
                if result != 0 {
                    return Ok(result);
                }
            }
        }

        let mut vmo = ZX_HANDLE_INVALID;
        let mut private_file_copy = false;
        let mut map_vmo_offset = offset;
        if anonymous {
            if fd != -1 || offset != 0 {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            let status = zx_vmo_create(aligned_len, 0, &mut vmo);
            if status != ZX_OK {
                return Ok(linux_errno(map_vm_status_to_errno(status)));
            }
            map_vmo_offset = 0;
        } else {
            if !offset.is_multiple_of(USER_PAGE_BYTES) {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            if private && (prot & LINUX_PROT_WRITE) != 0 {
                let source_vmo = match fd_table.as_vmo(fd, nexus_io::VmoFlags::READ) {
                    Ok(vmo) => vmo,
                    Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
                };
                let status = zx_vmo_create(aligned_len, 0, &mut vmo);
                if status != ZX_OK {
                    let _ = zx_handle_close(source_vmo);
                    return Ok(linux_errno(map_vm_status_to_errno(status)));
                }
                let mut bytes = Vec::new();
                if bytes
                    .try_reserve_exact(
                        usize::try_from(aligned_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    )
                    .is_err()
                {
                    let _ = zx_handle_close(source_vmo);
                    let _ = zx_handle_close(vmo);
                    return Ok(linux_errno(LINUX_ENOMEM));
                }
                bytes.resize(
                    usize::try_from(aligned_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    0,
                );
                let read_status = zx_vmo_read(source_vmo, &mut bytes, offset);
                let _ = zx_handle_close(source_vmo);
                if read_status != ZX_OK {
                    let _ = zx_handle_close(vmo);
                    return Ok(linux_errno(map_vm_status_to_errno(read_status)));
                }
                let write_status = zx_vmo_write(vmo, &bytes, 0);
                if write_status != ZX_OK {
                    let _ = zx_handle_close(vmo);
                    return Ok(linux_errno(map_vm_status_to_errno(write_status)));
                }
                private_file_copy = true;
                map_vmo_offset = 0;
            } else {
                if (prot & LINUX_PROT_WRITE) != 0 {
                    return Ok(linux_errno(LINUX_EACCES));
                }
                let mut vmo_flags = nexus_io::VmoFlags::READ;
                if (prot & LINUX_PROT_EXEC) != 0 {
                    vmo_flags |= nexus_io::VmoFlags::EXECUTE;
                }
                vmo = match fd_table.as_vmo(fd, vmo_flags) {
                    Ok(vmo) => vmo,
                    Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
                };
            }
        }

        let mut mapped_addr = 0u64;
        let status = zx_vmar_map_local(
            self.mmap_vmar,
            if fixed {
                map_options | ZX_VM_SPECIFIC
            } else {
                map_options
            },
            if fixed {
                addr.checked_sub(self.mmap_base)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?
            } else {
                0
            },
            vmo,
            map_vmo_offset,
            aligned_len,
            &mut mapped_addr,
        );
        if status != ZX_OK {
            let _ = zx_handle_close(vmo);
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }

        self.map_tree.insert(
            if fixed { addr } else { mapped_addr },
            LinuxMapEntry {
                base: if fixed { addr } else { mapped_addr },
                len: aligned_len,
                prot,
                backing: if anonymous || private_file_copy {
                    LinuxMapBacking::Anonymous { vmo }
                } else {
                    LinuxMapBacking::File { vmo, offset }
                },
            },
        );
        Ok(if fixed { addr } else { mapped_addr })
    }

    fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
        if !addr.is_multiple_of(USER_PAGE_BYTES) || len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let end = addr.checked_add(aligned_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let Some(overlaps) = self.covered_mappings(addr, end)? else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let status = zx_vmar_unmap_local(self.mmap_vmar, addr, aligned_len);
        if status != ZX_OK {
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }
        for entry in overlaps {
            let _ = self.map_tree.remove(&entry.base);
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let keep_left = entry.base < addr;
            let keep_right = end < entry_end;
            if keep_left {
                let backing = if keep_right {
                    duplicate_linux_map_backing(entry.backing)?
                } else {
                    entry.backing
                };
                self.map_tree.insert(
                    entry.base,
                    LinuxMapEntry {
                        base: entry.base,
                        len: addr - entry.base,
                        prot: entry.prot,
                        backing,
                    },
                );
            }
            if keep_right {
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        backing: entry.backing,
                    },
                );
            }
            if !keep_left && !keep_right {
                let handle = match entry.backing {
                    LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
                };
                let _ = zx_handle_close(handle);
            }
        }
        Ok(0)
    }

    fn mprotect(&mut self, addr: u64, len: u64, prot: u64) -> Result<u64, zx_status_t> {
        if !addr.is_multiple_of(USER_PAGE_BYTES) || len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let map_options = match map_linux_prot_to_vm_options(prot) {
            Ok(options) => options,
            Err(errno) => return Ok(linux_errno(errno)),
        };
        let end = addr.checked_add(aligned_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if addr >= self.heap_base && end <= self.heap_base + self.heap_mapped_len {
            let status = zx_vmar_protect_local(self.heap_vmar, map_options, addr, aligned_len);
            return Ok(if status == ZX_OK {
                0
            } else {
                linux_errno(map_vm_status_to_errno(status))
            });
        }
        if let Some(overlaps) = self.covered_exec_mappings(addr, end)? {
            let status = zx_vmar_protect_local(self.root_vmar, map_options, addr, aligned_len);
            if status != ZX_OK {
                return Ok(linux_errno(map_vm_status_to_errno(status)));
            }
            for entry in overlaps {
                let _ = self.exec_tree.remove(&entry.base);
                let entry_end = entry
                    .base
                    .checked_add(entry.len)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?;
                if entry.base < addr {
                    self.exec_tree.insert(
                        entry.base,
                        LinuxProtectEntry {
                            base: entry.base,
                            len: addr - entry.base,
                            prot: entry.prot,
                        },
                    );
                }
                let protected_end = end.min(entry_end);
                let protected_start = addr.max(entry.base);
                self.exec_tree.insert(
                    protected_start,
                    LinuxProtectEntry {
                        base: protected_start,
                        len: protected_end - protected_start,
                        prot,
                    },
                );
                if end < entry_end {
                    self.exec_tree.insert(
                        end,
                        LinuxProtectEntry {
                            base: end,
                            len: entry_end - end,
                            prot: entry.prot,
                        },
                    );
                }
            }
            return Ok(0);
        }
        let Some(overlaps) = self.covered_mappings(addr, end)? else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let status = zx_vmar_protect_local(self.mmap_vmar, map_options, addr, aligned_len);
        if status != ZX_OK {
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }
        for entry in overlaps {
            let _ = self.map_tree.remove(&entry.base);
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if entry.base < addr {
                self.map_tree.insert(
                    entry.base,
                    LinuxMapEntry {
                        base: entry.base,
                        len: addr - entry.base,
                        prot: entry.prot,
                        backing: duplicate_linux_map_backing(entry.backing)?,
                    },
                );
            }
            let protected_end = end.min(entry_end);
            let protected_start = addr.max(entry.base);
            self.map_tree.insert(
                protected_start,
                LinuxMapEntry {
                    base: protected_start,
                    len: protected_end - protected_start,
                    prot,
                    backing: entry.backing,
                },
            );
            if end < entry_end {
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        backing: duplicate_linux_map_backing(entry.backing)?,
                    },
                );
            }
        }
        Ok(0)
    }

    fn covered_mappings(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<Option<Vec<LinuxMapEntry>>, zx_status_t> {
        let mut overlaps = Vec::new();
        let mut cursor = addr;

        if let Some((_, entry)) = self.map_tree.range(..=addr).next_back() {
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if addr < entry_end {
                overlaps.push(*entry);
                cursor = entry_end;
            }
        }

        for (_, entry) in self.map_tree.range(addr..) {
            if entry.base >= end {
                break;
            }
            if entry.base > cursor {
                return Ok(None);
            }
            if overlaps
                .last()
                .map(|last| last.base != entry.base)
                .unwrap_or(true)
            {
                overlaps.push(*entry);
            }
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if entry_end > cursor {
                cursor = entry_end;
            }
            if cursor >= end {
                return Ok(Some(overlaps));
            }
        }

        if cursor >= end {
            Ok(Some(overlaps))
        } else {
            Ok(None)
        }
    }

    fn covered_exec_mappings(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<Option<Vec<LinuxProtectEntry>>, zx_status_t> {
        let mut overlaps = Vec::new();
        let mut cursor = addr;

        if let Some((_, entry)) = self.exec_tree.range(..=addr).next_back() {
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if addr < entry_end {
                overlaps.push(*entry);
                cursor = entry_end;
            }
        }

        for (_, entry) in self.exec_tree.range(addr..) {
            if entry.base >= end {
                break;
            }
            if entry.base > cursor {
                return Ok(None);
            }
            if overlaps
                .last()
                .map(|last| last.base != entry.base)
                .unwrap_or(true)
            {
                overlaps.push(*entry);
            }
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if entry_end > cursor {
                cursor = entry_end;
            }
            if cursor >= end {
                return Ok(Some(overlaps));
            }
        }

        if cursor >= end {
            Ok(Some(overlaps))
        } else {
            Ok(None)
        }
    }
}

fn duplicate_linux_map_backing(backing: LinuxMapBacking) -> Result<LinuxMapBacking, zx_status_t> {
    let handle = match backing {
        LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
    };
    let mut duplicated = ZX_HANDLE_INVALID;
    zx_status_result(zx_handle_duplicate(
        handle,
        ZX_RIGHT_SAME_RIGHTS,
        &mut duplicated,
    ))?;
    Ok(match backing {
        LinuxMapBacking::Anonymous { .. } => LinuxMapBacking::Anonymous { vmo: duplicated },
        LinuxMapBacking::File { offset, .. } => LinuxMapBacking::File {
            vmo: duplicated,
            offset,
        },
    })
}

fn allocate_child_vmar(
    parent_vmar: zx_handle_t,
    options: u32,
    size: u64,
) -> Result<(zx_handle_t, u64), zx_status_t> {
    let mut child_vmar = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(
        parent_vmar,
        options,
        0,
        size,
        &mut child_vmar,
        &mut child_addr,
    );
    if status == ZX_OK {
        Ok((child_vmar, child_addr))
    } else {
        Err(status)
    }
}

fn allocate_child_vmar_fixed(
    parent_vmar: zx_handle_t,
    options: u32,
    base: u64,
    size: u64,
) -> Result<zx_handle_t, zx_status_t> {
    let offset = base.checked_sub(USER_CODE_VA).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut child_vmar = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(
        parent_vmar,
        options,
        offset,
        size,
        &mut child_vmar,
        &mut child_addr,
    );
    if status != ZX_OK {
        return Err(status);
    }
    if child_addr != base {
        let _ = zx_handle_close(child_vmar);
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(child_vmar)
}

fn map_linux_prot_to_vm_options(prot: u64) -> Result<u32, i32> {
    if prot == 0 || (prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC)) != 0 {
        return Err(LINUX_EINVAL);
    }
    let mut options = ZX_VM_PERM_READ;
    if (prot & LINUX_PROT_WRITE) != 0 {
        options |= ZX_VM_PERM_WRITE;
    }
    if (prot & LINUX_PROT_EXEC) != 0 {
        options |= ZX_VM_PERM_EXECUTE;
    }
    Ok(options)
}
