use super::super::*;
use super::context::{
    LinuxMapBacking, LinuxMapEntry, LinuxMm, LinuxProtectEntry, LinuxWritableRange,
};

impl LinuxMm {
    pub(in crate::starnix) fn install_exec_writable_ranges(
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

    pub(in crate::starnix) fn brk(&mut self, requested: u64) -> u64 {
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
            let map_options = ZX_VM_SPECIFIC | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | ZX_VM_CLONE_COW;
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
    pub(in crate::starnix) fn mmap(
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
        let mut private_file_shadow = false;
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
                let mut vmo_flags = nexus_io::VmoFlags::READ;
                if (prot & LINUX_PROT_EXEC) != 0 {
                    vmo_flags |= nexus_io::VmoFlags::EXECUTE;
                }
                vmo = match fd_table.as_vmo(fd, vmo_flags) {
                    Ok(vmo) => vmo,
                    Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
                };
                private_file_shadow = true;
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
        let mut map_options = if fixed {
            map_options | ZX_VM_SPECIFIC
        } else {
            map_options
        };
        if anonymous {
            map_options |= ZX_VM_CLONE_COW;
        } else if private_file_shadow {
            map_options |= ZX_VM_PRIVATE_CLONE | ZX_VM_CLONE_COW;
        } else if shared || private {
            map_options |= ZX_VM_CLONE_SHARE;
        }
        let status = zx_vmar_map_local(
            self.mmap_vmar,
            map_options,
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

        let map_base = if fixed { addr } else { mapped_addr };
        let backing = if anonymous {
            LinuxMapBacking::Anonymous { vmo }
        } else {
            let mut mapping_vmo = ZX_HANDLE_INVALID;
            let capture_status =
                ax_vmar_get_mapping_vmo_local(self.mmap_vmar, map_base, &mut mapping_vmo);
            if capture_status != ZX_OK {
                let _ = zx_vmar_unmap_local(self.mmap_vmar, map_base, aligned_len);
                let _ = zx_handle_close(vmo);
                return Ok(linux_errno(map_vm_status_to_errno(capture_status)));
            }
            let _ = zx_handle_close(vmo);
            if private_file_shadow {
                LinuxMapBacking::Anonymous { vmo: mapping_vmo }
            } else {
                LinuxMapBacking::File {
                    vmo: mapping_vmo,
                    offset,
                }
            }
        };

        self.map_tree.insert(
            map_base,
            LinuxMapEntry {
                base: map_base,
                len: aligned_len,
                prot,
                flags,
                backing,
            },
        );
        Ok(map_base)
    }

    pub(in crate::starnix) fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
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
                    duplicate_linux_map_backing(entry.backing, 0)?
                } else {
                    entry.backing
                };
                self.map_tree.insert(
                    entry.base,
                    LinuxMapEntry {
                        base: entry.base,
                        len: addr - entry.base,
                        prot: entry.prot,
                        flags: entry.flags,
                        backing,
                    },
                );
            }
            if keep_right {
                let right_delta = end.checked_sub(entry.base).ok_or(ZX_ERR_OUT_OF_RANGE)?;
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        flags: entry.flags,
                        backing: rebase_linux_map_backing(entry.backing, right_delta)?,
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

    pub(in crate::starnix) fn mprotect(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, zx_status_t> {
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
                        flags: entry.flags,
                        backing: duplicate_linux_map_backing(entry.backing, 0)?,
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
                    flags: entry.flags,
                    backing: entry.backing,
                },
            );
            if end < entry_end {
                let right_delta = end.checked_sub(entry.base).ok_or(ZX_ERR_OUT_OF_RANGE)?;
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        flags: entry.flags,
                        backing: duplicate_linux_map_backing(entry.backing, right_delta)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_exec_writable_ranges_resets_tree_and_skips_mmap_window() {
        let mut mm = LinuxMm::empty_for_tests();
        mm.mmap_base = 0x4000_0000;
        mm.exec_tree.insert(
            0x1000,
            LinuxProtectEntry {
                base: 0x1000,
                len: 0x1000,
                prot: LINUX_PROT_READ,
            },
        );
        mm.install_exec_writable_ranges(&[
            LinuxWritableRange {
                base: 0x2000,
                len: 0x3000,
            },
            LinuxWritableRange {
                base: 0x4000_1000,
                len: 0x2000,
            },
        ])
        .expect("install exec ranges");

        assert_eq!(mm.exec_tree.len(), 1);
        let entry = mm.exec_tree.get(&0x2000).expect("non-mmap exec range");
        assert_eq!(entry.base, 0x2000);
        assert_eq!(entry.len, 0x3000);
        assert_eq!(entry.prot, LINUX_PROT_READ | LINUX_PROT_WRITE);
    }
}

fn duplicate_linux_map_backing(
    backing: LinuxMapBacking,
    delta: u64,
) -> Result<LinuxMapBacking, zx_status_t> {
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
            offset: offset.checked_add(delta).ok_or(ZX_ERR_OUT_OF_RANGE)?,
        },
    })
}

fn rebase_linux_map_backing(
    backing: LinuxMapBacking,
    delta: u64,
) -> Result<LinuxMapBacking, zx_status_t> {
    Ok(match backing {
        LinuxMapBacking::Anonymous { vmo } => LinuxMapBacking::Anonymous { vmo },
        LinuxMapBacking::File { vmo, offset } => LinuxMapBacking::File {
            vmo,
            offset: offset.checked_add(delta).ok_or(ZX_ERR_OUT_OF_RANGE)?,
        },
    })
}

pub(in crate::starnix) fn map_linux_prot_to_vm_options(prot: u64) -> Result<u32, i32> {
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
