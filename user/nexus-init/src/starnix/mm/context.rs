use super::super::*;

#[derive(Clone, Copy)]
pub(in crate::starnix) enum LinuxMapBacking {
    Anonymous { vmo: zx_handle_t },
    File { vmo: zx_handle_t, offset: u64 },
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxMapEntry {
    pub(in crate::starnix) base: u64,
    pub(in crate::starnix) len: u64,
    pub(in crate::starnix) prot: u64,
    pub(in crate::starnix) flags: u64,
    pub(in crate::starnix) backing: LinuxMapBacking,
}

impl LinuxMapEntry {
    pub(in crate::starnix) fn is_private(self) -> bool {
        (self.flags & LINUX_MAP_PRIVATE) != 0
    }
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxProtectEntry {
    pub(in crate::starnix) base: u64,
    pub(in crate::starnix) len: u64,
    pub(in crate::starnix) prot: u64,
}

pub(in crate::starnix) struct LinuxMm {
    pub(in crate::starnix) root_vmar: zx_handle_t,
    pub(in crate::starnix) heap_vmar: zx_handle_t,
    pub(in crate::starnix) heap_base: u64,
    pub(in crate::starnix) heap_limit: u64,
    pub(in crate::starnix) heap_vmo: zx_handle_t,
    pub(in crate::starnix) heap_break: u64,
    pub(in crate::starnix) heap_mapped_len: u64,
    pub(in crate::starnix) mmap_vmar: zx_handle_t,
    pub(in crate::starnix) mmap_base: u64,
    pub(in crate::starnix) exec_tree: BTreeMap<u64, LinuxProtectEntry>,
    pub(in crate::starnix) map_tree: BTreeMap<u64, LinuxMapEntry>,
}

#[derive(Clone)]
pub(in crate::starnix) struct LinuxWritableRange {
    pub(in crate::starnix) base: u64,
    pub(in crate::starnix) len: u64,
}

impl ProcessResources {
    pub(in crate::starnix) fn brk(&mut self, addr: u64) -> Result<u64, zx_status_t> {
        Ok(self.mm.brk(addr))
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
        self.mm
            .mmap(&self.fs.fd_table, addr, len, prot, flags, fd, offset)
    }

    pub(in crate::starnix) fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
        self.mm.munmap(addr, len)
    }

    pub(in crate::starnix) fn mprotect(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, zx_status_t> {
        self.mm.mprotect(addr, len, prot)
    }

    pub(in crate::starnix) fn map_private_anon(
        &mut self,
        len: u64,
        prot: u64,
    ) -> Result<u64, zx_status_t> {
        let mapped = self.mm.mmap(
            &self.fs.fd_table,
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
        self.mm.install_exec_writable_ranges(writable_ranges)
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
