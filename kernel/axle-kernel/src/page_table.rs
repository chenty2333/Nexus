use axle_page_table::{
    FlushOp, PageMapping, PageRange, PageTable, PageTableError, PageTableLock, ShootdownBatch,
};
use x86_64::PhysAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable as X86PageTable, PageTableFlags, PhysFrame, Size4KiB};

/// Concrete x86_64 page-table backing for one Axle address space.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UserPageTables {
    root_paddr: u64,
    pdpt_paddr: u64,
    user_pd_paddr: u64,
    user_pt_paddr: u64,
}

/// Locked transaction view over one concrete x86_64 user page-table set.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LockedUserPageTable {
    range: PageRange,
    tables: UserPageTables,
}

impl UserPageTables {
    /// Bind the bootstrap address space to the already-active PVH root and static user tables.
    pub(crate) fn bootstrap_current() -> Result<Self, PageTableError> {
        let (root_frame, _) = Cr3::read();
        let root_paddr = root_frame.start_address().as_u64();
        let pdpt_paddr = table(root_paddr)[0].addr().as_u64();
        Ok(Self {
            root_paddr,
            pdpt_paddr,
            user_pd_paddr: crate::userspace::bootstrap_user_pd_paddr(),
            user_pt_paddr: crate::userspace::bootstrap_user_pt_paddr(),
        })
    }

    /// Create one fresh address-space root by cloning current kernel mappings and
    /// installing a new user PD/PT subtree for the fixed bootstrap user window.
    pub(crate) fn clone_current_kernel_template() -> Result<Self, PageTableError> {
        let (current_root_frame, _) = Cr3::read();
        let current_root_paddr = current_root_frame.start_address().as_u64();
        let current_root = table(current_root_paddr);
        let current_pdpt_paddr = current_root[0].addr().as_u64();
        let current_pdpt = table(current_pdpt_paddr);

        let root_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;
        let pdpt_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;
        let user_pd_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;
        let user_pt_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;

        unsafe {
            // SAFETY: all page-table pages are allocated as page-sized, page-aligned, identity-
            // mapped kernel memory. Copying the current root and PDPT preserves kernel mappings.
            core::ptr::copy_nonoverlapping(
                current_root as *const X86PageTable,
                table_mut(root_paddr),
                1,
            );
            core::ptr::copy_nonoverlapping(
                current_pdpt as *const X86PageTable,
                table_mut(pdpt_paddr),
                1,
            );
        }

        let root_flags = current_root[0].flags();
        table_mut(root_paddr)[0].set_addr(PhysAddr::new(pdpt_paddr), root_flags);

        let user_table_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        table_mut(pdpt_paddr)[4].set_addr(PhysAddr::new(user_pd_paddr), user_table_flags);
        table_mut(user_pd_paddr)[0].set_addr(PhysAddr::new(user_pt_paddr), user_table_flags);

        Ok(Self {
            root_paddr,
            pdpt_paddr,
            user_pd_paddr,
            user_pt_paddr,
        })
    }

    pub(crate) const fn root_paddr(self) -> u64 {
        self.root_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn pdpt_paddr(self) -> u64 {
        self.pdpt_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn user_pd_paddr(self) -> u64 {
        self.user_pd_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn user_pt_paddr(self) -> u64 {
        self.user_pt_paddr
    }

    pub(crate) fn activate(self) -> Result<(), PageTableError> {
        let frame = frame(self.root_paddr)?;
        unsafe {
            // SAFETY: the root frame was either the currently loaded CR3 or one freshly
            // allocated/copy-initialized x86_64 page-table root with preserved kernel mappings.
            Cr3::write(frame, Cr3Flags::empty());
        }
        Ok(())
    }

    fn is_active(self) -> bool {
        let (frame, _) = Cr3::read();
        frame.start_address().as_u64() == self.root_paddr
    }

    fn entry(&self, va: u64) -> Result<&PageTableEntryAccessor, PageTableError> {
        let index = user_page_index(va)?;
        Ok(unsafe {
            // SAFETY: `user_pt_paddr` always points at one page-sized page table page owned by
            // this address space. The index is range-checked against the fixed user window.
            &*((&table(self.user_pt_paddr)[index]) as *const _ as *const PageTableEntryAccessor)
        })
    }

    fn entry_mut(&mut self, va: u64) -> Result<&mut PageTableEntryAccessor, PageTableError> {
        let index = user_page_index(va)?;
        Ok(unsafe {
            // SAFETY: `user_pt_paddr` always points at one page-sized page table page owned by
            // this address space. The index is range-checked against the fixed user window.
            &mut *((&mut table_mut(self.user_pt_paddr)[index]) as *mut _
                as *mut PageTableEntryAccessor)
        })
    }
}

impl PageTable for UserPageTables {
    type Lock<'a>
        = LockedUserPageTable
    where
        Self: 'a;

    fn lock(&mut self, range: PageRange) -> Result<Self::Lock<'_>, PageTableError> {
        Ok(LockedUserPageTable {
            range,
            tables: *self,
        })
    }
}

impl PageTableLock for LockedUserPageTable {
    fn range(&self) -> PageRange {
        self.range
    }

    fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
        let entry = self.tables.entry(va)?;
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(None);
        }
        PageMapping::new(
            entry.addr().as_u64(),
            entry.flags().contains(PageTableFlags::WRITABLE),
        )
        .map(Some)
    }

    fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError> {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if mapping.writable() {
            flags |= PageTableFlags::WRITABLE;
        }
        self.tables
            .entry_mut(va)?
            .set_addr(PhysAddr::new(mapping.paddr()), flags);
        Ok(())
    }

    fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError> {
        let entry = self.tables.entry_mut(va)?;
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Err(PageTableError::NotMapped);
        }
        entry.set_unused();
        Ok(())
    }

    fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError> {
        let entry = self.tables.entry_mut(va)?;
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Err(PageTableError::NotMapped);
        }
        let mut flags = entry.flags();
        if writable {
            flags |= PageTableFlags::WRITABLE;
        } else {
            flags.remove(PageTableFlags::WRITABLE);
        }
        entry.set_flags(flags);
        Ok(())
    }

    fn commit(self, shootdown: ShootdownBatch) -> Result<(), PageTableError> {
        if !self.tables.is_active() {
            return Ok(());
        }
        for op in shootdown.ops() {
            match *op {
                FlushOp::Page(va) => crate::arch::tlb::flush_page_global(va),
            }
        }
        Ok(())
    }
}

#[repr(transparent)]
struct PageTableEntryAccessor(PageTableEntry);

impl PageTableEntryAccessor {
    fn flags(&self) -> PageTableFlags {
        self.0.flags()
    }

    fn addr(&self) -> PhysAddr {
        self.0.addr()
    }

    fn set_addr(&mut self, addr: PhysAddr, flags: PageTableFlags) {
        self.0.set_addr(addr, flags);
    }

    fn set_flags(&mut self, flags: PageTableFlags) {
        self.0.set_flags(flags);
    }

    fn set_unused(&mut self) {
        self.0.set_unused();
    }
}

fn frame(paddr: u64) -> Result<PhysFrame<Size4KiB>, PageTableError> {
    PhysFrame::from_start_address(PhysAddr::new(paddr)).map_err(|_| PageTableError::InvalidArgs)
}

fn user_page_index(va: u64) -> Result<usize, PageTableError> {
    let base = crate::userspace::USER_CODE_VA;
    let len = crate::userspace::USER_REGION_BYTES;
    if va < base || va >= base.checked_add(len).ok_or(PageTableError::InvalidArgs)? {
        return Err(PageTableError::InvalidArgs);
    }
    if va & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
        return Err(PageTableError::InvalidArgs);
    }
    usize::try_from((va - base) / crate::userspace::USER_PAGE_BYTES)
        .map_err(|_| PageTableError::InvalidArgs)
}

fn table(paddr: u64) -> &'static X86PageTable {
    unsafe {
        // SAFETY: all page-table pages used here are kernel-owned, page-aligned, and identity
        // mapped. Callers only pass addresses that were either read from CR3/page-table entries
        // or allocated as dedicated page-table pages.
        &*(paddr as *const X86PageTable)
    }
}

fn table_mut(paddr: u64) -> &'static mut X86PageTable {
    unsafe {
        // SAFETY: all page-table pages used here are kernel-owned, page-aligned, and identity
        // mapped. Mutations are serialized by the kernel's transaction scaffolding.
        &mut *(paddr as *mut X86PageTable)
    }
}
