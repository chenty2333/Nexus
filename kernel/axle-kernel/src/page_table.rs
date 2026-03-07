extern crate alloc;

use alloc::sync::Arc;
use axle_page_table::{
    FlushOp, PageMapping, PageRange, PageTable, PageTableError, PageTableLock, ShootdownBatch,
};
use spin::Mutex;
use x86_64::PhysAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable as X86PageTable, PageTableFlags, PhysFrame, Size4KiB};

/// Fixed page-table level for one x86_64 page-table page descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PtPageLevel {
    /// PML4 root page.
    Pml4,
    /// First user-visible PDPT page.
    Pdpt,
    /// Fixed user-window PD page.
    Pd,
    /// Fixed user-window PT leaf page.
    Pt,
}

/// Current lock discipline for one page-table descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PtPageLockKind {
    /// Mutations are serialized by the surrounding transaction scaffolding.
    TxSerialized,
}

/// Metadata layout kind attached to one page-table descriptor.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PtMetaKind {
    /// No page-local metadata is attached to this descriptor yet.
    None,
    /// Entire covered subtree shares one uniform metadata template.
    Uniform(PtMetaTemplate),
    /// This descriptor is the fixed leaf PT that carries per-page metadata.
    Leaf,
}

/// Uniform metadata template for one fixed-shape page-table subtree.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PtMetaTemplate {
    present: bool,
    writable: bool,
    user_accessible: bool,
}

#[allow(dead_code)]
impl PtMetaTemplate {
    /// Whether every leaf entry in the covered subtree is present.
    pub(crate) const fn present(self) -> bool {
        self.present
    }

    /// Whether every leaf entry in the covered subtree is writable.
    pub(crate) const fn writable(self) -> bool {
        self.writable
    }

    /// Whether every leaf entry in the covered subtree is user accessible.
    pub(crate) const fn user_accessible(self) -> bool {
        self.user_accessible
    }
}

/// Fixed-shape descriptor for one concrete x86_64 page-table page.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PtPageDesc {
    level: PtPageLevel,
    table_paddr: u64,
    va_base: u64,
    lock_kind: PtPageLockKind,
    invalidate_epoch: u64,
    meta_kind: PtMetaKind,
}

#[allow(dead_code)]
impl PtPageDesc {
    /// Page-table level described by this descriptor.
    pub(crate) const fn level(self) -> PtPageLevel {
        self.level
    }

    /// Physical address of the concrete page-table page.
    pub(crate) const fn table_paddr(self) -> u64 {
        self.table_paddr
    }

    /// Lowest virtual address covered by this page-table page.
    pub(crate) const fn va_base(self) -> u64 {
        self.va_base
    }

    /// Current lock discipline for this page-table page.
    pub(crate) const fn lock_kind(self) -> PtPageLockKind {
        self.lock_kind
    }

    /// Most recent invalidation epoch recorded against this descriptor.
    pub(crate) const fn invalidate_epoch(self) -> u64 {
        self.invalidate_epoch
    }

    /// Current metadata attachment kind for this page-table page.
    pub(crate) const fn meta_kind(self) -> PtMetaKind {
        self.meta_kind
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserPageTableDescSet {
    root: PtPageDesc,
    pdpt: PtPageDesc,
    user_pd: PtPageDesc,
    user_pt: PtPageDesc,
}

#[allow(dead_code)]
impl UserPageTableDescSet {
    /// PML4 descriptor.
    pub(crate) const fn root(self) -> PtPageDesc {
        self.root
    }

    /// PDPT descriptor.
    pub(crate) const fn pdpt(self) -> PtPageDesc {
        self.pdpt
    }

    /// Fixed user-window PD descriptor.
    pub(crate) const fn user_pd(self) -> PtPageDesc {
        self.user_pd
    }

    /// Fixed user-window PT descriptor.
    pub(crate) const fn user_pt(self) -> PtPageDesc {
        self.user_pt
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct UserPageTableDescriptors {
    root: PtPageDesc,
    pdpt: PtPageDesc,
    user_pd: PtPageDesc,
    user_pt: PtPageDesc,
    next_invalidate_epoch: u64,
}

impl UserPageTableDescriptors {
    fn snapshot(&self) -> UserPageTableDescSet {
        UserPageTableDescSet {
            root: self.root,
            pdpt: self.pdpt,
            user_pd: self.user_pd,
            user_pt: self.user_pt,
        }
    }

    fn record_shootdown(&mut self, shootdown: &ShootdownBatch) {
        if shootdown.is_empty() {
            return;
        }
        let epoch = self.next_invalidate_epoch;
        self.next_invalidate_epoch = self.next_invalidate_epoch.wrapping_add(1);
        if shootdown
            .ops()
            .iter()
            .any(|op| matches!(*op, FlushOp::Page(_)))
        {
            self.user_pt.invalidate_epoch = epoch;
            self.user_pd.invalidate_epoch = epoch;
        }
    }

    fn refresh_uniform_metadata(&mut self, user_pt_paddr: u64) {
        let uniform = uniform_leaf_template(user_pt_paddr);
        self.user_pd.meta_kind = match uniform {
            Some(template) => PtMetaKind::Uniform(template),
            None => PtMetaKind::Leaf,
        };
        self.user_pt.meta_kind = match uniform {
            Some(template) => PtMetaKind::Uniform(template),
            None => PtMetaKind::Leaf,
        };
    }
}

/// Concrete x86_64 page-table backing for one Axle address space.
#[derive(Clone, Debug)]
pub(crate) struct UserPageTables {
    root_paddr: u64,
    pdpt_paddr: u64,
    user_pd_paddr: u64,
    user_pt_paddr: u64,
    descs: Arc<Mutex<UserPageTableDescriptors>>,
}

/// Locked transaction view over one concrete x86_64 user page-table set.
#[derive(Clone, Debug)]
pub(crate) struct LockedUserPageTable {
    range: PageRange,
    tables: UserPageTables,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageWalkIndices {
    pml4: usize,
    pdpt: usize,
    pd: usize,
    pt: usize,
}

impl UserPageTables {
    #[allow(dead_code)]
    fn descriptor_set(&self) -> UserPageTableDescSet {
        self.descs.lock().snapshot()
    }

    fn new_descriptors(
        root_paddr: u64,
        pdpt_paddr: u64,
        user_pd_paddr: u64,
        user_pt_paddr: u64,
    ) -> Arc<Mutex<UserPageTableDescriptors>> {
        let mut descs = UserPageTableDescriptors {
            root: PtPageDesc {
                level: PtPageLevel::Pml4,
                table_paddr: root_paddr,
                va_base: 0,
                lock_kind: PtPageLockKind::TxSerialized,
                invalidate_epoch: 0,
                meta_kind: PtMetaKind::None,
            },
            pdpt: PtPageDesc {
                level: PtPageLevel::Pdpt,
                table_paddr: pdpt_paddr,
                va_base: 0,
                lock_kind: PtPageLockKind::TxSerialized,
                invalidate_epoch: 0,
                meta_kind: PtMetaKind::None,
            },
            user_pd: PtPageDesc {
                level: PtPageLevel::Pd,
                table_paddr: user_pd_paddr,
                va_base: crate::userspace::USER_CODE_VA,
                lock_kind: PtPageLockKind::TxSerialized,
                invalidate_epoch: 0,
                meta_kind: PtMetaKind::None,
            },
            user_pt: PtPageDesc {
                level: PtPageLevel::Pt,
                table_paddr: user_pt_paddr,
                va_base: crate::userspace::USER_CODE_VA,
                lock_kind: PtPageLockKind::TxSerialized,
                invalidate_epoch: 0,
                meta_kind: PtMetaKind::Leaf,
            },
            next_invalidate_epoch: 1,
        };
        descs.refresh_uniform_metadata(user_pt_paddr);
        Arc::new(Mutex::new(descs))
    }

    /// Bind the bootstrap address space to the already-active PVH root and static user tables.
    pub(crate) fn bootstrap_current() -> Result<Self, PageTableError> {
        let (root_frame, _) = Cr3::read();
        let root_paddr = root_frame.start_address().as_u64();
        let pdpt_paddr = table(root_paddr)[0].addr().as_u64();
        let user_pd_paddr = crate::userspace::bootstrap_user_pd_paddr();
        let user_pt_paddr = crate::userspace::bootstrap_user_pt_paddr();
        Ok(Self {
            root_paddr,
            pdpt_paddr,
            user_pd_paddr,
            user_pt_paddr,
            descs: Self::new_descriptors(root_paddr, pdpt_paddr, user_pd_paddr, user_pt_paddr),
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
            descs: Self::new_descriptors(root_paddr, pdpt_paddr, user_pd_paddr, user_pt_paddr),
        })
    }

    #[allow(dead_code)]
    pub(crate) const fn root_paddr(&self) -> u64 {
        self.root_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn pdpt_paddr(&self) -> u64 {
        self.pdpt_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn user_pd_paddr(&self) -> u64 {
        self.user_pd_paddr
    }

    #[allow(dead_code)]
    pub(crate) const fn user_pt_paddr(&self) -> u64 {
        self.user_pt_paddr
    }

    #[allow(dead_code)]
    pub(crate) fn descriptors(&self) -> UserPageTableDescSet {
        self.descriptor_set()
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

    fn ensure_page_table_page(
        &mut self,
        parent_table_paddr: u64,
        index: usize,
    ) -> Result<u64, PageTableError> {
        let entry = &mut table_mut(parent_table_paddr)[index];
        if entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(entry.addr().as_u64());
        }

        let child_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;
        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        entry.set_addr(PhysAddr::new(child_paddr), flags);
        Ok(child_paddr)
    }

    fn leaf_table_paddr(&self, va: u64) -> Result<Option<u64>, PageTableError> {
        let indices = user_page_indices(va)?;
        let root_entry = &table(self.root_paddr)[indices.pml4];
        if !root_entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(None);
        }
        let pdpt_entry = &table(root_entry.addr().as_u64())[indices.pdpt];
        if !pdpt_entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(None);
        }
        let pd_entry = &table(pdpt_entry.addr().as_u64())[indices.pd];
        if !pd_entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(None);
        }
        Ok(Some(pd_entry.addr().as_u64()))
    }

    fn ensure_leaf_table_paddr(&mut self, va: u64) -> Result<u64, PageTableError> {
        let indices = user_page_indices(va)?;
        let root_paddr = self.root_paddr;
        let pdpt_paddr = self.ensure_page_table_page(root_paddr, indices.pml4)?;
        let pd_paddr = self.ensure_page_table_page(pdpt_paddr, indices.pdpt)?;
        let pt_paddr = self.ensure_page_table_page(pd_paddr, indices.pd)?;
        if pd_paddr == self.user_pd_paddr && indices.pd == 0 {
            self.user_pt_paddr = pt_paddr;
        }
        Ok(pt_paddr)
    }

    fn entry_mut(&mut self, va: u64) -> Result<&mut PageTableEntryAccessor, PageTableError> {
        let indices = user_page_indices(va)?;
        let pt_paddr = self.ensure_leaf_table_paddr(va)?;
        Ok(unsafe {
            // SAFETY: `pt_paddr` points at one page-sized PT page owned by this address space.
            &mut *((&mut table_mut(pt_paddr)[indices.pt]) as *mut _ as *mut PageTableEntryAccessor)
        })
    }

    fn existing_entry_mut(
        &mut self,
        va: u64,
    ) -> Result<Option<&mut PageTableEntryAccessor>, PageTableError> {
        let indices = user_page_indices(va)?;
        let Some(pt_paddr) = self.leaf_table_paddr(va)? else {
            return Ok(None);
        };
        Ok(Some(unsafe {
            // SAFETY: `pt_paddr` points at an existing PT page reached through present ancestors.
            &mut *((&mut table_mut(pt_paddr)[indices.pt]) as *mut _ as *mut PageTableEntryAccessor)
        }))
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
            tables: self.clone(),
        })
    }
}

impl PageTableLock for LockedUserPageTable {
    fn range(&self) -> PageRange {
        self.range
    }

    fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
        let indices = user_page_indices(va)?;
        let Some(pt_paddr) = self.tables.leaf_table_paddr(va)? else {
            return Ok(None);
        };
        let entry = &table(pt_paddr)[indices.pt];
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
        let Some(entry) = self.tables.existing_entry_mut(va)? else {
            return Err(PageTableError::NotMapped);
        };
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Err(PageTableError::NotMapped);
        }
        entry.set_unused();
        Ok(())
    }

    fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError> {
        let Some(entry) = self.tables.existing_entry_mut(va)? else {
            return Err(PageTableError::NotMapped);
        };
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
        {
            let mut descs = self.tables.descs.lock();
            descs.record_shootdown(&shootdown);
            descs.refresh_uniform_metadata(self.tables.user_pt_paddr);
        }
        if !self.tables.is_active() {
            return Ok(());
        }
        for op in shootdown.ops() {
            match *op {
                FlushOp::Page(va) => crate::arch::tlb::flush_page_local(va),
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

fn uniform_leaf_template(user_pt_paddr: u64) -> Option<PtMetaTemplate> {
    let table = table(user_pt_paddr);
    let mut entries = table.iter();
    let first = entries.next()?;
    let template = entry_meta_template(first);
    entries
        .all(|entry| entry_meta_template(entry) == template)
        .then_some(template)
}

fn entry_meta_template(entry: &PageTableEntry) -> PtMetaTemplate {
    let flags = entry.flags();
    PtMetaTemplate {
        present: flags.contains(PageTableFlags::PRESENT),
        writable: flags.contains(PageTableFlags::WRITABLE),
        user_accessible: flags.contains(PageTableFlags::USER_ACCESSIBLE),
    }
}

fn user_page_indices(va: u64) -> Result<PageWalkIndices, PageTableError> {
    let base = crate::userspace::USER_CODE_VA;
    let len = crate::userspace::USER_REGION_BYTES;
    if va < base || va >= base.checked_add(len).ok_or(PageTableError::InvalidArgs)? {
        return Err(PageTableError::InvalidArgs);
    }
    if va & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
        return Err(PageTableError::InvalidArgs);
    }
    Ok(PageWalkIndices {
        pml4: ((va >> 39) & 0x1ff) as usize,
        pdpt: ((va >> 30) & 0x1ff) as usize,
        pd: ((va >> 21) & 0x1ff) as usize,
        pt: ((va >> 12) & 0x1ff) as usize,
    })
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
