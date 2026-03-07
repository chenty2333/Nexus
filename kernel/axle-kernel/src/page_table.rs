extern crate alloc;

use alloc::collections::BTreeSet;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PtPageLevel {
    /// PML4 root page.
    Pml4,
    /// One PDPT page in the user half.
    Pdpt,
    /// One PD page in the user half.
    Pd,
    /// One PT leaf page in the user half.
    Pt,
}

impl PtPageLevel {
    const fn child_level(self) -> Option<Self> {
        match self {
            Self::Pml4 => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pd => Some(Self::Pt),
            Self::Pt => None,
        }
    }

    const fn child_coverage_bytes(self) -> u64 {
        match self {
            Self::Pml4 => 1_u64 << 39,
            Self::Pdpt => 1_u64 << 30,
            Self::Pd => 1_u64 << 21,
            Self::Pt => axle_page_table::PAGE_SIZE,
        }
    }
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
    /// This descriptor is one leaf PT page that carries per-page metadata.
    Leaf,
}

/// Uniform metadata template for one page-table subtree.
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

/// Descriptor for one concrete x86_64 page-table page.
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

    /// Bootstrap user PD descriptor snapshot.
    pub(crate) const fn user_pd(self) -> PtPageDesc {
        self.user_pd
    }

    /// Bootstrap user PT descriptor snapshot.
    pub(crate) const fn user_pt(self) -> PtPageDesc {
        self.user_pt
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct PtDescriptorStore {
    by_key: alloc::collections::BTreeMap<(PtPageLevel, u64), PtPageDesc>,
    by_table_paddr: alloc::collections::BTreeMap<u64, (PtPageLevel, u64)>,
    next_invalidate_epoch: u64,
}

impl PtDescriptorStore {
    fn snapshot(&self) -> UserPageTableDescSet {
        let user_pd_base = align_down_level(crate::userspace::USER_CODE_VA, PtPageLevel::Pd);
        let user_pt_base = align_down_level(crate::userspace::USER_CODE_VA, PtPageLevel::Pt);
        UserPageTableDescSet {
            root: self
                .descriptor(PtPageLevel::Pml4, 0)
                .expect("root descriptor must exist"),
            pdpt: self
                .descriptor(PtPageLevel::Pdpt, 0)
                .expect("bootstrap pdpt descriptor must exist"),
            user_pd: self
                .descriptor(PtPageLevel::Pd, user_pd_base)
                .expect("bootstrap user PD descriptor must exist"),
            user_pt: self
                .descriptor(PtPageLevel::Pt, user_pt_base)
                .expect("bootstrap user PT descriptor must exist"),
        }
    }

    fn record_shootdown(&mut self, shootdown: &ShootdownBatch) {
        if shootdown.is_empty() {
            return;
        }
        let epoch = self.next_invalidate_epoch;
        self.next_invalidate_epoch = self.next_invalidate_epoch.wrapping_add(1);
        for op in shootdown.ops() {
            match *op {
                FlushOp::Page(va) => {
                    let pt_base = align_down_level(va, PtPageLevel::Pt);
                    let pd_base = align_down_level(va, PtPageLevel::Pd);
                    self.update_invalidate_epoch(PtPageLevel::Pt, pt_base, epoch);
                    self.update_invalidate_epoch(PtPageLevel::Pd, pd_base, epoch);
                }
            }
        }
    }

    fn upsert_descriptor(&mut self, desc: PtPageDesc) {
        self.by_key.insert((desc.level, desc.va_base), desc);
        self.by_table_paddr
            .insert(desc.table_paddr, (desc.level, desc.va_base));
    }

    fn descriptor(&self, level: PtPageLevel, va_base: u64) -> Option<PtPageDesc> {
        self.by_key.get(&(level, va_base)).copied()
    }

    fn descriptor_by_table_paddr(&self, table_paddr: u64) -> Option<PtPageDesc> {
        let &(level, va_base) = self.by_table_paddr.get(&table_paddr)?;
        self.descriptor(level, va_base)
    }

    fn update_invalidate_epoch(&mut self, level: PtPageLevel, va_base: u64, epoch: u64) {
        if let Some(desc) = self.by_key.get_mut(&(level, va_base)) {
            desc.invalidate_epoch = epoch;
        }
    }

    fn max_invalidate_epoch(&self) -> u64 {
        self.by_key
            .values()
            .map(|desc| desc.invalidate_epoch)
            .max()
            .unwrap_or(0)
    }

    fn refresh_uniform_metadata_for_leaf(&mut self, leaf_table_paddr: u64) {
        let Some(leaf_desc) = self.descriptor_by_table_paddr(leaf_table_paddr) else {
            return;
        };
        let Some(level) = Some(leaf_desc.level) else {
            return;
        };
        if level != PtPageLevel::Pt {
            return;
        }
        let uniform = uniform_leaf_template(leaf_table_paddr);
        let mut leaf_updated = leaf_desc;
        leaf_updated.meta_kind = match uniform {
            Some(template) => PtMetaKind::Uniform(template),
            None => PtMetaKind::Leaf,
        };
        self.upsert_descriptor(leaf_updated);

        let parent_va_base = align_down_level(leaf_desc.va_base, PtPageLevel::Pd);
        let mut parent = match self.descriptor(PtPageLevel::Pd, parent_va_base) {
            Some(parent) => parent,
            None => return,
        };
        parent.meta_kind = match self.uniform_template_for_pd(parent_va_base) {
            Some(template) => PtMetaKind::Uniform(template),
            None => PtMetaKind::Leaf,
        };
        self.upsert_descriptor(parent);
    }

    fn uniform_template_for_pd(&self, pd_va_base: u64) -> Option<PtMetaTemplate> {
        let mut template: Option<PtMetaTemplate> = None;
        for slot in 0..512_u64 {
            let child_va_base = pd_va_base + slot * PtPageLevel::Pd.child_coverage_bytes();
            let child_meta = match self.descriptor(PtPageLevel::Pt, child_va_base) {
                Some(desc) => match desc.meta_kind {
                    PtMetaKind::Uniform(template) => template,
                    _ => return None,
                },
                None => PtMetaTemplate {
                    present: false,
                    writable: false,
                    user_accessible: true,
                },
            };
            match template {
                Some(current) if current != child_meta => return None,
                Some(_) => {}
                None => template = Some(child_meta),
            }
        }
        template
    }
}

/// Concrete x86_64 page-table backing for one Axle address space.
#[derive(Clone, Debug)]
pub(crate) struct UserPageTables {
    root_paddr: u64,
    pdpt_paddr: u64,
    user_pd_paddr: u64,
    user_pt_paddr: u64,
    descs: Arc<Mutex<PtDescriptorStore>>,
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
    ) -> Arc<Mutex<PtDescriptorStore>> {
        let mut descs = PtDescriptorStore {
            by_key: alloc::collections::BTreeMap::new(),
            by_table_paddr: alloc::collections::BTreeMap::new(),
            next_invalidate_epoch: 1,
        };
        descs.upsert_descriptor(PtPageDesc {
            level: PtPageLevel::Pml4,
            table_paddr: root_paddr,
            va_base: 0,
            lock_kind: PtPageLockKind::TxSerialized,
            invalidate_epoch: 0,
            meta_kind: PtMetaKind::None,
        });
        descs.upsert_descriptor(PtPageDesc {
            level: PtPageLevel::Pdpt,
            table_paddr: pdpt_paddr,
            va_base: 0,
            lock_kind: PtPageLockKind::TxSerialized,
            invalidate_epoch: 0,
            meta_kind: PtMetaKind::None,
        });
        descs.upsert_descriptor(PtPageDesc {
            level: PtPageLevel::Pd,
            table_paddr: user_pd_paddr,
            va_base: align_down_level(crate::userspace::USER_CODE_VA, PtPageLevel::Pd),
            lock_kind: PtPageLockKind::TxSerialized,
            invalidate_epoch: 0,
            meta_kind: PtMetaKind::Leaf,
        });
        descs.upsert_descriptor(PtPageDesc {
            level: PtPageLevel::Pt,
            table_paddr: user_pt_paddr,
            va_base: align_down_level(crate::userspace::USER_CODE_VA, PtPageLevel::Pt),
            lock_kind: PtPageLockKind::TxSerialized,
            invalidate_epoch: 0,
            meta_kind: PtMetaKind::Leaf,
        });
        descs.refresh_uniform_metadata_for_leaf(user_pt_paddr);
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
    /// installing one bootstrap user PD/PT anchor under the wider logical user window.
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

    pub(crate) fn descriptor(&self, level: PtPageLevel, va_base: u64) -> Option<PtPageDesc> {
        self.descs.lock().descriptor(level, va_base)
    }

    pub(crate) fn max_invalidate_epoch(&self) -> u64 {
        self.descs.lock().max_invalidate_epoch()
    }

    pub(crate) fn validate_descriptor_metadata_range(&self, base: u64, len: u64) -> bool {
        let Ok(range) = PageRange::new(base, len) else {
            return false;
        };
        let mut leaf_bases = BTreeSet::new();
        let mut va = range.base();
        while va < range.end() {
            leaf_bases.insert(align_down_level(va, PtPageLevel::Pt));
            let Some(next_va) = va.checked_add(axle_page_table::PAGE_SIZE) else {
                return false;
            };
            va = next_va;
        }

        let descs = self.descs.lock();
        let mut pd_bases = BTreeSet::new();
        for leaf_base in leaf_bases {
            let Some(leaf_desc) = descs.descriptor(PtPageLevel::Pt, leaf_base) else {
                continue;
            };
            let expected_leaf = match uniform_leaf_template(leaf_desc.table_paddr()) {
                Some(template) => PtMetaKind::Uniform(template),
                None => PtMetaKind::Leaf,
            };
            if leaf_desc.meta_kind() != expected_leaf {
                return false;
            }
            pd_bases.insert(align_down_level(leaf_base, PtPageLevel::Pd));
        }

        for pd_base in pd_bases {
            let Some(pd_desc) = descs.descriptor(PtPageLevel::Pd, pd_base) else {
                continue;
            };
            let expected_pd = match descs.uniform_template_for_pd(pd_base) {
                Some(template) => PtMetaKind::Uniform(template),
                None => PtMetaKind::Leaf,
            };
            if pd_desc.meta_kind() != expected_pd {
                return false;
            }
        }
        true
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
        parent_level: PtPageLevel,
        parent_table_paddr: u64,
        parent_va_base: u64,
        index: usize,
    ) -> Result<(u64, u64), PageTableError> {
        let child_level = parent_level
            .child_level()
            .ok_or(PageTableError::InvalidArgs)?;
        let child_va_base = parent_va_base + index as u64 * parent_level.child_coverage_bytes();
        let entry = &mut table_mut(parent_table_paddr)[index];
        if entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok((entry.addr().as_u64(), child_va_base));
        }

        let child_paddr =
            crate::userspace::alloc_bootstrap_zeroed_page().ok_or(PageTableError::Backend)?;
        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        entry.set_addr(PhysAddr::new(child_paddr), flags);
        self.descs.lock().upsert_descriptor(PtPageDesc {
            level: child_level,
            table_paddr: child_paddr,
            va_base: child_va_base,
            lock_kind: PtPageLockKind::TxSerialized,
            invalidate_epoch: 0,
            meta_kind: if child_level == PtPageLevel::Pt {
                PtMetaKind::Uniform(PtMetaTemplate {
                    present: false,
                    writable: false,
                    user_accessible: true,
                })
            } else {
                PtMetaKind::None
            },
        });
        Ok((child_paddr, child_va_base))
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
        let (pdpt_paddr, pdpt_va_base) =
            self.ensure_page_table_page(PtPageLevel::Pml4, root_paddr, 0, indices.pml4)?;
        let (pd_paddr, pd_va_base) =
            self.ensure_page_table_page(PtPageLevel::Pdpt, pdpt_paddr, pdpt_va_base, indices.pdpt)?;
        let (pt_paddr, _) =
            self.ensure_page_table_page(PtPageLevel::Pd, pd_paddr, pd_va_base, indices.pd)?;
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
            let mut refreshed_leafs = alloc::collections::BTreeSet::new();
            for op in shootdown.ops() {
                match *op {
                    FlushOp::Page(va) => {
                        if let Some(pt_desc) =
                            descs.descriptor(PtPageLevel::Pt, align_down_level(va, PtPageLevel::Pt))
                        {
                            refreshed_leafs.insert(pt_desc.table_paddr());
                        }
                    }
                }
            }
            for leaf_table_paddr in refreshed_leafs {
                descs.refresh_uniform_metadata_for_leaf(leaf_table_paddr);
            }
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

fn align_down_level(va: u64, level: PtPageLevel) -> u64 {
    let coverage = level.child_coverage_bytes();
    va & !(coverage - 1)
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
