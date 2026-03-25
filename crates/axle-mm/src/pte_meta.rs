//! Software page-table metadata, sparse leaf storage, and per-page state tracking.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::frame_table::RmapNodeId;
use super::types::AddressSpaceError;
use super::vmo::MapId;
use super::{
    PAGE_SIZE, PT_LEAF_PAGE_COUNT, align_down, is_page_aligned, validate_mapping_range, vpn_of,
};

/// Software page-metadata tag for one virtual page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PteMetaTag {
    /// Mapped but not currently backed by a resident frame.
    Reserved,
    /// Anonymous page that should be allocated on first fault.
    LazyAnon,
    /// VMO-backed page that should be materialized on first fault.
    LazyVmo,
    /// Resident page backed by one concrete frame.
    Present,
    /// Resident state has been evicted to swap-like storage.
    Swapped,
    /// Fragment page used by loan/message plumbing.
    LoanFrag,
    /// Fixed physical mapping that should not participate in normal COW.
    Phys,
}

/// Software shadow metadata for one `(address_space, vpn)` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PteMeta {
    pub(crate) tag: PteMetaTag,
    pub(crate) logical_write: bool,
    pub(crate) cow_shared: bool,
    pub(crate) pinned: bool,
    pub(crate) map_id: MapId,
    pub(crate) page_delta: u64,
}

impl PteMeta {
    /// Metadata tag for the page.
    pub const fn tag(self) -> PteMetaTag {
        self.tag
    }

    /// Whether the mapping is semantically writable, independent of current PTE state.
    pub const fn logical_write(self) -> bool {
        self.logical_write
    }

    /// Whether the page currently participates in a shared COW view.
    pub const fn cow_shared(self) -> bool {
        self.cow_shared
    }

    /// Whether the page is currently pinned by an in-flight kernel path.
    pub const fn pinned(self) -> bool {
        self.pinned
    }

    /// Coarse mapping record that owns this page.
    pub const fn map_id(self) -> MapId {
        self.map_id
    }

    /// Page offset from the start of the owning coarse mapping.
    pub const fn page_delta(self) -> u64 {
        self.page_delta
    }
}

/// Metadata-driven classification for one page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFaultDecision {
    /// Fault is not in scope for the userspace VM metadata layer.
    Unhandled,
    /// No metadata exists for the faulting virtual page.
    Unmapped,
    /// Fault hits an existing mapping but violates current protection state.
    ProtectionViolation,
    /// Fault should resolve through copy-on-write handling.
    CopyOnWrite,
    /// Fault is a non-present miss on a mapped page with the given metadata tag.
    NotPresent {
        /// Current metadata tag for the missing page.
        tag: PteMetaTag,
    },
}

#[derive(Debug)]
pub(crate) struct SparseLeafStore<T: Copy> {
    base_vpn: u64,
    page_count: u64,
    pub(crate) leaves: BTreeMap<u64, Vec<Option<T>>>,
}

impl<T: Copy> SparseLeafStore<T> {
    pub(crate) fn new(root_base: u64, root_len: u64) -> Result<Self, AddressSpaceError> {
        if root_len == 0 || !is_page_aligned(root_base) || !is_page_aligned(root_len) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        Ok(Self {
            base_vpn: vpn_of(root_base),
            page_count: root_len / PAGE_SIZE,
            leaves: BTreeMap::new(),
        })
    }

    pub(crate) fn get(&self, vpn: u64) -> Option<T> {
        let (leaf_base_vpn, slot_index) = self.leaf_slot(vpn).ok()?;
        self.leaves
            .get(&leaf_base_vpn)?
            .get(slot_index)
            .copied()
            .flatten()
    }

    pub(crate) fn set(&mut self, vpn: u64, value: Option<T>) -> Result<(), AddressSpaceError> {
        let (leaf_base_vpn, slot_index) = self.leaf_slot(vpn)?;
        match value {
            Some(value) => {
                let leaf = self
                    .leaves
                    .entry(leaf_base_vpn)
                    .or_insert_with(|| alloc::vec![None; PT_LEAF_PAGE_COUNT as usize]);
                leaf[slot_index] = Some(value);
            }
            None => {
                let mut remove_leaf = false;
                if let Some(leaf) = self.leaves.get_mut(&leaf_base_vpn) {
                    leaf[slot_index] = None;
                    remove_leaf = leaf.iter().all(Option::is_none);
                }
                if remove_leaf {
                    let _ = self.leaves.remove(&leaf_base_vpn);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn install_dense_range(
        &mut self,
        base: u64,
        values: &[T],
    ) -> Result<(), AddressSpaceError> {
        if values.is_empty() || !is_page_aligned(base) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let page_count =
            usize::try_from(self.range_page_count(base, values.len() as u64 * PAGE_SIZE)?)
                .map_err(|_| AddressSpaceError::InvalidArgs)?;
        for (page_index, value) in values.iter().copied().enumerate().take(page_count) {
            let vpn = vpn_of(base + (page_index as u64) * PAGE_SIZE);
            self.set(vpn, Some(value))?;
        }
        Ok(())
    }

    pub(crate) fn install_optional_range(
        &mut self,
        base: u64,
        values: &[Option<T>],
    ) -> Result<(), AddressSpaceError> {
        if values.is_empty() || !is_page_aligned(base) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let page_count =
            usize::try_from(self.range_page_count(base, values.len() as u64 * PAGE_SIZE)?)
                .map_err(|_| AddressSpaceError::InvalidArgs)?;
        for (page_index, value) in values.iter().copied().enumerate().take(page_count) {
            let vpn = vpn_of(base + (page_index as u64) * PAGE_SIZE);
            self.set(vpn, value)?;
        }
        Ok(())
    }

    pub(crate) fn clear_range(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let vpn = vpn_of(base + (page_index as u64) * PAGE_SIZE);
            self.set(vpn, None)?;
        }
        Ok(())
    }

    pub(crate) fn update_range<F>(
        &mut self,
        base: u64,
        len: u64,
        mut update: F,
    ) -> Result<(), AddressSpaceError>
    where
        F: FnMut(&mut T),
    {
        validate_mapping_range(base, len)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let vpn = vpn_of(base + (page_index as u64) * PAGE_SIZE);
            let (leaf_base_vpn, slot_index) = self.leaf_slot(vpn)?;
            let leaf = self
                .leaves
                .get_mut(&leaf_base_vpn)
                .ok_or(AddressSpaceError::NotFound)?;
            let value = leaf[slot_index]
                .as_mut()
                .ok_or(AddressSpaceError::NotFound)?;
            update(value);
        }
        Ok(())
    }

    fn leaf_slot(&self, vpn: u64) -> Result<(u64, usize), AddressSpaceError> {
        let relative = vpn
            .checked_sub(self.base_vpn)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if relative >= self.page_count {
            return Err(AddressSpaceError::OutOfRange);
        }
        let leaf_index = relative / PT_LEAF_PAGE_COUNT;
        let slot_index = usize::try_from(relative % PT_LEAF_PAGE_COUNT)
            .map_err(|_| AddressSpaceError::InvalidArgs)?;
        let leaf_base_vpn = self.base_vpn + leaf_index * PT_LEAF_PAGE_COUNT;
        Ok((leaf_base_vpn, slot_index))
    }

    fn range_page_count(&self, base: u64, len: u64) -> Result<u64, AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let first_vpn = vpn_of(base);
        let last_vpn = vpn_of(base + len - PAGE_SIZE);
        let first_relative = first_vpn
            .checked_sub(self.base_vpn)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let last_relative = last_vpn
            .checked_sub(self.base_vpn)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if last_relative >= self.page_count {
            return Err(AddressSpaceError::OutOfRange);
        }
        last_relative
            .checked_sub(first_relative)
            .and_then(|count| count.checked_add(1))
            .ok_or(AddressSpaceError::InvalidArgs)
    }
}

#[derive(Debug)]
pub(crate) struct PteMetaStore {
    pub(crate) leaves: SparseLeafStore<PteMeta>,
}

impl PteMetaStore {
    pub(crate) fn new(root_base: u64, root_len: u64) -> Result<Self, AddressSpaceError> {
        Ok(Self {
            leaves: SparseLeafStore::new(root_base, root_len)?,
        })
    }

    pub(crate) fn meta(&self, va: u64) -> Option<PteMeta> {
        let page_base = align_down(va, PAGE_SIZE);
        self.meta_for_vpn(vpn_of(page_base))
    }

    pub(crate) fn meta_for_vpn(&self, vpn: u64) -> Option<PteMeta> {
        self.leaves.get(vpn)
    }

    pub(crate) fn install_range(
        &mut self,
        base: u64,
        metas: &[PteMeta],
    ) -> Result<(), AddressSpaceError> {
        self.leaves.install_dense_range(base, metas)
    }

    pub(crate) fn clear_range(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        self.leaves.clear_range(base, len)
    }

    pub(crate) fn update_range<F>(
        &mut self,
        base: u64,
        len: u64,
        update: F,
    ) -> Result<(), AddressSpaceError>
    where
        F: FnMut(&mut PteMeta),
    {
        self.leaves.update_range(base, len, update)
    }
}

#[derive(Debug)]
pub(crate) struct RmapIndexStore {
    pub(crate) leaves: SparseLeafStore<RmapNodeId>,
}

impl RmapIndexStore {
    pub(crate) fn new(root_base: u64, root_len: u64) -> Result<Self, AddressSpaceError> {
        Ok(Self {
            leaves: SparseLeafStore::new(root_base, root_len)?,
        })
    }

    pub(crate) fn node(&self, va: u64) -> Option<RmapNodeId> {
        let page_base = align_down(va, PAGE_SIZE);
        self.node_for_vpn(vpn_of(page_base))
    }

    pub(crate) fn node_for_vpn(&self, vpn: u64) -> Option<RmapNodeId> {
        self.leaves.get(vpn)
    }

    pub(crate) fn install_range(
        &mut self,
        base: u64,
        nodes: &[Option<RmapNodeId>],
    ) -> Result<(), AddressSpaceError> {
        self.leaves.install_optional_range(base, nodes)
    }

    pub(crate) fn clear_range(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        self.leaves.clear_range(base, len)
    }

    pub(crate) fn set_node(
        &mut self,
        va: u64,
        node_id: Option<RmapNodeId>,
    ) -> Result<(), AddressSpaceError> {
        self.leaves.set(vpn_of(align_down(va, PAGE_SIZE)), node_id)
    }
}
