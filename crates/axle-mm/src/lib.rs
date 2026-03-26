#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Axle VM metadata core.
//!
//! This crate keeps the early `VMO / VMAR / VMA` model host-testable and
//! reusable inside the kernel. The current focus is:
//!
//! - bootstrap `AddressSpace` with a root VMAR
//! - `Vmo` allocation and fixed mappings
//! - coarse `MapRec` records for mapping control-plane identity
//! - `VA -> (VMO, offset, perms, frame)` reverse lookup
//! - bootstrap frame descriptors with ref / map / pin accounting
//! - VMA-granular copy-on-write metadata and fault resolution
//!
//! It still does **not** manage page tables.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;

mod frame_table;
mod pte_meta;
mod types;
mod vma;
mod vmo;

pub use frame_table::*;
pub use pte_meta::{PageFaultDecision, PteMeta, PteMetaTag};
pub use types::*;
pub use vma::*;
pub use vmo::*;

use frame_table::RmapNodeId;
use pte_meta::{PteMetaStore, RmapIndexStore};
use vmo::VmoFaultPolicy;

/// Canonical page size used by the metadata layer.
pub const PAGE_SIZE: u64 = 0x1000;
const PT_LEAF_PAGE_COUNT: u64 = 512;

bitflags! {
    /// Mapping permissions carried by a VMA.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MappingPerms: u32 {
        /// Read permission.
        const READ = 1 << 0;
        /// Write permission.
        const WRITE = 1 << 1;
        /// Execute permission.
        const EXECUTE = 1 << 2;
        /// User-accessible mapping.
        const USER = 1 << 3;
    }
}

/// Cache policy carried by one mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingCachePolicy {
    /// Normal cacheable memory.
    Cached,
    /// Device/MMIO-style uncached memory.
    DeviceMmio,
}

/// Clone policy carried by one mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingClonePolicy {
    /// This mapping does not participate in generic child-address-space cloning.
    None,
    /// Child address spaces inherit this mapping as one shared alias.
    SharedAlias,
    /// Child address spaces inherit this mapping through private copy-on-write semantics.
    PrivateCow,
}

bitflags! {
    /// Relevant fault bits observed by the VM metadata layer.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFaultFlags: u8 {
        /// Hardware reported the fault as present/protection rather than not-present.
        const PRESENT = 1 << 0;
        /// Faulting access attempted a write.
        const WRITE = 1 << 1;
        /// Fault originated from userspace.
        const USER = 1 << 2;
    }
}

const VA_MAGAZINE_BYTES: u64 = 0x20_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VaMagazine {
    cursor: u64,
    end: u64,
}

fn mix_u64(value: u64) -> u64 {
    let mut mixed = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

fn initial_vmar_random_state(address_space_id: AddressSpaceId, vmar: Vmar) -> u64 {
    mix_u64(
        address_space_id.raw().rotate_left(13)
            ^ vmar.id.raw().rotate_left(29)
            ^ vmar.base.rotate_left(7)
            ^ vmar.len.rotate_left(19),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VmarRecord {
    vmar: Vmar,
    parent_id: Option<VmarId>,
    alloc_cursor: u64,
    placement_policy: VmarPlacementPolicy,
    random_state: u64,
}

type SlotId = usize;

#[derive(Debug)]
struct StableSlots<T> {
    entries: Vec<Option<T>>,
    free: Vec<SlotId>,
}

impl<T> StableSlots<T> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }

    fn insert(&mut self, value: T) -> SlotId {
        if let Some(slot) = self.free.pop() {
            self.entries[slot] = Some(value);
            slot
        } else {
            self.entries.push(Some(value));
            self.entries.len() - 1
        }
    }

    fn get(&self, slot: SlotId) -> Option<&T> {
        self.entries.get(slot)?.as_ref()
    }

    fn get_mut(&mut self, slot: SlotId) -> Option<&mut T> {
        self.entries.get_mut(slot)?.as_mut()
    }

    fn remove(&mut self, slot: SlotId) -> Option<T> {
        let entry = self.entries.get_mut(slot)?;
        let value = entry.take()?;
        self.free.push(slot);
        Some(value)
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().filter_map(Option::as_ref)
    }
}

fn slot_list_insert<K: Ord>(index: &mut BTreeMap<K, Vec<SlotId>>, key: K, slot: SlotId) {
    index.entry(key).or_default().push(slot);
}

fn slot_list_remove<K: Ord>(index: &mut BTreeMap<K, Vec<SlotId>>, key: K, slot: SlotId) {
    let mut should_remove = false;
    if let Some(slots) = index.get_mut(&key) {
        if let Some(position) = slots.iter().position(|candidate| *candidate == slot) {
            slots.remove(position);
        }
        should_remove = slots.is_empty();
    }
    if should_remove {
        let _ = index.remove(&key);
    }
}

/// Metadata-only address space with one root VMAR.
#[derive(Debug)]
pub struct AddressSpace {
    id: AddressSpaceId,
    root: VmarRecord,
    vmars: StableSlots<VmarRecord>,
    vmars_by_id: BTreeMap<VmarId, SlotId>,
    vmar_slots_by_base: BTreeMap<u64, Vec<SlotId>>,
    child_vmar_slots_by_parent_id: BTreeMap<VmarId, Vec<SlotId>>,
    vmos: StableSlots<Vmo>,
    vmos_by_id: BTreeMap<VmoId, SlotId>,
    vmo_ids_by_identity_global_id: BTreeMap<GlobalVmoId, VmoId>,
    shared_vmo_ids_by_backing_global_id: BTreeMap<GlobalVmoId, VmoId>,
    map_recs: StableSlots<MapRec>,
    map_recs_by_id: BTreeMap<MapId, SlotId>,
    pte_meta: PteMetaStore,
    rmap_index: RmapIndexStore,
    vmas: StableSlots<Vma>,
    vma_slot_by_map_id: BTreeMap<MapId, SlotId>,
    vma_slots_by_base: BTreeMap<u64, SlotId>,
    vma_slots_by_vmar_id: BTreeMap<VmarId, Vec<SlotId>>,
    map_ids_by_vmo_id: BTreeMap<VmoId, Vec<MapId>>,
    va_magazines: BTreeMap<usize, VaMagazine>,
    next_vmar_id: u64,
    next_vmo_id: u64,
    next_map_id: u64,
}

impl AddressSpace {
    /// Create a new address space with a single root VMAR.
    pub fn new(root_base: u64, root_len: u64) -> Result<Self, AddressSpaceError> {
        Self::new_with_id(AddressSpaceId::new(0), root_base, root_len)
    }

    /// Create a new address space with one explicit stable id.
    pub fn new_with_id(
        id: AddressSpaceId,
        root_base: u64,
        root_len: u64,
    ) -> Result<Self, AddressSpaceError> {
        if root_len == 0 || !is_page_aligned(root_base) || !is_page_aligned(root_len) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let Some(_end) = root_base.checked_add(root_len) else {
            return Err(AddressSpaceError::InvalidArgs);
        };

        Ok(Self {
            id,
            root: VmarRecord {
                vmar: Vmar {
                    id: VmarId::new(1),
                    base: root_base,
                    len: root_len,
                },
                parent_id: None,
                alloc_cursor: root_base,
                placement_policy: VmarPlacementPolicy::Randomized,
                random_state: initial_vmar_random_state(
                    id,
                    Vmar {
                        id: VmarId::new(1),
                        base: root_base,
                        len: root_len,
                    },
                ),
            },
            vmars: StableSlots::new(),
            vmars_by_id: BTreeMap::new(),
            vmar_slots_by_base: BTreeMap::new(),
            child_vmar_slots_by_parent_id: BTreeMap::new(),
            vmos: StableSlots::new(),
            vmos_by_id: BTreeMap::new(),
            vmo_ids_by_identity_global_id: BTreeMap::new(),
            shared_vmo_ids_by_backing_global_id: BTreeMap::new(),
            map_recs: StableSlots::new(),
            map_recs_by_id: BTreeMap::new(),
            pte_meta: PteMetaStore::new(root_base, root_len)?,
            rmap_index: RmapIndexStore::new(root_base, root_len)?,
            vmas: StableSlots::new(),
            vma_slot_by_map_id: BTreeMap::new(),
            vma_slots_by_base: BTreeMap::new(),
            vma_slots_by_vmar_id: BTreeMap::new(),
            map_ids_by_vmo_id: BTreeMap::new(),
            va_magazines: BTreeMap::new(),
            next_vmar_id: 2,
            next_vmo_id: 1,
            next_map_id: 1,
        })
    }

    /// Stable address-space identifier.
    pub const fn id(&self) -> AddressSpaceId {
        self.id
    }

    /// Root VMAR metadata.
    pub const fn root_vmar(&self) -> Vmar {
        self.root.vmar
    }

    fn vmar_records_in_base_order(&self) -> impl Iterator<Item = VmarRecord> + '_ {
        self.vmar_slots_by_base
            .values()
            .flat_map(|slots| slots.iter().copied())
            .filter_map(|slot| self.vmars.get(slot).copied())
    }

    fn vmas_in_base_order(&self) -> impl Iterator<Item = Vma> + '_ {
        self.vma_slots_by_base
            .values()
            .filter_map(|slot| self.vmas.get(*slot).copied())
    }

    fn map_records_in_id_order(&self) -> impl Iterator<Item = MapRec> + '_ {
        self.map_recs_by_id
            .values()
            .filter_map(|slot| self.map_recs.get(*slot).copied())
    }

    fn insert_vmar_record(&mut self, record: VmarRecord) {
        let slot = self.vmars.insert(record);
        self.vmars_by_id.insert(record.vmar.id, slot);
        slot_list_insert(&mut self.vmar_slots_by_base, record.vmar.base, slot);
        if let Some(parent_id) = record.parent_id {
            self.insert_child_vmar_slot(parent_id, slot);
        }
    }

    fn remove_vmar_record(&mut self, id: VmarId) -> Option<VmarRecord> {
        let slot = self.vmars_by_id.remove(&id)?;
        let record = self.vmars.remove(slot)?;
        slot_list_remove(&mut self.vmar_slots_by_base, record.vmar.base, slot);
        if let Some(parent_id) = record.parent_id {
            slot_list_remove(&mut self.child_vmar_slots_by_parent_id, parent_id, slot);
        }
        Some(record)
    }

    fn insert_vmo(&mut self, vmo: Vmo) {
        let vmo_id = vmo.id();
        let global_id = vmo.global_id();
        let shared_backing_id = vmo.shared_backing_id();
        let slot = self.vmos.insert(vmo);
        self.vmos_by_id.insert(vmo_id, slot);
        self.vmo_ids_by_identity_global_id.insert(global_id, vmo_id);
        if let Some(shared_backing_id) = shared_backing_id {
            self.shared_vmo_ids_by_backing_global_id
                .insert(shared_backing_id, vmo_id);
        }
    }

    fn remove_vmo(&mut self, vmo_id: VmoId) -> Option<Vmo> {
        let slot = self.vmos_by_id.remove(&vmo_id)?;
        let vmo = self.vmos.remove(slot)?;
        self.vmo_ids_by_identity_global_id.remove(&vmo.global_id());
        if let Some(shared_backing_id) = vmo.shared_backing_id() {
            self.shared_vmo_ids_by_backing_global_id
                .remove(&shared_backing_id);
        }
        Some(vmo)
    }

    fn insert_map_record(&mut self, map_rec: MapRec) {
        let vmo_id = map_rec.vmo_id();
        let base = map_rec.base();
        let map_id = map_rec.id();
        let insert_at = self
            .map_ids_by_vmo_id
            .get(&vmo_id)
            .map(|map_ids| {
                map_ids
                    .iter()
                    .position(|candidate| {
                        self.map_record(*candidate)
                            .is_some_and(|existing| existing.base() > base)
                    })
                    .unwrap_or(map_ids.len())
            })
            .unwrap_or(0);
        let slot = self.map_recs.insert(map_rec);
        self.map_recs_by_id.insert(map_id, slot);
        self.map_ids_by_vmo_id
            .entry(vmo_id)
            .or_default()
            .insert(insert_at, map_id);
    }

    fn remove_map_record(&mut self, map_id: MapId) -> Option<MapRec> {
        let slot = self.map_recs_by_id.remove(&map_id)?;
        let map_rec = self.map_recs.remove(slot)?;
        if let Some(map_ids) = self.map_ids_by_vmo_id.get_mut(&map_rec.vmo_id()) {
            if let Some(position) = map_ids.iter().position(|candidate| *candidate == map_id) {
                map_ids.remove(position);
            }
            if map_ids.is_empty() {
                self.map_ids_by_vmo_id.remove(&map_rec.vmo_id());
            }
        }
        Some(map_rec)
    }

    fn insert_vma(&mut self, vma: Vma) {
        let slot = self.vmas.insert(vma);
        self.vma_slot_by_map_id.insert(vma.map_id, slot);
        self.vma_slots_by_base.insert(vma.base, slot);
        self.insert_vma_slot(vma.vmar_id, slot);
    }

    fn remove_vma_by_map_id(&mut self, map_id: MapId) -> Option<Vma> {
        let slot = self.vma_slot_by_map_id.remove(&map_id)?;
        let vma = self.vmas.remove(slot)?;
        self.vma_slots_by_base.remove(&vma.base);
        slot_list_remove(&mut self.vma_slots_by_vmar_id, vma.vmar_id, slot);
        Some(vma)
    }

    fn insert_child_vmar_slot(&mut self, parent_id: VmarId, slot: SlotId) {
        let Some(base) = self.vmars.get(slot).map(|record| record.vmar.base()) else {
            return;
        };
        let slots = self
            .child_vmar_slots_by_parent_id
            .entry(parent_id)
            .or_default();
        let insert_at = slots
            .iter()
            .position(|candidate| {
                self.vmars
                    .get(*candidate)
                    .is_some_and(|record| record.vmar.base() > base)
            })
            .unwrap_or(slots.len());
        slots.insert(insert_at, slot);
    }

    fn insert_vma_slot(&mut self, vmar_id: VmarId, slot: SlotId) {
        let Some(base) = self.vmas.get(slot).map(|vma| vma.base()) else {
            return;
        };
        let slots = self.vma_slots_by_vmar_id.entry(vmar_id).or_default();
        let insert_at = slots
            .iter()
            .position(|candidate| {
                self.vmas
                    .get(*candidate)
                    .is_some_and(|vma| vma.base() > base)
            })
            .unwrap_or(slots.len());
        slots.insert(insert_at, slot);
    }

    fn find_vma_slot_covering_range(&self, vmar_id: VmarId, base: u64, len: u64) -> Option<SlotId> {
        self.vma_slots_by_base
            .range(..=base)
            .next_back()
            .and_then(|(_, slot)| self.vmas.get(*slot).map(|vma| (*slot, *vma)))
            .and_then(|(slot, vma)| {
                (vma.vmar_id == vmar_id && vma.contains_range(base, len)).then_some(slot)
            })
    }

    fn vma_overlaps_range(&self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return true;
        };
        if self
            .vma_slots_by_base
            .range(..=base)
            .next_back()
            .and_then(|(_, slot)| self.vmas.get(*slot))
            .is_some_and(|vma| ranges_overlap(vma.base(), vma.len(), base, len))
        {
            return true;
        }
        self.vma_slots_by_base
            .range(base..)
            .filter_map(|(_, slot)| self.vmas.get(*slot))
            .take_while(|vma| vma.base() < end)
            .any(|vma| ranges_overlap(vma.base(), vma.len(), base, len))
    }

    /// Direct child VMAR reservations currently carved out of the root range.
    pub fn child_vmars(&self) -> Vec<Vmar> {
        self.vmar_records_in_base_order()
            .filter(|record| record.parent_id == Some(self.root.vmar.id))
            .map(|record| record.vmar)
            .collect()
    }

    /// Lookup one VMAR by id.
    pub fn vmar(&self, id: VmarId) -> Option<Vmar> {
        if self.root.vmar.id == id {
            return Some(self.root.vmar);
        }
        self.vmars_by_id
            .get(&id)
            .and_then(|slot| self.vmars.get(*slot))
            .map(|record| record.vmar)
    }

    fn vmar_record(&self, id: VmarId) -> Option<VmarRecord> {
        if self.root.vmar.id == id {
            return Some(self.root);
        }
        self.vmars_by_id
            .get(&id)
            .and_then(|slot| self.vmars.get(*slot))
            .copied()
    }

    fn vmar_record_mut(&mut self, id: VmarId) -> Option<&mut VmarRecord> {
        if self.root.vmar.id == id {
            return Some(&mut self.root);
        }
        let slot = *self.vmars_by_id.get(&id)?;
        self.vmars.get_mut(slot)
    }

    /// Allocate one child VMAR out of the root address space using a CPU-local VA magazine.
    pub fn allocate_subvmar_for_cpu(
        &mut self,
        cpu_id: usize,
        len: u64,
        align: u64,
    ) -> Result<Vmar, AddressSpaceError> {
        self.allocate_subvmar(
            cpu_id,
            self.root.vmar.id,
            0,
            len,
            align,
            VmarAllocMode::Compact,
            false,
            VmarPlacementPolicy::Compact,
        )
    }

    /// Allocate one child VMAR inside the given parent VMAR.
    #[allow(clippy::too_many_arguments)]
    pub fn allocate_subvmar(
        &mut self,
        cpu_id: usize,
        parent_vmar_id: VmarId,
        offset: u64,
        len: u64,
        align: u64,
        mode: VmarAllocMode,
        offset_is_upper_limit: bool,
        child_policy: VmarPlacementPolicy,
    ) -> Result<Vmar, AddressSpaceError> {
        let parent = self
            .vmar_record(parent_vmar_id)
            .ok_or(AddressSpaceError::InvalidVmar)?;
        validate_mapping_range(parent.vmar.base, len)?;
        if align == 0 || !align.is_power_of_two() || !is_page_aligned(align) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        if !is_page_aligned(offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        if mode == VmarAllocMode::Specific {
            if offset_is_upper_limit {
                return Err(AddressSpaceError::InvalidArgs);
            }
            let base = parent
                .vmar
                .base
                .checked_add(offset)
                .ok_or(AddressSpaceError::InvalidArgs)?;
            if base & (align - 1) != 0 {
                return Err(AddressSpaceError::InvalidArgs);
            }
            return self.insert_child_vmar(cpu_id, parent_vmar_id, base, len, child_policy);
        }
        if offset != 0 && !offset_is_upper_limit {
            return Err(AddressSpaceError::InvalidArgs);
        }

        if mode == VmarAllocMode::Compact
            && !offset_is_upper_limit
            && parent_vmar_id == self.root.vmar.id
            && let Some(base) = self.try_allocate_from_magazine(cpu_id, len, align)?
        {
            return self.insert_child_vmar(cpu_id, parent_vmar_id, base, len, child_policy);
        }

        let search_end =
            Self::search_end_for_allocation(parent.vmar, offset, len, offset_is_upper_limit)?;
        let placement_parent = if Self::should_place_compact(parent, mode) {
            VmarRecord {
                placement_policy: VmarPlacementPolicy::Compact,
                ..parent
            }
        } else {
            parent
        };
        let start_hint =
            self.placement_start_hint(placement_parent, cpu_id, len, align, search_end)?;
        let (base, gap_end) = self
            .find_free_gap_in_vmar_window_with_hint(
                parent_vmar_id,
                parent.vmar.base,
                search_end,
                start_hint,
                len,
                align,
            )
            .ok_or(AddressSpaceError::OutOfRange)?;
        let vmar = self.insert_child_vmar(cpu_id, parent_vmar_id, base, len, child_policy)?;
        if mode == VmarAllocMode::Compact && parent_vmar_id == self.root.vmar.id {
            let cursor = base
                .checked_add(len)
                .ok_or(AddressSpaceError::InvalidArgs)?;
            let preferred_end = base.saturating_add(VA_MAGAZINE_BYTES);
            self.va_magazines.insert(
                cpu_id,
                VaMagazine {
                    cursor,
                    end: core::cmp::max(cursor, core::cmp::min(gap_end, preferred_end)),
                },
            );
        }
        Ok(vmar)
    }

    /// Destroy one child VMAR and recursively tear down mappings inside it.
    pub fn destroy_vmar(
        &mut self,
        frames: &mut FrameTable,
        id: VmarId,
    ) -> Result<Vec<(u64, u64)>, AddressSpaceError> {
        if id == self.root.vmar.id {
            return Err(AddressSpaceError::Busy);
        }
        if self.vmar_record(id).is_none() {
            return Err(AddressSpaceError::InvalidVmar);
        }
        let subtree = self.collect_vmar_subtree_ids(id);
        let mut removed_vmas = Vec::new();
        self.append_destroy_unmaps_in_vmar_subtree(id, &mut removed_vmas);
        let removed_ranges = removed_vmas
            .iter()
            .map(|&(_, base, len)| (base, len))
            .collect();
        for (vmar_id, base, len) in removed_vmas {
            self.unmap_in_vmar(frames, vmar_id, base, len)?;
        }
        for vmar_id in subtree {
            let _ = self.remove_vmar_record(vmar_id);
        }
        Ok(removed_ranges)
    }

    fn insert_new_vmo(
        &mut self,
        kind: VmoKind,
        size_bytes: u64,
        global_id: GlobalVmoId,
        shared_backing_id: Option<GlobalVmoId>,
        fault_source_id: Option<GlobalVmoId>,
        fault_policy: VmoFaultPolicy,
    ) -> Result<VmoId, AddressSpaceError> {
        if size_bytes == 0 || !is_page_aligned(size_bytes) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let id = VmoId::new(self.next_vmo_id);
        self.next_vmo_id = self.next_vmo_id.wrapping_add(1);
        self.insert_vmo(Vmo {
            id,
            global_id,
            shared_backing_id,
            fault_source_id,
            kind,
            fault_policy,
            size_bytes,
            frames: alloc::vec![None; usize::try_from(size_bytes / PAGE_SIZE).unwrap_or(0)],
        });
        Ok(id)
    }

    /// Allocate a new local VMO record with one unique global identity.
    pub fn create_vmo(
        &mut self,
        kind: VmoKind,
        size_bytes: u64,
        global_id: GlobalVmoId,
    ) -> Result<VmoId, AddressSpaceError> {
        let fault_policy = vmo_fault_policy_for_create(kind);
        let fault_source_id = match fault_policy {
            VmoFaultPolicy::GlobalBacked => Some(global_id),
            VmoFaultPolicy::LocalAnonymous | VmoFaultPolicy::NonDemandPaged => None,
        };
        self.insert_new_vmo(
            kind,
            size_bytes,
            global_id,
            None,
            fault_source_id,
            fault_policy,
        )
    }

    /// Allocate one local private clone VMO with its own identity and an optional lazy fault source.
    pub fn create_private_clone_vmo(
        &mut self,
        kind: VmoKind,
        size_bytes: u64,
        clone_global_id: GlobalVmoId,
        fault_source_id: Option<GlobalVmoId>,
    ) -> Result<VmoId, AddressSpaceError> {
        let fault_policy = match kind {
            VmoKind::Anonymous => VmoFaultPolicy::LocalAnonymous,
            VmoKind::Physical | VmoKind::Contiguous => VmoFaultPolicy::NonDemandPaged,
            VmoKind::PagerBacked => VmoFaultPolicy::GlobalBacked,
        };
        if matches!(fault_policy, VmoFaultPolicy::GlobalBacked) && fault_source_id.is_none() {
            return Err(AddressSpaceError::InvalidArgs);
        }
        self.insert_new_vmo(
            kind,
            size_bytes,
            clone_global_id,
            None,
            fault_source_id,
            fault_policy,
        )
    }

    /// Return metadata for a tracked VMO.
    pub fn vmo(&self, id: VmoId) -> Option<&Vmo> {
        self.vmos_by_id
            .get(&id)
            .and_then(|slot| self.vmos.get(*slot))
    }

    /// Return metadata for one tracked VMO by kernel-global identity.
    pub fn vmo_by_global_id(&self, global_id: GlobalVmoId) -> Option<&Vmo> {
        self.vmo_id_by_global_id(global_id)
            .and_then(|vmo_id| self.vmo(vmo_id))
    }

    /// Return the local VMO id for one unique kernel-global VMO identity.
    pub fn vmo_id_by_global_id(&self, global_id: GlobalVmoId) -> Option<VmoId> {
        self.vmo_ids_by_identity_global_id.get(&global_id).copied()
    }

    /// Return the direct shared-alias VMO id for one shared/global backing identity.
    pub fn shared_vmo_id_by_backing_global_id(&self, global_id: GlobalVmoId) -> Option<VmoId> {
        self.shared_vmo_ids_by_backing_global_id
            .get(&global_id)
            .copied()
    }

    fn vmo_mut(&mut self, id: VmoId) -> Option<&mut Vmo> {
        let slot = *self.vmos_by_id.get(&id)?;
        self.vmos.get_mut(slot)
    }

    /// Validate whether one tracked VMO can be resized to `new_size_bytes`.
    pub fn validate_vmo_resize(
        &self,
        vmo_id: VmoId,
        new_size_bytes: u64,
    ) -> Result<(), AddressSpaceError> {
        if new_size_bytes == 0 || !is_page_aligned(new_size_bytes) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let vmo = self.vmo(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        if new_size_bytes >= vmo.size_bytes() {
            return Ok(());
        }

        let map_ids = self
            .map_ids_by_vmo_id
            .get(&vmo_id)
            .cloned()
            .unwrap_or_default();
        for map_id in map_ids {
            let Some(map_rec) = self.map_record(map_id) else {
                continue;
            };
            let Some(mapped_end) = map_rec.vmo_offset().checked_add(map_rec.len()) else {
                return Err(AddressSpaceError::InvalidArgs);
            };
            if mapped_end > new_size_bytes {
                return Err(AddressSpaceError::Busy);
            }
        }

        Ok(())
    }

    /// Resize one tracked VMO and return resident frames dropped from the truncated tail.
    pub fn resize_vmo(
        &mut self,
        vmo_id: VmoId,
        new_size_bytes: u64,
    ) -> Result<Vec<FrameId>, AddressSpaceError> {
        self.validate_vmo_resize(vmo_id, new_size_bytes)?;

        let new_page_count = usize::try_from(new_size_bytes / PAGE_SIZE)
            .map_err(|_| AddressSpaceError::InvalidArgs)?;
        let vmo = self.vmo_mut(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        let mut dropped = Vec::new();
        if new_page_count < vmo.frames.len() {
            dropped.extend(vmo.frames[new_page_count..].iter().flatten().copied());
        }
        vmo.size_bytes = new_size_bytes;
        vmo.frames.truncate(new_page_count);
        if new_page_count > vmo.frames.len() {
            vmo.frames.resize(new_page_count, None);
        }
        Ok(dropped)
    }

    /// Drop one tracked VMO when no live mappings still reference it.
    pub fn remove_vmo_if_unmapped(&mut self, vmo_id: VmoId) -> Result<bool, AddressSpaceError> {
        if self.vmo(vmo_id).is_none() {
            return Err(AddressSpaceError::InvalidVmo);
        }
        if self
            .map_ids_by_vmo_id
            .get(&vmo_id)
            .is_some_and(|map_ids| !map_ids.is_empty())
        {
            return Ok(false);
        }
        let _ = self.remove_vmo(vmo_id);
        Ok(true)
    }

    /// Import one kernel-global VMO description into this address space, or reuse an existing alias.
    pub fn import_vmo(
        &mut self,
        kind: VmoKind,
        size_bytes: u64,
        global_id: GlobalVmoId,
    ) -> Result<VmoId, AddressSpaceError> {
        if let Some(existing_id) = self.shared_vmo_id_by_backing_global_id(global_id) {
            let existing = self
                .vmo_mut(existing_id)
                .ok_or(AddressSpaceError::InvalidVmo)?;
            if existing.kind() != kind || existing.size_bytes() != size_bytes {
                return Err(AddressSpaceError::InvalidArgs);
            }
            let id = existing.id();
            let next_policy = vmo_fault_policy_for_import(kind);
            let changed = existing.fault_policy != next_policy;
            existing.fault_policy = next_policy;
            let _ = existing;
            if changed {
                self.refresh_all_vmo_page_metadata(id)?;
            }
            return Ok(id);
        }
        if size_bytes == 0 || !is_page_aligned(size_bytes) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let fault_policy = vmo_fault_policy_for_import(kind);
        let fault_source_id = match fault_policy {
            VmoFaultPolicy::GlobalBacked => Some(global_id),
            VmoFaultPolicy::LocalAnonymous | VmoFaultPolicy::NonDemandPaged => None,
        };
        self.insert_new_vmo(
            kind,
            size_bytes,
            global_id,
            Some(global_id),
            fault_source_id,
            fault_policy,
        )
    }

    fn refresh_all_vmo_page_metadata(&mut self, vmo_id: VmoId) -> Result<(), AddressSpaceError> {
        let page_count = self
            .vmo(vmo_id)
            .ok_or(AddressSpaceError::InvalidVmo)?
            .frames()
            .len();
        for page_index in 0..page_count {
            self.refresh_vmo_page_metadata(vmo_id, (page_index as u64) * PAGE_SIZE)?;
        }
        Ok(())
    }

    /// Return the current coarse mapping records in stable map-id order.
    pub fn map_records(&self) -> Vec<MapRec> {
        self.map_records_in_id_order().collect()
    }

    /// Return the coarse mapping record for one mapping id.
    pub fn map_record(&self, id: MapId) -> Option<MapRec> {
        self.map_recs_by_id
            .get(&id)
            .and_then(|slot| self.map_recs.get(*slot))
            .copied()
    }

    /// Resolve one virtual address back to its owning coarse mapping record.
    pub fn map_record_for_va(&self, va: u64) -> Option<MapRec> {
        self.resolve_page_state(va).map(|resolved| resolved.map_rec)
    }

    fn rmap_node_at(&self, va: u64) -> Option<RmapNodeId> {
        self.rmap_index.node(va)
    }

    /// Return one live reverse-mapping anchor for a frame, if this address space currently maps it.
    pub fn first_rmap_anchor_for_frame(&self, frame_id: FrameId) -> Option<ReverseMapAnchor> {
        self.first_rmap_anchor_for_frame_excluding(frame_id, None)
    }

    /// Resolve one reverse-mapping anchor back to its exact virtual page base.
    pub fn page_base_for_rmap_anchor(&self, anchor: ReverseMapAnchor) -> Option<u64> {
        if anchor.address_space_id() != self.id {
            return None;
        }
        let map_rec = self.map_record(anchor.map_id())?;
        let page_offset = anchor.page_delta().checked_mul(PAGE_SIZE)?;
        if page_offset >= map_rec.len() {
            return None;
        }
        map_rec.base().checked_add(page_offset)
    }

    /// Resolve one reverse-mapping anchor back to its live mapping metadata.
    pub fn lookup_rmap_anchor(&self, anchor: ReverseMapAnchor) -> Option<VmaLookup> {
        let resolved = self.resolve_page_state(self.page_base_for_rmap_anchor(anchor)?)?;
        (resolved.map_rec.id() == anchor.map_id() && resolved.page_delta == anchor.page_delta())
            .then(|| self.lookup_from_resolved_page(resolved, resolved.page_base))
            .flatten()
    }

    /// Return the current page metadata for one virtual address, if mapped.
    pub fn pte_meta(&self, va: u64) -> Option<PteMeta> {
        self.pte_meta.meta(va)
    }

    /// Return the current page metadata after validating its coarse mapping ownership.
    pub fn owned_pte_meta(&self, va: u64) -> Option<PteMeta> {
        self.resolve_page_state(va).map(|resolved| resolved.meta)
    }

    /// Return the current page metadata for one absolute virtual page number.
    pub fn pte_meta_for_vpn(&self, vpn: u64) -> Option<PteMeta> {
        self.pte_meta.meta_for_vpn(vpn)
    }

    /// Classify one page fault by consulting page metadata before any page-table action.
    pub fn classify_page_fault(&self, fault_va: u64, flags: PageFaultFlags) -> PageFaultDecision {
        if !flags.contains(PageFaultFlags::USER) {
            return PageFaultDecision::Unhandled;
        }

        let Some(resolved) = self.resolve_page_state(fault_va) else {
            return PageFaultDecision::Unmapped;
        };
        let meta = resolved.meta;
        let Some(vmo) = self.vmo(resolved.map_rec.vmo_id()) else {
            return PageFaultDecision::Unmapped;
        };

        if flags.contains(PageFaultFlags::PRESENT) {
            if flags.contains(PageFaultFlags::WRITE)
                && meta.cow_shared()
                && meta.logical_write()
                && matches!(meta.tag(), PteMetaTag::Present)
                && vmo.supports_copy_on_write()
            {
                PageFaultDecision::CopyOnWrite
            } else {
                PageFaultDecision::ProtectionViolation
            }
        } else {
            PageFaultDecision::NotPresent { tag: meta.tag() }
        }
    }

    /// Bind a resident frame to one page of a VMO.
    pub fn bind_vmo_frame(
        &mut self,
        vmo_id: VmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), AddressSpaceError> {
        if !is_page_aligned(offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let vmo = self.vmo_mut(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        if offset >= vmo.size_bytes {
            return Err(AddressSpaceError::OutOfRange);
        }
        let page_index =
            usize::try_from(offset / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let slot = vmo
            .frames
            .get_mut(page_index)
            .ok_or(AddressSpaceError::OutOfRange)?;
        match *slot {
            Some(existing) if existing != frame_id => Err(AddressSpaceError::AlreadyBound),
            Some(_) => Ok(()),
            None => {
                *slot = Some(frame_id);
                let _ = slot;
                let _ = vmo;
                self.refresh_vmo_page_metadata(vmo_id, offset)?;
                Ok(())
            }
        }
    }

    /// Install or replace one VMO frame binding.
    pub fn set_vmo_frame(
        &mut self,
        vmo_id: VmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), AddressSpaceError> {
        match self.bind_vmo_frame(vmo_id, offset, frame_id) {
            Ok(()) => Ok(()),
            Err(AddressSpaceError::AlreadyBound) => self.rebind_vmo_frame(vmo_id, offset, frame_id),
            Err(err) => Err(err),
        }
    }

    /// Attach one newly materialized VMO page to every existing mapping alias of that page.
    pub fn materialize_vmo_page_aliases(
        &mut self,
        frames: &mut FrameTable,
        vmo_id: VmoId,
        page_offset: u64,
        frame_id: FrameId,
    ) -> Result<Vec<u64>, AddressSpaceError> {
        if !is_page_aligned(page_offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let vmo = self.vmo(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        if vmo.frame_at_offset(page_offset) != Some(frame_id) {
            return Err(AddressSpaceError::InvalidFrame);
        }

        let mut page_targets = Vec::new();
        let mut installed = Vec::new();
        for vma in self.vmas_in_base_order() {
            let Some(map_rec) = self.map_record(vma.map_id) else {
                continue;
            };
            if map_rec.vmo_id() != vmo_id {
                continue;
            }
            if page_offset < map_rec.vmo_offset()
                || page_offset >= map_rec.vmo_offset() + map_rec.len()
            {
                continue;
            }

            let page_delta = (page_offset - map_rec.vmo_offset()) / PAGE_SIZE;
            let page_base = vma.base + page_delta * PAGE_SIZE;
            page_targets.push((vma.map_id, page_delta, page_base));
        }

        let mut page_bases = Vec::with_capacity(page_targets.len());
        for (map_id, page_delta, page_base) in page_targets {
            page_bases.push(page_base);
            if self.rmap_node_at(page_base).is_some() {
                continue;
            }

            let anchor = self.make_rmap_anchor(map_id, page_delta);
            let node_id = match frames.map_frame(frame_id, anchor) {
                Ok(node_id) => node_id,
                Err(err) => {
                    for (rollback_base, rollback_node) in installed {
                        let _ = self.rmap_index.set_node(rollback_base, None);
                        let _ = frames.unmap_frame(frame_id, rollback_node);
                    }
                    return Err(AddressSpaceError::FrameTable(err));
                }
            };
            if let Err(err) = self.rmap_index.set_node(page_base, Some(node_id)) {
                let _ = frames.unmap_frame(frame_id, node_id);
                for (rollback_base, rollback_node) in installed {
                    let _ = self.rmap_index.set_node(rollback_base, None);
                    let _ = frames.unmap_frame(frame_id, rollback_node);
                }
                return Err(err);
            }
            installed.push((page_base, node_id));
        }

        if let Err(err) = self.refresh_vmo_page_metadata(vmo_id, page_offset) {
            for (rollback_base, rollback_node) in installed {
                let _ = self.rmap_index.set_node(rollback_base, None);
                let _ = frames.unmap_frame(frame_id, rollback_node);
            }
            return Err(err);
        }

        Ok(page_bases)
    }

    /// Return the current VMA list in ascending virtual-address order.
    pub fn vmas(&self) -> Vec<Vma> {
        self.vmas_in_base_order().collect()
    }

    /// Return every mapped range currently backed by the given kernel-global VMO identity.
    pub fn mapped_ranges_for_global_vmo(&self, global_id: GlobalVmoId) -> Vec<(u64, u64)> {
        let Some(vmo_id) = self.shared_vmo_id_by_backing_global_id(global_id) else {
            return Vec::new();
        };
        self.map_ids_by_vmo_id
            .get(&vmo_id)
            .into_iter()
            .flatten()
            .filter_map(|map_id| self.map_record(*map_id))
            .map(|map_rec| (map_rec.base(), map_rec.len()))
            .collect()
    }

    /// Return every mapped range currently owned by the given VMAR subtree.
    pub fn mapped_ranges_in_vmar_subtree(&self, vmar_id: VmarId) -> Vec<(u64, u64)> {
        if self.vmar_record(vmar_id).is_none() {
            return Vec::new();
        }
        let mut ranges = Vec::new();
        self.append_mapped_ranges_in_vmar_subtree(vmar_id, &mut ranges);
        ranges
    }

    /// Install a fixed mapping into one VMAR.
    #[allow(clippy::too_many_arguments)]
    pub fn map_fixed_in_vmar(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.map_fixed_in_vmar_with_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            MappingCachePolicy::Cached,
        )
    }

    /// Install a fixed mapping into one VMAR with explicit cache policy.
    #[allow(clippy::too_many_arguments)]
    pub fn map_fixed_in_vmar_with_policy(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        cache_policy: MappingCachePolicy,
    ) -> Result<(), AddressSpaceError> {
        self.map_fixed_in_vmar_with_mapping_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            cache_policy,
            MappingClonePolicy::None,
        )
    }

    /// Install a fixed mapping into one VMAR with explicit cache and clone policy.
    #[allow(clippy::too_many_arguments)]
    pub fn map_fixed_in_vmar_with_mapping_policy(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        cache_policy: MappingCachePolicy,
        clone_policy: MappingClonePolicy,
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let vmar = self.vmar(vmar_id).ok_or(AddressSpaceError::InvalidVmar)?;
        if !max_perms.contains(perms) || !vmar.contains_range(base, len) {
            return Err(if !max_perms.contains(perms) {
                AddressSpaceError::PermissionIncrease
            } else {
                AddressSpaceError::OutOfRange
            });
        }
        if !is_page_aligned(vmo_offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let vmo = self.vmo(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        let Some(vmo_end) = vmo_offset.checked_add(len) else {
            return Err(AddressSpaceError::InvalidArgs);
        };
        if vmo_end > vmo.size_bytes() {
            return Err(AddressSpaceError::OutOfRange);
        }
        if self.vma_overlaps_range(base, len) {
            return Err(AddressSpaceError::Overlap);
        }
        if self.mapping_intersects_foreign_vmar(vmar_id, base, len) {
            return Err(AddressSpaceError::Overlap);
        }

        let global_vmo_id = vmo.global_id();
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let mut page_frames = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_offset = vmo_offset + (page_index as u64) * PAGE_SIZE;
            let frame_id = vmo.frame_at_offset(page_offset);
            if let Some(frame_id) = frame_id
                && !frames.contains(frame_id)
            {
                return Err(AddressSpaceError::InvalidFrame);
            }
            page_frames.push(frame_id);
        }
        if matches!(vmo.kind(), VmoKind::Physical | VmoKind::Contiguous)
            && page_frames.iter().any(Option::is_none)
        {
            return Err(AddressSpaceError::InvalidFrame);
        }

        let map_id = self.alloc_map_id();
        let mut incremented = Vec::new();
        let mut rmap_nodes = Vec::with_capacity(page_count);
        for (page_index, frame_id) in page_frames.iter().copied().enumerate() {
            let anchor = self.make_rmap_anchor(map_id, page_index as u64);
            let Some(frame_id) = frame_id else {
                rmap_nodes.push(None);
                continue;
            };
            if let Err(err) = frames.map_frame(frame_id, anchor).map(|node_id| {
                incremented.push((frame_id, node_id));
                rmap_nodes.push(Some(node_id));
            }) {
                for (rollback_frame, rollback_anchor) in incremented {
                    let _ = frames.unmap_frame(rollback_frame, rollback_anchor);
                }
                return Err(AddressSpaceError::FrameTable(err));
            }
        }

        let map_rec = MapRec {
            id: map_id,
            vmar_id,
            base,
            len,
            vmo_id,
            global_vmo_id,
            vmo_offset,
            max_perms,
            cache_policy,
        };
        let vma = Vma {
            map_id,
            vmar_id,
            base,
            len,
            perms,
            copy_on_write: false,
            clone_policy,
        };
        let page_meta = match self.build_pte_meta_range(map_rec, vma) {
            Ok(page_meta) => page_meta,
            Err(err) => {
                for (rollback_frame, rollback_anchor) in incremented {
                    let _ = frames.unmap_frame(rollback_frame, rollback_anchor);
                }
                return Err(err);
            }
        };
        if let Err(err) = self.pte_meta.install_range(base, &page_meta) {
            for (rollback_frame, rollback_anchor) in incremented {
                let _ = frames.unmap_frame(rollback_frame, rollback_anchor);
            }
            return Err(err);
        }
        if let Err(err) = self.rmap_index.install_range(base, &rmap_nodes) {
            let _ = self.pte_meta.clear_range(base, len);
            for (rollback_frame, rollback_anchor) in incremented {
                let _ = frames.unmap_frame(rollback_frame, rollback_anchor);
            }
            return Err(err);
        }
        self.insert_map_record(map_rec);
        self.insert_vma(vma);
        self.observe_mapping_placement(vmar_id, base, len);
        Ok(())
    }

    /// Install a fixed mapping into the root VMAR.
    #[allow(clippy::too_many_arguments)]
    pub fn map_fixed(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.map_fixed_in_vmar(
            frames,
            self.root.vmar.id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
        )
    }

    /// Install one non-specific mapping inside the given VMAR using its placement policy.
    #[allow(clippy::too_many_arguments)]
    pub fn map_anywhere_in_vmar(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        align: u64,
    ) -> Result<u64, AddressSpaceError> {
        self.map_anywhere_in_vmar_with_policy(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            align,
            MappingCachePolicy::Cached,
        )
    }

    /// Install one non-specific mapping with explicit cache policy.
    #[allow(clippy::too_many_arguments)]
    pub fn map_anywhere_in_vmar_with_policy(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        align: u64,
        cache_policy: MappingCachePolicy,
    ) -> Result<u64, AddressSpaceError> {
        self.map_anywhere_in_vmar_with_mapping_policy(
            frames,
            cpu_id,
            vmar_id,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            align,
            cache_policy,
            MappingClonePolicy::None,
        )
    }

    /// Install one non-specific mapping with explicit cache and clone policy.
    #[allow(clippy::too_many_arguments)]
    pub fn map_anywhere_in_vmar_with_mapping_policy(
        &mut self,
        frames: &mut FrameTable,
        cpu_id: usize,
        vmar_id: VmarId,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
        align: u64,
        cache_policy: MappingCachePolicy,
        clone_policy: MappingClonePolicy,
    ) -> Result<u64, AddressSpaceError> {
        let vmar = self
            .vmar_record(vmar_id)
            .ok_or(AddressSpaceError::InvalidVmar)?;
        let start_hint = match vmar.placement_policy {
            VmarPlacementPolicy::Compact => self.compact_start_hint(vmar),
            VmarPlacementPolicy::Randomized => vmar.vmar.base,
        };
        let base = self
            .find_free_gap_in_vmar_window_with_hint(
                vmar_id,
                vmar.vmar.base,
                vmar.vmar.end(),
                if vmar.placement_policy == VmarPlacementPolicy::Compact {
                    start_hint
                } else {
                    self.allocation_start_hint(vmar, cpu_id, len, align, vmar.vmar.end())?
                },
                len,
                align,
            )
            .map(|(base, _)| base)
            .ok_or(AddressSpaceError::OutOfRange)?;
        self.map_fixed_in_vmar_with_mapping_policy(
            frames,
            vmar_id,
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
            cache_policy,
            clone_policy,
        )?;
        Ok(base)
    }

    /// Remove an existing mapping.
    pub fn unmap_in_vmar(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let vma_slot = self
            .find_vma_slot_covering_range(vmar_id, base, len)
            .ok_or(AddressSpaceError::NotFound)?;
        let vma = *self.vmas.get(vma_slot).ok_or(AddressSpaceError::NotFound)?;
        let map_rec = self
            .map_record(vma.map_id)
            .ok_or(AddressSpaceError::NotFound)?;
        if map_rec.base() != base || map_rec.len() != len {
            return self.unmap_subrange_in_single_vma(frames, vma_slot, map_rec, vma, base, len);
        }
        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        let page_count =
            usize::try_from(vma.len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let page_base = vma.base + (page_index as u64) * PAGE_SIZE;
            let page_offset = map_rec.vmo_offset() + (page_index as u64) * PAGE_SIZE;
            let Some(frame_id) = vmo.frame_at_offset(page_offset) else {
                continue;
            };
            let state = frames
                .state(frame_id)
                .ok_or(AddressSpaceError::InvalidFrame)?;
            if state.map_count() == 0 || state.ref_count() == 0 {
                return Err(AddressSpaceError::FrameTable(FrameTableError::RefUnderflow));
            }
            let node_id = self
                .rmap_node_at(page_base)
                .ok_or(AddressSpaceError::FrameTable(
                    FrameTableError::MissingAnchor,
                ))?;
            frames
                .unmap_frame(frame_id, node_id)
                .map_err(AddressSpaceError::FrameTable)?;
        }
        let removed = self
            .remove_vma_by_map_id(vma.map_id)
            .ok_or(AddressSpaceError::NotFound)?;
        let _ = self.remove_map_record(removed.map_id);
        self.pte_meta.clear_range(removed.base, removed.len)?;
        self.rmap_index.clear_range(removed.base, removed.len)?;
        Ok(())
    }

    /// Remove an existing mapping from the root VMAR.
    pub fn unmap(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        self.unmap_in_vmar(frames, self.root.vmar.id, base, len)
    }

    /// Change permissions on an existing mapping without changing its extent.
    pub fn protect_in_vmar(
        &mut self,
        frames: &mut FrameTable,
        vmar_id: VmarId,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let vma_slot = self
            .find_vma_slot_covering_range(vmar_id, base, len)
            .ok_or(AddressSpaceError::NotFound)?;
        let vma = *self.vmas.get(vma_slot).ok_or(AddressSpaceError::NotFound)?;
        let map_rec = self
            .map_record(vma.map_id)
            .ok_or(AddressSpaceError::NotFound)?;
        if !map_rec.max_perms().contains(new_perms) {
            return Err(AddressSpaceError::PermissionIncrease);
        }
        if map_rec.base() != base || map_rec.len() != len {
            return self.protect_subrange_in_single_vma(
                frames, vma_slot, map_rec, vma, base, len, new_perms,
            );
        }
        let vma = self
            .vmas
            .get_mut(vma_slot)
            .ok_or(AddressSpaceError::NotFound)?;
        vma.perms = new_perms;
        let logical_write = new_perms.contains(MappingPerms::WRITE);
        let _ = vma;
        self.pte_meta.update_range(base, len, |meta| {
            meta.logical_write = logical_write;
        })?;
        Ok(())
    }

    fn unmap_subrange_in_single_vma(
        &mut self,
        frames: &mut FrameTable,
        vma_index: usize,
        map_rec: MapRec,
        vma: Vma,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        let end = base
            .checked_add(len)
            .ok_or(AddressSpaceError::InvalidArgs)?;
        let left_len = base - map_rec.base();
        let right_len = map_rec.end() - end;
        let left_nodes = if left_len != 0 {
            Some(self.collect_segment_nodes(
                frames,
                map_rec,
                map_rec.base(),
                left_len,
                map_rec.id(),
                false,
            )?)
        } else {
            None
        };
        self.remove_segment_nodes(frames, map_rec, base, len)?;
        let right_map_id = if right_len != 0 {
            Some(self.alloc_map_id())
        } else {
            None
        };
        let right_nodes = if let Some(right_map_id) = right_map_id {
            Some(self.collect_segment_nodes(frames, map_rec, end, right_len, right_map_id, true)?)
        } else {
            None
        };
        self.remove_mapping_metadata(vma_index, map_rec, vma)?;
        if let Some(nodes) = left_nodes {
            self.install_split_segment(
                map_rec.id(),
                map_rec,
                vma,
                map_rec.base(),
                left_len,
                vma.perms,
                nodes,
            )?;
        }
        if let (Some(right_map_id), Some(nodes)) = (right_map_id, right_nodes) {
            self.install_split_segment(
                right_map_id,
                map_rec,
                vma,
                end,
                right_len,
                vma.perms,
                nodes,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn protect_subrange_in_single_vma(
        &mut self,
        frames: &mut FrameTable,
        vma_index: usize,
        map_rec: MapRec,
        vma: Vma,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        let end = base
            .checked_add(len)
            .ok_or(AddressSpaceError::InvalidArgs)?;
        let left_len = base - map_rec.base();
        let right_len = map_rec.end() - end;
        let left_nodes = if left_len != 0 {
            Some(self.collect_segment_nodes(
                frames,
                map_rec,
                map_rec.base(),
                left_len,
                map_rec.id(),
                false,
            )?)
        } else {
            None
        };
        let middle_map_id = if left_len == 0 {
            map_rec.id()
        } else {
            self.alloc_map_id()
        };
        let middle_nodes =
            self.collect_segment_nodes(frames, map_rec, base, len, middle_map_id, left_len != 0)?;
        let right_map_id = if right_len != 0 {
            Some(self.alloc_map_id())
        } else {
            None
        };
        let right_nodes = if let Some(right_map_id) = right_map_id {
            Some(self.collect_segment_nodes(frames, map_rec, end, right_len, right_map_id, true)?)
        } else {
            None
        };
        self.remove_mapping_metadata(vma_index, map_rec, vma)?;
        if let Some(nodes) = left_nodes {
            self.install_split_segment(
                map_rec.id(),
                map_rec,
                vma,
                map_rec.base(),
                left_len,
                vma.perms,
                nodes,
            )?;
        }
        self.install_split_segment(
            middle_map_id,
            map_rec,
            vma,
            base,
            len,
            new_perms,
            middle_nodes,
        )?;
        if let (Some(right_map_id), Some(nodes)) = (right_map_id, right_nodes) {
            self.install_split_segment(
                right_map_id,
                map_rec,
                vma,
                end,
                right_len,
                vma.perms,
                nodes,
            )?;
        }
        Ok(())
    }

    fn collect_segment_nodes(
        &mut self,
        frames: &mut FrameTable,
        map_rec: MapRec,
        base: u64,
        len: u64,
        map_id: MapId,
        reanchor: bool,
    ) -> Result<Vec<Option<RmapNodeId>>, AddressSpaceError> {
        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let mut nodes = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_base = base + (page_index as u64) * PAGE_SIZE;
            let page_offset = map_rec
                .vmo_offset()
                .checked_add(page_base - map_rec.base())
                .ok_or(AddressSpaceError::InvalidArgs)?;
            let Some(frame_id) = vmo.frame_at_offset(page_offset) else {
                nodes.push(None);
                continue;
            };
            let node_id = self
                .rmap_node_at(page_base)
                .ok_or(AddressSpaceError::FrameTable(
                    FrameTableError::MissingAnchor,
                ))?;
            if reanchor {
                frames
                    .unmap_frame(frame_id, node_id)
                    .map_err(AddressSpaceError::FrameTable)?;
                let new_node = frames
                    .map_frame(frame_id, self.make_rmap_anchor(map_id, page_index as u64))
                    .map_err(AddressSpaceError::FrameTable)?;
                nodes.push(Some(new_node));
            } else {
                nodes.push(Some(node_id));
            }
        }
        Ok(nodes)
    }

    fn remove_segment_nodes(
        &mut self,
        frames: &mut FrameTable,
        map_rec: MapRec,
        base: u64,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let page_base = base + (page_index as u64) * PAGE_SIZE;
            let page_offset = map_rec
                .vmo_offset()
                .checked_add(page_base - map_rec.base())
                .ok_or(AddressSpaceError::InvalidArgs)?;
            let Some(frame_id) = vmo.frame_at_offset(page_offset) else {
                continue;
            };
            let node_id = self
                .rmap_node_at(page_base)
                .ok_or(AddressSpaceError::FrameTable(
                    FrameTableError::MissingAnchor,
                ))?;
            frames
                .unmap_frame(frame_id, node_id)
                .map_err(AddressSpaceError::FrameTable)?;
        }
        Ok(())
    }

    fn remove_mapping_metadata(
        &mut self,
        vma_slot: SlotId,
        map_rec: MapRec,
        vma: Vma,
    ) -> Result<(), AddressSpaceError> {
        let _ = self.vmas.get(vma_slot).ok_or(AddressSpaceError::NotFound)?;
        let _ = self
            .remove_vma_by_map_id(vma.map_id)
            .ok_or(AddressSpaceError::NotFound)?;
        let _ = self
            .remove_map_record(map_rec.id())
            .ok_or(AddressSpaceError::NotFound)?;
        self.pte_meta.clear_range(vma.base, vma.len)?;
        self.rmap_index.clear_range(vma.base, vma.len)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn install_split_segment(
        &mut self,
        map_id: MapId,
        source: MapRec,
        vma: Vma,
        base: u64,
        len: u64,
        perms: MappingPerms,
        nodes: Vec<Option<RmapNodeId>>,
    ) -> Result<(), AddressSpaceError> {
        if len == 0 {
            return Ok(());
        }
        let map_rec = MapRec {
            id: map_id,
            vmar_id: source.vmar_id(),
            base,
            len,
            vmo_id: source.vmo_id(),
            global_vmo_id: source.global_vmo_id(),
            vmo_offset: source
                .vmo_offset()
                .checked_add(base - source.base())
                .ok_or(AddressSpaceError::InvalidArgs)?,
            max_perms: source.max_perms(),
            cache_policy: source.cache_policy(),
        };
        let vma = Vma {
            map_id,
            vmar_id: vma.vmar_id,
            base,
            len,
            perms,
            copy_on_write: vma.copy_on_write,
            clone_policy: vma.clone_policy,
        };
        let page_meta = self.build_pte_meta_range(map_rec, vma)?;
        self.pte_meta.install_range(base, &page_meta)?;
        self.rmap_index.install_range(base, &nodes)?;
        self.insert_map_record(map_rec);
        self.insert_vma(vma);
        Ok(())
    }

    /// Change permissions on one existing root-VMAR mapping.
    pub fn protect(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        self.protect_in_vmar(frames, self.root.vmar.id, base, len, new_perms)
    }

    /// Arm an existing mapped range for copy-on-write handling.
    pub fn mark_copy_on_write(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let mut touched_vma_indices = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_base = base + (page_index as u64) * PAGE_SIZE;
            let resolved = self
                .resolve_page_state(page_base)
                .ok_or(AddressSpaceError::NotFound)?;
            let vmo = self
                .vmo(resolved.map_rec.vmo_id())
                .ok_or(AddressSpaceError::InvalidVmo)?;
            if !vmo.supports_copy_on_write() {
                return Err(AddressSpaceError::InvalidArgs);
            }
            if !resolved.map_rec.max_perms().contains(MappingPerms::WRITE) {
                return Err(AddressSpaceError::PermissionIncrease);
            }
            if !touched_vma_indices.contains(&resolved.vma_index) {
                touched_vma_indices.push(resolved.vma_index);
            }
        }
        self.pte_meta.update_range(base, len, |meta| {
            meta.logical_write = true;
            meta.cow_shared = true;
        })?;
        for index in touched_vma_indices {
            let vma = self
                .vmas
                .get_mut(index)
                .ok_or(AddressSpaceError::NotFound)?;
            vma.copy_on_write = true;
        }
        Ok(())
    }

    /// Materialize one lazy anonymous page by binding a newly allocated frame.
    pub fn resolve_lazy_anon_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        new_frame_id: FrameId,
    ) -> Result<LazyAnonFaultResolution, AddressSpaceError> {
        if !frames.contains(new_frame_id) {
            return Err(AddressSpaceError::InvalidFrame);
        }

        let page_base = align_down(fault_va, PAGE_SIZE);
        let resolved = self
            .resolve_page_state(page_base)
            .ok_or(AddressSpaceError::NotFound)?;
        let vma = resolved.vma;
        let page_offset = resolved.map_rec.vmo_offset() + (page_base - resolved.map_rec.base());
        let page_anchor = self.make_rmap_anchor(vma.map_id, resolved.page_delta);
        let vmo = self
            .vmo(resolved.map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        if vmo.kind() != VmoKind::Anonymous {
            return Err(AddressSpaceError::NotFound);
        }

        let meta = resolved.meta;
        if meta.tag() != PteMetaTag::LazyAnon {
            return Err(AddressSpaceError::NotFound);
        }
        if vmo.frame_at_offset(page_offset).is_some() {
            return Err(AddressSpaceError::AlreadyBound);
        }

        let node_id = frames
            .map_frame(new_frame_id, page_anchor)
            .map_err(AddressSpaceError::FrameTable)?;
        if let Err(err) = self.bind_vmo_frame(resolved.map_rec.vmo_id(), page_offset, new_frame_id)
        {
            let _ = frames.unmap_frame(new_frame_id, node_id);
            return Err(err);
        }
        self.rmap_index.set_node(page_base, Some(node_id))?;

        Ok(LazyAnonFaultResolution {
            fault_page_base: page_base,
            new_frame_id,
        })
    }

    /// Bind one lazy VMO-backed page to an already-chosen resident frame.
    pub fn resolve_lazy_vmo_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        frame_id: FrameId,
    ) -> Result<LazyVmoFaultResolution, AddressSpaceError> {
        if !frames.contains(frame_id) {
            return Err(AddressSpaceError::InvalidFrame);
        }

        let page_base = align_down(fault_va, PAGE_SIZE);
        let resolved = self
            .resolve_page_state(page_base)
            .ok_or(AddressSpaceError::NotFound)?;
        let vma = resolved.vma;
        let page_offset = resolved.map_rec.vmo_offset() + (page_base - resolved.map_rec.base());
        let page_anchor = self.make_rmap_anchor(vma.map_id, resolved.page_delta);
        let vmo = self
            .vmo(resolved.map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        if resolved.meta.tag() != PteMetaTag::LazyVmo {
            return Err(AddressSpaceError::NotFound);
        }
        if let Some(existing) = vmo.frame_at_offset(page_offset) {
            if existing != frame_id {
                return Err(AddressSpaceError::AlreadyBound);
            }
            return Ok(LazyVmoFaultResolution {
                fault_page_base: page_base,
                frame_id,
            });
        }

        let node_id = frames
            .map_frame(frame_id, page_anchor)
            .map_err(AddressSpaceError::FrameTable)?;
        if let Err(err) = self.bind_vmo_frame(resolved.map_rec.vmo_id(), page_offset, frame_id) {
            let _ = frames.unmap_frame(frame_id, node_id);
            return Err(err);
        }
        self.rmap_index.set_node(page_base, Some(node_id))?;

        Ok(LazyVmoFaultResolution {
            fault_page_base: page_base,
            frame_id,
        })
    }

    /// Resolve a write fault on a copy-on-write mapping by rebinding one page.
    pub fn resolve_cow_fault(
        &mut self,
        frames: &mut FrameTable,
        fault_va: u64,
        new_frame_id: FrameId,
    ) -> Result<CowFaultResolution, AddressSpaceError> {
        if !frames.contains(new_frame_id) {
            return Err(AddressSpaceError::InvalidFrame);
        }

        let page_base = align_down(fault_va, PAGE_SIZE);
        let resolved = self
            .resolve_page_state(page_base)
            .ok_or(AddressSpaceError::NotCopyOnWrite)?;
        let index = resolved.vma_index;
        let vma = resolved.vma;
        let map_rec = resolved.map_rec;
        let meta = resolved.meta;
        if !meta.cow_shared() || !meta.logical_write() || meta.tag() != PteMetaTag::Present {
            return Err(AddressSpaceError::NotCopyOnWrite);
        }
        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        if !vmo.supports_copy_on_write() {
            return Err(AddressSpaceError::NotCopyOnWrite);
        }

        let page_offset = map_rec.vmo_offset() + (page_base - map_rec.base());
        let fault_page_delta = resolved.page_delta;
        let page_anchor = self.make_rmap_anchor(vma.map_id, fault_page_delta);
        let old_node_id = self
            .rmap_node_at(page_base)
            .ok_or(AddressSpaceError::FrameTable(
                FrameTableError::MissingAnchor,
            ))?;
        let old_frame_id = self
            .vmo(map_rec.vmo_id())
            .and_then(|vmo| vmo.frame_at_offset(page_offset))
            .ok_or(AddressSpaceError::InvalidFrame)?;

        let new_node_id = frames
            .map_frame(new_frame_id, page_anchor)
            .map_err(AddressSpaceError::FrameTable)?;
        if let Err(err) = self.rebind_vmo_frame(map_rec.vmo_id(), page_offset, new_frame_id) {
            let _ = frames.unmap_frame(new_frame_id, new_node_id);
            return Err(err);
        }
        self.rmap_index.set_node(page_base, Some(new_node_id))?;
        if let Err(err) = frames.unmap_frame(old_frame_id, old_node_id) {
            let _ = self.rebind_vmo_frame(map_rec.vmo_id(), page_offset, old_frame_id);
            let _ = self.rmap_index.set_node(page_base, Some(old_node_id));
            let _ = frames.unmap_frame(new_frame_id, new_node_id);
            return Err(AddressSpaceError::FrameTable(err));
        }
        let vma = self
            .vmas
            .get_mut(index)
            .ok_or(AddressSpaceError::NotFound)?;
        vma.perms.insert(MappingPerms::WRITE);
        vma.copy_on_write = false;
        let refresh_base = vma.base;
        let refresh_len = vma.len;
        let _ = vma;
        self.pte_meta
            .update_range(refresh_base, refresh_len, |meta| {
                if meta.page_delta == fault_page_delta {
                    meta.logical_write = true;
                    meta.cow_shared = false;
                }
            })?;
        let still_cow = self.mapping_has_cow_shared(refresh_base, refresh_len)?;
        let vma = self
            .vmas
            .get_mut(index)
            .ok_or(AddressSpaceError::NotFound)?;
        vma.copy_on_write = still_cow;

        Ok(CowFaultResolution {
            fault_page_base: page_base,
            old_frame_id,
            new_frame_id,
        })
    }

    /// Replace every page of one anonymous mapping with shared frames and arm it for COW.
    pub fn replace_mapping_frames_copy_on_write(
        &mut self,
        frames: &mut FrameTable,
        base: u64,
        len: u64,
        replacement_frames: &[FrameId],
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        if replacement_frames.len() != page_count {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let index = self
            .find_vma_slot_covering_range(self.root.vmar.id, base, len)
            .ok_or(AddressSpaceError::NotFound)?;
        let vma = *self.vmas.get(index).ok_or(AddressSpaceError::NotFound)?;
        let map_rec = self
            .map_record(vma.map_id)
            .ok_or(AddressSpaceError::NotFound)?;
        if !map_rec.max_perms().contains(MappingPerms::WRITE) {
            return Err(AddressSpaceError::PermissionIncrease);
        }

        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        if vmo.kind() != VmoKind::Anonymous {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let mut page_rebindings = Vec::with_capacity(page_count);
        for (page_index, &new_frame_id) in replacement_frames.iter().enumerate() {
            if !frames.contains(new_frame_id) {
                return Err(AddressSpaceError::InvalidFrame);
            }
            let page_offset = map_rec
                .vmo_offset()
                .checked_add((page_index as u64) * PAGE_SIZE)
                .ok_or(AddressSpaceError::InvalidArgs)?;
            let page_anchor = self.make_rmap_anchor(vma.map_id, page_index as u64);
            let old_frame_id = vmo.frame_at_offset(page_offset);
            let page_base = vma.base + (page_index as u64) * PAGE_SIZE;
            let old_node_id = if old_frame_id.is_some() {
                Some(
                    self.rmap_node_at(page_base)
                        .ok_or(AddressSpaceError::FrameTable(
                            FrameTableError::MissingAnchor,
                        ))?,
                )
            } else {
                None
            };
            if let Some(existing) = old_frame_id {
                let state = frames
                    .state(existing)
                    .ok_or(AddressSpaceError::InvalidFrame)?;
                if state.ref_count() == 0 || state.map_count() == 0 {
                    return Err(AddressSpaceError::FrameTable(FrameTableError::RefUnderflow));
                }
            }
            page_rebindings.push((
                page_base,
                page_offset,
                page_anchor,
                old_node_id,
                old_frame_id,
                new_frame_id,
            ));
        }

        let mut incremented = Vec::new();
        for &(_, _, page_anchor, old_node_id, old_frame_id, new_frame_id) in &page_rebindings {
            if old_frame_id == Some(new_frame_id) {
                continue;
            }
            if let Err(err) = frames.map_frame(new_frame_id, page_anchor).map(|node_id| {
                incremented.push((new_frame_id, node_id, page_anchor, old_node_id));
            }) {
                for (rollback_frame, rollback_node, _, _) in incremented {
                    let _ = frames.unmap_frame(rollback_frame, rollback_node);
                }
                return Err(AddressSpaceError::FrameTable(err));
            }
        }

        for &(page_base, page_offset, _, old_node_id, old_frame_id, new_frame_id) in
            &page_rebindings
        {
            if old_frame_id == Some(new_frame_id) {
                continue;
            }
            let new_node_id = incremented
                .iter()
                .find_map(|&(frame_id, node_id, page_anchor, _)| {
                    (frame_id == new_frame_id
                        && page_anchor.page_delta()
                            == (page_offset - map_rec.vmo_offset()) / PAGE_SIZE)
                        .then_some(node_id)
                })
                .ok_or(AddressSpaceError::FrameTable(
                    FrameTableError::MissingAnchor,
                ))?;
            if let Err(err) = self.rebind_vmo_frame(map_rec.vmo_id(), page_offset, new_frame_id) {
                for (rollback_frame, rollback_node, _, _) in incremented {
                    let _ = frames.unmap_frame(rollback_frame, rollback_node);
                }
                return Err(err);
            }
            self.rmap_index.set_node(page_base, Some(new_node_id))?;
            let Some(old_frame_id) = old_frame_id else {
                continue;
            };
            let Some(old_node_id) = old_node_id else {
                return Err(AddressSpaceError::FrameTable(
                    FrameTableError::MissingAnchor,
                ));
            };
            frames
                .unmap_frame(old_frame_id, old_node_id)
                .map_err(AddressSpaceError::FrameTable)?;
        }

        let vma = self
            .vmas
            .get_mut(index)
            .ok_or(AddressSpaceError::NotFound)?;
        vma.perms.remove(MappingPerms::WRITE);
        vma.copy_on_write = true;
        let _ = vma;
        self.pte_meta.update_range(base, len, |meta| {
            meta.tag = PteMetaTag::Present;
            meta.logical_write = true;
            meta.cow_shared = true;
        })?;
        Ok(())
    }

    /// Resolve one virtual address to its backing VMO metadata.
    pub fn lookup(&self, va: u64) -> Option<VmaLookup> {
        self.resolve_page_state(va)
            .and_then(|resolved| self.lookup_from_resolved_page(resolved, va))
    }

    /// Resolve a virtual range if it is fully covered by a single VMA.
    pub fn lookup_range(&self, base: u64, len: u64) -> Option<VmaLookup> {
        let resolved = self.resolve_range_state(base, len)?;
        self.lookup_from_resolved_page(resolved, base)
    }

    /// Return whether the entire range is backed by contiguous VMAs.
    pub fn contains_range(&self, base: u64, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let len = len as u64;
        if validate_lookup_range(base, len).is_err() {
            return false;
        }
        let end = base + len;
        let mut cursor = base;
        let mut slot = self
            .vma_slots_by_base
            .range(..=base)
            .next_back()
            .map(|(_, slot)| *slot);
        while cursor < end {
            let Some(current_slot) = slot else {
                return false;
            };
            let Some(vma) = self.vmas.get(current_slot).copied() else {
                return false;
            };
            if !vma.contains(cursor) {
                return false;
            }
            cursor = core::cmp::min(vma.end(), end);
            slot = self
                .vma_slots_by_base
                .range((
                    core::ops::Bound::Excluded(vma.base),
                    core::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(_, slot)| *slot);
        }
        true
    }

    fn alloc_vmar_id(&mut self) -> VmarId {
        let id = VmarId::new(self.next_vmar_id);
        self.next_vmar_id = self.next_vmar_id.wrapping_add(1);
        id
    }

    fn alloc_map_id(&mut self) -> MapId {
        let id = MapId::new(self.next_map_id);
        self.next_map_id = self.next_map_id.wrapping_add(1);
        id
    }

    fn make_rmap_anchor(&self, map_id: MapId, page_delta: u64) -> ReverseMapAnchor {
        ReverseMapAnchor::new(self.id, map_id, page_delta)
    }

    fn lookup_from_resolved_page(&self, resolved: ResolvedPageState, va: u64) -> Option<VmaLookup> {
        let vma = resolved.vma;
        let vmo = self.vmo(resolved.map_rec.vmo_id())?;
        let resolved_offset = resolved.map_rec.vmo_offset() + (va - resolved.map_rec.base());
        let mut perms = vma.perms;
        if !resolved.meta.logical_write() || resolved.meta.cow_shared() {
            perms.remove(MappingPerms::WRITE);
        }
        Some(VmaLookup {
            address_space_id: self.id,
            map_id: resolved.map_rec.id(),
            vmar_id: resolved.map_rec.vmar_id(),
            vmo_id: resolved.map_rec.vmo_id(),
            global_vmo_id: vmo.global_id(),
            shared_backing_global_vmo_id: vmo.shared_backing_id(),
            fault_global_vmo_id: vmo.fault_source_id(),
            vmo_kind: vmo.kind(),
            vmo_offset: resolved_offset,
            frame_id: vmo.frame_at_offset(resolved_offset),
            perms,
            max_perms: resolved.map_rec.max_perms(),
            cache_policy: resolved.map_rec.cache_policy(),
            copy_on_write: resolved.meta.cow_shared(),
            clone_policy: vma.clone_policy,
            global_backed: vmo.is_global_backed(),
            mapping_base: resolved.map_rec.base(),
            mapping_len: resolved.map_rec.len(),
        })
    }

    fn resolve_page_state(&self, va: u64) -> Option<ResolvedPageState> {
        let page_base = align_down(va, PAGE_SIZE);
        let meta = self.pte_meta(page_base)?;
        let map_rec = self.map_record(meta.map_id())?;
        if !map_rec.contains_page(page_base) {
            return None;
        }
        let page_delta = (page_base - map_rec.base()) / PAGE_SIZE;
        if meta.page_delta() != page_delta {
            return None;
        }
        let vma_index = *self.vma_slot_by_map_id.get(&meta.map_id())?;
        let vma = *self.vmas.get(vma_index)?;
        if vma.vmar_id != map_rec.vmar_id()
            || vma.base != map_rec.base()
            || vma.len != map_rec.len()
            || !vma.contains(page_base)
        {
            return None;
        }
        Some(ResolvedPageState {
            page_base,
            page_delta,
            meta,
            map_rec,
            vma_index,
            vma,
        })
    }

    fn resolve_range_state(&self, base: u64, len: u64) -> Option<ResolvedPageState> {
        validate_lookup_range(base, len).ok()?;
        let resolved = self.resolve_page_state(base)?;
        if !resolved.map_rec.contains_range(base, len) {
            return None;
        }
        let last_page = align_down(base + len - 1, PAGE_SIZE);
        let mut page_base = align_down(base, PAGE_SIZE);
        while page_base <= last_page {
            let page = self.resolve_page_state(page_base)?;
            if page.map_rec.id() != resolved.map_rec.id() || page.vma_index != resolved.vma_index {
                return None;
            }
            page_base = page_base.checked_add(PAGE_SIZE)?;
        }
        Some(resolved)
    }

    fn first_rmap_anchor_for_frame_excluding(
        &self,
        frame_id: FrameId,
        excluded_map_id: Option<MapId>,
    ) -> Option<ReverseMapAnchor> {
        for vma in self.vmas.iter() {
            if excluded_map_id == Some(vma.map_id) {
                continue;
            }
            let Some(map_rec) = self.map_record(vma.map_id) else {
                continue;
            };
            let Some(vmo) = self.vmo(map_rec.vmo_id()) else {
                continue;
            };
            let page_count = vma.len / PAGE_SIZE;
            for page_delta in 0..page_count {
                let page_offset = map_rec.vmo_offset() + page_delta * PAGE_SIZE;
                if vmo.frame_at_offset(page_offset) == Some(frame_id) {
                    return Some(self.make_rmap_anchor(vma.map_id, page_delta));
                }
            }
        }
        None
    }

    fn refresh_vmo_page_metadata(
        &mut self,
        vmo_id: VmoId,
        page_offset: u64,
    ) -> Result<(), AddressSpaceError> {
        if !is_page_aligned(page_offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let vmo = self.vmo(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        let tag = pte_meta_tag_for_vmo(vmo, vmo.frame_at_offset(page_offset));
        let mut page_bases = Vec::new();
        for map_id in self
            .map_ids_by_vmo_id
            .get(&vmo_id)
            .into_iter()
            .flatten()
            .copied()
        {
            let Some(map_rec) = self.map_record(map_id) else {
                continue;
            };
            let Some(&vma_index) = self.vma_slot_by_map_id.get(&map_id) else {
                continue;
            };
            let Some(vma) = self.vmas.get(vma_index).copied() else {
                continue;
            };
            if page_offset < map_rec.vmo_offset()
                || page_offset >= map_rec.vmo_offset() + map_rec.len()
            {
                continue;
            }
            let page_delta = (page_offset - map_rec.vmo_offset()) / PAGE_SIZE;
            page_bases.push(vma.base + page_delta * PAGE_SIZE);
        }
        for page_base in page_bases {
            if self.pte_meta(page_base).is_some() {
                self.pte_meta
                    .update_range(page_base, PAGE_SIZE, |meta| meta.tag = tag)?;
            }
        }
        Ok(())
    }

    fn mapping_has_cow_shared(&self, base: u64, len: u64) -> Result<bool, AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let page_count =
            usize::try_from(len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        for page_index in 0..page_count {
            let page_base = base + (page_index as u64) * PAGE_SIZE;
            let meta = self
                .pte_meta(page_base)
                .ok_or(AddressSpaceError::NotFound)?;
            if meta.cow_shared() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn build_pte_meta_range(
        &self,
        map_rec: MapRec,
        vma: Vma,
    ) -> Result<Vec<PteMeta>, AddressSpaceError> {
        let vmo = self
            .vmo(map_rec.vmo_id())
            .ok_or(AddressSpaceError::InvalidVmo)?;
        let page_count =
            usize::try_from(vma.len / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let logical_write = vma.copy_on_write || vma.perms.contains(MappingPerms::WRITE);
        let mut page_meta = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let page_delta = page_index as u64;
            let page_offset = map_rec
                .vmo_offset()
                .checked_add(page_delta * PAGE_SIZE)
                .ok_or(AddressSpaceError::InvalidArgs)?;
            page_meta.push(PteMeta {
                tag: pte_meta_tag_for_vmo(vmo, vmo.frame_at_offset(page_offset)),
                logical_write,
                cow_shared: vma.copy_on_write,
                pinned: false,
                map_id: map_rec.id(),
                page_delta,
            });
        }
        Ok(page_meta)
    }

    fn try_allocate_from_magazine(
        &mut self,
        cpu_id: usize,
        len: u64,
        align: u64,
    ) -> Result<Option<u64>, AddressSpaceError> {
        let Some(magazine) = self.va_magazines.get(&cpu_id).copied() else {
            return Ok(None);
        };
        let Some(base) = align_up(magazine.cursor, align) else {
            return Ok(None);
        };
        let Some(end) = base.checked_add(len) else {
            return Err(AddressSpaceError::InvalidArgs);
        };
        if end > magazine.end || !self.root_range_is_free(base, len) {
            return Ok(None);
        }
        if let Some(magazine) = self.va_magazines.get_mut(&cpu_id) {
            magazine.cursor = end;
        }
        Ok(Some(base))
    }

    fn allocation_start_hint(
        &self,
        parent: VmarRecord,
        cpu_id: usize,
        len: u64,
        align: u64,
        window_end: u64,
    ) -> Result<u64, AddressSpaceError> {
        let usable_end = window_end
            .checked_sub(len)
            .and_then(|end| end.checked_add(align))
            .ok_or(AddressSpaceError::OutOfRange)?;
        self.aslr_start_hint(parent, cpu_id, len, align, usable_end)
    }

    fn compact_start_hint(&self, parent: VmarRecord) -> u64 {
        core::cmp::max(parent.vmar.base, parent.alloc_cursor)
    }

    fn placement_start_hint(
        &self,
        parent: VmarRecord,
        cpu_id: usize,
        len: u64,
        align: u64,
        window_end: u64,
    ) -> Result<u64, AddressSpaceError> {
        match parent.placement_policy {
            VmarPlacementPolicy::Compact => Ok(self.compact_start_hint(parent)),
            VmarPlacementPolicy::Randomized => {
                self.allocation_start_hint(parent, cpu_id, len, align, window_end)
            }
        }
    }

    fn aslr_start_hint(
        &self,
        parent: VmarRecord,
        cpu_id: usize,
        len: u64,
        align: u64,
        usable_end: u64,
    ) -> Result<u64, AddressSpaceError> {
        let candidate_min = parent.vmar.base;
        if usable_end <= candidate_min {
            return Ok(candidate_min);
        }
        let span = usable_end
            .checked_sub(candidate_min)
            .ok_or(AddressSpaceError::InvalidArgs)?;
        let slot_count = core::cmp::max(1, span / align);
        let seed = mix_u64(
            parent.random_state
                ^ len.rotate_left(5)
                ^ align.rotate_left(11)
                ^ parent.vmar.len.rotate_left(17)
                ^ (cpu_id as u64).wrapping_mul(0x94d0_49bb_1331_11eb),
        );
        let slot = if slot_count > 1 {
            1 + (seed % (slot_count - 1))
        } else {
            0
        };
        let candidate = candidate_min
            .checked_add(
                slot.checked_mul(align)
                    .ok_or(AddressSpaceError::InvalidArgs)?,
            )
            .ok_or(AddressSpaceError::InvalidArgs)?;
        Ok(core::cmp::min(candidate, usable_end - align))
    }

    fn observe_randomized_placement(&mut self, vmar_id: VmarId, base: u64, len: u64) {
        if let Some(record) = self.vmar_record_mut(vmar_id)
            && record.placement_policy == VmarPlacementPolicy::Randomized
        {
            record.random_state = mix_u64(
                record.random_state
                    ^ base.rotate_left(7)
                    ^ len.rotate_left(19)
                    ^ record.alloc_cursor.rotate_left(29),
            );
        }
    }

    fn observe_compact_cursor(&mut self, vmar_id: VmarId, base: u64, len: u64) {
        if let Some(record) = self.vmar_record_mut(vmar_id)
            && let Some(cursor) = base.checked_add(len)
            && cursor > record.alloc_cursor
        {
            record.alloc_cursor = cursor;
        }
    }

    fn observe_mapping_placement(&mut self, vmar_id: VmarId, base: u64, len: u64) {
        self.observe_compact_cursor(vmar_id, base, len);
        self.observe_randomized_placement(vmar_id, base, len);
    }

    fn search_end_for_allocation(
        parent: Vmar,
        offset: u64,
        len: u64,
        upper_limit: bool,
    ) -> Result<u64, AddressSpaceError> {
        if !upper_limit {
            return Ok(parent.end());
        }
        let upper_bound = parent
            .base
            .checked_add(offset)
            .ok_or(AddressSpaceError::InvalidArgs)?;
        if upper_bound > parent.end() {
            return Err(AddressSpaceError::InvalidArgs);
        }
        if upper_bound < parent.base.saturating_add(len) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        Ok(upper_bound)
    }

    fn find_free_gap_in_vmar_window_with_hint(
        &self,
        vmar_id: VmarId,
        window_start: u64,
        window_end: u64,
        start_hint: u64,
        len: u64,
        align: u64,
    ) -> Option<(u64, u64)> {
        let clamped_start = start_hint.clamp(window_start, window_end);
        self.find_free_gap_in_vmar_window(vmar_id, clamped_start, window_end, len, align)
            .or_else(|| {
                (clamped_start > window_start).then(|| {
                    self.find_free_gap_in_vmar_window(
                        vmar_id,
                        window_start,
                        clamped_start,
                        len,
                        align,
                    )
                })?
            })
    }

    fn should_place_compact(parent: VmarRecord, mode: VmarAllocMode) -> bool {
        mode == VmarAllocMode::Compact || parent.placement_policy == VmarPlacementPolicy::Compact
    }

    fn insert_child_vmar(
        &mut self,
        cpu_id: usize,
        parent_id: VmarId,
        base: u64,
        len: u64,
        placement_policy: VmarPlacementPolicy,
    ) -> Result<Vmar, AddressSpaceError> {
        if !self.range_is_free_in_vmar(parent_id, base, len) {
            return Err(AddressSpaceError::Overlap);
        }
        let vmar = Vmar {
            id: self.alloc_vmar_id(),
            base,
            len,
        };
        self.insert_vmar_record(VmarRecord {
            vmar,
            parent_id: Some(parent_id),
            alloc_cursor: base,
            placement_policy,
            random_state: initial_vmar_random_state(self.id, vmar),
        });
        if parent_id == self.root.vmar.id
            && let Some(magazine) = self.va_magazines.get_mut(&cpu_id)
        {
            let cursor = base
                .checked_add(len)
                .ok_or(AddressSpaceError::InvalidArgs)?;
            if cursor > magazine.cursor {
                magazine.cursor = cursor;
            }
        }
        if let Some(parent) = self.vmar_record_mut(parent_id)
            && let Some(cursor) = base.checked_add(len)
            && cursor > parent.alloc_cursor
        {
            parent.alloc_cursor = cursor;
        }
        self.observe_randomized_placement(parent_id, base, len);
        Ok(vmar)
    }

    fn occupied_ranges_for_vmar(&self, vmar_id: VmarId) -> Vec<(u64, u64)> {
        if self.vmar(vmar_id).is_none() {
            return Vec::new();
        }
        let vma_slots = self
            .vma_slots_by_vmar_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let child_slots = self
            .child_vmar_slots_by_parent_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut ranges = Vec::with_capacity(vma_slots.len() + child_slots.len());
        let mut vma_index = 0usize;
        let mut child_index = 0usize;
        while vma_index < vma_slots.len() || child_index < child_slots.len() {
            let next_vma = vma_slots
                .get(vma_index)
                .and_then(|slot| self.vmas.get(*slot))
                .map(|vma| (vma.base(), vma.end()));
            let next_child = child_slots
                .get(child_index)
                .and_then(|slot| self.vmars.get(*slot))
                .map(|record| (record.vmar.base(), record.vmar.end()));
            let next = match (next_vma, next_child) {
                (Some(vma), Some(child)) if vma.0 <= child.0 => {
                    vma_index += 1;
                    vma
                }
                (Some(_), Some(child)) => {
                    child_index += 1;
                    child
                }
                (Some(vma), None) => {
                    vma_index += 1;
                    vma
                }
                (None, Some(child)) => {
                    child_index += 1;
                    child
                }
                (None, None) => break,
            };
            if let Some((_, merged_end)) = ranges.last_mut()
                && next.0 <= *merged_end
            {
                *merged_end = core::cmp::max(*merged_end, next.1);
            } else {
                ranges.push(next);
            }
        }
        ranges
    }

    fn root_range_is_free(&self, base: u64, len: u64) -> bool {
        self.range_is_free_in_vmar(self.root.vmar.id, base, len)
    }

    fn find_free_gap_in_vmar_window(
        &self,
        vmar_id: VmarId,
        start: u64,
        end: u64,
        len: u64,
        align: u64,
    ) -> Option<(u64, u64)> {
        if start >= end {
            return None;
        }
        let occupied = self.occupied_ranges_for_vmar(vmar_id);
        let mut cursor = start;
        for (occupied_base, occupied_end) in occupied {
            if occupied_end <= cursor {
                continue;
            }
            if occupied_base >= end {
                break;
            }
            let gap_end = core::cmp::min(occupied_base, end);
            let candidate = align_up(cursor, align)?;
            if candidate.checked_add(len)? <= gap_end {
                return Some((candidate, gap_end));
            }
            cursor = core::cmp::max(cursor, core::cmp::min(occupied_end, end));
            if cursor >= end {
                return None;
            }
        }

        let candidate = align_up(cursor, align)?;
        (candidate.checked_add(len)? <= end).then_some((candidate, end))
    }

    fn range_is_free_in_vmar(&self, vmar_id: VmarId, base: u64, len: u64) -> bool {
        let Some(vmar) = self.vmar(vmar_id) else {
            return false;
        };
        vmar.contains_range(base, len)
            && !self.occupied_ranges_for_vmar(vmar_id).into_iter().any(
                |(occupied_base, occupied_end)| {
                    let occupied_len = occupied_end - occupied_base;
                    ranges_overlap(occupied_base, occupied_len, base, len)
                },
            )
    }

    fn mapping_intersects_foreign_vmar(&self, target_vmar_id: VmarId, base: u64, len: u64) -> bool {
        self.vmars.iter().any(|record| {
            record.vmar.id != target_vmar_id
                && !self.is_ancestor_vmar(record.vmar.id, target_vmar_id)
                && ranges_overlap(record.vmar.base(), record.vmar.len(), base, len)
        })
    }

    fn is_ancestor_vmar(&self, candidate_ancestor: VmarId, descendant: VmarId) -> bool {
        let mut current = self
            .vmar_record(descendant)
            .and_then(|record| record.parent_id);
        while let Some(parent_id) = current {
            if parent_id == candidate_ancestor {
                return true;
            }
            current = self
                .vmar_record(parent_id)
                .and_then(|record| record.parent_id);
        }
        false
    }

    fn collect_vmar_subtree_ids(&self, root_id: VmarId) -> Vec<VmarId> {
        let mut ids = vec![root_id];
        let mut cursor = 0;
        while cursor < ids.len() {
            let parent_id = ids[cursor];
            if let Some(slots) = self.child_vmar_slots_by_parent_id.get(&parent_id) {
                for &slot in slots {
                    let Some(record) = self.vmars.get(slot) else {
                        continue;
                    };
                    ids.push(record.vmar.id);
                }
            }
            cursor += 1;
        }
        ids
    }

    fn append_mapped_ranges_in_vmar_subtree(&self, vmar_id: VmarId, out: &mut Vec<(u64, u64)>) {
        let vma_slots = self
            .vma_slots_by_vmar_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let child_slots = self
            .child_vmar_slots_by_parent_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut vma_index = 0usize;
        let mut child_index = 0usize;
        while vma_index < vma_slots.len() || child_index < child_slots.len() {
            let next_vma = vma_slots
                .get(vma_index)
                .and_then(|slot| self.vmas.get(*slot))
                .map(|vma| (vma.base(), vma.len()));
            let next_child = child_slots
                .get(child_index)
                .and_then(|slot| self.vmars.get(*slot))
                .map(|record| (record.vmar.base(), record.vmar.id()));
            match (next_vma, next_child) {
                (Some(vma), Some(child)) if vma.0 <= child.0 => {
                    vma_index += 1;
                    out.push(vma);
                }
                (Some(_), Some((_, child_id))) => {
                    child_index += 1;
                    self.append_mapped_ranges_in_vmar_subtree(child_id, out);
                }
                (Some(vma), None) => {
                    vma_index += 1;
                    out.push(vma);
                }
                (None, Some((_, child_id))) => {
                    child_index += 1;
                    self.append_mapped_ranges_in_vmar_subtree(child_id, out);
                }
                (None, None) => break,
            }
        }
    }

    fn append_destroy_unmaps_in_vmar_subtree(
        &self,
        vmar_id: VmarId,
        out: &mut Vec<(VmarId, u64, u64)>,
    ) {
        let vma_slots = self
            .vma_slots_by_vmar_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let child_slots = self
            .child_vmar_slots_by_parent_id
            .get(&vmar_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut vma_index = 0usize;
        let mut child_index = 0usize;
        while vma_index < vma_slots.len() || child_index < child_slots.len() {
            let next_vma = vma_slots
                .get(vma_index)
                .and_then(|slot| self.vmas.get(*slot))
                .map(|vma| (vma.base(), vma.vmar_id, vma.len()));
            let next_child = child_slots
                .get(child_index)
                .and_then(|slot| self.vmars.get(*slot))
                .map(|record| (record.vmar.base(), record.vmar.id()));
            match (next_vma, next_child) {
                (Some((base, owner_vmar_id, len)), Some((child_base, _))) if base <= child_base => {
                    vma_index += 1;
                    out.push((owner_vmar_id, base, len));
                }
                (Some(_), Some((_, child_id))) => {
                    child_index += 1;
                    self.append_destroy_unmaps_in_vmar_subtree(child_id, out);
                }
                (Some((base, owner_vmar_id, len)), None) => {
                    vma_index += 1;
                    out.push((owner_vmar_id, base, len));
                }
                (None, Some((_, child_id))) => {
                    child_index += 1;
                    self.append_destroy_unmaps_in_vmar_subtree(child_id, out);
                }
                (None, None) => break,
            }
        }
    }

    fn rebind_vmo_frame(
        &mut self,
        vmo_id: VmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), AddressSpaceError> {
        if !is_page_aligned(offset) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let vmo = self.vmo_mut(vmo_id).ok_or(AddressSpaceError::InvalidVmo)?;
        if offset >= vmo.size_bytes {
            return Err(AddressSpaceError::OutOfRange);
        }
        let page_index =
            usize::try_from(offset / PAGE_SIZE).map_err(|_| AddressSpaceError::InvalidArgs)?;
        let slot = vmo
            .frames
            .get_mut(page_index)
            .ok_or(AddressSpaceError::OutOfRange)?;
        *slot = Some(frame_id);
        let _ = slot;
        let _ = vmo;
        self.refresh_vmo_page_metadata(vmo_id, offset)?;
        Ok(())
    }
}

fn validate_mapping_range(base: u64, len: u64) -> Result<(), AddressSpaceError> {
    if len == 0 || !is_page_aligned(base) || !is_page_aligned(len) {
        return Err(AddressSpaceError::InvalidArgs);
    }
    let Some(_end) = base.checked_add(len) else {
        return Err(AddressSpaceError::InvalidArgs);
    };
    Ok(())
}

fn validate_lookup_range(base: u64, len: u64) -> Result<(), AddressSpaceError> {
    if len == 0 {
        return Err(AddressSpaceError::InvalidArgs);
    }
    let Some(_end) = base.checked_add(len) else {
        return Err(AddressSpaceError::InvalidArgs);
    };
    Ok(())
}

fn is_page_aligned(value: u64) -> bool {
    value & (PAGE_SIZE - 1) == 0
}

const fn vpn_of(va: u64) -> u64 {
    va / PAGE_SIZE
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|aligned| aligned & !mask)
}

fn ranges_overlap(left_base: u64, left_len: u64, right_base: u64, right_len: u64) -> bool {
    let left_end = left_base + left_len;
    let right_end = right_base + right_len;
    left_base < right_end && right_base < left_end
}

const fn vmo_fault_policy_for_create(kind: VmoKind) -> VmoFaultPolicy {
    kind.fault_policy_for_create()
}

const fn vmo_fault_policy_for_import(kind: VmoKind) -> VmoFaultPolicy {
    kind.fault_policy_for_import()
}

fn pte_meta_tag_for_vmo(vmo: &Vmo, frame_id: Option<FrameId>) -> PteMetaTag {
    match frame_id {
        Some(_) => vmo.kind().resident_pte_tag(),
        None => vmo.missing_page_tag(),
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ROOT_BASE: u64 = 0x1_0000_0000;
    const ROOT_LEN: u64 = 0x4000;

    fn global_vmo_id(raw: u64) -> GlobalVmoId {
        GlobalVmoId::new(raw)
    }

    fn sample_space() -> (AddressSpace, FrameTable, FrameId, FrameId) {
        let mut frames = FrameTable::new();
        let code_frame = frames.register_existing(0x20_000).unwrap();
        let data_frame = frames.register_existing(0x30_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let code = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(1))
            .unwrap();
        let data = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(2))
            .unwrap();
        space.bind_vmo_frame(code, 0, code_frame).unwrap();
        space.bind_vmo_frame(data, 0, data_frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                code,
                0,
                MappingPerms::READ
                    | MappingPerms::WRITE
                    | MappingPerms::EXECUTE
                    | MappingPerms::USER,
                MappingPerms::READ
                    | MappingPerms::WRITE
                    | MappingPerms::EXECUTE
                    | MappingPerms::USER,
            )
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                data,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        (space, frames, code_frame, data_frame)
    }

    fn sample_large_space() -> (AddressSpace, FrameTable, [FrameId; 3]) {
        let mut frames = FrameTable::new();
        let frame0 = frames.register_existing(0x50_000).unwrap();
        let frame1 = frames.register_existing(0x51_000).unwrap();
        let frame2 = frames.register_existing(0x52_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 3, global_vmo_id(30))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame0).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, frame1).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE * 2, frame2).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 3,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        (space, frames, [frame0, frame1, frame2])
    }

    #[test]
    fn lookup_reports_vmo_offset_perms_and_frame() {
        let (space, frames, code_frame, _) = sample_space();
        let lookup = space.lookup(ROOT_BASE + 0x120).unwrap();
        let map_rec = space.map_record(lookup.map_id()).unwrap();
        assert_eq!(lookup.address_space_id(), space.id());
        assert_eq!(lookup.vmo_offset(), 0x120);
        assert_eq!(lookup.global_vmo_id(), global_vmo_id(1));
        assert!(lookup.perms().contains(MappingPerms::EXECUTE));
        assert_eq!(lookup.mapping_base(), ROOT_BASE);
        assert_eq!(lookup.mapping_len(), PAGE_SIZE);
        assert_eq!(lookup.frame_id(), Some(code_frame));
        assert_eq!(map_rec.base(), ROOT_BASE);
        assert_eq!(map_rec.len(), PAGE_SIZE);
        assert_eq!(map_rec.vmar_id(), space.root_vmar().id());
        assert_eq!(map_rec.vmo_id(), lookup.vmo_id());
        assert_eq!(map_rec.global_vmo_id(), lookup.global_vmo_id());
        assert_eq!(map_rec.vmo_offset(), 0);
        assert_eq!(
            map_rec.max_perms(),
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::EXECUTE | MappingPerms::USER
        );
        assert_eq!(frames.state(code_frame).unwrap().ref_count(), 1);
        assert_eq!(frames.state(code_frame).unwrap().map_count(), 1);
        assert_eq!(
            frames.state(code_frame).unwrap().rmap_anchor(),
            Some(ReverseMapAnchor::new(space.id(), lookup.map_id(), 0))
        );
    }

    #[test]
    fn child_vmar_mapping_preserves_vmar_identity() {
        let mut frames = FrameTable::new();
        let data_frame = frames.register_existing(0x40_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let data = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(9))
            .unwrap();
        space.bind_vmo_frame(data, 0, data_frame).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 2 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        space
            .map_fixed_in_vmar(
                &mut frames,
                child.id(),
                child.base(),
                PAGE_SIZE,
                data,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        let lookup = space.lookup(child.base()).unwrap();
        let map_rec = space.map_record(lookup.map_id()).unwrap();
        assert_eq!(lookup.address_space_id(), space.id());
        assert_eq!(lookup.vmar_id(), child.id());
        assert_eq!(map_rec.vmar_id(), child.id());
        assert_eq!(space.map_record_for_va(child.base()), Some(map_rec));

        assert_eq!(
            space
                .protect_in_vmar(
                    &mut frames,
                    space.root_vmar().id(),
                    child.base(),
                    PAGE_SIZE,
                    MappingPerms::READ | MappingPerms::USER,
                )
                .unwrap_err(),
            AddressSpaceError::NotFound
        );
        space
            .unmap_in_vmar(&mut frames, child.id(), child.base(), PAGE_SIZE)
            .unwrap();
        assert!(space.lookup(child.base()).is_none());
    }

    #[test]
    fn child_vmar_non_specific_mapping_and_destroy_releases_range() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x41_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(10))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 2 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let mapped = space
            .map_anywhere_in_vmar(
                &mut frames,
                0,
                child.id(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                PAGE_SIZE,
            )
            .unwrap();
        assert_eq!(mapped, child.base());

        let removed = space.destroy_vmar(&mut frames, child.id()).unwrap();
        assert_eq!(removed, vec![(child.base(), PAGE_SIZE)]);
        assert!(space.vmar(child.id()).is_none());
        assert!(space.lookup(child.base()).is_none());
        assert!(space.map_record_for_va(child.base()).is_none());
        assert!(space.pte_meta(child.base()).is_none());

        space
            .map_fixed(
                &mut frames,
                child.base(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
    }

    #[test]
    fn protect_subrange_of_single_vma_splits_metadata() {
        let (mut space, mut frames, _frames) = sample_large_space();

        space
            .protect(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let left = space.lookup(ROOT_BASE).unwrap();
        let middle = space.lookup(ROOT_BASE + PAGE_SIZE).unwrap();
        let right = space.lookup(ROOT_BASE + PAGE_SIZE * 2).unwrap();

        assert_eq!(left.mapping_base(), ROOT_BASE);
        assert_eq!(left.mapping_len(), PAGE_SIZE);
        assert_eq!(
            left.perms(),
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER
        );

        assert_eq!(middle.mapping_base(), ROOT_BASE + PAGE_SIZE);
        assert_eq!(middle.mapping_len(), PAGE_SIZE);
        assert_eq!(middle.perms(), MappingPerms::READ | MappingPerms::USER);

        assert_eq!(right.mapping_base(), ROOT_BASE + PAGE_SIZE * 2);
        assert_eq!(right.mapping_len(), PAGE_SIZE);
        assert_eq!(
            right.perms(),
            MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER
        );
    }

    #[test]
    fn unmap_subrange_of_single_vma_splits_metadata() {
        let (mut space, mut frames, _frames) = sample_large_space();

        space
            .unmap(&mut frames, ROOT_BASE + PAGE_SIZE, PAGE_SIZE)
            .unwrap();

        let left = space.lookup(ROOT_BASE).unwrap();
        let right = space.lookup(ROOT_BASE + PAGE_SIZE * 2).unwrap();

        assert_eq!(left.mapping_base(), ROOT_BASE);
        assert_eq!(left.mapping_len(), PAGE_SIZE);
        assert!(space.lookup(ROOT_BASE + PAGE_SIZE).is_none());
        assert_eq!(right.mapping_base(), ROOT_BASE + PAGE_SIZE * 2);
        assert_eq!(right.mapping_len(), PAGE_SIZE);
    }

    #[test]
    fn nested_vmar_allocate_supports_specific_offsets() {
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 4 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let grandchild = space
            .allocate_subvmar(
                0,
                child.id(),
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();

        assert_eq!(grandchild.base(), child.base() + PAGE_SIZE);
        assert_eq!(grandchild.len(), PAGE_SIZE);
        assert!(child.contains_range(grandchild.base(), grandchild.len()));
    }

    #[test]
    fn randomized_vmar_allocate_avoids_parent_base_when_slots_exist() {
        let wide_root_len = VA_MAGAZINE_BYTES * 2;
        let mut space = AddressSpace::new(ROOT_BASE, wide_root_len).unwrap();

        let child = space
            .allocate_subvmar(
                0,
                space.root_vmar().id(),
                0,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Randomized,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();
        assert_ne!(child.base(), ROOT_BASE);
        assert_eq!(child.base() % PAGE_SIZE, 0);
    }

    #[test]
    fn specific_vmar_allocate_rejects_misaligned_alignment() {
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();

        assert_eq!(
            space.allocate_subvmar(
                0,
                space.root_vmar().id(),
                PAGE_SIZE,
                PAGE_SIZE,
                4 * PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            ),
            Err(AddressSpaceError::InvalidArgs)
        );
    }

    #[test]
    fn upper_limit_vmar_allocate_respects_parent_bound() {
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let child = space
            .allocate_subvmar(
                0,
                space.root_vmar().id(),
                8 * PAGE_SIZE,
                4 * PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();
        let _reserved = space
            .allocate_subvmar(
                0,
                child.id(),
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();

        let upper_limited = space
            .allocate_subvmar(
                0,
                child.id(),
                4 * PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Randomized,
                true,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();

        assert!(upper_limited.base() >= child.base());
        assert!(upper_limited.end() <= child.base() + (4 * PAGE_SIZE));
    }

    #[test]
    fn compact_child_policy_places_descendants_tightly() {
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let compact_child = space
            .allocate_subvmar(
                0,
                space.root_vmar().id(),
                16 * PAGE_SIZE,
                4 * PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();

        let nested = space
            .allocate_subvmar(
                0,
                compact_child.id(),
                0,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Randomized,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();

        assert_eq!(nested.base(), compact_child.base());
    }

    #[test]
    fn mapped_ranges_for_global_vmo_stay_base_ordered_after_head_unmap() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x60_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .import_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(40))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        for page_offset in [0, 2, 4] {
            let base = ROOT_BASE + page_offset * PAGE_SIZE;
            space
                .map_fixed(
                    &mut frames,
                    base,
                    PAGE_SIZE,
                    vmo,
                    0,
                    MappingPerms::READ | MappingPerms::USER,
                    MappingPerms::READ | MappingPerms::USER,
                )
                .unwrap();
        }

        space.unmap(&mut frames, ROOT_BASE, PAGE_SIZE).unwrap();

        assert_eq!(
            space.mapped_ranges_for_global_vmo(global_vmo_id(40)),
            vec![
                (ROOT_BASE + 2 * PAGE_SIZE, PAGE_SIZE),
                (ROOT_BASE + 4 * PAGE_SIZE, PAGE_SIZE),
            ]
        );
    }

    #[test]
    fn compact_subvmar_allocate_keeps_child_ranges_ordered_after_head_destroy() {
        let mut frames = FrameTable::new();
        let frame0 = frames.register_existing(0x61_000).unwrap();
        let frame1 = frames.register_existing(0x62_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let root = space.root_vmar().id();
        let root_vmo = space
            .create_vmo(VmoKind::Anonymous, 2 * PAGE_SIZE, global_vmo_id(41))
            .unwrap();
        space.bind_vmo_frame(root_vmo, 0, frame0).unwrap();
        space.bind_vmo_frame(root_vmo, PAGE_SIZE, frame1).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                2 * PAGE_SIZE,
                root_vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let child_a = space
            .allocate_subvmar(
                0,
                root,
                2 * PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();
        let _child_b = space
            .allocate_subvmar(
                0,
                root,
                4 * PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();
        let _child_c = space
            .allocate_subvmar(
                0,
                root,
                6 * PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();

        let removed = space.destroy_vmar(&mut frames, child_a.id()).unwrap();
        assert!(removed.is_empty());

        let compact = space
            .allocate_subvmar(
                0,
                root,
                0,
                3 * PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Compact,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();

        assert_eq!(compact.base(), ROOT_BASE + 7 * PAGE_SIZE);
    }

    #[test]
    fn destroy_vmar_recursively_removes_descendants() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x41_1000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(101))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 4 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let grandchild = space
            .allocate_subvmar(
                0,
                child.id(),
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();
        space
            .map_fixed_in_vmar(
                &mut frames,
                grandchild.id(),
                grandchild.base(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let removed = space.destroy_vmar(&mut frames, child.id()).unwrap();
        assert_eq!(removed, vec![(grandchild.base(), PAGE_SIZE)]);
        assert!(space.vmar(child.id()).is_none());
        assert!(space.vmar(grandchild.id()).is_none());
        assert!(space.lookup(grandchild.base()).is_none());

        space
            .map_fixed(
                &mut frames,
                grandchild.base(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
    }

    #[test]
    fn child_vmar_page_local_cow_preserves_mapping_identity() {
        let mut frames = FrameTable::new();
        let original = frames.register_existing(0x42_000).unwrap();
        let replacement = frames.register_existing(0x43_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(11))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, original).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 2 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        space
            .map_fixed_in_vmar(
                &mut frames,
                child.id(),
                child.base(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        let before = space.lookup(child.base()).unwrap();
        space.mark_copy_on_write(child.base(), PAGE_SIZE).unwrap();
        let resolved = space
            .resolve_cow_fault(&mut frames, child.base() + 0x80, replacement)
            .unwrap();
        let after = space.lookup(child.base()).unwrap();
        let map_rec = space.map_record(after.map_id()).unwrap();
        assert_eq!(resolved.fault_page_base(), child.base());
        assert_eq!(after.address_space_id(), space.id());
        assert_eq!(after.map_id(), before.map_id());
        assert_eq!(after.vmar_id(), child.id());
        assert_eq!(after.frame_id(), Some(replacement));
        assert!(!after.is_copy_on_write());
        assert_eq!(map_rec.vmar_id(), child.id());
        assert_eq!(space.map_record_for_va(child.base()), Some(map_rec));
        assert_eq!(
            space.pte_meta(child.base()).unwrap().map_id(),
            after.map_id()
        );
        assert!(!space.pte_meta(child.base()).unwrap().cow_shared());
    }

    #[test]
    fn mixed_root_and_child_mappings_keep_distinct_page_ownership() {
        let mut frames = FrameTable::new();
        let root_frame = frames.register_existing(0x44_000).unwrap();
        let child_frame = frames.register_existing(0x45_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x8000_0000).unwrap();
        let root_vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(12))
            .unwrap();
        let child_vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(13))
            .unwrap();
        space.bind_vmo_frame(root_vmo, 0, root_frame).unwrap();
        space.bind_vmo_frame(child_vmo, 0, child_frame).unwrap();

        let child = space
            .allocate_subvmar_for_cpu(0, 2 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let far_root_base = ROOT_BASE + 0x4000_0000;
        space
            .map_fixed(
                &mut frames,
                far_root_base,
                PAGE_SIZE,
                root_vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space
            .map_anywhere_in_vmar(
                &mut frames,
                0,
                child.id(),
                PAGE_SIZE,
                child_vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                PAGE_SIZE,
            )
            .unwrap();

        let root_lookup = space.lookup(far_root_base).unwrap();
        let child_lookup = space.lookup(child.base()).unwrap();
        assert_eq!(root_lookup.address_space_id(), space.id());
        assert_eq!(child_lookup.address_space_id(), space.id());
        assert_eq!(root_lookup.vmar_id(), space.root_vmar().id());
        assert_eq!(child_lookup.vmar_id(), child.id());
        assert_ne!(root_lookup.map_id(), child_lookup.map_id());
        assert_eq!(
            space.map_record_for_va(far_root_base).unwrap().vmar_id(),
            space.root_vmar().id()
        );
        assert_eq!(
            space.map_record_for_va(child.base()).unwrap().vmar_id(),
            child.id()
        );
        assert_eq!(
            space.pte_meta(far_root_base).unwrap().map_id(),
            root_lookup.map_id()
        );
        assert_eq!(
            space.pte_meta(child.base()).unwrap().map_id(),
            child_lookup.map_id()
        );
    }

    #[test]
    fn map_records_follow_mapping_lifecycle() {
        let (mut space, mut frames, _, _) = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;
        let lookup = space.lookup(data_base).unwrap();
        let map_id = lookup.map_id();

        assert_eq!(space.map_records().len(), 2);
        assert_eq!(space.map_record(map_id).unwrap().base(), data_base);

        space.unmap(&mut frames, data_base, PAGE_SIZE).unwrap();

        assert!(space.map_record(map_id).is_none());
        assert_eq!(space.map_records().len(), 1);
    }

    #[test]
    fn pte_meta_tracks_mapping_identity_and_lifecycle() {
        let (mut space, mut frames, code_frame, _) = sample_space();
        let meta = space.pte_meta(ROOT_BASE + 0x80).unwrap();
        let lookup = space.lookup(ROOT_BASE + 0x80).unwrap();

        assert_eq!(meta.map_id(), lookup.map_id());
        assert_eq!(meta.page_delta(), 0);
        assert_eq!(meta.tag(), PteMetaTag::Present);
        assert!(meta.logical_write());
        assert!(!meta.cow_shared());
        assert_eq!(space.pte_meta_for_vpn(vpn_of(ROOT_BASE)).unwrap(), meta);
        assert_eq!(frames.state(code_frame).unwrap().ref_count(), 1);

        space.unmap(&mut frames, ROOT_BASE, PAGE_SIZE).unwrap();

        assert!(space.pte_meta(ROOT_BASE).is_none());
        assert!(space.pte_meta_for_vpn(vpn_of(ROOT_BASE)).is_none());
    }

    #[test]
    fn map_rejects_overlap_and_out_of_range() {
        let (mut space, mut frames, _, _) = sample_space();
        let extra = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(3))
            .unwrap();
        assert_eq!(
            space.map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE / 2,
                PAGE_SIZE,
                extra,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            ),
            Err(AddressSpaceError::InvalidArgs)
        );
        assert_eq!(
            space.map_fixed(
                &mut frames,
                ROOT_BASE + (3 * PAGE_SIZE),
                2 * PAGE_SIZE,
                extra,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            ),
            Err(AddressSpaceError::OutOfRange)
        );
        assert_eq!(
            space.map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                extra,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            ),
            Err(AddressSpaceError::Overlap)
        );
    }

    #[test]
    fn protect_and_unmap_update_metadata_and_refcounts() {
        let (mut space, mut frames, _, data_frame) = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;
        space
            .protect(
                &mut frames,
                data_base,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        assert_eq!(
            space.lookup(data_base).unwrap().perms(),
            MappingPerms::READ | MappingPerms::USER
        );
        assert_eq!(
            space.protect(
                &mut frames,
                data_base,
                PAGE_SIZE,
                MappingPerms::EXECUTE | MappingPerms::USER
            ),
            Err(AddressSpaceError::PermissionIncrease)
        );
        space.unmap(&mut frames, data_base, PAGE_SIZE).unwrap();
        assert!(space.lookup(data_base).is_none());
        assert_eq!(frames.state(data_frame).unwrap().ref_count(), 0);
        assert_eq!(frames.state(data_frame).unwrap().map_count(), 0);
    }

    #[test]
    fn pte_meta_follows_protect_and_cow_state() {
        let (mut space, mut frames, _, data_frame) = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;

        let initial = space.pte_meta(data_base).unwrap();
        assert_eq!(initial.tag(), PteMetaTag::Present);
        assert!(initial.logical_write());
        assert!(!initial.cow_shared());

        space
            .protect(
                &mut frames,
                data_base,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        let protected = space.pte_meta(data_base).unwrap();
        assert!(!protected.logical_write());
        assert!(!protected.cow_shared());

        space
            .protect(
                &mut frames,
                data_base,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space.mark_copy_on_write(data_base, PAGE_SIZE).unwrap();
        let cow = space.pte_meta(data_base).unwrap();
        assert_eq!(cow.tag(), PteMetaTag::Present);
        assert!(cow.logical_write());
        assert!(cow.cow_shared());

        let replacement = frames.register_existing(0x70_000).unwrap();
        space
            .resolve_cow_fault(&mut frames, data_base + 0x88, replacement)
            .unwrap();
        let resolved = space.pte_meta(data_base).unwrap();
        assert_eq!(resolved.tag(), PteMetaTag::Present);
        assert!(resolved.logical_write());
        assert!(!resolved.cow_shared());
        assert_eq!(frames.state(data_frame).unwrap().ref_count(), 0);
    }

    #[test]
    fn classify_page_fault_prefers_page_metadata() {
        let (mut space, _, _, _) = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;

        assert_eq!(
            space.classify_page_fault(
                data_base,
                PageFaultFlags::PRESENT | PageFaultFlags::WRITE | PageFaultFlags::USER,
            ),
            PageFaultDecision::ProtectionViolation
        );

        space.mark_copy_on_write(data_base, PAGE_SIZE).unwrap();
        assert_eq!(
            space.classify_page_fault(
                data_base + 0x44,
                PageFaultFlags::PRESENT | PageFaultFlags::WRITE | PageFaultFlags::USER,
            ),
            PageFaultDecision::CopyOnWrite
        );

        assert_eq!(
            space.classify_page_fault(data_base, PageFaultFlags::PRESENT | PageFaultFlags::USER,),
            PageFaultDecision::ProtectionViolation
        );
        assert_eq!(
            space.classify_page_fault(data_base, PageFaultFlags::PRESENT | PageFaultFlags::WRITE,),
            PageFaultDecision::Unhandled
        );
        assert_eq!(
            space.classify_page_fault(
                ROOT_BASE + (3 * PAGE_SIZE),
                PageFaultFlags::PRESENT | PageFaultFlags::WRITE | PageFaultFlags::USER,
            ),
            PageFaultDecision::Unmapped
        );

        space
            .pte_meta
            .update_range(data_base, PAGE_SIZE, |meta| meta.tag = PteMetaTag::LazyAnon)
            .unwrap();
        assert_eq!(
            space.classify_page_fault(data_base, PageFaultFlags::USER),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyAnon,
            }
        );
    }

    #[test]
    fn resolve_lazy_anon_fault_materializes_page_and_updates_metadata() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let lazy = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(20))
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                lazy,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        assert_eq!(
            space.classify_page_fault(ROOT_BASE, PageFaultFlags::USER),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyAnon,
            }
        );

        let frame = frames.register_existing(0x90_000).unwrap();
        let resolved = space
            .resolve_lazy_anon_fault(&mut frames, ROOT_BASE + 0x10, frame)
            .unwrap();

        assert_eq!(resolved.fault_page_base(), ROOT_BASE);
        assert_eq!(resolved.new_frame_id(), frame);
        assert_eq!(space.lookup(ROOT_BASE).unwrap().frame_id(), Some(frame));
        assert_eq!(
            space.pte_meta(ROOT_BASE).unwrap().tag(),
            PteMetaTag::Present
        );
        assert_eq!(frames.state(frame).unwrap().ref_count(), 1);
        assert_eq!(frames.state(frame).unwrap().map_count(), 1);
    }

    #[test]
    fn imported_anonymous_vmo_faults_as_lazy_vmo() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let shared = space
            .import_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(120))
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                shared,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        assert_eq!(
            space.classify_page_fault(ROOT_BASE, PageFaultFlags::USER),
            PageFaultDecision::NotPresent {
                tag: PteMetaTag::LazyVmo,
            }
        );
    }

    #[test]
    fn resolve_lazy_vmo_fault_binds_existing_frame_and_updates_metadata() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let shared = space
            .import_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(121))
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                shared,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        let frame = frames.register_existing(0x90_1000).unwrap();
        let resolved = space
            .resolve_lazy_vmo_fault(&mut frames, ROOT_BASE + 0x10, frame)
            .unwrap();

        assert_eq!(resolved.fault_page_base(), ROOT_BASE);
        assert_eq!(resolved.frame_id(), frame);
        assert_eq!(space.lookup(ROOT_BASE).unwrap().frame_id(), Some(frame));
        assert_eq!(
            space.pte_meta(ROOT_BASE).unwrap().tag(),
            PteMetaTag::Present
        );
        assert_eq!(frames.state(frame).unwrap().ref_count(), 1);
        assert_eq!(frames.state(frame).unwrap().map_count(), 1);
    }

    #[test]
    fn materialize_vmo_page_aliases_attaches_post_bind_frames_to_existing_mappings() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 2, global_vmo_id(204))
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 2,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        let frame = frames.register_existing(0x1000_3000).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, frame).unwrap();
        let updated = space
            .materialize_vmo_page_aliases(&mut frames, vmo, PAGE_SIZE, frame)
            .unwrap();

        assert_eq!(updated, vec![ROOT_BASE + PAGE_SIZE]);
        assert_eq!(
            space.lookup(ROOT_BASE + PAGE_SIZE).unwrap().frame_id(),
            Some(frame)
        );
        assert!(space.rmap_node_at(ROOT_BASE + PAGE_SIZE).is_some());
        assert_eq!(frames.state(frame).unwrap().ref_count(), 1);
        assert_eq!(frames.state(frame).unwrap().map_count(), 1);

        space.unmap(&mut frames, ROOT_BASE, PAGE_SIZE * 2).unwrap();
        assert_eq!(frames.state(frame).unwrap().ref_count(), 0);
        assert_eq!(frames.state(frame).unwrap().map_count(), 0);
    }

    #[test]
    fn non_anonymous_mappings_require_resident_frames() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let physical = space
            .create_vmo(VmoKind::Physical, PAGE_SIZE, global_vmo_id(122))
            .unwrap();
        let contiguous = space
            .create_vmo(VmoKind::Contiguous, PAGE_SIZE, global_vmo_id(123))
            .unwrap();

        assert_eq!(
            space.map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                physical,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            ),
            Err(AddressSpaceError::InvalidFrame)
        );
        assert_eq!(
            space.map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                contiguous,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            ),
            Err(AddressSpaceError::InvalidFrame)
        );
    }

    #[test]
    fn vmo_kind_policy_matrix_matches_contract() {
        assert!(VmoKind::Anonymous.supports_kernel_read());
        assert!(VmoKind::Anonymous.supports_kernel_write());
        assert!(VmoKind::Anonymous.supports_resize());
        assert!(VmoKind::Anonymous.supports_copy_on_write());
        assert!(VmoKind::Anonymous.supports_page_loan());
        assert!(!VmoKind::Anonymous.requires_resident_frames());

        assert!(!VmoKind::Physical.supports_kernel_read());
        assert!(!VmoKind::Physical.supports_kernel_write());
        assert!(!VmoKind::Physical.supports_resize());
        assert!(!VmoKind::Physical.supports_copy_on_write());
        assert!(!VmoKind::Physical.supports_page_loan());
        assert!(VmoKind::Physical.requires_resident_frames());

        assert!(VmoKind::Contiguous.supports_kernel_read());
        assert!(VmoKind::Contiguous.supports_kernel_write());
        assert!(!VmoKind::Contiguous.supports_resize());
        assert!(!VmoKind::Contiguous.supports_copy_on_write());
        assert!(!VmoKind::Contiguous.supports_page_loan());
        assert!(VmoKind::Contiguous.requires_resident_frames());

        assert!(VmoKind::PagerBacked.supports_kernel_read());
        assert!(!VmoKind::PagerBacked.supports_kernel_write());
        assert!(!VmoKind::PagerBacked.supports_resize());
        assert!(VmoKind::PagerBacked.supports_copy_on_write());
        assert!(!VmoKind::PagerBacked.supports_page_loan());
        assert!(!VmoKind::PagerBacked.requires_resident_frames());
    }

    #[test]
    fn imported_non_demand_vmos_keep_reserved_fault_policy() {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let physical = space
            .import_vmo(VmoKind::Physical, PAGE_SIZE, global_vmo_id(129))
            .unwrap();
        let contiguous = space
            .import_vmo(VmoKind::Contiguous, PAGE_SIZE, global_vmo_id(130))
            .unwrap();

        assert_eq!(
            space.vmo(physical).unwrap().missing_page_tag(),
            PteMetaTag::Reserved
        );
        assert_eq!(
            space.vmo(contiguous).unwrap().missing_page_tag(),
            PteMetaTag::Reserved
        );
    }

    #[test]
    fn imported_pager_backed_vmo_keeps_lazy_vmo_fault_policy() {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let pager = space
            .import_vmo(VmoKind::PagerBacked, PAGE_SIZE, global_vmo_id(133))
            .unwrap();

        assert_eq!(
            space.vmo(pager).unwrap().missing_page_tag(),
            PteMetaTag::LazyVmo
        );
    }

    #[test]
    fn private_pager_clone_keeps_distinct_identity_from_shared_source() {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let source_global = global_vmo_id(133);
        let clone_global = global_vmo_id(134);
        let imported = space
            .import_vmo(VmoKind::PagerBacked, PAGE_SIZE, source_global)
            .unwrap();
        let private = space
            .create_private_clone_vmo(
                VmoKind::PagerBacked,
                PAGE_SIZE,
                clone_global,
                Some(source_global),
            )
            .unwrap();

        assert_eq!(
            space.shared_vmo_id_by_backing_global_id(source_global),
            Some(imported)
        );
        assert_eq!(space.vmo_id_by_global_id(source_global), Some(imported));
        assert_eq!(space.vmo_id_by_global_id(clone_global), Some(private));
        assert_eq!(
            space.vmo(imported).unwrap().shared_backing_id(),
            Some(source_global)
        );
        assert_eq!(
            space.vmo(imported).unwrap().fault_source_id(),
            Some(source_global)
        );
        assert_eq!(space.vmo(private).unwrap().shared_backing_id(), None);
        assert_eq!(
            space.vmo(private).unwrap().fault_source_id(),
            Some(source_global)
        );
    }

    #[test]
    fn pager_backed_mapping_can_resolve_copy_on_write() {
        let mut frames = FrameTable::new();
        let shared = frames.register_existing(0x90_4000).unwrap();
        let replacement = frames.register_existing(0x90_5000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let pager = space
            .import_vmo(VmoKind::PagerBacked, PAGE_SIZE, global_vmo_id(134))
            .unwrap();
        space.set_vmo_frame(pager, 0, shared).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                pager,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space.mark_copy_on_write(ROOT_BASE, PAGE_SIZE).unwrap();

        let before = space.lookup(ROOT_BASE).unwrap();
        assert_eq!(before.frame_id(), Some(shared));
        assert!(before.is_copy_on_write());
        assert!(!before.perms().contains(MappingPerms::WRITE));

        let resolved = space
            .resolve_cow_fault(&mut frames, ROOT_BASE + 0x88, replacement)
            .unwrap();
        let after = space.lookup(ROOT_BASE).unwrap();

        assert_eq!(resolved.old_frame_id(), shared);
        assert_eq!(resolved.new_frame_id(), replacement);
        assert_eq!(after.frame_id(), Some(replacement));
        assert!(after.perms().contains(MappingPerms::WRITE));
        assert!(!after.is_copy_on_write());
    }

    #[test]
    fn mark_copy_on_write_rejects_non_copyable_vmos() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let physical = space
            .create_vmo(VmoKind::Physical, PAGE_SIZE, global_vmo_id(124))
            .unwrap();
        let contiguous = space
            .create_vmo(VmoKind::Contiguous, PAGE_SIZE, global_vmo_id(125))
            .unwrap();
        let phys_frame = frames.register_existing(0x90_2000).unwrap();
        let contig_frame = frames.register_existing(0x90_3000).unwrap();
        space.bind_vmo_frame(physical, 0, phys_frame).unwrap();
        space.bind_vmo_frame(contiguous, 0, contig_frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                physical,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                contiguous,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        assert_eq!(
            space.mark_copy_on_write(ROOT_BASE, PAGE_SIZE),
            Err(AddressSpaceError::InvalidArgs)
        );
        assert_eq!(
            space.mark_copy_on_write(ROOT_BASE + PAGE_SIZE, PAGE_SIZE),
            Err(AddressSpaceError::InvalidArgs)
        );
        assert_eq!(
            space.classify_page_fault(
                ROOT_BASE + PAGE_SIZE,
                PageFaultFlags::PRESENT | PageFaultFlags::WRITE | PageFaultFlags::USER,
            ),
            PageFaultDecision::ProtectionViolation
        );
        assert_eq!(
            space.pte_meta(ROOT_BASE + PAGE_SIZE).unwrap().tag(),
            PteMetaTag::Phys
        );
    }

    #[test]
    fn resident_non_demand_mappings_allow_protect() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let physical = space
            .create_vmo(VmoKind::Physical, PAGE_SIZE, global_vmo_id(131))
            .unwrap();
        let contiguous = space
            .create_vmo(VmoKind::Contiguous, PAGE_SIZE, global_vmo_id(132))
            .unwrap();
        let phys_frame = frames.register_existing(0x90_4000).unwrap();
        let contig_frame = frames.register_existing(0x90_5000).unwrap();
        space.bind_vmo_frame(physical, 0, phys_frame).unwrap();
        space.bind_vmo_frame(contiguous, 0, contig_frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                physical,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                contiguous,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        space
            .protect(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        space
            .protect(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let physical_meta = space.pte_meta(ROOT_BASE).unwrap();
        let contiguous_meta = space.pte_meta(ROOT_BASE + PAGE_SIZE).unwrap();
        assert_eq!(physical_meta.tag(), PteMetaTag::Phys);
        assert_eq!(contiguous_meta.tag(), PteMetaTag::Phys);
        assert!(!physical_meta.logical_write());
        assert!(!contiguous_meta.logical_write());
    }

    #[test]
    fn resize_vmo_grow_preserves_existing_frames() {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(126))
            .unwrap();
        let frame = FrameId::from_raw(0x90_4000).unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        let dropped = space.resize_vmo(vmo, PAGE_SIZE * 2).unwrap();

        assert!(dropped.is_empty());
        let vmo = space.vmo(vmo).unwrap();
        assert_eq!(vmo.size_bytes(), PAGE_SIZE * 2);
        assert_eq!(vmo.frame_at_offset(0), Some(frame));
        assert_eq!(vmo.frame_at_offset(PAGE_SIZE), None);
    }

    #[test]
    fn resize_vmo_rejects_truncating_live_mapping_tail() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 2, global_vmo_id(127))
            .unwrap();

        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 2,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        assert_eq!(
            space.validate_vmo_resize(vmo, PAGE_SIZE),
            Err(AddressSpaceError::Busy)
        );
        assert_eq!(
            space.resize_vmo(vmo, PAGE_SIZE),
            Err(AddressSpaceError::Busy)
        );
    }

    #[test]
    fn resize_vmo_shrink_returns_truncated_tail_frames() {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 2, global_vmo_id(128))
            .unwrap();
        let keep = FrameId::from_raw(0x90_5000).unwrap();
        let drop = FrameId::from_raw(0x90_6000).unwrap();
        space.bind_vmo_frame(vmo, 0, keep).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, drop).unwrap();

        let dropped = space.resize_vmo(vmo, PAGE_SIZE).unwrap();

        assert_eq!(dropped, vec![drop]);
        let vmo = space.vmo(vmo).unwrap();
        assert_eq!(vmo.size_bytes(), PAGE_SIZE);
        assert_eq!(vmo.frame_at_offset(0), Some(keep));
        assert_eq!(vmo.frame_at_offset(PAGE_SIZE), None);
    }

    #[test]
    fn resize_vmo_allows_shrink_after_tail_mapping_is_unmapped() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(203))
            .unwrap();
        let tail_base = ROOT_BASE + PAGE_SIZE;

        space.resize_vmo(vmo, PAGE_SIZE * 2).unwrap();
        space
            .map_fixed(
                &mut frames,
                tail_base,
                PAGE_SIZE,
                vmo,
                PAGE_SIZE,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        assert_eq!(
            space.validate_vmo_resize(vmo, PAGE_SIZE),
            Err(AddressSpaceError::Busy)
        );

        space.unmap(&mut frames, tail_base, PAGE_SIZE).unwrap();

        assert_eq!(space.validate_vmo_resize(vmo, PAGE_SIZE), Ok(()));
        assert_eq!(
            space.resize_vmo(vmo, PAGE_SIZE).unwrap(),
            Vec::<FrameId>::new()
        );
        assert_eq!(space.vmo(vmo).unwrap().size_bytes(), PAGE_SIZE);
    }

    #[test]
    fn replace_mapping_frames_copy_on_write_rebinds_shared_pages() {
        let mut frames = FrameTable::new();
        let original = frames.register_existing(0x91_000).unwrap();
        let shared = frames.register_existing(0x92_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(22))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, original).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        space
            .replace_mapping_frames_copy_on_write(&mut frames, ROOT_BASE, PAGE_SIZE, &[shared])
            .unwrap();

        let lookup = space.lookup(ROOT_BASE).unwrap();
        assert_eq!(lookup.frame_id(), Some(shared));
        assert!(lookup.is_copy_on_write());
        assert!(!lookup.perms().contains(MappingPerms::WRITE));

        let meta = space.pte_meta(ROOT_BASE).unwrap();
        assert_eq!(meta.tag(), PteMetaTag::Present);
        assert!(meta.logical_write());
        assert!(meta.cow_shared());

        assert_eq!(frames.state(original).unwrap().ref_count(), 0);
        assert_eq!(frames.state(original).unwrap().map_count(), 0);
        assert_eq!(frames.state(shared).unwrap().ref_count(), 1);
        assert_eq!(frames.state(shared).unwrap().map_count(), 1);
    }

    #[test]
    fn lookup_reports_page_local_cow_state() {
        let mut frames = FrameTable::new();
        let left = frames.register_existing(0xa0_000).unwrap();
        let right = frames.register_existing(0xb0_000).unwrap();
        let replacement = frames.register_existing(0xc0_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 2, global_vmo_id(21))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, left).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, right).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 2,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space.mark_copy_on_write(ROOT_BASE, PAGE_SIZE * 2).unwrap();

        space
            .resolve_cow_fault(&mut frames, ROOT_BASE + 0x80, replacement)
            .unwrap();

        assert!(!space.lookup(ROOT_BASE).unwrap().is_copy_on_write());
        assert!(
            space
                .lookup(ROOT_BASE + PAGE_SIZE)
                .unwrap()
                .is_copy_on_write()
        );
        assert!(space.vmas()[0].is_copy_on_write());
    }

    #[test]
    fn mark_copy_on_write_accepts_subrange_of_larger_mapping() {
        let mut frames = FrameTable::new();
        let left = frames.register_existing(0xd0_000).unwrap();
        let middle = frames.register_existing(0xe0_000).unwrap();
        let right = frames.register_existing(0xf0_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 3, global_vmo_id(23))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, left).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, middle).unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE * 2, right).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 3,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        space
            .mark_copy_on_write(ROOT_BASE + PAGE_SIZE, PAGE_SIZE)
            .unwrap();

        let left_lookup = space.lookup(ROOT_BASE).unwrap();
        assert!(!left_lookup.is_copy_on_write());
        assert!(left_lookup.perms().contains(MappingPerms::WRITE));

        let middle_lookup = space.lookup(ROOT_BASE + PAGE_SIZE).unwrap();
        assert!(middle_lookup.is_copy_on_write());
        assert!(!middle_lookup.perms().contains(MappingPerms::WRITE));

        let right_lookup = space.lookup(ROOT_BASE + PAGE_SIZE * 2).unwrap();
        assert!(!right_lookup.is_copy_on_write());
        assert!(right_lookup.perms().contains(MappingPerms::WRITE));

        let middle_meta = space.pte_meta(ROOT_BASE + PAGE_SIZE).unwrap();
        assert!(middle_meta.logical_write());
        assert!(middle_meta.cow_shared());
        assert!(space.vmas()[0].is_copy_on_write());
    }

    #[test]
    fn resolve_cow_fault_rebinds_frame_and_restores_write() {
        let (mut space, mut frames, _, data_frame) = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;
        let replacement = frames.register_existing(0x60_000).unwrap();

        space.mark_copy_on_write(data_base, PAGE_SIZE).unwrap();
        let before = space.lookup(data_base).unwrap();
        assert!(before.is_copy_on_write());
        assert!(!before.perms().contains(MappingPerms::WRITE));

        let resolved = space
            .resolve_cow_fault(&mut frames, data_base + 0x80, replacement)
            .unwrap();
        assert_eq!(resolved.fault_page_base(), data_base);
        assert_eq!(resolved.old_frame_id(), data_frame);
        assert_eq!(resolved.new_frame_id(), replacement);

        let after = space.lookup(data_base).unwrap();
        assert_eq!(after.frame_id(), Some(replacement));
        assert!(after.perms().contains(MappingPerms::WRITE));
        assert!(!after.is_copy_on_write());
        assert_eq!(frames.state(data_frame).unwrap().ref_count(), 0);
        assert_eq!(frames.state(data_frame).unwrap().map_count(), 0);
        assert_eq!(frames.state(replacement).unwrap().ref_count(), 1);
        assert_eq!(frames.state(replacement).unwrap().map_count(), 1);
    }

    #[test]
    fn contains_range_can_span_adjacent_vmas() {
        let (mut space, mut frames, _, _) = sample_space();
        let extra = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(4))
            .unwrap();
        let extra_frame = frames.register_existing(0x40_000).unwrap();
        space.bind_vmo_frame(extra, 0, extra_frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + (2 * PAGE_SIZE),
                PAGE_SIZE,
                extra,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        assert!(space.contains_range(ROOT_BASE + PAGE_SIZE, (2 * PAGE_SIZE) as usize));
        assert!(!space.contains_range(ROOT_BASE + (3 * PAGE_SIZE), PAGE_SIZE as usize));
    }

    #[test]
    fn frame_pin_and_unpin_update_pin_count() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x20_000).unwrap();
        frames.pin(frame).unwrap();
        frames.pin(frame).unwrap();
        assert_eq!(frames.state(frame).unwrap().pin_count(), 2);
        frames.unpin(frame).unwrap();
        frames.unpin(frame).unwrap();
        assert_eq!(frames.state(frame).unwrap().pin_count(), 0);
        assert_eq!(frames.unpin(frame), Err(FrameTableError::PinUnderflow));
    }

    #[test]
    fn unregister_existing_requires_idle_frame() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x20_000).unwrap();
        frames.pin(frame).unwrap();
        assert_eq!(
            frames.unregister_existing(frame),
            Err(FrameTableError::Busy)
        );
        frames.unpin(frame).unwrap();
        frames.unregister_existing(frame).unwrap();
        assert!(!frames.contains(frame));
    }

    #[test]
    fn frame_batch_loan_helpers_update_counts_and_rollback() {
        let mut frames = FrameTable::new();
        let frame0 = frames.register_existing(0x21_000).unwrap();
        let frame1 = frames.register_existing(0x22_000).unwrap();

        let loan = frames
            .pin_many(&[frame0, frame1])
            .unwrap()
            .into_loan(&mut frames)
            .unwrap();
        assert_eq!(frames.state(frame0).unwrap().pin_count(), 1);
        assert_eq!(frames.state(frame0).unwrap().loan_count(), 1);
        assert_eq!(frames.state(frame1).unwrap().pin_count(), 1);
        assert_eq!(frames.state(frame1).unwrap().loan_count(), 1);

        loan.release(&mut frames);
        assert_eq!(frames.state(frame0).unwrap().pin_count(), 0);
        assert_eq!(frames.state(frame0).unwrap().loan_count(), 0);
        assert_eq!(frames.state(frame1).unwrap().pin_count(), 0);
        assert_eq!(frames.state(frame1).unwrap().loan_count(), 0);

        let missing = FrameId::from_raw(0x23_000).unwrap();
        assert!(matches!(
            frames
                .pin_many(&[frame0, missing])
                .and_then(|pin| pin.into_loan(&mut frames)),
            Err(FrameTableError::NotFound)
        ));
        assert_eq!(frames.state(frame0).unwrap().pin_count(), 0);
        assert_eq!(frames.state(frame0).unwrap().loan_count(), 0);
    }

    #[test]
    fn frame_desc_tracks_map_count_and_placeholders() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0xd0_000).unwrap();

        let initial = frames.state(frame).unwrap();
        assert_eq!(initial.ref_count(), 0);
        assert_eq!(initial.map_count(), 0);
        assert_eq!(initial.loan_count(), 0);
        assert_eq!(initial.rmap_anchor(), None);
        assert_eq!(initial.rmap_anchor_count(), 0);

        frames.inc_map(frame).unwrap();
        frames.inc_map(frame).unwrap();
        let loan0 = frames
            .pin_frame(frame)
            .unwrap()
            .into_loan(&mut frames)
            .unwrap();
        let loan1 = frames
            .pin_frame(frame)
            .unwrap()
            .into_loan(&mut frames)
            .unwrap();
        let mapped = frames.state(frame).unwrap();
        assert_eq!(mapped.ref_count(), 2);
        assert_eq!(mapped.map_count(), 2);
        assert_eq!(mapped.loan_count(), 2);
        assert_eq!(mapped.rmap_anchor(), None);
        assert_eq!(mapped.rmap_anchor_count(), 0);
        assert_eq!(mapped.pin_count(), 2);

        frames.dec_map(frame).unwrap();
        frames.dec_map(frame).unwrap();
        loan0.release(&mut frames);
        loan1.release(&mut frames);
        let unmapped = frames.state(frame).unwrap();
        assert_eq!(unmapped.ref_count(), 0);
        assert_eq!(unmapped.map_count(), 0);
        assert_eq!(unmapped.loan_count(), 0);
        assert_eq!(unmapped.rmap_anchor_count(), 0);
        assert_eq!(frames.dec_map(frame), Err(FrameTableError::RefUnderflow));
        assert_eq!(unmapped.pin_count(), 0);
    }

    #[test]
    fn frame_anchor_moves_to_remaining_alias_in_same_address_space() {
        let mut frames = FrameTable::new();
        let shared = frames.register_existing(0xe0_000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(30))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, shared).unwrap();

        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        let first_anchor =
            ReverseMapAnchor::new(space.id(), space.lookup(ROOT_BASE).unwrap().map_id(), 0);
        assert_eq!(
            frames.state(shared).unwrap().rmap_anchor(),
            Some(first_anchor)
        );
        assert_eq!(frames.state(shared).unwrap().rmap_anchor_count(), 1);

        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        let second_anchor = ReverseMapAnchor::new(
            space.id(),
            space.lookup(ROOT_BASE + PAGE_SIZE).unwrap().map_id(),
            0,
        );
        assert_eq!(
            frames.state(shared).unwrap().rmap_anchor(),
            Some(second_anchor)
        );
        assert_eq!(frames.state(shared).unwrap().rmap_anchor_count(), 2);
        assert_eq!(frames.rmap_anchors(shared).unwrap().len(), 2);
        assert!(
            frames
                .rmap_anchors(shared)
                .unwrap()
                .contains(&second_anchor)
        );

        space.unmap(&mut frames, ROOT_BASE, PAGE_SIZE).unwrap();

        assert_eq!(
            frames.state(shared).unwrap().rmap_anchor(),
            Some(second_anchor)
        );
        assert_eq!(frames.state(shared).unwrap().rmap_anchor_count(), 1);
    }

    #[test]
    fn sparse_mapping_preserves_page_delta_in_rmap() {
        let mut frames = FrameTable::new();
        let late = frames.register_existing(0xe1_8000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE * 2, global_vmo_id(31))
            .unwrap();
        space.bind_vmo_frame(vmo, PAGE_SIZE, late).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE * 2,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let second_page_lookup = space.lookup(ROOT_BASE + PAGE_SIZE).unwrap();
        assert_eq!(
            frames.state(late).unwrap().rmap_anchor(),
            Some(ReverseMapAnchor::new(
                space.id(),
                second_page_lookup.map_id(),
                1
            ))
        );
        assert_eq!(frames.state(late).unwrap().rmap_anchor_count(), 1);

        space.unmap(&mut frames, ROOT_BASE, PAGE_SIZE * 2).unwrap();
        assert_eq!(frames.state(late).unwrap().map_count(), 0);
        assert_eq!(frames.state(late).unwrap().rmap_anchor_count(), 0);
    }

    #[test]
    fn sparse_metadata_allocates_per_leaf_page() {
        let wide_len = PT_LEAF_PAGE_COUNT * PAGE_SIZE * 2;
        let mut frames = FrameTable::new();
        let near = frames.register_existing(0xe2_0000).unwrap();
        let far = frames.register_existing(0xe2_1000).unwrap();

        let mut space = AddressSpace::new(ROOT_BASE, wide_len).unwrap();
        let near_vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(33))
            .unwrap();
        let far_vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(34))
            .unwrap();
        space.bind_vmo_frame(near_vmo, 0, near).unwrap();
        space.bind_vmo_frame(far_vmo, 0, far).unwrap();

        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                near_vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE + PT_LEAF_PAGE_COUNT * PAGE_SIZE,
                PAGE_SIZE,
                far_vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        assert_eq!(space.pte_meta.leaves.leaves.len(), 2);
        assert_eq!(space.rmap_index.leaves.leaves.len(), 2);

        space
            .unmap(
                &mut frames,
                ROOT_BASE + PT_LEAF_PAGE_COUNT * PAGE_SIZE,
                PAGE_SIZE,
            )
            .unwrap();

        assert_eq!(space.pte_meta.leaves.leaves.len(), 1);
        assert_eq!(space.rmap_index.leaves.leaves.len(), 1);
        assert!(space.lookup(ROOT_BASE).is_some());
        assert!(
            space
                .lookup(ROOT_BASE + PT_LEAF_PAGE_COUNT * PAGE_SIZE)
                .is_none()
        );
    }

    #[test]
    fn per_cpu_allocator_reserves_non_overlapping_child_vmars() {
        let wide_root_len = VA_MAGAZINE_BYTES * 2;
        let mut space = AddressSpace::new(ROOT_BASE, wide_root_len).unwrap();

        let left = space
            .allocate_subvmar_for_cpu(0, PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let middle = space
            .allocate_subvmar_for_cpu(0, 2 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let right = space
            .allocate_subvmar_for_cpu(1, PAGE_SIZE, 2 * PAGE_SIZE)
            .unwrap();

        assert_eq!(space.child_vmars().len(), 3);
        assert!(space.root_vmar().base() <= left.base());
        assert!(right.end() <= space.root_vmar().end());
        for pair in space.child_vmars().windows(2) {
            assert!(pair[0].end() <= pair[1].base());
        }
        assert!(left.end() <= middle.base());
        assert!(middle.end() <= right.base());
    }

    #[test]
    fn child_vmar_reservation_blocks_fixed_mapping_until_destroyed() {
        let wide_root_len = VA_MAGAZINE_BYTES * 2;
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0xe3_0000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, wide_root_len).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(35))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        let reserved = space
            .allocate_subvmar_for_cpu(0, PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        assert_eq!(
            space.map_fixed(
                &mut frames,
                reserved.base(),
                reserved.len(),
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            ),
            Err(AddressSpaceError::Overlap)
        );

        space.destroy_vmar(&mut frames, reserved.id()).unwrap();
        space
            .map_fixed(
                &mut frames,
                reserved.base(),
                reserved.len(),
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();
    }

    #[test]
    fn per_cpu_allocator_skips_existing_mappings_and_honors_alignment() {
        let wide_root_len = VA_MAGAZINE_BYTES * 2;
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0xe4_0000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, wide_root_len).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(36))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let allocated = space
            .allocate_subvmar_for_cpu(0, PAGE_SIZE, 2 * PAGE_SIZE)
            .unwrap();
        assert_eq!(allocated.base() % (2 * PAGE_SIZE), 0);
        assert_ne!(allocated.base(), ROOT_BASE);
        assert!(allocated.base() >= ROOT_BASE + PAGE_SIZE);
        assert!(allocated.end() <= space.root_vmar().end());
        assert_eq!(allocated.len(), PAGE_SIZE);
    }

    #[test]
    fn compact_vmar_allocate_tracks_parent_cursor() {
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let child = space
            .allocate_subvmar_for_cpu(0, 4 * PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        let grandchild = space
            .allocate_subvmar(
                0,
                child.id(),
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Randomized,
            )
            .unwrap();
        let compact = space
            .allocate_subvmar(
                0,
                child.id(),
                0,
                PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Compact,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();

        assert_eq!(grandchild.base(), child.base() + PAGE_SIZE);
        assert_eq!(compact.base(), child.base() + (2 * PAGE_SIZE));
    }

    #[test]
    fn compact_vmar_non_specific_map_uses_compact_cursor() {
        let mut frames = FrameTable::new();
        let frame = frames.register_existing(0x51_000).unwrap();
        let mut space = AddressSpace::new(ROOT_BASE, 0x20_0000).unwrap();
        let vmo = space
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(37))
            .unwrap();
        space.bind_vmo_frame(vmo, 0, frame).unwrap();

        let compact_child = space
            .allocate_subvmar(
                0,
                space.root_vmar().id(),
                16 * PAGE_SIZE,
                4 * PAGE_SIZE,
                PAGE_SIZE,
                VmarAllocMode::Specific,
                false,
                VmarPlacementPolicy::Compact,
            )
            .unwrap();
        let mapped = space
            .map_anywhere_in_vmar(
                &mut frames,
                0,
                compact_child.id(),
                PAGE_SIZE,
                vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
                PAGE_SIZE,
            )
            .unwrap();

        assert_eq!(mapped, compact_child.base());
    }

    #[test]
    fn lookup_rmap_anchor_resolves_with_explicit_address_space_id() {
        let mut frames = FrameTable::new();
        let shared = frames.register_existing(0xe1_000).unwrap();

        let mut left =
            AddressSpace::new_with_id(AddressSpaceId::new(10), ROOT_BASE, ROOT_LEN).unwrap();
        let left_vmo = left
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(31))
            .unwrap();
        left.bind_vmo_frame(left_vmo, 0, shared).unwrap();
        left.map_fixed(
            &mut frames,
            ROOT_BASE,
            PAGE_SIZE,
            left_vmo,
            0,
            MappingPerms::READ | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::USER,
        )
        .unwrap();

        let mut right =
            AddressSpace::new_with_id(AddressSpaceId::new(11), ROOT_BASE, ROOT_LEN).unwrap();
        let right_vmo = right
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(32))
            .unwrap();
        right.bind_vmo_frame(right_vmo, 0, shared).unwrap();
        right
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                right_vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let left_anchor = left.first_rmap_anchor_for_frame(shared).unwrap();
        let right_anchor = right.first_rmap_anchor_for_frame(shared).unwrap();

        assert_eq!(left_anchor.address_space_id(), left.id());
        assert_eq!(right_anchor.address_space_id(), right.id());
        assert!(left.lookup_rmap_anchor(right_anchor).is_none());
        assert_eq!(
            right.page_base_for_rmap_anchor(right_anchor),
            Some(ROOT_BASE + PAGE_SIZE)
        );
        assert_eq!(
            right.lookup_rmap_anchor(right_anchor).unwrap().frame_id(),
            Some(shared)
        );
    }

    #[test]
    fn shared_frame_refcount_spans_multiple_address_spaces() {
        let mut frames = FrameTable::new();
        let shared = frames.register_existing(0x50_000).unwrap();

        let mut left =
            AddressSpace::new_with_id(AddressSpaceId::new(40), ROOT_BASE, ROOT_LEN).unwrap();
        let left_vmo = left
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(10))
            .unwrap();
        left.bind_vmo_frame(left_vmo, 0, shared).unwrap();
        left.map_fixed(
            &mut frames,
            ROOT_BASE,
            PAGE_SIZE,
            left_vmo,
            0,
            MappingPerms::READ | MappingPerms::USER,
            MappingPerms::READ | MappingPerms::USER,
        )
        .unwrap();

        let mut right =
            AddressSpace::new_with_id(AddressSpaceId::new(41), ROOT_BASE, ROOT_LEN).unwrap();
        let right_vmo = right
            .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(11))
            .unwrap();
        right.bind_vmo_frame(right_vmo, 0, shared).unwrap();
        right
            .map_fixed(
                &mut frames,
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                right_vmo,
                0,
                MappingPerms::READ | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::USER,
            )
            .unwrap();

        let left_anchor =
            ReverseMapAnchor::new(left.id(), left.lookup(ROOT_BASE).unwrap().map_id(), 0);
        let right_anchor = ReverseMapAnchor::new(
            right.id(),
            right.lookup(ROOT_BASE + PAGE_SIZE).unwrap().map_id(),
            0,
        );
        assert_eq!(frames.state(shared).unwrap().ref_count(), 2);
        assert_eq!(frames.state(shared).unwrap().map_count(), 2);
        assert_eq!(frames.state(shared).unwrap().rmap_anchor_count(), 2);
        assert!(frames.rmap_anchors(shared).unwrap().contains(&left_anchor));
        assert!(frames.rmap_anchors(shared).unwrap().contains(&right_anchor));
        right
            .unmap(&mut frames, ROOT_BASE + PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        assert_eq!(frames.state(shared).unwrap().ref_count(), 1);
        assert_eq!(frames.state(shared).unwrap().map_count(), 1);
        assert_eq!(
            frames.state(shared).unwrap().rmap_anchor(),
            Some(left_anchor)
        );
        assert_eq!(frames.state(shared).unwrap().rmap_anchor_count(), 1);
    }

    #[cfg(feature = "loom")]
    struct LoomCowLoanModel {
        space: AddressSpace,
        frames: FrameTable,
        base: u64,
        shared: FrameId,
        replacement: FrameId,
    }

    #[cfg(feature = "loom")]
    impl LoomCowLoanModel {
        fn new() -> Self {
            let mut frames = FrameTable::new();
            let shared = frames.register_existing(0x56_000).unwrap();
            let replacement = frames.register_existing(0x57_000).unwrap();

            let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
            let vmo = space
                .create_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(200))
                .unwrap();
            space.bind_vmo_frame(vmo, 0, shared).unwrap();
            space
                .map_fixed(
                    &mut frames,
                    ROOT_BASE,
                    PAGE_SIZE,
                    vmo,
                    0,
                    MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                    MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                )
                .unwrap();
            space.mark_copy_on_write(ROOT_BASE, PAGE_SIZE).unwrap();

            Self {
                space,
                frames,
                base: ROOT_BASE,
                shared,
                replacement,
            }
        }

        fn resolve_cow(&mut self) {
            self.space
                .resolve_cow_fault(&mut self.frames, self.base + 0x80, self.replacement)
                .unwrap();
        }

        fn loan_shared_once(&mut self) {
            let loan = self
                .frames
                .pin_many(&[self.shared])
                .unwrap()
                .into_loan(&mut self.frames)
                .unwrap();
            loan.release(&mut self.frames);
        }
    }

    #[cfg(feature = "loom")]
    struct LoomLazyFaultLoanModel {
        space: AddressSpace,
        frames: FrameTable,
        base: u64,
        shared: FrameId,
    }

    #[cfg(feature = "loom")]
    impl LoomLazyFaultLoanModel {
        fn new() -> Self {
            let mut frames = FrameTable::new();
            let shared = frames.register_existing(0x58_000).unwrap();

            let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
            let vmo = space
                .import_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(201))
                .unwrap();
            space
                .map_fixed(
                    &mut frames,
                    ROOT_BASE,
                    PAGE_SIZE,
                    vmo,
                    0,
                    MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                    MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                )
                .unwrap();

            Self {
                space,
                frames,
                base: ROOT_BASE,
                shared,
            }
        }

        fn resolve_fault(&mut self) {
            self.space
                .resolve_lazy_vmo_fault(&mut self.frames, self.base + 0x10, self.shared)
                .unwrap();
        }

        fn loan_shared_once(&mut self) {
            let loan = self
                .frames
                .pin_many(&[self.shared])
                .unwrap()
                .into_loan(&mut self.frames)
                .unwrap();
            loan.release(&mut self.frames);
        }
    }

    #[cfg(feature = "loom")]
    #[test]
    fn loom_cow_fault_and_loan_release_preserve_frame_accounting() {
        use loom::sync::{Arc, Mutex};
        use loom::thread;

        loom::model(|| {
            let state = Arc::new(Mutex::new(LoomCowLoanModel::new()));

            let resolve_state = Arc::clone(&state);
            let resolve = thread::spawn(move || {
                thread::yield_now();
                let mut state = resolve_state.lock().unwrap();
                state.resolve_cow();
            });

            let loan_state = Arc::clone(&state);
            let loan = thread::spawn(move || {
                let mut state = loan_state.lock().unwrap();
                state.loan_shared_once();
            });

            resolve.join().unwrap();
            loan.join().unwrap();

            let state = state.lock().unwrap();
            let lookup = state.space.lookup(state.base).unwrap();
            assert_eq!(lookup.frame_id(), Some(state.replacement));
            assert!(lookup.perms().contains(MappingPerms::WRITE));
            assert!(!lookup.is_copy_on_write());

            let shared = state.frames.state(state.shared).unwrap();
            assert_eq!(shared.ref_count(), 0);
            assert_eq!(shared.map_count(), 0);
            assert_eq!(shared.pin_count(), 0);
            assert_eq!(shared.loan_count(), 0);
            assert_eq!(shared.rmap_anchor_count(), 0);

            let replacement = state.frames.state(state.replacement).unwrap();
            assert_eq!(replacement.ref_count(), 1);
            assert_eq!(replacement.map_count(), 1);
            assert_eq!(replacement.pin_count(), 0);
            assert_eq!(replacement.loan_count(), 0);
        });
    }

    #[cfg(feature = "loom")]
    #[test]
    fn loom_lazy_fault_and_loan_release_preserve_materialized_mapping() {
        use loom::sync::{Arc, Mutex};
        use loom::thread;

        loom::model(|| {
            let state = Arc::new(Mutex::new(LoomLazyFaultLoanModel::new()));

            let fault_state = Arc::clone(&state);
            let fault = thread::spawn(move || {
                thread::yield_now();
                let mut state = fault_state.lock().unwrap();
                state.resolve_fault();
            });

            let loan_state = Arc::clone(&state);
            let loan = thread::spawn(move || {
                let mut state = loan_state.lock().unwrap();
                state.loan_shared_once();
            });

            fault.join().unwrap();
            loan.join().unwrap();

            let state = state.lock().unwrap();
            let lookup = state.space.lookup(state.base).unwrap();
            assert_eq!(lookup.frame_id(), Some(state.shared));
            assert_eq!(
                state.space.pte_meta(state.base).unwrap().tag(),
                PteMetaTag::Present
            );

            let shared = state.frames.state(state.shared).unwrap();
            assert_eq!(shared.ref_count(), 1);
            assert_eq!(shared.map_count(), 1);
            assert_eq!(shared.pin_count(), 0);
            assert_eq!(shared.loan_count(), 0);
        });
    }

    proptest! {
        #[test]
        fn prop_vmas_remain_sorted_and_non_overlapping(slot_count in 1usize..8) {
            let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
            let mut frames = FrameTable::new();
            for index in 0..slot_count {
                let vmo = space
                    .create_vmo(
                        VmoKind::Anonymous,
                        PAGE_SIZE,
                        global_vmo_id((index as u64) + 100),
                    )
                    .unwrap();
                let frame = frames
                    .register_existing(0x1000_0000 + (index as u64 * PAGE_SIZE))
                    .unwrap();
                space.bind_vmo_frame(vmo, 0, frame).unwrap();
                let base = ROOT_BASE + (index as u64 * PAGE_SIZE);
                let _ = space.map_fixed(
                    &mut frames,
                    base,
                    PAGE_SIZE,
                    vmo,
                    0,
                    MappingPerms::READ | MappingPerms::USER,
                    MappingPerms::READ | MappingPerms::USER,
                );
            }

            let vmas = space.vmas();
            for pair in vmas.windows(2) {
                prop_assert!(pair[0].base() < pair[1].base());
                prop_assert!(pair[0].base() + pair[0].len() <= pair[1].base());
            }
        }

        #[test]
        fn prop_child_vmars_remain_sorted_and_non_overlapping(
            cpu_count in 1usize..4,
            alloc_count in 1usize..12,
        ) {
            let mut space = AddressSpace::new(ROOT_BASE, VA_MAGAZINE_BYTES * 2).unwrap();
            for index in 0..alloc_count {
                let cpu_id = index % cpu_count;
                let len = if index % 3 == 0 { 2 * PAGE_SIZE } else { PAGE_SIZE };
                let align = if index % 2 == 0 { PAGE_SIZE } else { 2 * PAGE_SIZE };
                let _ = space.allocate_subvmar_for_cpu(cpu_id, len, align);
            }

            for pair in space.child_vmars().windows(2) {
                prop_assert!(pair[0].base() < pair[1].base());
                prop_assert!(pair[0].end() <= pair[1].base());
            }
        }
    }

    #[test]
    fn futex_key_uses_private_identity_for_local_anonymous_vmo() {
        let (space, _, _, _) = sample_space();
        let lookup = space.lookup(ROOT_BASE + 0x20).unwrap();
        assert_eq!(
            FutexKey::from_lookup(99, ROOT_BASE + 0x20, lookup),
            FutexKey::PrivateAnonymous {
                process_id: 99,
                page_base: ROOT_BASE,
                byte_offset: 0x20,
            }
        );
    }

    #[test]
    fn futex_key_uses_shared_identity_for_imported_anonymous_vmo() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let shared = space
            .import_vmo(VmoKind::Anonymous, PAGE_SIZE, global_vmo_id(202))
            .unwrap();
        let frame = frames.register_existing(0x1000_2000).unwrap();
        space.bind_vmo_frame(shared, 0, frame).unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                shared,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        let lookup = space.lookup(ROOT_BASE + 0x24).unwrap();
        assert_eq!(
            FutexKey::from_lookup(99, ROOT_BASE + 0x24, lookup),
            FutexKey::Shared {
                global_vmo_id: global_vmo_id(202),
                offset: 0x24,
            }
        );
    }

    #[test]
    fn private_pager_clone_faults_from_shared_source_but_keeps_private_futex_identity() {
        let mut frames = FrameTable::new();
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let source_global = global_vmo_id(203);
        let clone_global = global_vmo_id(204);
        let imported = space
            .import_vmo(VmoKind::PagerBacked, PAGE_SIZE, source_global)
            .unwrap();
        let frame = frames.register_existing(0x1000_3000).unwrap();
        space.set_vmo_frame(imported, 0, frame).unwrap();
        let private = space
            .create_private_clone_vmo(
                VmoKind::PagerBacked,
                PAGE_SIZE,
                clone_global,
                Some(source_global),
            )
            .unwrap();
        space
            .map_fixed(
                &mut frames,
                ROOT_BASE,
                PAGE_SIZE,
                private,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();

        let lookup = space.lookup(ROOT_BASE + 0x28).unwrap();
        assert_eq!(lookup.global_vmo_id(), clone_global);
        assert_eq!(lookup.shared_backing_global_vmo_id(), None);
        assert_eq!(lookup.fault_global_vmo_id(), Some(source_global));
        assert!(lookup.is_global_backed());
        assert_eq!(
            FutexKey::from_lookup(99, ROOT_BASE + 0x28, lookup),
            FutexKey::PrivateAnonymous {
                process_id: 99,
                page_base: ROOT_BASE,
                byte_offset: 0x28,
            }
        );
    }
}
