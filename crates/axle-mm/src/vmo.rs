//! VMO, VMAR, and coarse mapping-record metadata.

use alloc::vec::Vec;

use super::frame_table::{AddressSpaceId, FrameId};
use super::pte_meta::PteMetaTag;
use super::{MappingCachePolicy, MappingPerms, PAGE_SIZE};

/// Identifier for a VMO tracked by an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmoId(u64);

impl VmoId {
    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Kernel-global identity for one VMO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobalVmoId(u64);

impl GlobalVmoId {
    /// Build from a raw non-zero id.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Identifier for a VMAR tracked by an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmarId(u64);

impl VmarId {
    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Identifier for one coarse mapping record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MapId(u64);

impl MapId {
    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Future frame-to-mapping reverse-lookup anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReverseMapAnchor {
    address_space_id: AddressSpaceId,
    map_id: MapId,
    page_delta: u64,
}

impl ReverseMapAnchor {
    /// Build an anchor from an address space, mapping id, and page index.
    pub const fn new(address_space_id: AddressSpaceId, map_id: MapId, page_delta: u64) -> Self {
        Self {
            address_space_id,
            map_id,
            page_delta,
        }
    }

    /// Address space owning the anchor.
    pub const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    /// Mapping record owning the anchor.
    pub const fn map_id(self) -> MapId {
        self.map_id
    }

    /// Page index within the mapping record.
    pub const fn page_delta(self) -> u64 {
        self.page_delta
    }
}

/// VMO backing kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmoKind {
    /// Anonymous memory.
    Anonymous,
    /// Fixed physical region (for MMIO or fixed mappings).
    Physical,
    /// Physically-contiguous memory.
    Contiguous,
    /// Read-only pager-backed memory populated on demand from one external source.
    PagerBacked,
}

impl VmoKind {
    /// Whether kernel byte-oriented `read` operations are allowed.
    pub const fn supports_kernel_read(self) -> bool {
        matches!(self, Self::Anonymous | Self::Contiguous | Self::PagerBacked)
    }

    /// Whether kernel byte-oriented `write` operations are allowed.
    pub const fn supports_kernel_write(self) -> bool {
        matches!(self, Self::Anonymous | Self::Contiguous)
    }

    /// Whether the VMO can change size after creation.
    pub const fn supports_resize(self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// Whether mappings of this VMO may be armed for copy-on-write.
    pub const fn supports_copy_on_write(self) -> bool {
        matches!(self, Self::Anonymous | Self::PagerBacked)
    }

    /// Whether mappings of this VMO may participate in page-loan transfer.
    pub const fn supports_page_loan(self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// Whether mappings of this VMO require a resident frame before mapping/faulting.
    pub const fn requires_resident_frames(self) -> bool {
        matches!(self, Self::Physical | Self::Contiguous)
    }

    pub(crate) const fn fault_policy_for_create(self) -> VmoFaultPolicy {
        match self {
            Self::Anonymous => VmoFaultPolicy::LocalAnonymous,
            Self::Physical | Self::Contiguous => VmoFaultPolicy::NonDemandPaged,
            Self::PagerBacked => VmoFaultPolicy::GlobalBacked,
        }
    }

    pub(crate) const fn fault_policy_for_import(self) -> VmoFaultPolicy {
        match self {
            Self::Anonymous | Self::PagerBacked => VmoFaultPolicy::GlobalBacked,
            Self::Physical | Self::Contiguous => VmoFaultPolicy::NonDemandPaged,
        }
    }

    pub(crate) const fn resident_pte_tag(self) -> PteMetaTag {
        match self {
            Self::Anonymous | Self::PagerBacked => PteMetaTag::Present,
            Self::Physical | Self::Contiguous => PteMetaTag::Phys,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VmoFaultPolicy {
    LocalAnonymous,
    GlobalBacked,
    NonDemandPaged,
}

/// Metadata for a VMO tracked by the address space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vmo {
    pub(crate) id: VmoId,
    pub(crate) global_id: GlobalVmoId,
    pub(crate) kind: VmoKind,
    pub(crate) fault_policy: VmoFaultPolicy,
    pub(crate) size_bytes: u64,
    pub(crate) frames: Vec<Option<FrameId>>,
}

impl Vmo {
    /// Stable id.
    pub const fn id(&self) -> VmoId {
        self.id
    }

    /// Kernel-global VMO identity.
    pub const fn global_id(&self) -> GlobalVmoId {
        self.global_id
    }

    /// Backing kind.
    pub const fn kind(&self) -> VmoKind {
        self.kind
    }

    /// Size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Whether faults for missing pages in this VMO resolve through a shared/global backing.
    pub const fn is_global_backed(&self) -> bool {
        matches!(self.fault_policy, VmoFaultPolicy::GlobalBacked)
    }

    /// Return the bound frame for the given byte offset, if one is resident.
    pub fn frame_at_offset(&self, offset: u64) -> Option<FrameId> {
        let page_index = usize::try_from(offset / PAGE_SIZE).ok()?;
        self.frames.get(page_index).copied().flatten()
    }

    /// Snapshot every currently bound frame slot.
    pub fn frames(&self) -> &[Option<FrameId>] {
        &self.frames
    }

    pub(crate) fn missing_page_tag(&self) -> PteMetaTag {
        match self.fault_policy {
            VmoFaultPolicy::LocalAnonymous => PteMetaTag::LazyAnon,
            VmoFaultPolicy::GlobalBacked => PteMetaTag::LazyVmo,
            VmoFaultPolicy::NonDemandPaged => PteMetaTag::Reserved,
        }
    }

    pub(crate) fn supports_copy_on_write(&self) -> bool {
        self.kind.supports_copy_on_write()
    }
}

/// Root VMAR metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vmar {
    pub(crate) id: VmarId,
    pub(crate) base: u64,
    pub(crate) len: u64,
}

impl Vmar {
    /// Stable id.
    pub const fn id(self) -> VmarId {
        self.id
    }

    /// Base virtual address.
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Span length in bytes.
    pub const fn len(self) -> u64 {
        self.len
    }

    /// Whether the VMAR span is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub(crate) fn end(self) -> u64 {
        self.base + self.len
    }

    pub(crate) fn contains_range(self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        base >= self.base && end <= self.end()
    }
}

/// Placement policy for child VMAR allocation inside one parent range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmarAllocMode {
    /// Require the returned child VMAR to start exactly at `parent.base + offset`.
    Specific,
    /// Prefer compact low-fragmentation placement near the parent's current cursor.
    Compact,
    /// Prefer ASLR-style placement within the parent, then wrap if needed.
    Randomized,
}

/// Default placement policy for non-specific allocations and mappings inside one VMAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmarPlacementPolicy {
    /// Keep later allocations and mappings close together.
    Compact,
    /// Preserve ASLR-style placement for later child allocations.
    Randomized,
}

/// Coarse mapping record linking VMAR control metadata to page-level state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapRec {
    pub(crate) id: MapId,
    pub(crate) vmar_id: VmarId,
    pub(crate) base: u64,
    pub(crate) len: u64,
    pub(crate) vmo_id: VmoId,
    pub(crate) global_vmo_id: GlobalVmoId,
    pub(crate) vmo_offset: u64,
    pub(crate) max_perms: MappingPerms,
    pub(crate) cache_policy: MappingCachePolicy,
}

impl MapRec {
    /// Stable mapping identifier.
    pub const fn id(self) -> MapId {
        self.id
    }

    /// Owning VMAR id.
    pub const fn vmar_id(self) -> VmarId {
        self.vmar_id
    }

    /// Mapping base address.
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Mapping span length in bytes.
    pub const fn len(self) -> u64 {
        self.len
    }

    /// Whether the mapping span is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Backing VMO id.
    pub const fn vmo_id(self) -> VmoId {
        self.vmo_id
    }

    /// Kernel-global VMO identity.
    pub const fn global_vmo_id(self) -> GlobalVmoId {
        self.global_vmo_id
    }

    /// Offset into the backing VMO.
    pub const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    /// Maximum allowed permissions for future `protect` operations.
    pub const fn max_perms(self) -> MappingPerms {
        self.max_perms
    }

    /// Fixed cache policy for this mapping.
    pub const fn cache_policy(self) -> MappingCachePolicy {
        self.cache_policy
    }

    pub(crate) fn end(self) -> u64 {
        self.base + self.len
    }

    pub(crate) fn contains_page(self, page_base: u64) -> bool {
        page_base >= self.base && page_base < self.end()
    }

    pub(crate) fn contains_range(self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        base >= self.base && end <= self.end()
    }
}
