//! Virtual-memory area (VMA) metadata and reverse lookup.

use super::frame_table::{AddressSpaceId, FrameId};
use super::vmo::{GlobalVmoId, MapId, VmarId, VmoId, VmoKind};
use super::{MappingCachePolicy, MappingClonePolicy, MappingPerms};

/// A single virtual-memory mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vma {
    pub(crate) map_id: MapId,
    pub(crate) vmar_id: VmarId,
    pub(crate) base: u64,
    pub(crate) len: u64,
    pub(crate) perms: MappingPerms,
    pub(crate) copy_on_write: bool,
    pub(crate) clone_policy: MappingClonePolicy,
}

impl Vma {
    /// Stable coarse mapping identifier.
    pub const fn map_id(self) -> MapId {
        self.map_id
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

    /// Current mapping permissions.
    pub const fn perms(self) -> MappingPerms {
        self.perms
    }

    /// Whether the mapping is armed for copy-on-write fault handling.
    pub const fn is_copy_on_write(self) -> bool {
        self.copy_on_write
    }

    /// Child-clone policy frozen for this mapping.
    pub const fn clone_policy(self) -> MappingClonePolicy {
        self.clone_policy
    }

    pub(crate) fn end(self) -> u64 {
        self.base + self.len
    }

    pub(crate) fn contains(self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }

    pub(crate) fn contains_range(self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        base >= self.base && end <= self.end()
    }
}

/// Result of resolving a virtual address back to its VMA and VMO metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaLookup {
    pub(crate) address_space_id: AddressSpaceId,
    pub(crate) map_id: MapId,
    pub(crate) vmar_id: VmarId,
    pub(crate) vmo_id: VmoId,
    pub(crate) global_vmo_id: GlobalVmoId,
    pub(crate) vmo_kind: VmoKind,
    pub(crate) vmo_offset: u64,
    pub(crate) frame_id: Option<FrameId>,
    pub(crate) perms: MappingPerms,
    pub(crate) max_perms: MappingPerms,
    pub(crate) cache_policy: MappingCachePolicy,
    pub(crate) copy_on_write: bool,
    pub(crate) clone_policy: MappingClonePolicy,
    pub(crate) global_backed: bool,
    pub(crate) mapping_base: u64,
    pub(crate) mapping_len: u64,
}

impl VmaLookup {
    /// Owning address space containing the resolved mapping.
    pub const fn address_space_id(self) -> AddressSpaceId {
        self.address_space_id
    }

    /// Stable coarse mapping identifier.
    pub const fn map_id(self) -> MapId {
        self.map_id
    }

    /// Owning VMAR containing the mapping.
    pub const fn vmar_id(self) -> VmarId {
        self.vmar_id
    }

    /// Backing VMO id.
    pub const fn vmo_id(self) -> VmoId {
        self.vmo_id
    }

    /// Kernel-global VMO identity.
    pub const fn global_vmo_id(self) -> GlobalVmoId {
        self.global_vmo_id
    }

    /// Backing VMO kind.
    pub const fn vmo_kind(self) -> VmoKind {
        self.vmo_kind
    }

    /// Byte offset into the backing VMO at the resolved VA.
    pub const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    /// Resident frame id for the resolved byte, if a frame is currently bound.
    pub const fn frame_id(self) -> Option<FrameId> {
        self.frame_id
    }

    /// Current mapping permissions.
    pub const fn perms(self) -> MappingPerms {
        self.perms
    }

    /// Maximum allowed permissions.
    pub const fn max_perms(self) -> MappingPerms {
        self.max_perms
    }

    /// Fixed cache policy for this mapping.
    pub const fn cache_policy(self) -> MappingCachePolicy {
        self.cache_policy
    }

    /// Whether the resolved mapping is currently armed for copy-on-write.
    pub const fn is_copy_on_write(self) -> bool {
        self.copy_on_write
    }

    /// Child-clone policy frozen for the resolved mapping.
    pub const fn clone_policy(self) -> MappingClonePolicy {
        self.clone_policy
    }

    /// Whether missing pages for this mapping fault through a shared/global backing source.
    pub const fn is_global_backed(self) -> bool {
        self.global_backed
    }

    /// Base virtual address of the containing mapping.
    pub const fn mapping_base(self) -> u64 {
        self.mapping_base
    }

    /// Length of the containing mapping.
    pub const fn mapping_len(self) -> u64 {
        self.mapping_len
    }
}
