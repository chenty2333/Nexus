//! Shared error and fault-resolution types for the address-space metadata layer.

use super::frame_table::{FrameId, FrameTableError};
use super::pte_meta::PteMeta;
use super::vma::{Vma, VmaLookup};
use super::vmo::{GlobalVmoId, MapRec};
use super::{PAGE_SIZE, align_down};

/// Stable futex key derived from VMA metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FutexKey {
    /// Shared key backed by a globally-identified VMO and byte offset.
    Shared {
        /// Kernel-global VMO identity.
        global_vmo_id: GlobalVmoId,
        /// Byte offset of the futex word inside the VMO.
        offset: u64,
    },
    /// Private fallback for anonymous mappings that lack a global identity.
    PrivateAnonymous {
        /// Owning process id.
        process_id: u64,
        /// Base address of the containing page.
        page_base: u64,
        /// Byte offset of the futex word inside the containing page.
        byte_offset: u16,
    },
}

impl FutexKey {
    /// Build a private anonymous fallback key from the current process and address.
    pub fn private_anonymous(process_id: u64, user_addr: u64) -> Self {
        Self::PrivateAnonymous {
            process_id,
            page_base: align_down(user_addr, PAGE_SIZE),
            byte_offset: (user_addr & (PAGE_SIZE - 1)) as u16,
        }
    }

    /// Build a futex key from resolved mapping metadata.
    pub fn from_lookup(process_id: u64, user_addr: u64, lookup: VmaLookup) -> Self {
        if lookup.is_global_backed() {
            return Self::Shared {
                global_vmo_id: lookup.global_vmo_id(),
                offset: lookup.vmo_offset(),
            };
        }

        Self::private_anonymous(process_id, user_addr)
    }
}

/// Errors returned by address-space metadata operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// Invalid alignment, zero-length, or overflowed range.
    InvalidArgs,
    /// Requested range lies outside the root VMAR.
    OutOfRange,
    /// Referenced VMO id does not exist.
    InvalidVmo,
    /// Referenced VMAR id does not exist.
    InvalidVmar,
    /// Referenced frame is not registered.
    InvalidFrame,
    /// Requested frame slot is already bound.
    AlreadyBound,
    /// Requested mapping overlaps an existing VMA.
    Overlap,
    /// Requested mapping or range was not found.
    NotFound,
    /// Requested VMAR operation cannot proceed while the range is still busy.
    Busy,
    /// `protect` attempted to grant permissions above `max_perms`.
    PermissionIncrease,
    /// Frame-table bookkeeping failed.
    FrameTable(FrameTableError),
    /// The mapping is not currently armed for copy-on-write fault handling.
    NotCopyOnWrite,
}

/// Result of resolving a copy-on-write fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowFaultResolution {
    pub(crate) fault_page_base: u64,
    pub(crate) old_frame_id: FrameId,
    pub(crate) new_frame_id: FrameId,
}

impl CowFaultResolution {
    /// Base virtual address of the faulting page.
    pub const fn fault_page_base(self) -> u64 {
        self.fault_page_base
    }

    /// Frame that backed the mapping before the COW split.
    pub const fn old_frame_id(self) -> FrameId {
        self.old_frame_id
    }

    /// Frame installed for the writable private copy.
    pub const fn new_frame_id(self) -> FrameId {
        self.new_frame_id
    }
}

/// Result of materializing one lazy anonymous page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LazyAnonFaultResolution {
    pub(crate) fault_page_base: u64,
    pub(crate) new_frame_id: FrameId,
}

impl LazyAnonFaultResolution {
    /// Base virtual address of the materialized page.
    pub const fn fault_page_base(self) -> u64 {
        self.fault_page_base
    }

    /// Frame installed for the new anonymous page.
    pub const fn new_frame_id(self) -> FrameId {
        self.new_frame_id
    }
}

/// Result of binding one lazy VMO-backed page to a resident frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LazyVmoFaultResolution {
    pub(crate) fault_page_base: u64,
    pub(crate) frame_id: FrameId,
}

impl LazyVmoFaultResolution {
    /// Base virtual address of the materialized page.
    pub const fn fault_page_base(self) -> u64 {
        self.fault_page_base
    }

    /// Frame that now backs the faulting page in this address space.
    pub const fn frame_id(self) -> FrameId {
        self.frame_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedPageState {
    pub(crate) page_base: u64,
    pub(crate) page_delta: u64,
    pub(crate) meta: PteMeta,
    pub(crate) map_rec: MapRec,
    pub(crate) vma_index: usize,
    pub(crate) vma: Vma,
}
