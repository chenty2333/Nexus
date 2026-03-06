#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Axle VM metadata core.
//!
//! This crate keeps the early `VMO / VMAR / VMA` model host-testable and
//! reusable inside the kernel. The current focus is metadata only:
//!
//! - bootstrap `AddressSpace` with a root VMAR
//! - `Vmo` allocation and fixed mappings
//! - `map / unmap / protect` metadata transitions
//! - `VA -> (VMO, offset, perms)` reverse lookup
//!
//! It deliberately does **not** manage page tables, physical frames, pinning, or
//! copy-on-write yet. Those stay in later phases.

extern crate alloc;

use alloc::vec::Vec;
use bitflags::bitflags;

/// Canonical page size used by the metadata layer.
pub const PAGE_SIZE: u64 = 0x1000;

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

/// Identifier for a VMO tracked by an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmoId(u64);

impl VmoId {
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
}

/// Metadata for a VMO tracked by the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vmo {
    id: VmoId,
    kind: VmoKind,
    size_bytes: u64,
}

impl Vmo {
    /// Stable id.
    pub const fn id(self) -> VmoId {
        self.id
    }

    /// Backing kind.
    pub const fn kind(self) -> VmoKind {
        self.kind
    }

    /// Size in bytes.
    pub const fn size_bytes(self) -> u64 {
        self.size_bytes
    }
}

/// Root VMAR metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vmar {
    id: VmarId,
    base: u64,
    len: u64,
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
}

/// A single virtual-memory mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vma {
    base: u64,
    len: u64,
    vmo_id: VmoId,
    vmo_offset: u64,
    perms: MappingPerms,
    max_perms: MappingPerms,
}

impl Vma {
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

    /// Offset into the backing VMO.
    pub const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    /// Current mapping permissions.
    pub const fn perms(self) -> MappingPerms {
        self.perms
    }

    /// Maximum allowed permissions for future `protect` operations.
    pub const fn max_perms(self) -> MappingPerms {
        self.max_perms
    }

    fn end(self) -> u64 {
        self.base + self.len
    }

    fn contains(self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }

    fn contains_range(self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        base >= self.base && end <= self.end()
    }
}

/// Result of resolving a virtual address back to its VMA and VMO metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaLookup {
    vmar_id: VmarId,
    vmo_id: VmoId,
    vmo_kind: VmoKind,
    vmo_offset: u64,
    perms: MappingPerms,
    max_perms: MappingPerms,
    mapping_base: u64,
    mapping_len: u64,
}

impl VmaLookup {
    /// Root VMAR containing the mapping.
    pub const fn vmar_id(self) -> VmarId {
        self.vmar_id
    }

    /// Backing VMO id.
    pub const fn vmo_id(self) -> VmoId {
        self.vmo_id
    }

    /// Backing VMO kind.
    pub const fn vmo_kind(self) -> VmoKind {
        self.vmo_kind
    }

    /// Byte offset into the backing VMO at the resolved VA.
    pub const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    /// Current mapping permissions.
    pub const fn perms(self) -> MappingPerms {
        self.perms
    }

    /// Maximum allowed permissions.
    pub const fn max_perms(self) -> MappingPerms {
        self.max_perms
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

/// Errors returned by address-space metadata operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// Invalid alignment, zero-length, or overflowed range.
    InvalidArgs,
    /// Requested range lies outside the root VMAR.
    OutOfRange,
    /// Referenced VMO id does not exist.
    InvalidVmo,
    /// Requested mapping overlaps an existing VMA.
    Overlap,
    /// Requested mapping or range was not found.
    NotFound,
    /// `protect` attempted to grant permissions above `max_perms`.
    PermissionIncrease,
}

/// Metadata-only address space with one root VMAR.
#[derive(Debug)]
pub struct AddressSpace {
    root: Vmar,
    vmos: Vec<Vmo>,
    vmas: Vec<Vma>,
    next_vmo_id: u64,
}

impl AddressSpace {
    /// Create a new address space with a single root VMAR.
    pub fn new(root_base: u64, root_len: u64) -> Result<Self, AddressSpaceError> {
        if root_len == 0 || !is_page_aligned(root_base) || !is_page_aligned(root_len) {
            return Err(AddressSpaceError::InvalidArgs);
        }
        let Some(_end) = root_base.checked_add(root_len) else {
            return Err(AddressSpaceError::InvalidArgs);
        };

        Ok(Self {
            root: Vmar {
                id: VmarId(1),
                base: root_base,
                len: root_len,
            },
            vmos: Vec::new(),
            vmas: Vec::new(),
            next_vmo_id: 1,
        })
    }

    /// Root VMAR metadata.
    pub const fn root_vmar(&self) -> Vmar {
        self.root
    }

    /// Allocate a new VMO record.
    pub fn create_vmo(
        &mut self,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<VmoId, AddressSpaceError> {
        if size_bytes == 0 || !is_page_aligned(size_bytes) {
            return Err(AddressSpaceError::InvalidArgs);
        }

        let id = VmoId(self.next_vmo_id);
        self.next_vmo_id = self.next_vmo_id.wrapping_add(1);
        self.vmos.push(Vmo {
            id,
            kind,
            size_bytes,
        });
        Ok(id)
    }

    /// Return metadata for a tracked VMO.
    pub fn vmo(&self, id: VmoId) -> Option<Vmo> {
        self.vmos.iter().copied().find(|vmo| vmo.id == id)
    }

    /// Return the current VMA list in ascending virtual-address order.
    pub fn vmas(&self) -> &[Vma] {
        &self.vmas
    }

    /// Install a fixed mapping into the root VMAR.
    pub fn map_fixed(
        &mut self,
        base: u64,
        len: u64,
        vmo_id: VmoId,
        vmo_offset: u64,
        perms: MappingPerms,
        max_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        if !max_perms.contains(perms) || !self.root_contains(base, len) {
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
        if self
            .vmas
            .iter()
            .any(|existing| overlaps(*existing, base, len))
        {
            return Err(AddressSpaceError::Overlap);
        }

        self.vmas.push(Vma {
            base,
            len,
            vmo_id,
            vmo_offset,
            perms,
            max_perms,
        });
        self.vmas.sort_by_key(|vma| vma.base);
        Ok(())
    }

    /// Remove an existing mapping.
    pub fn unmap(&mut self, base: u64, len: u64) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let index = self
            .vmas
            .iter()
            .position(|vma| vma.base == base && vma.len == len)
            .ok_or(AddressSpaceError::NotFound)?;
        self.vmas.remove(index);
        Ok(())
    }

    /// Change permissions on an existing mapping without changing its extent.
    pub fn protect(
        &mut self,
        base: u64,
        len: u64,
        new_perms: MappingPerms,
    ) -> Result<(), AddressSpaceError> {
        validate_mapping_range(base, len)?;
        let vma = self
            .vmas
            .iter_mut()
            .find(|vma| vma.base == base && vma.len == len)
            .ok_or(AddressSpaceError::NotFound)?;
        if !vma.max_perms.contains(new_perms) {
            return Err(AddressSpaceError::PermissionIncrease);
        }
        vma.perms = new_perms;
        Ok(())
    }

    /// Resolve one virtual address to its backing VMO metadata.
    pub fn lookup(&self, va: u64) -> Option<VmaLookup> {
        let vma = self.vmas.iter().copied().find(|vma| vma.contains(va))?;
        let vmo = self.vmo(vma.vmo_id)?;
        Some(VmaLookup {
            vmar_id: self.root.id,
            vmo_id: vma.vmo_id,
            vmo_kind: vmo.kind(),
            vmo_offset: vma.vmo_offset + (va - vma.base),
            perms: vma.perms,
            max_perms: vma.max_perms,
            mapping_base: vma.base,
            mapping_len: vma.len,
        })
    }

    /// Resolve a virtual range if it is fully covered by a single VMA.
    pub fn lookup_range(&self, base: u64, len: u64) -> Option<VmaLookup> {
        if validate_lookup_range(base, len).is_err() {
            return None;
        }
        let vma = self
            .vmas
            .iter()
            .copied()
            .find(|candidate| candidate.contains_range(base, len))?;
        let vmo = self.vmo(vma.vmo_id)?;
        Some(VmaLookup {
            vmar_id: self.root.id,
            vmo_id: vma.vmo_id,
            vmo_kind: vmo.kind(),
            vmo_offset: vma.vmo_offset + (base - vma.base),
            perms: vma.perms,
            max_perms: vma.max_perms,
            mapping_base: vma.base,
            mapping_len: vma.len,
        })
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
        while cursor < end {
            let Some(vma) = self
                .vmas
                .iter()
                .copied()
                .find(|candidate| candidate.contains(cursor))
            else {
                return false;
            };
            cursor = core::cmp::min(vma.end(), end);
        }
        true
    }

    fn root_contains(&self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        base >= self.root.base && end <= self.root.base + self.root.len
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

fn overlaps(vma: Vma, base: u64, len: u64) -> bool {
    let end = base + len;
    base < vma.end() && end > vma.base
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ROOT_BASE: u64 = 0x1_0000_0000;
    const ROOT_LEN: u64 = 0x4000;

    fn sample_space() -> AddressSpace {
        let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
        let code = space.create_vmo(VmoKind::Anonymous, PAGE_SIZE).unwrap();
        let data = space.create_vmo(VmoKind::Anonymous, PAGE_SIZE).unwrap();
        space
            .map_fixed(
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
                ROOT_BASE + PAGE_SIZE,
                PAGE_SIZE,
                data,
                0,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
                MappingPerms::READ | MappingPerms::WRITE | MappingPerms::USER,
            )
            .unwrap();
        space
    }

    #[test]
    fn lookup_reports_vmo_offset_and_perms() {
        let space = sample_space();
        let lookup = space.lookup(ROOT_BASE + 0x120).unwrap();
        assert_eq!(lookup.vmo_offset(), 0x120);
        assert!(lookup.perms().contains(MappingPerms::EXECUTE));
        assert_eq!(lookup.mapping_base(), ROOT_BASE);
        assert_eq!(lookup.mapping_len(), PAGE_SIZE);
    }

    #[test]
    fn map_rejects_overlap_and_out_of_range() {
        let mut space = sample_space();
        let extra = space.create_vmo(VmoKind::Anonymous, PAGE_SIZE).unwrap();
        assert_eq!(
            space.map_fixed(
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
    fn protect_and_unmap_update_metadata() {
        let mut space = sample_space();
        let data_base = ROOT_BASE + PAGE_SIZE;
        space
            .protect(
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
                data_base,
                PAGE_SIZE,
                MappingPerms::EXECUTE | MappingPerms::USER
            ),
            Err(AddressSpaceError::PermissionIncrease)
        );
        space.unmap(data_base, PAGE_SIZE).unwrap();
        assert!(space.lookup(data_base).is_none());
    }

    #[test]
    fn contains_range_can_span_adjacent_vmas() {
        let mut space = sample_space();
        let extra = space.create_vmo(VmoKind::Anonymous, PAGE_SIZE).unwrap();
        space
            .map_fixed(
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

    proptest! {
        #[test]
        fn prop_vmas_remain_sorted_and_non_overlapping(slot_count in 1usize..8) {
            let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
            for index in 0..slot_count {
                let vmo = space.create_vmo(VmoKind::Anonymous, PAGE_SIZE).unwrap();
                let base = ROOT_BASE + (index as u64 * PAGE_SIZE);
                let _ = space.map_fixed(
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
    }
}
