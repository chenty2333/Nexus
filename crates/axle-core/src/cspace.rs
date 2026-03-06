//! CSpace: per-process handle table with ABA protection and quarantine FIFO.
//!
//! Goals:
//! - O(1) lookup
//! - ABA-safe handle reuse (index+tag)
//! - Avoid hot reuse (FIFO free list + small quarantine)
//!
//! Notes:
//! - This is a **host-testable** semantic core. Kernel integration will wrap it with locks.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::capability::Capability;
use crate::handle::{HANDLE_MAX_SLOTS, HANDLE_TAG_RESERVED, Handle, HandleError, bump_tag};
use crate::revocation::{RevocationGroupToken, RevocationManager, RevocationRef};

#[derive(Clone, Copy, Debug)]
struct CapEntry {
    cap: Capability,
    rev: Option<RevocationRef>,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    entry: Option<CapEntry>,
    tag: u16,
}

impl Slot {
    fn empty() -> Self {
        Self {
            entry: None,
            tag: 0,
        }
    }
}

/// Errors returned by CSpace operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CSpaceError {
    /// No free slot available (process reached handle capacity).
    NoSlots,
    /// Handle encoding/decoding failed.
    Handle(HandleError),
    /// Handle does not currently reference a live slot/capability.
    BadHandle,
}

impl From<HandleError> for CSpaceError {
    fn from(e: HandleError) -> Self {
        CSpaceError::Handle(e)
    }
}

/// Per-process capability space.
///
/// - Index space is bounded by the handle encoding (default: 14 bits => 16384).
/// - We store slots densely and grow on demand.
pub struct CSpace {
    slots: Vec<Slot>,
    free_fifo: VecDeque<u16>,
    quarantine_fifo: VecDeque<u16>,
    quarantine_len: usize,
    max_slots: u16,
}

impl core::fmt::Debug for CSpace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CSpace")
            .field("slots_len", &self.slots.len())
            .field("free", &self.free_fifo.len())
            .field("quarantine", &self.quarantine_fifo.len())
            .field("quarantine_len", &self.quarantine_len)
            .field("max_slots", &self.max_slots)
            .finish()
    }
}

impl CSpace {
    /// Create a new CSpace.
    ///
    /// - `max_slots` must be <= `HANDLE_MAX_SLOTS` (14-bit index by default).
    /// - `quarantine_len` keeps the most recently freed slots out of the free list.
    pub fn new(max_slots: u16, quarantine_len: usize) -> Self {
        assert!(max_slots <= HANDLE_MAX_SLOTS);
        Self {
            slots: Vec::new(),
            free_fifo: VecDeque::new(),
            quarantine_fifo: VecDeque::new(),
            quarantine_len,
            max_slots,
        }
    }

    /// Current number of allocated slot entries (includes free slots).
    pub fn slots_len(&self) -> usize {
        self.slots.len()
    }

    fn alloc_entry(&mut self, entry: CapEntry) -> Result<Handle, CSpaceError> {
        // Prefer old-free slots (FIFO).
        let idx = if let Some(i) = self.free_fifo.pop_front() {
            i
        } else if (self.slots.len() as u16) < self.max_slots {
            let i = self.slots.len() as u16;
            self.slots.push(Slot::empty());
            i
        } else if let Some(i) = self.quarantine_fifo.pop_front() {
            // Capacity reached; we must reuse from quarantine.
            i
        } else {
            return Err(CSpaceError::NoSlots);
        };

        let slot = &mut self.slots[idx as usize];
        debug_assert!(slot.entry.is_none());

        // Defensive: reserved tag should never be used.
        if slot.tag == HANDLE_TAG_RESERVED {
            slot.tag = bump_tag(slot.tag);
        }

        slot.entry = Some(entry);
        Ok(Handle::new(idx, slot.tag)?)
    }

    /// Allocate a new handle (CSpace slot) for a capability (non-revocable).
    pub fn alloc(&mut self, cap: Capability) -> Result<Handle, CSpaceError> {
        self.alloc_entry(CapEntry { cap, rev: None })
    }

    /// Allocate a new handle whose capability is associated with the given revocation group.
    ///
    /// `group_token` is validated by `rev_mgr` and a snapshot epoch is captured at allocation.
    pub fn alloc_revocable(
        &mut self,
        cap: Capability,
        rev_mgr: &RevocationManager,
        group_token: RevocationGroupToken,
    ) -> Result<Handle, CSpaceError> {
        let rev = rev_mgr
            .snapshot(group_token)
            .map_err(|_| CSpaceError::BadHandle)?;
        self.alloc_entry(CapEntry {
            cap,
            rev: Some(rev),
        })
    }

    /// Duplicate a handle (same capability fields, same revocation association).
    pub fn duplicate(&mut self, h: Handle) -> Result<Handle, CSpaceError> {
        let (idx, tag) = h.decode()?;
        let slot = self.slots.get(idx as usize).ok_or(CSpaceError::BadHandle)?;
        if slot.tag != tag {
            return Err(CSpaceError::BadHandle);
        }
        let entry = slot.entry.ok_or(CSpaceError::BadHandle)?;
        self.alloc_entry(entry)
    }

    /// Duplicate a handle while replacing the stored rights with a derived subset.
    pub fn duplicate_derived(&mut self, h: Handle, rights: u32) -> Result<Handle, CSpaceError> {
        let (idx, tag) = h.decode()?;
        let slot = self.slots.get(idx as usize).ok_or(CSpaceError::BadHandle)?;
        if slot.tag != tag {
            return Err(CSpaceError::BadHandle);
        }
        let mut entry = slot.entry.ok_or(CSpaceError::BadHandle)?;
        entry.cap = Capability::new(entry.cap.object_id(), rights, entry.cap.generation());
        self.alloc_entry(entry)
    }

    /// Replace a handle in-place with a rights-derived version.
    ///
    /// The slot stays occupied, but its ABA tag is bumped so the old handle value
    /// becomes invalid immediately.
    pub fn replace_derived(&mut self, h: Handle, rights: u32) -> Result<Handle, CSpaceError> {
        let (idx, tag) = h.decode()?;
        let slot = self
            .slots
            .get_mut(idx as usize)
            .ok_or(CSpaceError::BadHandle)?;
        if slot.tag != tag {
            return Err(CSpaceError::BadHandle);
        }
        let mut entry = slot.entry.ok_or(CSpaceError::BadHandle)?;
        let new_tag = bump_tag(slot.tag);
        entry.cap = Capability::new(entry.cap.object_id(), rights, entry.cap.generation());
        slot.tag = new_tag;
        slot.entry = Some(entry);
        Handle::new(idx, new_tag).map_err(Into::into)
    }

    /// Lookup a capability (by value copy) from a handle, without revocation checks.
    pub fn get(&self, h: Handle) -> Result<Capability, CSpaceError> {
        Ok(self.get_entry(h)?.cap)
    }

    /// Lookup a capability from a handle, enforcing revocation group validity (if present).
    pub fn get_checked(
        &self,
        h: Handle,
        rev_mgr: &RevocationManager,
    ) -> Result<Capability, CSpaceError> {
        let entry = self.get_entry(h)?;
        if let Some(r) = entry.rev
            && !rev_mgr.is_live(r)
        {
            return Err(CSpaceError::BadHandle);
        }
        Ok(entry.cap)
    }

    fn get_entry(&self, h: Handle) -> Result<CapEntry, CSpaceError> {
        let (idx, tag) = h.decode()?;
        let slot = self.slots.get(idx as usize).ok_or(CSpaceError::BadHandle)?;
        if slot.tag != tag {
            return Err(CSpaceError::BadHandle);
        }
        slot.entry.ok_or(CSpaceError::BadHandle)
    }

    /// Close (destroy) a handle, freeing its slot.
    ///
    /// This increments the slot tag (ABA protection) and enqueues the index into a quarantine FIFO.
    pub fn close(&mut self, h: Handle) -> Result<(), CSpaceError> {
        let (idx, tag) = h.decode()?;
        let slot = self
            .slots
            .get_mut(idx as usize)
            .ok_or(CSpaceError::BadHandle)?;

        if slot.tag != tag || slot.entry.is_none() {
            return Err(CSpaceError::BadHandle);
        }

        slot.entry = None;
        slot.tag = bump_tag(slot.tag);

        self.quarantine_fifo.push_back(idx);
        self.flush_quarantine();
        Ok(())
    }

    /// Move old quarantined slots into the free list, preserving a tail quarantine window.
    fn flush_quarantine(&mut self) {
        while self.quarantine_fifo.len() > self.quarantine_len {
            if let Some(i) = self.quarantine_fifo.pop_front() {
                self.free_fifo.push_back(i);
            }
        }
    }

    /// Debug-only: how many indices are in the free FIFO.
    pub fn debug_free_len(&self) -> usize {
        self.free_fifo.len()
    }

    /// Debug-only: how many indices are in the quarantine FIFO.
    pub fn debug_quarantine_len(&self) -> usize {
        self.quarantine_fifo.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::HANDLE_FIXED_BITS_MASK;
    use crate::handle::HANDLE_FIXED_BITS_VALUE;
    use crate::revocation::RevocationManager;
    use proptest::prelude::*;

    #[test]
    fn alloc_lookup_close() {
        let mut cs = CSpace::new(8, 2);
        let cap = Capability::new(1, 0xAA55, 7);

        let h = cs.alloc(cap).unwrap();
        assert_eq!(h.raw() & HANDLE_FIXED_BITS_MASK, HANDLE_FIXED_BITS_VALUE);

        let got = cs.get(h).unwrap();
        assert_eq!(got, cap);

        cs.close(h).unwrap();
        assert_eq!(cs.get(h).unwrap_err(), CSpaceError::BadHandle);
    }

    #[test]
    fn aba_protection_on_reuse() {
        // max_slots=1 forces reuse of the same slot.
        let mut cs = CSpace::new(1, 0);
        let cap1 = Capability::new(1, 1, 1);
        let cap2 = Capability::new(2, 2, 2);

        let h1 = cs.alloc(cap1).unwrap();
        cs.close(h1).unwrap();

        let h2 = cs.alloc(cap2).unwrap();
        assert_ne!(h1.raw(), h2.raw(), "tag must change on reuse");
        assert_eq!(cs.get(h1).unwrap_err(), CSpaceError::BadHandle);
        assert_eq!(cs.get(h2).unwrap(), cap2);
    }

    #[test]
    fn quarantine_delays_hot_reuse_but_does_not_reduce_capacity() {
        // max_slots=2, quarantine_len=1 means: the most recently freed slot is quarantined.
        let mut cs = CSpace::new(2, 1);

        let h1 = cs.alloc(Capability::new(1, 0, 0)).unwrap();
        let h2 = cs.alloc(Capability::new(2, 0, 0)).unwrap();

        // Close both; now both are free, but one remains quarantined.
        cs.close(h1).unwrap();
        cs.close(h2).unwrap();

        assert_eq!(cs.debug_quarantine_len(), 1);
        // One should have been flushed to free list.
        assert_eq!(cs.debug_free_len(), 1);

        // We can still allocate 2 handles (capacity not reduced).
        let a = cs.alloc(Capability::new(3, 0, 0)).unwrap();
        let b = cs.alloc(Capability::new(4, 0, 0)).unwrap();
        let _ = (a, b);
    }

    #[test]
    fn duplicate_inherits_revocation() {
        let mut mgr = RevocationManager::new();
        let grp = mgr.create_group();
        let mut cs = CSpace::new(4, 0);

        let cap = Capability::new(9, 0x1, 0);
        let h1 = cs.alloc_revocable(cap, &mgr, grp).unwrap();
        let h2 = cs.duplicate(h1).unwrap();

        assert_eq!(cs.get_checked(h1, &mgr).unwrap(), cap);
        assert_eq!(cs.get_checked(h2, &mgr).unwrap(), cap);

        // revoke: both become bad
        mgr.revoke(grp).unwrap();
        assert_eq!(
            cs.get_checked(h1, &mgr).unwrap_err(),
            CSpaceError::BadHandle
        );
        assert_eq!(
            cs.get_checked(h2, &mgr).unwrap_err(),
            CSpaceError::BadHandle
        );
    }

    #[test]
    fn duplicate_derived_reduces_rights_and_keeps_revocation() {
        let mut mgr = RevocationManager::new();
        let grp = mgr.create_group();
        let mut cs = CSpace::new(4, 0);

        let cap = Capability::new(42, 0b1111, 9);
        let h1 = cs.alloc_revocable(cap, &mgr, grp).unwrap();
        let h2 = cs.duplicate_derived(h1, 0b0011).unwrap();

        assert_eq!(cs.get_checked(h1, &mgr).unwrap(), cap);
        assert_eq!(
            cs.get_checked(h2, &mgr).unwrap(),
            Capability::new(42, 0b0011, 9)
        );

        mgr.revoke(grp).unwrap();
        assert_eq!(cs.get_checked(h1, &mgr), Err(CSpaceError::BadHandle));
        assert_eq!(cs.get_checked(h2, &mgr), Err(CSpaceError::BadHandle));
    }

    #[test]
    fn replace_derived_invalidates_old_handle() {
        let mut cs = CSpace::new(4, 0);
        let h1 = cs.alloc(Capability::new(7, 0b1111, 3)).unwrap();

        let h2 = cs.replace_derived(h1, 0b0011).unwrap();

        assert_eq!(cs.get(h1), Err(CSpaceError::BadHandle));
        assert_eq!(cs.get(h2), Ok(Capability::new(7, 0b0011, 3)));
    }

    proptest! {
        #[test]
        fn prop_closed_handles_never_resolve(
            ops in prop::collection::vec((0u8..5, any::<u16>(), any::<u64>(), any::<u32>()), 1..128)
        ) {
            let mut cs = CSpace::new(32, 4);
            let mut active: Vec<Handle> = Vec::new();
            let mut closed: Vec<Handle> = Vec::new();

            for (kind, selector, object_id, rights) in ops {
                match kind {
                    0 => {
                        if let Ok(h) = cs.alloc(Capability::new(object_id, rights, u32::from(selector))) {
                            active.push(h);
                        }
                    }
                    1 => {
                        if !active.is_empty() {
                            let idx = usize::from(selector) % active.len();
                            let h = active.swap_remove(idx);
                            prop_assert_eq!(cs.close(h), Ok(()));
                            closed.push(h);
                        }
                    }
                    2 => {
                        if !active.is_empty() {
                            let idx = usize::from(selector) % active.len();
                            if let Ok(h) = cs.duplicate(active[idx]) {
                                active.push(h);
                            }
                        }
                    }
                    3 => {
                        if !active.is_empty() {
                            let idx = usize::from(selector) % active.len();
                            if let Ok(h) = cs.duplicate_derived(active[idx], rights) {
                                active.push(h);
                            }
                        }
                    }
                    4 => {
                        if !active.is_empty() {
                            let idx = usize::from(selector) % active.len();
                            let h = active.swap_remove(idx);
                            match cs.replace_derived(h, rights) {
                                Ok(new_h) => {
                                    active.push(new_h);
                                    closed.push(h);
                                }
                                Err(CSpaceError::BadHandle) => closed.push(h),
                                Err(_) => {}
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                for &h in &closed {
                    prop_assert_eq!(cs.get(h), Err(CSpaceError::BadHandle));
                }
            }
        }
    }
}
