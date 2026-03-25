//! Physical-frame bookkeeping: descriptors, reference counting, and reverse-map nodes.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{PAGE_SIZE, ReverseMapAnchor, is_page_aligned};

/// Identifier for a registered physical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameId(u64);

impl FrameId {
    /// Construct one frame id from a raw page-aligned physical address.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw & (PAGE_SIZE - 1) != 0 {
            return None;
        }
        Some(Self(raw))
    }

    /// Raw page-aligned physical address.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Identifier for one VM metadata address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddressSpaceId(u64);

impl AddressSpaceId {
    /// Build an address-space identifier from one raw kernel-global id.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RmapNodeId(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RmapNodeRecord {
    frame_id: FrameId,
    anchor: ReverseMapAnchor,
    prev: Option<RmapNodeId>,
    next: Option<RmapNodeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RmapNodeSlot {
    Free { next_free: Option<RmapNodeId> },
    Occupied(RmapNodeRecord),
}

#[derive(Debug, Default)]
struct RmapNodeArena {
    slots: Vec<RmapNodeSlot>,
    free_head: Option<RmapNodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameDescRecord {
    id: FrameId,
    ref_count: u32,
    map_count: u32,
    pin_count: u32,
    loan_count: u32,
    rmap_head: Option<RmapNodeId>,
    rmap_anchor_count: u32,
}

/// Snapshot of one frame descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameDesc {
    id: FrameId,
    ref_count: u32,
    map_count: u32,
    pin_count: u32,
    loan_count: u32,
    rmap_anchor: Option<ReverseMapAnchor>,
    rmap_anchor_count: u32,
}

impl FrameDesc {
    /// Frame identifier.
    pub const fn id(self) -> FrameId {
        self.id
    }

    /// Total number of active references tracked for this frame.
    pub const fn ref_count(self) -> u32 {
        self.ref_count
    }

    /// Number of active mappings referencing this frame.
    pub const fn map_count(self) -> u32 {
        self.map_count
    }

    /// Number of active pins on this frame.
    pub const fn pin_count(self) -> u32 {
        self.pin_count
    }

    /// Number of active in-flight loans on this frame.
    pub const fn loan_count(self) -> u32 {
        self.loan_count
    }

    /// Reverse-mapping anchor reserved for future frame-to-mapping lookup.
    pub const fn rmap_anchor(self) -> Option<ReverseMapAnchor> {
        self.rmap_anchor
    }

    /// Total number of currently tracked reverse-mapping anchors for this frame.
    pub const fn rmap_anchor_count(self) -> u32 {
        self.rmap_anchor_count
    }
}

/// Owned reference to one frame-table refcount increment.
#[derive(Debug)]
#[must_use = "frame references must be explicitly released"]
pub struct FrameRef {
    frame_id: Option<FrameId>,
}

impl FrameRef {
    /// Borrow the owned frame identifier.
    pub const fn frame_id(&self) -> Option<FrameId> {
        self.frame_id
    }

    /// Release this reference back into the frame table.
    pub fn release(mut self, frames: &mut FrameTable) -> Result<(), FrameTableError> {
        if let Some(frame_id) = self.frame_id.take() {
            frames.dec_ref(frame_id)?;
        }
        Ok(())
    }
}

impl Drop for FrameRef {
    fn drop(&mut self) {
        assert!(
            self.frame_id.is_none(),
            "FrameRef dropped without explicit release"
        );
    }
}

/// Owned pin over one or more registered frames.
#[derive(Debug)]
#[must_use = "pin tokens must be explicitly released or converted into a loan"]
pub struct PinToken {
    frame_ids: Option<Vec<FrameId>>,
}

impl PinToken {
    /// Borrow the pinned frames.
    pub fn frame_ids(&self) -> &[FrameId] {
        self.frame_ids.as_deref().unwrap_or(&[])
    }

    /// Convert this pin into one in-flight loan over the same frames.
    pub fn into_loan(mut self, frames: &mut FrameTable) -> Result<LoanToken, FrameTableError> {
        let frame_ids = self.frame_ids.take().unwrap_or_default();
        if let Err(err) = frames.inc_loan_many(&frame_ids) {
            frames.release_pins(&frame_ids);
            return Err(err);
        }
        Ok(LoanToken {
            frame_ids: Some(frame_ids),
        })
    }

    /// Release this pin without creating a loan.
    pub fn release(mut self, frames: &mut FrameTable) {
        if let Some(frame_ids) = self.frame_ids.take() {
            frames.release_pins(&frame_ids);
        }
    }
}

impl Drop for PinToken {
    fn drop(&mut self) {
        assert!(
            self.frame_ids.is_none(),
            "PinToken dropped without explicit release"
        );
    }
}

/// Owned in-flight loan over one or more registered frames.
#[derive(Debug)]
#[must_use = "loan tokens must be explicitly released"]
pub struct LoanToken {
    frame_ids: Option<Vec<FrameId>>,
}

impl LoanToken {
    /// Borrow the loaned frames.
    pub fn frame_ids(&self) -> &[FrameId] {
        self.frame_ids.as_deref().unwrap_or(&[])
    }

    /// Release the loan and its underlying pins.
    pub fn release(mut self, frames: &mut FrameTable) {
        if let Some(frame_ids) = self.frame_ids.take() {
            frames.release_loans(&frame_ids);
        }
    }
}

impl Drop for LoanToken {
    fn drop(&mut self) {
        assert!(
            self.frame_ids.is_none(),
            "LoanToken dropped without explicit release"
        );
    }
}

/// Errors returned by frame-table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameTableError {
    /// Invalid alignment or overflowed arithmetic.
    InvalidArgs,
    /// Frame is already registered.
    AlreadyExists,
    /// Frame is not registered.
    NotFound,
    /// Refcount or pin count overflowed.
    CountOverflow,
    /// Refcount was decremented below zero.
    RefUnderflow,
    /// Pin count was decremented below zero.
    PinUnderflow,
    /// Loan count was decremented below zero.
    LoanUnderflow,
    /// One mapping anchor to remove was not present on the frame.
    MissingAnchor,
    /// Frame still has active refs, mappings, pins, loans, or reverse-map anchors.
    Busy,
}

/// Global physical-frame bookkeeping used by the bootstrap kernel.
#[derive(Debug, Default)]
pub struct FrameTable {
    frames: BTreeMap<FrameId, FrameDescRecord>,
    rmap_nodes: RmapNodeArena,
}

impl RmapNodeArena {
    fn alloc(&mut self, node: RmapNodeRecord) -> RmapNodeId {
        if let Some(id) = self.free_head {
            let slot = self
                .slots
                .get_mut(id.0)
                .expect("free-list node id must reference one arena slot");
            let next_free = match *slot {
                RmapNodeSlot::Free { next_free } => next_free,
                RmapNodeSlot::Occupied(_) => unreachable!("free-list node must not be occupied"),
            };
            *slot = RmapNodeSlot::Occupied(node);
            self.free_head = next_free;
            return id;
        }

        let id = RmapNodeId(self.slots.len());
        self.slots.push(RmapNodeSlot::Occupied(node));
        id
    }

    fn get(&self, id: RmapNodeId) -> Option<&RmapNodeRecord> {
        match self.slots.get(id.0)? {
            RmapNodeSlot::Occupied(node) => Some(node),
            RmapNodeSlot::Free { .. } => None,
        }
    }

    fn get_mut(&mut self, id: RmapNodeId) -> Option<&mut RmapNodeRecord> {
        match self.slots.get_mut(id.0)? {
            RmapNodeSlot::Occupied(node) => Some(node),
            RmapNodeSlot::Free { .. } => None,
        }
    }

    fn free(&mut self, id: RmapNodeId) -> Option<RmapNodeRecord> {
        let slot = self.slots.get_mut(id.0)?;
        let node = match *slot {
            RmapNodeSlot::Occupied(node) => node,
            RmapNodeSlot::Free { .. } => return None,
        };
        *slot = RmapNodeSlot::Free {
            next_free: self.free_head,
        };
        self.free_head = Some(id);
        Some(node)
    }
}

impl FrameTable {
    /// Create an empty frame table.
    pub fn new() -> Self {
        Self {
            frames: BTreeMap::new(),
            rmap_nodes: RmapNodeArena::default(),
        }
    }

    /// Register an existing physical frame by page-aligned address.
    pub fn register_existing(&mut self, paddr: u64) -> Result<FrameId, FrameTableError> {
        if !is_page_aligned(paddr) {
            return Err(FrameTableError::InvalidArgs);
        }
        let id = FrameId(paddr);
        if self.frames.contains_key(&id) {
            return Err(FrameTableError::AlreadyExists);
        }
        self.frames.insert(
            id,
            FrameDescRecord {
                id,
                ref_count: 0,
                map_count: 0,
                pin_count: 0,
                loan_count: 0,
                rmap_head: None,
                rmap_anchor_count: 0,
            },
        );
        Ok(id)
    }

    /// Remove a previously registered frame that no longer has active users.
    pub fn unregister_existing(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frames.get(&id).ok_or(FrameTableError::NotFound)?;
        if frame.ref_count != 0
            || frame.map_count != 0
            || frame.pin_count != 0
            || frame.loan_count != 0
            || frame.rmap_head.is_some()
            || frame.rmap_anchor_count != 0
        {
            return Err(FrameTableError::Busy);
        }
        let _ = self.frames.remove(&id);
        Ok(())
    }

    /// Return whether the frame id is known.
    pub fn contains(&self, id: FrameId) -> bool {
        self.frames.contains_key(&id)
    }

    /// Snapshot the current descriptor state of one registered frame.
    pub fn state(&self, id: FrameId) -> Option<FrameDesc> {
        self.frames.get(&id).map(|frame| FrameDesc {
            id: frame.id,
            ref_count: frame.ref_count,
            map_count: frame.map_count,
            pin_count: frame.pin_count,
            loan_count: frame.loan_count,
            rmap_anchor: frame
                .rmap_head
                .and_then(|head| self.rmap_nodes.get(head).map(|node| node.anchor)),
            rmap_anchor_count: frame.rmap_anchor_count,
        })
    }

    /// Return the full reverse-mapping anchor set for one frame.
    pub fn rmap_anchors(&self, id: FrameId) -> Option<Vec<ReverseMapAnchor>> {
        let frame = self.frames.get(&id)?;
        let mut anchors = Vec::with_capacity(frame.rmap_anchor_count as usize);
        let mut cursor = frame.rmap_head;
        while let Some(node_id) = cursor {
            let node = self.rmap_nodes.get(node_id)?;
            anchors.push(node.anchor);
            cursor = node.next;
        }
        Some(anchors)
    }

    /// Increment the mapping count and total refcount for a registered frame.
    pub fn inc_map(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        let map_count = frame
            .map_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        let ref_count = frame
            .ref_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        frame.map_count = map_count;
        frame.ref_count = ref_count;
        Ok(())
    }

    /// Register one mapping anchor for a frame and bump its map/ref counts.
    pub(crate) fn map_frame(
        &mut self,
        id: FrameId,
        anchor: ReverseMapAnchor,
    ) -> Result<RmapNodeId, FrameTableError> {
        let frame = self.frames.get(&id).ok_or(FrameTableError::NotFound)?;
        let head = frame.rmap_head;
        let map_count = frame
            .map_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        let ref_count = frame
            .ref_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        let rmap_anchor_count = frame
            .rmap_anchor_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        let node_id = self.rmap_nodes.alloc(RmapNodeRecord {
            frame_id: id,
            anchor,
            prev: None,
            next: head,
        });
        if let Some(head_id) = head {
            let node = self
                .rmap_nodes
                .get_mut(head_id)
                .ok_or(FrameTableError::MissingAnchor)?;
            node.prev = Some(node_id);
        }
        let frame = self.frames.get_mut(&id).ok_or(FrameTableError::NotFound)?;
        frame.map_count = map_count;
        frame.ref_count = ref_count;
        frame.rmap_anchor_count = rmap_anchor_count;
        frame.rmap_head = Some(node_id);
        Ok(node_id)
    }

    /// Decrement the mapping count and total refcount for a registered frame.
    pub fn dec_map(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        if frame.map_count == 0 || frame.ref_count == 0 {
            return Err(FrameTableError::RefUnderflow);
        }
        frame.map_count -= 1;
        frame.ref_count -= 1;
        Ok(())
    }

    /// Remove one mapping anchor from a frame.
    pub(crate) fn unmap_frame(
        &mut self,
        id: FrameId,
        node_id: RmapNodeId,
    ) -> Result<(), FrameTableError> {
        let frame = self.frames.get(&id).ok_or(FrameTableError::NotFound)?;
        let Some(node) = self.rmap_nodes.get(node_id).copied() else {
            return Err(FrameTableError::MissingAnchor);
        };
        if node.frame_id != id {
            return Err(FrameTableError::MissingAnchor);
        }
        if frame.map_count == 0 || frame.ref_count == 0 || frame.rmap_anchor_count == 0 {
            return Err(FrameTableError::RefUnderflow);
        }
        if let Some(prev_id) = node.prev {
            let prev = self
                .rmap_nodes
                .get_mut(prev_id)
                .ok_or(FrameTableError::MissingAnchor)?;
            prev.next = node.next;
        } else {
            self.frames
                .get_mut(&id)
                .ok_or(FrameTableError::NotFound)?
                .rmap_head = node.next;
        }
        if let Some(next_id) = node.next {
            let next = self
                .rmap_nodes
                .get_mut(next_id)
                .ok_or(FrameTableError::MissingAnchor)?;
            next.prev = node.prev;
        }
        let _removed = self
            .rmap_nodes
            .free(node_id)
            .ok_or(FrameTableError::MissingAnchor)?;
        let frame = self.frames.get_mut(&id).ok_or(FrameTableError::NotFound)?;
        frame.map_count -= 1;
        frame.ref_count -= 1;
        frame.rmap_anchor_count -= 1;
        Ok(())
    }

    /// Acquire one owned frame reference.
    pub fn acquire_frame_ref(&mut self, id: FrameId) -> Result<FrameRef, FrameTableError> {
        self.inc_ref(id)?;
        Ok(FrameRef { frame_id: Some(id) })
    }

    /// Acquire one owned pin over a single frame.
    pub fn pin_frame(&mut self, id: FrameId) -> Result<PinToken, FrameTableError> {
        self.pin_many(&[id])
    }

    /// Acquire one owned pin over multiple frames, rolling back on failure.
    pub fn pin_many(&mut self, ids: &[FrameId]) -> Result<PinToken, FrameTableError> {
        for (applied, &id) in ids.iter().enumerate() {
            if let Err(err) = self.pin(id) {
                self.release_pins(&ids[..applied]);
                return Err(err);
            }
        }
        Ok(PinToken {
            frame_ids: Some(ids.to_vec()),
        })
    }

    /// Increment the total refcount for a registered frame.
    fn inc_ref(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        frame.ref_count = frame
            .ref_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        Ok(())
    }

    /// Decrement the total refcount for a registered frame.
    fn dec_ref(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        if frame.ref_count == 0 {
            return Err(FrameTableError::RefUnderflow);
        }
        frame.ref_count -= 1;
        Ok(())
    }

    /// Pin a registered frame.
    pub(crate) fn pin(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        frame.pin_count = frame
            .pin_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        Ok(())
    }

    /// Unpin a previously pinned frame.
    pub(crate) fn unpin(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        if frame.pin_count == 0 {
            return Err(FrameTableError::PinUnderflow);
        }
        frame.pin_count -= 1;
        Ok(())
    }

    /// Increment the in-flight loan count for a registered frame.
    fn inc_loan(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        frame.loan_count = frame
            .loan_count
            .checked_add(1)
            .ok_or(FrameTableError::CountOverflow)?;
        Ok(())
    }

    /// Decrement the in-flight loan count for a registered frame.
    fn dec_loan(&mut self, id: FrameId) -> Result<(), FrameTableError> {
        let frame = self.frame_mut(id)?;
        if frame.loan_count == 0 {
            return Err(FrameTableError::LoanUnderflow);
        }
        frame.loan_count -= 1;
        Ok(())
    }

    fn inc_loan_many(&mut self, ids: &[FrameId]) -> Result<(), FrameTableError> {
        for (applied, &id) in ids.iter().enumerate() {
            if let Err(err) = self.inc_loan(id) {
                self.release_loans_only(&ids[..applied]);
                return Err(err);
            }
        }
        Ok(())
    }

    fn release_pins(&mut self, ids: &[FrameId]) {
        for &id in ids {
            let _ = self.unpin(id);
        }
    }

    fn release_loans_only(&mut self, ids: &[FrameId]) {
        for &id in ids {
            let _ = self.dec_loan(id);
        }
    }

    /// Drop in-flight loan pins for multiple frames.
    fn release_loans(&mut self, ids: &[FrameId]) {
        for &id in ids {
            let _ = self.dec_loan(id);
            let _ = self.unpin(id);
        }
    }

    fn frame_mut(&mut self, id: FrameId) -> Result<&mut FrameDescRecord, FrameTableError> {
        self.frames.get_mut(&id).ok_or(FrameTableError::NotFound)
    }
}
