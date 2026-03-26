//! Revocation groups: O(1) “bulk invalidation” for derived/duplicated capabilities.
//!
//! This is a host-testable semantic core intended to be embedded in a kernel object table.
//!
//! Model:
//! - A **RevocationGroup** has an `epoch` counter.
//! - A capability/handle may carry a **RevocationRef** recording the group's epoch at issuance.
//! - `revoke(group)` increments epoch, invalidating all refs from earlier epochs.
//! - A `generation` field prevents stale tokens from revoking a recycled group id.

use alloc::vec::Vec;

/// A stable group identifier (index into the manager's group table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevocationGroupId(u32);

impl RevocationGroupId {
    /// Raw numeric id (for logging/debug).
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Unforgeable-ish token representing authority to revoke a group.
///
/// In the real kernel this would typically be represented by a handle to a “revoker” object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevocationGroupToken {
    id: RevocationGroupId,
    generation: u64,
}

impl RevocationGroupToken {
    /// Group id referenced by this token.
    pub const fn id(self) -> RevocationGroupId {
        self.id
    }

    /// Token generation used to reject stale handles after recycle.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// A revocation reference carried by a capability/handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevocationRef {
    id: RevocationGroupId,
    generation: u64,
    epoch: u64,
}

impl RevocationRef {
    /// Group id.
    pub const fn id(self) -> RevocationGroupId {
        self.id
    }

    /// Group generation captured at issuance.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Epoch snapshot at issuance.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// One small fixed-size set of revocation references carried by deferred control-plane state.
///
/// This is used for state whose effect is delayed after the originating handle operation:
/// queued kernel packets, async observers, blocked waits, or armed timers.  Revocation can then
/// eagerly purge only the deferred state that still depends on a revoked handle epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RevocationSet {
    first: Option<RevocationRef>,
    second: Option<RevocationRef>,
}

impl RevocationSet {
    /// Empty provenance.
    pub const fn none() -> Self {
        Self {
            first: None,
            second: None,
        }
    }

    /// Provenance carrying one reference.
    pub const fn one(first: Option<RevocationRef>) -> Self {
        Self {
            first,
            second: None,
        }
    }

    /// Provenance carrying up to two references.
    pub fn pair(first: Option<RevocationRef>, second: Option<RevocationRef>) -> Self {
        if first.is_some() && first == second {
            return Self::one(first);
        }
        Self { first, second }
    }

    /// Returns `true` when this provenance is empty.
    pub const fn is_empty(self) -> bool {
        self.first.is_none() && self.second.is_none()
    }

    /// Return the contained references in stable order.
    pub const fn refs(self) -> [Option<RevocationRef>; 2] {
        [self.first, self.second]
    }

    /// Returns `true` when any carried reference belongs to a now-revoked epoch.
    pub fn contains_revoked(
        self,
        group: RevocationGroupId,
        generation: u64,
        current_epoch: u64,
    ) -> bool {
        self.refs().into_iter().flatten().any(|rev| {
            rev.id() == group && rev.generation() == generation && rev.epoch() < current_epoch
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct GroupSlot {
    generation: u64,
    epoch: u64,
    live: bool,
}

/// Errors returned by revocation operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationError {
    /// Token does not refer to a live group (wrong gen or retired).
    InvalidToken,
}

/// Manages revocation groups (allocate/revoke/retire).
///
/// In a kernel this would typically live in the global object table.
#[derive(Debug, Default)]
pub struct RevocationManager {
    groups: Vec<GroupSlot>,
    free: Vec<u32>,
}

impl RevocationManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new group and return its revocation token.
    pub fn create_group(&mut self) -> RevocationGroupToken {
        if let Some(id) = self.free.pop() {
            let slot = &mut self.groups[id as usize];
            debug_assert!(!slot.live);
            slot.live = true;
            slot.generation = slot.generation.saturating_add(1);
            slot.epoch = 0;
            RevocationGroupToken {
                id: RevocationGroupId(id),
                generation: slot.generation,
            }
        } else {
            let id = self.groups.len() as u32;
            self.groups.push(GroupSlot {
                generation: 1,
                epoch: 0,
                live: true,
            });
            RevocationGroupToken {
                id: RevocationGroupId(id),
                generation: 1,
            }
        }
    }

    /// Retire a group id, making its current token invalid.
    ///
    /// This is optional in Axle's model, but useful for tests and for eventual resource cleanup.
    pub fn retire_group(&mut self, token: RevocationGroupToken) -> Result<(), RevocationError> {
        let Some(slot) = self.groups.get_mut(token.id.0 as usize) else {
            return Err(RevocationError::InvalidToken);
        };
        if !slot.live || slot.generation != token.generation {
            return Err(RevocationError::InvalidToken);
        }
        slot.live = false;
        self.free.push(token.id.0);
        Ok(())
    }

    /// Revoke all capabilities associated with the group (epoch++).
    pub fn revoke(&mut self, token: RevocationGroupToken) -> Result<(), RevocationError> {
        let Some(slot) = self.groups.get_mut(token.id.0 as usize) else {
            return Err(RevocationError::InvalidToken);
        };
        if !slot.live || slot.generation != token.generation {
            return Err(RevocationError::InvalidToken);
        }
        slot.epoch = slot.epoch.saturating_add(1);
        Ok(())
    }

    /// Create a `RevocationRef` capturing the current epoch for this group token.
    pub fn snapshot(&self, token: RevocationGroupToken) -> Result<RevocationRef, RevocationError> {
        let Some(slot) = self.groups.get(token.id.0 as usize) else {
            return Err(RevocationError::InvalidToken);
        };
        if !slot.live || slot.generation != token.generation {
            return Err(RevocationError::InvalidToken);
        }
        Ok(RevocationRef {
            id: token.id,
            generation: token.generation,
            epoch: slot.epoch,
        })
    }

    /// Return whether the given reference is still valid (epoch matches current).
    pub fn is_live(&self, r: RevocationRef) -> bool {
        let Some(slot) = self.groups.get(r.id.0 as usize) else {
            return false;
        };
        slot.live && slot.generation == r.generation && slot.epoch == r.epoch
    }

    /// Current epoch value of a group (for diagnostics).
    pub fn epoch_of(&self, id: RevocationGroupId) -> Option<u64> {
        self.groups.get(id.0 as usize).map(|s| s.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn revoke_invalidates_old_refs() {
        let mut mgr = RevocationManager::new();
        let tok = mgr.create_group();
        let r1 = mgr.snapshot(tok).unwrap();
        assert!(mgr.is_live(r1));

        mgr.revoke(tok).unwrap();
        assert!(!mgr.is_live(r1));

        let r2 = mgr.snapshot(tok).unwrap();
        assert!(mgr.is_live(r2));
    }

    #[test]
    fn retire_makes_token_invalid_and_prevents_stale_use() {
        let mut mgr = RevocationManager::new();
        let tok1 = mgr.create_group();
        let id = tok1.id();
        mgr.retire_group(tok1).unwrap();

        // old token can no longer snapshot/revoke
        assert_eq!(mgr.revoke(tok1).unwrap_err(), RevocationError::InvalidToken);

        // id can be reused but gen changes, preventing stale token from acting.
        let tok2 = mgr.create_group();
        assert_eq!(tok2.id(), id);
        assert_ne!(tok2.generation, tok1.generation);
        mgr.revoke(tok2).unwrap();
    }

    proptest! {
        #[test]
        fn prop_only_latest_epoch_remains_live(revoke_count in 0u8..32) {
            let mut mgr = RevocationManager::new();
            let tok = mgr.create_group();
            let mut refs = vec![mgr.snapshot(tok).unwrap()];

            for _ in 0..revoke_count {
                let previous = mgr.snapshot(tok).unwrap();
                mgr.revoke(tok).unwrap();
                prop_assert!(!mgr.is_live(previous));
                refs.push(mgr.snapshot(tok).unwrap());
            }

            let latest = *refs.last().unwrap();
            for r in refs.iter().copied().take(refs.len().saturating_sub(1)) {
                prop_assert!(!mgr.is_live(r));
            }
            prop_assert!(mgr.is_live(latest));
        }
    }
}
