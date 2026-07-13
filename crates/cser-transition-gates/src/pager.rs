// SPDX-License-Identifier: MPL-2.0

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultKey {
    pub address_space_id: u64,
    pub address_space_generation: u64,
    pub page_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultTicket {
    slot_generation: u64,
    continuation_id: u64,
    authority_epoch: u64,
    binding_epoch: u64,
}

impl FaultTicket {
    pub const fn slot_generation(self) -> u64 {
        self.slot_generation
    }

    pub const fn continuation_id(self) -> u64 {
        self.continuation_id
    }

    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterFault {
    Leader(FaultTicket),
    Follower(FaultTicket),
}

impl RegisterFault {
    pub const fn ticket(self) -> FaultTicket {
        match self {
            Self::Leader(ticket) | Self::Follower(ticket) => ticket,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPhase {
    Registered,
    Prepared,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationOutcome {
    Resolved,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerLifecycle {
    Bound,
    Fallback,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerError {
    InvalidConfiguration,
    InvalidIdentity,
    SlotFull,
    DifferentFaultInFlight,
    DuplicateContinuation,
    UnknownContinuation,
    NotLeader,
    InvalidPhase,
    StaleAuthority,
    StaleBinding,
    NoSupervisor,
    AlreadyTerminal,
    SnapshotRequired,
    SnapshotMismatch,
    ReplacementNotReady,
    NotAdoptable,
    MappingMismatch,
    ExternalQuiescenceRequired,
    NotQuiescent,
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingReceipt {
    key: FaultKey,
    slot_generation: u64,
    publication_sequence: u64,
}

impl MappingReceipt {
    pub const fn key(self) -> FaultKey {
        self.key
    }

    pub const fn slot_generation(self) -> u64 {
        self.slot_generation
    }

    pub const fn publication_sequence(self) -> u64 {
        self.publication_sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerCrashReceipt {
    pub previous_binding_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerSnapshot {
    replacement: u64,
    binding_epoch: u64,
    domain_revision: u64,
    slot_generation: u64,
}

impl PagerSnapshot {
    pub const fn replacement(self) -> u64 {
        self.replacement
    }

    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    pub const fn domain_revision(self) -> u64 {
        self.domain_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerRebindReceipt {
    pub replacement: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerRevokeReceipt {
    pub closed_authority_epoch: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationReceipt {
    pub continuation_id: u64,
    pub outcome: ContinuationOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerProjection {
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub lifecycle: PagerLifecycle,
    pub supervisor: Option<u64>,
    pub fault_key: Option<FaultKey>,
    pub fault_phase: Option<FaultPhase>,
    pub waiter_count: usize,
    pub terminalizations: usize,
    pub mapping_publications: u64,
    pub snapshot_taken: bool,
    pub replacement_ready: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CommitMappingError<E> {
    Gate(PagerError),
    Publication(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageSlot<const WAITERS: usize> {
    key: FaultKey,
    generation: u64,
    leader: u64,
    phase: FaultPhase,
    tickets: [Option<FaultTicket>; WAITERS],
    outcomes: [Option<ContinuationOutcome>; WAITERS],
    mapping: Option<MappingReceipt>,
}

impl<const WAITERS: usize> PageSlot<WAITERS> {
    fn ticket_index(&self, ticket: FaultTicket) -> Result<usize, PagerError> {
        self.tickets
            .iter()
            .position(|candidate| *candidate == Some(ticket))
            .ok_or(PagerError::UnknownContinuation)
    }

    fn continuation_index(&self, continuation_id: u64) -> Option<usize> {
        self.tickets.iter().position(|candidate| {
            candidate.is_some_and(|ticket| ticket.continuation_id == continuation_id)
        })
    }

    fn waiter_count(&self) -> usize {
        self.tickets.iter().flatten().count()
    }

    fn terminalizations(&self) -> usize {
        self.outcomes.iter().flatten().count()
    }
}

/// Same-page publication, pager crash/rebind, and one-shot continuation gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerGate<const WAITERS: usize> {
    authority_epoch: u64,
    binding_epoch: u64,
    lifecycle: PagerLifecycle,
    supervisor: Option<u64>,
    slot: Option<PageSlot<WAITERS>>,
    next_slot_generation: u64,
    next_publication_sequence: u64,
    snapshot: Option<PagerSnapshot>,
    replacement_ready: bool,
}

impl<const WAITERS: usize> PagerGate<WAITERS> {
    pub fn new(
        authority_epoch: u64,
        binding_epoch: u64,
        supervisor: u64,
    ) -> Result<Self, PagerError> {
        if WAITERS == 0 || authority_epoch == 0 || binding_epoch == 0 || supervisor == 0 {
            return Err(PagerError::InvalidConfiguration);
        }
        Ok(Self {
            authority_epoch,
            binding_epoch,
            lifecycle: PagerLifecycle::Bound,
            supervisor: Some(supervisor),
            slot: None,
            next_slot_generation: 1,
            next_publication_sequence: 1,
            snapshot: None,
            replacement_ready: false,
        })
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn binding_epoch(&self) -> u64 {
        self.binding_epoch
    }

    pub const fn supervisor(&self) -> Option<u64> {
        self.supervisor
    }

    pub fn projection(&self) -> PagerProjection {
        PagerProjection {
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            lifecycle: self.lifecycle,
            supervisor: self.supervisor,
            fault_key: self.slot.map(|slot| slot.key),
            fault_phase: self.slot.map(|slot| slot.phase),
            waiter_count: self.slot.map_or(0, |slot| slot.waiter_count()),
            terminalizations: self.slot.map_or(0, |slot| slot.terminalizations()),
            mapping_publications: u64::from(self.slot.is_some_and(|slot| slot.mapping.is_some())),
            snapshot_taken: self.snapshot.is_some(),
            replacement_ready: self.replacement_ready,
        }
    }

    pub fn register(
        &mut self,
        key: FaultKey,
        continuation_id: u64,
    ) -> Result<RegisterFault, PagerError> {
        self.require_bound()?;
        if key.address_space_id == 0 || key.address_space_generation == 0 || continuation_id == 0 {
            return Err(PagerError::InvalidIdentity);
        }

        if let Some(slot) = self.slot.as_mut() {
            if slot.key != key || slot.phase == FaultPhase::Published {
                return Err(PagerError::DifferentFaultInFlight);
            }
            if slot.continuation_index(continuation_id).is_some() {
                return Err(PagerError::DuplicateContinuation);
            }
            let index = slot
                .tickets
                .iter()
                .position(Option::is_none)
                .ok_or(PagerError::SlotFull)?;
            let ticket = FaultTicket {
                slot_generation: slot.generation,
                continuation_id,
                authority_epoch: self.authority_epoch,
                binding_epoch: self.binding_epoch,
            };
            slot.tickets[index] = Some(ticket);
            return Ok(RegisterFault::Follower(ticket));
        }

        let generation = self.next_slot_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let ticket = FaultTicket {
            slot_generation: generation,
            continuation_id,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
        };
        let mut tickets = [None; WAITERS];
        tickets[0] = Some(ticket);
        self.slot = Some(PageSlot {
            key,
            generation,
            leader: continuation_id,
            phase: FaultPhase::Registered,
            tickets,
            outcomes: [None; WAITERS],
            mapping: None,
        });
        self.next_slot_generation = next_generation;
        Ok(RegisterFault::Leader(ticket))
    }

    pub fn prepare_leader(&mut self, leader: FaultTicket) -> Result<(), PagerError> {
        self.validate_current(leader)?;
        let slot = self.slot.as_mut().ok_or(PagerError::UnknownContinuation)?;
        if slot.leader != leader.continuation_id {
            return Err(PagerError::NotLeader);
        }
        if slot.phase != FaultPhase::Registered {
            return Err(PagerError::InvalidPhase);
        }
        slot.phase = FaultPhase::Prepared;
        Ok(())
    }

    pub fn crash(&mut self, presented_binding_epoch: u64) -> Result<PagerCrashReceipt, PagerError> {
        if self.lifecycle != PagerLifecycle::Bound || self.supervisor.is_none() {
            return Err(PagerError::NoSupervisor);
        }
        if presented_binding_epoch != self.binding_epoch {
            return Err(PagerError::StaleBinding);
        }
        let binding_epoch = self
            .binding_epoch
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let receipt = PagerCrashReceipt {
            previous_binding_epoch: self.binding_epoch,
            binding_epoch,
        };
        self.binding_epoch = binding_epoch;
        self.lifecycle = PagerLifecycle::Fallback;
        self.supervisor = None;
        self.snapshot = None;
        self.replacement_ready = false;
        Ok(receipt)
    }

    pub fn reply_gate(&self, authority_epoch: u64, binding_epoch: u64) -> Result<(), PagerError> {
        if authority_epoch != self.authority_epoch {
            return Err(PagerError::StaleAuthority);
        }
        if binding_epoch != self.binding_epoch {
            return Err(PagerError::StaleBinding);
        }
        self.require_bound()
    }

    pub fn snapshot(
        &mut self,
        replacement: u64,
        domain_revision: u64,
    ) -> Result<PagerSnapshot, PagerError> {
        if replacement == 0 {
            return Err(PagerError::InvalidIdentity);
        }
        if self.lifecycle != PagerLifecycle::Fallback || self.supervisor.is_some() {
            return Err(PagerError::NoSupervisor);
        }
        if self.snapshot.is_some() {
            return Err(PagerError::SnapshotMismatch);
        }
        let snapshot = PagerSnapshot {
            replacement,
            binding_epoch: self.binding_epoch,
            domain_revision,
            slot_generation: self.slot.map_or(0, |slot| slot.generation),
        };
        self.snapshot = Some(snapshot);
        Ok(snapshot)
    }

    pub fn ready(&mut self, snapshot: PagerSnapshot) -> Result<(), PagerError> {
        if self.snapshot != Some(snapshot)
            || snapshot.binding_epoch != self.binding_epoch
            || snapshot.slot_generation != self.slot.map_or(0, |slot| slot.generation)
        {
            return Err(PagerError::SnapshotMismatch);
        }
        self.replacement_ready = true;
        Ok(())
    }

    pub fn rebind(&mut self, replacement: u64) -> Result<PagerRebindReceipt, PagerError> {
        if self.lifecycle != PagerLifecycle::Fallback || self.supervisor.is_some() {
            return Err(PagerError::NoSupervisor);
        }
        let snapshot = self.snapshot.ok_or(PagerError::SnapshotRequired)?;
        if !self.replacement_ready {
            return Err(PagerError::ReplacementNotReady);
        }
        if replacement != snapshot.replacement {
            return Err(PagerError::SnapshotMismatch);
        }
        self.lifecycle = PagerLifecycle::Bound;
        self.supervisor = Some(replacement);
        Ok(PagerRebindReceipt {
            replacement,
            binding_epoch: self.binding_epoch,
        })
    }

    pub fn adopt(&mut self, old: FaultTicket) -> Result<FaultTicket, PagerError> {
        self.require_bound()?;
        if old.authority_epoch != self.authority_epoch || old.binding_epoch >= self.binding_epoch {
            return Err(PagerError::NotAdoptable);
        }
        let slot = self.slot.as_mut().ok_or(PagerError::UnknownContinuation)?;
        let index = slot.ticket_index(old)?;
        if slot.outcomes[index].is_some() || slot.phase == FaultPhase::Published {
            return Err(PagerError::NotAdoptable);
        }
        let adopted = FaultTicket {
            binding_epoch: self.binding_epoch,
            ..old
        };
        slot.tickets[index] = Some(adopted);
        Ok(adopted)
    }

    pub fn commit_mapping_with<T, E>(
        &mut self,
        leader: FaultTicket,
        publish: impl FnOnce() -> Result<T, E>,
    ) -> Result<(MappingReceipt, T), CommitMappingError<E>> {
        self.validate_current(leader)
            .map_err(CommitMappingError::Gate)?;
        let slot = self
            .slot
            .as_ref()
            .ok_or(CommitMappingError::Gate(PagerError::UnknownContinuation))?;
        if slot.leader != leader.continuation_id {
            return Err(CommitMappingError::Gate(PagerError::NotLeader));
        }
        if slot.phase != FaultPhase::Prepared || slot.mapping.is_some() {
            return Err(CommitMappingError::Gate(PagerError::InvalidPhase));
        }
        let sequence = self.next_publication_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(CommitMappingError::Gate(PagerError::CounterOverflow))?;
        let output = publish().map_err(CommitMappingError::Publication)?;
        let slot = self.slot.as_mut().unwrap();
        let receipt = MappingReceipt {
            key: slot.key,
            slot_generation: slot.generation,
            publication_sequence: sequence,
        };
        slot.phase = FaultPhase::Published;
        slot.mapping = Some(receipt);
        self.next_publication_sequence = next_sequence;
        Ok((receipt, output))
    }

    pub fn terminalize(
        &mut self,
        ticket: FaultTicket,
        mapping: Option<MappingReceipt>,
        outcome: ContinuationOutcome,
    ) -> Result<ContinuationReceipt, PagerError> {
        let slot = self.slot.as_ref().ok_or(PagerError::UnknownContinuation)?;
        let index = slot.ticket_index(ticket)?;
        if slot.outcomes[index].is_some() {
            return Err(PagerError::AlreadyTerminal);
        }
        match outcome {
            ContinuationOutcome::Resolved => {
                self.validate_current(ticket)?;
                if slot.phase != FaultPhase::Published || slot.mapping != mapping {
                    return Err(PagerError::MappingMismatch);
                }
            }
            ContinuationOutcome::Aborted => {
                if self.lifecycle != PagerLifecycle::Closing || mapping.is_some() {
                    return Err(PagerError::InvalidPhase);
                }
            }
        }
        self.slot.as_mut().unwrap().outcomes[index] = Some(outcome);
        Ok(ContinuationReceipt {
            continuation_id: ticket.continuation_id,
            outcome,
        })
    }

    /// Completes a continuation from an already-published kernel mapping.
    /// The service binding may have crashed, but the immutable mapping receipt
    /// remains valid and no old user-space reply authority is consulted.
    pub fn terminalize_published_kernel(
        &mut self,
        ticket: FaultTicket,
        mapping: MappingReceipt,
    ) -> Result<ContinuationReceipt, PagerError> {
        let slot = self.slot.as_ref().ok_or(PagerError::UnknownContinuation)?;
        let index = slot.ticket_index(ticket)?;
        if slot.outcomes[index].is_some() {
            return Err(PagerError::AlreadyTerminal);
        }
        if slot.phase != FaultPhase::Published || slot.mapping != Some(mapping) {
            return Err(PagerError::MappingMismatch);
        }
        self.slot.as_mut().unwrap().outcomes[index] = Some(ContinuationOutcome::Resolved);
        Ok(ContinuationReceipt {
            continuation_id: ticket.continuation_id,
            outcome: ContinuationOutcome::Resolved,
        })
    }

    /// Lets the kernel abort an unresolved orphan without first reopening or
    /// transferring its old binding authority. This is the atomic competitor
    /// to explicit adoption after a replacement has rebound.
    pub fn abort_orphan(&mut self, ticket: FaultTicket) -> Result<ContinuationReceipt, PagerError> {
        if !matches!(
            self.lifecycle,
            PagerLifecycle::Bound | PagerLifecycle::Fallback
        ) {
            return Err(PagerError::InvalidPhase);
        }
        let slot = self.slot.as_ref().ok_or(PagerError::UnknownContinuation)?;
        let index = slot.ticket_index(ticket)?;
        if slot.outcomes[index].is_some() {
            return Err(PagerError::AlreadyTerminal);
        }
        if slot.phase == FaultPhase::Published {
            return Err(PagerError::InvalidPhase);
        }
        self.slot.as_mut().unwrap().outcomes[index] = Some(ContinuationOutcome::Aborted);
        Ok(ContinuationReceipt {
            continuation_id: ticket.continuation_id,
            outcome: ContinuationOutcome::Aborted,
        })
    }

    pub fn begin_revoke(&mut self) -> Result<PagerRevokeReceipt, PagerError> {
        if !matches!(
            self.lifecycle,
            PagerLifecycle::Bound | PagerLifecycle::Fallback
        ) {
            return Err(PagerError::InvalidPhase);
        }
        let authority_epoch = self
            .authority_epoch
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let receipt = PagerRevokeReceipt {
            closed_authority_epoch: self.authority_epoch,
            authority_epoch,
            binding_epoch: self.binding_epoch,
        };
        self.authority_epoch = authority_epoch;
        self.lifecycle = PagerLifecycle::Closing;
        self.supervisor = None;
        Ok(receipt)
    }

    pub fn complete_revoke(&mut self, external_quiescent: bool) -> Result<(), PagerError> {
        if self.lifecycle != PagerLifecycle::Closing {
            return Err(PagerError::InvalidPhase);
        }
        if !external_quiescent {
            return Err(PagerError::ExternalQuiescenceRequired);
        }
        if self
            .slot
            .is_some_and(|slot| slot.terminalizations() != slot.waiter_count())
        {
            return Err(PagerError::NotQuiescent);
        }
        self.lifecycle = PagerLifecycle::Revoked;
        Ok(())
    }

    pub fn tickets(&self) -> [Option<FaultTicket>; WAITERS] {
        self.slot.map_or([None; WAITERS], |slot| slot.tickets)
    }

    fn require_bound(&self) -> Result<(), PagerError> {
        if self.lifecycle != PagerLifecycle::Bound || self.supervisor.is_none() {
            Err(PagerError::NoSupervisor)
        } else {
            Ok(())
        }
    }

    fn validate_current(&self, ticket: FaultTicket) -> Result<(), PagerError> {
        if ticket.authority_epoch != self.authority_epoch {
            return Err(PagerError::StaleAuthority);
        }
        if ticket.binding_epoch != self.binding_epoch {
            return Err(PagerError::StaleBinding);
        }
        self.require_bound()?;
        self.slot
            .as_ref()
            .ok_or(PagerError::UnknownContinuation)?
            .ticket_index(ticket)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FaultKey {
        FaultKey {
            address_space_id: 1,
            address_space_generation: 1,
            page_address: 0x4000,
        }
    }

    #[test]
    fn same_page_waiters_share_one_mapping_and_terminalize_once() {
        let mut gate = PagerGate::<2>::new(7, 1, 10).unwrap();
        let leader = gate.register(key(), 100).unwrap().ticket();
        let follower = gate.register(key(), 101).unwrap().ticket();
        gate.prepare_leader(leader).unwrap();
        let (mapping, ()) = gate
            .commit_mapping_with(leader, || Ok::<_, ()>(()))
            .unwrap();
        gate.terminalize(leader, Some(mapping), ContinuationOutcome::Resolved)
            .unwrap();
        gate.terminalize(follower, Some(mapping), ContinuationOutcome::Resolved)
            .unwrap();
        assert_eq!(gate.projection().mapping_publications, 1);
        assert_eq!(gate.projection().terminalizations, 2);
        let before = gate;
        assert_eq!(
            gate.terminalize(follower, Some(mapping), ContinuationOutcome::Resolved),
            Err(PagerError::AlreadyTerminal)
        );
        assert_eq!(gate, before);
    }

    #[test]
    fn old_reply_is_stale_across_crash_and_rebind() {
        let mut gate = PagerGate::<2>::new(7, 1, 10).unwrap();
        let old = gate.register(key(), 100).unwrap().ticket();
        gate.prepare_leader(old).unwrap();
        gate.crash(1).unwrap();
        assert_eq!(
            gate.commit_mapping_with(old, || Ok::<_, ()>(())),
            Err(CommitMappingError::Gate(PagerError::StaleBinding))
        );
        let snapshot = gate.snapshot(11, 3).unwrap();
        gate.ready(snapshot).unwrap();
        gate.rebind(11).unwrap();
        let adopted = gate.adopt(old).unwrap();
        assert_eq!(adopted.binding_epoch(), 2);
        assert_eq!(
            gate.commit_mapping_with(old, || Ok::<_, ()>(())),
            Err(CommitMappingError::Gate(PagerError::StaleBinding))
        );
    }
}
