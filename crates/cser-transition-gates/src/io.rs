// SPDX-License-Identifier: MPL-2.0

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBinding {
    epoch: u64,
}

impl IoBinding {
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoIdentity {
    pub request_id: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub device_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoPhase {
    Active,
    ServiceUnavailable,
    Closing,
    Quiesced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoTerminal {
    Completed,
    IndeterminateAfterReset,
    AbortedBeforeCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoError {
    InvalidConfiguration,
    LedgerFull,
    UnknownEffect,
    StaleAuthority,
    StaleBinding,
    StaleDeviceGeneration,
    ServiceUnavailable,
    Closing,
    AlreadyCommitted,
    NotCommitted,
    AlreadyTerminal,
    InvalidReceipt,
    InvalidPhase,
    InvalidOwner,
    DuplicateOwner,
    ResetRequired,
    IotlbRequired,
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoCommitReceipt {
    identity: IoIdentity,
    sequence: u64,
}

impl IoCommitReceipt {
    pub const fn identity(self) -> IoIdentity {
        self.identity
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoTerminalReceipt {
    pub identity: IoIdentity,
    pub terminal: IoTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoCrashReceipt {
    pub previous_binding_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseReceipt {
    authority_epoch: u64,
    device_generation: u64,
    aborted: usize,
}

impl CloseReceipt {
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }

    pub const fn aborted(self) -> usize {
        self.aborted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetOutcome {
    closed_generation: u64,
    device_generation: u64,
    terminalized: usize,
    nonce: u64,
}

impl ResetOutcome {
    pub const fn closed_generation(self) -> u64 {
        self.closed_generation
    }

    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }

    pub const fn terminalized(self) -> usize {
        self.terminalized
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IoCommitError<E> {
    Gate(IoError),
    Publication(E),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResetAttempt {
    generation: u64,
    nonce: u64,
}

impl ResetAttempt {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn retain(self) -> ResetTombstone {
        ResetTombstone {
            generation: self.generation,
            nonce: self.nonce,
        }
    }

    pub fn acknowledge(self) -> ResetReceipt {
        ResetReceipt {
            generation: self.generation,
            nonce: self.nonce,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResetTombstone {
    generation: u64,
    nonce: u64,
}

impl ResetTombstone {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn retry(self) -> ResetAttempt {
        ResetAttempt {
            generation: self.generation,
            nonce: self.nonce,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResetReceipt {
    generation: u64,
    nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiescenceReceipt {
    generation: u64,
    nonce: u64,
    completed: usize,
}

impl QuiescenceReceipt {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn completed(self) -> usize {
        self.completed
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct IotlbAttempt<const OWNERS: usize> {
    generation: u64,
    nonce: u64,
    completed: [bool; OWNERS],
}

impl<const OWNERS: usize> IotlbAttempt<OWNERS> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn owner_complete(mut self, owner: usize) -> Result<IotlbProgress<OWNERS>, IoError> {
        if owner >= OWNERS {
            return Err(IoError::InvalidOwner);
        }
        if self.completed[owner] {
            return Err(IoError::DuplicateOwner);
        }
        self.completed[owner] = true;
        let count = self.completed.iter().filter(|done| **done).count();
        if count == OWNERS {
            Ok(IotlbProgress::Complete(QuiescenceReceipt {
                generation: self.generation,
                nonce: self.nonce,
                completed: count,
            }))
        } else {
            Ok(IotlbProgress::Pending(self))
        }
    }

    pub fn retain(self) -> IotlbTombstone<OWNERS> {
        IotlbTombstone {
            generation: self.generation,
            nonce: self.nonce,
            completed: self.completed,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct IotlbTombstone<const OWNERS: usize> {
    generation: u64,
    nonce: u64,
    completed: [bool; OWNERS],
}

impl<const OWNERS: usize> IotlbTombstone<OWNERS> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn retry(self) -> IotlbAttempt<OWNERS> {
        IotlbAttempt {
            generation: self.generation,
            nonce: self.nonce,
            completed: self.completed,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IotlbProgress<const OWNERS: usize> {
    Pending(IotlbAttempt<OWNERS>),
    Complete(QuiescenceReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IoEffect {
    identity: IoIdentity,
    committed: bool,
    terminal: Option<IoTerminal>,
    commit_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoProjection {
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub device_generation: u64,
    pub phase: IoPhase,
    pub effect_count: usize,
    pub committed: usize,
    pub terminalized: usize,
    pub reset_pending: bool,
    pub iotlb_pending: bool,
}

/// Publication/reset/IOTLB semantic ledger. Queue and DMA payloads stay outside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoGate<const EFFECTS: usize> {
    authority_epoch: u64,
    binding_epoch: u64,
    device_generation: u64,
    next_request_id: u64,
    next_commit_sequence: u64,
    next_reset_nonce: u64,
    next_iotlb_nonce: u64,
    phase: IoPhase,
    effects: [Option<IoEffect>; EFFECTS],
    authority_advanced_for_rebind: bool,
    binding_advanced_for_rebind: bool,
    active_reset_nonce: Option<u64>,
    active_iotlb_nonce: Option<u64>,
}

impl<const EFFECTS: usize> IoGate<EFFECTS> {
    pub fn new() -> Result<Self, IoError> {
        if EFFECTS == 0 {
            return Err(IoError::InvalidConfiguration);
        }
        Ok(Self {
            authority_epoch: 1,
            binding_epoch: 1,
            device_generation: 1,
            next_request_id: 1,
            next_commit_sequence: 1,
            next_reset_nonce: 1,
            next_iotlb_nonce: 1,
            phase: IoPhase::Active,
            effects: [None; EFFECTS],
            authority_advanced_for_rebind: false,
            binding_advanced_for_rebind: false,
            active_reset_nonce: None,
            active_iotlb_nonce: None,
        })
    }

    pub fn projection(&self) -> IoProjection {
        IoProjection {
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            device_generation: self.device_generation,
            phase: self.phase,
            effect_count: self.effects.iter().flatten().count(),
            committed: self
                .effects
                .iter()
                .flatten()
                .filter(|effect| effect.committed)
                .count(),
            terminalized: self
                .effects
                .iter()
                .flatten()
                .filter(|effect| effect.terminal.is_some())
                .count(),
            reset_pending: self.active_reset_nonce.is_some(),
            iotlb_pending: self.active_iotlb_nonce.is_some(),
        }
    }

    pub const fn next_request_id(&self) -> u64 {
        self.next_request_id
    }

    pub fn binding_token(&self) -> Result<IoBinding, IoError> {
        match self.phase {
            IoPhase::Active => Ok(IoBinding {
                epoch: self.binding_epoch,
            }),
            IoPhase::ServiceUnavailable | IoPhase::Quiesced => Err(IoError::ServiceUnavailable),
            IoPhase::Closing => Err(IoError::Closing),
        }
    }

    pub fn register(&mut self, binding: IoBinding) -> Result<IoIdentity, IoError> {
        if binding.epoch != self.binding_epoch {
            return Err(IoError::StaleBinding);
        }
        self.require_active()?;
        let index = self
            .effects
            .iter()
            .position(Option::is_none)
            .ok_or(IoError::LedgerFull)?;
        let request_id = self.next_request_id;
        let next_request_id = request_id.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let identity = IoIdentity {
            request_id,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            device_generation: self.device_generation,
        };
        self.effects[index] = Some(IoEffect {
            identity,
            committed: false,
            terminal: None,
            commit_sequence: None,
        });
        self.next_request_id = next_request_id;
        Ok(identity)
    }

    pub fn accepts_service_action(&self, identity: IoIdentity) -> bool {
        self.validate_service(identity).is_ok()
            && self
                .effect(identity)
                .is_some_and(|effect| effect.terminal.is_none())
    }

    pub fn commit_with<T, E>(
        &mut self,
        identity: IoIdentity,
        publish: impl FnOnce() -> Result<T, E>,
    ) -> Result<(IoCommitReceipt, T), IoCommitError<E>> {
        self.validate_service(identity)
            .map_err(IoCommitError::Gate)?;
        let effect = self
            .effect(identity)
            .ok_or(IoCommitError::Gate(IoError::UnknownEffect))?;
        if effect.terminal.is_some() {
            return Err(IoCommitError::Gate(IoError::AlreadyTerminal));
        }
        if effect.committed {
            return Err(IoCommitError::Gate(IoError::AlreadyCommitted));
        }
        let sequence = self.next_commit_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(IoCommitError::Gate(IoError::CounterOverflow))?;
        let output = publish().map_err(IoCommitError::Publication)?;
        let effect = self.effect_mut(identity).unwrap();
        effect.committed = true;
        effect.commit_sequence = Some(sequence);
        self.next_commit_sequence = next_sequence;
        Ok((IoCommitReceipt { identity, sequence }, output))
    }

    pub fn accept_notify(
        &self,
        identity: IoIdentity,
        commit: IoCommitReceipt,
    ) -> Result<(), IoError> {
        self.validate_service(identity)?;
        let effect = self.effect(identity).ok_or(IoError::UnknownEffect)?;
        if commit.identity != identity || effect.commit_sequence != Some(commit.sequence) {
            return Err(IoError::InvalidReceipt);
        }
        if effect.terminal.is_some() {
            return Err(IoError::AlreadyTerminal);
        }
        Ok(())
    }

    pub fn complete_device(&mut self, identity: IoIdentity) -> Result<IoTerminalReceipt, IoError> {
        if identity.device_generation != self.device_generation {
            return Err(IoError::StaleDeviceGeneration);
        }
        let effect = self.effect(identity).ok_or(IoError::UnknownEffect)?;
        if !effect.committed {
            return Err(IoError::NotCommitted);
        }
        if effect.terminal.is_some() {
            return Err(IoError::AlreadyTerminal);
        }
        self.effect_mut(identity).unwrap().terminal = Some(IoTerminal::Completed);
        Ok(IoTerminalReceipt {
            identity,
            terminal: IoTerminal::Completed,
        })
    }

    pub fn crash_service(&mut self) -> Result<IoCrashReceipt, IoError> {
        self.require_active()?;
        let binding_epoch = self
            .binding_epoch
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let receipt = IoCrashReceipt {
            previous_binding_epoch: self.binding_epoch,
            binding_epoch,
        };
        self.binding_epoch = binding_epoch;
        self.binding_advanced_for_rebind = true;
        self.phase = IoPhase::ServiceUnavailable;
        Ok(receipt)
    }

    pub fn begin_closing(&mut self) -> Result<CloseReceipt, IoError> {
        if !matches!(self.phase, IoPhase::Active | IoPhase::ServiceUnavailable) {
            return Err(IoError::InvalidPhase);
        }
        let authority_epoch = self
            .authority_epoch
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let mut aborted = 0;
        for effect in self.effects.iter_mut().flatten() {
            if effect.identity.device_generation == self.device_generation
                && !effect.committed
                && effect.terminal.is_none()
            {
                effect.terminal = Some(IoTerminal::AbortedBeforeCommit);
                aborted += 1;
            }
        }
        self.authority_epoch = authority_epoch;
        self.authority_advanced_for_rebind = true;
        self.phase = IoPhase::Closing;
        Ok(CloseReceipt {
            authority_epoch,
            device_generation: self.device_generation,
            aborted,
        })
    }

    pub fn begin_reset(&mut self, close: CloseReceipt) -> Result<ResetAttempt, IoError> {
        if self.phase != IoPhase::Closing
            || close.authority_epoch != self.authority_epoch
            || close.device_generation != self.device_generation
            || self.active_reset_nonce.is_some()
        {
            return Err(IoError::InvalidReceipt);
        }
        let nonce = self.next_reset_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(IoError::CounterOverflow)?;
        self.next_reset_nonce = next_nonce;
        self.active_reset_nonce = Some(nonce);
        Ok(ResetAttempt {
            generation: self.device_generation,
            nonce,
        })
    }

    pub fn apply_reset(&mut self, receipt: ResetReceipt) -> Result<ResetOutcome, IoError> {
        if self.phase != IoPhase::Closing
            || receipt.generation != self.device_generation
            || self.active_reset_nonce != Some(receipt.nonce)
        {
            return Err(IoError::InvalidReceipt);
        }
        let device_generation = self
            .device_generation
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let mut terminalized = 0;
        for effect in self.effects.iter_mut().flatten() {
            if effect.identity.device_generation == receipt.generation
                && effect.committed
                && effect.terminal.is_none()
            {
                effect.terminal = Some(IoTerminal::IndeterminateAfterReset);
                terminalized += 1;
            }
        }
        self.device_generation = device_generation;
        self.active_reset_nonce = None;
        Ok(ResetOutcome {
            closed_generation: receipt.generation,
            device_generation,
            terminalized,
            nonce: receipt.nonce,
        })
    }

    pub fn begin_iotlb<const OWNERS: usize>(
        &mut self,
        reset: ResetOutcome,
    ) -> Result<IotlbAttempt<OWNERS>, IoError> {
        if OWNERS == 0
            || self.phase != IoPhase::Closing
            || reset.device_generation != self.device_generation
            || reset.closed_generation.checked_add(1) != Some(reset.device_generation)
            || self.active_iotlb_nonce.is_some()
        {
            return Err(IoError::InvalidReceipt);
        }
        let nonce = self.next_iotlb_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(IoError::CounterOverflow)?;
        self.next_iotlb_nonce = next_nonce;
        self.active_iotlb_nonce = Some(nonce);
        Ok(IotlbAttempt {
            generation: reset.closed_generation,
            nonce,
            completed: [false; OWNERS],
        })
    }

    pub fn mark_quiesced(&mut self, receipt: QuiescenceReceipt) -> Result<(), IoError> {
        if self.phase != IoPhase::Closing
            || self.active_reset_nonce.is_some()
            || self.active_iotlb_nonce != Some(receipt.nonce)
            || receipt.generation.checked_add(1) != Some(self.device_generation)
            || receipt.completed == 0
        {
            return Err(IoError::InvalidReceipt);
        }
        self.active_iotlb_nonce = None;
        self.phase = IoPhase::Quiesced;
        Ok(())
    }

    pub fn rebind_after_quiescence(&mut self) -> Result<IoBinding, IoError> {
        if self.phase != IoPhase::Quiesced {
            return Err(IoError::InvalidPhase);
        }
        let authority_epoch = if self.authority_advanced_for_rebind {
            self.authority_epoch
        } else {
            self.authority_epoch
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?
        };
        let binding_epoch = if self.binding_advanced_for_rebind {
            self.binding_epoch
        } else {
            self.binding_epoch
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?
        };
        self.authority_epoch = authority_epoch;
        self.binding_epoch = binding_epoch;
        self.authority_advanced_for_rebind = false;
        self.binding_advanced_for_rebind = false;
        self.phase = IoPhase::Active;
        Ok(IoBinding {
            epoch: self.binding_epoch,
        })
    }

    pub fn terminal(&self, identity: IoIdentity) -> Option<IoTerminal> {
        self.effect(identity).and_then(|effect| effect.terminal)
    }

    fn require_active(&self) -> Result<(), IoError> {
        match self.phase {
            IoPhase::Active => Ok(()),
            IoPhase::ServiceUnavailable | IoPhase::Quiesced => Err(IoError::ServiceUnavailable),
            IoPhase::Closing => Err(IoError::Closing),
        }
    }

    fn validate_service(&self, identity: IoIdentity) -> Result<(), IoError> {
        self.require_active()?;
        if identity.authority_epoch != self.authority_epoch {
            return Err(IoError::StaleAuthority);
        }
        if identity.binding_epoch != self.binding_epoch {
            return Err(IoError::StaleBinding);
        }
        if identity.device_generation != self.device_generation {
            return Err(IoError::StaleDeviceGeneration);
        }
        if self.effect(identity).is_none() {
            return Err(IoError::UnknownEffect);
        }
        Ok(())
    }

    fn effect(&self, identity: IoIdentity) -> Option<&IoEffect> {
        self.effects
            .iter()
            .flatten()
            .find(|effect| effect.identity == identity)
    }

    fn effect_mut(&mut self, identity: IoIdentity) -> Option<&mut IoEffect> {
        self.effects
            .iter_mut()
            .flatten()
            .find(|effect| effect.identity == identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_and_reset_choose_one_terminal_and_iotlb_gates_quiescence() {
        let mut gate = IoGate::<4>::new().unwrap();
        let binding = gate.binding_token().unwrap();
        let first = gate.register(binding).unwrap();
        let second = gate.register(binding).unwrap();
        gate.commit_with(first, || Ok::<_, ()>(())).unwrap();
        gate.commit_with(second, || Ok::<_, ()>(())).unwrap();
        gate.complete_device(first).unwrap();
        let close = gate.begin_closing().unwrap();
        let reset = gate.begin_reset(close).unwrap().acknowledge();
        let outcome = gate.apply_reset(reset).unwrap();
        assert_eq!(outcome.terminalized(), 1);
        assert_eq!(gate.terminal(first), Some(IoTerminal::Completed));
        assert_eq!(
            gate.terminal(second),
            Some(IoTerminal::IndeterminateAfterReset)
        );
        let attempt = gate.begin_iotlb::<3>(outcome).unwrap();
        let attempt = match attempt.owner_complete(0).unwrap() {
            IotlbProgress::Pending(attempt) => attempt,
            IotlbProgress::Complete(_) => panic!("three owners are required"),
        };
        let attempt = match attempt.retain().retry().owner_complete(1).unwrap() {
            IotlbProgress::Pending(attempt) => attempt,
            IotlbProgress::Complete(_) => panic!("one owner remains"),
        };
        let receipt = match attempt.owner_complete(2).unwrap() {
            IotlbProgress::Complete(receipt) => receipt,
            IotlbProgress::Pending(_) => panic!("all owners completed"),
        };
        gate.mark_quiesced(receipt).unwrap();
        assert_eq!(gate.projection().phase, IoPhase::Quiesced);
    }

    #[test]
    fn timeout_tombstone_preserves_reset_identity() {
        let mut gate = IoGate::<1>::new().unwrap();
        let identity = gate.register(gate.binding_token().unwrap()).unwrap();
        gate.commit_with(identity, || Ok::<_, ()>(())).unwrap();
        let close = gate.begin_closing().unwrap();
        let pending = gate.begin_reset(close).unwrap().retain();
        let before = gate.projection();
        assert!(before.reset_pending);
        let outcome = gate.apply_reset(pending.retry().acknowledge()).unwrap();
        assert_eq!(outcome.closed_generation(), 1);
    }
}
