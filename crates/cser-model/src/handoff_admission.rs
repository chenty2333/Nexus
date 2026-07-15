//! Independent safe-Rust oracle for reversible handoff admission.
//!
//! This module models the local contract in RFC 0002. It deliberately does not
//! call the OSTD Registry or model a distributed ownership implementation.

use alloc::collections::{BTreeMap, BTreeSet};

/// Stable identifier for one local handoff attempt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HandoffId(u64);

impl HandoffId {
    /// Constructs a handoff identifier.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable identifier for one effect in the local oracle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalEffectId(u64);

impl LocalEffectId {
    /// Constructs an effect identifier for queries and negative tests.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic position in the trusted ownership decision log.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogPosition(u64);

impl LogPosition {
    /// Constructs a log position.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Current lifecycle of the local authority scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalScopePhase {
    /// The authority epoch remains live.
    Active,
    /// A commit decision fenced the source and closure is in progress.
    Closing,
    /// Every frozen effect and publication reached terminal closure.
    Revoked,
}

/// Current authority available to the source principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePrincipal {
    /// Ordinary source execution is authorized.
    Active,
    /// Admission is frozen while the ownership decision is unknown.
    Frozen,
    /// A commit decision permanently fenced the old source authority.
    Fenced,
    /// Abort opened admission, but the crashed source binding must recover.
    RecoveryRequired,
}

/// External destination authorization observed by the local oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationAuthority {
    /// No destination execution authority exists.
    Inactive,
    /// Exact local closure authorized destination execution.
    Active,
    /// A retained post-commit effect requires recovery before activation.
    RecoveryRequired,
}

/// Local disposition of one descendant effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectDisposition {
    /// Identity and resources are registered but no backend preparation exists.
    Registered,
    /// Backend preparation exists but no external commit occurred.
    Prepared,
    /// The external commit point was crossed and the effect must drain.
    Committed,
    /// The effect completed; its one-shot publication may still be pending.
    Completed,
    /// The effect was explicitly aborted before commit.
    Aborted,
    /// Hardware or provider closure is indeterminate and resources are retained.
    Retained,
}

impl EffectDisposition {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Frozen-cohort readiness for an external ownership commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeReadiness {
    /// All preconditions for an ownership commit are satisfied.
    ReadyToCommit,
    /// Registered or prepared effects must be explicitly aborted first.
    NeedsAbort,
    /// A completed effect still has an unacknowledged closure publication.
    PublicationPending,
    /// A retained tombstone blocks the ownership commit.
    BlockedRetained,
}

/// Durable intent reference supplied by the external ownership log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareIntent {
    /// Handoff attempt identity.
    pub handoff: HandoffId,
    /// Ownership-log namespace identity.
    pub log_identity: u64,
    /// Position of the recoverable intent record.
    pub intent_position: LogPosition,
    /// Incarnation of the decision service.
    pub service_incarnation: u64,
    /// Identity of the key authorized for this log incarnation.
    pub key_identity: u64,
}

/// Receipt for one reversible local admission freeze.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeReceipt {
    handoff: HandoffId,
    log_identity: u64,
    intent_position: LogPosition,
    service_incarnation: u64,
    key_identity: u64,
    registry_instance: u64,
    boot_incarnation: u64,
    scope_id: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    freeze_generation: u64,
    frozen_scope_revision: u64,
    cohort_digest: u64,
    classification_digest: u64,
}

impl FreezeReceipt {
    /// Returns the handoff identity.
    #[must_use]
    pub const fn handoff(&self) -> HandoffId {
        self.handoff
    }

    /// Returns the freeze generation.
    #[must_use]
    pub const fn freeze_generation(&self) -> u64 {
        self.freeze_generation
    }

    /// Returns the frozen cohort digest.
    #[must_use]
    pub const fn cohort_digest(&self) -> u64 {
        self.cohort_digest
    }

    /// Returns the frozen classification digest.
    #[must_use]
    pub const fn classification_digest(&self) -> u64 {
        self.classification_digest
    }
}

/// Result of freezing local effect admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeOutcome {
    /// Immutable receipt for this frozen generation.
    pub receipt: FreezeReceipt,
    /// Current readiness derived from the frozen cohort.
    pub readiness: FreezeReadiness,
}

/// Typed authoritative ownership abort receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipAbortReceipt {
    /// Handoff attempt identity.
    pub handoff: HandoffId,
    /// Freeze generation decided by this receipt.
    pub freeze_generation: u64,
    /// Ownership-log namespace identity.
    pub log_identity: u64,
    /// Monotonic decision position after the intent.
    pub decision_position: LogPosition,
    /// Incarnation of the decision service.
    pub service_incarnation: u64,
    /// Identity of the authorized decision key.
    pub key_identity: u64,
}

/// Typed authoritative ownership commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipCommitReceipt {
    /// Handoff attempt identity.
    pub handoff: HandoffId,
    /// Freeze generation decided by this receipt.
    pub freeze_generation: u64,
    /// Ownership-log namespace identity.
    pub log_identity: u64,
    /// Monotonic decision position after the intent.
    pub decision_position: LogPosition,
    /// Incarnation of the decision service.
    pub service_incarnation: u64,
    /// Identity of the authorized decision key.
    pub key_identity: u64,
}

/// Exact receipt proving local source closure for one committed handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureReceipt {
    handoff: HandoffId,
    freeze_generation: u64,
    decision_position: LogPosition,
    registry_instance: u64,
    boot_incarnation: u64,
    scope_id: u64,
    closed_authority_epoch: u64,
    authority_epoch: u64,
    cohort_digest: u64,
    closure_sequence: u64,
}

impl ClosureReceipt {
    /// Returns the handoff identity.
    #[must_use]
    pub const fn handoff(&self) -> HandoffId {
        self.handoff
    }

    /// Returns the unique local closure sequence.
    #[must_use]
    pub const fn closure_sequence(&self) -> u64 {
        self.closure_sequence
    }
}

/// Progress returned by an idempotent commit-close operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureProgress {
    /// Committed effects or closure publications still need progress.
    Pending,
    /// At least one effect remains retained and activation is unauthorized.
    Retained,
    /// Exact source closure was reached.
    Closed(ClosureReceipt),
}

/// Result of an authoritative abort and thaw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThawProgress {
    /// The existing source binding may resume ordinary execution.
    Thawed,
    /// The gate opened, but a crashed source binding must recover first.
    SourceRecoveryRequired,
}

/// Current externally queryable local handoff progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffProgress {
    /// No local freeze exists.
    Open,
    /// A decision remains unknown and the source stays frozen.
    Frozen(FreezeReadiness),
    /// An abort decision opened the gate.
    Aborted(ThawProgress),
    /// A commit decision is driving local closure.
    Committed(ClosureProgress),
}

/// Failure returned by the independent handoff-admission oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffAdmissionError {
    /// A durable intent must precede freeze.
    IntentRequired,
    /// The source scope is not in the required phase.
    InvalidScopePhase,
    /// The admission gate is not in the required state.
    InvalidGate,
    /// Ordinary source execution authority is unavailable.
    SourceNotActive,
    /// The supplied effect identity does not exist.
    UnknownEffect,
    /// The effect is in the wrong disposition for this transition.
    InvalidEffectState,
    /// An integer generation or sequence would overflow.
    CounterOverflow,
    /// A typed receipt does not bind the exact frozen identity.
    ReceiptMismatch,
    /// The decision position does not follow the intent position.
    StaleDecision,
    /// A different authoritative decision already exists.
    ConflictingDecision,
    /// Uncommitted or publication work prevents ownership commit.
    NotReadyToCommit,
    /// A retained tombstone blocks ownership commit or closure.
    RetainedTombstone,
    /// A typed ownership decision is required for this transition.
    DecisionReceiptRequired,
    /// A stale or frozen service binding attempted publication.
    StaleBinding,
    /// Exact local closure is required before destination activation.
    ClosureRequired,
    /// A supplied closure receipt differs from the authoritative receipt.
    ClosureMismatch,
    /// A source binding did not crash and therefore needs no recovery.
    RecoveryNotRequired,
    /// A model invariant was violated.
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnershipDecision {
    Abort(DecisionIdentity),
    Commit(DecisionIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecisionIdentity {
    handoff: HandoffId,
    freeze_generation: u64,
    position: LogPosition,
    log_identity: u64,
    service_incarnation: u64,
    key_identity: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FrozenState {
    receipt: FreezeReceipt,
    cohort: BTreeSet<LocalEffectId>,
    committed_at_freeze: BTreeSet<LocalEffectId>,
}

/// Independent bounded state machine for RFC 0002 local semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffAdmissionModel {
    registry_instance: u64,
    boot_incarnation: u64,
    scope_id: u64,
    initial_authority_epoch: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    scope_revision: u64,
    scope_phase: LocalScopePhase,
    source: SourcePrincipal,
    destination: DestinationAuthority,
    effects: BTreeMap<LocalEffectId, EffectDisposition>,
    pending_publications: BTreeSet<LocalEffectId>,
    next_effect_id: u64,
    next_freeze_generation: u64,
    next_closure_sequence: u64,
    intent: Option<PrepareIntent>,
    frozen: Option<FrozenState>,
    decision: Option<OwnershipDecision>,
    closure: Option<ClosureReceipt>,
    source_crashed: bool,
}

impl HandoffAdmissionModel {
    /// Constructs one active local scope with an open admission gate.
    #[must_use]
    pub fn new(
        registry_instance: u64,
        boot_incarnation: u64,
        scope_id: u64,
        authority_epoch: u64,
        binding_epoch: u64,
    ) -> Self {
        Self {
            registry_instance,
            boot_incarnation,
            scope_id,
            initial_authority_epoch: authority_epoch,
            authority_epoch,
            binding_epoch,
            scope_revision: 0,
            scope_phase: LocalScopePhase::Active,
            source: SourcePrincipal::Active,
            destination: DestinationAuthority::Inactive,
            effects: BTreeMap::new(),
            pending_publications: BTreeSet::new(),
            next_effect_id: 1,
            next_freeze_generation: 1,
            next_closure_sequence: 1,
            intent: None,
            frozen: None,
            decision: None,
            closure: None,
            source_crashed: false,
        }
    }

    /// Returns the current local scope phase.
    #[must_use]
    pub const fn scope_phase(&self) -> LocalScopePhase {
        self.scope_phase
    }

    /// Returns the current source-principal state.
    #[must_use]
    pub const fn source_principal(&self) -> SourcePrincipal {
        self.source
    }

    /// Returns the observed destination authority.
    #[must_use]
    pub const fn destination_authority(&self) -> DestinationAuthority {
        self.destination
    }

    /// Returns the current authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Returns the current binding epoch.
    #[must_use]
    pub const fn binding_epoch(&self) -> u64 {
        self.binding_epoch
    }

    /// Returns one effect's current disposition.
    pub fn effect_disposition(
        &self,
        effect: LocalEffectId,
    ) -> Result<EffectDisposition, HandoffAdmissionError> {
        self.effects
            .get(&effect)
            .copied()
            .ok_or(HandoffAdmissionError::UnknownEffect)
    }

    /// Records one recoverable ownership intent without changing local authority.
    pub fn record_intent(&mut self, intent: PrepareIntent) -> Result<(), HandoffAdmissionError> {
        if self.scope_phase != LocalScopePhase::Active || self.frozen.is_some() {
            return Err(HandoffAdmissionError::InvalidGate);
        }
        if let Some(existing) = self.intent {
            return if existing == intent {
                Ok(())
            } else {
                Err(HandoffAdmissionError::ReceiptMismatch)
            };
        }
        if intent.handoff.get() == 0
            || intent.log_identity == 0
            || intent.intent_position.get() == 0
            || intent.service_incarnation == 0
            || intent.key_identity == 0
        {
            return Err(HandoffAdmissionError::ReceiptMismatch);
        }
        self.intent = Some(intent);
        self.check_invariants()
    }

    /// Registers one effect while the source and admission gate remain active.
    pub fn register_effect(&mut self) -> Result<LocalEffectId, HandoffAdmissionError> {
        self.require_open_source()?;
        let effect = LocalEffectId::new(self.next_effect_id);
        self.next_effect_id = self
            .next_effect_id
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        self.scope_revision = self
            .scope_revision
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        self.effects.insert(effect, EffectDisposition::Registered);
        self.check_invariants()?;
        Ok(effect)
    }

    /// Prepares one registered effect while admission remains open.
    pub fn prepare_effect(&mut self, effect: LocalEffectId) -> Result<(), HandoffAdmissionError> {
        self.require_open_source()?;
        if self.effect_disposition(effect)? != EffectDisposition::Registered {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        self.effects.insert(effect, EffectDisposition::Prepared);
        self.advance_scope_revision()?;
        self.check_invariants()
    }

    /// Crosses the first external commit point while admission remains open.
    pub fn commit_effect(&mut self, effect: LocalEffectId) -> Result<(), HandoffAdmissionError> {
        self.require_open_source()?;
        match self.effect_disposition(effect)? {
            EffectDisposition::Prepared => {
                self.effects.insert(effect, EffectDisposition::Committed);
                self.advance_scope_revision()?;
                self.check_invariants()
            }
            EffectDisposition::Committed => Ok(()),
            _ => Err(HandoffAdmissionError::InvalidEffectState),
        }
    }

    /// Marks an already committed effect retained by an honest timeout.
    pub fn retain_effect(&mut self, effect: LocalEffectId) -> Result<(), HandoffAdmissionError> {
        if self.effect_disposition(effect)? != EffectDisposition::Committed {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        if let Some(frozen) = &self.frozen
            && !frozen.committed_at_freeze.contains(&effect)
        {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        self.effects.insert(effect, EffectDisposition::Retained);
        self.advance_scope_revision()?;
        if matches!(self.decision, Some(OwnershipDecision::Commit(_))) {
            self.destination = DestinationAuthority::RecoveryRequired;
        }
        self.check_invariants()
    }

    /// Freezes admission after a durable intent has been recorded.
    pub fn freeze_admission(&mut self) -> Result<FreezeOutcome, HandoffAdmissionError> {
        self.require_open_source()?;
        let intent = self.intent.ok_or(HandoffAdmissionError::IntentRequired)?;
        let freeze_generation = self.next_freeze_generation;
        self.next_freeze_generation = self
            .next_freeze_generation
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        let cohort: BTreeSet<_> = self
            .effects
            .iter()
            .filter_map(|(effect, state)| (!state.is_terminal()).then_some(*effect))
            .collect();
        let committed_at_freeze = self
            .effects
            .iter()
            .filter_map(|(effect, state)| {
                matches!(
                    state,
                    EffectDisposition::Committed | EffectDisposition::Retained
                )
                .then_some(*effect)
            })
            .collect();
        let receipt = FreezeReceipt {
            handoff: intent.handoff,
            log_identity: intent.log_identity,
            intent_position: intent.intent_position,
            service_incarnation: intent.service_incarnation,
            key_identity: intent.key_identity,
            registry_instance: self.registry_instance,
            boot_incarnation: self.boot_incarnation,
            scope_id: self.scope_id,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch,
            freeze_generation,
            frozen_scope_revision: self.scope_revision,
            cohort_digest: cohort_digest(&cohort),
            classification_digest: classification_digest(&cohort, &self.effects),
        };
        self.frozen = Some(FrozenState {
            receipt: receipt.clone(),
            cohort,
            committed_at_freeze,
        });
        self.source = SourcePrincipal::Frozen;
        let readiness = self.freeze_readiness()?;
        self.check_invariants()?;
        Ok(FreezeOutcome { receipt, readiness })
    }

    /// Returns current progress for the active or completed local handoff.
    pub fn query_handoff(&self) -> Result<HandoffProgress, HandoffAdmissionError> {
        match self.decision {
            Some(OwnershipDecision::Abort(_)) => Ok(HandoffProgress::Aborted(
                if self.source == SourcePrincipal::RecoveryRequired {
                    ThawProgress::SourceRecoveryRequired
                } else {
                    ThawProgress::Thawed
                },
            )),
            Some(OwnershipDecision::Commit(_)) => {
                Ok(HandoffProgress::Committed(self.closure_progress()?))
            }
            None if self.frozen.is_some() => Ok(HandoffProgress::Frozen(self.freeze_readiness()?)),
            None => Ok(HandoffProgress::Open),
        }
    }

    /// Explicitly aborts every registered or prepared member of the frozen cohort.
    pub fn abort_uncommitted(
        &mut self,
        receipt: &FreezeReceipt,
    ) -> Result<usize, HandoffAdmissionError> {
        self.validate_freeze_receipt(receipt)?;
        if self.decision.is_some() {
            return Err(HandoffAdmissionError::ConflictingDecision);
        }
        let cohort = self.frozen.as_ref().unwrap().cohort.clone();
        let mut aborted = 0;
        for effect in cohort {
            if matches!(
                self.effects[&effect],
                EffectDisposition::Registered | EffectDisposition::Prepared
            ) {
                self.effects.insert(effect, EffectDisposition::Aborted);
                aborted += 1;
            }
        }
        if aborted != 0 {
            self.advance_scope_revision()?;
        }
        self.check_invariants()?;
        Ok(aborted)
    }

    /// Completes one effect that was already committed when freeze linearized.
    pub fn complete_committed(
        &mut self,
        effect: LocalEffectId,
    ) -> Result<(), HandoffAdmissionError> {
        let frozen = self
            .frozen
            .as_ref()
            .ok_or(HandoffAdmissionError::InvalidGate)?;
        if !frozen.committed_at_freeze.contains(&effect)
            || self.effect_disposition(effect)? != EffectDisposition::Committed
        {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        self.effects.insert(effect, EffectDisposition::Completed);
        self.pending_publications.insert(effect);
        self.advance_scope_revision()?;
        self.check_invariants()
    }

    /// Acknowledges one closure-owned completion publication.
    pub fn acknowledge_closure_publication(
        &mut self,
        effect: LocalEffectId,
    ) -> Result<(), HandoffAdmissionError> {
        if !self.pending_publications.remove(&effect) {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        self.advance_scope_revision()?;
        self.check_invariants()
    }

    /// Reconciles a retained effect to a completed, publication-pending state.
    pub fn reconcile_retained(
        &mut self,
        effect: LocalEffectId,
    ) -> Result<(), HandoffAdmissionError> {
        if self.effect_disposition(effect)? != EffectDisposition::Retained {
            return Err(HandoffAdmissionError::InvalidEffectState);
        }
        self.effects.insert(effect, EffectDisposition::Completed);
        self.pending_publications.insert(effect);
        self.advance_scope_revision()?;
        if matches!(self.decision, Some(OwnershipDecision::Commit(_))) {
            self.destination = DestinationAuthority::Inactive;
        }
        self.check_invariants()
    }

    /// Records a source service crash without losing the frozen kernel state.
    pub fn crash_source(&mut self) -> Result<u64, HandoffAdmissionError> {
        if self.scope_phase != LocalScopePhase::Active {
            return Err(HandoffAdmissionError::InvalidScopePhase);
        }
        let old_binding = self.binding_epoch;
        self.binding_epoch = self
            .binding_epoch
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        self.source_crashed = true;
        if self.frozen.is_none() {
            self.source = SourcePrincipal::RecoveryRequired;
        }
        self.advance_scope_revision()?;
        self.check_invariants()?;
        Ok(old_binding)
    }

    /// Probes a service-owned publication; frozen or stale bindings reject.
    pub fn publish_from_binding(&self, binding_epoch: u64) -> Result<(), HandoffAdmissionError> {
        if binding_epoch != self.binding_epoch
            || self.source != SourcePrincipal::Active
            || self.frozen.is_some()
        {
            return Err(HandoffAdmissionError::StaleBinding);
        }
        Ok(())
    }

    /// Rejects phase-only thaw without a typed ownership abort receipt.
    pub const fn unfreeze_without_receipt(&self) -> Result<(), HandoffAdmissionError> {
        Err(HandoffAdmissionError::DecisionReceiptRequired)
    }

    /// Applies or replays one authoritative abort decision.
    pub fn unfreeze(
        &mut self,
        receipt: OwnershipAbortReceipt,
    ) -> Result<ThawProgress, HandoffAdmissionError> {
        let presented = decision_identity_from_abort(receipt);
        match self.decision {
            Some(OwnershipDecision::Abort(existing)) if existing == presented => {
                return Ok(if self.source == SourcePrincipal::RecoveryRequired {
                    ThawProgress::SourceRecoveryRequired
                } else {
                    ThawProgress::Thawed
                });
            }
            Some(_) => return Err(HandoffAdmissionError::ConflictingDecision),
            None => {}
        }
        let identity = self.validate_abort_receipt(receipt)?;
        self.decision = Some(OwnershipDecision::Abort(identity));
        self.frozen = None;
        let progress = if self.source_crashed {
            self.source = SourcePrincipal::RecoveryRequired;
            ThawProgress::SourceRecoveryRequired
        } else {
            self.source = SourcePrincipal::Active;
            ThawProgress::Thawed
        };
        self.check_invariants()?;
        Ok(progress)
    }

    /// Recovers a crashed source only after an authoritative abort opened the gate.
    pub fn recover_source_after_abort(&mut self) -> Result<(), HandoffAdmissionError> {
        if !matches!(self.decision, Some(OwnershipDecision::Abort(_)))
            || self.source != SourcePrincipal::RecoveryRequired
        {
            return Err(HandoffAdmissionError::RecoveryNotRequired);
        }
        self.source_crashed = false;
        self.source = SourcePrincipal::Active;
        self.check_invariants()
    }

    /// Applies, advances, or replays one authoritative commit-close operation.
    pub fn commit_close(
        &mut self,
        receipt: OwnershipCommitReceipt,
    ) -> Result<ClosureProgress, HandoffAdmissionError> {
        let presented = decision_identity_from_commit(receipt);
        match self.decision {
            Some(OwnershipDecision::Commit(existing)) if existing == presented => {
                self.try_finalize_closure(existing)?;
                self.check_invariants()?;
                return self.closure_progress();
            }
            Some(_) => return Err(HandoffAdmissionError::ConflictingDecision),
            None => {
                let identity = self.validate_commit_receipt(receipt)?;
                match self.freeze_readiness()? {
                    FreezeReadiness::ReadyToCommit => {}
                    FreezeReadiness::BlockedRetained => {
                        return Err(HandoffAdmissionError::RetainedTombstone);
                    }
                    FreezeReadiness::NeedsAbort | FreezeReadiness::PublicationPending => {
                        return Err(HandoffAdmissionError::NotReadyToCommit);
                    }
                }
                self.decision = Some(OwnershipDecision::Commit(identity));
                self.scope_phase = LocalScopePhase::Closing;
                self.source = SourcePrincipal::Fenced;
                self.authority_epoch = self
                    .authority_epoch
                    .checked_add(1)
                    .ok_or(HandoffAdmissionError::CounterOverflow)?;
                self.advance_scope_revision()?;
                self.try_finalize_closure(identity)?;
            }
        }
        self.check_invariants()?;
        self.closure_progress()
    }

    /// Authorizes destination execution only from the exact local closure receipt.
    pub fn authorize_destination(
        &mut self,
        receipt: &ClosureReceipt,
    ) -> Result<(), HandoffAdmissionError> {
        let Some(authoritative) = &self.closure else {
            return Err(HandoffAdmissionError::ClosureRequired);
        };
        if authoritative != receipt {
            return Err(HandoffAdmissionError::ClosureMismatch);
        }
        self.destination = DestinationAuthority::Active;
        self.check_invariants()
    }

    /// Rejects activation when no exact closure receipt is available.
    pub const fn authorize_destination_without_closure(&self) -> Result<(), HandoffAdmissionError> {
        Err(HandoffAdmissionError::ClosureRequired)
    }

    /// Checks every bounded local safety invariant.
    pub fn check_invariants(&self) -> Result<(), HandoffAdmissionError> {
        if self.authority_epoch < self.initial_authority_epoch
            || self.authority_epoch > self.initial_authority_epoch.saturating_add(1)
        {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        if self.frozen.is_some() && self.source == SourcePrincipal::Active {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        if let Some(frozen) = &self.frozen {
            if frozen.receipt.cohort_digest != cohort_digest(&frozen.cohort)
                || frozen
                    .committed_at_freeze
                    .iter()
                    .any(|effect| !frozen.cohort.contains(effect))
            {
                return Err(HandoffAdmissionError::InvariantViolation);
            }
            let live: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, state)| (!state.is_terminal()).then_some(*effect))
                .collect();
            if !live.is_subset(&frozen.cohort) {
                return Err(HandoffAdmissionError::InvariantViolation);
            }
            for (effect, disposition) in &self.effects {
                if matches!(
                    disposition,
                    EffectDisposition::Committed | EffectDisposition::Retained
                ) && !frozen.committed_at_freeze.contains(effect)
                {
                    return Err(HandoffAdmissionError::InvariantViolation);
                }
            }
        }
        if self.pending_publications.iter().any(|effect| {
            self.effects.get(effect) != Some(&EffectDisposition::Completed)
                || self
                    .frozen
                    .as_ref()
                    .is_none_or(|frozen| !frozen.committed_at_freeze.contains(effect))
        }) {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        match self.decision {
            Some(OwnershipDecision::Abort(_)) => {
                if self.frozen.is_some()
                    || self.scope_phase != LocalScopePhase::Active
                    || self.destination != DestinationAuthority::Inactive
                    || !matches!(
                        self.source,
                        SourcePrincipal::Active | SourcePrincipal::RecoveryRequired
                    )
                {
                    return Err(HandoffAdmissionError::InvariantViolation);
                }
            }
            Some(OwnershipDecision::Commit(_)) => {
                if self.frozen.is_none()
                    || self.source != SourcePrincipal::Fenced
                    || !matches!(
                        self.scope_phase,
                        LocalScopePhase::Closing | LocalScopePhase::Revoked
                    )
                    || self.authority_epoch != self.initial_authority_epoch.saturating_add(1)
                {
                    return Err(HandoffAdmissionError::InvariantViolation);
                }
            }
            None => {
                if self.frozen.is_some()
                    && (self.source != SourcePrincipal::Frozen
                        || self.destination != DestinationAuthority::Inactive)
                {
                    return Err(HandoffAdmissionError::InvariantViolation);
                }
            }
        }
        if self
            .effects
            .values()
            .any(|state| *state == EffectDisposition::Retained)
            && self.closure.is_some()
        {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        if let Some(closure) = &self.closure
            && (self.scope_phase != LocalScopePhase::Revoked
                || !self.pending_publications.is_empty()
                || self.effects.values().any(|state| !state.is_terminal())
                || closure.authority_epoch != self.authority_epoch
                || closure.closed_authority_epoch != self.initial_authority_epoch)
        {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        if self.destination == DestinationAuthority::Active && self.closure.is_none() {
            return Err(HandoffAdmissionError::InvariantViolation);
        }
        Ok(())
    }

    fn require_open_source(&self) -> Result<(), HandoffAdmissionError> {
        if self.scope_phase != LocalScopePhase::Active {
            return Err(HandoffAdmissionError::InvalidScopePhase);
        }
        if self.frozen.is_some() {
            return Err(HandoffAdmissionError::InvalidGate);
        }
        if self.source != SourcePrincipal::Active {
            return Err(HandoffAdmissionError::SourceNotActive);
        }
        Ok(())
    }

    fn advance_scope_revision(&mut self) -> Result<(), HandoffAdmissionError> {
        self.scope_revision = self
            .scope_revision
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        Ok(())
    }

    fn freeze_readiness(&self) -> Result<FreezeReadiness, HandoffAdmissionError> {
        let frozen = self
            .frozen
            .as_ref()
            .ok_or(HandoffAdmissionError::InvalidGate)?;
        if frozen
            .cohort
            .iter()
            .any(|effect| self.effects[effect] == EffectDisposition::Retained)
        {
            return Ok(FreezeReadiness::BlockedRetained);
        }
        if frozen.cohort.iter().any(|effect| {
            matches!(
                self.effects[effect],
                EffectDisposition::Registered | EffectDisposition::Prepared
            )
        }) {
            return Ok(FreezeReadiness::NeedsAbort);
        }
        if !self.pending_publications.is_empty() {
            return Ok(FreezeReadiness::PublicationPending);
        }
        Ok(FreezeReadiness::ReadyToCommit)
    }

    fn validate_freeze_receipt(
        &self,
        receipt: &FreezeReceipt,
    ) -> Result<(), HandoffAdmissionError> {
        if self.frozen.as_ref().map(|frozen| &frozen.receipt) == Some(receipt) {
            Ok(())
        } else {
            Err(HandoffAdmissionError::ReceiptMismatch)
        }
    }

    fn validate_abort_receipt(
        &self,
        receipt: OwnershipAbortReceipt,
    ) -> Result<DecisionIdentity, HandoffAdmissionError> {
        self.validate_decision_fields(
            receipt.handoff,
            receipt.freeze_generation,
            receipt.log_identity,
            receipt.decision_position,
            receipt.service_incarnation,
            receipt.key_identity,
        )
    }

    fn validate_commit_receipt(
        &self,
        receipt: OwnershipCommitReceipt,
    ) -> Result<DecisionIdentity, HandoffAdmissionError> {
        self.validate_decision_fields(
            receipt.handoff,
            receipt.freeze_generation,
            receipt.log_identity,
            receipt.decision_position,
            receipt.service_incarnation,
            receipt.key_identity,
        )
    }

    fn validate_decision_fields(
        &self,
        handoff: HandoffId,
        freeze_generation: u64,
        log_identity: u64,
        decision_position: LogPosition,
        service_incarnation: u64,
        key_identity: u64,
    ) -> Result<DecisionIdentity, HandoffAdmissionError> {
        let frozen = self
            .frozen
            .as_ref()
            .ok_or(HandoffAdmissionError::InvalidGate)?;
        let receipt = &frozen.receipt;
        if handoff != receipt.handoff
            || freeze_generation != receipt.freeze_generation
            || log_identity != receipt.log_identity
            || service_incarnation != receipt.service_incarnation
            || key_identity != receipt.key_identity
        {
            return Err(HandoffAdmissionError::ReceiptMismatch);
        }
        if decision_position <= receipt.intent_position {
            return Err(HandoffAdmissionError::StaleDecision);
        }
        Ok(DecisionIdentity {
            handoff,
            freeze_generation,
            position: decision_position,
            log_identity,
            service_incarnation,
            key_identity,
        })
    }

    fn try_finalize_closure(
        &mut self,
        decision: DecisionIdentity,
    ) -> Result<(), HandoffAdmissionError> {
        if self.closure.is_some()
            || self.effects.values().any(|state| !state.is_terminal())
            || !self.pending_publications.is_empty()
        {
            return Ok(());
        }
        let frozen = self
            .frozen
            .as_ref()
            .ok_or(HandoffAdmissionError::InvalidGate)?;
        let closure_sequence = self.next_closure_sequence;
        self.next_closure_sequence = self
            .next_closure_sequence
            .checked_add(1)
            .ok_or(HandoffAdmissionError::CounterOverflow)?;
        self.scope_phase = LocalScopePhase::Revoked;
        self.closure = Some(ClosureReceipt {
            handoff: frozen.receipt.handoff,
            freeze_generation: frozen.receipt.freeze_generation,
            decision_position: decision.position,
            registry_instance: self.registry_instance,
            boot_incarnation: self.boot_incarnation,
            scope_id: self.scope_id,
            closed_authority_epoch: self.initial_authority_epoch,
            authority_epoch: self.authority_epoch,
            cohort_digest: frozen.receipt.cohort_digest,
            closure_sequence,
        });
        Ok(())
    }

    fn closure_progress(&self) -> Result<ClosureProgress, HandoffAdmissionError> {
        if let Some(receipt) = &self.closure {
            return Ok(ClosureProgress::Closed(receipt.clone()));
        }
        let frozen = self
            .frozen
            .as_ref()
            .ok_or(HandoffAdmissionError::InvalidGate)?;
        if frozen
            .cohort
            .iter()
            .any(|effect| self.effects[effect] == EffectDisposition::Retained)
        {
            Ok(ClosureProgress::Retained)
        } else {
            Ok(ClosureProgress::Pending)
        }
    }
}

const fn decision_identity_from_abort(receipt: OwnershipAbortReceipt) -> DecisionIdentity {
    DecisionIdentity {
        handoff: receipt.handoff,
        freeze_generation: receipt.freeze_generation,
        position: receipt.decision_position,
        log_identity: receipt.log_identity,
        service_incarnation: receipt.service_incarnation,
        key_identity: receipt.key_identity,
    }
}

const fn decision_identity_from_commit(receipt: OwnershipCommitReceipt) -> DecisionIdentity {
    DecisionIdentity {
        handoff: receipt.handoff,
        freeze_generation: receipt.freeze_generation,
        position: receipt.decision_position,
        log_identity: receipt.log_identity,
        service_incarnation: receipt.service_incarnation,
        key_identity: receipt.key_identity,
    }
}

fn cohort_digest(cohort: &BTreeSet<LocalEffectId>) -> u64 {
    cohort.iter().fold(0xcbf2_9ce4_8422_2325, |digest, effect| {
        digest.rotate_left(7) ^ effect.get().wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn classification_digest(
    cohort: &BTreeSet<LocalEffectId>,
    effects: &BTreeMap<LocalEffectId, EffectDisposition>,
) -> u64 {
    cohort.iter().fold(0x8422_2325_cbf2_9ce4, |digest, effect| {
        let tag = match effects[effect] {
            EffectDisposition::Registered => 1,
            EffectDisposition::Prepared => 2,
            EffectDisposition::Committed => 3,
            EffectDisposition::Completed => 4,
            EffectDisposition::Aborted => 5,
            EffectDisposition::Retained => 6,
        };
        digest.rotate_left(11) ^ effect.get().wrapping_mul(17) ^ tag
    })
}
