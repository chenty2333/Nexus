// SPDX-License-Identifier: MPL-2.0

/// Stable identity for one externally coordinated handoff attempt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HandoffId(u64);

impl HandoffId {
    pub const fn new(value: u64) -> Result<Self, HandoffGateError> {
        if value == 0 {
            return Err(HandoffGateError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic position in the external ownership-decision log.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogPosition(u64);

impl LogPosition {
    pub const fn new(value: u64) -> Result<Self, HandoffGateError> {
        if value == 0 {
            return Err(HandoffGateError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Durable intent accepted from the external ownership service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareIntent {
    handoff: HandoffId,
    log_identity: u64,
    intent_position: LogPosition,
    service_incarnation: u64,
    key_identity: u64,
    request_digest: u64,
}

impl PrepareIntent {
    pub const fn new(
        handoff: HandoffId,
        log_identity: u64,
        intent_position: LogPosition,
        service_incarnation: u64,
        key_identity: u64,
        request_digest: u64,
    ) -> Result<Self, HandoffGateError> {
        if log_identity == 0 || service_incarnation == 0 || key_identity == 0 || request_digest == 0
        {
            return Err(HandoffGateError::InvalidIdentity);
        }
        Ok(Self {
            handoff,
            log_identity,
            intent_position,
            service_incarnation,
            key_identity,
            request_digest,
        })
    }

    pub const fn handoff(self) -> HandoffId {
        self.handoff
    }

    pub const fn request_digest(self) -> u64 {
        self.request_digest
    }
}

/// Registry-owned identity and cohort projection captured at freeze.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreezeContext {
    pub registry_instance: u64,
    pub boot_incarnation: u64,
    pub scope_id: u64,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub scope_revision: u64,
    pub cohort_digest: u64,
    pub classification_digest: u64,
}

impl FreezeContext {
    const fn validate(self) -> Result<(), HandoffGateError> {
        if self.registry_instance == 0
            || self.boot_incarnation == 0
            || self.scope_id == 0
            || self.scope_generation == 0
            || self.authority_epoch == 0
            || self.binding_epoch == 0
            || self.cohort_digest == 0
            || self.classification_digest == 0
        {
            return Err(HandoffGateError::InvalidIdentity);
        }
        Ok(())
    }
}

/// Exact local receipt returned after admission and cohort classification
/// linearize under the production Registry lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreezeReceipt {
    intent: PrepareIntent,
    context: FreezeContext,
    freeze_generation: u64,
}

impl FreezeReceipt {
    pub const fn intent(self) -> PrepareIntent {
        self.intent
    }

    pub const fn context(self) -> FreezeContext {
        self.context
    }

    pub const fn freeze_generation(self) -> u64 {
        self.freeze_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipDecision {
    Abort,
    Commit,
}

/// Authenticated ownership input after an adapter has verified its native
/// bytes. The gate validates the complete semantic identity again before
/// mutating local admission state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipDecisionReceipt {
    handoff: HandoffId,
    context: FreezeContext,
    freeze_generation: u64,
    log_identity: u64,
    decision_position: LogPosition,
    service_incarnation: u64,
    key_identity: u64,
    request_digest: u64,
    decision: OwnershipDecision,
}

impl OwnershipDecisionReceipt {
    pub const fn new(
        freeze: FreezeReceipt,
        decision_position: LogPosition,
        request_digest: u64,
        decision: OwnershipDecision,
    ) -> Result<Self, HandoffGateError> {
        if request_digest == 0 {
            return Err(HandoffGateError::InvalidIdentity);
        }
        Ok(Self {
            handoff: freeze.intent.handoff,
            context: freeze.context,
            freeze_generation: freeze.freeze_generation,
            log_identity: freeze.intent.log_identity,
            decision_position,
            service_incarnation: freeze.intent.service_incarnation,
            key_identity: freeze.intent.key_identity,
            request_digest,
            decision,
        })
    }

    pub const fn decision(self) -> OwnershipDecision {
        self.decision
    }

    pub const fn context(self) -> FreezeContext {
        self.context
    }

    pub const fn decision_position(self) -> LogPosition {
        self.decision_position
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionPhase {
    Open,
    Frozen,
    CommitAccepted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionProjection {
    pub phase: AdmissionPhase,
    pub freeze: Option<FreezeReceipt>,
    pub decision: Option<OwnershipDecisionReceipt>,
    pub last_abort: Option<OwnershipDecisionReceipt>,
    pub next_freeze_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffGateError {
    InvalidIdentity,
    CounterOverflow,
    AdmissionFrozen,
    AdmissionOpen,
    ReceiptMismatch,
    StaleDecision,
    ConflictingDecision,
}

/// Reversible admission gate orthogonal to an authority scope's
/// `Active -> Closing -> Revoked` lifecycle.
///
/// The containing Registry owns cohort construction, effect classification,
/// credits, and closure. This object owns only the exact freeze generation and
/// abort-or-commit winner, so it cannot become a second effect ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffAdmissionGate {
    phase: AdmissionPhase,
    freeze: Option<FreezeReceipt>,
    decision: Option<OwnershipDecisionReceipt>,
    last_abort: Option<OwnershipDecisionReceipt>,
    next_freeze_generation: u64,
}

impl HandoffAdmissionGate {
    pub const fn new() -> Self {
        Self {
            phase: AdmissionPhase::Open,
            freeze: None,
            decision: None,
            last_abort: None,
            next_freeze_generation: 1,
        }
    }

    pub const fn projection(&self) -> AdmissionProjection {
        AdmissionProjection {
            phase: self.phase,
            freeze: self.freeze,
            decision: self.decision,
            last_abort: self.last_abort,
            next_freeze_generation: self.next_freeze_generation,
        }
    }

    pub const fn require_open(&self) -> Result<(), HandoffGateError> {
        if matches!(self.phase, AdmissionPhase::Open) {
            Ok(())
        } else {
            Err(HandoffGateError::AdmissionFrozen)
        }
    }

    pub fn freeze(
        &mut self,
        intent: PrepareIntent,
        context: FreezeContext,
    ) -> Result<FreezeReceipt, HandoffGateError> {
        context.validate()?;
        if let Some(existing) = self.freeze {
            return if existing.intent == intent && existing.context == context {
                Ok(existing)
            } else {
                Err(HandoffGateError::AdmissionFrozen)
            };
        }
        self.require_open()?;
        let freeze_generation = self.next_freeze_generation;
        let next_freeze_generation = freeze_generation
            .checked_add(1)
            .ok_or(HandoffGateError::CounterOverflow)?;
        let receipt = FreezeReceipt {
            intent,
            context,
            freeze_generation,
        };
        self.freeze = Some(receipt);
        self.phase = AdmissionPhase::Frozen;
        self.next_freeze_generation = next_freeze_generation;
        Ok(receipt)
    }

    pub fn accept_decision(
        &mut self,
        receipt: OwnershipDecisionReceipt,
    ) -> Result<OwnershipDecision, HandoffGateError> {
        let Some(freeze) = self.freeze else {
            return match self.last_abort {
                Some(existing) if existing == receipt => Ok(OwnershipDecision::Abort),
                Some(existing) if same_attempt(existing, receipt) => {
                    if receipt.decision == OwnershipDecision::Commit {
                        Err(HandoffGateError::ConflictingDecision)
                    } else {
                        Err(HandoffGateError::ReceiptMismatch)
                    }
                }
                _ => Err(HandoffGateError::AdmissionOpen),
            };
        };
        validate_decision(freeze, receipt)?;
        if let Some(existing) = self.decision {
            return if existing == receipt {
                Ok(existing.decision)
            } else if existing.decision != receipt.decision {
                Err(HandoffGateError::ConflictingDecision)
            } else {
                Err(HandoffGateError::ReceiptMismatch)
            };
        }
        match receipt.decision {
            OwnershipDecision::Abort => {
                self.freeze = None;
                self.decision = None;
                self.last_abort = Some(receipt);
                self.phase = AdmissionPhase::Open;
            }
            OwnershipDecision::Commit => {
                self.decision = Some(receipt);
                self.phase = AdmissionPhase::CommitAccepted;
            }
        }
        Ok(receipt.decision)
    }
}

impl Default for HandoffAdmissionGate {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_decision(
    freeze: FreezeReceipt,
    decision: OwnershipDecisionReceipt,
) -> Result<(), HandoffGateError> {
    if decision.handoff != freeze.intent.handoff
        || decision.context != freeze.context
        || decision.freeze_generation != freeze.freeze_generation
        || decision.log_identity != freeze.intent.log_identity
        || decision.service_incarnation != freeze.intent.service_incarnation
        || decision.key_identity != freeze.intent.key_identity
        || decision.request_digest != freeze.intent.request_digest
    {
        return Err(HandoffGateError::ReceiptMismatch);
    }
    if decision.decision_position.get() <= freeze.intent.intent_position.get() {
        return Err(HandoffGateError::StaleDecision);
    }
    Ok(())
}

fn same_attempt(left: OwnershipDecisionReceipt, right: OwnershipDecisionReceipt) -> bool {
    left.handoff == right.handoff
        && left.context == right.context
        && left.freeze_generation == right.freeze_generation
        && left.log_identity == right.log_identity
        && left.service_incarnation == right.service_incarnation
        && left.key_identity == right.key_identity
        && left.request_digest == right.request_digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (HandoffAdmissionGate, PrepareIntent, FreezeContext) {
        let gate = HandoffAdmissionGate::new();
        let intent = PrepareIntent::new(
            HandoffId::new(7).unwrap(),
            11,
            LogPosition::new(13).unwrap(),
            17,
            19,
            23,
        )
        .unwrap();
        let context = FreezeContext {
            registry_instance: 29,
            boot_incarnation: 31,
            scope_id: 37,
            scope_generation: 41,
            authority_epoch: 43,
            binding_epoch: 47,
            scope_revision: 0,
            cohort_digest: 53,
            classification_digest: 59,
        };
        (gate, intent, context)
    }

    #[test]
    fn exact_freeze_and_abort_replay_are_idempotent() {
        let (mut gate, intent, context) = fixture();
        let freeze = gate.freeze(intent, context).unwrap();
        assert_eq!(gate.freeze(intent, context), Ok(freeze));
        assert_eq!(gate.require_open(), Err(HandoffGateError::AdmissionFrozen));

        let abort = OwnershipDecisionReceipt::new(
            freeze,
            LogPosition::new(61).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Abort,
        )
        .unwrap();
        assert_eq!(gate.accept_decision(abort), Ok(OwnershipDecision::Abort));
        assert_eq!(gate.accept_decision(abort), Ok(OwnershipDecision::Abort));
        assert_eq!(gate.require_open(), Ok(()));
    }

    #[test]
    fn commit_is_terminal_and_conflicting_abort_is_failure_atomic() {
        let (mut gate, intent, context) = fixture();
        let freeze = gate.freeze(intent, context).unwrap();
        let commit = OwnershipDecisionReceipt::new(
            freeze,
            LogPosition::new(61).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Commit,
        )
        .unwrap();
        gate.accept_decision(commit).unwrap();
        let before = gate.projection();
        let abort = OwnershipDecisionReceipt::new(
            freeze,
            LogPosition::new(67).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Abort,
        )
        .unwrap();
        assert_eq!(
            gate.accept_decision(abort),
            Err(HandoffGateError::ConflictingDecision)
        );
        assert_eq!(gate.projection(), before);
    }

    #[test]
    fn stale_or_substituted_decisions_do_not_mutate() {
        let (mut gate, intent, context) = fixture();
        let freeze = gate.freeze(intent, context).unwrap();
        for (position, digest, expected) in [
            (13, intent.request_digest(), HandoffGateError::StaleDecision),
            (61, 71, HandoffGateError::ReceiptMismatch),
        ] {
            let receipt = OwnershipDecisionReceipt::new(
                freeze,
                LogPosition::new(position).unwrap(),
                digest,
                OwnershipDecision::Commit,
            )
            .unwrap();
            let before = gate.projection();
            assert_eq!(gate.accept_decision(receipt), Err(expected));
            assert_eq!(gate.projection(), before);
        }
    }

    #[test]
    fn decision_from_another_freeze_context_is_rejected_without_mutation() {
        let (_, intent, context) = fixture();
        let mut source = HandoffAdmissionGate::new();
        let source_freeze = source.freeze(intent, context).unwrap();
        let mut target = HandoffAdmissionGate::new();
        let target_context = FreezeContext {
            registry_instance: context.registry_instance + 1,
            scope_id: context.scope_id + 1,
            cohort_digest: context.cohort_digest + 1,
            ..context
        };
        target.freeze(intent, target_context).unwrap();
        let foreign = OwnershipDecisionReceipt::new(
            source_freeze,
            LogPosition::new(61).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Commit,
        )
        .unwrap();
        let before = target.projection();

        assert_eq!(
            target.accept_decision(foreign),
            Err(HandoffGateError::ReceiptMismatch)
        );
        assert_eq!(target.projection(), before);
    }

    #[test]
    fn abort_retires_the_attempt_and_next_freeze_gets_a_new_generation() {
        let (mut gate, intent, context) = fixture();
        let first = gate.freeze(intent, context).unwrap();
        let first_abort = OwnershipDecisionReceipt::new(
            first,
            LogPosition::new(61).unwrap(),
            intent.request_digest(),
            OwnershipDecision::Abort,
        )
        .unwrap();
        gate.accept_decision(first_abort).unwrap();
        assert_eq!(
            gate.accept_decision(first_abort),
            Ok(OwnershipDecision::Abort)
        );

        let next_intent = PrepareIntent::new(
            HandoffId::new(73).unwrap(),
            79,
            LogPosition::new(83).unwrap(),
            89,
            97,
            101,
        )
        .unwrap();
        let next_context = FreezeContext {
            scope_revision: context.scope_revision + 1,
            cohort_digest: context.cohort_digest + 1,
            classification_digest: context.classification_digest + 1,
            ..context
        };
        let second = gate.freeze(next_intent, next_context).unwrap();
        assert_eq!(second.freeze_generation(), first.freeze_generation() + 1);
        let before = gate.projection();
        assert_eq!(
            gate.accept_decision(first_abort),
            Err(HandoffGateError::ReceiptMismatch)
        );
        assert_eq!(gate.projection(), before);
    }
}
