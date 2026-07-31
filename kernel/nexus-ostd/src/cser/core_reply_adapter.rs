// SPDX-License-Identifier: MPL-2.0

//! Physical OSTD reply custody for the portable CSER core.
//!
//! The portable core remains the sole semantic authority.  This adapter owns
//! only the real `Waiter`/`Waker`, the published payload, and exact physical
//! observations used by the configured reply verifier.  Its atomic state is
//! not an obligation ledger: it cannot fence, adopt, settle, retire, or release
//! a core claim.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};

use cser_core::{
    ClaimId, ClaimScope, ComponentId, CoreError, Digest, EffectFactChallenge, EffectFactKind,
    EffectReceiptVerifier, Engine, EvidenceChallenge, REPLY_APPLY_RECEIPT_SCHEMA, REPLY_DOMAIN,
    REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_OBLIGATION_PUBLICATION, REPLY_RECEIPT_SCHEMA,
    REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, ReceiptVerifier, ResourceGeneration,
    ResourceId, SettlementClaim, VerificationError, VerifiedApplyReceipt,
    VerifiedEffectObservation, VerifiedObservation, VerifiedRetirementEvidence,
    VerifiedSettlementAck, VerifierIdentity,
};
use ostd::sync::{SpinLock, Waiter, Waker};
use sha2::{Digest as _, Sha256};

const REPLY_ARMED: u8 = 0;
const REPLY_APPLYING: u8 = 1;
const REPLY_PUBLISHED: u8 = 2;
const REPLY_ACKNOWLEDGED: u8 = 3;
const REPLY_INDETERMINATE: u8 = 4;

/// Exact core and physical coordinate of one reply publication slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyCoordinate {
    effect: cser_core::EffectId,
    component: Option<ComponentId>,
    claim: ClaimId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
}

impl ReplyCoordinate {
    pub(crate) const fn new(
        effect: cser_core::EffectId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
    ) -> Self {
        Self {
            effect,
            component: None,
            claim,
            resource,
            resource_generation,
        }
    }

    pub(crate) const fn new_component(
        effect: cser_core::EffectId,
        component: ComponentId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
    ) -> Self {
        Self {
            effect,
            component: Some(component),
            claim,
            resource,
            resource_generation,
        }
    }

    pub(crate) const fn effect(self) -> cser_core::EffectId {
        self.effect
    }

    pub(crate) const fn component(self) -> Option<ComponentId> {
        self.component
    }

    pub(crate) const fn claim(self) -> ClaimId {
        self.claim
    }

    pub(crate) const fn resource(self) -> ResourceId {
        self.resource
    }

    pub(crate) const fn resource_generation(self) -> ResourceGeneration {
        self.resource_generation
    }
}

/// Immutable physical publication plan bound into the durable apply intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyPlan {
    coordinate: ReplyCoordinate,
    publication_sequence: u64,
    value: u64,
    intent_digest: Digest,
    payload_digest: Digest,
}

impl ReplyPlan {
    /// Returns the digest which must be passed to
    /// `SettlementClaim::record_apply_intent`.
    pub(crate) const fn intent_digest(self) -> Digest {
        self.intent_digest
    }

    /// Returns the exact result delivered to the waiting client.
    pub(crate) const fn value(self) -> u64 {
        self.value
    }

    pub(crate) const fn coordinate(self) -> ReplyCoordinate {
        self.coordinate
    }

    pub(crate) const fn publication_sequence(self) -> u64 {
        self.publication_sequence
    }

    /// Returns the exact payload identity committed by a durable reply
    /// outbox before the physical waiter publication is reconciled.
    #[cfg(feature = "cser-production")]
    pub(crate) const fn payload_digest(self) -> Digest {
        self.payload_digest
    }

    pub(crate) fn apply_receipt_digest(self) -> Digest {
        apply_digest(self)
    }

    pub(crate) fn acknowledgement_digest(self) -> Digest {
        ack_digest(self)
    }

    pub(crate) fn retirement_receipt_digest(self) -> Digest {
        retirement_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishedReply {
    plan: ReplyPlan,
}

struct ReplyPhysicalState {
    phase: AtomicU8,
    published: SpinLock<Option<PublishedReply>>,
    waker: Arc<Waker>,
}

/// Client-side endpoint for one real OSTD blocking reply.
pub(crate) struct ReplyReceiver {
    coordinate: ReplyCoordinate,
    waiter: Waiter,
    state: Arc<ReplyPhysicalState>,
}

/// Kernel physical custodian for the reply slot retained by the causal estate.
///
/// This value is deliberately non-cloneable.  The receiver shares only the
/// underlying physical endpoint and has no core settlement authority.
pub(crate) struct ReplyCustody {
    coordinate: ReplyCoordinate,
    state: Arc<ReplyPhysicalState>,
}

/// Physical publication failure.  No verifier receipt is minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyApplyError {
    /// The supplied plan belongs to another physical reply slot.
    WrongCoordinate,
    /// Another executor is between apply-start and a knowable result.
    ApplyInProgress,
    /// The waiter could not be woken after the payload was installed.
    Indeterminate,
}

/// Client-side acknowledgement failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyAckError {
    /// The client woke without a matching published payload.
    MissingPublication,
    /// The acknowledgement for this endpoint was already emitted.
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyApplyObservation {
    plan: ReplyPlan,
    digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyAckObservation {
    plan: ReplyPlan,
    digest: Digest,
}

/// Creates one real OSTD reply endpoint and its kernel custodian.
pub(crate) fn reply_pair(coordinate: ReplyCoordinate) -> (ReplyReceiver, ReplyCustody) {
    let (waiter, waker) = Waiter::new_pair();
    let state = Arc::new(ReplyPhysicalState {
        phase: AtomicU8::new(REPLY_ARMED),
        published: SpinLock::new(None),
        waker,
    });
    (
        ReplyReceiver {
            coordinate,
            waiter,
            state: Arc::clone(&state),
        },
        ReplyCustody { coordinate, state },
    )
}

/// Builds the deterministic plan shared by the durable commit provider and
/// the later physical reply custodian.
pub(crate) fn reply_plan(
    coordinate: ReplyCoordinate,
    publication_sequence: u64,
    value: u64,
) -> Result<ReplyPlan, ReplyApplyError> {
    if publication_sequence == 0 {
        return Err(ReplyApplyError::WrongCoordinate);
    }
    let intent_digest = hash_plan(
        b"nexus.ostd.cser-core.reply-intent.v1",
        coordinate,
        publication_sequence,
        value,
    );
    let payload_digest = hash_plan(
        b"nexus.ostd.cser-core.reply-payload.v1",
        coordinate,
        publication_sequence,
        value,
    );
    Ok(ReplyPlan {
        coordinate,
        publication_sequence,
        value,
        intent_digest,
        payload_digest,
    })
}

impl ReplyCustody {
    /// Builds an immutable plan for one kernel-owned publication attempt.
    pub(crate) fn plan(
        &self,
        publication_sequence: u64,
        value: u64,
    ) -> Result<ReplyPlan, ReplyApplyError> {
        reply_plan(self.coordinate, publication_sequence, value)
    }

    /// Applies the real OSTD wake after the core apply intent is durable.
    ///
    /// A repeated call after publication is an observation of the same
    /// physical result; it never wakes the client twice.
    pub(crate) fn apply(
        &self,
        challenge: EffectFactChallenge,
        plan: ReplyPlan,
    ) -> Result<ReplyApplyObservation, ReplyApplyError> {
        if plan.coordinate != self.coordinate
            || challenge.kind() != EffectFactKind::ApplyCompleted
            || challenge.effect() != self.coordinate.effect
            || challenge.component() != self.coordinate.component
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.operation() != plan.intent_digest
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != REPLY_APPLY_RECEIPT_SCHEMA
        {
            return Err(ReplyApplyError::WrongCoordinate);
        }
        match self.state.phase.compare_exchange(
            REPLY_ARMED,
            REPLY_APPLYING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                *self.state.published.lock() = Some(PublishedReply { plan });
                self.state.phase.store(REPLY_PUBLISHED, Ordering::Release);
                if self.state.waker.wake_up() {
                    Ok(apply_observation(plan))
                } else {
                    match self.state.phase.compare_exchange(
                        REPLY_PUBLISHED,
                        REPLY_INDETERMINATE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Err(REPLY_ACKNOWLEDGED) => Ok(apply_observation(plan)),
                        Ok(_) | Err(_) => Err(ReplyApplyError::Indeterminate),
                    }
                }
            }
            Err(REPLY_PUBLISHED | REPLY_ACKNOWLEDGED) => self.observe_apply(plan),
            Err(REPLY_APPLYING) => Err(ReplyApplyError::ApplyInProgress),
            Err(REPLY_INDETERMINATE) => Err(ReplyApplyError::Indeterminate),
            Err(_) => Err(ReplyApplyError::Indeterminate),
        }
    }

    /// Re-delivers one source-exact reply whose durable apply record survived
    /// an executor or machine restart.
    ///
    /// The caller must first validate that record through the persistent reply
    /// provider. This physical operation remains idempotent for the fresh
    /// endpoint and carries no core settlement authority.
    pub(crate) fn redeliver_durable(
        &self,
        plan: ReplyPlan,
        durable_apply_digest: Digest,
    ) -> Result<(), ReplyApplyError> {
        if plan.coordinate != self.coordinate
            || durable_apply_digest != apply_digest(plan)
            || durable_apply_digest.is_zero()
        {
            return Err(ReplyApplyError::WrongCoordinate);
        }
        match self.state.phase.compare_exchange(
            REPLY_ARMED,
            REPLY_APPLYING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                *self.state.published.lock() = Some(PublishedReply { plan });
                self.state.phase.store(REPLY_PUBLISHED, Ordering::Release);
                if self.state.waker.wake_up() {
                    Ok(())
                } else {
                    match self.state.phase.compare_exchange(
                        REPLY_PUBLISHED,
                        REPLY_INDETERMINATE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Err(REPLY_ACKNOWLEDGED) => Ok(()),
                        Ok(_) | Err(_) => Err(ReplyApplyError::Indeterminate),
                    }
                }
            }
            Err(REPLY_PUBLISHED | REPLY_ACKNOWLEDGED) => self
                .observe_apply(plan)
                .map(|_| ())
                .map_err(|_| ReplyApplyError::Indeterminate),
            Err(REPLY_APPLYING) => Err(ReplyApplyError::ApplyInProgress),
            Err(REPLY_INDETERMINATE) => Err(ReplyApplyError::Indeterminate),
            Err(_) => Err(ReplyApplyError::Indeterminate),
        }
    }

    /// Reconciles a publication after a successor or manager crashed.
    pub(crate) fn observe_apply(
        &self,
        plan: ReplyPlan,
    ) -> Result<ReplyApplyObservation, ReplyApplyError> {
        if plan.coordinate != self.coordinate {
            return Err(ReplyApplyError::WrongCoordinate);
        }
        match self.state.phase.load(Ordering::Acquire) {
            REPLY_PUBLISHED | REPLY_ACKNOWLEDGED => {
                let published = *self.state.published.lock();
                match published {
                    Some(PublishedReply { plan: observed }) if observed == plan => {
                        Ok(apply_observation(observed))
                    }
                    _ => Err(ReplyApplyError::WrongCoordinate),
                }
            }
            REPLY_APPLYING => Err(ReplyApplyError::ApplyInProgress),
            REPLY_ARMED => Err(ReplyApplyError::Indeterminate),
            REPLY_INDETERMINATE => Err(ReplyApplyError::Indeterminate),
            _ => Err(ReplyApplyError::Indeterminate),
        }
    }

    /// Verifies a real or reconciled publication for one exact core claim.
    pub(crate) fn verify_applied(
        &self,
        engine: &Engine,
        claim: &SettlementClaim,
        observation: &ReplyApplyObservation,
    ) -> Result<VerifiedApplyReceipt, CoreError> {
        engine.verify_apply_completion(claim, &ReplyEffectVerifier { custody: self }, observation)
    }

    /// Returns the client acknowledgement after the real waiter observed the
    /// publication.
    pub(crate) fn observe_ack(
        &self,
        plan: ReplyPlan,
    ) -> Result<ReplyAckObservation, ReplyAckError> {
        if plan.coordinate != self.coordinate {
            return Err(ReplyAckError::MissingPublication);
        }
        if self.state.phase.load(Ordering::Acquire) != REPLY_ACKNOWLEDGED {
            return Err(ReplyAckError::MissingPublication);
        }
        let published = *self.state.published.lock();
        match published {
            Some(PublishedReply { plan: observed }) if observed == plan => {
                Ok(ack_observation(observed))
            }
            _ => Err(ReplyAckError::MissingPublication),
        }
    }

    /// Verifies the real client acknowledgement for final settlement.
    pub(crate) fn verify_settlement_ack(
        &self,
        engine: &Engine,
        claim: &SettlementClaim,
        observation: &ReplyAckObservation,
    ) -> Result<VerifiedSettlementAck, CoreError> {
        engine.verify_settlement_ack(claim, &ReplyAckVerifier { custody: self }, observation)
    }

    /// Verifies the same real acknowledgement as physical retirement evidence
    /// for the reply-slot claim.
    pub(crate) fn verify_retirement(
        &self,
        engine: &Engine,
        observation: &ReplyAckObservation,
    ) -> Result<VerifiedRetirementEvidence, CoreError> {
        match self.coordinate.component {
            Some(component) => engine.verify_component_retirement_evidence(
                self.coordinate.effect,
                component,
                self.coordinate.claim,
                REPLY_EVIDENCE_PUBLICATION_ACK,
                &ReplyRetirementVerifier { custody: self },
                observation,
            ),
            None => engine.verify_retirement_evidence(
                self.coordinate.effect,
                self.coordinate.claim,
                REPLY_EVIDENCE_PUBLICATION_ACK,
                &ReplyRetirementVerifier { custody: self },
                observation,
            ),
        }
    }
}

impl ReplyReceiver {
    /// Blocks a real OSTD task until publication and acknowledges exactly once.
    pub(crate) fn wait_and_ack(self) -> Result<u64, ReplyAckError> {
        self.waiter.wait();
        if self.state.phase.load(Ordering::Acquire) != REPLY_PUBLISHED {
            return Err(ReplyAckError::MissingPublication);
        }
        let published = *self.state.published.lock();
        let Some(PublishedReply { plan }) = published else {
            return Err(ReplyAckError::MissingPublication);
        };
        if plan.coordinate != self.coordinate {
            return Err(ReplyAckError::MissingPublication);
        }
        self.state
            .phase
            .compare_exchange(
                REPLY_PUBLISHED,
                REPLY_ACKNOWLEDGED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ReplyAckError::Duplicate)?;
        Ok(plan.value())
    }
}

struct ReplyEffectVerifier<'a> {
    custody: &'a ReplyCustody,
}

impl EffectReceiptVerifier for ReplyEffectVerifier<'_> {
    type Receipt = ReplyApplyObservation;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(REPLY_VERIFIER, 1, REPLY_APPLY_RECEIPT_SCHEMA)
            .expect("standard reply verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        let phase = self.custody.state.phase.load(Ordering::Acquire);
        if challenge.kind() != EffectFactKind::ApplyCompleted
            || challenge.effect() != self.custody.coordinate.effect
            || challenge.component() != self.custody.coordinate.component
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.operation() != receipt.plan.intent_digest
            || receipt.plan.coordinate != self.custody.coordinate
            || receipt.digest != apply_digest(receipt.plan)
            || !matches!(phase, REPLY_PUBLISHED | REPLY_ACKNOWLEDGED)
            || *self.custody.state.published.lock() != Some(PublishedReply { plan: receipt.plan })
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::fact(
            challenge.current_observation(),
            receipt.digest,
        ))
    }
}

impl EffectReceiptVerifier for ReplyAckVerifier<'_> {
    type Receipt = ReplyAckObservation;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(REPLY_VERIFIER, 1, REPLY_SETTLEMENT_RECEIPT_SCHEMA)
            .expect("standard reply acknowledgement verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if challenge.kind() != EffectFactKind::SettlementAcknowledged
            || challenge.effect() != self.custody.coordinate.effect
            || challenge.component() != self.custody.coordinate.component
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.operation() != receipt.plan.intent_digest
            || challenge.predecessor() != Some(apply_digest(receipt.plan))
            || receipt.plan.coordinate != self.custody.coordinate
            || receipt.digest != ack_digest(receipt.plan)
            || self.custody.state.phase.load(Ordering::Acquire) != REPLY_ACKNOWLEDGED
            || *self.custody.state.published.lock() != Some(PublishedReply { plan: receipt.plan })
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::fact(
            challenge.current_observation(),
            receipt.digest,
        ))
    }
}

struct ReplyAckVerifier<'a> {
    custody: &'a ReplyCustody,
}

struct ReplyRetirementVerifier<'a> {
    custody: &'a ReplyCustody,
}

impl ReceiptVerifier for ReplyRetirementVerifier<'_> {
    type Receipt = ReplyAckObservation;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(REPLY_VERIFIER, 1, REPLY_RECEIPT_SCHEMA)
            .expect("standard reply retirement verifier identity is valid")
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if challenge.effect() != self.custody.coordinate.effect
            || challenge.component() != self.custody.coordinate.component
            || challenge.claim() != self.custody.coordinate.claim
            || challenge.domain() != REPLY_DOMAIN
            || challenge.kind() != REPLY_EVIDENCE_PUBLICATION_ACK
            || challenge.scope() != ClaimScope::Logical
            || challenge.resource() != self.custody.coordinate.resource
            || challenge.resource_generation() != self.custody.coordinate.resource_generation
            || receipt.plan.coordinate != self.custody.coordinate
            || receipt.digest != ack_digest(receipt.plan)
            || self.custody.state.phase.load(Ordering::Acquire) != REPLY_ACKNOWLEDGED
            || *self.custody.state.published.lock() != Some(PublishedReply { plan: receipt.plan })
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
            retirement_digest(receipt.plan),
        ))
    }
}

fn apply_observation(plan: ReplyPlan) -> ReplyApplyObservation {
    ReplyApplyObservation {
        plan,
        digest: apply_digest(plan),
    }
}

fn ack_observation(plan: ReplyPlan) -> ReplyAckObservation {
    ReplyAckObservation {
        plan,
        digest: ack_digest(plan),
    }
}

fn apply_digest(plan: ReplyPlan) -> Digest {
    hash_receipt(b"nexus.ostd.cser-core.reply-apply.v1", plan)
}

fn ack_digest(plan: ReplyPlan) -> Digest {
    hash_receipt(b"nexus.ostd.cser-core.reply-ack.v1", plan)
}

fn retirement_digest(plan: ReplyPlan) -> Digest {
    hash_receipt(b"nexus.ostd.cser-core.reply-retirement.v1", plan)
}

fn hash_receipt(domain: &[u8], plan: ReplyPlan) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_coordinate(&mut hasher, plan.coordinate);
    hasher.update(plan.publication_sequence.to_le_bytes());
    hasher.update(plan.value.to_le_bytes());
    hasher.update(plan.intent_digest.bytes());
    hasher.update(plan.payload_digest.bytes());
    Digest::new(hasher.finalize().into())
}

fn hash_plan(
    domain: &[u8],
    coordinate: ReplyCoordinate,
    publication_sequence: u64,
    value: u64,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_coordinate(&mut hasher, coordinate);
    hasher.update(publication_sequence.to_le_bytes());
    hasher.update(value.to_le_bytes());
    Digest::new(hasher.finalize().into())
}

fn hash_coordinate(hasher: &mut Sha256, coordinate: ReplyCoordinate) {
    hasher.update(coordinate.effect.root().get().to_le_bytes());
    hasher.update(coordinate.effect.sequence().to_le_bytes());
    match coordinate.component {
        Some(component) => {
            hasher.update([1]);
            hasher.update(component.get().to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(coordinate.claim.get().to_le_bytes());
    hasher.update(coordinate.resource.get().to_le_bytes());
    hasher.update(coordinate.resource_generation.get().to_le_bytes());
}
