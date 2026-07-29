// SPDX-License-Identifier: MPL-2.0

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::convert::Infallible;

use sha2::{Digest as _, Sha256};

use crate::{
    BootGeneration, ChargeAccountId, ClaimId, ClaimKindId, ClaimScopePolicy, CreditClassId,
    DeviceGeneration, DeviceGenerationEffect, DeviceScopeId, Digest, DomainCatalog, DomainId,
    EffectId, EvidenceKindId, Freshness, FreshnessAxes, JournalDecodeError, JournalGeneration,
    JournalRecord, JournalRepair, ObligationKindId, ObligationPolicy, PrincipalIncarnation,
    ReceiptSchemaId, RegistryInstance, ResourceGeneration, ResourceId, RootId, SnapshotId,
    VerifierId, scan_journal, scan_journal_to_head,
};

/// Exact runtime scope of one resource claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClaimScope {
    /// Logical resource with no independently reset device.
    Logical,
    /// Resource belonging to one exact reset/quarantine domain.
    Device(DeviceScopeId),
}

/// Authority state of one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityState {
    /// The exact current incarnation may still act.
    Active,
    /// The originating or successor incarnation has been fenced.
    Fenced,
    /// Revocation won the action gate.
    Revoked,
}

/// Principal or kernel object currently responsible for an estate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyState {
    /// A live, exact principal incarnation is the operational custodian.
    Principal(PrincipalIncarnation),
    /// The non-authorizing kernel estate retains the obligation post mortem.
    KernelEstate,
    /// The estate has settled and released every physical claim.
    Released,
}

/// External commit state of one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitState {
    /// The effect exists but is not prepared.
    Registered,
    /// Resources are prepared but no external commit intent is durable.
    Prepared,
    /// A write-ahead external commit intent is durable.
    CommitIntentDurable,
    /// The external commit was acknowledged or conservatively reconstructed.
    Committed,
}

/// Knowledge of the externally visible effect outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeState {
    /// No terminal outcome is known.
    Pending,
    /// The effect completed successfully with the exact result digest.
    KnownSuccess(Digest),
    /// The effect completed with a known failure digest.
    KnownFailure(Digest),
    /// The result is unresolved and must be reconciled.
    Indeterminate(Digest),
}

/// Physical retirement state of an estate's claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementState {
    /// Claims exist but the effect has not crossed its commit boundary.
    Held,
    /// One or more claims await typed retirement evidence.
    RetirementPending,
    /// Every claim has been retired but the estate record remains.
    Retired,
    /// The terminal estate was explicitly released.
    Released,
}

/// Settlement state of one committed obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementState {
    /// Settlement is unavailable before a committed effect is fenced.
    Unavailable,
    /// This obligation class closes only through typed retirement evidence.
    NotRequired,
    /// Kernel custody permits one exact successor claim.
    Open {
        /// Monotonic claim generation.
        generation: u64,
    },
    /// A successor holds the settlement authority.
    Claimed {
        /// Exact claimant incarnation.
        claimant: PrincipalIncarnation,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// Publication or reconciliation intent is durable before external apply.
    ApplyIntentDurable {
        /// Exact claimant incarnation.
        claimant: PrincipalIncarnation,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// External apply happened but acknowledgement is not durably settled.
    AppliedUnacknowledged {
        /// Exact claimant incarnation.
        claimant: PrincipalIncarnation,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// A prior claimant crashed after a durable intent or apply.
    ReconciliationRequired {
        /// Monotonic claim generation available to the next claimant.
        generation: u64,
        /// Whether external apply was already observed.
        applied: bool,
    },
    /// The obligation was settled once.
    Settled,
    /// An uncommitted effect was revoked before adoption.
    ///
    /// Committed obligations never use this terminal state: revocation closes
    /// their successor authority while leaving Open/ReconciliationRequired in
    /// kernel custody.
    Revoked,
}

/// Recovery lane state for one causal root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRecoveryState {
    /// A live binding owns future authority.
    Active {
        /// Exact live incarnation.
        incarnation: PrincipalIncarnation,
        /// Exact binding generation.
        binding_generation: u64,
    },
    /// The previous binding is fenced and no snapshot is active.
    Fenced {
        /// Last fenced incarnation.
        crashed: PrincipalIncarnation,
        /// Last fenced binding generation.
        binding_generation: u64,
        /// Number of observed crashes for this root.
        crash_generation: u64,
    },
    /// A stable non-authorizing recovery snapshot exists.
    Snapshotted {
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Snapshot contents digest.
        digest: Digest,
    },
    /// A fresh incarnation declared itself ready for the exact snapshot.
    Ready {
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Ready successor incarnation.
        successor: PrincipalIncarnation,
    },
    /// The fresh incarnation is rebound but owns no old obligation implicitly.
    Rebound {
        /// Rebound successor incarnation.
        successor: PrincipalIncarnation,
        /// New binding generation.
        binding_generation: u64,
    },
    /// Crash fencing succeeded, but automatic recovery may not mint authority.
    ///
    /// Reaching this state is fail-closed: the dead incarnation and every
    /// estate are fenced, while snapshot/ready/rebind/adoption require an
    /// explicit operator recovery mechanism outside the automatic lane.
    RecoveryExhausted {
        /// Last incarnation whose authority was fenced.
        crashed: PrincipalIncarnation,
        /// Last binding generation whose authority was fenced.
        binding_generation: u64,
        /// Saturating number of observed crashes for this root.
        crash_generation: u64,
    },
}

/// Bounded capacity and pressure policy for one core instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreLimits {
    max_roots: usize,
    max_estates: usize,
    max_total_claims: usize,
    max_resource_records: usize,
    max_claims_per_estate: usize,
    max_units_per_account: u64,
    max_crashes_per_root: u64,
}

impl CoreLimits {
    /// Creates a non-zero bounded policy.
    pub const fn new(
        max_roots: usize,
        max_estates: usize,
        max_total_claims: usize,
        max_resource_records: usize,
        max_claims_per_estate: usize,
        max_units_per_account: u64,
        max_crashes_per_root: u64,
    ) -> Result<Self, CoreError> {
        if max_roots == 0
            || max_estates == 0
            || max_total_claims == 0
            || max_resource_records == 0
            || max_claims_per_estate == 0
            || max_units_per_account == 0
            || max_crashes_per_root == 0
        {
            return Err(CoreError::InvalidLimits);
        }
        Ok(Self {
            max_roots,
            max_estates,
            max_total_claims,
            max_resource_records,
            max_claims_per_estate,
            max_units_per_account,
            max_crashes_per_root,
        })
    }

    /// Returns a conservative test and single-service profile.
    pub const fn bounded_default() -> Self {
        Self {
            max_roots: 64,
            max_estates: 1024,
            max_total_claims: 4096,
            max_resource_records: 4096,
            max_claims_per_estate: 32,
            max_units_per_account: 1 << 20,
            max_crashes_per_root: 1024,
        }
    }
}

/// Exact configured identity of a trusted receipt verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierIdentity {
    verifier: VerifierId,
    epoch: u64,
    receipt_schema: ReceiptSchemaId,
}

impl VerifierIdentity {
    /// Creates one non-zero verifier incarnation and receipt schema.
    pub const fn new(
        verifier: VerifierId,
        epoch: u64,
        receipt_schema: ReceiptSchemaId,
    ) -> Result<Self, CoreError> {
        if epoch == 0 {
            Err(CoreError::InvalidPayload)
        } else {
            Ok(Self {
                verifier,
                epoch,
                receipt_schema,
            })
        }
    }

    /// Returns the verifier class.
    pub const fn verifier(self) -> VerifierId {
        self.verifier
    }

    /// Returns the exact verifier incarnation epoch.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the canonical receipt schema.
    pub const fn receipt_schema(self) -> ReceiptSchemaId {
        self.receipt_schema
    }
}

/// Read-only exact challenge passed to a configured domain verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceChallenge {
    effect: EffectId,
    claim: ClaimId,
    domain: DomainId,
    kind: EvidenceKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    subject: Freshness,
    current_observation: Freshness,
    expected_verifier: VerifierId,
    expected_receipt_schema: ReceiptSchemaId,
}

impl EvidenceChallenge {
    /// Returns the exact effect.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the exact claim.
    pub const fn claim(self) -> ClaimId {
        self.claim
    }

    /// Returns the domain schema.
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the evidence class.
    pub const fn kind(self) -> EvidenceKindId {
        self.kind
    }

    /// Returns the claim's logical or device scope.
    pub const fn scope(self) -> ClaimScope {
        self.scope
    }

    /// Returns the exact protected resource.
    pub const fn resource(self) -> ResourceId {
        self.resource
    }

    /// Returns the exact protected allocation generation.
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Returns the exact enrolled subject.
    pub const fn subject(self) -> Freshness {
        self.subject
    }

    /// Returns the current verifier context before applying the receipt.
    pub const fn current_observation(self) -> Freshness {
        self.current_observation
    }

    /// Returns the configured verifier class.
    pub const fn expected_verifier(self) -> VerifierId {
        self.expected_verifier
    }

    /// Returns the configured canonical receipt schema.
    pub const fn expected_receipt_schema(self) -> ReceiptSchemaId {
        self.expected_receipt_schema
    }
}

/// Canonical observation returned only through the configured verifier call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedObservation {
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
}

impl VerifiedObservation {
    /// Constructs the verifier's canonical interpretation of one raw receipt.
    pub const fn new(subject: Freshness, observation: Freshness, digest: Digest) -> Self {
        Self {
            subject,
            observation,
            digest,
        }
    }

    /// Returns the exact receipt subject.
    pub const fn subject(self) -> Freshness {
        self.subject
    }

    /// Returns the exact verifier observation.
    pub const fn observation(self) -> Freshness {
        self.observation
    }

    /// Returns the canonical receipt digest.
    pub const fn digest(self) -> Digest {
        self.digest
    }
}

/// Domain or platform verifier failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// The raw receipt did not verify against the exact challenge.
    Rejected,
}

/// Trusted adapter boundary which converts raw receipts into exact observations.
pub trait ReceiptVerifier {
    /// Domain-specific raw receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Verifies and canonicalizes one exact receipt challenge.
    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError>;
}

/// External effect fact verified at an exact core lifecycle stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectFactKind {
    /// Outcome of the write-ahead external commit operation.
    CommitOutcome,
    /// Completion of the durable settlement apply intent.
    ApplyCompleted,
    /// Final acknowledgement of an applied settlement.
    SettlementAcknowledged,
}

impl EffectFactKind {
    const fn tag(self) -> u8 {
        match self {
            Self::CommitOutcome => 1,
            Self::ApplyCompleted => 2,
            Self::SettlementAcknowledged => 3,
        }
    }
}

/// Non-indeterminate outcome established by an external commit verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalOutcome {
    /// The external commit completed successfully.
    Success,
    /// The external commit completed with a known failure.
    Failure,
}

/// Read-only exact challenge passed to an external effect-fact verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectFactChallenge {
    kind: EffectFactKind,
    effect: EffectId,
    domain: DomainId,
    obligation: ObligationKindId,
    actor: PrincipalIncarnation,
    generation: u64,
    nonce: u64,
    operation: Digest,
    predecessor: Option<Digest>,
    current_observation: Freshness,
    expected_verifier: VerifierId,
    expected_receipt_schema: ReceiptSchemaId,
}

impl EffectFactChallenge {
    /// Returns the exact fact stage.
    pub const fn kind(self) -> EffectFactKind {
        self.kind
    }

    /// Returns the exact effect.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the domain schema.
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the obligation class.
    pub const fn obligation(self) -> ObligationKindId {
        self.obligation
    }

    /// Returns the exact committing principal or settlement claimant.
    pub const fn actor(self) -> PrincipalIncarnation {
        self.actor
    }

    /// Returns the exact authority or settlement generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the core-minted one-shot nonce.
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Returns the durable operation or apply-intent digest.
    pub const fn operation(self) -> Digest {
        self.operation
    }

    /// Returns the preceding verified fact when the stage requires one.
    pub const fn predecessor(self) -> Option<Digest> {
        self.predecessor
    }

    /// Returns the exact verifier freshness context.
    pub const fn current_observation(self) -> Freshness {
        self.current_observation
    }

    /// Returns the configured verifier class.
    pub const fn expected_verifier(self) -> VerifierId {
        self.expected_verifier
    }

    /// Returns the configured canonical receipt schema.
    pub const fn expected_receipt_schema(self) -> ReceiptSchemaId {
        self.expected_receipt_schema
    }
}

/// Canonical effect-fact observation returned by a configured verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEffectObservation {
    freshness: Freshness,
    digest: Digest,
    outcome: Option<ExternalOutcome>,
}

impl VerifiedEffectObservation {
    /// Constructs a verified external commit outcome.
    pub const fn commit(freshness: Freshness, outcome: ExternalOutcome, digest: Digest) -> Self {
        Self {
            freshness,
            digest,
            outcome: Some(outcome),
        }
    }

    /// Constructs a verified apply or settlement acknowledgement.
    pub const fn fact(freshness: Freshness, digest: Digest) -> Self {
        Self {
            freshness,
            digest,
            outcome: None,
        }
    }

    /// Returns the exact verifier freshness context.
    pub const fn freshness(self) -> Freshness {
        self.freshness
    }

    /// Returns the canonical typed receipt digest.
    pub const fn digest(self) -> Digest {
        self.digest
    }

    /// Returns the known external commit outcome, when applicable.
    pub const fn outcome(self) -> Option<ExternalOutcome> {
        self.outcome
    }
}

/// Trusted adapter boundary for commit, apply, and settlement receipts.
pub trait EffectReceiptVerifier {
    /// Domain-specific raw receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Verifies and canonicalizes one exact effect-fact challenge.
    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError>;
}

/// Complete verifier provenance durably bound to one accepted fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierStamp {
    identity: VerifierIdentity,
    receipt_digest: Digest,
}

impl VerifierStamp {
    /// Returns the exact verifier identity and epoch.
    pub const fn identity(self) -> VerifierIdentity {
        self.identity
    }

    /// Returns the canonical receipt digest.
    pub const fn receipt_digest(self) -> Digest {
        self.receipt_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedEffectFact {
    kind: EffectFactKind,
    effect: EffectId,
    actor: PrincipalIncarnation,
    generation: u64,
    nonce: u64,
    operation: Digest,
    predecessor: Option<Digest>,
    freshness: Freshness,
    stamp: VerifierStamp,
    outcome: Option<ExternalOutcome>,
}

/// Non-forgeable verified outcome for one exact commit intent.
///
/// The tuple field is private, so an adapter cannot manufacture a verified
/// outcome without passing through [`Engine::verify_commit_outcome`].
///
/// ```compile_fail
/// use cser_core::VerifiedCommitOutcome;
///
/// fn forge() -> VerifiedCommitOutcome {
///     VerifiedCommitOutcome(())
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedCommitOutcome(VerifiedEffectFact);

/// Non-forgeable proof that one exact settlement apply intent completed.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedApplyReceipt(VerifiedEffectFact);

/// Non-forgeable final acknowledgement for one exact settlement claim.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedSettlementAck(VerifiedEffectFact);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementEvidence {
    kind: EvidenceKindId,
    subject: Freshness,
    freshness: Freshness,
    stamp: VerifierStamp,
}

/// Non-forgeable verified fact for one exact effect/claim pair.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedRetirementEvidence {
    effect: EffectId,
    claim: ClaimId,
    evidence: RetirementEvidence,
}

impl VerifiedRetirementEvidence {
    /// Consumes this verified fact into the only live evidence-ingress command.
    pub fn submit(self) -> Command {
        Command(CommandKind::SubmitEvidence {
            effect: self.effect,
            claim: self.claim,
            evidence: self.evidence,
        })
    }
}

/// Opaque authorized semantic command.
///
/// Sensitive commands are minted only by linear core descriptors, and the
/// resulting authority cannot be duplicated.
///
/// ```compile_fail
/// fn duplicate(command: cser_core::Command) {
///     let _copy = command.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn forge_snapshot() -> cser_core::Command {
///     cser_core::Command::Snapshot
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Command(CommandKind);

/// Replayable durable semantic command kind. This is never live ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommandKind {
    /// Creates one registered causal estate and its root if absent.
    CreateEstate {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact originating principal incarnation.
        origin: PrincipalIncarnation,
        /// Initial binding generation.
        binding_generation: u64,
        /// Domain defining the obligation.
        domain: DomainId,
        /// Domain-defined obligation class.
        obligation: ObligationKindId,
        /// Account charged for retained claims.
        charge_account: ChargeAccountId,
    },
    /// Adds one typed claim before effect preparation.
    AddClaim {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live principal requesting the enrollment.
        actor: PrincipalIncarnation,
        /// Exact live binding generation.
        binding_generation: u64,
        /// Stable claim identity.
        claim: ClaimId,
        /// Domain defining the claim.
        domain: DomainId,
        /// Domain-defined claim class.
        kind: ClaimKindId,
        /// Exact logical or device scope of this claim.
        scope: ClaimScope,
        /// Exact resource protected by the claim.
        resource: ResourceId,
        /// Exact allocation generation of the protected resource.
        resource_generation: ResourceGeneration,
        /// Conserved resource units.
        units: u64,
    },
    /// Freezes claim enrollment and prepares the effect.
    PrepareEffect {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live principal preparing the effect.
        actor: PrincipalIncarnation,
        /// Exact live binding generation.
        binding_generation: u64,
    },
    /// Durably records intent before an external commit point.
    RecordCommitIntent {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live principal crossing the commit gate.
        actor: PrincipalIncarnation,
        /// Exact live binding generation.
        binding_generation: u64,
        /// Digest of the external operation coordinates.
        operation: Digest,
    },
    /// Acknowledges the exact write-ahead commit intent.
    AcknowledgeCommit {
        /// Verifier-bound exact commit fact.
        fact: VerifiedEffectFact,
    },
    /// Fences one exact live incarnation and preserves committed estates.
    FenceIncarnation {
        /// Causal root being fenced.
        root: RootId,
        /// Exact crashed incarnation.
        crashed: PrincipalIncarnation,
        /// Exact old binding generation.
        binding_generation: u64,
    },
    /// Captures a stable, non-authorizing recovery snapshot.
    Snapshot {
        /// Causal root being recovered.
        root: RootId,
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Digest of the complete snapshot projection.
        digest: Digest,
    },
    /// Marks a fresh incarnation ready for an exact snapshot.
    Ready {
        /// Causal root being recovered.
        root: RootId,
        /// Exact snapshot identity.
        snapshot: SnapshotId,
        /// Fresh successor incarnation.
        successor: PrincipalIncarnation,
    },
    /// Installs a fresh binding without implicitly adopting any effect.
    Rebind {
        /// Causal root being recovered.
        root: RootId,
        /// Exact snapshot identity.
        snapshot: SnapshotId,
        /// Fresh successor incarnation.
        successor: PrincipalIncarnation,
        /// New binding generation.
        binding_generation: u64,
    },
    /// Explicitly transfers one uncommitted orphan into successor custody.
    AdoptEffect {
        /// Stable orphan effect identity.
        effect: EffectId,
        /// Exact rebound successor incarnation.
        successor: PrincipalIncarnation,
        /// Exact rebound binding generation.
        binding_generation: u64,
    },
    /// Claims one exact committed obligation for settlement.
    ClaimSettlement {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact rebound claimant.
        claimant: PrincipalIncarnation,
    },
    /// Durably records settlement intent before publication or reconciliation.
    RecordApplyIntent {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact claimant incarnation.
        claimant: PrincipalIncarnation,
        /// Claim generation.
        generation: u64,
        /// Secret one-shot nonce.
        nonce: u64,
        /// Digest of the intended external action.
        intent: Digest,
    },
    /// Records that the exact durable intent was externally applied.
    RecordApplied {
        /// Verifier-bound exact apply-completion fact.
        fact: VerifiedEffectFact,
    },
    /// Durably settles an externally applied obligation.
    Settle {
        /// Verifier-bound exact settlement acknowledgement.
        fact: VerifiedEffectFact,
    },
    /// Closes settlement honestly with an indeterminate result.
    MarkIndeterminate {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact claimant incarnation.
        claimant: PrincipalIncarnation,
        /// Claim generation.
        generation: u64,
        /// Secret one-shot nonce.
        nonce: u64,
        /// Digest describing the unresolved outcome.
        reason: Digest,
    },
    /// Revokes one exact observed authority epoch.
    ///
    /// For a committed effect this closes successor authority without
    /// terminalizing its settlement or reconciliation obligation.
    BeginRevoke {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live root actor authorizing this revoke attempt.
        expected_actor: PrincipalIncarnation,
        /// Exact live root binding authorizing this revoke attempt.
        binding_generation: u64,
        /// Exact estate authority epoch observed before the race.
        authority_epoch: u64,
    },
    /// Submits typed, freshness-bound evidence for one exact resource claim.
    SubmitEvidence {
        /// Stable effect identity.
        effect: EffectId,
        /// Stable claim identity.
        claim: ClaimId,
        /// Typed retirement evidence.
        evidence: RetirementEvidence,
    },
    /// Establishes a fresh boot and reclaims authority from the prior boot.
    CheckpointRecovery {
        /// Fresh boot generation.
        boot: BootGeneration,
        /// Fresh journal generation.
        journal: JournalGeneration,
        /// Device generation observed behind boot quarantine.
        device: DeviceGeneration,
    },
    /// Releases a settled, fully retired estate record.
    ReleaseEstate {
        /// Stable effect identity.
        effect: EffectId,
    },
    /// Durably reserves the next allocation generation after exact retirement.
    ReserveReuse {
        /// Estate which will retain the new generation before hardware use.
        effect: EffectId,
        /// Exact live principal requesting the reuse reservation.
        actor: PrincipalIncarnation,
        /// Exact live binding generation.
        binding_generation: u64,
        /// Stable claim identity for the new allocation generation.
        claim: ClaimId,
        /// Domain defining the claim.
        domain: DomainId,
        /// Domain-defined claim class.
        kind: ClaimKindId,
        /// Exact logical or device scope of the new claim.
        scope: ClaimScope,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact retired generation which is being advanced.
        expected_generation: ResourceGeneration,
        /// Conserved resource units retained before hardware reuse.
        units: u64,
    },
    /// Consumes one exact durable reservation before external resource reuse.
    #[non_exhaustive]
    ActivateResourceReuse {
        /// Estate retaining the resource before external reuse.
        effect: EffectId,
        /// Exact principal incarnation which received the bearer.
        actor: PrincipalIncarnation,
        /// Exact binding generation which received the bearer.
        binding_generation: u64,
        /// Exact estate authority epoch which received the bearer.
        authority_epoch: u64,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact reserved allocation generation.
        resource_generation: ResourceGeneration,
        /// One-shot reservation nonce.
        nonce: u64,
        /// Freshness coordinates at reservation time.
        freshness: Freshness,
    },
    /// Reissues a pending reuse bearer only after explicit effect adoption.
    ReclaimResourceReuse {
        /// Adopted estate retaining the resource.
        effect: EffectId,
        /// Exact live successor incarnation.
        actor: PrincipalIncarnation,
        /// Exact live successor binding generation.
        binding_generation: u64,
        /// Exact adopted estate authority epoch.
        authority_epoch: u64,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact pending allocation generation.
        resource_generation: ResourceGeneration,
    },
}

/// Untrusted live request surface. Receipt-dependent transitions are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRequest {
    /// Registers one causal estate.
    CreateEstate {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact originating principal incarnation.
        origin: PrincipalIncarnation,
        /// Exact live binding generation.
        binding_generation: u64,
        /// Domain schema.
        domain: DomainId,
        /// Obligation class.
        obligation: ObligationKindId,
        /// Retained-resource charge account.
        charge_account: ChargeAccountId,
    },
    /// Enrolls one resource claim before preparation.
    AddClaim {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live actor.
        actor: PrincipalIncarnation,
        /// Exact live binding.
        binding_generation: u64,
        /// Stable claim identity.
        claim: ClaimId,
        /// Domain schema.
        domain: DomainId,
        /// Claim class.
        kind: ClaimKindId,
        /// Logical or device scope.
        scope: ClaimScope,
        /// Stable protected resource.
        resource: ResourceId,
        /// Exact allocation generation.
        resource_generation: ResourceGeneration,
        /// Conserved units.
        units: u64,
    },
    /// Freezes claim enrollment and prepares an effect.
    PrepareEffect {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live actor.
        actor: PrincipalIncarnation,
        /// Exact live binding.
        binding_generation: u64,
    },
    /// Records write-ahead intent before an external commit.
    RecordCommitIntent {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact live actor.
        actor: PrincipalIncarnation,
        /// Exact live binding.
        binding_generation: u64,
        /// Exact external operation coordinates.
        operation: Digest,
    },
    /// Requests an immediate fence of one exact incarnation.
    FenceIncarnation {
        /// Causal root.
        root: RootId,
        /// Exact crashed incarnation.
        crashed: PrincipalIncarnation,
        /// Exact old binding.
        binding_generation: u64,
    },
    /// Marks a successor ready for one exact snapshot.
    Ready {
        /// Causal root.
        root: RootId,
        /// Exact snapshot.
        snapshot: SnapshotId,
        /// Fresh successor.
        successor: PrincipalIncarnation,
    },
    /// Installs one fresh binding without implicit adoption.
    Rebind {
        /// Causal root.
        root: RootId,
        /// Exact snapshot.
        snapshot: SnapshotId,
        /// Fresh successor.
        successor: PrincipalIncarnation,
        /// Fresh binding generation.
        binding_generation: u64,
    },
    /// Requests explicit adoption of one uncommitted orphan.
    AdoptEffect {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact rebound successor.
        successor: PrincipalIncarnation,
        /// Exact rebound binding.
        binding_generation: u64,
    },
    /// Requests a one-shot settlement claim.
    ClaimSettlement {
        /// Stable committed effect.
        effect: EffectId,
        /// Exact live claimant.
        claimant: PrincipalIncarnation,
    },
    /// Races revocation against adoption or settlement.
    BeginRevoke {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact observed live actor.
        expected_actor: PrincipalIncarnation,
        /// Exact observed binding.
        binding_generation: u64,
        /// Exact observed authority epoch.
        authority_epoch: u64,
    },
    /// Commits a fresh boot/journal recovery checkpoint.
    CheckpointRecovery {
        /// Fresh boot generation.
        boot: BootGeneration,
        /// Fresh journal generation.
        journal: JournalGeneration,
        /// Observed base device generation.
        device: DeviceGeneration,
    },
    /// Releases a terminal, fully retired estate.
    ReleaseEstate {
        /// Stable effect identity.
        effect: EffectId,
    },
    /// Reserves and retains the next resource allocation generation.
    ReserveReuse {
        /// Estate retaining the new claim.
        effect: EffectId,
        /// Exact live actor.
        actor: PrincipalIncarnation,
        /// Exact live binding.
        binding_generation: u64,
        /// Stable new claim identity.
        claim: ClaimId,
        /// Domain schema.
        domain: DomainId,
        /// Claim class.
        kind: ClaimKindId,
        /// Logical or device scope.
        scope: ClaimScope,
        /// Stable protected resource.
        resource: ResourceId,
        /// Exact retired allocation generation.
        expected_generation: ResourceGeneration,
        /// Conserved units retained before external reuse.
        units: u64,
    },
}

impl From<CommandRequest> for Command {
    fn from(request: CommandRequest) -> Self {
        Self(match request {
            CommandRequest::CreateEstate {
                effect,
                origin,
                binding_generation,
                domain,
                obligation,
                charge_account,
            } => CommandKind::CreateEstate {
                effect,
                origin,
                binding_generation,
                domain,
                obligation,
                charge_account,
            },
            CommandRequest::AddClaim {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            } => CommandKind::AddClaim {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            },
            CommandRequest::PrepareEffect {
                effect,
                actor,
                binding_generation,
            } => CommandKind::PrepareEffect {
                effect,
                actor,
                binding_generation,
            },
            CommandRequest::RecordCommitIntent {
                effect,
                actor,
                binding_generation,
                operation,
            } => CommandKind::RecordCommitIntent {
                effect,
                actor,
                binding_generation,
                operation,
            },
            CommandRequest::FenceIncarnation {
                root,
                crashed,
                binding_generation,
            } => CommandKind::FenceIncarnation {
                root,
                crashed,
                binding_generation,
            },
            CommandRequest::Ready {
                root,
                snapshot,
                successor,
            } => CommandKind::Ready {
                root,
                snapshot,
                successor,
            },
            CommandRequest::Rebind {
                root,
                snapshot,
                successor,
                binding_generation,
            } => CommandKind::Rebind {
                root,
                snapshot,
                successor,
                binding_generation,
            },
            CommandRequest::AdoptEffect {
                effect,
                successor,
                binding_generation,
            } => CommandKind::AdoptEffect {
                effect,
                successor,
                binding_generation,
            },
            CommandRequest::ClaimSettlement { effect, claimant } => {
                CommandKind::ClaimSettlement { effect, claimant }
            }
            CommandRequest::BeginRevoke {
                effect,
                expected_actor,
                binding_generation,
                authority_epoch,
            } => CommandKind::BeginRevoke {
                effect,
                expected_actor,
                binding_generation,
                authority_epoch,
            },
            CommandRequest::CheckpointRecovery {
                boot,
                journal,
                device,
            } => CommandKind::CheckpointRecovery {
                boot,
                journal,
                device,
            },
            CommandRequest::ReleaseEstate { effect } => CommandKind::ReleaseEstate { effect },
            CommandRequest::ReserveReuse {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                expected_generation,
                units,
            } => CommandKind::ReserveReuse {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                expected_generation,
                units,
            },
        })
    }
}

/// Exact write-ahead external commit authority.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitIntent {
    effect: EffectId,
    nonce: u64,
}

impl CommitIntent {
    /// Returns the committed effect identity.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Consumes the intent with a verifier-bound exact external outcome.
    pub fn acknowledge(self, outcome: VerifiedCommitOutcome) -> Result<Command, CommitUseError> {
        let fact = outcome.0;
        if fact.kind != EffectFactKind::CommitOutcome
            || fact.effect != self.effect
            || fact.nonce != self.nonce
        {
            return Err(CommitUseError {
                error: CoreError::StaleCommitIntent,
                intent: self,
            });
        }
        Ok(Command(CommandKind::AcknowledgeCommit { fact }))
    }
}

/// A rejected local commit acknowledgement which preserves the linear intent.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitUseError {
    error: CoreError,
    intent: CommitIntent,
}

impl CommitUseError {
    /// Returns the semantic reason the local use was rejected.
    pub const fn error(&self) -> &CoreError {
        &self.error
    }

    /// Recovers the still-valid commit intent.
    pub fn into_intent(self) -> CommitIntent {
        self.intent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimStage {
    Fresh,
    Intent,
    Applied,
    ReconcileIntent,
    ReconcileApplied,
}

/// Non-cloneable one-shot settlement authority for one exact effect.
#[derive(Debug, Eq, PartialEq)]
pub struct SettlementClaim {
    effect: EffectId,
    claimant: PrincipalIncarnation,
    generation: u64,
    nonce: u64,
    stage: ClaimStage,
}

/// A rejected local settlement operation that preserves the linear claim.
#[derive(Debug, Eq, PartialEq)]
pub struct ClaimUseError {
    error: CoreError,
    claim: SettlementClaim,
}

impl ClaimUseError {
    /// Returns the semantic reason the operation was rejected.
    pub const fn error(&self) -> &CoreError {
        &self.error
    }

    /// Recovers the still-valid claim for a different legal operation.
    pub fn into_claim(self) -> SettlementClaim {
        self.claim
    }
}

impl SettlementClaim {
    /// Returns the exact claimed effect.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Returns the exact claimant.
    pub const fn claimant(&self) -> PrincipalIncarnation {
        self.claimant
    }

    /// Returns the monotonic settlement-claim generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Consumes a fresh claim to create a durable external apply intent.
    pub fn record_apply_intent(self, intent: Digest) -> Result<Command, ClaimUseError> {
        if self.stage != ClaimStage::Fresh {
            return Err(ClaimUseError {
                error: CoreError::WrongSettlementStage,
                claim: self,
            });
        }
        Ok(Command(CommandKind::RecordApplyIntent {
            effect: self.effect,
            claimant: self.claimant,
            generation: self.generation,
            nonce: self.nonce,
            intent,
        }))
    }

    /// Consumes an intent-stage claim after exact external reconciliation.
    pub fn record_applied(self, evidence: VerifiedApplyReceipt) -> Result<Command, ClaimUseError> {
        if !matches!(self.stage, ClaimStage::Intent | ClaimStage::ReconcileIntent) {
            return Err(ClaimUseError {
                error: CoreError::WrongSettlementStage,
                claim: self,
            });
        }
        let fact = evidence.0;
        if fact.kind != EffectFactKind::ApplyCompleted
            || fact.effect != self.effect
            || fact.actor != self.claimant
            || fact.generation != self.generation
            || fact.nonce != self.nonce
        {
            return Err(ClaimUseError {
                error: CoreError::StaleSettlementClaim,
                claim: self,
            });
        }
        Ok(Command(CommandKind::RecordApplied { fact }))
    }

    /// Consumes an applied-stage claim to durably settle once.
    pub fn settle(self, acknowledgement: VerifiedSettlementAck) -> Result<Command, ClaimUseError> {
        if !matches!(
            self.stage,
            ClaimStage::Applied | ClaimStage::ReconcileApplied
        ) {
            return Err(ClaimUseError {
                error: CoreError::WrongSettlementStage,
                claim: self,
            });
        }
        let fact = acknowledgement.0;
        if fact.kind != EffectFactKind::SettlementAcknowledged
            || fact.effect != self.effect
            || fact.actor != self.claimant
            || fact.generation != self.generation
            || fact.nonce != self.nonce
        {
            return Err(ClaimUseError {
                error: CoreError::StaleSettlementClaim,
                claim: self,
            });
        }
        Ok(Command(CommandKind::Settle { fact }))
    }

    /// Consumes any live claim and records an honest indeterminate outcome.
    pub fn mark_indeterminate(self, reason: Digest) -> Command {
        Command(CommandKind::MarkIndeterminate {
            effect: self.effect,
            claimant: self.claimant,
            generation: self.generation,
            nonce: self.nonce,
            reason,
        })
    }
}

/// Non-cloneable bearer for one durably retained resource-generation reservation.
#[derive(Debug, Eq, PartialEq)]
pub struct ReusePermit {
    effect: EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    authority_epoch: u64,
    resource: ResourceId,
    generation: ResourceGeneration,
    freshness: Freshness,
    nonce: u64,
}

impl ReusePermit {
    /// Returns the reusable resource.
    pub const fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Returns the estate retaining the resource.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Returns the exact newly reserved allocation generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Returns the exact freshness coordinates at authorization.
    pub const fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// Consumes this bearer into a durable activation command. The external
    /// allocator must not reuse the resource until that command commits.
    pub fn activate(self) -> Command {
        Command(CommandKind::ActivateResourceReuse {
            effect: self.effect,
            actor: self.actor,
            binding_generation: self.binding_generation,
            authority_epoch: self.authority_epoch,
            resource: self.resource,
            resource_generation: self.generation,
            nonce: self.nonce,
            freshness: self.freshness,
        })
    }
}

/// Normalized semantic event emitted by a successful transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionEvent {
    /// A causal estate was created.
    EstateCreated,
    /// A typed resource claim was enrolled.
    ClaimAdded,
    /// An effect was prepared.
    EffectPrepared,
    /// A write-ahead commit intent became durable.
    CommitIntentDurable,
    /// An external commit was acknowledged.
    EffectCommitted,
    /// A live incarnation was fenced.
    IncarnationFenced,
    /// A recovery snapshot was captured.
    Snapshot,
    /// A successor became ready.
    Ready,
    /// A successor binding was installed.
    Rebound,
    /// One exact uncommitted orphan was explicitly adopted.
    EffectAdopted,
    /// A settlement claim was minted.
    SettlementClaimed,
    /// A settlement apply intent became durable.
    ApplyIntentDurable,
    /// External settlement apply was recorded.
    AppliedUnacknowledged,
    /// An obligation was settled.
    Settled,
    /// An indeterminate outcome was materialized.
    Indeterminate,
    /// Revocation won the exact authority gate.
    Revoked,
    /// Typed retirement evidence was accepted.
    EvidenceAccepted,
    /// A fresh boot recovery checkpoint was made durable.
    RecoveryCheckpointed,
    /// The next allocation generation of a retired resource was reserved.
    ResourceReuseReserved,
    /// A pending reuse bearer was reissued to an explicitly adopted successor.
    ResourceReuseReclaimed,
    /// The exact durable reuse bearer was consumed before external use.
    ResourceReuseActivated,
    /// A fully retired estate was released.
    EstateReleased,
}

/// Linear authority returned by a successful transition.
#[derive(Debug, Eq, PartialEq)]
pub enum TransitionOutput {
    /// The transition returns no bearer authority.
    None,
    /// A write-ahead external commit intent.
    CommitIntent(CommitIntent),
    /// A one-shot settlement claim or its next durable stage.
    SettlementClaim(SettlementClaim),
    /// A durable, one-shot resource-generation reservation.
    ReusePermit(ReusePermit),
}

/// Receipt for one durably committed semantic transition.
#[derive(Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    revision: u64,
    head: Digest,
    projection: Digest,
    event: TransitionEvent,
    output: TransitionOutput,
}

impl TransitionReceipt {
    /// Returns the new journal revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the new journal head digest.
    pub const fn head(&self) -> Digest {
        self.head
    }

    /// Returns the complete deterministic projection digest.
    pub const fn projection(&self) -> Digest {
        self.projection
    }

    /// Returns the normalized transition event.
    pub const fn event(&self) -> TransitionEvent {
        self.event
    }

    /// Consumes the receipt and returns its linear output.
    pub fn into_output(self) -> TransitionOutput {
        self.output
    }
}

/// Public projection of one causal estate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstateProjection {
    /// Stable effect identity.
    pub effect: EffectId,
    /// Immutable originating incarnation.
    pub causal_owner: PrincipalIncarnation,
    /// Current live principal or non-authorizing kernel custodian.
    pub custodian: CustodyState,
    /// Account still charged for retained resources.
    pub charge_owner: ChargeAccountId,
    /// Domain-defined obligation class.
    pub obligation: (DomainId, ObligationKindId),
    /// Domain-selected lifecycle enforced for this obligation.
    pub obligation_policy: ObligationPolicy,
    /// Current authority state.
    pub authority: AuthorityState,
    /// Monotonic epoch of the estate authority gate.
    ///
    /// Revocation commands bind this value so a command prepared before an
    /// adoption or fence cannot revoke the newly installed authority.
    pub authority_epoch: u64,
    /// Current commit state.
    pub commit: CommitState,
    /// Current outcome knowledge.
    pub outcome: OutcomeState,
    /// Current settlement state.
    pub settlement: SettlementState,
    /// Current physical retirement state.
    pub retirement: RetirementState,
    /// Total claim count.
    pub claim_count: usize,
    /// Claims still retaining resources.
    pub retained_claims: usize,
}

/// Public, non-authorizing projection of one domain-defined resource claim.
///
/// This is the boot-recovery enumeration surface.  It contains enough exact
/// identity to challenge a platform verifier after replay, but no release,
/// reuse, adoption, or settlement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProjection {
    /// Estate which owns the claim.
    pub effect: EffectId,
    /// Stable claim identity within the estate.
    pub claim: ClaimId,
    /// Domain which defined the claim lifecycle.
    pub domain: DomainId,
    /// Domain-defined claim class.
    pub kind: ClaimKindId,
    /// Conserved credit class charged while the claim is retained.
    pub credit_class: CreditClassId,
    /// Logical or exact device scope.
    pub scope: ClaimScope,
    /// Concrete resource identity protected from premature reuse.
    pub resource: ResourceId,
    /// Generation of the protected resource.
    pub resource_generation: ResourceGeneration,
    /// Conserved units charged to the estate.
    pub units: u64,
    /// Freshness under which the claim was enrolled.
    pub enrolled_freshness: Freshness,
    /// Whether every configured retirement requirement has been accepted.
    pub retired: bool,
}

/// One estate in a core-generated recovery cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryItem {
    /// Stable effect identity.
    pub effect: EffectId,
    /// Current non-authorizing custodian.
    pub custodian: CustodyState,
    /// Domain-defined obligation class.
    pub obligation: (DomainId, ObligationKindId),
    /// Current authority state.
    pub authority: AuthorityState,
    /// Exact authority epoch observed by the snapshot.
    pub authority_epoch: u64,
    /// Current external commit state.
    pub commit: CommitState,
    /// Current outcome knowledge.
    pub outcome: OutcomeState,
    /// Current successor-settlement state.
    pub settlement: SettlementState,
    /// Current physical-retirement state.
    pub retirement: RetirementState,
    /// Total claim count.
    pub claim_count: usize,
    /// Claims which still retain resources.
    pub retained_claims: usize,
    /// Whether this exact estate may be explicitly execution-adopted.
    pub adoptable: bool,
    /// Whether this exact estate carries a live successor-settlement duty.
    pub settlement_required: bool,
}

/// Exact, non-authorizing recovery cohort generated from core state.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    root: RootId,
    snapshot: SnapshotId,
    digest: Digest,
    covered_revision: u64,
    covered_head: Digest,
    items: Vec<RecoveryItem>,
}

impl RecoverySnapshot {
    /// Returns the causal root covered by this snapshot.
    pub const fn root(&self) -> RootId {
        self.root
    }

    /// Returns the stable snapshot identity.
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the core-generated complete cohort digest.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the journal revision covered by the cohort.
    pub const fn covered_revision(&self) -> u64 {
        self.covered_revision
    }

    /// Returns the journal head covered by the cohort.
    pub const fn covered_head(&self) -> Digest {
        self.covered_head
    }

    /// Returns the ordered estate cohort.
    pub fn items(&self) -> &[RecoveryItem] {
        &self.items
    }

    /// Consumes the descriptor into the only command which can record this
    /// exact snapshot. The transition still rejects if state changed.
    pub fn record(self) -> Command {
        Command(CommandKind::Snapshot {
            root: self.root,
            snapshot: self.snapshot,
            digest: self.digest,
        })
    }
}

/// Per-account retained charging projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargeProjection {
    /// Charged account.
    pub account: ChargeAccountId,
    /// Independently conserved credit class.
    pub class: CreditClassId,
    /// Retained resource units.
    pub retained_units: u64,
}

/// Bounded pressure projection for observability and admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PressureProjection {
    /// Number of causal roots.
    pub roots: usize,
    /// Number of estate records.
    pub estates: usize,
    /// Number of retained claims.
    pub retained_claims: usize,
    /// Whether boot or corruption quarantine blocks resource reuse.
    pub quarantined: bool,
    /// Whether an ambiguous persistence failure requires journal recovery.
    pub persistence_recovery_required: bool,
}

/// Failure while constructing a structurally valid trusted recovery anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAnchorError {
    /// The catalog used the reserved zero digest.
    ZeroDigest,
    /// Revision zero and the zero head must be presented together.
    InconsistentGenesis,
    /// The committed and next epochs name different Registry instances.
    RegistryMismatch,
    /// Recovery cannot silently change the active principal-binding epoch.
    BindingMismatch,
    /// The next boot, journal, or device epoch is stale or rolled back.
    NonAdvancingEpoch,
}

/// Trusted, non-optional anchor used to recover one exact journal prefix.
///
/// The caller must obtain all fields atomically from a freshness provider that
/// cannot be rolled back with the journal storage. Constructing this value
/// checks its internal epoch relationship; it does not make rollbackable bytes
/// trustworthy.
///
/// Recovery anchors are consumed and deliberately cannot be cloned.
///
/// ```compile_fail
/// fn duplicate(anchor: cser_core::RecoveryAnchor) {
///     let _copy = anchor.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryAnchor {
    catalog_digest: Digest,
    committed_freshness: Freshness,
    next_freshness: Freshness,
    minimum_revision: u64,
    expected_head: Digest,
}

impl RecoveryAnchor {
    /// Creates an exact, single-use recovery anchor from a trusted provider.
    ///
    /// Calling this constructor is an explicit assertion that the fields were
    /// read atomically from storage which cannot be rolled back with the
    /// journal.
    pub const fn from_trusted_provider(
        catalog_digest: Digest,
        committed_freshness: Freshness,
        next_freshness: Freshness,
        minimum_revision: u64,
        expected_head: Digest,
    ) -> Result<Self, RecoveryAnchorError> {
        if catalog_digest.is_zero() {
            return Err(RecoveryAnchorError::ZeroDigest);
        }
        if (minimum_revision == 0) != expected_head.is_zero() {
            return Err(RecoveryAnchorError::InconsistentGenesis);
        }
        if committed_freshness.registry().get() != next_freshness.registry().get() {
            return Err(RecoveryAnchorError::RegistryMismatch);
        }
        if committed_freshness.binding() != next_freshness.binding() {
            return Err(RecoveryAnchorError::BindingMismatch);
        }
        if next_freshness.boot().get() <= committed_freshness.boot().get()
            || next_freshness.journal().get() <= committed_freshness.journal().get()
            || next_freshness.device().get() < committed_freshness.device().get()
        {
            return Err(RecoveryAnchorError::NonAdvancingEpoch);
        }
        Ok(Self {
            catalog_digest,
            committed_freshness,
            next_freshness,
            minimum_revision,
            expected_head,
        })
    }

    /// Returns the catalog schema digest protected by the anchor.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the exact freshness epoch of the acknowledged journal tip.
    pub const fn committed_freshness(&self) -> Freshness {
        self.committed_freshness
    }

    /// Returns the fresh epoch to install after exact replay.
    pub const fn next_freshness(&self) -> Freshness {
        self.next_freshness
    }

    /// Returns the minimum acknowledged journal revision.
    pub const fn minimum_revision(&self) -> u64 {
        self.minimum_revision
    }

    /// Returns the exact acknowledged journal head.
    pub const fn expected_head(&self) -> Digest {
        self.expected_head
    }
}

/// Recovered engine and exact journal-boundary observations.
#[derive(Debug)]
pub struct RecoveryReport {
    engine: Engine,
    acknowledged_revision: u64,
    acknowledged_head: Digest,
    journal_repair: Option<JournalRepair>,
}

impl RecoveryReport {
    /// Consumes the report and returns the recovered authoritative engine.
    pub fn into_engine(self) -> Engine {
        self.engine
    }

    /// Returns the acknowledged prefix revision.
    pub const fn acknowledged_revision(&self) -> u64 {
        self.acknowledged_revision
    }

    /// Returns the acknowledged prefix head.
    pub const fn acknowledged_head(&self) -> Digest {
        self.acknowledged_head
    }

    /// Returns the byte offset of an ignored incomplete final record.
    pub const fn torn_tail(&self) -> Option<usize> {
        match self.journal_repair {
            Some(JournalRepair::TornTail { offset }) => Some(offset),
            Some(JournalRepair::UnanchoredSuffix { .. }) | None => None,
        }
    }

    /// Returns the exact storage repair required before another append.
    pub const fn journal_repair(&self) -> Option<JournalRepair> {
        self.journal_repair
    }
}

/// Failure returned by the authoritative state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    /// At least one limit is zero.
    InvalidLimits,
    /// A generation or nonce overflowed.
    GenerationExhausted,
    /// A declared obligation class is unknown.
    UnknownObligationClass,
    /// A declared claim class is unknown.
    UnknownClaimClass,
    /// The effect already exists.
    DuplicateEstate,
    /// The effect does not exist.
    UnknownEstate,
    /// The claim already exists.
    DuplicateClaim,
    /// The claim does not exist.
    UnknownClaim,
    /// The obligation contract does not permit this claim class.
    ClaimNotAllowed,
    /// Required or maximum claim cardinality is not satisfied.
    ClaimCardinalityViolation,
    /// The obligation contract forbids successor execution adoption.
    AdoptionForbidden,
    /// A claim or resource was presented in the wrong logical/device scope.
    WrongClaimScope,
    /// The root does not exist.
    UnknownRoot,
    /// A root or estate capacity would be exceeded.
    CapacityExceeded,
    /// A per-account retained-unit limit would be exceeded.
    Backpressure,
    /// The requested operation is invalid for the current commit state.
    WrongCommitState,
    /// The requested operation is invalid for the current settlement stage.
    WrongSettlementStage,
    /// The recovery lane is in the wrong phase.
    WrongRecoveryState,
    /// The presented incarnation or binding is stale.
    StaleIncarnation,
    /// The presented estate authority epoch is stale.
    StaleAuthorityEpoch,
    /// The presented snapshot is not exact.
    StaleSnapshot,
    /// Revocation or another claimant already closed the gate.
    GateClosed,
    /// A live settlement claim won before revocation.
    GateClaimed,
    /// A claim token does not match the authoritative state.
    StaleSettlementClaim,
    /// A commit intent does not match the authoritative state.
    StaleCommitIntent,
    /// The evidence class is not required by the claim.
    UnexpectedEvidence,
    /// The evidence was already accepted.
    DuplicateEvidence,
    /// A declared predecessor receipt has not yet been accepted.
    EvidenceOutOfOrder,
    /// Evidence freshness does not match the exact active generations.
    StaleEvidence,
    /// The configured verifier class is absent or does not match the rule.
    UnknownVerifier,
    /// The verifier incarnation is stale.
    StaleVerifierEpoch,
    /// The verifier uses a different canonical receipt schema.
    ReceiptSchemaMismatch,
    /// The configured verifier rejected the raw receipt.
    VerificationFailed,
    /// A device reset receipt attempted to skip or roll back a generation.
    InvalidDeviceGenerationAdvance,
    /// Zero resource units or a zero digest was supplied where forbidden.
    InvalidPayload,
    /// Recovery must be checkpointed before ordinary transitions.
    RecoveryPending,
    /// A failed append or barrier may already have made its record durable.
    PersistenceRecoveryRequired,
    /// A recovered torn journal tail must be repaired and recovered again.
    JournalRepairRequired,
    /// Automatic recovery authority is exhausted and requires operator action.
    RecoveryExhausted,
    /// Resource reuse remains blocked by boot quarantine.
    Quarantined,
    /// The resource still has at least one retained claim.
    ResourceRetained,
    /// The resource has never been enrolled.
    UnknownResource,
    /// A retired resource requires a durable reuse reservation.
    ResourceReuseRequired,
    /// A resource allocation generation is not exact.
    StaleResourceGeneration,
    /// A resource reuse reservation is already outstanding.
    ReuseAlreadyReserved,
    /// A resource reuse permit does not match the durable reservation.
    StaleReusePermit,
    /// The estate is not settled and fully retired.
    EstateNotReleasable,
    /// Journal replay detected a revision conflict.
    RevisionConflict,
    /// Journal replay detected a broken predecessor chain.
    PredecessorMismatch,
    /// Journal records bind a different catalog or Registry.
    SchemaMismatch,
    /// A trusted freshness anchor is stale or rolled back.
    FreshnessRollback,
    /// An external expected head or minimum revision was not present.
    RollbackDetected,
    /// A deterministic internal invariant failed.
    InvariantViolation,
    /// Journal encoding or decoding failed.
    Journal(JournalDecodeError),
}

/// Failure while executing a durable transition.
#[derive(Debug, Eq, PartialEq)]
pub enum TxError<E> {
    /// The semantic transition was rejected before persistence.
    Core(CoreError),
    /// The journal record could not be encoded.
    Journal(JournalDecodeError),
    /// The persistence provider rejected or failed the append/barrier.
    Persist(E),
}

/// Marker used by adapters which erase their persistence error type.
pub trait JournalFailure: core::fmt::Debug + Eq {}

impl<T> JournalFailure for T where T: core::fmt::Debug + Eq {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootRecord {
    origin: PrincipalIncarnation,
    state: RootRecoveryState,
    last_binding_generation: u64,
    last_incarnation_generation: u64,
    crash_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequirementState {
    kind: EvidenceKindId,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    subject_freshness: FreshnessAxes,
    observation_freshness: FreshnessAxes,
    strictly_advanced: FreshnessAxes,
    device_generation: DeviceGenerationEffect,
    prerequisite: Option<EvidenceKindId>,
    accepted: Option<AcceptedEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedEvidence {
    subject: Freshness,
    observation: Freshness,
    stamp: VerifierStamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClaimRecord {
    id: ClaimId,
    domain: DomainId,
    kind: ClaimKindId,
    credit_class: CreditClassId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    enrolled_freshness: Freshness,
    requirements: Vec<RequirementState>,
    retired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingReuse {
    effect: EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    authority_epoch: u64,
    nonce: u64,
    freshness: Freshness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourcePhase {
    Claimed { pending_reuse: Option<PendingReuse> },
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceRecord {
    scope: ClaimScope,
    generation: ResourceGeneration,
    phase: ResourcePhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EstateRecord {
    effect: EffectId,
    causal_owner: PrincipalIncarnation,
    custodian: CustodyState,
    charge_owner: ChargeAccountId,
    domain: DomainId,
    obligation: ObligationKindId,
    obligation_policy: ObligationPolicy,
    authority: AuthorityState,
    authority_epoch: u64,
    commit: CommitState,
    commit_nonce: Option<u64>,
    commit_operation: Option<Digest>,
    commit_fact: Option<VerifiedEffectFact>,
    outcome: OutcomeState,
    settlement: SettlementState,
    settlement_nonce: Option<u64>,
    claim_stage: Option<ClaimStage>,
    settlement_intent: Option<Digest>,
    applied_fact: Option<VerifiedEffectFact>,
    settlement_fact: Option<VerifiedEffectFact>,
    retirement: RetirementState,
    claims: BTreeMap<ClaimId, ClaimRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    roots: BTreeMap<RootId, RootRecord>,
    estates: BTreeMap<EffectId, EstateRecord>,
    resource_index: BTreeMap<ResourceId, Vec<(EffectId, ClaimId)>>,
    resources: BTreeMap<ResourceId, ResourceRecord>,
    charges: BTreeMap<(ChargeAccountId, CreditClassId), u64>,
    device_generations: BTreeMap<DeviceScopeId, DeviceGeneration>,
    device_quarantine: BTreeSet<DeviceScopeId>,
    verifier_epochs: BTreeMap<VerifierId, u64>,
    revision: u64,
    head: Digest,
    next_nonce: u64,
    freshness: Freshness,
    recovery_target: Option<Freshness>,
}

/// The sole authoritative portable CSER state machine.
#[derive(Debug)]
pub struct Engine {
    catalog: DomainCatalog,
    limits: CoreLimits,
    state: State,
    persistence_recovery_required: bool,
    journal_repair_required: Option<JournalRepair>,
}

impl Engine {
    /// Creates an empty authoritative Registry under exact freshness coordinates.
    pub fn new(catalog: DomainCatalog, limits: CoreLimits, freshness: Freshness) -> Self {
        let verifier_epochs = catalog
            .verifier_ids()
            .into_iter()
            .map(|verifier| (verifier, 1))
            .collect();
        Self {
            catalog,
            limits,
            state: State {
                roots: BTreeMap::new(),
                estates: BTreeMap::new(),
                resource_index: BTreeMap::new(),
                resources: BTreeMap::new(),
                charges: BTreeMap::new(),
                device_generations: BTreeMap::new(),
                device_quarantine: BTreeSet::new(),
                verifier_epochs,
                revision: 0,
                head: Digest::ZERO,
                next_nonce: 1,
                freshness,
                recovery_target: None,
            },
            persistence_recovery_required: false,
            journal_repair_required: None,
        }
    }

    /// Returns the current journal revision.
    pub const fn revision(&self) -> u64 {
        self.state.revision
    }

    /// Returns the current journal head digest.
    pub const fn head(&self) -> Digest {
        self.state.head
    }

    /// Returns the active freshness coordinates.
    pub const fn freshness(&self) -> Freshness {
        self.state.freshness
    }

    /// Returns freshness bound to one root's latest principal binding.
    pub fn freshness_for_root(&self, root: RootId) -> Option<Freshness> {
        self.state.roots.get(&root).and_then(|record| {
            self.state
                .freshness
                .with_binding(record.last_binding_generation)
                .ok()
        })
    }

    /// Returns the current generation of one independently reset device scope.
    pub fn device_generation(&self, scope: DeviceScopeId) -> Option<DeviceGeneration> {
        self.state.device_generations.get(&scope).copied()
    }

    /// Builds the exact current challenge for a domain receipt verifier.
    pub fn evidence_challenge(
        &self,
        effect: EffectId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
    ) -> Result<EvidenceChallenge, CoreError> {
        let root = self
            .state
            .roots
            .get(&effect.root())
            .ok_or(CoreError::UnknownRoot)?;
        let estate = self
            .state
            .estates
            .get(&effect)
            .ok_or(CoreError::UnknownEstate)?;
        let claim = estate
            .claims
            .get(&claim_id)
            .ok_or(CoreError::UnknownClaim)?;
        if claim.retired {
            return Err(CoreError::DuplicateEvidence);
        }
        let rule = self
            .catalog
            .claim_rule(claim.domain, claim.kind)
            .ok_or(CoreError::UnknownClaimClass)?
            .evidence()
            .iter()
            .find(|rule| rule.kind() == kind)
            .ok_or(CoreError::UnexpectedEvidence)?;
        let current_observation =
            scoped_freshness(&self.state, claim.scope, root.last_binding_generation)?;
        Ok(EvidenceChallenge {
            effect,
            claim: claim_id,
            domain: claim.domain,
            kind,
            scope: claim.scope,
            resource: claim.resource,
            resource_generation: claim.resource_generation,
            subject: claim.enrolled_freshness,
            current_observation,
            expected_verifier: rule.verifier(),
            expected_receipt_schema: rule.receipt_schema(),
        })
    }

    /// Reports whether one exact retirement requirement has already won its
    /// durable transition.
    ///
    /// This read-only projection grants no evidence authority. Hardware
    /// adapters use it to prove prerequisites are committed before consuming a
    /// non-replayable reset owner into the next physical closure phase.
    pub fn retirement_evidence_accepted(
        &self,
        effect: EffectId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
    ) -> Result<bool, CoreError> {
        let claim = self
            .state
            .estates
            .get(&effect)
            .and_then(|estate| estate.claims.get(&claim_id))
            .ok_or(CoreError::UnknownClaim)?;
        claim
            .requirements
            .iter()
            .find(|requirement| requirement.kind == kind)
            .map(|requirement| requirement.accepted.is_some())
            .ok_or(CoreError::UnexpectedEvidence)
    }

    /// Verifies one raw domain receipt against an exact, current claim challenge.
    ///
    /// The returned fact is linear and must still win the authoritative
    /// transition race when submitted.
    pub fn verify_retirement_evidence<V: ReceiptVerifier>(
        &self,
        effect: EffectId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedRetirementEvidence, CoreError> {
        let challenge = self.evidence_challenge(effect, claim_id, kind)?;
        let identity = verifier.identity();
        if identity.verifier() != challenge.expected_verifier() {
            return Err(CoreError::UnknownVerifier);
        }
        if identity.receipt_schema() != challenge.expected_receipt_schema() {
            return Err(CoreError::ReceiptSchemaMismatch);
        }
        if self
            .state
            .verifier_epochs
            .get(&identity.verifier())
            .copied()
            != Some(identity.epoch())
        {
            return Err(CoreError::StaleVerifierEpoch);
        }
        let observation = verifier
            .verify(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(observation.digest())?;
        Ok(VerifiedRetirementEvidence {
            effect,
            claim: claim_id,
            evidence: RetirementEvidence {
                kind,
                subject: observation.subject(),
                freshness: observation.observation(),
                stamp: VerifierStamp {
                    identity,
                    receipt_digest: observation.digest(),
                },
            },
        })
    }

    /// Builds the exact challenge for one outstanding external commit intent.
    pub fn commit_outcome_challenge(
        &self,
        intent: &CommitIntent,
    ) -> Result<EffectFactChallenge, CoreError> {
        let estate = self
            .state
            .estates
            .get(&intent.effect)
            .ok_or(CoreError::UnknownEstate)?;
        if estate.commit != CommitState::CommitIntentDurable
            || estate.commit_nonce != Some(intent.nonce)
        {
            return Err(CoreError::StaleCommitIntent);
        }
        let operation = estate
            .commit_operation
            .ok_or(CoreError::InvariantViolation)?;
        let binding = self
            .catalog
            .obligation_rule(estate.domain, estate.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .commit_outcome();
        Ok(EffectFactChallenge {
            kind: EffectFactKind::CommitOutcome,
            effect: intent.effect,
            domain: estate.domain,
            obligation: estate.obligation,
            actor: estate.causal_owner,
            generation: estate.authority_epoch,
            nonce: intent.nonce,
            operation,
            predecessor: None,
            current_observation: estate_freshness(&self.state, estate)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
        })
    }

    /// Verifies a typed outcome for one exact external commit intent.
    pub fn verify_commit_outcome<V: EffectReceiptVerifier>(
        &self,
        intent: &CommitIntent,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedCommitOutcome, CoreError> {
        let challenge = self.commit_outcome_challenge(intent)?;
        self.verify_effect_fact(challenge, verifier, receipt)
            .map(VerifiedCommitOutcome)
    }

    /// Builds the exact challenge for externally completing a durable
    /// settlement apply intent.
    pub fn apply_completion_challenge(
        &self,
        claim: &SettlementClaim,
    ) -> Result<EffectFactChallenge, CoreError> {
        if !matches!(
            claim.stage,
            ClaimStage::Intent | ClaimStage::ReconcileIntent
        ) {
            return Err(CoreError::WrongSettlementStage);
        }
        let estate = self
            .state
            .estates
            .get(&claim.effect)
            .ok_or(CoreError::UnknownEstate)?;
        if !settlement_claim_matches(estate, claim)
            || !matches!(
                estate.settlement,
                SettlementState::ApplyIntentDurable { .. } | SettlementState::Claimed { .. }
            )
        {
            return Err(CoreError::StaleSettlementClaim);
        }
        let operation = estate
            .settlement_intent
            .ok_or(CoreError::InvariantViolation)?;
        let binding = self
            .catalog
            .obligation_rule(estate.domain, estate.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .apply_completed()
            .ok_or(CoreError::WrongSettlementStage)?;
        Ok(EffectFactChallenge {
            kind: EffectFactKind::ApplyCompleted,
            effect: claim.effect,
            domain: estate.domain,
            obligation: estate.obligation,
            actor: claim.claimant,
            generation: claim.generation,
            nonce: claim.nonce,
            operation,
            predecessor: None,
            current_observation: estate_freshness(&self.state, estate)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
        })
    }

    /// Verifies completion of one exact durable settlement apply intent.
    pub fn verify_apply_completion<V: EffectReceiptVerifier>(
        &self,
        claim: &SettlementClaim,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedApplyReceipt, CoreError> {
        let challenge = self.apply_completion_challenge(claim)?;
        self.verify_effect_fact(challenge, verifier, receipt)
            .map(VerifiedApplyReceipt)
    }

    /// Builds the exact final acknowledgement challenge for an applied
    /// settlement claim.
    pub fn settlement_ack_challenge(
        &self,
        claim: &SettlementClaim,
    ) -> Result<EffectFactChallenge, CoreError> {
        if !matches!(
            claim.stage,
            ClaimStage::Applied | ClaimStage::ReconcileApplied
        ) {
            return Err(CoreError::WrongSettlementStage);
        }
        let estate = self
            .state
            .estates
            .get(&claim.effect)
            .ok_or(CoreError::UnknownEstate)?;
        if !settlement_claim_matches(estate, claim)
            || !matches!(
                estate.settlement,
                SettlementState::AppliedUnacknowledged { .. } | SettlementState::Claimed { .. }
            )
        {
            return Err(CoreError::StaleSettlementClaim);
        }
        let operation = estate
            .settlement_intent
            .ok_or(CoreError::InvariantViolation)?;
        let predecessor = estate
            .applied_fact
            .map(|fact| fact.stamp.receipt_digest)
            .ok_or(CoreError::InvariantViolation)?;
        let binding = self
            .catalog
            .obligation_rule(estate.domain, estate.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .settlement_acknowledged()
            .ok_or(CoreError::WrongSettlementStage)?;
        Ok(EffectFactChallenge {
            kind: EffectFactKind::SettlementAcknowledged,
            effect: claim.effect,
            domain: estate.domain,
            obligation: estate.obligation,
            actor: claim.claimant,
            generation: claim.generation,
            nonce: claim.nonce,
            operation,
            predecessor: Some(predecessor),
            current_observation: estate_freshness(&self.state, estate)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
        })
    }

    /// Verifies the final acknowledgement for one exact settlement claim.
    pub fn verify_settlement_ack<V: EffectReceiptVerifier>(
        &self,
        claim: &SettlementClaim,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedSettlementAck, CoreError> {
        let challenge = self.settlement_ack_challenge(claim)?;
        self.verify_effect_fact(challenge, verifier, receipt)
            .map(VerifiedSettlementAck)
    }

    fn verify_effect_fact<V: EffectReceiptVerifier>(
        &self,
        challenge: EffectFactChallenge,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedEffectFact, CoreError> {
        let identity = verifier.identity();
        if identity.verifier() != challenge.expected_verifier() {
            return Err(CoreError::UnknownVerifier);
        }
        if identity.receipt_schema() != challenge.expected_receipt_schema() {
            return Err(CoreError::ReceiptSchemaMismatch);
        }
        if self
            .state
            .verifier_epochs
            .get(&identity.verifier())
            .copied()
            != Some(identity.epoch())
        {
            return Err(CoreError::StaleVerifierEpoch);
        }
        let observation = verifier
            .verify(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(observation.digest())?;
        if observation.freshness() != challenge.current_observation()
            || matches!(
                (challenge.kind(), observation.outcome()),
                (EffectFactKind::CommitOutcome, None)
                    | (
                        EffectFactKind::ApplyCompleted | EffectFactKind::SettlementAcknowledged,
                        Some(_)
                    )
            )
        {
            return Err(CoreError::StaleEvidence);
        }
        Ok(VerifiedEffectFact {
            kind: challenge.kind(),
            effect: challenge.effect(),
            actor: challenge.actor(),
            generation: challenge.generation(),
            nonce: challenge.nonce(),
            operation: challenge.operation(),
            predecessor: challenge.predecessor(),
            freshness: observation.freshness(),
            stamp: VerifierStamp {
                identity,
                receipt_digest: observation.digest(),
            },
            outcome: observation.outcome(),
        })
    }

    /// Returns the catalog schema digest.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog.digest()
    }

    /// Prepares, durably appends, and atomically swaps one transition.
    ///
    /// The persistence closure must append `record.bytes()` and complete the
    /// profile's durability barrier before returning success. It is invoked
    /// while no core state has changed. A persistence failure leaves the full
    /// semantic projection unchanged, but latches this engine into
    /// recovery-required state because the candidate record may already be
    /// durable.
    pub fn transact<E, P, C>(
        &mut self,
        command: C,
        persist: P,
    ) -> Result<TransitionReceipt, TxError<E>>
    where
        C: Into<Command>,
        P: FnOnce(&JournalRecord) -> Result<(), E>,
    {
        self.transact_with_freshness(command, |record, _| persist(record))
    }

    /// Prepares and commits one transition through a typed durability provider.
    ///
    /// Unlike [`Self::transact`], this path also passes the candidate
    /// post-transition freshness to the provider. That is required for a
    /// recovery checkpoint, whose record is encoded under the previously
    /// committed epoch but atomically advances the trusted anchor to the
    /// already-reserved next epoch.
    pub fn transact_durable<P, C>(
        &mut self,
        command: C,
        persistence: &mut P,
    ) -> Result<TransitionReceipt, TxError<P::Error>>
    where
        C: Into<Command>,
        P: crate::TransitionDurability,
    {
        self.transact_with_freshness(command, |record, freshness| {
            persistence.persist_transition(record, freshness)
        })
    }

    fn transact_with_freshness<E, P, C>(
        &mut self,
        command: C,
        persist: P,
    ) -> Result<TransitionReceipt, TxError<E>>
    where
        C: Into<Command>,
        P: FnOnce(&JournalRecord, Freshness) -> Result<(), E>,
    {
        let Command(command) = command.into();
        if self.journal_repair_required.is_some() {
            return Err(TxError::Core(CoreError::JournalRepairRequired));
        }
        if self.persistence_recovery_required {
            return Err(TxError::Core(CoreError::PersistenceRecoveryRequired));
        }
        if self.state.recovery_target.is_some()
            && !matches!(&command, CommandKind::CheckpointRecovery { .. })
        {
            return Err(TxError::Core(CoreError::RecoveryPending));
        }
        let mut candidate = self.state.clone();
        let output = apply_command(&self.catalog, self.limits, &mut candidate, &command)
            .map_err(TxError::Core)?;
        check_invariants(&self.catalog, self.limits, &candidate).map_err(TxError::Core)?;

        let record = JournalRecord::build(
            self.state.revision,
            self.state.freshness.boot(),
            self.state.freshness.registry(),
            self.state.freshness.binding(),
            self.state.freshness.journal(),
            self.state.freshness.device(),
            self.catalog.digest(),
            self.state.head,
            command,
        )
        .map_err(TxError::Journal)?;
        if let Err(error) = persist(&record, candidate.freshness) {
            self.persistence_recovery_required = true;
            return Err(TxError::Persist(error));
        }

        candidate.revision = record.revision();
        candidate.head = record.digest();
        let event = output.event;
        let output = output.into_public();
        self.state = candidate;
        Ok(TransitionReceipt {
            revision: record.revision(),
            head: record.digest(),
            projection: self.projection_digest(),
            event,
            output,
        })
    }

    /// Executes an in-memory transition for non-durable profiles.
    pub fn transact_volatile<C: Into<Command>>(
        &mut self,
        command: C,
    ) -> Result<TransitionReceipt, CoreError> {
        self.transact(command, |_| Ok::<(), Infallible>(()))
            .map_err(|error| match error {
                TxError::Core(error) => error,
                TxError::Journal(error) => CoreError::Journal(error),
                TxError::Persist(never) => match never {},
            })
    }

    /// Recovers the exact journal prefix named by a trusted external anchor.
    ///
    /// There is intentionally no unanchored production recovery path. The
    /// catalog digest, committed epoch, minimum revision, and exact head must
    /// all agree before the next freshness epoch can be installed.
    pub fn recover(
        catalog: DomainCatalog,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
    ) -> Result<RecoveryReport, CoreError> {
        if anchor.catalog_digest != catalog.digest() {
            return Err(CoreError::SchemaMismatch);
        }
        if anchor.minimum_revision == 0 {
            let journal_repair =
                (!bytes.is_empty()).then_some(JournalRepair::UnanchoredSuffix { offset: 0 });
            let mut engine = Self::new(catalog, limits, anchor.committed_freshness);
            engine.state.recovery_target = Some(anchor.next_freshness);
            engine.journal_repair_required = journal_repair;
            return Ok(RecoveryReport {
                acknowledged_revision: 0,
                acknowledged_head: Digest::ZERO,
                journal_repair,
                engine,
            });
        }
        let (scan, accepted_count, journal_repair) = match scan_journal(bytes) {
            Ok(scan) => {
                let accepted_index = scan
                    .records()
                    .iter()
                    .position(|record| record.digest() == anchor.expected_head)
                    .ok_or(CoreError::RollbackDetected)?;
                let accepted_count = accepted_index + 1;
                let accepted_len = scan.records()[..accepted_count]
                    .iter()
                    .map(|record| record.bytes().len())
                    .sum();
                let repair = if accepted_count < scan.records().len() {
                    Some(JournalRepair::UnanchoredSuffix {
                        offset: accepted_len,
                    })
                } else {
                    scan.torn_tail()
                        .map(|offset| JournalRepair::TornTail { offset })
                };
                (scan, accepted_count, repair)
            }
            Err(full_error) => {
                let scan = scan_journal_to_head(bytes, anchor.expected_head)
                    .map_err(CoreError::Journal)?
                    .ok_or(CoreError::Journal(full_error))?;
                let accepted_count = scan.records().len();
                let offset = scan.unanchored_suffix().unwrap_or_else(|| {
                    scan.records()
                        .iter()
                        .map(|record| record.bytes().len())
                        .sum()
                });
                (
                    scan,
                    accepted_count,
                    Some(JournalRepair::UnanchoredSuffix { offset }),
                )
            }
        };
        let records = &scan.records()[..accepted_count];
        let first = records.first().ok_or(CoreError::RollbackDetected)?;
        if first.catalog_digest() != catalog.digest()
            || first.registry() != anchor.committed_freshness.registry()
        {
            return Err(CoreError::SchemaMismatch);
        }
        let initial = Freshness::new(
            first.boot(),
            first.registry(),
            first.binding(),
            first.device(),
            first.journal(),
        )
        .map_err(|_| CoreError::InvariantViolation)?;
        let mut engine = Self::new(catalog, limits, initial);

        for record in records {
            if record.base_revision() != engine.state.revision
                || record.revision()
                    != engine
                        .state
                        .revision
                        .checked_add(1)
                        .ok_or(CoreError::GenerationExhausted)?
            {
                return Err(CoreError::RevisionConflict);
            }
            if record.predecessor() != engine.state.head {
                return Err(CoreError::PredecessorMismatch);
            }
            if record.catalog_digest() != engine.catalog.digest()
                || record.registry() != engine.state.freshness.registry()
                || record.binding() != engine.state.freshness.binding()
                || record.boot() != engine.state.freshness.boot()
                || record.journal() != engine.state.freshness.journal()
                || record.device() != engine.state.freshness.device()
            {
                return Err(CoreError::SchemaMismatch);
            }
            if let CommandKind::CheckpointRecovery {
                boot,
                journal,
                device,
            } = record.command()
            {
                if boot.get() <= engine.state.freshness.boot().get()
                    || journal.get() <= engine.state.freshness.journal().get()
                    || device.get() < engine.state.freshness.device().get()
                {
                    return Err(CoreError::FreshnessRollback);
                }
                engine.state.recovery_target = Some(
                    Freshness::new(
                        *boot,
                        engine.state.freshness.registry(),
                        engine.state.freshness.binding(),
                        *device,
                        *journal,
                    )
                    .map_err(|_| CoreError::InvariantViolation)?,
                );
            }
            apply_command(
                &engine.catalog,
                engine.limits,
                &mut engine.state,
                record.command(),
            )?;
            check_invariants(&engine.catalog, engine.limits, &engine.state)?;
            engine.state.revision = record.revision();
            engine.state.head = record.digest();
        }

        if engine.state.revision < anchor.minimum_revision {
            return Err(CoreError::RollbackDetected);
        }
        if anchor.expected_head != engine.state.head {
            return Err(CoreError::RollbackDetected);
        }
        if engine.state.freshness != anchor.committed_freshness {
            return Err(CoreError::FreshnessRollback);
        }
        let target = anchor.next_freshness;
        if target.registry() != engine.state.freshness.registry()
            || target.binding() != engine.state.freshness.binding()
            || target.boot().get() <= engine.state.freshness.boot().get()
            || target.journal().get() <= engine.state.freshness.journal().get()
            || target.device().get() < engine.state.freshness.device().get()
        {
            return Err(CoreError::FreshnessRollback);
        }
        engine.state.recovery_target = Some(target);
        for claim in engine
            .state
            .estates
            .values()
            .flat_map(|estate| estate.claims.values())
            .filter(|claim| !claim.retired)
        {
            if let ClaimScope::Device(scope) = claim.scope {
                engine.state.device_quarantine.insert(scope);
            }
        }
        engine.journal_repair_required = journal_repair;

        Ok(RecoveryReport {
            acknowledged_revision: engine.state.revision,
            acknowledged_head: engine.state.head,
            journal_repair,
            engine,
        })
    }

    /// Returns a public estate projection.
    pub fn estate(&self, effect: EffectId) -> Option<EstateProjection> {
        self.state.estates.get(&effect).map(project_estate)
    }

    /// Returns every claim for one exact estate in stable claim-id order.
    ///
    /// The returned values are observations only.  A recovery adapter must
    /// still request an exact evidence challenge and submit the resulting
    /// one-shot command before any resource becomes reusable.
    pub fn claims(&self, effect: EffectId) -> Result<Vec<ClaimProjection>, CoreError> {
        let estate = self
            .state
            .estates
            .get(&effect)
            .ok_or(CoreError::UnknownEstate)?;
        Ok(estate
            .claims
            .values()
            .map(|claim| project_claim(effect, claim))
            .collect())
    }

    /// Enumerates all non-retired claims in stable effect/claim order.
    ///
    /// Boot recovery uses this bounded projection to reconstruct physical
    /// custodians and quarantine work from the authoritative replayed state;
    /// adapters must not persist a parallel semantic tombstone index.
    pub fn retained_claims(&self) -> Vec<ClaimProjection> {
        self.state
            .estates
            .iter()
            .flat_map(|(effect, estate)| {
                estate
                    .claims
                    .values()
                    .filter(|claim| !claim.retired)
                    .map(|claim| project_claim(*effect, claim))
            })
            .collect()
    }

    /// Returns a root recovery projection.
    pub fn root(&self, root: RootId) -> Option<RootRecoveryState> {
        self.state.roots.get(&root).map(|record| record.state)
    }

    /// Generates an exact, ordered and non-authorizing recovery cohort for one
    /// fenced root. The caller may inspect the cohort before consuming it into
    /// [`RecoverySnapshot::record`].
    pub fn snapshot_root(
        &self,
        root: RootId,
        snapshot: SnapshotId,
    ) -> Result<RecoverySnapshot, CoreError> {
        build_recovery_snapshot(&self.catalog, &self.state, root, snapshot)
    }

    /// Returns retained charging for one exact account and credit class.
    pub fn charge(&self, account: ChargeAccountId, class: CreditClassId) -> ChargeProjection {
        ChargeProjection {
            account,
            class,
            retained_units: self
                .state
                .charges
                .get(&(account, class))
                .copied()
                .unwrap_or(0),
        }
    }

    /// Returns the bounded global pressure projection.
    pub fn pressure(&self) -> PressureProjection {
        PressureProjection {
            roots: self.state.roots.len(),
            estates: self.state.estates.len(),
            retained_claims: self
                .state
                .estates
                .values()
                .map(|estate| {
                    estate
                        .claims
                        .values()
                        .filter(|claim| !claim.retired)
                        .count()
                })
                .sum(),
            quarantined: self.journal_repair_required.is_some()
                || !self.state.device_quarantine.is_empty(),
            persistence_recovery_required: self.persistence_recovery_required,
        }
    }

    /// Returns whether an append/barrier failure made the durable head
    /// ambiguous and therefore disabled further transitions on this engine.
    pub const fn persistence_recovery_required(&self) -> bool {
        self.persistence_recovery_required
    }

    /// Returns the first byte offset which must be repaired before this
    /// recovered engine can execute any semantic transition.
    pub const fn journal_repair_required(&self) -> Option<JournalRepair> {
        self.journal_repair_required
    }

    /// Checks whether one exact retired generation can be reserved for reuse.
    ///
    /// This read-only result is not reuse authority. A caller must durably
    /// transact [`CommandKind::ReserveReuse`] and consume its returned
    /// [`ReusePermit`] when enrolling the next claim.
    pub fn check_reusable(
        &self,
        resource: ResourceId,
        expected_generation: ResourceGeneration,
    ) -> Result<(), CoreError> {
        if self.state.recovery_target.is_some() {
            return Err(CoreError::RecoveryPending);
        }
        match self.state.resources.get(&resource) {
            Some(ResourceRecord {
                scope,
                generation,
                phase: ResourcePhase::Retired,
                ..
            }) if *generation == expected_generation => {
                if scope_is_quarantined(&self.state, *scope) {
                    Err(CoreError::Quarantined)
                } else {
                    Ok(())
                }
            }
            Some(ResourceRecord {
                phase: ResourcePhase::Claimed { .. },
                ..
            }) => Err(CoreError::ResourceRetained),
            Some(_) => Err(CoreError::StaleResourceGeneration),
            None => Err(CoreError::UnknownResource),
        }
    }

    /// Builds a linear reissue request for a reuse reservation whose previous
    /// bearer died with an earlier estate authority epoch.
    ///
    /// The returned command is bound to the exact current actor, binding,
    /// authority epoch, resource and allocation generation. It can still lose
    /// a concurrent fence or adoption race when durably transacted.
    pub fn reclaim_resource_reuse(
        &self,
        effect: EffectId,
        actor: PrincipalIncarnation,
        binding_generation: u64,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
    ) -> Result<Command, CoreError> {
        if self.state.recovery_target.is_some() {
            return Err(CoreError::RecoveryPending);
        }
        require_active_actor(&self.state, effect, actor, binding_generation)?;
        let estate = self
            .state
            .estates
            .get(&effect)
            .ok_or(CoreError::UnknownEstate)?;
        if !estate.claims.values().any(|claim| {
            !claim.retired
                && claim.resource == resource
                && claim.resource_generation == resource_generation
        }) {
            return Err(CoreError::UnknownClaim);
        }
        let record = self
            .state
            .resources
            .get(&resource)
            .ok_or(CoreError::UnknownResource)?;
        if record.generation != resource_generation {
            return Err(CoreError::StaleResourceGeneration);
        }
        if scope_is_quarantined(&self.state, record.scope) {
            return Err(CoreError::Quarantined);
        }
        if !matches!(
            record.phase,
            ResourcePhase::Claimed {
                pending_reuse: Some(_)
            }
        ) {
            return Err(CoreError::StaleReusePermit);
        }
        Ok(Command(CommandKind::ReclaimResourceReuse {
            effect,
            actor,
            binding_generation,
            authority_epoch: estate.authority_epoch,
            resource,
            resource_generation,
        }))
    }

    /// Computes a deterministic digest over the authoritative projection.
    pub fn projection_digest(&self) -> Digest {
        projection_digest(&self.state, self.catalog.digest())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputData {
    None,
    CommitIntent {
        effect: EffectId,
        nonce: u64,
    },
    Settlement {
        effect: EffectId,
        claimant: PrincipalIncarnation,
        generation: u64,
        nonce: u64,
        stage: ClaimStage,
    },
    ReusePermit {
        effect: EffectId,
        actor: PrincipalIncarnation,
        binding_generation: u64,
        authority_epoch: u64,
        resource: ResourceId,
        generation: ResourceGeneration,
        freshness: Freshness,
        nonce: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppliedOutput {
    event: TransitionEvent,
    output: OutputData,
}

impl AppliedOutput {
    const fn none(event: TransitionEvent) -> Self {
        Self {
            event,
            output: OutputData::None,
        }
    }

    fn into_public(self) -> TransitionOutput {
        match self.output {
            OutputData::None => TransitionOutput::None,
            OutputData::CommitIntent { effect, nonce } => {
                TransitionOutput::CommitIntent(CommitIntent { effect, nonce })
            }
            OutputData::Settlement {
                effect,
                claimant,
                generation,
                nonce,
                stage,
            } => TransitionOutput::SettlementClaim(SettlementClaim {
                effect,
                claimant,
                generation,
                nonce,
                stage,
            }),
            OutputData::ReusePermit {
                effect,
                actor,
                binding_generation,
                authority_epoch,
                resource,
                generation,
                freshness,
                nonce,
            } => TransitionOutput::ReusePermit(ReusePermit {
                effect,
                actor,
                binding_generation,
                authority_epoch,
                resource,
                generation,
                freshness,
                nonce,
            }),
        }
    }
}

fn apply_command(
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut State,
    command: &CommandKind,
) -> Result<AppliedOutput, CoreError> {
    match *command {
        CommandKind::CreateEstate {
            effect,
            origin,
            binding_generation,
            domain,
            obligation,
            charge_account,
        } => {
            if binding_generation == 0 {
                return Err(CoreError::InvalidPayload);
            }
            let obligation_rule = catalog
                .obligation_rule(domain, obligation)
                .ok_or(CoreError::UnknownObligationClass)?;
            if state.estates.contains_key(&effect) {
                return Err(CoreError::DuplicateEstate);
            }
            if state.estates.len() >= limits.max_estates {
                return Err(CoreError::CapacityExceeded);
            }

            match state.roots.get(&effect.root()) {
                Some(root) => {
                    if root.origin.principal() != origin.principal()
                        || !matches!(
                            root.state,
                            RootRecoveryState::Active {
                                incarnation,
                                binding_generation: live_binding,
                            } | RootRecoveryState::Rebound {
                                successor: incarnation,
                                binding_generation: live_binding,
                            } if incarnation == origin && live_binding == binding_generation
                        )
                    {
                        return Err(CoreError::StaleIncarnation);
                    }
                }
                None => {
                    if state.roots.len() >= limits.max_roots {
                        return Err(CoreError::CapacityExceeded);
                    }
                    state.roots.insert(
                        effect.root(),
                        RootRecord {
                            origin,
                            state: RootRecoveryState::Active {
                                incarnation: origin,
                                binding_generation,
                            },
                            last_binding_generation: binding_generation,
                            last_incarnation_generation: origin.generation(),
                            crash_generation: 0,
                        },
                    );
                }
            }

            state.estates.insert(
                effect,
                EstateRecord {
                    effect,
                    causal_owner: origin,
                    custodian: CustodyState::Principal(origin),
                    charge_owner: charge_account,
                    domain,
                    obligation,
                    obligation_policy: obligation_rule.policy(),
                    authority: AuthorityState::Active,
                    authority_epoch: 1,
                    commit: CommitState::Registered,
                    commit_nonce: None,
                    commit_operation: None,
                    commit_fact: None,
                    outcome: OutcomeState::Pending,
                    settlement: SettlementState::Unavailable,
                    settlement_nonce: None,
                    settlement_intent: None,
                    applied_fact: None,
                    settlement_fact: None,
                    retirement: RetirementState::Held,
                    claims: BTreeMap::new(),
                    claim_stage: None,
                },
            );
            Ok(AppliedOutput::none(TransitionEvent::EstateCreated))
        }
        CommandKind::AddClaim {
            effect,
            actor,
            binding_generation,
            claim,
            domain,
            kind,
            scope,
            resource,
            resource_generation,
            units,
        } => enroll_claim(
            catalog,
            limits,
            state,
            effect,
            actor,
            binding_generation,
            claim,
            domain,
            kind,
            scope,
            resource,
            resource_generation,
            units,
            None,
        ),
        CommandKind::PrepareEffect {
            effect,
            actor,
            binding_generation,
        } => {
            require_active_actor(state, effect, actor, binding_generation)?;
            {
                let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
                validate_obligation_claims(catalog, estate)?;
            }
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if estate.authority != AuthorityState::Active
                || estate.commit != CommitState::Registered
            {
                return Err(CoreError::WrongCommitState);
            }
            estate.commit = CommitState::Prepared;
            Ok(AppliedOutput::none(TransitionEvent::EffectPrepared))
        }
        CommandKind::RecordCommitIntent {
            effect,
            actor,
            binding_generation,
            operation,
        } => {
            require_digest(operation)?;
            require_active_actor(state, effect, actor, binding_generation)?;
            let nonce = allocate_nonce(state)?;
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if catalog
                .obligation_rule(estate.domain, estate.obligation)
                .ok_or(CoreError::InvariantViolation)?
                .adoption()
                != crate::AdoptionPolicy::UncommittedOnly
            {
                return Err(CoreError::AdoptionForbidden);
            }
            if estate.authority != AuthorityState::Active || estate.commit != CommitState::Prepared
            {
                return Err(CoreError::WrongCommitState);
            }
            estate.commit = CommitState::CommitIntentDurable;
            estate.commit_nonce = Some(nonce);
            estate.commit_operation = Some(operation);
            Ok(AppliedOutput {
                event: TransitionEvent::CommitIntentDurable,
                output: OutputData::CommitIntent { effect, nonce },
            })
        }
        CommandKind::AcknowledgeCommit { fact } => {
            let effect = fact.effect;
            {
                let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
                validate_effect_fact(catalog, state, estate, fact)?;
                if fact.kind != EffectFactKind::CommitOutcome
                    || fact.actor != estate.causal_owner
                    || fact.generation != estate.authority_epoch
                    || fact.operation != estate.commit_operation.unwrap_or(Digest::ZERO)
                    || fact.predecessor.is_some()
                {
                    return Err(CoreError::StaleCommitIntent);
                }
            }
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if estate.commit != CommitState::CommitIntentDurable
                || estate.commit_nonce != Some(fact.nonce)
            {
                return Err(CoreError::StaleCommitIntent);
            }
            let outcome = match fact.outcome.ok_or(CoreError::VerificationFailed)? {
                ExternalOutcome::Success => OutcomeState::KnownSuccess(fact.stamp.receipt_digest),
                ExternalOutcome::Failure => OutcomeState::KnownFailure(fact.stamp.receipt_digest),
            };
            estate.commit = CommitState::Committed;
            estate.commit_nonce = None;
            estate.commit_fact = Some(fact);
            estate.outcome = outcome;
            initialize_committed_disposition(estate)?;
            refresh_retirement(estate);
            Ok(AppliedOutput::none(TransitionEvent::EffectCommitted))
        }
        CommandKind::FenceIncarnation {
            root,
            crashed,
            binding_generation,
        } => {
            apply_fence_incarnation(
                state,
                root,
                crashed,
                binding_generation,
                limits.max_crashes_per_root,
            )?;
            Ok(AppliedOutput::none(TransitionEvent::IncarnationFenced))
        }
        CommandKind::Snapshot {
            root,
            snapshot,
            digest,
        } => {
            require_digest(digest)?;
            let expected = build_recovery_snapshot(catalog, state, root, snapshot)?;
            if expected.digest != digest {
                return Err(CoreError::StaleSnapshot);
            }
            let root_record = state.roots.get_mut(&root).ok_or(CoreError::UnknownRoot)?;
            if matches!(
                root_record.state,
                RootRecoveryState::RecoveryExhausted { .. }
            ) {
                return Err(CoreError::RecoveryExhausted);
            }
            if !matches!(root_record.state, RootRecoveryState::Fenced { .. }) {
                return Err(CoreError::WrongRecoveryState);
            }
            root_record.state = RootRecoveryState::Snapshotted { snapshot, digest };
            Ok(AppliedOutput::none(TransitionEvent::Snapshot))
        }
        CommandKind::Ready {
            root,
            snapshot,
            successor,
        } => {
            let root_record = state.roots.get_mut(&root).ok_or(CoreError::UnknownRoot)?;
            let expected = match root_record.state {
                RootRecoveryState::Snapshotted {
                    snapshot: expected, ..
                } => expected,
                RootRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if expected != snapshot {
                return Err(CoreError::StaleSnapshot);
            }
            if successor.principal() != root_record.origin.principal()
                || successor.generation() <= root_record.last_incarnation_generation
            {
                return Err(CoreError::StaleIncarnation);
            }
            root_record.state = RootRecoveryState::Ready {
                snapshot,
                successor,
            };
            Ok(AppliedOutput::none(TransitionEvent::Ready))
        }
        CommandKind::Rebind {
            root,
            snapshot,
            successor,
            binding_generation,
        } => {
            if binding_generation == 0 {
                return Err(CoreError::InvalidPayload);
            }
            let root_record = state.roots.get_mut(&root).ok_or(CoreError::UnknownRoot)?;
            match root_record.state {
                RootRecoveryState::Ready {
                    snapshot: expected,
                    successor: expected_successor,
                } if expected == snapshot && expected_successor == successor => {}
                RootRecoveryState::Ready { .. } => return Err(CoreError::StaleSnapshot),
                RootRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            }
            if binding_generation <= root_record.last_binding_generation {
                return Err(CoreError::StaleIncarnation);
            }
            root_record.last_binding_generation = binding_generation;
            root_record.last_incarnation_generation = successor.generation();
            root_record.state = RootRecoveryState::Rebound {
                successor,
                binding_generation,
            };
            Ok(AppliedOutput::none(TransitionEvent::Rebound))
        }
        CommandKind::AdoptEffect {
            effect,
            successor,
            binding_generation,
        } => {
            let root = state
                .roots
                .get(&effect.root())
                .ok_or(CoreError::UnknownRoot)?;
            if matches!(root.state, RootRecoveryState::RecoveryExhausted { .. }) {
                return Err(CoreError::RecoveryExhausted);
            }
            if !matches!(
                root.state,
                RootRecoveryState::Rebound {
                    successor: current,
                    binding_generation: current_binding,
                } if current == successor && current_binding == binding_generation
            ) {
                return Err(CoreError::StaleIncarnation);
            }
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if estate.authority == AuthorityState::Revoked
                || estate.settlement == SettlementState::Revoked
            {
                return Err(CoreError::GateClosed);
            }
            if estate.authority != AuthorityState::Fenced
                || !matches!(
                    estate.commit,
                    CommitState::Registered | CommitState::Prepared
                )
                || estate.settlement != SettlementState::Unavailable
                || estate.custodian != CustodyState::KernelEstate
            {
                return Err(CoreError::WrongCommitState);
            }
            estate.authority_epoch = estate
                .authority_epoch
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted)?;
            estate.authority = AuthorityState::Active;
            estate.custodian = CustodyState::Principal(successor);
            refresh_retirement(estate);
            Ok(AppliedOutput::none(TransitionEvent::EffectAdopted))
        }
        CommandKind::ClaimSettlement { effect, claimant } => {
            let root = state
                .roots
                .get(&effect.root())
                .ok_or(CoreError::UnknownRoot)?;
            let live_claimant = match root.state {
                RootRecoveryState::Active { incarnation, .. } => incarnation,
                RootRecoveryState::Rebound { successor, .. } => successor,
                RootRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if live_claimant != claimant {
                return Err(CoreError::StaleIncarnation);
            }
            let (generation, stage) = {
                let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
                if estate.obligation_policy != ObligationPolicy::SuccessorSettlement {
                    return Err(CoreError::WrongSettlementStage);
                }
                if estate.authority == AuthorityState::Revoked {
                    return Err(CoreError::GateClosed);
                }
                let claimable = match estate.settlement {
                    SettlementState::Open { generation } => (generation, ClaimStage::Fresh),
                    SettlementState::ReconciliationRequired {
                        generation,
                        applied,
                    } => (
                        generation,
                        if applied {
                            ClaimStage::ReconcileApplied
                        } else {
                            ClaimStage::ReconcileIntent
                        },
                    ),
                    SettlementState::Claimed { .. }
                    | SettlementState::ApplyIntentDurable { .. }
                    | SettlementState::AppliedUnacknowledged { .. } => {
                        return Err(CoreError::GateClaimed);
                    }
                    SettlementState::Settled | SettlementState::Revoked => {
                        return Err(CoreError::GateClosed);
                    }
                    SettlementState::Unavailable | SettlementState::NotRequired => {
                        return Err(CoreError::WrongSettlementStage);
                    }
                };
                let custody_matches = matches!(
                    (estate.authority, estate.custodian),
                    (
                        AuthorityState::Active,
                        CustodyState::Principal(current),
                    ) if current == claimant
                ) || matches!(
                    (estate.authority, estate.custodian),
                    (AuthorityState::Fenced, CustodyState::KernelEstate)
                );
                if estate.commit != CommitState::Committed || !custody_matches {
                    return Err(CoreError::WrongCommitState);
                }
                claimable
            };
            let nonce = allocate_nonce(state)?;
            let estate = state
                .estates
                .get_mut(&effect)
                .expect("estate validated before nonce allocation");
            estate.settlement = SettlementState::Claimed {
                claimant,
                generation,
            };
            estate.settlement_nonce = Some(nonce);
            estate.claim_stage = Some(stage);
            Ok(AppliedOutput {
                event: TransitionEvent::SettlementClaimed,
                output: OutputData::Settlement {
                    effect,
                    claimant,
                    generation,
                    nonce,
                    stage,
                },
            })
        }
        CommandKind::RecordApplyIntent {
            effect,
            claimant,
            generation,
            nonce,
            intent,
        } => {
            require_digest(intent)?;
            let estate = exact_claim_mut(state, effect, claimant, generation, nonce)?;
            if estate.claim_stage != Some(ClaimStage::Fresh) {
                return Err(CoreError::WrongSettlementStage);
            }
            estate.settlement = SettlementState::ApplyIntentDurable {
                claimant,
                generation,
            };
            estate.claim_stage = Some(ClaimStage::Intent);
            estate.settlement_intent = Some(intent);
            Ok(AppliedOutput {
                event: TransitionEvent::ApplyIntentDurable,
                output: OutputData::Settlement {
                    effect,
                    claimant,
                    generation,
                    nonce,
                    stage: ClaimStage::Intent,
                },
            })
        }
        CommandKind::RecordApplied { fact } => {
            let effect = fact.effect;
            {
                let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
                validate_effect_fact(catalog, state, estate, fact)?;
                if fact.kind != EffectFactKind::ApplyCompleted
                    || fact.operation != estate.settlement_intent.unwrap_or(Digest::ZERO)
                    || fact.predecessor.is_some()
                {
                    return Err(CoreError::StaleSettlementClaim);
                }
            }
            let estate = exact_claim_mut(state, effect, fact.actor, fact.generation, fact.nonce)?;
            let next_stage = match estate.claim_stage {
                Some(ClaimStage::Intent) => ClaimStage::Applied,
                Some(ClaimStage::ReconcileIntent) => ClaimStage::ReconcileApplied,
                _ => return Err(CoreError::WrongSettlementStage),
            };
            estate.settlement = SettlementState::AppliedUnacknowledged {
                claimant: fact.actor,
                generation: fact.generation,
            };
            estate.claim_stage = Some(next_stage);
            estate.applied_fact = Some(fact);
            Ok(AppliedOutput {
                event: TransitionEvent::AppliedUnacknowledged,
                output: OutputData::Settlement {
                    effect,
                    claimant: fact.actor,
                    generation: fact.generation,
                    nonce: fact.nonce,
                    stage: next_stage,
                },
            })
        }
        CommandKind::Settle { fact } => {
            let effect = fact.effect;
            {
                let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
                validate_effect_fact(catalog, state, estate, fact)?;
                if fact.kind != EffectFactKind::SettlementAcknowledged
                    || fact.operation != estate.settlement_intent.unwrap_or(Digest::ZERO)
                    || fact.predecessor
                        != estate
                            .applied_fact
                            .map(|applied| applied.stamp.receipt_digest)
                {
                    return Err(CoreError::StaleSettlementClaim);
                }
            }
            let estate = exact_claim_mut(state, effect, fact.actor, fact.generation, fact.nonce)?;
            if !matches!(
                estate.claim_stage,
                Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
            ) {
                return Err(CoreError::WrongSettlementStage);
            }
            estate.settlement = SettlementState::Settled;
            estate.settlement_nonce = None;
            estate.claim_stage = None;
            estate.settlement_fact = Some(fact);
            refresh_retirement(estate);
            Ok(AppliedOutput::none(TransitionEvent::Settled))
        }
        CommandKind::MarkIndeterminate {
            effect,
            claimant,
            generation,
            nonce,
            reason,
        } => {
            require_digest(reason)?;
            let estate = exact_claim_mut(state, effect, claimant, generation, nonce)?;
            let applied = matches!(
                estate.claim_stage,
                Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
            );
            let next_generation = generation
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted)?;
            estate.outcome = OutcomeState::Indeterminate(reason);
            estate.settlement = SettlementState::ReconciliationRequired {
                generation: next_generation,
                applied,
            };
            estate.settlement_nonce = None;
            estate.claim_stage = None;
            refresh_retirement(estate);
            Ok(AppliedOutput::none(TransitionEvent::Indeterminate))
        }
        CommandKind::BeginRevoke {
            effect,
            expected_actor,
            binding_generation,
            authority_epoch,
        } => {
            let root = state
                .roots
                .get(&effect.root())
                .ok_or(CoreError::UnknownRoot)?;
            let live = match root.state {
                RootRecoveryState::Active {
                    incarnation,
                    binding_generation: live_binding,
                }
                | RootRecoveryState::Rebound {
                    successor: incarnation,
                    binding_generation: live_binding,
                } => (incarnation, live_binding),
                RootRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if live != (expected_actor, binding_generation) {
                return Err(CoreError::StaleIncarnation);
            }
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if estate.authority_epoch != authority_epoch {
                return Err(CoreError::StaleAuthorityEpoch);
            }
            match (estate.authority, estate.custodian) {
                (AuthorityState::Active, CustodyState::Principal(actor))
                    if actor == expected_actor => {}
                (AuthorityState::Fenced, CustodyState::KernelEstate) => {}
                (AuthorityState::Revoked, _) => return Err(CoreError::GateClosed),
                _ => return Err(CoreError::StaleAuthorityEpoch),
            }
            match estate.settlement {
                SettlementState::Open { .. } | SettlementState::ReconciliationRequired { .. } => {
                    estate.authority_epoch = estate
                        .authority_epoch
                        .checked_add(1)
                        .ok_or(CoreError::GenerationExhausted)?;
                    estate.authority = AuthorityState::Revoked;
                    estate.custodian = CustodyState::KernelEstate;
                    estate.settlement_nonce = None;
                    estate.claim_stage = None;
                    // A committed revoke closes only successor authority. The
                    // obligation remains Open/ReconciliationRequired in kernel
                    // custody until a trusted kernel recovery path resolves it.
                    refresh_retirement(estate);
                    Ok(AppliedOutput::none(TransitionEvent::Revoked))
                }
                SettlementState::Claimed { .. }
                | SettlementState::ApplyIntentDurable { .. }
                | SettlementState::AppliedUnacknowledged { .. } => Err(CoreError::GateClaimed),
                SettlementState::Settled
                | SettlementState::Revoked
                | SettlementState::NotRequired => Err(CoreError::GateClosed),
                SettlementState::Unavailable
                    if estate.commit != CommitState::Committed
                        && estate.authority != AuthorityState::Revoked =>
                {
                    estate.authority_epoch = estate
                        .authority_epoch
                        .checked_add(1)
                        .ok_or(CoreError::GenerationExhausted)?;
                    estate.settlement = SettlementState::Revoked;
                    estate.authority = AuthorityState::Revoked;
                    estate.custodian = CustodyState::KernelEstate;
                    refresh_retirement(estate);
                    Ok(AppliedOutput::none(TransitionEvent::Revoked))
                }
                SettlementState::Unavailable => Err(CoreError::WrongSettlementStage),
            }
        }
        CommandKind::SubmitEvidence {
            effect,
            claim,
            evidence,
        } => apply_evidence(catalog, state, effect, claim, evidence),
        CommandKind::CheckpointRecovery {
            boot,
            journal,
            device,
        } => {
            let target = state.recovery_target.ok_or(CoreError::WrongRecoveryState)?;
            if target.boot() != boot
                || target.journal() != journal
                || target.device() != device
                || target.registry() != state.freshness.registry()
            {
                return Err(CoreError::FreshnessRollback);
            }
            let roots: Vec<RootId> = state.roots.keys().copied().collect();
            for root in roots {
                fence_root_for_boot(state, root, limits.max_crashes_per_root)?;
            }
            state.freshness.set_boot_and_journal(boot, journal);
            state.freshness.set_device(device);
            state.recovery_target = None;
            Ok(AppliedOutput::none(TransitionEvent::RecoveryCheckpointed))
        }
        CommandKind::ReserveReuse {
            effect,
            actor,
            binding_generation,
            claim,
            domain,
            kind,
            scope,
            resource,
            expected_generation,
            units,
        } => {
            if state.recovery_target.is_some() {
                return Err(CoreError::RecoveryPending);
            }
            if scope_is_quarantined(state, scope) {
                return Err(CoreError::Quarantined);
            }
            require_active_actor(state, effect, actor, binding_generation)?;
            let authority_epoch = state
                .estates
                .get(&effect)
                .ok_or(CoreError::UnknownEstate)?
                .authority_epoch;
            let record = state
                .resources
                .get(&resource)
                .ok_or(CoreError::UnknownResource)?;
            if record.scope != scope {
                return Err(CoreError::WrongClaimScope);
            }
            if record.generation != expected_generation {
                return Err(CoreError::StaleResourceGeneration);
            }
            match record.phase {
                ResourcePhase::Claimed { .. } => return Err(CoreError::ResourceRetained),
                ResourcePhase::Retired => {}
            }
            let generation = ResourceGeneration::new(
                expected_generation
                    .get()
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?,
            )
            .map_err(|_| CoreError::GenerationExhausted)?;
            let nonce = allocate_nonce(state)?;
            let reservation_freshness = scoped_freshness(state, scope, binding_generation)?;
            state.resources.insert(
                resource,
                ResourceRecord {
                    scope,
                    generation,
                    phase: ResourcePhase::Claimed {
                        pending_reuse: Some(PendingReuse {
                            effect,
                            actor,
                            binding_generation,
                            authority_epoch,
                            nonce,
                            freshness: reservation_freshness,
                        }),
                    },
                },
            );
            enroll_claim(
                catalog,
                limits,
                state,
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                generation,
                units,
                Some(nonce),
            )?;
            Ok(AppliedOutput {
                event: TransitionEvent::ResourceReuseReserved,
                output: OutputData::ReusePermit {
                    effect,
                    actor,
                    binding_generation,
                    authority_epoch,
                    resource,
                    generation,
                    freshness: reservation_freshness,
                    nonce,
                },
            })
        }
        CommandKind::ActivateResourceReuse {
            effect,
            actor,
            binding_generation,
            authority_epoch,
            resource,
            resource_generation,
            nonce,
            freshness,
        } => {
            require_active_actor(state, effect, actor, binding_generation)?;
            if state
                .estates
                .get(&effect)
                .ok_or(CoreError::UnknownEstate)?
                .authority_epoch
                != authority_epoch
            {
                return Err(CoreError::StaleAuthorityEpoch);
            }
            let scope = state
                .resources
                .get(&resource)
                .ok_or(CoreError::UnknownResource)?
                .scope;
            if scope_is_quarantined(state, scope) {
                return Err(CoreError::Quarantined);
            }
            let current_freshness = scoped_freshness(state, scope, binding_generation)?;
            let record = state
                .resources
                .get_mut(&resource)
                .expect("resource was validated");
            if record.generation != resource_generation {
                return Err(CoreError::StaleResourceGeneration);
            }
            match record.phase {
                ResourcePhase::Claimed {
                    pending_reuse:
                        Some(PendingReuse {
                            effect: expected_effect,
                            actor: expected_actor,
                            binding_generation: expected_binding,
                            authority_epoch: expected_epoch,
                            nonce: expected_nonce,
                            freshness: expected_freshness,
                        }),
                } if expected_effect == effect
                    && expected_actor == actor
                    && expected_binding == binding_generation
                    && expected_epoch == authority_epoch
                    && expected_nonce == nonce
                    && expected_freshness == freshness
                    && freshness == current_freshness =>
                {
                    record.phase = ResourcePhase::Claimed {
                        pending_reuse: None,
                    };
                    Ok(AppliedOutput::none(TransitionEvent::ResourceReuseActivated))
                }
                _ => Err(CoreError::StaleReusePermit),
            }
        }
        CommandKind::ReclaimResourceReuse {
            effect,
            actor,
            binding_generation,
            authority_epoch,
            resource,
            resource_generation,
        } => {
            require_active_actor(state, effect, actor, binding_generation)?;
            let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
            if estate.authority_epoch != authority_epoch {
                return Err(CoreError::StaleAuthorityEpoch);
            }
            if !estate.claims.values().any(|claim| {
                !claim.retired
                    && claim.resource == resource
                    && claim.resource_generation == resource_generation
            }) {
                return Err(CoreError::UnknownClaim);
            }
            let (previous, scope) = match state.resources.get(&resource) {
                Some(ResourceRecord {
                    scope,
                    generation,
                    phase:
                        ResourcePhase::Claimed {
                            pending_reuse: Some(pending),
                        },
                }) if *generation == resource_generation => (*pending, *scope),
                Some(ResourceRecord { generation, .. }) if *generation != resource_generation => {
                    return Err(CoreError::StaleResourceGeneration);
                }
                _ => return Err(CoreError::StaleReusePermit),
            };
            if scope_is_quarantined(state, scope) {
                return Err(CoreError::Quarantined);
            }
            if previous.effect != effect
                || previous.authority_epoch >= authority_epoch
                || (previous.actor == actor && previous.binding_generation == binding_generation)
            {
                return Err(CoreError::GateClaimed);
            }
            let nonce = allocate_nonce(state)?;
            let reservation_freshness = scoped_freshness(state, scope, binding_generation)?;
            let pending = PendingReuse {
                effect,
                actor,
                binding_generation,
                authority_epoch,
                nonce,
                freshness: reservation_freshness,
            };
            state
                .resources
                .get_mut(&resource)
                .expect("resource was validated")
                .phase = ResourcePhase::Claimed {
                pending_reuse: Some(pending),
            };
            Ok(AppliedOutput {
                event: TransitionEvent::ResourceReuseReclaimed,
                output: OutputData::ReusePermit {
                    effect,
                    actor,
                    binding_generation,
                    authority_epoch,
                    resource,
                    generation: resource_generation,
                    freshness: reservation_freshness,
                    nonce,
                },
            })
        }
        CommandKind::ReleaseEstate { effect } => {
            let estate = state
                .estates
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEstate)?;
            if estate.retirement != RetirementState::Retired
                || !matches!(
                    estate.settlement,
                    SettlementState::Settled
                        | SettlementState::Revoked
                        | SettlementState::NotRequired
                )
            {
                return Err(CoreError::EstateNotReleasable);
            }
            estate.retirement = RetirementState::Released;
            estate.custodian = CustodyState::Released;
            Ok(AppliedOutput::none(TransitionEvent::EstateReleased))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn enroll_claim(
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut State,
    effect: EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    claim: ClaimId,
    domain: DomainId,
    kind: ClaimKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    reservation_nonce: Option<u64>,
) -> Result<AppliedOutput, CoreError> {
    if units == 0 {
        return Err(CoreError::InvalidPayload);
    }
    let rule = catalog
        .claim_rule(domain, kind)
        .ok_or(CoreError::UnknownClaimClass)?;
    if !matches!(
        (rule.scope(), scope),
        (ClaimScopePolicy::Logical, ClaimScope::Logical)
            | (ClaimScopePolicy::Device, ClaimScope::Device(_))
    ) {
        return Err(CoreError::WrongClaimScope);
    }
    if let ClaimScope::Device(device_scope) = scope {
        state
            .device_generations
            .entry(device_scope)
            .or_insert(state.freshness.device());
        if state.device_quarantine.contains(&device_scope) {
            return Err(CoreError::Quarantined);
        }
    }
    let credit_class = rule.credit_class();
    let credit_limit = catalog
        .credit_rule(credit_class)
        .ok_or(CoreError::InvariantViolation)?
        .max_units_per_account()
        .min(limits.max_units_per_account);
    require_active_actor(state, effect, actor, binding_generation)?;

    match (state.resources.get(&resource), reservation_nonce) {
        (None, None) if resource_generation.get() == 1 => {
            if state.resources.len() >= limits.max_resource_records {
                return Err(CoreError::CapacityExceeded);
            }
        }
        (
            Some(ResourceRecord {
                scope: existing_scope,
                generation,
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: None,
                    },
            }),
            None,
        ) if *existing_scope == scope && *generation == resource_generation => {}
        (
            Some(ResourceRecord {
                scope: existing_scope,
                generation,
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: Some(PendingReuse { nonce, .. }),
                    },
            }),
            Some(presented_nonce),
        ) if *existing_scope == scope
            && *generation == resource_generation
            && *nonce == presented_nonce => {}
        (
            Some(ResourceRecord {
                scope: existing, ..
            }),
            _,
        ) if *existing != scope => {
            return Err(CoreError::WrongClaimScope);
        }
        (Some(ResourceRecord { generation, .. }), _) if *generation != resource_generation => {
            return Err(CoreError::StaleResourceGeneration);
        }
        (
            Some(ResourceRecord {
                phase: ResourcePhase::Retired,
                ..
            }),
            None,
        )
        | (
            Some(ResourceRecord {
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: Some(_),
                    },
                ..
            }),
            None,
        ) => {
            return Err(CoreError::ResourceReuseRequired);
        }
        (
            Some(ResourceRecord {
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: None,
                    },
                ..
            }),
            None,
        ) => {
            return Err(CoreError::StaleResourceGeneration);
        }
        (Some(ResourceRecord { .. }), Some(_)) | (None, Some(_)) => {
            return Err(CoreError::StaleReusePermit);
        }
        (None, None) => return Err(CoreError::StaleResourceGeneration),
    }

    let enrolled_freshness = scoped_freshness(state, scope, binding_generation)?;
    let total_claims: usize = state
        .estates
        .values()
        .map(|estate| estate.claims.len())
        .sum();
    if total_claims >= limits.max_total_claims {
        return Err(CoreError::CapacityExceeded);
    }
    let estate = state
        .estates
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEstate)?;
    if estate.authority != AuthorityState::Active || estate.commit != CommitState::Registered {
        return Err(CoreError::WrongCommitState);
    }
    if estate.domain != domain {
        return Err(CoreError::UnknownClaimClass);
    }
    let cardinality = catalog
        .obligation_rule(estate.domain, estate.obligation)
        .ok_or(CoreError::InvariantViolation)?
        .claims()
        .iter()
        .find(|allowed| allowed.kind() == kind)
        .ok_or(CoreError::ClaimNotAllowed)?;
    let existing_of_kind = estate
        .claims
        .values()
        .filter(|candidate| candidate.kind == kind)
        .count();
    if existing_of_kind >= usize::from(cardinality.maximum()) {
        return Err(CoreError::ClaimCardinalityViolation);
    }
    if estate.claims.len() >= limits.max_claims_per_estate {
        return Err(CoreError::CapacityExceeded);
    }
    if estate.claims.contains_key(&claim) {
        return Err(CoreError::DuplicateClaim);
    }
    let charged = state
        .charges
        .get(&(estate.charge_owner, credit_class))
        .copied()
        .unwrap_or(0);
    let next = charged.checked_add(units).ok_or(CoreError::Backpressure)?;
    if next > credit_limit {
        return Err(CoreError::Backpressure);
    }

    let requirements = rule
        .evidence()
        .iter()
        .map(|evidence| RequirementState {
            kind: evidence.kind(),
            verifier: evidence.verifier(),
            receipt_schema: evidence.receipt_schema(),
            subject_freshness: evidence.subject_freshness(),
            observation_freshness: evidence.observation_freshness(),
            strictly_advanced: evidence.strictly_advanced(),
            device_generation: evidence.device_generation(),
            prerequisite: evidence.prerequisite(),
            accepted: None,
        })
        .collect();
    estate.claims.insert(
        claim,
        ClaimRecord {
            id: claim,
            domain,
            kind,
            credit_class,
            scope,
            resource,
            resource_generation,
            units,
            enrolled_freshness,
            requirements,
            retired: false,
        },
    );
    *state
        .charges
        .entry((estate.charge_owner, credit_class))
        .or_insert(0) = next;
    let entries = state.resource_index.entry(resource).or_default();
    match entries.binary_search(&(effect, claim)) {
        Ok(_) => return Err(CoreError::InvariantViolation),
        Err(index) => entries.insert(index, (effect, claim)),
    }
    if reservation_nonce.is_none() {
        state.resources.insert(
            resource,
            ResourceRecord {
                scope,
                generation: resource_generation,
                phase: ResourcePhase::Claimed {
                    pending_reuse: None,
                },
            },
        );
    }
    Ok(AppliedOutput::none(TransitionEvent::ClaimAdded))
}

fn allocate_nonce(state: &mut State) -> Result<u64, CoreError> {
    let nonce = state.next_nonce;
    state.next_nonce = state
        .next_nonce
        .checked_add(1)
        .ok_or(CoreError::GenerationExhausted)?;
    if nonce == 0 {
        return Err(CoreError::GenerationExhausted);
    }
    Ok(nonce)
}

fn validate_obligation_claims(
    catalog: &DomainCatalog,
    estate: &EstateRecord,
) -> Result<(), CoreError> {
    let rule = catalog
        .obligation_rule(estate.domain, estate.obligation)
        .ok_or(CoreError::InvariantViolation)?;
    if estate.claims.len() < usize::from(rule.minimum_total_claims()) {
        return Err(CoreError::ClaimCardinalityViolation);
    }
    for cardinality in rule.claims() {
        let count = estate
            .claims
            .values()
            .filter(|claim| claim.kind == cardinality.kind())
            .count();
        if count < usize::from(cardinality.minimum()) || count > usize::from(cardinality.maximum())
        {
            return Err(CoreError::ClaimCardinalityViolation);
        }
    }
    if estate.claims.values().any(|claim| {
        !rule
            .claims()
            .iter()
            .any(|allowed| allowed.kind() == claim.kind)
    }) {
        return Err(CoreError::ClaimNotAllowed);
    }
    Ok(())
}

fn scoped_freshness(
    state: &State,
    scope: ClaimScope,
    binding_generation: u64,
) -> Result<Freshness, CoreError> {
    let freshness = state
        .freshness
        .with_binding(binding_generation)
        .map_err(|_| CoreError::InvariantViolation)?;
    match scope {
        ClaimScope::Logical => Ok(freshness),
        ClaimScope::Device(device_scope) => state
            .device_generations
            .get(&device_scope)
            .copied()
            .map(|device| freshness.with_device(device))
            .ok_or(CoreError::WrongClaimScope),
    }
}

fn estate_freshness(state: &State, estate: &EstateRecord) -> Result<Freshness, CoreError> {
    let binding_generation = state
        .roots
        .get(&estate.effect.root())
        .ok_or(CoreError::UnknownRoot)?
        .last_binding_generation;
    let mut device_scope = None;
    for claim in estate.claims.values() {
        if let ClaimScope::Device(scope) = claim.scope {
            if device_scope.is_some_and(|existing| existing != scope) {
                return Err(CoreError::WrongClaimScope);
            }
            device_scope = Some(scope);
        }
    }
    scoped_freshness(
        state,
        device_scope.map_or(ClaimScope::Logical, ClaimScope::Device),
        binding_generation,
    )
}

fn settlement_claim_matches(estate: &EstateRecord, claim: &SettlementClaim) -> bool {
    let identity_matches = match estate.settlement {
        SettlementState::Claimed {
            claimant,
            generation,
        }
        | SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        }
        | SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => claimant == claim.claimant && generation == claim.generation,
        _ => false,
    };
    identity_matches && estate.settlement_nonce == Some(claim.nonce)
}

fn scope_is_quarantined(state: &State, scope: ClaimScope) -> bool {
    matches!(scope, ClaimScope::Device(device) if state.device_quarantine.contains(&device))
}

fn require_digest(digest: Digest) -> Result<(), CoreError> {
    if digest.is_zero() {
        Err(CoreError::InvalidPayload)
    } else {
        Ok(())
    }
}

fn require_active_actor(
    state: &State,
    effect: EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
) -> Result<(), CoreError> {
    let root = state
        .roots
        .get(&effect.root())
        .ok_or(CoreError::UnknownRoot)?;
    let live = match root.state {
        RootRecoveryState::Active {
            incarnation,
            binding_generation,
        }
        | RootRecoveryState::Rebound {
            successor: incarnation,
            binding_generation,
        } => (incarnation, binding_generation),
        _ => return Err(CoreError::WrongRecoveryState),
    };
    if live != (actor, binding_generation) {
        return Err(CoreError::StaleIncarnation);
    }
    let estate = state.estates.get(&effect).ok_or(CoreError::UnknownEstate)?;
    if estate.authority != AuthorityState::Active
        || estate.custodian != CustodyState::Principal(actor)
    {
        return Err(CoreError::StaleIncarnation);
    }
    Ok(())
}

fn exact_claim_mut(
    state: &mut State,
    effect: EffectId,
    claimant: PrincipalIncarnation,
    generation: u64,
    nonce: u64,
) -> Result<&mut EstateRecord, CoreError> {
    let estate = state
        .estates
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEstate)?;
    let matches = match estate.settlement {
        SettlementState::Claimed {
            claimant: expected,
            generation: expected_generation,
        }
        | SettlementState::ApplyIntentDurable {
            claimant: expected,
            generation: expected_generation,
        }
        | SettlementState::AppliedUnacknowledged {
            claimant: expected,
            generation: expected_generation,
        } => expected == claimant && expected_generation == generation,
        _ => false,
    };
    if !matches || estate.settlement_nonce != Some(nonce) {
        return Err(CoreError::StaleSettlementClaim);
    }
    Ok(estate)
}

fn apply_fence_incarnation(
    state: &mut State,
    root: RootId,
    crashed: PrincipalIncarnation,
    binding_generation: u64,
    max_crashes: u64,
) -> Result<(), CoreError> {
    let quota_exhausted = {
        let root_record = state.roots.get_mut(&root).ok_or(CoreError::UnknownRoot)?;
        let live = match root_record.state {
            RootRecoveryState::Active {
                incarnation,
                binding_generation: live_binding,
            }
            | RootRecoveryState::Rebound {
                successor: incarnation,
                binding_generation: live_binding,
            } => (incarnation, live_binding),
            RootRecoveryState::RecoveryExhausted { .. } => {
                return Err(CoreError::RecoveryExhausted);
            }
            _ => return Err(CoreError::WrongRecoveryState),
        };
        if live != (crashed, binding_generation) {
            return Err(CoreError::StaleIncarnation);
        }
        let (crash_generation, exhausted) =
            next_crash_generation(root_record.crash_generation, max_crashes);
        root_record.crash_generation = crash_generation;
        root_record.last_binding_generation = binding_generation;
        root_record.state = if exhausted {
            RootRecoveryState::RecoveryExhausted {
                crashed,
                binding_generation,
                crash_generation,
            }
        } else {
            RootRecoveryState::Fenced {
                crashed,
                binding_generation,
                crash_generation,
            }
        };
        exhausted
    };
    let authority_epoch_exhausted = fence_estates(state, root)?;
    if authority_epoch_exhausted && !quota_exhausted {
        let root_record = state.roots.get_mut(&root).expect("root was validated");
        root_record.state = RootRecoveryState::RecoveryExhausted {
            crashed,
            binding_generation,
            crash_generation: root_record.crash_generation,
        };
    }
    Ok(())
}

/// Fences every estate and returns whether an authority epoch saturated.
fn fence_estates(state: &mut State, root: RootId) -> Result<bool, CoreError> {
    let mut authority_epoch_exhausted = false;
    for estate in state
        .estates
        .values_mut()
        .filter(|estate| estate.effect.root() == root)
    {
        if estate.retirement == RetirementState::Released {
            continue;
        }
        if estate.authority != AuthorityState::Revoked {
            if estate.authority == AuthorityState::Active {
                match estate.authority_epoch.checked_add(1) {
                    Some(next) => estate.authority_epoch = next,
                    None => authority_epoch_exhausted = true,
                }
            }
            estate.authority = AuthorityState::Fenced;
            estate.custodian = CustodyState::KernelEstate;
        }
        if estate.commit == CommitState::CommitIntentDurable {
            let reason = estate
                .commit_operation
                .ok_or(CoreError::InvariantViolation)?;
            estate.commit = CommitState::Committed;
            estate.commit_nonce = None;
            estate.outcome = OutcomeState::Indeterminate(reason);
        }
        if estate.commit == CommitState::Committed {
            initialize_committed_disposition(estate)?;
            if estate.obligation_policy == ObligationPolicy::SuccessorSettlement {
                reclaim_settlement(estate)?;
            }
        }
        refresh_retirement(estate);
    }
    Ok(authority_epoch_exhausted)
}

fn reclaim_settlement(estate: &mut EstateRecord) -> Result<(), CoreError> {
    let next_generation =
        match estate.settlement {
            SettlementState::Unavailable => 1,
            SettlementState::NotRequired => return Ok(()),
            SettlementState::Open { generation } | SettlementState::Claimed { generation, .. } => {
                generation
                    .checked_add(u64::from(!matches!(
                        estate.settlement,
                        SettlementState::Open { .. }
                    )))
                    .ok_or(CoreError::GenerationExhausted)?
            }
            SettlementState::ApplyIntentDurable { generation, .. }
            | SettlementState::AppliedUnacknowledged { generation, .. }
            | SettlementState::ReconciliationRequired { generation, .. } => generation
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted)?,
            SettlementState::Settled | SettlementState::Revoked => return Ok(()),
        };
    estate.settlement = match estate.settlement {
        SettlementState::Claimed { .. } => match estate.claim_stage {
            Some(ClaimStage::Fresh) => SettlementState::Open {
                generation: next_generation,
            },
            Some(ClaimStage::ReconcileIntent) => SettlementState::ReconciliationRequired {
                generation: next_generation,
                applied: false,
            },
            Some(ClaimStage::ReconcileApplied) => SettlementState::ReconciliationRequired {
                generation: next_generation,
                applied: true,
            },
            _ => return Err(CoreError::InvariantViolation),
        },
        SettlementState::ApplyIntentDurable { .. } => SettlementState::ReconciliationRequired {
            generation: next_generation,
            applied: false,
        },
        SettlementState::AppliedUnacknowledged { .. } => SettlementState::ReconciliationRequired {
            generation: next_generation,
            applied: true,
        },
        SettlementState::ReconciliationRequired { applied, .. } => {
            SettlementState::ReconciliationRequired {
                generation: next_generation,
                applied,
            }
        }
        SettlementState::Settled | SettlementState::Revoked | SettlementState::NotRequired => {
            estate.settlement
        }
        _ => SettlementState::Open {
            generation: next_generation,
        },
    };
    estate.settlement_nonce = None;
    estate.claim_stage = None;
    Ok(())
}

fn initialize_committed_disposition(estate: &mut EstateRecord) -> Result<(), CoreError> {
    match (estate.obligation_policy, estate.settlement) {
        (ObligationPolicy::SuccessorSettlement, SettlementState::Unavailable) => {
            estate.settlement = SettlementState::Open { generation: 1 };
        }
        (ObligationPolicy::RetirementEvidence, SettlementState::Unavailable) => {
            estate.settlement = SettlementState::NotRequired;
        }
        (ObligationPolicy::SuccessorSettlement, SettlementState::NotRequired)
        | (ObligationPolicy::RetirementEvidence, SettlementState::Open { .. })
        | (
            ObligationPolicy::RetirementEvidence,
            SettlementState::Claimed { .. }
            | SettlementState::ApplyIntentDurable { .. }
            | SettlementState::AppliedUnacknowledged { .. }
            | SettlementState::ReconciliationRequired { .. }
            | SettlementState::Settled,
        ) => return Err(CoreError::InvariantViolation),
        _ => {}
    }
    Ok(())
}

fn fence_root_for_boot(state: &mut State, root: RootId, max_crashes: u64) -> Result<(), CoreError> {
    let (crashed, binding_generation, quota_exhausted) = {
        let root_record = state.roots.get_mut(&root).ok_or(CoreError::UnknownRoot)?;
        let already_exhausted = matches!(
            root_record.state,
            RootRecoveryState::RecoveryExhausted { .. }
        );
        let crashed = match root_record.state {
            RootRecoveryState::Active { incarnation, .. }
            | RootRecoveryState::Rebound {
                successor: incarnation,
                ..
            } => incarnation,
            RootRecoveryState::Fenced { crashed, .. }
            | RootRecoveryState::RecoveryExhausted { crashed, .. } => crashed,
            RootRecoveryState::Snapshotted { .. } | RootRecoveryState::Ready { .. } => {
                PrincipalIncarnation::new(
                    root_record.origin.principal(),
                    root_record.last_incarnation_generation,
                )
                .map_err(|_| CoreError::InvariantViolation)?
            }
        };
        let (crash_generation, quota_exhausted) = if already_exhausted {
            (root_record.crash_generation, true)
        } else {
            next_crash_generation(root_record.crash_generation, max_crashes)
        };
        root_record.crash_generation = crash_generation;
        let binding_generation = root_record.last_binding_generation;
        root_record.state = if quota_exhausted {
            RootRecoveryState::RecoveryExhausted {
                crashed,
                binding_generation,
                crash_generation,
            }
        } else {
            RootRecoveryState::Fenced {
                crashed,
                binding_generation,
                crash_generation,
            }
        };
        (crashed, binding_generation, quota_exhausted)
    };
    let authority_epoch_exhausted = fence_estates(state, root)?;
    if authority_epoch_exhausted && !quota_exhausted {
        let root_record = state.roots.get_mut(&root).expect("root was validated");
        root_record.state = RootRecoveryState::RecoveryExhausted {
            crashed,
            binding_generation,
            crash_generation: root_record.crash_generation,
        };
    }
    Ok(())
}

fn next_crash_generation(current: u64, max_crashes: u64) -> (u64, bool) {
    match current.checked_add(1) {
        Some(next) => (next, next > max_crashes),
        None => (u64::MAX, true),
    }
}

fn apply_evidence(
    catalog: &DomainCatalog,
    state: &mut State,
    effect: EffectId,
    claim_id: ClaimId,
    evidence: RetirementEvidence,
) -> Result<AppliedOutput, CoreError> {
    require_digest(evidence.stamp.receipt_digest)?;
    let root = state
        .roots
        .get(&effect.root())
        .ok_or(CoreError::UnknownRoot)?;
    let binding_generation = root.last_binding_generation;
    let claim_record = state
        .estates
        .get(&effect)
        .and_then(|estate| estate.claims.get(&claim_id))
        .ok_or(CoreError::UnknownClaim)?;
    let claim_scope = claim_record.scope;
    let declared = catalog
        .claim_rule(claim_record.domain, claim_record.kind)
        .ok_or(CoreError::UnknownClaimClass)?
        .evidence()
        .iter()
        .find(|rule| rule.kind() == evidence.kind)
        .copied()
        .ok_or(CoreError::UnexpectedEvidence)?;
    if evidence.stamp.identity.verifier() != declared.verifier() {
        return Err(CoreError::UnknownVerifier);
    }
    if evidence.stamp.identity.receipt_schema() != declared.receipt_schema() {
        return Err(CoreError::ReceiptSchemaMismatch);
    }
    if state.verifier_epochs.get(&declared.verifier()).copied()
        != Some(evidence.stamp.identity.epoch())
    {
        return Err(CoreError::StaleVerifierEpoch);
    }
    if declared.device_generation() == DeviceGenerationEffect::AdvanceOne {
        let ClaimScope::Device(device_scope) = claim_scope else {
            return Err(CoreError::InvariantViolation);
        };
        let current = state
            .device_generations
            .get(&device_scope)
            .copied()
            .ok_or(CoreError::WrongClaimScope)?;
        let observed = evidence.freshness.device();
        let next = current
            .get()
            .checked_add(1)
            .and_then(|value| DeviceGeneration::new(value).ok())
            .ok_or(CoreError::GenerationExhausted)?;
        if observed == next {
            state.device_generations.insert(device_scope, next);
        } else if observed != current || observed.get() <= evidence.subject.device().get() {
            return Err(CoreError::InvalidDeviceGenerationAdvance);
        }
    }
    let current_freshness = scoped_freshness(state, claim_scope, binding_generation)?;
    let (charge_owner, credit_class, resource, resource_generation, units, retired_now) = {
        let estate = state
            .estates
            .get_mut(&effect)
            .ok_or(CoreError::UnknownEstate)?;
        if estate.authority == AuthorityState::Active && estate.commit != CommitState::Committed {
            return Err(CoreError::WrongCommitState);
        }
        if estate.retirement == RetirementState::Released {
            return Err(CoreError::EstateNotReleasable);
        }
        let claim = estate
            .claims
            .get_mut(&claim_id)
            .ok_or(CoreError::UnknownClaim)?;
        let rule = catalog
            .claim_rule(claim.domain, claim.kind)
            .ok_or(CoreError::UnknownClaimClass)?;
        if rule.evidence().len() != claim.requirements.len() {
            return Err(CoreError::InvariantViolation);
        }
        if claim.retired {
            return Err(CoreError::DuplicateEvidence);
        }
        let requirement_index = claim
            .requirements
            .iter()
            .position(|requirement| requirement.kind == evidence.kind)
            .ok_or(CoreError::UnexpectedEvidence)?;
        let requirement = &claim.requirements[requirement_index];
        if requirement.accepted.is_some() {
            return Err(CoreError::DuplicateEvidence);
        }
        if let Some(prerequisite) = requirement.prerequisite
            && !claim
                .requirements
                .iter()
                .any(|candidate| candidate.kind == prerequisite && candidate.accepted.is_some())
        {
            return Err(CoreError::EvidenceOutOfOrder);
        }
        validate_evidence_freshness(
            requirement,
            evidence,
            claim.enrolled_freshness,
            current_freshness,
            binding_generation,
        )?;
        claim.requirements[requirement_index].accepted = Some(AcceptedEvidence {
            subject: evidence.subject,
            observation: evidence.freshness,
            stamp: evidence.stamp,
        });
        let retired_now = claim
            .requirements
            .iter()
            .all(|requirement| requirement.accepted.is_some());
        if retired_now {
            claim.retired = true;
        }
        (
            estate.charge_owner,
            claim.credit_class,
            claim.resource,
            claim.resource_generation,
            claim.units,
            retired_now,
        )
    };

    if retired_now {
        let charged = state
            .charges
            .get_mut(&(charge_owner, credit_class))
            .ok_or(CoreError::InvariantViolation)?;
        *charged = charged
            .checked_sub(units)
            .ok_or(CoreError::InvariantViolation)?;
        let entries = state
            .resource_index
            .get_mut(&resource)
            .ok_or(CoreError::InvariantViolation)?;
        let before = entries.len();
        entries.retain(|entry| *entry != (effect, claim_id));
        if entries.len() + 1 != before {
            return Err(CoreError::InvariantViolation);
        }
        if entries.is_empty() {
            state.resource_index.remove(&resource);
            let record = state
                .resources
                .get_mut(&resource)
                .ok_or(CoreError::InvariantViolation)?;
            if record.generation != resource_generation
                || !matches!(record.phase, ResourcePhase::Claimed { .. })
            {
                return Err(CoreError::InvariantViolation);
            }
            record.phase = ResourcePhase::Retired;
        }
        let estate = state
            .estates
            .get_mut(&effect)
            .expect("estate remains present while evidence retires");
        refresh_retirement(estate);
        if let ClaimScope::Device(scope) = claim_scope
            && !state.estates.values().any(|estate| {
                estate
                    .claims
                    .values()
                    .any(|claim| !claim.retired && claim.scope == ClaimScope::Device(scope))
            })
        {
            state.device_quarantine.remove(&scope);
        }
    }

    Ok(AppliedOutput::none(TransitionEvent::EvidenceAccepted))
}

fn validate_effect_fact(
    catalog: &DomainCatalog,
    state: &State,
    estate: &EstateRecord,
    fact: VerifiedEffectFact,
) -> Result<(), CoreError> {
    require_digest(fact.stamp.receipt_digest)?;
    if fact.effect != estate.effect || fact.freshness != estate_freshness(state, estate)? {
        return Err(CoreError::StaleEvidence);
    }
    let receipts = catalog
        .obligation_rule(estate.domain, estate.obligation)
        .ok_or(CoreError::UnknownObligationClass)?
        .receipts();
    let binding = match fact.kind {
        EffectFactKind::CommitOutcome => Some(receipts.commit_outcome()),
        EffectFactKind::ApplyCompleted => receipts.apply_completed(),
        EffectFactKind::SettlementAcknowledged => receipts.settlement_acknowledged(),
    }
    .ok_or(CoreError::WrongSettlementStage)?;
    if fact.stamp.identity.verifier() != binding.verifier() {
        return Err(CoreError::UnknownVerifier);
    }
    if fact.stamp.identity.receipt_schema() != binding.receipt_schema() {
        return Err(CoreError::ReceiptSchemaMismatch);
    }
    if state.verifier_epochs.get(&binding.verifier()).copied() != Some(fact.stamp.identity.epoch())
    {
        return Err(CoreError::StaleVerifierEpoch);
    }
    if matches!(
        (fact.kind, fact.outcome),
        (EffectFactKind::CommitOutcome, None)
            | (
                EffectFactKind::ApplyCompleted | EffectFactKind::SettlementAcknowledged,
                Some(_)
            )
    ) {
        return Err(CoreError::VerificationFailed);
    }
    Ok(())
}

fn fact_stamp_matches(
    state: &State,
    fact: VerifiedEffectFact,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> bool {
    !fact.stamp.receipt_digest.is_zero()
        && fact.stamp.identity.verifier() == verifier
        && fact.stamp.identity.receipt_schema() == receipt_schema
        && state.verifier_epochs.get(&verifier).copied() == Some(fact.stamp.identity.epoch())
}

fn validate_evidence_freshness(
    requirement: &RequirementState,
    evidence: RetirementEvidence,
    enrolled: Freshness,
    active: Freshness,
    binding_generation: u64,
) -> Result<(), CoreError> {
    if !freshness_matches(
        requirement.subject_freshness,
        evidence.subject,
        enrolled,
        enrolled.binding(),
    ) || !freshness_matches(
        requirement.observation_freshness,
        evidence.freshness,
        active,
        binding_generation,
    ) || !freshness_strictly_advances(
        requirement.strictly_advanced,
        evidence.subject,
        evidence.freshness,
    ) {
        return Err(CoreError::StaleEvidence);
    }
    Ok(())
}

fn freshness_matches(
    axes: FreshnessAxes,
    presented: Freshness,
    expected: Freshness,
    expected_binding: u64,
) -> bool {
    (!axes.contains(FreshnessAxes::BOOT) || presented.boot() == expected.boot())
        && (!axes.contains(FreshnessAxes::REGISTRY) || presented.registry() == expected.registry())
        && (!axes.contains(FreshnessAxes::BINDING) || presented.binding() == expected_binding)
        && (!axes.contains(FreshnessAxes::DEVICE) || presented.device() == expected.device())
        && (!axes.contains(FreshnessAxes::JOURNAL) || presented.journal() == expected.journal())
}

fn freshness_strictly_advances(
    axes: FreshnessAxes,
    subject: Freshness,
    observation: Freshness,
) -> bool {
    (!axes.contains(FreshnessAxes::BOOT) || observation.boot().get() > subject.boot().get())
        && (!axes.contains(FreshnessAxes::REGISTRY)
            || observation.registry().get() > subject.registry().get())
        && (!axes.contains(FreshnessAxes::BINDING) || observation.binding() > subject.binding())
        && (!axes.contains(FreshnessAxes::DEVICE)
            || observation.device().get() > subject.device().get())
        && (!axes.contains(FreshnessAxes::JOURNAL)
            || observation.journal().get() > subject.journal().get())
}

fn refresh_retirement(estate: &mut EstateRecord) {
    if estate.retirement == RetirementState::Released {
        return;
    }
    if estate.claims.is_empty() {
        estate.retirement = if estate.commit == CommitState::Committed {
            RetirementState::Retired
        } else {
            RetirementState::Held
        };
        return;
    }
    estate.retirement = if estate.claims.values().all(|claim| claim.retired) {
        RetirementState::Retired
    } else if estate.commit == CommitState::Committed || estate.authority != AuthorityState::Active
    {
        RetirementState::RetirementPending
    } else {
        RetirementState::Held
    };
}

fn project_estate(estate: &EstateRecord) -> EstateProjection {
    EstateProjection {
        effect: estate.effect,
        causal_owner: estate.causal_owner,
        custodian: estate.custodian,
        charge_owner: estate.charge_owner,
        obligation: (estate.domain, estate.obligation),
        obligation_policy: estate.obligation_policy,
        authority: estate.authority,
        authority_epoch: estate.authority_epoch,
        commit: estate.commit,
        outcome: estate.outcome,
        settlement: estate.settlement,
        retirement: estate.retirement,
        claim_count: estate.claims.len(),
        retained_claims: estate
            .claims
            .values()
            .filter(|claim| !claim.retired)
            .count(),
    }
}

fn project_claim(effect: EffectId, claim: &ClaimRecord) -> ClaimProjection {
    ClaimProjection {
        effect,
        claim: claim.id,
        domain: claim.domain,
        kind: claim.kind,
        credit_class: claim.credit_class,
        scope: claim.scope,
        resource: claim.resource,
        resource_generation: claim.resource_generation,
        units: claim.units,
        enrolled_freshness: claim.enrolled_freshness,
        retired: claim.retired,
    }
}

fn build_recovery_snapshot(
    catalog: &DomainCatalog,
    state: &State,
    root: RootId,
    snapshot: SnapshotId,
) -> Result<RecoverySnapshot, CoreError> {
    let root_record = state.roots.get(&root).ok_or(CoreError::UnknownRoot)?;
    match root_record.state {
        RootRecoveryState::Fenced { .. } => {}
        RootRecoveryState::RecoveryExhausted { .. } => {
            return Err(CoreError::RecoveryExhausted);
        }
        _ => return Err(CoreError::WrongRecoveryState),
    }
    let mut items = Vec::new();
    for estate in state
        .estates
        .values()
        .filter(|estate| estate.effect.root() == root)
    {
        let adoption = catalog
            .obligation_rule(estate.domain, estate.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .adoption();
        items.push(RecoveryItem {
            effect: estate.effect,
            custodian: estate.custodian,
            obligation: (estate.domain, estate.obligation),
            authority: estate.authority,
            authority_epoch: estate.authority_epoch,
            commit: estate.commit,
            outcome: estate.outcome,
            settlement: estate.settlement,
            retirement: estate.retirement,
            claim_count: estate.claims.len(),
            retained_claims: estate
                .claims
                .values()
                .filter(|claim| !claim.retired)
                .count(),
            adoptable: adoption == crate::AdoptionPolicy::UncommittedOnly
                && estate.authority == AuthorityState::Fenced
                && matches!(
                    estate.commit,
                    CommitState::Registered | CommitState::Prepared
                )
                && estate.settlement == SettlementState::Unavailable
                && estate.custodian == CustodyState::KernelEstate,
            settlement_required: estate.obligation_policy == ObligationPolicy::SuccessorSettlement
                && estate.commit == CommitState::Committed
                && !matches!(
                    estate.settlement,
                    SettlementState::Settled
                        | SettlementState::Revoked
                        | SettlementState::NotRequired
                ),
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.recovery-snapshot.v1");
    hasher.update(root.get().to_le_bytes());
    hasher.update(snapshot.get().to_le_bytes());
    hasher.update(state.revision.to_le_bytes());
    hasher.update(state.head.bytes());
    hash_root_state(&mut hasher, root_record.state);
    for item in &items {
        hasher.update(item.effect.root().get().to_le_bytes());
        hasher.update(item.effect.sequence().to_le_bytes());
        hash_custody(&mut hasher, item.custodian);
        hasher.update(item.obligation.0.get().to_le_bytes());
        hasher.update(item.obligation.1.get().to_le_bytes());
        hasher.update([authority_tag(item.authority)]);
        hasher.update(item.authority_epoch.to_le_bytes());
        hasher.update([commit_tag(item.commit)]);
        hash_outcome(&mut hasher, item.outcome);
        hash_settlement(&mut hasher, item.settlement);
        hasher.update([retirement_tag(item.retirement)]);
        hasher.update((item.claim_count as u64).to_le_bytes());
        hasher.update((item.retained_claims as u64).to_le_bytes());
        hasher.update([u8::from(item.adoptable), u8::from(item.settlement_required)]);
    }
    Ok(RecoverySnapshot {
        root,
        snapshot,
        digest: Digest::new(hasher.finalize().into()),
        covered_revision: state.revision,
        covered_head: state.head,
        items,
    })
}

fn check_invariants(
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &State,
) -> Result<(), CoreError> {
    if state.roots.len() > limits.max_roots
        || state.estates.len() > limits.max_estates
        || state.resources.len() > limits.max_resource_records
    {
        return Err(CoreError::InvariantViolation);
    }
    let total_claims: usize = state
        .estates
        .values()
        .map(|estate| estate.claims.len())
        .sum();
    if total_claims > limits.max_total_claims || state.next_nonce == 0 {
        return Err(CoreError::InvariantViolation);
    }

    let mut expected_charges: BTreeMap<(ChargeAccountId, CreditClassId), u64> = BTreeMap::new();
    let mut expected_resources: BTreeMap<ResourceId, Vec<(EffectId, ClaimId)>> = BTreeMap::new();
    let mut active_resource_generations: BTreeMap<ResourceId, ResourceGeneration> = BTreeMap::new();
    let mut active_resource_scopes: BTreeMap<ResourceId, ClaimScope> = BTreeMap::new();
    for estate in state.estates.values() {
        let obligation_rule = catalog
            .obligation_rule(estate.domain, estate.obligation)
            .ok_or(CoreError::InvariantViolation)?;
        if !state.roots.contains_key(&estate.effect.root())
            || obligation_rule.policy() != estate.obligation_policy
            || estate.claims.len() > limits.max_claims_per_estate
            || estate.authority_epoch == 0
        {
            return Err(CoreError::InvariantViolation);
        }
        for cardinality in obligation_rule.claims() {
            let count = estate
                .claims
                .values()
                .filter(|claim| claim.kind == cardinality.kind())
                .count();
            if count > usize::from(cardinality.maximum())
                || (estate.commit != CommitState::Registered
                    && count < usize::from(cardinality.minimum()))
            {
                return Err(CoreError::InvariantViolation);
            }
        }
        if estate.claims.values().any(|claim| {
            !obligation_rule
                .claims()
                .iter()
                .any(|allowed| allowed.kind() == claim.kind)
        }) {
            return Err(CoreError::InvariantViolation);
        }
        if estate.commit != CommitState::Registered
            && estate.claims.len() < usize::from(obligation_rule.minimum_total_claims())
        {
            return Err(CoreError::InvariantViolation);
        }
        match estate.commit {
            CommitState::CommitIntentDurable
                if estate.commit_nonce.is_none() || estate.commit_operation.is_none() =>
            {
                return Err(CoreError::InvariantViolation);
            }
            CommitState::CommitIntentDurable => {}
            _ if estate.commit_nonce.is_some() => return Err(CoreError::InvariantViolation),
            _ => {}
        }
        let receipts = obligation_rule.receipts();
        if let Some(fact) = estate.commit_fact {
            if estate.commit != CommitState::Committed
                || fact.kind != EffectFactKind::CommitOutcome
                || fact.effect != estate.effect
                || fact.actor != estate.causal_owner
                || fact.operation != estate.commit_operation.unwrap_or(Digest::ZERO)
                || fact.predecessor.is_some()
                || fact.outcome.is_none()
                || !fact_stamp_matches(
                    state,
                    fact,
                    receipts.commit_outcome().verifier(),
                    receipts.commit_outcome().receipt_schema(),
                )
            {
                return Err(CoreError::InvariantViolation);
            }
            if matches!(
                estate.outcome,
                OutcomeState::KnownSuccess(digest) | OutcomeState::KnownFailure(digest)
                    if digest != fact.stamp.receipt_digest
            ) {
                return Err(CoreError::InvariantViolation);
            }
        } else if matches!(
            estate.outcome,
            OutcomeState::KnownSuccess(_) | OutcomeState::KnownFailure(_)
        ) {
            return Err(CoreError::InvariantViolation);
        }
        if let Some(fact) = estate.applied_fact {
            let Some(binding) = receipts.apply_completed() else {
                return Err(CoreError::InvariantViolation);
            };
            if fact.kind != EffectFactKind::ApplyCompleted
                || fact.effect != estate.effect
                || fact.operation != estate.settlement_intent.unwrap_or(Digest::ZERO)
                || fact.predecessor.is_some()
                || fact.outcome.is_some()
                || !fact_stamp_matches(state, fact, binding.verifier(), binding.receipt_schema())
            {
                return Err(CoreError::InvariantViolation);
            }
        }
        let applied_required = matches!(
            estate.settlement,
            SettlementState::AppliedUnacknowledged { .. }
                | SettlementState::ReconciliationRequired { applied: true, .. }
                | SettlementState::Settled
        ) || matches!(
            estate.claim_stage,
            Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
        );
        if applied_required != estate.applied_fact.is_some() {
            return Err(CoreError::InvariantViolation);
        }
        if let Some(fact) = estate.settlement_fact {
            let Some(binding) = receipts.settlement_acknowledged() else {
                return Err(CoreError::InvariantViolation);
            };
            if estate.settlement != SettlementState::Settled
                || fact.kind != EffectFactKind::SettlementAcknowledged
                || fact.effect != estate.effect
                || fact.operation != estate.settlement_intent.unwrap_or(Digest::ZERO)
                || fact.predecessor
                    != estate
                        .applied_fact
                        .map(|applied| applied.stamp.receipt_digest)
                || fact.outcome.is_some()
                || !fact_stamp_matches(state, fact, binding.verifier(), binding.receipt_schema())
            {
                return Err(CoreError::InvariantViolation);
            }
        } else if estate.settlement == SettlementState::Settled {
            return Err(CoreError::InvariantViolation);
        }
        let claim_authority_live = matches!(
            estate.settlement,
            SettlementState::Claimed { .. }
                | SettlementState::ApplyIntentDurable { .. }
                | SettlementState::AppliedUnacknowledged { .. }
        );
        if claim_authority_live
            != (estate.settlement_nonce.is_some() && estate.claim_stage.is_some())
        {
            return Err(CoreError::InvariantViolation);
        }
        if estate.retirement == RetirementState::Released
            && (!estate.claims.values().all(|claim| claim.retired)
                || !matches!(
                    estate.settlement,
                    SettlementState::Settled
                        | SettlementState::Revoked
                        | SettlementState::NotRequired
                )
                || estate.custodian != CustodyState::Released)
        {
            return Err(CoreError::InvariantViolation);
        }
        if estate.retirement != RetirementState::Released
            && estate.custodian == CustodyState::Released
        {
            return Err(CoreError::InvariantViolation);
        }
        match estate.obligation_policy {
            ObligationPolicy::SuccessorSettlement
                if estate.settlement == SettlementState::NotRequired =>
            {
                return Err(CoreError::InvariantViolation);
            }
            ObligationPolicy::RetirementEvidence
                if estate.commit == CommitState::Committed
                    && estate.settlement != SettlementState::NotRequired =>
            {
                return Err(CoreError::InvariantViolation);
            }
            _ => {}
        }

        for claim in estate.claims.values() {
            let rule = catalog
                .claim_rule(claim.domain, claim.kind)
                .ok_or(CoreError::InvariantViolation)?;
            if rule.evidence().len() != claim.requirements.len()
                || claim.domain != estate.domain
                || claim.credit_class != rule.credit_class()
                || !matches!(
                    (rule.scope(), claim.scope),
                    (ClaimScopePolicy::Logical, ClaimScope::Logical)
                        | (ClaimScopePolicy::Device, ClaimScope::Device(_))
                )
                || claim.retired
                    != claim
                        .requirements
                        .iter()
                        .all(|requirement| requirement.accepted.is_some())
            {
                return Err(CoreError::InvariantViolation);
            }
            for (requirement, declared) in claim.requirements.iter().zip(rule.evidence().iter()) {
                if requirement.kind != declared.kind()
                    || requirement.verifier != declared.verifier()
                    || requirement.receipt_schema != declared.receipt_schema()
                    || requirement.subject_freshness != declared.subject_freshness()
                    || requirement.observation_freshness != declared.observation_freshness()
                    || requirement.strictly_advanced != declared.strictly_advanced()
                    || requirement.device_generation != declared.device_generation()
                    || requirement.prerequisite != declared.prerequisite()
                {
                    return Err(CoreError::InvariantViolation);
                }
                if let Some(accepted) = requirement.accepted
                    && (accepted.stamp.receipt_digest == Digest::ZERO
                        || accepted.stamp.identity.verifier() != requirement.verifier
                        || accepted.stamp.identity.receipt_schema() != requirement.receipt_schema
                        || accepted.stamp.identity.epoch() == 0
                        || !freshness_matches(
                            requirement.subject_freshness,
                            accepted.subject,
                            claim.enrolled_freshness,
                            claim.enrolled_freshness.binding(),
                        )
                        || !freshness_strictly_advances(
                            requirement.strictly_advanced,
                            accepted.subject,
                            accepted.observation,
                        )
                        || requirement.prerequisite.is_some_and(|prerequisite| {
                            !claim.requirements.iter().any(|candidate| {
                                candidate.kind == prerequisite && candidate.accepted.is_some()
                            })
                        }))
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            if !claim.retired {
                let charged = expected_charges
                    .entry((estate.charge_owner, claim.credit_class))
                    .or_insert(0);
                *charged = charged
                    .checked_add(claim.units)
                    .ok_or(CoreError::InvariantViolation)?;
                expected_resources
                    .entry(claim.resource)
                    .or_default()
                    .push((estate.effect, claim.id));
                if active_resource_generations
                    .insert(claim.resource, claim.resource_generation)
                    .is_some_and(|generation| generation != claim.resource_generation)
                {
                    return Err(CoreError::InvariantViolation);
                }
                if active_resource_scopes
                    .insert(claim.resource, claim.scope)
                    .is_some_and(|scope| scope != claim.scope)
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
        }
        let projected = project_estate(estate);
        let expected_retirement = if estate.retirement == RetirementState::Released {
            RetirementState::Released
        } else if estate.claims.is_empty() {
            if estate.commit == CommitState::Committed {
                RetirementState::Retired
            } else {
                RetirementState::Held
            }
        } else if projected.retained_claims == 0 {
            RetirementState::Retired
        } else if estate.commit == CommitState::Committed
            || estate.authority != AuthorityState::Active
        {
            RetirementState::RetirementPending
        } else {
            RetirementState::Held
        };
        if estate.retirement != expected_retirement {
            return Err(CoreError::InvariantViolation);
        }
    }
    for key in state.charges.keys().chain(expected_charges.keys()) {
        let actual = state.charges.get(key).copied().unwrap_or(0);
        let expected = expected_charges.get(key).copied().unwrap_or(0);
        let class_limit = catalog
            .credit_rule(key.1)
            .ok_or(CoreError::InvariantViolation)?
            .max_units_per_account()
            .min(limits.max_units_per_account);
        if actual != expected || actual > class_limit {
            return Err(CoreError::InvariantViolation);
        }
    }
    if state.resource_index != expected_resources {
        return Err(CoreError::InvariantViolation);
    }
    for (resource, record) in &state.resources {
        match record.phase {
            ResourcePhase::Claimed { pending_reuse } => {
                let pending_is_invalid = pending_reuse.is_some_and(|pending| {
                    pending.nonce == 0
                        || pending.binding_generation == 0
                        || pending.authority_epoch == 0
                        || !state.estates.get(&pending.effect).is_some_and(|estate| {
                            estate.claims.values().any(|claim| {
                                !claim.retired
                                    && claim.resource == *resource
                                    && claim.resource_generation == record.generation
                            })
                        })
                });
                if expected_resources.get(resource).is_none_or(Vec::is_empty)
                    || active_resource_generations.get(resource) != Some(&record.generation)
                    || active_resource_scopes.get(resource) != Some(&record.scope)
                    || pending_is_invalid
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            ResourcePhase::Retired => {
                if expected_resources.contains_key(resource) {
                    return Err(CoreError::InvariantViolation);
                }
            }
        }
    }
    if expected_resources
        .keys()
        .any(|resource| !state.resources.contains_key(resource))
    {
        return Err(CoreError::InvariantViolation);
    }
    for root in state.roots.values() {
        let crash_state_matches = match root.state {
            RootRecoveryState::Fenced {
                crash_generation, ..
            }
            | RootRecoveryState::RecoveryExhausted {
                crash_generation, ..
            } => crash_generation == root.crash_generation,
            _ => true,
        };
        let over_quota_is_exhausted = root.crash_generation <= limits.max_crashes_per_root
            || matches!(root.state, RootRecoveryState::RecoveryExhausted { .. });
        if !over_quota_is_exhausted
            || !crash_state_matches
            || root.last_binding_generation == 0
            || root.last_incarnation_generation < root.origin.generation()
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(())
}

fn projection_digest(state: &State, catalog: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.projection.v5");
    hasher.update(catalog.bytes());
    hasher.update(state.revision.to_le_bytes());
    hasher.update(state.head.bytes());
    hash_freshness(&mut hasher, state.freshness);
    hasher.update(state.next_nonce.to_le_bytes());
    hasher.update([u8::from(state.recovery_target.is_some())]);
    if let Some(target) = state.recovery_target {
        hash_freshness(&mut hasher, target);
    }
    for (root_id, root) in &state.roots {
        hasher.update(root_id.get().to_le_bytes());
        hash_incarnation(&mut hasher, root.origin);
        hasher.update(root.last_binding_generation.to_le_bytes());
        hasher.update(root.last_incarnation_generation.to_le_bytes());
        hasher.update(root.crash_generation.to_le_bytes());
        hash_root_state(&mut hasher, root.state);
    }
    hasher.update([0xfe]);
    for (effect_id, estate) in &state.estates {
        hasher.update(effect_id.root().get().to_le_bytes());
        hasher.update(effect_id.sequence().to_le_bytes());
        hash_incarnation(&mut hasher, estate.causal_owner);
        hash_custody(&mut hasher, estate.custodian);
        hasher.update(estate.charge_owner.get().to_le_bytes());
        hasher.update(estate.domain.get().to_le_bytes());
        hasher.update(estate.obligation.get().to_le_bytes());
        hasher.update([estate.obligation_policy.tag()]);
        hasher.update(estate.authority_epoch.to_le_bytes());
        hasher.update([
            authority_tag(estate.authority),
            commit_tag(estate.commit),
            retirement_tag(estate.retirement),
        ]);
        hash_outcome(&mut hasher, estate.outcome);
        hash_settlement(&mut hasher, estate.settlement);
        hash_optional_u64(&mut hasher, estate.commit_nonce);
        hash_optional_digest(&mut hasher, estate.commit_operation);
        hash_optional_effect_fact(&mut hasher, estate.commit_fact);
        hash_optional_u64(&mut hasher, estate.settlement_nonce);
        hasher.update([estate.claim_stage.map(claim_stage_tag).unwrap_or(0)]);
        hash_optional_digest(&mut hasher, estate.settlement_intent);
        hash_optional_effect_fact(&mut hasher, estate.applied_fact);
        hash_optional_effect_fact(&mut hasher, estate.settlement_fact);
        for (claim_id, claim) in &estate.claims {
            hasher.update(claim_id.get().to_le_bytes());
            hasher.update(claim.domain.get().to_le_bytes());
            hasher.update(claim.kind.get().to_le_bytes());
            hasher.update(claim.credit_class.get().to_le_bytes());
            hash_claim_scope(&mut hasher, claim.scope);
            hasher.update(claim.resource.get().to_le_bytes());
            hasher.update(claim.resource_generation.get().to_le_bytes());
            hasher.update(claim.units.to_le_bytes());
            hash_freshness(&mut hasher, claim.enrolled_freshness);
            hasher.update([u8::from(claim.retired)]);
            for requirement in &claim.requirements {
                hasher.update(requirement.kind.get().to_le_bytes());
                hasher.update(requirement.verifier.get().to_le_bytes());
                hasher.update(requirement.receipt_schema.get().to_le_bytes());
                hasher.update([requirement.subject_freshness.bits()]);
                hasher.update([requirement.observation_freshness.bits()]);
                hasher.update([requirement.strictly_advanced.bits()]);
                hasher.update([match requirement.device_generation {
                    DeviceGenerationEffect::None => 1,
                    DeviceGenerationEffect::AdvanceOne => 2,
                }]);
                hasher.update(
                    requirement
                        .prerequisite
                        .map(EvidenceKindId::get)
                        .unwrap_or(0)
                        .to_le_bytes(),
                );
                hasher.update([u8::from(requirement.accepted.is_some())]);
                if let Some(accepted) = requirement.accepted {
                    hash_freshness(&mut hasher, accepted.subject);
                    hash_freshness(&mut hasher, accepted.observation);
                    hash_verifier_stamp(&mut hasher, accepted.stamp);
                }
            }
        }
        hasher.update([0xfd]);
    }
    hasher.update([0xfc]);
    for (resource, record) in &state.resources {
        hasher.update(resource.get().to_le_bytes());
        hash_claim_scope(&mut hasher, record.scope);
        hasher.update(record.generation.get().to_le_bytes());
        match record.phase {
            ResourcePhase::Claimed { pending_reuse } => {
                hasher.update([1, u8::from(pending_reuse.is_some())]);
                if let Some(pending) = pending_reuse {
                    hasher.update(pending.effect.root().get().to_le_bytes());
                    hasher.update(pending.effect.sequence().to_le_bytes());
                    hash_incarnation(&mut hasher, pending.actor);
                    hasher.update(pending.binding_generation.to_le_bytes());
                    hasher.update(pending.authority_epoch.to_le_bytes());
                    hasher.update(pending.nonce.to_le_bytes());
                    hash_freshness(&mut hasher, pending.freshness);
                }
            }
            ResourcePhase::Retired => hasher.update([2]),
        }
    }
    hasher.update([0xfb]);
    for (scope, generation) in &state.device_generations {
        hasher.update(scope.get().to_le_bytes());
        hasher.update(generation.get().to_le_bytes());
        hasher.update([u8::from(state.device_quarantine.contains(scope))]);
    }
    hasher.update([0xfa]);
    for (verifier, epoch) in &state.verifier_epochs {
        hasher.update(verifier.get().to_le_bytes());
        hasher.update(epoch.to_le_bytes());
    }
    Digest::new(hasher.finalize().into())
}

fn hash_verifier_stamp(hasher: &mut Sha256, stamp: VerifierStamp) {
    hasher.update(stamp.identity.verifier().get().to_le_bytes());
    hasher.update(stamp.identity.epoch().to_le_bytes());
    hasher.update(stamp.identity.receipt_schema().get().to_le_bytes());
    hasher.update(stamp.receipt_digest.bytes());
}

fn hash_optional_effect_fact(hasher: &mut Sha256, fact: Option<VerifiedEffectFact>) {
    hasher.update([u8::from(fact.is_some())]);
    if let Some(fact) = fact {
        hasher.update([fact.kind.tag()]);
        hasher.update(fact.effect.root().get().to_le_bytes());
        hasher.update(fact.effect.sequence().to_le_bytes());
        hash_incarnation(hasher, fact.actor);
        hasher.update(fact.generation.to_le_bytes());
        hasher.update(fact.nonce.to_le_bytes());
        hasher.update(fact.operation.bytes());
        hash_optional_digest(hasher, fact.predecessor);
        hash_freshness(hasher, fact.freshness);
        hash_verifier_stamp(hasher, fact.stamp);
        hasher.update([match fact.outcome {
            None => 0,
            Some(ExternalOutcome::Success) => 1,
            Some(ExternalOutcome::Failure) => 2,
        }]);
    }
}

fn hash_claim_scope(hasher: &mut Sha256, scope: ClaimScope) {
    match scope {
        ClaimScope::Logical => hasher.update([1]),
        ClaimScope::Device(device) => {
            hasher.update([2]);
            hasher.update(device.get().to_le_bytes());
        }
    }
}

fn hash_freshness(hasher: &mut Sha256, freshness: Freshness) {
    hasher.update(freshness.boot().get().to_le_bytes());
    hasher.update(freshness.registry().get().to_le_bytes());
    hasher.update(freshness.binding().to_le_bytes());
    hasher.update(freshness.device().get().to_le_bytes());
    hasher.update(freshness.journal().get().to_le_bytes());
}

fn hash_incarnation(hasher: &mut Sha256, incarnation: PrincipalIncarnation) {
    hasher.update(incarnation.principal().get().to_le_bytes());
    hasher.update(incarnation.generation().to_le_bytes());
}

fn hash_custody(hasher: &mut Sha256, custody: CustodyState) {
    match custody {
        CustodyState::Principal(incarnation) => {
            hasher.update([1]);
            hash_incarnation(hasher, incarnation);
        }
        CustodyState::KernelEstate => hasher.update([2]),
        CustodyState::Released => hasher.update([3]),
    }
}

fn hash_root_state(hasher: &mut Sha256, state: RootRecoveryState) {
    match state {
        RootRecoveryState::Active {
            incarnation,
            binding_generation,
        } => {
            hasher.update([1]);
            hash_incarnation(hasher, incarnation);
            hasher.update(binding_generation.to_le_bytes());
        }
        RootRecoveryState::Fenced {
            crashed,
            binding_generation,
            crash_generation,
        } => {
            hasher.update([2]);
            hash_incarnation(hasher, crashed);
            hasher.update(binding_generation.to_le_bytes());
            hasher.update(crash_generation.to_le_bytes());
        }
        RootRecoveryState::Snapshotted { snapshot, digest } => {
            hasher.update([3]);
            hasher.update(snapshot.get().to_le_bytes());
            hasher.update(digest.bytes());
        }
        RootRecoveryState::Ready {
            snapshot,
            successor,
        } => {
            hasher.update([4]);
            hasher.update(snapshot.get().to_le_bytes());
            hash_incarnation(hasher, successor);
        }
        RootRecoveryState::Rebound {
            successor,
            binding_generation,
        } => {
            hasher.update([5]);
            hash_incarnation(hasher, successor);
            hasher.update(binding_generation.to_le_bytes());
        }
        RootRecoveryState::RecoveryExhausted {
            crashed,
            binding_generation,
            crash_generation,
        } => {
            hasher.update([6]);
            hash_incarnation(hasher, crashed);
            hasher.update(binding_generation.to_le_bytes());
            hasher.update(crash_generation.to_le_bytes());
        }
    }
}

fn hash_outcome(hasher: &mut Sha256, outcome: OutcomeState) {
    match outcome {
        OutcomeState::Pending => hasher.update([0]),
        OutcomeState::KnownSuccess(digest) => {
            hasher.update([1]);
            hasher.update(digest.bytes());
        }
        OutcomeState::KnownFailure(digest) => {
            hasher.update([2]);
            hasher.update(digest.bytes());
        }
        OutcomeState::Indeterminate(digest) => {
            hasher.update([3]);
            hasher.update(digest.bytes());
        }
    }
}

fn hash_settlement(hasher: &mut Sha256, settlement: SettlementState) {
    match settlement {
        SettlementState::Unavailable => hasher.update([0]),
        SettlementState::NotRequired => hasher.update([1]),
        SettlementState::Open { generation } => {
            hasher.update([2]);
            hasher.update(generation.to_le_bytes());
        }
        SettlementState::Claimed {
            claimant,
            generation,
        } => {
            hasher.update([3]);
            hash_incarnation(hasher, claimant);
            hasher.update(generation.to_le_bytes());
        }
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => {
            hasher.update([4]);
            hash_incarnation(hasher, claimant);
            hasher.update(generation.to_le_bytes());
        }
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => {
            hasher.update([5]);
            hash_incarnation(hasher, claimant);
            hasher.update(generation.to_le_bytes());
        }
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => {
            hasher.update([6, u8::from(applied)]);
            hasher.update(generation.to_le_bytes());
        }
        SettlementState::Settled => hasher.update([7]),
        SettlementState::Revoked => hasher.update([8]),
    }
}

fn hash_optional_u64(hasher: &mut Sha256, value: Option<u64>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        hasher.update(value.to_le_bytes());
    }
}

fn hash_optional_digest(hasher: &mut Sha256, value: Option<Digest>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        hasher.update(value.bytes());
    }
}

const fn authority_tag(state: AuthorityState) -> u8 {
    match state {
        AuthorityState::Active => 1,
        AuthorityState::Fenced => 2,
        AuthorityState::Revoked => 3,
    }
}

const fn commit_tag(state: CommitState) -> u8 {
    match state {
        CommitState::Registered => 1,
        CommitState::Prepared => 2,
        CommitState::CommitIntentDurable => 3,
        CommitState::Committed => 4,
    }
}

const fn retirement_tag(state: RetirementState) -> u8 {
    match state {
        RetirementState::Held => 1,
        RetirementState::RetirementPending => 2,
        RetirementState::Retired => 3,
        RetirementState::Released => 4,
    }
}

const fn claim_stage_tag(stage: ClaimStage) -> u8 {
    match stage {
        ClaimStage::Fresh => 1,
        ClaimStage::Intent => 2,
        ClaimStage::Applied => 3,
        ClaimStage::ReconcileIntent => 4,
        ClaimStage::ReconcileApplied => 5,
    }
}

/// Failure while decoding a semantic command payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDecodeError {
    /// The payload ended before a complete field.
    UnexpectedEof,
    /// A command or outcome discriminant is unknown.
    InvalidTag,
    /// A stable identity or generation decoded as zero.
    InvalidIdentity,
    /// Bytes remain after the complete command.
    TrailingBytes,
}

impl CommandKind {
    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match *self {
            Self::CreateEstate {
                effect,
                origin,
                binding_generation,
                domain,
                obligation,
                charge_account,
            } => {
                put_u8(&mut bytes, 1);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, origin);
                put_u64(&mut bytes, binding_generation);
                put_u32(&mut bytes, domain.get());
                put_u32(&mut bytes, obligation.get());
                put_u64(&mut bytes, charge_account.get());
            }
            Self::AddClaim {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            } => {
                put_u8(&mut bytes, 2);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, domain.get());
                put_u32(&mut bytes, kind.get());
                put_claim_scope(&mut bytes, scope);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, resource_generation.get());
                put_u64(&mut bytes, units);
            }
            Self::PrepareEffect {
                effect,
                actor,
                binding_generation,
            } => {
                put_u8(&mut bytes, 3);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
            }
            Self::RecordCommitIntent {
                effect,
                actor,
                binding_generation,
                operation,
            } => {
                put_u8(&mut bytes, 4);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
                put_digest(&mut bytes, operation);
            }
            Self::AcknowledgeCommit { fact } => {
                put_u8(&mut bytes, 5);
                put_effect_fact(&mut bytes, fact);
            }
            Self::FenceIncarnation {
                root,
                crashed,
                binding_generation,
            } => {
                put_u8(&mut bytes, 6);
                put_u64(&mut bytes, root.get());
                put_incarnation(&mut bytes, crashed);
                put_u64(&mut bytes, binding_generation);
            }
            Self::Snapshot {
                root,
                snapshot,
                digest,
            } => {
                put_u8(&mut bytes, 7);
                put_u64(&mut bytes, root.get());
                put_u64(&mut bytes, snapshot.get());
                put_digest(&mut bytes, digest);
            }
            Self::Ready {
                root,
                snapshot,
                successor,
            } => {
                put_u8(&mut bytes, 8);
                put_u64(&mut bytes, root.get());
                put_u64(&mut bytes, snapshot.get());
                put_incarnation(&mut bytes, successor);
            }
            Self::Rebind {
                root,
                snapshot,
                successor,
                binding_generation,
            } => {
                put_u8(&mut bytes, 9);
                put_u64(&mut bytes, root.get());
                put_u64(&mut bytes, snapshot.get());
                put_incarnation(&mut bytes, successor);
                put_u64(&mut bytes, binding_generation);
            }
            Self::ClaimSettlement { effect, claimant } => {
                put_u8(&mut bytes, 10);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, claimant);
            }
            Self::RecordApplyIntent {
                effect,
                claimant,
                generation,
                nonce,
                intent,
            } => {
                put_u8(&mut bytes, 11);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, claimant);
                put_u64(&mut bytes, generation);
                put_u64(&mut bytes, nonce);
                put_digest(&mut bytes, intent);
            }
            Self::RecordApplied { fact } => {
                put_u8(&mut bytes, 12);
                put_effect_fact(&mut bytes, fact);
            }
            Self::Settle { fact } => {
                put_u8(&mut bytes, 13);
                put_effect_fact(&mut bytes, fact);
            }
            Self::MarkIndeterminate {
                effect,
                claimant,
                generation,
                nonce,
                reason,
            } => {
                put_u8(&mut bytes, 14);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, claimant);
                put_u64(&mut bytes, generation);
                put_u64(&mut bytes, nonce);
                put_digest(&mut bytes, reason);
            }
            Self::BeginRevoke {
                effect,
                expected_actor,
                binding_generation,
                authority_epoch,
            } => {
                put_u8(&mut bytes, 15);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, expected_actor);
                put_u64(&mut bytes, binding_generation);
                put_u64(&mut bytes, authority_epoch);
            }
            Self::SubmitEvidence {
                effect,
                claim,
                evidence,
            } => {
                put_u8(&mut bytes, 16);
                put_effect(&mut bytes, effect);
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, evidence.kind.get());
                put_freshness(&mut bytes, evidence.subject);
                put_freshness(&mut bytes, evidence.freshness);
                put_u32(&mut bytes, evidence.stamp.identity.verifier().get());
                put_u64(&mut bytes, evidence.stamp.identity.epoch());
                put_u32(&mut bytes, evidence.stamp.identity.receipt_schema().get());
                put_digest(&mut bytes, evidence.stamp.receipt_digest);
            }
            Self::CheckpointRecovery {
                boot,
                journal,
                device,
            } => {
                put_u8(&mut bytes, 17);
                put_u64(&mut bytes, boot.get());
                put_u64(&mut bytes, journal.get());
                put_u64(&mut bytes, device.get());
            }
            Self::ReleaseEstate { effect } => {
                put_u8(&mut bytes, 20);
                put_effect(&mut bytes, effect);
            }
            Self::AdoptEffect {
                effect,
                successor,
                binding_generation,
            } => {
                put_u8(&mut bytes, 21);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, successor);
                put_u64(&mut bytes, binding_generation);
            }
            Self::ReserveReuse {
                effect,
                actor,
                binding_generation,
                claim,
                domain,
                kind,
                scope,
                resource,
                expected_generation,
                units,
            } => {
                put_u8(&mut bytes, 22);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, domain.get());
                put_u32(&mut bytes, kind.get());
                put_claim_scope(&mut bytes, scope);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, expected_generation.get());
                put_u64(&mut bytes, units);
            }
            Self::ActivateResourceReuse {
                effect,
                actor,
                binding_generation,
                authority_epoch,
                resource,
                resource_generation,
                nonce,
                freshness,
            } => {
                put_u8(&mut bytes, 23);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
                put_u64(&mut bytes, authority_epoch);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, resource_generation.get());
                put_u64(&mut bytes, nonce);
                put_freshness(&mut bytes, freshness);
            }
            Self::ReclaimResourceReuse {
                effect,
                actor,
                binding_generation,
                authority_epoch,
                resource,
                resource_generation,
            } => {
                put_u8(&mut bytes, 24);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, binding_generation);
                put_u64(&mut bytes, authority_epoch);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, resource_generation.get());
            }
        }
        bytes
    }

    pub(crate) fn decode_payload(bytes: &[u8]) -> Result<Self, CommandDecodeError> {
        let mut cursor = Cursor::new(bytes);
        let command = match cursor.u8()? {
            1 => Self::CreateEstate {
                effect: cursor.effect()?,
                origin: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                domain: DomainId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                obligation: ObligationKindId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                charge_account: ChargeAccountId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            2 => Self::AddClaim {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                domain: DomainId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                kind: ClaimKindId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                scope: cursor.claim_scope()?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                units: cursor.nonzero_u64()?,
            },
            3 => Self::PrepareEffect {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
            },
            4 => Self::RecordCommitIntent {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                operation: cursor.digest()?,
            },
            5 => Self::AcknowledgeCommit {
                fact: cursor.effect_fact()?,
            },
            6 => Self::FenceIncarnation {
                root: RootId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                crashed: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
            },
            7 => Self::Snapshot {
                root: RootId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                digest: cursor.digest()?,
            },
            8 => Self::Ready {
                root: RootId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                successor: cursor.incarnation()?,
            },
            9 => Self::Rebind {
                root: RootId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                successor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
            },
            10 => Self::ClaimSettlement {
                effect: cursor.effect()?,
                claimant: cursor.incarnation()?,
            },
            11 => Self::RecordApplyIntent {
                effect: cursor.effect()?,
                claimant: cursor.incarnation()?,
                generation: cursor.nonzero_u64()?,
                nonce: cursor.nonzero_u64()?,
                intent: cursor.digest()?,
            },
            12 => Self::RecordApplied {
                fact: cursor.effect_fact()?,
            },
            13 => Self::Settle {
                fact: cursor.effect_fact()?,
            },
            14 => Self::MarkIndeterminate {
                effect: cursor.effect()?,
                claimant: cursor.incarnation()?,
                generation: cursor.nonzero_u64()?,
                nonce: cursor.nonzero_u64()?,
                reason: cursor.digest()?,
            },
            15 => Self::BeginRevoke {
                effect: cursor.effect()?,
                expected_actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                authority_epoch: cursor.nonzero_u64()?,
            },
            16 => Self::SubmitEvidence {
                effect: cursor.effect()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                evidence: RetirementEvidence {
                    kind: EvidenceKindId::new(cursor.u32()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                    subject: cursor.freshness()?,
                    freshness: cursor.freshness()?,
                    stamp: VerifierStamp {
                        identity: VerifierIdentity {
                            verifier: VerifierId::new(cursor.u32()?)
                                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                            epoch: cursor.nonzero_u64()?,
                            receipt_schema: ReceiptSchemaId::new(cursor.u32()?)
                                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                        },
                        receipt_digest: cursor.digest()?,
                    },
                },
            },
            17 => Self::CheckpointRecovery {
                boot: BootGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                journal: JournalGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                device: DeviceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            20 => Self::ReleaseEstate {
                effect: cursor.effect()?,
            },
            21 => Self::AdoptEffect {
                effect: cursor.effect()?,
                successor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
            },
            22 => Self::ReserveReuse {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                domain: DomainId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                kind: ClaimKindId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                scope: cursor.claim_scope()?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                expected_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                units: cursor.nonzero_u64()?,
            },
            23 => Self::ActivateResourceReuse {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                authority_epoch: cursor.nonzero_u64()?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                nonce: cursor.nonzero_u64()?,
                freshness: cursor.freshness()?,
            },
            24 => Self::ReclaimResourceReuse {
                effect: cursor.effect()?,
                actor: cursor.incarnation()?,
                binding_generation: cursor.nonzero_u64()?,
                authority_epoch: cursor.nonzero_u64()?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        cursor.finish()?;
        Ok(command)
    }
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_digest(bytes: &mut Vec<u8>, digest: Digest) {
    bytes.extend_from_slice(&digest.bytes());
}

fn put_effect(bytes: &mut Vec<u8>, effect: EffectId) {
    put_u64(bytes, effect.root().get());
    put_u64(bytes, effect.sequence());
}

fn put_incarnation(bytes: &mut Vec<u8>, incarnation: PrincipalIncarnation) {
    put_u64(bytes, incarnation.principal().get());
    put_u64(bytes, incarnation.generation());
}

fn put_claim_scope(bytes: &mut Vec<u8>, scope: ClaimScope) {
    match scope {
        ClaimScope::Logical => put_u8(bytes, 1),
        ClaimScope::Device(device) => {
            put_u8(bytes, 2);
            put_u64(bytes, device.get());
        }
    }
}

fn put_freshness(bytes: &mut Vec<u8>, freshness: Freshness) {
    put_u64(bytes, freshness.boot().get());
    put_u64(bytes, freshness.registry().get());
    put_u64(bytes, freshness.binding());
    put_u64(bytes, freshness.device().get());
    put_u64(bytes, freshness.journal().get());
}

fn put_effect_fact(bytes: &mut Vec<u8>, fact: VerifiedEffectFact) {
    put_u8(bytes, fact.kind.tag());
    put_effect(bytes, fact.effect);
    put_incarnation(bytes, fact.actor);
    put_u64(bytes, fact.generation);
    put_u64(bytes, fact.nonce);
    put_digest(bytes, fact.operation);
    put_u8(bytes, u8::from(fact.predecessor.is_some()));
    if let Some(predecessor) = fact.predecessor {
        put_digest(bytes, predecessor);
    }
    put_freshness(bytes, fact.freshness);
    put_u32(bytes, fact.stamp.identity.verifier().get());
    put_u64(bytes, fact.stamp.identity.epoch());
    put_u32(bytes, fact.stamp.identity.receipt_schema().get());
    put_digest(bytes, fact.stamp.receipt_digest);
    put_u8(
        bytes,
        match fact.outcome {
            None => 0,
            Some(ExternalOutcome::Success) => 1,
            Some(ExternalOutcome::Failure) => 2,
        },
    );
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CommandDecodeError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(CommandDecodeError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CommandDecodeError::UnexpectedEof)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CommandDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CommandDecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CommandDecodeError::UnexpectedEof)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, CommandDecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CommandDecodeError::UnexpectedEof)?,
        ))
    }

    fn nonzero_u64(&mut self) -> Result<u64, CommandDecodeError> {
        let value = self.u64()?;
        if value == 0 {
            Err(CommandDecodeError::InvalidIdentity)
        } else {
            Ok(value)
        }
    }

    fn digest(&mut self) -> Result<Digest, CommandDecodeError> {
        Ok(Digest::new(
            self.take(32)?
                .try_into()
                .map_err(|_| CommandDecodeError::UnexpectedEof)?,
        ))
    }

    fn effect(&mut self) -> Result<EffectId, CommandDecodeError> {
        let root = RootId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        EffectId::new(root, self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn incarnation(&mut self) -> Result<PrincipalIncarnation, CommandDecodeError> {
        let principal = crate::PrincipalId::new(self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)?;
        PrincipalIncarnation::new(principal, self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn claim_scope(&mut self) -> Result<ClaimScope, CommandDecodeError> {
        match self.u8()? {
            1 => Ok(ClaimScope::Logical),
            2 => DeviceScopeId::new(self.u64()?)
                .map(ClaimScope::Device)
                .map_err(|_| CommandDecodeError::InvalidIdentity),
            _ => Err(CommandDecodeError::InvalidTag),
        }
    }

    fn freshness(&mut self) -> Result<Freshness, CommandDecodeError> {
        let boot =
            BootGeneration::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let registry =
            RegistryInstance::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let binding = self.nonzero_u64()?;
        let device =
            DeviceGeneration::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let journal =
            JournalGeneration::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        Freshness::new(boot, registry, binding, device, journal)
            .map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn effect_fact(&mut self) -> Result<VerifiedEffectFact, CommandDecodeError> {
        let kind = match self.u8()? {
            1 => EffectFactKind::CommitOutcome,
            2 => EffectFactKind::ApplyCompleted,
            3 => EffectFactKind::SettlementAcknowledged,
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        let effect = self.effect()?;
        let actor = self.incarnation()?;
        let generation = self.nonzero_u64()?;
        let nonce = self.nonzero_u64()?;
        let operation = self.digest()?;
        let predecessor = match self.u8()? {
            0 => None,
            1 => Some(self.digest()?),
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        let freshness = self.freshness()?;
        let verifier =
            VerifierId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let epoch = self.nonzero_u64()?;
        let receipt_schema =
            ReceiptSchemaId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let receipt_digest = self.digest()?;
        let outcome = match self.u8()? {
            0 => None,
            1 => Some(ExternalOutcome::Success),
            2 => Some(ExternalOutcome::Failure),
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        Ok(VerifiedEffectFact {
            kind,
            effect,
            actor,
            generation,
            nonce,
            operation,
            predecessor,
            freshness,
            stamp: VerifierStamp {
                identity: VerifierIdentity {
                    verifier,
                    epoch,
                    receipt_schema,
                },
                receipt_digest,
            },
            outcome,
        })
    }

    fn finish(self) -> Result<(), CommandDecodeError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CommandDecodeError::TrailingBytes)
        }
    }
}
