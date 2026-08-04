// SPDX-License-Identifier: MPL-2.0

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use sha2::{Digest as _, Sha256};

use crate::{
    ClaimKindId, ComponentId, CompositeKindId, CreditClassId, Digest, DomainId, EvidenceKindId,
    ObligationKindId, ReceiptSchemaId, VerifierId,
};

/// Whether an explicitly rebound successor may adopt an unfinished effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionPolicy {
    /// The obligation never permits execution adoption.
    Forbidden,
    /// Only an effect which has not crossed its external commit point may move.
    UncommittedOnly,
}

impl AdoptionPolicy {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Forbidden => 1,
            Self::UncommittedOnly => 2,
        }
    }
}

/// Cardinality of one legal claim class in an obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimCardinality {
    kind: ClaimKindId,
    minimum: u16,
    maximum: u16,
}

impl ClaimCardinality {
    /// Declares an inclusive non-zero cardinality range.
    pub const fn new(
        kind: ClaimKindId,
        minimum: u16,
        maximum: u16,
    ) -> Result<Self, DomainCatalogError> {
        if maximum == 0 || minimum > maximum {
            Err(DomainCatalogError::InvalidCardinality)
        } else {
            Ok(Self {
                kind,
                minimum,
                maximum,
            })
        }
    }

    /// Returns the legal claim class.
    pub const fn kind(self) -> ClaimKindId {
        self.kind
    }

    /// Returns the minimum required count.
    pub const fn minimum(self) -> u16 {
        self.minimum
    }

    /// Returns the maximum legal count.
    pub const fn maximum(self) -> u16 {
        self.maximum
    }
}

/// Whether a claim is logical or belongs to an independently reset device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimScopePolicy {
    /// The claim has no device-reset scope.
    Logical,
    /// Every claim instance must name one exact device scope.
    Device,
}

impl ClaimScopePolicy {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Logical => 1,
            Self::Device => 2,
        }
    }
}

/// How two live claims naming one resource coordinate interact.
///
/// This is the admission algebra of a claim class. It is declared by the
/// domain, not inferred by the engine, because whether concurrent custody of a
/// resource is safe is a property of the provider that backs it, and the engine
/// cannot observe that property.
///
/// The algebra is deliberately small. It records only what the engine can
/// enforce with exact identifier equality: whether a second live claim on the
/// same coordinate may exist at all. It says nothing about whether two
/// *different* coordinates alias one physical extent; that remains a separate
/// hardware gate, as it must, since a `ResourceId` is opaque to the engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictMode {
    /// At most one live claim may name the coordinate.
    ///
    /// A second enrollment is refused while the first is unretired. Retirement
    /// of that single claim retires the coordinate and makes it eligible for a
    /// generation-bound reuse permit.
    Exclusive,
    /// Any number of live claims may name the coordinate concurrently.
    ///
    /// The coordinate is retired only when the last live claim retires, so a
    /// reuse permit is never issued while a custodian remains. Every sharer
    /// must still discharge its own evidence conjunction: sharing weakens the
    /// admission test, never the retirement obligation.
    Shared,
}

impl ConflictMode {
    /// Returns whether two live claims may coexist on one exact coordinate.
    ///
    /// Compatibility is symmetric: either class may permit sharing only when
    /// the other does too. Keeping both operands here prevents a caller from
    /// accidentally treating the candidate's declaration as authoritative.
    pub const fn compatible_with(self, other: Self) -> bool {
        matches!((self, other), (Self::Shared, Self::Shared))
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Exclusive => 1,
            Self::Shared => 2,
        }
    }
}

/// Typed conserved-credit policy shared by compatible claim classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditRule {
    class: CreditClassId,
    max_units_per_account: u64,
}

impl CreditRule {
    /// Returns the conserved credit class.
    pub const fn class(self) -> CreditClassId {
        self.class
    }

    /// Returns the independent per-account limit for this class.
    pub const fn max_units_per_account(self) -> u64 {
        self.max_units_per_account
    }
}

/// Core lifecycle selected by one domain-defined obligation class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationPolicy {
    /// A committed result must cross the one-shot settlement gate.
    SuccessorSettlement,
    /// Typed physical retirement evidence is the only remaining disposition.
    RetirementEvidence,
}

impl ObligationPolicy {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::SuccessorSettlement => 1,
            Self::RetirementEvidence => 2,
        }
    }
}

/// Trusted verifier and canonical schema for one external effect fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptBinding {
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
}

impl ReceiptBinding {
    /// Declares the verifier class and canonical receipt schema.
    pub const fn new(verifier: VerifierId, receipt_schema: ReceiptSchemaId) -> Self {
        Self {
            verifier,
            receipt_schema,
        }
    }

    /// Returns the configured verifier class.
    pub const fn verifier(self) -> VerifierId {
        self.verifier
    }

    /// Returns the canonical receipt schema.
    pub const fn receipt_schema(self) -> ReceiptSchemaId {
        self.receipt_schema
    }
}

/// Verifier bindings for external commit and settlement facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObligationReceipts {
    commit_outcome: ReceiptBinding,
    apply_completed: Option<ReceiptBinding>,
    settlement_acknowledged: Option<ReceiptBinding>,
}

impl ObligationReceipts {
    /// Declares a retirement-only obligation with a typed external commit
    /// outcome and no successor settlement stages.
    pub const fn retirement_only(commit_outcome: ReceiptBinding) -> Self {
        Self {
            commit_outcome,
            apply_completed: None,
            settlement_acknowledged: None,
        }
    }

    /// Declares all typed external facts required by a successor-settled
    /// obligation.
    pub const fn successor_settlement(
        commit_outcome: ReceiptBinding,
        apply_completed: ReceiptBinding,
        settlement_acknowledged: ReceiptBinding,
    ) -> Self {
        Self {
            commit_outcome,
            apply_completed: Some(apply_completed),
            settlement_acknowledged: Some(settlement_acknowledged),
        }
    }

    /// Returns the external commit-outcome verifier binding.
    pub const fn commit_outcome(self) -> ReceiptBinding {
        self.commit_outcome
    }

    /// Returns the external apply-completion verifier binding.
    pub const fn apply_completed(self) -> Option<ReceiptBinding> {
        self.apply_completed
    }

    /// Returns the final settlement-acknowledgement verifier binding.
    pub const fn settlement_acknowledged(self) -> Option<ReceiptBinding> {
        self.settlement_acknowledged
    }
}

/// Declarative rule for one domain-defined obligation class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationRule {
    domain: DomainId,
    kind: ObligationKindId,
    policy: ObligationPolicy,
    adoption: AdoptionPolicy,
    receipts: ObligationReceipts,
    minimum_total_claims: u16,
    claims: Vec<ClaimCardinality>,
}

impl ObligationRule {
    /// Returns the defining domain.
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Returns the obligation class.
    pub const fn kind(&self) -> ObligationKindId {
        self.kind
    }

    /// Returns the lifecycle enforced by the core.
    pub const fn policy(&self) -> ObligationPolicy {
        self.policy
    }

    /// Returns the explicit successor-adoption policy.
    pub const fn adoption(&self) -> AdoptionPolicy {
        self.adoption
    }

    /// Returns verifier bindings for external commit and settlement facts.
    pub const fn receipts(&self) -> ObligationReceipts {
        self.receipts
    }

    /// Returns the minimum total claims required before preparation.
    pub const fn minimum_total_claims(&self) -> u16 {
        self.minimum_total_claims
    }

    /// Returns every legal claim class and its cardinality.
    pub fn claims(&self) -> &[ClaimCardinality] {
        &self.claims
    }
}

/// Declarative identity and lifecycle policy for one obligation class.
///
/// Claim cardinalities are supplied separately to
/// [`DomainCatalogBuilder::obligation`] so callers can build them as a
/// borrowed, bounded table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObligationSpec {
    domain: DomainId,
    kind: ObligationKindId,
    policy: ObligationPolicy,
    adoption: AdoptionPolicy,
    receipts: ObligationReceipts,
    minimum_total_claims: u16,
}

impl ObligationSpec {
    /// Declares one domain-defined obligation lifecycle.
    pub const fn new(
        domain: DomainId,
        kind: ObligationKindId,
        policy: ObligationPolicy,
        adoption: AdoptionPolicy,
        receipts: ObligationReceipts,
        minimum_total_claims: u16,
    ) -> Self {
        Self {
            domain,
            kind,
            policy,
            adoption,
            receipts,
            minimum_total_claims,
        }
    }
}

/// One catalog-bound obligation component of a composite effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositeComponentSpec {
    component: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
}

impl CompositeComponentSpec {
    /// Binds one stable component slot to an exact domain obligation.
    pub const fn new(
        component: ComponentId,
        domain: DomainId,
        obligation: ObligationKindId,
    ) -> Self {
        Self {
            component,
            domain,
            obligation,
        }
    }

    /// Returns the stable component slot.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns the defining domain.
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the exact obligation class.
    pub const fn obligation(self) -> ObligationKindId {
        self.obligation
    }
}

/// Catalog-defined product of one or more obligation components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeRule {
    kind: CompositeKindId,
    components: Vec<CompositeComponentSpec>,
}

impl CompositeRule {
    /// Returns the composite effect class.
    pub const fn kind(&self) -> CompositeKindId {
        self.kind
    }

    /// Returns the complete ordered component schema.
    pub fn components(&self) -> &[CompositeComponentSpec] {
        &self.components
    }

    /// Resolves one stable component slot.
    pub fn component(&self, component: ComponentId) -> Option<CompositeComponentSpec> {
        self.components
            .iter()
            .copied()
            .find(|candidate| candidate.component() == component)
    }
}

/// Freshness coordinates an evidence class must match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshnessAxes(u8);

impl FreshnessAxes {
    const NONE: Self = Self(0);
    /// Evidence must match the active boot.
    pub const BOOT: Self = Self(1 << 0);
    /// Evidence must match the Registry instance.
    pub const REGISTRY: Self = Self(1 << 1);
    /// Evidence must match the active principal binding.
    pub const BINDING: Self = Self(1 << 2);
    /// Evidence must match the active device generation.
    pub const DEVICE: Self = Self(1 << 3);
    /// Evidence must match the durable journal generation.
    pub const JOURNAL: Self = Self(1 << 4);

    /// Returns the union of two coordinate sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether all coordinates in `other` are required.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }
}

/// Exact subject represented by one evidence requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceSubjectBinding {
    /// The evidence names the logical effect and claim directly.
    LogicalEffect,
    /// The evidence must exactly name selected enrollment coordinates.
    EnrolledGeneration(FreshnessAxes),
}

impl EvidenceSubjectBinding {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::LogicalEffect => 1,
            Self::EnrolledGeneration(_) => 2,
        }
    }

    pub(crate) const fn axes(self) -> FreshnessAxes {
        match self {
            Self::LogicalEffect => FreshnessAxes::NONE,
            Self::EnrolledGeneration(axes) => axes,
        }
    }
}

/// Which custody question one evidence kind can answer.
///
/// The two capabilities are independent, and neither implies the other. Device
/// reset, IRQ drain, and IOTLB invalidation establish that a provider will not
/// touch a resource again while saying nothing about whether an earlier DMA
/// write succeeded. An idempotency-keyed remote receipt establishes the
/// external outcome while establishing no quiescence, because the endpoint may
/// still retry.
///
/// This is a property of one (claim class, evidence kind) pair under a declared
/// failure model, not a label on an endpoint: the same endpoint may expose
/// different capabilities for different operations, and the evidence may
/// originate from the endpoint, a kernel custodian, a device reset protocol, or
/// a third-party verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCapability {
    /// Establishes what the external operation did, not that access has ceased.
    ///
    /// Never sufficient on its own to permit conflicting reuse of a physical
    /// resource. Logical outcome state advances only through the separately
    /// verified effect-fact and settlement paths.
    Outcome,
    /// Establishes that the provider will not access the resource again.
    ///
    /// Sufficient to retire a physical claim and permit generation reuse. Never
    /// sufficient on its own to decide the logical outcome.
    Quiescence,
}

impl EvidenceCapability {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Outcome => 1,
            Self::Quiescence => 2,
        }
    }

    /// Returns whether this capability can retire a physical claim.
    pub const fn permits_reuse(self) -> bool {
        matches!(self, Self::Quiescence)
    }
}

/// Whether evidence remains obtainable after every admitted crash window.
///
/// A claim whose only evidence is lost when the observer dies can never retire,
/// so this is a safety-relevant catalog property rather than a quality of
/// service. The distinction is recoverable obtainability, not the transport:
/// a one-shot push that the sender persists and retransmits until durable
/// acknowledgement is recoverable, while a queryable endpoint that forgets the
/// operation across its own restart is not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRecovery {
    /// The verifier can re-obtain the fact after any admitted crash.
    ///
    /// Queryable by durable operation identity, retransmitted by the sender
    /// until durable acknowledgement, or reconstructible from local durable
    /// state.
    Recoverable,
    /// The fact is observable at most once and is lost if that window is missed.
    ///
    /// This is endpoint classification only. It cannot support automatic
    /// CSER retirement: a crash inside the observation window leaves no
    /// recoverable path to release a claim.
    Ephemeral,
}

impl EvidenceRecovery {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Recoverable => 1,
            Self::Ephemeral => 2,
        }
    }

    /// Returns whether the fact survives an admitted crash window.
    pub const fn survives_crash(self) -> bool {
        matches!(self, Self::Recoverable)
    }
}

/// Whether accepting a receipt may advance one device generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceGenerationEffect {
    /// The receipt observes but does not advance a device generation.
    None,
    /// The receipt may establish exactly the next generation for its scope.
    AdvanceOne,
}

impl DeviceGenerationEffect {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::None => 1,
            Self::AdvanceOne => 2,
        }
    }
}

/// One exact typed retirement-evidence requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRule {
    kind: EvidenceKindId,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    subject: EvidenceSubjectBinding,
    observation_freshness: FreshnessAxes,
    strictly_advanced: FreshnessAxes,
    device_generation: DeviceGenerationEffect,
    prerequisite: Option<EvidenceKindId>,
    capability: EvidenceCapability,
    recovery: EvidenceRecovery,
}

impl EvidenceRule {
    /// Creates evidence for a logical effect, verified under an exact schema.
    ///
    /// This is appropriate for evidence, such as a reply acknowledgement,
    /// whose subject is the current logical effect rather than an enrolled
    /// physical generation.
    pub const fn logical(
        kind: EvidenceKindId,
        receipt: ReceiptBinding,
        observation_freshness: FreshnessAxes,
    ) -> Self {
        Self {
            kind,
            verifier: receipt.verifier(),
            receipt_schema: receipt.receipt_schema(),
            subject: EvidenceSubjectBinding::LogicalEffect,
            observation_freshness,
            strictly_advanced: FreshnessAxes::NONE,
            device_generation: DeviceGenerationEffect::None,
            prerequisite: None,
            capability: EvidenceCapability::Outcome,
            recovery: EvidenceRecovery::Recoverable,
        }
    }

    /// Declares that this logical evidence is observable at most once.
    ///
    /// A claim class whose evidence is ephemeral cannot guarantee retirement
    /// across a crash inside the observation window, so the catalog records the
    /// weaker capability rather than letting the failure model stay implicit.
    pub const fn ephemeral(mut self) -> Self {
        self.recovery = EvidenceRecovery::Ephemeral;
        self
    }

    /// Creates a retirement requirement for an exactly enrolled subject.
    ///
    /// `subject_freshness` selects coordinates which must exactly match the
    /// claim's enrollment snapshot. `observation_freshness` selects
    /// coordinates which must match the active verifier context.
    /// `strictly_advanced` selects coordinates for which the verifier
    /// observation must additionally be newer than the enrolled subject.
    /// `prerequisite`, when present, must already have been accepted for the
    /// same claim.
    pub const fn retirement(
        kind: EvidenceKindId,
        receipt: ReceiptBinding,
        subject_freshness: FreshnessAxes,
        observation_freshness: FreshnessAxes,
        strictly_advanced: FreshnessAxes,
        device_generation: DeviceGenerationEffect,
        prerequisite: Option<EvidenceKindId>,
    ) -> Self {
        Self {
            kind,
            verifier: receipt.verifier(),
            receipt_schema: receipt.receipt_schema(),
            subject: EvidenceSubjectBinding::EnrolledGeneration(subject_freshness),
            observation_freshness,
            strictly_advanced,
            device_generation,
            prerequisite,
            capability: EvidenceCapability::Quiescence,
            recovery: EvidenceRecovery::Recoverable,
        }
    }

    /// Returns the evidence class.
    pub const fn kind(self) -> EvidenceKindId {
        self.kind
    }

    /// Returns the configured verifier class.
    pub const fn verifier(self) -> VerifierId {
        self.verifier
    }

    /// Returns the canonical receipt schema.
    pub const fn receipt_schema(self) -> ReceiptSchemaId {
        self.receipt_schema
    }

    /// Returns the exact subject-binding rule.
    pub const fn subject(self) -> EvidenceSubjectBinding {
        self.subject
    }

    /// Returns coordinates which identify an enrolled physical subject.
    pub const fn subject_freshness(self) -> FreshnessAxes {
        self.subject.axes()
    }

    /// Returns coordinates which must match the active verifier observation.
    pub const fn observation_freshness(self) -> FreshnessAxes {
        self.observation_freshness
    }

    /// Returns coordinates which must advance from subject to observation.
    pub const fn strictly_advanced(self) -> FreshnessAxes {
        self.strictly_advanced
    }

    /// Returns the exact device-generation side effect.
    pub const fn device_generation(self) -> DeviceGenerationEffect {
        self.device_generation
    }

    /// Returns the evidence class which must already be accepted.
    pub const fn prerequisite(self) -> Option<EvidenceKindId> {
        self.prerequisite
    }

    /// Returns which custody question this evidence class can answer.
    pub const fn capability(self) -> EvidenceCapability {
        self.capability
    }

    /// Returns whether the fact survives an admitted crash window.
    pub const fn recovery(self) -> EvidenceRecovery {
        self.recovery
    }
}

/// Declarative rule for one domain-defined claim class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRule {
    domain: DomainId,
    kind: ClaimKindId,
    credit_class: CreditClassId,
    scope: ClaimScopePolicy,
    conflict: ConflictMode,
    evidence: Vec<EvidenceRule>,
}

impl ClaimRule {
    /// Returns the defining domain.
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Returns the claim class.
    pub const fn kind(&self) -> ClaimKindId {
        self.kind
    }

    /// Returns the independently conserved charge class.
    pub const fn credit_class(&self) -> CreditClassId {
        self.credit_class
    }

    /// Returns whether instances must name a device scope.
    pub const fn scope(&self) -> ClaimScopePolicy {
        self.scope
    }

    /// Returns how concurrent claims on one resource coordinate interact.
    pub const fn conflict(&self) -> ConflictMode {
        self.conflict
    }

    /// Returns the complete evidence conjunction.
    pub fn evidence(&self) -> &[EvidenceRule] {
        &self.evidence
    }
}

/// Error while constructing a declarative domain catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainCatalogError {
    /// A conserved credit class already exists.
    DuplicateCreditClass,
    /// A conserved credit limit is zero.
    InvalidCreditLimit,
    /// The obligation class already exists.
    DuplicateObligation,
    /// The claim class already exists.
    DuplicateClaim,
    /// A claim class has no typed evidence requirement.
    MissingEvidence,
    /// The same evidence class appears twice in one claim rule.
    DuplicateEvidence,
    /// An evidence requirement names a class absent from the same claim.
    MissingPrerequisite,
    /// An evidence requirement directly or transitively depends on itself.
    CyclicPrerequisite,
    /// A strict-advance coordinate is not bound on both sides.
    InvalidFreshnessRelation,
    /// A device-generation advance is not exact or not device-scoped.
    InvalidDeviceGenerationEffect,
    /// An evidence capability contradicts its subject binding.
    ///
    /// Quiescence must be bound to an exactly enrolled physical generation,
    /// because permitting reuse requires knowing which incarnation of the
    /// resource has fallen silent. Outcome evidence must be bound to the
    /// logical effect, because settlement is a fact about the operation rather
    /// than about a resource generation.
    InvalidEvidenceCapability,
    /// A device-scoped claim declares no quiescence evidence.
    ///
    /// Outcome evidence alone never establishes that a provider has stopped
    /// touching a resource, so a reusable physical claim resting only on
    /// outcome evidence would permit conflicting reuse without custody.
    MissingQuiescenceEvidence,
    /// A retirement-only obligation references a claim which is not a
    /// crash-recoverable physical-quiescence claim.
    ///
    /// Every claim class permitted by a retirement-only lifecycle, including a
    /// cardinality-zero optional class, must be device-scoped, must carry a
    /// quiescence path, and must make every evidence requirement recoverable.
    /// Otherwise a legal enrollment could release a resource on outcome-only
    /// evidence or strand forever after a crash misses one conjunct.
    InvalidRetirementEvidenceClaim,
    /// A device claim's evidence conjunction includes a fact lost across a
    /// crash window.
    ///
    /// Every requirement must be re-obtainable: the core retires a claim only
    /// after its complete conjunction has been accepted. An ephemeral outcome
    /// requirement can therefore strand physical custody just as surely as
    /// ephemeral quiescence evidence can.
    UnrecoverableRetirementEvidence,
    /// A shared claim class declares evidence which advances a device
    /// generation.
    ///
    /// Sharers retire independently against a generation each enrolled
    /// against. A scope-wide advance performed by one sharer would strand the
    /// others at a generation they can no longer prove quiescent, so the two
    /// declarations cannot be combined.
    SharedClaimAdvancesGeneration,
    /// Verifier observations omit the mandatory boot/Registry/journal floor.
    InsufficientObservationFreshness,
    /// A claim names an unregistered conserved credit class.
    UnknownCreditClass,
    /// One obligation repeats or misconfigures a legal claim cardinality.
    InvalidCardinality,
    /// One obligation names a claim class absent from its domain.
    UnknownObligationClaim,
    /// External receipt bindings do not match the selected lifecycle.
    InvalidObligationReceipts,
    /// A composite effect class already exists.
    DuplicateComposite,
    /// A composite repeats a component slot or contains no components.
    InvalidComposite,
    /// A composite component names an unknown obligation.
    UnknownCompositeObligation,
}

/// Builder for a sealed, digest-bound domain catalog.
#[derive(Clone, Debug, Default)]
pub struct DomainCatalogBuilder {
    credits: BTreeMap<CreditClassId, CreditRule>,
    obligations: BTreeMap<(DomainId, ObligationKindId), ObligationRule>,
    claims: BTreeMap<(DomainId, ClaimKindId), ClaimRule>,
    composites: BTreeMap<CompositeKindId, CompositeRule>,
}

impl DomainCatalogBuilder {
    /// Creates an empty builder.
    pub const fn new() -> Self {
        Self {
            credits: BTreeMap::new(),
            obligations: BTreeMap::new(),
            claims: BTreeMap::new(),
            composites: BTreeMap::new(),
        }
    }

    /// Registers one independently conserved and bounded credit class.
    pub fn credit_class(
        mut self,
        class: CreditClassId,
        max_units_per_account: u64,
    ) -> Result<Self, DomainCatalogError> {
        if max_units_per_account == 0 {
            return Err(DomainCatalogError::InvalidCreditLimit);
        }
        if self.credits.contains_key(&class) {
            return Err(DomainCatalogError::DuplicateCreditClass);
        }
        self.credits.insert(
            class,
            CreditRule {
                class,
                max_units_per_account,
            },
        );
        Ok(self)
    }

    /// Registers one domain-defined obligation class.
    pub fn obligation(
        mut self,
        spec: ObligationSpec,
        claims: &[ClaimCardinality],
    ) -> Result<Self, DomainCatalogError> {
        let ObligationSpec {
            domain,
            kind,
            policy,
            adoption,
            receipts,
            minimum_total_claims,
        } = spec;
        let maximum_total = claims
            .iter()
            .map(|claim| u64::from(claim.maximum()))
            .sum::<u64>();
        if claims.is_empty()
            || minimum_total_claims == 0
            || u64::from(minimum_total_claims) > maximum_total
        {
            return Err(DomainCatalogError::InvalidCardinality);
        }
        if matches!(
            (
                policy,
                receipts.apply_completed(),
                receipts.settlement_acknowledged(),
            ),
            (ObligationPolicy::SuccessorSettlement, None, _)
                | (ObligationPolicy::SuccessorSettlement, _, None)
                | (ObligationPolicy::RetirementEvidence, Some(_), _)
                | (ObligationPolicy::RetirementEvidence, _, Some(_))
        ) {
            return Err(DomainCatalogError::InvalidObligationReceipts);
        }
        let mut classes = BTreeSet::new();
        if claims.iter().any(|claim| {
            claim.maximum() == 0
                || claim.minimum() > claim.maximum()
                || !classes.insert(claim.kind())
        }) {
            return Err(DomainCatalogError::InvalidCardinality);
        }
        let key = (domain, kind);
        if self.obligations.contains_key(&key) {
            return Err(DomainCatalogError::DuplicateObligation);
        }
        self.obligations.insert(
            key,
            ObligationRule {
                domain,
                kind,
                policy,
                adoption,
                receipts,
                minimum_total_claims,
                claims: claims.to_vec(),
            },
        );
        Ok(self)
    }

    /// Registers one exclusively held claim class and its evidence conjunction.
    ///
    /// Exclusion is the default because it is the conservative admission rule:
    /// a class which is in fact safe to share is merely over-restricted, while a
    /// class wrongly declared shareable admits concurrent custody of a resource
    /// whose provider cannot tolerate it.
    pub fn claim(
        self,
        domain: DomainId,
        kind: ClaimKindId,
        credit_class: CreditClassId,
        scope: ClaimScopePolicy,
        evidence: &[EvidenceRule],
    ) -> Result<Self, DomainCatalogError> {
        self.claim_with_conflict(
            domain,
            kind,
            credit_class,
            scope,
            ConflictMode::Exclusive,
            evidence,
        )
    }

    /// Registers one claim class with an explicit admission algebra.
    pub fn claim_with_conflict(
        mut self,
        domain: DomainId,
        kind: ClaimKindId,
        credit_class: CreditClassId,
        scope: ClaimScopePolicy,
        conflict: ConflictMode,
        evidence: &[EvidenceRule],
    ) -> Result<Self, DomainCatalogError> {
        if evidence.is_empty() {
            return Err(DomainCatalogError::MissingEvidence);
        }
        if !self.credits.contains_key(&credit_class) {
            return Err(DomainCatalogError::UnknownCreditClass);
        }
        let observation_floor = FreshnessAxes::BOOT
            .union(FreshnessAxes::REGISTRY)
            .union(FreshnessAxes::JOURNAL);
        let mut kinds = BTreeSet::new();
        for rule in evidence {
            if !kinds.insert(rule.kind()) {
                return Err(DomainCatalogError::DuplicateEvidence);
            }
            if !rule.observation_freshness().contains(observation_floor) {
                return Err(DomainCatalogError::InsufficientObservationFreshness);
            }
            if !rule.subject_freshness().contains(rule.strictly_advanced())
                || !rule
                    .observation_freshness()
                    .contains(rule.strictly_advanced())
            {
                return Err(DomainCatalogError::InvalidFreshnessRelation);
            }
            if rule.device_generation() == DeviceGenerationEffect::AdvanceOne
                && (!rule.strictly_advanced().contains(FreshnessAxes::DEVICE)
                    || scope != ClaimScopePolicy::Device)
            {
                return Err(DomainCatalogError::InvalidDeviceGenerationEffect);
            }
            // Capability and subject binding are two views of one fact: reuse
            // admission needs the exact retired generation, while settlement
            // needs the logical effect. A rule which mixes them would let one
            // custody question be answered with evidence about the other.
            let capability_matches_subject = match rule.subject() {
                EvidenceSubjectBinding::LogicalEffect => {
                    rule.capability() == EvidenceCapability::Outcome
                }
                EvidenceSubjectBinding::EnrolledGeneration(_) => {
                    rule.capability() == EvidenceCapability::Quiescence
                }
            };
            if !capability_matches_subject {
                return Err(DomainCatalogError::InvalidEvidenceCapability);
            }
            // The core retires a claim only after every requirement in its
            // conjunction has been accepted. Any one-shot fact can disappear
            // across a crash and strand that automatic-retirement contract.
            // This applies equally to logical and physical custody: the
            // latter additionally needs a quiescence fact below.
            if !rule.recovery().survives_crash() {
                return Err(DomainCatalogError::UnrecoverableRetirementEvidence);
            }
        }
        // A device-scoped claim names a physical resource whose reuse must be
        // gated, so its evidence conjunction must contain at least one
        // quiescence fact. Outcome evidence cannot substitute.
        if scope == ClaimScopePolicy::Device
            && !evidence
                .iter()
                .any(|rule| rule.capability().permits_reuse())
        {
            return Err(DomainCatalogError::MissingQuiescenceEvidence);
        }
        // Advancing a device generation is a scope-wide effect, but sharers
        // retire independently and each holds an enrollment snapshot of that
        // same generation. If one sharer's retirement advanced the generation,
        // every remaining sharer's snapshot would become stale through no act
        // of its own, and its evidence could never match. Shared custody and
        // scope-wide generation advance are therefore mutually exclusive.
        if conflict == ConflictMode::Shared
            && evidence
                .iter()
                .any(|rule| rule.device_generation() == DeviceGenerationEffect::AdvanceOne)
        {
            return Err(DomainCatalogError::SharedClaimAdvancesGeneration);
        }
        for rule in evidence {
            if let Some(prerequisite) = rule.prerequisite()
                && !kinds.contains(&prerequisite)
            {
                return Err(DomainCatalogError::MissingPrerequisite);
            }
            let mut visited = BTreeSet::new();
            let mut next = rule.prerequisite();
            while let Some(kind) = next {
                if !visited.insert(kind) || kind == rule.kind() {
                    return Err(DomainCatalogError::CyclicPrerequisite);
                }
                next = evidence
                    .iter()
                    .find(|candidate| candidate.kind() == kind)
                    .and_then(|candidate| candidate.prerequisite());
            }
        }
        let key = (domain, kind);
        if self.claims.contains_key(&key) {
            return Err(DomainCatalogError::DuplicateClaim);
        }
        self.claims.insert(
            key,
            ClaimRule {
                domain,
                kind,
                credit_class,
                scope,
                conflict,
                evidence: evidence.to_vec(),
            },
        );
        Ok(self)
    }

    /// Registers an exact non-empty component product.
    ///
    /// Components are catalog data rather than adapter callbacks. This keeps
    /// component identity and cross-domain membership stable across replay.
    pub fn composite(
        mut self,
        kind: CompositeKindId,
        components: &[CompositeComponentSpec],
    ) -> Result<Self, DomainCatalogError> {
        if components.is_empty() {
            return Err(DomainCatalogError::InvalidComposite);
        }
        let mut ids = BTreeSet::new();
        if components
            .iter()
            .any(|component| !ids.insert(component.component()))
        {
            return Err(DomainCatalogError::InvalidComposite);
        }
        if self.composites.contains_key(&kind) {
            return Err(DomainCatalogError::DuplicateComposite);
        }
        self.composites.insert(
            kind,
            CompositeRule {
                kind,
                components: components.to_vec(),
            },
        );
        Ok(self)
    }

    /// Seals the catalog and computes its deterministic schema digest.
    pub fn build(self) -> Result<DomainCatalog, DomainCatalogError> {
        for ((domain, _), obligation) in &self.obligations {
            for claim in obligation.claims() {
                let Some(rule) = self.claims.get(&(*domain, claim.kind())) else {
                    return Err(DomainCatalogError::UnknownObligationClaim);
                };
                // Every legal claim class, including one with minimum
                // cardinality zero, can be enrolled by a retirement-only
                // obligation and subsequently released. It must therefore be
                // a physical device claim with a quiescence path. Because all
                // declared requirements must be accepted before retirement,
                // every conjunct must also survive a crash window; one
                // ephemeral outcome or quiescence fact can otherwise strand
                // the claim forever. Validating only ClaimScopePolicy::Device
                // would let an outcome-only logical claim bypass the contract.
                if obligation.policy() == ObligationPolicy::RetirementEvidence
                    && (rule.scope() != ClaimScopePolicy::Device
                        || !rule
                            .evidence()
                            .iter()
                            .any(|evidence| evidence.capability().permits_reuse())
                        || rule
                            .evidence()
                            .iter()
                            .any(|evidence| !evidence.recovery().survives_crash()))
                {
                    return Err(DomainCatalogError::InvalidRetirementEvidenceClaim);
                }
            }
        }
        if self.composites.values().any(|composite| {
            composite.components().iter().any(|component| {
                !self
                    .obligations
                    .contains_key(&(component.domain(), component.obligation()))
            })
        }) {
            return Err(DomainCatalogError::UnknownCompositeObligation);
        }
        let digest = catalog_digest(
            &self.credits,
            &self.obligations,
            &self.claims,
            &self.composites,
        );
        Ok(DomainCatalog {
            credits: self.credits,
            obligations: self.obligations,
            claims: self.claims,
            composites: self.composites,
            digest,
        })
    }
}

/// Sealed domain schema used by the authoritative engine and journal replay.
#[derive(Clone, Debug)]
pub struct DomainCatalog {
    credits: BTreeMap<CreditClassId, CreditRule>,
    obligations: BTreeMap<(DomainId, ObligationKindId), ObligationRule>,
    claims: BTreeMap<(DomainId, ClaimKindId), ClaimRule>,
    composites: BTreeMap<CompositeKindId, CompositeRule>,
    digest: Digest,
}

impl DomainCatalog {
    /// Returns the deterministic schema digest bound into journal records.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns an obligation rule by exact domain and class.
    pub fn obligation_rule(
        &self,
        domain: DomainId,
        kind: ObligationKindId,
    ) -> Option<&ObligationRule> {
        self.obligations.get(&(domain, kind))
    }

    /// Returns a claim rule by exact domain and class.
    pub fn claim_rule(&self, domain: DomainId, kind: ClaimKindId) -> Option<&ClaimRule> {
        self.claims.get(&(domain, kind))
    }

    /// Returns one exact composite effect schema.
    pub fn composite_rule(&self, kind: CompositeKindId) -> Option<&CompositeRule> {
        self.composites.get(&kind)
    }

    /// Returns one conserved-credit rule.
    pub fn credit_rule(&self, class: CreditClassId) -> Option<CreditRule> {
        self.credits.get(&class).copied()
    }

    pub(crate) fn verifier_ids(&self) -> BTreeSet<VerifierId> {
        let mut verifiers: BTreeSet<_> = self
            .claims
            .values()
            .flat_map(|claim| claim.evidence().iter().map(|rule| rule.verifier()))
            .collect();
        for obligation in self.obligations.values() {
            let receipts = obligation.receipts();
            verifiers.insert(receipts.commit_outcome().verifier());
            if let Some(binding) = receipts.apply_completed() {
                verifiers.insert(binding.verifier());
            }
            if let Some(binding) = receipts.settlement_acknowledged() {
                verifiers.insert(binding.verifier());
            }
        }
        verifiers
    }
}

fn catalog_digest(
    credits: &BTreeMap<CreditClassId, CreditRule>,
    obligations: &BTreeMap<(DomainId, ObligationKindId), ObligationRule>,
    claims: &BTreeMap<(DomainId, ClaimKindId), ClaimRule>,
    composites: &BTreeMap<CompositeKindId, CompositeRule>,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.domain-catalog.v6");
    for (class, rule) in credits {
        hasher.update(class.get().to_le_bytes());
        hasher.update(rule.max_units_per_account().to_le_bytes());
    }
    hasher.update([0xfe]);
    for ((domain, kind), rule) in obligations {
        hasher.update(domain.get().to_le_bytes());
        hasher.update(kind.get().to_le_bytes());
        hasher.update([rule.policy().tag()]);
        hasher.update([rule.adoption().tag()]);
        hash_receipt_binding(&mut hasher, Some(rule.receipts().commit_outcome()));
        hash_receipt_binding(&mut hasher, rule.receipts().apply_completed());
        hash_receipt_binding(&mut hasher, rule.receipts().settlement_acknowledged());
        hasher.update(rule.minimum_total_claims().to_le_bytes());
        hasher.update((rule.claims().len() as u64).to_le_bytes());
        for claim in rule.claims() {
            hasher.update(claim.kind().get().to_le_bytes());
            hasher.update(claim.minimum().to_le_bytes());
            hasher.update(claim.maximum().to_le_bytes());
        }
    }
    hasher.update([0xff]);
    for ((domain, kind), rule) in claims {
        hasher.update(domain.get().to_le_bytes());
        hasher.update(kind.get().to_le_bytes());
        hasher.update(rule.credit_class().get().to_le_bytes());
        hasher.update([rule.scope().tag()]);
        hasher.update([rule.conflict().tag()]);
        hasher.update((rule.evidence.len() as u64).to_le_bytes());
        for evidence in &rule.evidence {
            hasher.update(evidence.kind().get().to_le_bytes());
            hasher.update(evidence.verifier().get().to_le_bytes());
            hasher.update(evidence.receipt_schema().get().to_le_bytes());
            hasher.update([evidence.subject().tag()]);
            hasher.update([evidence.subject_freshness().bits()]);
            hasher.update([evidence.observation_freshness().bits()]);
            hasher.update([evidence.strictly_advanced().bits()]);
            hasher.update([evidence.device_generation().tag()]);
            hasher.update(
                evidence
                    .prerequisite()
                    .map(EvidenceKindId::get)
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
            hasher.update([evidence.capability().tag()]);
            hasher.update([evidence.recovery().tag()]);
        }
    }
    hasher.update([0xfd]);
    for (kind, rule) in composites {
        hasher.update(kind.get().to_le_bytes());
        hasher.update((rule.components().len() as u64).to_le_bytes());
        for component in rule.components() {
            hasher.update(component.component().get().to_le_bytes());
            hasher.update(component.domain().get().to_le_bytes());
            hasher.update(component.obligation().get().to_le_bytes());
        }
    }
    Digest::new(hasher.finalize().into())
}

fn hash_receipt_binding(hasher: &mut Sha256, binding: Option<ReceiptBinding>) {
    hasher.update([u8::from(binding.is_some())]);
    if let Some(binding) = binding {
        hasher.update(binding.verifier().get().to_le_bytes());
        hasher.update(binding.receipt_schema().get().to_le_bytes());
    }
}
