// SPDX-License-Identifier: MPL-2.0

//! Registry-private bounded root scope lanes.
//!
//! RFC 0001 has one root authority per scope. Root-to-root parents, nested
//! authority scopes, and multiple-root effects are deliberately absent here;
//! effect ancestry remains a tree inside one root.
//!
//! Scope ids are allocator-owned fixed slots. A caller never chooses an id or
//! generation for a new root. Fresh allocation consumes a non-duplicable
//! permit that a future `EffectRegistry` integration must mint only after its
//! operation-freshness and quota checks. Recovery accepts a descriptive
//! selector but never allocates. Reusing a compact slot requires a second
//! linear permit bound to that exact compact generation.
//!
//! Closure and clearance permits are also sealed inside this child module.
//! Their raw constructors are intentionally inaccessible to the parent module.
//! This foundation does not yet claim a production `EffectRegistry` minting
//! path; that path must be implemented here from actual Registry receipts and
//! projections before these transitions are wired into production.

use sha2::{Digest as _, Sha256};

const ROOT_CONTRACT_SCHEMA: &[u8] = b"nexus.cser.root-contract.v2-unreleased";
const ROOT_CLOSURE_ACK_SCHEMA: &[u8] = b"nexus.cser.root-closure-ack.v1-unreleased";
const ROOT_CLEARANCE_SCHEMA: &[u8] = b"nexus.cser.root-clearance.v1-unreleased";
const ROOT_DIGEST_SIZE: usize = 32;

/// RFC root-lineage coordinates. Authority epoch remains a separate contract
/// coordinate because revoke advances it without allocating a new scope lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootLineage {
    registry_instance: u64,
    scope_id: u64,
    scope_generation: u64,
}

impl RootLineage {
    fn new(
        registry_instance: u64,
        scope_id: u64,
        scope_generation: u64,
    ) -> Result<Self, RootLaneError> {
        if registry_instance == 0 {
            return Err(RootLaneError::ZeroRegistryInstance);
        }
        if scope_id == 0 {
            return Err(RootLaneError::ZeroScopeId);
        }
        if scope_generation == 0 {
            return Err(RootLaneError::ZeroScopeGeneration);
        }
        Ok(Self {
            registry_instance,
            scope_id,
            scope_generation,
        })
    }

    pub(super) const fn registry_instance(self) -> u64 {
        self.registry_instance
    }

    pub(super) const fn scope_id(self) -> u64 {
        self.scope_id
    }

    pub(super) const fn scope_generation(self) -> u64 {
        self.scope_generation
    }
}

/// Descriptive lookup selector decoded from a Registry-issued opaque handle.
/// It is not authority and can never allocate an unknown scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootSelector {
    lineage: RootLineage,
}

impl RootSelector {
    pub(super) fn new(
        registry_instance: u64,
        scope_id: u64,
        scope_generation: u64,
    ) -> Result<Self, RootLaneError> {
        Ok(Self {
            lineage: RootLineage::new(registry_instance, scope_id, scope_generation)?,
        })
    }

    pub(super) const fn lineage(self) -> RootLineage {
        self.lineage
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootPolicy {
    flags: u32,
    max_effects: u32,
    max_tombstones: u32,
    queue_credits: u32,
    page_credits: u32,
}

impl RootPolicy {
    pub(super) const fn new(
        flags: u32,
        max_effects: u32,
        max_tombstones: u32,
        queue_credits: u32,
        page_credits: u32,
    ) -> Self {
        Self {
            flags,
            max_effects,
            max_tombstones,
            queue_credits,
            page_credits,
        }
    }
}

/// Copyable description of a root contract before the table assigns its fixed
/// scope id and generation. It carries no mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootContractTemplate {
    authority_epoch: u64,
    binding_epoch: u64,
    owner_id: u64,
    owner_generation: u64,
    policy_revision: u64,
    policy: RootPolicy,
    request_key: [u8; ROOT_DIGEST_SIZE],
}

impl RootContractTemplate {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        authority_epoch: u64,
        binding_epoch: u64,
        owner_id: u64,
        owner_generation: u64,
        policy_revision: u64,
        policy: RootPolicy,
        request_key: [u8; ROOT_DIGEST_SIZE],
    ) -> Result<Self, RootLaneError> {
        if authority_epoch == 0 {
            return Err(RootLaneError::ZeroAuthorityEpoch);
        }
        if binding_epoch == 0 {
            return Err(RootLaneError::ZeroBindingEpoch);
        }
        if owner_id == 0 {
            return Err(RootLaneError::ZeroOwnerId);
        }
        if owner_generation == 0 {
            return Err(RootLaneError::ZeroOwnerGeneration);
        }
        if policy_revision == 0 {
            return Err(RootLaneError::ZeroPolicyRevision);
        }
        if request_key.iter().all(|byte| *byte == 0) {
            return Err(RootLaneError::ZeroRequestKey);
        }
        Ok(Self {
            authority_epoch,
            binding_epoch,
            owner_id,
            owner_generation,
            policy_revision,
            policy,
            request_key,
        })
    }

    pub(super) const fn request_key(self) -> [u8; ROOT_DIGEST_SIZE] {
        self.request_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalRootDigest([u8; ROOT_DIGEST_SIZE]);

impl CanonicalRootDigest {
    const fn into_bytes(self) -> [u8; ROOT_DIGEST_SIZE] {
        self.0
    }
}

fn canonical_contract_digest(
    lineage: RootLineage,
    template: RootContractTemplate,
) -> CanonicalRootDigest {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, ROOT_CONTRACT_SCHEMA);
    digest_lineage(&mut hasher, lineage);
    digest_u64(&mut hasher, template.authority_epoch);
    digest_u64(&mut hasher, template.binding_epoch);
    digest_u64(&mut hasher, template.owner_id);
    digest_u64(&mut hasher, template.owner_generation);
    digest_u64(&mut hasher, template.policy_revision);
    digest_u32(&mut hasher, template.policy.flags);
    digest_u32(&mut hasher, template.policy.max_effects);
    digest_u32(&mut hasher, template.policy.max_tombstones);
    digest_u32(&mut hasher, template.policy.queue_credits);
    digest_u32(&mut hasher, template.policy.page_credits);
    digest_field(&mut hasher, &template.request_key);
    CanonicalRootDigest(hasher.finalize().into())
}

fn digest_lineage(hasher: &mut Sha256, lineage: RootLineage) {
    digest_u64(hasher, lineage.registry_instance);
    digest_u64(hasher, lineage.scope_id);
    digest_u64(hasher, lineage.scope_generation);
}

fn digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("bounded canonical field length");
    hasher.update(length.to_le_bytes());
    hasher.update(bytes);
}

fn digest_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn digest_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RootRetention {
    Full,
    AckedRetained,
    Compact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AckedEvidence {
    closure_sequence: u64,
    closure_receipt_digest: [u8; ROOT_DIGEST_SIZE],
    evidence_digest: [u8; ROOT_DIGEST_SIZE],
}

impl AckedEvidence {
    fn new(
        lineage: RootLineage,
        contract_digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
        closure_sequence: u64,
        closure_receipt_digest: [u8; ROOT_DIGEST_SIZE],
    ) -> Result<Self, RootLaneError> {
        if closure_sequence == 0 {
            return Err(RootLaneError::ZeroClosureSequence);
        }
        if closure_receipt_digest.iter().all(|byte| *byte == 0) {
            return Err(RootLaneError::ZeroClosureReceiptDigest);
        }
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, ROOT_CLOSURE_ACK_SCHEMA);
        digest_lineage(&mut hasher, lineage);
        digest_field(&mut hasher, &contract_digest.0);
        digest_field(&mut hasher, &request_key);
        digest_u64(&mut hasher, closure_sequence);
        digest_field(&mut hasher, &closure_receipt_digest);
        Ok(Self {
            closure_sequence,
            closure_receipt_digest,
            evidence_digest: hasher.finalize().into(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClearanceEvidence {
    revision: u64,
    digest: [u8; ROOT_DIGEST_SIZE],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootLane {
    Full {
        lineage: RootLineage,
        template: RootContractTemplate,
        digest: CanonicalRootDigest,
    },
    AckedRetained {
        lineage: RootLineage,
        digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
        acknowledgement: AckedEvidence,
    },
    Compact {
        lineage: RootLineage,
        digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
        acknowledgement: AckedEvidence,
        clearance: ClearanceEvidence,
    },
}

impl RootLane {
    const fn lineage(self) -> RootLineage {
        match self {
            Self::Full { lineage, .. }
            | Self::AckedRetained { lineage, .. }
            | Self::Compact { lineage, .. } => lineage,
        }
    }

    const fn digest(self) -> CanonicalRootDigest {
        match self {
            Self::Full { digest, .. }
            | Self::AckedRetained { digest, .. }
            | Self::Compact { digest, .. } => digest,
        }
    }

    const fn request_key(self) -> [u8; ROOT_DIGEST_SIZE] {
        match self {
            Self::Full { template, .. } => template.request_key,
            Self::AckedRetained { request_key, .. } | Self::Compact { request_key, .. } => {
                request_key
            }
        }
    }

    const fn retention(self) -> RootRetention {
        match self {
            Self::Full { .. } => RootRetention::Full,
            Self::AckedRetained { .. } => RootRetention::AckedRetained,
            Self::Compact { .. } => RootRetention::Compact,
        }
    }

    const fn acknowledgement(self) -> Option<AckedEvidence> {
        match self {
            Self::Full { .. } => None,
            Self::AckedRetained {
                acknowledgement, ..
            }
            | Self::Compact {
                acknowledgement, ..
            } => Some(acknowledgement),
        }
    }

    const fn clearance(self) -> Option<ClearanceEvidence> {
        match self {
            Self::Compact { clearance, .. } => Some(clearance),
            Self::Full { .. } | Self::AckedRetained { .. } => None,
        }
    }

    const fn observation(self) -> RootLaneObservation {
        let acknowledgement = self.acknowledgement();
        let clearance = self.clearance();
        RootLaneObservation {
            lineage: self.lineage(),
            contract_digest: self.digest(),
            request_key: self.request_key(),
            retention: self.retention(),
            closure_sequence: match acknowledgement {
                Some(evidence) => Some(evidence.closure_sequence),
                None => None,
            },
            closure_receipt_digest: match acknowledgement {
                Some(evidence) => Some(evidence.closure_receipt_digest),
                None => None,
            },
            closure_evidence_digest: match acknowledgement {
                Some(evidence) => Some(evidence.evidence_digest),
                None => None,
            },
            clearance_revision: match clearance {
                Some(evidence) => Some(evidence.revision),
                None => None,
            },
            clearance_digest: match clearance {
                Some(evidence) => Some(evidence.digest),
                None => None,
            },
        }
    }
}

/// Copyable diagnostic projection. It grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootLaneObservation {
    lineage: RootLineage,
    contract_digest: CanonicalRootDigest,
    request_key: [u8; ROOT_DIGEST_SIZE],
    retention: RootRetention,
    closure_sequence: Option<u64>,
    closure_receipt_digest: Option<[u8; ROOT_DIGEST_SIZE]>,
    closure_evidence_digest: Option<[u8; ROOT_DIGEST_SIZE]>,
    clearance_revision: Option<u64>,
    clearance_digest: Option<[u8; ROOT_DIGEST_SIZE]>,
}

impl RootLaneObservation {
    pub(super) const fn lineage(self) -> RootLineage {
        self.lineage
    }

    pub(super) const fn selector(self) -> RootSelector {
        RootSelector {
            lineage: self.lineage,
        }
    }

    pub(super) const fn contract_digest(self) -> [u8; ROOT_DIGEST_SIZE] {
        self.contract_digest.into_bytes()
    }

    pub(super) const fn request_key(self) -> [u8; ROOT_DIGEST_SIZE] {
        self.request_key
    }

    pub(super) const fn retention(self) -> RootRetention {
        self.retention
    }
}

/// Descriptive result. No variant contains root execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RootAdmissionStatus {
    AllocatedFull(RootLaneObservation),
    AdvancedFull(RootLaneObservation),
    ExistingFull(RootLaneObservation),
    ExistingAckedRetained(RootLaneObservation),
    ExistingCompact(RootLaneObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RootTransitionStatus {
    Applied(RootLaneObservation),
    ExactReplay(RootLaneObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RootLaneError {
    ZeroCapacity,
    CapacityUnrepresentable,
    ZeroRegistryInstance,
    ZeroScopeId,
    ZeroScopeGeneration,
    ZeroAuthorityEpoch,
    ZeroBindingEpoch,
    ZeroOwnerId,
    ZeroOwnerGeneration,
    ZeroPolicyRevision,
    ZeroRequestKey,
    ZeroClosureSequence,
    ZeroClosureReceiptDigest,
    ZeroClearanceRevision,
    ForeignRegistry,
    CapacityExhausted,
    PermitCapacityExhausted,
    UnknownPermit,
    StalePermit,
    PermitKindConflict,
    UnknownScope,
    StaleGeneration {
        presented: u64,
        current: u64,
    },
    UnknownGeneration {
        presented: u64,
        current: u64,
    },
    IdentityConflict {
        generation: u64,
    },
    RequestKeyInUse,
    InvalidRetention {
        expected: RootRetention,
        current: RootRetention,
    },
    ClosureEvidenceConflict,
    ClearanceEvidenceConflict,
    CompactPermitConflict,
    CounterOverflow,
    RetainedOwnersRemain,
    PendingPublicationsRemain,
    LiveEffectsRemain,
    LiveDescendantsRemain,
    OutstandingCreditsRemain,
    ReplayLocatorsRemain,
    DeviceOwnersRemain,
    ResetOwnersRemain,
    IotlbOwnersRemain,
}

/// Failure that returns the exact non-duplicable input without mutation.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct LinearRootFailure<P> {
    error: RootLaneError,
    proof: P,
}

impl<P> LinearRootFailure<P> {
    pub(super) const fn error(&self) -> RootLaneError {
        self.error
    }

    pub(super) fn into_proof(self) -> P {
        self.proof
    }
}

/// Compact coordinate for one table-owned pending authority record. The slot
/// and monotonically increasing generation prevent a stale bearer from
/// selecting a later reservation after the fixed slot is reused.
#[derive(Debug, Eq, PartialEq)]
struct BearerKey {
    registry_instance: u64,
    slot_id: u64,
    generation: u64,
}

/// Fresh operation authority. The complete template remains in the table;
/// this non-duplicable bearer contains only an opaque reservation coordinate.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FreshScopePermit {
    key: BearerKey,
}

/// Sealed closure acknowledgement. The verified receipt projection remains in
/// the table rather than being duplicated into the linear bearer.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ClosureAckPermit {
    key: BearerKey,
}

/// Complete authoritative zero-check required before final root compaction.
/// The type and constructor are private so the parent cannot substitute raw
/// caller-provided counters for a Registry projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedClearanceProjection {
    revision: u64,
    retained_owners: u32,
    pending_publications: u32,
    live_effects: u32,
    live_descendants: u32,
    outstanding_credit_units: u64,
    unresolved_replay_locators: u32,
    device_owners: u32,
    reset_owners: u32,
    iotlb_owners: u32,
}

impl RetainedClearanceProjection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        revision: u64,
        retained_owners: u32,
        pending_publications: u32,
        live_effects: u32,
        live_descendants: u32,
        outstanding_credit_units: u64,
        unresolved_replay_locators: u32,
        device_owners: u32,
        reset_owners: u32,
        iotlb_owners: u32,
    ) -> Result<Self, RootLaneError> {
        if revision == 0 {
            return Err(RootLaneError::ZeroClearanceRevision);
        }
        for (value, error) in [
            (retained_owners, RootLaneError::RetainedOwnersRemain),
            (
                pending_publications,
                RootLaneError::PendingPublicationsRemain,
            ),
            (live_effects, RootLaneError::LiveEffectsRemain),
            (live_descendants, RootLaneError::LiveDescendantsRemain),
            (
                unresolved_replay_locators,
                RootLaneError::ReplayLocatorsRemain,
            ),
            (device_owners, RootLaneError::DeviceOwnersRemain),
            (reset_owners, RootLaneError::ResetOwnersRemain),
            (iotlb_owners, RootLaneError::IotlbOwnersRemain),
        ] {
            if value != 0 {
                return Err(error);
            }
        }
        if outstanding_credit_units != 0 {
            return Err(RootLaneError::OutstandingCreditsRemain);
        }
        Ok(Self {
            revision,
            retained_owners,
            pending_publications,
            live_effects,
            live_descendants,
            outstanding_credit_units,
            unresolved_replay_locators,
            device_owners,
            reset_owners,
            iotlb_owners,
        })
    }

    fn canonical_evidence(
        self,
        observation: RootLaneObservation,
        acknowledgement: AckedEvidence,
    ) -> ClearanceEvidence {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, ROOT_CLEARANCE_SCHEMA);
        digest_lineage(&mut hasher, observation.lineage);
        digest_field(&mut hasher, &observation.contract_digest.0);
        digest_field(&mut hasher, &observation.request_key);
        digest_field(&mut hasher, &acknowledgement.evidence_digest);
        digest_u64(&mut hasher, self.revision);
        digest_u32(&mut hasher, self.retained_owners);
        digest_u32(&mut hasher, self.pending_publications);
        digest_u32(&mut hasher, self.live_effects);
        digest_u32(&mut hasher, self.live_descendants);
        digest_u64(&mut hasher, self.outstanding_credit_units);
        digest_u32(&mut hasher, self.unresolved_replay_locators);
        digest_u32(&mut hasher, self.device_owners);
        digest_u32(&mut hasher, self.reset_owners);
        digest_u32(&mut hasher, self.iotlb_owners);
        ClearanceEvidence {
            revision: self.revision,
            digest: hasher.finalize().into(),
        }
    }
}

/// Sealed final-clearance authority. The private mint accepts only the complete
/// zero-checked projection above.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ClearancePermit {
    key: BearerKey,
}

/// Exact compact-predecessor authority. The predecessor evidence and fresh
/// target remain in the fixed pending table slot selected by this key.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct CompactLanePermit {
    key: BearerKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingProof {
    Fresh {
        template: RootContractTemplate,
    },
    ClosureAck {
        lineage: RootLineage,
        contract_digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
        acknowledgement: AckedEvidence,
    },
    Clearance {
        lineage: RootLineage,
        contract_digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
        acknowledgement: AckedEvidence,
        clearance: ClearanceEvidence,
    },
    Advance {
        predecessor: RootLineage,
        predecessor_digest: CanonicalRootDigest,
        predecessor_request_key: [u8; ROOT_DIGEST_SIZE],
        acknowledgement: AckedEvidence,
        clearance: ClearanceEvidence,
        target: RootContractTemplate,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingReservation {
    generation: u64,
    proof: PendingProof,
}

// RFC 0004 compact-bearer limits are compile-time invariants, not merely test
// expectations. The selector plus fresh bearer is the largest fallible linear
// input; every failure returns only the exact compact bearer and typed error.
const _: () = {
    assert!(core::mem::size_of::<BearerKey>() <= 64);
    assert!(core::mem::size_of::<FreshScopePermit>() <= 64);
    assert!(core::mem::size_of::<ClosureAckPermit>() <= 64);
    assert!(core::mem::size_of::<ClearancePermit>() <= 64);
    assert!(core::mem::size_of::<CompactLanePermit>() <= 64);
    assert!(core::mem::size_of::<RootSelector>() + core::mem::size_of::<FreshScopePermit>() <= 96);
    assert!(core::mem::size_of::<LinearRootFailure<FreshScopePermit>>() <= 120);
    assert!(core::mem::size_of::<LinearRootFailure<ClosureAckPermit>>() <= 120);
    assert!(core::mem::size_of::<LinearRootFailure<ClearancePermit>>() <= 120);
    assert!(core::mem::size_of::<LinearRootFailure<CompactLanePermit>>() <= 120);
};

/// Unique bounded table owned by one `EffectRegistry`.
///
/// This type deliberately does not implement `Clone` or `Copy`.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RootLaneTable<const LANES: usize> {
    registry_instance: u64,
    next_bearer_generation: u64,
    lanes: [Option<RootLane>; LANES],
    pending: [Option<PendingReservation>; LANES],
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootLaneFullSnapshot<const LANES: usize> {
    next_bearer_generation: u64,
    lanes: [Option<RootLane>; LANES],
    pending: [Option<PendingReservation>; LANES],
}

impl<const LANES: usize> RootLaneTable<LANES> {
    pub(super) fn new(registry_instance: u64) -> Result<Self, RootLaneError> {
        if registry_instance == 0 {
            return Err(RootLaneError::ZeroRegistryInstance);
        }
        if LANES == 0 {
            return Err(RootLaneError::ZeroCapacity);
        }
        if u64::try_from(LANES).is_err() {
            return Err(RootLaneError::CapacityUnrepresentable);
        }
        Ok(Self {
            registry_instance,
            next_bearer_generation: 1,
            lanes: [None; LANES],
            pending: [None; LANES],
        })
    }

    pub(super) fn len(&self) -> usize {
        self.lanes.iter().filter(|lane| lane.is_some()).count()
    }

    pub(super) const fn capacity(&self) -> usize {
        LANES
    }

    pub(super) fn get(&self, scope_id: u64) -> Option<RootLaneObservation> {
        let index = self.slot_index(scope_id).ok()?;
        self.lanes[index].map(RootLane::observation)
    }

    /// Foundation-only reservation hook. A future child-module
    /// `impl EffectRegistry` must call this only after operation freshness,
    /// replay, and quota checks; the parent module cannot mint the bearer.
    fn reserve_fresh(
        &mut self,
        template: RootContractTemplate,
    ) -> Result<FreshScopePermit, RootLaneError> {
        Ok(FreshScopePermit {
            key: self.reserve_proof(PendingProof::Fresh { template })?,
        })
    }

    /// Foundation-only receipt verifier hook. The verified evidence is stored
    /// in the table and the returned bearer is only its opaque coordinate.
    fn reserve_closure_ack(
        &mut self,
        observation: RootLaneObservation,
        closure_sequence: u64,
        closure_receipt_digest: [u8; ROOT_DIGEST_SIZE],
    ) -> Result<ClosureAckPermit, RootLaneError> {
        let acknowledgement = AckedEvidence::new(
            observation.lineage,
            observation.contract_digest,
            observation.request_key,
            closure_sequence,
            closure_receipt_digest,
        )?;
        Ok(ClosureAckPermit {
            key: self.reserve_proof(PendingProof::ClosureAck {
                lineage: observation.lineage,
                contract_digest: observation.contract_digest,
                request_key: observation.request_key,
                acknowledgement,
            })?,
        })
    }

    /// Foundation-only complete-clearance verifier hook.
    fn reserve_clearance(
        &mut self,
        observation: RootLaneObservation,
        projection: RetainedClearanceProjection,
    ) -> Result<ClearancePermit, RootLaneError> {
        if !matches!(
            observation.retention,
            RootRetention::AckedRetained | RootRetention::Compact
        ) {
            return Err(RootLaneError::InvalidRetention {
                expected: RootRetention::AckedRetained,
                current: observation.retention,
            });
        }
        let acknowledgement = AckedEvidence {
            closure_sequence: observation
                .closure_sequence
                .ok_or(RootLaneError::ClosureEvidenceConflict)?,
            closure_receipt_digest: observation
                .closure_receipt_digest
                .ok_or(RootLaneError::ClosureEvidenceConflict)?,
            evidence_digest: observation
                .closure_evidence_digest
                .ok_or(RootLaneError::ClosureEvidenceConflict)?,
        };
        let clearance = projection.canonical_evidence(observation, acknowledgement);
        Ok(ClearancePermit {
            key: self.reserve_proof(PendingProof::Clearance {
                lineage: observation.lineage,
                contract_digest: observation.contract_digest,
                request_key: observation.request_key,
                acknowledgement,
                clearance,
            })?,
        })
    }

    /// Allocates only a never-used fixed slot and generates scope id/generation.
    pub(super) fn allocate(
        &mut self,
        permit: FreshScopePermit,
    ) -> Result<RootAdmissionStatus, LinearRootFailure<FreshScopePermit>> {
        let (pending_index, pending) = match self.pending_proof(&permit.key) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(LinearRootFailure {
                    error,
                    proof: permit,
                });
            }
        };
        let PendingProof::Fresh { template } = pending else {
            return Err(LinearRootFailure {
                error: RootLaneError::PermitKindConflict,
                proof: permit,
            });
        };
        if self.request_key_in_use(template.request_key) {
            return Err(LinearRootFailure {
                error: RootLaneError::RequestKeyInUse,
                proof: permit,
            });
        }
        let Some(index) = self.lanes.iter().position(Option::is_none) else {
            return Err(LinearRootFailure {
                error: RootLaneError::CapacityExhausted,
                proof: permit,
            });
        };
        let scope_id = match u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
        {
            Some(scope_id) => scope_id,
            None => {
                return Err(LinearRootFailure {
                    error: RootLaneError::CapacityUnrepresentable,
                    proof: permit,
                });
            }
        };
        let lineage = RootLineage {
            registry_instance: self.registry_instance,
            scope_id,
            scope_generation: 1,
        };
        let digest = canonical_contract_digest(lineage, template);
        let installed = RootLane::Full {
            lineage,
            template,
            digest,
        };
        self.lanes[index] = Some(installed);
        self.pending[pending_index] = None;
        Ok(RootAdmissionStatus::AllocatedFull(installed.observation()))
    }

    /// Recovers only an exact existing generation. Unknown or future selectors
    /// never allocate and every result is descriptive.
    pub(super) fn recover(
        &self,
        selector: RootSelector,
        template: RootContractTemplate,
    ) -> Result<RootAdmissionStatus, RootLaneError> {
        let index = self.require_exact_selector(selector)?;
        let current = self.lanes[index].ok_or(RootLaneError::UnknownScope)?;
        let digest = canonical_contract_digest(selector.lineage, template);
        if digest != current.digest() {
            return Err(RootLaneError::IdentityConflict {
                generation: selector.lineage.scope_generation,
            });
        }
        Ok(match current.retention() {
            RootRetention::Full => RootAdmissionStatus::ExistingFull(current.observation()),
            RootRetention::AckedRetained => {
                RootAdmissionStatus::ExistingAckedRetained(current.observation())
            }
            RootRetention::Compact => RootAdmissionStatus::ExistingCompact(current.observation()),
        })
    }

    /// Consumes a fresh operation and binds it to one exact compact predecessor.
    pub(super) fn prepare_advance(
        &mut self,
        selector: RootSelector,
        fresh: FreshScopePermit,
    ) -> Result<CompactLanePermit, LinearRootFailure<FreshScopePermit>> {
        let (pending_index, pending) = match self.pending_proof(&fresh.key) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(LinearRootFailure {
                    error,
                    proof: fresh,
                });
            }
        };
        let PendingProof::Fresh { template } = pending else {
            return Err(LinearRootFailure {
                error: RootLaneError::PermitKindConflict,
                proof: fresh,
            });
        };
        if self.request_key_in_use(template.request_key) {
            return Err(LinearRootFailure {
                error: RootLaneError::RequestKeyInUse,
                proof: fresh,
            });
        }
        let index = match self.require_exact_selector(selector) {
            Ok(index) => index,
            Err(error) => {
                return Err(LinearRootFailure {
                    error,
                    proof: fresh,
                });
            }
        };
        let current = self.lanes[index].unwrap();
        let RootLane::Compact {
            lineage,
            digest,
            request_key,
            acknowledgement,
            clearance,
        } = current
        else {
            return Err(LinearRootFailure {
                error: RootLaneError::InvalidRetention {
                    expected: RootRetention::Compact,
                    current: current.retention(),
                },
                proof: fresh,
            });
        };
        self.pending[pending_index] = Some(PendingReservation {
            generation: fresh.key.generation,
            proof: PendingProof::Advance {
                predecessor: lineage,
                predecessor_digest: digest,
                predecessor_request_key: request_key,
                acknowledgement,
                clearance,
                target: template,
            },
        });
        Ok(CompactLanePermit { key: fresh.key })
    }

    /// Advances one exact compact slot. All fallible checks precede mutation.
    pub(super) fn advance(
        &mut self,
        permit: CompactLanePermit,
    ) -> Result<RootAdmissionStatus, LinearRootFailure<CompactLanePermit>> {
        let (pending_index, pending) = match self.pending_proof(&permit.key) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(LinearRootFailure {
                    error,
                    proof: permit,
                });
            }
        };
        let PendingProof::Advance {
            predecessor,
            predecessor_digest,
            predecessor_request_key,
            acknowledgement: predecessor_acknowledgement,
            clearance: predecessor_clearance,
            target,
        } = pending
        else {
            return Err(LinearRootFailure {
                error: RootLaneError::PermitKindConflict,
                proof: permit,
            });
        };
        let selector = RootSelector {
            lineage: predecessor,
        };
        let index = match self.require_exact_selector(selector) {
            Ok(index) => index,
            Err(error) => {
                return Err(LinearRootFailure {
                    error,
                    proof: permit,
                });
            }
        };
        let current = self.lanes[index].unwrap();
        let RootLane::Compact {
            lineage: current_lineage,
            digest: current_digest,
            request_key: current_request_key,
            acknowledgement: current_acknowledgement,
            clearance: current_clearance,
        } = current
        else {
            return Err(LinearRootFailure {
                error: RootLaneError::InvalidRetention {
                    expected: RootRetention::Compact,
                    current: current.retention(),
                },
                proof: permit,
            });
        };
        if current_lineage != predecessor
            || current_digest != predecessor_digest
            || current_request_key != predecessor_request_key
            || current_acknowledgement != predecessor_acknowledgement
            || current_clearance != predecessor_clearance
        {
            return Err(LinearRootFailure {
                error: RootLaneError::CompactPermitConflict,
                proof: permit,
            });
        }
        if self.request_key_in_use(target.request_key) {
            return Err(LinearRootFailure {
                error: RootLaneError::RequestKeyInUse,
                proof: permit,
            });
        }
        let next_generation = match current_lineage.scope_generation.checked_add(1) {
            Some(next) => next,
            None => {
                return Err(LinearRootFailure {
                    error: RootLaneError::CounterOverflow,
                    proof: permit,
                });
            }
        };
        let next_lineage = RootLineage {
            scope_generation: next_generation,
            ..current_lineage
        };
        let next_digest = canonical_contract_digest(next_lineage, target);
        let installed = RootLane::Full {
            lineage: next_lineage,
            template: target,
            digest: next_digest,
        };
        self.lanes[index] = Some(installed);
        self.pending[pending_index] = None;
        Ok(RootAdmissionStatus::AdvancedFull(installed.observation()))
    }

    pub(super) fn acknowledge_retained(
        &mut self,
        proof: ClosureAckPermit,
    ) -> Result<RootTransitionStatus, LinearRootFailure<ClosureAckPermit>> {
        let (pending_index, pending) = match self.pending_proof(&proof.key) {
            Ok(pending) => pending,
            Err(error) => return Err(LinearRootFailure { error, proof }),
        };
        let PendingProof::ClosureAck {
            lineage,
            contract_digest,
            request_key,
            acknowledgement,
        } = pending
        else {
            return Err(LinearRootFailure {
                error: RootLaneError::PermitKindConflict,
                proof,
            });
        };
        let index = match self.require_exact_contract(lineage, contract_digest, request_key) {
            Ok(index) => index,
            Err(error) => return Err(LinearRootFailure { error, proof }),
        };
        let current = self.lanes[index].unwrap();
        match current {
            RootLane::Full { .. } => {
                let next = RootLane::AckedRetained {
                    lineage,
                    digest: contract_digest,
                    request_key,
                    acknowledgement,
                };
                self.lanes[index] = Some(next);
                self.pending[pending_index] = None;
                Ok(RootTransitionStatus::Applied(next.observation()))
            }
            RootLane::AckedRetained {
                acknowledgement: current_acknowledgement,
                ..
            }
            | RootLane::Compact {
                acknowledgement: current_acknowledgement,
                ..
            } if current_acknowledgement == acknowledgement => {
                self.pending[pending_index] = None;
                Ok(RootTransitionStatus::ExactReplay(current.observation()))
            }
            RootLane::AckedRetained { .. } | RootLane::Compact { .. } => Err(LinearRootFailure {
                error: RootLaneError::ClosureEvidenceConflict,
                proof,
            }),
        }
    }

    pub(super) fn compact(
        &mut self,
        proof: ClearancePermit,
    ) -> Result<RootTransitionStatus, LinearRootFailure<ClearancePermit>> {
        let (pending_index, pending) = match self.pending_proof(&proof.key) {
            Ok(pending) => pending,
            Err(error) => return Err(LinearRootFailure { error, proof }),
        };
        let PendingProof::Clearance {
            lineage,
            contract_digest,
            request_key,
            acknowledgement,
            clearance,
        } = pending
        else {
            return Err(LinearRootFailure {
                error: RootLaneError::PermitKindConflict,
                proof,
            });
        };
        let index = match self.require_exact_contract(lineage, contract_digest, request_key) {
            Ok(index) => index,
            Err(error) => return Err(LinearRootFailure { error, proof }),
        };
        let current = self.lanes[index].unwrap();
        match current {
            RootLane::AckedRetained {
                acknowledgement: current_acknowledgement,
                ..
            } if current_acknowledgement == acknowledgement => {
                let next = RootLane::Compact {
                    lineage,
                    digest: contract_digest,
                    request_key,
                    acknowledgement,
                    clearance,
                };
                self.lanes[index] = Some(next);
                self.pending[pending_index] = None;
                Ok(RootTransitionStatus::Applied(next.observation()))
            }
            RootLane::AckedRetained { .. } => Err(LinearRootFailure {
                error: RootLaneError::ClosureEvidenceConflict,
                proof,
            }),
            RootLane::Compact {
                acknowledgement: current_acknowledgement,
                clearance: current_clearance,
                ..
            } if current_acknowledgement == acknowledgement && current_clearance == clearance => {
                self.pending[pending_index] = None;
                Ok(RootTransitionStatus::ExactReplay(current.observation()))
            }
            RootLane::Compact { .. } => Err(LinearRootFailure {
                error: RootLaneError::ClearanceEvidenceConflict,
                proof,
            }),
            RootLane::Full { .. } => Err(LinearRootFailure {
                error: RootLaneError::InvalidRetention {
                    expected: RootRetention::AckedRetained,
                    current: RootRetention::Full,
                },
                proof,
            }),
        }
    }

    fn reserve_proof(&mut self, proof: PendingProof) -> Result<BearerKey, RootLaneError> {
        let index = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(RootLaneError::PermitCapacityExhausted)?;
        let slot_id = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(RootLaneError::CapacityUnrepresentable)?;
        let generation = self.next_bearer_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(RootLaneError::CounterOverflow)?;
        let key = BearerKey {
            registry_instance: self.registry_instance,
            slot_id,
            generation,
        };
        self.pending[index] = Some(PendingReservation { generation, proof });
        self.next_bearer_generation = next_generation;
        Ok(key)
    }

    fn pending_proof(&self, key: &BearerKey) -> Result<(usize, PendingProof), RootLaneError> {
        if key.registry_instance != self.registry_instance {
            return Err(RootLaneError::ForeignRegistry);
        }
        let index = self.permit_slot_index(key.slot_id)?;
        let reservation = self.pending[index].ok_or(RootLaneError::UnknownPermit)?;
        if reservation.generation != key.generation {
            return Err(RootLaneError::StalePermit);
        }
        Ok((index, reservation.proof))
    }

    fn permit_slot_index(&self, slot_id: u64) -> Result<usize, RootLaneError> {
        let zero_based = slot_id.checked_sub(1).ok_or(RootLaneError::UnknownPermit)?;
        let index = usize::try_from(zero_based).map_err(|_| RootLaneError::UnknownPermit)?;
        if index >= LANES {
            return Err(RootLaneError::UnknownPermit);
        }
        Ok(index)
    }

    fn slot_index(&self, scope_id: u64) -> Result<usize, RootLaneError> {
        let zero_based = scope_id.checked_sub(1).ok_or(RootLaneError::ZeroScopeId)?;
        let index = usize::try_from(zero_based).map_err(|_| RootLaneError::UnknownScope)?;
        if index >= LANES {
            return Err(RootLaneError::UnknownScope);
        }
        Ok(index)
    }

    fn require_exact_selector(&self, selector: RootSelector) -> Result<usize, RootLaneError> {
        let presented = selector.lineage;
        if presented.registry_instance != self.registry_instance {
            return Err(RootLaneError::ForeignRegistry);
        }
        let index = self.slot_index(presented.scope_id)?;
        let current = self.lanes[index].ok_or(RootLaneError::UnknownScope)?;
        let current_generation = current.lineage().scope_generation;
        if presented.scope_generation < current_generation {
            return Err(RootLaneError::StaleGeneration {
                presented: presented.scope_generation,
                current: current_generation,
            });
        }
        if presented.scope_generation > current_generation {
            return Err(RootLaneError::UnknownGeneration {
                presented: presented.scope_generation,
                current: current_generation,
            });
        }
        Ok(index)
    }

    fn require_exact_contract(
        &self,
        lineage: RootLineage,
        digest: CanonicalRootDigest,
        request_key: [u8; ROOT_DIGEST_SIZE],
    ) -> Result<usize, RootLaneError> {
        let index = self.require_exact_selector(RootSelector { lineage })?;
        let current = self.lanes[index].unwrap();
        if digest != current.digest() || request_key != current.request_key() {
            return Err(RootLaneError::IdentityConflict {
                generation: lineage.scope_generation,
            });
        }
        Ok(index)
    }

    fn request_key_in_use(&self, request_key: [u8; ROOT_DIGEST_SIZE]) -> bool {
        self.lanes
            .iter()
            .flatten()
            .any(|lane| lane.request_key() == request_key)
    }

    #[cfg(test)]
    fn full_snapshot(&self) -> RootLaneFullSnapshot<LANES> {
        RootLaneFullSnapshot {
            next_bearer_generation: self.next_bearer_generation,
            lanes: self.lanes,
            pending: self.pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    const REGISTRY: u64 = 0x51;

    fn request_key(tag: u8) -> [u8; ROOT_DIGEST_SIZE] {
        [tag; ROOT_DIGEST_SIZE]
    }

    fn template(tag: u8) -> RootContractTemplate {
        RootContractTemplate::new(
            41,
            7,
            100,
            3,
            1,
            RootPolicy::new(0, 8, 8, 16, 16),
            request_key(tag),
        )
        .unwrap()
    }

    fn fresh<const LANES: usize>(table: &mut RootLaneTable<LANES>, tag: u8) -> FreshScopePermit {
        table.reserve_fresh(template(tag)).unwrap()
    }

    fn key_coordinate(key: &BearerKey) -> (u64, u64, u64) {
        (key.registry_instance, key.slot_id, key.generation)
    }

    fn observation<const LANES: usize>(
        table: &RootLaneTable<LANES>,
        scope_id: u64,
    ) -> RootLaneObservation {
        table.get(scope_id).unwrap()
    }

    fn acknowledgement<const LANES: usize>(
        table: &mut RootLaneTable<LANES>,
        observation: RootLaneObservation,
        sequence: u64,
        tag: u8,
    ) -> ClosureAckPermit {
        table
            .reserve_closure_ack(observation, sequence, request_key(tag))
            .unwrap()
    }

    fn zero_projection(revision: u64) -> RetainedClearanceProjection {
        RetainedClearanceProjection::new(revision, 0, 0, 0, 0, 0, 0, 0, 0, 0).unwrap()
    }

    fn clearance<const LANES: usize>(
        table: &mut RootLaneTable<LANES>,
        observation: RootLaneObservation,
        revision: u64,
    ) -> ClearancePermit {
        table
            .reserve_clearance(observation, zero_projection(revision))
            .unwrap()
    }

    fn compact_one<const LANES: usize>(
        table: &mut RootLaneTable<LANES>,
        scope_id: u64,
    ) -> RootLaneObservation {
        let full = observation(table, scope_id);
        let acknowledgement_permit = acknowledgement(table, full, 3, 4);
        table.acknowledge_retained(acknowledgement_permit).unwrap();
        let retained = observation(table, scope_id);
        let clearance_permit = clearance(table, retained, 5);
        table.compact(clearance_permit).unwrap();
        observation(table, scope_id)
    }

    #[test]
    fn validates_capacity_selector_and_each_zero_contract_coordinate() {
        assert_eq!(
            RootLaneTable::<0>::new(REGISTRY),
            Err(RootLaneError::ZeroCapacity)
        );
        assert_eq!(
            RootLaneTable::<1>::new(0),
            Err(RootLaneError::ZeroRegistryInstance)
        );
        assert_eq!(
            RootSelector::new(0, 1, 1),
            Err(RootLaneError::ZeroRegistryInstance)
        );
        assert_eq!(
            RootSelector::new(REGISTRY, 0, 1),
            Err(RootLaneError::ZeroScopeId)
        );
        assert_eq!(
            RootSelector::new(REGISTRY, 1, 0),
            Err(RootLaneError::ZeroScopeGeneration)
        );

        let policy = RootPolicy::new(0, 1, 1, 1, 1);
        for (result, expected) in [
            (
                RootContractTemplate::new(0, 1, 1, 1, 1, policy, request_key(1)),
                RootLaneError::ZeroAuthorityEpoch,
            ),
            (
                RootContractTemplate::new(1, 0, 1, 1, 1, policy, request_key(1)),
                RootLaneError::ZeroBindingEpoch,
            ),
            (
                RootContractTemplate::new(1, 1, 0, 1, 1, policy, request_key(1)),
                RootLaneError::ZeroOwnerId,
            ),
            (
                RootContractTemplate::new(1, 1, 1, 0, 1, policy, request_key(1)),
                RootLaneError::ZeroOwnerGeneration,
            ),
            (
                RootContractTemplate::new(1, 1, 1, 1, 0, policy, request_key(1)),
                RootLaneError::ZeroPolicyRevision,
            ),
            (
                RootContractTemplate::new(1, 1, 1, 1, 1, policy, [0; ROOT_DIGEST_SIZE]),
                RootLaneError::ZeroRequestKey,
            ),
        ] {
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn canonical_contract_digest_is_frozen_and_every_field_is_bound() {
        let lineage = RootLineage::new(REGISTRY, 1, 1).unwrap();
        let original = template(0x71);
        assert_eq!(
            canonical_contract_digest(lineage, original).into_bytes(),
            [
                0x1d, 0x28, 0x91, 0xf2, 0xee, 0x50, 0x49, 0x93, 0x7f, 0x16, 0xcb, 0xba, 0x30, 0xfa,
                0x12, 0xfb, 0xec, 0x9b, 0x2e, 0x86, 0xd2, 0x4c, 0x52, 0xca, 0xca, 0x7f, 0x2d, 0x4b,
                0xe6, 0xd6, 0x60, 0x9b,
            ]
        );

        let lineages = [
            RootLineage::new(REGISTRY + 1, 1, 1).unwrap(),
            RootLineage::new(REGISTRY, 2, 1).unwrap(),
            RootLineage::new(REGISTRY, 1, 2).unwrap(),
        ];
        for mutation in lineages {
            assert_ne!(
                canonical_contract_digest(mutation, original),
                canonical_contract_digest(lineage, original)
            );
        }
        let mutations = [
            RootContractTemplate {
                authority_epoch: 42,
                ..original
            },
            RootContractTemplate {
                binding_epoch: 8,
                ..original
            },
            RootContractTemplate {
                owner_id: 101,
                ..original
            },
            RootContractTemplate {
                owner_generation: 4,
                ..original
            },
            RootContractTemplate {
                policy_revision: 2,
                ..original
            },
            RootContractTemplate {
                policy: RootPolicy::new(1, 8, 8, 16, 16),
                ..original
            },
            RootContractTemplate {
                policy: RootPolicy::new(0, 9, 8, 16, 16),
                ..original
            },
            RootContractTemplate {
                policy: RootPolicy::new(0, 8, 9, 16, 16),
                ..original
            },
            RootContractTemplate {
                policy: RootPolicy::new(0, 8, 8, 17, 16),
                ..original
            },
            RootContractTemplate {
                policy: RootPolicy::new(0, 8, 8, 16, 17),
                ..original
            },
            RootContractTemplate {
                request_key: request_key(0x72),
                ..original
            },
        ];
        for mutation in mutations {
            assert_ne!(
                canonical_contract_digest(lineage, mutation),
                canonical_contract_digest(lineage, original)
            );
        }
    }

    #[test]
    fn allocate_owns_fixed_ids_and_returns_fresh_permit_on_every_failure() {
        let mut table = RootLaneTable::<2>::new(REGISTRY).unwrap();
        let first_permit = fresh(&mut table, 1);
        let first = table.allocate(first_permit).unwrap();
        let RootAdmissionStatus::AllocatedFull(first) = first else {
            panic!("unexpected allocation status");
        };
        assert_eq!(first.lineage.scope_id(), 1);
        assert_eq!(first.lineage.scope_generation(), 1);
        assert_eq!(first.request_key(), request_key(1));

        let second_permit = fresh(&mut table, 2);
        let second = table.allocate(second_permit).unwrap();
        let RootAdmissionStatus::AllocatedFull(second) = second else {
            panic!("unexpected allocation status");
        };
        assert_eq!(second.lineage.scope_id(), 2);
        assert_eq!(second.lineage.scope_generation(), 1);

        let exhausted = fresh(&mut table, 3);
        let exhausted_coordinate = key_coordinate(&exhausted.key);
        let before = table.full_snapshot();
        let failure = table.allocate(exhausted).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::CapacityExhausted);
        let returned = failure.into_proof();
        assert_eq!(key_coordinate(&returned.key), exhausted_coordinate);
        assert_eq!(
            table.pending_proof(&returned.key).unwrap().1,
            PendingProof::Fresh {
                template: template(3)
            }
        );
        assert_eq!(table.full_snapshot(), before);

        let mut foreign_table = RootLaneTable::<1>::new(REGISTRY + 1).unwrap();
        let foreign = foreign_table.reserve_fresh(template(4)).unwrap();
        let foreign_coordinate = key_coordinate(&foreign.key);
        let failure = table.allocate(foreign).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::ForeignRegistry);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            foreign_coordinate
        );
        assert_eq!(table.full_snapshot(), before);
    }

    #[test]
    fn reused_pending_slot_rejects_stale_bearer_and_returns_exact_key() {
        let mut table = RootLaneTable::<1>::new(REGISTRY).unwrap();
        let first = fresh(&mut table, 1);
        let first_coordinate = key_coordinate(&first.key);
        table.allocate(first).unwrap();

        let replacement = fresh(&mut table, 2);
        let replacement_coordinate = key_coordinate(&replacement.key);
        assert_eq!(first_coordinate.1, replacement_coordinate.1);
        assert_ne!(first_coordinate.2, replacement_coordinate.2);

        // Only this child-module test can construct a raw stale coordinate.
        let stale = FreshScopePermit {
            key: BearerKey {
                registry_instance: first_coordinate.0,
                slot_id: first_coordinate.1,
                generation: first_coordinate.2,
            },
        };
        let before = table.full_snapshot();
        let failure = table.allocate(stale).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::StalePermit);
        let returned = failure.into_proof();
        assert_eq!(key_coordinate(&returned.key), first_coordinate);
        assert_eq!(table.full_snapshot(), before);
        assert!(table.pending_proof(&replacement.key).is_ok());
    }

    #[test]
    fn recover_is_read_only_exact_typed_and_never_allocates() {
        let mut table = RootLaneTable::<2>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let before = table.full_snapshot();
        let selector = observation(&table, 1).selector();
        assert!(matches!(
            table.recover(selector, template(1)),
            Ok(RootAdmissionStatus::ExistingFull(_))
        ));
        assert_eq!(
            table.recover(selector, template(2)),
            Err(RootLaneError::IdentityConflict { generation: 1 })
        );
        assert_eq!(
            table.recover(RootSelector::new(REGISTRY, 2, 1).unwrap(), template(2)),
            Err(RootLaneError::UnknownScope)
        );
        assert_eq!(
            table.recover(RootSelector::new(REGISTRY, 1, 2).unwrap(), template(1)),
            Err(RootLaneError::UnknownGeneration {
                presented: 2,
                current: 1,
            })
        );
        assert_eq!(
            table.recover(
                RootSelector::new(REGISTRY, u64::MAX, 1).unwrap(),
                template(1),
            ),
            Err(RootLaneError::UnknownScope)
        );
        assert_eq!(table.full_snapshot(), before);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn closure_ack_is_domain_bound_linear_and_failure_atomic() {
        let mut table = RootLaneTable::<2>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let full = observation(&table, 1);

        let foreign_observation = RootLaneObservation {
            lineage: RootLineage::new(REGISTRY + 1, 1, 1).unwrap(),
            ..full
        };
        let foreign = acknowledgement(&mut table, foreign_observation, 3, 4);
        let foreign_coordinate = key_coordinate(&foreign.key);
        let before = table.full_snapshot();
        let failure = table.acknowledge_retained(foreign).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::ForeignRegistry);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            foreign_coordinate
        );
        assert_eq!(table.full_snapshot(), before);

        let acknowledgement_permit = acknowledgement(&mut table, full, 3, 4);
        let applied = table.acknowledge_retained(acknowledgement_permit).unwrap();
        assert!(matches!(applied, RootTransitionStatus::Applied(_)));
        let retained = observation(&table, 1);
        assert_eq!(retained.request_key(), request_key(1));
        let acknowledgement_permit = acknowledgement(&mut table, retained, 3, 4);
        let replay = table.acknowledge_retained(acknowledgement_permit).unwrap();
        assert!(matches!(replay, RootTransitionStatus::ExactReplay(_)));
        let conflicting = acknowledgement(&mut table, retained, 3, 5);
        let conflicting_coordinate = key_coordinate(&conflicting.key);
        let before_conflict = table.full_snapshot();
        let failure = table.acknowledge_retained(conflicting).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::ClosureEvidenceConflict);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            conflicting_coordinate
        );
        assert_eq!(table.full_snapshot(), before_conflict);
    }

    #[test]
    fn clearance_projection_mechanically_rejects_every_live_category() {
        assert_eq!(
            RetainedClearanceProjection::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            Err(RootLaneError::ZeroClearanceRevision)
        );
        for (projection, expected) in [
            (
                RetainedClearanceProjection::new(1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
                RootLaneError::RetainedOwnersRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 1, 0, 0, 0, 0, 0, 0, 0),
                RootLaneError::PendingPublicationsRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 1, 0, 0, 0, 0, 0, 0),
                RootLaneError::LiveEffectsRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
                RootLaneError::LiveDescendantsRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 0, 1, 0, 0, 0, 0),
                RootLaneError::OutstandingCreditsRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 0, 0, 1, 0, 0, 0),
                RootLaneError::ReplayLocatorsRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 0, 0, 0, 1, 0, 0),
                RootLaneError::DeviceOwnersRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 0, 0, 0, 0, 1, 0),
                RootLaneError::ResetOwnersRemain,
            ),
            (
                RetainedClearanceProjection::new(1, 0, 0, 0, 0, 0, 0, 0, 0, 1),
                RootLaneError::IotlbOwnersRemain,
            ),
        ] {
            assert_eq!(projection, Err(expected));
        }
    }

    #[test]
    fn compaction_requires_ack_and_exact_clearance_evidence() {
        let mut table = RootLaneTable::<1>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let full = observation(&table, 1);
        assert_eq!(
            table.reserve_clearance(full, zero_projection(1)),
            Err(RootLaneError::InvalidRetention {
                expected: RootRetention::AckedRetained,
                current: RootRetention::Full,
            })
        );

        let acknowledgement_permit = acknowledgement(&mut table, full, 3, 4);
        table.acknowledge_retained(acknowledgement_permit).unwrap();
        let retained = observation(&table, 1);
        let clearance_permit = clearance(&mut table, retained, 5);
        let applied = table.compact(clearance_permit).unwrap();
        assert!(matches!(applied, RootTransitionStatus::Applied(_)));
        let compact = observation(&table, 1);
        assert_eq!(compact.request_key(), request_key(1));
        let clearance_permit = clearance(&mut table, compact, 5);
        let replay = table.compact(clearance_permit).unwrap();
        assert!(matches!(replay, RootTransitionStatus::ExactReplay(_)));
        assert!(matches!(
            table.recover(compact.selector(), template(1)),
            Ok(RootAdmissionStatus::ExistingCompact(_))
        ));

        let conflicting = clearance(&mut table, compact, 6);
        let conflicting_coordinate = key_coordinate(&conflicting.key);
        let before = table.full_snapshot();
        let failure = table.compact(conflicting).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::ClearanceEvidenceConflict);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            conflicting_coordinate
        );
        assert_eq!(table.full_snapshot(), before);
    }

    #[test]
    fn current_request_key_cannot_allocate_or_advance_as_new_work() {
        let mut table = RootLaneTable::<2>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let compact = compact_one(&mut table, 1);

        let duplicate = fresh(&mut table, 1);
        let duplicate_coordinate = key_coordinate(&duplicate.key);
        let before = table.full_snapshot();
        let failure = table.allocate(duplicate).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::RequestKeyInUse);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            duplicate_coordinate
        );
        assert_eq!(table.full_snapshot(), before);

        let duplicate = fresh(&mut table, 1);
        let duplicate_coordinate = key_coordinate(&duplicate.key);
        let before = table.full_snapshot();
        let failure = table
            .prepare_advance(compact.selector(), duplicate)
            .unwrap_err();
        assert_eq!(failure.error(), RootLaneError::RequestKeyInUse);
        assert_eq!(
            key_coordinate(&failure.into_proof().key),
            duplicate_coordinate
        );
        assert_eq!(table.full_snapshot(), before);
    }

    #[test]
    fn advance_consumes_exact_compact_permit_and_table_generates_successor() {
        let mut table = RootLaneTable::<1>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let compact = compact_one(&mut table, 1);
        let fresh = fresh(&mut table, 2);
        let permit = table.prepare_advance(compact.selector(), fresh).unwrap();
        let advanced = table.advance(permit).unwrap();
        let RootAdmissionStatus::AdvancedFull(advanced) = advanced else {
            panic!("unexpected advance status");
        };
        assert_eq!(advanced.lineage.scope_id(), 1);
        assert_eq!(advanced.lineage.scope_generation(), 2);
        assert_eq!(advanced.request_key(), request_key(2));
        assert_eq!(
            table.recover(compact.selector(), template(1)),
            Err(RootLaneError::StaleGeneration {
                presented: 1,
                current: 2,
            })
        );
        assert!(matches!(
            table.recover(advanced.selector(), template(2)),
            Ok(RootAdmissionStatus::ExistingFull(_))
        ));
    }

    #[test]
    fn stale_advance_returns_exact_permit_without_mutation() {
        let mut table = RootLaneTable::<2>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let compact = compact_one(&mut table, 1);
        let winner_fresh = fresh(&mut table, 2);
        let winner = table
            .prepare_advance(compact.selector(), winner_fresh)
            .unwrap();
        let stale_fresh = fresh(&mut table, 3);
        let stale = table
            .prepare_advance(compact.selector(), stale_fresh)
            .unwrap();
        let stale_coordinate = key_coordinate(&stale.key);
        table.advance(winner).unwrap();
        let before = table.full_snapshot();
        let failure = table.advance(stale).unwrap_err();
        assert_eq!(
            failure.error(),
            RootLaneError::StaleGeneration {
                presented: 1,
                current: 2,
            }
        );
        let returned = failure.into_proof();
        assert_eq!(key_coordinate(&returned.key), stale_coordinate);
        assert!(matches!(
            table.pending_proof(&returned.key).unwrap().1,
            PendingProof::Advance { target, .. } if target.request_key() == request_key(3)
        ));
        assert_eq!(table.full_snapshot(), before);
    }

    #[test]
    fn advance_overflow_is_typed_atomic_and_returns_permit() {
        let lineage = RootLineage::new(REGISTRY, 1, u64::MAX).unwrap();
        let target = template(2);
        let acknowledgement = AckedEvidence::new(
            lineage,
            canonical_contract_digest(lineage, template(1)),
            request_key(1),
            3,
            request_key(4),
        )
        .unwrap();
        let observation = RootLaneObservation {
            lineage,
            contract_digest: canonical_contract_digest(lineage, template(1)),
            request_key: request_key(1),
            retention: RootRetention::AckedRetained,
            closure_sequence: Some(acknowledgement.closure_sequence),
            closure_receipt_digest: Some(acknowledgement.closure_receipt_digest),
            closure_evidence_digest: Some(acknowledgement.evidence_digest),
            clearance_revision: None,
            clearance_digest: None,
        };
        let clearance = zero_projection(5).canonical_evidence(observation, acknowledgement);
        let mut table = RootLaneTable::<1> {
            registry_instance: REGISTRY,
            next_bearer_generation: 1,
            lanes: [Some(RootLane::Compact {
                lineage,
                digest: observation.contract_digest,
                request_key: request_key(1),
                acknowledgement,
                clearance,
            })],
            pending: [None],
        };
        let fresh = table.reserve_fresh(target).unwrap();
        let permit = table
            .prepare_advance(observation.selector(), fresh)
            .unwrap();
        let permit_coordinate = key_coordinate(&permit.key);
        let before = table.full_snapshot();
        let failure = table.advance(permit).unwrap_err();
        assert_eq!(failure.error(), RootLaneError::CounterOverflow);
        let returned = failure.into_proof();
        assert_eq!(key_coordinate(&returned.key), permit_coordinate);
        assert!(matches!(
            table.pending_proof(&returned.key).unwrap().1,
            PendingProof::Advance { target, .. } if target.request_key() == request_key(2)
        ));
        assert_eq!(table.full_snapshot(), before);
    }

    #[test]
    fn representation_is_bounded_and_full_test_snapshot_covers_contract_state() {
        assert!(
            size_of::<RootLane>() <= 224,
            "RootLane={}",
            size_of::<RootLane>()
        );
        assert!(
            size_of::<RootLaneObservation>() <= 224,
            "RootLaneObservation grew to {} bytes",
            size_of::<RootLaneObservation>()
        );
        assert!(
            size_of::<FreshScopePermit>() <= 64,
            "FreshScopePermit grew to {} bytes",
            size_of::<FreshScopePermit>()
        );
        assert!(
            size_of::<ClosureAckPermit>() <= 64,
            "ClosureAckPermit grew to {} bytes",
            size_of::<ClosureAckPermit>()
        );
        assert!(
            size_of::<ClearancePermit>() <= 64,
            "ClearancePermit grew to {} bytes",
            size_of::<ClearancePermit>()
        );
        assert!(
            size_of::<CompactLanePermit>() <= 64,
            "CompactLanePermit grew to {} bytes",
            size_of::<CompactLanePermit>()
        );
        assert!(size_of::<FreshScopePermit>() + size_of::<RootSelector>() <= 96);
        assert!(size_of::<LinearRootFailure<FreshScopePermit>>() <= 120);
        assert!(size_of::<LinearRootFailure<ClosureAckPermit>>() <= 120);
        assert!(size_of::<LinearRootFailure<ClearancePermit>>() <= 120);
        assert!(size_of::<LinearRootFailure<CompactLanePermit>>() <= 120);
        assert_eq!(
            size_of::<RootLaneTable<4>>(),
            2 * size_of::<u64>()
                + 4 * size_of::<Option<RootLane>>()
                + 4 * size_of::<Option<PendingReservation>>()
        );

        let mut table = RootLaneTable::<1>::new(REGISTRY).unwrap();
        let permit = fresh(&mut table, 1);
        table.allocate(permit).unwrap();
        let before = table.full_snapshot();
        let Some(RootLane::Full { template, .. }) = before.lanes[0] else {
            panic!("full contract missing from test snapshot");
        };
        assert_eq!(template, super::tests::template(1));
    }
}
