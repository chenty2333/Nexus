// SPDX-License-Identifier: MPL-2.0

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
#[cfg(feature = "test-support")]
use core::convert::Infallible;

use sha2::{Digest as _, Sha256};

use crate::authenticated_map::AuthenticatedMap;
use crate::persistent_map::{StateMap, StateSet};
use crate::{
    ArtifactBinding, ArtifactLeaseState, ArtifactPinChallenge, ArtifactPinVerifier,
    ArtifactReceiptBindings, ArtifactReleaseChallenge, ArtifactReleasePermit,
    ArtifactReleaseVerifier, BootGeneration, CatalogSet, ChargeAccountId, ClaimId, ClaimKindId,
    ClaimScopePolicy, ComponentId, CompositeKindId, ConflictMode, CreditClassId, DeviceGeneration,
    DeviceGenerationEffect, DeviceScopeId, Digest, DomainCatalog, DomainId, EffectId,
    EvidenceKindId, ExecutorCoordinate, Freshness, FreshnessAxes, JournalCheckpoint,
    JournalCheckpointDecodeError, JournalDecodeError, JournalGeneration, JournalRecord,
    JournalRepair, MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES, ObligationKindId, ObligationPolicy,
    OperationId, ProviderCoordinate, ProviderGeneration, ProviderId, ReceiptSchemaId,
    RecoveryBinding, RegistryInstance, ResourceGeneration, ResourceId, SnapshotId, VerifierBinding,
    VerifierGeneration, VerifierId, WorldId, scan_journal, scan_journal_to_head,
    validate_verifier_set,
};

/// Forces recognized predecessor journals through typed schema rejection even
/// when the trusted anchor names genesis. Other unanchored bytes remain repairable
/// failed-write residue rather than authoritative journal state.
pub(crate) fn reject_recognized_legacy_journal_prefix(
    bytes: &[u8],
) -> Result<(), JournalDecodeError> {
    if bytes.starts_with(b"CSERJR9\0")
        || bytes.starts_with(b"CSERJR8\0")
        || bytes.starts_with(b"CSERJR6\0")
        || bytes.starts_with(b"CSERJR7\0")
        || bytes.starts_with(b"CSERJR5\0")
        || bytes.starts_with(b"CSERJR4\0")
    {
        scan_journal(bytes)?;
    }
    Ok(())
}

/// Exact runtime scope of one resource claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClaimScope {
    /// Logical resource with no independently reset device.
    Logical,
    /// Resource belonging to one exact reset/quarantine domain.
    Device(DeviceScopeId),
}

/// Canonical, version-one description of the only child admitted by the
/// bounded handoff guard.  It is data, not authority: live installation
/// requires a [`VerifiedChildDescriptor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildDescriptorV1 {
    /// Fixed descriptor grammar version.
    pub schema: u16,
    /// Fixed child sequence below the parent's operation.
    pub sequence: u64,
    /// The retired source composite.
    pub parent: EffectId,
    /// The successful source component.
    pub parent_component: ComponentId,
    /// Canonical route coordinate.
    pub route_digest: Digest,
    /// Catalog-defined one-component child product.
    pub child_kind: CompositeKindId,
    /// The sole child component.
    pub child_component: ComponentId,
    /// Exact child claim identity and class.
    pub claim: ClaimId,
    /// Catalog-defined class of the child claim.
    pub claim_kind: ClaimKindId,
    /// Exact logical or device scope of the child claim.
    pub scope: ClaimScope,
    /// Exact resource retained by the child claim.
    pub resource: ResourceId,
    /// Exact allocation generation retained by the child claim.
    pub resource_generation: ResourceGeneration,
    /// Conserved units retained by the child claim.
    pub units: u64,
    /// Digest of the verified handoff input.
    pub input_digest: Digest,
    /// Exact catalog under which the descriptor was verified.
    pub catalog_digest: Digest,
}

/// Exact fixed width of a version-one child descriptor wire record.
///
/// The eight-byte magic is part of the canonical preimage.  Keeping the
/// logical scope's zero device field on wire makes the grammar fixed-width and
/// prevents a device descriptor from being reinterpreted as a logical one by
/// a permissive decoder.
pub const CHILD_DESCRIPTOR_V1_WIRE_LEN: usize = 187;
const CHILD_DESCRIPTOR_V1_MAGIC: &[u8; 8] = b"NXSCHD03";

/// Hard codec ceiling for every variable-length command vector.  This is a
/// wire-level bound shared by live command admission and journal decoding;
/// semantic catalog and [`CoreLimits`] checks may impose a smaller bound.
pub const MAX_COMMAND_VECTOR_ITEMS: usize = 4096;
/// Hard payload ceiling used when constructing and decoding journal commands.
/// Whole-state checkpoint images remain independently bounded by
/// [`MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES`].
pub const MAX_COMMAND_PAYLOAD_BYTES: usize = MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES + 256;

/// A malformed or non-canonical child descriptor wire record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildDescriptorDecodeError {
    /// The record has the wrong length, magic, identity, scope encoding, or
    /// fixed grammar version.
    InvalidEncoding,
}

impl ChildDescriptorV1 {
    /// Returns the unique fixed-width canonical representation used at every
    /// adapter boundary and as the descriptor hash preimage.
    pub fn encode_wire(self) -> [u8; CHILD_DESCRIPTOR_V1_WIRE_LEN] {
        let mut bytes = [0; CHILD_DESCRIPTOR_V1_WIRE_LEN];
        bytes[..8].copy_from_slice(CHILD_DESCRIPTOR_V1_MAGIC);
        let mut at = 8;
        child_wire_put_u16(&mut bytes, &mut at, self.schema);
        child_wire_put_u64(&mut bytes, &mut at, self.sequence);
        child_wire_put_u64(&mut bytes, &mut at, self.parent.operation().get());
        child_wire_put_u64(&mut bytes, &mut at, self.parent.sequence());
        child_wire_put_u32(&mut bytes, &mut at, self.parent_component.get());
        child_wire_put_digest(&mut bytes, &mut at, self.route_digest);
        child_wire_put_u32(&mut bytes, &mut at, self.child_kind.get());
        child_wire_put_u32(&mut bytes, &mut at, self.child_component.get());
        child_wire_put_u64(&mut bytes, &mut at, self.claim.get());
        child_wire_put_u32(&mut bytes, &mut at, self.claim_kind.get());
        match self.scope {
            ClaimScope::Logical => {
                child_wire_put_u8(&mut bytes, &mut at, 0);
                child_wire_put_u64(&mut bytes, &mut at, 0);
            }
            ClaimScope::Device(scope) => {
                child_wire_put_u8(&mut bytes, &mut at, 1);
                child_wire_put_u64(&mut bytes, &mut at, scope.get());
            }
        }
        child_wire_put_u64(&mut bytes, &mut at, self.resource.get());
        child_wire_put_u64(&mut bytes, &mut at, self.resource_generation.get());
        child_wire_put_u64(&mut bytes, &mut at, self.units);
        child_wire_put_digest(&mut bytes, &mut at, self.input_digest);
        child_wire_put_digest(&mut bytes, &mut at, self.catalog_digest);
        debug_assert_eq!(at, CHILD_DESCRIPTOR_V1_WIRE_LEN);
        bytes
    }

    /// Strictly decodes the canonical fixed-width child descriptor grammar.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, ChildDescriptorDecodeError> {
        if bytes.len() != CHILD_DESCRIPTOR_V1_WIRE_LEN || bytes[..8] != *CHILD_DESCRIPTOR_V1_MAGIC {
            return Err(ChildDescriptorDecodeError::InvalidEncoding);
        }
        let mut at = 8;
        let schema = child_wire_u16(bytes, &mut at)?;
        if schema != 1 {
            return Err(ChildDescriptorDecodeError::InvalidEncoding);
        }
        let sequence = child_wire_u64(bytes, &mut at)?;
        let parent = EffectId::new(
            OperationId::new(child_wire_u64(bytes, &mut at)?)
                .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?,
            child_wire_u64(bytes, &mut at)?,
        )
        .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let parent_component = ComponentId::new(child_wire_u32(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let route_digest = child_wire_digest(bytes, &mut at)?;
        let child_kind = CompositeKindId::new(child_wire_u32(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let child_component = ComponentId::new(child_wire_u32(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let claim = ClaimId::new(child_wire_u64(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let claim_kind = ClaimKindId::new(child_wire_u32(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let scope_tag = child_wire_u8(bytes, &mut at)?;
        let scope_id = child_wire_u64(bytes, &mut at)?;
        let scope = match (scope_tag, scope_id) {
            (0, 0) => ClaimScope::Logical,
            (1, id) => ClaimScope::Device(
                DeviceScopeId::new(id).map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?,
            ),
            _ => return Err(ChildDescriptorDecodeError::InvalidEncoding),
        };
        let resource = ResourceId::new(child_wire_u64(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let resource_generation = ResourceGeneration::new(child_wire_u64(bytes, &mut at)?)
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
        let units = child_wire_u64(bytes, &mut at)?;
        let input_digest = child_wire_digest(bytes, &mut at)?;
        let catalog_digest = child_wire_digest(bytes, &mut at)?;
        if at != bytes.len() {
            return Err(ChildDescriptorDecodeError::InvalidEncoding);
        }
        Ok(Self {
            schema,
            sequence,
            parent,
            parent_component,
            route_digest,
            child_kind,
            child_component,
            claim,
            claim_kind,
            scope,
            resource,
            resource_generation,
            units,
            input_digest,
            catalog_digest,
        })
    }

    /// The deterministic child identity.  Callers must treat a collision as a
    /// fail-closed handoff rejection rather than selecting another sequence.
    pub fn child_effect(self) -> Result<EffectId, CoreError> {
        if self.schema != 1 || self.sequence != 1 {
            return Err(CoreError::InvalidPayload);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"CSER3-single-hop-child-effect-v1");
        hasher.update(handoff_descriptor_digest(self).bytes());
        let bytes: [u8; 32] = hasher.finalize().into();
        let mut sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        if sequence == 0 {
            sequence = 1;
        }
        EffectId::new(self.parent.operation(), sequence).map_err(|_| CoreError::InvalidPayload)
    }
}

/// Opaque verifier-minted authority to use a child descriptor at handoff
/// ingress.  There is intentionally no `CommandRequest` equivalent.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedChildDescriptor {
    descriptor: ChildDescriptorV1,
    receipt_digest: Digest,
}

/// Trust boundary for a platform verifier of canonical child descriptors.
pub trait ChildDescriptorVerifier {
    /// Opaque receipt supplied by the platform verifier.
    type Receipt;
    /// Validates the descriptor and returns the digest of its canonical receipt.
    fn verify_child_descriptor(
        &self,
        descriptor: ChildDescriptorV1,
        receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError>;
}

/// Read-only recovery challenge for resolving a fenced, indeterminate handoff
/// parent without reconstructing its spent commit nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffResolutionChallenge {
    effect: EffectId,
    component: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
    operation: Digest,
    descriptor: ChildDescriptorV1,
    current_observation: Freshness,
    expected_verifier: VerifierId,
    expected_receipt_schema: ReceiptSchemaId,
    verification_scope: ProviderVerificationScope,
}

impl HandoffResolutionChallenge {
    /// Returns the fenced parent effect.
    pub const fn effect(self) -> EffectId {
        self.effect
    }
    /// Returns the sole parent component being resolved.
    pub const fn component(self) -> ComponentId {
        self.component
    }
    /// Returns the parent component domain.
    pub const fn domain(self) -> DomainId {
        self.domain
    }
    /// Returns the parent component obligation class.
    pub const fn obligation(self) -> ObligationKindId {
        self.obligation
    }
    /// Returns the durable operation whose outcome was indeterminate.
    pub const fn operation(self) -> Digest {
        self.operation
    }
    /// Returns the independently verified descriptor bound to this resolution.
    pub const fn descriptor(self) -> ChildDescriptorV1 {
        self.descriptor
    }
    /// Returns the current recovery freshness context.
    pub const fn current_observation(self) -> Freshness {
        self.current_observation
    }
    /// Returns the configured recovery verifier identity.
    pub const fn expected_verifier(self) -> VerifierId {
        self.expected_verifier
    }
    /// Returns the configured canonical recovery receipt schema.
    pub const fn expected_receipt_schema(self) -> ReceiptSchemaId {
        self.expected_receipt_schema
    }

    /// Returns the exact world/provider/catalog/verifier scope for this
    /// challenge.
    pub const fn verification_scope(self) -> ProviderVerificationScope {
        self.verification_scope
    }

    /// Returns the verifier binding derived from the mandatory exact scope.
    pub const fn expected_verifier_binding(self) -> VerifierBinding {
        self.verification_scope.verifier_binding()
    }
}

/// Role of a durable handoff recovery fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffRecoveryRole {
    /// Fact resolves the fenced source/parent operation.
    Parent,
    /// Fact resolves the fenced installed target/child operation.
    Child,
}

/// Exact verifier-bound recovery fact for one handoff role.
///
/// The fact is durable evidence, not a fresh execution capability. Its
/// coordinates bind the role, effect, component, external operation,
/// descriptor, freshness, verifier provenance, and provider scope together so
/// replay cannot move evidence across handoff roles or provider generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedHandoffRecoveryFact {
    role: HandoffRecoveryRole,
    effect: EffectId,
    component: ComponentId,
    operation: Digest,
    descriptor_digest: Digest,
    freshness: Freshness,
    stamp: VerifierStamp,
    verification_scope: ProviderVerificationScope,
}

impl VerifiedHandoffRecoveryFact {
    fn from_challenge(
        role: HandoffRecoveryRole,
        challenge: HandoffResolutionChallenge,
        stamp: VerifierStamp,
    ) -> Self {
        Self {
            role,
            effect: challenge.effect(),
            component: challenge.component(),
            operation: challenge.operation(),
            descriptor_digest: handoff_descriptor_digest(challenge.descriptor()),
            freshness: challenge.current_observation(),
            stamp,
            verification_scope: challenge.verification_scope(),
        }
    }

    /// Returns the handoff role authenticated by this fact.
    pub const fn role(self) -> HandoffRecoveryRole {
        self.role
    }

    /// Returns the exact effect authenticated by this fact.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the exact component authenticated by this fact.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns the exact external operation digest authenticated by this fact.
    pub const fn operation(self) -> Digest {
        self.operation
    }

    /// Returns the canonical handoff descriptor digest authenticated by this
    /// fact.
    pub const fn descriptor_digest(self) -> Digest {
        self.descriptor_digest
    }

    /// Returns the exact freshness at which the fact was verified.
    pub const fn freshness(self) -> Freshness {
        self.freshness
    }

    /// Returns complete verifier identity and receipt provenance.
    pub const fn stamp(self) -> VerifierStamp {
        self.stamp
    }

    /// Returns the exact provider/world/catalog scope authenticated by this
    /// fact.
    pub const fn verification_scope(self) -> ProviderVerificationScope {
        self.verification_scope
    }
}

/// Dedicated trust boundary for proving terminal handoff-parent success after
/// crash recovery. This is intentionally distinct from [`EffectReceiptVerifier`]
/// and never receives or reconstructs a commit nonce.
pub trait HandoffResolutionVerifier {
    /// Platform-specific recovery receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Proves that the challenged operation terminally succeeded and is bound
    /// to the exact opaque child descriptor in the challenge.
    fn verify_handoff_parent_success(
        &self,
        challenge: &HandoffResolutionChallenge,
        receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError>;
}

/// Dedicated trust boundary for proving terminal handoff-child success after
/// crash recovery, without reconstructing the child's consumed commit nonce.
pub trait HandoffChildResolutionVerifier {
    /// Platform-specific recovery receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Proves the challenged installed child terminally succeeded and remains
    /// bound to the exact descriptor which created it.
    fn verify_handoff_child_success(
        &self,
        challenge: &HandoffResolutionChallenge,
        receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError>;
}

/// Opaque proof minted only by [`HandoffResolutionVerifier`] for the dedicated
/// fenced-parent recovery transition.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedHandoffResolution {
    descriptor: VerifiedChildDescriptor,
    fact: VerifiedHandoffRecoveryFact,
}

impl VerifiedHandoffResolution {
    /// Consumes this proof into the only recovery handoff-parent command.
    pub fn resolve(self) -> Command {
        Command(CommandKind::ResolveIndeterminateHandoffParent {
            descriptor: self.descriptor.descriptor,
            descriptor_receipt_digest: self.descriptor.receipt_digest,
            fact: self.fact,
        })
    }
}

/// Opaque proof for resolving only an installed, fenced handoff child.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedHandoffChildResolution {
    descriptor: VerifiedChildDescriptor,
    fact: VerifiedHandoffRecoveryFact,
}

impl VerifiedHandoffChildResolution {
    /// Consumes this proof into the nonce-free handoff recovery command.
    pub fn resolve(self) -> Command {
        Command(CommandKind::ResolveIndeterminateHandoffParent {
            descriptor: self.descriptor.descriptor,
            descriptor_receipt_digest: self.descriptor.receipt_digest,
            fact: self.fact,
        })
    }
}

/// Authority state of one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityState {
    /// The exact current executor may still act.
    Active,
    /// The originating or successor executor has been fenced.
    Fenced,
    /// Revocation won the action gate.
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Durable custody of an effect obligation.
pub enum CustodyState {
    /// The exact executor coordinate currently holds the obligation.
    Executor(ExecutorCoordinate),
    /// The non-authorizing core retains the obligation post mortem.
    CoreOwned,
    /// The effect has settled and released every physical claim.
    Released,
}

/// Aggregate escape and discharge state of one composite effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectEscapeState {
    /// No component crossed an irreversible external commit point.
    Unescaped,
    /// At least one component escaped and no component has discharged yet.
    Escaped,
    /// At least one claim or component discharged while other work remains.
    PartiallyDischarged,
    /// Every component obligation and resource claim is terminal.
    Retired,
    /// The terminal composite record was explicitly released.
    Released,
}

/// Core-owned projection of the current custodian for one component claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimCustodian {
    /// A logical claim is retained by the non-authorizing core.
    CoreOwned,
    /// A physical claim is retained by the provider for one exact device scope.
    DeviceProvider(DeviceScopeId),
    /// Typed retirement evidence released the old resource generation.
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

/// Physical retirement state of an effect's claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementState {
    /// Claims exist but the effect has not crossed its commit boundary.
    Held,
    /// One or more claims await typed retirement evidence.
    RetirementPending,
    /// Every claim has been retired but the effect record remains.
    Retired,
    /// The terminal effect was explicitly released.
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
        /// Exact claimant executor.
        claimant: ExecutorCoordinate,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// Publication or reconciliation intent is durable before external apply.
    ApplyIntentDurable {
        /// Exact claimant executor.
        claimant: ExecutorCoordinate,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// External apply happened but acknowledgement is not durably settled.
    AppliedUnacknowledged {
        /// Exact claimant executor.
        claimant: ExecutorCoordinate,
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

/// Recovery lane state for one causal operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationRecoveryState {
    /// The operation is authorized for the exact live executor coordinate.
    Active {
        /// Exact live executor.
        executor: ExecutorCoordinate,
    },
    /// The prior executor coordinate has been durably fenced.
    Fenced {
        /// Last fenced executor.
        crashed: ExecutorCoordinate,
        /// Number of observed crashes for this operation.
        crash_generation: u64,
    },
    /// A stable non-authorizing recovery snapshot exists.
    Snapshotted {
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Snapshot contents digest.
        digest: Digest,
    },
    /// A fresh executor declared itself ready for the exact snapshot.
    Ready {
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Ready successor executor.
        successor: ExecutorCoordinate,
    },
    /// The fresh executor is rebound but owns no old obligation implicitly.
    Rebound {
        /// Rebound successor executor.
        successor: ExecutorCoordinate,
    },
    /// Crash fencing succeeded, but automatic recovery may not mint authority.
    ///
    /// Reaching this state is fail-closed: the dead executor and every
    /// composite effect are fenced, while snapshot/ready/rebind/adoption require an
    /// explicit operator recovery mechanism outside the automatic lane.
    RecoveryExhausted {
        /// Last executor whose authority was fenced.
        crashed: ExecutorCoordinate,
        /// Saturating number of observed crashes for this operation.
        crash_generation: u64,
    },
}

/// Durable history bounds for one core instance.
///
/// These collections intentionally retain tombstones and immutable release
/// provenance rather than silently garbage-collecting authority history.  A
/// deployment that needs a different churn budget supplies this policy when
/// constructing [`CoreLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryLimits {
    /// Maximum provider-generation records, including retired generations.
    pub provider_generations: usize,
    /// Maximum provider identities with a retained generation high-water mark.
    pub providers: usize,
    /// Maximum artifact leases, including released leases.
    pub artifact_leases: usize,
    /// Maximum device-scope generations, including historical scopes.
    pub device_generations: usize,
    /// Maximum catalog-defined components in one composite effect.
    pub components_per_effect: usize,
}

const fn min_usize(left: usize, right: usize) -> usize {
    if left < right { left } else { right }
}

const fn max_usize(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

impl HistoryLimits {
    /// Creates a non-zero durable history policy.
    pub const fn new(
        provider_generations: usize,
        providers: usize,
        artifact_leases: usize,
        device_generations: usize,
        components_per_effect: usize,
    ) -> Result<Self, CoreError> {
        Self {
            provider_generations,
            providers,
            artifact_leases,
            device_generations,
            components_per_effect,
        }
        .validate()
    }

    const fn validate(self) -> Result<Self, CoreError> {
        let Self {
            provider_generations,
            providers,
            artifact_leases,
            device_generations,
            components_per_effect,
        } = self;
        if provider_generations == 0
            || providers == 0
            || artifact_leases == 0
            || device_generations == 0
            || components_per_effect == 0
            || provider_generations > u32::MAX as usize
            || providers > u32::MAX as usize
            || artifact_leases > u32::MAX as usize
            || device_generations > u32::MAX as usize
            || components_per_effect > u32::MAX as usize
            || components_per_effect > MAX_COMMAND_VECTOR_ITEMS
        {
            return Err(CoreError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Bounded capacity and pressure policy for one core instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreLimits {
    max_operations: usize,
    max_effects: usize,
    max_total_claims: usize,
    max_resource_records: usize,
    max_claims_per_effect: usize,
    max_units_per_account: u64,
    max_crashes_per_operation: u64,
    /// Maximum durable provider-generation records, including retired history.
    max_provider_generations: usize,
    /// Maximum durable provider high-water entries, including providers with
    /// no currently live generation.
    max_provider_high_water: usize,
    /// Maximum durable artifact leases, including released leases retained as
    /// immutable provenance history.
    max_artifact_leases: usize,
    /// Maximum durable device-scope generations, including quarantined or
    /// otherwise historical scopes.
    max_device_generations: usize,
    /// Maximum catalog-defined component records in one composite effect.
    max_components_per_effect: usize,
}

impl CoreLimits {
    /// Creates a non-zero bounded policy.
    pub const fn new(
        max_operations: usize,
        max_effects: usize,
        max_total_claims: usize,
        max_resource_records: usize,
        max_claims_per_effect: usize,
        max_units_per_account: u64,
        max_crashes_per_operation: u64,
    ) -> Result<Self, CoreError> {
        if max_operations == 0
            || max_effects == 0
            || max_total_claims == 0
            || max_resource_records == 0
            || max_claims_per_effect == 0
            || max_units_per_account == 0
            || max_crashes_per_operation == 0
            || max_operations > u32::MAX as usize
            || max_effects > u32::MAX as usize
            || max_total_claims > u32::MAX as usize
            || max_resource_records > u32::MAX as usize
            || max_claims_per_effect > u32::MAX as usize
        {
            return Err(CoreError::InvalidLimits);
        }
        let history = HistoryLimits {
            provider_generations: max_usize(
                min_usize(max_effects.saturating_mul(4), u32::MAX as usize),
                max_effects,
            ),
            providers: max_effects,
            artifact_leases: max_usize(max_total_claims, max_effects),
            device_generations: max_resource_records,
            // This is deliberately independent of the per-component claim
            // budget so adding component cardinality does not silently make
            // an existing seven-argument profile reject its catalog.
            components_per_effect: min_usize(
                max_usize(max_claims_per_effect, 32),
                MAX_COMMAND_VECTOR_ITEMS,
            ),
        };
        Ok(Self {
            max_operations,
            max_effects,
            max_total_claims,
            max_resource_records,
            max_claims_per_effect,
            max_units_per_account,
            max_crashes_per_operation,
            max_provider_generations: history.provider_generations,
            max_provider_high_water: history.providers,
            max_artifact_leases: history.artifact_leases,
            max_device_generations: history.device_generations,
            max_components_per_effect: history.components_per_effect,
        })
    }

    /// Replaces the durable history policy while preserving the ordinary
    /// operation, effect, claim, resource, charging, and crash limits.
    pub const fn with_durable_history_limits(
        mut self,
        history: HistoryLimits,
    ) -> Result<Self, CoreError> {
        let history = match history.validate() {
            Ok(history) => history,
            Err(error) => return Err(error),
        };
        self.max_provider_generations = history.provider_generations;
        self.max_provider_high_water = history.providers;
        self.max_artifact_leases = history.artifact_leases;
        self.max_device_generations = history.device_generations;
        self.max_components_per_effect = history.components_per_effect;
        Ok(self)
    }

    /// Returns a conservative test and single-service profile.
    pub const fn bounded_default() -> Self {
        Self {
            max_operations: 64,
            max_effects: 1024,
            max_total_claims: 4096,
            max_resource_records: 4096,
            max_claims_per_effect: 32,
            max_units_per_account: 1 << 20,
            max_crashes_per_operation: 1024,
            max_provider_generations: 4096,
            max_provider_high_water: 1024,
            max_artifact_leases: 4096,
            max_device_generations: 4096,
            max_components_per_effect: 32,
        }
    }

    /// Maximum durable provider-generation records, including retired history.
    pub const fn max_provider_generations(self) -> usize {
        self.max_provider_generations
    }

    /// Maximum durable provider high-water entries.
    pub const fn max_provider_high_water(self) -> usize {
        self.max_provider_high_water
    }

    /// Maximum durable artifact leases, including released history.
    pub const fn max_artifact_leases(self) -> usize {
        self.max_artifact_leases
    }

    /// Maximum durable device-scope generations, including historical scopes.
    pub const fn max_device_generations(self) -> usize {
        self.max_device_generations
    }

    /// Maximum component records in one composite effect.
    pub const fn max_components_per_effect(self) -> usize {
        self.max_components_per_effect
    }
}

/// Exact configured identity of a trusted receipt verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierIdentity {
    verifier: VerifierId,
    epoch: u64,
    receipt_schema: ReceiptSchemaId,
    implementation_digest: Digest,
}

impl VerifierIdentity {
    /// Creates an exact verifier identity bound to a provider-generation
    /// verifier cannot satisfy a challenge with only its class, epoch, and
    /// schema while silently changing implementation.
    pub const fn new_exact(binding: VerifierBinding) -> Self {
        Self {
            verifier: binding.verifier(),
            epoch: binding.generation().get(),
            receipt_schema: binding.receipt_schema(),
            implementation_digest: binding.implementation_digest(),
        }
    }

    /// Returns the verifier class.
    pub const fn verifier(self) -> VerifierId {
        self.verifier
    }

    /// Returns the exact verifier executor epoch.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the canonical receipt schema.
    pub const fn receipt_schema(self) -> ReceiptSchemaId {
        self.receipt_schema
    }

    /// Returns the exact implementation identity.
    pub const fn implementation_digest(self) -> Digest {
        self.implementation_digest
    }
}

/// Exact world/provider/operation/catalog scope derived from one scoped
/// composite and its provider-generation verifier record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderVerificationScope {
    world: WorldId,
    provider: ProviderCoordinate,
    operation: OperationId,
    catalog_digest: Digest,
    verifier_binding: VerifierBinding,
}

impl ProviderVerificationScope {
    pub(crate) const fn new(
        world: WorldId,
        provider: ProviderCoordinate,
        operation: OperationId,
        catalog_digest: Digest,
        verifier_binding: VerifierBinding,
    ) -> Self {
        Self {
            world,
            provider,
            operation,
            catalog_digest,
            verifier_binding,
        }
    }

    /// Returns the authoritative world which allocated this scope.
    pub const fn world(self) -> WorldId {
        self.world
    }

    /// Returns the exact provider generation bound to this scope.
    pub const fn provider(self) -> ProviderCoordinate {
        self.provider
    }

    /// Returns the operation which allocated the scoped composite.
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the catalog digest used to interpret the scoped composite.
    pub const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }

    /// Returns the verifier binding selected by the catalog.
    pub const fn verifier_binding(self) -> VerifierBinding {
        self.verifier_binding
    }
}

/// Read-only exact challenge passed to a configured domain verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceChallenge {
    effect: EffectId,
    component: ComponentId,
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
    expected_verifier_binding: VerifierBinding,
    verification_scope: ProviderVerificationScope,
}

impl EvidenceChallenge {
    /// Returns the exact effect.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the component slot for a composite-effect claim.
    pub const fn component(self) -> ComponentId {
        self.component
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

    /// Returns the expected verifier binding, when the challenge is typed.
    pub const fn expected_verifier_binding(self) -> VerifierBinding {
        self.expected_verifier_binding
    }

    /// Returns the exact world/provider/operation/catalog scope for this
    /// component challenge.
    pub const fn verification_scope(self) -> ProviderVerificationScope {
        self.verification_scope
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
    component: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
    actor: ExecutorCoordinate,
    generation: u64,
    nonce: u64,
    operation: Digest,
    predecessor: Option<Digest>,
    current_observation: Freshness,
    expected_verifier: VerifierId,
    expected_receipt_schema: ReceiptSchemaId,
    expected_verifier_binding: VerifierBinding,
    verification_scope: ProviderVerificationScope,
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

    /// Returns the component slot for a composite-effect fact.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns the domain schema.
    pub const fn domain(self) -> DomainId {
        self.domain
    }

    /// Returns the obligation class.
    pub const fn obligation(self) -> ObligationKindId {
        self.obligation
    }

    /// Returns the exact executor coordinate which authored the fact.
    pub const fn actor(self) -> ExecutorCoordinate {
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

    /// Returns the expected verifier binding, when the challenge is typed.
    pub const fn expected_verifier_binding(self) -> VerifierBinding {
        self.expected_verifier_binding
    }

    /// Returns the exact world/provider/operation/catalog scope for this
    /// component challenge.
    pub const fn verification_scope(self) -> ProviderVerificationScope {
        self.verification_scope
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
    component: ComponentId,
    actor: ExecutorCoordinate,
    generation: u64,
    nonce: u64,
    operation: Digest,
    predecessor: Option<Digest>,
    freshness: Freshness,
    stamp: VerifierStamp,
    verification_scope: ProviderVerificationScope,
    outcome: Option<ExternalOutcome>,
}

impl VerifiedEffectFact {
    pub(crate) const fn verification_scope(self) -> ProviderVerificationScope {
        self.verification_scope
    }
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

impl VerifiedCommitOutcome {
    /// Returns the exact scope retained by the verified commit token.
    pub const fn verification_scope(&self) -> ProviderVerificationScope {
        self.0.verification_scope()
    }
}

/// Non-forgeable proof that one exact settlement apply intent completed.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedApplyReceipt(VerifiedEffectFact);

impl VerifiedApplyReceipt {
    /// Returns the exact scope retained by the verified apply token.
    pub const fn verification_scope(&self) -> ProviderVerificationScope {
        self.0.verification_scope()
    }
}

/// Non-forgeable final acknowledgement for one exact settlement claim.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedSettlementAck(VerifiedEffectFact);

impl VerifiedSettlementAck {
    /// Returns the exact scope retained by the verified settlement token.
    pub const fn verification_scope(&self) -> ProviderVerificationScope {
        self.0.verification_scope()
    }
}

/// Non-forgeable proof that an exact recovery-artifact closure was pinned.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedArtifactPin {
    binding: ArtifactBinding,
    pin_stamp: Digest,
}

impl VerifiedArtifactPin {
    /// Returns the exact artifact tuple authenticated by the verifier.
    pub const fn binding(&self) -> ArtifactBinding {
        self.binding
    }

    /// Consumes this proof into the only artifact-pin command.
    pub fn record(self) -> Command {
        Command(CommandKind::RecordArtifactPin {
            binding: self.binding,
            pin_stamp: self.pin_stamp,
        })
    }
}

/// Non-forgeable proof that an exact authorized artifact release was observed.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedArtifactRelease {
    permit: ArtifactReleasePermit,
    release_stamp: Digest,
}

impl VerifiedArtifactRelease {
    /// Returns the exact release permit authenticated by the verifier.
    pub const fn permit(&self) -> &ArtifactReleasePermit {
        &self.permit
    }

    /// Consumes this proof into the only artifact-release command.
    pub fn confirm(self) -> Command {
        let permit = self.permit;
        Command(CommandKind::RecordArtifactRelease {
            binding: permit.binding(),
            pin_stamp: permit.pin_stamp(),
            release_operation: permit.release_operation(),
            nonce: permit.nonce(),
            release_stamp: self.release_stamp,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementEvidence {
    kind: EvidenceKindId,
    subject: Freshness,
    freshness: Freshness,
    stamp: VerifierStamp,
    verification_scope: ProviderVerificationScope,
}

/// Non-forgeable verified fact for one exact effect/claim pair.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedRetirementEvidence {
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    evidence: RetirementEvidence,
}

impl VerifiedRetirementEvidence {
    /// Returns the exact scope retained by the verified evidence token.
    pub const fn verification_scope(&self) -> ProviderVerificationScope {
        self.evidence.verification_scope
    }
}

impl VerifiedRetirementEvidence {
    /// Consumes this verified fact into the only live evidence-ingress command.
    pub fn submit(self) -> Command {
        Command(CommandKind::SubmitComponentEvidence {
            effect: self.effect,
            component: self.component,
            claim: self.claim,
            evidence: self.evidence,
        })
    }
}

impl VerifiedChildDescriptor {
    /// Returns the verified canonical descriptor without granting a raw command
    /// construction path.
    pub const fn descriptor(&self) -> ChildDescriptorV1 {
        self.descriptor
    }

    /// Consumes the verifier-minted descriptor into an atomic child install
    /// carrying the exact target provider generation.
    pub fn install(
        self,
        origin: ExecutorCoordinate,
        charge_account: ChargeAccountId,
        provider: ComponentProviderBinding,
    ) -> Command {
        Command(CommandKind::InstallHandoffChild {
            descriptor: self.descriptor,
            origin,
            charge_account,
            provider,
        })
    }

    /// Creates the sole atomic source-release/target-intent command.
    pub fn release_source_and_record_target_intent(
        self,
        actor: ExecutorCoordinate,
        operation: Digest,
    ) -> Command {
        Command(CommandKind::ReleaseHandoffSourceAndRecordTargetIntent {
            descriptor: self.descriptor,
            actor,
            operation,
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

/// Durable provider-generation effect-side lifecycle.
///
/// This is deliberately narrower than a provider's admission, execution, or
/// physical-unload fences.  CSER only records the point at which escaped
/// effects may no longer acquire new authority and the later settlement and
/// retirement phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEffectState {
    /// The generation admits new scoped effects.
    Active,
    /// No new effect authority may be acquired; existing effects may settle.
    EffectFenced {
        /// Monotonic provider effect-side epoch.
        epoch: u64,
    },
    /// Only settlement, evidence, and release operations remain legal.
    SettlementOnly {
        /// Monotonic provider effect-side epoch.
        epoch: u64,
    },
    /// All CSER-bound effects have retired for this generation.
    Retired {
        /// Monotonic provider effect-side epoch.
        epoch: u64,
    },
}

/// Recovery-artifact identity supplied at scoped admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactAdmission {
    artifact: crate::RecoveryArtifactId,
    schema_digest: Digest,
    closure_digest: Digest,
}

impl ArtifactAdmission {
    /// Creates one exact artifact lease request.
    pub const fn new(
        artifact: crate::RecoveryArtifactId,
        schema_digest: Digest,
        closure_digest: Digest,
    ) -> Self {
        Self {
            artifact,
            schema_digest,
            closure_digest,
        }
    }

    /// Returns the requested artifact lease identity.
    pub const fn artifact(self) -> crate::RecoveryArtifactId {
        self.artifact
    }

    /// Returns the artifact receipt schema digest.
    pub const fn schema_digest(self) -> Digest {
        self.schema_digest
    }

    /// Returns the retained artifact closure digest.
    pub const fn closure_digest(self) -> Digest {
        self.closure_digest
    }
}

/// A component slot bound to one exact provider generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentProviderBinding {
    component: ComponentId,
    provider: ProviderCoordinate,
    artifact: Option<ArtifactAdmission>,
}

impl ComponentProviderBinding {
    /// Binds a catalog component to an exact world/provider generation.
    pub const fn new(component: ComponentId, provider: ProviderCoordinate) -> Self {
        Self {
            component,
            provider,
            artifact: None,
        }
    }

    /// Binds an exact recovery-artifact lease request to this component.
    pub const fn with_artifact(self, artifact: ArtifactAdmission) -> Self {
        Self {
            artifact: Some(artifact),
            ..self
        }
    }

    /// Returns the catalog component slot.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns the exact provider coordinate.
    pub const fn provider(self) -> ProviderCoordinate {
        self.provider
    }

    /// Returns the optional recovery-artifact lease request.
    pub const fn artifact(self) -> Option<ArtifactAdmission> {
        self.artifact
    }
}

/// Public projection of one durable provider-generation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderGenerationProjection {
    /// Exact world/provider/generation coordinate.
    pub coordinate: ProviderCoordinate,
    /// Catalog digest used when the generation was registered.
    pub catalog_digest: Digest,
    /// Canonical digest computed by CSER from the exact verifier set.
    pub verifier_set_digest: Digest,
    /// Canonical exact verifier-generation bindings retained by this
    /// provider generation.
    pub verifier_bindings: Vec<VerifierBinding>,
    /// Optional exact artifact pin/release verifier pair.
    pub artifact_receipts: Option<ArtifactReceiptBindings>,
    /// Effect-side lifecycle state.
    pub state: ProviderEffectState,
    /// Number of live composite component bindings.
    pub live_component_bindings: usize,
}

impl Command {
    /// Returns stable normalized trace coordinates without granting authority.
    pub const fn coordinates(&self) -> TransitionCoordinates {
        self.0.coordinates()
    }
}

/// Replayable durable semantic command kind. This is never live ingress.
// Keeping verified facts inline avoids adding a heap allocation to every
// prepared transition. The enum is internal and never stored in a dense
// long-lived collection, so the larger stack value is the intentional trade.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommandKind {
    /// Registers one exact provider generation in this semantic world.
    RegisterProviderGeneration {
        coordinate: ProviderCoordinate,
        catalog_digest: Digest,
        verifier_bindings: Vec<VerifierBinding>,
    },
    /// Binds optional exact artifact pin/release verifier identities.
    BindArtifactReceiptVerifiers {
        /// Provider generation receiving the artifact verifier pair.
        coordinate: ProviderCoordinate,
        /// Exact pin and release verifier bindings.
        receipts: ArtifactReceiptBindings,
    },
    /// Fences new effect-side authority for one provider generation.
    FenceProviderEffects {
        coordinate: ProviderCoordinate,
        expected_epoch: u64,
    },
    /// Enters the settlement-only phase for one provider generation.
    EnterProviderSettlementOnly {
        coordinate: ProviderCoordinate,
        expected_epoch: u64,
    },
    /// Retires one provider generation after every bound component is released.
    RetireProviderEffects {
        coordinate: ProviderCoordinate,
        expected_epoch: u64,
    },
    /// Atomically aborts a scoped effect that never crossed its external
    /// commit boundary. This is the escape valve after an effect fence:
    /// pre-commit components must not permanently block provider retirement.
    AbortUnescapedEffect { effect: EffectId },
    /// Records a verifier-authenticated artifact pin.
    RecordArtifactPin {
        binding: ArtifactBinding,
        pin_stamp: Digest,
    },
    /// Authorizes artifact release after the component is terminal.
    AuthorizeArtifactRelease {
        effect: EffectId,
        component: ComponentId,
    },
    /// Records a verifier-authenticated artifact release confirmation.
    RecordArtifactRelease {
        binding: ArtifactBinding,
        pin_stamp: Digest,
        release_operation: OperationId,
        nonce: u64,
        release_stamp: Digest,
    },
    /// Atomically admits a composite effect with exact provider bindings.
    AdmitScopedCompositeEffect {
        effect: EffectId,
        origin: ExecutorCoordinate,
        kind: CompositeKindId,
        charge_account: ChargeAccountId,
        bindings: Vec<ComponentProviderBinding>,
    },
    /// Adds one claim to an exact catalog-defined component.
    AddComponentClaim {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Stable claim identity, unique within the parent effect.
        claim: ClaimId,
        /// Domain-defined claim class.
        kind: ClaimKindId,
        /// Exact logical or device scope.
        scope: ClaimScope,
        /// Exact protected resource.
        resource: ResourceId,
        /// Exact allocation generation.
        resource_generation: ResourceGeneration,
        /// Conserved resource units.
        units: u64,
    },
    /// Freezes claim enrollment for every component atomically.
    PrepareCompositeEffect {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
    },
    /// Records a component-local write-ahead external commit intent.
    RecordComponentCommitIntent {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component crossing its commit gate.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Digest of the external operation coordinates.
        operation: Digest,
    },
    /// Atomically records the complete component commit-intent cohort.
    RecordCompositeCommitIntents {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Complete catalog-ordered component operation set.
        operations: Vec<ComponentCommitOperation>,
    },
    /// Acknowledges the exact write-ahead commit intent.
    AcknowledgeCommit {
        /// Verifier-bound exact commit fact.
        fact: VerifiedEffectFact,
    },
    /// Fences one exact live executor and preserves committed composites.
    FenceExecutor {
        /// Causal operation being fenced.
        operation: OperationId,
        /// Exact crashed executor.
        crashed: ExecutorCoordinate,
    },
    /// Captures a stable, non-authorizing recovery snapshot.
    Snapshot {
        /// Causal operation being recovered.
        operation: OperationId,
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Digest of the complete snapshot projection.
        digest: Digest,
    },
    /// Marks a fresh executor ready for an exact snapshot.
    Ready {
        /// Causal operation being recovered.
        operation: OperationId,
        /// Exact snapshot identity.
        snapshot: SnapshotId,
        /// Fresh successor executor.
        successor: ExecutorCoordinate,
    },
    /// Binds a fresh executor coordinate to an exact recovery snapshot.
    Rebind {
        /// Causal operation being recovered.
        operation: OperationId,
        /// Exact snapshot identity.
        snapshot: SnapshotId,
        /// Fresh successor executor.
        successor: ExecutorCoordinate,
    },
    /// Explicitly transfers one uncommitted orphan into successor custody.
    AdoptEffect {
        /// Stable orphan effect identity.
        effect: EffectId,
        /// Exact rebound successor executor.
        successor: ExecutorCoordinate,
    },
    /// Refreshes wholly-precommit component claims after explicit adoption.
    RebaseCompositePrecommitClaims {
        /// Stable adopted composite effect identity.
        effect: EffectId,
        /// Exact active successor executor.
        actor: ExecutorCoordinate,
    },
    /// Claims one exact committed component obligation for settlement.
    ClaimComponentSettlement {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact successor-settled component.
        component: ComponentId,
        /// Exact rebound claimant.
        claimant: ExecutorCoordinate,
    },
    /// Records component-local settlement intent before external apply.
    RecordComponentApplyIntent {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component.
        component: ComponentId,
        /// Exact claimant executor.
        claimant: ExecutorCoordinate,
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
    /// Closes one component settlement authority with an indeterminate result.
    MarkComponentIndeterminate {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component.
        component: ComponentId,
        /// Exact claimant executor.
        claimant: ExecutorCoordinate,
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
        /// Exact live operation actor authorizing this revoke attempt.
        expected_actor: ExecutorCoordinate,
        /// Exact composite authority epoch observed before the race.
        authority_epoch: u64,
    },
    /// Submits typed evidence for one exact component-local resource claim.
    SubmitComponentEvidence {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component.
        component: ComponentId,
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
    /// Releases a fully terminal composite effect record.
    ReleaseCompositeEffect {
        /// Shared parent effect.
        effect: EffectId,
    },
    /// Reserves a retired resource generation for one exact component.
    ReserveComponentReuse {
        /// Shared parent effect.
        effect: EffectId,
        /// Component retaining the next generation.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Stable new claim identity.
        claim: ClaimId,
        /// Domain-defined claim class.
        kind: ClaimKindId,
        /// Exact logical or device scope.
        scope: ClaimScope,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact retired generation being advanced.
        expected_generation: ResourceGeneration,
        /// Conserved units retained before external reuse.
        units: u64,
        /// Provider-defined physical layout and drain contract digest.
        reuse_contract: Digest,
    },
    /// Consumes one exact durable reservation before external resource reuse.
    #[non_exhaustive]
    ActivateResourceReuse {
        /// Composite effect retaining the resource before external reuse.
        effect: EffectId,
        /// Composite component retaining the reservation.
        component: ComponentId,
        actor: ExecutorCoordinate,
        /// Exact composite authority epoch which received the bearer.
        authority_epoch: u64,
        /// Exact next-generation claim retained before reuse.
        claim: ClaimId,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact terminal generation from which reuse advances.
        previous_generation: ResourceGeneration,
        /// Exact reserved allocation generation.
        resource_generation: ResourceGeneration,
        /// Catalog digest defining the claim and evidence rules.
        catalog_digest: Digest,
        /// Digest of the retained old-generation retirement evidence.
        retirement_digest: Digest,
        /// Provider-defined physical layout and drain contract digest.
        reuse_contract: Digest,
        /// One-shot reservation nonce.
        nonce: u64,
        /// Freshness coordinates at reservation time.
        freshness: Freshness,
    },
    /// Reissues a pending reuse bearer only after explicit effect adoption.
    ReclaimResourceReuse {
        /// Adopted composite effect retaining the resource.
        effect: EffectId,
        /// Composite component retaining the reservation.
        component: ComponentId,
        /// Exact live successor executor.
        actor: ExecutorCoordinate,
        /// Exact adopted composite authority epoch.
        authority_epoch: u64,
        /// Exact pending next-generation claim.
        claim: ClaimId,
        /// Stable resource identity.
        resource: ResourceId,
        /// Exact pending allocation generation.
        resource_generation: ResourceGeneration,
    },
    /// Internal canonical primary-state checkpoint; no public ingress exists.
    WholeStateCheckpointV1 {
        /// Immutable canonical primary-state image shared by journal clones.
        state: Arc<[u8]>,
        projection: Digest,
    },
    /// Evidence-bound acknowledgement that opens the one permitted handoff.
    AcknowledgeHandoffParent {
        fact: VerifiedEffectFact,
        descriptor: ChildDescriptorV1,
        descriptor_receipt_digest: Digest,
    },
    /// Atomically creates, claims, and prepares the canonical child.
    InstallHandoffChild {
        descriptor: ChildDescriptorV1,
        origin: ExecutorCoordinate,
        charge_account: ChargeAccountId,
        provider: ComponentProviderBinding,
    },
    /// Atomically releases the terminal source and arms the sole target intent.
    ReleaseHandoffSourceAndRecordTargetIntent {
        descriptor: ChildDescriptorV1,
        actor: ExecutorCoordinate,
        operation: Digest,
    },
    /// Resolves a crash-fenced indeterminate source into a success-bound
    /// handoff source without recreating the consumed commit nonce.
    ResolveIndeterminateHandoffParent {
        descriptor: ChildDescriptorV1,
        descriptor_receipt_digest: Digest,
        fact: VerifiedHandoffRecoveryFact,
    },
}

impl CommandKind {
    /// Derives trace coordinates for commands whose role is determined by
    /// durable state. Tag 41 is shared by fenced-source and installed-target
    /// recovery, so a target resolution must be attributed to the child it
    /// changes rather than to the source descriptor's parent.
    fn coordinates_for_state(&self, state: &impl StateAccess) -> TransitionCoordinates {
        if let Self::ResolveIndeterminateHandoffParent {
            descriptor,
            descriptor_receipt_digest,
            fact,
            ..
        } = self
            && let Ok(child) = descriptor.child_effect()
            && handoff_child_resolution_eligible(
                state,
                *descriptor,
                *descriptor_receipt_digest,
                *fact,
            )
        {
            return TransitionCoordinates::new(
                Some(child.operation()),
                Some(child),
                Some(descriptor.child_component),
                None,
            );
        }
        self.coordinates()
    }

    const fn coordinates(&self) -> TransitionCoordinates {
        let (operation, effect, component, claim) = match self {
            Self::RegisterProviderGeneration { .. }
            | Self::BindArtifactReceiptVerifiers { .. }
            | Self::FenceProviderEffects { .. }
            | Self::EnterProviderSettlementOnly { .. }
            | Self::RetireProviderEffects { .. } => (None, None, None, None),
            Self::AbortUnescapedEffect { effect } => {
                (Some(effect.operation()), Some(*effect), None, None)
            }
            Self::AuthorizeArtifactRelease { effect, component } => (
                Some(effect.operation()),
                Some(*effect),
                Some(*component),
                None,
            ),
            Self::RecordArtifactPin { binding, .. }
            | Self::RecordArtifactRelease { binding, .. } => (
                Some(binding.effect().operation()),
                Some(binding.effect()),
                Some(binding.component()),
                None,
            ),
            Self::AdmitScopedCompositeEffect { effect, .. } => {
                (Some(effect.operation()), Some(*effect), None, None)
            }
            Self::PrepareCompositeEffect { effect, .. }
            | Self::RecordCompositeCommitIntents { effect, .. }
            | Self::AdoptEffect { effect, .. }
            | Self::RebaseCompositePrecommitClaims { effect, .. }
            | Self::BeginRevoke { effect, .. }
            | Self::ReleaseCompositeEffect { effect } => {
                (Some(effect.operation()), Some(*effect), None, None)
            }
            Self::AddComponentClaim {
                effect,
                component,
                claim,
                ..
            }
            | Self::SubmitComponentEvidence {
                effect,
                component,
                claim,
                ..
            }
            | Self::ReserveComponentReuse {
                effect,
                component,
                claim,
                ..
            } => (
                Some(effect.operation()),
                Some(*effect),
                Some(*component),
                Some(*claim),
            ),
            Self::RecordComponentCommitIntent {
                effect, component, ..
            }
            | Self::ClaimComponentSettlement {
                effect, component, ..
            }
            | Self::RecordComponentApplyIntent {
                effect, component, ..
            }
            | Self::MarkComponentIndeterminate {
                effect, component, ..
            } => (
                Some(effect.operation()),
                Some(*effect),
                Some(*component),
                None,
            ),
            Self::AcknowledgeCommit { fact }
            | Self::RecordApplied { fact }
            | Self::Settle { fact } => (
                Some(fact.effect.operation()),
                Some(fact.effect),
                Some(fact.component),
                None,
            ),
            Self::ActivateResourceReuse {
                effect,
                component,
                claim,
                ..
            }
            | Self::ReclaimResourceReuse {
                effect,
                component,
                claim,
                ..
            } => (
                Some(effect.operation()),
                Some(*effect),
                Some(*component),
                Some(*claim),
            ),
            Self::FenceExecutor { operation, .. }
            | Self::Snapshot { operation, .. }
            | Self::Ready { operation, .. }
            | Self::Rebind { operation, .. } => (Some(*operation), None, None, None),
            Self::CheckpointRecovery { .. } | Self::WholeStateCheckpointV1 { .. } => {
                (None, None, None, None)
            }
            Self::AcknowledgeHandoffParent { fact, .. } => (
                Some(fact.effect.operation()),
                Some(fact.effect),
                Some(fact.component),
                None,
            ),
            Self::InstallHandoffChild { descriptor, .. } => (
                Some(descriptor.parent.operation()),
                Some(descriptor.parent),
                None,
                Some(descriptor.claim),
            ),
            Self::ReleaseHandoffSourceAndRecordTargetIntent { descriptor, .. } => (
                Some(descriptor.parent.operation()),
                Some(descriptor.parent),
                Some(descriptor.parent_component),
                None,
            ),
            Self::ResolveIndeterminateHandoffParent { fact, .. } => (
                Some(fact.effect.operation()),
                Some(fact.effect),
                Some(fact.component),
                None,
            ),
        };
        TransitionCoordinates::new(operation, effect, component, claim)
    }
}

/// One component entry in an atomic composite commit-intent cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentCommitOperation {
    component: ComponentId,
    operation: Digest,
}

impl ComponentCommitOperation {
    /// Binds one component slot to its exact external operation coordinates.
    pub const fn new(component: ComponentId, operation: Digest) -> Self {
        Self {
            component,
            operation,
        }
    }

    /// Returns the catalog component slot.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns the exact external operation digest.
    pub const fn operation(self) -> Digest {
        self.operation
    }
}

/// Untrusted live request surface. Receipt-dependent transitions are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRequest {
    /// Registers one exact provider generation.
    RegisterProviderGeneration {
        /// World/provider/generation coordinate.
        coordinate: ProviderCoordinate,
        /// Exact catalog digest.
        catalog_digest: Digest,
        /// Exact verifier-generation bindings. CSER validates and hashes this
        /// set against the catalog; callers cannot supply a digest directly.
        verifier_bindings: Vec<VerifierBinding>,
    },
    /// Binds optional exact artifact pin/release verifier identities.
    BindArtifactReceiptVerifiers {
        /// Provider generation receiving the artifact verifier pair.
        coordinate: ProviderCoordinate,
        /// Exact pin and release verifier bindings.
        receipts: ArtifactReceiptBindings,
    },
    /// Fences effect admission for one provider generation.
    FenceProviderEffects {
        /// Provider coordinate.
        coordinate: ProviderCoordinate,
        /// Epoch observed by the caller.
        expected_epoch: u64,
    },
    /// Enters settlement-only mode for one provider generation.
    EnterProviderSettlementOnly {
        /// Provider coordinate.
        coordinate: ProviderCoordinate,
        /// Epoch observed by the caller.
        expected_epoch: u64,
    },
    /// Retires one provider generation after all bound effects release.
    RetireProviderEffects {
        /// Provider coordinate.
        coordinate: ProviderCoordinate,
        /// Epoch observed by the caller.
        expected_epoch: u64,
    },
    /// Aborts one scoped effect whose components are all still pre-commit.
    AbortUnescapedEffect {
        /// Stable scoped effect identity.
        effect: EffectId,
    },
    /// Requests release authorization for a terminal artifact lease.
    AuthorizeArtifactRelease {
        /// Composite effect owning the artifact lease.
        effect: EffectId,
        /// Required-artifact component slot.
        component: ComponentId,
    },
    /// Admits one operation with exact component provider bindings.
    AdmitScopedCompositeEffect {
        /// Stable escaped-effect identity.
        effect: EffectId,
        /// Exact originating executor.
        origin: ExecutorCoordinate,
        /// Catalog-defined component product.
        kind: CompositeKindId,
        /// Retained-resource charge account.
        charge_account: ChargeAccountId,
        /// Exact catalog component/provider bindings.
        bindings: Vec<ComponentProviderBinding>,
    },
    /// Enrolls one component-local resource claim before preparation.
    AddComponentClaim {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact catalog component slot.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Stable claim identity, unique within the effect.
        claim: ClaimId,
        /// Domain-defined claim class.
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
    /// Atomically freezes enrollment and prepares every component.
    PrepareCompositeEffect {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
    },
    /// Records a component-local write-ahead external commit intent.
    RecordComponentCommitIntent {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact component crossing its commit gate.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Exact external operation coordinates.
        operation: Digest,
    },
    /// Atomically arms every component before any external commit may occur.
    RecordCompositeCommitIntents {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Complete catalog-ordered component operation set.
        operations: Vec<ComponentCommitOperation>,
    },
    /// Requests an immediate fence of one exact executor.
    FenceExecutor {
        /// Causal operation.
        operation: OperationId,
        /// Exact crashed executor.
        crashed: ExecutorCoordinate,
    },
    /// Marks a successor ready for one exact snapshot.
    Ready {
        /// Causal operation.
        operation: OperationId,
        /// Exact snapshot.
        snapshot: SnapshotId,
        /// Fresh successor.
        successor: ExecutorCoordinate,
    },
    /// Binds a fresh executor coordinate to an exact recovery snapshot.
    Rebind {
        /// Causal operation.
        operation: OperationId,
        /// Exact snapshot.
        snapshot: SnapshotId,
        /// Fresh successor.
        successor: ExecutorCoordinate,
    },
    /// Requests explicit adoption of one uncommitted orphan.
    AdoptEffect {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact rebound successor.
        successor: ExecutorCoordinate,
    },
    /// Requests a freshness rebase for an adopted wholly-precommit composite.
    RebaseCompositePrecommitClaims {
        /// Stable adopted composite effect identity.
        effect: EffectId,
        /// Exact active successor.
        actor: ExecutorCoordinate,
    },
    /// Requests a one-shot claim for an exact committed component.
    ClaimComponentSettlement {
        /// Shared parent effect.
        effect: EffectId,
        /// Exact successor-settled component.
        component: ComponentId,
        /// Exact live claimant.
        claimant: ExecutorCoordinate,
    },
    /// Races revocation against adoption or settlement.
    BeginRevoke {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact observed live actor.
        expected_actor: ExecutorCoordinate,
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
    /// Releases a terminal composite effect.
    ReleaseCompositeEffect {
        /// Shared parent effect.
        effect: EffectId,
    },
    /// Reserves and retains a resource generation in one exact component.
    ReserveComponentReuse {
        /// Shared parent effect.
        effect: EffectId,
        /// Component retaining the new claim.
        component: ComponentId,
        /// Exact live actor.
        actor: ExecutorCoordinate,
        /// Stable new claim identity.
        claim: ClaimId,
        /// Domain-defined claim class.
        kind: ClaimKindId,
        /// Logical or device scope.
        scope: ClaimScope,
        /// Stable protected resource.
        resource: ResourceId,
        /// Exact retired allocation generation.
        expected_generation: ResourceGeneration,
        /// Conserved units.
        units: u64,
        /// Provider-defined physical layout and drain contract digest.
        reuse_contract: Digest,
    },
}

impl CommandRequest {}

impl From<CommandRequest> for Command {
    fn from(request: CommandRequest) -> Self {
        Self(match request {
            CommandRequest::RegisterProviderGeneration {
                coordinate,
                catalog_digest,
                verifier_bindings,
            } => CommandKind::RegisterProviderGeneration {
                coordinate,
                catalog_digest,
                verifier_bindings,
            },
            CommandRequest::BindArtifactReceiptVerifiers {
                coordinate,
                receipts,
            } => CommandKind::BindArtifactReceiptVerifiers {
                coordinate,
                receipts,
            },
            CommandRequest::FenceProviderEffects {
                coordinate,
                expected_epoch,
            } => CommandKind::FenceProviderEffects {
                coordinate,
                expected_epoch,
            },
            CommandRequest::EnterProviderSettlementOnly {
                coordinate,
                expected_epoch,
            } => CommandKind::EnterProviderSettlementOnly {
                coordinate,
                expected_epoch,
            },
            CommandRequest::RetireProviderEffects {
                coordinate,
                expected_epoch,
            } => CommandKind::RetireProviderEffects {
                coordinate,
                expected_epoch,
            },
            CommandRequest::AbortUnescapedEffect { effect } => {
                CommandKind::AbortUnescapedEffect { effect }
            }
            CommandRequest::AuthorizeArtifactRelease { effect, component } => {
                CommandKind::AuthorizeArtifactRelease { effect, component }
            }
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin,
                kind,
                charge_account,
                bindings,
            } => CommandKind::AdmitScopedCompositeEffect {
                effect,
                origin,
                kind,
                charge_account,
                bindings,
            },
            CommandRequest::AddComponentClaim {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            } => CommandKind::AddComponentClaim {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            },
            CommandRequest::PrepareCompositeEffect { effect, actor } => {
                CommandKind::PrepareCompositeEffect { effect, actor }
            }
            CommandRequest::RecordComponentCommitIntent {
                effect,
                component,
                actor,
                operation,
            } => CommandKind::RecordComponentCommitIntent {
                effect,
                component,
                actor,
                operation,
            },
            CommandRequest::RecordCompositeCommitIntents {
                effect,
                actor,
                operations,
            } => CommandKind::RecordCompositeCommitIntents {
                effect,
                actor,
                operations,
            },
            CommandRequest::FenceExecutor { operation, crashed } => {
                CommandKind::FenceExecutor { operation, crashed }
            }
            CommandRequest::Ready {
                operation,
                snapshot,
                successor,
            } => CommandKind::Ready {
                operation,
                snapshot,
                successor,
            },
            CommandRequest::Rebind {
                operation,
                snapshot,
                successor,
            } => CommandKind::Rebind {
                operation,
                snapshot,
                successor,
            },
            CommandRequest::AdoptEffect { effect, successor } => {
                CommandKind::AdoptEffect { effect, successor }
            }
            CommandRequest::RebaseCompositePrecommitClaims { effect, actor } => {
                CommandKind::RebaseCompositePrecommitClaims { effect, actor }
            }
            CommandRequest::ClaimComponentSettlement {
                effect,
                component,
                claimant,
            } => CommandKind::ClaimComponentSettlement {
                effect,
                component,
                claimant,
            },
            CommandRequest::BeginRevoke {
                effect,
                expected_actor,
                authority_epoch,
            } => CommandKind::BeginRevoke {
                effect,
                expected_actor,
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
            CommandRequest::ReleaseCompositeEffect { effect } => {
                CommandKind::ReleaseCompositeEffect { effect }
            }
            CommandRequest::ReserveComponentReuse {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                expected_generation,
                units,
                reuse_contract,
            } => CommandKind::ReserveComponentReuse {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                expected_generation,
                units,
                reuse_contract,
            },
        })
    }
}

/// Exact write-ahead external commit authority.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitIntent {
    effect: EffectId,
    component: ComponentId,
    nonce: u64,
}

impl CommitIntent {
    /// Returns the committed effect identity.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Returns the component slot for a composite-effect commit.
    pub const fn component(&self) -> ComponentId {
        self.component
    }

    /// Consumes the intent with a verifier-bound exact external outcome.
    pub fn acknowledge(self, outcome: VerifiedCommitOutcome) -> Result<Command, CommitUseError> {
        let fact = outcome.0;
        if fact.kind != EffectFactKind::CommitOutcome
            || fact.effect != self.effect
            || fact.component != self.component
            || fact.nonce != self.nonce
        {
            return Err(CommitUseError {
                error: CoreError::StaleCommitIntent,
                intent: self,
            });
        }
        Ok(Command(CommandKind::AcknowledgeCommit { fact }))
    }

    /// Consumes a successful parent-component outcome and an independently
    /// verified descriptor into the sole source-opening acknowledgement.
    pub fn acknowledge_handoff_parent_success(
        self,
        outcome: VerifiedCommitOutcome,
        descriptor: VerifiedChildDescriptor,
    ) -> Result<Command, CommitUseError> {
        let fact = outcome.0;
        if fact.kind != EffectFactKind::CommitOutcome
            || fact.effect != self.effect
            || fact.component != self.component
            || fact.nonce != self.nonce
            || fact.outcome != Some(ExternalOutcome::Success)
        {
            return Err(CommitUseError {
                error: CoreError::StaleCommitIntent,
                intent: self,
            });
        }
        let _receipt_digest = descriptor.receipt_digest;
        Ok(Command(CommandKind::AcknowledgeHandoffParent {
            fact,
            descriptor: descriptor.descriptor,
            descriptor_receipt_digest: descriptor.receipt_digest,
        }))
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
    component: ComponentId,
    claimant: ExecutorCoordinate,
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

    /// Returns the component slot for a composite-effect settlement claim.
    pub const fn component(&self) -> ComponentId {
        self.component
    }

    /// Returns the exact claimant.
    pub const fn claimant(&self) -> ExecutorCoordinate {
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
        Ok(Command(CommandKind::RecordComponentApplyIntent {
            effect: self.effect,
            component: self.component,
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
            || fact.component != self.component
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
            || fact.component != self.component
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
        Command(CommandKind::MarkComponentIndeterminate {
            effect: self.effect,
            component: self.component,
            claimant: self.claimant,
            generation: self.generation,
            nonce: self.nonce,
            reason,
        })
    }
}

/// Non-cloneable handle for one durably retained resource-generation reservation.
///
/// Moving this value prevents ordinary caller reuse, but is not the authority
/// boundary. Activation succeeds only while the engine retains a matching
/// [`PendingReuse`] record and every actor, epoch, claim, generation, digest,
/// contract, freshness, and nonce field matches that durable reservation.
#[derive(Debug, Eq, PartialEq)]
pub struct ReusePermit {
    effect: EffectId,
    component: ComponentId,
    actor: ExecutorCoordinate,
    authority_epoch: u64,
    claim: ClaimId,
    resource: ResourceId,
    previous_generation: ResourceGeneration,
    generation: ResourceGeneration,
    catalog_digest: Digest,
    retirement_digest: Digest,
    reuse_contract: Digest,
    freshness: Freshness,
    nonce: u64,
}

impl ReusePermit {
    /// Returns the reusable resource.
    pub const fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Returns the composite effect retaining the resource.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Returns the component which retains a composite-effect reuse reservation.
    pub const fn component(&self) -> ComponentId {
        self.component
    }

    /// Returns the exact next-generation claim retained by this permit.
    pub const fn claim(&self) -> ClaimId {
        self.claim
    }

    /// Returns the exact terminal generation from which reuse advances.
    pub const fn previous_generation(&self) -> ResourceGeneration {
        self.previous_generation
    }

    /// Returns the exact newly reserved allocation generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Returns the catalog digest defining the claim and evidence contract.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the digest of the retained old-generation retirement evidence.
    pub const fn retirement_digest(&self) -> Digest {
        self.retirement_digest
    }

    /// Returns the provider-defined physical layout and drain contract digest.
    pub const fn reuse_contract(&self) -> Digest {
        self.reuse_contract
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
            component: self.component,
            actor: self.actor,
            authority_epoch: self.authority_epoch,
            claim: self.claim,
            resource: self.resource,
            previous_generation: self.previous_generation,
            resource_generation: self.generation,
            catalog_digest: self.catalog_digest,
            retirement_digest: self.retirement_digest,
            reuse_contract: self.reuse_contract,
            nonce: self.nonce,
            freshness: self.freshness,
        })
    }
}

/// Stable parent/component/claim coordinates carried by normalized trace v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionCoordinates {
    operation: Option<OperationId>,
    effect: Option<EffectId>,
    component: Option<ComponentId>,
    claim: Option<ClaimId>,
}

impl TransitionCoordinates {
    /// Constructs one non-authorizing normalized coordinate tuple.
    pub const fn new(
        operation: Option<OperationId>,
        effect: Option<EffectId>,
        component: Option<ComponentId>,
        claim: Option<ClaimId>,
    ) -> Self {
        Self {
            operation,
            effect,
            component,
            claim,
        }
    }

    /// Returns the causal operation, when the command is operation scoped.
    pub const fn operation(self) -> Option<OperationId> {
        self.operation
    }

    /// Returns the parent effect, when the command is effect scoped.
    pub const fn effect(self) -> Option<EffectId> {
        self.effect
    }

    /// Returns the exact component, when the command is component scoped.
    pub const fn component(self) -> Option<ComponentId> {
        self.component
    }

    /// Returns the exact claim, when the command is claim scoped.
    pub const fn claim(self) -> Option<ClaimId> {
        self.claim
    }
}

/// Normalized outcome of a receipt-bearing transition attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionResult {
    /// The transition became durable and changed the authoritative revision.
    Applied,
}

/// Normalized semantic event emitted by a successful transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionEvent {
    /// A provider generation was registered.
    ProviderGenerationRegistered,
    /// New effect authority was fenced for a provider generation.
    ProviderEffectsFenced,
    /// A provider generation entered settlement-only mode.
    ProviderSettlementOnly,
    /// A provider generation was retired.
    ProviderEffectsRetired,
    /// Exact artifact pin/release verifiers were bound to a provider.
    ArtifactReceiptVerifiersBound,
    /// A scoped composite effect was admitted.
    ScopedCompositeAdmitted,
    /// A typed resource claim was enrolled.
    ClaimAdded,
    /// An effect was prepared.
    EffectPrepared,
    /// A write-ahead commit intent became durable.
    CommitIntentDurable,
    /// An external commit was acknowledged.
    EffectCommitted,
    /// A live executor was fenced.
    ExecutorFenced,
    /// A recovery snapshot was captured.
    Snapshot,
    /// A successor became ready.
    Ready,
    /// A successor was rebound to the recovery lane.
    Rebound,
    /// One exact uncommitted orphan was explicitly adopted.
    EffectAdopted,
    /// Adopted wholly-precommit claims were rebound to current freshness.
    CompositePrecommitClaimsRebased,
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
    /// A fully retired composite effect was released.
    CompositeEffectReleased,
    /// A recovery artifact was durably pinned.
    ArtifactPinned,
    /// Artifact release was durably authorized.
    ArtifactReleaseAuthorized,
    /// A recovery artifact was durably released.
    ArtifactReleased,
}

/// Linear authority returned by a successful transition.
#[derive(Debug, Eq, PartialEq)]
pub enum TransitionOutput {
    /// The transition returns no bearer authority.
    None,
    /// A write-ahead external commit intent.
    CommitIntent(CommitIntent),
    /// Complete linear bearer set returned by one atomic composite escape gate.
    CompositeCommitIntents(Vec<CommitIntent>),
    /// A one-shot settlement claim or its next durable stage.
    SettlementClaim(SettlementClaim),
    /// A durable, one-shot resource-generation reservation.
    ReusePermit(ReusePermit),
    /// A durable artifact release permit.
    ArtifactReleasePermit(ArtifactReleasePermit),
}

/// Receipt for one durably committed semantic transition.
#[derive(Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    core_api_profile: u16,
    journal_schema: u16,
    catalog_digest: Digest,
    projection_version: u16,
    trace_version: u16,
    revision: u64,
    head: Digest,
    projection: Digest,
    coordinates: TransitionCoordinates,
    result: TransitionResult,
    event: TransitionEvent,
    output: TransitionOutput,
}

impl TransitionReceipt {
    /// Returns the semantic API profile which executed the transition.
    pub const fn core_api_profile(&self) -> u16 {
        self.core_api_profile
    }

    /// Returns the durable command grammar bound to the transition.
    pub const fn journal_schema(&self) -> u16 {
        self.journal_schema
    }

    /// Returns the aggregate catalog-set digest protecting the transition.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the deterministic projection schema coordinate.
    pub const fn projection_version(&self) -> u16 {
        self.projection_version
    }

    /// Returns the normalized trace schema coordinate.
    pub const fn trace_version(&self) -> u16 {
        self.trace_version
    }

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

    /// Returns exact operation/effect/component/claim trace coordinates.
    pub const fn coordinates(&self) -> TransitionCoordinates {
        self.coordinates
    }

    /// Returns the committed result represented by this receipt.
    pub const fn result(&self) -> TransitionResult {
        self.result
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

/// Public, non-authorizing projection of one domain-defined resource claim.
///
/// This is the boot-recovery enumeration surface.  It contains enough exact
/// identity to challenge a platform verifier after replay, but no release,
/// reuse, adoption, or settlement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProjection {
    /// Effect which owns the claim.
    pub effect: EffectId,
    /// Stable claim identity within the effect.
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
    /// Conserved units charged to the effect.
    pub units: u64,
    /// Freshness under which the claim was enrolled.
    pub enrolled_freshness: Freshness,
    /// Whether every configured retirement requirement has been accepted.
    pub retired: bool,
}

/// Public projection of one composite effect sharing a single authority gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeEffectProjection {
    /// Stable escaped-effect identity shared by every component.
    pub effect: EffectId,
    /// Catalog-defined heterogeneous component product.
    pub kind: CompositeKindId,
    /// Exact immutable catalog digest used to interpret this effect.
    pub catalog_digest: Digest,
    /// Immutable originating executor.
    pub causal_owner: ExecutorCoordinate,
    /// Current custody of the composite obligation.
    pub custodian: CustodyState,
    /// Account charged for every retained component claim.
    pub charge_owner: ChargeAccountId,
    /// Stable operation identity shared by every component.
    pub operation: OperationId,
    /// Exact component/provider bindings fixed at scoped admission.
    pub provider_bindings: Vec<ComponentProviderBinding>,
    /// Shared authority gate for all components.
    pub authority: AuthorityState,
    /// Monotonic epoch of the shared authority gate.
    pub authority_epoch: u64,
    /// Aggregate escape/partial-discharge lifecycle.
    pub escape: EffectEscapeState,
    /// Exact number of catalog-bound components.
    pub component_count: usize,
    /// Claims still retaining an old resource generation.
    pub retained_claims: usize,
    /// Durable, non-authorizing state of the only catalog-defined handoff
    /// relation involving this composite.
    pub handoff: SingleHopHandoffProjection,
}

/// Public recovery-only view of a bounded single-hop handoff.
///
/// The descriptor is deliberately visible after replay so a successor can ask
/// its platform verifier to re-establish the same evidence.  This value is not
/// a [`VerifiedChildDescriptor`] and cannot install or release anything by
/// itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingleHopHandoffProjection {
    /// No handoff state is attached to this composite.
    None,
    /// A successful source has durably bound its exact descriptor and terminal
    /// receipt; `child_installed` says whether the child was atomically
    /// enrolled and prepared before a crash.
    Source {
        /// Exact child descriptor that must be independently re-verified.
        descriptor: Box<ChildDescriptorV1>,
        /// Receipt proving the parent component's successful terminal outcome.
        terminal_receipt_digest: Digest,
        /// Receipt authenticating the descriptor presented to the child.
        descriptor_receipt_digest: Digest,
        /// Optional exact recovery fact accepted for the parent role.
        recovery_fact: Option<VerifiedHandoffRecoveryFact>,
        /// Whether the exact target was durably created, claimed, and prepared.
        child_installed: bool,
    },
    /// A prepared child is bound to the exact parent and descriptor digest.
    Target {
        /// Exact source composite that authorized this child.
        parent: EffectId,
        /// Canonical digest of the source-bound descriptor.
        descriptor_digest: Digest,
        /// Optional exact recovery fact accepted for the child role.
        recovery_fact: Option<VerifiedHandoffRecoveryFact>,
    },
}

/// Public projection of one obligation component in a composite effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentProjection {
    /// Shared parent effect identity.
    pub effect: EffectId,
    /// Stable component slot within the catalog product.
    pub component: ComponentId,
    /// Domain-defined obligation class.
    pub obligation: (DomainId, ObligationKindId),
    /// Domain-selected lifecycle.
    pub obligation_policy: ObligationPolicy,
    /// Component-local external commit state.
    pub commit: CommitState,
    /// Exact durable external operation identity, once a commit intent exists.
    pub commit_operation: Option<Digest>,
    /// Component-local outcome knowledge.
    pub outcome: OutcomeState,
    /// Component-local successor settlement state.
    pub settlement: SettlementState,
    /// Component-local physical retirement state.
    pub retirement: RetirementState,
    /// Total claims belonging to this component.
    pub claim_count: usize,
    /// Claims which still retain resources.
    pub retained_claims: usize,
}

/// Public projection of one component-local resource claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentClaimProjection {
    /// Shared parent effect identity.
    pub effect: EffectId,
    /// Component which defines this claim.
    pub component: ComponentId,
    /// Stable claim identity within the parent effect.
    pub claim: ClaimId,
    /// Domain which defines the claim lifecycle.
    pub domain: DomainId,
    /// Domain-defined claim class.
    pub kind: ClaimKindId,
    /// Conserved credit class charged while retained.
    pub credit_class: CreditClassId,
    /// Logical or exact device scope.
    pub scope: ClaimScope,
    /// Core-derived current claim custodian.
    pub custodian: ClaimCustodian,
    /// Stable protected resource identity.
    pub resource: ResourceId,
    /// Exact protected allocation generation.
    pub resource_generation: ResourceGeneration,
    /// Conserved units.
    pub units: u64,
    /// Enrollment freshness.
    pub enrolled_freshness: Freshness,
    /// Whether every typed retirement requirement has been accepted.
    pub retired: bool,
}

/// One effect in a core-generated recovery cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderObligation {
    /// Exact provider generation carrying this obligation.
    pub provider: ProviderCoordinate,
    /// Scoped operation which caused the obligation.
    pub operation: OperationId,
    /// Catalog digest used to interpret the operation.
    pub catalog_digest: Digest,
    /// Parent effect retaining the obligation.
    pub effect: EffectId,
    /// Component slot retaining the obligation.
    pub component: ComponentId,
    /// Optional recovery-artifact closure retained for this component.
    pub artifact: Option<ArtifactBinding>,
    /// Shared provider/effect authority state.
    pub authority: AuthorityState,
    /// Component commit state.
    pub commit: CommitState,
    /// Component outcome knowledge.
    pub outcome: OutcomeState,
    /// Component settlement state.
    pub settlement: SettlementState,
    /// Component retirement state.
    pub retirement: RetirementState,
}

/// Public non-authorizing projection of one recovery-artifact lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRecoveryItem {
    /// Exact artifact binding retained by the recovery projection.
    pub binding: ArtifactBinding,
    /// Current durable lease state.
    pub lease: ArtifactLeaseState,
    /// Whether CSER has durably authorized the artifact authority to release.
    pub releasable: bool,
}

impl ArtifactRecoveryItem {
    /// Returns whether this lease has a durable release authorization.
    pub const fn is_releasable(self) -> bool {
        self.releasable
    }
}

/// One component-local obligation in a core-generated recovery cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentRecoveryItem {
    /// Shared parent effect identity.
    pub effect: EffectId,
    /// Catalog-defined component slot.
    pub component: ComponentId,
    /// Domain-defined obligation class.
    pub obligation: (DomainId, ObligationKindId),
    /// Shared effect authority state.
    pub authority: AuthorityState,
    /// Exact shared authority epoch observed by the snapshot.
    pub authority_epoch: u64,
    /// Component-local external commit state.
    pub commit: CommitState,
    /// Durable external operation identity used to validate recovery substrate.
    pub commit_operation: Option<Digest>,
    /// Component-local outcome knowledge.
    pub outcome: OutcomeState,
    /// Component-local settlement state.
    pub settlement: SettlementState,
    /// Component-local retirement state.
    pub retirement: RetirementState,
    /// Claims belonging to this component.
    pub claim_count: usize,
    /// Claims which still retain resources.
    pub retained_claims: usize,
    /// Whether this component still requires successor settlement.
    pub settlement_required: bool,
}

/// One verifier-bound retirement fact retained in snapshot schema v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEvidenceItem {
    /// Domain-defined evidence class.
    pub kind: EvidenceKindId,
    /// Exact freshness of the protected claim when challenged.
    pub subject: Freshness,
    /// Exact accepted verifier observation.
    pub observation: Freshness,
    /// Verifier identity, epoch, schema, and receipt digest.
    pub stamp: VerifierStamp,
    /// Exact provider scope retained by the accepted fact.
    pub verification_scope: ProviderVerificationScope,
}

/// One exact retained component claim in snapshot schema v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentClaimRecoveryItem {
    /// Complete non-authorizing claim projection.
    pub claim: ComponentClaimProjection,
    /// Accepted retirement facts in catalog requirement order.
    pub accepted_evidence: Vec<RecoveryEvidenceItem>,
    /// Evidence kinds still required, in catalog requirement order.
    pub pending_evidence: Vec<EvidenceKindId>,
}

/// One parent effect and its ordered component graph in snapshot schema v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeRecoveryItem {
    /// Shared parent effect identity.
    pub effect: EffectId,
    /// Catalog-defined complete component product.
    pub kind: CompositeKindId,
    /// Exact immutable catalog digest used to interpret this effect.
    pub catalog_digest: Digest,
    /// Exact originating executor coordinate.
    pub causal_owner: ExecutorCoordinate,
    /// Current parent-level custodian.
    pub custodian: CustodyState,
    /// Account charged for retained component claims.
    pub charge_owner: ChargeAccountId,
    /// Common parent authority state.
    pub authority: AuthorityState,
    /// Common parent authority epoch.
    pub authority_epoch: u64,
    /// Derived parent escape and completion state.
    pub escape: EffectEscapeState,
    /// Complete ordered component graph.
    pub components: Vec<ComponentRecoveryItem>,
    /// Every retained claim and its partial evidence state, ordered by component
    /// and claim identity.
    pub retained_claims: Vec<ComponentClaimRecoveryItem>,
    /// Durable non-authorizing handoff information needed to re-verify a
    /// crash-interrupted source or target relationship.
    pub handoff: SingleHopHandoffProjection,
}

/// Exact, non-authorizing recovery cohort generated from core state.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    core_api_profile: u16,
    snapshot_version: u16,
    journal_schema: u16,
    catalog_digest: Digest,
    operation: OperationId,
    snapshot: SnapshotId,
    digest: Digest,
    covered_revision: u64,
    covered_head: Digest,
    composites: Vec<CompositeRecoveryItem>,
    artifacts: Vec<ArtifactRecoveryItem>,
}

impl RecoverySnapshot {
    /// Returns the semantic API profile which produced this cohort.
    pub const fn core_api_profile(&self) -> u16 {
        self.core_api_profile
    }

    /// Returns the recovery snapshot schema coordinate.
    pub const fn snapshot_version(&self) -> u16 {
        self.snapshot_version
    }

    /// Returns the journal grammar bound by the covered head.
    pub const fn journal_schema(&self) -> u16 {
        self.journal_schema
    }

    /// Returns the aggregate catalog-set digest protecting this snapshot.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the causal operation covered by this snapshot.
    pub const fn operation(&self) -> OperationId {
        self.operation
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

    /// Returns parent-grouped composite graphs in stable effect order.
    pub fn composites(&self) -> &[CompositeRecoveryItem] {
        &self.composites
    }

    /// Returns exact provider/artifact recovery obligations covered by this
    /// snapshot in stable artifact identity order.
    pub fn artifacts(&self) -> &[ArtifactRecoveryItem] {
        &self.artifacts
    }

    /// Consumes the descriptor into the only command which can record this
    /// exact snapshot. The transition still rejects if state changed.
    pub fn record(self) -> Command {
        Command(CommandKind::Snapshot {
            operation: self.operation,
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
    /// Number of causal operations.
    pub operations: usize,
    /// Number of composite effect records.
    pub composites: usize,
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
    /// The catalog-set used the reserved zero digest.
    ZeroDigest,
    /// Revision zero and the zero head must be presented together.
    InconsistentGenesis,
    /// The committed and next epochs name different Registry instances.
    RegistryMismatch,
    /// The trusted binding tuple does not match the freshness coordinates.
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
    binding: RecoveryBinding,
    committed_freshness: Freshness,
    next_freshness: Freshness,
    minimum_revision: u64,
    expected_head: Digest,
    projection: Digest,
}

impl RecoveryAnchor {
    /// Creates an exact, single-use recovery anchor from a trusted provider.
    ///
    /// Calling this constructor is an explicit assertion that the fields were
    /// read atomically from storage which cannot be rolled back with the
    /// journal.
    pub const fn from_trusted_provider(
        binding: RecoveryBinding,
        committed_freshness: Freshness,
        next_freshness: Freshness,
        minimum_revision: u64,
        expected_head: Digest,
        projection: Digest,
    ) -> Result<Self, RecoveryAnchorError> {
        if binding.catalog_digest().is_zero() || projection.is_zero() {
            return Err(RecoveryAnchorError::ZeroDigest);
        }
        if (minimum_revision == 0) != expected_head.is_zero() {
            return Err(RecoveryAnchorError::InconsistentGenesis);
        }
        if committed_freshness.registry().get() != next_freshness.registry().get()
            || committed_freshness.registry().get() != binding.registry().get()
        {
            return Err(RecoveryAnchorError::RegistryMismatch);
        }
        if next_freshness.boot().get() <= committed_freshness.boot().get()
            || next_freshness.journal().get() <= committed_freshness.journal().get()
            || next_freshness.device().get() < committed_freshness.device().get()
        {
            return Err(RecoveryAnchorError::NonAdvancingEpoch);
        }
        Ok(Self {
            binding,
            committed_freshness,
            next_freshness,
            minimum_revision,
            expected_head,
            projection,
        })
    }

    /// Returns the aggregate catalog-set digest protected by the anchor.
    pub const fn catalog_digest(&self) -> Digest {
        self.binding.catalog_digest()
    }

    /// Returns the complete trusted recovery binding.
    pub const fn binding(&self) -> RecoveryBinding {
        self.binding
    }

    /// Returns the semantic world bound by this anchor.
    pub const fn world(&self) -> WorldId {
        self.binding.world()
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

    /// Returns the final projection protected by this anchor.
    pub const fn projection(&self) -> Digest {
        self.projection
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
    /// A scoped command names a different semantic world.
    WorldMismatch,
    /// The requested provider generation is not registered.
    UnknownProviderGeneration,
    /// A provider generation is not strictly newer than its durable history.
    ProviderGenerationStale,
    /// The provider generation lifecycle does not permit this transition.
    ProviderLifecycleViolation,
    /// Provider bindings do not exactly match the catalog component product.
    ProviderBindingMismatch,
    /// Components of one composite resolve to different immutable catalogs.
    CatalogMismatch,
    /// A provider generation's exact verifier bindings do not match the
    /// catalog-required class/schema set.
    VerifierSetMismatch,
    /// A provider generation still has live component bindings.
    ProviderEffectsLive,
    /// A required recovery-artifact admission omitted its lease.
    ArtifactRequired,
    /// Artifact coordinates or a lease identity did not match the catalog.
    ArtifactBindingMismatch,
    /// The provider has no exact artifact pin/release verifier pair.
    ArtifactVerifierMismatch,
    /// A required artifact has not been pinned before the commit boundary.
    ArtifactNotPinned,
    /// An artifact lease is not yet eligible for release authorization.
    ArtifactNotReleasable,
    /// Artifact release confirmation did not match its durable permit.
    ArtifactReleaseMismatch,
    /// A command or recovered record does not belong to this API profile.
    IncompatibleApiProfile,
    /// A guarded bounded handoff must use its dedicated transition.
    HandoffGuardRequired,
    /// At least one limit is zero.
    InvalidLimits,
    /// A generation or nonce overflowed.
    GenerationExhausted,
    /// A declared obligation class is unknown.
    UnknownObligationClass,
    /// A declared claim class is unknown.
    UnknownClaimClass,
    /// The effect already exists.
    DuplicateEffect,
    /// The effect does not exist.
    UnknownEffect,
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
    /// The operation does not exist.
    UnknownOperation,
    /// A operation or composite-effect capacity would be exceeded.
    CapacityExceeded,
    /// A per-account retained-unit limit would be exceeded.
    Backpressure,
    /// The requested operation is invalid for the current commit state.
    WrongCommitState,
    /// The requested operation is invalid for the current settlement stage.
    WrongSettlementStage,
    /// The recovery lane is in the wrong phase.
    WrongRecoveryState,
    /// The presented executor coordinate is not the exact live coordinate.
    StaleExecutor,
    /// The presented composite authority epoch is stale.
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
    ///
    /// Unsupported evidence is rejected before it can mint a retirement
    /// command. This is core-wide fail-closed: the live claim, its charge,
    /// and its resource-reuse gate remain unchanged.
    UnexpectedEvidence,
    /// The evidence was already accepted.
    DuplicateEvidence,
    /// A declared predecessor receipt has not yet been accepted.
    EvidenceOutOfOrder,
    /// Evidence freshness does not match the exact active generations.
    StaleEvidence,
    /// The configured verifier class is absent or does not match the rule.
    UnknownVerifier,
    /// The verifier executor is stale.
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
    /// The composite effect is not settled and fully retired.
    EffectNotReleasable,
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
    /// This state is outside the current compact-checkpoint codec profile.
    UnsupportedCheckpointState,
    /// The canonical compact-checkpoint image exceeds the journal envelope limit.
    CheckpointImageTooLarge,
    /// Journal encoding or decoding failed.
    Journal(JournalDecodeError),
    /// A journal checkpoint envelope was malformed.
    JournalCheckpoint(JournalCheckpointDecodeError),
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
struct CompositeRecoveryRecord {
    origin: ExecutorCoordinate,
    state: OperationRecoveryState,
    last_executor: ExecutorCoordinate,
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
    verification_scope: ProviderVerificationScope,
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
/// Authoritative durable state for one-shot resource reuse.
///
/// A presented [`ReusePermit`] is only a convenient handle to this record; the
/// activation transition compares the complete retained tuple before enrolling
/// the next resource generation.
struct PendingReuse {
    effect: EffectId,
    component: ComponentId,
    actor: ExecutorCoordinate,
    authority_epoch: u64,
    claim: ClaimId,
    previous_generation: ResourceGeneration,
    catalog_digest: Digest,
    retirement_digest: Digest,
    reuse_contract: Digest,
    nonce: u64,
    freshness: Freshness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Keeping the pending contract inline preserves a non-allocating, Copy state
// transition on the durable path; its size is bounded by the fixed schema.
#[allow(clippy::large_enum_variant)]
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
struct ComponentRecord {
    id: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
    obligation_policy: ObligationPolicy,
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
struct CompositeEffectRecord {
    effect: EffectId,
    kind: CompositeKindId,
    /// Exact immutable catalog used to create and interpret this effect.
    catalog_digest: Digest,
    causal_owner: ExecutorCoordinate,
    custodian: CustodyState,
    charge_owner: ChargeAccountId,
    authority: AuthorityState,
    authority_epoch: u64,
    handoff: SingleHopRole,
    /// This is provenance only: it must never contribute to provider live
    /// accounting or admission gates.
    released_provenance: Option<ReleasedCompositeProvenance>,
    components: BTreeMap<ComponentId, ComponentRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderGenerationRecord {
    coordinate: ProviderCoordinate,
    catalog_digest: Digest,
    verifier_set_digest: Digest,
    verifier_bindings: Vec<VerifierBinding>,
    artifact_receipts: Option<ArtifactReceiptBindings>,
    state: ProviderEffectState,
    live_component_bindings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopedCompositeRecord {
    /// Exact immutable catalog shared by every provider binding.
    catalog_digest: Digest,
    bindings: BTreeMap<ComponentId, ProviderCoordinate>,
    artifacts: BTreeMap<ComponentId, ArtifactBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleasedCompositeProvenance {
    /// Exact immutable catalog retained after live provider accounting ends.
    catalog_digest: Digest,
    bindings: BTreeMap<ComponentId, ProviderCoordinate>,
    artifacts: BTreeMap<ComponentId, ArtifactBinding>,
}

impl From<ScopedCompositeRecord> for ReleasedCompositeProvenance {
    fn from(scoped: ScopedCompositeRecord) -> Self {
        Self {
            catalog_digest: scoped.catalog_digest,
            bindings: scoped.bindings,
            artifacts: scoped.artifacts,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SingleHopRole {
    None,
    Source {
        descriptor: Box<ChildDescriptorV1>,
        terminal_receipt_digest: Digest,
        descriptor_receipt_digest: Digest,
        recovery_fact: Option<VerifiedHandoffRecoveryFact>,
    },
    Target {
        parent: EffectId,
        descriptor_digest: Digest,
        recovery_fact: Option<VerifiedHandoffRecoveryFact>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    world: WorldId,
    provider_generations: StateMap<ProviderCoordinate, ProviderGenerationRecord>,
    provider_high_water: StateMap<ProviderId, ProviderGeneration>,
    scoped_composites: StateMap<EffectId, ScopedCompositeRecord>,
    artifact_leases: StateMap<crate::RecoveryArtifactId, ArtifactLeaseState>,
    recovery_operations: StateMap<OperationId, CompositeRecoveryRecord>,
    composite_effects: StateMap<EffectId, CompositeEffectRecord>,
    composite_resource_index: StateMap<ResourceId, Vec<(EffectId, ComponentId, ClaimId)>>,
    resources: StateMap<ResourceId, ResourceRecord>,
    charges: StateMap<(ChargeAccountId, CreditClassId), u64>,
    device_generations: StateMap<DeviceScopeId, DeviceGeneration>,
    device_quarantine: StateSet<DeviceScopeId>,
    revision: u64,
    head: Digest,
    next_nonce: u64,
    /// Derived count of all composite-component claims. Claims are retired
    /// in place, so only enrollment changes this value.
    total_claims: usize,
    freshness: Freshness,
    recovery_target: Option<Freshness>,
    projection_cache: ProjectionCache,
}

type ResourceIndexMap = StateMap<ResourceId, Vec<(EffectId, ComponentId, ClaimId)>>;

impl StateAccess for State {
    fn world(&self) -> WorldId {
        self.world
    }
    fn provider_generations(&self) -> &StateMap<ProviderCoordinate, ProviderGenerationRecord> {
        &self.provider_generations
    }
    fn provider_high_water(&self) -> &StateMap<ProviderId, ProviderGeneration> {
        &self.provider_high_water
    }
    fn scoped_composites(&self) -> &StateMap<EffectId, ScopedCompositeRecord> {
        &self.scoped_composites
    }
    fn artifact_leases(&self) -> &StateMap<crate::RecoveryArtifactId, ArtifactLeaseState> {
        &self.artifact_leases
    }
    fn recovery_operations(&self) -> &StateMap<OperationId, CompositeRecoveryRecord> {
        &self.recovery_operations
    }
    fn composite_effects(&self) -> &StateMap<EffectId, CompositeEffectRecord> {
        &self.composite_effects
    }
    fn composite_resource_index(&self) -> &ResourceIndexMap {
        &self.composite_resource_index
    }
    fn resources(&self) -> &StateMap<ResourceId, ResourceRecord> {
        &self.resources
    }
    fn charges(&self) -> &StateMap<(ChargeAccountId, CreditClassId), u64> {
        &self.charges
    }
    fn device_generations(&self) -> &StateMap<DeviceScopeId, DeviceGeneration> {
        &self.device_generations
    }
    fn device_quarantine(&self) -> &StateSet<DeviceScopeId> {
        &self.device_quarantine
    }
    fn revision(&self) -> u64 {
        self.revision
    }
    fn head(&self) -> Digest {
        self.head
    }
    fn next_nonce(&self) -> u64 {
        self.next_nonce
    }
    fn total_claims(&self) -> usize {
        self.total_claims
    }
    fn freshness(&self) -> Freshness {
        self.freshness
    }
    fn recovery_target(&self) -> Option<Freshness> {
        self.recovery_target
    }
    fn projection_cache(&self) -> &ProjectionCache {
        &self.projection_cache
    }
}

impl StateAccessMut for State {
    fn provider_generations_mut(
        &mut self,
    ) -> &mut StateMap<ProviderCoordinate, ProviderGenerationRecord> {
        &mut self.provider_generations
    }
    fn provider_high_water_mut(&mut self) -> &mut StateMap<ProviderId, ProviderGeneration> {
        &mut self.provider_high_water
    }
    fn scoped_composites_mut(&mut self) -> &mut StateMap<EffectId, ScopedCompositeRecord> {
        &mut self.scoped_composites
    }
    fn artifact_leases_mut(
        &mut self,
    ) -> &mut StateMap<crate::RecoveryArtifactId, ArtifactLeaseState> {
        &mut self.artifact_leases
    }
    fn recovery_operations_mut(&mut self) -> &mut StateMap<OperationId, CompositeRecoveryRecord> {
        &mut self.recovery_operations
    }
    fn composite_effects_mut(&mut self) -> &mut StateMap<EffectId, CompositeEffectRecord> {
        &mut self.composite_effects
    }
    fn composite_resource_index_mut(&mut self) -> &mut ResourceIndexMap {
        &mut self.composite_resource_index
    }
    fn resources_mut(&mut self) -> &mut StateMap<ResourceId, ResourceRecord> {
        &mut self.resources
    }
    fn charges_mut(&mut self) -> &mut StateMap<(ChargeAccountId, CreditClassId), u64> {
        &mut self.charges
    }
    fn device_generations_mut(&mut self) -> &mut StateMap<DeviceScopeId, DeviceGeneration> {
        &mut self.device_generations
    }
    fn device_quarantine_mut(&mut self) -> &mut StateSet<DeviceScopeId> {
        &mut self.device_quarantine
    }
    fn set_revision(&mut self, value: u64) {
        self.revision = value;
    }
    fn set_head(&mut self, value: Digest) {
        self.head = value;
    }
    fn set_next_nonce(&mut self, value: u64) {
        self.next_nonce = value;
    }
    fn set_total_claims(&mut self, value: usize) {
        self.total_claims = value;
    }
    fn freshness_mut(&mut self) -> &mut Freshness {
        &mut self.freshness
    }
    fn set_recovery_target(&mut self, value: Option<Freshness>) {
        self.recovery_target = value;
    }
    fn set_projection_cache(&mut self, value: ProjectionCache) {
        self.projection_cache = value;
    }
}

/// Derived authenticated projection of [`State`].
///
/// The sparse map contains one canonical leaf for every primary projection
/// record.  The scalar envelope is kept separately so revision/head and
/// freshness changes do not require walking unrelated records.  This value is
/// deliberately omitted from the checkpoint image; recovery reconstructs it
/// from primary state and verifies the resulting digest against the anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectionCache {
    leaves: AuthenticatedMap,
    digest: Digest,
}

impl ProjectionCache {
    fn from_leaves(state: &impl StateAccess, catalog: Digest, leaves: AuthenticatedMap) -> Self {
        Self {
            digest: projection_envelope(state, catalog, leaves.root_digest()),
            leaves,
        }
    }
}

/// The sole authoritative portable CSER state machine.
#[derive(Debug)]
pub struct Engine {
    catalog: CatalogSet,
    limits: CoreLimits,
    state: State,
    persistence_recovery_required: bool,
    journal_repair_required: Option<JournalRepair>,
}

/// Keep a committed top-level value or publish its prepared replacement.
///
/// A delta owns replacements rather than a second `State`.  That distinction
/// is important at the durability boundary: after the journal append has
/// succeeded, publication only moves already-validated roots and scalars into
/// the committed state.
enum Change<T> {
    Keep,
    Set(T),
}

trait StateAccess {
    fn world(&self) -> WorldId;
    fn provider_generations(&self) -> &StateMap<ProviderCoordinate, ProviderGenerationRecord>;
    fn provider_high_water(&self) -> &StateMap<ProviderId, ProviderGeneration>;
    fn scoped_composites(&self) -> &StateMap<EffectId, ScopedCompositeRecord>;
    fn artifact_leases(&self) -> &StateMap<crate::RecoveryArtifactId, ArtifactLeaseState>;
    fn recovery_operations(&self) -> &StateMap<OperationId, CompositeRecoveryRecord>;
    fn composite_effects(&self) -> &StateMap<EffectId, CompositeEffectRecord>;
    fn composite_resource_index(&self) -> &ResourceIndexMap;
    fn resources(&self) -> &StateMap<ResourceId, ResourceRecord>;
    fn charges(&self) -> &StateMap<(ChargeAccountId, CreditClassId), u64>;
    fn device_generations(&self) -> &StateMap<DeviceScopeId, DeviceGeneration>;
    fn device_quarantine(&self) -> &StateSet<DeviceScopeId>;
    fn revision(&self) -> u64;
    fn head(&self) -> Digest;
    fn next_nonce(&self) -> u64;
    fn total_claims(&self) -> usize;
    fn freshness(&self) -> Freshness;
    fn recovery_target(&self) -> Option<Freshness>;
    fn projection_cache(&self) -> &ProjectionCache;
}

trait StateAccessMut: StateAccess {
    fn provider_generations_mut(
        &mut self,
    ) -> &mut StateMap<ProviderCoordinate, ProviderGenerationRecord>;
    fn provider_high_water_mut(&mut self) -> &mut StateMap<ProviderId, ProviderGeneration>;
    fn scoped_composites_mut(&mut self) -> &mut StateMap<EffectId, ScopedCompositeRecord>;
    fn artifact_leases_mut(
        &mut self,
    ) -> &mut StateMap<crate::RecoveryArtifactId, ArtifactLeaseState>;
    fn recovery_operations_mut(&mut self) -> &mut StateMap<OperationId, CompositeRecoveryRecord>;
    fn composite_effects_mut(&mut self) -> &mut StateMap<EffectId, CompositeEffectRecord>;
    fn composite_resource_index_mut(&mut self) -> &mut ResourceIndexMap;
    fn resources_mut(&mut self) -> &mut StateMap<ResourceId, ResourceRecord>;
    fn charges_mut(&mut self) -> &mut StateMap<(ChargeAccountId, CreditClassId), u64>;
    fn device_generations_mut(&mut self) -> &mut StateMap<DeviceScopeId, DeviceGeneration>;
    fn device_quarantine_mut(&mut self) -> &mut StateSet<DeviceScopeId>;
    fn set_revision(&mut self, value: u64);
    fn set_head(&mut self, value: Digest);
    fn set_next_nonce(&mut self, value: u64);
    fn set_total_claims(&mut self, value: usize);
    fn freshness_mut(&mut self) -> &mut Freshness;
    fn set_recovery_target(&mut self, value: Option<Freshness>);
    fn set_projection_cache(&mut self, value: ProjectionCache);

    // Production preparation records projection addresses at the point where
    // the corresponding primary record is mutated. Replay/checkpoint helpers
    // use the default no-op implementations because they rebuild the complete
    // projection independently.
    fn touch_provider_high_water(&mut self, _provider: ProviderId) {}
    fn touch_provider_generation(&mut self, _coordinate: ProviderCoordinate) {}
    fn touch_scoped_composite(&mut self, _effect: EffectId) {}
    fn touch_artifact_lease(&mut self, _artifact: crate::RecoveryArtifactId) {}
    fn touch_operation(&mut self, _operation: OperationId) {}
    fn touch_composite(&mut self, _effect: EffectId) {}
    fn touch_resource(&mut self, _resource: ResourceId) {}
    fn touch_device(&mut self, _scope: DeviceScopeId) {}
}

/// Exact prepared replacement for every top-level state collection/scalar.
struct PreparedStateDelta {
    world: Change<WorldId>,
    provider_generations: Change<StateMap<ProviderCoordinate, ProviderGenerationRecord>>,
    provider_high_water: Change<StateMap<ProviderId, ProviderGeneration>>,
    scoped_composites: Change<StateMap<EffectId, ScopedCompositeRecord>>,
    artifact_leases: Change<StateMap<crate::RecoveryArtifactId, ArtifactLeaseState>>,
    recovery_operations: Change<StateMap<OperationId, CompositeRecoveryRecord>>,
    composite_effects: Change<StateMap<EffectId, CompositeEffectRecord>>,
    composite_resource_index: Change<ResourceIndexMap>,
    resources: Change<StateMap<ResourceId, ResourceRecord>>,
    charges: Change<StateMap<(ChargeAccountId, CreditClassId), u64>>,
    device_generations: Change<StateMap<DeviceScopeId, DeviceGeneration>>,
    device_quarantine: Change<StateSet<DeviceScopeId>>,
    revision: Change<u64>,
    head: Change<Digest>,
    next_nonce: Change<u64>,
    total_claims: Change<usize>,
    freshness: Change<Freshness>,
    recovery_target: Change<Option<Freshness>>,
    projection_cache: Change<ProjectionCache>,
}

/// Borrowed builder for one transition. A collection is cloned from the
/// committed root only on its first mutation; all subsequent updates reuse
/// that slot's path-copied root. This is the production preparation surface,
/// not a second state image.
struct DeltaBuilder<'a> {
    base: &'a State,
    world: Change<WorldId>,
    provider_generations: Change<StateMap<ProviderCoordinate, ProviderGenerationRecord>>,
    provider_high_water: Change<StateMap<ProviderId, ProviderGeneration>>,
    scoped_composites: Change<StateMap<EffectId, ScopedCompositeRecord>>,
    artifact_leases: Change<StateMap<crate::RecoveryArtifactId, ArtifactLeaseState>>,
    recovery_operations: Change<StateMap<OperationId, CompositeRecoveryRecord>>,
    composite_effects: Change<StateMap<EffectId, CompositeEffectRecord>>,
    composite_resource_index: Change<ResourceIndexMap>,
    resources: Change<StateMap<ResourceId, ResourceRecord>>,
    charges: Change<StateMap<(ChargeAccountId, CreditClassId), u64>>,
    device_generations: Change<StateMap<DeviceScopeId, DeviceGeneration>>,
    device_quarantine: Change<StateSet<DeviceScopeId>>,
    revision: Change<u64>,
    head: Change<Digest>,
    next_nonce: Change<u64>,
    total_claims: Change<usize>,
    freshness: Change<Freshness>,
    recovery_target: Change<Option<Freshness>>,
    projection_cache: Change<ProjectionCache>,
    projection_touches: ProjectionTouches,
}

fn change_ref<'a, T>(change: &'a Change<T>, base: &'a T) -> &'a T {
    match change {
        Change::Keep => base,
        Change::Set(value) => value,
    }
}

impl<'a> DeltaBuilder<'a> {
    fn new(base: &'a State) -> Self {
        Self {
            base,
            world: Change::Keep,
            provider_generations: Change::Keep,
            provider_high_water: Change::Keep,
            scoped_composites: Change::Keep,
            artifact_leases: Change::Keep,
            recovery_operations: Change::Keep,
            composite_effects: Change::Keep,
            composite_resource_index: Change::Keep,
            resources: Change::Keep,
            charges: Change::Keep,
            device_generations: Change::Keep,
            device_quarantine: Change::Keep,
            revision: Change::Keep,
            head: Change::Keep,
            next_nonce: Change::Keep,
            total_claims: Change::Keep,
            freshness: Change::Keep,
            recovery_target: Change::Keep,
            projection_cache: Change::Keep,
            projection_touches: ProjectionTouches::default(),
        }
    }

    fn finish(self) -> PreparedStateDelta {
        PreparedStateDelta {
            world: self.world,
            provider_generations: self.provider_generations,
            provider_high_water: self.provider_high_water,
            scoped_composites: self.scoped_composites,
            artifact_leases: self.artifact_leases,
            recovery_operations: self.recovery_operations,
            composite_effects: self.composite_effects,
            composite_resource_index: self.composite_resource_index,
            resources: self.resources,
            charges: self.charges,
            device_generations: self.device_generations,
            device_quarantine: self.device_quarantine,
            revision: self.revision,
            head: self.head,
            next_nonce: self.next_nonce,
            total_claims: self.total_claims,
            freshness: self.freshness,
            recovery_target: self.recovery_target,
            projection_cache: self.projection_cache,
        }
    }

    fn take_projection_touches(&mut self) -> ProjectionTouches {
        core::mem::take(&mut self.projection_touches)
    }

    fn ensure_provider_generations(
        &mut self,
    ) -> &mut StateMap<ProviderCoordinate, ProviderGenerationRecord> {
        if matches!(self.provider_generations, Change::Keep) {
            self.provider_generations = Change::Set(self.base.provider_generations.clone());
        }
        match &mut self.provider_generations {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_provider_high_water(&mut self) -> &mut StateMap<ProviderId, ProviderGeneration> {
        if matches!(self.provider_high_water, Change::Keep) {
            self.provider_high_water = Change::Set(self.base.provider_high_water.clone());
        }
        match &mut self.provider_high_water {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_scoped_composites(&mut self) -> &mut StateMap<EffectId, ScopedCompositeRecord> {
        if matches!(self.scoped_composites, Change::Keep) {
            self.scoped_composites = Change::Set(self.base.scoped_composites.clone());
        }
        match &mut self.scoped_composites {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_artifact_leases(
        &mut self,
    ) -> &mut StateMap<crate::RecoveryArtifactId, ArtifactLeaseState> {
        if matches!(self.artifact_leases, Change::Keep) {
            self.artifact_leases = Change::Set(self.base.artifact_leases.clone());
        }
        match &mut self.artifact_leases {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_recovery_operations(
        &mut self,
    ) -> &mut StateMap<OperationId, CompositeRecoveryRecord> {
        if matches!(self.recovery_operations, Change::Keep) {
            self.recovery_operations = Change::Set(self.base.recovery_operations.clone());
        }
        match &mut self.recovery_operations {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_composite_effects(&mut self) -> &mut StateMap<EffectId, CompositeEffectRecord> {
        if matches!(self.composite_effects, Change::Keep) {
            self.composite_effects = Change::Set(self.base.composite_effects.clone());
        }
        match &mut self.composite_effects {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_composite_resource_index(&mut self) -> &mut ResourceIndexMap {
        if matches!(self.composite_resource_index, Change::Keep) {
            self.composite_resource_index = Change::Set(self.base.composite_resource_index.clone());
        }
        match &mut self.composite_resource_index {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_resources(&mut self) -> &mut StateMap<ResourceId, ResourceRecord> {
        if matches!(self.resources, Change::Keep) {
            self.resources = Change::Set(self.base.resources.clone());
        }
        match &mut self.resources {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_charges(&mut self) -> &mut StateMap<(ChargeAccountId, CreditClassId), u64> {
        if matches!(self.charges, Change::Keep) {
            self.charges = Change::Set(self.base.charges.clone());
        }
        match &mut self.charges {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_device_generations(&mut self) -> &mut StateMap<DeviceScopeId, DeviceGeneration> {
        if matches!(self.device_generations, Change::Keep) {
            self.device_generations = Change::Set(self.base.device_generations.clone());
        }
        match &mut self.device_generations {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn ensure_device_quarantine(&mut self) -> &mut StateSet<DeviceScopeId> {
        if matches!(self.device_quarantine, Change::Keep) {
            self.device_quarantine = Change::Set(self.base.device_quarantine.clone());
        }
        match &mut self.device_quarantine {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
}

impl<'a> StateAccess for DeltaBuilder<'a> {
    fn world(&self) -> WorldId {
        self.base.world()
    }
    fn provider_generations(&self) -> &StateMap<ProviderCoordinate, ProviderGenerationRecord> {
        change_ref(&self.provider_generations, self.base.provider_generations())
    }
    fn provider_high_water(&self) -> &StateMap<ProviderId, ProviderGeneration> {
        change_ref(&self.provider_high_water, self.base.provider_high_water())
    }
    fn scoped_composites(&self) -> &StateMap<EffectId, ScopedCompositeRecord> {
        change_ref(&self.scoped_composites, self.base.scoped_composites())
    }
    fn artifact_leases(&self) -> &StateMap<crate::RecoveryArtifactId, ArtifactLeaseState> {
        change_ref(&self.artifact_leases, self.base.artifact_leases())
    }
    fn recovery_operations(&self) -> &StateMap<OperationId, CompositeRecoveryRecord> {
        change_ref(&self.recovery_operations, self.base.recovery_operations())
    }
    fn composite_effects(&self) -> &StateMap<EffectId, CompositeEffectRecord> {
        change_ref(&self.composite_effects, self.base.composite_effects())
    }
    fn composite_resource_index(&self) -> &ResourceIndexMap {
        change_ref(
            &self.composite_resource_index,
            self.base.composite_resource_index(),
        )
    }
    fn resources(&self) -> &StateMap<ResourceId, ResourceRecord> {
        change_ref(&self.resources, self.base.resources())
    }
    fn charges(&self) -> &StateMap<(ChargeAccountId, CreditClassId), u64> {
        change_ref(&self.charges, self.base.charges())
    }
    fn device_generations(&self) -> &StateMap<DeviceScopeId, DeviceGeneration> {
        change_ref(&self.device_generations, self.base.device_generations())
    }
    fn device_quarantine(&self) -> &StateSet<DeviceScopeId> {
        change_ref(&self.device_quarantine, self.base.device_quarantine())
    }
    fn revision(&self) -> u64 {
        match self.revision {
            Change::Keep => self.base.revision(),
            Change::Set(value) => value,
        }
    }
    fn head(&self) -> Digest {
        match self.head {
            Change::Keep => self.base.head(),
            Change::Set(value) => value,
        }
    }
    fn next_nonce(&self) -> u64 {
        match self.next_nonce {
            Change::Keep => self.base.next_nonce(),
            Change::Set(value) => value,
        }
    }
    fn total_claims(&self) -> usize {
        match self.total_claims {
            Change::Keep => self.base.total_claims(),
            Change::Set(value) => value,
        }
    }
    fn freshness(&self) -> Freshness {
        match self.freshness {
            Change::Keep => self.base.freshness(),
            Change::Set(value) => value,
        }
    }
    fn recovery_target(&self) -> Option<Freshness> {
        match self.recovery_target {
            Change::Keep => self.base.recovery_target(),
            Change::Set(value) => value,
        }
    }
    fn projection_cache(&self) -> &ProjectionCache {
        change_ref(&self.projection_cache, self.base.projection_cache())
    }
}

impl<'a> StateAccessMut for DeltaBuilder<'a> {
    fn provider_generations_mut(
        &mut self,
    ) -> &mut StateMap<ProviderCoordinate, ProviderGenerationRecord> {
        self.ensure_provider_generations()
    }
    fn provider_high_water_mut(&mut self) -> &mut StateMap<ProviderId, ProviderGeneration> {
        self.ensure_provider_high_water()
    }
    fn scoped_composites_mut(&mut self) -> &mut StateMap<EffectId, ScopedCompositeRecord> {
        self.ensure_scoped_composites()
    }
    fn artifact_leases_mut(
        &mut self,
    ) -> &mut StateMap<crate::RecoveryArtifactId, ArtifactLeaseState> {
        self.ensure_artifact_leases()
    }
    fn recovery_operations_mut(&mut self) -> &mut StateMap<OperationId, CompositeRecoveryRecord> {
        self.ensure_recovery_operations()
    }
    fn composite_effects_mut(&mut self) -> &mut StateMap<EffectId, CompositeEffectRecord> {
        self.ensure_composite_effects()
    }
    fn composite_resource_index_mut(&mut self) -> &mut ResourceIndexMap {
        self.ensure_composite_resource_index()
    }
    fn resources_mut(&mut self) -> &mut StateMap<ResourceId, ResourceRecord> {
        self.ensure_resources()
    }
    fn charges_mut(&mut self) -> &mut StateMap<(ChargeAccountId, CreditClassId), u64> {
        self.ensure_charges()
    }
    fn device_generations_mut(&mut self) -> &mut StateMap<DeviceScopeId, DeviceGeneration> {
        self.ensure_device_generations()
    }
    fn device_quarantine_mut(&mut self) -> &mut StateSet<DeviceScopeId> {
        self.ensure_device_quarantine()
    }
    fn set_revision(&mut self, value: u64) {
        self.revision = Change::Set(value);
    }
    fn set_head(&mut self, value: Digest) {
        self.head = Change::Set(value);
    }
    fn set_next_nonce(&mut self, value: u64) {
        self.next_nonce = Change::Set(value);
    }
    fn set_total_claims(&mut self, value: usize) {
        self.total_claims = Change::Set(value);
    }
    fn freshness_mut(&mut self) -> &mut Freshness {
        if matches!(self.freshness, Change::Keep) {
            self.freshness = Change::Set(self.base.freshness);
        }
        match &mut self.freshness {
            Change::Set(value) => value,
            Change::Keep => unreachable!(),
        }
    }
    fn set_recovery_target(&mut self, value: Option<Freshness>) {
        self.recovery_target = Change::Set(value);
    }
    fn set_projection_cache(&mut self, value: ProjectionCache) {
        self.projection_cache = Change::Set(value);
    }

    fn touch_provider_high_water(&mut self, provider: ProviderId) {
        self.projection_touches.provider_high_water.insert(provider);
    }
    fn touch_provider_generation(&mut self, coordinate: ProviderCoordinate) {
        self.projection_touches
            .provider_generations
            .insert(coordinate);
    }
    fn touch_scoped_composite(&mut self, effect: EffectId) {
        self.projection_touches.scoped_composites.insert(effect);
    }
    fn touch_artifact_lease(&mut self, artifact: crate::RecoveryArtifactId) {
        self.projection_touches.artifact_leases.insert(artifact);
    }
    fn touch_operation(&mut self, operation: OperationId) {
        self.projection_touches.operations.insert(operation);
    }
    fn touch_composite(&mut self, effect: EffectId) {
        self.projection_touches.composites.insert(effect);
    }
    fn touch_resource(&mut self, resource: ResourceId) {
        self.projection_touches.resources.insert(resource);
    }
    fn touch_device(&mut self, scope: DeviceScopeId) {
        self.projection_touches.devices.insert(scope);
    }
}

impl PreparedStateDelta {
    fn freshness(&self, current: Freshness) -> Freshness {
        match &self.freshness {
            Change::Keep => current,
            Change::Set(freshness) => *freshness,
        }
    }

    /// Publishes this delta.  This function intentionally contains only
    /// conditional moves; it does not call a fallible helper, allocate, walk
    /// a map, hash, or invoke verifier logic.
    fn apply(self, state: &mut State) {
        let Self {
            world,
            provider_generations,
            provider_high_water,
            scoped_composites,
            artifact_leases,
            recovery_operations,
            composite_effects,
            composite_resource_index,
            resources,
            charges,
            device_generations,
            device_quarantine,
            revision,
            head,
            next_nonce,
            total_claims,
            freshness,
            recovery_target,
            projection_cache,
        } = self;
        apply_change(&mut state.world, world);
        apply_change(&mut state.provider_generations, provider_generations);
        apply_change(&mut state.provider_high_water, provider_high_water);
        apply_change(&mut state.scoped_composites, scoped_composites);
        apply_change(&mut state.artifact_leases, artifact_leases);
        apply_change(&mut state.recovery_operations, recovery_operations);
        apply_change(&mut state.composite_effects, composite_effects);
        apply_change(
            &mut state.composite_resource_index,
            composite_resource_index,
        );
        apply_change(&mut state.resources, resources);
        apply_change(&mut state.charges, charges);
        apply_change(&mut state.device_generations, device_generations);
        apply_change(&mut state.device_quarantine, device_quarantine);
        apply_change(&mut state.revision, revision);
        apply_change(&mut state.head, head);
        apply_change(&mut state.next_nonce, next_nonce);
        apply_change(&mut state.total_claims, total_claims);
        apply_change(&mut state.freshness, freshness);
        apply_change(&mut state.recovery_target, recovery_target);
        apply_change(&mut state.projection_cache, projection_cache);
    }
}

fn apply_change<T>(slot: &mut T, change: Change<T>) {
    if let Change::Set(value) = change {
        *slot = value;
    }
}

fn checkpoint_state_matches<S: StateAccess>(state: &S, rebuilt: &State) -> bool {
    state.world() == rebuilt.world
        && state.provider_generations() == &rebuilt.provider_generations
        && state.provider_high_water() == &rebuilt.provider_high_water
        && state.scoped_composites() == &rebuilt.scoped_composites
        && state.artifact_leases() == &rebuilt.artifact_leases
        && state.recovery_operations() == &rebuilt.recovery_operations
        && state.composite_effects() == &rebuilt.composite_effects
        && state.composite_resource_index() == &rebuilt.composite_resource_index
        && state.resources() == &rebuilt.resources
        && charges_equal_ignoring_zero(state.charges(), &rebuilt.charges)
        && state.device_generations() == &rebuilt.device_generations
        && state.device_quarantine() == &rebuilt.device_quarantine
        && state.revision() == rebuilt.revision
        && state.head() == rebuilt.head
        && state.next_nonce() == rebuilt.next_nonce
        && state.total_claims() == rebuilt.total_claims
        && state.freshness() == rebuilt.freshness
        && state.recovery_target() == rebuilt.recovery_target
}

fn state_within_limits(state: &impl StateAccess, limits: CoreLimits) -> bool {
    state.recovery_operations().len() <= limits.max_operations
        && state.composite_effects().len() <= limits.max_effects
        && state.resources().len() <= limits.max_resource_records
        && state.provider_generations().len() <= limits.max_provider_generations
        && state.provider_high_water().len() <= limits.max_provider_high_water
        && state.artifact_leases().len() <= limits.max_artifact_leases
        && state.device_generations().len() <= limits.max_device_generations
        && state.total_claims() <= limits.max_total_claims
        && state.composite_effects().values().all(|effect| {
            effect.components.len() <= limits.max_components_per_effect
                && effect
                    .components
                    .values()
                    .all(|component| component.claims.len() <= limits.max_claims_per_effect)
        })
}

fn charges_equal_ignoring_zero(
    left: &StateMap<(ChargeAccountId, CreditClassId), u64>,
    right: &StateMap<(ChargeAccountId, CreditClassId), u64>,
) -> bool {
    left.iter()
        .filter(|(_, units)| **units != 0)
        .eq(right.iter().filter(|(_, units)| **units != 0))
}

/// The complete result of the semantic half of one transition.
struct PreparedTransition {
    delta: PreparedStateDelta,
    record: JournalRecord,
    receipt: TransitionReceipt,
}

#[allow(clippy::large_enum_variant)]
enum TransitionInput {
    Command(Command),
    ValidatedCheckpoint(ValidatedCheckpointImage),
}

/// Private proof that a compact checkpoint image was encoded from a fully
/// validated live state.  There is deliberately no public constructor: only
/// the local compact-checkpoint path may use this image without decoding it.
struct ValidatedCheckpointImage {
    image: Arc<[u8]>,
    projection: Digest,
}

impl ValidatedCheckpointImage {
    fn from_live_state(
        state: &State,
        catalog: &CatalogSet,
        limits: CoreLimits,
    ) -> Result<Self, CoreError> {
        check_invariants_for_catalog_set(catalog, limits, state)?;
        let rebuilt_projection = build_projection_cache(state, catalog.digest());
        if state.projection_cache() != &rebuilt_projection {
            return Err(CoreError::InvariantViolation);
        }
        let image = encode_whole_state_checkpoint(state);
        if image.len() > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
            return Err(CoreError::CheckpointImageTooLarge);
        }
        Ok(Self {
            image: Arc::from(image.into_boxed_slice()),
            projection: rebuilt_projection.digest,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PrepareError {
    Core(CoreError),
    Journal(JournalDecodeError),
}

/// Initializes the common composite record after an exact provider-scoped
/// admission has validated every component binding. Keeping this helper
/// private means replay and public requests cannot create an unbound effect.
fn initialize_composite_effect(
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    origin: ExecutorCoordinate,
    kind: CompositeKindId,
    charge_account: ChargeAccountId,
) -> Result<(), CoreError> {
    let component_specs = catalog
        .composite_rule(kind)
        .ok_or(CoreError::UnknownObligationClass)?
        .components()
        .to_vec();
    if component_specs.len() > limits.max_components_per_effect {
        return Err(CoreError::CapacityExceeded);
    }
    if state.composite_effects().contains_key(&effect) {
        return Err(CoreError::DuplicateEffect);
    }
    if state.composite_effects().len() >= limits.max_effects {
        return Err(CoreError::CapacityExceeded);
    }
    match state.recovery_operations().get(&effect.operation()) {
        Some(operation) => {
            if operation.origin.executor() != origin.executor()
                || !matches!(
                    operation.state,
                    OperationRecoveryState::Active { executor }
                        | OperationRecoveryState::Rebound {
                            successor: executor,
                        } if executor == origin
                )
            {
                return Err(CoreError::StaleExecutor);
            }
        }
        None => {
            if state.recovery_operations().len() >= limits.max_operations {
                return Err(CoreError::CapacityExceeded);
            }
            state.touch_operation(effect.operation());
            state.recovery_operations_mut().insert_mut(
                effect.operation(),
                CompositeRecoveryRecord {
                    origin,
                    state: OperationRecoveryState::Active { executor: origin },
                    last_executor: origin,
                    crash_generation: 0,
                },
            );
        }
    }
    let mut components = BTreeMap::new();
    for spec in component_specs {
        let obligation = catalog
            .obligation_rule(spec.domain(), spec.obligation())
            .ok_or(CoreError::UnknownObligationClass)?;
        components.insert(
            spec.component(),
            ComponentRecord {
                id: spec.component(),
                domain: spec.domain(),
                obligation: spec.obligation(),
                obligation_policy: obligation.policy(),
                commit: CommitState::Registered,
                commit_nonce: None,
                commit_operation: None,
                commit_fact: None,
                outcome: OutcomeState::Pending,
                settlement: SettlementState::Unavailable,
                settlement_nonce: None,
                claim_stage: None,
                settlement_intent: None,
                applied_fact: None,
                settlement_fact: None,
                retirement: RetirementState::Held,
                claims: BTreeMap::new(),
            },
        );
    }
    state.touch_composite(effect);
    state.composite_effects_mut().insert_mut(
        effect,
        CompositeEffectRecord {
            effect,
            kind,
            catalog_digest: catalog.digest(),
            causal_owner: origin,
            custodian: CustodyState::Executor(origin),
            charge_owner: charge_account,
            authority: AuthorityState::Active,
            authority_epoch: 1,
            handoff: SingleHopRole::None,
            released_provenance: None,
            components,
        },
    );
    Ok(())
}

impl Engine {
    /// Creates the sole engine grammar, scoped to one exact semantic world.
    pub fn new(
        world: WorldId,
        catalog_set: CatalogSet,
        limits: CoreLimits,
        freshness: Freshness,
    ) -> Self {
        let mut engine = Self {
            catalog: catalog_set,
            limits,
            state: State {
                world,
                provider_generations: StateMap::new(),
                provider_high_water: StateMap::new(),
                scoped_composites: StateMap::new(),
                artifact_leases: StateMap::new(),
                recovery_operations: StateMap::new(),
                composite_effects: StateMap::new(),
                composite_resource_index: StateMap::new(),
                resources: StateMap::new(),
                charges: StateMap::new(),
                device_generations: StateMap::new(),
                device_quarantine: StateSet::new(),
                revision: 0,
                head: Digest::ZERO,
                next_nonce: 1,
                total_claims: 0,
                freshness,
                recovery_target: None,
                projection_cache: ProjectionCache {
                    leaves: AuthenticatedMap::new(),
                    digest: Digest::ZERO,
                },
            },
            persistence_recovery_required: false,
            journal_repair_required: None,
        };
        engine.state.projection_cache =
            build_projection_cache(&engine.state, engine.catalog.digest());
        engine
    }

    /// Resolves one exact immutable catalog by schema digest.
    fn catalog_for(&self, digest: Digest) -> Result<&DomainCatalog, CoreError> {
        self.catalog.get(digest).ok_or(CoreError::SchemaMismatch)
    }

    /// Resolves the catalog recorded by an admitted or released effect.
    fn effect_catalog(&self, effect: EffectId) -> Result<&DomainCatalog, CoreError> {
        let digest = self
            .state
            .composite_effects()
            .get(&effect)
            .map(|composite| composite.catalog_digest)
            .ok_or(CoreError::UnknownEffect)?;
        self.catalog_for(digest)
    }

    /// Resolves the exact catalog material required by one command.  Commands
    /// which operate on an admitted effect use that effect's immutable
    /// provenance; provider lifecycle commands use their provider record;
    /// registration and verifier-bound receipts carry the digest explicitly.
    fn command_catalog_digest(&self, command: &CommandKind) -> Result<Digest, CoreError> {
        let digest = match command {
            CommandKind::RegisterProviderGeneration { catalog_digest, .. } => *catalog_digest,
            CommandKind::AdmitScopedCompositeEffect { bindings, .. } => {
                // Admission is a product over exact provider generations.  Do
                // not let the wire order choose the semantic catalog: every
                // bound generation must agree on one immutable catalog, and a
                // mixed set is rejected before the command dispatcher sees a
                // domain materialization.
                let mut consensus = None;
                for binding in bindings {
                    let provider_catalog = self
                        .state
                        .provider_generations()
                        .get(&binding.provider())
                        .ok_or(CoreError::UnknownProviderGeneration)?
                        .catalog_digest;
                    match consensus {
                        Some(expected) if expected != provider_catalog => {
                            return Err(CoreError::CatalogMismatch);
                        }
                        None => consensus = Some(provider_catalog),
                        _ => {}
                    }
                }
                consensus.ok_or(CoreError::CatalogMismatch)?
            }
            CommandKind::RecordArtifactPin { binding, .. }
            | CommandKind::RecordArtifactRelease { binding, .. } => binding.catalog_digest(),
            CommandKind::ResolveIndeterminateHandoffParent { descriptor, .. } => {
                descriptor.catalog_digest
            }
            CommandKind::ActivateResourceReuse { catalog_digest, .. } => *catalog_digest,
            CommandKind::BindArtifactReceiptVerifiers { coordinate, .. }
            | CommandKind::FenceProviderEffects { coordinate, .. }
            | CommandKind::EnterProviderSettlementOnly { coordinate, .. }
            | CommandKind::RetireProviderEffects { coordinate, .. } => self
                .state
                .provider_generations()
                .get(coordinate)
                .map(|record| record.catalog_digest)
                .ok_or(CoreError::UnknownProviderGeneration)?,
            CommandKind::AbortUnescapedEffect { effect }
            | CommandKind::AuthorizeArtifactRelease { effect, .. }
            | CommandKind::BeginRevoke { effect, .. }
            | CommandKind::ReleaseCompositeEffect { effect }
            | CommandKind::RecordCompositeCommitIntents { effect, .. }
            | CommandKind::PrepareCompositeEffect { effect, .. }
            | CommandKind::AdoptEffect { effect, .. }
            | CommandKind::RebaseCompositePrecommitClaims { effect, .. }
            | CommandKind::ClaimComponentSettlement { effect, .. }
            | CommandKind::RecordComponentCommitIntent { effect, .. }
            | CommandKind::RecordComponentApplyIntent { effect, .. }
            | CommandKind::MarkComponentIndeterminate { effect, .. }
            | CommandKind::SubmitComponentEvidence { effect, .. }
            | CommandKind::AddComponentClaim { effect, .. }
            | CommandKind::ReserveComponentReuse { effect, .. }
            | CommandKind::ReclaimResourceReuse { effect, .. } => self
                .state
                .composite_effects()
                .get(effect)
                .map(|composite| composite.catalog_digest)
                .ok_or(CoreError::UnknownEffect)?,
            CommandKind::AcknowledgeCommit { fact }
            | CommandKind::RecordApplied { fact }
            | CommandKind::Settle { fact }
            | CommandKind::AcknowledgeHandoffParent { fact, .. } => self
                .state
                .composite_effects()
                .get(&fact.effect)
                .map(|composite| composite.catalog_digest)
                .ok_or(CoreError::UnknownEffect)?,
            CommandKind::InstallHandoffChild { descriptor, .. }
            | CommandKind::ReleaseHandoffSourceAndRecordTargetIntent { descriptor, .. } => {
                descriptor.catalog_digest
            }
            // These commands carry no effect/provider coordinate. They are
            // validated against the aggregate set and do not interpret a
            // domain product directly.
            CommandKind::CheckpointRecovery { .. }
            | CommandKind::WholeStateCheckpointV1 { .. }
            | CommandKind::Snapshot { .. }
            | CommandKind::FenceExecutor { .. }
            | CommandKind::Ready { .. }
            | CommandKind::Rebind { .. } => self.catalog.digest(),
        };
        if matches!(
            command,
            CommandKind::CheckpointRecovery { .. }
                | CommandKind::WholeStateCheckpointV1 { .. }
                | CommandKind::Snapshot { .. }
                | CommandKind::FenceExecutor { .. }
                | CommandKind::Ready { .. }
                | CommandKind::Rebind { .. }
        ) {
            // Structural commands carry the aggregate catalog-set digest but
            // do not select one catalog member for domain interpretation.
            Ok(digest)
        } else if self.catalog.contains(digest) {
            Ok(digest)
        } else {
            Err(CoreError::SchemaMismatch)
        }
    }

    /// Supplies a domain materialization to the command dispatcher. Commands
    /// such as checkpoint recovery and recovery-lane bookkeeping carry no
    /// domain coordinate; their dispatcher branches are structural only, so
    /// the materialization is never consulted (whole-state checkpoints use
    /// the complete set explicitly).
    fn command_catalog(&self, command: &CommandKind) -> Result<Option<&DomainCatalog>, CoreError> {
        match command {
            CommandKind::CheckpointRecovery { .. }
            | CommandKind::WholeStateCheckpointV1 { .. }
            | CommandKind::Snapshot { .. }
            | CommandKind::FenceExecutor { .. }
            | CommandKind::Ready { .. }
            | CommandKind::Rebind { .. } => Ok(None),
            _ => self
                .catalog_for(self.command_catalog_digest(command)?)
                .map(Some),
        }
    }

    /// Returns the current journal revision.
    pub fn revision(&self) -> u64 {
        self.state.revision()
    }

    /// Returns the current journal head digest.
    pub fn head(&self) -> Digest {
        self.state.head()
    }

    /// Returns the active freshness coordinates.
    pub fn freshness(&self) -> Freshness {
        self.state.freshness()
    }

    /// Returns active freshness when the operation is present in recovery.
    pub fn freshness_for_operation(&self, operation: OperationId) -> Option<Freshness> {
        self.state
            .recovery_operations()
            .contains_key(&operation)
            .then_some(self.state.freshness())
    }

    /// Returns the current generation of one independently reset device scope.
    pub fn device_generation(&self, scope: DeviceScopeId) -> Option<DeviceGeneration> {
        self.state.device_generations().get(&scope).copied()
    }

    /// Builds the exact current challenge for one component-local claim.
    pub fn component_evidence_challenge(
        &self,
        effect: EffectId,
        component: ComponentId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
    ) -> Result<EvidenceChallenge, CoreError> {
        self.state
            .recovery_operations()
            .get(&effect.operation())
            .ok_or(CoreError::UnknownOperation)?;
        let claim = self
            .state
            .composite_effects()
            .get(&effect)
            .and_then(|composite| composite.components.get(&component))
            .and_then(|component| component.claims.get(&claim_id))
            .ok_or(CoreError::UnknownClaim)?;
        if claim.retired {
            return Err(CoreError::DuplicateEvidence);
        }
        let catalog = self.effect_catalog(effect)?;
        let rule = catalog
            .claim_rule(claim.domain, claim.kind)
            .ok_or(CoreError::UnknownClaimClass)?
            .evidence()
            .iter()
            .find(|rule| rule.kind() == kind)
            .ok_or(CoreError::UnexpectedEvidence)?;
        let current_observation = scoped_freshness(&self.state, claim.scope)?;
        let verification_scope = self.scoped_verification_scope(
            effect,
            component,
            rule.verifier(),
            rule.receipt_schema(),
        )?;
        let expected_verifier_binding = verification_scope.verifier_binding();
        Ok(EvidenceChallenge {
            effect,
            component,
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
            expected_verifier_binding,
            verification_scope,
        })
    }

    /// Reports whether one component-local retirement requirement is durable.
    pub fn component_retirement_evidence_accepted(
        &self,
        effect: EffectId,
        component: ComponentId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
    ) -> Result<bool, CoreError> {
        let claim = self
            .state
            .composite_effects()
            .get(&effect)
            .and_then(|composite| composite.components.get(&component))
            .and_then(|component| component.claims.get(&claim_id))
            .ok_or(CoreError::UnknownClaim)?;
        claim
            .requirements
            .iter()
            .find(|requirement| requirement.kind == kind)
            .map(|requirement| requirement.accepted.is_some())
            .ok_or(CoreError::UnexpectedEvidence)
    }

    /// Verifies one raw receipt for an exact component-local claim.
    pub fn verify_component_retirement_evidence<V: ReceiptVerifier>(
        &self,
        effect: EffectId,
        component: ComponentId,
        claim_id: ClaimId,
        kind: EvidenceKindId,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedRetirementEvidence, CoreError> {
        let challenge = self.component_evidence_challenge(effect, component, claim_id, kind)?;
        let identity = verifier.identity();
        self.validate_verifier_identity(
            identity,
            challenge.expected_verifier(),
            challenge.expected_receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
        let observation = verifier
            .verify(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(observation.digest())?;
        Ok(VerifiedRetirementEvidence {
            effect,
            component,
            claim: claim_id,
            evidence: RetirementEvidence {
                kind,
                subject: observation.subject(),
                freshness: observation.observation(),
                stamp: VerifierStamp {
                    identity,
                    receipt_digest: observation.digest(),
                },
                verification_scope: challenge.verification_scope(),
            },
        })
    }

    /// Builds the exact challenge for one outstanding external commit intent.
    pub fn commit_outcome_challenge(
        &self,
        intent: &CommitIntent,
    ) -> Result<EffectFactChallenge, CoreError> {
        let component = intent.component;
        let composite = self
            .state
            .composite_effects()
            .get(&intent.effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if component_record.commit != CommitState::CommitIntentDurable
            || component_record.commit_nonce != Some(intent.nonce)
        {
            return Err(CoreError::StaleCommitIntent);
        }
        let operation = component_record
            .commit_operation
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = self.effect_catalog(intent.effect)?;
        let binding = catalog
            .obligation_rule(component_record.domain, component_record.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .commit_outcome();
        let verification_scope = self.scoped_verification_scope(
            intent.effect,
            component,
            binding.verifier(),
            binding.receipt_schema(),
        )?;
        let expected_verifier_binding = verification_scope.verifier_binding();
        Ok(EffectFactChallenge {
            kind: EffectFactKind::CommitOutcome,
            effect: intent.effect,
            component,
            domain: component_record.domain,
            obligation: component_record.obligation,
            actor: composite.causal_owner,
            generation: composite.authority_epoch,
            nonce: intent.nonce,
            operation,
            predecessor: None,
            current_observation: component_freshness(&self.state, composite, component_record)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            expected_verifier_binding,
            verification_scope,
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

    /// Verifies a canonical bounded child descriptor at the embedding's
    /// trust boundary.  The resulting value is opaque and cannot be recreated
    /// from a raw command request or external output bytes.
    pub fn verify_child_descriptor<V: ChildDescriptorVerifier>(
        &self,
        descriptor: ChildDescriptorV1,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedChildDescriptor, CoreError> {
        if !self.catalog.contains(descriptor.catalog_digest)
            || descriptor.route_digest.is_zero()
            || descriptor.input_digest.is_zero()
            || descriptor.units == 0
            || descriptor.child_effect().is_err()
        {
            return Err(CoreError::InvalidPayload);
        }
        let receipt_digest = verifier
            .verify_child_descriptor(descriptor, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(receipt_digest)?;
        Ok(VerifiedChildDescriptor {
            descriptor,
            receipt_digest,
        })
    }

    /// Builds the only recovery challenge that may resolve a fenced,
    /// indeterminate handoff parent. The descriptor is already opaque
    /// verifier-minted authority; this method only exposes its immutable
    /// canonical data to the separate recovery verifier.
    pub fn handoff_resolution_challenge(
        &self,
        descriptor: &VerifiedChildDescriptor,
    ) -> Result<HandoffResolutionChallenge, CoreError> {
        let descriptor = descriptor.descriptor;
        let operation_record = self
            .state
            .recovery_operations()
            .get(&descriptor.parent.operation())
            .ok_or(CoreError::UnknownEffect)?;
        let composite = self
            .state
            .composite_effects()
            .get(&descriptor.parent)
            .ok_or(CoreError::UnknownEffect)?;
        let component = composite
            .components
            .get(&descriptor.parent_component)
            .ok_or(CoreError::UnknownObligationClass)?;
        let operation_digest = component
            .commit_operation
            .ok_or(CoreError::WrongCommitState)?;
        let catalog = self.effect_catalog(descriptor.parent)?;
        if !matches!(
            operation_record.state,
            OperationRecoveryState::Fenced { .. }
        ) || composite.authority != AuthorityState::Fenced
            || composite.custodian != CustodyState::CoreOwned
            || !matches!(composite.handoff, SingleHopRole::None)
            || component.commit != CommitState::Committed
            || component.commit_nonce.is_some()
            || component.commit_fact.is_some()
            || component.outcome != OutcomeState::Indeterminate(operation_digest)
            || descriptor.catalog_digest != catalog.digest()
            || composite.catalog_digest != descriptor.catalog_digest
            || descriptor.parent != composite.effect
            || descriptor.child_effect().is_err()
            || !matches!(catalog.single_hop_handoff_rule(composite.kind), Some(rule) if rule.target() == descriptor.child_kind)
        {
            return Err(CoreError::HandoffGuardRequired);
        }
        let binding = catalog
            .obligation_rule(component.domain, component.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .commit_outcome();
        let verification_scope = self.scoped_verification_scope(
            descriptor.parent,
            descriptor.parent_component,
            binding.verifier(),
            binding.receipt_schema(),
        )?;
        Ok(HandoffResolutionChallenge {
            effect: descriptor.parent,
            component: descriptor.parent_component,
            domain: component.domain,
            obligation: component.obligation,
            operation: operation_digest,
            descriptor,
            current_observation: component_freshness(&self.state, composite, component)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            verification_scope,
        })
    }

    /// Verifies a terminal-success recovery receipt and binds it to an opaque
    /// child descriptor for [`VerifiedHandoffResolution::resolve`].
    pub fn verify_handoff_resolution<V: HandoffResolutionVerifier>(
        &self,
        descriptor: VerifiedChildDescriptor,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedHandoffResolution, CoreError> {
        let challenge = self.handoff_resolution_challenge(&descriptor)?;
        let identity = verifier.identity();
        self.validate_verifier_identity(
            identity,
            challenge.expected_verifier(),
            challenge.expected_receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
        let terminal_receipt_digest = verifier
            .verify_handoff_parent_success(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(terminal_receipt_digest)?;
        let fact = VerifiedHandoffRecoveryFact::from_challenge(
            HandoffRecoveryRole::Parent,
            challenge,
            VerifierStamp {
                identity,
                receipt_digest: terminal_receipt_digest,
            },
        );
        Ok(VerifiedHandoffResolution { descriptor, fact })
    }

    /// Builds the exact challenge for an already installed handoff child whose
    /// nonce was consumed by checkpoint recovery.
    pub fn handoff_child_resolution_challenge(
        &self,
        descriptor: &VerifiedChildDescriptor,
    ) -> Result<HandoffResolutionChallenge, CoreError> {
        let descriptor = descriptor.descriptor;
        let child = descriptor.child_effect()?;
        let operation_record = self
            .state
            .recovery_operations()
            .get(&child.operation())
            .ok_or(CoreError::UnknownEffect)?;
        let composite = self
            .state
            .composite_effects()
            .get(&child)
            .ok_or(CoreError::UnknownEffect)?;
        let component = composite
            .components
            .get(&descriptor.child_component)
            .ok_or(CoreError::UnknownObligationClass)?;
        let source = self
            .state
            .composite_effects()
            .get(&descriptor.parent)
            .ok_or(CoreError::UnknownEffect)?;
        let operation_digest = component
            .commit_operation
            .ok_or(CoreError::WrongCommitState)?;
        let catalog = self.effect_catalog(child)?;
        if !matches!(
            operation_record.state,
            OperationRecoveryState::Fenced { .. }
        ) || composite.authority != AuthorityState::Fenced
            || composite.custodian != CustodyState::CoreOwned
            || composite.catalog_digest != descriptor.catalog_digest
            || source.catalog_digest != descriptor.catalog_digest
            || !matches!(composite.handoff, SingleHopRole::Target { parent, descriptor_digest, recovery_fact: None } if parent == descriptor.parent && descriptor_digest == handoff_descriptor_digest(descriptor))
            || !matches!(&source.handoff, SingleHopRole::Source { descriptor: saved, .. } if **saved == descriptor)
            || component.commit != CommitState::Committed
            || component.commit_nonce.is_some()
            || component.commit_fact.is_some()
            || component.outcome != OutcomeState::Indeterminate(operation_digest)
        {
            return Err(CoreError::HandoffGuardRequired);
        }
        let binding = catalog
            .obligation_rule(component.domain, component.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .commit_outcome();
        let verification_scope = self.scoped_verification_scope(
            child,
            descriptor.child_component,
            binding.verifier(),
            binding.receipt_schema(),
        )?;
        Ok(HandoffResolutionChallenge {
            effect: child,
            component: descriptor.child_component,
            domain: component.domain,
            obligation: component.obligation,
            operation: operation_digest,
            descriptor,
            current_observation: component_freshness(&self.state, composite, component)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            verification_scope,
        })
    }

    /// Verifies a terminal-success receipt for the one installed fenced child.
    pub fn verify_handoff_child_resolution<V: HandoffChildResolutionVerifier>(
        &self,
        descriptor: VerifiedChildDescriptor,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedHandoffChildResolution, CoreError> {
        let challenge = self.handoff_child_resolution_challenge(&descriptor)?;
        let identity = verifier.identity();
        self.validate_verifier_identity(
            identity,
            challenge.expected_verifier(),
            challenge.expected_receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
        let terminal_receipt_digest = verifier
            .verify_handoff_child_success(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(terminal_receipt_digest)?;
        let fact = VerifiedHandoffRecoveryFact::from_challenge(
            HandoffRecoveryRole::Child,
            challenge,
            VerifierStamp {
                identity,
                receipt_digest: terminal_receipt_digest,
            },
        );
        Ok(VerifiedHandoffChildResolution { descriptor, fact })
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
        let component = claim.component;
        let composite = self
            .state
            .composite_effects()
            .get(&claim.effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if !component_claim_matches(component_record, claim)
            || !matches!(
                component_record.settlement,
                SettlementState::ApplyIntentDurable { .. } | SettlementState::Claimed { .. }
            )
        {
            return Err(CoreError::StaleSettlementClaim);
        }
        let operation = component_record
            .settlement_intent
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = self.effect_catalog(claim.effect)?;
        let binding = catalog
            .obligation_rule(component_record.domain, component_record.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .apply_completed()
            .ok_or(CoreError::WrongSettlementStage)?;
        let verification_scope = self.scoped_verification_scope(
            claim.effect,
            component,
            binding.verifier(),
            binding.receipt_schema(),
        )?;
        let expected_verifier_binding = verification_scope.verifier_binding();
        Ok(EffectFactChallenge {
            kind: EffectFactKind::ApplyCompleted,
            effect: claim.effect,
            component,
            domain: component_record.domain,
            obligation: component_record.obligation,
            actor: claim.claimant,
            generation: claim.generation,
            nonce: claim.nonce,
            operation,
            predecessor: None,
            current_observation: component_freshness(&self.state, composite, component_record)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            expected_verifier_binding,
            verification_scope,
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
        let component = claim.component;
        let composite = self
            .state
            .composite_effects()
            .get(&claim.effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if !component_claim_matches(component_record, claim)
            || !matches!(
                component_record.settlement,
                SettlementState::AppliedUnacknowledged { .. } | SettlementState::Claimed { .. }
            )
        {
            return Err(CoreError::StaleSettlementClaim);
        }
        let operation = component_record
            .settlement_intent
            .ok_or(CoreError::InvariantViolation)?;
        let predecessor = component_record
            .applied_fact
            .map(|fact| fact.stamp.receipt_digest)
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = self.effect_catalog(claim.effect)?;
        let binding = catalog
            .obligation_rule(component_record.domain, component_record.obligation)
            .ok_or(CoreError::UnknownObligationClass)?
            .receipts()
            .settlement_acknowledged()
            .ok_or(CoreError::WrongSettlementStage)?;
        let verification_scope = self.scoped_verification_scope(
            claim.effect,
            component,
            binding.verifier(),
            binding.receipt_schema(),
        )?;
        let expected_verifier_binding = verification_scope.verifier_binding();
        Ok(EffectFactChallenge {
            kind: EffectFactKind::SettlementAcknowledged,
            effect: claim.effect,
            component,
            domain: component_record.domain,
            obligation: component_record.obligation,
            actor: claim.claimant,
            generation: claim.generation,
            nonce: claim.nonce,
            operation,
            predecessor: Some(predecessor),
            current_observation: component_freshness(&self.state, composite, component_record)?,
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            expected_verifier_binding,
            verification_scope,
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
        self.validate_verifier_identity(
            identity,
            challenge.expected_verifier(),
            challenge.expected_receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
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
            component: challenge.component(),
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
            verification_scope: challenge.verification_scope(),
            outcome: observation.outcome(),
        })
    }

    /// Returns the aggregate digest of the immutable catalog set.
    pub const fn catalog_set_digest(&self) -> Digest {
        self.catalog.digest()
    }

    /// Returns the immutable catalog set protecting this engine.
    pub fn catalog_set(&self) -> &CatalogSet {
        &self.catalog
    }

    /// Returns the semantic world bound to this engine.
    pub const fn world(&self) -> WorldId {
        self.state.world
    }

    /// Returns the durable projection of one provider generation.
    pub fn provider_generation_projection(
        &self,
        coordinate: ProviderCoordinate,
    ) -> Option<ProviderGenerationProjection> {
        self.state
            .provider_generations()
            .get(&coordinate)
            .map(|record| ProviderGenerationProjection {
                coordinate: record.coordinate,
                catalog_digest: record.catalog_digest,
                verifier_set_digest: record.verifier_set_digest,
                verifier_bindings: record.verifier_bindings.clone(),
                artifact_receipts: record.artifact_receipts,
                state: record.state,
                live_component_bindings: record.live_component_bindings,
            })
    }

    /// Returns the durable state of one recovery-artifact lease.
    pub fn artifact_lease(
        &self,
        artifact: crate::RecoveryArtifactId,
    ) -> Option<ArtifactLeaseState> {
        self.state.artifact_leases().get(&artifact).copied()
    }

    /// Returns all component obligations retained by one exact provider
    /// generation. The result is a non-authorizing stable projection; it does
    /// not grant settlement, release, or execution authority.
    pub fn provider_obligations(&self, coordinate: ProviderCoordinate) -> Vec<ProviderObligation> {
        let mut obligations = Vec::new();
        for (effect, scoped) in self.state.scoped_composites() {
            for (component, provider) in &scoped.bindings {
                if *provider != coordinate {
                    continue;
                }
                let Some(composite) = self.state.composite_effects().get(effect) else {
                    continue;
                };
                let Some(record) = composite.components.get(component) else {
                    continue;
                };
                obligations.push(ProviderObligation {
                    provider: coordinate,
                    operation: effect.operation(),
                    catalog_digest: scoped.catalog_digest,
                    effect: *effect,
                    component: *component,
                    artifact: scoped.artifacts.get(component).copied(),
                    authority: composite.authority,
                    commit: record.commit,
                    outcome: record.outcome,
                    settlement: record.settlement,
                    retirement: record.retirement,
                });
            }
        }
        obligations
    }

    /// Returns all durable artifact recovery operations, including already
    /// released leases retained for audit and snapshot identity.
    pub fn artifact_recovery_items(&self) -> Vec<ArtifactRecoveryItem> {
        self.state
            .artifact_leases()
            .values()
            .map(|lease| ArtifactRecoveryItem {
                binding: lease.binding(),
                lease: *lease,
                releasable: matches!(lease, ArtifactLeaseState::ReleaseAuthorized { .. }),
            })
            .collect()
    }

    /// Returns only artifact operations whose release authorization is durable.
    pub fn releasable_artifacts(&self) -> Vec<ArtifactRecoveryItem> {
        self.artifact_recovery_items()
            .into_iter()
            .filter(|item| item.is_releasable())
            .collect()
    }

    /// Builds the exact pin challenge for a required artifact lease.
    pub fn artifact_pin_challenge(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<ArtifactPinChallenge, CoreError> {
        let scoped = self
            .state
            .scoped_composites()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let binding = scoped
            .artifacts
            .get(&component)
            .copied()
            .ok_or(CoreError::ArtifactRequired)?;
        if self
            .state
            .artifact_leases()
            .contains_key(&binding.artifact_id())
        {
            return Err(CoreError::ArtifactBindingMismatch);
        }
        let provider = scoped
            .bindings
            .get(&component)
            .ok_or(CoreError::ProviderBindingMismatch)?;
        if scoped.catalog_digest
            != self
                .state
                .provider_generations()
                .get(provider)
                .ok_or(CoreError::UnknownProviderGeneration)?
                .catalog_digest
            || !self.catalog.contains(scoped.catalog_digest)
        {
            return Err(CoreError::CatalogMismatch);
        }
        let receipts = self
            .state
            .provider_generations()
            .get(provider)
            .and_then(|record| record.artifact_receipts)
            .ok_or(CoreError::ArtifactVerifierMismatch)?;
        Ok(ArtifactPinChallenge::new(binding, receipts.pin()))
    }

    /// Verifies one exact artifact pin receipt and returns a non-forgeable
    /// command descriptor.
    pub fn verify_artifact_pin<V: ArtifactPinVerifier>(
        &self,
        effect: EffectId,
        component: ComponentId,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedArtifactPin, CoreError> {
        let challenge = self.artifact_pin_challenge(effect, component)?;
        self.validate_verifier_identity(
            verifier.identity(),
            challenge.expected_verifier_binding().verifier(),
            challenge.expected_verifier_binding().receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
        let pin_stamp = verifier
            .verify(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(pin_stamp)?;
        Ok(VerifiedArtifactPin {
            binding: challenge.binding(),
            pin_stamp,
        })
    }

    /// Returns the exact durable release challenge for an authorized lease.
    pub fn artifact_release_challenge(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<ArtifactReleaseChallenge, CoreError> {
        let scoped = self
            .state
            .scoped_composites()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let binding = scoped
            .artifacts
            .get(&component)
            .copied()
            .ok_or(CoreError::ArtifactRequired)?;
        let lease = self
            .state
            .artifact_leases()
            .get(&binding.artifact_id())
            .ok_or(CoreError::ArtifactNotPinned)?;
        let (pin_stamp, release_operation, nonce) = match lease {
            ArtifactLeaseState::ReleaseAuthorized {
                pin_stamp,
                release_operation,
                nonce,
                ..
            } => (*pin_stamp, *release_operation, *nonce),
            ArtifactLeaseState::Pinned { .. } => return Err(CoreError::ArtifactNotReleasable),
            ArtifactLeaseState::Released { .. } => return Err(CoreError::ArtifactReleaseMismatch),
        };
        let provider = scoped
            .bindings
            .get(&component)
            .ok_or(CoreError::ProviderBindingMismatch)?;
        if scoped.catalog_digest
            != self
                .state
                .provider_generations()
                .get(provider)
                .ok_or(CoreError::UnknownProviderGeneration)?
                .catalog_digest
            || !self.catalog.contains(scoped.catalog_digest)
        {
            return Err(CoreError::CatalogMismatch);
        }
        let receipts = self
            .state
            .provider_generations()
            .get(provider)
            .and_then(|record| record.artifact_receipts)
            .ok_or(CoreError::ArtifactVerifierMismatch)?;
        Ok(ArtifactReleaseChallenge::new(
            binding,
            pin_stamp,
            release_operation,
            nonce,
            receipts.release(),
        ))
    }

    /// Reissues the same durable release permit after recovery.
    pub fn artifact_release_permit(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<ArtifactReleasePermit, CoreError> {
        let challenge = self.artifact_release_challenge(effect, component)?;
        self.state
            .artifact_leases()
            .get(&challenge.binding().artifact_id())
            .and_then(|lease| lease.release_permit().ok())
            .ok_or(CoreError::ArtifactReleaseMismatch)
    }

    /// Verifies one exact artifact release receipt and returns a linear proof.
    pub fn verify_artifact_release<V: ArtifactReleaseVerifier>(
        &self,
        effect: EffectId,
        component: ComponentId,
        verifier: &V,
        receipt: &V::Receipt,
    ) -> Result<VerifiedArtifactRelease, CoreError> {
        let challenge = self.artifact_release_challenge(effect, component)?;
        self.validate_verifier_identity(
            verifier.identity(),
            challenge.expected_verifier_binding().verifier(),
            challenge.expected_verifier_binding().receipt_schema(),
            challenge.expected_verifier_binding(),
        )?;
        let release_stamp = verifier
            .verify(&challenge, receipt)
            .map_err(|_| CoreError::VerificationFailed)?;
        require_digest(release_stamp)?;
        let permit = self.artifact_release_permit(effect, component)?;
        Ok(VerifiedArtifactRelease {
            permit,
            release_stamp,
        })
    }

    /// Resolves the complete exact scope retained by one scoped component.
    /// all come from authoritative state; callers cannot supply replacements.
    fn scoped_verification_scope(
        &self,
        effect: EffectId,
        component: ComponentId,
        verifier: VerifierId,
        receipt_schema: ReceiptSchemaId,
    ) -> Result<ProviderVerificationScope, CoreError> {
        let Some(scope_source) = self
            .state
            .scoped_composites()
            .get(&effect)
            .map(|scoped| (scoped.catalog_digest, &scoped.bindings))
            .or_else(|| {
                self.state
                    .composite_effects()
                    .get(&effect)
                    .and_then(|composite| composite.released_provenance.as_ref())
                    .map(|provenance| (provenance.catalog_digest, &provenance.bindings))
            })
        else {
            return Err(CoreError::UnknownEffect);
        };
        let provider = *scope_source
            .1
            .get(&component)
            .ok_or(CoreError::ProviderBindingMismatch)?;
        let record = self
            .state
            .provider_generations()
            .get(&provider)
            .ok_or(CoreError::UnknownProviderGeneration)?;
        let binding = record
            .verifier_bindings
            .iter()
            .find(|binding| {
                binding.verifier() == verifier && binding.receipt_schema() == receipt_schema
            })
            .copied()
            .ok_or(CoreError::VerifierSetMismatch)?;
        let world = self.state.world();
        if world != provider.world()
            || scope_source.0 != record.catalog_digest
            || !self.catalog.contains(record.catalog_digest)
        {
            return Err(CoreError::ProviderBindingMismatch);
        }
        Ok(ProviderVerificationScope::new(
            world,
            provider,
            effect.operation(),
            record.catalog_digest,
            binding,
        ))
    }

    fn validate_verifier_identity(
        &self,
        identity: VerifierIdentity,
        expected_verifier: VerifierId,
        expected_receipt_schema: ReceiptSchemaId,
        expected_binding: VerifierBinding,
    ) -> Result<(), CoreError> {
        if identity.verifier() != expected_verifier {
            return Err(CoreError::UnknownVerifier);
        }
        if identity.receipt_schema() != expected_receipt_schema {
            return Err(CoreError::ReceiptSchemaMismatch);
        }
        if identity.implementation_digest() != expected_binding.implementation_digest() {
            return Err(CoreError::UnknownVerifier);
        }
        if identity.epoch() != expected_binding.generation().get() {
            return Err(CoreError::StaleVerifierEpoch);
        }
        Ok(())
    }

    /// Prepares, durably appends, and atomically swaps one transition.
    ///
    /// The persistence closure must append `record.bytes()` and complete the
    /// profile's durability barrier before returning success. It is invoked
    /// while no core state has changed. A persistence failure leaves the full
    /// semantic projection unchanged, but latches this engine into
    /// recovery-required state because the prepared record may already be
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
        self.transact_with_freshness(command, |record, _, _| persist(record))
    }

    /// Prepares and commits one transition through a typed durability provider.
    ///
    /// Unlike [`Self::transact`], this path also passes the prepared
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
        self.transact_with_freshness(command, |record, freshness, projection| {
            persistence.persist_transition(record, freshness, projection)
        })
    }

    /// Appends and anchors an internal whole-state checkpoint record.
    pub fn compact_checkpoint_durable<P>(
        &mut self,
        persistence: &mut P,
    ) -> Result<TransitionReceipt, TxError<P::Error>>
    where
        P: crate::TransitionDurability,
    {
        if self.state.recovery_target().is_some() {
            return Err(TxError::Core(CoreError::RecoveryPending));
        }
        if !state_within_limits(&self.state, self.limits) {
            return Err(TxError::Core(CoreError::CapacityExceeded));
        }
        // The image was produced from this immutable live state and is
        // validated against the full invariant/projection oracles before it
        // enters the durable boundary.  Keep that proof private so a caller
        // cannot use it to bypass decoding an arbitrary checkpoint image.
        let checkpoint =
            ValidatedCheckpointImage::from_live_state(&self.state, &self.catalog, self.limits)
                .map_err(TxError::Core)?;
        self.transact_with_validated_checkpoint(checkpoint, |record, freshness, projection| {
            persistence.persist_transition(record, freshness, projection)
        })
    }

    fn transact_with_freshness<E, P, C>(
        &mut self,
        command: C,
        persist: P,
    ) -> Result<TransitionReceipt, TxError<E>>
    where
        C: Into<Command>,
        P: FnOnce(&JournalRecord, Freshness, Digest) -> Result<(), E>,
    {
        self.transact_with_input(TransitionInput::Command(command.into()), persist)
    }

    fn transact_with_validated_checkpoint<E, P>(
        &mut self,
        checkpoint: ValidatedCheckpointImage,
        persist: P,
    ) -> Result<TransitionReceipt, TxError<E>>
    where
        P: FnOnce(&JournalRecord, Freshness, Digest) -> Result<(), E>,
    {
        self.transact_with_input(TransitionInput::ValidatedCheckpoint(checkpoint), persist)
    }

    fn transact_with_input<E, P>(
        &mut self,
        input: TransitionInput,
        persist: P,
    ) -> Result<TransitionReceipt, TxError<E>>
    where
        P: FnOnce(&JournalRecord, Freshness, Digest) -> Result<(), E>,
    {
        let prepared = self.prepare_input(input).map_err(|error| match error {
            PrepareError::Core(error) => TxError::Core(error),
            PrepareError::Journal(error) => TxError::Journal(error),
        })?;
        // Arm before entering user-controlled persistence.  A provider can
        // panic before writing anything, after appending bytes, or after its
        // barrier; all three cases are ambiguous to the core.  The latch is
        // cleared only after assignment-only publication has completed.
        self.persistence_recovery_required = true;
        #[cfg(feature = "std")]
        let persisted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            persist(
                &prepared.record,
                prepared.delta.freshness(self.state.freshness()),
                prepared.receipt.projection,
            )
        }));
        #[cfg(feature = "std")]
        let persisted = match persisted {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        #[cfg(not(feature = "std"))]
        let persisted = persist(
            &prepared.record,
            prepared.delta.freshness(self.state.freshness()),
            prepared.receipt.projection,
        );
        if let Err(error) = persisted {
            return Err(TxError::Persist(error));
        }
        let receipt = self.apply_prepared(prepared);
        self.persistence_recovery_required = false;
        Ok(receipt)
    }

    fn prepare_input(&self, input: TransitionInput) -> Result<PreparedTransition, PrepareError> {
        match input {
            TransitionInput::Command(command) => self.prepare_transition(command),
            TransitionInput::ValidatedCheckpoint(checkpoint) => {
                self.prepare_validated_checkpoint(checkpoint)
            }
        }
    }

    /// Executes all fallible semantic work for one transition.
    ///
    /// This includes applying and validating the prepared delta, constructing
    /// the journal record, and computing the projection and public output before
    /// persistence is entered. The prepared revision and head must be
    /// visible to the projection hash, because those coordinates are part of
    /// the authoritative projection.
    fn prepare_transition<C>(&self, command: C) -> Result<PreparedTransition, PrepareError>
    where
        C: Into<Command>,
    {
        let Command(command) = command.into();
        self.prepare_transition_inner(command, false)
    }

    fn prepare_validated_checkpoint(
        &self,
        checkpoint: ValidatedCheckpointImage,
    ) -> Result<PreparedTransition, PrepareError> {
        self.prepare_transition_inner(
            CommandKind::WholeStateCheckpointV1 {
                state: checkpoint.image,
                projection: checkpoint.projection,
            },
            true,
        )
    }

    fn prepare_transition_inner(
        &self,
        command: CommandKind,
        validated_checkpoint: bool,
    ) -> Result<PreparedTransition, PrepareError> {
        let coordinates = command.coordinates_for_state(&self.state);
        if self.journal_repair_required.is_some() {
            return Err(PrepareError::Core(CoreError::JournalRepairRequired));
        }
        if self.persistence_recovery_required {
            return Err(PrepareError::Core(CoreError::PersistenceRecoveryRequired));
        }
        if self.state.recovery_target().is_some()
            && !matches!(&command, CommandKind::CheckpointRecovery { .. })
        {
            return Err(PrepareError::Core(CoreError::RecoveryPending));
        }
        command
            .validate_wire_limits()
            .map_err(|_| PrepareError::Core(CoreError::CapacityExceeded))?;
        let command_catalog = self.command_catalog(&command).map_err(PrepareError::Core)?;
        let mut delta = DeltaBuilder::new(&self.state);
        let output = if validated_checkpoint {
            // `ValidatedCheckpointImage` can only be constructed from this
            // live state immediately above, after full invariant and
            // projection checks.  Its private path therefore skips decoding
            // the image it just encoded; all ordinary/replayed checkpoint
            // commands still go through the decoder below.
            AppliedOutput::none(TransitionEvent::RecoveryCheckpointed)
        } else {
            apply_command(
                &self.catalog,
                command_catalog,
                self.limits,
                &mut delta,
                &command,
            )
            .map_err(PrepareError::Core)?
        };
        // The mutation hooks on `DeltaBuilder` are the sole production source
        // of projection addresses.  In particular, an idempotent write is
        // still a touch: recovery overlays may intentionally write a value
        // equal to the primary value while changing the authenticated
        // projection envelope.
        let touches = delta.take_projection_touches();
        delta.set_total_claims(
            transition_total_claims(&self.state, &delta, &touches).map_err(PrepareError::Core)?,
        );
        #[cfg(feature = "full-invariant-oracle")]
        check_invariants_for_catalog_set(&self.catalog, self.limits, &delta)
            .map_err(PrepareError::Core)?;
        #[cfg(not(feature = "full-invariant-oracle"))]
        check_transition_local_invariants(
            command_catalog,
            self.limits,
            &self.state,
            &delta,
            &touches,
        )
        .map_err(PrepareError::Core)?;

        let world = self.state.world;
        let record = JournalRecord::build(
            self.state.revision(),
            self.state.freshness(),
            RecoveryBinding::new(
                crate::RecoveryProfile::current(),
                world,
                self.catalog.digest(),
                self.state.freshness().registry(),
            )
            .map_err(|_| PrepareError::Core(CoreError::SchemaMismatch))?,
            self.state.projection_cache().digest,
            self.state.head(),
            command,
        )
        .map_err(PrepareError::Journal)?;

        delta.set_revision(record.revision());
        delta.set_head(record.digest());
        refresh_projection_cache(&self.state, &mut delta, &touches, self.catalog.digest());
        let projection = delta.projection_cache().digest;
        let event = output.event;
        let output = output.into_public();
        let receipt = TransitionReceipt {
            core_api_profile: crate::CSER_CORE_API_PROFILE_VERSION,
            journal_schema: crate::JOURNAL_SCHEMA_VERSION,
            catalog_digest: self.catalog.digest(),
            projection_version: crate::PROJECTION_VERSION,
            trace_version: crate::NORMALIZED_TRACE_VERSION,
            revision: record.revision(),
            head: record.digest(),
            projection,
            coordinates,
            result: TransitionResult::Applied,
            event,
            output,
        };
        Ok(PreparedTransition {
            delta: delta.finish(),
            record,
            receipt,
        })
    }

    /// Publishes a transition after its journal record has become durable.
    ///
    /// The prepared delta and receipt contain all semantic work. Keep
    /// this path deliberately infallible and allocation-free: persistence has
    /// already crossed the only externally observable commit boundary.
    fn apply_prepared(&mut self, prepared: PreparedTransition) -> TransitionReceipt {
        let PreparedTransition {
            delta,
            record: _,
            receipt,
        } = prepared;
        delta.apply(&mut self.state);
        receipt
    }

    /// Executes an in-memory transition for test and model profiles.
    ///
    /// This API is deliberately absent from production builds. A production
    /// embedding must use [`Self::transact_durable`] so a successful core
    /// transition cannot become visible before its journal and anchor update.
    #[cfg(feature = "test-support")]
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
        catalog: CatalogSet,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
    ) -> Result<RecoveryReport, CoreError> {
        let world = anchor.world();
        Self::recover_with_world(catalog, limits, anchor, bytes, world)
    }

    fn recover_with_world(
        catalog: CatalogSet,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
        expected_world: WorldId,
    ) -> Result<RecoveryReport, CoreError> {
        if anchor.catalog_digest() != catalog.digest()
            || anchor.binding().profile() != crate::RecoveryProfile::current()
        {
            return Err(CoreError::SchemaMismatch);
        }
        if anchor.minimum_revision == 0 {
            reject_recognized_legacy_journal_prefix(bytes).map_err(CoreError::Journal)?;
            let journal_repair =
                (!bytes.is_empty()).then_some(JournalRepair::UnanchoredSuffix { offset: 0 });
            let mut engine = Self::new(
                expected_world,
                catalog,
                limits,
                anchor.committed_freshness(),
            );
            if engine.projection_digest() != anchor.projection() {
                return Err(CoreError::RollbackDetected);
            }
            engine.state.recovery_target = Some(anchor.next_freshness);
            engine.journal_repair_required = journal_repair;
            return Ok(RecoveryReport {
                acknowledged_revision: 0,
                acknowledged_head: Digest::ZERO,
                journal_repair,
                engine,
            });
        }
        // Stop decoding as soon as the trusted head is found.  A complete
        // checksum-valid suffix is not authoritative and must not be
        // materialized merely to discover that it follows the anchor.
        let scan = scan_journal_to_head(bytes, anchor.expected_head())
            .map_err(CoreError::Journal)?
            .ok_or(CoreError::RollbackDetected)?;
        let accepted_count = scan.records().len();
        let journal_repair = scan
            .torn_tail()
            .map(|offset| JournalRepair::TornTail { offset })
            .or_else(|| {
                scan.unanchored_suffix()
                    .map(|offset| JournalRepair::UnanchoredSuffix { offset })
            });
        let records = &scan.records()[..accepted_count];
        let first = records.first().ok_or(CoreError::RollbackDetected)?;
        if first.catalog_digest() != catalog.digest()
            || first.registry() != anchor.committed_freshness().registry()
        {
            return Err(CoreError::SchemaMismatch);
        }
        let initial = Freshness::new(
            first.boot(),
            first.registry(),
            first.device(),
            first.journal(),
        );
        let mut engine = Self::new(expected_world, catalog, limits, initial);

        replay_records(&mut engine, records, anchor.binding(), expected_world)?;

        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state)?;
        let rebuilt_projection = build_projection_cache(&engine.state, engine.catalog.digest());
        if rebuilt_projection.digest != engine.projection_digest() {
            return Err(CoreError::InvariantViolation);
        }
        engine.state.projection_cache = rebuilt_projection;

        if engine.state.revision() < anchor.minimum_revision {
            return Err(CoreError::RollbackDetected);
        }
        if anchor.expected_head() != engine.state.head() {
            return Err(CoreError::RollbackDetected);
        }
        if engine.state.freshness() != anchor.committed_freshness() {
            return Err(CoreError::FreshnessRollback);
        }
        if engine.projection_digest() != anchor.projection() {
            return Err(CoreError::RollbackDetected);
        }
        let target = anchor.next_freshness;
        if target.registry() != engine.state.freshness().registry()
            || target.boot().get() <= engine.state.freshness().boot().get()
            || target.journal().get() <= engine.state.freshness().journal().get()
            || target.device().get() < engine.state.freshness().device().get()
        {
            return Err(CoreError::FreshnessRollback);
        }
        engine.state.recovery_target = Some(target);
        quarantine_live_device_claims(&mut engine.state);
        engine.journal_repair_required = journal_repair;

        Ok(RecoveryReport {
            acknowledged_revision: engine.state.revision(),
            acknowledged_head: engine.state.head(),
            journal_repair,
            engine,
        })
    }

    /// Returns the shared parent projection of one composite effect.
    pub fn composite_effect(&self, effect: EffectId) -> Option<CompositeEffectProjection> {
        self.state
            .composite_effects()
            .get(&effect)
            .map(|composite| project_composite_effect(composite, &self.state))
    }

    /// Returns one component-local obligation projection.
    pub fn component(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Option<ComponentProjection> {
        self.state
            .composite_effects()
            .get(&effect)
            .and_then(|composite| composite.components.get(&component))
            .map(|record| project_component(effect, record))
    }

    /// Returns every claim for one exact component in stable claim-id order.
    pub fn component_claims(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<Vec<ComponentClaimProjection>, CoreError> {
        let component_record = self
            .state
            .composite_effects()
            .get(&effect)
            .and_then(|composite| composite.components.get(&component))
            .ok_or(CoreError::UnknownEffect)?;
        Ok(component_record
            .claims
            .values()
            .map(|claim| project_component_claim(effect, component, claim))
            .collect())
    }

    /// Enumerates every retained component-local claim in stable order.
    pub fn retained_component_claims(&self) -> Vec<ComponentClaimProjection> {
        self.state
            .composite_effects()
            .iter()
            .flat_map(|(effect, composite)| {
                composite
                    .components
                    .iter()
                    .flat_map(move |(component, record)| {
                        record
                            .claims
                            .values()
                            .filter(|claim| !claim.retired)
                            .map(move |claim| project_component_claim(*effect, *component, claim))
                    })
            })
            .collect()
    }

    /// Returns a operation recovery projection.
    pub fn operation(&self, operation: OperationId) -> Option<OperationRecoveryState> {
        self.state
            .recovery_operations()
            .get(&operation)
            .map(|record| record.state)
    }

    /// Returns the exact component commit intents which remain durable but
    /// unacknowledged for one composite effect.
    ///
    /// This is deliberately a recovery projection, not a constructor: callers
    /// can only obtain nonces and operations already durably recorded by
    /// [`CommandRequest::RecordCompositeCommitIntents`].  It lets a successor
    /// complete a crash-interrupted acknowledgement cohort without attempting
    /// to record a second cohort over non-`Prepared` components.
    pub fn outstanding_component_commit_intents(
        &self,
        effect: EffectId,
    ) -> Result<Vec<CommitIntent>, CoreError> {
        let composite = self
            .state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        Ok(composite
            .components
            .iter()
            .filter_map(|(component, record)| {
                (record.commit == CommitState::CommitIntentDurable)
                    .then_some(record.commit_nonce)
                    .flatten()
                    .map(|nonce| CommitIntent {
                        effect,
                        component: *component,
                        nonce,
                    })
            })
            .collect())
    }

    /// Generates an exact, ordered and non-authorizing recovery cohort for one
    /// fenced operation. The caller may inspect the cohort before consuming it into
    /// [`RecoverySnapshot::record`].
    pub fn snapshot_operation(
        &self,
        operation: OperationId,
        snapshot: SnapshotId,
    ) -> Result<RecoverySnapshot, CoreError> {
        if !self
            .state
            .composite_effects()
            .keys()
            .any(|effect| effect.operation() == operation)
        {
            return Err(CoreError::UnknownOperation);
        }
        build_recovery_snapshot(&self.catalog, &self.state, operation, snapshot)
    }

    /// Returns retained charging for one exact account and credit class.
    pub fn charge(&self, account: ChargeAccountId, class: CreditClassId) -> ChargeProjection {
        ChargeProjection {
            account,
            class,
            retained_units: self
                .state
                .charges()
                .get(&(account, class))
                .copied()
                .unwrap_or(0),
        }
    }

    /// Returns the bounded global pressure projection.
    pub fn pressure(&self) -> PressureProjection {
        PressureProjection {
            operations: self.state.recovery_operations().len(),
            composites: self.state.composite_effects().len(),
            retained_claims: self
                .state
                .composite_effects()
                .values()
                .flat_map(|composite| composite.components.values())
                .map(|component| {
                    component
                        .claims
                        .values()
                        .filter(|claim| !claim.retired)
                        .count()
                })
                .sum::<usize>(),
            quarantined: self.journal_repair_required.is_some()
                || !self.state.device_quarantine().is_empty(),
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
    /// transact [`CommandKind::ReserveComponentReuse`] and consume its returned
    /// [`ReusePermit`] when enrolling the next claim.
    pub fn check_reusable(
        &self,
        resource: ResourceId,
        expected_generation: ResourceGeneration,
    ) -> Result<(), CoreError> {
        if self.state.recovery_target().is_some() {
            return Err(CoreError::RecoveryPending);
        }
        match self.state.resources().get(&resource) {
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

    /// Reports whether one further claim may be enrolled against a live
    /// resource coordinate under the catalog's admission algebra.
    ///
    /// This read-only precheck is never authority. It evaluates only the
    /// catalog-bound scope, generation, quarantine, and conflict conditions;
    /// callers must still transact enrollment to check authority, cardinality,
    /// credit, and races. Unlike [`Engine::check_reusable`], it asks whether a
    /// custodian may join a live coordinate rather than whether reuse is safe.
    pub fn check_co_claimable(
        &self,
        effect: EffectId,
        domain: DomainId,
        kind: ClaimKindId,
        scope: ClaimScope,
        resource: ResourceId,
        expected_generation: ResourceGeneration,
    ) -> Result<(), CoreError> {
        if self.state.recovery_target().is_some() {
            return Err(CoreError::RecoveryPending);
        }
        let catalog = self.effect_catalog(effect)?;
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
        if scope_is_quarantined(&self.state, scope) {
            return Err(CoreError::Quarantined);
        }
        match self.state.resources().get(&resource) {
            None if expected_generation.get() == 1 => Ok(()),
            None => Err(CoreError::StaleResourceGeneration),
            Some(ResourceRecord { generation, .. }) if *generation != expected_generation => {
                Err(CoreError::StaleResourceGeneration)
            }
            Some(ResourceRecord {
                scope: existing, ..
            }) if *existing != scope => Err(CoreError::WrongClaimScope),
            Some(ResourceRecord { scope, .. }) if scope_is_quarantined(&self.state, *scope) => {
                Err(CoreError::Quarantined)
            }
            Some(ResourceRecord {
                phase: ResourcePhase::Retired,
                ..
            })
            | Some(ResourceRecord {
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: Some(_),
                    },
                ..
            }) => Err(CoreError::ResourceReuseRequired),
            Some(ResourceRecord {
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: None,
                    },
                ..
            }) => {
                if !resource_allows_additional_custodian(
                    self.catalog_set(),
                    &self.state,
                    resource,
                    expected_generation,
                    rule.conflict(),
                )? {
                    Err(CoreError::ResourceRetained)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Builds a linear reissue request for one component-local reuse
    /// reservation after explicit composite-effect adoption.
    pub fn reclaim_component_resource_reuse(
        &self,
        effect: EffectId,
        component: ComponentId,
        actor: ExecutorCoordinate,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
    ) -> Result<Command, CoreError> {
        if self.state.recovery_target().is_some() {
            return Err(CoreError::RecoveryPending);
        }
        require_active_composite_actor(&self.state, effect, actor)?;
        let composite = self
            .state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        let record = self
            .state
            .resources()
            .get(&resource)
            .ok_or(CoreError::UnknownResource)?;
        if record.generation != resource_generation {
            return Err(CoreError::StaleResourceGeneration);
        }
        if scope_is_quarantined(&self.state, record.scope) {
            return Err(CoreError::Quarantined);
        }
        let pending = match record.phase {
            ResourcePhase::Claimed {
                pending_reuse: Some(pending),
            } if pending.effect == effect && pending.component == component => pending,
            _ => return Err(CoreError::StaleReusePermit),
        };
        let claim_record = component_record
            .claims
            .get(&pending.claim)
            .ok_or(CoreError::UnknownClaim)?;
        if claim_record.retired
            || claim_record.resource != resource
            || claim_record.resource_generation != resource_generation
        {
            return Err(CoreError::UnknownClaim);
        }
        Ok(Command(CommandKind::ReclaimResourceReuse {
            effect,
            component,
            actor,
            authority_epoch: composite.authority_epoch,
            claim: pending.claim,
            resource,
            resource_generation,
        }))
    }

    /// Computes a deterministic digest over the authoritative projection.
    pub fn projection_digest(&self) -> Digest {
        self.state.projection_cache().digest
    }

    /// Creates a canonical exact-replay checkpoint for the current journal prefix.
    ///
    /// Checkpoint creation is intentionally refused while recovery is pending:
    /// a replacement image must describe an already checkpointed freshness
    /// epoch, never the half-recovered state which still needs its durable
    /// `CheckpointRecovery` transition. The result is an envelope containing
    /// the original records verbatim, not a compact private-state codec.
    pub fn journal_checkpoint(&self, journal_image: &[u8]) -> Result<JournalCheckpoint, CoreError> {
        if self.state.recovery_target().is_some() {
            return Err(CoreError::RecoveryPending);
        }
        if self.persistence_recovery_required {
            return Err(CoreError::PersistenceRecoveryRequired);
        }
        if self.journal_repair_required.is_some() {
            return Err(CoreError::JournalRepairRequired);
        }
        let checkpoint = JournalCheckpoint::build(
            RecoveryBinding::new(
                crate::RecoveryProfile::current(),
                self.state.world(),
                self.catalog.digest(),
                self.state.freshness().registry(),
            )
            .map_err(|_| CoreError::SchemaMismatch)?,
            self.state.freshness(),
            self.state.revision(),
            self.state.head(),
            self.projection_digest(),
            journal_image,
        )
        .map_err(CoreError::JournalCheckpoint)?;
        let rebuilt = Self::validate_journal_checkpoint_for_world(
            self.catalog.clone(),
            self.limits,
            &checkpoint,
            self.state.world(),
        )?;
        if rebuilt.projection_digest() != self.projection_digest() {
            return Err(CoreError::InvariantViolation);
        }
        Ok(checkpoint)
    }

    /// Recovers a journal checkpoint after one full replay/validation pass.
    ///
    /// This is crate-private so callers cannot supply an unvalidated state or
    /// bypass the checkpoint envelope and exact trusted-anchor coordinates.
    /// The checkpoint image is replayed by
    /// [`Self::validate_journal_checkpoint_for_world`], then this method only
    /// installs the post-replay recovery overlay while retaining the trusted
    /// projection cache as the recovery base.
    pub(crate) fn recover_validated_journal_checkpoint(
        catalog: CatalogSet,
        limits: CoreLimits,
        checkpoint: &JournalCheckpoint,
        anchor: RecoveryAnchor,
    ) -> Result<RecoveryReport, CoreError> {
        let expected = checkpoint.anchor();
        if anchor.binding() != expected.binding()
            || anchor.catalog_digest() != expected.catalog_digest()
            || anchor.committed_freshness() != expected.freshness()
            || anchor.minimum_revision() != expected.revision()
            || anchor.expected_head() != expected.head()
            || anchor.projection() != expected.projection()
        {
            return Err(CoreError::RollbackDetected);
        }

        let expected_world = anchor.world();
        let mut engine = Self::validate_journal_checkpoint_for_world(
            catalog,
            limits,
            checkpoint,
            expected_world,
        )?;
        let target = anchor.next_freshness();
        let current = engine.state.freshness();
        if target.registry() != current.registry()
            || target.boot().get() <= current.boot().get()
            || target.journal().get() <= current.journal().get()
            || target.device().get() < current.device().get()
        {
            return Err(CoreError::FreshnessRollback);
        }

        // Keep the validated trusted projection cache unchanged. The target
        // and quarantine are a transient primary-state overlay; the durable
        // CheckpointRecovery transition will later rebuild and publish its
        // post-checkpoint projection.
        engine.state.recovery_target = Some(target);
        quarantine_live_device_claims(&mut engine.state);

        Ok(RecoveryReport {
            acknowledged_revision: engine.state.revision(),
            acknowledged_head: engine.state.head(),
            journal_repair: None,
            engine,
        })
    }

    fn validate_journal_checkpoint_for_world(
        catalog: CatalogSet,
        limits: CoreLimits,
        checkpoint: &JournalCheckpoint,
        expected_world: WorldId,
    ) -> Result<Self, CoreError> {
        let anchor = checkpoint.anchor();
        if anchor.catalog_digest() != catalog.digest()
            || anchor.binding().profile() != crate::RecoveryProfile::current()
        {
            return Err(CoreError::SchemaMismatch);
        }
        let scan = scan_journal(checkpoint.image()).map_err(CoreError::Journal)?;
        if scan.torn_tail().is_some() || scan.unanchored_suffix().is_some() {
            return Err(CoreError::RollbackDetected);
        }
        if anchor.revision() == 0 {
            if !scan.records().is_empty() {
                return Err(CoreError::RevisionConflict);
            }
            let engine = Self::new(expected_world, catalog, limits, anchor.freshness());
            if !anchor.head().is_zero() || engine.projection_digest() != anchor.projection() {
                return Err(CoreError::RollbackDetected);
            }
            return Ok(engine);
        }
        let first = scan.records().first().ok_or(CoreError::RollbackDetected)?;
        if first.catalog_digest() != catalog.digest()
            || first.registry() != anchor.freshness().registry()
        {
            return Err(CoreError::SchemaMismatch);
        }
        let initial = Freshness::new(
            first.boot(),
            first.registry(),
            first.device(),
            first.journal(),
        );
        let mut engine = Self::new(expected_world, catalog, limits, initial);
        replay_records(
            &mut engine,
            scan.records(),
            anchor.binding(),
            expected_world,
        )?;
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state)?;
        let rebuilt_projection = build_projection_cache(&engine.state, engine.catalog.digest());
        if rebuilt_projection.digest != engine.projection_digest() {
            return Err(CoreError::InvariantViolation);
        }
        engine.state.projection_cache = rebuilt_projection;
        if engine.state.revision() != anchor.revision()
            || engine.state.head() != anchor.head()
            || engine.state.freshness() != anchor.freshness()
            || engine.state.recovery_target().is_some()
            || engine.projection_digest() != anchor.projection()
        {
            return Err(CoreError::RollbackDetected);
        }
        Ok(engine)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum OutputData {
    None,
    CommitIntent {
        effect: EffectId,
        component: ComponentId,
        nonce: u64,
    },
    CompositeCommitIntents {
        effect: EffectId,
        intents: Vec<(ComponentId, u64)>,
    },
    Settlement {
        effect: EffectId,
        component: ComponentId,
        claimant: ExecutorCoordinate,
        generation: u64,
        nonce: u64,
        stage: ClaimStage,
    },
    ReusePermit {
        effect: EffectId,
        component: ComponentId,
        actor: ExecutorCoordinate,
        authority_epoch: u64,
        claim: ClaimId,
        resource: ResourceId,
        previous_generation: ResourceGeneration,
        generation: ResourceGeneration,
        catalog_digest: Digest,
        retirement_digest: Digest,
        reuse_contract: Digest,
        freshness: Freshness,
        nonce: u64,
    },
    ArtifactReleasePermit {
        binding: ArtifactBinding,
        pin_stamp: Digest,
        release_operation: OperationId,
        nonce: u64,
    },
}

#[derive(Debug, Eq, PartialEq)]
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
            OutputData::CommitIntent {
                effect,
                component,
                nonce,
            } => TransitionOutput::CommitIntent(CommitIntent {
                effect,
                component,
                nonce,
            }),
            OutputData::CompositeCommitIntents { effect, intents } => {
                TransitionOutput::CompositeCommitIntents(
                    intents
                        .into_iter()
                        .map(|(component, nonce)| CommitIntent {
                            effect,
                            component,
                            nonce,
                        })
                        .collect(),
                )
            }
            OutputData::Settlement {
                effect,
                component,
                claimant,
                generation,
                nonce,
                stage,
            } => TransitionOutput::SettlementClaim(SettlementClaim {
                effect,
                component,
                claimant,
                generation,
                nonce,
                stage,
            }),
            OutputData::ReusePermit {
                effect,
                component,
                actor,
                authority_epoch,
                claim,
                resource,
                previous_generation,
                generation,
                catalog_digest,
                retirement_digest,
                reuse_contract,
                freshness,
                nonce,
            } => TransitionOutput::ReusePermit(ReusePermit {
                effect,
                component,
                actor,
                authority_epoch,
                claim,
                resource,
                previous_generation,
                generation,
                catalog_digest,
                retirement_digest,
                reuse_contract,
                freshness,
                nonce,
            }),
            OutputData::ArtifactReleasePermit {
                binding,
                pin_stamp,
                release_operation,
                nonce,
            } => TransitionOutput::ArtifactReleasePermit(ArtifactReleasePermit::from_parts(
                binding,
                pin_stamp,
                release_operation,
                nonce,
            )),
        }
    }
}

fn apply_structural_command<S: StateAccessMut>(
    catalogs: &CatalogSet,
    limits: CoreLimits,
    state: &mut S,
    command: &CommandKind,
) -> Result<AppliedOutput, CoreError> {
    match command {
        CommandKind::FenceExecutor { operation, crashed } => {
            apply_fence_incarnation(
                state,
                *operation,
                *crashed,
                limits.max_crashes_per_operation,
            )?;
            Ok(AppliedOutput::none(TransitionEvent::ExecutorFenced))
        }
        CommandKind::Snapshot {
            operation,
            snapshot,
            digest,
        } => {
            require_digest(*digest)?;
            let expected = build_recovery_snapshot(catalogs, state, *operation, *snapshot)?;
            if expected.digest != *digest {
                return Err(CoreError::StaleSnapshot);
            }
            state.touch_operation(*operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(operation)
                .ok_or(CoreError::UnknownOperation)?;
            if matches!(
                operation_record.state,
                OperationRecoveryState::RecoveryExhausted { .. }
            ) {
                return Err(CoreError::RecoveryExhausted);
            }
            if !matches!(
                operation_record.state,
                OperationRecoveryState::Fenced { .. }
            ) {
                return Err(CoreError::WrongRecoveryState);
            }
            operation_record.state = OperationRecoveryState::Snapshotted {
                snapshot: *snapshot,
                digest: *digest,
            };
            Ok(AppliedOutput::none(TransitionEvent::Snapshot))
        }
        CommandKind::WholeStateCheckpointV1 {
            state: image,
            projection,
        } => {
            let rebuilt = decode_whole_state_checkpoint(image, catalogs, limits)?;
            if rebuilt.recovery_target.is_some()
                || rebuilt.projection_cache.digest != *projection
                || !checkpoint_state_matches(state, &rebuilt)
            {
                return Err(CoreError::InvariantViolation);
            }
            Ok(AppliedOutput::none(TransitionEvent::RecoveryCheckpointed))
        }
        CommandKind::CheckpointRecovery {
            boot,
            journal,
            device,
        } => {
            let target = state
                .recovery_target()
                .ok_or(CoreError::WrongRecoveryState)?;
            if target.boot() != *boot
                || target.journal() != *journal
                || target.device() != *device
                || target.registry() != state.freshness().registry()
                || state
                    .device_generations()
                    .values()
                    .any(|generation| *generation > *device)
            {
                return Err(CoreError::FreshnessRollback);
            }
            let operations: Vec<OperationId> =
                state.recovery_operations().keys().copied().collect();
            for operation in operations {
                state.touch_operation(operation);
                fence_operation_for_boot(state, operation, limits.max_crashes_per_operation)?;
            }
            state.freshness_mut().set_boot_and_journal(*boot, *journal);
            state.freshness_mut().set_device(*device);
            let device_scopes: Vec<DeviceScopeId> =
                state.device_generations().keys().copied().collect();
            for scope in device_scopes {
                state.touch_device(scope);
                *state
                    .device_generations_mut()
                    .get_mut(&scope)
                    .expect("scope was collected from device generations") = *device;
            }
            quarantine_live_device_claims(state);
            state.set_recovery_target(None);
            Ok(AppliedOutput::none(TransitionEvent::RecoveryCheckpointed))
        }
        CommandKind::Ready {
            operation,
            snapshot,
            successor,
        } => {
            state.touch_operation(*operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(operation)
                .ok_or(CoreError::UnknownOperation)?;
            let expected = match operation_record.state {
                OperationRecoveryState::Snapshotted {
                    snapshot: expected, ..
                } => expected,
                OperationRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if expected != *snapshot {
                return Err(CoreError::StaleSnapshot);
            }
            if successor.executor() != operation_record.origin.executor()
                || successor.generation() <= operation_record.last_executor.generation()
            {
                return Err(CoreError::StaleExecutor);
            }
            operation_record.state = OperationRecoveryState::Ready {
                snapshot: *snapshot,
                successor: *successor,
            };
            Ok(AppliedOutput::none(TransitionEvent::Ready))
        }
        CommandKind::Rebind {
            operation,
            snapshot,
            successor,
        } => {
            state.touch_operation(*operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(operation)
                .ok_or(CoreError::UnknownOperation)?;
            match operation_record.state {
                OperationRecoveryState::Ready {
                    snapshot: expected,
                    successor: expected_successor,
                } if expected == *snapshot && expected_successor == *successor => {}
                OperationRecoveryState::Ready { .. } => return Err(CoreError::StaleSnapshot),
                OperationRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            }
            if successor.generation() <= operation_record.last_executor.generation() {
                return Err(CoreError::StaleExecutor);
            }
            operation_record.last_executor = *successor;
            operation_record.state = OperationRecoveryState::Rebound {
                successor: *successor,
            };
            Ok(AppliedOutput::none(TransitionEvent::Rebound))
        }
        _ => Err(CoreError::InvariantViolation),
    }
}

fn apply_command<S: StateAccessMut>(
    catalogs: &CatalogSet,
    catalog: Option<&DomainCatalog>,
    limits: CoreLimits,
    state: &mut S,
    command: &CommandKind,
) -> Result<AppliedOutput, CoreError> {
    if matches!(
        command,
        CommandKind::CheckpointRecovery { .. }
            | CommandKind::WholeStateCheckpointV1 { .. }
            | CommandKind::Snapshot { .. }
            | CommandKind::FenceExecutor { .. }
            | CommandKind::Ready { .. }
            | CommandKind::Rebind { .. }
    ) {
        return apply_structural_command(catalogs, limits, state, command);
    }
    let catalog = catalog.ok_or(CoreError::SchemaMismatch)?;
    apply_command_internal(catalogs, catalog, limits, state, command)
}

/// Applies one command. Composite records are created only by the scoped
/// admission and verified handoff paths below; no unbound constructor is
/// replayable or available through the request surface.
fn apply_command_internal<S: StateAccessMut>(
    catalogs: &CatalogSet,
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut S,
    command: &CommandKind,
) -> Result<AppliedOutput, CoreError> {
    enforce_scoped_provider_gate(state, command)?;
    match command.clone() {
        CommandKind::RegisterProviderGeneration {
            coordinate,
            catalog_digest,
            mut verifier_bindings,
        } => {
            if state.world() != coordinate.world() {
                return Err(CoreError::WorldMismatch);
            }
            if catalog_digest != catalog.digest()
                || state.provider_generations().contains_key(&coordinate)
            {
                return Err(CoreError::ProviderGenerationStale);
            }
            if state
                .provider_high_water()
                .get(&coordinate.provider())
                .is_some_and(|generation| coordinate.generation() <= *generation)
            {
                return Err(CoreError::ProviderGenerationStale);
            }
            if state.provider_generations().len() >= limits.max_provider_generations
                || (!state
                    .provider_high_water()
                    .contains_key(&coordinate.provider())
                    && state.provider_high_water().len() >= limits.max_provider_high_water)
            {
                return Err(CoreError::CapacityExceeded);
            }
            let required = catalog.verifier_class_bindings();
            let required: Vec<_> = required.into_iter().collect();
            let verifier_set_digest = validate_verifier_set(&verifier_bindings, &required)
                .map_err(|_| CoreError::VerifierSetMismatch)?;
            verifier_bindings.sort_unstable_by(|left, right| {
                left.class_binding()
                    .cmp(&right.class_binding())
                    .then_with(|| left.cmp(right))
            });
            state.touch_provider_high_water(coordinate.provider());
            state
                .provider_high_water_mut()
                .insert_mut(coordinate.provider(), coordinate.generation());
            state.touch_provider_generation(coordinate);
            state.provider_generations_mut().insert_mut(
                coordinate,
                ProviderGenerationRecord {
                    coordinate,
                    catalog_digest,
                    verifier_set_digest,
                    verifier_bindings,
                    artifact_receipts: None,
                    state: ProviderEffectState::Active,
                    live_component_bindings: 0,
                },
            );
            Ok(AppliedOutput::none(
                TransitionEvent::ProviderGenerationRegistered,
            ))
        }
        CommandKind::BindArtifactReceiptVerifiers {
            coordinate,
            receipts,
        } => {
            if state.world() != coordinate.world() {
                return Err(CoreError::WorldMismatch);
            }
            state.touch_provider_generation(coordinate);
            let record = state
                .provider_generations_mut()
                .get_mut(&coordinate)
                .ok_or(CoreError::UnknownProviderGeneration)?;
            if !matches!(record.state, ProviderEffectState::Active)
                || record.artifact_receipts.is_some()
                || record.live_component_bindings != 0
            {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            record.artifact_receipts = Some(receipts);
            Ok(AppliedOutput::none(
                TransitionEvent::ArtifactReceiptVerifiersBound,
            ))
        }
        CommandKind::RecordArtifactPin { binding, pin_stamp } => {
            require_digest(pin_stamp)?;
            validate_artifact_binding(catalog, state, binding)?;
            if state.artifact_leases().contains_key(&binding.artifact_id()) {
                return Err(CoreError::ArtifactBindingMismatch);
            }
            if state.artifact_leases().len() >= limits.max_artifact_leases {
                return Err(CoreError::CapacityExceeded);
            }
            let lease = ArtifactLeaseState::pin(binding, pin_stamp)
                .map_err(|_| CoreError::ArtifactBindingMismatch)?;
            state.touch_artifact_lease(binding.artifact_id());
            state
                .artifact_leases_mut()
                .insert_mut(binding.artifact_id(), lease);
            Ok(AppliedOutput::none(TransitionEvent::ArtifactPinned))
        }
        CommandKind::AuthorizeArtifactRelease { effect, component } => {
            let binding = state
                .scoped_composites()
                .get(&effect)
                .and_then(|scoped| scoped.artifacts.get(&component))
                .copied()
                .ok_or(CoreError::ArtifactRequired)?;
            let composite = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            let record = composite
                .components
                .get(&component)
                .ok_or(CoreError::UnknownObligationClass)?;
            if record.retirement != RetirementState::Retired
                || !matches!(
                    record.settlement,
                    SettlementState::Settled
                        | SettlementState::Revoked
                        | SettlementState::NotRequired
                )
            {
                return Err(CoreError::ArtifactNotReleasable);
            }
            let nonce = allocate_nonce(state)?;
            let release_operation =
                OperationId::new(nonce).map_err(|_| CoreError::GenerationExhausted)?;
            let lease = state
                .artifact_leases()
                .get(&binding.artifact_id())
                .copied()
                .ok_or(CoreError::ArtifactNotPinned)?;
            let (next, permit) = lease
                .authorize_release(release_operation, nonce)
                .map_err(|_| CoreError::ArtifactNotReleasable)?;
            state.touch_artifact_lease(binding.artifact_id());
            state
                .artifact_leases_mut()
                .insert_mut(binding.artifact_id(), next);
            Ok(AppliedOutput {
                event: TransitionEvent::ArtifactReleaseAuthorized,
                output: OutputData::ArtifactReleasePermit {
                    binding,
                    pin_stamp: permit.pin_stamp(),
                    release_operation: permit.release_operation(),
                    nonce: permit.nonce(),
                },
            })
        }
        CommandKind::RecordArtifactRelease {
            binding,
            pin_stamp,
            release_operation,
            nonce,
            release_stamp,
        } => {
            require_digest(release_stamp)?;
            validate_artifact_binding(catalog, state, binding)?;
            let lease = state
                .artifact_leases()
                .get(&binding.artifact_id())
                .copied()
                .ok_or(CoreError::ArtifactNotPinned)?;
            let permit =
                ArtifactReleasePermit::from_parts(binding, pin_stamp, release_operation, nonce);
            let next = lease
                .confirm_release(permit, release_stamp)
                .map_err(|_| CoreError::ArtifactReleaseMismatch)?;
            state.touch_artifact_lease(binding.artifact_id());
            state
                .artifact_leases_mut()
                .insert_mut(binding.artifact_id(), next);
            Ok(AppliedOutput::none(TransitionEvent::ArtifactReleased))
        }
        CommandKind::FenceProviderEffects {
            coordinate,
            expected_epoch,
        } => {
            state.touch_provider_generation(coordinate);
            let record = state
                .provider_generations_mut()
                .get_mut(&coordinate)
                .ok_or(CoreError::UnknownProviderGeneration)?;
            if !matches!(record.state, ProviderEffectState::Active)
                || expected_epoch != provider_epoch(record.state)
            {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            record.state = ProviderEffectState::EffectFenced {
                epoch: expected_epoch
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?,
            };
            Ok(AppliedOutput::none(TransitionEvent::ProviderEffectsFenced))
        }
        CommandKind::EnterProviderSettlementOnly {
            coordinate,
            expected_epoch,
        } => {
            let current = state
                .provider_generations()
                .get(&coordinate)
                .ok_or(CoreError::UnknownProviderGeneration)?
                .state;
            if !matches!(current, ProviderEffectState::EffectFenced { .. })
                || expected_epoch != provider_epoch(current)
            {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            if state.scoped_composites().iter().any(|(effect, scoped)| {
                scoped.bindings.values().any(|bound| bound == &coordinate)
                    && state
                        .composite_effects()
                        .get(effect)
                        .is_some_and(|composite| {
                            composite.custodian != CustodyState::Released
                                && composite.components.values().any(|component| {
                                    matches!(
                                        component.commit,
                                        CommitState::Registered
                                            | CommitState::Prepared
                                            | CommitState::CommitIntentDurable
                                    ) && scoped.bindings.get(&component.id) == Some(&coordinate)
                                        // A revoked pre-commit effect has no
                                        // remaining execution bearer. Its
                                        // binding may still be retained solely
                                        // by a pinned recovery artifact, which
                                        // settlement-only authority must be
                                        // able to drain.
                                        && !(composite.authority == AuthorityState::Revoked
                                            && component.settlement
                                                == SettlementState::Revoked
                                            && component.claims.is_empty())
                                })
                        })
            }) {
                return Err(CoreError::ProviderEffectsLive);
            }
            state.touch_provider_generation(coordinate);
            state
                .provider_generations_mut()
                .get_mut(&coordinate)
                .expect("validated provider")
                .state = ProviderEffectState::SettlementOnly {
                epoch: expected_epoch
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?,
            };
            Ok(AppliedOutput::none(TransitionEvent::ProviderSettlementOnly))
        }
        CommandKind::RetireProviderEffects {
            coordinate,
            expected_epoch,
        } => {
            let current_state = state
                .provider_generations()
                .get(&coordinate)
                .ok_or(CoreError::UnknownProviderGeneration)?
                .state;
            if !matches!(current_state, ProviderEffectState::SettlementOnly { .. })
                || expected_epoch != provider_epoch(current_state)
            {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            if state
                .provider_generations()
                .get(&coordinate)
                .is_some_and(|record| record.live_component_bindings != 0)
            {
                return Err(CoreError::ProviderEffectsLive);
            }
            if state.artifact_leases().iter().any(|(_, lease)| {
                lease.binding().provider() == coordinate
                    && !matches!(lease, ArtifactLeaseState::Released { .. })
            }) {
                return Err(CoreError::ProviderEffectsLive);
            }
            state.touch_provider_generation(coordinate);
            let record = state
                .provider_generations_mut()
                .get_mut(&coordinate)
                .expect("validated provider generation");
            record.state = ProviderEffectState::Retired {
                epoch: expected_epoch
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?,
            };
            Ok(AppliedOutput::none(TransitionEvent::ProviderEffectsRetired))
        }
        CommandKind::AbortUnescapedEffect { effect } => {
            let scoped = state
                .scoped_composites()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if scoped.bindings.values().any(|provider| {
                state
                    .provider_generations()
                    .get(provider)
                    .is_none_or(|record| matches!(record.state, ProviderEffectState::Active))
            }) {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            // An installed handoff child owns a prepared reservation which is
            // deliberately absent from the live resource index and charge
            // aggregate.  It cannot pass through the ordinary pre-commit
            // revocation loop: doing so would subtract a second time and turn
            // a valid provider-fence cancellation into InvariantViolation.
            if let Some(descriptor) = prepared_handoff_target_for_abort(state, effect)? {
                return abort_prepared_handoff_target(state, descriptor);
            }
            let (causal_owner, authority_epoch) = {
                let composite = state
                    .composite_effects()
                    .get(&effect)
                    .ok_or(CoreError::UnknownEffect)?;
                (composite.causal_owner, composite.authority_epoch)
            };
            revoke_composite_effect(state, effect, causal_owner, authority_epoch)?;
            let retired = state
                .composite_effects()
                .get(&effect)
                .is_some_and(|composite| {
                    composite_escape_state(composite) == EffectEscapeState::Retired
                });
            if !retired {
                return Err(CoreError::WrongCommitState);
            }
            revoke_unpinned_artifact_placeholders(state, effect)?;
            if artifacts_released_for_effect(state, effect) {
                state.touch_composite(effect);
                let composite = state
                    .composite_effects_mut()
                    .get_mut(&effect)
                    .ok_or(CoreError::UnknownEffect)?;
                composite.custodian = CustodyState::Released;
                composite.authority = AuthorityState::Revoked;
                for component in composite.components.values_mut() {
                    component.retirement = RetirementState::Released;
                }
                release_scoped_provider_bindings(state, effect)?;
            }
            Ok(AppliedOutput::none(
                if artifacts_released_for_effect(state, effect) {
                    TransitionEvent::CompositeEffectReleased
                } else {
                    TransitionEvent::Revoked
                },
            ))
        }
        CommandKind::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind,
            charge_account,
            bindings,
        } => {
            let operation = effect.operation();
            let schema = catalog
                .composite_rule(kind)
                .ok_or(CoreError::UnknownObligationClass)?;
            if bindings.len() != schema.components().len() {
                return Err(CoreError::ProviderBindingMismatch);
            }
            let mut bound = BTreeMap::new();
            let mut artifacts = BTreeMap::new();
            let mut effect_catalog_digest = None;
            for item in bindings {
                if item.provider().world() != state.world()
                    || bound.insert(item.component(), item.provider()).is_some()
                {
                    return Err(CoreError::ProviderBindingMismatch);
                }
                let declared = schema
                    .component(item.component())
                    .ok_or(CoreError::ProviderBindingMismatch)?;
                let record = state
                    .provider_generations()
                    .get(&item.provider())
                    .ok_or(CoreError::UnknownProviderGeneration)?;
                match effect_catalog_digest {
                    Some(expected) if expected != record.catalog_digest => {
                        return Err(CoreError::CatalogMismatch);
                    }
                    None => effect_catalog_digest = Some(record.catalog_digest),
                    _ => {}
                }
                if record.state != ProviderEffectState::Active || declared.component().get() == 0 {
                    return Err(CoreError::ProviderLifecycleViolation);
                }
                match (declared.artifact_policy(), item.artifact()) {
                    (crate::RecoveryArtifactPolicy::Required, Some(admission)) => {
                        let receipts = record
                            .artifact_receipts
                            .ok_or(CoreError::ArtifactVerifierMismatch)?;
                        let binding = ArtifactBinding::new(
                            admission.artifact(),
                            item.provider(),
                            operation,
                            effect,
                            item.component(),
                            catalog.digest(),
                            admission.schema_digest(),
                            record.verifier_set_digest,
                            admission.closure_digest(),
                        )
                        .map_err(|_| CoreError::ArtifactBindingMismatch)?;
                        if state.artifact_leases().contains_key(&binding.artifact_id())
                            || state.scoped_composites().values().any(|scoped| {
                                scoped
                                    .artifacts
                                    .values()
                                    .any(|existing| existing.artifact_id() == binding.artifact_id())
                            })
                            || artifacts.values().any(|existing: &ArtifactBinding| {
                                existing.artifact_id() == binding.artifact_id()
                            })
                            || artifacts.insert(item.component(), binding).is_some()
                            || receipts.pin().verifier().get() == 0
                            || receipts.release().verifier().get() == 0
                        {
                            return Err(CoreError::ArtifactBindingMismatch);
                        }
                    }
                    (crate::RecoveryArtifactPolicy::Required, None) => {
                        return Err(CoreError::ArtifactRequired);
                    }
                    (crate::RecoveryArtifactPolicy::NotRequired, Some(_)) => {
                        return Err(CoreError::ArtifactBindingMismatch);
                    }
                    (crate::RecoveryArtifactPolicy::NotRequired, None) => {}
                }
            }
            if schema
                .components()
                .iter()
                .any(|declared| !bound.contains_key(&declared.component()))
            {
                return Err(CoreError::ProviderBindingMismatch);
            }
            initialize_composite_effect(
                catalog,
                limits,
                state,
                effect,
                origin,
                kind,
                charge_account,
            )?;
            let effect_catalog_digest = effect_catalog_digest.ok_or(CoreError::CatalogMismatch)?;
            for provider in bound.values() {
                state.touch_provider_generation(*provider);
                let record = state
                    .provider_generations_mut()
                    .get_mut(provider)
                    .expect("validated provider");
                record.live_component_bindings = record
                    .live_component_bindings
                    .checked_add(1)
                    .ok_or(CoreError::CapacityExceeded)?;
            }
            state.touch_scoped_composite(effect);
            state.scoped_composites_mut().insert_mut(
                effect,
                ScopedCompositeRecord {
                    catalog_digest: effect_catalog_digest,
                    bindings: bound,
                    artifacts,
                },
            );
            Ok(AppliedOutput::none(
                TransitionEvent::ScopedCompositeAdmitted,
            ))
        }
        CommandKind::ResolveIndeterminateHandoffParent {
            descriptor,
            descriptor_receipt_digest,
            fact,
        } => {
            require_digest(descriptor_receipt_digest)?;
            require_digest(fact.operation)?;
            require_digest(fact.descriptor_digest)?;
            require_digest(fact.stamp.receipt_digest)?;
            let child = descriptor.child_effect()?;
            if handoff_child_resolution_eligible(state, descriptor, descriptor_receipt_digest, fact)
            {
                let child_composite = state
                    .composite_effects()
                    .get(&child)
                    .ok_or(CoreError::UnknownEffect)?;
                let child_component = child_composite
                    .components
                    .get(&descriptor.child_component)
                    .ok_or(CoreError::UnknownObligationClass)?;
                if !handoff_recovery_fact_matches(
                    state,
                    catalog,
                    fact,
                    HandoffRecoveryCoordinates::new(
                        HandoffRecoveryRole::Child,
                        child,
                        descriptor.child_component,
                        child_component
                            .commit_operation
                            .ok_or(CoreError::WrongCommitState)?,
                        handoff_descriptor_digest(descriptor),
                        component_freshness(state, child_composite, child_component)?,
                    ),
                ) {
                    return Err(CoreError::HandoffGuardRequired);
                }
                state.touch_composite(child);
                let child_composite = state
                    .composite_effects_mut()
                    .get_mut(&child)
                    .expect("validated child");
                child_composite
                    .components
                    .get_mut(&descriptor.child_component)
                    .expect("validated component")
                    .outcome = OutcomeState::KnownSuccess(fact.stamp.receipt_digest);
                if let SingleHopRole::Target { recovery_fact, .. } = &mut child_composite.handoff {
                    *recovery_fact = Some(fact);
                }
                return Ok(AppliedOutput::none(TransitionEvent::EffectCommitted));
            }
            if !state.scoped_composites().contains_key(&descriptor.parent) {
                return Err(CoreError::IncompatibleApiProfile);
            }
            let operation_record = state
                .recovery_operations()
                .get(&descriptor.parent.operation())
                .ok_or(CoreError::UnknownEffect)?;
            let composite = state
                .composite_effects()
                .get(&descriptor.parent)
                .ok_or(CoreError::UnknownEffect)?;
            let component = composite
                .components
                .get(&descriptor.parent_component)
                .ok_or(CoreError::UnknownObligationClass)?;
            let operation_digest = component
                .commit_operation
                .ok_or(CoreError::WrongCommitState)?;
            if !matches!(
                operation_record.state,
                OperationRecoveryState::Fenced { .. }
            ) || composite.authority != AuthorityState::Fenced
                || composite.custodian != CustodyState::CoreOwned
                || !matches!(composite.handoff, SingleHopRole::None)
                || component.commit != CommitState::Committed
                || component.commit_nonce.is_some()
                || component.commit_fact.is_some()
                || component.outcome != OutcomeState::Indeterminate(operation_digest)
                || descriptor.catalog_digest != catalog.digest()
                || composite.catalog_digest != descriptor.catalog_digest
                || descriptor.parent != composite.effect
                || descriptor.child_effect().is_err()
                || !matches!(catalog.single_hop_handoff_rule(composite.kind), Some(rule) if rule.target() == descriptor.child_kind)
                || !handoff_recovery_fact_matches(
                    state,
                    catalog,
                    fact,
                    HandoffRecoveryCoordinates::new(
                        HandoffRecoveryRole::Parent,
                        descriptor.parent,
                        descriptor.parent_component,
                        operation_digest,
                        handoff_descriptor_digest(descriptor),
                        component_freshness(state, composite, component)?,
                    ),
                )
            {
                return Err(CoreError::HandoffGuardRequired);
            }
            state.touch_composite(descriptor.parent);
            let composite = state
                .composite_effects_mut()
                .get_mut(&descriptor.parent)
                .expect("validated source");
            let component = composite
                .components
                .get_mut(&descriptor.parent_component)
                .expect("validated component");
            component.outcome = OutcomeState::KnownSuccess(fact.stamp.receipt_digest);
            composite.handoff = SingleHopRole::Source {
                descriptor: Box::new(descriptor),
                terminal_receipt_digest: fact.stamp.receipt_digest,
                descriptor_receipt_digest,
                recovery_fact: Some(fact),
            };
            Ok(AppliedOutput::none(TransitionEvent::EffectCommitted))
        }
        CommandKind::AcknowledgeHandoffParent {
            fact,
            descriptor,
            descriptor_receipt_digest,
        } => {
            let source_kind = state
                .composite_effects()
                .get(&fact.effect)
                .ok_or(CoreError::UnknownEffect)?
                .kind;
            if !state.scoped_composites().contains_key(&fact.effect) {
                return Err(CoreError::IncompatibleApiProfile);
            }
            if descriptor.parent != fact.effect
                || descriptor.parent_component != fact.component
                || descriptor.catalog_digest != catalog.digest()
                || state
                    .composite_effects()
                    .get(&descriptor.parent)
                    .is_none_or(|composite| composite.catalog_digest != descriptor.catalog_digest)
                || descriptor.child_effect().is_err()
                || !matches!(catalog.single_hop_handoff_rule(source_kind), Some(rule) if rule.target() == descriptor.child_kind)
            {
                return Err(CoreError::InvalidPayload);
            }
            acknowledge_component_commit(
                catalog,
                state,
                fact.effect,
                descriptor.parent_component,
                fact,
            )?;
            state.touch_composite(descriptor.parent);
            let composite = state
                .composite_effects_mut()
                .get_mut(&descriptor.parent)
                .ok_or(CoreError::UnknownEffect)?;
            let component = composite
                .components
                .get(&descriptor.parent_component)
                .ok_or(CoreError::UnknownObligationClass)?;
            let OutcomeState::KnownSuccess(receipt) = component.outcome else {
                return Err(CoreError::VerificationFailed);
            };
            if !matches!(composite.handoff, SingleHopRole::None) {
                return Err(CoreError::HandoffGuardRequired);
            }
            composite.handoff = SingleHopRole::Source {
                descriptor: Box::new(descriptor),
                terminal_receipt_digest: receipt,
                descriptor_receipt_digest,
                recovery_fact: None,
            };
            Ok(AppliedOutput::none(TransitionEvent::EffectCommitted))
        }
        CommandKind::InstallHandoffChild {
            descriptor,
            origin,
            charge_account,
            provider,
        } => {
            let child = descriptor.child_effect()?;
            if descriptor.catalog_digest != catalog.digest() || child == descriptor.parent {
                return Err(CoreError::InvalidPayload);
            }
            let source = state
                .composite_effects()
                .get(&descriptor.parent)
                .ok_or(CoreError::UnknownEffect)?;
            if !state.scoped_composites().contains_key(&descriptor.parent) {
                return Err(CoreError::IncompatibleApiProfile);
            }
            if !matches!(catalog.single_hop_handoff_rule(source.kind), Some(rule) if rule.target() == descriptor.child_kind)
            {
                return Err(CoreError::HandoffGuardRequired);
            }
            if source.catalog_digest != descriptor.catalog_digest {
                return Err(CoreError::CatalogMismatch);
            }
            if !matches!(&source.handoff, SingleHopRole::Source { descriptor: saved, .. } if **saved == descriptor)
            {
                return Err(CoreError::HandoffGuardRequired);
            }
            if !handoff_source_claim_matches(source, descriptor) {
                return Err(CoreError::HandoffGuardRequired);
            }
            let schema = catalog
                .composite_rule(descriptor.child_kind)
                .ok_or(CoreError::UnknownObligationClass)?;
            if schema.components().len() != 1
                || schema.components()[0].component() != descriptor.child_component
            {
                return Err(CoreError::InvalidPayload);
            }
            if provider.component() != descriptor.child_component
                || provider.provider().world() != state.world()
            {
                return Err(CoreError::ProviderBindingMismatch);
            }
            let provider_record = state
                .provider_generations()
                .get(&provider.provider())
                .ok_or(CoreError::UnknownProviderGeneration)?;
            if provider_record.catalog_digest != catalog.digest()
                || !matches!(provider_record.state, ProviderEffectState::Active)
            {
                return Err(CoreError::ProviderLifecycleViolation);
            }
            let mut artifacts = BTreeMap::new();
            match (
                schema.components()[0].artifact_policy(),
                provider.artifact(),
            ) {
                (crate::RecoveryArtifactPolicy::Required, Some(admission)) => {
                    let receipts = provider_record
                        .artifact_receipts
                        .ok_or(CoreError::ArtifactVerifierMismatch)?;
                    let binding = ArtifactBinding::new(
                        admission.artifact(),
                        provider.provider(),
                        child.operation(),
                        child,
                        descriptor.child_component,
                        catalog.digest(),
                        admission.schema_digest(),
                        provider_record.verifier_set_digest,
                        admission.closure_digest(),
                    )
                    .map_err(|_| CoreError::ArtifactBindingMismatch)?;
                    if state.artifact_leases().contains_key(&binding.artifact_id())
                        || state.scoped_composites().values().any(|scoped| {
                            scoped
                                .artifacts
                                .values()
                                .any(|existing| existing.artifact_id() == binding.artifact_id())
                        })
                        || receipts.pin().verifier().get() == 0
                        || receipts.release().verifier().get() == 0
                    {
                        return Err(CoreError::ArtifactBindingMismatch);
                    }
                    artifacts.insert(descriptor.child_component, binding);
                }
                (crate::RecoveryArtifactPolicy::Required, None) => {
                    return Err(CoreError::ArtifactRequired);
                }
                (crate::RecoveryArtifactPolicy::NotRequired, Some(_)) => {
                    return Err(CoreError::ArtifactBindingMismatch);
                }
                (crate::RecoveryArtifactPolicy::NotRequired, None) => {}
            }
            initialize_composite_effect(
                catalog,
                limits,
                state,
                child,
                origin,
                descriptor.child_kind,
                charge_account,
            )?;
            state.touch_provider_generation(provider.provider());
            let provider_record = state
                .provider_generations_mut()
                .get_mut(&provider.provider())
                .expect("validated provider");
            provider_record.live_component_bindings = provider_record
                .live_component_bindings
                .checked_add(1)
                .ok_or(CoreError::CapacityExceeded)?;
            let mut bindings = BTreeMap::new();
            bindings.insert(descriptor.child_component, provider.provider());
            state.touch_scoped_composite(child);
            state.scoped_composites_mut().insert_mut(
                child,
                ScopedCompositeRecord {
                    catalog_digest: catalog.digest(),
                    bindings,
                    artifacts,
                },
            );
            enroll_component_claim(
                catalogs,
                catalog,
                limits,
                state,
                child,
                descriptor.child_component,
                origin,
                descriptor.claim,
                descriptor.claim_kind,
                descriptor.scope,
                descriptor.resource,
                descriptor.resource_generation,
                descriptor.units,
                None,
                Some(descriptor),
            )?;
            apply_command(
                catalogs,
                Some(catalog),
                limits,
                state,
                &CommandKind::PrepareCompositeEffect {
                    effect: child,
                    actor: origin,
                },
            )?;
            state.touch_composite(child);
            state
                .composite_effects_mut()
                .get_mut(&child)
                .expect("created child")
                .handoff = SingleHopRole::Target {
                parent: descriptor.parent,
                descriptor_digest: handoff_descriptor_digest(descriptor),
                recovery_fact: None,
            };
            Ok(AppliedOutput::none(TransitionEvent::EffectPrepared))
        }
        CommandKind::ReleaseHandoffSourceAndRecordTargetIntent {
            descriptor,
            actor,
            operation,
        } => {
            let child = descriptor.child_effect()?;
            let descriptor_digest = handoff_descriptor_digest(descriptor);
            if !state.scoped_composites().contains_key(&descriptor.parent)
                || !state.scoped_composites().contains_key(&child)
            {
                return Err(CoreError::IncompatibleApiProfile);
            }
            // This is a preflight-only check.  In particular, do not release
            // the source claim, alter the target role, or call the generic
            // commit-intent transition until every required source artifact
            // lease is already durably Released.
            ensure_required_artifact_leases_released(catalog, state, descriptor.parent)?;
            {
                let source = state
                    .composite_effects()
                    .get(&descriptor.parent)
                    .ok_or(CoreError::UnknownEffect)?;
                if source.catalog_digest != descriptor.catalog_digest
                    || state
                        .scoped_composites()
                        .get(&descriptor.parent)
                        .is_some_and(|scoped| scoped.catalog_digest != descriptor.catalog_digest)
                    || !matches!(&source.handoff, SingleHopRole::Source { descriptor: saved, .. } if **saved == descriptor)
                {
                    return Err(CoreError::HandoffGuardRequired);
                }
                let target = state
                    .composite_effects()
                    .get(&child)
                    .ok_or(CoreError::UnknownEffect)?;
                if target.catalog_digest != descriptor.catalog_digest
                    || state
                        .scoped_composites()
                        .get(&child)
                        .is_some_and(|scoped| scoped.catalog_digest != descriptor.catalog_digest)
                    || !matches!(target.handoff, SingleHopRole::Target { parent, descriptor_digest: saved, recovery_fact: None } if parent == descriptor.parent && saved == descriptor_digest)
                {
                    return Err(CoreError::HandoffGuardRequired);
                }
                ensure_handoff_target_artifact_admission(
                    catalog,
                    state,
                    child,
                    descriptor.child_component,
                )?;
            }
            // The generic component command deliberately rejects a Target;
            // temporarily remove only the in-memory guard while executing the
            // same state-machine transition, then restore it before the
            // prepared delta can be committed.
            let target_role = state
                .composite_effects()
                .get(&child)
                .expect("validated target")
                .handoff
                .clone();
            state.touch_composite(child);
            state
                .composite_effects_mut()
                .get_mut(&child)
                .expect("validated target")
                .handoff = SingleHopRole::None;
            let intent = apply_command(
                catalogs,
                Some(catalog),
                limits,
                state,
                &CommandKind::RecordComponentCommitIntent {
                    effect: child,
                    component: descriptor.child_component,
                    actor,
                    operation,
                },
            )?;
            state.touch_composite(child);
            state
                .composite_effects_mut()
                .get_mut(&child)
                .expect("validated target")
                .handoff = target_role;
            release_handoff_source_claim(state, descriptor)?;
            activate_prepared_handoff_target(catalog, limits, state, child, descriptor)?;
            state.touch_composite(descriptor.parent);
            let source = state
                .composite_effects_mut()
                .get_mut(&descriptor.parent)
                .expect("validated source");
            source.custodian = CustodyState::Released;
            source.authority = AuthorityState::Revoked;
            for component in source.components.values_mut() {
                component.settlement = SettlementState::Revoked;
                component.retirement = RetirementState::Released;
            }
            release_scoped_provider_bindings(state, descriptor.parent)?;
            Ok(intent)
        }
        CommandKind::AddComponentClaim {
            effect,
            component,
            actor,
            claim,
            kind,
            scope,
            resource,
            resource_generation,
            units,
        } => enroll_component_claim(
            catalogs,
            catalog,
            limits,
            state,
            effect,
            component,
            actor,
            claim,
            kind,
            scope,
            resource,
            resource_generation,
            units,
            None,
            None,
        ),
        CommandKind::PrepareCompositeEffect { effect, actor } => {
            require_active_composite_actor(state, effect, actor)?;
            {
                let composite = state
                    .composite_effects()
                    .get(&effect)
                    .ok_or(CoreError::UnknownEffect)?;
                if composite.authority != AuthorityState::Active
                    || composite
                        .components
                        .values()
                        .any(|component| component.commit != CommitState::Registered)
                {
                    return Err(CoreError::WrongCommitState);
                }
                for component in composite.components.values() {
                    validate_component_claims(catalog, component)?;
                }
            }
            state.touch_composite(effect);
            let composite = state
                .composite_effects_mut()
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            for component in composite.components.values_mut() {
                component.commit = CommitState::Prepared;
            }
            Ok(AppliedOutput::none(TransitionEvent::EffectPrepared))
        }
        CommandKind::RecordComponentCommitIntent {
            effect,
            component,
            actor,
            operation,
        } => {
            require_digest(operation)?;
            require_active_composite_actor(state, effect, actor)?;
            if !artifact_ready_for_component(state, effect, component) {
                return Err(CoreError::ArtifactNotPinned);
            }
            let nonce = allocate_nonce(state)?;
            state.touch_composite(effect);
            let composite = state
                .composite_effects_mut()
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if matches!(composite.handoff, SingleHopRole::Target { .. }) {
                return Err(CoreError::HandoffGuardRequired);
            }
            if composite.components.len() != 1 {
                return Err(CoreError::WrongCommitState);
            }
            let component_record = composite
                .components
                .get_mut(&component)
                .ok_or(CoreError::UnknownObligationClass)?;
            if composite.authority != AuthorityState::Active
                || component_record.commit != CommitState::Prepared
            {
                return Err(CoreError::WrongCommitState);
            }
            component_record.commit = CommitState::CommitIntentDurable;
            component_record.commit_nonce = Some(nonce);
            component_record.commit_operation = Some(operation);
            Ok(AppliedOutput {
                event: TransitionEvent::CommitIntentDurable,
                output: OutputData::CommitIntent {
                    effect,
                    component,
                    nonce,
                },
            })
        }
        CommandKind::RecordCompositeCommitIntents {
            effect,
            actor,
            operations,
        } => {
            require_active_composite_actor(state, effect, actor)?;
            let composite = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            let component_specs = catalog
                .composite_rule(composite.kind)
                .ok_or(CoreError::UnknownObligationClass)?
                .components();
            if operations.len() != component_specs.len()
                || operations
                    .iter()
                    .zip(component_specs)
                    .any(|(operation, expected)| {
                        operation.component() != expected.component()
                            || operation.operation().is_zero()
                    })
                || composite
                    .components
                    .values()
                    .any(|component| component.commit != CommitState::Prepared)
            {
                return Err(CoreError::WrongCommitState);
            }
            if operations.iter().any(|operation| {
                !artifact_ready_for_component(state, effect, operation.component())
            }) {
                return Err(CoreError::ArtifactNotPinned);
            }
            let mut intents = Vec::with_capacity(operations.len());
            for operation in &operations {
                intents.push((operation.component(), allocate_nonce(state)?));
            }
            state.touch_composite(effect);
            let composite = state
                .composite_effects_mut()
                .get_mut(&effect)
                .expect("composite was validated before nonce allocation");
            for (operation, (component, nonce)) in operations.into_iter().zip(&intents) {
                let record = composite
                    .components
                    .get_mut(component)
                    .expect("catalog-ordered component was validated");
                record.commit = CommitState::CommitIntentDurable;
                record.commit_nonce = Some(*nonce);
                record.commit_operation = Some(operation.operation());
            }
            Ok(AppliedOutput {
                event: TransitionEvent::CommitIntentDurable,
                output: OutputData::CompositeCommitIntents { effect, intents },
            })
        }
        CommandKind::AcknowledgeCommit { fact } => {
            let component = fact.component;
            acknowledge_component_commit(catalog, state, fact.effect, component, fact)
        }
        CommandKind::FenceExecutor { operation, crashed } => {
            state.touch_operation(operation);
            apply_fence_incarnation(state, operation, crashed, limits.max_crashes_per_operation)?;
            Ok(AppliedOutput::none(TransitionEvent::ExecutorFenced))
        }
        CommandKind::Snapshot {
            operation,
            snapshot,
            digest,
        } => {
            require_digest(digest)?;
            let expected = build_recovery_snapshot(catalogs, state, operation, snapshot)?;
            if expected.digest != digest {
                return Err(CoreError::StaleSnapshot);
            }
            state.touch_operation(operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(&operation)
                .ok_or(CoreError::UnknownOperation)?;
            if matches!(
                operation_record.state,
                OperationRecoveryState::RecoveryExhausted { .. }
            ) {
                return Err(CoreError::RecoveryExhausted);
            }
            if !matches!(
                operation_record.state,
                OperationRecoveryState::Fenced { .. }
            ) {
                return Err(CoreError::WrongRecoveryState);
            }
            operation_record.state = OperationRecoveryState::Snapshotted { snapshot, digest };
            Ok(AppliedOutput::none(TransitionEvent::Snapshot))
        }
        CommandKind::Ready {
            operation,
            snapshot,
            successor,
        } => {
            state.touch_operation(operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(&operation)
                .ok_or(CoreError::UnknownOperation)?;
            let expected = match operation_record.state {
                OperationRecoveryState::Snapshotted {
                    snapshot: expected, ..
                } => expected,
                OperationRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if expected != snapshot {
                return Err(CoreError::StaleSnapshot);
            }
            if successor.executor() != operation_record.origin.executor()
                || successor.generation() <= operation_record.last_executor.generation()
            {
                return Err(CoreError::StaleExecutor);
            }
            operation_record.state = OperationRecoveryState::Ready {
                snapshot,
                successor,
            };
            Ok(AppliedOutput::none(TransitionEvent::Ready))
        }
        CommandKind::Rebind {
            operation,
            snapshot,
            successor,
        } => {
            state.touch_operation(operation);
            let operation_record = state
                .recovery_operations_mut()
                .get_mut(&operation)
                .ok_or(CoreError::UnknownOperation)?;
            match operation_record.state {
                OperationRecoveryState::Ready {
                    snapshot: expected,
                    successor: expected_successor,
                } if expected == snapshot && expected_successor == successor => {}
                OperationRecoveryState::Ready { .. } => return Err(CoreError::StaleSnapshot),
                OperationRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            }
            if successor.generation() <= operation_record.last_executor.generation() {
                return Err(CoreError::StaleExecutor);
            }
            operation_record.last_executor = successor;
            operation_record.state = OperationRecoveryState::Rebound { successor };
            Ok(AppliedOutput::none(TransitionEvent::Rebound))
        }
        CommandKind::AdoptEffect { effect, successor } => {
            let operation = state
                .recovery_operations()
                .get(&effect.operation())
                .ok_or(CoreError::UnknownOperation)?;
            if matches!(
                operation.state,
                OperationRecoveryState::RecoveryExhausted { .. }
            ) {
                return Err(CoreError::RecoveryExhausted);
            }
            if !matches!(
                operation.state,
                OperationRecoveryState::Rebound {
                    successor: current,
                } if current == successor
            ) {
                return Err(CoreError::StaleExecutor);
            }
            state.touch_composite(effect);
            let composite = state
                .composite_effects_mut()
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if composite.authority == AuthorityState::Revoked {
                return Err(CoreError::GateClosed);
            }
            if composite.authority != AuthorityState::Fenced
                || composite.custodian != CustodyState::CoreOwned
            {
                return Err(CoreError::WrongCommitState);
            }
            for component in composite.components.values() {
                validate_component_execution_adoption(catalog, component)?;
            }
            composite.authority_epoch = composite
                .authority_epoch
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted)?;
            composite.authority = AuthorityState::Active;
            composite.custodian = CustodyState::Executor(successor);
            for component in composite.components.values_mut() {
                refresh_component_retirement(component, composite.authority);
            }
            Ok(AppliedOutput::none(TransitionEvent::EffectAdopted))
        }
        CommandKind::RebaseCompositePrecommitClaims { effect, actor } => {
            rebase_composite_precommit_claims(catalog, state, effect, actor)?;
            Ok(AppliedOutput::none(
                TransitionEvent::CompositePrecommitClaimsRebased,
            ))
        }
        CommandKind::ClaimComponentSettlement {
            effect,
            component,
            claimant,
        } => claim_component_settlement(state, effect, component, claimant),
        CommandKind::RecordComponentApplyIntent {
            effect,
            component,
            claimant,
            generation,
            nonce,
            intent,
        } => {
            require_digest(intent)?;
            state.touch_composite(effect);
            let component_record =
                exact_component_claim_mut(state, effect, component, claimant, generation, nonce)?;
            if component_record.claim_stage != Some(ClaimStage::Fresh) {
                return Err(CoreError::WrongSettlementStage);
            }
            component_record.settlement = SettlementState::ApplyIntentDurable {
                claimant,
                generation,
            };
            component_record.claim_stage = Some(ClaimStage::Intent);
            component_record.settlement_intent = Some(intent);
            Ok(AppliedOutput {
                event: TransitionEvent::ApplyIntentDurable,
                output: OutputData::Settlement {
                    effect,
                    component,
                    claimant,
                    generation,
                    nonce,
                    stage: ClaimStage::Intent,
                },
            })
        }
        CommandKind::RecordApplied { fact } => {
            let component = fact.component;
            record_component_applied(catalog, state, fact.effect, component, fact)
        }
        CommandKind::Settle { fact } => {
            let component = fact.component;
            settle_component(catalog, state, fact.effect, component, fact)
        }
        CommandKind::MarkComponentIndeterminate {
            effect,
            component,
            claimant,
            generation,
            nonce,
            reason,
        } => {
            require_digest(reason)?;
            let authority = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?
                .authority;
            let component_record =
                exact_component_claim_mut(state, effect, component, claimant, generation, nonce)?;
            let applied = matches!(
                component_record.claim_stage,
                Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
            );
            let next_generation = generation
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted)?;
            component_record.outcome = OutcomeState::Indeterminate(reason);
            component_record.settlement = SettlementState::ReconciliationRequired {
                generation: next_generation,
                applied,
            };
            component_record.settlement_nonce = None;
            component_record.claim_stage = None;
            refresh_component_retirement(component_record, authority);
            Ok(AppliedOutput::none(TransitionEvent::Indeterminate))
        }
        CommandKind::BeginRevoke {
            effect,
            expected_actor,
            authority_epoch,
        } => {
            let operation = state
                .recovery_operations()
                .get(&effect.operation())
                .ok_or(CoreError::UnknownOperation)?;
            let live = match operation.state {
                OperationRecoveryState::Active { executor }
                | OperationRecoveryState::Rebound {
                    successor: executor,
                } => executor,
                OperationRecoveryState::RecoveryExhausted { .. } => {
                    return Err(CoreError::RecoveryExhausted);
                }
                _ => return Err(CoreError::WrongRecoveryState),
            };
            if live != expected_actor {
                return Err(CoreError::StaleExecutor);
            }
            revoke_composite_effect(state, effect, expected_actor, authority_epoch)
        }
        CommandKind::SubmitComponentEvidence {
            effect,
            component,
            claim,
            evidence,
        } => apply_component_evidence(catalog, state, effect, component, claim, evidence),
        CommandKind::WholeStateCheckpointV1 {
            state: image,
            projection,
        } => {
            let rebuilt = decode_whole_state_checkpoint(&image, catalogs, limits)?;
            // Replay applies primary commands without maintaining the
            // derived cache; compare the checkpoint against primary state
            // and the independently rebuilt cache, not the stale replay
            // cache carried by the replay image.
            if rebuilt.recovery_target.is_some()
                || rebuilt.projection_cache.digest != projection
                || !checkpoint_state_matches(state, &rebuilt)
            {
                return Err(CoreError::InvariantViolation);
            }
            // The checkpoint intentionally excludes derived reverse indexes
            // and charge caches. In particular, a live terminal transition
            // may retain an otherwise harmless zero-valued charge entry until
            // a later in-memory mutation, while checkpoint recovery rebuilds
            // the canonical empty cache. The projection binds every durable
            // primary field, and the exact comparison above differs from the
            // live state only by normalizing those semantically empty keys.
            // `decode_whole_state_checkpoint` has already rebuilt and
            // invariant-checked every derived structure.
            Ok(AppliedOutput::none(TransitionEvent::RecoveryCheckpointed))
        }
        CommandKind::CheckpointRecovery {
            boot,
            journal,
            device,
        } => {
            let target = state
                .recovery_target()
                .ok_or(CoreError::WrongRecoveryState)?;
            if target.boot() != boot
                || target.journal() != journal
                || target.device() != device
                || target.registry() != state.freshness().registry()
                || state
                    .device_generations()
                    .values()
                    .any(|generation| *generation > device)
            {
                return Err(CoreError::FreshnessRollback);
            }
            let operations: Vec<OperationId> =
                state.recovery_operations().keys().copied().collect();
            for operation in operations {
                state.touch_operation(operation);
                fence_operation_for_boot(state, operation, limits.max_crashes_per_operation)?;
            }
            state.freshness().set_boot_and_journal(boot, journal);
            state.freshness().set_device(device);
            let device_scopes: Vec<DeviceScopeId> =
                state.device_generations().keys().copied().collect();
            for scope in device_scopes {
                state.touch_device(scope);
                *state
                    .device_generations_mut()
                    .get_mut(&scope)
                    .expect("scope was collected from device generations") = device;
            }
            // Cold recovery installs this fail-closed overlay before the
            // checkpoint is durable, while retaining the trusted anchor's
            // projection as the record base. Rebuild the same overlay when
            // replay reaches the checkpoint so its resulting projection is
            // identical to the live recovery transition.
            quarantine_live_device_claims(state);
            state.set_recovery_target(None);
            Ok(AppliedOutput::none(TransitionEvent::RecoveryCheckpointed))
        }
        CommandKind::ReserveComponentReuse {
            effect,
            component,
            actor,
            claim,
            kind,
            scope,
            resource,
            expected_generation,
            units,
            reuse_contract,
        } => {
            require_digest(reuse_contract)?;
            if state.recovery_target().is_some() {
                return Err(CoreError::RecoveryPending);
            }
            if scope_is_quarantined(state, scope) {
                return Err(CoreError::Quarantined);
            }
            require_active_composite_actor(state, effect, actor)?;
            let authority_epoch = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?
                .authority_epoch;
            let record = state
                .resources()
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
            let catalog_digest = catalog.digest();
            let retirement_digest =
                retirement_contract_digest(catalog_digest, state, resource, expected_generation)?;
            let generation = ResourceGeneration::new(
                expected_generation
                    .get()
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?,
            )
            .map_err(|_| CoreError::GenerationExhausted)?;
            let nonce = allocate_nonce(state)?;
            let reservation_freshness = scoped_freshness(state, scope)?;
            state.touch_resource(resource);
            state.resources_mut().insert_mut(
                resource,
                ResourceRecord {
                    scope,
                    generation,
                    phase: ResourcePhase::Claimed {
                        pending_reuse: Some(PendingReuse {
                            effect,
                            component,
                            actor,
                            authority_epoch,
                            claim,
                            previous_generation: expected_generation,
                            catalog_digest,
                            retirement_digest,
                            reuse_contract,
                            nonce,
                            freshness: reservation_freshness,
                        }),
                    },
                },
            );
            enroll_component_claim(
                catalogs,
                catalog,
                limits,
                state,
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                generation,
                units,
                Some(nonce),
                None,
            )?;
            Ok(AppliedOutput {
                event: TransitionEvent::ResourceReuseReserved,
                output: OutputData::ReusePermit {
                    effect,
                    component,
                    actor,
                    authority_epoch,
                    claim,
                    resource,
                    previous_generation: expected_generation,
                    generation,
                    catalog_digest,
                    retirement_digest,
                    reuse_contract,
                    freshness: reservation_freshness,
                    nonce,
                },
            })
        }
        CommandKind::ActivateResourceReuse {
            effect,
            component,
            actor,
            authority_epoch,
            claim,
            resource,
            previous_generation,
            resource_generation,
            catalog_digest,
            retirement_digest,
            reuse_contract,
            nonce,
            freshness,
        } => {
            if catalog_digest != catalog.digest()
                || retirement_digest.is_zero()
                || reuse_contract.is_zero()
                || previous_generation
                    .get()
                    .checked_add(1)
                    .map(ResourceGeneration::new)
                    != Some(Ok(resource_generation))
            {
                return Err(CoreError::StaleReusePermit);
            }
            require_active_composite_actor(state, effect, actor)?;
            let composite = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if composite.authority_epoch != authority_epoch {
                return Err(CoreError::StaleAuthorityEpoch);
            }
            let claim_record = composite
                .components
                .get(&component)
                .and_then(|record| record.claims.get(&claim))
                .ok_or(CoreError::UnknownClaim)?;
            if claim_record.retired
                || claim_record.resource != resource
                || claim_record.resource_generation != resource_generation
            {
                return Err(CoreError::StaleReusePermit);
            }
            let scope = state
                .resources()
                .get(&resource)
                .ok_or(CoreError::UnknownResource)?
                .scope;
            if scope_is_quarantined(state, scope) {
                return Err(CoreError::Quarantined);
            }
            let current_freshness = scoped_freshness(state, scope)?;
            state.touch_resource(resource);
            let record = state
                .resources_mut()
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
                            component: expected_component,
                            actor: expected_actor,
                            authority_epoch: expected_epoch,
                            claim: expected_claim,
                            previous_generation: expected_previous_generation,
                            catalog_digest: expected_catalog_digest,
                            retirement_digest: expected_retirement_digest,
                            reuse_contract: expected_reuse_contract,
                            nonce: expected_nonce,
                            freshness: expected_freshness,
                        }),
                } if expected_effect == effect
                    && expected_component == component
                    && expected_actor == actor
                    && expected_epoch == authority_epoch
                    && expected_claim == claim
                    && expected_previous_generation == previous_generation
                    && expected_catalog_digest == catalog_digest
                    && expected_retirement_digest == retirement_digest
                    && expected_reuse_contract == reuse_contract
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
            component,
            actor,
            authority_epoch,
            claim,
            resource,
            resource_generation,
        } => {
            require_active_composite_actor(state, effect, actor)?;
            let composite = state
                .composite_effects()
                .get(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if composite.authority_epoch != authority_epoch {
                return Err(CoreError::StaleAuthorityEpoch);
            }
            let component_record = composite
                .components
                .get(&component)
                .ok_or(CoreError::UnknownObligationClass)?;
            let claim_record = component_record
                .claims
                .get(&claim)
                .ok_or(CoreError::UnknownClaim)?;
            if claim_record.retired
                || claim_record.resource != resource
                || claim_record.resource_generation != resource_generation
            {
                return Err(CoreError::UnknownClaim);
            }
            let (previous, scope) = match state.resources().get(&resource) {
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
                || previous.component != component
                || previous.claim != claim
                || previous.authority_epoch >= authority_epoch
                || previous.actor == actor
            {
                return Err(CoreError::GateClaimed);
            }
            let nonce = allocate_nonce(state)?;
            let reservation_freshness = scoped_freshness(state, scope)?;
            let pending = PendingReuse {
                effect,
                component,
                actor,
                authority_epoch,
                claim,
                previous_generation: previous.previous_generation,
                catalog_digest: previous.catalog_digest,
                retirement_digest: previous.retirement_digest,
                reuse_contract: previous.reuse_contract,
                nonce,
                freshness: reservation_freshness,
            };
            state.touch_resource(resource);
            state
                .resources_mut()
                .get_mut(&resource)
                .expect("resource was validated")
                .phase = ResourcePhase::Claimed {
                pending_reuse: Some(pending),
            };
            Ok(AppliedOutput {
                event: TransitionEvent::ResourceReuseReclaimed,
                output: OutputData::ReusePermit {
                    effect,
                    component,
                    actor,
                    authority_epoch,
                    claim,
                    resource,
                    previous_generation: previous.previous_generation,
                    generation: resource_generation,
                    catalog_digest: previous.catalog_digest,
                    retirement_digest: previous.retirement_digest,
                    reuse_contract: previous.reuse_contract,
                    freshness: reservation_freshness,
                    nonce,
                },
            })
        }
        CommandKind::ReleaseCompositeEffect { effect } => {
            if !artifacts_released_for_effect(state, effect) {
                return Err(CoreError::EffectNotReleasable);
            }
            state.touch_composite(effect);
            let composite = state
                .composite_effects_mut()
                .get_mut(&effect)
                .ok_or(CoreError::UnknownEffect)?;
            if matches!(composite.handoff, SingleHopRole::Source { .. }) {
                return Err(CoreError::HandoffGuardRequired);
            }
            if composite_escape_state(composite) != EffectEscapeState::Retired {
                return Err(CoreError::EffectNotReleasable);
            }
            composite.custodian = CustodyState::Released;
            composite.authority = AuthorityState::Revoked;
            for component in composite.components.values_mut() {
                component.retirement = RetirementState::Released;
            }
            if artifacts_released_for_effect(state, effect) {
                release_scoped_provider_bindings(state, effect)?;
            }
            Ok(AppliedOutput::none(
                TransitionEvent::CompositeEffectReleased,
            ))
        }
    }
}

/// updated together so checkpoint/replay can never observe a released effect
/// still keeping a generation artificially live.
fn release_scoped_provider_bindings(
    state: &mut impl StateAccessMut,
    effect: EffectId,
) -> Result<(), CoreError> {
    state.touch_scoped_composite(effect);
    let Some(scoped) = state.scoped_composites_mut().remove_mut(&effect) else {
        return Ok(());
    };
    let provenance = ReleasedCompositeProvenance::from(scoped.clone());
    state.touch_composite(effect);
    let composite = state
        .composite_effects_mut()
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    if composite.released_provenance.replace(provenance).is_some() {
        return Err(CoreError::InvariantViolation);
    }
    for provider in scoped.bindings.values() {
        state.touch_provider_generation(*provider);
        let record = state
            .provider_generations_mut()
            .get_mut(provider)
            .ok_or(CoreError::UnknownProviderGeneration)?;
        record.live_component_bindings = record
            .live_component_bindings
            .checked_sub(1)
            .ok_or(CoreError::InvariantViolation)?;
    }
    Ok(())
}

fn validate_artifact_binding(
    catalog: &DomainCatalog,
    state: &impl StateAccess,
    binding: ArtifactBinding,
) -> Result<(), CoreError> {
    if binding.catalog_digest() != catalog.digest() || state.world() != binding.provider().world() {
        return Err(CoreError::ArtifactBindingMismatch);
    }
    if state
        .provider_generations()
        .get(&binding.provider())
        .is_none_or(|record| record.catalog_digest != binding.catalog_digest())
    {
        return Err(CoreError::CatalogMismatch);
    }
    let scoped = state
        .scoped_composites()
        .get(&binding.effect())
        .ok_or(CoreError::UnknownEffect)?;
    if binding.operation() != binding.effect().operation()
        || scoped.bindings.get(&binding.component()) != Some(&binding.provider())
        || scoped.artifacts.get(&binding.component()) != Some(&binding)
    {
        return Err(CoreError::ArtifactBindingMismatch);
    }
    let provider = state
        .provider_generations()
        .get(&binding.provider())
        .ok_or(CoreError::UnknownProviderGeneration)?;
    if provider.verifier_set_digest != binding.verifier_set_digest() {
        return Err(CoreError::ArtifactBindingMismatch);
    }
    Ok(())
}

fn artifact_ready_for_component(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
) -> bool {
    let Some(scoped) = state.scoped_composites().get(&effect) else {
        return true;
    };
    let Some(binding) = scoped.artifacts.get(&component) else {
        return true;
    };
    matches!(
        state.artifact_leases().get(&binding.artifact_id()),
        Some(ArtifactLeaseState::Pinned {
            binding: pinned,
            ..
        }) if pinned == binding
    )
}

fn artifacts_released_for_effect(state: &impl StateAccess, effect: EffectId) -> bool {
    state.scoped_composites().get(&effect).is_none_or(|scoped| {
        scoped.artifacts.values().all(|binding| {
            matches!(
                state.artifact_leases().get(&binding.artifact_id()),
                Some(ArtifactLeaseState::Released { .. })
            )
        })
    })
}

/// Checks the source side of the handoff pivot without changing state.
/// Required artifact leases are independent of the resource-claim pivot: a
/// source may only release its claim after every one of its admitted required
/// artifact closures has reached the terminal `Released` state.
fn ensure_required_artifact_leases_released(
    catalog: &DomainCatalog,
    state: &impl StateAccess,
    effect: EffectId,
) -> Result<(), CoreError> {
    let composite = state
        .composite_effects()
        .get(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    let schema = catalog
        .composite_rule(composite.kind)
        .ok_or(CoreError::UnknownObligationClass)?;
    let Some(scoped) = state.scoped_composites().get(&effect) else {
        if schema
            .components()
            .iter()
            .any(|component| component.artifact_policy() == crate::RecoveryArtifactPolicy::Required)
        {
            return Err(CoreError::ArtifactRequired);
        }
        return Ok(());
    };
    for component in schema.components() {
        if component.artifact_policy() != crate::RecoveryArtifactPolicy::Required {
            continue;
        }
        let binding = scoped
            .artifacts
            .get(&component.component())
            .ok_or(CoreError::ArtifactRequired)?;
        match state.artifact_leases().get(&binding.artifact_id()) {
            Some(ArtifactLeaseState::Released { .. }) => {}
            Some(_) => return Err(CoreError::ArtifactNotReleasable),
            None => return Err(CoreError::ArtifactRequired),
        }
    }
    Ok(())
}

/// Verifies that a handoff target with a Required artifact policy is backed by
/// the same exact scoped admission used by ordinary composite effects. The
/// current handoff install command has no admission payload and rejects such
/// targets, but this check also protects the pivot if a future recovery path
/// materializes a target from durable state.
fn ensure_handoff_target_artifact_admission(
    catalog: &DomainCatalog,
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
) -> Result<(), CoreError> {
    let composite = state
        .composite_effects()
        .get(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    let schema = catalog
        .composite_rule(composite.kind)
        .ok_or(CoreError::UnknownObligationClass)?;
    let Some(declared) = schema.component(component) else {
        return Err(CoreError::ProviderBindingMismatch);
    };
    if declared.artifact_policy() != crate::RecoveryArtifactPolicy::Required {
        return Ok(());
    }
    let scoped = state
        .scoped_composites()
        .get(&effect)
        .ok_or(CoreError::ArtifactRequired)?;
    let binding = scoped
        .artifacts
        .get(&component)
        .copied()
        .ok_or(CoreError::ArtifactRequired)?;
    validate_artifact_binding(catalog, state, binding)
}

/// Withdraws only artifact admission placeholders which never acquired a
/// durable global lease. Pinned, release-authorized, and released bindings
/// remain attached to the scoped effect until the normal release transition.
fn revoke_unpinned_artifact_placeholders(
    state: &mut impl StateAccessMut,
    effect: EffectId,
) -> Result<(), CoreError> {
    let Some(scoped) = state.scoped_composites().get(&effect) else {
        return Ok(());
    };
    let unpinned: Vec<_> = scoped
        .artifacts
        .iter()
        .filter_map(|(component, binding)| {
            (!state.artifact_leases().contains_key(&binding.artifact_id())).then_some(*component)
        })
        .collect();
    if unpinned.is_empty() {
        return Ok(());
    }
    state.touch_scoped_composite(effect);
    let scoped = state
        .scoped_composites_mut()
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    for component in unpinned {
        scoped.artifacts.remove(&component);
    }
    Ok(())
}

fn provider_epoch(state: ProviderEffectState) -> u64 {
    match state {
        ProviderEffectState::Active => 1,
        ProviderEffectState::EffectFenced { epoch }
        | ProviderEffectState::SettlementOnly { epoch }
        | ProviderEffectState::Retired { epoch } => epoch,
    }
}

fn enforce_scoped_provider_gate(
    state: &impl StateAccess,
    command: &CommandKind,
) -> Result<(), CoreError> {
    let effect = match command {
        CommandKind::AddComponentClaim { effect, .. }
        | CommandKind::PrepareCompositeEffect { effect, .. }
        | CommandKind::RecordComponentCommitIntent { effect, .. }
        | CommandKind::RecordCompositeCommitIntents { effect, .. }
        | CommandKind::AdoptEffect { effect, .. }
        | CommandKind::RebaseCompositePrecommitClaims { effect, .. }
        | CommandKind::ReserveComponentReuse { effect, .. }
        | CommandKind::ReclaimResourceReuse { effect, .. }
        | CommandKind::ActivateResourceReuse { effect, .. } => Some(*effect),
        CommandKind::RecordArtifactPin { binding, .. } => Some(binding.effect()),
        _ => None,
    };
    let Some(effect) = effect else {
        return Ok(());
    };
    if state.composite_effects().contains_key(&effect)
        && !state.scoped_composites().contains_key(&effect)
        && state
            .composite_effects()
            .get(&effect)
            .is_some_and(|composite| composite.released_provenance.is_none())
    {
        return Err(CoreError::IncompatibleApiProfile);
    }
    let Some(scoped) = state.scoped_composites().get(&effect) else {
        return Ok(());
    };
    let admission = matches!(
        command,
        CommandKind::AddComponentClaim { .. }
            | CommandKind::PrepareCompositeEffect { .. }
            | CommandKind::RecordComponentCommitIntent { .. }
            | CommandKind::RecordCompositeCommitIntents { .. }
            | CommandKind::AdoptEffect { .. }
            | CommandKind::RebaseCompositePrecommitClaims { .. }
            | CommandKind::ReserveComponentReuse { .. }
            | CommandKind::ReclaimResourceReuse { .. }
            | CommandKind::ActivateResourceReuse { .. }
            | CommandKind::RecordArtifactPin { .. }
    );
    if !admission {
        return Ok(());
    }
    let component = match command {
        CommandKind::AddComponentClaim { component, .. }
        | CommandKind::RecordComponentCommitIntent { component, .. }
        | CommandKind::ReserveComponentReuse { component, .. } => Some(*component),
        CommandKind::RecordArtifactPin { binding, .. } => Some(binding.component()),
        CommandKind::ReclaimResourceReuse { component, .. }
        | CommandKind::ActivateResourceReuse { component, .. } => Some(*component),
        _ => None,
    };
    if let Some(component) = component
        && !scoped.bindings.contains_key(&component)
    {
        return Err(CoreError::ProviderBindingMismatch);
    }
    let providers = component
        .and_then(|component| scoped.bindings.get(&component).copied())
        .into_iter()
        .chain(
            component
                .is_none()
                .then_some(scoped.bindings.values().copied())
                .into_iter()
                .flatten(),
        );
    for provider in providers {
        let record = state
            .provider_generations()
            .get(&provider)
            .ok_or(CoreError::UnknownProviderGeneration)?;
        if !matches!(record.state, ProviderEffectState::Active) {
            return Err(CoreError::ProviderLifecycleViolation);
        }
    }
    Ok(())
}

/// Tag 41 is shared by source and child recovery. A target takes the child
/// branch only after recovery has durably consumed its nonce and marked the
/// exact committed operation indeterminate. A merely installed/prepared child
/// must not preempt a still-valid parent resolution.
fn handoff_child_resolution_eligible(
    state: &impl StateAccess,
    descriptor: ChildDescriptorV1,
    descriptor_receipt_digest: Digest,
    fact: VerifiedHandoffRecoveryFact,
) -> bool {
    let Ok(child) = descriptor.child_effect() else {
        return false;
    };
    if child == descriptor.parent {
        return false;
    }
    let Some(recovery_operation) = state.recovery_operations().get(&child.operation()) else {
        return false;
    };
    let Some(composite) = state.composite_effects().get(&child) else {
        return false;
    };
    let Some(source) = state.composite_effects().get(&descriptor.parent) else {
        return false;
    };
    let Some(source_provenance) = source.released_provenance.as_ref() else {
        return false;
    };
    // The child recovery branch is reachable only after the atomic pivot.
    // That pivot keeps the installed child live-scoped but releases the
    // parent provider accounting into immutable provenance. Requiring the
    // parent to remain in `scoped_composites` selects the exact opposite state
    // and makes every legitimate post-pivot cold recovery fail closed.
    if !state.scoped_composites().contains_key(&child)
        || state.scoped_composites().contains_key(&descriptor.parent)
        || source.authority != AuthorityState::Revoked
        || source.custodian != CustodyState::Released
        || source_provenance.catalog_digest != descriptor.catalog_digest
        || !source_provenance
            .bindings
            .contains_key(&descriptor.parent_component)
        || source
            .components
            .values()
            .any(|component| component.retirement != RetirementState::Released)
    {
        return false;
    }
    let Some(component) = composite.components.get(&descriptor.child_component) else {
        return false;
    };
    let Some(commit_operation) = component.commit_operation else {
        return false;
    };
    matches!(
        recovery_operation.state,
        OperationRecoveryState::Fenced { .. }
    ) && composite.authority == AuthorityState::Fenced
        && composite.custodian == CustodyState::CoreOwned
        && matches!(composite.handoff, SingleHopRole::Target { parent, descriptor_digest, recovery_fact: None } if parent == descriptor.parent && descriptor_digest == handoff_descriptor_digest(descriptor))
        && matches!(&source.handoff, SingleHopRole::Source { descriptor: saved, descriptor_receipt_digest: saved_receipt, .. } if **saved == descriptor && *saved_receipt == descriptor_receipt_digest)
        && component.commit == CommitState::Committed
        && component.commit_nonce.is_none()
        && component.commit_fact.is_none()
        && component.outcome == OutcomeState::Indeterminate(commit_operation)
        && fact.role == HandoffRecoveryRole::Child
        && fact.effect == child
        && fact.component == descriptor.child_component
        && fact.operation == commit_operation
        && fact.descriptor_digest == handoff_descriptor_digest(descriptor)
}

/// Validates every coordinate carried by a handoff recovery fact before it is
/// allowed to alter an indeterminate outcome. This is deliberately separate
/// from the structural branch selector above: tag-41 replay must validate the
/// exact catalog-selected verifier and scope before any mutation.
#[derive(Clone, Copy)]
struct HandoffRecoveryCoordinates {
    role: HandoffRecoveryRole,
    effect: EffectId,
    component: ComponentId,
    operation: Digest,
    descriptor_digest: Digest,
    freshness: Freshness,
}

impl HandoffRecoveryCoordinates {
    const fn new(
        role: HandoffRecoveryRole,
        effect: EffectId,
        component: ComponentId,
        operation: Digest,
        descriptor_digest: Digest,
        freshness: Freshness,
    ) -> Self {
        Self {
            role,
            effect,
            component,
            operation,
            descriptor_digest,
            freshness,
        }
    }
}

fn handoff_recovery_fact_matches(
    state: &impl StateAccess,
    catalog: &DomainCatalog,
    fact: VerifiedHandoffRecoveryFact,
    expected: HandoffRecoveryCoordinates,
) -> bool {
    if fact.role != expected.role
        || fact.effect != expected.effect
        || fact.component != expected.component
        || fact.operation != expected.operation
        || fact.descriptor_digest != expected.descriptor_digest
        || fact.freshness != expected.freshness
        || fact.verification_scope.operation() != expected.effect.operation()
        || fact.stamp.receipt_digest.is_zero()
    {
        return false;
    }
    let Some(composite) = state.composite_effects().get(&expected.effect) else {
        return false;
    };
    let Some(record) = composite.components.get(&expected.component) else {
        return false;
    };
    let Some(binding) = catalog
        .obligation_rule(record.domain, record.obligation)
        .map(|rule| rule.receipts().commit_outcome())
    else {
        return false;
    };
    validate_state_verifier_identity(
        state,
        expected.effect,
        expected.component,
        fact.stamp.identity,
        binding.verifier(),
        binding.receipt_schema(),
    )
    .is_ok()
        && validate_state_verification_scope(
            state,
            expected.effect,
            expected.component,
            fact.verification_scope,
            binding.verifier(),
            binding.receipt_schema(),
        )
        .is_ok()
}

/// Summarizes every live custodian at one exact resource generation. Each
/// incumbent claim is interpreted by the immutable catalog recorded on its
/// owning composite; no incoming catalog or catalog-set iteration order may
/// change the result.
fn live_resource_conflict_summary_for_set(
    catalogs: &CatalogSet,
    state: &impl StateAccess,
    resource: ResourceId,
    generation: ResourceGeneration,
    candidate: ConflictMode,
) -> Result<(usize, bool), CoreError> {
    let mut custodians = 0usize;
    let mut compatible = true;
    let Some(entries) = state.composite_resource_index().get(&resource) else {
        return Ok((0, true));
    };
    for (effect, component, claim_id) in entries {
        let composite = state
            .composite_effects()
            .get(effect)
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = catalogs
            .get(composite.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let claim = composite
            .components
            .get(component)
            .and_then(|component| component.claims.get(claim_id))
            .ok_or(CoreError::InvariantViolation)?;
        if claim.retired || claim.resource != resource || claim.resource_generation != generation {
            return Err(CoreError::InvariantViolation);
        }
        let rule = catalog
            .claim_rule(claim.domain, claim.kind)
            .ok_or(CoreError::InvariantViolation)?;
        custodians = custodians
            .checked_add(1)
            .ok_or(CoreError::InvariantViolation)?;
        compatible &= candidate.compatible_with(rule.conflict());
    }
    Ok((custodians, compatible))
}

/// Returns whether an incoming class may join a live coordinate. Compatibility
/// is symmetric: every incumbent and the incoming claim must explicitly opt
/// into shared custody.
fn resource_allows_additional_custodian(
    catalogs: &CatalogSet,
    state: &impl StateAccess,
    resource: ResourceId,
    generation: ResourceGeneration,
    incoming: ConflictMode,
) -> Result<bool, CoreError> {
    let (custodians, compatible) =
        live_resource_conflict_summary_for_set(catalogs, state, resource, generation, incoming)?;
    if custodians == 0 {
        return Err(CoreError::InvariantViolation);
    }
    Ok(compatible)
}

fn handoff_source_claim_matches(
    source: &CompositeEffectRecord,
    descriptor: ChildDescriptorV1,
) -> bool {
    source
        .components
        .get(&descriptor.parent_component)
        .is_some_and(|component| {
            component.claims.len() == 1
                && component.claims.values().any(|claim| {
                    claim.id == descriptor.claim
                        && !claim.retired
                        && claim.kind == descriptor.claim_kind
                        && claim.scope == descriptor.scope
                        && claim.resource == descriptor.resource
                        && claim.resource_generation == descriptor.resource_generation
                        && claim.units == descriptor.units
                })
        })
}

#[allow(clippy::too_many_arguments)]
fn handoff_target_reservation_matches(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    kind: ClaimKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    descriptor: Option<ChildDescriptorV1>,
) -> bool {
    let Some(descriptor) = descriptor else {
        return false;
    };
    descriptor.child_effect() == Ok(effect)
        && descriptor.child_component == component
        && descriptor.claim == claim
        && descriptor.claim_kind == kind
        && descriptor.scope == scope
        && descriptor.resource == resource
        && descriptor.resource_generation == resource_generation
        && descriptor.units == units
        && matches!(
            state.composite_effects().get(&descriptor.parent),
            Some(source) if matches!(&source.handoff, SingleHopRole::Source { descriptor: saved, .. } if **saved == descriptor)
                && handoff_source_claim_matches(source, descriptor)
        )
}

/// Returns the descriptor for an installed child which is still only a
/// prepared, non-executable reservation. Such a child is the one handoff
/// state that cannot use the ordinary pre-commit abort path: its claim has
/// was admitted directly outside the live resource index and charge aggregate.
fn prepared_handoff_target_for_abort(
    state: &impl StateAccess,
    child: EffectId,
) -> Result<Option<ChildDescriptorV1>, CoreError> {
    let Some(target) = state.composite_effects().get(&child) else {
        return Err(CoreError::UnknownEffect);
    };
    let SingleHopRole::Target {
        parent,
        descriptor_digest,
        recovery_fact,
    } = target.handoff
    else {
        return Ok(None);
    };
    if recovery_fact.is_some() {
        return Err(CoreError::WrongCommitState);
    }
    let source = state
        .composite_effects()
        .get(&parent)
        .ok_or(CoreError::HandoffGuardRequired)?;
    let SingleHopRole::Source { descriptor, .. } = &source.handoff else {
        return Err(CoreError::HandoffGuardRequired);
    };
    let descriptor = **descriptor;
    if descriptor.child_effect() != Ok(child)
        || descriptor_digest != handoff_descriptor_digest(descriptor)
        || !handoff_source_claim_matches(source, descriptor)
    {
        return Err(CoreError::HandoffGuardRequired);
    }
    if !matches!(
        (target.authority, target.custodian),
        (AuthorityState::Active, CustodyState::Executor(_))
            | (AuthorityState::Fenced, CustodyState::CoreOwned)
    ) {
        return Err(CoreError::WrongCommitState);
    }
    let component = target
        .components
        .get(&descriptor.child_component)
        .ok_or(CoreError::UnknownObligationClass)?;
    if component.commit != CommitState::Prepared
        || component.commit_nonce.is_some()
        || component.commit_operation.is_some()
        || component.commit_fact.is_some()
        || component.outcome != OutcomeState::Pending
        || component.settlement != SettlementState::Unavailable
        || component.settlement_nonce.is_some()
        || component.claim_stage.is_some()
        || component.settlement_intent.is_some()
        || component.applied_fact.is_some()
        || component.settlement_fact.is_some()
        || component.claims.len() != 1
        || !component_is_prepared_handoff_target(state, target, component)
    {
        return Err(CoreError::WrongCommitState);
    }
    Ok(Some(descriptor))
}

/// Cancels the installed child reservation after its provider generation has
/// been fenced. The source claim remains the live custodian of the exact
/// resource coordinate; only the inactive child claim and its provider
/// binding are cleaned up. Both handoff roles are cleared because this branch
/// abandoned the child before its commit gate and has no outcome to resolve.
fn abort_prepared_handoff_target(
    state: &mut impl StateAccessMut,
    descriptor: ChildDescriptorV1,
) -> Result<AppliedOutput, CoreError> {
    let child = descriptor.child_effect()?;
    let (causal_owner, authority_epoch) = {
        let target = state
            .composite_effects()
            .get(&child)
            .ok_or(CoreError::UnknownEffect)?;
        let component = target
            .components
            .get(&descriptor.child_component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if !component_is_prepared_handoff_target(state, target, component) {
            return Err(CoreError::HandoffGuardRequired);
        }
        (target.causal_owner, target.authority_epoch)
    };

    // The reservation was deliberately omitted from both derived live
    // structures at install time. Removing its primary claim is therefore
    // the complete claim/resource cleanup; no charge or index decrement is
    // permitted here.
    state.touch_composite(child);
    state
        .composite_effects_mut()
        .get_mut(&child)
        .ok_or(CoreError::UnknownEffect)?
        .components
        .get_mut(&descriptor.child_component)
        .ok_or(CoreError::UnknownObligationClass)?
        .claims
        .clear();
    revoke_composite_effect(state, child, causal_owner, authority_epoch)?;

    state.touch_composite(descriptor.parent);
    state
        .composite_effects_mut()
        .get_mut(&descriptor.parent)
        .ok_or(CoreError::UnknownEffect)?
        .handoff = SingleHopRole::None;
    state.touch_composite(child);
    state
        .composite_effects_mut()
        .get_mut(&child)
        .ok_or(CoreError::UnknownEffect)?
        .handoff = SingleHopRole::None;

    revoke_unpinned_artifact_placeholders(state, child)?;
    let released = artifacts_released_for_effect(state, child);
    if released {
        state.touch_composite(child);
        let target = state
            .composite_effects_mut()
            .get_mut(&child)
            .ok_or(CoreError::UnknownEffect)?;
        target.custodian = CustodyState::Released;
        target.authority = AuthorityState::Revoked;
        for component in target.components.values_mut() {
            component.retirement = RetirementState::Released;
        }
        release_scoped_provider_bindings(state, child)?;
    }
    Ok(AppliedOutput::none(if released {
        TransitionEvent::CompositeEffectReleased
    } else {
        TransitionEvent::Revoked
    }))
}

fn component_is_prepared_handoff_target(
    state: &impl StateAccess,
    composite: &CompositeEffectRecord,
    component: &ComponentRecord,
) -> bool {
    component
        .claims
        .values()
        .any(|claim| prepared_handoff_target_claim(state, composite, component, claim))
}

fn release_handoff_source_claim(
    state: &mut impl StateAccessMut,
    descriptor: ChildDescriptorV1,
) -> Result<(), CoreError> {
    let (charge_owner, credit_class, source_claim) = {
        let source = state
            .composite_effects()
            .get(&descriptor.parent)
            .ok_or(CoreError::UnknownEffect)?;
        if !handoff_source_claim_matches(source, descriptor) {
            return Err(CoreError::HandoffGuardRequired);
        }
        let claim = source.components[&descriptor.parent_component]
            .claims
            .get(&descriptor.claim)
            .expect("matched sole source claim");
        (source.charge_owner, claim.credit_class, claim.id)
    };
    let charged = state
        .charges_mut()
        .get_mut(&(charge_owner, credit_class))
        .ok_or(CoreError::InvariantViolation)?;
    *charged = charged
        .checked_sub(descriptor.units)
        .ok_or(CoreError::InvariantViolation)?;
    let entries = state
        .composite_resource_index_mut()
        .get_mut(&descriptor.resource)
        .ok_or(CoreError::InvariantViolation)?;
    let before = entries.len();
    entries
        .retain(|entry| *entry != (descriptor.parent, descriptor.parent_component, source_claim));
    if entries.len() + 1 != before {
        return Err(CoreError::InvariantViolation);
    }
    if entries.is_empty() {
        state
            .composite_resource_index_mut()
            .remove_mut(&descriptor.resource);
    }
    state.touch_resource(descriptor.resource);
    if !state
        .composite_resource_index()
        .contains_key(&descriptor.resource)
    {
        state.touch_resource(descriptor.resource);
        state
            .resources_mut()
            .get_mut(&descriptor.resource)
            .ok_or(CoreError::InvariantViolation)?
            .phase = ResourcePhase::Retired;
    }
    state.touch_composite(descriptor.parent);
    state
        .composite_effects_mut()
        .get_mut(&descriptor.parent)
        .expect("validated source")
        .components
        .get_mut(&descriptor.parent_component)
        .expect("validated source component")
        .claims
        .clear();
    Ok(())
}

fn activate_prepared_handoff_target(
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut impl StateAccessMut,
    child: EffectId,
    descriptor: ChildDescriptorV1,
) -> Result<(), CoreError> {
    let (charge_owner, credit_class, target_catalog_digest) = {
        let target = state
            .composite_effects()
            .get(&child)
            .ok_or(CoreError::UnknownEffect)?;
        let claim = target
            .components
            .get(&descriptor.child_component)
            .and_then(|component| component.claims.get(&descriptor.claim))
            .ok_or(CoreError::UnknownClaim)?;
        if claim.retired
            || claim.kind != descriptor.claim_kind
            || claim.scope != descriptor.scope
            || claim.resource != descriptor.resource
            || claim.resource_generation != descriptor.resource_generation
            || claim.units != descriptor.units
        {
            return Err(CoreError::HandoffGuardRequired);
        }
        (
            target.charge_owner,
            claim.credit_class,
            target.catalog_digest,
        )
    };
    if target_catalog_digest != catalog.digest() || descriptor.catalog_digest != catalog.digest() {
        return Err(CoreError::CatalogMismatch);
    }
    let limit = catalog
        .credit_rule(credit_class)
        .ok_or(CoreError::InvariantViolation)?
        .max_units_per_account()
        .min(limits.max_units_per_account);
    let charged_catalog = charged_for_catalog(state, catalog.digest(), charge_owner, credit_class)?
        .checked_sub(descriptor.units)
        .ok_or(CoreError::InvariantViolation)?;
    // The source claim has already been released and the target reservation
    // is transiently no longer recognizable by the stable-state reservation
    // helper: that helper deliberately requires the source claim to remain
    // present. The exact target claim was validated above and is still absent
    // from the reverse index, so remove its already-counted units before
    // checking the post-pivot catalog subtotal. Then add exactly those units
    // to the cross-catalog aggregate cache; never replace the aggregate with
    // the local catalog subtotal.
    let next_catalog = charged_catalog
        .checked_add(descriptor.units)
        .ok_or(CoreError::Backpressure)?;
    if next_catalog > limit {
        return Err(CoreError::Backpressure);
    }
    let next_global = state
        .charges()
        .get(&(charge_owner, credit_class))
        .copied()
        .unwrap_or(0)
        .checked_add(descriptor.units)
        .ok_or(CoreError::Backpressure)?;
    if next_global > limits.max_units_per_account {
        return Err(CoreError::Backpressure);
    }
    *state
        .charges_mut()
        .get_or_insert_with_mut((charge_owner, credit_class), || 0) = next_global;
    state.touch_resource(descriptor.resource);
    let resource_record = state
        .resources_mut()
        .get_mut(&descriptor.resource)
        .ok_or(CoreError::InvariantViolation)?;
    if resource_record.scope != descriptor.scope
        || resource_record.generation != descriptor.resource_generation
        || !matches!(
            resource_record.phase,
            ResourcePhase::Retired | ResourcePhase::Claimed { .. }
        )
    {
        return Err(CoreError::InvariantViolation);
    }
    resource_record.phase = ResourcePhase::Claimed {
        pending_reuse: None,
    };
    let entries = state
        .composite_resource_index_mut()
        .get_or_insert_with_mut(descriptor.resource, Vec::new);
    match entries.binary_search(&(child, descriptor.child_component, descriptor.claim)) {
        Ok(_) => return Err(CoreError::InvariantViolation),
        Err(index) => entries.insert(index, (child, descriptor.child_component, descriptor.claim)),
    }
    Ok(())
}

fn prepared_handoff_target_claim(
    state: &impl StateAccess,
    composite: &CompositeEffectRecord,
    component: &ComponentRecord,
    claim: &ClaimRecord,
) -> bool {
    let SingleHopRole::Target {
        parent,
        descriptor_digest,
        recovery_fact: _,
    } = composite.handoff
    else {
        return false;
    };
    let Some(source) = state.composite_effects().get(&parent) else {
        return false;
    };
    let SingleHopRole::Source { descriptor, .. } = &source.handoff else {
        return false;
    };
    matches!(
        component.commit,
        CommitState::Prepared | CommitState::CommitIntentDurable
    )
        // A target remains charge/index-deactivated until the pivot restores
        // its live custody.  Checking the derived index makes this helper
        // valid across the target's Prepared -> CommitIntentDurable step; it
        // becomes false immediately after activation adds the exact index
        // entry back.
        && !state
            .composite_resource_index()
            .get(&claim.resource)
            .is_some_and(|entries| {
                entries.contains(&(composite.effect, component.id, claim.id))
            })
        && handoff_source_claim_matches(source, **descriptor)
        && handoff_descriptor_digest(**descriptor) == descriptor_digest
        && descriptor.child_effect() == Ok(composite.effect)
        && descriptor.child_component == component.id
        && descriptor.claim == claim.id
        && descriptor.claim_kind == claim.kind
        && descriptor.scope == claim.scope
        && descriptor.resource == claim.resource
        && descriptor.resource_generation == claim.resource_generation
        && descriptor.units == claim.units
        && !claim.retired
}

/// Returns the live charge total owned by one immutable catalog.  The
/// persisted `State::charges` map is intentionally an aggregate cache keyed
/// only by account/class, so cross-catalog validation must not infer a
/// catalog-local limit from that aggregate (or from another catalog's rule).
fn charged_for_catalog(
    state: &impl StateAccess,
    catalog_digest: Digest,
    charge_owner: ChargeAccountId,
    credit_class: CreditClassId,
) -> Result<u64, CoreError> {
    state
        .composite_effects()
        .values()
        .filter(|composite| {
            composite.catalog_digest == catalog_digest && composite.charge_owner == charge_owner
        })
        .flat_map(|composite| {
            composite
                .components
                .values()
                .map(move |component| (composite, component))
        })
        .flat_map(|(composite, component)| {
            component.claims.values().filter_map(move |claim| {
                (claim.credit_class == credit_class
                    && !claim.retired
                    && !prepared_handoff_target_claim(state, composite, component, claim))
                .then_some(claim.units)
            })
        })
        .try_fold(0u64, |total, units| {
            total
                .checked_add(units)
                .ok_or(CoreError::InvariantViolation)
        })
}

#[allow(clippy::too_many_arguments)]
fn enroll_component_claim(
    catalogs: &CatalogSet,
    catalog: &DomainCatalog,
    limits: CoreLimits,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    actor: ExecutorCoordinate,
    claim: ClaimId,
    kind: ClaimKindId,
    scope: ClaimScope,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    units: u64,
    reservation_nonce: Option<u64>,
    handoff_target: Option<ChildDescriptorV1>,
) -> Result<AppliedOutput, CoreError> {
    if units == 0 {
        return Err(CoreError::InvalidPayload);
    }
    require_active_composite_actor(state, effect, actor)?;
    let (domain, obligation, charge_owner, authority, commit) = {
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        (
            component_record.domain,
            component_record.obligation,
            composite.charge_owner,
            composite.authority,
            component_record.commit,
        )
    };
    if authority != AuthorityState::Active || commit != CommitState::Registered {
        return Err(CoreError::WrongCommitState);
    }
    // `component_freshness` is intentionally a scalar coordinate today. A
    // component may therefore carry logical claims or claims for one device
    // scope, but admitting a second distinct device scope would create a
    // state that cannot be given one exact freshness for commit/settlement.
    if let ClaimScope::Device(incoming_scope) = scope {
        let existing_scope = state
            .composite_effects()
            .get(&effect)
            .and_then(|composite| composite.components.get(&component))
            .and_then(|component| {
                component
                    .claims
                    .values()
                    .find_map(|claim| match claim.scope {
                        ClaimScope::Device(scope) => Some(scope),
                        ClaimScope::Logical => None,
                    })
            });
        if existing_scope.is_some_and(|existing| existing != incoming_scope) {
            return Err(CoreError::WrongClaimScope);
        }
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
        if !state.device_generations().contains_key(&device_scope) {
            if state.device_generations().len() >= limits.max_device_generations {
                return Err(CoreError::CapacityExceeded);
            }
            let device_generation = state.freshness().device();
            state.touch_device(device_scope);
            state
                .device_generations_mut()
                .insert_mut(device_scope, device_generation);
        }
        if state.device_quarantine().contains(&device_scope) {
            return Err(CoreError::Quarantined);
        }
    }
    let cardinality = catalog
        .obligation_rule(domain, obligation)
        .ok_or(CoreError::InvariantViolation)?
        .claims()
        .iter()
        .find(|allowed| allowed.kind() == kind)
        .ok_or(CoreError::ClaimNotAllowed)?;
    let credit_class = rule.credit_class();
    let credit_limit = catalog
        .credit_rule(credit_class)
        .ok_or(CoreError::InvariantViolation)?
        .max_units_per_account()
        .min(limits.max_units_per_account);
    let inactive_handoff_reservation = handoff_target.is_some();

    match (state.resources().get(&resource), reservation_nonce) {
        (None, None) if resource_generation.get() == 1 => {
            if state.resources().len() >= limits.max_resource_records {
                return Err(CoreError::CapacityExceeded);
            }
        }
        (
            Some(ResourceRecord {
                scope: existing_scope,
                generation,
                phase:
                    ResourcePhase::Claimed {
                        pending_reuse: Some(pending),
                    },
            }),
            Some(presented_nonce),
        ) if *existing_scope == scope
            && *generation == resource_generation
            && pending.effect == effect
            && pending.component == component
            && pending.nonce == presented_nonce => {}
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
        ) => return Err(CoreError::ResourceReuseRequired),
        // Same admission algebra as the single-obligation path. A shared
        // coordinate may be co-held across components of one composite, or
        // across separate effects; the retirement reference count spans both
        // indexes, so neither can strand the other.
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
            if !resource_allows_additional_custodian(
                catalogs,
                state,
                resource,
                resource_generation,
                rule.conflict(),
            )? && !handoff_target_reservation_matches(
                state,
                effect,
                component,
                claim,
                kind,
                scope,
                resource,
                resource_generation,
                units,
                handoff_target,
            ) {
                return Err(CoreError::ResourceRetained);
            }
        }
        (Some(ResourceRecord { .. }), Some(_)) | (None, Some(_)) => {
            return Err(CoreError::StaleReusePermit);
        }
        (None, None) => return Err(CoreError::StaleResourceGeneration),
    }

    let enrolled_freshness = scoped_freshness(state, scope)?;
    if state.total_claims() >= limits.max_total_claims {
        return Err(CoreError::CapacityExceeded);
    }
    let charged = charged_for_catalog(state, catalog.digest(), charge_owner, credit_class)?;
    let current_global = state
        .charges()
        .get(&(charge_owner, credit_class))
        .copied()
        .unwrap_or(0);
    let next_global = if inactive_handoff_reservation {
        // The child is durable topology but not yet a live custodian. Do not
        // transiently charge or index it only to subtract those derived values
        // later in the same transition: that can overflow or falsely reject a
        // replacement at the exact account ceiling. The pivot performs the
        // real post-source-release capacity check before activating custody.
        if units > credit_limit {
            return Err(CoreError::Backpressure);
        }
        current_global
    } else {
        let next_catalog = charged.checked_add(units).ok_or(CoreError::Backpressure)?;
        if next_catalog > credit_limit {
            return Err(CoreError::Backpressure);
        }
        let next = current_global
            .checked_add(units)
            .ok_or(CoreError::Backpressure)?;
        if next > limits.max_units_per_account {
            return Err(CoreError::Backpressure);
        }
        next
    };
    state.touch_composite(effect);
    let composite = state
        .composite_effects_mut()
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    if composite
        .components
        .values()
        .any(|candidate| candidate.claims.contains_key(&claim))
    {
        return Err(CoreError::DuplicateClaim);
    }
    let component_record = composite
        .components
        .get_mut(&component)
        .ok_or(CoreError::UnknownObligationClass)?;
    let existing_of_kind = component_record
        .claims
        .values()
        .filter(|candidate| candidate.kind == kind)
        .count();
    if existing_of_kind >= usize::from(cardinality.maximum()) {
        return Err(CoreError::ClaimCardinalityViolation);
    }
    if component_record.claims.len() >= limits.max_claims_per_effect {
        return Err(CoreError::CapacityExceeded);
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
    component_record.claims.insert(
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
    if !inactive_handoff_reservation {
        *state
            .charges_mut()
            .get_or_insert_with_mut((charge_owner, credit_class), || 0) = next_global;
        let entries = state
            .composite_resource_index_mut()
            .get_or_insert_with_mut(resource, Vec::new);
        match entries.binary_search(&(effect, component, claim)) {
            Ok(_) => return Err(CoreError::InvariantViolation),
            Err(index) => entries.insert(index, (effect, component, claim)),
        }
    }
    if reservation_nonce.is_none() && !inactive_handoff_reservation {
        state.touch_resource(resource);
        state.resources_mut().insert_mut(
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
    let total_claims = state
        .total_claims()
        .checked_add(1)
        .ok_or(CoreError::CapacityExceeded)?;
    state.set_total_claims(total_claims);
    Ok(AppliedOutput::none(TransitionEvent::ClaimAdded))
}

fn allocate_nonce(state: &mut impl StateAccessMut) -> Result<u64, CoreError> {
    let nonce = state.next_nonce();
    let next_nonce = state
        .next_nonce()
        .checked_add(1)
        .ok_or(CoreError::GenerationExhausted)?;
    state.set_next_nonce(next_nonce);
    if nonce == 0 {
        return Err(CoreError::GenerationExhausted);
    }
    Ok(nonce)
}

fn validate_component_claims(
    catalog: &DomainCatalog,
    component: &ComponentRecord,
) -> Result<(), CoreError> {
    let mut device_scope = None;
    for claim in component.claims.values() {
        if let ClaimScope::Device(scope) = claim.scope
            && device_scope
                .replace(scope)
                .is_some_and(|existing| existing != scope)
        {
            return Err(CoreError::WrongClaimScope);
        }
    }
    let rule = catalog
        .obligation_rule(component.domain, component.obligation)
        .ok_or(CoreError::InvariantViolation)?;
    if component.claims.len() < usize::from(rule.minimum_total_claims()) {
        return Err(CoreError::ClaimCardinalityViolation);
    }
    for cardinality in rule.claims() {
        let count = component
            .claims
            .values()
            .filter(|claim| claim.kind == cardinality.kind())
            .count();
        if count < usize::from(cardinality.minimum()) || count > usize::from(cardinality.maximum())
        {
            return Err(CoreError::ClaimCardinalityViolation);
        }
    }
    if component.claims.values().any(|claim| {
        !rule
            .claims()
            .iter()
            .any(|allowed| allowed.kind() == claim.kind)
    }) {
        return Err(CoreError::ClaimNotAllowed);
    }
    Ok(())
}

fn scoped_freshness(state: &impl StateAccess, scope: ClaimScope) -> Result<Freshness, CoreError> {
    let freshness = state.freshness();
    match scope {
        ClaimScope::Logical => Ok(freshness),
        ClaimScope::Device(device_scope) => state
            .device_generations()
            .get(&device_scope)
            .copied()
            .map(|device| freshness.with_device(device))
            .ok_or(CoreError::WrongClaimScope),
    }
}

fn component_freshness(
    state: &impl StateAccess,
    _composite: &CompositeEffectRecord,
    component: &ComponentRecord,
) -> Result<Freshness, CoreError> {
    let mut device_scope = None;
    for claim in component.claims.values() {
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
    )
}

fn component_claim_matches(component: &ComponentRecord, claim: &SettlementClaim) -> bool {
    let identity_matches = match component.settlement {
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
    identity_matches && component.settlement_nonce == Some(claim.nonce)
}

fn component_terminal(component: &ComponentRecord) -> bool {
    matches!(
        component.retirement,
        RetirementState::Retired | RetirementState::Released
    ) && matches!(
        component.settlement,
        SettlementState::Settled | SettlementState::Revoked | SettlementState::NotRequired
    )
}

fn component_abort_terminal(
    composite: &CompositeEffectRecord,
    component: &ComponentRecord,
) -> bool {
    composite.authority == AuthorityState::Revoked
        && matches!(
            component.commit,
            CommitState::Registered | CommitState::Prepared
        )
        && component.outcome == OutcomeState::Pending
        && component.settlement == SettlementState::Revoked
        && component.settlement_nonce.is_none()
        && component.claim_stage.is_none()
        && component.settlement_intent.is_none()
        && component.applied_fact.is_none()
        && component.settlement_fact.is_none()
        && component.commit_nonce.is_none()
        && component.commit_operation.is_none()
        && component.commit_fact.is_none()
        && component.claims.is_empty()
        && matches!(
            component.retirement,
            RetirementState::Retired | RetirementState::Released
        )
}

fn validate_component_execution_adoption(
    catalog: &DomainCatalog,
    component: &ComponentRecord,
) -> Result<(), CoreError> {
    let adoption = catalog
        .obligation_rule(component.domain, component.obligation)
        .ok_or(CoreError::InvariantViolation)?
        .adoption();
    if adoption != crate::AdoptionPolicy::UncommittedOnly {
        return Err(CoreError::AdoptionForbidden);
    }
    if !matches!(
        component.commit,
        CommitState::Registered | CommitState::Prepared
    ) || component.settlement != SettlementState::Unavailable
        || !matches!(
            component.retirement,
            RetirementState::Held | RetirementState::RetirementPending
        )
        || component.claims.values().any(|claim| {
            claim.retired
                || claim
                    .requirements
                    .iter()
                    .any(|requirement| requirement.accepted.is_some())
        })
    {
        return Err(CoreError::WrongCommitState);
    }
    Ok(())
}

fn rebase_composite_precommit_claims(
    catalog: &DomainCatalog,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    actor: ExecutorCoordinate,
) -> Result<(), CoreError> {
    if state.recovery_target().is_some() {
        return Err(CoreError::RecoveryPending);
    }
    require_active_composite_actor(state, effect, actor)?;

    let mut rebases = Vec::new();
    let mut touched_device_scopes = BTreeSet::new();
    let mut has_stale_claim = false;
    {
        state.touch_composite(effect);
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        if composite.causal_owner == actor
            || composite.authority_epoch <= 1
            || composite_escape_state(composite) != EffectEscapeState::Unescaped
        {
            return Err(CoreError::WrongCommitState);
        }
        for component in composite.components.values() {
            validate_component_execution_adoption(catalog, component)?;
            if !matches!(
                component.commit,
                CommitState::Registered | CommitState::Prepared
            ) || component.commit_nonce.is_some()
                || component.commit_operation.is_some()
                || component.commit_fact.is_some()
                || component.outcome != OutcomeState::Pending
                || component.settlement != SettlementState::Unavailable
                || component.settlement_nonce.is_some()
                || component.claim_stage.is_some()
                || component.settlement_intent.is_some()
                || component.applied_fact.is_some()
                || component.settlement_fact.is_some()
                || component.retirement != RetirementState::Held
            {
                return Err(CoreError::WrongCommitState);
            }
            for claim in component.claims.values() {
                if claim.retired
                    || claim
                        .requirements
                        .iter()
                        .any(|requirement| requirement.accepted.is_some())
                {
                    return Err(CoreError::WrongCommitState);
                }
                let current = scoped_freshness(state, claim.scope)?;
                has_stale_claim |= claim.enrolled_freshness != current;
                if let ClaimScope::Device(scope) = claim.scope {
                    touched_device_scopes.insert(scope);
                }
                rebases.push((component.id, claim.id, current));
            }
        }
    }
    if !has_stale_claim {
        return Err(CoreError::StaleEvidence);
    }
    if touched_device_scopes
        .iter()
        .any(|scope| device_scope_has_retained_claim_outside_composite(state, *scope, effect))
    {
        return Err(CoreError::ResourceRetained);
    }

    {
        state.touch_composite(effect);
        let composite = state
            .composite_effects_mut()
            .get_mut(&effect)
            .expect("composite was validated before claim rebasing");
        for (component, claim, freshness) in rebases {
            composite
                .components
                .get_mut(&component)
                .and_then(|record| record.claims.get_mut(&claim))
                .expect("claim was validated before claim rebasing")
                .enrolled_freshness = freshness;
        }
    }
    for scope in touched_device_scopes {
        if !device_scope_has_stale_retained_claim(state, scope)? {
            state.touch_device(scope);
            state.device_quarantine_mut().remove_mut(&scope);
        }
    }
    Ok(())
}

fn composite_escape_state(composite: &CompositeEffectRecord) -> EffectEscapeState {
    if composite.custodian == CustodyState::Released
        || composite
            .components
            .values()
            .all(|component| component.retirement == RetirementState::Released)
    {
        return EffectEscapeState::Released;
    }
    if composite.components.values().all(component_terminal) {
        return EffectEscapeState::Retired;
    }
    let escaped = composite.components.values().any(|component| {
        matches!(
            component.commit,
            CommitState::CommitIntentDurable | CommitState::Committed
        )
    });
    if !escaped {
        return EffectEscapeState::Unescaped;
    }
    let discharged = composite.components.values().any(|component| {
        component.claims.values().any(|claim| claim.retired)
            || matches!(
                component.settlement,
                SettlementState::Settled | SettlementState::Revoked
            )
            || component.retirement == RetirementState::Retired
    });
    if discharged {
        EffectEscapeState::PartiallyDischarged
    } else {
        EffectEscapeState::Escaped
    }
}

fn quarantine_live_device_claims(state: &mut impl StateAccessMut) {
    let scopes: Vec<_> = state
        .composite_effects()
        .values()
        .flat_map(|composite| composite.components.values())
        .flat_map(|component| component.claims.values())
        .filter(|claim| !claim.retired)
        .filter_map(|claim| match claim.scope {
            ClaimScope::Device(scope) => Some(scope),
            ClaimScope::Logical => None,
        })
        .collect();
    for scope in scopes {
        state.touch_device(scope);
        state.device_quarantine_mut().insert_mut(scope);
    }
}

/// Replays a trusted record slice through one delta per record.  The helper is
/// shared by anchored recovery and journal-checkpoint validation so both paths
/// retain the same command, projection, and checkpoint semantics.
fn replay_records(
    engine: &mut Engine,
    records: &[JournalRecord],
    binding: RecoveryBinding,
    expected_world: WorldId,
) -> Result<(), CoreError> {
    for (index, record) in records.iter().enumerate() {
        let replay_catalog = if matches!(
            record.command(),
            CommandKind::CheckpointRecovery { .. }
                | CommandKind::WholeStateCheckpointV1 { .. }
                | CommandKind::Snapshot { .. }
                | CommandKind::FenceExecutor { .. }
                | CommandKind::Ready { .. }
                | CommandKind::Rebind { .. }
        ) {
            None
        } else {
            let digest = engine.command_catalog_digest(record.command())?;
            Some(
                engine
                    .catalog
                    .get(digest)
                    .ok_or(CoreError::SchemaMismatch)?,
            )
        };
        if record.recovery_binding() != binding {
            return Err(CoreError::RollbackDetected);
        }

        // A leading whole-state checkpoint is a validated base for replay,
        // not a command which needs to decode the same image again.  Every
        // later checkpoint is decoded exactly once here and compared as a
        // no-op against the delta candidate.
        let mut decoded_checkpoint = None;
        let mut validated_checkpoint_base = false;
        if let CommandKind::WholeStateCheckpointV1 {
            state: image,
            projection,
        } = record.command()
        {
            let rebuilt = decode_whole_state_checkpoint(image, &engine.catalog, engine.limits)?;
            if rebuilt.recovery_target.is_some() || rebuilt.projection_cache.digest != *projection {
                return Err(CoreError::RollbackDetected);
            }
            if index == 0 {
                if rebuilt.revision != record.base_revision()
                    || rebuilt.head != record.predecessor()
                    || rebuilt.freshness.boot() != record.boot()
                    || rebuilt.freshness.registry() != record.registry()
                    || rebuilt.freshness.journal() != record.journal()
                    || rebuilt.freshness.device() != record.device()
                {
                    return Err(CoreError::RollbackDetected);
                }
                if rebuilt.world != expected_world {
                    return Err(CoreError::WorldMismatch);
                }
                engine.state = rebuilt;
                validated_checkpoint_base = true;
            } else {
                decoded_checkpoint = Some(rebuilt);
            }
        }

        if record.base_revision() != engine.state.revision()
            || record.revision()
                != engine
                    .state
                    .revision
                    .checked_add(1)
                    .ok_or(CoreError::GenerationExhausted)?
        {
            return Err(CoreError::RevisionConflict);
        }
        if record.predecessor() != engine.state.head() {
            return Err(CoreError::PredecessorMismatch);
        }
        if record.catalog_digest() != engine.catalog.digest()
            || record.registry() != engine.state.freshness().registry()
            || record.boot() != engine.state.freshness().boot()
            || record.journal() != engine.state.freshness().journal()
            || record.device() != engine.state.freshness().device()
        {
            return Err(CoreError::SchemaMismatch);
        }

        // The record was prepared while cold recovery retained the trusted
        // anchor's projection cache, even though the primary overlay was
        // staged for the pending checkpoint. Keep that ordering: validate the
        // record against the old cache before staging its prelude in this
        // replay delta.
        if record.base_projection() != engine.projection_digest() {
            return Err(CoreError::RollbackDetected);
        }

        let mut delta = DeltaBuilder::new(&engine.state);
        restore_checkpoint_recovery_prelude(&mut delta, record.command())?;
        let prelude_touches = delta.take_projection_touches();

        if validated_checkpoint_base {
            // The leading checkpoint was decoded and installed above; it is
            // the validated replay base and therefore a no-op record.
        } else if let Some(rebuilt) = decoded_checkpoint.as_ref() {
            if !checkpoint_state_matches(&delta, rebuilt) {
                return Err(CoreError::InvariantViolation);
            }
        } else {
            apply_command(
                &engine.catalog,
                replay_catalog,
                engine.limits,
                &mut delta,
                record.command(),
            )?;
        }

        let mut touches = delta.take_projection_touches();
        touches.merge(prelude_touches);
        delta.set_total_claims(transition_total_claims(&engine.state, &delta, &touches)?);
        check_transition_local_invariants(
            replay_catalog,
            engine.limits,
            &engine.state,
            &delta,
            &touches,
        )?;
        delta.set_revision(record.revision());
        delta.set_head(record.digest());
        refresh_projection_cache(&engine.state, &mut delta, &touches, engine.catalog.digest());
        delta.finish().apply(&mut engine.state);
    }
    Ok(())
}

fn restore_checkpoint_recovery_prelude(
    state: &mut impl StateAccessMut,
    command: &CommandKind,
) -> Result<(), CoreError> {
    let CommandKind::CheckpointRecovery {
        boot,
        journal,
        device,
    } = command
    else {
        return Ok(());
    };
    if boot.get() <= state.freshness().boot().get()
        || journal.get() <= state.freshness().journal().get()
        || device.get() < state.freshness().device().get()
    {
        return Err(CoreError::FreshnessRollback);
    }
    let target = Freshness::new(*boot, state.freshness().registry(), *device, *journal);
    // Replay may need this overlay to validate the record's base projection,
    // but must keep it in the same delta as the command itself.  In
    // particular, do not rebuild the complete projection before the command
    // has been applied.
    state.set_recovery_target(Some(target));
    quarantine_live_device_claims(state);
    Ok(())
}

fn scope_is_quarantined(state: &impl StateAccess, scope: ClaimScope) -> bool {
    matches!(scope, ClaimScope::Device(device) if state.device_quarantine().contains(&device))
}

fn require_digest(digest: Digest) -> Result<(), CoreError> {
    if digest.is_zero() {
        Err(CoreError::InvalidPayload)
    } else {
        Ok(())
    }
}

fn require_active_composite_actor(
    state: &impl StateAccess,
    effect: EffectId,
    actor: ExecutorCoordinate,
) -> Result<(), CoreError> {
    let operation = state
        .recovery_operations()
        .get(&effect.operation())
        .ok_or(CoreError::UnknownOperation)?;
    let live = match operation.state {
        OperationRecoveryState::Active { executor }
        | OperationRecoveryState::Rebound {
            successor: executor,
        } => executor,
        _ => return Err(CoreError::WrongRecoveryState),
    };
    if live != actor {
        return Err(CoreError::StaleExecutor);
    }
    let composite = state
        .composite_effects()
        .get(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    if composite.authority != AuthorityState::Active
        || composite.custodian != CustodyState::Executor(actor)
    {
        return Err(CoreError::StaleExecutor);
    }
    Ok(())
}

fn exact_component_claim_mut(
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    claimant: ExecutorCoordinate,
    generation: u64,
    nonce: u64,
) -> Result<&mut ComponentRecord, CoreError> {
    state.touch_composite(effect);
    let component_record = state
        .composite_effects_mut()
        .get_mut(&effect)
        .and_then(|composite| composite.components.get_mut(&component))
        .ok_or(CoreError::UnknownEffect)?;
    let matches = match component_record.settlement {
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
    if !matches || component_record.settlement_nonce != Some(nonce) {
        return Err(CoreError::StaleSettlementClaim);
    }
    Ok(component_record)
}

fn apply_fence_incarnation(
    state: &mut impl StateAccessMut,
    operation: OperationId,
    crashed: ExecutorCoordinate,
    max_crashes: u64,
) -> Result<(), CoreError> {
    state.touch_operation(operation);
    let quota_exhausted = {
        let operation_record = state
            .recovery_operations_mut()
            .get_mut(&operation)
            .ok_or(CoreError::UnknownOperation)?;
        let live = match operation_record.state {
            OperationRecoveryState::Active { executor }
            | OperationRecoveryState::Rebound {
                successor: executor,
            } => executor,
            OperationRecoveryState::RecoveryExhausted { .. } => {
                return Err(CoreError::RecoveryExhausted);
            }
            _ => return Err(CoreError::WrongRecoveryState),
        };
        if live != crashed {
            return Err(CoreError::StaleExecutor);
        }
        let (crash_generation, exhausted) =
            next_crash_generation(operation_record.crash_generation, max_crashes);
        operation_record.crash_generation = crash_generation;
        operation_record.last_executor = crashed;
        operation_record.state = if exhausted {
            OperationRecoveryState::RecoveryExhausted {
                crashed,
                crash_generation,
            }
        } else {
            OperationRecoveryState::Fenced {
                crashed,
                crash_generation,
            }
        };
        exhausted
    };
    let authority_epoch_exhausted = fence_composite_effects(state, operation)?;
    if authority_epoch_exhausted && !quota_exhausted {
        state.touch_operation(operation);
        let operation_record = state
            .recovery_operations_mut()
            .get_mut(&operation)
            .expect("operation was validated");
        operation_record.state = OperationRecoveryState::RecoveryExhausted {
            crashed,
            crash_generation: operation_record.crash_generation,
        };
    }
    Ok(())
}

/// Fences every composite effect and returns whether an authority epoch saturated.
fn fence_composite_effects(
    state: &mut impl StateAccessMut,
    operation: OperationId,
) -> Result<bool, CoreError> {
    let mut authority_epoch_exhausted = false;
    let composite_ids: Vec<EffectId> = state
        .composite_effects()
        .keys()
        .copied()
        .filter(|effect| effect.operation() == operation)
        .collect();
    for effect in composite_ids {
        state.touch_composite(effect);
        let composite = state
            .composite_effects_mut()
            .get_mut(&effect)
            .expect("composite was collected from state");
        if composite_escape_state(composite) == EffectEscapeState::Released {
            continue;
        }
        if composite.authority != AuthorityState::Revoked {
            if composite.authority == AuthorityState::Active {
                match composite.authority_epoch.checked_add(1) {
                    Some(next) => composite.authority_epoch = next,
                    None => authority_epoch_exhausted = true,
                }
            }
            composite.authority = AuthorityState::Fenced;
            composite.custodian = CustodyState::CoreOwned;
        }
        for component in composite.components.values_mut() {
            if component.commit == CommitState::CommitIntentDurable {
                let reason = component
                    .commit_operation
                    .ok_or(CoreError::InvariantViolation)?;
                component.commit = CommitState::Committed;
                component.commit_nonce = None;
                component.outcome = OutcomeState::Indeterminate(reason);
            }
            if component.commit == CommitState::Committed {
                initialize_component_disposition(component)?;
                if component.obligation_policy == ObligationPolicy::SuccessorSettlement {
                    reclaim_component_settlement(component)?;
                }
            }
            refresh_component_retirement(component, composite.authority);
        }
    }
    Ok(authority_epoch_exhausted)
}

fn initialize_component_disposition(component: &mut ComponentRecord) -> Result<(), CoreError> {
    match (component.obligation_policy, component.settlement) {
        (ObligationPolicy::SuccessorSettlement, SettlementState::Unavailable) => {
            component.settlement = SettlementState::Open { generation: 1 };
        }
        (ObligationPolicy::RetirementEvidence, SettlementState::Unavailable) => {
            component.settlement = SettlementState::NotRequired;
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

fn reclaim_component_settlement(component: &mut ComponentRecord) -> Result<(), CoreError> {
    let next_generation =
        match component.settlement {
            SettlementState::Unavailable => 1,
            SettlementState::NotRequired => return Ok(()),
            SettlementState::Open { generation } | SettlementState::Claimed { generation, .. } => {
                generation
                    .checked_add(u64::from(!matches!(
                        component.settlement,
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
    component.settlement = match component.settlement {
        SettlementState::Claimed { .. } => match component.claim_stage {
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
            component.settlement
        }
        _ => SettlementState::Open {
            generation: next_generation,
        },
    };
    component.settlement_nonce = None;
    component.claim_stage = None;
    Ok(())
}

fn fence_operation_for_boot(
    state: &mut impl StateAccessMut,
    operation: OperationId,
    max_crashes: u64,
) -> Result<(), CoreError> {
    if matches!(
        state
            .recovery_operations()
            .get(&operation)
            .ok_or(CoreError::UnknownOperation)?
            .state,
        OperationRecoveryState::Fenced { .. } | OperationRecoveryState::RecoveryExhausted { .. }
    ) {
        return Ok(());
    }
    let (crashed, quota_exhausted) = {
        state.touch_operation(operation);
        let operation_record = state
            .recovery_operations_mut()
            .get_mut(&operation)
            .ok_or(CoreError::UnknownOperation)?;
        let crashed = match operation_record.state {
            OperationRecoveryState::Active { executor, .. }
            | OperationRecoveryState::Rebound {
                successor: executor,
                ..
            } => executor,
            OperationRecoveryState::Fenced { .. }
            | OperationRecoveryState::RecoveryExhausted { .. } => {
                unreachable!("terminal fence states returned above")
            }
            OperationRecoveryState::Snapshotted { .. } | OperationRecoveryState::Ready { .. } => {
                operation_record.last_executor
            }
        };
        let (crash_generation, quota_exhausted) =
            next_crash_generation(operation_record.crash_generation, max_crashes);
        operation_record.crash_generation = crash_generation;
        operation_record.state = if quota_exhausted {
            OperationRecoveryState::RecoveryExhausted {
                crashed,
                crash_generation,
            }
        } else {
            OperationRecoveryState::Fenced {
                crashed,
                crash_generation,
            }
        };
        (crashed, quota_exhausted)
    };
    let authority_epoch_exhausted = fence_composite_effects(state, operation)?;
    if authority_epoch_exhausted && !quota_exhausted {
        state.touch_operation(operation);
        let operation_record = state
            .recovery_operations_mut()
            .get_mut(&operation)
            .expect("operation was validated");
        operation_record.state = OperationRecoveryState::RecoveryExhausted {
            crashed,
            crash_generation: operation_record.crash_generation,
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

fn acknowledge_component_commit(
    catalog: &DomainCatalog,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    fact: VerifiedEffectFact,
) -> Result<AppliedOutput, CoreError> {
    {
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        validate_component_fact(catalog, state, composite, component_record, fact)?;
        if fact.kind != EffectFactKind::CommitOutcome
            || fact.actor != composite.causal_owner
            || fact.generation != composite.authority_epoch
            || fact.operation != component_record.commit_operation.unwrap_or(Digest::ZERO)
            || fact.predecessor.is_some()
        {
            return Err(CoreError::StaleCommitIntent);
        }
    }
    state.touch_composite(effect);
    let composite = state
        .composite_effects_mut()
        .get_mut(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    let authority = composite.authority;
    let component_record = composite
        .components
        .get_mut(&component)
        .ok_or(CoreError::UnknownObligationClass)?;
    if component_record.commit != CommitState::CommitIntentDurable
        || component_record.commit_nonce != Some(fact.nonce)
    {
        return Err(CoreError::StaleCommitIntent);
    }
    component_record.outcome = match fact.outcome.ok_or(CoreError::VerificationFailed)? {
        ExternalOutcome::Success => OutcomeState::KnownSuccess(fact.stamp.receipt_digest),
        ExternalOutcome::Failure => OutcomeState::KnownFailure(fact.stamp.receipt_digest),
    };
    component_record.commit = CommitState::Committed;
    component_record.commit_nonce = None;
    component_record.commit_fact = Some(fact);
    initialize_component_disposition(component_record)?;
    refresh_component_retirement(component_record, authority);
    Ok(AppliedOutput::none(TransitionEvent::EffectCommitted))
}

fn claim_component_settlement(
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    claimant: ExecutorCoordinate,
) -> Result<AppliedOutput, CoreError> {
    let operation = state
        .recovery_operations()
        .get(&effect.operation())
        .ok_or(CoreError::UnknownOperation)?;
    let live_claimant = match operation.state {
        OperationRecoveryState::Active { executor, .. } => executor,
        OperationRecoveryState::Rebound { successor, .. } => successor,
        OperationRecoveryState::RecoveryExhausted { .. } => {
            return Err(CoreError::RecoveryExhausted);
        }
        _ => return Err(CoreError::WrongRecoveryState),
    };
    if live_claimant != claimant {
        return Err(CoreError::StaleExecutor);
    }
    let (generation, stage) = {
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if component_record.obligation_policy != ObligationPolicy::SuccessorSettlement {
            return Err(CoreError::WrongSettlementStage);
        }
        if composite.authority == AuthorityState::Revoked {
            return Err(CoreError::GateClosed);
        }
        let claimable = match component_record.settlement {
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
            (composite.authority, composite.custodian),
            (AuthorityState::Active, CustodyState::Executor(current)) if current == claimant
        ) || matches!(
            (composite.authority, composite.custodian),
            (AuthorityState::Fenced, CustodyState::CoreOwned)
        );
        if component_record.commit != CommitState::Committed || !custody_matches {
            return Err(CoreError::WrongCommitState);
        }
        claimable
    };
    let nonce = allocate_nonce(state)?;
    state.touch_composite(effect);
    let component_record = state
        .composite_effects_mut()
        .get_mut(&effect)
        .and_then(|composite| composite.components.get_mut(&component))
        .expect("component validated before nonce allocation");
    component_record.settlement = SettlementState::Claimed {
        claimant,
        generation,
    };
    component_record.settlement_nonce = Some(nonce);
    component_record.claim_stage = Some(stage);
    Ok(AppliedOutput {
        event: TransitionEvent::SettlementClaimed,
        output: OutputData::Settlement {
            effect,
            component,
            claimant,
            generation,
            nonce,
            stage,
        },
    })
}

fn record_component_applied(
    catalog: &DomainCatalog,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    fact: VerifiedEffectFact,
) -> Result<AppliedOutput, CoreError> {
    {
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        validate_component_fact(catalog, state, composite, component_record, fact)?;
        if fact.kind != EffectFactKind::ApplyCompleted
            || fact.operation != component_record.settlement_intent.unwrap_or(Digest::ZERO)
            || fact.predecessor.is_some()
        {
            return Err(CoreError::StaleSettlementClaim);
        }
    }
    let component_record = exact_component_claim_mut(
        state,
        effect,
        component,
        fact.actor,
        fact.generation,
        fact.nonce,
    )?;
    let next_stage = match component_record.claim_stage {
        Some(ClaimStage::Intent) => ClaimStage::Applied,
        Some(ClaimStage::ReconcileIntent) => ClaimStage::ReconcileApplied,
        _ => return Err(CoreError::WrongSettlementStage),
    };
    component_record.settlement = SettlementState::AppliedUnacknowledged {
        claimant: fact.actor,
        generation: fact.generation,
    };
    component_record.claim_stage = Some(next_stage);
    component_record.applied_fact = Some(fact);
    Ok(AppliedOutput {
        event: TransitionEvent::AppliedUnacknowledged,
        output: OutputData::Settlement {
            effect,
            component,
            claimant: fact.actor,
            generation: fact.generation,
            nonce: fact.nonce,
            stage: next_stage,
        },
    })
}

fn settle_component(
    catalog: &DomainCatalog,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    fact: VerifiedEffectFact,
) -> Result<AppliedOutput, CoreError> {
    {
        let composite = state
            .composite_effects()
            .get(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let component_record = composite
            .components
            .get(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        validate_component_fact(catalog, state, composite, component_record, fact)?;
        if fact.kind != EffectFactKind::SettlementAcknowledged
            || fact.operation != component_record.settlement_intent.unwrap_or(Digest::ZERO)
            || fact.predecessor
                != component_record
                    .applied_fact
                    .map(|applied| applied.stamp.receipt_digest)
        {
            return Err(CoreError::StaleSettlementClaim);
        }
    }
    let authority = state
        .composite_effects()
        .get(&effect)
        .expect("composite was validated")
        .authority;
    let component_record = exact_component_claim_mut(
        state,
        effect,
        component,
        fact.actor,
        fact.generation,
        fact.nonce,
    )?;
    if !matches!(
        component_record.claim_stage,
        Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
    ) {
        return Err(CoreError::WrongSettlementStage);
    }
    component_record.settlement = SettlementState::Settled;
    component_record.settlement_nonce = None;
    component_record.claim_stage = None;
    component_record.settlement_fact = Some(fact);
    refresh_component_retirement(component_record, authority);
    Ok(AppliedOutput::none(TransitionEvent::Settled))
}

fn revoke_composite_effect(
    state: &mut impl StateAccessMut,
    effect: EffectId,
    expected_actor: ExecutorCoordinate,
    authority_epoch: u64,
) -> Result<AppliedOutput, CoreError> {
    let composite = state
        .composite_effects()
        .get(&effect)
        .ok_or(CoreError::UnknownEffect)?;
    if composite.authority_epoch != authority_epoch {
        return Err(CoreError::StaleAuthorityEpoch);
    }
    match (composite.authority, composite.custodian) {
        (AuthorityState::Active, CustodyState::Executor(actor)) if actor == expected_actor => {}
        (AuthorityState::Fenced, CustodyState::CoreOwned) => {}
        (AuthorityState::Revoked, _) => return Err(CoreError::GateClosed),
        _ => return Err(CoreError::StaleAuthorityEpoch),
    }
    if composite.components.values().any(|component| {
        matches!(
            component.settlement,
            SettlementState::Claimed { .. }
                | SettlementState::ApplyIntentDurable { .. }
                | SettlementState::AppliedUnacknowledged { .. }
        )
    }) {
        return Err(CoreError::GateClaimed);
    }
    if composite.components.values().all(component_terminal) {
        return Err(CoreError::GateClosed);
    }
    if composite.components.values().any(|component| {
        !matches!(
            component.commit,
            CommitState::Registered | CommitState::Prepared
        ) || component.settlement != SettlementState::Unavailable
            || component.claims.values().any(|claim| {
                claim.retired
                    || claim
                        .requirements
                        .iter()
                        .any(|requirement| requirement.accepted.is_some())
            })
    }) {
        return Err(CoreError::WrongCommitState);
    }
    let charge_owner = composite.charge_owner;
    let claims = composite
        .components
        .iter()
        .flat_map(|(component, record)| {
            record.claims.values().map(|claim| {
                (
                    *component,
                    claim.id,
                    claim.credit_class,
                    claim.scope,
                    claim.resource,
                    claim.resource_generation,
                    claim.units,
                )
            })
        })
        .collect::<Vec<_>>();
    for (component, claim, _, _, resource, resource_generation, _) in &claims {
        let record = state
            .resources()
            .get(resource)
            .ok_or(CoreError::InvariantViolation)?;
        if record.generation != *resource_generation {
            return Err(CoreError::InvariantViolation);
        }
        if resource_generation.get() > 1
            && !matches!(
                record.phase,
                ResourcePhase::Claimed {
                    pending_reuse: Some(PendingReuse {
                        effect: pending_effect,
                        component: pending_component,
                        claim: pending_claim,
                        ..
                    })
                } if pending_effect == effect
                    && pending_component == *component
                    && pending_claim == *claim
            )
        {
            // A consumed generation+1 permit may already have authorized
            // external reuse. It cannot be collapsed by a precommit abort.
            return Err(CoreError::WrongCommitState);
        }
    }

    let mut released_device_scopes = BTreeSet::new();
    for (component, claim, credit_class, scope, resource, resource_generation, units) in claims {
        let charged = state
            .charges_mut()
            .get_mut(&(charge_owner, credit_class))
            .ok_or(CoreError::InvariantViolation)?;
        *charged = charged
            .checked_sub(units)
            .ok_or(CoreError::InvariantViolation)?;
        let entries = state
            .composite_resource_index_mut()
            .get_mut(&resource)
            .ok_or(CoreError::InvariantViolation)?;
        let before = entries.len();
        entries.retain(|entry| *entry != (effect, component, claim));
        if entries.len() + 1 != before {
            return Err(CoreError::InvariantViolation);
        }
        if entries.is_empty() {
            state.composite_resource_index_mut().remove_mut(&resource);
        }
        if !state.composite_resource_index().contains_key(&resource) {
            let record = *state
                .resources()
                .get(&resource)
                .ok_or(CoreError::InvariantViolation)?;
            if record.generation != resource_generation
                || !matches!(record.phase, ResourcePhase::Claimed { .. })
            {
                return Err(CoreError::InvariantViolation);
            }
            match record.phase {
                ResourcePhase::Claimed {
                    pending_reuse: Some(pending),
                } => {
                    state.touch_resource(resource);
                    state.resources_mut().insert_mut(
                        resource,
                        ResourceRecord {
                            scope: record.scope,
                            generation: pending.previous_generation,
                            phase: ResourcePhase::Retired,
                        },
                    );
                }
                ResourcePhase::Claimed {
                    pending_reuse: None,
                } => {
                    state.touch_resource(resource);
                    state.resources_mut().remove_mut(&resource);
                }
                ResourcePhase::Retired => return Err(CoreError::InvariantViolation),
            }
        }
        if let ClaimScope::Device(scope) = scope {
            released_device_scopes.insert(scope);
        }
    }
    state.touch_composite(effect);
    let composite = state
        .composite_effects_mut()
        .get_mut(&effect)
        .expect("composite remains present during atomic abort");
    composite.authority_epoch = composite
        .authority_epoch
        .checked_add(1)
        .ok_or(CoreError::GenerationExhausted)?;
    composite.authority = AuthorityState::Revoked;
    composite.custodian = CustodyState::CoreOwned;
    for component in composite.components.values_mut() {
        component.settlement = SettlementState::Revoked;
        component.claims.clear();
        component.settlement_nonce = None;
        component.claim_stage = None;
        refresh_component_retirement(component, composite.authority);
    }
    for scope in released_device_scopes {
        if !device_scope_has_retained_claim(state, scope) {
            state.touch_device(scope);
            state.device_quarantine_mut().remove_mut(&scope);
        }
    }
    Ok(AppliedOutput::none(TransitionEvent::Revoked))
}

fn apply_component_evidence(
    catalog: &DomainCatalog,
    state: &mut impl StateAccessMut,
    effect: EffectId,
    component: ComponentId,
    claim_id: ClaimId,
    evidence: RetirementEvidence,
) -> Result<AppliedOutput, CoreError> {
    require_digest(evidence.stamp.receipt_digest)?;
    state
        .recovery_operations()
        .get(&effect.operation())
        .ok_or(CoreError::UnknownOperation)?;
    let claim_record = state
        .composite_effects()
        .get(&effect)
        .and_then(|composite| composite.components.get(&component))
        .and_then(|component| component.claims.get(&claim_id))
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
    validate_state_verifier_identity(
        state,
        effect,
        component,
        evidence.stamp.identity,
        declared.verifier(),
        declared.receipt_schema(),
    )?;
    validate_state_verification_scope(
        state,
        effect,
        component,
        evidence.verification_scope,
        declared.verifier(),
        declared.receipt_schema(),
    )?;
    if declared.device_generation() == DeviceGenerationEffect::AdvanceOne {
        let ClaimScope::Device(device_scope) = claim_scope else {
            return Err(CoreError::InvariantViolation);
        };
        let current = state
            .device_generations()
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
            state.touch_device(device_scope);
            state
                .device_generations_mut()
                .insert_mut(device_scope, next);
        } else if observed != current || observed.get() <= evidence.subject.device().get() {
            return Err(CoreError::InvalidDeviceGenerationAdvance);
        }
    }
    let current_freshness = scoped_freshness(state, claim_scope)?;
    let (charge_owner, authority, credit_class, resource, resource_generation, units, retired_now) = {
        state.touch_composite(effect);
        let composite = state
            .composite_effects_mut()
            .get_mut(&effect)
            .ok_or(CoreError::UnknownEffect)?;
        let authority = composite.authority;
        if composite.custodian == CustodyState::Released {
            return Err(CoreError::EffectNotReleasable);
        }
        let component_record = composite
            .components
            .get_mut(&component)
            .ok_or(CoreError::UnknownObligationClass)?;
        if component_record.commit != CommitState::Committed {
            return Err(CoreError::WrongCommitState);
        }
        if component_record.retirement == RetirementState::Released {
            return Err(CoreError::EffectNotReleasable);
        }
        let claim = component_record
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
        )?;
        claim.requirements[requirement_index].accepted = Some(AcceptedEvidence {
            subject: evidence.subject,
            observation: evidence.freshness,
            stamp: evidence.stamp,
            verification_scope: evidence.verification_scope,
        });
        let retired_now = claim
            .requirements
            .iter()
            .all(|requirement| requirement.accepted.is_some());
        if retired_now {
            claim.retired = true;
        }
        (
            composite.charge_owner,
            authority,
            claim.credit_class,
            claim.resource,
            claim.resource_generation,
            claim.units,
            retired_now,
        )
    };
    if retired_now {
        let charged = state
            .charges_mut()
            .get_mut(&(charge_owner, credit_class))
            .ok_or(CoreError::InvariantViolation)?;
        *charged = charged
            .checked_sub(units)
            .ok_or(CoreError::InvariantViolation)?;
        let entries = state
            .composite_resource_index_mut()
            .get_mut(&resource)
            .ok_or(CoreError::InvariantViolation)?;
        let before = entries.len();
        entries.retain(|entry| *entry != (effect, component, claim_id));
        if entries.len() + 1 != before {
            return Err(CoreError::InvariantViolation);
        }
        if entries.is_empty() {
            state.composite_resource_index_mut().remove_mut(&resource);
        }
        if !state.composite_resource_index().contains_key(&resource) {
            state.touch_resource(resource);
            let record = state
                .resources_mut()
                .get_mut(&resource)
                .ok_or(CoreError::InvariantViolation)?;
            if record.generation != resource_generation
                || !matches!(record.phase, ResourcePhase::Claimed { .. })
            {
                return Err(CoreError::InvariantViolation);
            }
            record.phase = ResourcePhase::Retired;
        }
        state.touch_composite(effect);
        let composite = state
            .composite_effects_mut()
            .get_mut(&effect)
            .expect("composite remains present while evidence retires");
        let component_record = composite
            .components
            .get_mut(&component)
            .expect("component remains present while evidence retires");
        refresh_component_retirement(component_record, authority);
        if let ClaimScope::Device(scope) = claim_scope
            && !device_scope_has_retained_claim(state, scope)
        {
            state.touch_device(scope);
            state.device_quarantine_mut().remove_mut(&scope);
        }
    }
    Ok(AppliedOutput::none(TransitionEvent::EvidenceAccepted))
}

fn device_scope_has_retained_claim(state: &impl StateAccess, scope: DeviceScopeId) -> bool {
    state.composite_effects().values().any(|composite| {
        composite.components.values().any(|component| {
            component
                .claims
                .values()
                .any(|claim| !claim.retired && claim.scope == ClaimScope::Device(scope))
        })
    })
}

fn device_scope_has_retained_claim_outside_composite(
    state: &impl StateAccess,
    scope: DeviceScopeId,
    effect: EffectId,
) -> bool {
    state
        .composite_effects()
        .iter()
        .any(|(candidate, composite)| {
            *candidate != effect
                && composite.components.values().any(|component| {
                    component
                        .claims
                        .values()
                        .any(|claim| !claim.retired && claim.scope == ClaimScope::Device(scope))
                })
        })
}

fn device_scope_has_stale_retained_claim(
    state: &impl StateAccess,
    scope: DeviceScopeId,
) -> Result<bool, CoreError> {
    for composite in state.composite_effects().values() {
        state
            .recovery_operations()
            .get(&composite.effect.operation())
            .ok_or(CoreError::InvariantViolation)?;
        let current = scoped_freshness(state, ClaimScope::Device(scope))?;
        if composite.components.values().any(|component| {
            component.claims.values().any(|claim| {
                !claim.retired
                    && claim.scope == ClaimScope::Device(scope)
                    && claim.enrolled_freshness != current
            })
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_component_fact(
    catalog: &DomainCatalog,
    state: &impl StateAccess,
    composite: &CompositeEffectRecord,
    component: &ComponentRecord,
    fact: VerifiedEffectFact,
) -> Result<(), CoreError> {
    require_digest(fact.stamp.receipt_digest)?;
    if fact.effect != composite.effect
        || fact.component != component.id
        || fact.freshness != component_freshness(state, composite, component)?
    {
        return Err(CoreError::StaleEvidence);
    }
    let receipts = catalog
        .obligation_rule(component.domain, component.obligation)
        .ok_or(CoreError::UnknownObligationClass)?
        .receipts();
    let binding = match fact.kind {
        EffectFactKind::CommitOutcome => Some(receipts.commit_outcome()),
        EffectFactKind::ApplyCompleted => receipts.apply_completed(),
        EffectFactKind::SettlementAcknowledged => receipts.settlement_acknowledged(),
    }
    .ok_or(CoreError::WrongSettlementStage)?;
    validate_state_verifier_identity(
        state,
        composite.effect,
        component.id,
        fact.stamp.identity,
        binding.verifier(),
        binding.receipt_schema(),
    )?;
    validate_state_verification_scope(
        state,
        composite.effect,
        component.id,
        fact.verification_scope,
        binding.verifier(),
        binding.receipt_schema(),
    )?;
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
    state: &impl StateAccess,
    fact: VerifiedEffectFact,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> bool {
    !fact.stamp.receipt_digest.is_zero()
        && validate_state_verifier_identity(
            state,
            fact.effect,
            fact.component,
            fact.stamp.identity,
            verifier,
            receipt_schema,
        )
        .is_ok()
        && state_scoped_verification_scope(
            state,
            fact.effect,
            fact.component,
            verifier,
            receipt_schema,
        ) == Ok(fact.verification_scope)
}

fn validate_evidence_freshness(
    requirement: &RequirementState,
    evidence: RetirementEvidence,
    enrolled: Freshness,
    active: Freshness,
) -> Result<(), CoreError> {
    if !freshness_matches(requirement.subject_freshness, evidence.subject, enrolled)
        || !freshness_matches(
            requirement.observation_freshness,
            evidence.freshness,
            active,
        )
        || !freshness_strictly_advances(
            requirement.strictly_advanced,
            evidence.subject,
            evidence.freshness,
        )
    {
        return Err(CoreError::StaleEvidence);
    }
    Ok(())
}

fn freshness_matches(axes: FreshnessAxes, presented: Freshness, expected: Freshness) -> bool {
    (!axes.contains(FreshnessAxes::BOOT) || presented.boot() == expected.boot())
        && (!axes.contains(FreshnessAxes::REGISTRY) || presented.registry() == expected.registry())
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
        && (!axes.contains(FreshnessAxes::DEVICE)
            || observation.device().get() > subject.device().get())
        && (!axes.contains(FreshnessAxes::JOURNAL)
            || observation.journal().get() > subject.journal().get())
}

fn refresh_component_retirement(component: &mut ComponentRecord, authority: AuthorityState) {
    if component.retirement == RetirementState::Released {
        return;
    }
    if component.claims.is_empty() {
        component.retirement = if component.commit == CommitState::Committed
            || component.settlement == SettlementState::Revoked
        {
            RetirementState::Retired
        } else {
            RetirementState::Held
        };
        return;
    }
    component.retirement = if component.claims.values().all(|claim| claim.retired) {
        RetirementState::Retired
    } else if component.commit == CommitState::Committed || authority != AuthorityState::Active {
        RetirementState::RetirementPending
    } else {
        RetirementState::Held
    };
}

fn project_composite_effect(
    composite: &CompositeEffectRecord,
    state: &impl StateAccess,
) -> CompositeEffectProjection {
    let provenance = state
        .scoped_composites()
        .get(&composite.effect)
        .map(|scoped| &scoped.bindings)
        .or_else(|| {
            composite
                .released_provenance
                .as_ref()
                .map(|provenance| &provenance.bindings)
        });
    CompositeEffectProjection {
        effect: composite.effect,
        kind: composite.kind,
        catalog_digest: composite.catalog_digest,
        causal_owner: composite.causal_owner,
        custodian: composite.custodian,
        charge_owner: composite.charge_owner,
        operation: composite.effect.operation(),
        provider_bindings: provenance
            .map(|bindings| {
                bindings
                    .iter()
                    .map(|(component, provider)| {
                        ComponentProviderBinding::new(*component, *provider)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        authority: composite.authority,
        authority_epoch: composite.authority_epoch,
        escape: composite_escape_state(composite),
        component_count: composite.components.len(),
        retained_claims: composite
            .components
            .values()
            .flat_map(|component| component.claims.values())
            .filter(|claim| !claim.retired)
            .count(),
        handoff: project_single_hop_handoff(composite, Some(state)),
    }
}

fn project_single_hop_handoff(
    composite: &CompositeEffectRecord,
    state: Option<&impl StateAccess>,
) -> SingleHopHandoffProjection {
    match &composite.handoff {
        SingleHopRole::None => SingleHopHandoffProjection::None,
        SingleHopRole::Source {
            descriptor,
            terminal_receipt_digest,
            descriptor_receipt_digest,
            recovery_fact,
        } => SingleHopHandoffProjection::Source {
            descriptor: descriptor.clone(),
            terminal_receipt_digest: *terminal_receipt_digest,
            descriptor_receipt_digest: *descriptor_receipt_digest,
            recovery_fact: *recovery_fact,
            child_installed: state.is_some_and(|state| {
                descriptor.child_effect().ok().and_then(|child| state.composite_effects().get(&child)).is_some_and(|child| {
                    matches!(child.handoff, SingleHopRole::Target { parent, descriptor_digest, recovery_fact: _ } if parent == composite.effect && descriptor_digest == handoff_descriptor_digest(**descriptor))
                })
            }),
        },
        SingleHopRole::Target { parent, descriptor_digest, recovery_fact } => SingleHopHandoffProjection::Target {
            parent: *parent,
            descriptor_digest: *descriptor_digest,
            recovery_fact: *recovery_fact,
        },
    }
}

fn project_component(effect: EffectId, component: &ComponentRecord) -> ComponentProjection {
    ComponentProjection {
        effect,
        component: component.id,
        obligation: (component.domain, component.obligation),
        obligation_policy: component.obligation_policy,
        commit: component.commit,
        commit_operation: component.commit_operation,
        outcome: component.outcome,
        settlement: component.settlement,
        retirement: component.retirement,
        claim_count: component.claims.len(),
        retained_claims: component
            .claims
            .values()
            .filter(|claim| !claim.retired)
            .count(),
    }
}

fn project_component_claim(
    effect: EffectId,
    component: ComponentId,
    claim: &ClaimRecord,
) -> ComponentClaimProjection {
    let custodian = if claim.retired {
        ClaimCustodian::Released
    } else {
        match claim.scope {
            ClaimScope::Logical => ClaimCustodian::CoreOwned,
            ClaimScope::Device(scope) => ClaimCustodian::DeviceProvider(scope),
        }
    };
    ComponentClaimProjection {
        effect,
        component,
        claim: claim.id,
        domain: claim.domain,
        kind: claim.kind,
        credit_class: claim.credit_class,
        scope: claim.scope,
        custodian,
        resource: claim.resource,
        resource_generation: claim.resource_generation,
        units: claim.units,
        enrolled_freshness: claim.enrolled_freshness,
        retired: claim.retired,
    }
}

fn build_recovery_snapshot(
    catalogs: &CatalogSet,
    state: &impl StateAccess,
    operation: OperationId,
    snapshot: SnapshotId,
) -> Result<RecoverySnapshot, CoreError> {
    let operation_record = state
        .recovery_operations()
        .get(&operation)
        .ok_or(CoreError::UnknownOperation)?;
    match operation_record.state {
        OperationRecoveryState::Fenced { .. } => {}
        OperationRecoveryState::RecoveryExhausted { .. } => {
            return Err(CoreError::RecoveryExhausted);
        }
        _ => return Err(CoreError::WrongRecoveryState),
    }
    let mut composites = Vec::new();
    for composite in state
        .composite_effects()
        .values()
        .filter(|composite| composite.effect.operation() == operation)
    {
        let catalog = catalogs
            .get(composite.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        if catalog.composite_rule(composite.kind).is_none() {
            return Err(CoreError::InvariantViolation);
        }
        let mut components = Vec::new();
        let mut retained_claims = Vec::new();
        for component in composite.components.values() {
            let item = ComponentRecoveryItem {
                effect: composite.effect,
                component: component.id,
                obligation: (component.domain, component.obligation),
                authority: composite.authority,
                authority_epoch: composite.authority_epoch,
                commit: component.commit,
                commit_operation: component.commit_operation,
                outcome: component.outcome,
                settlement: component.settlement,
                retirement: component.retirement,
                claim_count: component.claims.len(),
                retained_claims: component
                    .claims
                    .values()
                    .filter(|claim| !claim.retired)
                    .count(),
                settlement_required: component.obligation_policy
                    == ObligationPolicy::SuccessorSettlement
                    && component.commit == CommitState::Committed
                    && !matches!(
                        component.settlement,
                        SettlementState::Settled
                            | SettlementState::Revoked
                            | SettlementState::NotRequired
                    ),
            };
            components.push(item);
            for claim in component.claims.values().filter(|claim| !claim.retired) {
                let mut accepted_evidence = Vec::new();
                let mut pending_evidence = Vec::new();
                for requirement in &claim.requirements {
                    match requirement.accepted {
                        Some(accepted) => accepted_evidence.push(RecoveryEvidenceItem {
                            kind: requirement.kind,
                            subject: accepted.subject,
                            observation: accepted.observation,
                            stamp: accepted.stamp,
                            verification_scope: accepted.verification_scope,
                        }),
                        None => pending_evidence.push(requirement.kind),
                    }
                }
                retained_claims.push(ComponentClaimRecoveryItem {
                    claim: project_component_claim(composite.effect, component.id, claim),
                    accepted_evidence,
                    pending_evidence,
                });
            }
        }
        composites.push(CompositeRecoveryItem {
            effect: composite.effect,
            kind: composite.kind,
            catalog_digest: composite.catalog_digest,
            causal_owner: composite.causal_owner,
            custodian: composite.custodian,
            charge_owner: composite.charge_owner,
            authority: composite.authority,
            authority_epoch: composite.authority_epoch,
            escape: composite_escape_state(composite),
            components,
            retained_claims,
            handoff: project_single_hop_handoff(composite, Some(state)),
        });
    }
    let artifacts = state
        .artifact_leases()
        .values()
        .filter(|lease| lease.binding().effect().operation() == operation)
        .map(|lease| ArtifactRecoveryItem {
            binding: lease.binding(),
            lease: *lease,
            releasable: matches!(lease, ArtifactLeaseState::ReleaseAuthorized { .. }),
        })
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.recovery-snapshot.v6");
    hasher.update(crate::CSER_CORE_API_PROFILE_VERSION.to_le_bytes());
    hasher.update(crate::RECOVERY_SNAPSHOT_VERSION.to_le_bytes());
    hasher.update(crate::JOURNAL_SCHEMA_VERSION.to_le_bytes());
    hasher.update(catalogs.digest().bytes());
    hasher.update(operation.get().to_le_bytes());
    hasher.update(snapshot.get().to_le_bytes());
    hasher.update(state.revision().to_le_bytes());
    hasher.update(state.head().bytes());
    hash_operation_state(&mut hasher, operation_record.state);
    hasher.update([0xfd]);
    for composite in &composites {
        hasher.update(composite.effect.operation().get().to_le_bytes());
        hasher.update(composite.effect.sequence().to_le_bytes());
        hasher.update(composite.kind.get().to_le_bytes());
        hash_incarnation(&mut hasher, composite.causal_owner);
        hash_custody(&mut hasher, composite.custodian);
        hasher.update(composite.charge_owner.get().to_le_bytes());
        hasher.update([authority_tag(composite.authority)]);
        hasher.update(composite.authority_epoch.to_le_bytes());
        hasher.update([effect_escape_tag(composite.escape)]);
        hash_single_hop_handoff_projection(&mut hasher, composite.handoff.clone());
        hasher.update((composite.components.len() as u64).to_le_bytes());
        for item in &composite.components {
            hasher.update(item.component.get().to_le_bytes());
            hasher.update(item.obligation.0.get().to_le_bytes());
            hasher.update(item.obligation.1.get().to_le_bytes());
            hasher.update([authority_tag(item.authority)]);
            hasher.update(item.authority_epoch.to_le_bytes());
            hasher.update([commit_tag(item.commit)]);
            hasher.update([u8::from(item.commit_operation.is_some())]);
            if let Some(operation) = item.commit_operation {
                hasher.update(operation.bytes());
            }
            hash_outcome(&mut hasher, item.outcome);
            hash_settlement(&mut hasher, item.settlement);
            hasher.update([retirement_tag(item.retirement)]);
            hasher.update((item.claim_count as u64).to_le_bytes());
            hasher.update((item.retained_claims as u64).to_le_bytes());
            hasher.update([u8::from(item.settlement_required)]);
        }
        hasher.update([0xfc]);
        hasher.update((composite.retained_claims.len() as u64).to_le_bytes());
        for item in &composite.retained_claims {
            let claim = item.claim;
            hasher.update(claim.component.get().to_le_bytes());
            hasher.update(claim.claim.get().to_le_bytes());
            hasher.update(claim.domain.get().to_le_bytes());
            hasher.update(claim.kind.get().to_le_bytes());
            hasher.update(claim.credit_class.get().to_le_bytes());
            hash_claim_scope(&mut hasher, claim.scope);
            hash_claim_custodian(&mut hasher, claim.custodian);
            hasher.update(claim.resource.get().to_le_bytes());
            hasher.update(claim.resource_generation.get().to_le_bytes());
            hasher.update(claim.units.to_le_bytes());
            hash_freshness(&mut hasher, claim.enrolled_freshness);
            hasher.update((item.accepted_evidence.len() as u64).to_le_bytes());
            for evidence in &item.accepted_evidence {
                hasher.update(evidence.kind.get().to_le_bytes());
                hash_freshness(&mut hasher, evidence.subject);
                hash_freshness(&mut hasher, evidence.observation);
                hash_provider_verification_scope(&mut hasher, evidence.verification_scope);
                hash_verifier_stamp(&mut hasher, evidence.stamp);
            }
            hasher.update((item.pending_evidence.len() as u64).to_le_bytes());
            for evidence in &item.pending_evidence {
                hasher.update(evidence.get().to_le_bytes());
            }
        }
    }
    hasher.update([0xfb]);
    hasher.update((artifacts.len() as u64).to_le_bytes());
    for artifact in &artifacts {
        hash_artifact_binding(&mut hasher, artifact.binding);
        hash_artifact_lease(&mut hasher, artifact.lease);
        hasher.update([u8::from(artifact.releasable)]);
    }
    Ok(RecoverySnapshot {
        core_api_profile: crate::CSER_CORE_API_PROFILE_VERSION,
        snapshot_version: crate::RECOVERY_SNAPSHOT_VERSION,
        journal_schema: crate::JOURNAL_SCHEMA_VERSION,
        catalog_digest: catalogs.digest(),
        operation,
        snapshot,
        digest: Digest::new(hasher.finalize().into()),
        covered_revision: state.revision(),
        covered_head: state.head(),
        composites,
        artifacts,
    })
}

fn check_invariants(
    catalogs: &CatalogSet,
    limits: CoreLimits,
    state: &impl StateAccess,
) -> Result<(), CoreError> {
    if state.world().get() == 0 {
        return Err(CoreError::InvariantViolation);
    }
    if state
        .device_quarantine()
        .iter()
        .any(|scope| !state.device_generations().contains_key(scope))
    {
        return Err(CoreError::InvariantViolation);
    }
    for (coordinate, record) in state.provider_generations() {
        let catalog = catalogs
            .get(record.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let required_verifiers: Vec<_> = catalog.verifier_class_bindings().into_iter().collect();
        let verifier_digest = validate_verifier_set(&record.verifier_bindings, &required_verifiers)
            .map_err(|_| CoreError::InvariantViolation)?;
        let epoch_valid = match record.state {
            ProviderEffectState::Active => provider_epoch(record.state) == 1,
            ProviderEffectState::EffectFenced { epoch } => epoch >= 2,
            ProviderEffectState::SettlementOnly { epoch } => epoch >= 3,
            ProviderEffectState::Retired { epoch } => epoch >= 4,
        };
        if state.world() != coordinate.world()
            || record.coordinate != *coordinate
            || record.catalog_digest != catalog.digest()
            || record.verifier_set_digest != verifier_digest
            || !verifier_bindings_are_canonical(&record.verifier_bindings)
            || !epoch_valid
            || record.live_component_bindings == 0
                && state
                    .scoped_composites()
                    .values()
                    .any(|scoped| scoped.bindings.values().any(|bound| bound == coordinate))
            || state
                .provider_high_water()
                .get(&coordinate.provider())
                .is_none_or(|high| *high < coordinate.generation())
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    for (provider, high) in state.provider_high_water() {
        if high.get() == 0
            || state
                .provider_generations()
                .keys()
                .filter(|coordinate| coordinate.provider() == *provider)
                .any(|coordinate| coordinate.generation() > *high)
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    let mut expected_provider_bindings: BTreeMap<ProviderCoordinate, usize> = BTreeMap::new();
    let mut expected_artifacts = BTreeMap::new();
    for (effect, scoped) in state.scoped_composites() {
        let composite = state
            .composite_effects()
            .get(effect)
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = catalogs
            .get(composite.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let schema = catalog
            .composite_rule(composite.kind)
            .ok_or(CoreError::InvariantViolation)?;
        if scoped.catalog_digest != composite.catalog_digest
            || scoped.bindings.len() != composite.components.len()
            || scoped
                .bindings
                .keys()
                .any(|component| !composite.components.contains_key(component))
        {
            return Err(CoreError::InvariantViolation);
        }
        for (component, provider) in &scoped.bindings {
            let provider_record = state.provider_generations().get(provider);
            if state.world() != provider.world()
                || provider_record.is_none()
                || provider_record
                    .is_some_and(|record| record.catalog_digest != composite.catalog_digest)
            {
                return Err(CoreError::InvariantViolation);
            }
            *expected_provider_bindings.entry(*provider).or_default() += 1;
            let declared = schema
                .component(*component)
                .ok_or(CoreError::InvariantViolation)?;
            let component_record = composite
                .components
                .get(component)
                .ok_or(CoreError::InvariantViolation)?;
            match (declared.artifact_policy(), scoped.artifacts.get(component)) {
                (crate::RecoveryArtifactPolicy::Required, Some(binding)) => {
                    let provider_record = provider_record.ok_or(CoreError::InvariantViolation)?;
                    if provider_record.artifact_receipts.is_none()
                        || binding.provider() != *provider
                        || binding.operation() != effect.operation()
                        || binding.effect() != *effect
                        || binding.component() != *component
                        || binding.catalog_digest() != catalog.digest()
                        || binding.verifier_set_digest() != provider_record.verifier_set_digest
                        || expected_artifacts
                            .insert(binding.artifact_id(), *binding)
                            .is_some()
                    {
                        return Err(CoreError::InvariantViolation);
                    }
                }
                (crate::RecoveryArtifactPolicy::NotRequired, None) => {}
                (crate::RecoveryArtifactPolicy::Required, None)
                    if component_abort_terminal(composite, component_record) => {}
                _ => return Err(CoreError::InvariantViolation),
            }
        }
    }
    for (coordinate, record) in state.provider_generations() {
        if record.live_component_bindings
            != expected_provider_bindings
                .get(coordinate)
                .copied()
                .unwrap_or(0)
        {
            return Err(CoreError::InvariantViolation);
        }
        if matches!(record.state, ProviderEffectState::Retired { .. })
            && (record.live_component_bindings != 0
                || state.artifact_leases().values().any(|lease| {
                    lease.binding().provider() == *coordinate
                        && !matches!(lease, ArtifactLeaseState::Released { .. })
                }))
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    for (artifact, lease) in state.artifact_leases() {
        let binding = lease.binding();
        if *artifact != binding.artifact_id()
            || lease.pin_stamp().is_zero()
            || lease.release_stamp().is_some_and(Digest::is_zero)
            || lease.release_nonce().is_some_and(|nonce| nonce == 0)
        {
            return Err(CoreError::InvariantViolation);
        }
        match expected_artifacts.get(artifact) {
            Some(expected) if *expected == binding => {}
            None if matches!(lease, ArtifactLeaseState::Released { .. }) => {
                let composite = state
                    .composite_effects()
                    .get(&binding.effect())
                    .ok_or(CoreError::InvariantViolation)?;
                let component = composite
                    .components
                    .get(&binding.component())
                    .ok_or(CoreError::InvariantViolation)?;
                let provider_record = state
                    .provider_generations()
                    .get(&binding.provider())
                    .ok_or(CoreError::InvariantViolation)?;
                if component.retirement != RetirementState::Released
                    || binding.catalog_digest() != composite.catalog_digest
                    || provider_record.catalog_digest != composite.catalog_digest
                    || composite
                        .released_provenance
                        .as_ref()
                        .and_then(|provenance| provenance.artifacts.get(&binding.component()))
                        != Some(&binding)
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            _ => return Err(CoreError::InvariantViolation),
        }
    }
    if expected_artifacts.keys().any(|artifact| {
        state
            .artifact_leases()
            .get(artifact)
            .is_some_and(|lease| lease.binding() != expected_artifacts[artifact])
    }) {
        return Err(CoreError::InvariantViolation);
    }
    if state.recovery_operations().len() > limits.max_operations
        || state.composite_effects().len() > limits.max_effects
        || state.resources().len() > limits.max_resource_records
        || state.provider_generations().len() > limits.max_provider_generations
        || state.provider_high_water().len() > limits.max_provider_high_water
        || state.artifact_leases().len() > limits.max_artifact_leases
        || state.device_generations().len() > limits.max_device_generations
    {
        return Err(CoreError::InvariantViolation);
    }
    let total_claims = count_state_claims(state)?;
    if state.total_claims() != total_claims
        || total_claims > limits.max_total_claims
        || state.next_nonce() == 0
    {
        return Err(CoreError::InvariantViolation);
    }

    let mut expected_charges: StateMap<(ChargeAccountId, CreditClassId), u64> = StateMap::new();
    let mut expected_catalog_charges: BTreeMap<(Digest, ChargeAccountId, CreditClassId), u64> =
        BTreeMap::new();
    let mut expected_composite_resources: StateMap<
        ResourceId,
        Vec<(EffectId, ComponentId, ClaimId)>,
    > = StateMap::new();
    let mut active_resource_generations: BTreeMap<ResourceId, ResourceGeneration> = BTreeMap::new();
    let mut active_resource_scopes: BTreeMap<ResourceId, ClaimScope> = BTreeMap::new();
    for composite in state.composite_effects().values() {
        let catalog = catalogs
            .get(composite.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        if !state.scoped_composites().contains_key(&composite.effect)
            && composite.released_provenance.is_none()
        {
            // A primary composite without immutable provider provenance can
            // only come from a predecessor checkpoint. Do not let recovery
            // or replay turn that image into a live unscoped effect.
            return Err(CoreError::IncompatibleApiProfile);
        }
        let composite_rule = catalog
            .composite_rule(composite.kind)
            .ok_or(CoreError::InvariantViolation)?;
        let operation = state
            .recovery_operations()
            .get(&composite.effect.operation())
            .ok_or(CoreError::InvariantViolation)?;
        if operation.origin.executor() != composite.causal_owner.executor()
            || composite.authority_epoch == 0
            || composite.components.len() != composite_rule.components().len()
            || composite.components.len() > limits.max_components_per_effect
            || !composite_rule.components().iter().all(|declared| {
                composite
                    .components
                    .get(&declared.component())
                    .is_some_and(|component| {
                        component.domain == declared.domain()
                            && component.obligation == declared.obligation()
                    })
            })
            || !matches!(
                (composite.authority, composite.custodian),
                (AuthorityState::Active, CustodyState::Executor(_))
                    | (
                        AuthorityState::Fenced | AuthorityState::Revoked,
                        CustodyState::CoreOwned
                    )
                    | (AuthorityState::Revoked, CustodyState::Released)
            )
        {
            return Err(CoreError::InvariantViolation);
        }
        if let Some(provenance) = &composite.released_provenance {
            if composite.authority != AuthorityState::Revoked
                || composite.custodian != CustodyState::Released
                || state.scoped_composites().contains_key(&composite.effect)
                || provenance.catalog_digest != composite.catalog_digest
                || provenance.bindings.len() != composite.components.len()
                || provenance
                    .bindings
                    .keys()
                    .any(|component| !composite.components.contains_key(component))
            {
                return Err(CoreError::InvariantViolation);
            }
            for (component, provider) in &provenance.bindings {
                let provider_record = state
                    .provider_generations()
                    .get(provider)
                    .ok_or(CoreError::InvariantViolation)?;
                if state.world() != provider.world()
                    || provider_record.catalog_digest != catalog.digest()
                {
                    return Err(CoreError::InvariantViolation);
                }
                let schema = composite_rule
                    .component(*component)
                    .ok_or(CoreError::InvariantViolation)?;
                let artifact = provenance.artifacts.get(component);
                match (schema.artifact_policy(), artifact) {
                    (crate::RecoveryArtifactPolicy::Required, Some(binding)) => {
                        if binding.provider() != *provider
                            || binding.operation() != composite.effect.operation()
                            || binding.effect() != composite.effect
                            || binding.component() != *component
                            || binding.catalog_digest() != catalog.digest()
                            || binding.verifier_set_digest() != provider_record.verifier_set_digest
                            || !matches!(
                                state.artifact_leases().get(&binding.artifact_id()),
                                Some(ArtifactLeaseState::Released { .. })
                            )
                        {
                            return Err(CoreError::InvariantViolation);
                        }
                    }
                    (crate::RecoveryArtifactPolicy::Required, None)
                        if composite
                            .components
                            .get(component)
                            .is_some_and(|record| component_abort_terminal(composite, record)) => {}
                    (crate::RecoveryArtifactPolicy::NotRequired, None) => {}
                    _ => return Err(CoreError::InvariantViolation),
                }
            }
            if provenance
                .artifacts
                .keys()
                .any(|component| !provenance.bindings.contains_key(component))
            {
                return Err(CoreError::InvariantViolation);
            }
        }
        let released = composite.custodian == CustodyState::Released;
        if released
            != composite
                .components
                .values()
                .all(|component| component.retirement == RetirementState::Released)
        {
            return Err(CoreError::InvariantViolation);
        }
        match &composite.handoff {
            SingleHopRole::None => {}
            SingleHopRole::Source {
                descriptor,
                terminal_receipt_digest,
                descriptor_receipt_digest,
                recovery_fact,
            } => {
                let fact_valid = recovery_fact.is_none_or(|fact| {
                    composite
                        .components
                        .get(&descriptor.parent_component)
                        .and_then(|component| component.commit_operation)
                        .is_some_and(|operation| {
                            component_freshness(
                                state,
                                composite,
                                composite
                                    .components
                                    .get(&descriptor.parent_component)
                                    .expect("validated component"),
                            )
                            .is_ok_and(|freshness| {
                                handoff_recovery_fact_matches(
                                    state,
                                    catalog,
                                    fact,
                                    HandoffRecoveryCoordinates::new(
                                        HandoffRecoveryRole::Parent,
                                        composite.effect,
                                        descriptor.parent_component,
                                        operation,
                                        handoff_descriptor_digest(**descriptor),
                                        freshness,
                                    ),
                                ) && fact.stamp.receipt_digest == *terminal_receipt_digest
                            })
                        })
                });
                if descriptor.parent != composite.effect
                    || descriptor.catalog_digest != catalog.digest()
                    || descriptor.child_effect().is_err()
                    || !matches!(catalog.single_hop_handoff_rule(composite.kind), Some(rule) if rule.target() == descriptor.child_kind)
                    || terminal_receipt_digest.is_zero()
                    || descriptor_receipt_digest.is_zero()
                    || !fact_valid
                    || !matches!(
                        composite.components.get(&descriptor.parent_component).map(|component| component.outcome),
                        Some(OutcomeState::KnownSuccess(receipt)) if receipt == *terminal_receipt_digest
                    )
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            SingleHopRole::Target {
                parent,
                descriptor_digest,
                recovery_fact,
            } => {
                let fact_valid = recovery_fact.is_none_or(|fact| {
                    composite
                        .components
                        .get(&fact.component)
                        .is_some_and(|component| {
                            component.commit_operation.is_some_and(|operation| {
                                component_freshness(state, composite, component).is_ok_and(
                                    |freshness| {
                                        handoff_recovery_fact_matches(
                                            state,
                                            catalog,
                                            fact,
                                            HandoffRecoveryCoordinates::new(
                                                HandoffRecoveryRole::Child,
                                                composite.effect,
                                                fact.component,
                                                operation,
                                                *descriptor_digest,
                                                freshness,
                                            ),
                                        ) && matches!(
                                            component.outcome,
                                            OutcomeState::KnownSuccess(receipt)
                                                if receipt == fact.stamp.receipt_digest
                                        )
                                    },
                                )
                            })
                        })
                });
                if parent.operation() != composite.effect.operation()
                    || descriptor_digest.is_zero()
                    || !fact_valid
                    || composite.components.len() != 1
                    || !matches!(state.composite_effects().get(parent).map(|source| (&source.handoff, source.kind, source.catalog_digest)), Some((SingleHopRole::Source { descriptor, .. }, source_kind, source_catalog_digest)) if source_catalog_digest == composite.catalog_digest && catalog.single_hop_handoff_rule(source_kind).is_some_and(|rule| rule.target() == composite.kind) && handoff_descriptor_digest(**descriptor) == *descriptor_digest)
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
        }
        let mut claim_ids = BTreeSet::new();
        for component in composite.components.values() {
            let mut component_device_scope = None;
            for claim in component.claims.values() {
                if let ClaimScope::Device(scope) = claim.scope
                    && component_device_scope
                        .replace(scope)
                        .is_some_and(|existing| existing != scope)
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            let obligation_rule = catalog
                .obligation_rule(component.domain, component.obligation)
                .ok_or(CoreError::InvariantViolation)?;
            if obligation_rule.policy() != component.obligation_policy
                || component.claims.len() > limits.max_claims_per_effect
                || component.id.get() == 0
            {
                return Err(CoreError::InvariantViolation);
            }
            for cardinality in obligation_rule.claims() {
                let count = component
                    .claims
                    .values()
                    .filter(|claim| claim.kind == cardinality.kind())
                    .count();
                if count > usize::from(cardinality.maximum())
                    || (component.commit != CommitState::Registered
                        && component.settlement != SettlementState::Revoked
                        && count < usize::from(cardinality.minimum()))
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            if component.claims.values().any(|claim| {
                !obligation_rule
                    .claims()
                    .iter()
                    .any(|allowed| allowed.kind() == claim.kind)
            }) || (component.commit != CommitState::Registered
                && component.settlement != SettlementState::Revoked
                && component.claims.len() < usize::from(obligation_rule.minimum_total_claims()))
            {
                return Err(CoreError::InvariantViolation);
            }
            match component.commit {
                CommitState::CommitIntentDurable
                    if component.commit_nonce.is_none() || component.commit_operation.is_none() =>
                {
                    return Err(CoreError::InvariantViolation);
                }
                CommitState::CommitIntentDurable => {}
                _ if component.commit_nonce.is_some() => {
                    return Err(CoreError::InvariantViolation);
                }
                _ => {}
            }
            let receipts = obligation_rule.receipts();
            if let Some(fact) = component.commit_fact {
                if component.commit != CommitState::Committed
                    || fact.kind != EffectFactKind::CommitOutcome
                    || fact.effect != composite.effect
                    || fact.component != component.id
                    || fact.actor != composite.causal_owner
                    || fact.operation != component.commit_operation.unwrap_or(Digest::ZERO)
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
                    component.outcome,
                    OutcomeState::KnownSuccess(digest) | OutcomeState::KnownFailure(digest)
                        if digest != fact.stamp.receipt_digest
                ) {
                    return Err(CoreError::InvariantViolation);
                }
            } else if matches!(
                component.outcome,
                OutcomeState::KnownSuccess(_) | OutcomeState::KnownFailure(_)
            ) && !matches!(
                (&composite.handoff, component.outcome),
                (
                    SingleHopRole::Source {
                        descriptor,
                        terminal_receipt_digest,
                        ..
                    },
                    OutcomeState::KnownSuccess(receipt),
                ) if descriptor.parent_component == component.id && receipt == *terminal_receipt_digest
            ) && !matches!(
                (&composite.handoff, component.outcome),
                (SingleHopRole::Target { .. }, OutcomeState::KnownSuccess(_))
            ) {
                return Err(CoreError::InvariantViolation);
            }
            if let Some(fact) = component.applied_fact {
                let Some(binding) = receipts.apply_completed() else {
                    return Err(CoreError::InvariantViolation);
                };
                if fact.kind != EffectFactKind::ApplyCompleted
                    || fact.effect != composite.effect
                    || fact.component != component.id
                    || fact.operation != component.settlement_intent.unwrap_or(Digest::ZERO)
                    || fact.predecessor.is_some()
                    || fact.outcome.is_some()
                    || !fact_stamp_matches(
                        state,
                        fact,
                        binding.verifier(),
                        binding.receipt_schema(),
                    )
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            let applied_required = matches!(
                component.settlement,
                SettlementState::AppliedUnacknowledged { .. }
                    | SettlementState::ReconciliationRequired { applied: true, .. }
                    | SettlementState::Settled
            ) || matches!(
                component.claim_stage,
                Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
            );
            if applied_required != component.applied_fact.is_some() {
                return Err(CoreError::InvariantViolation);
            }
            if let Some(fact) = component.settlement_fact {
                let Some(binding) = receipts.settlement_acknowledged() else {
                    return Err(CoreError::InvariantViolation);
                };
                if component.settlement != SettlementState::Settled
                    || fact.kind != EffectFactKind::SettlementAcknowledged
                    || fact.effect != composite.effect
                    || fact.component != component.id
                    || fact.operation != component.settlement_intent.unwrap_or(Digest::ZERO)
                    || fact.predecessor
                        != component
                            .applied_fact
                            .map(|applied| applied.stamp.receipt_digest)
                    || fact.outcome.is_some()
                    || !fact_stamp_matches(
                        state,
                        fact,
                        binding.verifier(),
                        binding.receipt_schema(),
                    )
                {
                    return Err(CoreError::InvariantViolation);
                }
            } else if component.settlement == SettlementState::Settled {
                return Err(CoreError::InvariantViolation);
            }
            let claim_authority_live = matches!(
                component.settlement,
                SettlementState::Claimed { .. }
                    | SettlementState::ApplyIntentDurable { .. }
                    | SettlementState::AppliedUnacknowledged { .. }
            );
            if claim_authority_live
                != (component.settlement_nonce.is_some() && component.claim_stage.is_some())
            {
                return Err(CoreError::InvariantViolation);
            }
            match component.obligation_policy {
                ObligationPolicy::SuccessorSettlement
                    if component.settlement == SettlementState::NotRequired =>
                {
                    return Err(CoreError::InvariantViolation);
                }
                ObligationPolicy::RetirementEvidence
                    if component.commit == CommitState::Committed
                        && component.settlement != SettlementState::NotRequired =>
                {
                    return Err(CoreError::InvariantViolation);
                }
                _ => {}
            }
            for claim in component.claims.values() {
                if !claim_ids.insert(claim.id) {
                    return Err(CoreError::InvariantViolation);
                }
                let rule = catalog
                    .claim_rule(claim.domain, claim.kind)
                    .ok_or(CoreError::InvariantViolation)?;
                if claim.domain != component.domain
                    || claim.credit_class != rule.credit_class()
                    || rule.evidence().len() != claim.requirements.len()
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
                for (requirement, declared) in claim.requirements.iter().zip(rule.evidence().iter())
                {
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
                        && (validate_state_verifier_identity(
                            state,
                            composite.effect,
                            component.id,
                            accepted.stamp.identity,
                            requirement.verifier,
                            requirement.receipt_schema,
                        )
                        .is_err()
                            || validate_state_verification_scope(
                                state,
                                composite.effect,
                                component.id,
                                accepted.verification_scope,
                                requirement.verifier,
                                requirement.receipt_schema,
                            )
                            .is_err()
                            || accepted.stamp.receipt_digest == Digest::ZERO
                            || accepted.stamp.identity.verifier() != requirement.verifier
                            || accepted.stamp.identity.receipt_schema()
                                != requirement.receipt_schema
                            || accepted.stamp.identity.epoch() == 0
                            || !freshness_matches(
                                requirement.subject_freshness,
                                accepted.subject,
                                claim.enrolled_freshness,
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
                if !claim.retired
                    && !prepared_handoff_target_claim(state, composite, component, claim)
                {
                    let charged = expected_charges
                        .get_or_insert_with_mut((composite.charge_owner, claim.credit_class), || 0);
                    *charged = charged
                        .checked_add(claim.units)
                        .ok_or(CoreError::InvariantViolation)?;
                    let catalog_charged = expected_catalog_charges
                        .entry((
                            composite.catalog_digest,
                            composite.charge_owner,
                            claim.credit_class,
                        ))
                        .or_insert(0);
                    *catalog_charged = catalog_charged
                        .checked_add(claim.units)
                        .ok_or(CoreError::InvariantViolation)?;
                    expected_composite_resources
                        .get_or_insert_with_mut(claim.resource, Vec::new)
                        .push((composite.effect, component.id, claim.id));
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
            let retained_claims = component
                .claims
                .values()
                .filter(|claim| !claim.retired)
                .count();
            let expected_retirement = if component.retirement == RetirementState::Released {
                RetirementState::Released
            } else if component.claims.is_empty() {
                if component.commit == CommitState::Committed
                    || component.settlement == SettlementState::Revoked
                {
                    RetirementState::Retired
                } else {
                    RetirementState::Held
                }
            } else if retained_claims == 0 {
                RetirementState::Retired
            } else if component.commit == CommitState::Committed
                || composite.authority != AuthorityState::Active
            {
                RetirementState::RetirementPending
            } else {
                RetirementState::Held
            };
            if component.retirement != expected_retirement {
                return Err(CoreError::InvariantViolation);
            }
        }
    }
    for key in state.charges().keys().chain(expected_charges.keys()) {
        let actual = state.charges().get(key).copied().unwrap_or(0);
        let expected = expected_charges.get(key).copied().unwrap_or(0);
        if actual != expected || actual > limits.max_units_per_account {
            return Err(CoreError::InvariantViolation);
        }
    }
    for ((catalog_digest, _charge_owner, credit_class), charged) in expected_catalog_charges {
        let catalog = catalogs
            .get(catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let class_limit = catalog
            .credit_rule(credit_class)
            .ok_or(CoreError::InvariantViolation)?
            .max_units_per_account()
            .min(limits.max_units_per_account);
        if charged > class_limit {
            return Err(CoreError::InvariantViolation);
        }
    }
    if *state.composite_resource_index() != expected_composite_resources {
        return Err(CoreError::InvariantViolation);
    }
    for (resource, record) in state.resources() {
        match record.phase {
            ResourcePhase::Claimed { pending_reuse } => {
                let (custodians, all_shared) = live_resource_conflict_summary_for_set(
                    catalogs,
                    state,
                    *resource,
                    record.generation,
                    ConflictMode::Shared,
                )?;
                if custodians == 0 || (custodians > 1 && !all_shared) {
                    return Err(CoreError::InvariantViolation);
                }
                let pending_is_invalid =
                    pending_reuse.is_some_and(|pending| {
                        let Some(pending_catalog) = catalogs.get(pending.catalog_digest) else {
                            return true;
                        };
                        pending.nonce == 0
                            || pending.authority_epoch == 0
                            || pending.catalog_digest != pending_catalog.digest()
                            || state.composite_effects().get(&pending.effect).is_none_or(
                                |composite| composite.catalog_digest != pending.catalog_digest,
                            )
                            || pending.retirement_digest.is_zero()
                            || pending.reuse_contract.is_zero()
                            || pending.previous_generation.get().checked_add(1)
                                != Some(record.generation.get())
                            || !state
                                .composite_effects()
                                .get(&pending.effect)
                                .and_then(|composite| composite.components.get(&pending.component))
                                .is_some_and(|component| {
                                    component.claims.get(&pending.claim).is_some_and(|claim| {
                                        !claim.retired
                                            && claim.resource == *resource
                                            && claim.resource_generation == record.generation
                                    })
                                })
                    });
                if expected_composite_resources
                    .get(resource)
                    .is_none_or(Vec::is_empty)
                    || active_resource_generations.get(resource) != Some(&record.generation)
                    || active_resource_scopes.get(resource) != Some(&record.scope)
                    || pending_is_invalid
                {
                    return Err(CoreError::InvariantViolation);
                }
            }
            ResourcePhase::Retired => {
                if expected_composite_resources.contains_key(resource) {
                    return Err(CoreError::InvariantViolation);
                }
            }
        }
    }
    if expected_composite_resources
        .keys()
        .any(|resource| !state.resources().contains_key(resource))
    {
        return Err(CoreError::InvariantViolation);
    }
    for operation in state.recovery_operations().values() {
        let crash_state_matches = match operation.state {
            OperationRecoveryState::Fenced {
                crash_generation, ..
            }
            | OperationRecoveryState::RecoveryExhausted {
                crash_generation, ..
            } => crash_generation == operation.crash_generation,
            _ => true,
        };
        let over_quota_is_exhausted = operation.crash_generation
            <= limits.max_crashes_per_operation
            || matches!(
                operation.state,
                OperationRecoveryState::RecoveryExhausted { .. }
            );
        if !over_quota_is_exhausted
            || !crash_state_matches
            || operation.last_executor.generation() < operation.origin.generation()
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(())
}

/// Runs the complete invariant oracle against the exact catalog recorded by
/// every provider generation and composite effect.
fn check_invariants_for_catalog_set(
    catalogs: &CatalogSet,
    limits: CoreLimits,
    state: &impl StateAccess,
) -> Result<(), CoreError> {
    check_invariants(catalogs, limits, state)
}

fn verifier_bindings_are_canonical(bindings: &[VerifierBinding]) -> bool {
    bindings.windows(2).all(|pair| {
        pair[0]
            .class_binding()
            .cmp(&pair[1].class_binding())
            .then_with(|| pair[0].cmp(&pair[1]))
            != core::cmp::Ordering::Greater
    })
}

fn state_scoped_verifier_binding(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> Result<VerifierBinding, CoreError> {
    Ok(
        state_scoped_verification_scope(state, effect, component, verifier, receipt_schema)?
            .verifier_binding(),
    )
}

fn state_scoped_verification_scope(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> Result<ProviderVerificationScope, CoreError> {
    let Some(scope_source) = state
        .scoped_composites()
        .get(&effect)
        .map(|scoped| (scoped.catalog_digest, &scoped.bindings))
        .or_else(|| {
            state
                .composite_effects()
                .get(&effect)
                .and_then(|composite| composite.released_provenance.as_ref())
                .map(|provenance| (provenance.catalog_digest, &provenance.bindings))
        })
    else {
        return Err(CoreError::UnknownEffect);
    };
    let provider = *scope_source
        .1
        .get(&component)
        .ok_or(CoreError::ProviderBindingMismatch)?;
    let record = state
        .provider_generations()
        .get(&provider)
        .ok_or(CoreError::UnknownProviderGeneration)?;
    let binding = record
        .verifier_bindings
        .iter()
        .find(|binding| {
            binding.verifier() == verifier && binding.receipt_schema() == receipt_schema
        })
        .copied()
        .ok_or(CoreError::VerifierSetMismatch)?;
    let world = state.world();
    if world != provider.world() || scope_source.0 != record.catalog_digest {
        return Err(CoreError::ProviderBindingMismatch);
    }
    Ok(ProviderVerificationScope::new(
        world,
        provider,
        effect.operation(),
        record.catalog_digest,
        binding,
    ))
}

fn validate_state_verification_scope(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
    provided: ProviderVerificationScope,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> Result<(), CoreError> {
    let expected =
        state_scoped_verification_scope(state, effect, component, verifier, receipt_schema)?;
    if expected != provided {
        return Err(CoreError::ProviderBindingMismatch);
    }
    Ok(())
}

fn validate_state_verifier_identity(
    state: &impl StateAccess,
    effect: EffectId,
    component: ComponentId,
    identity: VerifierIdentity,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
) -> Result<(), CoreError> {
    if identity.verifier() != verifier {
        return Err(CoreError::UnknownVerifier);
    }
    if identity.receipt_schema() != receipt_schema {
        return Err(CoreError::ReceiptSchemaMismatch);
    }
    let binding =
        state_scoped_verifier_binding(state, effect, component, verifier, receipt_schema)?;
    if identity.implementation_digest() != binding.implementation_digest() {
        return Err(CoreError::UnknownVerifier);
    }
    if identity.epoch() != binding.generation().get() {
        return Err(CoreError::StaleVerifierEpoch);
    }
    Ok(())
}

fn retirement_contract_digest(
    catalog_digest: Digest,
    state: &impl StateAccess,
    resource: ResourceId,
    generation: ResourceGeneration,
) -> Result<Digest, CoreError> {
    let record = state
        .resources()
        .get(&resource)
        .ok_or(CoreError::UnknownResource)?;
    if record.generation != generation || record.phase != ResourcePhase::Retired {
        return Err(CoreError::ResourceRetained);
    }

    let mut claims = Vec::new();
    for (effect, composite) in state.composite_effects() {
        for (component, record) in &composite.components {
            for claim in record.claims.values() {
                if claim.resource == resource && claim.resource_generation == generation {
                    claims.push((*effect, Some(*component), claim));
                }
            }
        }
    }
    if claims.is_empty()
        || claims.iter().any(|(_, _, claim)| {
            !claim.retired
                || claim
                    .requirements
                    .iter()
                    .any(|requirement| requirement.accepted.is_none())
        })
    {
        return Err(CoreError::InvariantViolation);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"CSER-RESOURCE-RETIREMENT-V1");
    hasher.update(catalog_digest.bytes());
    hasher.update(resource.get().to_le_bytes());
    hasher.update(generation.get().to_le_bytes());
    hash_claim_scope(&mut hasher, record.scope);
    hasher.update((claims.len() as u64).to_le_bytes());
    for (effect, component, claim) in claims {
        hasher.update(effect.operation().get().to_le_bytes());
        hasher.update(effect.sequence().to_le_bytes());
        hash_optional_component(&mut hasher, component);
        hasher.update(claim.id.get().to_le_bytes());
        hasher.update(claim.domain.get().to_le_bytes());
        hasher.update(claim.kind.get().to_le_bytes());
        hasher.update(claim.credit_class.get().to_le_bytes());
        hash_claim_scope(&mut hasher, claim.scope);
        hasher.update(claim.resource.get().to_le_bytes());
        hasher.update(claim.resource_generation.get().to_le_bytes());
        hasher.update(claim.units.to_le_bytes());
        hash_freshness(&mut hasher, claim.enrolled_freshness);
        hasher.update((claim.requirements.len() as u64).to_le_bytes());
        for requirement in &claim.requirements {
            hasher.update(requirement.kind.get().to_le_bytes());
            hasher.update(requirement.verifier.get().to_le_bytes());
            hasher.update(requirement.receipt_schema.get().to_le_bytes());
            let accepted = requirement.accepted.ok_or(CoreError::InvariantViolation)?;
            hash_freshness(&mut hasher, accepted.subject);
            hash_freshness(&mut hasher, accepted.observation);
            hash_provider_verification_scope(&mut hasher, accepted.verification_scope);
            hash_verifier_stamp(&mut hasher, accepted.stamp);
        }
    }
    Ok(Digest::new(hasher.finalize().into()))
}

#[allow(dead_code)]
fn full_projection_digest(state: &impl StateAccess, catalog: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.projection.v10");
    hasher.update(crate::CSER_CORE_API_PROFILE_VERSION.to_le_bytes());
    hasher.update(crate::PROJECTION_VERSION.to_le_bytes());
    hasher.update(crate::JOURNAL_SCHEMA_VERSION.to_le_bytes());
    hasher.update(catalog.bytes());
    hasher.update(state.revision().to_le_bytes());
    hasher.update(state.head().bytes());
    hash_freshness(&mut hasher, state.freshness());
    hasher.update(state.next_nonce().to_le_bytes());
    {
        hasher.update([1]);
        hasher.update(state.world().get().to_le_bytes());
        for (provider, high) in state.provider_high_water() {
            hasher.update(provider.get().to_le_bytes());
            hasher.update(high.get().to_le_bytes());
        }
        hasher.update([0xf0]);
        for (coordinate, record) in state.provider_generations() {
            hasher.update(coordinate.world().get().to_le_bytes());
            hasher.update(coordinate.provider().get().to_le_bytes());
            hasher.update(coordinate.generation().get().to_le_bytes());
            hasher.update(record.catalog_digest.bytes());
            hasher.update(record.verifier_set_digest.bytes());
            hasher.update((record.verifier_bindings.len() as u64).to_le_bytes());
            for binding in &record.verifier_bindings {
                hash_verifier_binding(&mut hasher, *binding);
            }
            match record.artifact_receipts {
                Some(receipts) => {
                    hasher.update([1]);
                    hash_verifier_binding(&mut hasher, receipts.pin());
                    hash_verifier_binding(&mut hasher, receipts.release());
                }
                None => hasher.update([0]),
            }
            hasher.update([provider_state_tag(record.state)]);
            hasher.update(provider_epoch(record.state).to_le_bytes());
            hasher.update((record.live_component_bindings as u64).to_le_bytes());
        }
        hasher.update([0xf1]);
        for (effect, scoped) in state.scoped_composites() {
            hasher.update(effect.operation().get().to_le_bytes());
            hasher.update(effect.sequence().to_le_bytes());
            hasher.update((scoped.bindings.len() as u64).to_le_bytes());
            for (component, provider) in &scoped.bindings {
                hasher.update(component.get().to_le_bytes());
                hasher.update(provider.world().get().to_le_bytes());
                hasher.update(provider.provider().get().to_le_bytes());
                hasher.update(provider.generation().get().to_le_bytes());
            }
            hasher.update([0xf3]);
            hasher.update((scoped.artifacts.len() as u64).to_le_bytes());
            for (component, binding) in &scoped.artifacts {
                hasher.update(component.get().to_le_bytes());
                hash_artifact_binding(&mut hasher, *binding);
            }
        }
        hasher.update([0xf2]);
        hasher.update((state.artifact_leases().len() as u64).to_le_bytes());
        for (artifact, lease) in state.artifact_leases() {
            hasher.update(artifact.get().to_le_bytes());
            hash_artifact_lease(&mut hasher, *lease);
        }
        hasher.update([0xf4]);
    }
    hasher.update([u8::from(state.recovery_target().is_some())]);
    if let Some(target) = state.recovery_target() {
        hash_freshness(&mut hasher, target);
    }
    for (operation_id, operation) in state.recovery_operations() {
        hasher.update(operation_id.get().to_le_bytes());
        hash_incarnation(&mut hasher, operation.origin);
        hash_incarnation(&mut hasher, operation.last_executor);
        hasher.update(operation.crash_generation.to_le_bytes());
        hash_operation_state(&mut hasher, operation.state);
    }
    hasher.update([0xfe]);
    hasher.update([0xf9]);
    for (effect_id, composite) in state.composite_effects() {
        hasher.update(effect_id.operation().get().to_le_bytes());
        hasher.update(effect_id.sequence().to_le_bytes());
        hasher.update(composite.kind.get().to_le_bytes());
        hash_incarnation(&mut hasher, composite.causal_owner);
        hash_custody(&mut hasher, composite.custodian);
        hasher.update(composite.charge_owner.get().to_le_bytes());
        hasher.update([
            authority_tag(composite.authority),
            effect_escape_tag(composite_escape_state(composite)),
        ]);
        hasher.update(composite.authority_epoch.to_le_bytes());
        match &composite.handoff {
            SingleHopRole::None => hasher.update([0]),
            SingleHopRole::Source {
                descriptor,
                terminal_receipt_digest,
                descriptor_receipt_digest,
                recovery_fact,
            } => {
                hasher.update([1]);
                hasher.update(handoff_descriptor_digest(**descriptor).bytes());
                hasher.update(terminal_receipt_digest.bytes());
                hasher.update(descriptor_receipt_digest.bytes());
                hash_optional_handoff_recovery_fact(&mut hasher, *recovery_fact);
            }
            SingleHopRole::Target {
                parent,
                descriptor_digest,
                recovery_fact,
            } => {
                hasher.update([2]);
                hasher.update(parent.operation().get().to_le_bytes());
                hasher.update(parent.sequence().to_le_bytes());
                hasher.update(descriptor_digest.bytes());
                hash_optional_handoff_recovery_fact(&mut hasher, *recovery_fact);
            }
        }
        for (component_id, component) in &composite.components {
            hasher.update(component_id.get().to_le_bytes());
            hasher.update(component.domain.get().to_le_bytes());
            hasher.update(component.obligation.get().to_le_bytes());
            hasher.update([
                component.obligation_policy.tag(),
                commit_tag(component.commit),
                retirement_tag(component.retirement),
            ]);
            hash_outcome(&mut hasher, component.outcome);
            hash_settlement(&mut hasher, component.settlement);
            hash_optional_u64(&mut hasher, component.commit_nonce);
            hash_optional_digest(&mut hasher, component.commit_operation);
            hash_optional_effect_fact(&mut hasher, component.commit_fact);
            hash_optional_u64(&mut hasher, component.settlement_nonce);
            hasher.update([component.claim_stage.map(claim_stage_tag).unwrap_or(0)]);
            hash_optional_digest(&mut hasher, component.settlement_intent);
            hash_optional_effect_fact(&mut hasher, component.applied_fact);
            hash_optional_effect_fact(&mut hasher, component.settlement_fact);
            for (claim_id, claim) in &component.claims {
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
                        hash_provider_verification_scope(&mut hasher, accepted.verification_scope);
                        hash_verifier_stamp(&mut hasher, accepted.stamp);
                    }
                }
            }
            hasher.update([0xf8]);
        }
        hasher.update([0xf7]);
    }
    hasher.update([0xfc]);
    for (resource, record) in state.resources() {
        hasher.update(resource.get().to_le_bytes());
        hash_claim_scope(&mut hasher, record.scope);
        hasher.update(record.generation.get().to_le_bytes());
        match record.phase {
            ResourcePhase::Claimed { pending_reuse } => {
                hasher.update([1, u8::from(pending_reuse.is_some())]);
                if let Some(pending) = pending_reuse {
                    hasher.update(pending.effect.operation().get().to_le_bytes());
                    hasher.update(pending.effect.sequence().to_le_bytes());
                    hash_component(&mut hasher, pending.component);
                    hash_incarnation(&mut hasher, pending.actor);
                    hasher.update(pending.authority_epoch.to_le_bytes());
                    hasher.update(pending.claim.get().to_le_bytes());
                    hasher.update(pending.previous_generation.get().to_le_bytes());
                    hasher.update(pending.catalog_digest.bytes());
                    hasher.update(pending.retirement_digest.bytes());
                    hasher.update(pending.reuse_contract.bytes());
                    hasher.update(pending.nonce.to_le_bytes());
                    hash_freshness(&mut hasher, pending.freshness);
                }
            }
            ResourcePhase::Retired => hasher.update([2]),
        }
    }
    hasher.update([0xfb]);
    for (scope, generation) in state.device_generations() {
        hasher.update(scope.get().to_le_bytes());
        hasher.update(generation.get().to_le_bytes());
        hasher.update([u8::from(state.device_quarantine().contains(scope))]);
    }
    Digest::new(hasher.finalize().into())
}

const PROJECTION_LEAF_KEY_TAG: &[u8] = b"CSER/Projection/LeafKey/v1";
const PROJECTION_LEAF_VALUE_TAG: &[u8] = b"CSER/Projection/LeafValue/v1";

const LEAF_PROVIDER_HIGH_WATER: u8 = 1;
const LEAF_PROVIDER_RECORD: u8 = 2;
const LEAF_SCOPED_EFFECT: u8 = 3;
const LEAF_ARTIFACT_LEASE: u8 = 4;
const LEAF_OPERATION: u8 = 5;
const LEAF_COMPOSITE: u8 = 7;
const LEAF_RESOURCE: u8 = 8;
const LEAF_DEVICE: u8 = 9;

fn projection_record_digest(tag: &[u8], write: impl FnOnce(&mut Sha256)) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_LEAF_VALUE_TAG);
    hasher.update(tag);
    write(&mut hasher);
    Digest::new(hasher.finalize().into())
}

fn projection_leaf_key(category: u8, key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_LEAF_KEY_TAG);
    hasher.update([category]);
    hasher.update((key.len() as u64).to_le_bytes());
    hasher.update(key);
    hasher.finalize().into()
}

fn projection_key_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

fn projection_key_effect(effect: EffectId) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&effect.operation().get().to_le_bytes());
    key[8..].copy_from_slice(&effect.sequence().to_le_bytes());
    key
}

fn projection_key_provider(coordinate: ProviderCoordinate) -> [u8; 24] {
    let mut key = [0; 24];
    key[..8].copy_from_slice(&coordinate.world().get().to_le_bytes());
    key[8..16].copy_from_slice(&coordinate.provider().get().to_le_bytes());
    key[16..].copy_from_slice(&coordinate.generation().get().to_le_bytes());
    key
}

fn hash_provider_record(record: &ProviderGenerationRecord) -> Digest {
    projection_record_digest(b"provider", |hasher| {
        hasher.update(record.coordinate.world().get().to_le_bytes());
        hasher.update(record.coordinate.provider().get().to_le_bytes());
        hasher.update(record.coordinate.generation().get().to_le_bytes());
        hasher.update(record.catalog_digest.bytes());
        hasher.update(record.verifier_set_digest.bytes());
        hasher.update((record.verifier_bindings.len() as u64).to_le_bytes());
        for binding in &record.verifier_bindings {
            hash_verifier_binding(hasher, *binding);
        }
        match record.artifact_receipts {
            Some(receipts) => {
                hasher.update([1]);
                hash_verifier_binding(hasher, receipts.pin());
                hash_verifier_binding(hasher, receipts.release());
            }
            None => hasher.update([0]),
        }
        hasher.update([provider_state_tag(record.state)]);
        hasher.update(provider_epoch(record.state).to_le_bytes());
        hasher.update((record.live_component_bindings as u64).to_le_bytes());
    })
}

fn hash_scoped_record(effect: EffectId, record: &ScopedCompositeRecord) -> Digest {
    projection_record_digest(b"scoped", |hasher| {
        hasher.update(effect.operation().get().to_le_bytes());
        hasher.update(record.catalog_digest.bytes());
        hasher.update((record.bindings.len() as u64).to_le_bytes());
        for (component, provider) in &record.bindings {
            hasher.update(component.get().to_le_bytes());
            hasher.update(provider.world().get().to_le_bytes());
            hasher.update(provider.provider().get().to_le_bytes());
            hasher.update(provider.generation().get().to_le_bytes());
        }
        hasher.update((record.artifacts.len() as u64).to_le_bytes());
        for (component, binding) in &record.artifacts {
            hasher.update(component.get().to_le_bytes());
            hash_artifact_binding(hasher, *binding);
        }
    })
}

fn hash_operation_record(record: &CompositeRecoveryRecord) -> Digest {
    projection_record_digest(b"operation", |hasher| {
        hash_incarnation(hasher, record.origin);
        hash_incarnation(hasher, record.last_executor);
        hasher.update(record.crash_generation.to_le_bytes());
        hash_operation_state(hasher, record.state);
    })
}

fn hash_requirement_record(requirement: &RequirementState, hasher: &mut Sha256) {
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
    match requirement.accepted {
        Some(accepted) => {
            hasher.update([1]);
            hash_freshness(hasher, accepted.subject);
            hash_freshness(hasher, accepted.observation);
            hash_provider_verification_scope(hasher, accepted.verification_scope);
            hash_verifier_stamp(hasher, accepted.stamp);
        }
        None => hasher.update([0]),
    }
}

fn hash_claim_record(claim: &ClaimRecord, hasher: &mut Sha256) {
    hasher.update(claim.id.get().to_le_bytes());
    hasher.update(claim.domain.get().to_le_bytes());
    hasher.update(claim.kind.get().to_le_bytes());
    hasher.update(claim.credit_class.get().to_le_bytes());
    hash_claim_scope(hasher, claim.scope);
    hasher.update(claim.resource.get().to_le_bytes());
    hasher.update(claim.resource_generation.get().to_le_bytes());
    hasher.update(claim.units.to_le_bytes());
    hash_freshness(hasher, claim.enrolled_freshness);
    hasher.update([u8::from(claim.retired)]);
    hasher.update((claim.requirements.len() as u64).to_le_bytes());
    for requirement in &claim.requirements {
        hash_requirement_record(requirement, hasher);
    }
}

fn hash_component_record(record: &ComponentRecord, hasher: &mut Sha256) {
    hasher.update(record.id.get().to_le_bytes());
    hasher.update(record.domain.get().to_le_bytes());
    hasher.update(record.obligation.get().to_le_bytes());
    hasher.update([
        record.obligation_policy.tag(),
        commit_tag(record.commit),
        retirement_tag(record.retirement),
    ]);
    hash_outcome(hasher, record.outcome);
    hash_settlement(hasher, record.settlement);
    hash_optional_u64(hasher, record.commit_nonce);
    hash_optional_digest(hasher, record.commit_operation);
    hash_optional_effect_fact(hasher, record.commit_fact);
    hash_optional_u64(hasher, record.settlement_nonce);
    hasher.update([record.claim_stage.map(claim_stage_tag).unwrap_or(0)]);
    hash_optional_digest(hasher, record.settlement_intent);
    hash_optional_effect_fact(hasher, record.applied_fact);
    hash_optional_effect_fact(hasher, record.settlement_fact);
    hasher.update((record.claims.len() as u64).to_le_bytes());
    for (claim_id, claim) in &record.claims {
        hasher.update(claim_id.get().to_le_bytes());
        hash_claim_record(claim, hasher);
    }
}

fn hash_composite_record(record: &CompositeEffectRecord) -> Digest {
    projection_record_digest(b"composite", |hasher| {
        hasher.update(record.effect.operation().get().to_le_bytes());
        hasher.update(record.effect.sequence().to_le_bytes());
        hasher.update(record.kind.get().to_le_bytes());
        hasher.update(record.catalog_digest.bytes());
        hash_incarnation(hasher, record.causal_owner);
        hash_custody(hasher, record.custodian);
        hasher.update(record.charge_owner.get().to_le_bytes());
        hasher.update([
            authority_tag(record.authority),
            effect_escape_tag(composite_escape_state(record)),
        ]);
        hasher.update(record.authority_epoch.to_le_bytes());
        match &record.handoff {
            SingleHopRole::None => hasher.update([0]),
            SingleHopRole::Source {
                descriptor,
                terminal_receipt_digest,
                descriptor_receipt_digest,
                recovery_fact,
            } => {
                hasher.update([1]);
                hasher.update(handoff_descriptor_digest(**descriptor).bytes());
                hasher.update(terminal_receipt_digest.bytes());
                hasher.update(descriptor_receipt_digest.bytes());
                hash_optional_handoff_recovery_fact(hasher, *recovery_fact);
            }
            SingleHopRole::Target {
                parent,
                descriptor_digest,
                recovery_fact,
            } => {
                hasher.update([2]);
                hasher.update(parent.operation().get().to_le_bytes());
                hasher.update(parent.sequence().to_le_bytes());
                hasher.update(descriptor_digest.bytes());
                hash_optional_handoff_recovery_fact(hasher, *recovery_fact);
            }
        }
        if let Some(provenance) = &record.released_provenance {
            // Absence preserves the pre-provenance encoding for every live
            // composite. Released provenance is an additive terminal suffix.
            hasher.update(b"released-provenance-v1");
            hash_released_provenance(hasher, provenance);
        }
        hasher.update((record.components.len() as u64).to_le_bytes());
        for (component_id, component) in &record.components {
            hasher.update(component_id.get().to_le_bytes());
            hash_component_record(component, hasher);
        }
    })
}

fn hash_released_provenance(hasher: &mut Sha256, provenance: &ReleasedCompositeProvenance) {
    hasher.update(provenance.catalog_digest.bytes());
    hasher.update((provenance.bindings.len() as u64).to_le_bytes());
    for (component, provider) in &provenance.bindings {
        hasher.update(component.get().to_le_bytes());
        hasher.update(provider.world().get().to_le_bytes());
        hasher.update(provider.provider().get().to_le_bytes());
        hasher.update(provider.generation().get().to_le_bytes());
    }
    hasher.update((provenance.artifacts.len() as u64).to_le_bytes());
    for (component, binding) in &provenance.artifacts {
        hasher.update(component.get().to_le_bytes());
        hash_artifact_binding(hasher, *binding);
    }
}

fn hash_resource_record(record: &ResourceRecord) -> Digest {
    projection_record_digest(b"resource", |hasher| {
        hash_claim_scope(hasher, record.scope);
        hasher.update(record.generation.get().to_le_bytes());
        match record.phase {
            ResourcePhase::Claimed { pending_reuse } => {
                hasher.update([1, u8::from(pending_reuse.is_some())]);
                if let Some(pending) = pending_reuse {
                    hasher.update(pending.effect.operation().get().to_le_bytes());
                    hasher.update(pending.effect.sequence().to_le_bytes());
                    hash_component(hasher, pending.component);
                    hash_incarnation(hasher, pending.actor);
                    hasher.update(pending.authority_epoch.to_le_bytes());
                    hasher.update(pending.claim.get().to_le_bytes());
                    hasher.update(pending.previous_generation.get().to_le_bytes());
                    hasher.update(pending.catalog_digest.bytes());
                    hasher.update(pending.retirement_digest.bytes());
                    hasher.update(pending.reuse_contract.bytes());
                    hasher.update(pending.nonce.to_le_bytes());
                    hash_freshness(hasher, pending.freshness);
                }
            }
            ResourcePhase::Retired => hasher.update([2]),
        }
    })
}

fn hash_device_record(generation: Option<DeviceGeneration>, quarantined: bool) -> Digest {
    projection_record_digest(b"device", |hasher| {
        match generation {
            Some(generation) => {
                hasher.update([1]);
                hasher.update(generation.get().to_le_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update([u8::from(quarantined)]);
    })
}

fn insert_projection_leaf(leaves: &mut AuthenticatedMap, category: u8, key: &[u8], value: Digest) {
    let _ = leaves.insert_mut(projection_leaf_key(category, key), value);
}

fn build_projection_cache(state: &impl StateAccess, catalog: Digest) -> ProjectionCache {
    let mut leaves = AuthenticatedMap::new();
    for (provider, generation) in state.provider_high_water() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_PROVIDER_HIGH_WATER,
            &projection_key_u64(provider.get()),
            projection_record_digest(b"provider-high-water", |hasher| {
                hasher.update(generation.get().to_le_bytes());
            }),
        );
    }
    for (coordinate, record) in state.provider_generations() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_PROVIDER_RECORD,
            &projection_key_provider(*coordinate),
            hash_provider_record(record),
        );
    }
    for (effect, record) in state.scoped_composites() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_SCOPED_EFFECT,
            &projection_key_effect(*effect),
            hash_scoped_record(*effect, record),
        );
    }
    for (artifact, lease) in state.artifact_leases() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_ARTIFACT_LEASE,
            &projection_key_u64(artifact.get()),
            projection_record_digest(b"artifact-lease", |hasher| {
                hash_artifact_lease(hasher, *lease);
            }),
        );
    }
    for (operation, record) in state.recovery_operations() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_OPERATION,
            &projection_key_u64(operation.get()),
            hash_operation_record(record),
        );
    }
    for (effect, record) in state.composite_effects() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_COMPOSITE,
            &projection_key_effect(*effect),
            hash_composite_record(record),
        );
    }
    for (resource, record) in state.resources() {
        insert_projection_leaf(
            &mut leaves,
            LEAF_RESOURCE,
            &projection_key_u64(resource.get()),
            hash_resource_record(record),
        );
    }
    let mut device_scopes = state.device_quarantine().clone();
    device_scopes.extend(state.device_generations().keys().copied());
    for scope in &device_scopes {
        insert_projection_leaf(
            &mut leaves,
            LEAF_DEVICE,
            &projection_key_u64(scope.get()),
            hash_device_record(
                state.device_generations().get(scope).copied(),
                state.device_quarantine().contains(scope),
            ),
        );
    }
    ProjectionCache::from_leaves(state, catalog, leaves)
}

fn projection_envelope(state: &impl StateAccess, catalog: Digest, leaves_root: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.projection.v10");
    hasher.update(crate::CSER_CORE_API_PROFILE_VERSION.to_le_bytes());
    hasher.update(crate::PROJECTION_VERSION.to_le_bytes());
    hasher.update(crate::JOURNAL_SCHEMA_VERSION.to_le_bytes());
    hasher.update(catalog.bytes());
    hasher.update(state.revision().to_le_bytes());
    hasher.update(state.head().bytes());
    hash_freshness(&mut hasher, state.freshness());
    hasher.update(state.next_nonce().to_le_bytes());
    hasher.update([1]);
    hasher.update(state.world().get().to_le_bytes());
    match state.recovery_target() {
        Some(target) => {
            hasher.update([1]);
            hash_freshness(&mut hasher, target);
        }
        None => hasher.update([0]),
    }
    hasher.update(leaves_root.bytes());
    Digest::new(hasher.finalize().into())
}

#[derive(Default)]
struct ProjectionTouches {
    provider_high_water: BTreeSet<ProviderId>,
    provider_generations: BTreeSet<ProviderCoordinate>,
    scoped_composites: BTreeSet<EffectId>,
    artifact_leases: BTreeSet<crate::RecoveryArtifactId>,
    operations: BTreeSet<OperationId>,
    composites: BTreeSet<EffectId>,
    resources: BTreeSet<ResourceId>,
    devices: BTreeSet<DeviceScopeId>,
}

impl ProjectionTouches {
    fn merge(&mut self, other: Self) {
        self.provider_high_water.extend(other.provider_high_water);
        self.provider_generations.extend(other.provider_generations);
        self.scoped_composites.extend(other.scoped_composites);
        self.artifact_leases.extend(other.artifact_leases);
        self.operations.extend(other.operations);
        self.composites.extend(other.composites);
        self.resources.extend(other.resources);
        self.devices.extend(other.devices);
    }
}

fn transition_total_claims(
    previous: &impl StateAccess,
    candidate: &impl StateAccess,
    touches: &ProjectionTouches,
) -> Result<usize, CoreError> {
    let mut effects = BTreeSet::new();
    effects.extend(touches.composites.iter().copied());
    let mut total = previous.total_claims();
    for effect in effects {
        let before = previous
            .composite_effects()
            .get(&effect)
            .map(|composite| composite.components.values().map(|c| c.claims.len()).sum())
            .unwrap_or(0);
        let after = candidate
            .composite_effects()
            .get(&effect)
            .map(|composite| composite.components.values().map(|c| c.claims.len()).sum())
            .unwrap_or(0);
        if after >= before {
            total = total
                .checked_add(after - before)
                .ok_or(CoreError::InvariantViolation)?;
        } else {
            total = total
                .checked_sub(before - after)
                .ok_or(CoreError::InvariantViolation)?;
        }
    }
    Ok(total)
}

/// Production transition gate. The command application functions perform the
/// detailed semantic checks; this gate only checks the bounded state touched
/// by this command and the derived structures that expose it. Full
/// `check_invariants` remains the differential oracle in test builds and is
/// retained at initialization/recovery/checkpoint admission boundaries.
fn check_transition_local_invariants(
    catalog: Option<&DomainCatalog>,
    limits: CoreLimits,
    previous: &impl StateAccess,
    candidate: &impl StateAccess,
    touches: &ProjectionTouches,
) -> Result<(), CoreError> {
    let _ = catalog;
    if candidate.next_nonce() == 0
        || candidate.total_claims() > limits.max_total_claims
        || candidate.recovery_operations().len() > limits.max_operations
        || candidate.composite_effects().len() > limits.max_effects
        || candidate.resources().len() > limits.max_resource_records
    {
        return Err(CoreError::InvariantViolation);
    }

    for operation in &touches.operations {
        if !candidate.recovery_operations().contains_key(operation) {
            return Err(CoreError::InvariantViolation);
        }
        if candidate
            .composite_effects()
            .keys()
            .any(|effect| effect.operation() == *operation)
            && !candidate.recovery_operations().contains_key(operation)
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    for effect in &touches.composites {
        if !candidate.composite_effects().contains_key(effect)
            || !candidate
                .recovery_operations()
                .contains_key(&effect.operation())
        {
            return Err(CoreError::InvariantViolation);
        }
    }

    for provider in &touches.provider_generations {
        if !candidate.provider_generations().contains_key(provider) {
            return Err(CoreError::InvariantViolation);
        }
    }
    for provider in &touches.provider_high_water {
        if candidate
            .provider_high_water()
            .get(provider)
            .is_none_or(|generation| generation.get() == 0)
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    for effect in &touches.scoped_composites {
        if candidate.scoped_composites().contains_key(effect) {
            continue;
        }
        let released = previous.scoped_composites().contains_key(effect)
            && candidate
                .composite_effects()
                .get(effect)
                .is_some_and(|composite| {
                    composite.authority == AuthorityState::Revoked
                        && composite.custodian == CustodyState::Released
                        && composite
                            .components
                            .values()
                            .all(|component| component.retirement == RetirementState::Released)
                });
        if !released {
            return Err(CoreError::InvariantViolation);
        }
    }
    for artifact in &touches.artifact_leases {
        let admitted_unpinned = touches.scoped_composites.iter().any(|effect| {
            candidate
                .scoped_composites()
                .get(effect)
                .is_some_and(|scoped| {
                    scoped
                        .artifacts
                        .values()
                        .any(|binding| binding.artifact_id() == *artifact)
                })
        });
        if !candidate.artifact_leases().contains_key(artifact) && !admitted_unpinned {
            return Err(CoreError::InvariantViolation);
        }
    }
    for scope in &touches.devices {
        if candidate.device_quarantine().contains(scope)
            && candidate.device_generations().get(scope).is_none()
        {
            return Err(CoreError::InvariantViolation);
        }
    }

    // Validate reverse-index references for every touched resource. This is
    // bounded by the custodians of touched resources, not unrelated effects.
    for resource in &touches.resources {
        if let Some(entries) = candidate.composite_resource_index().get(resource) {
            for (effect, component, claim) in entries {
                let Some(claim_record) = candidate
                    .composite_effects()
                    .get(effect)
                    .and_then(|composite| composite.components.get(component))
                    .and_then(|component| component.claims.get(claim))
                else {
                    return Err(CoreError::InvariantViolation);
                };
                if claim_record.retired || claim_record.resource != *resource {
                    return Err(CoreError::InvariantViolation);
                }
            }
        }
        let indexed = candidate
            .composite_resource_index()
            .get(resource)
            .is_some_and(|entries| !entries.is_empty());
        if indexed && !candidate.resources().contains_key(resource) {
            return Err(CoreError::InvariantViolation);
        }
    }

    // A touched active claim must have a matching charge and reverse index.
    for effect in touches.composites.iter().copied() {
        if let Some(composite) = candidate.composite_effects().get(&effect) {
            for component in composite.components.values() {
                for claim in component.claims.values().filter(|claim| !claim.retired) {
                    if prepared_handoff_target_claim(candidate, composite, component, claim) {
                        continue;
                    }
                    if candidate
                        .composite_resource_index()
                        .get(&claim.resource)
                        .is_none_or(|entries| !entries.contains(&(effect, component.id, claim.id)))
                        || candidate
                            .charges()
                            .get(&(composite.charge_owner, claim.credit_class))
                            .is_none_or(|units| *units < claim.units)
                    {
                        return Err(CoreError::InvariantViolation);
                    }
                }
            }
        }
    }
    Ok(())
}

fn sync_projection_leaf<T>(
    leaves: &mut AuthenticatedMap,
    category: u8,
    key: &[u8],
    value: Option<&T>,
    digest: impl FnOnce(&T) -> Digest,
) {
    let key = projection_leaf_key(category, key);
    match value {
        Some(value) => {
            let _ = leaves.insert_mut(key, digest(value));
        }
        None => {
            let _ = leaves.remove_mut(&key);
        }
    }
}

fn refresh_projection_cache(
    previous: &impl StateAccess,
    candidate: &mut impl StateAccessMut,
    touches: &ProjectionTouches,
    catalog: Digest,
) {
    let mut leaves = previous.projection_cache().leaves.clone();
    for provider in &touches.provider_high_water {
        sync_projection_leaf(
            &mut leaves,
            LEAF_PROVIDER_HIGH_WATER,
            &projection_key_u64(provider.get()),
            candidate.provider_high_water().get(provider),
            |generation| {
                projection_record_digest(b"provider-high-water", |hasher| {
                    hasher.update(generation.get().to_le_bytes());
                })
            },
        );
    }
    for coordinate in &touches.provider_generations {
        sync_projection_leaf(
            &mut leaves,
            LEAF_PROVIDER_RECORD,
            &projection_key_provider(*coordinate),
            candidate.provider_generations().get(coordinate),
            hash_provider_record,
        );
    }
    for effect in &touches.scoped_composites {
        sync_projection_leaf(
            &mut leaves,
            LEAF_SCOPED_EFFECT,
            &projection_key_effect(*effect),
            candidate.scoped_composites().get(effect),
            |record| hash_scoped_record(*effect, record),
        );
    }
    for artifact in &touches.artifact_leases {
        sync_projection_leaf(
            &mut leaves,
            LEAF_ARTIFACT_LEASE,
            &projection_key_u64(artifact.get()),
            candidate.artifact_leases().get(artifact),
            |lease| {
                projection_record_digest(b"artifact-lease", |hasher| {
                    hash_artifact_lease(hasher, *lease);
                })
            },
        );
    }
    for operation in &touches.operations {
        sync_projection_leaf(
            &mut leaves,
            LEAF_OPERATION,
            &projection_key_u64(operation.get()),
            candidate.recovery_operations().get(operation),
            hash_operation_record,
        );
    }
    for effect in &touches.composites {
        sync_projection_leaf(
            &mut leaves,
            LEAF_COMPOSITE,
            &projection_key_effect(*effect),
            candidate.composite_effects().get(effect),
            hash_composite_record,
        );
    }
    for resource in &touches.resources {
        sync_projection_leaf(
            &mut leaves,
            LEAF_RESOURCE,
            &projection_key_u64(resource.get()),
            candidate.resources().get(resource),
            hash_resource_record,
        );
    }
    for scope in &touches.devices {
        let generation = candidate.device_generations().get(scope).copied();
        let quarantined = candidate.device_quarantine().contains(scope);
        let key = projection_leaf_key(LEAF_DEVICE, &projection_key_u64(scope.get()));
        if generation.is_some() || quarantined {
            let _ = leaves.insert_mut(key, hash_device_record(generation, quarantined));
        } else {
            let _ = leaves.remove_mut(&key);
        }
    }
    let projection = ProjectionCache::from_leaves(candidate, catalog, leaves);
    candidate.set_projection_cache(projection);

    #[cfg(feature = "test-support")]
    {
        let rebuilt = build_projection_cache(candidate, catalog);
        if candidate.projection_cache() != &rebuilt {
            let report = |category: u8, key: &[u8], label: &str| {
                let key = projection_leaf_key(category, key);
                let incremental = candidate.projection_cache().leaves.get(&key);
                let full = rebuilt.leaves.get(&key);
                if incremental != full {
                    panic!(
                        "projection mismatch {label}: key={key:?} incremental={incremental:?} full={full:?}"
                    );
                }
            };
            for provider in candidate.provider_high_water().keys() {
                report(
                    LEAF_PROVIDER_HIGH_WATER,
                    &projection_key_u64(provider.get()),
                    "provider-high-water",
                );
            }
            for coordinate in candidate.provider_generations().keys() {
                report(
                    LEAF_PROVIDER_RECORD,
                    &projection_key_provider(*coordinate),
                    "provider",
                );
            }
            for effect in candidate.scoped_composites().keys() {
                report(
                    LEAF_SCOPED_EFFECT,
                    &projection_key_effect(*effect),
                    "scoped",
                );
            }
            for operation in candidate.recovery_operations().keys() {
                report(
                    LEAF_OPERATION,
                    &projection_key_u64(operation.get()),
                    "operation",
                );
            }
            for effect in candidate.composite_effects().keys() {
                report(LEAF_COMPOSITE, &projection_key_effect(*effect), "composite");
            }
            for resource in candidate.resources().keys() {
                report(
                    LEAF_RESOURCE,
                    &projection_key_u64(resource.get()),
                    "resource",
                );
            }
            for scope in candidate.device_generations().keys() {
                report(
                    LEAF_DEVICE,
                    &projection_key_u64(scope.get()),
                    "device scope",
                );
            }
        }
        assert_eq!(
            candidate.projection_cache(),
            &rebuilt,
            "incremental projection cache diverged from a full rebuild"
        );
    }
}

#[allow(dead_code)]
fn projection_digest(state: &impl StateAccess, catalog: Digest) -> Digest {
    full_projection_digest(state, catalog)
}

fn hash_verifier_stamp(hasher: &mut Sha256, stamp: VerifierStamp) {
    hasher.update(stamp.identity.verifier().get().to_le_bytes());
    hasher.update(stamp.identity.epoch().to_le_bytes());
    hasher.update(stamp.identity.receipt_schema().get().to_le_bytes());
    hasher.update(stamp.identity.implementation_digest().bytes());
    hasher.update(stamp.receipt_digest.bytes());
}

fn hash_verifier_binding(hasher: &mut Sha256, binding: VerifierBinding) {
    hasher.update(binding.verifier().get().to_le_bytes());
    hasher.update(binding.generation().get().to_le_bytes());
    hasher.update(binding.receipt_schema().get().to_le_bytes());
    hasher.update(binding.implementation_digest().bytes());
}

fn hash_artifact_binding(hasher: &mut Sha256, binding: ArtifactBinding) {
    hasher.update(binding.artifact_id().get().to_le_bytes());
    hasher.update(binding.provider().world().get().to_le_bytes());
    hasher.update(binding.provider().provider().get().to_le_bytes());
    hasher.update(binding.provider().generation().get().to_le_bytes());
    hasher.update(binding.operation().get().to_le_bytes());
    hasher.update(binding.effect().operation().get().to_le_bytes());
    hasher.update(binding.effect().sequence().to_le_bytes());
    hasher.update(binding.component().get().to_le_bytes());
    hasher.update(binding.catalog_digest().bytes());
    hasher.update(binding.schema_digest().bytes());
    hasher.update(binding.verifier_set_digest().bytes());
    hasher.update(binding.closure_digest().bytes());
}

fn hash_artifact_lease(hasher: &mut Sha256, lease: ArtifactLeaseState) {
    match lease {
        ArtifactLeaseState::Pinned { binding, pin_stamp } => {
            hasher.update([1]);
            hash_artifact_binding(hasher, binding);
            hasher.update(pin_stamp.bytes());
        }
        ArtifactLeaseState::ReleaseAuthorized {
            binding,
            pin_stamp,
            release_operation,
            nonce,
        } => {
            hasher.update([2]);
            hash_artifact_binding(hasher, binding);
            hasher.update(pin_stamp.bytes());
            hasher.update(release_operation.get().to_le_bytes());
            hasher.update(nonce.to_le_bytes());
        }
        ArtifactLeaseState::Released {
            binding,
            pin_stamp,
            release_stamp,
        } => {
            hasher.update([3]);
            hash_artifact_binding(hasher, binding);
            hasher.update(pin_stamp.bytes());
            hasher.update(release_stamp.bytes());
        }
    }
}

fn hash_optional_effect_fact(hasher: &mut Sha256, fact: Option<VerifiedEffectFact>) {
    hasher.update([u8::from(fact.is_some())]);
    if let Some(fact) = fact {
        hasher.update([fact.kind.tag()]);
        hasher.update(fact.effect.operation().get().to_le_bytes());
        hasher.update(fact.effect.sequence().to_le_bytes());
        hash_component(hasher, fact.component);
        hash_incarnation(hasher, fact.actor);
        hasher.update(fact.generation.to_le_bytes());
        hasher.update(fact.nonce.to_le_bytes());
        hasher.update(fact.operation.bytes());
        hash_optional_digest(hasher, fact.predecessor);
        hash_freshness(hasher, fact.freshness);
        hash_provider_verification_scope(hasher, fact.verification_scope);
        hash_verifier_stamp(hasher, fact.stamp);
        hasher.update([match fact.outcome {
            None => 0,
            Some(ExternalOutcome::Success) => 1,
            Some(ExternalOutcome::Failure) => 2,
        }]);
    }
}

fn hash_optional_handoff_recovery_fact(
    hasher: &mut Sha256,
    fact: Option<VerifiedHandoffRecoveryFact>,
) {
    hasher.update([u8::from(fact.is_some())]);
    let Some(fact) = fact else {
        return;
    };
    hasher.update([match fact.role {
        HandoffRecoveryRole::Parent => 1,
        HandoffRecoveryRole::Child => 2,
    }]);
    hasher.update(fact.effect.operation().get().to_le_bytes());
    hasher.update(fact.effect.sequence().to_le_bytes());
    hash_component(hasher, fact.component);
    hasher.update(fact.operation.bytes());
    hasher.update(fact.descriptor_digest.bytes());
    hash_freshness(hasher, fact.freshness);
    hash_provider_verification_scope(hasher, fact.verification_scope);
    hash_verifier_stamp(hasher, fact.stamp);
}

fn hash_provider_verification_scope(hasher: &mut Sha256, scope: ProviderVerificationScope) {
    hasher.update(scope.world.get().to_le_bytes());
    hasher.update(scope.provider.world().get().to_le_bytes());
    hasher.update(scope.provider.provider().get().to_le_bytes());
    hasher.update(scope.provider.generation().get().to_le_bytes());
    hasher.update(scope.operation.get().to_le_bytes());
    hasher.update(scope.catalog_digest.bytes());
    hash_verifier_binding(hasher, scope.verifier_binding);
}

fn hash_component(hasher: &mut Sha256, component: ComponentId) {
    hasher.update(component.get().to_le_bytes());
}

fn hash_optional_component(hasher: &mut Sha256, component: Option<ComponentId>) {
    hasher.update([u8::from(component.is_some())]);
    if let Some(component) = component {
        hasher.update(component.get().to_le_bytes());
    }
}

const fn effect_escape_tag(state: EffectEscapeState) -> u8 {
    match state {
        EffectEscapeState::Unescaped => 1,
        EffectEscapeState::Escaped => 2,
        EffectEscapeState::PartiallyDischarged => 3,
        EffectEscapeState::Retired => 4,
        EffectEscapeState::Released => 5,
    }
}

const fn provider_state_tag(state: ProviderEffectState) -> u8 {
    match state {
        ProviderEffectState::Active => 1,
        ProviderEffectState::EffectFenced { .. } => 2,
        ProviderEffectState::SettlementOnly { .. } => 3,
        ProviderEffectState::Retired { .. } => 4,
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
    hasher.update(freshness.device().get().to_le_bytes());
    hasher.update(freshness.journal().get().to_le_bytes());
}

fn hash_incarnation(hasher: &mut Sha256, executor: ExecutorCoordinate) {
    hasher.update(executor.executor().get().to_le_bytes());
    hasher.update(executor.generation().get().to_le_bytes());
}

fn hash_custody(hasher: &mut Sha256, custody: CustodyState) {
    match custody {
        CustodyState::Executor(executor) => {
            hasher.update([1]);
            hash_incarnation(hasher, executor);
        }
        CustodyState::CoreOwned => hasher.update([2]),
        CustodyState::Released => hasher.update([3]),
    }
}

fn hash_claim_custodian(hasher: &mut Sha256, custody: ClaimCustodian) {
    match custody {
        ClaimCustodian::CoreOwned => hasher.update([1]),
        ClaimCustodian::DeviceProvider(scope) => {
            hasher.update([2]);
            hasher.update(scope.get().to_le_bytes());
        }
        ClaimCustodian::Released => hasher.update([3]),
    }
}

fn hash_operation_state(hasher: &mut Sha256, state: OperationRecoveryState) {
    match state {
        OperationRecoveryState::Active { executor } => {
            hasher.update([1]);
            hash_incarnation(hasher, executor);
        }
        OperationRecoveryState::Fenced {
            crashed,
            crash_generation,
        } => {
            hasher.update([2]);
            hash_incarnation(hasher, crashed);
            hasher.update(crash_generation.to_le_bytes());
        }
        OperationRecoveryState::Snapshotted { snapshot, digest } => {
            hasher.update([3]);
            hasher.update(snapshot.get().to_le_bytes());
            hasher.update(digest.bytes());
        }
        OperationRecoveryState::Ready {
            snapshot,
            successor,
        } => {
            hasher.update([4]);
            hasher.update(snapshot.get().to_le_bytes());
            hash_incarnation(hasher, successor);
        }
        OperationRecoveryState::Rebound { successor } => {
            hasher.update([5]);
            hash_incarnation(hasher, successor);
        }
        OperationRecoveryState::RecoveryExhausted {
            crashed,
            crash_generation,
        } => {
            hasher.update([6]);
            hash_incarnation(hasher, crashed);
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

fn handoff_descriptor_digest(descriptor: ChildDescriptorV1) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(descriptor.encode_wire());
    Digest::new(hasher.finalize().into())
}

fn hash_single_hop_handoff_projection(hasher: &mut Sha256, handoff: SingleHopHandoffProjection) {
    match handoff {
        SingleHopHandoffProjection::None => hasher.update([0]),
        SingleHopHandoffProjection::Source {
            descriptor,
            terminal_receipt_digest,
            descriptor_receipt_digest,
            recovery_fact,
            child_installed,
        } => {
            hasher.update([1]);
            hasher.update(handoff_descriptor_digest(*descriptor).bytes());
            hasher.update(terminal_receipt_digest.bytes());
            hasher.update(descriptor_receipt_digest.bytes());
            hash_optional_handoff_recovery_fact(hasher, recovery_fact);
            hasher.update([u8::from(child_installed)]);
        }
        SingleHopHandoffProjection::Target {
            parent,
            descriptor_digest,
            recovery_fact,
        } => {
            hasher.update([2]);
            hasher.update(parent.operation().get().to_le_bytes());
            hasher.update(parent.sequence().to_le_bytes());
            hasher.update(descriptor_digest.bytes());
            hash_optional_handoff_recovery_fact(hasher, recovery_fact);
        }
    }
}

fn child_wire_put_u8(bytes: &mut [u8], at: &mut usize, value: u8) {
    bytes[*at] = value;
    *at += 1;
}
fn child_wire_put_u16(bytes: &mut [u8], at: &mut usize, value: u16) {
    bytes[*at..*at + 2].copy_from_slice(&value.to_le_bytes());
    *at += 2;
}
fn child_wire_put_u32(bytes: &mut [u8], at: &mut usize, value: u32) {
    bytes[*at..*at + 4].copy_from_slice(&value.to_le_bytes());
    *at += 4;
}
fn child_wire_put_u64(bytes: &mut [u8], at: &mut usize, value: u64) {
    bytes[*at..*at + 8].copy_from_slice(&value.to_le_bytes());
    *at += 8;
}
fn child_wire_put_digest(bytes: &mut [u8], at: &mut usize, value: Digest) {
    bytes[*at..*at + 32].copy_from_slice(&value.bytes());
    *at += 32;
}
fn child_wire_u8(bytes: &[u8], at: &mut usize) -> Result<u8, ChildDescriptorDecodeError> {
    let value = *bytes
        .get(*at)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?;
    *at += 1;
    Ok(value)
}
fn child_wire_u16(bytes: &[u8], at: &mut usize) -> Result<u16, ChildDescriptorDecodeError> {
    let end = at
        .checked_add(2)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?;
    let value = u16::from_le_bytes(
        bytes
            .get(*at..end)
            .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?
            .try_into()
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?,
    );
    *at = end;
    Ok(value)
}
fn child_wire_u32(bytes: &[u8], at: &mut usize) -> Result<u32, ChildDescriptorDecodeError> {
    let end = at
        .checked_add(4)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?;
    let value = u32::from_le_bytes(
        bytes
            .get(*at..end)
            .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?
            .try_into()
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?,
    );
    *at = end;
    Ok(value)
}
fn child_wire_u64(bytes: &[u8], at: &mut usize) -> Result<u64, ChildDescriptorDecodeError> {
    let end = at
        .checked_add(8)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?;
    let value = u64::from_le_bytes(
        bytes
            .get(*at..end)
            .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?
            .try_into()
            .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?,
    );
    *at = end;
    Ok(value)
}
fn child_wire_digest(bytes: &[u8], at: &mut usize) -> Result<Digest, ChildDescriptorDecodeError> {
    let end = at
        .checked_add(32)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?;
    let value: [u8; 32] = bytes
        .get(*at..end)
        .ok_or(ChildDescriptorDecodeError::InvalidEncoding)?
        .try_into()
        .map_err(|_| ChildDescriptorDecodeError::InvalidEncoding)?;
    *at = end;
    Ok(Digest::new(value))
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
    /// A command payload or variable-length vector exceeds the codec bound.
    PayloadTooLarge,
    /// A variable-length command vector exceeds the codec bound.
    CountTooLarge,
    /// A command or outcome discriminant is unknown.
    InvalidTag,
    /// A stable identity or generation decoded as zero.
    InvalidIdentity,
    /// Bytes remain after the complete command.
    TrailingBytes,
}

impl CommandKind {
    fn validate_wire_limits(&self) -> Result<(), CommandDecodeError> {
        let count = |count: usize, item_bytes: usize| {
            if count > MAX_COMMAND_VECTOR_ITEMS {
                return Err(CommandDecodeError::CountTooLarge);
            }
            let encoded_len = count
                .checked_mul(item_bytes)
                .ok_or(CommandDecodeError::CountTooLarge)?;
            if encoded_len > MAX_COMMAND_PAYLOAD_BYTES {
                return Err(CommandDecodeError::PayloadTooLarge);
            }
            Ok(())
        };
        match self {
            Self::RegisterProviderGeneration {
                verifier_bindings, ..
            } => count(verifier_bindings.len(), 4 + 8 + 4 + 32)?,
            Self::AdmitScopedCompositeEffect { bindings, .. } => {
                // This is the smallest wire representation; the decoder also
                // checks the remaining bytes before reserving capacity.
                count(bindings.len(), 4 + 24 + 1 + 8 + 32 + 32)?
            }
            Self::RecordCompositeCommitIntents { operations, .. } => {
                count(operations.len(), 4 + 32)?
            }
            Self::WholeStateCheckpointV1 { state, .. }
                if state.len() > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES =>
            {
                return Err(CommandDecodeError::PayloadTooLarge);
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn try_encode_payload(&self) -> Result<Vec<u8>, CommandDecodeError> {
        let encoded_len = self.try_encoded_payload_len()?;
        let mut bytes = Vec::with_capacity(encoded_len);
        self.encode_payload_into(&mut bytes)?;
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    /// Returns the exact canonical payload length without allocating or
    /// cloning command-owned vectors.  Journal construction uses this to
    /// reserve its final record buffer before writing the header and payload.
    pub(crate) fn try_encoded_payload_len(&self) -> Result<usize, CommandDecodeError> {
        self.validate_wire_limits()?;
        const COMPONENT_PROVIDER_BINDING_NONE_LEN: usize = 4 + 24 + 1;
        const COMPONENT_PROVIDER_BINDING_ARTIFACT_LEN: usize = 4 + 24 + 1 + 8 + 32 + 32;
        const CHILD_DESCRIPTOR_FIXED_LEN: usize =
            2 + 8 + 16 + 4 + 32 + 4 + 4 + 8 + 4 + 1 + 8 + 8 + 8 + 32 + 32;
        const EFFECT_FACT_FIXED_LEN: usize =
            1 + 16 + 4 + 16 + 8 + 8 + 32 + 1 + 32 + 120 + 48 + 32 + 1;
        let add = |base: usize, extra: usize| {
            base.checked_add(extra)
                .ok_or(CommandDecodeError::PayloadTooLarge)
        };
        let vector = |base: usize, count: usize, item: usize| {
            count
                .checked_mul(item)
                .and_then(|extra| base.checked_add(extra))
                .ok_or(CommandDecodeError::PayloadTooLarge)
        };
        let descriptor_len = |value: &ChildDescriptorV1| {
            CHILD_DESCRIPTOR_FIXED_LEN
                .checked_add(match value.scope {
                    ClaimScope::Logical => 0,
                    ClaimScope::Device(_) => 8,
                })
                .ok_or(CommandDecodeError::PayloadTooLarge)
        };
        let effect_fact = |fact: &VerifiedEffectFact| {
            EFFECT_FACT_FIXED_LEN
                .checked_add(usize::from(fact.predecessor.is_some()) * 32)
                .ok_or(CommandDecodeError::PayloadTooLarge)
        };
        let len = match self {
            Self::RegisterProviderGeneration {
                verifier_bindings, ..
            } => vector(61, verifier_bindings.len(), 48)?,
            Self::BindArtifactReceiptVerifiers { .. } => 121,
            Self::FenceProviderEffects { .. }
            | Self::EnterProviderSettlementOnly { .. }
            | Self::RetireProviderEffects { .. } => 33,
            Self::AdmitScopedCompositeEffect { bindings, .. } => {
                let mut len = 49usize;
                for binding in bindings {
                    len = add(
                        len,
                        if binding.artifact().is_some() {
                            COMPONENT_PROVIDER_BINDING_ARTIFACT_LEN
                        } else {
                            COMPONENT_PROVIDER_BINDING_NONE_LEN
                        },
                    )?;
                }
                len
            }
            Self::AbortUnescapedEffect { .. } => 17,
            Self::RecordArtifactPin { .. } => 221,
            Self::AuthorizeArtifactRelease { .. } => 21,
            Self::RecordArtifactRelease { .. } => 269,
            Self::AcknowledgeCommit { fact }
            | Self::RecordApplied { fact }
            | Self::Settle { fact } => add(1, effect_fact(fact)?)?,
            Self::FenceExecutor { .. } => 25,
            Self::Snapshot { .. } => 49,
            Self::Ready { .. } | Self::Rebind { .. } => 33,
            Self::BeginRevoke { .. } => 41,
            Self::CheckpointRecovery { .. } => 25,
            Self::AdoptEffect { .. } => 33,
            Self::ActivateResourceReuse { .. } => 213,
            Self::ReclaimResourceReuse { .. } => 69,
            Self::AddComponentClaim { scope, .. } => add(
                73,
                match scope {
                    ClaimScope::Logical => 1,
                    ClaimScope::Device(_) => 9,
                },
            )?,
            Self::PrepareCompositeEffect { .. } => 33,
            Self::RecordComponentCommitIntent { .. } => 69,
            Self::ClaimComponentSettlement { .. } => 37,
            Self::RecordComponentApplyIntent { .. } | Self::MarkComponentIndeterminate { .. } => 85,
            Self::SubmitComponentEvidence { .. } => 297,
            Self::ReleaseCompositeEffect { .. } => 17,
            Self::ReserveComponentReuse { scope, .. } => add(
                105,
                match scope {
                    ClaimScope::Logical => 1,
                    ClaimScope::Device(_) => 9,
                },
            )?,
            Self::RecordCompositeCommitIntents { operations, .. } => {
                vector(37, operations.len(), 36)?
            }
            Self::RebaseCompositePrecommitClaims { .. } => 33,
            Self::WholeStateCheckpointV1 { state, .. } => {
                if state.len() > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
                    return Err(CommandDecodeError::PayloadTooLarge);
                }
                add(37, state.len())?
            }
            Self::AcknowledgeHandoffParent {
                fact, descriptor, ..
            } => add(add(1, effect_fact(fact)?)?, descriptor_len(descriptor)?)?
                .checked_add(32)
                .ok_or(CommandDecodeError::PayloadTooLarge)?,
            Self::InstallHandoffChild {
                descriptor: value,
                provider,
                ..
            } => add(
                add(25, descriptor_len(value)?)?,
                if provider.artifact().is_some() {
                    COMPONENT_PROVIDER_BINDING_ARTIFACT_LEN
                } else {
                    COMPONENT_PROVIDER_BINDING_NONE_LEN
                },
            )?,
            Self::ReleaseHandoffSourceAndRecordTargetIntent { descriptor, .. } => {
                add(add(49, descriptor_len(descriptor)?)?, 0)?
            }
            Self::ResolveIndeterminateHandoffParent { descriptor, .. } => {
                add(350, descriptor_len(descriptor)?)?
            }
        };
        if len > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(CommandDecodeError::PayloadTooLarge);
        }
        Ok(len)
    }

    #[allow(dead_code)]
    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        self.try_encode_payload()
            .expect("command payload satisfies the shared wire ceiling")
    }

    #[allow(clippy::needless_borrow)]
    pub(crate) fn encode_payload_into(
        &self,
        mut bytes: &mut Vec<u8>,
    ) -> Result<(), CommandDecodeError> {
        match self {
            Self::RegisterProviderGeneration {
                coordinate,
                catalog_digest,
                verifier_bindings,
            } => {
                put_u8(&mut bytes, 42);
                put_provider_coordinate(&mut bytes, coordinate);
                put_digest(&mut bytes, catalog_digest);
                put_u32(&mut bytes, verifier_bindings.len() as u32);
                for binding in verifier_bindings {
                    put_u32(&mut bytes, binding.verifier().get());
                    put_u64(&mut bytes, binding.generation().get());
                    put_u32(&mut bytes, binding.receipt_schema().get());
                    put_digest(&mut bytes, binding.implementation_digest());
                }
            }
            Self::BindArtifactReceiptVerifiers {
                coordinate,
                receipts,
            } => {
                put_u8(&mut bytes, 48);
                put_provider_coordinate(&mut bytes, coordinate);
                for binding in [receipts.pin(), receipts.release()] {
                    put_u32(&mut bytes, binding.verifier().get());
                    put_u64(&mut bytes, binding.generation().get());
                    put_u32(&mut bytes, binding.receipt_schema().get());
                    put_digest(&mut bytes, binding.implementation_digest());
                }
            }
            Self::FenceProviderEffects {
                coordinate,
                expected_epoch,
            } => {
                put_u8(&mut bytes, 43);
                put_provider_coordinate(&mut bytes, coordinate);
                put_u64(&mut bytes, expected_epoch);
            }
            Self::EnterProviderSettlementOnly {
                coordinate,
                expected_epoch,
            } => {
                put_u8(&mut bytes, 44);
                put_provider_coordinate(&mut bytes, coordinate);
                put_u64(&mut bytes, expected_epoch);
            }
            Self::RetireProviderEffects {
                coordinate,
                expected_epoch,
            } => {
                put_u8(&mut bytes, 45);
                put_provider_coordinate(&mut bytes, coordinate);
                put_u64(&mut bytes, expected_epoch);
            }
            Self::AdmitScopedCompositeEffect {
                effect,
                origin,
                kind,
                charge_account,
                bindings,
            } => {
                put_u8(&mut bytes, 46);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, origin);
                put_u32(&mut bytes, kind.get());
                put_u64(&mut bytes, charge_account.get());
                put_u32(&mut bytes, bindings.len() as u32);
                for binding in bindings {
                    put_u32(&mut bytes, binding.component().get());
                    put_provider_coordinate(&mut bytes, binding.provider());
                    match binding.artifact() {
                        Some(artifact) => {
                            put_u8(&mut bytes, 1);
                            put_u64(&mut bytes, artifact.artifact().get());
                            put_digest(&mut bytes, artifact.schema_digest());
                            put_digest(&mut bytes, artifact.closure_digest());
                        }
                        None => put_u8(&mut bytes, 0),
                    }
                }
            }
            Self::AbortUnescapedEffect { effect } => {
                put_u8(&mut bytes, 47);
                put_effect(&mut bytes, effect);
            }
            Self::RecordArtifactPin { binding, pin_stamp } => {
                put_u8(&mut bytes, 49);
                put_artifact_binding(&mut bytes, binding);
                put_digest(&mut bytes, pin_stamp);
            }
            Self::AuthorizeArtifactRelease { effect, component } => {
                put_u8(&mut bytes, 50);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
            }
            Self::RecordArtifactRelease {
                binding,
                pin_stamp,
                release_operation,
                nonce,
                release_stamp,
            } => {
                put_u8(&mut bytes, 51);
                put_artifact_binding(&mut bytes, binding);
                put_digest(&mut bytes, pin_stamp);
                put_u64(&mut bytes, release_operation.get());
                put_u64(&mut bytes, nonce);
                put_digest(&mut bytes, release_stamp);
            }
            Self::AcknowledgeCommit { fact } => {
                put_u8(&mut bytes, 5);
                put_effect_fact(&mut bytes, fact);
            }
            Self::FenceExecutor { operation, crashed } => {
                put_u8(&mut bytes, 6);
                put_u64(&mut bytes, operation.get());
                put_incarnation(&mut bytes, crashed);
            }
            Self::Snapshot {
                operation,
                snapshot,
                digest,
            } => {
                put_u8(&mut bytes, 7);
                put_u64(&mut bytes, operation.get());
                put_u64(&mut bytes, snapshot.get());
                put_digest(&mut bytes, digest);
            }
            Self::Ready {
                operation,
                snapshot,
                successor,
            } => {
                put_u8(&mut bytes, 8);
                put_u64(&mut bytes, operation.get());
                put_u64(&mut bytes, snapshot.get());
                put_incarnation(&mut bytes, successor);
            }
            Self::Rebind {
                operation,
                snapshot,
                successor,
            } => {
                put_u8(&mut bytes, 9);
                put_u64(&mut bytes, operation.get());
                put_u64(&mut bytes, snapshot.get());
                put_incarnation(&mut bytes, successor);
            }
            Self::RecordApplied { fact } => {
                put_u8(&mut bytes, 12);
                put_effect_fact(&mut bytes, fact);
            }
            Self::Settle { fact } => {
                put_u8(&mut bytes, 13);
                put_effect_fact(&mut bytes, fact);
            }
            Self::BeginRevoke {
                effect,
                expected_actor,
                authority_epoch,
            } => {
                put_u8(&mut bytes, 15);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, expected_actor);
                put_u64(&mut bytes, authority_epoch);
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
            Self::AdoptEffect { effect, successor } => {
                put_u8(&mut bytes, 21);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, successor);
            }
            Self::ActivateResourceReuse {
                effect,
                component,
                actor,
                authority_epoch,
                claim,
                resource,
                previous_generation,
                resource_generation,
                catalog_digest,
                retirement_digest,
                reuse_contract,
                nonce,
                freshness,
            } => {
                put_u8(&mut bytes, 23);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, authority_epoch);
                put_u64(&mut bytes, claim.get());
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, previous_generation.get());
                put_u64(&mut bytes, resource_generation.get());
                put_digest(&mut bytes, catalog_digest);
                put_digest(&mut bytes, retirement_digest);
                put_digest(&mut bytes, reuse_contract);
                put_u64(&mut bytes, nonce);
                put_freshness(&mut bytes, freshness);
            }
            Self::ReclaimResourceReuse {
                effect,
                component,
                actor,
                authority_epoch,
                claim,
                resource,
                resource_generation,
            } => {
                put_u8(&mut bytes, 24);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, authority_epoch);
                put_u64(&mut bytes, claim.get());
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, resource_generation.get());
            }
            Self::AddComponentClaim {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                resource_generation,
                units,
            } => {
                put_u8(&mut bytes, 26);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, kind.get());
                put_claim_scope(&mut bytes, scope);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, resource_generation.get());
                put_u64(&mut bytes, units);
            }
            Self::PrepareCompositeEffect { effect, actor } => {
                put_u8(&mut bytes, 27);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
            }
            Self::RecordComponentCommitIntent {
                effect,
                component,
                actor,
                operation,
            } => {
                put_u8(&mut bytes, 28);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, actor);
                put_digest(&mut bytes, operation);
            }
            Self::ClaimComponentSettlement {
                effect,
                component,
                claimant,
            } => {
                put_u8(&mut bytes, 29);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, claimant);
            }
            Self::RecordComponentApplyIntent {
                effect,
                component,
                claimant,
                generation,
                nonce,
                intent,
            } => {
                put_u8(&mut bytes, 30);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, claimant);
                put_u64(&mut bytes, generation);
                put_u64(&mut bytes, nonce);
                put_digest(&mut bytes, intent);
            }
            Self::MarkComponentIndeterminate {
                effect,
                component,
                claimant,
                generation,
                nonce,
                reason,
            } => {
                put_u8(&mut bytes, 31);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, claimant);
                put_u64(&mut bytes, generation);
                put_u64(&mut bytes, nonce);
                put_digest(&mut bytes, reason);
            }
            Self::SubmitComponentEvidence {
                effect,
                component,
                claim,
                evidence,
            } => {
                put_u8(&mut bytes, 32);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, evidence.kind.get());
                put_freshness(&mut bytes, evidence.subject);
                put_freshness(&mut bytes, evidence.freshness);
                put_provider_verification_scope(&mut bytes, evidence.verification_scope);
                put_verifier_identity(&mut bytes, evidence.stamp.identity);
                put_digest(&mut bytes, evidence.stamp.receipt_digest);
            }
            Self::ReleaseCompositeEffect { effect } => {
                put_u8(&mut bytes, 33);
                put_effect(&mut bytes, effect);
            }
            Self::ReserveComponentReuse {
                effect,
                component,
                actor,
                claim,
                kind,
                scope,
                resource,
                expected_generation,
                units,
                reuse_contract,
            } => {
                put_u8(&mut bytes, 34);
                put_effect(&mut bytes, effect);
                put_u32(&mut bytes, component.get());
                put_incarnation(&mut bytes, actor);
                put_u64(&mut bytes, claim.get());
                put_u32(&mut bytes, kind.get());
                put_claim_scope(&mut bytes, scope);
                put_u64(&mut bytes, resource.get());
                put_u64(&mut bytes, expected_generation.get());
                put_u64(&mut bytes, units);
                put_digest(&mut bytes, reuse_contract);
            }
            Self::RecordCompositeCommitIntents {
                effect,
                actor,
                operations,
            } => {
                put_u8(&mut bytes, 35);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
                put_u32(&mut bytes, operations.len() as u32);
                for operation in operations {
                    put_u32(&mut bytes, operation.component().get());
                    put_digest(&mut bytes, operation.operation());
                }
            }
            Self::RebaseCompositePrecommitClaims { effect, actor } => {
                put_u8(&mut bytes, 36);
                put_effect(&mut bytes, effect);
                put_incarnation(&mut bytes, actor);
            }
            Self::WholeStateCheckpointV1 { state, projection } => {
                put_u8(&mut bytes, 37);
                put_digest(&mut bytes, projection);
                put_u32(&mut bytes, state.len() as u32);
                bytes.extend_from_slice(&state);
            }
            Self::AcknowledgeHandoffParent {
                fact,
                descriptor,
                descriptor_receipt_digest,
            } => {
                put_u8(&mut bytes, 38);
                put_effect_fact(&mut bytes, fact);
                put_child_descriptor(&mut bytes, descriptor);
                put_digest(&mut bytes, descriptor_receipt_digest);
            }
            Self::InstallHandoffChild {
                descriptor,
                origin,
                charge_account,
                provider,
            } => {
                put_u8(&mut bytes, 39);
                put_child_descriptor(&mut bytes, descriptor);
                put_incarnation(&mut bytes, origin);
                put_u64(&mut bytes, charge_account.get());
                put_component_provider_binding(&mut bytes, provider);
            }
            Self::ReleaseHandoffSourceAndRecordTargetIntent {
                descriptor,
                actor,
                operation,
            } => {
                put_u8(&mut bytes, 40);
                put_child_descriptor(&mut bytes, descriptor);
                put_incarnation(&mut bytes, actor);
                put_digest(&mut bytes, operation);
            }
            Self::ResolveIndeterminateHandoffParent {
                descriptor,
                descriptor_receipt_digest,
                fact,
            } => {
                put_u8(&mut bytes, 41);
                put_child_descriptor(&mut bytes, descriptor);
                put_digest(&mut bytes, descriptor_receipt_digest);
                put_handoff_recovery_fact(&mut bytes, fact);
            }
        }
        Ok(())
    }

    pub(crate) fn decode_payload(bytes: &[u8]) -> Result<Self, CommandDecodeError> {
        if bytes.len() > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(CommandDecodeError::PayloadTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        let command = match cursor.u8()? {
            42 => {
                let coordinate = cursor.provider_coordinate()?;
                let catalog_digest = cursor.digest()?;
                let count = checked_vector_count(&mut cursor, 4 + 8 + 4 + 32)?;
                let mut verifier_bindings = Vec::with_capacity(count);
                for _ in 0..count {
                    let verifier = VerifierId::new(cursor.u32()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                    let generation = VerifierGeneration::new(cursor.u64()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                    let receipt_schema = ReceiptSchemaId::new(cursor.u32()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                    let implementation_digest = cursor.digest()?;
                    let binding = VerifierBinding::new(
                        verifier,
                        generation,
                        receipt_schema,
                        implementation_digest,
                    )
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                    verifier_bindings.push(binding);
                }
                Self::RegisterProviderGeneration {
                    coordinate,
                    catalog_digest,
                    verifier_bindings,
                }
            }
            43 => Self::FenceProviderEffects {
                coordinate: cursor.provider_coordinate()?,
                expected_epoch: cursor.nonzero_u64()?,
            },
            44 => Self::EnterProviderSettlementOnly {
                coordinate: cursor.provider_coordinate()?,
                expected_epoch: cursor.nonzero_u64()?,
            },
            45 => Self::RetireProviderEffects {
                coordinate: cursor.provider_coordinate()?,
                expected_epoch: cursor.nonzero_u64()?,
            },
            46 => {
                let effect = cursor.effect()?;
                let origin = cursor.executor()?;
                let kind = CompositeKindId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                let charge_account = ChargeAccountId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                let count = checked_vector_count(&mut cursor, 4 + 24 + 1)?;
                // Every binding has at least a component id, a provider
                // coordinate, and the artifact tag.  Bound the count before
                // reserving attacker-controlled capacity; the semantic
                // catalog/cardinality check still runs when the command is
                // applied.
                const MIN_COMPONENT_PROVIDER_BINDING_BYTES: usize = 4 + 24 + 1;
                let encoded_len = count
                    .checked_mul(MIN_COMPONENT_PROVIDER_BINDING_BYTES)
                    .ok_or(CommandDecodeError::UnexpectedEof)?;
                if cursor.remaining() < encoded_len {
                    return Err(CommandDecodeError::UnexpectedEof);
                }
                let mut bindings = Vec::with_capacity(count);
                for _ in 0..count {
                    let component = ComponentId::new(cursor.u32()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?;
                    let mut binding =
                        ComponentProviderBinding::new(component, cursor.provider_coordinate()?);
                    binding = match cursor.u8()? {
                        0 => binding,
                        1 => binding.with_artifact(ArtifactAdmission::new(
                            crate::RecoveryArtifactId::new(cursor.u64()?)
                                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                            cursor.digest()?,
                            cursor.digest()?,
                        )),
                        _ => return Err(CommandDecodeError::InvalidTag),
                    };
                    bindings.push(binding);
                }
                Self::AdmitScopedCompositeEffect {
                    effect,
                    origin,
                    kind,
                    charge_account,
                    bindings,
                }
            }
            47 => Self::AbortUnescapedEffect {
                effect: cursor.effect()?,
            },
            48 => {
                let coordinate = cursor.provider_coordinate()?;
                let pin = cursor.verifier_binding()?;
                let release = cursor.verifier_binding()?;
                Self::BindArtifactReceiptVerifiers {
                    coordinate,
                    receipts: ArtifactReceiptBindings::new(pin, release),
                }
            }
            49 => Self::RecordArtifactPin {
                binding: cursor.artifact_binding()?,
                pin_stamp: cursor.digest()?,
            },
            50 => Self::AuthorizeArtifactRelease {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            51 => Self::RecordArtifactRelease {
                binding: cursor.artifact_binding()?,
                pin_stamp: cursor.digest()?,
                release_operation: OperationId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                nonce: cursor.nonzero_u64()?,
                release_stamp: cursor.digest()?,
            },
            1..=4 => return Err(CommandDecodeError::InvalidTag),
            5 => Self::AcknowledgeCommit {
                fact: cursor.effect_fact()?,
            },
            6 => Self::FenceExecutor {
                operation: OperationId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                crashed: cursor.executor()?,
            },
            7 => Self::Snapshot {
                operation: OperationId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                digest: cursor.digest()?,
            },
            8 => Self::Ready {
                operation: OperationId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                successor: cursor.executor()?,
            },
            9 => Self::Rebind {
                operation: OperationId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                snapshot: SnapshotId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                successor: cursor.executor()?,
            },
            10..=11 => return Err(CommandDecodeError::InvalidTag),
            12 => Self::RecordApplied {
                fact: cursor.effect_fact()?,
            },
            13 => Self::Settle {
                fact: cursor.effect_fact()?,
            },
            14 => return Err(CommandDecodeError::InvalidTag),
            15 => Self::BeginRevoke {
                effect: cursor.effect()?,
                expected_actor: cursor.executor()?,
                authority_epoch: cursor.nonzero_u64()?,
            },
            16 => return Err(CommandDecodeError::InvalidTag),
            17 => Self::CheckpointRecovery {
                boot: BootGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                journal: JournalGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                device: DeviceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            21 => Self::AdoptEffect {
                effect: cursor.effect()?,
                successor: cursor.executor()?,
            },
            22 => return Err(CommandDecodeError::InvalidTag),
            23 => Self::ActivateResourceReuse {
                effect: cursor.effect()?,
                component: cursor.component()?,
                actor: cursor.executor()?,
                authority_epoch: cursor.nonzero_u64()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                previous_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                catalog_digest: cursor.digest()?,
                retirement_digest: cursor.digest()?,
                reuse_contract: cursor.digest()?,
                nonce: cursor.nonzero_u64()?,
                freshness: cursor.freshness()?,
            },
            24 => Self::ReclaimResourceReuse {
                effect: cursor.effect()?,
                component: cursor.component()?,
                actor: cursor.executor()?,
                authority_epoch: cursor.nonzero_u64()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                resource_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            },
            // The unbound composite constructor is an internal helper for
            // scoped admission/handoff only and is never a journal grammar.
            25 => return Err(CommandDecodeError::InvalidTag),
            26 => Self::AddComponentClaim {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                actor: cursor.executor()?,
                claim: ClaimId::new(cursor.u64()?)
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
            27 => Self::PrepareCompositeEffect {
                effect: cursor.effect()?,
                actor: cursor.executor()?,
            },
            28 => Self::RecordComponentCommitIntent {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                actor: cursor.executor()?,
                operation: cursor.digest()?,
            },
            29 => Self::ClaimComponentSettlement {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                claimant: cursor.executor()?,
            },
            30 => Self::RecordComponentApplyIntent {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                claimant: cursor.executor()?,
                generation: cursor.nonzero_u64()?,
                nonce: cursor.nonzero_u64()?,
                intent: cursor.digest()?,
            },
            31 => Self::MarkComponentIndeterminate {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                claimant: cursor.executor()?,
                generation: cursor.nonzero_u64()?,
                nonce: cursor.nonzero_u64()?,
                reason: cursor.digest()?,
            },
            32 => Self::SubmitComponentEvidence {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                evidence: RetirementEvidence {
                    kind: EvidenceKindId::new(cursor.u32()?)
                        .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                    subject: cursor.freshness()?,
                    freshness: cursor.freshness()?,
                    verification_scope: cursor.provider_verification_scope()?,
                    stamp: VerifierStamp {
                        identity: VerifierIdentity {
                            verifier: VerifierId::new(cursor.u32()?)
                                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                            epoch: cursor.nonzero_u64()?,
                            receipt_schema: ReceiptSchemaId::new(cursor.u32()?)
                                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                            implementation_digest: cursor.digest()?,
                        },
                        receipt_digest: cursor.digest()?,
                    },
                },
            },
            33 => Self::ReleaseCompositeEffect {
                effect: cursor.effect()?,
            },
            34 => Self::ReserveComponentReuse {
                effect: cursor.effect()?,
                component: ComponentId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                actor: cursor.executor()?,
                claim: ClaimId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                kind: ClaimKindId::new(cursor.u32()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                scope: cursor.claim_scope()?,
                resource: ResourceId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                expected_generation: ResourceGeneration::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                units: cursor.nonzero_u64()?,
                reuse_contract: cursor.digest()?,
            },
            35 => {
                let effect = cursor.effect()?;
                let actor = cursor.executor()?;
                let count = checked_vector_count(&mut cursor, core::mem::size_of::<u32>() + 32)?;
                let mut operations = Vec::with_capacity(count);
                for _ in 0..count {
                    operations.push(ComponentCommitOperation::new(
                        ComponentId::new(cursor.u32()?)
                            .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                        cursor.digest()?,
                    ));
                }
                Self::RecordCompositeCommitIntents {
                    effect,
                    actor,
                    operations,
                }
            }
            36 => Self::RebaseCompositePrecommitClaims {
                effect: cursor.effect()?,
                actor: cursor.executor()?,
            },
            37 => {
                let projection = cursor.digest()?;
                let len = cursor.u32()? as usize;
                if len > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
                    return Err(CommandDecodeError::UnexpectedEof);
                }
                let state = Arc::from(cursor.take(len)?.to_vec().into_boxed_slice());
                Self::WholeStateCheckpointV1 { state, projection }
            }
            38 => Self::AcknowledgeHandoffParent {
                fact: cursor.effect_fact()?,
                descriptor: cursor.child_descriptor()?,
                descriptor_receipt_digest: cursor.digest()?,
            },
            39 => Self::InstallHandoffChild {
                descriptor: cursor.child_descriptor()?,
                origin: cursor.executor()?,
                charge_account: ChargeAccountId::new(cursor.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                provider: cursor.component_provider_binding()?,
            },
            40 => Self::ReleaseHandoffSourceAndRecordTargetIntent {
                descriptor: cursor.child_descriptor()?,
                actor: cursor.executor()?,
                operation: cursor.digest()?,
            },
            41 => Self::ResolveIndeterminateHandoffParent {
                descriptor: cursor.child_descriptor()?,
                descriptor_receipt_digest: cursor.digest()?,
                fact: cursor.handoff_recovery_fact()?,
            },
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        cursor.finish()?;
        Ok(command)
    }
}

fn checked_vector_count(
    cursor: &mut Cursor<'_>,
    minimum_item_bytes: usize,
) -> Result<usize, CommandDecodeError> {
    let count = usize::try_from(cursor.u32()?).map_err(|_| CommandDecodeError::CountTooLarge)?;
    if count > MAX_COMMAND_VECTOR_ITEMS {
        return Err(CommandDecodeError::CountTooLarge);
    }
    let encoded_len = count
        .checked_mul(minimum_item_bytes)
        .ok_or(CommandDecodeError::CountTooLarge)?;
    if encoded_len > MAX_COMMAND_PAYLOAD_BYTES {
        return Err(CommandDecodeError::PayloadTooLarge);
    }
    if cursor.remaining() < encoded_len {
        return Err(CommandDecodeError::UnexpectedEof);
    }
    Ok(count)
}

fn put_u8<V: core::borrow::Borrow<u8>>(bytes: &mut Vec<u8>, value: V) {
    bytes.push(*value.borrow());
}

fn put_verifier_identity<V: core::borrow::Borrow<VerifierIdentity>>(
    bytes: &mut Vec<u8>,
    identity: V,
) {
    let identity = identity.borrow();
    put_u32(bytes, identity.verifier().get());
    put_u64(bytes, identity.epoch());
    put_u32(bytes, identity.receipt_schema().get());
    put_digest(bytes, identity.implementation_digest());
}

fn put_handoff_recovery_fact<V: core::borrow::Borrow<VerifiedHandoffRecoveryFact>>(
    bytes: &mut Vec<u8>,
    fact: V,
) {
    let fact = fact.borrow();
    put_u8(
        bytes,
        match fact.role {
            HandoffRecoveryRole::Parent => 1,
            HandoffRecoveryRole::Child => 2,
        },
    );
    put_effect(bytes, fact.effect);
    put_u32(bytes, fact.component.get());
    put_digest(bytes, fact.operation);
    put_digest(bytes, fact.descriptor_digest);
    put_freshness(bytes, fact.freshness);
    put_provider_verification_scope(bytes, fact.verification_scope);
    put_verifier_identity(bytes, fact.stamp.identity);
    put_digest(bytes, fact.stamp.receipt_digest);
}

// The compact checkpoint codec deliberately lives beside the journal command
// grammar.  This small header is already useful as a canonical framing and,
// importantly, leaves no fallback to an embedded journal image.  The primary
// collection codecs are added below this framing as each State variant gains a
// bounded decoder.
const WHOLE_STATE_CHECKPOINT_MAGIC: &[u8; 8] = b"CSERWS3\0";
const PREVIOUS_WHOLE_STATE_CHECKPOINT_MAGIC: &[u8; 8] = b"CSERWS2\0";

fn encode_whole_state_checkpoint(state: &impl StateAccess) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WHOLE_STATE_CHECKPOINT_MAGIC);
    put_u16(&mut bytes, 3);
    put_u64(&mut bytes, state.revision());
    put_digest(&mut bytes, state.head());
    put_u64(&mut bytes, state.next_nonce());
    put_freshness(&mut bytes, state.freshness());
    put_u8(&mut bytes, 1);
    put_u64(&mut bytes, state.world().get());
    put_u32(&mut bytes, state.provider_high_water().len() as u32);
    for (provider, generation) in state.provider_high_water() {
        put_u64(&mut bytes, provider.get());
        put_u64(&mut bytes, generation.get());
    }
    put_u32(&mut bytes, state.provider_generations().len() as u32);
    for (coordinate, record) in state.provider_generations() {
        put_provider_coordinate(&mut bytes, *coordinate);
        put_digest(&mut bytes, record.catalog_digest);
        put_digest(&mut bytes, record.verifier_set_digest);
        put_u32(&mut bytes, record.verifier_bindings.len() as u32);
        for binding in &record.verifier_bindings {
            put_verifier_binding(&mut bytes, *binding);
        }
        match record.artifact_receipts {
            Some(receipts) => {
                put_u8(&mut bytes, 1);
                put_verifier_binding(&mut bytes, receipts.pin());
                put_verifier_binding(&mut bytes, receipts.release());
            }
            None => put_u8(&mut bytes, 0),
        }
        put_u8(&mut bytes, provider_state_tag(record.state));
        put_u64(&mut bytes, provider_epoch(record.state));
        put_u64(&mut bytes, record.live_component_bindings as u64);
    }
    put_u32(&mut bytes, state.scoped_composites().len() as u32);
    for (effect, scoped) in state.scoped_composites() {
        put_effect(&mut bytes, *effect);
        put_digest(&mut bytes, scoped.catalog_digest);
        put_u32(&mut bytes, scoped.bindings.len() as u32);
        for (component, provider) in &scoped.bindings {
            put_u32(&mut bytes, component.get());
            put_provider_coordinate(&mut bytes, *provider);
        }
        put_u32(&mut bytes, scoped.artifacts.len() as u32);
        for (component, binding) in &scoped.artifacts {
            put_u32(&mut bytes, component.get());
            put_artifact_binding(&mut bytes, *binding);
        }
    }
    put_u32(&mut bytes, state.artifact_leases().len() as u32);
    for (artifact, lease) in state.artifact_leases() {
        put_u64(&mut bytes, artifact.get());
        match lease {
            ArtifactLeaseState::Pinned { binding, pin_stamp } => {
                put_u8(&mut bytes, 1);
                put_artifact_binding(&mut bytes, *binding);
                put_digest(&mut bytes, *pin_stamp);
            }
            ArtifactLeaseState::ReleaseAuthorized {
                binding,
                pin_stamp,
                release_operation,
                nonce,
            } => {
                put_u8(&mut bytes, 2);
                put_artifact_binding(&mut bytes, *binding);
                put_digest(&mut bytes, *pin_stamp);
                put_u64(&mut bytes, release_operation.get());
                put_u64(&mut bytes, *nonce);
            }
            ArtifactLeaseState::Released {
                binding,
                pin_stamp,
                release_stamp,
            } => {
                put_u8(&mut bytes, 3);
                put_artifact_binding(&mut bytes, *binding);
                put_digest(&mut bytes, *pin_stamp);
                put_digest(&mut bytes, *release_stamp);
            }
        }
    }
    // Collections are emitted in BTree order.  Derived reverse indexes and
    // charges deliberately do not appear in this image.
    put_u32(&mut bytes, state.recovery_operations().len() as u32);
    for (id, operation) in state.recovery_operations() {
        checkpoint_put_operation(&mut bytes, *id, operation);
    }
    put_u32(&mut bytes, state.composite_effects().len() as u32);
    for (effect, composite) in state.composite_effects() {
        checkpoint_put_composite(&mut bytes, *effect, composite);
    }
    put_u32(&mut bytes, state.resources().len() as u32);
    for (resource, record) in state.resources() {
        checkpoint_put_resource(&mut bytes, *resource, *record);
    }
    put_u32(&mut bytes, state.device_generations().len() as u32);
    for (scope, generation) in state.device_generations() {
        put_u64(&mut bytes, scope.get());
        put_u64(&mut bytes, generation.get());
    }
    put_u32(&mut bytes, state.device_quarantine().len() as u32);
    for scope in state.device_quarantine() {
        put_u64(&mut bytes, scope.get());
    }
    bytes
}

fn decode_whole_state_checkpoint(
    bytes: &[u8],
    catalogs: &CatalogSet,
    limits: CoreLimits,
) -> Result<State, CoreError> {
    let mut cursor = Cursor::new(bytes);
    let magic = cursor.take(8).map_err(|_| CoreError::InvariantViolation)?;
    if magic == PREVIOUS_WHOLE_STATE_CHECKPOINT_MAGIC {
        return Err(CoreError::UnsupportedCheckpointState);
    }
    if magic != WHOLE_STATE_CHECKPOINT_MAGIC {
        return Err(CoreError::InvariantViolation);
    }
    if cursor.u16().map_err(|_| CoreError::InvariantViolation)? != 3 {
        return Err(CoreError::InvariantViolation);
    }
    let revision = cursor.u64().map_err(|_| CoreError::InvariantViolation)?;
    let head = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
    let next_nonce = cursor
        .nonzero_u64()
        .map_err(|_| CoreError::InvariantViolation)?;
    let freshness = cursor
        .freshness()
        .map_err(|_| CoreError::InvariantViolation)?;
    if cursor.u8().map_err(|_| CoreError::InvariantViolation)? != 1 {
        return Err(CoreError::InvariantViolation);
    }
    let world = WorldId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let high_water_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if high_water_count > limits.max_provider_high_water {
        return Err(CoreError::InvariantViolation);
    }
    let mut provider_high_water = BTreeMap::new();
    let mut previous_provider = None;
    for _ in 0..high_water_count {
        let provider = ProviderId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_provider, provider)?;
        let generation =
            ProviderGeneration::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                .map_err(|_| CoreError::InvariantViolation)?;
        if provider_high_water.insert(provider, generation).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    let provider_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if provider_count > limits.max_provider_generations {
        return Err(CoreError::InvariantViolation);
    }
    let mut provider_generations = BTreeMap::new();
    let mut previous_provider_generation = None;
    for _ in 0..provider_count {
        let coordinate = cursor
            .provider_coordinate()
            .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_provider_generation, coordinate)?;
        let catalog_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
        let provider_catalog = catalogs
            .get(catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let verifier_set_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
        let verifier_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
        let required_verifiers = provider_catalog.verifier_class_bindings();
        if verifier_count != required_verifiers.len()
            || verifier_count
                .checked_mul(4 + 8 + 4 + 32)
                .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
        {
            return Err(CoreError::InvariantViolation);
        }
        let mut verifier_bindings = Vec::with_capacity(verifier_count);
        for _ in 0..verifier_count {
            verifier_bindings.push(
                cursor
                    .verifier_binding()
                    .map_err(|_| CoreError::InvariantViolation)?,
            );
        }
        let artifact_receipts = match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
            0 => None,
            1 => Some(ArtifactReceiptBindings::new(
                cursor
                    .verifier_binding()
                    .map_err(|_| CoreError::InvariantViolation)?,
                cursor
                    .verifier_binding()
                    .map_err(|_| CoreError::InvariantViolation)?,
            )),
            _ => return Err(CoreError::InvariantViolation),
        };
        let state_tag = cursor.u8().map_err(|_| CoreError::InvariantViolation)?;
        let epoch = cursor
            .nonzero_u64()
            .map_err(|_| CoreError::InvariantViolation)?;
        let live_component_bindings =
            usize::try_from(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                .map_err(|_| CoreError::InvariantViolation)?;
        let provider_state = match state_tag {
            1 if epoch == 1 => ProviderEffectState::Active,
            2 if epoch >= 2 => ProviderEffectState::EffectFenced { epoch },
            3 if epoch >= 3 => ProviderEffectState::SettlementOnly { epoch },
            4 if epoch >= 4 => ProviderEffectState::Retired { epoch },
            _ => return Err(CoreError::InvariantViolation),
        };
        if provider_generations
            .insert(
                coordinate,
                ProviderGenerationRecord {
                    coordinate,
                    catalog_digest,
                    verifier_set_digest,
                    verifier_bindings,
                    artifact_receipts,
                    state: provider_state,
                    live_component_bindings,
                },
            )
            .is_some()
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    let scoped_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if scoped_count > limits.max_effects {
        return Err(CoreError::InvariantViolation);
    }
    let mut scoped_composites = BTreeMap::new();
    let mut previous_scoped_effect = None;
    for _ in 0..scoped_count {
        let effect = cursor.effect().map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_scoped_effect, effect)?;
        let catalog_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
        if !catalogs.contains(catalog_digest) {
            return Err(CoreError::SchemaMismatch);
        }
        let binding_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
        const CHECKPOINT_COMPONENT_BINDING_BYTES: usize = 4 + 24;
        if binding_count > limits.max_components_per_effect
            || binding_count
                .checked_mul(CHECKPOINT_COMPONENT_BINDING_BYTES)
                .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
        {
            return Err(CoreError::InvariantViolation);
        }
        let mut bindings = BTreeMap::new();
        let mut previous_binding_component = None;
        for _ in 0..binding_count {
            let component =
                ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
                    .map_err(|_| CoreError::InvariantViolation)?;
            checkpoint_require_strictly_increasing(&mut previous_binding_component, component)?;
            let provider = cursor
                .provider_coordinate()
                .map_err(|_| CoreError::InvariantViolation)?;
            if bindings.insert(component, provider).is_some() {
                return Err(CoreError::InvariantViolation);
            }
        }
        let artifact_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
        if artifact_count > binding_count {
            return Err(CoreError::InvariantViolation);
        }
        const CHECKPOINT_ARTIFACT_BINDING_BYTES: usize = 8 + 24 + 8 + 16 + 4 + (4 * 32);
        if artifact_count
            .checked_mul(4 + CHECKPOINT_ARTIFACT_BINDING_BYTES)
            .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
        {
            return Err(CoreError::InvariantViolation);
        }
        let mut artifacts = BTreeMap::new();
        let mut previous_artifact_component = None;
        for _ in 0..artifact_count {
            let component =
                ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
                    .map_err(|_| CoreError::InvariantViolation)?;
            checkpoint_require_strictly_increasing(&mut previous_artifact_component, component)?;
            let binding = cursor
                .artifact_binding()
                .map_err(|_| CoreError::InvariantViolation)?;
            if artifacts.insert(component, binding).is_some() {
                return Err(CoreError::InvariantViolation);
            }
        }
        if scoped_composites
            .insert(
                effect,
                ScopedCompositeRecord {
                    catalog_digest,
                    bindings,
                    artifacts,
                },
            )
            .is_some()
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    let artifact_lease_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if artifact_lease_count > limits.max_artifact_leases {
        return Err(CoreError::InvariantViolation);
    }
    let mut artifact_leases = BTreeMap::new();
    let mut previous_artifact_lease = None;
    for _ in 0..artifact_lease_count {
        let artifact = crate::RecoveryArtifactId::new(
            cursor.u64().map_err(|_| CoreError::InvariantViolation)?,
        )
        .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_artifact_lease, artifact)?;
        let tag = cursor.u8().map_err(|_| CoreError::InvariantViolation)?;
        let binding = cursor
            .artifact_binding()
            .map_err(|_| CoreError::InvariantViolation)?;
        let pin_stamp = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
        let lease = match tag {
            1 => ArtifactLeaseState::Pinned { binding, pin_stamp },
            2 => ArtifactLeaseState::ReleaseAuthorized {
                binding,
                pin_stamp,
                release_operation: OperationId::new(
                    cursor.u64().map_err(|_| CoreError::InvariantViolation)?,
                )
                .map_err(|_| CoreError::InvariantViolation)?,
                nonce: cursor
                    .nonzero_u64()
                    .map_err(|_| CoreError::InvariantViolation)?,
            },
            3 => ArtifactLeaseState::Released {
                binding,
                pin_stamp,
                release_stamp: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
            },
            _ => return Err(CoreError::InvariantViolation),
        };
        if artifact != binding.artifact_id() || artifact_leases.insert(artifact, lease).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    let operation_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if operation_count > limits.max_operations {
        return Err(CoreError::InvariantViolation);
    }
    let operations = checkpoint_read_operations_count(&mut cursor, operation_count)?;
    let composite_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if composite_count > limits.max_effects {
        return Err(CoreError::InvariantViolation);
    }
    let composites =
        checkpoint_read_composites_count(&mut cursor, catalogs, composite_count, limits)?;
    checkpoint_validate_scoped_cardinality(&scoped_composites, &composites, catalogs)?;
    let resource_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if resource_count > limits.max_resource_records {
        return Err(CoreError::InvariantViolation);
    }
    let mut resources = BTreeMap::new();
    let mut previous_resource = None;
    for _ in 0..resource_count {
        let (resource, record) = checkpoint_read_resource(&mut cursor)?;
        checkpoint_require_strictly_increasing(&mut previous_resource, resource)?;
        if resources.insert(resource, record).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    let device_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if device_count > limits.max_device_generations {
        return Err(CoreError::InvariantViolation);
    }
    let mut device_generations = BTreeMap::new();
    let mut previous_device_scope = None;
    for _ in 0..device_count {
        let scope = DeviceScopeId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_device_scope, scope)?;
        let generation =
            DeviceGeneration::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                .map_err(|_| CoreError::InvariantViolation)?;
        if device_generations.insert(scope, generation).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    let quarantine_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if quarantine_count > device_count {
        return Err(CoreError::InvariantViolation);
    }
    let mut device_quarantine = BTreeSet::new();
    let mut previous_quarantine_scope = None;
    for _ in 0..quarantine_count {
        let scope = DeviceScopeId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_quarantine_scope, scope)?;
        if !device_generations.contains_key(&scope) {
            return Err(CoreError::InvariantViolation);
        }
        if !device_quarantine.insert(scope) {
            return Err(CoreError::InvariantViolation);
        }
    }
    if cursor.finish().is_err() {
        return Err(CoreError::InvariantViolation);
    }
    let mut state = State {
        world,
        provider_generations: provider_generations.into_iter().collect(),
        provider_high_water: provider_high_water.into_iter().collect(),
        scoped_composites: scoped_composites.into_iter().collect(),
        artifact_leases: artifact_leases.into_iter().collect(),
        recovery_operations: operations.into_iter().collect(),
        composite_effects: composites.into_iter().collect(),
        composite_resource_index: StateMap::new(),
        resources: resources.into_iter().collect(),
        charges: StateMap::new(),
        device_generations: device_generations.into_iter().collect(),
        device_quarantine: device_quarantine.into_iter().collect(),
        revision,
        head,
        next_nonce,
        total_claims: 0,
        freshness,
        recovery_target: None,
        projection_cache: ProjectionCache {
            leaves: AuthenticatedMap::new(),
            digest: Digest::ZERO,
        },
    };
    checkpoint_rebuild_derived(&mut state)?;
    state.set_total_claims(count_state_claims(&state)?);
    let projection = build_projection_cache(&state, catalogs.digest());
    state.projection_cache = projection;
    check_invariants_for_catalog_set(catalogs, limits, &state)?;
    Ok(state)
}

fn checkpoint_require_strictly_increasing<K: Copy + Ord>(
    previous: &mut Option<K>,
    current: K,
) -> Result<(), CoreError> {
    if previous.is_some_and(|previous| current <= previous) {
        return Err(CoreError::InvariantViolation);
    }
    *previous = Some(current);
    Ok(())
}

fn checkpoint_validate_scoped_cardinality(
    scoped_composites: &BTreeMap<EffectId, ScopedCompositeRecord>,
    composites: &BTreeMap<EffectId, CompositeEffectRecord>,
    catalogs: &CatalogSet,
) -> Result<(), CoreError> {
    for (effect, scoped) in scoped_composites {
        let composite = composites
            .get(effect)
            .ok_or(CoreError::InvariantViolation)?;
        let catalog = catalogs
            .get(composite.catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let schema = catalog
            .composite_rule(composite.kind)
            .ok_or(CoreError::InvariantViolation)?;
        let required_artifacts = schema
            .components()
            .iter()
            .filter(|component| {
                component.artifact_policy() == crate::RecoveryArtifactPolicy::Required
            })
            .count();
        if scoped.catalog_digest != composite.catalog_digest
            || scoped.bindings.len() != schema.components().len()
            || scoped
                .bindings
                .keys()
                .any(|component| schema.component(*component).is_none())
            || scoped.artifacts.len() > required_artifacts
            || scoped
                .artifacts
                .keys()
                .any(|component| !scoped.bindings.contains_key(component))
            || scoped.artifacts.keys().any(|component| {
                schema.component(*component).is_none_or(|declared| {
                    declared.artifact_policy() != crate::RecoveryArtifactPolicy::Required
                })
            })
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(())
}

fn checkpoint_put_composite(bytes: &mut Vec<u8>, effect: EffectId, record: &CompositeEffectRecord) {
    put_effect(bytes, effect);
    put_u32(bytes, record.kind.get());
    put_digest(bytes, record.catalog_digest);
    put_incarnation(bytes, record.causal_owner);
    checkpoint_put_custody(bytes, record.custodian);
    put_u64(bytes, record.charge_owner.get());
    put_u8(bytes, authority_tag(record.authority));
    put_u64(bytes, record.authority_epoch);
    checkpoint_put_handoff(bytes, record.handoff.clone());
    checkpoint_put_released_provenance(bytes, record.released_provenance.as_ref());
    put_u32(bytes, record.components.len() as u32);
    for component in record.components.values() {
        checkpoint_put_component(bytes, component);
    }
}

fn checkpoint_put_released_provenance(
    bytes: &mut Vec<u8>,
    provenance: Option<&ReleasedCompositeProvenance>,
) {
    let Some(provenance) = provenance else {
        put_u8(bytes, 0);
        return;
    };
    put_u8(bytes, 1);
    put_digest(bytes, provenance.catalog_digest);
    put_u32(bytes, provenance.bindings.len() as u32);
    for (component, provider) in &provenance.bindings {
        put_u32(bytes, component.get());
        put_provider_coordinate(bytes, *provider);
    }
    put_u32(bytes, provenance.artifacts.len() as u32);
    for (component, binding) in &provenance.artifacts {
        put_u32(bytes, component.get());
        put_artifact_binding(bytes, *binding);
    }
}

fn checkpoint_read_released_provenance(
    cursor: &mut Cursor<'_>,
    catalogs: &CatalogSet,
    schema: &crate::CompositeRule,
) -> Result<Option<ReleasedCompositeProvenance>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => {
            let catalog_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
            if !catalogs.contains(catalog_digest) {
                return Err(CoreError::SchemaMismatch);
            }
            let binding_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
            if binding_count != schema.components().len() {
                return Err(CoreError::InvariantViolation);
            }
            if binding_count
                .checked_mul(4 + 24)
                .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
            {
                return Err(CoreError::InvariantViolation);
            }
            let mut bindings = BTreeMap::new();
            let mut previous_binding_component = None;
            for _ in 0..binding_count {
                let component =
                    ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
                        .map_err(|_| CoreError::InvariantViolation)?;
                checkpoint_require_strictly_increasing(&mut previous_binding_component, component)?;
                let provider = cursor
                    .provider_coordinate()
                    .map_err(|_| CoreError::InvariantViolation)?;
                if bindings.insert(component, provider).is_some() {
                    return Err(CoreError::InvariantViolation);
                }
            }
            let artifact_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
            let required_artifacts = schema
                .components()
                .iter()
                .filter(|component| {
                    component.artifact_policy() == crate::RecoveryArtifactPolicy::Required
                })
                .count();
            if artifact_count > required_artifacts {
                return Err(CoreError::InvariantViolation);
            }
            const CHECKPOINT_ARTIFACT_BINDING_BYTES: usize = 8 + 24 + 8 + 16 + 4 + (4 * 32);
            if artifact_count
                .checked_mul(4 + CHECKPOINT_ARTIFACT_BINDING_BYTES)
                .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
            {
                return Err(CoreError::InvariantViolation);
            }
            let mut artifacts = BTreeMap::new();
            let mut previous_artifact_component = None;
            for _ in 0..artifact_count {
                let component =
                    ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
                        .map_err(|_| CoreError::InvariantViolation)?;
                checkpoint_require_strictly_increasing(
                    &mut previous_artifact_component,
                    component,
                )?;
                let binding = cursor
                    .artifact_binding()
                    .map_err(|_| CoreError::InvariantViolation)?;
                if artifacts.insert(component, binding).is_some() {
                    return Err(CoreError::InvariantViolation);
                }
            }
            Ok(Some(ReleasedCompositeProvenance {
                catalog_digest,
                bindings,
                artifacts,
            }))
        }
        _ => Err(CoreError::InvariantViolation),
    }
}

fn checkpoint_put_handoff(bytes: &mut Vec<u8>, handoff: SingleHopRole) {
    match handoff {
        SingleHopRole::None => put_u8(bytes, 0),
        SingleHopRole::Source {
            descriptor,
            terminal_receipt_digest,
            descriptor_receipt_digest,
            recovery_fact,
        } => {
            put_u8(bytes, 1);
            put_child_descriptor(bytes, *descriptor);
            put_digest(bytes, terminal_receipt_digest);
            put_digest(bytes, descriptor_receipt_digest);
            put_u8(bytes, u8::from(recovery_fact.is_some()));
            if let Some(fact) = recovery_fact {
                put_handoff_recovery_fact(bytes, fact);
            }
        }
        SingleHopRole::Target {
            parent,
            descriptor_digest,
            recovery_fact,
        } => {
            put_u8(bytes, 2);
            put_effect(bytes, parent);
            put_digest(bytes, descriptor_digest);
            put_u8(bytes, u8::from(recovery_fact.is_some()));
            if let Some(fact) = recovery_fact {
                put_handoff_recovery_fact(bytes, fact);
            }
        }
    }
}

fn checkpoint_read_handoff(cursor: &mut Cursor<'_>) -> Result<SingleHopRole, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(SingleHopRole::None),
        1 => Ok(SingleHopRole::Source {
            descriptor: Box::new(
                cursor
                    .child_descriptor()
                    .map_err(|_| CoreError::InvariantViolation)?,
            ),
            terminal_receipt_digest: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
            descriptor_receipt_digest: cursor
                .digest()
                .map_err(|_| CoreError::InvariantViolation)?,
            recovery_fact: checkpoint_read_option_handoff_fact(cursor)?,
        }),
        2 => Ok(SingleHopRole::Target {
            parent: cursor.effect().map_err(|_| CoreError::InvariantViolation)?,
            descriptor_digest: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
            recovery_fact: checkpoint_read_option_handoff_fact(cursor)?,
        }),
        _ => Err(CoreError::InvariantViolation),
    }
}

fn checkpoint_read_composites_count(
    cursor: &mut Cursor<'_>,
    catalogs: &CatalogSet,
    count: usize,
    limits: CoreLimits,
) -> Result<BTreeMap<EffectId, CompositeEffectRecord>, CoreError> {
    let mut total_claims = 0usize;
    let mut composites = BTreeMap::new();
    let mut previous_effect = None;
    for _ in 0..count {
        let effect = cursor.effect().map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_effect, effect)?;
        let kind = CompositeKindId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
        let catalog_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
        let catalog = catalogs
            .get(catalog_digest)
            .ok_or(CoreError::SchemaMismatch)?;
        let causal_owner = cursor
            .executor()
            .map_err(|_| CoreError::InvariantViolation)?;
        let custodian = checkpoint_read_custody(cursor)?;
        let charge_owner =
            ChargeAccountId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                .map_err(|_| CoreError::InvariantViolation)?;
        let authority = checkpoint_read_authority(cursor)?;
        let authority_epoch = cursor
            .nonzero_u64()
            .map_err(|_| CoreError::InvariantViolation)?;
        let handoff = checkpoint_read_handoff(cursor)?;
        let schema = catalog
            .composite_rule(kind)
            .ok_or(CoreError::SchemaMismatch)?;
        let released_provenance = checkpoint_read_released_provenance(cursor, catalogs, schema)?;
        let component_count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
        if component_count > limits.max_components_per_effect
            || component_count != schema.components().len()
        {
            return Err(CoreError::InvariantViolation);
        }
        if component_count
            .checked_mul(4)
            .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
        {
            return Err(CoreError::InvariantViolation);
        }
        let mut components = BTreeMap::new();
        let mut previous_component = None;
        for _ in 0..component_count {
            let component = checkpoint_read_component(cursor, catalog, schema, limits)?;
            checkpoint_require_strictly_increasing(&mut previous_component, component.id)?;
            total_claims = total_claims
                .checked_add(component.claims.len())
                .ok_or(CoreError::InvariantViolation)?;
            if total_claims > limits.max_total_claims {
                return Err(CoreError::InvariantViolation);
            }
            if components.insert(component.id, component).is_some() {
                return Err(CoreError::InvariantViolation);
            }
        }
        let record = CompositeEffectRecord {
            effect,
            kind,
            catalog_digest,
            causal_owner,
            custodian,
            charge_owner,
            authority,
            authority_epoch,
            handoff,
            released_provenance,
            components,
        };
        if composites.insert(effect, record).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(composites)
}

fn checkpoint_put_component(bytes: &mut Vec<u8>, component: &ComponentRecord) {
    put_u32(bytes, component.id.get());
    checkpoint_put_component_dynamic(bytes, component);
}

fn checkpoint_read_component(
    cursor: &mut Cursor<'_>,
    catalog: &DomainCatalog,
    schema: &crate::CompositeRule,
    limits: CoreLimits,
) -> Result<ComponentRecord, CoreError> {
    let id = ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let static_spec = schema.component(id).ok_or(CoreError::InvariantViolation)?;
    let obligation_rule = catalog
        .obligation_rule(static_spec.domain(), static_spec.obligation())
        .ok_or(CoreError::SchemaMismatch)?;
    checkpoint_read_component_dynamic(
        cursor,
        id,
        static_spec.domain(),
        static_spec.obligation(),
        obligation_rule.policy(),
        catalog,
        limits,
    )
}

fn checkpoint_put_component_dynamic(bytes: &mut Vec<u8>, component: &ComponentRecord) {
    put_u8(bytes, commit_tag(component.commit));
    checkpoint_put_option_u64(bytes, component.commit_nonce);
    checkpoint_put_option_digest(bytes, component.commit_operation);
    checkpoint_put_option_fact(bytes, component.commit_fact);
    checkpoint_put_outcome(bytes, component.outcome);
    checkpoint_put_settlement(bytes, component.settlement);
    checkpoint_put_option_u64(bytes, component.settlement_nonce);
    checkpoint_put_option_stage(bytes, component.claim_stage);
    checkpoint_put_option_digest(bytes, component.settlement_intent);
    checkpoint_put_option_fact(bytes, component.applied_fact);
    checkpoint_put_option_fact(bytes, component.settlement_fact);
    put_u8(bytes, retirement_tag(component.retirement));
    put_u32(bytes, component.claims.len() as u32);
    for claim in component.claims.values() {
        checkpoint_put_claim(bytes, claim);
    }
}

fn checkpoint_read_component_dynamic(
    cursor: &mut Cursor<'_>,
    id: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
    obligation_policy: ObligationPolicy,
    catalog: &DomainCatalog,
    limits: CoreLimits,
) -> Result<ComponentRecord, CoreError> {
    let commit = checkpoint_read_commit(cursor)?;
    let commit_nonce = checkpoint_read_option_u64(cursor)?;
    let commit_operation = checkpoint_read_option_digest(cursor)?;
    let commit_fact = checkpoint_read_option_fact(cursor)?;
    let outcome = checkpoint_read_outcome(cursor)?;
    let settlement = checkpoint_read_settlement(cursor)?;
    let settlement_nonce = checkpoint_read_option_u64(cursor)?;
    let claim_stage = checkpoint_read_option_stage(cursor)?;
    let settlement_intent = checkpoint_read_option_digest(cursor)?;
    let applied_fact = checkpoint_read_option_fact(cursor)?;
    let settlement_fact = checkpoint_read_option_fact(cursor)?;
    let retirement = checkpoint_read_retirement(cursor)?;
    let count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    if count > limits.max_claims_per_effect {
        return Err(CoreError::InvariantViolation);
    }
    if count
        .checked_mul(8)
        .is_none_or(|encoded_len| cursor.remaining() < encoded_len)
    {
        return Err(CoreError::InvariantViolation);
    }
    let mut claims = BTreeMap::new();
    let mut previous_claim = None;
    for _ in 0..count {
        let claim = checkpoint_read_claim(cursor, domain, catalog)?;
        checkpoint_require_strictly_increasing(&mut previous_claim, claim.id)?;
        if claims.insert(claim.id, claim).is_some() {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(ComponentRecord {
        id,
        domain,
        obligation,
        obligation_policy,
        commit,
        commit_nonce,
        commit_operation,
        commit_fact,
        outcome,
        settlement,
        settlement_nonce,
        claim_stage,
        settlement_intent,
        applied_fact,
        settlement_fact,
        retirement,
        claims,
    })
}

fn checkpoint_put_claim(bytes: &mut Vec<u8>, claim: &ClaimRecord) {
    put_u64(bytes, claim.id.get());
    put_u32(bytes, claim.kind.get());
    put_claim_scope(bytes, claim.scope);
    put_u64(bytes, claim.resource.get());
    put_u64(bytes, claim.resource_generation.get());
    put_u64(bytes, claim.units);
    put_freshness(bytes, claim.enrolled_freshness);
    put_u8(bytes, u8::from(claim.retired));
    put_u32(bytes, claim.requirements.len() as u32);
    for requirement in &claim.requirements {
        checkpoint_put_option_accepted(bytes, requirement.accepted);
    }
}

fn checkpoint_read_claim(
    cursor: &mut Cursor<'_>,
    domain: DomainId,
    catalog: &DomainCatalog,
) -> Result<ClaimRecord, CoreError> {
    let id = ClaimId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let kind = ClaimKindId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let scope = cursor
        .claim_scope()
        .map_err(|_| CoreError::InvariantViolation)?;
    let resource = ResourceId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let resource_generation =
        ResourceGeneration::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
    let units = cursor.u64().map_err(|_| CoreError::InvariantViolation)?;
    if units == 0 {
        return Err(CoreError::InvariantViolation);
    }
    let enrolled_freshness = cursor
        .freshness()
        .map_err(|_| CoreError::InvariantViolation)?;
    let retired = match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => false,
        1 => true,
        _ => return Err(CoreError::InvariantViolation),
    };
    let count = cursor.u32().map_err(|_| CoreError::InvariantViolation)? as usize;
    let rule = catalog
        .claim_rule(domain, kind)
        .ok_or(CoreError::SchemaMismatch)?;
    if count != rule.evidence().len()
        || !matches!(
            (rule.scope(), scope),
            (ClaimScopePolicy::Logical, ClaimScope::Logical)
                | (ClaimScopePolicy::Device, ClaimScope::Device(_))
        )
    {
        return Err(CoreError::InvariantViolation);
    }
    let mut requirements = Vec::with_capacity(count);
    for evidence in rule.evidence() {
        requirements.push(RequirementState {
            kind: evidence.kind(),
            verifier: evidence.verifier(),
            receipt_schema: evidence.receipt_schema(),
            subject_freshness: evidence.subject_freshness(),
            observation_freshness: evidence.observation_freshness(),
            strictly_advanced: evidence.strictly_advanced(),
            device_generation: evidence.device_generation(),
            prerequisite: evidence.prerequisite(),
            accepted: checkpoint_read_option_accepted(cursor)?,
        });
    }
    Ok(ClaimRecord {
        id,
        domain,
        kind,
        credit_class: rule.credit_class(),
        scope,
        resource,
        resource_generation,
        units,
        enrolled_freshness,
        requirements,
        retired,
    })
}

fn checkpoint_put_resource(bytes: &mut Vec<u8>, resource: ResourceId, record: ResourceRecord) {
    put_u64(bytes, resource.get());
    put_claim_scope(bytes, record.scope);
    put_u64(bytes, record.generation.get());
    match record.phase {
        ResourcePhase::Retired => put_u8(bytes, 1),
        ResourcePhase::Claimed {
            pending_reuse: None,
        } => put_u8(bytes, 2),
        ResourcePhase::Claimed {
            pending_reuse: Some(p),
        } => {
            put_u8(bytes, 3);
            checkpoint_put_pending_reuse(bytes, p);
        }
    }
}
fn checkpoint_read_resource(
    cursor: &mut Cursor<'_>,
) -> Result<(ResourceId, ResourceRecord), CoreError> {
    let resource = ResourceId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let scope = cursor
        .claim_scope()
        .map_err(|_| CoreError::InvariantViolation)?;
    let generation =
        ResourceGeneration::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
    let phase = match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => ResourcePhase::Retired,
        2 => ResourcePhase::Claimed {
            pending_reuse: None,
        },
        3 => ResourcePhase::Claimed {
            pending_reuse: Some(checkpoint_read_pending_reuse(cursor)?),
        },
        _ => return Err(CoreError::InvariantViolation),
    };
    Ok((
        resource,
        ResourceRecord {
            scope,
            generation,
            phase,
        },
    ))
}
fn checkpoint_put_pending_reuse(bytes: &mut Vec<u8>, p: PendingReuse) {
    put_effect(bytes, p.effect);
    put_u32(bytes, p.component.get());
    put_incarnation(bytes, p.actor);
    put_u64(bytes, p.authority_epoch);
    put_u64(bytes, p.claim.get());
    put_u64(bytes, p.previous_generation.get());
    put_digest(bytes, p.catalog_digest);
    put_digest(bytes, p.retirement_digest);
    put_digest(bytes, p.reuse_contract);
    put_u64(bytes, p.nonce);
    put_freshness(bytes, p.freshness);
}
fn checkpoint_read_pending_reuse(cursor: &mut Cursor<'_>) -> Result<PendingReuse, CoreError> {
    Ok(PendingReuse {
        effect: cursor.effect().map_err(|_| CoreError::InvariantViolation)?,
        component: ComponentId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?,
        actor: cursor
            .executor()
            .map_err(|_| CoreError::InvariantViolation)?,
        authority_epoch: cursor
            .nonzero_u64()
            .map_err(|_| CoreError::InvariantViolation)?,
        claim: ClaimId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?,
        previous_generation: ResourceGeneration::new(
            cursor.u64().map_err(|_| CoreError::InvariantViolation)?,
        )
        .map_err(|_| CoreError::InvariantViolation)?,
        catalog_digest: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        retirement_digest: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        reuse_contract: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        nonce: cursor
            .nonzero_u64()
            .map_err(|_| CoreError::InvariantViolation)?,
        freshness: cursor
            .freshness()
            .map_err(|_| CoreError::InvariantViolation)?,
    })
}

fn checkpoint_rebuild_derived(state: &mut impl StateAccessMut) -> Result<(), CoreError> {
    let composites: Vec<_> = state
        .composite_effects()
        .iter()
        .map(|(effect, composite)| (*effect, composite.clone()))
        .collect();
    for (effect, composite) in &composites {
        for (component_id, component) in &composite.components {
            for claim in component.claims.values() {
                if !claim.retired
                    && !prepared_handoff_target_claim(state, composite, component, claim)
                {
                    state
                        .composite_resource_index_mut()
                        .get_or_insert_with_mut(claim.resource, Vec::new)
                        .push((*effect, *component_id, claim.id));
                    let charged = state
                        .charges()
                        .get(&(composite.charge_owner, claim.credit_class))
                        .copied()
                        .unwrap_or(0)
                        .checked_add(claim.units)
                        .ok_or(CoreError::InvariantViolation)?;
                    *state.charges_mut().get_or_insert_with_mut(
                        (composite.charge_owner, claim.credit_class),
                        || 0,
                    ) = charged;
                }
            }
        }
    }
    let composite_resource_keys: Vec<_> =
        state.composite_resource_index().keys().copied().collect();
    for resource in composite_resource_keys {
        state
            .composite_resource_index_mut()
            .get_mut(&resource)
            .expect("resource index key was collected")
            .sort_unstable();
    }
    Ok(())
}

fn count_state_claims(state: &impl StateAccess) -> Result<usize, CoreError> {
    state
        .composite_effects()
        .values()
        .flat_map(|composite| composite.components.values())
        .map(|component| component.claims.len())
        .try_fold(0usize, |count, claims| {
            count
                .checked_add(claims)
                .ok_or(CoreError::InvariantViolation)
        })
}

fn checkpoint_put_option_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    put_u8(bytes, u8::from(value.is_some()));
    if let Some(value) = value {
        put_u64(bytes, value);
    }
}
fn checkpoint_read_option_u64(cursor: &mut Cursor<'_>) -> Result<Option<u64>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => Ok(Some(
            cursor
                .nonzero_u64()
                .map_err(|_| CoreError::InvariantViolation)?,
        )),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_put_option_digest(bytes: &mut Vec<u8>, value: Option<Digest>) {
    put_u8(bytes, u8::from(value.is_some()));
    if let Some(value) = value {
        put_digest(bytes, value);
    }
}
fn checkpoint_read_option_digest(cursor: &mut Cursor<'_>) -> Result<Option<Digest>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => Ok(Some(
            cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        )),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_put_option_fact(bytes: &mut Vec<u8>, value: Option<VerifiedEffectFact>) {
    put_u8(bytes, u8::from(value.is_some()));
    if let Some(value) = value {
        put_effect_fact(bytes, value);
    }
}
fn checkpoint_read_option_fact(
    cursor: &mut Cursor<'_>,
) -> Result<Option<VerifiedEffectFact>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => cursor
            .effect_fact()
            .map(Some)
            .map_err(|_| CoreError::InvariantViolation),
        _ => Err(CoreError::InvariantViolation),
    }
}

fn checkpoint_read_option_handoff_fact(
    cursor: &mut Cursor<'_>,
) -> Result<Option<VerifiedHandoffRecoveryFact>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => cursor
            .handoff_recovery_fact()
            .map(Some)
            .map_err(|_| CoreError::InvariantViolation),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_put_option_accepted(bytes: &mut Vec<u8>, value: Option<AcceptedEvidence>) {
    put_u8(bytes, u8::from(value.is_some()));
    if let Some(value) = value {
        put_freshness(bytes, value.subject);
        put_freshness(bytes, value.observation);
        put_provider_verification_scope(bytes, value.verification_scope);
        put_verifier_identity(bytes, value.stamp.identity);
        put_digest(bytes, value.stamp.receipt_digest);
    }
}
fn checkpoint_read_option_accepted(
    cursor: &mut Cursor<'_>,
) -> Result<Option<AcceptedEvidence>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => return Ok(None),
        1 => {}
        _ => return Err(CoreError::InvariantViolation),
    }
    let subject = cursor
        .freshness()
        .map_err(|_| CoreError::InvariantViolation)?;
    let observation = cursor
        .freshness()
        .map_err(|_| CoreError::InvariantViolation)?;
    let verification_scope = cursor
        .provider_verification_scope()
        .map_err(|_| CoreError::InvariantViolation)?;
    let verifier = VerifierId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
        .map_err(|_| CoreError::InvariantViolation)?;
    let epoch = cursor
        .nonzero_u64()
        .map_err(|_| CoreError::InvariantViolation)?;
    let receipt_schema =
        ReceiptSchemaId::new(cursor.u32().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
    let implementation_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
    let receipt_digest = cursor.digest().map_err(|_| CoreError::InvariantViolation)?;
    Ok(Some(AcceptedEvidence {
        subject,
        observation,
        stamp: VerifierStamp {
            identity: VerifierIdentity {
                verifier,
                epoch,
                receipt_schema,
                implementation_digest,
            },
            receipt_digest,
        },
        verification_scope,
    }))
}
fn checkpoint_put_outcome(bytes: &mut Vec<u8>, value: OutcomeState) {
    match value {
        OutcomeState::Pending => put_u8(bytes, 1),
        OutcomeState::KnownSuccess(d) => {
            put_u8(bytes, 2);
            put_digest(bytes, d)
        }
        OutcomeState::KnownFailure(d) => {
            put_u8(bytes, 3);
            put_digest(bytes, d)
        }
        OutcomeState::Indeterminate(d) => {
            put_u8(bytes, 4);
            put_digest(bytes, d)
        }
    }
}
fn checkpoint_read_outcome(cursor: &mut Cursor<'_>) -> Result<OutcomeState, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => Ok(OutcomeState::Pending),
        2 => Ok(OutcomeState::KnownSuccess(
            cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        )),
        3 => Ok(OutcomeState::KnownFailure(
            cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        )),
        4 => Ok(OutcomeState::Indeterminate(
            cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
        )),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_read_commit(cursor: &mut Cursor<'_>) -> Result<CommitState, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => Ok(CommitState::Registered),
        2 => Ok(CommitState::Prepared),
        3 => Ok(CommitState::CommitIntentDurable),
        4 => Ok(CommitState::Committed),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_read_retirement(cursor: &mut Cursor<'_>) -> Result<RetirementState, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => Ok(RetirementState::Held),
        2 => Ok(RetirementState::RetirementPending),
        3 => Ok(RetirementState::Retired),
        4 => Ok(RetirementState::Released),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_put_option_stage(bytes: &mut Vec<u8>, value: Option<ClaimStage>) {
    put_u8(bytes, value.map(claim_stage_tag).unwrap_or(0));
}
fn checkpoint_read_option_stage(cursor: &mut Cursor<'_>) -> Result<Option<ClaimStage>, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        0 => Ok(None),
        1 => Ok(Some(ClaimStage::Fresh)),
        2 => Ok(Some(ClaimStage::Intent)),
        3 => Ok(Some(ClaimStage::Applied)),
        4 => Ok(Some(ClaimStage::ReconcileIntent)),
        5 => Ok(Some(ClaimStage::ReconcileApplied)),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_put_settlement(bytes: &mut Vec<u8>, value: SettlementState) {
    match value {
        SettlementState::Unavailable => put_u8(bytes, 1),
        SettlementState::NotRequired => put_u8(bytes, 2),
        SettlementState::Open { generation } => {
            put_u8(bytes, 3);
            put_u64(bytes, generation)
        }
        SettlementState::Claimed {
            claimant,
            generation,
        } => {
            put_u8(bytes, 4);
            put_incarnation(bytes, claimant);
            put_u64(bytes, generation)
        }
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => {
            put_u8(bytes, 5);
            put_incarnation(bytes, claimant);
            put_u64(bytes, generation)
        }
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => {
            put_u8(bytes, 6);
            put_incarnation(bytes, claimant);
            put_u64(bytes, generation)
        }
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => {
            put_u8(bytes, 7);
            put_u64(bytes, generation);
            put_u8(bytes, u8::from(applied))
        }
        SettlementState::Settled => put_u8(bytes, 8),
        SettlementState::Revoked => put_u8(bytes, 9),
    }
}
fn checkpoint_read_settlement(cursor: &mut Cursor<'_>) -> Result<SettlementState, CoreError> {
    let tag = cursor.u8().map_err(|_| CoreError::InvariantViolation)?;
    let generation_value =
        |c: &mut Cursor<'_>| c.nonzero_u64().map_err(|_| CoreError::InvariantViolation);
    let actor = |c: &mut Cursor<'_>| c.executor().map_err(|_| CoreError::InvariantViolation);
    match tag {
        1 => Ok(SettlementState::Unavailable),
        2 => Ok(SettlementState::NotRequired),
        3 => Ok(SettlementState::Open {
            generation: generation_value(cursor)?,
        }),
        4 => Ok(SettlementState::Claimed {
            claimant: actor(cursor)?,
            generation: generation_value(cursor)?,
        }),
        5 => Ok(SettlementState::ApplyIntentDurable {
            claimant: actor(cursor)?,
            generation: generation_value(cursor)?,
        }),
        6 => Ok(SettlementState::AppliedUnacknowledged {
            claimant: actor(cursor)?,
            generation: generation_value(cursor)?,
        }),
        7 => {
            let generation = generation_value(cursor)?;
            let applied = match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
                0 => false,
                1 => true,
                _ => return Err(CoreError::InvariantViolation),
            };
            Ok(SettlementState::ReconciliationRequired {
                generation,
                applied,
            })
        }
        8 => Ok(SettlementState::Settled),
        9 => Ok(SettlementState::Revoked),
        _ => Err(CoreError::InvariantViolation),
    }
}

fn checkpoint_put_custody(bytes: &mut Vec<u8>, custody: CustodyState) {
    match custody {
        CustodyState::Executor(executor) => {
            put_u8(bytes, 1);
            put_incarnation(bytes, executor);
        }
        CustodyState::CoreOwned => put_u8(bytes, 2),
        CustodyState::Released => put_u8(bytes, 3),
    }
}
fn checkpoint_read_custody(cursor: &mut Cursor<'_>) -> Result<CustodyState, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => Ok(CustodyState::Executor(
            cursor
                .executor()
                .map_err(|_| CoreError::InvariantViolation)?,
        )),
        2 => Ok(CustodyState::CoreOwned),
        3 => Ok(CustodyState::Released),
        _ => Err(CoreError::InvariantViolation),
    }
}
fn checkpoint_read_authority(cursor: &mut Cursor<'_>) -> Result<AuthorityState, CoreError> {
    match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
        1 => Ok(AuthorityState::Active),
        2 => Ok(AuthorityState::Fenced),
        3 => Ok(AuthorityState::Revoked),
        _ => Err(CoreError::InvariantViolation),
    }
}

fn checkpoint_put_operation(
    bytes: &mut Vec<u8>,
    id: OperationId,
    operation: &CompositeRecoveryRecord,
) {
    put_u64(bytes, id.get());
    put_incarnation(bytes, operation.origin);
    put_incarnation(bytes, operation.last_executor);
    put_u64(bytes, operation.crash_generation);
    match operation.state {
        OperationRecoveryState::Active { executor } => {
            put_u8(bytes, 1);
            put_incarnation(bytes, executor);
        }
        OperationRecoveryState::Fenced {
            crashed,
            crash_generation,
        } => {
            put_u8(bytes, 2);
            put_incarnation(bytes, crashed);
            put_u64(bytes, crash_generation);
        }
        OperationRecoveryState::Snapshotted { snapshot, digest } => {
            put_u8(bytes, 3);
            put_u64(bytes, snapshot.get());
            put_digest(bytes, digest);
        }
        OperationRecoveryState::Ready {
            snapshot,
            successor,
        } => {
            put_u8(bytes, 4);
            put_u64(bytes, snapshot.get());
            put_incarnation(bytes, successor);
        }
        OperationRecoveryState::Rebound { successor } => {
            put_u8(bytes, 5);
            put_incarnation(bytes, successor);
        }
        OperationRecoveryState::RecoveryExhausted {
            crashed,
            crash_generation,
        } => {
            put_u8(bytes, 6);
            put_incarnation(bytes, crashed);
            put_u64(bytes, crash_generation);
        }
    }
}

fn checkpoint_read_operations_count(
    cursor: &mut Cursor<'_>,
    count: usize,
) -> Result<BTreeMap<OperationId, CompositeRecoveryRecord>, CoreError> {
    let mut operations = BTreeMap::new();
    let mut previous_id = None;
    for _ in 0..count {
        let id = OperationId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
            .map_err(|_| CoreError::InvariantViolation)?;
        checkpoint_require_strictly_increasing(&mut previous_id, id)?;
        let origin = cursor
            .executor()
            .map_err(|_| CoreError::InvariantViolation)?;
        let last_executor = cursor
            .executor()
            .map_err(|_| CoreError::InvariantViolation)?;
        let crash_generation = cursor.u64().map_err(|_| CoreError::InvariantViolation)?;
        let state = match cursor.u8().map_err(|_| CoreError::InvariantViolation)? {
            1 => OperationRecoveryState::Active {
                executor: cursor
                    .executor()
                    .map_err(|_| CoreError::InvariantViolation)?,
            },
            2 => OperationRecoveryState::Fenced {
                crashed: cursor
                    .executor()
                    .map_err(|_| CoreError::InvariantViolation)?,
                crash_generation: cursor.u64().map_err(|_| CoreError::InvariantViolation)?,
            },
            3 => OperationRecoveryState::Snapshotted {
                snapshot: SnapshotId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                    .map_err(|_| CoreError::InvariantViolation)?,
                digest: cursor.digest().map_err(|_| CoreError::InvariantViolation)?,
            },
            4 => OperationRecoveryState::Ready {
                snapshot: SnapshotId::new(cursor.u64().map_err(|_| CoreError::InvariantViolation)?)
                    .map_err(|_| CoreError::InvariantViolation)?,
                successor: cursor
                    .executor()
                    .map_err(|_| CoreError::InvariantViolation)?,
            },
            5 => OperationRecoveryState::Rebound {
                successor: cursor
                    .executor()
                    .map_err(|_| CoreError::InvariantViolation)?,
            },
            6 => OperationRecoveryState::RecoveryExhausted {
                crashed: cursor
                    .executor()
                    .map_err(|_| CoreError::InvariantViolation)?,
                crash_generation: cursor.u64().map_err(|_| CoreError::InvariantViolation)?,
            },
            _ => return Err(CoreError::InvariantViolation),
        };
        if operations
            .insert(
                id,
                CompositeRecoveryRecord {
                    origin,
                    state,
                    last_executor,
                    crash_generation,
                },
            )
            .is_some()
        {
            return Err(CoreError::InvariantViolation);
        }
    }
    Ok(operations)
}

fn put_u16<V: core::borrow::Borrow<u16>>(bytes: &mut Vec<u8>, value: V) {
    bytes.extend_from_slice(&value.borrow().to_le_bytes());
}

fn put_u32<V: core::borrow::Borrow<u32>>(bytes: &mut Vec<u8>, value: V) {
    bytes.extend_from_slice(&value.borrow().to_le_bytes());
}

fn put_u64<V: core::borrow::Borrow<u64>>(bytes: &mut Vec<u8>, value: V) {
    bytes.extend_from_slice(&value.borrow().to_le_bytes());
}

fn put_digest<V: core::borrow::Borrow<Digest>>(bytes: &mut Vec<u8>, digest: V) {
    bytes.extend_from_slice(&digest.borrow().bytes());
}

fn put_effect<V: core::borrow::Borrow<EffectId>>(bytes: &mut Vec<u8>, effect: V) {
    let effect = effect.borrow();
    put_u64(bytes, effect.operation().get());
    put_u64(bytes, effect.sequence());
}

fn put_provider_coordinate<V: core::borrow::Borrow<ProviderCoordinate>>(
    bytes: &mut Vec<u8>,
    coordinate: V,
) {
    let coordinate = coordinate.borrow();
    put_u64(bytes, coordinate.world().get());
    put_u64(bytes, coordinate.provider().get());
    put_u64(bytes, coordinate.generation().get());
}

fn put_component_provider_binding<V: core::borrow::Borrow<ComponentProviderBinding>>(
    bytes: &mut Vec<u8>,
    binding: V,
) {
    let binding = binding.borrow();
    put_u32(bytes, binding.component().get());
    put_provider_coordinate(bytes, binding.provider());
    match binding.artifact() {
        Some(artifact) => {
            put_u8(bytes, 1);
            put_u64(bytes, artifact.artifact().get());
            put_digest(bytes, artifact.schema_digest());
            put_digest(bytes, artifact.closure_digest());
        }
        None => put_u8(bytes, 0),
    }
}

fn put_verifier_binding<V: core::borrow::Borrow<VerifierBinding>>(bytes: &mut Vec<u8>, binding: V) {
    let binding = binding.borrow();
    put_u32(bytes, binding.verifier().get());
    put_u64(bytes, binding.generation().get());
    put_u32(bytes, binding.receipt_schema().get());
    put_digest(bytes, binding.implementation_digest());
}

fn put_artifact_binding<V: core::borrow::Borrow<ArtifactBinding>>(bytes: &mut Vec<u8>, binding: V) {
    let binding = binding.borrow();
    put_u64(bytes, binding.artifact_id().get());
    put_provider_coordinate(bytes, binding.provider());
    put_u64(bytes, binding.operation().get());
    put_effect(bytes, binding.effect());
    put_u32(bytes, binding.component().get());
    put_digest(bytes, binding.catalog_digest());
    put_digest(bytes, binding.schema_digest());
    put_digest(bytes, binding.verifier_set_digest());
    put_digest(bytes, binding.closure_digest());
}

fn put_child_descriptor<V: core::borrow::Borrow<ChildDescriptorV1>>(bytes: &mut Vec<u8>, value: V) {
    let value = value.borrow();
    put_u16(bytes, value.schema);
    put_u64(bytes, value.sequence);
    put_effect(bytes, value.parent);
    put_u32(bytes, value.parent_component.get());
    put_digest(bytes, value.route_digest);
    put_u32(bytes, value.child_kind.get());
    put_u32(bytes, value.child_component.get());
    put_u64(bytes, value.claim.get());
    put_u32(bytes, value.claim_kind.get());
    put_claim_scope(bytes, value.scope);
    put_u64(bytes, value.resource.get());
    put_u64(bytes, value.resource_generation.get());
    put_u64(bytes, value.units);
    put_digest(bytes, value.input_digest);
    put_digest(bytes, value.catalog_digest);
}

fn put_incarnation<V: core::borrow::Borrow<ExecutorCoordinate>>(bytes: &mut Vec<u8>, executor: V) {
    let executor = executor.borrow();
    put_u64(bytes, executor.executor().get());
    put_u64(bytes, executor.generation().get());
}

fn put_claim_scope<V: core::borrow::Borrow<ClaimScope>>(bytes: &mut Vec<u8>, scope: V) {
    match scope.borrow() {
        ClaimScope::Logical => put_u8(bytes, 1),
        ClaimScope::Device(device) => {
            put_u8(bytes, 2);
            put_u64(bytes, device.get());
        }
    }
}

fn put_freshness<V: core::borrow::Borrow<Freshness>>(bytes: &mut Vec<u8>, freshness: V) {
    let freshness = freshness.borrow();
    put_u64(bytes, freshness.boot().get());
    put_u64(bytes, freshness.registry().get());
    put_u64(bytes, freshness.device().get());
    put_u64(bytes, freshness.journal().get());
}

fn put_effect_fact<V: core::borrow::Borrow<VerifiedEffectFact>>(bytes: &mut Vec<u8>, fact: V) {
    let fact = fact.borrow();
    put_u8(bytes, fact.kind.tag());
    put_effect(bytes, fact.effect);
    put_u32(bytes, fact.component.get());
    put_incarnation(bytes, fact.actor);
    put_u64(bytes, fact.generation);
    put_u64(bytes, fact.nonce);
    put_digest(bytes, fact.operation);
    put_u8(bytes, u8::from(fact.predecessor.is_some()));
    if let Some(predecessor) = fact.predecessor {
        put_digest(bytes, predecessor);
    }
    put_freshness(bytes, fact.freshness);
    put_provider_verification_scope(bytes, fact.verification_scope);
    put_verifier_identity(bytes, fact.stamp.identity);
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

fn put_provider_verification_scope<V: core::borrow::Borrow<ProviderVerificationScope>>(
    bytes: &mut Vec<u8>,
    scope: V,
) {
    let scope = scope.borrow();
    put_u64(bytes, scope.world.get());
    put_provider_coordinate(bytes, scope.provider);
    put_u64(bytes, scope.operation.get());
    put_digest(bytes, scope.catalog_digest);
    put_verifier_binding(bytes, scope.verifier_binding);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn child_descriptor(&mut self) -> Result<ChildDescriptorV1, CommandDecodeError> {
        Ok(ChildDescriptorV1 {
            schema: self.u16()?,
            sequence: self.nonzero_u64()?,
            parent: self.effect()?,
            parent_component: ComponentId::new(self.u32()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            route_digest: self.digest()?,
            child_kind: CompositeKindId::new(self.u32()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            child_component: ComponentId::new(self.u32()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            claim: ClaimId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?,
            claim_kind: ClaimKindId::new(self.u32()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            scope: self.claim_scope()?,
            resource: ResourceId::new(self.u64()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            resource_generation: ResourceGeneration::new(self.u64()?)
                .map_err(|_| CommandDecodeError::InvalidIdentity)?,
            units: self.nonzero_u64()?,
            input_digest: self.digest()?,
            catalog_digest: self.digest()?,
        })
    }
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

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn u8(&mut self) -> Result<u8, CommandDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CommandDecodeError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CommandDecodeError::UnexpectedEof)?,
        ))
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
        let operation =
            OperationId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        EffectId::new(operation, self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn provider_coordinate(&mut self) -> Result<ProviderCoordinate, CommandDecodeError> {
        let world = WorldId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let provider =
            ProviderId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let generation = ProviderGeneration::new(self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)?;
        Ok(ProviderCoordinate::new(world, provider, generation))
    }

    fn component_provider_binding(
        &mut self,
    ) -> Result<ComponentProviderBinding, CommandDecodeError> {
        let component =
            ComponentId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let provider = self.provider_coordinate()?;
        let binding = ComponentProviderBinding::new(component, provider);
        match self.u8()? {
            0 => Ok(binding),
            1 => Ok(binding.with_artifact(ArtifactAdmission::new(
                crate::RecoveryArtifactId::new(self.u64()?)
                    .map_err(|_| CommandDecodeError::InvalidIdentity)?,
                self.digest()?,
                self.digest()?,
            ))),
            _ => Err(CommandDecodeError::InvalidTag),
        }
    }

    fn verifier_binding(&mut self) -> Result<VerifierBinding, CommandDecodeError> {
        let verifier =
            VerifierId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let generation = VerifierGeneration::new(self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let receipt_schema =
            ReceiptSchemaId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        VerifierBinding::new(verifier, generation, receipt_schema, self.digest()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn provider_verification_scope(
        &mut self,
    ) -> Result<ProviderVerificationScope, CommandDecodeError> {
        let world = WorldId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let provider = self.provider_coordinate()?;
        let operation =
            OperationId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let catalog_digest = self.digest()?;
        let verifier_binding = self.verifier_binding()?;
        Ok(ProviderVerificationScope::new(
            world,
            provider,
            operation,
            catalog_digest,
            verifier_binding,
        ))
    }

    fn artifact_binding(&mut self) -> Result<ArtifactBinding, CommandDecodeError> {
        let artifact = crate::RecoveryArtifactId::new(self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let provider = self.provider_coordinate()?;
        let operation =
            OperationId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let effect = self.effect()?;
        let component =
            ComponentId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        ArtifactBinding::new(
            artifact,
            provider,
            operation,
            effect,
            component,
            self.digest()?,
            self.digest()?,
            self.digest()?,
            self.digest()?,
        )
        .map_err(|_| CommandDecodeError::InvalidIdentity)
    }

    fn executor(&mut self) -> Result<ExecutorCoordinate, CommandDecodeError> {
        let executor =
            crate::ExecutorId::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let generation = crate::ExecutorGeneration::new(self.u64()?)
            .map_err(|_| CommandDecodeError::InvalidIdentity)?;
        Ok(ExecutorCoordinate::new(executor, generation))
    }

    fn component(&mut self) -> Result<ComponentId, CommandDecodeError> {
        ComponentId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)
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
        let device =
            DeviceGeneration::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let journal =
            JournalGeneration::new(self.u64()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        Ok(Freshness::new(boot, registry, device, journal))
    }

    fn handoff_recovery_fact(&mut self) -> Result<VerifiedHandoffRecoveryFact, CommandDecodeError> {
        let role = match self.u8()? {
            1 => HandoffRecoveryRole::Parent,
            2 => HandoffRecoveryRole::Child,
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        let effect = self.effect()?;
        let component = self.component()?;
        let operation = self.digest()?;
        let descriptor_digest = self.digest()?;
        let freshness = self.freshness()?;
        let verification_scope = self.provider_verification_scope()?;
        let verifier =
            VerifierId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let epoch = self.nonzero_u64()?;
        let receipt_schema =
            ReceiptSchemaId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let implementation_digest = self.digest()?;
        let receipt_digest = self.digest()?;
        Ok(VerifiedHandoffRecoveryFact {
            role,
            effect,
            component,
            operation,
            descriptor_digest,
            freshness,
            stamp: VerifierStamp {
                identity: VerifierIdentity {
                    verifier,
                    epoch,
                    receipt_schema,
                    implementation_digest,
                },
                receipt_digest,
            },
            verification_scope,
        })
    }

    fn effect_fact(&mut self) -> Result<VerifiedEffectFact, CommandDecodeError> {
        let kind = match self.u8()? {
            1 => EffectFactKind::CommitOutcome,
            2 => EffectFactKind::ApplyCompleted,
            3 => EffectFactKind::SettlementAcknowledged,
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        let effect = self.effect()?;
        let component = self.component()?;
        let actor = self.executor()?;
        let generation = self.nonzero_u64()?;
        let nonce = self.nonzero_u64()?;
        let operation = self.digest()?;
        let predecessor = match self.u8()? {
            0 => None,
            1 => Some(self.digest()?),
            _ => return Err(CommandDecodeError::InvalidTag),
        };
        let freshness = self.freshness()?;
        let verification_scope = self.provider_verification_scope()?;
        let verifier =
            VerifierId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let epoch = self.nonzero_u64()?;
        let receipt_schema =
            ReceiptSchemaId::new(self.u32()?).map_err(|_| CommandDecodeError::InvalidIdentity)?;
        let implementation_digest = self.digest()?;
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
            component,
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
                    implementation_digest,
                },
                receipt_digest,
            },
            verification_scope,
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

#[cfg(test)]
mod handoff_recovery_fact_tests {
    use super::*;

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn descriptor() -> ChildDescriptorV1 {
        ChildDescriptorV1 {
            schema: 1,
            sequence: 1,
            parent: EffectId::new(OperationId::new(9).unwrap(), 1).unwrap(),
            parent_component: ComponentId::new(1).unwrap(),
            route_digest: Digest::new([0x21; 32]),
            child_kind: CompositeKindId::new(2).unwrap(),
            child_component: ComponentId::new(2).unwrap(),
            claim: ClaimId::new(3).unwrap(),
            claim_kind: ClaimKindId::new(4).unwrap(),
            scope: ClaimScope::Logical,
            resource: ResourceId::new(5).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
            input_digest: Digest::new([0x22; 32]),
            catalog_digest: Digest::new([0x23; 32]),
        }
    }

    #[test]
    fn tag_41_and_checkpoint_roundtrip_preserve_the_complete_fact() {
        let descriptor = descriptor();
        let provider = ProviderCoordinate::new(
            WorldId::new(7).unwrap(),
            ProviderId::new(8).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let binding = VerifierBinding::new(
            VerifierId::new(9).unwrap(),
            VerifierGeneration::new(1).unwrap(),
            ReceiptSchemaId::new(10).unwrap(),
            Digest::new([0x24; 32]),
        )
        .unwrap();
        let scope = ProviderVerificationScope::new(
            WorldId::new(7).unwrap(),
            provider,
            descriptor.parent.operation(),
            descriptor.catalog_digest,
            binding,
        );
        let challenge = HandoffResolutionChallenge {
            effect: descriptor.parent,
            component: descriptor.parent_component,
            domain: DomainId::new(1).unwrap(),
            obligation: ObligationKindId::new(1).unwrap(),
            operation: Digest::new([0x25; 32]),
            descriptor,
            current_observation: freshness(),
            expected_verifier: binding.verifier(),
            expected_receipt_schema: binding.receipt_schema(),
            verification_scope: scope,
        };
        let fact = VerifiedHandoffRecoveryFact::from_challenge(
            HandoffRecoveryRole::Parent,
            challenge,
            VerifierStamp {
                identity: VerifierIdentity::new_exact(binding),
                receipt_digest: Digest::new([0x26; 32]),
            },
        );
        let command = CommandKind::ResolveIndeterminateHandoffParent {
            descriptor,
            descriptor_receipt_digest: Digest::new([0x27; 32]),
            fact,
        };
        assert_eq!(
            CommandKind::decode_payload(&command.try_encode_payload().unwrap()).unwrap(),
            command
        );

        let handoff = SingleHopRole::Source {
            descriptor: Box::new(descriptor),
            terminal_receipt_digest: fact.stamp.receipt_digest,
            descriptor_receipt_digest: Digest::new([0x27; 32]),
            recovery_fact: Some(fact),
        };
        let mut bytes = Vec::new();
        checkpoint_put_handoff(&mut bytes, handoff.clone());
        assert_eq!(
            checkpoint_read_handoff(&mut Cursor::new(&bytes)).unwrap(),
            handoff
        );
    }
}

#[cfg(test)]
mod whole_state_checkpoint_tests {
    use super::*;
    use crate::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, DEVICE_CLAIM_IOVA,
        DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, REPLY_CLAIM_PUBLICATION_SLOT,
        standard_catalog, tool_dma_catalog,
    };
    use alloc::vec;

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn seed(journal: &mut Vec<u8>) -> (Engine, EffectId, ExecutorCoordinate) {
        let catalog = standard_catalog();
        let catalog_set = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            catalog_set,
            CoreLimits::bounded_default(),
            freshness(),
        );
        let effect = EffectId::new(OperationId::new(91).unwrap(), 1).unwrap();
        let actor = ExecutorCoordinate::new(
            crate::ExecutorId::new(9).unwrap(),
            crate::ExecutorGeneration::new(1).unwrap(),
        );
        let provider = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let catalog_digest = catalog.digest();
        let verifier_bindings = catalog
            .verifier_class_bindings()
            .into_iter()
            .map(|class| {
                VerifierBinding::new(
                    class.verifier(),
                    VerifierGeneration::new(1).unwrap(),
                    class.receipt_schema(),
                    Digest::new([0x91; 32]),
                )
                .unwrap()
            })
            .collect();
        let mut request = |engine: &mut Engine, request| {
            engine
                .transact(request, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .unwrap()
        };
        request(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest,
                verifier_bindings,
            },
        );
        request(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: ChargeAccountId::new(1).unwrap(),
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
                ],
            },
        );
        let device = ClaimScope::Device(DeviceScopeId::new(7).unwrap());
        for (component, claim, kind, scope, resource) in [
            (
                AGENT_COMPONENT_REPLY,
                ClaimId::new(1).unwrap(),
                REPLY_CLAIM_PUBLICATION_SLOT,
                ClaimScope::Logical,
                ResourceId::new(1).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(2).unwrap(),
                DEVICE_CLAIM_QUEUE_SLOT,
                device,
                ResourceId::new(2).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(3).unwrap(),
                DEVICE_CLAIM_PINNED_PAGE,
                device,
                ResourceId::new(3).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(4).unwrap(),
                DEVICE_CLAIM_IOVA,
                device,
                ResourceId::new(4).unwrap(),
            ),
        ] {
            request(
                &mut engine,
                CommandRequest::AddComponentClaim {
                    effect,
                    component,
                    actor,
                    claim,
                    kind,
                    scope,
                    resource,
                    resource_generation: ResourceGeneration::new(1).unwrap(),
                    units: 1,
                },
            );
        }
        request(
            &mut engine,
            CommandRequest::PrepareCompositeEffect { effect, actor },
        );
        (engine, effect, actor)
    }

    fn append_checkpoint(engine: &mut Engine, journal: &mut Vec<u8>) {
        let command = Command(CommandKind::WholeStateCheckpointV1 {
            state: Arc::from(encode_whole_state_checkpoint(&engine.state).into_boxed_slice()),
            projection: engine.projection_digest(),
        });
        engine
            .transact(command, |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            })
            .unwrap();
    }

    #[test]
    fn mixed_catalog_provider_generations_use_exact_material_in_full_invariants() {
        let standard = standard_catalog();
        let tool = tool_dma_catalog();
        let standard_digest = standard.digest();
        let tool_digest = tool.digest();
        assert_ne!(standard_digest, tool_digest);
        let catalogs = CatalogSet::new(&[standard.clone(), tool.clone()]).unwrap();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            catalogs,
            CoreLimits::bounded_default(),
            freshness(),
        );
        for (provider_id, catalog, digest) in [
            (ProviderId::new(11).unwrap(), standard, standard_digest),
            (ProviderId::new(12).unwrap(), tool, tool_digest),
        ] {
            let coordinate = ProviderCoordinate::new(
                WorldId::new(1).unwrap(),
                provider_id,
                ProviderGeneration::new(1).unwrap(),
            );
            let verifier_bindings = catalog
                .verifier_class_bindings()
                .into_iter()
                .map(|class| {
                    VerifierBinding::new(
                        class.verifier(),
                        VerifierGeneration::new(1).unwrap(),
                        class.receipt_schema(),
                        Digest::new([provider_id.get() as u8; 32]),
                    )
                    .unwrap()
                })
                .collect();
            engine
                .transact(
                    CommandRequest::RegisterProviderGeneration {
                        coordinate,
                        catalog_digest: digest,
                        verifier_bindings,
                    },
                    |_| Ok::<(), ()>(()),
                )
                .unwrap();
        }
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state).unwrap();

        let coordinate = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(12).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        engine
            .state
            .provider_generations_mut()
            .get_mut(&coordinate)
            .unwrap()
            .catalog_digest = standard_digest;
        assert!(
            check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state)
                .is_err()
        );
    }

    #[test]
    fn scoped_admission_uses_catalog_consensus_not_binding_order() {
        let standard = standard_catalog();
        let tool = tool_dma_catalog();
        let standard_digest = standard.digest();
        let tool_digest = tool.digest();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[standard.clone(), tool.clone()]).unwrap(),
            CoreLimits::bounded_default(),
            freshness(),
        );
        let register =
            |engine: &mut Engine, provider: ProviderCoordinate, catalog: &DomainCatalog| {
                let verifier_bindings = catalog
                    .verifier_class_bindings()
                    .into_iter()
                    .map(|class| {
                        VerifierBinding::new(
                            class.verifier(),
                            VerifierGeneration::new(1).unwrap(),
                            class.receipt_schema(),
                            Digest::new([provider.provider().get() as u8; 32]),
                        )
                        .unwrap()
                    })
                    .collect();
                engine
                    .transact(
                        CommandRequest::RegisterProviderGeneration {
                            coordinate: provider,
                            catalog_digest: catalog.digest(),
                            verifier_bindings,
                        },
                        |_| Ok::<(), ()>(()),
                    )
                    .unwrap();
            };
        let standard_a = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(21).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let standard_b = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(22).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let tool_provider = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(23).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        register(&mut engine, standard_a, &standard);
        register(&mut engine, standard_b, &standard);
        register(&mut engine, tool_provider, &tool);

        // Reordering equal-catalog bindings must not change the selected
        // semantic material or the resulting admission.
        let valid = engine.transact(
            CommandRequest::AdmitScopedCompositeEffect {
                effect: EffectId::new(OperationId::new(301).unwrap(), 1).unwrap(),
                origin: ExecutorCoordinate::new(
                    crate::ExecutorId::new(301).unwrap(),
                    crate::ExecutorGeneration::new(1).unwrap(),
                ),
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: ChargeAccountId::new(301).unwrap(),
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, standard_b),
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, standard_a),
                ],
            },
            |_| Ok::<(), ()>(()),
        );
        assert!(valid.is_ok());

        // A mixed set is rejected before any first binding can select a
        // catalog, regardless of which component appears first on the wire.
        for bindings in [
            vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, standard_a),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, tool_provider),
            ],
            vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, tool_provider),
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, standard_a),
            ],
        ] {
            let error = engine
                .transact(
                    CommandRequest::AdmitScopedCompositeEffect {
                        effect: EffectId::new(OperationId::new(302).unwrap(), 1).unwrap(),
                        origin: ExecutorCoordinate::new(
                            crate::ExecutorId::new(302).unwrap(),
                            crate::ExecutorGeneration::new(1).unwrap(),
                        ),
                        kind: AGENT_OPERATION_COMPOSITE,
                        charge_account: ChargeAccountId::new(302).unwrap(),
                        bindings,
                    },
                    |_| Ok::<(), ()>(()),
                )
                .unwrap_err();
            assert!(matches!(error, TxError::Core(CoreError::CatalogMismatch)));
        }
        assert_eq!(
            engine.catalog.get(standard_digest).unwrap().digest(),
            standard_digest
        );
        assert_eq!(
            engine.catalog.get(tool_digest).unwrap().digest(),
            tool_digest
        );
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state).unwrap();
    }

    #[test]
    fn bounded_tool_dma_checkpoint_roundtrip_and_suffix_replay() {
        let mut journal = Vec::new();
        let (mut engine, effect, actor) = seed(&mut journal);
        append_checkpoint(&mut engine, &mut journal);
        engine
            .transact(
                CommandRequest::RecordCompositeCommitIntents {
                    effect,
                    actor,
                    operations: vec![
                        ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, Digest::new([3; 32])),
                        ComponentCommitOperation::new(AGENT_COMPONENT_DMA, Digest::new([4; 32])),
                    ],
                },
                |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
        let decoded = decode_whole_state_checkpoint(
            &encode_whole_state_checkpoint(&engine.state),
            engine.catalog_set(),
            engine.limits,
        )
        .unwrap();
        assert_eq!(decoded, engine.state);
        let target = Freshness::new(
            BootGeneration::new(2).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(2).unwrap(),
        );
        let anchor = RecoveryAnchor::from_trusted_provider(
            RecoveryBinding::new(
                crate::RecoveryProfile::current(),
                WorldId::new(1).unwrap(),
                engine.catalog.digest(),
                engine.state.freshness().registry(),
            )
            .unwrap(),
            engine.state.freshness(),
            target,
            engine.state.revision(),
            engine.state.head(),
            engine.projection_digest(),
        )
        .unwrap();
        let recovered = Engine::recover(engine.catalog.clone(), engine.limits, anchor, &journal)
            .unwrap()
            .into_engine();
        assert_eq!(recovered.state.revision(), engine.state.revision());
        assert_eq!(recovered.state.head(), engine.state.head());
        assert_eq!(
            recovered
                .state
                .composite_effects()
                .get(&effect)
                .unwrap()
                .components,
            engine
                .state
                .composite_effects()
                .get(&effect)
                .unwrap()
                .components
        );
    }

    #[test]
    fn bounded_tool_dma_checkpoint_rejects_corruption() {
        let mut journal = Vec::new();
        let (engine, _, _) = seed(&mut journal);
        let mut image = encode_whole_state_checkpoint(&engine.state);
        image[0] ^= 0x80;
        assert!(
            decode_whole_state_checkpoint(&image, engine.catalog_set(), engine.limits).is_err()
        );
    }

    #[test]
    fn whole_state_schema_two_is_recognized_and_rejected() {
        let mut journal = Vec::new();
        let (engine, _, _) = seed(&mut journal);
        let mut image = encode_whole_state_checkpoint(&engine.state);
        image[..8].copy_from_slice(PREVIOUS_WHOLE_STATE_CHECKPOINT_MAGIC);
        image[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode_whole_state_checkpoint(&image, engine.catalog_set(), engine.limits),
            Err(CoreError::UnsupportedCheckpointState)
        );
    }

    #[test]
    fn checkpoint_accepts_canonical_rebuild_of_zero_derived_charge_entries() {
        let mut journal = Vec::new();
        let (mut engine, _, _) = seed(&mut journal);
        // Retiring the final live claim leaves this zero-valued derived cache
        // entry permitted by the invariant checker. It is intentionally not
        // serialized; recovery rebuilds the canonical empty cache.
        let (_, credit_class) = engine
            .state
            .charges()
            .keys()
            .next()
            .copied()
            .expect("seeded charge");
        engine
            .state
            .charges_mut()
            .insert_mut((ChargeAccountId::new(2).unwrap(), credit_class), 0);
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state).unwrap();

        append_checkpoint(&mut engine, &mut journal);
        let rebuilt = decode_whole_state_checkpoint(
            &encode_whole_state_checkpoint(&engine.state),
            engine.catalog_set(),
            engine.limits,
        )
        .unwrap();
        assert_ne!(rebuilt, engine.state);
        let mut canonical = engine.state.clone();
        canonical.charges.retain_mut(|_, units| *units != 0);
        assert_eq!(rebuilt, canonical);
        assert_eq!(rebuilt.projection_cache.digest, engine.projection_digest());
    }

    #[test]
    fn checkpoint_rejects_noncanonical_acceptance_and_oversized_counts() {
        assert!(checkpoint_read_option_accepted(&mut Cursor::new(&[2])).is_err());
        let engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            freshness(),
        );
        let mut image = encode_whole_state_checkpoint(&engine.state);
        // framing (8+2), revision, head, nonce and freshness precede the
        // world-presence tag.
        let operations_offset = 8 + 2 + 8 + 32 + 8 + (4 * 8);
        image[operations_offset..operations_offset + 4].copy_from_slice(
            &u32::try_from(engine.limits.max_operations + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(
            decode_whole_state_checkpoint(&image, engine.catalog_set(), engine.limits).is_err()
        );

        let mut payload = vec![37];
        payload.extend_from_slice(&Digest::ZERO.bytes());
        payload.extend_from_slice(
            &u32::try_from(MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(matches!(
            CommandKind::decode_payload(&payload),
            Err(CommandDecodeError::UnexpectedEof)
        ));
    }

    #[test]
    fn tag_46_rejects_huge_binding_count_before_reserving() {
        let mut payload = vec![46];
        put_effect(
            &mut payload,
            EffectId::new(OperationId::new(1).unwrap(), 1).unwrap(),
        );
        put_incarnation(
            &mut payload,
            ExecutorCoordinate::new(
                crate::ExecutorId::new(1).unwrap(),
                crate::ExecutorGeneration::new(1).unwrap(),
            ),
        );
        put_u32(&mut payload, AGENT_OPERATION_COMPOSITE.get());
        put_u64(&mut payload, 1);
        put_u32(&mut payload, u32::MAX);
        assert_eq!(
            CommandKind::decode_payload(&payload),
            Err(CommandDecodeError::CountTooLarge)
        );
    }

    #[test]
    fn tags_42_and_35_reject_huge_vector_counts_before_reserving() {
        let provider = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let mut registration = vec![42];
        put_provider_coordinate(&mut registration, provider);
        put_digest(&mut registration, Digest::new([1; 32]));
        put_u32(&mut registration, u32::MAX);
        assert_eq!(
            CommandKind::decode_payload(&registration),
            Err(CommandDecodeError::CountTooLarge)
        );

        let mut cohort = vec![35];
        put_effect(
            &mut cohort,
            EffectId::new(OperationId::new(1).unwrap(), 1).unwrap(),
        );
        put_incarnation(
            &mut cohort,
            ExecutorCoordinate::new(
                crate::ExecutorId::new(1).unwrap(),
                crate::ExecutorGeneration::new(1).unwrap(),
            ),
        );
        put_u32(&mut cohort, u32::MAX);
        assert_eq!(
            CommandKind::decode_payload(&cohort),
            Err(CommandDecodeError::CountTooLarge)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn persistence_panic_latches_before_any_bytes_are_persisted() {
        let mut journal = Vec::new();
        let (mut engine, effect, actor) = seed(&mut journal);
        let command = CommandRequest::FenceExecutor {
            operation: effect.operation(),
            crashed: actor,
        };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = engine.transact(command, |_record| -> Result<(), ()> {
                panic!("persistence failed before append");
            });
        }));
        assert!(panic.is_err());
        assert!(engine.persistence_recovery_required());
        assert!(matches!(
            engine.transact(
                CommandRequest::FenceExecutor {
                    operation: effect.operation(),
                    crashed: actor,
                },
                |_| Ok::<(), ()>(()),
            ),
            Err(TxError::Core(CoreError::PersistenceRecoveryRequired))
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn persistence_panic_after_append_keeps_the_recovery_latch_armed() {
        let mut journal = Vec::new();
        let (mut engine, effect, actor) = seed(&mut journal);
        let command = CommandRequest::FenceExecutor {
            operation: effect.operation(),
            crashed: actor,
        };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = engine.transact(command, |record| -> Result<(), ()> {
                journal.extend_from_slice(record.bytes());
                panic!("persistence failed after append");
            });
        }));
        assert!(panic.is_err());
        assert!(!journal.is_empty());
        assert!(engine.persistence_recovery_required());
    }

    #[test]
    fn checkpoint_rejects_nested_counts_and_noncanonical_wire_order() {
        let mut journal = Vec::new();
        let (engine, _, _) = seed(&mut journal);
        let image = encode_whole_state_checkpoint(&engine.state);

        // The provider verifier count is checked against the exact catalog
        // verifier set before the decoder reserves or enters that loop.
        let high_water_count_offset = 8 + 2 + 8 + 32 + 8 + 32 + 1 + 8;
        let high_water_count = u32::from_le_bytes(
            image[high_water_count_offset..high_water_count_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let provider_count_offset = high_water_count_offset + 4 + high_water_count * 16;
        assert_eq!(
            u32::from_le_bytes(
                image[provider_count_offset..provider_count_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        let verifier_count_offset = provider_count_offset + 4 + 24 + 32 + 32;
        let mut oversized_verifiers = image.clone();
        oversized_verifiers[verifier_count_offset..verifier_count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            decode_whole_state_checkpoint(
                &oversized_verifiers,
                engine.catalog_set(),
                engine.limits
            )
            .is_err()
        );

        // Reversing two high-water keys is a non-canonical BTree wire image,
        // even though the key set itself is otherwise valid.
        let mut noncanonical = image.clone();
        let inserted_at = provider_count_offset;
        let mut extra = Vec::new();
        put_u64(&mut extra, 2);
        put_u64(&mut extra, 1);
        noncanonical.splice(inserted_at..inserted_at, extra);
        noncanonical[high_water_count_offset..high_water_count_offset + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let (first, rest) = noncanonical[high_water_count_offset + 4..].split_at_mut(16);
        let second = &mut rest[..16];
        first.swap_with_slice(second);
        assert!(
            decode_whole_state_checkpoint(&noncanonical, engine.catalog_set(), engine.limits)
                .is_err()
        );
    }

    #[test]
    fn checkpoint_rejects_quarantine_without_device_generation() {
        let mut journal = Vec::new();
        let (engine, _, _) = seed(&mut journal);
        let mut image = encode_whole_state_checkpoint(&engine.state);
        assert_eq!(
            u32::from_le_bytes(image[image.len() - 4..].try_into().unwrap()),
            0
        );
        image.truncate(image.len() - 4);
        put_u32(&mut image, 1);
        put_u64(&mut image, 99);
        assert!(
            decode_whole_state_checkpoint(&image, engine.catalog_set(), engine.limits).is_err()
        );

        let mut invalid_state = engine.state.clone();
        invalid_state
            .device_quarantine_mut()
            .insert_mut(DeviceScopeId::new(99).unwrap());
        assert!(
            check_invariants_for_catalog_set(engine.catalog_set(), engine.limits, &invalid_state)
                .is_err()
        );
    }

    #[test]
    fn handoff_recovery_fact_rejects_cross_role_descriptor_provider_and_verifier_replay() {
        let mut journal = Vec::new();
        let (engine, effect, _) = seed(&mut journal);
        let component = engine
            .state
            .composite_effects()
            .get(&effect)
            .unwrap()
            .components
            .get(&AGENT_COMPONENT_REPLY)
            .unwrap();
        let catalog = engine
            .catalog
            .get(
                engine
                    .state
                    .composite_effects()
                    .get(&effect)
                    .unwrap()
                    .catalog_digest,
            )
            .unwrap();
        let receipt = catalog
            .obligation_rule(component.domain, component.obligation)
            .unwrap()
            .receipts()
            .commit_outcome();
        let scope = engine
            .scoped_verification_scope(
                effect,
                AGENT_COMPONENT_REPLY,
                receipt.verifier(),
                receipt.receipt_schema(),
            )
            .unwrap();
        let operation = Digest::new([0x51; 32]);
        let descriptor_digest = Digest::new([0x52; 32]);
        let fact = VerifiedHandoffRecoveryFact {
            role: HandoffRecoveryRole::Parent,
            effect,
            component: AGENT_COMPONENT_REPLY,
            operation,
            descriptor_digest,
            freshness: component_freshness(
                &engine.state,
                engine.state.composite_effects().get(&effect).unwrap(),
                component,
            )
            .unwrap(),
            stamp: VerifierStamp {
                identity: VerifierIdentity::new_exact(scope.verifier_binding()),
                receipt_digest: Digest::new([0x53; 32]),
            },
            verification_scope: scope,
        };
        let expected = HandoffRecoveryCoordinates::new(
            HandoffRecoveryRole::Parent,
            effect,
            AGENT_COMPONENT_REPLY,
            operation,
            descriptor_digest,
            fact.freshness,
        );
        assert!(handoff_recovery_fact_matches(
            &engine.state,
            catalog,
            fact,
            expected,
        ));
        assert!(!handoff_recovery_fact_matches(
            &engine.state,
            catalog,
            VerifiedHandoffRecoveryFact {
                role: HandoffRecoveryRole::Child,
                ..fact
            },
            expected,
        ));
        assert!(!handoff_recovery_fact_matches(
            &engine.state,
            catalog,
            VerifiedHandoffRecoveryFact {
                descriptor_digest: Digest::new([0x54; 32]),
                ..fact
            },
            expected,
        ));
        let wrong_provider = ProviderCoordinate::new(
            scope.world(),
            ProviderId::new(99).unwrap(),
            scope.provider().generation(),
        );
        assert!(!handoff_recovery_fact_matches(
            &engine.state,
            catalog,
            VerifiedHandoffRecoveryFact {
                verification_scope: ProviderVerificationScope::new(
                    scope.world(),
                    wrong_provider,
                    scope.operation(),
                    scope.catalog_digest(),
                    scope.verifier_binding(),
                ),
                ..fact
            },
            expected,
        ));
        let wrong_binding = VerifierBinding::new(
            scope.verifier_binding().verifier(),
            scope.verifier_binding().generation(),
            scope.verifier_binding().receipt_schema(),
            Digest::new([0x55; 32]),
        )
        .unwrap();
        assert!(!handoff_recovery_fact_matches(
            &engine.state,
            catalog,
            VerifiedHandoffRecoveryFact {
                stamp: VerifierStamp {
                    identity: VerifierIdentity::new_exact(wrong_binding),
                    ..fact.stamp
                },
                ..fact
            },
            expected,
        ));
    }
}

#[cfg(test)]
mod prepared_delta_tests {
    use super::*;

    fn empty_state() -> State {
        State {
            world: WorldId::new(1).unwrap(),
            provider_generations: StateMap::new(),
            provider_high_water: StateMap::new(),
            scoped_composites: StateMap::new(),
            artifact_leases: StateMap::new(),
            recovery_operations: StateMap::new(),
            composite_effects: StateMap::new(),
            composite_resource_index: StateMap::new(),
            resources: StateMap::new(),
            charges: StateMap::new(),
            device_generations: StateMap::new(),
            device_quarantine: StateSet::new(),
            revision: 0,
            head: Digest::ZERO,
            next_nonce: 1,
            total_claims: 0,
            freshness: Freshness::new(
                BootGeneration::new(1).unwrap(),
                RegistryInstance::new(1).unwrap(),
                DeviceGeneration::new(1).unwrap(),
                JournalGeneration::new(1).unwrap(),
            ),
            recovery_target: None,
            projection_cache: ProjectionCache {
                leaves: AuthenticatedMap::new(),
                digest: Digest::ZERO,
            },
        }
    }

    #[test]
    fn keep_slots_preserve_every_untouched_root() {
        let base = empty_state();
        let mut published = base.clone();
        let mut builder = DeltaBuilder::new(&base);
        builder.set_revision(1);
        let prepared = builder.finish();
        prepared.apply(&mut published);

        assert_eq!(published.revision, 1);
        assert!(
            published
                .provider_generations
                .ptr_eq(&base.provider_generations)
        );
        assert!(
            published
                .provider_high_water
                .ptr_eq(&base.provider_high_water)
        );
        assert!(published.scoped_composites.ptr_eq(&base.scoped_composites));
        assert!(published.artifact_leases.ptr_eq(&base.artifact_leases));
        assert!(
            published
                .recovery_operations
                .ptr_eq(&base.recovery_operations)
        );
        assert!(published.composite_effects.ptr_eq(&base.composite_effects));
        assert!(
            published
                .composite_resource_index
                .ptr_eq(&base.composite_resource_index)
        );
        assert!(published.resources.ptr_eq(&base.resources));
        assert!(published.charges.ptr_eq(&base.charges));
        assert!(
            published
                .device_generations
                .ptr_eq(&base.device_generations)
        );
        assert!(published.device_quarantine.ptr_eq(&base.device_quarantine));
        assert!(
            published
                .projection_cache
                .leaves
                .ptr_eq(&base.projection_cache.leaves)
        );
    }

    #[test]
    fn first_mutation_copies_only_the_touched_root() {
        let base = empty_state();
        let mut published = base.clone();
        let resource = ResourceId::new(1).unwrap();
        let mut builder = DeltaBuilder::new(&base);
        builder.ensure_resources().insert_mut(
            resource,
            ResourceRecord {
                scope: ClaimScope::Logical,
                generation: ResourceGeneration::new(1).unwrap(),
                phase: ResourcePhase::Retired,
            },
        );
        builder.finish().apply(&mut published);

        assert!(published.resources.get(&resource).is_some());
        assert!(!published.resources.ptr_eq(&base.resources));
        assert!(published.composite_effects.ptr_eq(&base.composite_effects));
        assert!(published.charges.ptr_eq(&base.charges));
        assert!(published.device_quarantine.ptr_eq(&base.device_quarantine));
    }
}

#[cfg(test)]
mod projection_v10_tests {
    use super::*;
    use crate::{
        AGENT_COMPONENT_DMA, AGENT_OPERATION_COMPOSITE, CREDIT_QUEUE_SLOT, DEVICE_CLAIM_QUEUE_SLOT,
        DEVICE_DOMAIN, DEVICE_OBLIGATION_DMA,
    };

    fn digest(tag: u8) -> Digest {
        Digest::new([tag; 32])
    }

    fn freshness(device: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(2).unwrap(),
            DeviceGeneration::new(device).unwrap(),
            JournalGeneration::new(3).unwrap(),
        )
    }

    fn pending_reuse_mut(
        state: &mut impl StateAccessMut,
        resource: ResourceId,
    ) -> &mut PendingReuse {
        match &mut state.resources_mut().get_mut(&resource).unwrap().phase {
            ResourcePhase::Claimed {
                pending_reuse: Some(pending),
            } => pending,
            _ => panic!("projection fixture must retain a pending reuse contract"),
        }
    }

    fn assert_projection_changes(
        baseline: &State,
        catalog: Digest,
        mutate: impl FnOnce(&mut State),
    ) {
        let expected_revision = baseline.revision;
        let expected_head = baseline.head;
        let expected = projection_digest(baseline, catalog);
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert_eq!(changed.revision, expected_revision);
        assert_eq!(changed.head, expected_head);
        assert_ne!(projection_digest(&changed, catalog), expected);
    }

    #[test]
    fn projection_v10_binds_composite_claim_and_pending_reuse_fields_at_fixed_head() {
        let catalog = crate::standard_catalog();
        let catalog_digest = catalog.digest();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[catalog]).unwrap(),
            CoreLimits::bounded_default(),
            freshness(1),
        );
        let effect = EffectId::new(OperationId::new(0xc607).unwrap(), 11).unwrap();
        let actor = ExecutorCoordinate::new(
            crate::ExecutorId::new(7).unwrap(),
            crate::ExecutorGeneration::new(3).unwrap(),
        );
        let claim = ClaimId::new(17).unwrap();
        let resource = ResourceId::new(23).unwrap();
        let scope = ClaimScope::Device(DeviceScopeId::new(29).unwrap());
        let mut claims = BTreeMap::new();
        claims.insert(
            claim,
            ClaimRecord {
                id: claim,
                domain: DEVICE_DOMAIN,
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                credit_class: CREDIT_QUEUE_SLOT,
                scope,
                resource,
                resource_generation: ResourceGeneration::new(2).unwrap(),
                units: 1,
                enrolled_freshness: freshness(2),
                requirements: Vec::new(),
                retired: false,
            },
        );
        let mut components = BTreeMap::new();
        components.insert(
            AGENT_COMPONENT_DMA,
            ComponentRecord {
                id: AGENT_COMPONENT_DMA,
                domain: DEVICE_DOMAIN,
                obligation: DEVICE_OBLIGATION_DMA,
                obligation_policy: ObligationPolicy::RetirementEvidence,
                commit: CommitState::Registered,
                commit_nonce: None,
                commit_operation: None,
                commit_fact: None,
                outcome: OutcomeState::Pending,
                settlement: SettlementState::NotRequired,
                settlement_nonce: None,
                claim_stage: None,
                settlement_intent: None,
                applied_fact: None,
                settlement_fact: None,
                retirement: RetirementState::Held,
                claims,
            },
        );
        engine.state.composite_effects_mut().insert_mut(
            effect,
            CompositeEffectRecord {
                effect,
                kind: AGENT_OPERATION_COMPOSITE,
                catalog_digest,
                causal_owner: actor,
                custodian: CustodyState::Executor(actor),
                charge_owner: ChargeAccountId::new(31).unwrap(),
                authority: AuthorityState::Active,
                authority_epoch: 1,
                handoff: SingleHopRole::None,
                released_provenance: None,
                components,
            },
        );
        engine.state.resources_mut().insert_mut(
            resource,
            ResourceRecord {
                scope,
                generation: ResourceGeneration::new(2).unwrap(),
                phase: ResourcePhase::Claimed {
                    pending_reuse: Some(PendingReuse {
                        effect,
                        component: AGENT_COMPONENT_DMA,
                        actor,
                        authority_epoch: 1,
                        claim,
                        previous_generation: ResourceGeneration::new(1).unwrap(),
                        catalog_digest,
                        retirement_digest: digest(0x41),
                        reuse_contract: digest(0x42),
                        nonce: 5,
                        freshness: freshness(2),
                    }),
                },
            },
        );

        let mut baseline = engine.state;
        // The fixture edits primary state directly, so refresh the retained
        // cache before comparing it with the independent full rebuild.
        baseline.projection_cache = build_projection_cache(&baseline, catalog_digest);
        let rebuilt = build_projection_cache(&baseline, catalog_digest);
        assert_eq!(baseline.projection_cache, rebuilt);
        let golden = rebuilt.digest;
        assert_eq!(
            golden.bytes(),
            [
                172, 92, 8, 238, 195, 229, 38, 54, 117, 132, 206, 85, 235, 2, 22, 207, 158, 101,
                43, 98, 103, 64, 25, 33, 72, 13, 156, 191, 121, 60, 38, 149,
            ]
        );

        assert_projection_changes(&baseline, catalog_digest, |state| {
            state
                .composite_effects_mut()
                .get_mut(&effect)
                .unwrap()
                .authority_epoch = 2;
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            state
                .composite_effects_mut()
                .get_mut(&effect)
                .unwrap()
                .components
                .get_mut(&AGENT_COMPONENT_DMA)
                .unwrap()
                .settlement = SettlementState::Settled;
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            state
                .composite_effects_mut()
                .get_mut(&effect)
                .unwrap()
                .components
                .get_mut(&AGENT_COMPONENT_DMA)
                .unwrap()
                .claims
                .get_mut(&claim)
                .unwrap()
                .units = 2;
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).claim = ClaimId::new(18).unwrap();
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).previous_generation =
                ResourceGeneration::new(9).unwrap();
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).catalog_digest = digest(0x51);
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).retirement_digest = digest(0x52);
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).reuse_contract = digest(0x53);
        });
        assert_projection_changes(&baseline, catalog_digest, |state| {
            pending_reuse_mut(state, resource).freshness = freshness(3);
        });
    }
}

// This is deliberately an ignored, std-only measurement rather than a normal
// test or a production instrumentation surface. It emits one JSON object per
// fixed state size, so a development run can be retained as JSONL without
// turning a host-specific latency into a correctness assertion. Run with:
//
// cargo test -p cser-core --release --features std --lib \
//   portable_core_state_work_profile -- --ignored --nocapture
//
// `transition_no_persist_median_ns` covers the same prepared-delta construction,
// command application, canonical invariant check, journal-record construction,
// and projection digest that `Engine::transact` performs, but deliberately
// excludes an embedding's journal write/readback/flush and anchor advance.
// Those boundaries belong to the durable provider and must be measured in its
// own runtime profile. The fixture is catalog-valid and the canonical full
// checker/digest remain the oracle for every size, so this profile cannot
// accidentally benchmark an invalid shortcut.
#[cfg(all(test, feature = "std"))]
mod performance_profile_tests {
    use std::{hint::black_box, time::Instant};

    use super::*;
    use crate::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, DEVICE_CLAIM_IOVA,
        DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DeviceScopeId,
        REPLY_CLAIM_PUBLICATION_SLOT, standard_catalog,
    };

    // Stable comparison points, not a capacity promise. The development plan
    // intentionally keeps these few sizes fixed while allowing repetitions
    // and workload shape to evolve.
    const SIZES: [usize; 4] = [4, 64, 512, 4096];
    const WARMUPS: usize = 3;
    const SAMPLES: usize = 11;

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn transact(engine: &mut Engine, request: CommandRequest) {
        engine.transact(request, |_| Ok::<(), ()>(())).unwrap();
    }

    fn exact_catalog(engine: &Engine) -> &DomainCatalog {
        let digest = engine
            .state
            .composite_effects()
            .values()
            .next()
            .expect("fixture composite")
            .catalog_digest;
        engine.catalog.get(digest).expect("fixture catalog")
    }

    fn seed_one_composite() -> Engine {
        let limits = CoreLimits::new(1, 1024, 4096, 4096, 64, 1 << 20, 1).unwrap();
        let catalog = standard_catalog();
        let catalog_digest = catalog.digest();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[catalog]).unwrap(),
            limits,
            freshness(),
        );
        let operation = OperationId::new(1).unwrap();
        let effect = EffectId::new(operation, 1).unwrap();
        let actor = ExecutorCoordinate::new(
            crate::ExecutorId::new(1).unwrap(),
            crate::ExecutorGeneration::new(1).unwrap(),
        );
        let account = ChargeAccountId::new(1).unwrap();
        let generation = ResourceGeneration::new(1).unwrap();
        let device_scope = ClaimScope::Device(DeviceScopeId::new(1).unwrap());
        let provider = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let verifier_bindings = engine
            .catalog
            .iter()
            .next()
            .map(|(_, catalog)| catalog)
            .expect("catalog set is non-empty")
            .verifier_class_bindings()
            .into_iter()
            .map(|class| {
                VerifierBinding::new(
                    class.verifier(),
                    VerifierGeneration::new(1).unwrap(),
                    class.receipt_schema(),
                    Digest::new([0x92; 32]),
                )
                .unwrap()
            })
            .collect();
        transact(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest,
                verifier_bindings,
            },
        );
        transact(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: account,
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
                ],
            },
        );
        for (component, claim, kind, scope, resource) in [
            (
                AGENT_COMPONENT_REPLY,
                ClaimId::new(1).unwrap(),
                REPLY_CLAIM_PUBLICATION_SLOT,
                ClaimScope::Logical,
                ResourceId::new(1).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(2).unwrap(),
                DEVICE_CLAIM_QUEUE_SLOT,
                device_scope,
                ResourceId::new(2).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(3).unwrap(),
                DEVICE_CLAIM_PINNED_PAGE,
                device_scope,
                ResourceId::new(3).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(4).unwrap(),
                DEVICE_CLAIM_IOVA,
                device_scope,
                ResourceId::new(4).unwrap(),
            ),
        ] {
            transact(
                &mut engine,
                CommandRequest::AddComponentClaim {
                    effect,
                    component,
                    actor,
                    claim,
                    kind,
                    scope,
                    resource,
                    resource_generation: generation,
                    units: 1,
                },
            );
        }
        transact(
            &mut engine,
            CommandRequest::PrepareCompositeEffect { effect, actor },
        );
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state).unwrap();
        engine
    }

    fn append_composite(engine: &mut Engine, sequence: u64) {
        let operation = OperationId::new(1).unwrap();
        let effect = EffectId::new(operation, sequence).unwrap();
        let actor = engine
            .state
            .recovery_operations()
            .get(&operation)
            .expect("fixture operation")
            .last_executor;
        let provider = *engine
            .state
            .provider_generations()
            .keys()
            .next()
            .expect("fixture provider");
        let account = ChargeAccountId::new(1).unwrap();
        let generation = ResourceGeneration::new(1).unwrap();
        let device_scope = ClaimScope::Device(DeviceScopeId::new(1).unwrap());
        transact(
            engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: account,
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
                ],
            },
        );
        for (component, claim, kind, scope, resource) in [
            (
                AGENT_COMPONENT_REPLY,
                ClaimId::new(1).unwrap(),
                REPLY_CLAIM_PUBLICATION_SLOT,
                ClaimScope::Logical,
                ResourceId::new((sequence - 1) * 4 + 1).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(2).unwrap(),
                DEVICE_CLAIM_QUEUE_SLOT,
                device_scope,
                ResourceId::new((sequence - 1) * 4 + 2).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(3).unwrap(),
                DEVICE_CLAIM_PINNED_PAGE,
                device_scope,
                ResourceId::new((sequence - 1) * 4 + 3).unwrap(),
            ),
            (
                AGENT_COMPONENT_DMA,
                ClaimId::new(4).unwrap(),
                DEVICE_CLAIM_IOVA,
                device_scope,
                ResourceId::new((sequence - 1) * 4 + 4).unwrap(),
            ),
        ] {
            transact(
                engine,
                CommandRequest::AddComponentClaim {
                    effect,
                    component,
                    actor,
                    claim,
                    kind,
                    scope,
                    resource,
                    resource_generation: generation,
                    units: 1,
                },
            );
        }
        transact(
            engine,
            CommandRequest::PrepareCompositeEffect { effect, actor },
        );
    }

    fn fixture(live_claims: usize) -> Engine {
        assert!(SIZES.contains(&live_claims));
        assert_eq!(live_claims % 4, 0, "composite fixture has four claims");
        let mut engine = seed_one_composite();
        let composites = live_claims / 4;
        for sequence in 2..=u64::try_from(composites).unwrap() {
            append_composite(&mut engine, sequence);
        }
        check_invariants_for_catalog_set(&engine.catalog, engine.limits, &engine.state).unwrap();
        engine
    }

    fn median_ns(mut values: Vec<u128>) -> u128 {
        values.sort_unstable();
        values[values.len() / 2]
    }

    fn measure(mut operation: impl FnMut()) -> u128 {
        for _ in 0..WARMUPS {
            operation();
        }
        let mut values = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let started = Instant::now();
            operation();
            values.push(started.elapsed().as_nanos());
        }
        median_ns(values)
    }

    fn profile_command() -> CommandKind {
        CommandKind::FenceExecutor {
            operation: OperationId::new(1).unwrap(),
            crashed: ExecutorCoordinate::new(
                crate::ExecutorId::new(1).unwrap(),
                crate::ExecutorGeneration::new(1).unwrap(),
            ),
        }
    }

    /// Measures command application into a prepared delta. Each invocation
    /// starts with a borrowed committed root; only roots touched by the
    /// command are path-copied by `DeltaBuilder`.
    fn measure_delta_apply(engine: &Engine, make_command: fn() -> CommandKind) -> u128 {
        for _ in 0..WARMUPS {
            let mut delta = DeltaBuilder::new(&engine.state);
            let command = make_command();
            black_box(apply_command(
                &engine.catalog,
                Some(exact_catalog(engine)),
                engine.limits,
                &mut delta,
                &command,
            ))
            .unwrap();
            black_box(delta.finish());
        }
        let mut values = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let mut delta = DeltaBuilder::new(&engine.state);
            let command = make_command();
            let started = Instant::now();
            black_box(apply_command(
                &engine.catalog,
                Some(exact_catalog(engine)),
                engine.limits,
                &mut delta,
                &command,
            ))
            .unwrap();
            black_box(delta.finish());
            values.push(started.elapsed().as_nanos());
        }
        median_ns(values)
    }

    /// Measures the portable, non-I/O portion of one transition. It mirrors
    /// the ordering in `transact_with_freshness` while retaining the base
    /// engine so every sample starts at the same revision and semantic state.
    fn measure_transition_without_persistence(
        engine: &Engine,
        make_command: fn() -> CommandKind,
    ) -> u128 {
        for _ in 0..WARMUPS {
            black_box(engine.prepare_transition(Command(make_command())).unwrap());
        }
        let mut values = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let started = Instant::now();
            black_box(engine.prepare_transition(Command(make_command())).unwrap());
            values.push(started.elapsed().as_nanos());
        }
        median_ns(values)
    }

    fn live_claim_count(state: &impl StateAccess) -> usize {
        state
            .composite_effects()
            .values()
            .map(|effect| {
                effect
                    .components
                    .values()
                    .map(|component| component.claims.len())
                    .sum::<usize>()
            })
            .sum::<usize>()
    }

    #[test]
    #[ignore = "manual portable-core performance profile; timing is not a correctness assertion"]
    fn portable_core_state_work_profile() {
        for live_claims in SIZES {
            let engine = fixture(live_claims);
            let invariant_ns = measure(|| {
                black_box(check_invariants_for_catalog_set(
                    &engine.catalog,
                    engine.limits,
                    &engine.state,
                ))
                .unwrap();
            });
            let digest_ns = measure(|| {
                black_box(projection_digest(&engine.state, engine.catalog.digest()));
            });
            let apply_ns = measure_delta_apply(&engine, profile_command);
            let transition_no_persist_ns =
                measure_transition_without_persistence(&engine, profile_command);
            println!(
                "CSER_CORE_STATE_PROFILE {{\"profile_version\":3,\"scope\":\"portable_core_no_persistence\",\"live_claims\":{},\"composites\":{},\"resources\":{},\"delta_apply_median_ns\":{},\"invariant_median_ns\":{},\"projection_digest_median_ns\":{},\"transition_no_persist_median_ns\":{},\"warmups\":{},\"samples\":{}}}",
                live_claim_count(&engine.state),
                engine.state.composite_effects().len(),
                engine.state.resources().len(),
                apply_ns,
                invariant_ns,
                digest_ns,
                transition_no_persist_ns,
                WARMUPS,
                SAMPLES,
            );
        }
        // Keep a non-timing semantic assertion at the end of the manual run.
        assert_eq!(fixture(4096).state.composite_effects().len(), 1024);
    }
}
