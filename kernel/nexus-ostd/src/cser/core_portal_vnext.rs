// SPDX-License-Identifier: MPL-2.0

//! Stateless `NXP3` ingress for the authoritative portable CSER core.
//!
//! This module is intentionally separate from the retired portal. An `NXP3` request
//! carries stable [`cser_core`] identities directly and is evaluated by the
//! same production owner that serializes durable core transitions. There are
//! no negotiated sessions, opaque selector tables, receipt selectors, replay
//! caches, or adapter-owned lifecycle records.
//!
//! A request id is only a response-correlation value. Retrying a request calls
//! the authoritative owner again; the caller must query core state after an
//! ambiguous reply instead of relying on session-local replay memory.
//!
//! The client surface is deliberately narrower than [`CommandRequest`]. It
//! admits composite-effect creation, component-local claim enrollment,
//! preparation, and write-ahead commit intent. Fencing, recovery, adoption, settlement, revocation,
//! freshness checkpoints, retirement, and resource reuse belong to trusted
//! supervisor or domain paths. Receipt-dependent transitions are represented
//! by linear [`cser_core::Command`] values and cannot enter this interface at
//! all.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::{boxed::Box, sync::Arc, vec::Vec};
use cser_core::{
    CommandRequest, ComponentClaimProjection, ComponentId, ComponentProjection,
    CompositeEffectProjection, Digest, EffectId, Freshness, PressureProjection,
    TransitionCoordinates, TransitionEvent, TransitionReceipt, TransitionResult,
};

/// Wire-family marker for the rebaselined portal contract.
pub(crate) const NXP3_MAGIC: [u8; 4] = *b"NXP3";
/// Major protocol version for the rebaselined portal contract.
pub(crate) const NXP3_VERSION_MAJOR: u16 = 3;
/// Minor protocol version understood by this implementation.
pub(crate) const NXP3_VERSION_MINOR: u16 = 0;

/// Rejection while validating the fixed `NXP3` envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortalProtocolError {
    /// The envelope belongs to another protocol family.
    InvalidMagic,
    /// The envelope uses an unsupported major or minor version.
    UnsupportedVersion,
    /// Zero is not a valid response-correlation id.
    InvalidRequestId,
}

/// Fixed, validated protocol metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortalProtocolHeader {
    request_id: u64,
}

impl PortalProtocolHeader {
    /// Validates decoded transport fields without retaining transport state.
    pub(crate) fn from_parts(
        magic: [u8; 4],
        major: u16,
        minor: u16,
        request_id: u64,
    ) -> Result<Self, PortalProtocolError> {
        if magic != NXP3_MAGIC {
            return Err(PortalProtocolError::InvalidMagic);
        }
        if major != NXP3_VERSION_MAJOR || minor != NXP3_VERSION_MINOR {
            return Err(PortalProtocolError::UnsupportedVersion);
        }
        if request_id == 0 {
            return Err(PortalProtocolError::InvalidRequestId);
        }
        Ok(Self { request_id })
    }

    /// Constructs the canonical in-kernel header.
    pub(crate) fn new(request_id: u64) -> Result<Self, PortalProtocolError> {
        Self::from_parts(
            NXP3_MAGIC,
            NXP3_VERSION_MAJOR,
            NXP3_VERSION_MINOR,
            request_id,
        )
    }

    /// Returns the ephemeral response-correlation id.
    pub(crate) const fn request_id(self) -> u64 {
        self.request_id
    }
}

/// Non-authorizing query evaluated under the production owner's core lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreQuery {
    /// Project one exact composite parent by its stable identity.
    CompositeEffect(EffectId),
    /// Project one exact obligation component.
    Component(EffectId, ComponentId),
    /// Enumerate claims for one exact component in stable claim-id order.
    ComponentClaims(EffectId, ComponentId),
    /// Project bounded global admission and quarantine pressure.
    Pressure,
}

/// Operation admitted by the stateless protocol envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PortalOperation {
    /// Ask the production owner to evaluate one untrusted core request.
    Transact(CommandRequest),
    /// Ask the production owner for one lock-consistent projection.
    Observe(CoreQuery),
}

/// One validated request. It owns no authority or replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PortalRequest {
    header: PortalProtocolHeader,
    operation: PortalOperation,
}

impl PortalRequest {
    /// Creates one client transition request under the canonical `NXP3` header.
    pub(crate) fn transact(
        request_id: u64,
        request: CommandRequest,
    ) -> Result<Self, PortalProtocolError> {
        Ok(Self {
            header: PortalProtocolHeader::new(request_id)?,
            operation: PortalOperation::Transact(request),
        })
    }

    /// Creates one non-authorizing observation request.
    pub(crate) fn observe(request_id: u64, query: CoreQuery) -> Result<Self, PortalProtocolError> {
        Ok(Self {
            header: PortalProtocolHeader::new(request_id)?,
            operation: PortalOperation::Observe(query),
        })
    }

    /// Builds a request from a separately decoded and validated header.
    pub(crate) const fn from_validated_parts(
        header: PortalProtocolHeader,
        operation: PortalOperation,
    ) -> Self {
        Self { header, operation }
    }

    /// Returns the ephemeral response-correlation id.
    pub(crate) const fn request_id(&self) -> u64 {
        self.header.request_id()
    }
}

/// Exact transition metadata safe to return to an untrusted caller.
///
/// This view deliberately omits [`cser_core::TransitionOutput`]. Before a
/// production owner returns it, that owner must place any commit intent or
/// other linear output in its trusted domain custodian. Dropping a linear
/// output merely to form this view is an integration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreTransitionView {
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
}

impl CoreTransitionView {
    /// Copies the non-linear metadata from an authoritative durable receipt.
    pub(crate) const fn from_receipt(receipt: &TransitionReceipt) -> Self {
        Self {
            core_api_profile: receipt.core_api_profile(),
            journal_schema: receipt.journal_schema(),
            catalog_digest: receipt.catalog_digest(),
            projection_version: receipt.projection_version(),
            trace_version: receipt.trace_version(),
            revision: receipt.revision(),
            head: receipt.head(),
            projection: receipt.projection(),
            coordinates: receipt.coordinates(),
            result: receipt.result(),
            event: receipt.event(),
        }
    }

    /// Returns the semantic API profile which committed the transition.
    pub(crate) const fn core_api_profile(self) -> u16 {
        self.core_api_profile
    }

    /// Returns the durable command grammar coordinate.
    pub(crate) const fn journal_schema(self) -> u16 {
        self.journal_schema
    }

    /// Returns the catalog digest used by the authoritative owner.
    pub(crate) const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }

    /// Returns the deterministic projection schema coordinate.
    pub(crate) const fn projection_version(self) -> u16 {
        self.projection_version
    }

    /// Returns the normalized trace schema coordinate.
    pub(crate) const fn trace_version(self) -> u16 {
        self.trace_version
    }

    /// Returns the committed journal revision.
    pub(crate) const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the committed journal head.
    pub(crate) const fn head(self) -> Digest {
        self.head
    }

    /// Returns the deterministic complete-state projection digest.
    pub(crate) const fn projection(self) -> Digest {
        self.projection
    }

    /// Returns exact normalized root/effect/component/claim coordinates.
    pub(crate) const fn coordinates(self) -> TransitionCoordinates {
        self.coordinates
    }

    /// Returns the normalized committed result.
    pub(crate) const fn result(self) -> TransitionResult {
        self.result
    }

    /// Returns the normalized transition event.
    pub(crate) const fn event(self) -> TransitionEvent {
        self.event
    }
}

/// Core coordinates captured under the same owner lock as an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreObservationStamp {
    revision: u64,
    head: Digest,
    freshness: Freshness,
}

impl CoreObservationStamp {
    /// Constructs a lock-consistent observation stamp.
    pub(crate) const fn new(revision: u64, head: Digest, freshness: Freshness) -> Self {
        Self {
            revision,
            head,
            freshness,
        }
    }

    /// Returns the observed journal revision.
    pub(crate) const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the observed journal head.
    pub(crate) const fn head(self) -> Digest {
        self.head
    }

    /// Returns all active freshness coordinates.
    pub(crate) const fn freshness(self) -> Freshness {
        self.freshness
    }
}

/// Non-authorizing projection returned directly from the portable core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoreObservation {
    /// Exact composite parent projection, or absence at the observed revision.
    CompositeEffect {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Stable identity requested by the caller.
        effect: EffectId,
        /// Current core projection.
        composite: Option<Box<CompositeEffectProjection>>,
    },
    /// Exact component projection, or absence at the observed revision.
    Component {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Stable parent identity requested by the caller.
        effect: EffectId,
        /// Stable component slot requested by the caller.
        component: ComponentId,
        /// Current core projection.
        projection: Option<ComponentProjection>,
    },
    /// Exact claim set for one component.
    ComponentClaims {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Stable identity requested by the caller.
        effect: EffectId,
        /// Stable component slot requested by the caller.
        component: ComponentId,
        /// Current core projections in stable claim-id order.
        claims: Vec<ComponentClaimProjection>,
    },
    /// Current bounded global pressure.
    Pressure {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Current core projection.
        pressure: PressureProjection,
    },
}

impl CoreObservation {
    /// Returns the coordinates bound to this projection.
    pub(crate) const fn stamp(&self) -> CoreObservationStamp {
        match self {
            Self::CompositeEffect { stamp, .. }
            | Self::Component { stamp, .. }
            | Self::ComponentClaims { stamp, .. }
            | Self::Pressure { stamp, .. } => *stamp,
        }
    }
}

/// Trusted transition family which cannot enter the client portal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedTransition {
    /// Provider registration, fencing, drain, and retirement are owner-owned.
    ProviderLifecycle,
    /// Closed component/provider admission is owner-owned.
    ScopedAdmission,
    /// Recovery-artifact verifier binding and release are owner-owned.
    ArtifactLifecycle,
    /// Immediate executor fencing is supervisor-owned.
    Fence,
    /// Snapshot readiness and binding installation are supervisor-owned.
    Recovery,
    /// Orphan adoption is supervisor-owned.
    Adoption,
    /// Claiming or advancing settlement is domain/supervisor-owned.
    Settlement,
    /// Revocation races are supervisor-owned.
    Revocation,
    /// Cross-boot freshness activation is boot-owner-only.
    FreshnessCheckpoint,
    /// Effect retirement and release require trusted evidence paths.
    Retirement,
    /// Resource reuse requires a linear, durable permit.
    ResourceReuse,
}

/// Policy rejection before the production owner is called.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortalPolicyError {
    /// The operation belongs to a trusted domain or supervisor interface.
    TrustedPathRequired(TrustedTransition),
}

/// Failure returned by one stateless dispatch.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PortalDispatchError<E> {
    /// The requested transition is not client-authorized.
    Policy(PortalPolicyError),
    /// The unique production owner rejected or could not persist the request.
    Registry(E),
}

/// Response body carrying no bearer authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PortalResponseBody {
    /// One durably committed transition projection.
    Transition(CoreTransitionView),
    /// One non-authorizing lock-consistent observation.
    Observation(CoreObservation),
}

/// One correlated `NXP3` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PortalResponse {
    request_id: u64,
    body: PortalResponseBody,
}

impl PortalResponse {
    /// Returns the request correlation id.
    pub(crate) const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the non-authorizing response body.
    pub(crate) const fn body(&self) -> &PortalResponseBody {
        &self.body
    }
}

/// One authoritative recovered core owner shared by every production ingress.
///
/// `transact` must serialize through the same durable runtime used by trusted
/// domain and supervisor paths. It must reserve and retain any linear
/// `TransitionOutput` in the appropriate trusted custodian before returning a
/// [`CoreTransitionView`]. `observe` must collect the projection and its stamp
/// under the same core lock.
pub(crate) trait CoreRegistry: Send + Sync {
    /// Durable transition or observation error returned by the owner.
    type Error;

    /// Executes one client-admissible request through the unique core owner.
    fn transact(&self, request: CommandRequest) -> Result<CoreTransitionView, Self::Error>;

    /// Reads one non-authorizing projection from that same owner.
    fn observe(&self, query: CoreQuery) -> Result<CoreObservation, Self::Error>;
}

/// Stateless `NXP3` adapter over the shared production owner.
pub(crate) struct CorePortalVNext<R> {
    owner: Arc<R>,
}

impl<R> Clone for CorePortalVNext<R> {
    fn clone(&self) -> Self {
        Self {
            owner: Arc::clone(&self.owner),
        }
    }
}

impl<R: CoreRegistry> CorePortalVNext<R> {
    /// Binds this ingress to the exact owner installed during production boot.
    pub(crate) const fn new(owner: Arc<R>) -> Self {
        Self { owner }
    }

    /// Dispatches without installing any session, selector, or replay state.
    pub(crate) fn dispatch(
        &self,
        request: PortalRequest,
    ) -> Result<PortalResponse, PortalDispatchError<R::Error>> {
        let request_id = request.request_id();
        let body = match request.operation {
            PortalOperation::Transact(command) => {
                require_client_command(&command).map_err(PortalDispatchError::Policy)?;
                PortalResponseBody::Transition(
                    self.owner
                        .transact(command)
                        .map_err(PortalDispatchError::Registry)?,
                )
            }
            PortalOperation::Observe(query) => PortalResponseBody::Observation(
                self.owner
                    .observe(query)
                    .map_err(PortalDispatchError::Registry)?,
            ),
        };
        Ok(PortalResponse { request_id, body })
    }
}

fn require_client_command(request: &CommandRequest) -> Result<(), PortalPolicyError> {
    let trusted = match request {
        CommandRequest::AddComponentClaim { .. }
        | CommandRequest::PrepareCompositeEffect { .. }
        | CommandRequest::RecordComponentCommitIntent { .. }
        | CommandRequest::RecordCompositeCommitIntents { .. } => return Ok(()),
        CommandRequest::RegisterProviderGeneration { .. }
        | CommandRequest::FenceProviderEffects { .. }
        | CommandRequest::EnterProviderSettlementOnly { .. }
        | CommandRequest::RetireProviderEffects { .. } => TrustedTransition::ProviderLifecycle,
        CommandRequest::AdmitScopedCompositeEffect { .. } => TrustedTransition::ScopedAdmission,
        CommandRequest::BindArtifactReceiptVerifiers { .. }
        | CommandRequest::AuthorizeArtifactRelease { .. } => TrustedTransition::ArtifactLifecycle,
        CommandRequest::AbortUnescapedEffect { .. } => TrustedTransition::Retirement,
        CommandRequest::FenceExecutor { .. } => TrustedTransition::Fence,
        CommandRequest::Ready { .. } | CommandRequest::Rebind { .. } => TrustedTransition::Recovery,
        CommandRequest::AdoptEffect { .. }
        | CommandRequest::RebaseCompositePrecommitClaims { .. } => TrustedTransition::Adoption,
        CommandRequest::ClaimComponentSettlement { .. } => TrustedTransition::Settlement,
        CommandRequest::BeginRevoke { .. } => TrustedTransition::Revocation,
        CommandRequest::CheckpointRecovery { .. } => TrustedTransition::FreshnessCheckpoint,
        CommandRequest::ReleaseCompositeEffect { .. } => TrustedTransition::Retirement,
        CommandRequest::ReserveComponentReuse { .. } => TrustedTransition::ResourceReuse,
    };
    Err(PortalPolicyError::TrustedPathRequired(trusted))
}

#[cfg(test)]
mod tests {
    use __cser_alloc::sync::Arc;
    use __cser_core::sync::atomic::{AtomicUsize, Ordering};

    use cser_core::{
        BootGeneration, ChargeAccountId, ClaimId, ClaimScope, CommandRequest,
        ComponentCommitOperation, ComponentId, ComponentProviderBinding, CompositeKindId,
        CoreError, DeviceGeneration, EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
        Freshness, JournalGeneration, OperationId, ProviderCoordinate, ProviderGeneration,
        ProviderId, RegistryInstance, ResourceGeneration, ResourceId, SnapshotId, TransitionEvent,
        WorldId,
    };

    use super::*;

    struct FakeRegistry {
        transacts: AtomicUsize,
        observations: AtomicUsize,
    }

    impl FakeRegistry {
        const fn new() -> Self {
            Self {
                transacts: AtomicUsize::new(0),
                observations: AtomicUsize::new(0),
            }
        }
    }

    impl CoreRegistry for FakeRegistry {
        type Error = CoreError;

        fn transact(&self, request: CommandRequest) -> Result<CoreTransitionView, Self::Error> {
            let count = self.transacts.fetch_add(1, Ordering::AcqRel) + 1;
            let event = match request {
                CommandRequest::AdmitScopedCompositeEffect { .. } => {
                    TransitionEvent::ScopedCompositeAdmitted
                }
                CommandRequest::AddComponentClaim { .. } => TransitionEvent::ClaimAdded,
                CommandRequest::PrepareCompositeEffect { .. } => TransitionEvent::EffectPrepared,
                CommandRequest::RecordComponentCommitIntent { .. }
                | CommandRequest::RecordCompositeCommitIntents { .. } => {
                    TransitionEvent::CommitIntentDurable
                }
                _ => return Err(CoreError::InvariantViolation),
            };
            Ok(CoreTransitionView {
                core_api_profile: cser_core::CSER_CORE_API_PROFILE_VERSION,
                journal_schema: cser_core::JOURNAL_SCHEMA_VERSION,
                catalog_digest: digest(77),
                projection_version: cser_core::PROJECTION_VERSION,
                trace_version: cser_core::NORMALIZED_TRACE_VERSION,
                revision: count as u64,
                head: digest(count as u8),
                projection: digest((count + 32) as u8),
                coordinates: TransitionCoordinates::new(None, None, None, None),
                result: TransitionResult::Applied,
                event,
            })
        }

        fn observe(&self, query: CoreQuery) -> Result<CoreObservation, Self::Error> {
            self.observations.fetch_add(1, Ordering::AcqRel);
            let stamp = CoreObservationStamp::new(9, digest(9), freshness());
            match query {
                CoreQuery::CompositeEffect(effect) => Ok(CoreObservation::CompositeEffect {
                    stamp,
                    effect,
                    composite: None,
                }),
                CoreQuery::Component(effect, component) => Ok(CoreObservation::Component {
                    stamp,
                    effect,
                    component,
                    projection: None,
                }),
                CoreQuery::ComponentClaims(effect, component) => {
                    Ok(CoreObservation::ComponentClaims {
                        stamp,
                        effect,
                        component,
                        claims: Vec::new(),
                    })
                }
                CoreQuery::Pressure => Ok(CoreObservation::Pressure {
                    stamp,
                    pressure: PressureProjection {
                        operations: 0,
                        composites: 0,
                        retained_claims: 0,
                        quarantined: false,
                        persistence_recovery_required: false,
                    },
                }),
            }
        }
    }

    fn operation() -> OperationId {
        OperationId::new(7).unwrap()
    }

    fn effect() -> EffectId {
        EffectId::new(operation(), 11).unwrap()
    }

    fn component() -> ComponentId {
        ComponentId::new(17).unwrap()
    }

    fn actor() -> ExecutorCoordinate {
        ExecutorCoordinate::new(
            ExecutorId::new(13).unwrap(),
            ExecutorGeneration::new(2).unwrap(),
        )
    }

    fn digest(tag: u8) -> Digest {
        Digest::new([tag; 32])
    }

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(2).unwrap(),
            RegistryInstance::new(3).unwrap(),
            DeviceGeneration::new(5).unwrap(),
            JournalGeneration::new(6).unwrap(),
        )
    }

    fn admit() -> CommandRequest {
        CommandRequest::AdmitScopedCompositeEffect {
            effect: effect(),
            origin: actor(),
            kind: CompositeKindId::new(41).unwrap(),
            charge_account: ChargeAccountId::new(23).unwrap(),
            bindings: vec![ComponentProviderBinding::new(
                component(),
                ProviderCoordinate::new(
                    WorldId::new(1).unwrap(),
                    ProviderId::new(2).unwrap(),
                    ProviderGeneration::new(1).unwrap(),
                ),
            )],
        }
    }

    fn add_component_claim() -> CommandRequest {
        CommandRequest::AddComponentClaim {
            effect: effect(),
            component: component(),
            actor: actor(),
            claim: ClaimId::new(29).unwrap(),
            kind: cser_core::ClaimKindId::new(31).unwrap(),
            scope: ClaimScope::Logical,
            resource: ResourceId::new(37).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        }
    }

    #[test]
    fn protocol_identity_is_distinct_and_fail_closed() {
        assert_eq!(NXP3_MAGIC, *b"NXP3");
        assert_eq!(NXP3_VERSION_MAJOR, 3);
        assert_eq!(NXP3_VERSION_MINOR, 0);
        assert_eq!(
            PortalProtocolHeader::from_parts(*b"NXP2", 3, 0, 1),
            Err(PortalProtocolError::InvalidMagic)
        );
        assert_eq!(
            PortalProtocolHeader::from_parts(NXP3_MAGIC, 2, 0, 1),
            Err(PortalProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            PortalProtocolHeader::from_parts(NXP3_MAGIC, 3, 1, 1),
            Err(PortalProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            PortalProtocolHeader::new(0),
            Err(PortalProtocolError::InvalidRequestId)
        );
    }

    #[test]
    fn scoped_admission_is_supervisor_only() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));
        assert_eq!(
            portal.dispatch(PortalRequest::transact(1, admit()).unwrap()),
            Err(PortalDispatchError::Policy(
                PortalPolicyError::TrustedPathRequired(TrustedTransition::ScopedAdmission)
            ))
        );
        assert_eq!(owner.transacts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn scoped_composite_mutation_prefix_reaches_the_shared_owner() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));
        let commands = [
            add_component_claim(),
            CommandRequest::PrepareCompositeEffect {
                effect: effect(),
                actor: actor(),
            },
            CommandRequest::RecordComponentCommitIntent {
                effect: effect(),
                component: component(),
                actor: actor(),
                operation: digest(43),
            },
            CommandRequest::RecordCompositeCommitIntents {
                effect: effect(),
                actor: actor(),
                operations: vec![ComponentCommitOperation::new(component(), digest(44))],
            },
        ];

        for (index, command) in commands.into_iter().enumerate() {
            let request_id = u64::try_from(index).unwrap() + 1;
            let response = portal
                .dispatch(PortalRequest::transact(request_id, command).unwrap())
                .unwrap();
            assert_eq!(response.request_id(), request_id);
            assert!(matches!(response.body(), PortalResponseBody::Transition(_)));
        }
        assert_eq!(owner.transacts.load(Ordering::Acquire), 4);
    }

    #[test]
    fn supervisor_domain_and_retirement_requests_are_rejected_before_owner() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));
        let rejected = [
            (
                CommandRequest::FenceExecutor {
                    operation: operation(),
                    crashed: actor(),
                },
                TrustedTransition::Fence,
            ),
            (
                CommandRequest::Ready {
                    operation: operation(),
                    snapshot: SnapshotId::new(43).unwrap(),
                    successor: actor(),
                },
                TrustedTransition::Recovery,
            ),
            (
                CommandRequest::Rebind {
                    operation: operation(),
                    snapshot: SnapshotId::new(43).unwrap(),
                    successor: actor(),
                },
                TrustedTransition::Recovery,
            ),
            (
                CommandRequest::AdoptEffect {
                    effect: effect(),
                    successor: actor(),
                },
                TrustedTransition::Adoption,
            ),
            (
                CommandRequest::RebaseCompositePrecommitClaims {
                    effect: effect(),
                    actor: actor(),
                },
                TrustedTransition::Adoption,
            ),
            (
                CommandRequest::ClaimComponentSettlement {
                    effect: effect(),
                    component: component(),
                    claimant: actor(),
                },
                TrustedTransition::Settlement,
            ),
            (
                CommandRequest::BeginRevoke {
                    effect: effect(),
                    expected_actor: actor(),
                    authority_epoch: 1,
                },
                TrustedTransition::Revocation,
            ),
            (
                CommandRequest::CheckpointRecovery {
                    boot: BootGeneration::new(2).unwrap(),
                    journal: JournalGeneration::new(2).unwrap(),
                    device: DeviceGeneration::new(2).unwrap(),
                },
                TrustedTransition::FreshnessCheckpoint,
            ),
            (
                CommandRequest::ReleaseCompositeEffect { effect: effect() },
                TrustedTransition::Retirement,
            ),
            (
                CommandRequest::ReserveComponentReuse {
                    effect: effect(),
                    component: component(),
                    actor: actor(),
                    claim: ClaimId::new(53).unwrap(),
                    kind: cser_core::ClaimKindId::new(31).unwrap(),
                    scope: ClaimScope::Logical,
                    resource: ResourceId::new(37).unwrap(),
                    expected_generation: ResourceGeneration::new(1).unwrap(),
                    units: 1,
                    reuse_contract: digest(18),
                },
                TrustedTransition::ResourceReuse,
            ),
        ];

        for (index, (command, expected)) in rejected.into_iter().enumerate() {
            let result = portal.dispatch(
                PortalRequest::transact(u64::try_from(index).unwrap() + 1, command).unwrap(),
            );
            assert_eq!(
                result,
                Err(PortalDispatchError::Policy(
                    PortalPolicyError::TrustedPathRequired(expected)
                ))
            );
        }
        assert_eq!(owner.transacts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn queries_are_direct_core_projections_and_retries_are_not_cached() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));

        for query in [
            CoreQuery::CompositeEffect(effect()),
            CoreQuery::Component(effect(), component()),
            CoreQuery::ComponentClaims(effect(), component()),
            CoreQuery::Pressure,
        ] {
            let response = portal
                .dispatch(PortalRequest::observe(50, query).unwrap())
                .unwrap();
            let PortalResponseBody::Observation(observation) = response.body() else {
                panic!("query returned a transition");
            };
            assert_eq!(observation.stamp().revision(), 9);
            assert_eq!(observation.stamp().head(), digest(9));
            assert_eq!(observation.stamp().freshness(), freshness());
        }
        assert_eq!(owner.observations.load(Ordering::Acquire), 4);

        let request = PortalRequest::transact(60, admit()).unwrap();
        assert_eq!(
            portal.dispatch(request.clone()),
            Err(PortalDispatchError::Policy(
                PortalPolicyError::TrustedPathRequired(TrustedTransition::ScopedAdmission)
            ))
        );
        assert_eq!(
            portal.dispatch(request),
            Err(PortalDispatchError::Policy(
                PortalPolicyError::TrustedPathRequired(TrustedTransition::ScopedAdmission)
            ))
        );
        assert_eq!(owner.transacts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn registry_errors_propagate_without_an_adapter_side_receipt() {
        struct FailingRegistry;

        impl CoreRegistry for FailingRegistry {
            type Error = CoreError;

            fn transact(
                &self,
                _request: CommandRequest,
            ) -> Result<CoreTransitionView, Self::Error> {
                Err(CoreError::Backpressure)
            }

            fn observe(&self, _query: CoreQuery) -> Result<CoreObservation, Self::Error> {
                Err(CoreError::PersistenceRecoveryRequired)
            }
        }

        let portal = CorePortalVNext::new(Arc::new(FailingRegistry));
        assert_eq!(
            portal.dispatch(PortalRequest::transact(1, add_component_claim()).unwrap()),
            Err(PortalDispatchError::Registry(CoreError::Backpressure))
        );
        assert_eq!(
            portal.dispatch(PortalRequest::observe(2, CoreQuery::Pressure).unwrap()),
            Err(PortalDispatchError::Registry(
                CoreError::PersistenceRecoveryRequired
            ))
        );
    }
}
