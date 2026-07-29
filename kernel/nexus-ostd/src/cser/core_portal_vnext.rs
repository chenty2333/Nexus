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
//! admits estate creation, claim enrollment, preparation, and write-ahead
//! commit intent. Fencing, recovery, adoption, settlement, revocation,
//! freshness checkpoints, retirement, and resource reuse belong to trusted
//! supervisor or domain paths. Receipt-dependent transitions are represented
//! by linear [`cser_core::Command`] values and cannot enter this interface at
//! all.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::{sync::Arc, vec::Vec};
use cser_core::{
    ClaimProjection, CommandRequest, Digest, EffectId, EstateProjection, Freshness,
    PressureProjection, TransitionEvent,
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
    /// Project one exact estate by its stable identity.
    Estate(EffectId),
    /// Enumerate claims for one exact estate in stable claim-id order.
    Claims(EffectId),
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
    revision: u64,
    head: Digest,
    projection: Digest,
    event: TransitionEvent,
}

impl CoreTransitionView {
    /// Constructs a view after the owner has retained any linear output.
    pub(crate) const fn new(
        revision: u64,
        head: Digest,
        projection: Digest,
        event: TransitionEvent,
    ) -> Self {
        Self {
            revision,
            head,
            projection,
            event,
        }
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
    /// Exact estate projection, or absence at the observed revision.
    Estate {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Stable identity requested by the caller.
        effect: EffectId,
        /// Current core projection.
        estate: Option<EstateProjection>,
    },
    /// Exact claim set for one estate.
    Claims {
        /// Lock-consistent core coordinates.
        stamp: CoreObservationStamp,
        /// Stable identity requested by the caller.
        effect: EffectId,
        /// Current core projections in stable claim-id order.
        claims: Vec<ClaimProjection>,
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
            Self::Estate { stamp, .. }
            | Self::Claims { stamp, .. }
            | Self::Pressure { stamp, .. } => *stamp,
        }
    }
}

/// Trusted transition family which cannot enter the client portal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedTransition {
    /// Immediate incarnation fencing is supervisor-owned.
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
    /// Estate retirement and release require trusted evidence paths.
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
        CommandRequest::CreateEstate { .. }
        | CommandRequest::AddClaim { .. }
        | CommandRequest::PrepareEffect { .. }
        | CommandRequest::RecordCommitIntent { .. } => return Ok(()),
        CommandRequest::FenceIncarnation { .. } => TrustedTransition::Fence,
        CommandRequest::Ready { .. } | CommandRequest::Rebind { .. } => TrustedTransition::Recovery,
        CommandRequest::AdoptEffect { .. } => TrustedTransition::Adoption,
        CommandRequest::ClaimSettlement { .. } => TrustedTransition::Settlement,
        CommandRequest::BeginRevoke { .. } => TrustedTransition::Revocation,
        CommandRequest::CheckpointRecovery { .. } => TrustedTransition::FreshnessCheckpoint,
        CommandRequest::ReleaseEstate { .. } => TrustedTransition::Retirement,
        CommandRequest::ReserveReuse { .. } => TrustedTransition::ResourceReuse,
    };
    Err(PortalPolicyError::TrustedPathRequired(trusted))
}

#[cfg(test)]
mod tests {
    use __cser_alloc::sync::Arc;
    use __cser_core::sync::atomic::{AtomicUsize, Ordering};

    use cser_core::{
        BootGeneration, ChargeAccountId, ClaimId, ClaimScope, CommandRequest, CoreError,
        DeviceGeneration, DomainId, EffectId, Freshness, JournalGeneration, ObligationKindId,
        PrincipalId, PrincipalIncarnation, RegistryInstance, ResourceGeneration, ResourceId,
        RootId, SnapshotId, TransitionEvent,
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
                CommandRequest::CreateEstate { .. } => TransitionEvent::EstateCreated,
                CommandRequest::AddClaim { .. } => TransitionEvent::ClaimAdded,
                CommandRequest::PrepareEffect { .. } => TransitionEvent::EffectPrepared,
                CommandRequest::RecordCommitIntent { .. } => TransitionEvent::CommitIntentDurable,
                _ => return Err(CoreError::InvariantViolation),
            };
            Ok(CoreTransitionView::new(
                count as u64,
                digest(count as u8),
                digest((count + 32) as u8),
                event,
            ))
        }

        fn observe(&self, query: CoreQuery) -> Result<CoreObservation, Self::Error> {
            self.observations.fetch_add(1, Ordering::AcqRel);
            let stamp = CoreObservationStamp::new(9, digest(9), freshness());
            match query {
                CoreQuery::Estate(effect) => Ok(CoreObservation::Estate {
                    stamp,
                    effect,
                    estate: None,
                }),
                CoreQuery::Claims(effect) => Ok(CoreObservation::Claims {
                    stamp,
                    effect,
                    claims: Vec::new(),
                }),
                CoreQuery::Pressure => Ok(CoreObservation::Pressure {
                    stamp,
                    pressure: PressureProjection {
                        roots: 0,
                        estates: 0,
                        retained_claims: 0,
                        quarantined: false,
                        persistence_recovery_required: false,
                    },
                }),
            }
        }
    }

    fn root() -> RootId {
        RootId::new(7).unwrap()
    }

    fn effect() -> EffectId {
        EffectId::new(root(), 11).unwrap()
    }

    fn actor() -> PrincipalIncarnation {
        PrincipalIncarnation::new(PrincipalId::new(13).unwrap(), 2).unwrap()
    }

    fn digest(tag: u8) -> Digest {
        Digest::new([tag; 32])
    }

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(2).unwrap(),
            RegistryInstance::new(3).unwrap(),
            4,
            DeviceGeneration::new(5).unwrap(),
            JournalGeneration::new(6).unwrap(),
        )
        .unwrap()
    }

    fn create() -> CommandRequest {
        CommandRequest::CreateEstate {
            effect: effect(),
            origin: actor(),
            binding_generation: 4,
            domain: DomainId::new(17).unwrap(),
            obligation: ObligationKindId::new(19).unwrap(),
            charge_account: ChargeAccountId::new(23).unwrap(),
        }
    }

    fn add_claim() -> CommandRequest {
        CommandRequest::AddClaim {
            effect: effect(),
            actor: actor(),
            binding_generation: 4,
            claim: ClaimId::new(29).unwrap(),
            domain: DomainId::new(17).unwrap(),
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
    fn only_client_lifecycle_prefix_reaches_the_shared_owner() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));
        let commands = [
            create(),
            add_claim(),
            CommandRequest::PrepareEffect {
                effect: effect(),
                actor: actor(),
                binding_generation: 4,
            },
            CommandRequest::RecordCommitIntent {
                effect: effect(),
                actor: actor(),
                binding_generation: 4,
                operation: digest(41),
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
        assert_eq!(Arc::strong_count(&owner), 2);
    }

    #[test]
    fn supervisor_domain_and_retirement_requests_are_rejected_before_owner() {
        let owner = Arc::new(FakeRegistry::new());
        let portal = CorePortalVNext::new(Arc::clone(&owner));
        let rejected = [
            (
                CommandRequest::FenceIncarnation {
                    root: root(),
                    crashed: actor(),
                    binding_generation: 4,
                },
                TrustedTransition::Fence,
            ),
            (
                CommandRequest::Ready {
                    root: root(),
                    snapshot: SnapshotId::new(43).unwrap(),
                    successor: actor(),
                },
                TrustedTransition::Recovery,
            ),
            (
                CommandRequest::Rebind {
                    root: root(),
                    snapshot: SnapshotId::new(43).unwrap(),
                    successor: actor(),
                    binding_generation: 4,
                },
                TrustedTransition::Recovery,
            ),
            (
                CommandRequest::AdoptEffect {
                    effect: effect(),
                    successor: actor(),
                    binding_generation: 4,
                },
                TrustedTransition::Adoption,
            ),
            (
                CommandRequest::ClaimSettlement {
                    effect: effect(),
                    claimant: actor(),
                },
                TrustedTransition::Settlement,
            ),
            (
                CommandRequest::BeginRevoke {
                    effect: effect(),
                    expected_actor: actor(),
                    binding_generation: 4,
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
                CommandRequest::ReleaseEstate { effect: effect() },
                TrustedTransition::Retirement,
            ),
            (
                CommandRequest::ReserveReuse {
                    effect: effect(),
                    actor: actor(),
                    binding_generation: 4,
                    claim: ClaimId::new(47).unwrap(),
                    domain: DomainId::new(17).unwrap(),
                    kind: cser_core::ClaimKindId::new(31).unwrap(),
                    scope: ClaimScope::Logical,
                    resource: ResourceId::new(37).unwrap(),
                    expected_generation: ResourceGeneration::new(1).unwrap(),
                    units: 1,
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
            CoreQuery::Estate(effect()),
            CoreQuery::Claims(effect()),
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
        assert_eq!(owner.observations.load(Ordering::Acquire), 3);

        let request = PortalRequest::transact(60, create()).unwrap();
        portal.dispatch(request.clone()).unwrap();
        portal.dispatch(request).unwrap();
        assert_eq!(owner.transacts.load(Ordering::Acquire), 2);
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
            portal.dispatch(PortalRequest::transact(1, create()).unwrap()),
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
