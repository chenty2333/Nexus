//! Executable reference model for mediated VirtIO I/O revocation.
//!
//! The model fixes the Stage 5 protocol boundary: publishing `avail.idx` is
//! the externally visible commit point, a device reset is quiescence rather
//! than rollback, and DMA ownership survives every timeout until a completed
//! IOTLB invalidation permits release. It is a deterministic protocol oracle,
//! not a VirtIO transport, IOMMU implementation, or hardware model.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{ScopeId, ScopeState};

macro_rules! scalar_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Constructs a value from its numeric representation.
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
    };
}

scalar_type!(
    /// Authority generation closed only by `IoModel::revoke_begin`.
    AuthorityEpoch
);
scalar_type!(
    /// User-space I/O-service generation advanced only by `IoModel::crash`.
    BindingEpoch
);
scalar_type!(
    /// Device generation advanced only by an acknowledged whole-device reset.
    DeviceGeneration
);
scalar_type!(
    /// Stable identity of one user-space I/O service instance.
    IoServiceId
);
scalar_type!(
    /// Stable identity of one exclusively mediated VirtIO device.
    DeviceId
);
scalar_type!(
    /// Stable identity of the device's exclusively mediated split queue.
    QueueId
);
scalar_type!(
    /// Stable identity of one mediated request effect.
    RequestId
);
scalar_type!(
    /// Stable identity of one retained DMA lease.
    DmaLeaseId
);
scalar_type!(
    /// Stable identity of one IOMMU mapping.
    MappingId
);
scalar_type!(
    /// Abstract I/O virtual address of a DMA mapping.
    Iova
);

/// Independently conserved renewable resources retained by DMA leases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LeaseCredits {
    /// Virtqueue descriptor slots reserved by a request.
    pub queue_slots: u64,
    /// Physical pages pinned while the DMA lease remains retained.
    pub pinned_pages: u64,
    /// Bytes reachable through the retained DMA mapping.
    pub dma_bytes: u64,
}

impl LeaseCredits {
    /// A resource vector containing no renewable credits.
    pub const ZERO: Self = Self::new(0, 0, 0);

    /// Constructs a typed renewable-resource vector.
    #[must_use]
    pub const fn new(queue_slots: u64, pinned_pages: u64, dma_bytes: u64) -> Self {
        Self {
            queue_slots,
            pinned_pages,
            dma_bytes,
        }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            queue_slots: self.queue_slots.checked_add(other.queue_slots)?,
            pinned_pages: self.pinned_pages.checked_add(other.pinned_pages)?,
            dma_bytes: self.dma_bytes.checked_add(other.dma_bytes)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            queue_slots: self.queue_slots.checked_sub(other.queue_slots)?,
            pinned_pages: self.pinned_pages.checked_sub(other.pinned_pages)?,
            dma_bytes: self.dma_bytes.checked_sub(other.dma_bytes)?,
        })
    }

    fn contains(self, other: Self) -> bool {
        self.queue_slots >= other.queue_slots
            && self.pinned_pages >= other.pinned_pages
            && self.dma_bytes >= other.dma_bytes
    }
}

/// Non-renewable charges consumed when a request publishes `avail.idx`.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommitCharges(u64);

impl CommitCharges {
    /// No commit charges.
    pub const ZERO: Self = Self(0);

    /// Constructs a commit-charge balance.
    #[must_use]
    pub const fn new(charges: u64) -> Self {
        Self(charges)
    }

    /// Returns the number of commit charges.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Initial typed capacity of one mediated-I/O authority scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoBudget {
    /// Renewable queue, pin, and DMA capacity.
    pub leases: LeaseCredits,
    /// Non-renewable external-publication capacity.
    pub commit_charges: CommitCharges,
}

impl IoBudget {
    /// Constructs a typed scope budget.
    #[must_use]
    pub const fn new(leases: LeaseCredits, commit_charges: CommitCharges) -> Self {
        Self {
            leases,
            commit_charges,
        }
    }
}

/// Resources reserved atomically when one request is registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestGrant {
    /// Renewable resources held until synchronous invalidation completes.
    pub lease: LeaseCredits,
    /// Charge held before publication and spent at `avail.idx` publication.
    pub commit_charge: CommitCharges,
}

impl RequestGrant {
    /// Constructs one request grant.
    #[must_use]
    pub const fn new(lease: LeaseCredits, commit_charge: CommitCharges) -> Self {
        Self {
            lease,
            commit_charge,
        }
    }
}

/// Full identity retained for one DMA mapping until synchronous invalidation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DmaIdentity {
    lease: DmaLeaseId,
    mapping: MappingId,
    iova: Iova,
}

impl DmaIdentity {
    /// Constructs one DMA identity tuple.
    #[must_use]
    pub const fn new(lease: DmaLeaseId, mapping: MappingId, iova: Iova) -> Self {
        Self {
            lease,
            mapping,
            iova,
        }
    }

    /// Returns the lease identity.
    #[must_use]
    pub const fn lease(self) -> DmaLeaseId {
        self.lease
    }

    /// Returns the IOMMU mapping identity.
    #[must_use]
    pub const fn mapping(self) -> MappingId {
        self.mapping
    }

    /// Returns the abstract I/O virtual address.
    #[must_use]
    pub const fn iova(self) -> Iova {
        self.iova
    }
}

/// Lifecycle of one mediated I/O effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoEffectState {
    /// Authority, typed budget, and a DMA identity are reserved.
    Registered,
    /// Descriptors are constructed but `avail.idx` is not published.
    Prepared,
    /// `avail.idx` was release-published and the device may observe the request.
    Committed,
    /// An unpublished DMA mapping is being synchronously invalidated.
    Cancelling,
    /// A matching current-generation completion terminalized the request.
    Completed,
    /// An unpublished request was cancelled after the publish gate closed.
    Cancelled,
    /// Reset stopped future DMA, but the external outcome is not knowable.
    IndeterminateAfterReset,
}

impl IoEffectState {
    /// Returns whether the effect has one immutable terminal outcome.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::IndeterminateAfterReset
        )
    }
}

/// Accounting disposition of a request's non-renewable commit charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDisposition {
    /// The unpublished request exclusively reserves the charge.
    Held,
    /// `avail.idx` publication consumed the charge; reset cannot refund it.
    Spent,
    /// Cancellation returned the never-published charge.
    Returned,
}

/// Safety state of one queue or request DMA lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaLeaseState {
    /// Credits and identity are reserved, but no IOMMU mapping exists yet.
    Absent,
    /// The IOMMU mapping exists and its backing resources are retained.
    Mapped,
    /// Page-table entries were removed, but IOTLB completion is outstanding.
    UnmappedAwaitingInvalidation,
    /// Synchronous invalidation completed and resources may be reused.
    Released,
}

/// Lifecycle of the kernel fallback and replacement service handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoFallbackState {
    /// A live user-space I/O service is bound.
    Standby,
    /// A service crash was fenced and kernel fallback selection is required.
    Required,
    /// The kernel fallback owns committed work and may issue a snapshot.
    Running,
    /// A replacement accepted a fresh snapshot and may be installed.
    ReplacementReady,
}

/// Public reset progress of a closing device scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetState {
    /// Active scope has not requested device closure.
    Idle,
    /// Revocation closed submissions and requires a whole-device reset.
    Required,
    /// One reset command is awaiting acknowledgement or timeout.
    InFlight,
    /// The command timed out and retained ownership is represented by a tombstone.
    TimedOut,
    /// Reset acknowledgement established device quiescence.
    Acknowledged,
}

/// Public synchronous-IOTLB-invalidation progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationState {
    /// DMA mappings have not been removed.
    NotStarted,
    /// Unmap and invalidation were issued; completion is outstanding.
    InFlight,
    /// Invalidation timed out and all DMA ownership remains retained.
    TimedOut,
    /// Invalidation completion made every lease releasable.
    Acknowledged,
}

/// One independently invalidated DMA lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvalidateTarget {
    /// The scope-owned split-queue mapping.
    Queue,
    /// One request buffer/descriptor mapping.
    Request(RequestId),
}

/// Opaque proof of the service currently bound to an active I/O scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBindingToken {
    scope: ScopeId,
    service: IoServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
}

impl IoBindingToken {
    /// Returns the bound scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the service identity.
    #[must_use]
    pub const fn service(self) -> IoServiceId {
        self.service
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the captured binding generation.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }
}

/// Full fenced identity of one user-space-mediated request operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestToken {
    scope: ScopeId,
    request: RequestId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device: DeviceId,
    queue: QueueId,
    device_generation: DeviceGeneration,
}

impl RequestToken {
    /// Returns the owning scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.scope
    }

    /// Returns the stable request identity.
    #[must_use]
    pub const fn request(self) -> RequestId {
        self.request
    }

    /// Returns the captured authority generation.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the binding generation currently owning unpublished work.
    #[must_use]
    pub const fn binding_epoch(self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the mediated device identity.
    #[must_use]
    pub const fn device(self) -> DeviceId {
        self.device
    }

    /// Returns the mediated queue identity.
    #[must_use]
    pub const fn queue(self) -> QueueId {
        self.queue
    }

    /// Returns the device generation in which publication may occur.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// Kernel-authenticated device completion message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceCompletion {
    scope: ScopeId,
    request: RequestId,
    device: DeviceId,
    queue: QueueId,
    device_generation: DeviceGeneration,
}

impl DeviceCompletion {
    /// Returns the completed request identity.
    #[must_use]
    pub const fn request(self) -> RequestId {
        self.request
    }

    /// Returns the device generation observed by the completion.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// One orphaned unpublished request in a replacement snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoRequestSnapshot {
    /// Request identity before explicit adoption.
    pub token: RequestToken,
    /// Either `Registered` or `Prepared`.
    pub state: IoEffectState,
    /// DMA identity retained across service failure.
    pub dma: DmaIdentity,
    /// Typed grant retained across service failure.
    pub grant: RequestGrant,
}

/// Immutable recovery snapshot used by the replacement readiness handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoRecoverySnapshot {
    scope: ScopeId,
    service: IoServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    recovery_revision: u64,
    requests: Vec<IoRequestSnapshot>,
}

impl IoRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the replacement service identity.
    #[must_use]
    pub const fn service(&self) -> IoServiceId {
        self.service
    }

    /// Returns the orphaned unpublished request cohort.
    #[must_use]
    pub fn requests(&self) -> &[IoRequestSnapshot] {
        &self.requests
    }
}

/// Opaque proof that a replacement accepted a still-fresh snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoReadyToken {
    scope: ScopeId,
    service: IoServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    recovery_revision: u64,
}

/// Opaque identity of one in-flight whole-device reset command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetAttempt {
    scope: ScopeId,
    attempt: u64,
    device_generation: DeviceGeneration,
}

impl ResetAttempt {
    /// Returns the reset attempt sequence number.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.attempt
    }

    /// Returns the pre-reset device generation.
    #[must_use]
    pub const fn device_generation(self) -> DeviceGeneration {
        self.device_generation
    }
}

/// Opaque identity of one in-flight synchronous IOTLB invalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidateAttempt {
    scope: ScopeId,
    target: InvalidateTarget,
    attempt: u64,
    device_generation: DeviceGeneration,
}

impl InvalidateAttempt {
    /// Returns the independently invalidated lease.
    #[must_use]
    pub const fn target(self) -> InvalidateTarget {
        self.target
    }

    /// Returns the invalidation attempt sequence number.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.attempt
    }
}

/// DMA ownership retained by a timeout tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedDmaSummary {
    /// Whether the operation's causal subset includes the retained queue mapping.
    pub queue_lease: bool,
    /// Number of retained request mappings in the operation's causal subset.
    pub request_leases: usize,
    /// Renewable resources owned by the queue/request leases listed above.
    pub lease_credits: LeaseCredits,
    /// Scope-wide snapshot of unpublished commit charges still held pending cancellation.
    pub held_commit_charges: CommitCharges,
}

/// Linear retained ownership returned by a reset timeout.
///
/// The type is intentionally neither `Copy` nor `Clone`. Dropping it cannot
/// release anything: the model keeps the leases retained and the scope in
/// `Closing`. Its retained DMA subset is the queue plus device-visible
/// committed requests; never-published requests remain separate cancellation
/// and invalidation obligations. Only `retry_reset` consumes the witness and
/// starts new reset work.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a reset timeout retains DMA ownership until retry succeeds"]
pub struct ResetTombstone {
    scope: ScopeId,
    failed_attempt: u64,
    device_generation: DeviceGeneration,
    retained: RetainedDmaSummary,
}

impl ResetTombstone {
    /// Returns the closing scope whose ownership is retained.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the failed reset attempt sequence number.
    #[must_use]
    pub const fn failed_attempt(&self) -> u64 {
        self.failed_attempt
    }

    /// Returns the retained DMA and credit summary.
    #[must_use]
    pub const fn retained(&self) -> RetainedDmaSummary {
        self.retained
    }
}

/// Linear retained ownership returned by an invalidation timeout.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "an invalidation timeout retains DMA ownership until retry succeeds"]
pub struct InvalidateTombstone {
    scope: ScopeId,
    target: InvalidateTarget,
    failed_attempt: u64,
    device_generation: DeviceGeneration,
    retained: RetainedDmaSummary,
}

impl InvalidateTombstone {
    /// Returns the closing scope whose ownership is retained.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the independently retained lease.
    #[must_use]
    pub const fn target(&self) -> InvalidateTarget {
        self.target
    }

    /// Returns the failed invalidation attempt sequence number.
    #[must_use]
    pub const fn failed_attempt(&self) -> u64 {
        self.failed_attempt
    }

    /// Returns the retained DMA and credit summary.
    #[must_use]
    pub const fn retained(&self) -> RetainedDmaSummary {
        self.retained
    }
}

/// Error that returns a reset tombstone instead of dropping retained ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct ResetRetryError {
    error: IoError,
    tombstone: ResetTombstone,
}

impl ResetRetryError {
    /// Returns the protocol rejection.
    #[must_use]
    pub const fn error(&self) -> IoError {
        self.error
    }

    /// Recovers the retained-ownership witness.
    pub fn into_tombstone(self) -> ResetTombstone {
        self.tombstone
    }
}

/// Error that returns an invalidation tombstone instead of dropping ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidateRetryError {
    error: IoError,
    tombstone: InvalidateTombstone,
}

impl InvalidateRetryError {
    /// Returns the protocol rejection.
    #[must_use]
    pub const fn error(&self) -> IoError {
        self.error
    }

    /// Recovers the retained-ownership witness.
    pub fn into_tombstone(self) -> InvalidateTombstone {
        self.tombstone
    }
}

/// Read-only projection of one mediated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoRequestView {
    /// Current full request token, updated only by explicit adoption.
    pub token: RequestToken,
    /// Effect lifecycle.
    pub state: IoEffectState,
    /// Typed request grant.
    pub grant: RequestGrant,
    /// Commit-charge accounting disposition.
    pub commit_disposition: CommitDisposition,
    /// Retained DMA identity.
    pub dma: DmaIdentity,
    /// DMA lease safety state.
    pub dma_state: DmaLeaseState,
    /// Per-request synchronous invalidation progress.
    pub invalidation: InvalidationState,
    /// Number of successful `avail.idx` publications.
    pub avail_publications: u8,
    /// Whether the optional notification hint was sent.
    pub notified: bool,
    /// Whether this request still owns a descriptor slot in the live queue.
    pub queue_slot_owned: bool,
    /// Number of immutable terminal outcomes.
    pub terminalizations: u8,
}

/// Read-only projection of the scope-owned split queue lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLeaseView {
    /// Queue identity.
    pub queue: QueueId,
    /// Queue DMA identity.
    pub dma: DmaIdentity,
    /// Queue mapping safety state.
    pub dma_state: DmaLeaseState,
    /// Queue-specific synchronous invalidation progress.
    pub invalidation: InvalidationState,
    /// Renewable credits retained by the queue mapping.
    pub credits: LeaseCredits,
}

/// Scope-local work accounting for bounded revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoRevocationProgress {
    /// Authority generation closed by `RevokeBegin`.
    pub closed_epoch: AuthorityEpoch,
    /// Requests in this scope at the revocation linearization point.
    pub target_count: usize,
    /// Unpublished requests visited by `CancelUnpublished`.
    pub cancel_steps: usize,
    /// Entries actually selected from the unpublished-work index.
    pub cancel_index_visits: usize,
    /// Live-obligation entries actually examined by `ResetAck`.
    pub reset_index_visits: usize,
    /// Committed effects terminalized by `ResetAck`.
    pub reset_terminalizations: usize,
    /// Request DMA leases released by `InvalidateAck`.
    pub invalidated_request_leases: usize,
}

/// Read-only projection of one mediated-I/O scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoScopeView {
    /// Scope lifecycle.
    pub state: ScopeState,
    /// Current authority generation.
    pub authority_epoch: AuthorityEpoch,
    /// Current service-binding generation.
    pub binding_epoch: BindingEpoch,
    /// Current reset-fenced device generation.
    pub device_generation: DeviceGeneration,
    /// Exclusively owned device.
    pub device: DeviceId,
    /// Exclusively owned queue.
    pub queue: QueueId,
    /// Current service binding, if any.
    pub service: Option<IoServiceId>,
    /// Kernel fallback/replacement lifecycle.
    pub fallback: IoFallbackState,
    /// Immutable typed initial budget.
    pub initial_budget: IoBudget,
    /// Renewable credits not retained by queue or request DMA.
    pub free_lease_credits: LeaseCredits,
    /// Commit charges available for registration.
    pub free_commit_charges: CommitCharges,
    /// Commit charges held by unpublished requests.
    pub held_commit_charges: CommitCharges,
    /// Commit charges consumed at `avail.idx` publication.
    pub spent_commit_charges: CommitCharges,
    /// Current abstract split-ring `avail.idx` value.
    pub avail_idx: u64,
    /// Immutable request records retained only as protocol history/query data.
    pub historical_requests: usize,
    /// Request cleanup obligations retained in the scope-local reverse index.
    pub live_obligations: usize,
    /// Unpublished requests selectable without scanning committed or historical work.
    pub unpublished_obligations: usize,
    /// Requests that have not yet acquired exactly one terminal outcome.
    pub nonterminal_requests: usize,
    /// Descriptor-slot obligations that must be cleared before queue teardown.
    pub queue_slot_obligations: usize,
    /// Whether reset acknowledgement established device quiescence.
    pub device_quiesced: bool,
    /// Whole-device reset progress.
    pub reset: ResetState,
    /// Queue-lease synchronous invalidation progress.
    pub invalidation: InvalidationState,
    /// Scope-local revocation work accounting.
    pub revocation: Option<IoRevocationProgress>,
}

/// Stable operation vocabulary shared with the finite successor specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoAction {
    /// Create an exclusive mediated device/queue scope.
    CreateScope,
    /// Reserve one request grant and DMA identity.
    Register,
    /// Finish descriptors without publishing them.
    Prepare,
    /// Fence a crashed user-space service.
    Crash,
    /// Select the kernel fallback.
    FallbackPick,
    /// Accept replacement readiness from a fresh snapshot.
    Ready,
    /// Install the ready replacement service.
    Rebind,
    /// Explicitly transfer unpublished work to the replacement binding.
    Adopt,
    /// Release-publish `avail.idx`, the request commit point.
    PublishAvail,
    /// Send an optional post-commit device notification hint.
    Notify,
    /// Accept one matching current-generation device completion.
    DeviceComplete,
    /// Close the publication gate and authority generation.
    RevokeBegin,
    /// Terminalize one unpublished effect as cancelled.
    CancelUnpublished,
    /// Issue a whole-device reset.
    BeginReset,
    /// Acknowledge reset and terminalize outstanding committed work.
    ResetAck,
    /// Retain all ownership after a reset timeout.
    ResetTimeout,
    /// Reissue reset from a retained tombstone.
    RetryReset,
    /// Remove DMA mappings and issue synchronous IOTLB invalidation.
    BeginInvalidate,
    /// Complete invalidation and release every DMA lease.
    InvalidateAck,
    /// Retain all ownership after invalidation timeout.
    InvalidateTimeout,
    /// Reissue invalidation from a retained tombstone.
    RetryInvalidate,
    /// Publish closure after every safety obligation is discharged.
    RevokeComplete,
}

/// One successful operation in the model's total linearization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoTraceEvent {
    /// Zero-based total-order position.
    pub seq: usize,
    /// Operation that linearized.
    pub action: IoAction,
    /// Scope affected by the operation.
    pub scope: ScopeId,
    /// Request affected by the operation, when applicable.
    pub request: Option<RequestId>,
    /// Authority generation immediately after the operation.
    pub authority_epoch: AuthorityEpoch,
    /// Binding generation immediately after the operation.
    pub binding_epoch: BindingEpoch,
    /// Device generation immediately after the operation.
    pub device_generation: DeviceGeneration,
}

/// Rejected mediated-I/O model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoError {
    /// The requested scope does not exist.
    UnknownScope(ScopeId),
    /// The requested request does not exist.
    UnknownRequest(RequestId),
    /// The device is already owned by another non-revoked scope.
    DeviceInUse(DeviceId),
    /// The queue is already owned by another non-revoked scope.
    QueueInUse(QueueId),
    /// A DMA lease, mapping, or IOVA identity is still retained.
    DmaIdentityInUse(DmaIdentity),
    /// The scope is not in the required lifecycle state.
    InvalidScopeState {
        /// Actual scope state.
        state: ScopeState,
    },
    /// The request is not in the state required by the operation.
    InvalidRequestState {
        /// Actual request state.
        state: IoEffectState,
    },
    /// The authority generation was closed by revocation.
    StaleAuthority {
        /// Presented generation.
        presented: AuthorityEpoch,
        /// Current generation.
        current: AuthorityEpoch,
    },
    /// A former service binding attempted to act after crash fencing.
    StaleBinding {
        /// Presented generation.
        presented: BindingEpoch,
        /// Current generation.
        current: BindingEpoch,
    },
    /// An orphan request has not been explicitly adopted.
    RequestBindingFenced {
        /// Generation still owning the request.
        request_binding: BindingEpoch,
        /// Current scope binding generation.
        current_binding: BindingEpoch,
    },
    /// A completion or publication names a reset-fenced device generation.
    StaleDeviceGeneration {
        /// Presented generation.
        presented: DeviceGeneration,
        /// Current generation.
        current: DeviceGeneration,
    },
    /// A binding token names a service other than the installed service.
    WrongService,
    /// No user-space service is currently bound.
    ServiceUnavailable,
    /// A live service is already bound.
    ServiceAlreadyBound,
    /// The kernel fallback is not at the required handshake stage.
    FallbackUnavailable,
    /// A recovery snapshot changed before readiness or rebind.
    StaleRecoverySnapshot,
    /// The request token differs from the kernel record.
    RequestIdentityMismatch,
    /// The request is not orphaned unpublished work eligible for adoption.
    NotAdoptable,
    /// A request grant lacks exactly one slot, pinned memory, DMA bytes, or charge.
    InvalidGrant,
    /// A queue DMA lease lacks pins/bytes or incorrectly consumes request slots.
    InvalidQueueLease,
    /// Typed lease capacity is insufficient.
    LeaseBudgetExhausted {
        /// Requested renewable credits.
        requested: LeaseCredits,
        /// Currently free renewable credits.
        available: LeaseCredits,
    },
    /// Commit-charge capacity is insufficient.
    CommitBudgetExhausted {
        /// Requested commit charges.
        requested: CommitCharges,
        /// Currently free commit charges.
        available: CommitCharges,
    },
    /// The request has already crossed the `avail.idx` commit point.
    AlreadyPublished,
    /// The optional notification was attempted before publication.
    NotifyBeforePublish,
    /// The optional notification hint was already issued once.
    AlreadyNotified,
    /// The request already has an immutable terminal outcome.
    AlreadyTerminal,
    /// Reset is not in the state required by the operation.
    InvalidResetState {
        /// Actual reset state.
        state: ResetState,
    },
    /// A reset response or tombstone names an old attempt.
    StaleResetAttempt,
    /// Device reset has not established quiescence.
    DeviceNotQuiescent,
    /// Request descriptor slots still refer to the queue being torn down.
    QueueSlotsOutstanding {
        /// Number of requests that still own a live queue slot.
        remaining: usize,
    },
    /// Invalidation is not in the state required by the operation.
    InvalidInvalidationState {
        /// Actual invalidation state.
        state: InvalidationState,
    },
    /// An invalidation response or tombstone names an old attempt.
    StaleInvalidateAttempt,
    /// Closure was requested before all obligations were discharged.
    RevocationNotQuiescent,
    /// A monotonically increasing identity or generation overflowed.
    CounterOverflow,
    /// Internal state relationships were inconsistent.
    InvariantViolation(&'static str),
}

/// Failure reported by a full model invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoInvariantViolation {
    /// Renewable lease credits are not conserved.
    LeaseBudgetConservation(ScopeId),
    /// Commit charges are not conserved.
    CommitBudgetConservation(ScopeId),
    /// Effect state and commit-charge disposition disagree.
    RequestChargeState(RequestId),
    /// Publication count or notification state disagrees with effect state.
    PublicationState(RequestId),
    /// Terminal effects did not terminalize exactly once.
    Terminalization(RequestId),
    /// Scope reverse index differs from its nonterminal requests.
    LiveReverseIndex(ScopeId),
    /// Scope unpublished-work index differs from registered/prepared work.
    UnpublishedReverseIndex(ScopeId),
    /// Incremental terminalization count differs from request history.
    NonterminalCount(ScopeId),
    /// Queue-slot reverse index differs from prepared/committed work.
    QueueSlotIndex(ScopeId),
    /// A request is missing from or mismatched with its scope.
    OrphanRequest(RequestId),
    /// A request carries a generation newer than its scope.
    FutureGeneration(RequestId),
    /// DMA lease state and invalidation progress disagree.
    DmaLeaseSafety(ScopeId),
    /// A retained DMA identity is missing from the global ownership indexes.
    DmaIdentityIndex(DmaIdentity),
    /// Global DMA ownership indexes contain a missing or orphaned identity.
    DmaOwnershipIndex,
    /// Device or queue exclusive-ownership index disagrees with scope state.
    ExclusiveOwner(ScopeId),
    /// Reset state, device generation, and quiescence disagree.
    ResetState(ScopeId),
    /// Revocation metadata disagrees with scope lifecycle.
    RevocationState(ScopeId),
    /// A revoked scope still has an outstanding obligation.
    RevokedScope(ScopeId),
    /// Service presence and fallback metadata disagree.
    FallbackState(ScopeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyRecord {
    service: IoServiceId,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    recovery_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetRecord {
    Idle,
    Required,
    InFlight {
        attempt: u64,
        device_generation: DeviceGeneration,
    },
    TimedOut {
        attempt: u64,
        device_generation: DeviceGeneration,
    },
    Acknowledged,
}

impl ResetRecord {
    const fn view(self) -> ResetState {
        match self {
            Self::Idle => ResetState::Idle,
            Self::Required => ResetState::Required,
            Self::InFlight { .. } => ResetState::InFlight,
            Self::TimedOut { .. } => ResetState::TimedOut,
            Self::Acknowledged => ResetState::Acknowledged,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidationRecord {
    NotStarted,
    InFlight {
        attempt: u64,
        device_generation: DeviceGeneration,
    },
    TimedOut {
        attempt: u64,
        device_generation: DeviceGeneration,
    },
    Acknowledged,
}

impl InvalidationRecord {
    const fn view(self) -> InvalidationState {
        match self {
            Self::NotStarted => InvalidationState::NotStarted,
            Self::InFlight { .. } => InvalidationState::InFlight,
            Self::TimedOut { .. } => InvalidationState::TimedOut,
            Self::Acknowledged => InvalidationState::Acknowledged,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueLeaseRecord {
    queue: QueueId,
    dma: DmaIdentity,
    state: DmaLeaseState,
    invalidation: InvalidationRecord,
    credits: LeaseCredits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestRecord {
    token: RequestToken,
    state: IoEffectState,
    grant: RequestGrant,
    commit_disposition: CommitDisposition,
    dma: DmaIdentity,
    dma_state: DmaLeaseState,
    invalidation: InvalidationRecord,
    avail_publications: u8,
    notified: bool,
    queue_slot_owned: bool,
    terminalizations: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevocationRecord {
    closed_epoch: AuthorityEpoch,
    target_count: usize,
    cancel_steps: usize,
    cancel_index_visits: usize,
    reset_index_visits: usize,
    reset_terminalizations: usize,
    invalidated_request_leases: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IoScopeRecord {
    state: ScopeState,
    authority_epoch: AuthorityEpoch,
    binding_epoch: BindingEpoch,
    device_generation: DeviceGeneration,
    device: DeviceId,
    queue: QueueId,
    service: Option<IoServiceId>,
    fallback: IoFallbackState,
    ready: Option<ReadyRecord>,
    recovery_revision: u64,
    initial_budget: IoBudget,
    free_lease_credits: LeaseCredits,
    free_commit_charges: CommitCharges,
    held_commit_charges: CommitCharges,
    spent_commit_charges: CommitCharges,
    queue_lease: QueueLeaseRecord,
    requests: BTreeSet<RequestId>,
    live_obligations: BTreeSet<RequestId>,
    unpublished_obligations: BTreeSet<RequestId>,
    nonterminal_requests: usize,
    queue_slot_obligations: BTreeSet<RequestId>,
    avail_idx: u64,
    device_quiesced: bool,
    reset: ResetRecord,
    next_attempt: u64,
    revocation: Option<RevocationRecord>,
}

/// Deterministic `no_std + alloc` mediated VirtIO reference model.
///
/// Concurrent actors are represented by invoking atomic methods in alternate
/// orders. Failed methods perform no mutation, so commit/revoke,
/// completion/reset, and timeout/retry orders can be compared directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoModel {
    next_scope: u64,
    next_request: u64,
    scopes: BTreeMap<ScopeId, IoScopeRecord>,
    requests: BTreeMap<RequestId, RequestRecord>,
    device_owners: BTreeMap<DeviceId, ScopeId>,
    queue_owners: BTreeMap<QueueId, ScopeId>,
    issued_dma_leases: BTreeSet<DmaLeaseId>,
    issued_mappings: BTreeSet<MappingId>,
    active_dma_leases: BTreeSet<DmaLeaseId>,
    active_mappings: BTreeSet<MappingId>,
    active_iovas: BTreeSet<Iova>,
    trace: Vec<IoTraceEvent>,
}

impl Default for IoModel {
    fn default() -> Self {
        Self::new()
    }
}

impl IoModel {
    /// Creates an empty mediated-I/O model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_request: 1,
            scopes: BTreeMap::new(),
            requests: BTreeMap::new(),
            device_owners: BTreeMap::new(),
            queue_owners: BTreeMap::new(),
            issued_dma_leases: BTreeSet::new(),
            issued_mappings: BTreeSet::new(),
            active_dma_leases: BTreeSet::new(),
            active_mappings: BTreeSet::new(),
            active_iovas: BTreeSet::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active scope that exclusively owns one device and queue.
    pub fn create_scope(
        &mut self,
        service: IoServiceId,
        device: DeviceId,
        queue: QueueId,
        initial_budget: IoBudget,
        queue_dma: DmaIdentity,
        queue_credits: LeaseCredits,
    ) -> Result<(ScopeId, IoBindingToken), IoError> {
        if queue_credits.queue_slots != 0
            || queue_credits.pinned_pages == 0
            || queue_credits.dma_bytes == 0
        {
            return Err(IoError::InvalidQueueLease);
        }
        if self.device_owners.contains_key(&device) {
            return Err(IoError::DeviceInUse(device));
        }
        if self.queue_owners.contains_key(&queue) {
            return Err(IoError::QueueInUse(queue));
        }
        self.validate_dma_available(queue_dma)?;
        if !initial_budget.leases.contains(queue_credits) {
            return Err(IoError::LeaseBudgetExhausted {
                requested: queue_credits,
                available: initial_budget.leases,
            });
        }
        let free_lease_credits = initial_budget
            .leases
            .checked_sub(queue_credits)
            .ok_or(IoError::InvariantViolation("queue lease budget underflow"))?;
        let scope = ScopeId::new(self.next_scope);
        let next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);
        let device_generation = DeviceGeneration::new(1);
        self.next_scope = next_scope;
        self.reserve_dma(queue_dma);
        self.device_owners.insert(device, scope);
        self.queue_owners.insert(queue, scope);
        self.scopes.insert(
            scope,
            IoScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                binding_epoch,
                device_generation,
                device,
                queue,
                service: Some(service),
                fallback: IoFallbackState::Standby,
                ready: None,
                recovery_revision: 0,
                initial_budget,
                free_lease_credits,
                free_commit_charges: initial_budget.commit_charges,
                held_commit_charges: CommitCharges::ZERO,
                spent_commit_charges: CommitCharges::ZERO,
                queue_lease: QueueLeaseRecord {
                    queue,
                    dma: queue_dma,
                    state: DmaLeaseState::Mapped,
                    invalidation: InvalidationRecord::NotStarted,
                    credits: queue_credits,
                },
                requests: BTreeSet::new(),
                live_obligations: BTreeSet::new(),
                unpublished_obligations: BTreeSet::new(),
                nonterminal_requests: 0,
                queue_slot_obligations: BTreeSet::new(),
                avail_idx: 0,
                device_quiesced: false,
                reset: ResetRecord::Idle,
                next_attempt: 1,
                revocation: None,
            },
        );
        self.push_trace(IoAction::CreateScope, scope, None);
        Ok((
            scope,
            IoBindingToken {
                scope,
                service,
                authority_epoch,
                binding_epoch,
            },
        ))
    }

    /// Registers one request and reserves its typed grant and DMA identity.
    pub fn register(
        &mut self,
        binding: IoBindingToken,
        grant: RequestGrant,
        dma: DmaIdentity,
    ) -> Result<RequestToken, IoError> {
        if grant.lease.queue_slots != 1
            || grant.lease.pinned_pages == 0
            || grant.lease.dma_bytes == 0
            || grant.commit_charge == CommitCharges::ZERO
        {
            return Err(IoError::InvalidGrant);
        }
        self.validate_dma_available(dma)?;
        let scope = self.validate_binding(binding)?;
        if !scope.free_lease_credits.contains(grant.lease) {
            return Err(IoError::LeaseBudgetExhausted {
                requested: grant.lease,
                available: scope.free_lease_credits,
            });
        }
        if scope.free_commit_charges.get() < grant.commit_charge.get() {
            return Err(IoError::CommitBudgetExhausted {
                requested: grant.commit_charge,
                available: scope.free_commit_charges,
            });
        }
        let free_lease = scope.free_lease_credits.checked_sub(grant.lease).ok_or(
            IoError::InvariantViolation("request lease budget underflow"),
        )?;
        let free_commit = scope
            .free_commit_charges
            .get()
            .checked_sub(grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation("commit budget underflow"))?;
        let held_commit = scope
            .held_commit_charges
            .get()
            .checked_add(grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let nonterminal_requests = scope
            .nonterminal_requests
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request = RequestId::new(self.next_request);
        let next_request = self
            .next_request
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let token = RequestToken {
            scope: binding.scope,
            request,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            device: scope.device,
            queue: scope.queue,
            device_generation: scope.device_generation,
        };

        self.next_request = next_request;
        self.reserve_dma(dma);
        self.requests.insert(
            request,
            RequestRecord {
                token,
                state: IoEffectState::Registered,
                grant,
                commit_disposition: CommitDisposition::Held,
                dma,
                dma_state: DmaLeaseState::Absent,
                invalidation: InvalidationRecord::NotStarted,
                avail_publications: 0,
                notified: false,
                queue_slot_owned: false,
                terminalizations: 0,
            },
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(IoError::UnknownScope(binding.scope))?;
        scope.free_lease_credits = free_lease;
        scope.free_commit_charges = CommitCharges::new(free_commit);
        scope.held_commit_charges = CommitCharges::new(held_commit);
        scope.nonterminal_requests = nonterminal_requests;
        scope.recovery_revision = revision;
        scope.requests.insert(request);
        scope.live_obligations.insert(request);
        scope.unpublished_obligations.insert(request);
        self.push_trace(IoAction::Register, binding.scope, Some(request));
        Ok(token)
    }

    /// Completes descriptor construction without crossing the commit point.
    pub fn prepare(&mut self, binding: IoBindingToken, token: RequestToken) -> Result<(), IoError> {
        self.validate_current_reply(binding, token)?;
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state != IoEffectState::Registered {
            return Err(if request.state.is_terminal() {
                IoError::AlreadyTerminal
            } else {
                IoError::InvalidRequestState {
                    state: request.state,
                }
            });
        }
        if request.dma_state != DmaLeaseState::Absent
            || request.invalidation != InvalidationRecord::NotStarted
            || request.queue_slot_owned
        {
            return Err(IoError::InvariantViolation(
                "registered request does not own one reserved DMA identity",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        if scope.queue_slot_obligations.contains(&token.request) {
            return Err(IoError::InvariantViolation(
                "registered request already owns a queue slot",
            ));
        }
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request = self
            .requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        request.state = IoEffectState::Prepared;
        request.dma_state = DmaLeaseState::Mapped;
        request.queue_slot_owned = true;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        scope.recovery_revision = revision;
        scope.queue_slot_obligations.insert(token.request);
        self.push_trace(IoAction::Prepare, token.scope, Some(token.request));
        Ok(())
    }

    /// Fences a crashed service by advancing only the binding generation.
    pub fn crash(&mut self, binding: IoBindingToken) -> Result<(), IoError> {
        let scope = self.validate_binding(binding)?;
        let binding_epoch = BindingEpoch::new(
            scope
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(IoError::UnknownScope(binding.scope))?;
        scope.binding_epoch = binding_epoch;
        scope.service = None;
        scope.fallback = IoFallbackState::Required;
        scope.ready = None;
        self.push_trace(IoAction::Crash, binding.scope, None);
        Ok(())
    }

    /// Selects the minimal kernel fallback after service failure.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active
            || record.service.is_some()
            || record.fallback != IoFallbackState::Required
        {
            return Err(IoError::FallbackUnavailable);
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?
            .fallback = IoFallbackState::Running;
        self.push_trace(IoAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures orphaned `Registered` and `Prepared` work for a replacement.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        service: IoServiceId,
    ) -> Result<IoRecoverySnapshot, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active
            || record.service.is_some()
            || record.fallback != IoFallbackState::Running
        {
            return Err(IoError::FallbackUnavailable);
        }
        let mut requests = Vec::new();
        for request in &record.unpublished_obligations {
            let request = self
                .requests
                .get(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            if matches!(
                request.state,
                IoEffectState::Registered | IoEffectState::Prepared
            ) {
                requests.push(IoRequestSnapshot {
                    token: request.token,
                    state: request.state,
                    dma: request.dma,
                    grant: request.grant,
                });
            }
        }
        Ok(IoRecoverySnapshot {
            scope,
            service,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            recovery_revision: record.recovery_revision,
            requests,
        })
    }

    /// Accepts replacement readiness only from a still-current snapshot.
    pub fn ready(&mut self, snapshot: &IoRecoverySnapshot) -> Result<IoReadyToken, IoError> {
        let scope = self
            .scopes
            .get(&snapshot.scope)
            .ok_or(IoError::UnknownScope(snapshot.scope))?;
        if scope.state != ScopeState::Active
            || scope.service.is_some()
            || scope.fallback != IoFallbackState::Running
        {
            return Err(IoError::FallbackUnavailable);
        }
        if snapshot.authority_epoch != scope.authority_epoch
            || snapshot.binding_epoch != scope.binding_epoch
            || snapshot.device_generation != scope.device_generation
            || snapshot.recovery_revision != scope.recovery_revision
        {
            return Err(IoError::StaleRecoverySnapshot);
        }
        let token = IoReadyToken {
            scope: snapshot.scope,
            service: snapshot.service,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            device_generation: snapshot.device_generation,
            recovery_revision: snapshot.recovery_revision,
        };
        let scope = self
            .scopes
            .get_mut(&snapshot.scope)
            .ok_or(IoError::UnknownScope(snapshot.scope))?;
        scope.fallback = IoFallbackState::ReplacementReady;
        scope.ready = Some(ReadyRecord {
            service: token.service,
            authority_epoch: token.authority_epoch,
            binding_epoch: token.binding_epoch,
            device_generation: token.device_generation,
            recovery_revision: token.recovery_revision,
        });
        self.push_trace(IoAction::Ready, snapshot.scope, None);
        Ok(token)
    }

    /// Installs a ready replacement without changing any generation.
    pub fn rebind(&mut self, ready: IoReadyToken) -> Result<IoBindingToken, IoError> {
        let scope = self
            .scopes
            .get(&ready.scope)
            .ok_or(IoError::UnknownScope(ready.scope))?;
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if scope.service.is_some() {
            return Err(IoError::ServiceAlreadyBound);
        }
        if scope.fallback != IoFallbackState::ReplacementReady {
            return Err(IoError::FallbackUnavailable);
        }
        let expected = ReadyRecord {
            service: ready.service,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
            device_generation: ready.device_generation,
            recovery_revision: ready.recovery_revision,
        };
        if scope.ready != Some(expected)
            || ready.authority_epoch != scope.authority_epoch
            || ready.binding_epoch != scope.binding_epoch
            || ready.device_generation != scope.device_generation
            || ready.recovery_revision != scope.recovery_revision
        {
            return Err(IoError::StaleRecoverySnapshot);
        }
        let binding = IoBindingToken {
            scope: ready.scope,
            service: ready.service,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
        };
        let scope = self
            .scopes
            .get_mut(&ready.scope)
            .ok_or(IoError::UnknownScope(ready.scope))?;
        scope.service = Some(ready.service);
        scope.fallback = IoFallbackState::Standby;
        scope.ready = None;
        self.push_trace(IoAction::Rebind, ready.scope, None);
        Ok(binding)
    }

    /// Explicitly transfers one orphaned unpublished request to a replacement.
    pub fn adopt(
        &mut self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<RequestToken, IoError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_request_token(token)?;
        if token.scope != binding.scope {
            return Err(IoError::RequestIdentityMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        if !matches!(
            request.state,
            IoEffectState::Registered | IoEffectState::Prepared
        ) || request.token.binding_epoch == scope.binding_epoch
        {
            return Err(IoError::NotAdoptable);
        }
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let mut adopted = token;
        adopted.binding_epoch = scope.binding_epoch;
        self.requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?
            .token = adopted;
        self.scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?
            .recovery_revision = revision;
        self.push_trace(IoAction::Adopt, token.scope, Some(token.request));
        Ok(adopted)
    }

    /// Release-publishes `avail.idx`, the mediated request commit point.
    ///
    /// Descriptor construction and notification are deliberately outside this
    /// transition. Once this method succeeds, reset may report an
    /// indeterminate outcome but can never turn the request into `Cancelled`.
    pub fn publish_avail(
        &mut self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<u64, IoError> {
        self.validate_current_reply(binding, token)?;
        let request = *self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state == IoEffectState::Committed {
            return Err(IoError::AlreadyPublished);
        }
        if request.state != IoEffectState::Prepared {
            return Err(IoError::InvalidRequestState {
                state: request.state,
            });
        }
        if request.commit_disposition != CommitDisposition::Held {
            return Err(IoError::InvariantViolation(
                "prepared request does not hold commit charge",
            ));
        }
        if request.dma_state != DmaLeaseState::Mapped
            || request.invalidation != InvalidationRecord::NotStarted
            || !request.queue_slot_owned
        {
            return Err(IoError::InvariantViolation(
                "prepared publication lacks one live DMA mapping",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        let avail_idx = scope
            .avail_idx
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let spent = scope
            .spent_commit_charges
            .get()
            .checked_add(request.grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let held = scope
            .held_commit_charges
            .get()
            .checked_sub(request.grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation(
                "prepared request commit charge is not in the held ledger",
            ))?;
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;

        let request = self
            .requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        request.state = IoEffectState::Committed;
        request.commit_disposition = CommitDisposition::Spent;
        request.avail_publications = 1;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        scope.avail_idx = avail_idx;
        scope.held_commit_charges = CommitCharges::new(held);
        scope.spent_commit_charges = CommitCharges::new(spent);
        scope.recovery_revision = revision;
        scope.unpublished_obligations.remove(&token.request);
        self.push_trace(IoAction::PublishAvail, token.scope, Some(token.request));
        Ok(avail_idx)
    }

    /// Records the optional post-commit notification hint.
    ///
    /// A polling device may observe `avail.idx` before this operation, so this
    /// action never changes publication, charge, or terminal state. The
    /// binding identifies the original publisher; it may be crash-fenced after
    /// commit because committed work is owned by the kernel/device path.
    pub fn notify(&mut self, binding: IoBindingToken, token: RequestToken) -> Result<(), IoError> {
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        self.validate_request_token(token)?;
        if binding.scope != token.scope
            || binding.authority_epoch != token.authority_epoch
            || binding.binding_epoch != token.binding_epoch
            || token.device != scope.device
            || token.queue != scope.queue
        {
            return Err(IoError::RequestIdentityMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state != IoEffectState::Committed {
            return Err(IoError::NotifyBeforePublish);
        }
        if request.notified {
            return Err(IoError::AlreadyNotified);
        }
        self.requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?
            .notified = true;
        self.push_trace(IoAction::Notify, token.scope, Some(token.request));
        Ok(())
    }

    /// Creates an authenticated completion witness for a committed request.
    pub fn completion_for(&self, request: RequestId) -> Result<DeviceCompletion, IoError> {
        let request = self
            .requests
            .get(&request)
            .ok_or(IoError::UnknownRequest(request))?;
        if request.state != IoEffectState::Committed {
            return Err(if request.state.is_terminal() {
                IoError::AlreadyTerminal
            } else {
                IoError::InvalidRequestState {
                    state: request.state,
                }
            });
        }
        Ok(DeviceCompletion {
            scope: request.token.scope,
            request: request.token.request,
            device: request.token.device,
            queue: request.token.queue,
            device_generation: request.token.device_generation,
        })
    }

    /// Terminalizes a committed request from one current-generation completion.
    pub fn device_complete(&mut self, completion: DeviceCompletion) -> Result<(), IoError> {
        let scope = self
            .scopes
            .get(&completion.scope)
            .ok_or(IoError::UnknownScope(completion.scope))?;
        if completion.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: completion.device_generation,
                current: scope.device_generation,
            });
        }
        if completion.device != scope.device || completion.queue != scope.queue {
            return Err(IoError::RequestIdentityMismatch);
        }
        let request = self
            .requests
            .get(&completion.request)
            .ok_or(IoError::UnknownRequest(completion.request))?;
        if request.token.scope != completion.scope
            || request.token.device != completion.device
            || request.token.queue != completion.queue
            || request.token.device_generation != completion.device_generation
        {
            return Err(IoError::RequestIdentityMismatch);
        }
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state != IoEffectState::Committed {
            return Err(IoError::InvalidRequestState {
                state: request.state,
            });
        }
        if !request.queue_slot_owned || !scope.queue_slot_obligations.contains(&completion.request)
        {
            return Err(IoError::InvariantViolation(
                "committed request lacks its queue-slot obligation",
            ));
        }
        let nonterminal_requests =
            scope
                .nonterminal_requests
                .checked_sub(1)
                .ok_or(IoError::InvariantViolation(
                    "completion underflowed nonterminal request count",
                ))?;
        let request = self
            .requests
            .get_mut(&completion.request)
            .ok_or(IoError::UnknownRequest(completion.request))?;
        request.state = IoEffectState::Completed;
        request.queue_slot_owned = false;
        request.terminalizations = 1;
        let scope = self
            .scopes
            .get_mut(&completion.scope)
            .ok_or(IoError::UnknownScope(completion.scope))?;
        scope.nonterminal_requests = nonterminal_requests;
        scope.queue_slot_obligations.remove(&completion.request);
        self.push_trace(
            IoAction::DeviceComplete,
            completion.scope,
            Some(completion.request),
        );
        Ok(())
    }

    /// Closes the `avail.idx` publication gate and advances only authority.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let closed_epoch = record.authority_epoch;
        let authority_epoch = AuthorityEpoch::new(
            record
                .authority_epoch
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let target_count = record.live_obligations.len();
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.authority_epoch = authority_epoch;
        record.service = None;
        record.ready = None;
        record.reset = ResetRecord::Required;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            cancel_steps: 0,
            cancel_index_visits: 0,
            reset_index_visits: 0,
            reset_terminalizations: 0,
            invalidated_request_leases: 0,
        });
        self.push_trace(IoAction::RevokeBegin, scope, None);
        Ok(())
    }

    /// Cancels the next unpublished request through the target scope's index.
    pub fn cancel_unpublished(&mut self, scope: ScopeId) -> Result<Option<RequestId>, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let request_id = record.unpublished_obligations.iter().next().copied();
        let Some(request_id) = request_id else {
            return Ok(None);
        };
        let request = *self
            .requests
            .get(&request_id)
            .ok_or(IoError::UnknownRequest(request_id))?;
        if request.commit_disposition != CommitDisposition::Held {
            return Err(IoError::InvariantViolation(
                "unpublished request lacks held commit charge",
            ));
        }
        if !matches!(
            request.state,
            IoEffectState::Registered | IoEffectState::Prepared
        ) {
            return Err(IoError::InvariantViolation(
                "unpublished index contains a published or terminal request",
            ));
        }
        let free_commit = record
            .free_commit_charges
            .get()
            .checked_add(request.grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let held_commit = record
            .held_commit_charges
            .get()
            .checked_sub(request.grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation(
                "unpublished request charge is absent from held ledger",
            ))?;
        let direct_cancel = request.state == IoEffectState::Registered;
        let free_lease = if direct_cancel {
            Some(
                record
                    .free_lease_credits
                    .checked_add(request.grant.lease)
                    .ok_or(IoError::CounterOverflow)?,
            )
        } else {
            None
        };
        if direct_cancel && request.dma_state != DmaLeaseState::Absent {
            return Err(IoError::InvariantViolation(
                "registered cancellation found an established DMA mapping",
            ));
        }
        if direct_cancel && request.queue_slot_owned {
            return Err(IoError::InvariantViolation(
                "registered cancellation found a queue-slot obligation",
            ));
        }
        if !direct_cancel
            && (request.dma_state != DmaLeaseState::Mapped
                || !request.queue_slot_owned
                || !record.queue_slot_obligations.contains(&request_id))
        {
            return Err(IoError::InvariantViolation(
                "prepared cancellation lacks its DMA or queue-slot obligation",
            ));
        }
        let nonterminal_requests =
            if direct_cancel {
                Some(record.nonterminal_requests.checked_sub(1).ok_or(
                    IoError::InvariantViolation(
                        "registered cancellation underflowed nonterminal request count",
                    ),
                )?)
            } else {
                None
            };
        let revocation = record
            .revocation
            .as_ref()
            .ok_or(IoError::InvariantViolation(
                "closing scope lacks revocation",
            ))?;
        let cancel_steps = revocation
            .cancel_steps
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let cancel_index_visits = revocation
            .cancel_index_visits
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request_dma = request.dma;
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or(IoError::UnknownRequest(request_id))?;
        request.state = if direct_cancel {
            IoEffectState::Cancelled
        } else {
            IoEffectState::Cancelling
        };
        request.commit_disposition = CommitDisposition::Returned;
        request.terminalizations = u8::from(direct_cancel);
        request.queue_slot_owned = false;
        if direct_cancel {
            request.dma_state = DmaLeaseState::Released;
        }
        let scope_record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        scope_record.free_commit_charges = CommitCharges::new(free_commit);
        scope_record.held_commit_charges = CommitCharges::new(held_commit);
        scope_record.unpublished_obligations.remove(&request_id);
        scope_record.queue_slot_obligations.remove(&request_id);
        if let Some(free_lease) = free_lease {
            scope_record.free_lease_credits = free_lease;
            scope_record.live_obligations.remove(&request_id);
        }
        if let Some(nonterminal_requests) = nonterminal_requests {
            scope_record.nonterminal_requests = nonterminal_requests;
        }
        let revocation = scope_record
            .revocation
            .as_mut()
            .ok_or(IoError::InvariantViolation(
                "closing scope lacks revocation",
            ))?;
        revocation.cancel_steps = cancel_steps;
        revocation.cancel_index_visits = cancel_index_visits;
        if direct_cancel {
            self.release_dma(request_dma);
        }
        self.push_trace(IoAction::CancelUnpublished, scope, Some(request_id));
        Ok(Some(request_id))
    }

    /// Issues a whole-device reset after the publication gate closes.
    ///
    /// Reset may run in parallel with cancellation and invalidation of work
    /// that was never published. Its acknowledgement affects only requests
    /// that are still `Committed` at that linearization point.
    pub fn begin_reset(&mut self, scope: ScopeId) -> Result<ResetAttempt, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.reset != ResetRecord::Required {
            return Err(IoError::InvalidResetState {
                state: record.reset.view(),
            });
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = ResetAttempt {
            scope,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.next_attempt = next_attempt;
        record.reset = ResetRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        self.push_trace(IoAction::BeginReset, scope, None);
        Ok(token)
    }

    /// Records reset timeout without releasing any DMA object or credit.
    pub fn reset_timeout(&mut self, attempt: ResetAttempt) -> Result<ResetTombstone, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_reset_attempt(record, attempt)?;
        let retained = self.reset_retained_summary(attempt.scope)?;
        self.scopes
            .get_mut(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?
            .reset = ResetRecord::TimedOut {
            attempt: attempt.attempt,
            device_generation: attempt.device_generation,
        };
        self.push_trace(IoAction::ResetTimeout, attempt.scope, None);
        Ok(ResetTombstone {
            scope: attempt.scope,
            failed_attempt: attempt.attempt,
            device_generation: attempt.device_generation,
            retained,
        })
    }

    /// Reissues reset by consuming a matching retained-ownership tombstone.
    pub fn retry_reset(
        &mut self,
        tombstone: ResetTombstone,
    ) -> Result<ResetAttempt, Box<ResetRetryError>> {
        match self.retry_reset_inner(&tombstone) {
            Ok(attempt) => Ok(attempt),
            Err(error) => Err(Box::new(ResetRetryError { error, tombstone })),
        }
    }

    /// Acknowledges whole-device reset and establishes quiescence.
    ///
    /// Every still-`Committed` request becomes
    /// `IndeterminateAfterReset`. Requests whose completion linearized first
    /// remain `Completed`. The device generation advances exactly once.
    pub fn reset_ack(&mut self, attempt: ResetAttempt) -> Result<usize, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_reset_attempt(record, attempt)?;
        let new_generation = DeviceGeneration::new(
            record
                .device_generation
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let committed: Vec<_> = record
            .live_obligations
            .iter()
            .copied()
            .filter(|request| {
                self.requests
                    .get(request)
                    .is_some_and(|request| request.state == IoEffectState::Committed)
            })
            .collect();
        if committed.iter().any(|request| {
            self.requests
                .get(request)
                .is_none_or(|request| !request.queue_slot_owned)
                || !record.queue_slot_obligations.contains(request)
        }) {
            return Err(IoError::InvariantViolation(
                "committed reset target lacks a queue-slot obligation",
            ));
        }
        let nonterminal_requests = record
            .nonterminal_requests
            .checked_sub(committed.len())
            .ok_or(IoError::InvariantViolation(
                "reset terminalization underflowed nonterminal request count",
            ))?;
        let revocation = record
            .revocation
            .as_ref()
            .ok_or(IoError::InvariantViolation("reset lacks revocation"))?;
        let reset_index_visits = revocation
            .reset_index_visits
            .checked_add(record.live_obligations.len())
            .ok_or(IoError::CounterOverflow)?;
        for request in &committed {
            let record = self
                .requests
                .get_mut(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            record.state = IoEffectState::IndeterminateAfterReset;
            record.queue_slot_owned = false;
            record.terminalizations = 1;
        }
        let scope = self
            .scopes
            .get_mut(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        scope.device_generation = new_generation;
        scope.device_quiesced = true;
        scope.reset = ResetRecord::Acknowledged;
        scope.nonterminal_requests = nonterminal_requests;
        for request in &committed {
            scope.queue_slot_obligations.remove(request);
        }
        let revocation = scope
            .revocation
            .as_mut()
            .ok_or(IoError::InvariantViolation("reset lacks revocation"))?;
        revocation.reset_index_visits = reset_index_visits;
        revocation.reset_terminalizations = committed.len();
        self.push_trace(IoAction::ResetAck, attempt.scope, None);
        Ok(committed.len())
    }

    /// Removes one safe queue/request mapping and issues synchronous invalidation.
    ///
    /// A `Cancelling` request was never published, and a `Completed` request
    /// has a device completion proving it is no longer accessed; either may be
    /// cleaned independently. An indeterminate request and the queue require
    /// reset acknowledgement first.
    pub fn begin_invalidate(
        &mut self,
        scope: ScopeId,
        target: InvalidateTarget,
    ) -> Result<InvalidateAttempt, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        match target {
            InvalidateTarget::Queue => {
                if !record.device_quiesced || record.reset != ResetRecord::Acknowledged {
                    return Err(IoError::DeviceNotQuiescent);
                }
                if !record.queue_slot_obligations.is_empty() {
                    return Err(IoError::QueueSlotsOutstanding {
                        remaining: record.queue_slot_obligations.len(),
                    });
                }
                if record.queue_lease.invalidation != InvalidationRecord::NotStarted {
                    return Err(IoError::InvalidInvalidationState {
                        state: record.queue_lease.invalidation.view(),
                    });
                }
                if record.queue_lease.state != DmaLeaseState::Mapped {
                    return Err(IoError::InvariantViolation(
                        "queue is not mapped at invalidation begin",
                    ));
                }
            }
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                if !matches!(
                    request.state,
                    IoEffectState::Cancelling
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset
                ) {
                    return Err(IoError::InvalidRequestState {
                        state: request.state,
                    });
                }
                if request.state == IoEffectState::IndeterminateAfterReset
                    && (!record.device_quiesced || record.reset != ResetRecord::Acknowledged)
                {
                    return Err(IoError::DeviceNotQuiescent);
                }
                if request.invalidation != InvalidationRecord::NotStarted {
                    return Err(IoError::InvalidInvalidationState {
                        state: request.invalidation.view(),
                    });
                }
                if request.dma_state != DmaLeaseState::Mapped {
                    return Err(IoError::InvariantViolation(
                        "request is not mapped at invalidation begin",
                    ));
                }
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = InvalidateAttempt {
            scope,
            target,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.next_attempt = next_attempt;
        let invalidation = InvalidationRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        match target {
            InvalidateTarget::Queue => {
                record.queue_lease.state = DmaLeaseState::UnmappedAwaitingInvalidation;
                record.queue_lease.invalidation = invalidation;
            }
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                request.dma_state = DmaLeaseState::UnmappedAwaitingInvalidation;
                request.invalidation = invalidation;
            }
        }
        self.push_trace(
            IoAction::BeginInvalidate,
            scope,
            match target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(token)
    }

    /// Records invalidation timeout while retaining the target identity and credit.
    pub fn invalidate_timeout(
        &mut self,
        attempt: InvalidateAttempt,
    ) -> Result<InvalidateTombstone, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_invalidate_attempt(record, attempt)?;
        let retained = self.target_retained_summary(attempt.scope, attempt.target)?;
        let timed_out = InvalidationRecord::TimedOut {
            attempt: attempt.attempt,
            device_generation: attempt.device_generation,
        };
        match attempt.target {
            InvalidateTarget::Queue => {
                self.scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?
                    .queue_lease
                    .invalidation = timed_out;
            }
            InvalidateTarget::Request(request) => {
                self.requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?
                    .invalidation = timed_out;
            }
        }
        self.push_trace(
            IoAction::InvalidateTimeout,
            attempt.scope,
            match attempt.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(InvalidateTombstone {
            scope: attempt.scope,
            target: attempt.target,
            failed_attempt: attempt.attempt,
            device_generation: attempt.device_generation,
            retained,
        })
    }

    /// Reissues invalidation by consuming a retained-ownership tombstone.
    pub fn retry_invalidate(
        &mut self,
        tombstone: InvalidateTombstone,
    ) -> Result<InvalidateAttempt, Box<InvalidateRetryError>> {
        match self.retry_invalidate_inner(&tombstone) {
            Ok(attempt) => Ok(attempt),
            Err(error) => Err(Box::new(InvalidateRetryError { error, tombstone })),
        }
    }

    /// Accepts synchronous IOTLB completion and releases one DMA lease.
    pub fn invalidate_ack(&mut self, attempt: InvalidateAttempt) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_invalidate_attempt(record, attempt)?;
        let (dma, returned, terminalize_cancellation) = match attempt.target {
            InvalidateTarget::Queue => (record.queue_lease.dma, record.queue_lease.credits, false),
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                (
                    request.dma,
                    request.grant.lease,
                    request.state == IoEffectState::Cancelling,
                )
            }
        };
        let free_after = record
            .free_lease_credits
            .checked_add(returned)
            .ok_or(IoError::CounterOverflow)?;
        let nonterminal_after =
            if terminalize_cancellation {
                Some(record.nonterminal_requests.checked_sub(1).ok_or(
                    IoError::InvariantViolation(
                        "cancel completion underflowed nonterminal request count",
                    ),
                )?)
            } else {
                None
            };
        let invalidated_request_leases = if matches!(attempt.target, InvalidateTarget::Request(_)) {
            record
                .revocation
                .as_ref()
                .map(|revocation| {
                    revocation
                        .invalidated_request_leases
                        .checked_add(1)
                        .ok_or(IoError::CounterOverflow)
                })
                .transpose()?
        } else {
            None
        };
        match attempt.target {
            InvalidateTarget::Queue => {
                let record = self
                    .scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?;
                record.queue_lease.state = DmaLeaseState::Released;
                record.queue_lease.invalidation = InvalidationRecord::Acknowledged;
                record.free_lease_credits = free_after;
            }
            InvalidateTarget::Request(request_id) => {
                let request = self
                    .requests
                    .get_mut(&request_id)
                    .ok_or(IoError::UnknownRequest(request_id))?;
                request.dma_state = DmaLeaseState::Released;
                request.invalidation = InvalidationRecord::Acknowledged;
                if terminalize_cancellation {
                    request.state = IoEffectState::Cancelled;
                    request.terminalizations = 1;
                }
                let record = self
                    .scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?;
                record.free_lease_credits = free_after;
                record.live_obligations.remove(&request_id);
                if let Some(nonterminal_after) = nonterminal_after {
                    record.nonterminal_requests = nonterminal_after;
                }
                if let (Some(revocation), Some(invalidated_request_leases)) =
                    (record.revocation.as_mut(), invalidated_request_leases)
                {
                    revocation.invalidated_request_leases = invalidated_request_leases;
                }
            }
        }
        self.release_dma(dma);
        self.push_trace(
            IoAction::InvalidateAck,
            attempt.scope,
            match attempt.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(())
    }

    /// Publishes quiescent closure after reset and invalidation complete.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.device_quiesced
            || record.reset != ResetRecord::Acknowledged
            || record.queue_lease.invalidation != InvalidationRecord::Acknowledged
            || !record.live_obligations.is_empty()
            || !record.unpublished_obligations.is_empty()
            || record.nonterminal_requests != 0
            || !record.queue_slot_obligations.is_empty()
            || record.queue_lease.state != DmaLeaseState::Released
            || record.held_commit_charges != CommitCharges::ZERO
            || record.free_lease_credits != record.initial_budget.leases
        {
            return Err(IoError::RevocationNotQuiescent);
        }
        let device = record.device;
        let queue = record.queue;
        self.scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.device_owners.remove(&device);
        self.queue_owners.remove(&queue);
        self.push_trace(IoAction::RevokeComplete, scope, None);
        Ok(())
    }

    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<IoScopeView> {
        let record = self.scopes.get(&scope)?;
        Some(IoScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            device: record.device,
            queue: record.queue,
            service: record.service,
            fallback: record.fallback,
            initial_budget: record.initial_budget,
            free_lease_credits: record.free_lease_credits,
            free_commit_charges: record.free_commit_charges,
            held_commit_charges: record.held_commit_charges,
            spent_commit_charges: record.spent_commit_charges,
            avail_idx: record.avail_idx,
            historical_requests: record.requests.len(),
            live_obligations: record.live_obligations.len(),
            unpublished_obligations: record.unpublished_obligations.len(),
            nonterminal_requests: record.nonterminal_requests,
            queue_slot_obligations: record.queue_slot_obligations.len(),
            device_quiesced: record.device_quiesced,
            reset: record.reset.view(),
            invalidation: record.queue_lease.invalidation.view(),
            revocation: record.revocation.map(|revocation| IoRevocationProgress {
                closed_epoch: revocation.closed_epoch,
                target_count: revocation.target_count,
                cancel_steps: revocation.cancel_steps,
                cancel_index_visits: revocation.cancel_index_visits,
                reset_index_visits: revocation.reset_index_visits,
                reset_terminalizations: revocation.reset_terminalizations,
                invalidated_request_leases: revocation.invalidated_request_leases,
            }),
        })
    }

    /// Returns a read-only request projection.
    #[must_use]
    pub fn request(&self, request: RequestId) -> Option<IoRequestView> {
        self.requests.get(&request).map(|request| IoRequestView {
            token: request.token,
            state: request.state,
            grant: request.grant,
            commit_disposition: request.commit_disposition,
            dma: request.dma,
            dma_state: request.dma_state,
            invalidation: request.invalidation.view(),
            avail_publications: request.avail_publications,
            notified: request.notified,
            queue_slot_owned: request.queue_slot_owned,
            terminalizations: request.terminalizations,
        })
    }

    /// Returns the scope-owned queue lease projection.
    #[must_use]
    pub fn queue_lease(&self, scope: ScopeId) -> Option<QueueLeaseView> {
        self.scopes.get(&scope).map(|record| QueueLeaseView {
            queue: record.queue_lease.queue,
            dma: record.queue_lease.dma,
            dma_state: record.queue_lease.state,
            invalidation: record.queue_lease.invalidation.view(),
            credits: record.queue_lease.credits,
        })
    }

    /// Returns whether any live scope still retains a component of this identity.
    #[must_use]
    pub fn dma_identity_retained(&self, dma: DmaIdentity) -> bool {
        self.active_dma_leases.contains(&dma.lease)
            || self.active_mappings.contains(&dma.mapping)
            || self.active_iovas.contains(&dma.iova)
    }

    /// Returns the number of scopes in the model.
    #[must_use]
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    /// Returns the number of requests across every scope.
    #[must_use]
    pub fn global_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Returns the immutable successful-operation trace.
    #[must_use]
    pub fn trace(&self) -> &[IoTraceEvent] {
        &self.trace
    }

    /// Audits typed budgets, generation fences, ownership, and closure state.
    pub fn check_invariants(&self) -> Result<(), IoInvariantViolation> {
        let mut expected_issued_dma_leases = BTreeSet::new();
        let mut expected_issued_mappings = BTreeSet::new();
        let mut expected_active_dma_leases = BTreeSet::new();
        let mut expected_active_mappings = BTreeSet::new();
        let mut expected_active_iovas = BTreeSet::new();
        for (scope_id, scope) in &self.scopes {
            let mut retained_lease = if scope.queue_lease.state == DmaLeaseState::Released {
                LeaseCredits::ZERO
            } else {
                scope.queue_lease.credits
            };
            let mut held_commit = 0u64;
            let mut derived_live = BTreeSet::new();
            let mut derived_unpublished = BTreeSet::new();
            let mut derived_queue_slots = BTreeSet::new();
            let mut derived_nonterminal = 0usize;
            if !expected_issued_dma_leases.insert(scope.queue_lease.dma.lease)
                || !expected_issued_mappings.insert(scope.queue_lease.dma.mapping)
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            if scope.queue_lease.state != DmaLeaseState::Released
                && (!expected_active_dma_leases.insert(scope.queue_lease.dma.lease)
                    || !expected_active_mappings.insert(scope.queue_lease.dma.mapping)
                    || !expected_active_iovas.insert(scope.queue_lease.dma.iova))
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            for request_id in &scope.requests {
                let request = self
                    .requests
                    .get(request_id)
                    .ok_or(IoInvariantViolation::OrphanRequest(*request_id))?;
                if request.token.scope != *scope_id
                    || request.token.device != scope.device
                    || request.token.queue != scope.queue
                {
                    return Err(IoInvariantViolation::OrphanRequest(*request_id));
                }
                if request.token.authority_epoch.get() > scope.authority_epoch.get()
                    || request.token.binding_epoch.get() > scope.binding_epoch.get()
                    || request.token.device_generation.get() > scope.device_generation.get()
                {
                    return Err(IoInvariantViolation::FutureGeneration(*request_id));
                }
                if !expected_issued_dma_leases.insert(request.dma.lease)
                    || !expected_issued_mappings.insert(request.dma.mapping)
                {
                    return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                }
                if request.dma_state != DmaLeaseState::Released {
                    retained_lease = retained_lease
                        .checked_add(request.grant.lease)
                        .ok_or(IoInvariantViolation::LeaseBudgetConservation(*scope_id))?;
                    if !self.dma_identity_indexed(request.dma) {
                        return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                    }
                    if !expected_active_dma_leases.insert(request.dma.lease)
                        || !expected_active_mappings.insert(request.dma.mapping)
                        || !expected_active_iovas.insert(request.dma.iova)
                    {
                        return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                    }
                } else if self.active_dma_leases.contains(&request.dma.lease)
                    || self.active_mappings.contains(&request.dma.mapping)
                {
                    return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                }
                match (request.state, request.commit_disposition) {
                    (
                        IoEffectState::Registered | IoEffectState::Prepared,
                        CommitDisposition::Held,
                    ) => {
                        held_commit = held_commit
                            .checked_add(request.grant.commit_charge.get())
                            .ok_or(IoInvariantViolation::CommitBudgetConservation(*scope_id))?;
                    }
                    (
                        IoEffectState::Committed
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset,
                        CommitDisposition::Spent,
                    )
                    | (
                        IoEffectState::Cancelling | IoEffectState::Cancelled,
                        CommitDisposition::Returned,
                    ) => {}
                    _ => return Err(IoInvariantViolation::RequestChargeState(*request_id)),
                }
                let published = matches!(
                    request.state,
                    IoEffectState::Committed
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset
                );
                if request.avail_publications != u8::from(published)
                    || (request.notified && !published)
                {
                    return Err(IoInvariantViolation::PublicationState(*request_id));
                }
                if request.terminalizations != u8::from(request.state.is_terminal()) {
                    return Err(IoInvariantViolation::Terminalization(*request_id));
                }
                if !request.state.is_terminal() {
                    derived_nonterminal = derived_nonterminal
                        .checked_add(1)
                        .ok_or(IoInvariantViolation::NonterminalCount(*scope_id))?;
                }
                if matches!(
                    request.state,
                    IoEffectState::Registered | IoEffectState::Prepared
                ) {
                    derived_unpublished.insert(*request_id);
                }
                let should_own_queue_slot = matches!(
                    request.state,
                    IoEffectState::Prepared | IoEffectState::Committed
                );
                if request.queue_slot_owned != should_own_queue_slot {
                    return Err(IoInvariantViolation::QueueSlotIndex(*scope_id));
                }
                if request.queue_slot_owned {
                    derived_queue_slots.insert(*request_id);
                }
                if request.dma_state != DmaLeaseState::Released {
                    derived_live.insert(*request_id);
                }
            }
            let lease_sum = scope
                .free_lease_credits
                .checked_add(retained_lease)
                .ok_or(IoInvariantViolation::LeaseBudgetConservation(*scope_id))?;
            if lease_sum != scope.initial_budget.leases {
                return Err(IoInvariantViolation::LeaseBudgetConservation(*scope_id));
            }
            let charge_sum = scope
                .free_commit_charges
                .get()
                .checked_add(held_commit)
                .and_then(|value| value.checked_add(scope.spent_commit_charges.get()))
                .ok_or(IoInvariantViolation::CommitBudgetConservation(*scope_id))?;
            if charge_sum != scope.initial_budget.commit_charges.get() {
                return Err(IoInvariantViolation::CommitBudgetConservation(*scope_id));
            }
            if scope.held_commit_charges != CommitCharges::new(held_commit) {
                return Err(IoInvariantViolation::CommitBudgetConservation(*scope_id));
            }
            if derived_live != scope.live_obligations {
                return Err(IoInvariantViolation::LiveReverseIndex(*scope_id));
            }
            if derived_unpublished != scope.unpublished_obligations {
                return Err(IoInvariantViolation::UnpublishedReverseIndex(*scope_id));
            }
            if derived_nonterminal != scope.nonterminal_requests {
                return Err(IoInvariantViolation::NonterminalCount(*scope_id));
            }
            if derived_queue_slots != scope.queue_slot_obligations {
                return Err(IoInvariantViolation::QueueSlotIndex(*scope_id));
            }
            if scope.queue_lease.state != DmaLeaseState::Released {
                if !self.dma_identity_indexed(scope.queue_lease.dma) {
                    return Err(IoInvariantViolation::DmaIdentityIndex(
                        scope.queue_lease.dma,
                    ));
                }
            } else if self
                .active_dma_leases
                .contains(&scope.queue_lease.dma.lease)
                || self
                    .active_mappings
                    .contains(&scope.queue_lease.dma.mapping)
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            if !Self::dma_invalidation_pair_valid(
                scope.queue_lease.state,
                scope.queue_lease.invalidation,
                false,
            ) || scope.requests.iter().any(|request| {
                self.requests.get(request).is_none_or(|request| {
                    !Self::dma_invalidation_pair_valid(
                        request.dma_state,
                        request.invalidation,
                        true,
                    ) || !Self::request_dma_state_valid(request)
                })
            }) {
                return Err(IoInvariantViolation::DmaLeaseSafety(*scope_id));
            }
            match scope.reset {
                ResetRecord::Idle if scope.state != ScopeState::Active => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Required if scope.state != ScopeState::Closing => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::InFlight { .. } | ResetRecord::TimedOut { .. }
                    if scope.state != ScopeState::Closing =>
                {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Acknowledged
                    if !scope.device_quiesced
                        || scope.live_obligations.iter().any(|request| {
                            self.requests
                                .get(request)
                                .is_some_and(|request| request.state == IoEffectState::Committed)
                        }) =>
                {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Acknowledged => {}
                _ if scope.device_quiesced => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                _ => {}
            }
            match scope.state {
                ScopeState::Active if scope.revocation.is_some() => {
                    return Err(IoInvariantViolation::RevocationState(*scope_id));
                }
                ScopeState::Closing | ScopeState::Revoked if scope.revocation.is_none() => {
                    return Err(IoInvariantViolation::RevocationState(*scope_id));
                }
                _ => {}
            }
            if let Some(revocation) = scope.revocation
                && (revocation.cancel_steps != revocation.cancel_index_visits
                    || revocation.cancel_steps > revocation.target_count
                    || revocation.reset_index_visits > revocation.target_count
                    || revocation.reset_terminalizations > revocation.reset_index_visits
                    || revocation.invalidated_request_leases > revocation.target_count
                    || scope.live_obligations.len() > revocation.target_count)
            {
                return Err(IoInvariantViolation::RevocationState(*scope_id));
            }
            if scope.state == ScopeState::Revoked
                && (!scope.device_quiesced
                    || scope.reset != ResetRecord::Acknowledged
                    || scope.queue_lease.invalidation != InvalidationRecord::Acknowledged
                    || !scope.live_obligations.is_empty()
                    || !scope.unpublished_obligations.is_empty()
                    || scope.nonterminal_requests != 0
                    || !scope.queue_slot_obligations.is_empty()
                    || retained_lease != LeaseCredits::ZERO
                    || held_commit != 0
                    || scope.held_commit_charges != CommitCharges::ZERO
                    || self.device_owners.get(&scope.device) == Some(scope_id)
                    || self.queue_owners.get(&scope.queue) == Some(scope_id))
            {
                return Err(IoInvariantViolation::RevokedScope(*scope_id));
            }
            if scope.state != ScopeState::Revoked
                && (self.device_owners.get(&scope.device) != Some(scope_id)
                    || self.queue_owners.get(&scope.queue) != Some(scope_id))
            {
                return Err(IoInvariantViolation::ExclusiveOwner(*scope_id));
            }
            let fallback_ok = match scope.fallback {
                IoFallbackState::Standby => {
                    scope.service.is_some() || scope.state != ScopeState::Active
                }
                IoFallbackState::Required | IoFallbackState::Running => scope.service.is_none(),
                IoFallbackState::ReplacementReady => {
                    scope.service.is_none() && scope.ready.is_some()
                }
            };
            if !fallback_ok {
                return Err(IoInvariantViolation::FallbackState(*scope_id));
            }
        }
        if expected_issued_dma_leases != self.issued_dma_leases
            || expected_issued_mappings != self.issued_mappings
            || expected_active_dma_leases != self.active_dma_leases
            || expected_active_mappings != self.active_mappings
            || expected_active_iovas != self.active_iovas
        {
            return Err(IoInvariantViolation::DmaOwnershipIndex);
        }
        for (request_id, request) in &self.requests {
            let scope = self
                .scopes
                .get(&request.token.scope)
                .ok_or(IoInvariantViolation::OrphanRequest(*request_id))?;
            if !scope.requests.contains(request_id) {
                return Err(IoInvariantViolation::OrphanRequest(*request_id));
            }
        }
        Ok(())
    }

    fn validate_binding(&self, token: IoBindingToken) -> Result<&IoScopeRecord, IoError> {
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if token.binding_epoch != scope.binding_epoch {
            return Err(IoError::StaleBinding {
                presented: token.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        let service = scope.service.ok_or(IoError::ServiceUnavailable)?;
        if token.service != service {
            return Err(IoError::WrongService);
        }
        Ok(scope)
    }

    fn validate_request_token(&self, token: RequestToken) -> Result<&RequestRecord, IoError> {
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.token != token {
            return Err(IoError::RequestIdentityMismatch);
        }
        Ok(request)
    }

    fn validate_current_reply(
        &self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<(), IoError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_request_token(token)?;
        if token.scope != binding.scope
            || token.device != scope.device
            || token.queue != scope.queue
        {
            return Err(IoError::RequestIdentityMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.binding_epoch != scope.binding_epoch {
            return Err(IoError::RequestBindingFenced {
                request_binding: token.binding_epoch,
                current_binding: scope.binding_epoch,
            });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        if request.token != token {
            return Err(IoError::RequestIdentityMismatch);
        }
        Ok(())
    }

    fn validate_dma_available(&self, dma: DmaIdentity) -> Result<(), IoError> {
        if self.issued_dma_leases.contains(&dma.lease)
            || self.issued_mappings.contains(&dma.mapping)
            || self.active_iovas.contains(&dma.iova)
        {
            return Err(IoError::DmaIdentityInUse(dma));
        }
        Ok(())
    }

    fn reserve_dma(&mut self, dma: DmaIdentity) {
        self.issued_dma_leases.insert(dma.lease);
        self.issued_mappings.insert(dma.mapping);
        self.active_dma_leases.insert(dma.lease);
        self.active_mappings.insert(dma.mapping);
        self.active_iovas.insert(dma.iova);
    }

    fn release_dma(&mut self, dma: DmaIdentity) {
        self.active_dma_leases.remove(&dma.lease);
        self.active_mappings.remove(&dma.mapping);
        self.active_iovas.remove(&dma.iova);
    }

    fn dma_identity_indexed(&self, dma: DmaIdentity) -> bool {
        self.active_dma_leases.contains(&dma.lease)
            && self.active_mappings.contains(&dma.mapping)
            && self.active_iovas.contains(&dma.iova)
    }

    fn reset_retained_summary(&self, scope: ScopeId) -> Result<RetainedDmaSummary, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        let mut credits = if record.queue_lease.state == DmaLeaseState::Released {
            LeaseCredits::ZERO
        } else {
            record.queue_lease.credits
        };
        let mut request_leases = 0usize;
        for request in &record.live_obligations {
            let request = self
                .requests
                .get(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            if request.state == IoEffectState::Committed
                && request.dma_state != DmaLeaseState::Released
            {
                request_leases += 1;
                credits = credits
                    .checked_add(request.grant.lease)
                    .ok_or(IoError::CounterOverflow)?;
            }
        }
        Ok(RetainedDmaSummary {
            queue_lease: record.queue_lease.state != DmaLeaseState::Released,
            request_leases,
            lease_credits: credits,
            held_commit_charges: record.held_commit_charges,
        })
    }

    fn target_retained_summary(
        &self,
        scope: ScopeId,
        target: InvalidateTarget,
    ) -> Result<RetainedDmaSummary, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        match target {
            InvalidateTarget::Queue => Ok(RetainedDmaSummary {
                queue_lease: record.queue_lease.state != DmaLeaseState::Released,
                request_leases: 0,
                lease_credits: if record.queue_lease.state == DmaLeaseState::Released {
                    LeaseCredits::ZERO
                } else {
                    record.queue_lease.credits
                },
                held_commit_charges: CommitCharges::ZERO,
            }),
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                Ok(RetainedDmaSummary {
                    queue_lease: false,
                    request_leases: usize::from(request.dma_state != DmaLeaseState::Released),
                    lease_credits: if request.dma_state == DmaLeaseState::Released {
                        LeaseCredits::ZERO
                    } else {
                        request.grant.lease
                    },
                    held_commit_charges: if request.commit_disposition == CommitDisposition::Held {
                        request.grant.commit_charge
                    } else {
                        CommitCharges::ZERO
                    },
                })
            }
        }
    }

    fn validate_reset_attempt(
        &self,
        scope: &IoScopeRecord,
        attempt: ResetAttempt,
    ) -> Result<(), IoError> {
        if scope.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        match scope.reset {
            ResetRecord::InFlight {
                attempt: expected,
                device_generation,
            } if expected == attempt.attempt
                && device_generation == attempt.device_generation
                && scope.device_generation == attempt.device_generation =>
            {
                Ok(())
            }
            ResetRecord::InFlight { .. } => Err(IoError::StaleResetAttempt),
            _ => Err(IoError::InvalidResetState {
                state: scope.reset.view(),
            }),
        }
    }

    fn retry_reset_inner(&mut self, tombstone: &ResetTombstone) -> Result<ResetAttempt, IoError> {
        let record = self
            .scopes
            .get(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        match record.reset {
            ResetRecord::TimedOut {
                attempt,
                device_generation,
            } if attempt == tombstone.failed_attempt
                && device_generation == tombstone.device_generation
                && record.device_generation == tombstone.device_generation => {}
            ResetRecord::TimedOut { .. } => return Err(IoError::StaleResetAttempt),
            _ => {
                return Err(IoError::InvalidResetState {
                    state: record.reset.view(),
                });
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = ResetAttempt {
            scope: tombstone.scope,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        record.next_attempt = next_attempt;
        record.reset = ResetRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        self.push_trace(IoAction::RetryReset, tombstone.scope, None);
        Ok(token)
    }

    fn validate_invalidate_attempt(
        &self,
        scope: &IoScopeRecord,
        attempt: InvalidateAttempt,
    ) -> Result<(), IoError> {
        if scope.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        let invalidation = match attempt.target {
            InvalidateTarget::Queue => scope.queue_lease.invalidation,
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != attempt.scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                request.invalidation
            }
        };
        match invalidation {
            InvalidationRecord::InFlight {
                attempt: expected,
                device_generation,
            } if expected == attempt.attempt
                && device_generation == attempt.device_generation
                && (attempt.target != InvalidateTarget::Queue
                    || scope.device_generation == attempt.device_generation) =>
            {
                Ok(())
            }
            InvalidationRecord::InFlight { .. } => Err(IoError::StaleInvalidateAttempt),
            _ => Err(IoError::InvalidInvalidationState {
                state: invalidation.view(),
            }),
        }
    }

    fn retry_invalidate_inner(
        &mut self,
        tombstone: &InvalidateTombstone,
    ) -> Result<InvalidateAttempt, IoError> {
        let record = self
            .scopes
            .get(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        if record.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let invalidation = match tombstone.target {
            InvalidateTarget::Queue => record.queue_lease.invalidation,
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != tombstone.scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                request.invalidation
            }
        };
        match invalidation {
            InvalidationRecord::TimedOut {
                attempt,
                device_generation,
            } if attempt == tombstone.failed_attempt
                && device_generation == tombstone.device_generation
                && (tombstone.target != InvalidateTarget::Queue
                    || record.device_generation == tombstone.device_generation) => {}
            InvalidationRecord::TimedOut { .. } => {
                return Err(IoError::StaleInvalidateAttempt);
            }
            _ => {
                return Err(IoError::InvalidInvalidationState {
                    state: invalidation.view(),
                });
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = InvalidateAttempt {
            scope: tombstone.scope,
            target: tombstone.target,
            attempt,
            device_generation: if tombstone.target == InvalidateTarget::Queue {
                record.device_generation
            } else {
                tombstone.device_generation
            },
        };
        let record = self
            .scopes
            .get_mut(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        record.next_attempt = next_attempt;
        let in_flight = InvalidationRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        match tombstone.target {
            InvalidateTarget::Queue => record.queue_lease.invalidation = in_flight,
            InvalidateTarget::Request(request) => {
                self.requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?
                    .invalidation = in_flight;
            }
        }
        self.push_trace(
            IoAction::RetryInvalidate,
            tombstone.scope,
            match tombstone.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(token)
    }

    fn dma_invalidation_pair_valid(
        state: DmaLeaseState,
        invalidation: InvalidationRecord,
        allow_reserved: bool,
    ) -> bool {
        matches!(
            (state, invalidation),
            (DmaLeaseState::Absent, InvalidationRecord::NotStarted) if allow_reserved
        ) || matches!(
            (state, invalidation),
            (DmaLeaseState::Mapped, InvalidationRecord::NotStarted)
                | (
                    DmaLeaseState::UnmappedAwaitingInvalidation,
                    InvalidationRecord::InFlight { .. } | InvalidationRecord::TimedOut { .. }
                )
                | (DmaLeaseState::Released, InvalidationRecord::Acknowledged)
                | (DmaLeaseState::Released, InvalidationRecord::NotStarted)
        )
    }

    fn request_dma_state_valid(request: &RequestRecord) -> bool {
        match request.state {
            IoEffectState::Registered => request.dma_state == DmaLeaseState::Absent,
            IoEffectState::Prepared | IoEffectState::Committed => {
                request.dma_state == DmaLeaseState::Mapped
            }
            IoEffectState::Cancelling => matches!(
                request.dma_state,
                DmaLeaseState::Mapped | DmaLeaseState::UnmappedAwaitingInvalidation
            ),
            IoEffectState::Completed | IoEffectState::IndeterminateAfterReset => matches!(
                request.dma_state,
                DmaLeaseState::Mapped
                    | DmaLeaseState::UnmappedAwaitingInvalidation
                    | DmaLeaseState::Released
            ),
            IoEffectState::Cancelled => request.dma_state == DmaLeaseState::Released,
        }
    }

    fn push_trace(&mut self, action: IoAction, scope: ScopeId, request: Option<RequestId>) {
        let Some(record) = self.scopes.get(&scope) else {
            return;
        };
        self.trace.push(IoTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            request,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
        });
    }
}
