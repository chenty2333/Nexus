//! Executable reference model for mediated VirtIO I/O revocation.
//!
//! The model fixes the Stage 5 protocol boundary: publishing `avail.idx` is
//! the externally visible commit point, a device reset is quiescence rather
//! than rollback, and DMA ownership survives every timeout until a completed
//! IOTLB invalidation permits release. It is a deterministic protocol oracle,
//! not a VirtIO transport, IOMMU implementation, or hardware model.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{ScopeId, ScopeState};

mod helpers;
mod operations;
mod queries;

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
