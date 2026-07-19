// SPDX-License-Identifier: MPL-2.0

//! Root-bound causal infrastructure owned privately by [`super::EffectRegistry`].
//!
//! These records cover kernel execution obligations; they are not business
//! effects and never consume effect credits. The module is a private child of
//! `effect_registry`, so canonical Registry identities are the only vocabulary.
//! Authoritative records are cloneable only into an explicitly
//! non-authoritative transaction candidate. Bearer values are linear Rust
//! values: none implements `Clone` or `Copy`, and a query never recreates one.

use alloc::vec::Vec;
use core::marker::PhantomData;

mod continuation;
mod deadline;
mod delayed;
mod device;
mod fault;
mod invariants;
mod reply;
mod root;
mod service;
mod task;

use self::{
    continuation::validate_continuation_publication_ack,
    delayed::delayed_command_phase_live,
    device::device_phase_live,
    fault::validate_fault_bearer,
    invariants::check_scope_invariants,
    service::{service_request_phase_live, validate_service_request_bearer},
};

use super::{
    CommitReceipt as RegistryCommitReceipt, DeviceClosureReceipt as RegistryDeviceClosureReceipt,
    DeviceEnvelope, DomainKey, EffectKey, PortalHandle, ResourceKey, ScopeKey, TaskKey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InfrastructureLimits {
    pub(crate) workloads: u32,
    pub(crate) tasks: u32,
    pub(crate) service_requests: u32,
    pub(crate) delayed_commands: u32,
    pub(crate) faults: u32,
    pub(crate) continuations: u32,
    pub(crate) deadline_series: u32,
    pub(crate) device_preparations: u32,
    pub(crate) replies: u32,
    pub(crate) queue_slots: u32,
    pub(crate) pinned_pages: u32,
    pub(crate) dma_mappings: u32,
    pub(crate) diagnostic_events: u32,
}

impl InfrastructureLimits {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        workloads: u32,
        tasks: u32,
        service_requests: u32,
        delayed_commands: u32,
        faults: u32,
        continuations: u32,
        deadline_series: u32,
        device_preparations: u32,
        replies: u32,
        queue_slots: u32,
        pinned_pages: u32,
        dma_mappings: u32,
        diagnostic_events: u32,
    ) -> Result<Self, InfrastructureError> {
        if workloads == 0
            || tasks == 0
            || service_requests == 0
            || delayed_commands == 0
            || faults == 0
            || continuations == 0
            || deadline_series == 0
            || device_preparations == 0
            || replies == 0
            || queue_slots == 0
            || pinned_pages == 0
            || dma_mappings == 0
            || diagnostic_events == 0
        {
            return Err(InfrastructureError::InvalidLimits);
        }
        Ok(Self {
            workloads,
            tasks,
            service_requests,
            delayed_commands,
            faults,
            continuations,
            deadline_series,
            device_preparations,
            replies,
            queue_slots,
            pinned_pages,
            dma_mappings,
            diagnostic_events,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InfrastructureKind {
    Workload,
    Task,
    ServiceRequest,
    DelayedCommand,
    Fault,
    Continuation,
    Deadline,
    DevicePreparation,
    Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InfrastructureError {
    InvalidLimits,
    AllocationFailed,
    InvalidGeneration,
    InvalidIdentity,
    UnknownScope,
    UnknownDomain,
    UnknownWorkload,
    UnknownObligation,
    NotEnabled,
    AlreadyEnabled,
    CandidateHasNoAuthority,
    ScopeNotActive,
    ForeignRegistry,
    ForeignScope,
    ForeignRootEffect,
    ForeignParent,
    ForeignWorkload,
    StaleAuthority,
    StaleBinding,
    StaleGeneration,
    StaleClaim,
    ExactReplay,
    IdentityConflict,
    InvalidState,
    InvalidReceipt,
    QuotaExceeded(InfrastructureKind),
    PinnedPageQuotaExceeded,
    DmaMappingQuotaExceeded,
    QueueSlotQuotaExceeded,
    CounterOverflow,
    ClosureBlocked { kind: InfrastructureKind, live: u32 },
    ClosureNotStarted,
    ClosureAlreadyStarted,
    ClosureRetained,
    Invariant(&'static str),
}

/// Retry-safe failure for a transition which consumes a linear bearer.
/// The authoritative record is unchanged and the exact input is returned;
/// callers never have to manufacture a fence merely to recover authority
/// from validation, quota, or stale-observation errors.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LinearFailure<T> {
    error: InfrastructureError,
    input: T,
}

impl<T> LinearFailure<T> {
    pub(crate) const fn error(&self) -> InfrastructureError {
        self.error
    }

    pub(crate) fn into_input(self) -> T {
        self.input
    }

    pub(crate) fn into_parts(self) -> (InfrastructureError, T) {
        (self.error, self.input)
    }
}

type LinearResult<I, O> = Result<O, LinearFailure<I>>;

fn linear_apply<I, O>(
    input: I,
    transition: impl FnOnce(&I) -> Result<O, InfrastructureError>,
) -> LinearResult<I, O> {
    match transition(&input) {
        Ok(output) => Ok(output),
        Err(error) => Err(LinearFailure { error, input }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LedgerMode {
    Authoritative,
    NonAuthoritativeCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestKey {
    id: u64,
    generation: u64,
}

impl RequestKey {
    fn new(id: u64, generation: u64) -> Result<Self, InfrastructureError> {
        if id == 0 || generation == 0 {
            return Err(InfrastructureError::InvalidGeneration);
        }
        Ok(Self { id, generation })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootStamp {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    root_effect: EffectKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainStamp {
    domain: DomainKey,
    binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkloadStamp {
    request: RequestKey,
    nonce: u64,
    bearer_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParentStamp {
    RootEffect(EffectKey),
    Request(RequestKey),
    Task(TaskWorkDescriptor),
    Effect(EffectKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BearerStamp<I> {
    root: RootStamp,
    domain: DomainStamp,
    workload: WorkloadStamp,
    identity: I,
    parent: ParentStamp,
    nonce: u64,
    bearer_generation: u64,
}

/// Compact root authority shared by opaque infrastructure bearers.
///
/// This is deliberately neither `Clone` nor `Copy`: a transition may inspect
/// it through a borrow, but only the authoritative record may mint a successor
/// bearer.  The root effect and all domain/workload/parent coordinates remain
/// in that record and are revalidated on every action.
#[derive(Debug, Eq, PartialEq)]
struct AuthorityKey {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
}

mod bearer_state {
    pub(super) trait Sealed {}

    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum ContinuationPending {}
    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum ContinuationClaimed {}
    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum ContinuationPublishing {}
    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum ContinuationAcknowledged {}
    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum ContinuationResuming {}

    impl Sealed for ContinuationPending {}
    impl Sealed for ContinuationClaimed {}
    impl Sealed for ContinuationPublishing {}
    impl Sealed for ContinuationAcknowledged {}
    impl Sealed for ContinuationResuming {}
}

/// Opaque, state-typed authority for one fixed continuation slot.
///
/// The key intentionally contains no descriptor, domain, source, parent, or
/// workload snapshot.  Those facts have exactly one authoritative copy in
/// `ContinuationRecord`; a key is accepted only after revalidating that full
/// record and matching all of the compact coordinates below.
#[derive(Debug, Eq, PartialEq)]
struct BearerKey<State: bearer_state::Sealed> {
    authority: AuthorityKey,
    slot: u64,
    object_generation: u64,
    bearer_generation: u64,
    nonce: u64,
    state: PhantomData<fn() -> State>,
}

/// Descriptive root coordinates presented when opening or adopting a workload.
///
/// This value is not authority and cannot be used in place of an opaque
/// [`WorkloadContext`]. The authoritative Registry revalidates every field
/// before admitting a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkloadRootPresentation {
    scope: ScopeKey,
    authority_epoch: u64,
    root_effect: EffectKey,
}

impl WorkloadRootPresentation {
    pub(super) const fn new(scope: ScopeKey, authority_epoch: u64, root_effect: EffectKey) -> Self {
        Self {
            scope,
            authority_epoch,
            root_effect,
        }
    }
}

/// Portable request coordinates for one workload admission or fenced adoption.
///
/// The request remains descriptive: construction grants no bearer authority,
/// and the Registry validates the domain epoch and generational identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkloadRequestPresentation {
    domain: DomainKey,
    binding_epoch: u64,
    request_id: u64,
    request_generation: u64,
}

impl WorkloadRequestPresentation {
    pub(super) const fn new(
        domain: DomainKey,
        binding_epoch: u64,
        request_id: u64,
        request_generation: u64,
    ) -> Self {
        Self {
            domain,
            binding_epoch,
            request_id,
            request_generation,
        }
    }
}

/// Opaque, root-specific request context. It is not a process-global context.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WorkloadContext {
    root: RootStamp,
    domain: DomainStamp,
    workload: WorkloadStamp,
    parent: ParentStamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskWorkRole {
    GuestSyscallWork,
    ServiceRequest,
    ReplacementRecovery,
    SupervisorControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VmAuthorityKey {
    id: u64,
    generation: u64,
}

impl VmAuthorityKey {
    pub(crate) fn new(id: u64, generation: u64) -> Result<Self, InfrastructureError> {
        if id == 0 || generation == 0 {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(Self { id, generation })
    }

    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskWorkDescriptor {
    pub(crate) work_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) role: TaskWorkRole,
    pub(crate) vm: Option<VmAuthorityKey>,
}

impl TaskWorkDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.work_id == 0
            || self.generation == 0
            || self.task.generation() == 0
            || (matches!(
                self.role,
                TaskWorkRole::GuestSyscallWork
                    | TaskWorkRole::ServiceRequest
                    | TaskWorkRole::ReplacementRecovery
            ) && self.vm.is_none())
        {
            return Err(InfrastructureError::InvalidGeneration);
        }
        Ok(())
    }
}

/// A root-specific runnable/work admission. It must not be described as the
/// lifetime authority for a process task which existed before the root.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TaskLease(BearerStamp<TaskWorkDescriptor>);

/// Successor returned exactly once by the entry claim. An admitted lease can
/// no longer be reused to run or reap the work item.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EnteredTaskLease(BearerStamp<TaskWorkDescriptor>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskRecoveryState {
    Admitted,
    Entered,
    Rejected,
    Isolated,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskRecoveryProjection {
    pub(crate) descriptor: TaskWorkDescriptor,
    pub(crate) state: TaskRecoveryState,
    pub(crate) live_children: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TaskAdoption {
    Admitted(TaskLease),
    Entered(EnteredTaskLease),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceRequestDescriptor {
    pub(crate) request_id: u64,
    pub(crate) generation: u64,
    pub(crate) queue: ResourceKey,
    pub(crate) queue_generation: u64,
    pub(crate) destination_domain: DomainKey,
    pub(crate) destination_binding_epoch: u64,
    pub(crate) command_digest: u64,
    pub(crate) payload_slot: u32,
    pub(crate) payload_generation: u64,
    pub(crate) response_slot_id: u64,
    pub(crate) response_slot_generation: u64,
}

impl ServiceRequestDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.request_id == 0
            || self.generation == 0
            || self.queue.generation() == 0
            || self.queue_generation == 0
            || self.destination_binding_epoch == 0
            || self.command_digest == 0
            || self.payload_generation == 0
            || self.response_slot_id == 0
            || self.response_slot_generation == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceRequestTicket(BearerStamp<ServiceRequestDescriptor>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceEnqueueIntent {
    request: BearerStamp<ServiceRequestDescriptor>,
    bound_continuation: BearerStamp<ContinuationDescriptor>,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceEnqueueReceipt {
    pub(crate) queue: ResourceKey,
    pub(crate) queue_generation: u64,
    pub(crate) payload_slot: u32,
    pub(crate) payload_generation: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UnarmedServiceRequest {
    request: BearerStamp<ServiceRequestDescriptor>,
    receipt: ServiceEnqueueReceipt,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceArmIntent {
    request: BearerStamp<ServiceRequestDescriptor>,
    queue_receipt: ServiceEnqueueReceipt,
    bound_continuation: BearerStamp<ContinuationDescriptor>,
    arm_generation: u64,
    arm_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceArmReceipt {
    pub(crate) response_slot_id: u64,
    pub(crate) response_slot_generation: u64,
    pub(crate) bound_continuation_id: u64,
    pub(crate) bound_continuation_generation: u64,
    pub(crate) arm_generation: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EnqueuedServiceRequest {
    request: BearerStamp<ServiceRequestDescriptor>,
    queue_receipt: ServiceEnqueueReceipt,
    arm_receipt: ServiceArmReceipt,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceClaim {
    request: BearerStamp<ServiceRequestDescriptor>,
    queue_receipt: ServiceEnqueueReceipt,
    arm_receipt: ServiceArmReceipt,
    claim_generation: u64,
    claim_nonce: u64,
    claimant: TaskWorkDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceChildReceipt {
    pub(crate) child_effect: EffectKey,
    pub(crate) registration_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ValidatedServiceChildProof {
    receipt: ServiceChildReceipt,
}

impl ValidatedServiceChildProof {
    pub(super) const fn new(receipt: ServiceChildReceipt) -> Self {
        Self { receipt }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BoundServiceRequest {
    request: BearerStamp<ServiceRequestDescriptor>,
    queue_receipt: ServiceEnqueueReceipt,
    arm_receipt: ServiceArmReceipt,
    child_receipt: ServiceChildReceipt,
    claimant: TaskWorkDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceCompletionReceipt {
    pub(crate) request_id: u64,
    pub(crate) generation: u64,
    pub(crate) child_effect: EffectKey,
    pub(crate) result_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceCompletionOutcome {
    pub(crate) receipt: ServiceCompletionReceipt,
    pub(crate) response: ContinuationLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceRequestRecoveryState {
    ReservedUnbound,
    ReservedBound,
    EnqueueUncertain,
    QueueWrittenUnarmed,
    ArmUncertain,
    Armed,
    Claimed,
    ChildBound,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceRequestRecoveryProjection {
    pub(crate) descriptor: ServiceRequestDescriptor,
    pub(crate) state: ServiceRequestRecoveryState,
    pub(crate) enqueue_receipt: Option<ServiceEnqueueReceipt>,
    pub(crate) arm_receipt: Option<ServiceArmReceipt>,
    pub(crate) child_receipt: Option<ServiceChildReceipt>,
    pub(crate) completion_receipt: Option<ServiceCompletionReceipt>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ServiceRequestAdoption {
    Reserved(ServiceRequestTicket),
    ReplayEnqueue(ServiceEnqueueIntent),
    QueueWrittenUnarmed(UnarmedServiceRequest),
    ReplayArm(ServiceArmIntent),
    Enqueued(EnqueuedServiceRequest),
    Claimed(ServiceClaim),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandDescriptor {
    pub(crate) command_id: u64,
    pub(crate) generation: u64,
    pub(crate) request_id: u64,
    pub(crate) request_generation: u64,
    pub(crate) destination_domain: DomainKey,
    pub(crate) destination_binding_epoch: u64,
    pub(crate) sender: TaskKey,
    pub(crate) target: PortalHandle,
    pub(crate) command_digest: u64,
    pub(crate) actor_slot: u32,
    pub(crate) actor_generation: u64,
}

impl DelayedCommandDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.command_id == 0
            || self.generation == 0
            || self.request_id == 0
            || self.request_generation == 0
            || self.destination_binding_epoch == 0
            || self.sender.generation() == 0
            || self.target.effect().generation() == 0
            || self.command_digest == 0
            || self.actor_generation == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandTicket(BearerStamp<DelayedCommandDescriptor>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandIntent {
    command: BearerStamp<DelayedCommandDescriptor>,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandReceipt {
    pub(crate) actor_slot: u32,
    pub(crate) actor_generation: u64,
    pub(crate) command_digest: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DelayedCommandRejectionReason {
    StaleTarget,
    RequestAborted,
    ClosureDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandRejectionReceipt {
    pub(crate) reason: DelayedCommandRejectionReason,
    pub(crate) target_effect: EffectKey,
    pub(crate) evidence_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DelayedCommandRecoveryState {
    Reserved,
    PublicationUncertain,
    Issued,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelayedCommandRecoveryProjection {
    pub(crate) descriptor: DelayedCommandDescriptor,
    pub(crate) state: DelayedCommandRecoveryState,
    pub(crate) receipt: Option<DelayedCommandReceipt>,
    pub(crate) rejection: Option<DelayedCommandRejectionReceipt>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ValidatedAbortProof {
    evidence_digest: u64,
}

impl ValidatedAbortProof {
    pub(super) const fn new(evidence_digest: u64) -> Self {
        Self { evidence_digest }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultAccess {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FaultDescriptor {
    pub(crate) fault_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) instruction_pointer: u64,
    pub(crate) address: u64,
    pub(crate) access: FaultAccess,
    pub(crate) architecture_error: u64,
    pub(crate) service_domain: DomainKey,
    pub(crate) service_binding_epoch: u64,
}

impl FaultDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.fault_id == 0
            || self.generation == 0
            || self.task.generation() == 0
            || self.vm_generation == 0
            || self.instruction_pointer == 0
            || self.service_binding_epoch == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FaultEvent(BearerStamp<FaultDescriptor>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ArmedFaultEvent(BearerStamp<FaultDescriptor>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultDisposition {
    CrashService,
    IsolateTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FaultObservation {
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) instruction_pointer: u64,
    pub(crate) address: u64,
    pub(crate) access: FaultAccess,
    pub(crate) architecture_error: u64,
    pub(crate) evidence_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceFaultProjection {
    pub(crate) fault_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) disposition: FaultDisposition,
    pub(crate) service_domain: DomainKey,
    pub(crate) closed_binding_epoch: u64,
    pub(crate) crash_generation: u64,
    pub(crate) evidence_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceFaultReceipt {
    fault: BearerStamp<FaultDescriptor>,
    projection: ServiceFaultProjection,
    receipt_generation: u64,
    receipt_nonce: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceCrashCause {
    projection: ServiceFaultProjection,
    consume_generation: u64,
    consume_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FaultRecoveryProjection {
    pub(crate) descriptor: FaultDescriptor,
    pub(crate) receipt: Option<ServiceFaultProjection>,
    pub(crate) consumed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct FaultDispositionPlan {
    event: BearerStamp<FaultDescriptor>,
    task: BearerStamp<TaskWorkDescriptor>,
    projection: ServiceFaultProjection,
    base_revision: u64,
    next_binding_epoch: u64,
    receipt_generation: u64,
    receipt_nonce: u64,
    next_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AppliedFaultDisposition {
    event: BearerStamp<FaultDescriptor>,
    projection: ServiceFaultProjection,
    receipt_generation: u64,
    receipt_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationDescriptor {
    pub(crate) continuation_id: u64,
    pub(crate) generation: u64,
    pub(crate) vm_generation: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
}

impl ContinuationDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.continuation_id == 0
            || self.generation == 0
            || self.vm_generation == 0
            || self.source_binding_epoch == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationLease(BearerKey<bearer_state::ContinuationPending>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WakeClaim(BearerKey<bearer_state::ContinuationClaimed>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationPublicationReceipt {
    pub(crate) vm_generation: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
    pub(crate) outcome_digest: u64,
}

/// External publication acknowledgement.  This value is descriptive evidence,
/// not authority: only the separate one-shot publication bearer may consume it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationPublicationAckReceipt {
    pub(crate) continuation_id: u64,
    pub(crate) generation: u64,
    pub(crate) claim_generation: u64,
    pub(crate) claim_nonce: u64,
    pub(crate) apply_generation: u64,
    pub(crate) apply_nonce: u64,
    pub(crate) publication_sequence: u64,
    pub(crate) vm_generation: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
    pub(crate) outcome_digest: u64,
    pub(crate) external_receipt_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationPublicationAuthority(BearerKey<bearer_state::ContinuationPublishing>);

/// Copyable instructions for the external publication apply. Copying this
/// value never copies authority; acknowledgement consumes the separate opaque
/// authority exactly once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationPublicationPlan {
    pub(crate) descriptor: ContinuationDescriptor,
    pub(crate) claim_generation: u64,
    pub(crate) claim_nonce: u64,
    pub(crate) apply_generation: u64,
    pub(crate) apply_nonce: u64,
    pub(crate) publication_sequence: u64,
    pub(crate) receipt: ContinuationPublicationReceipt,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationPublicationIntent {
    authority: ContinuationPublicationAuthority,
    plan: ContinuationPublicationPlan,
}

impl ContinuationPublicationIntent {
    pub(crate) const fn plan(&self) -> ContinuationPublicationPlan {
        self.plan
    }

    pub(crate) fn into_authority(self) -> ContinuationPublicationAuthority {
        self.authority
    }
}

/// Receipt which alone gates the post-publication resume path.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationAckReceipt(BearerKey<bearer_state::ContinuationAcknowledged>);

/// Persisted-before-wake successor. Replaying this intent after a fence is
/// idempotent by the Registry-minted publication sequence.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationResumeAuthority(BearerKey<bearer_state::ContinuationResuming>);

/// Copyable instructions for the external resume apply. Completion consumes
/// the separate linear authority, never this descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationResumePlan {
    pub(crate) descriptor: ContinuationDescriptor,
    pub(crate) publication_ack: ContinuationPublicationAckReceipt,
    pub(crate) publication_sequence: u64,
    pub(crate) outcome_digest: u64,
    pub(crate) ack_generation: u64,
    pub(crate) ack_nonce: u64,
    pub(crate) resume_generation: u64,
    pub(crate) resume_nonce: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ContinuationResumeIntent {
    authority: ContinuationResumeAuthority,
    plan: ContinuationResumePlan,
}

impl ContinuationResumeIntent {
    pub(crate) const fn plan(&self) -> ContinuationResumePlan {
        self.plan
    }

    pub(crate) fn into_authority(self) -> ContinuationResumeAuthority {
        self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationResumeReceipt {
    pub(crate) continuation_id: u64,
    pub(crate) generation: u64,
    pub(crate) publication_sequence: u64,
    pub(crate) vm_generation: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
    pub(crate) outcome_digest: u64,
    pub(crate) ack_generation: u64,
    pub(crate) ack_nonce: u64,
    pub(crate) resume_generation: u64,
    pub(crate) resume_nonce: u64,
    pub(crate) external_receipt_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContinuationRecoveryState {
    Pending,
    Claimed,
    PublicationUncertain,
    AcknowledgedPendingResume { publication_sequence: u64 },
    ResumeUncertain { publication_sequence: u64 },
    Resumed { publication_sequence: u64 },
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationRecoveryProjection {
    pub(crate) descriptor: ContinuationDescriptor,
    pub(crate) parent_task: TaskWorkDescriptor,
    pub(crate) state: ContinuationRecoveryState,
    pub(crate) claim_generation: u64,
    pub(crate) publication_ack: Option<ContinuationPublicationAckReceipt>,
    pub(crate) resume_receipt: Option<ContinuationResumeReceipt>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ContinuationAdoption {
    Pending(ContinuationLease),
    Claimed(WakeClaim),
    ReplayPublication(ContinuationPublicationIntent),
    Acknowledged(ContinuationAckReceipt),
    ReplayResume(ContinuationResumeIntent),
}

const _: () = {
    assert!(core::mem::size_of::<AuthorityKey>() <= 32);
    assert!(core::mem::size_of::<BearerKey<bearer_state::ContinuationPending>>() <= 64);
    assert!(core::mem::size_of::<ContinuationLease>() <= 96);
    assert!(core::mem::size_of::<WakeClaim>() <= 96);
    assert!(core::mem::size_of::<ContinuationPublicationAuthority>() <= 96);
    assert!(core::mem::size_of::<ContinuationPublicationAckReceipt>() <= 96);
    assert!(core::mem::size_of::<ContinuationAckReceipt>() <= 96);
    assert!(core::mem::size_of::<ContinuationResumeAuthority>() <= 96);
    assert!(core::mem::size_of::<ContinuationResumeReceipt>() <= 96);
    assert!(core::mem::size_of::<LinearFailure<ContinuationLease>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<WakeClaim>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationPublicationAuthority>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationAckReceipt>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationResumeAuthority>>() <= 120);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlinePurpose {
    Wait,
    Retry,
    Recovery,
    DeviceClosure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineClockBasis {
    /// Count observed by the injected timer callback. This tranche does not
    /// claim wall-clock or true monotonic-time semantics.
    ObservedCallbackTick,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeadlineDescriptor {
    pub(crate) series_id: u64,
    pub(crate) generation: u64,
    pub(crate) purpose: DeadlinePurpose,
    pub(crate) clock: DeadlineClockBasis,
    pub(crate) deadline_tick: u64,
    pub(crate) attempt: u32,
    pub(crate) max_attempts: u32,
    pub(crate) backoff_ticks: u64,
}

impl DeadlineDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.series_id == 0
            || self.generation == 0
            || self.deadline_tick == 0
            || self.attempt == 0
            || self.max_attempts == 0
            || self.attempt > self.max_attempts
            || self.backoff_ticks == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DeadlineLease(BearerStamp<DeadlineDescriptor>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DeadlineExpiryReceipt {
    deadline: BearerStamp<DeadlineDescriptor>,
    observed_tick: u64,
    expiry_nonce: u64,
    exhausted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineRecoveryState {
    Armed,
    Fired,
    ExhaustedRetained,
    QuarantinedRetained,
    Cancelled,
    Resolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeadlineRecoveryProjection {
    pub(crate) descriptor: DeadlineDescriptor,
    pub(crate) parent_task: TaskWorkDescriptor,
    pub(crate) state: DeadlineRecoveryState,
    pub(crate) observed_tick: Option<u64>,
    pub(crate) reconciliation: Option<DeadlineReconciliationReceipt>,
    pub(crate) terminal_evidence_digest: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineExhaustedDisposition {
    AbortWork,
    RetryBySupervisor,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeadlineReconciliationReceipt {
    pub(crate) disposition: DeadlineExhaustedDisposition,
    pub(crate) evidence_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeadlineSupervisorRetry {
    pub(crate) generation: u64,
    pub(crate) deadline_tick: u64,
    pub(crate) max_attempts: u32,
    pub(crate) backoff_ticks: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DeadlineQuarantineTicket {
    deadline: BearerStamp<DeadlineDescriptor>,
    receipt: DeadlineReconciliationReceipt,
    quarantine_generation: u64,
    quarantine_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeadlineQuarantineReleaseReceipt {
    pub(crate) evidence_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeadlineReconciliationOutcome {
    Aborted,
    Retried(DeadlineLease),
    Quarantined(DeadlineQuarantineTicket),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeadlineAdoption {
    Armed(DeadlineLease),
    Fired(DeadlineExpiryReceipt),
    Exhausted(DeadlineExpiryReceipt),
    Quarantined(DeadlineQuarantineTicket),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceReservationCoordinates {
    pub(crate) preparation_id: u64,
    pub(crate) generation: u64,
    /// Registry-owned device/BDF resource. Session and descriptor-token
    /// identity do not exist until the hardware apply succeeds.
    pub(crate) owned_device: ResourceKey,
    pub(crate) queue: u16,
    pub(crate) device_generation: u64,
    pub(crate) operation_digest: u64,
    pub(crate) queue_slots: u32,
    pub(crate) pinned_pages: u32,
    pub(crate) dma_mappings: u32,
    /// Index of a preallocated kernel adapter slot which will own the linear
    /// prepared request before hardware success is acknowledged.
    pub(crate) actor_slot: u32,
}

impl DeviceReservationCoordinates {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.preparation_id == 0
            || self.generation == 0
            || self.device_generation == 0
            || self.operation_digest == 0
            || self.queue_slots != 1
            || self.pinned_pages == 0
            || self.dma_mappings == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DevicePreparationTicket(BearerStamp<DeviceReservationCoordinates>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DeviceApplyIntent {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DeviceMaterializationPlan {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    owner: PreparedOwner,
    base_revision: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MaterializedDeviceTicket {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    owner: PreparedOwner,
    cohort_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ValidatedDeviceClosureProof {
    receipt: RegistryDeviceClosureReceipt,
}

impl ValidatedDeviceClosureProof {
    pub(super) const fn new(receipt: RegistryDeviceClosureReceipt) -> Self {
        Self { receipt }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceHardwareReceipt {
    pub(crate) owned_device: ResourceKey,
    pub(crate) device: DeviceEnvelope,
    pub(crate) operation_digest: u64,
    pub(crate) actor_slot: u32,
    pub(crate) hardware_receipt_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceRollbackReceipt {
    pub(crate) owned_device: ResourceKey,
    pub(crate) queue: u16,
    pub(crate) device_generation: u64,
    pub(crate) operation_digest: u64,
    pub(crate) actor_slot: u32,
    pub(crate) rollback_receipt_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevicePreparationRecoveryState {
    Reserved,
    ApplyingHardware,
    PreparedRetained,
    Materialized,
    Released,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DevicePreparationRecoveryProjection {
    pub(crate) coordinates: DeviceReservationCoordinates,
    pub(crate) parent_effect: EffectKey,
    pub(crate) state: DevicePreparationRecoveryState,
    pub(crate) prepared_device: Option<DeviceEnvelope>,
    pub(crate) cohort_digest: Option<u64>,
    pub(crate) rollback_receipt: Option<DeviceRollbackReceipt>,
    pub(crate) closure_receipt: Option<RegistryDeviceClosureReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedOwner {
    owned_device: ResourceKey,
    device: DeviceEnvelope,
    operation_digest: u64,
    actor_slot: u32,
    hardware_receipt_digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyDescriptor {
    pub(crate) reply_id: u64,
    pub(crate) generation: u64,
    pub(crate) guest_task: TaskKey,
    pub(crate) guest_vm_generation: u64,
    pub(crate) descriptor_digest: u64,
    pub(crate) result_digest: u64,
    pub(crate) byte_count: u64,
    pub(crate) destination_digest: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
    /// Exact preallocated FsClosureWork/FsDeviceFlight payload selector.
    pub(crate) payload_slot: u32,
    pub(crate) payload_generation: u64,
    pub(crate) flight_cookie: u64,
}

impl ReplyDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.reply_id == 0
            || self.generation == 0
            || self.guest_task.generation() == 0
            || self.guest_vm_generation == 0
            || self.descriptor_digest == 0
            || self.result_digest == 0
            || self.destination_digest == 0
            || self.source_binding_epoch == 0
            || self.payload_generation == 0
            || self.flight_cookie == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReplyRecord(BearerStamp<ReplyDescriptor>);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReplyClaim {
    reply: BearerStamp<ReplyDescriptor>,
    claim_generation: u64,
    claim_nonce: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReplyPublicationIntent {
    reply: BearerStamp<ReplyDescriptor>,
    claim_generation: u64,
    claim_nonce: u64,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyPublicationReceipt {
    pub(crate) payload_slot: u32,
    pub(crate) payload_generation: u64,
    pub(crate) flight_cookie: u64,
    pub(crate) descriptor_digest: u64,
    pub(crate) result_digest: u64,
    pub(crate) byte_count: u64,
    pub(crate) destination_digest: u64,
    pub(crate) backend_effect: EffectKey,
    pub(crate) backend_commit_sequence: u64,
    pub(crate) external_apply_digest: u64,
}

/// Receipt which alone gates the guest wake following reply publication.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReplyAckReceipt {
    reply: BearerStamp<ReplyDescriptor>,
    backend_effect: EffectKey,
    backend_commit_sequence: u64,
    publication_receipt: ReplyPublicationReceipt,
    ack_generation: u64,
    ack_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyCompletionReceipt {
    pub(crate) reply_id: u64,
    pub(crate) generation: u64,
    pub(crate) backend_effect: EffectKey,
    pub(crate) backend_commit_sequence: u64,
    pub(crate) external_apply_digest: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ValidatedCommitProof {
    receipt: RegistryCommitReceipt,
}

impl ValidatedCommitProof {
    pub(super) fn new(receipt: RegistryCommitReceipt) -> Self {
        Self { receipt }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyRecoveryState {
    Prepared,
    Claimed,
    PublicationUncertain,
    AcknowledgedPendingWake,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyRecoveryProjection {
    pub(crate) descriptor: ReplyDescriptor,
    pub(crate) backend_effect: EffectKey,
    pub(crate) backend_commit_sequence: u64,
    pub(crate) state: ReplyRecoveryState,
    pub(crate) claim_generation: u64,
    pub(crate) publication_receipt: Option<ReplyPublicationReceipt>,
    pub(crate) completion_receipt: Option<ReplyCompletionReceipt>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyAdoption {
    Prepared(ReplyRecord),
    Claimed(ReplyClaim),
    ReplayPublication(ReplyPublicationIntent),
    Acknowledged(ReplyAckReceipt),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InfrastructureLiveCounts {
    pub(crate) workloads: u32,
    pub(crate) tasks: u32,
    pub(crate) service_requests: u32,
    pub(crate) delayed_commands: u32,
    pub(crate) faults: u32,
    pub(crate) continuations: u32,
    pub(crate) deadlines: u32,
    pub(crate) device_preparations: u32,
    pub(crate) replies: u32,
    pub(crate) queue_slots: u32,
    pub(crate) pinned_pages: u32,
    pub(crate) dma_mappings: u32,
}

/// Independently reconstructed use of the three retained-device resources.
///
/// This is a projection of primary [`DeviceRecord`] phase and immutable
/// reservation coordinates.  It is deliberately separate from
/// [`InfrastructureLiveCounts`]: the latter is stored accounting which must
/// be checked, never an input to this recomputation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResourceUsage {
    pub(crate) queue_slots: u32,
    pub(crate) pinned_pages: u32,
    pub(crate) dma_mappings: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InfrastructureEventKind {
    WorkloadOpened,
    WorkloadAdopted,
    WorkloadClosed,
    TaskAdmitted,
    TaskEntered,
    TaskRejected,
    TaskIsolated,
    TaskReaped,
    ServiceRequestReserved,
    ServiceRequestPublishing,
    ServiceRequestEnqueued,
    ServiceRequestClaimed,
    ServiceRequestChildBound,
    ServiceRequestCompleted,
    ServiceRequestCancelled,
    DelayedCommandReserved,
    DelayedCommandPublishing,
    DelayedCommandIssued,
    DelayedCommandRejected,
    FaultReserved,
    FaultObserved,
    ContinuationCreated,
    ContinuationClaimed,
    ContinuationPublishing,
    ContinuationAcknowledged,
    ContinuationCancelled,
    DeadlineArmed,
    DeadlineFired,
    DeadlineRearmed,
    DeadlineCancelled,
    DeadlineResolved,
    DeadlineExhaustedResolved,
    DeviceReserved,
    DeviceApplying,
    DeviceRolledBack,
    DevicePreparedRetained,
    DeviceMaterialized,
    DeviceReleased,
    DeviceCancelled,
    ReplyPrepared,
    ReplyClaimed,
    ReplyPublishing,
    ReplyAcknowledged,
    ReplyCancelled,
    ClosureStarted,
    ClosureFinished,
    DomainFenced,
    AuthorityAdvanced,
    ScopeRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InfrastructureEvent {
    pub(crate) sequence: u64,
    pub(crate) kind: InfrastructureEventKind,
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InfrastructureDiagnostics {
    pub(crate) scope: ScopeKey,
    pub(crate) authority_epoch: u64,
    pub(crate) root_effect: EffectKey,
    pub(crate) revision: u64,
    pub(crate) limits: InfrastructureLimits,
    pub(crate) live: InfrastructureLiveCounts,
    pub(crate) events: Vec<InfrastructureEvent>,
    pub(crate) dropped_events: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InfrastructureRecoveryProjection {
    pub(crate) revision: u64,
    pub(crate) domain: Option<DomainKey>,
    pub(crate) binding_epoch: Option<u64>,
    pub(crate) live: InfrastructureLiveCounts,
    pub(crate) claimed_publications: u32,
    pub(crate) uncertain_publications: u32,
    pub(crate) prepared_or_applying_devices: u32,
    pub(crate) digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InfrastructureHandoffReadiness {
    Ready,
    NeedsAbort,
    PublicationPending,
    BlockedRetained,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InfrastructureClosureSelection {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    sequence: u64,
    nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InfrastructureClosureWorkState {
    Cancellable,
    MustIsolate,
    PublicationClaimed,
    PublicationUncertain,
    PreparedRetained,
    ExhaustedRetained,
    Workload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InfrastructureClosureWork {
    pub(crate) kind: InfrastructureKind,
    pub(crate) id: u64,
    pub(crate) generation: u64,
    pub(crate) state: InfrastructureClosureWorkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkloadPhase {
    Open,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkloadRecord {
    request: RequestKey,
    root_effect: EffectKey,
    parent: ParentStamp,
    domain: DomainKey,
    admission_binding_epoch: u64,
    current_binding_epoch: u64,
    nonce: u64,
    bearer_generation: u64,
    phase: WorkloadPhase,
    live_children: u32,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskPhase {
    Admitted,
    Entered,
    Rejected,
    Isolated,
    Reaped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TaskRecord {
    stamp: BearerStamp<TaskWorkDescriptor>,
    phase: TaskPhase,
    live_children: u32,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRequestPhase {
    ReservedUnbound,
    ReservedBound,
    Publishing {
        apply_generation: u64,
        apply_nonce: u64,
    },
    QueueWrittenUnarmed {
        queue_receipt: ServiceEnqueueReceipt,
    },
    Arming {
        queue_receipt: ServiceEnqueueReceipt,
        arm_generation: u64,
        arm_nonce: u64,
    },
    Armed {
        queue_receipt: ServiceEnqueueReceipt,
        arm_receipt: ServiceArmReceipt,
    },
    Claimed {
        queue_receipt: ServiceEnqueueReceipt,
        arm_receipt: ServiceArmReceipt,
        claim_generation: u64,
        claim_nonce: u64,
        claimant: TaskWorkDescriptor,
    },
    ChildBound {
        queue_receipt: ServiceEnqueueReceipt,
        arm_receipt: ServiceArmReceipt,
        child_receipt: ServiceChildReceipt,
        claimant: TaskWorkDescriptor,
    },
    Completed {
        receipt: ServiceCompletionReceipt,
    },
    Cancelled {
        evidence_digest: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceRequestStateRecord {
    stamp: BearerStamp<ServiceRequestDescriptor>,
    bound_continuation: Option<BearerStamp<ContinuationDescriptor>>,
    apply_generation: u64,
    arm_generation: u64,
    claim_generation: u64,
    phase: ServiceRequestPhase,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DelayedCommandPhase {
    Reserved,
    Publishing {
        apply_generation: u64,
        apply_nonce: u64,
    },
    Issued {
        receipt: DelayedCommandReceipt,
    },
    Rejected {
        receipt: DelayedCommandRejectionReceipt,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DelayedCommandStateRecord {
    stamp: BearerStamp<DelayedCommandDescriptor>,
    apply_generation: u64,
    phase: DelayedCommandPhase,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPhase {
    Reserved,
    Observed {
        projection: ServiceFaultProjection,
        receipt_generation: u64,
        receipt_nonce: u64,
        consumed: bool,
        consume_generation: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FaultStateRecord {
    stamp: BearerStamp<FaultDescriptor>,
    phase: FaultPhase,
    receipt_generation: u64,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContinuationPhase {
    Pending,
    Claimed {
        claim_generation: u64,
        claim_nonce: u64,
        outcome_digest: u64,
    },
    Publishing {
        claim_generation: u64,
        claim_nonce: u64,
        apply_generation: u64,
        apply_nonce: u64,
        publication_sequence: u64,
        receipt: ContinuationPublicationReceipt,
    },
    Acknowledged {
        publication_sequence: u64,
        outcome_digest: u64,
        ack_generation: u64,
        ack_nonce: u64,
    },
    Resuming {
        publication_sequence: u64,
        outcome_digest: u64,
        ack_generation: u64,
        ack_nonce: u64,
        resume_generation: u64,
        resume_nonce: u64,
    },
    Resumed {
        publication_sequence: u64,
        receipt: ContinuationResumeReceipt,
    },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContinuationRecord {
    stamp: BearerStamp<ContinuationDescriptor>,
    origin_source: DomainStamp,
    claim_generation: u64,
    apply_generation: u64,
    ack_generation: u64,
    resume_generation: u64,
    publication_ack: Option<ContinuationPublicationAckReceipt>,
    service_owner: Option<RequestKey>,
    phase: ContinuationPhase,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeadlinePhase {
    Armed,
    Fired {
        expiry_nonce: u64,
        observed_tick: u64,
    },
    ExhaustedRetained {
        expiry_nonce: u64,
        observed_tick: u64,
    },
    QuarantinedRetained {
        observed_tick: u64,
        receipt: DeadlineReconciliationReceipt,
        quarantine_generation: u64,
        quarantine_nonce: u64,
    },
    Cancelled,
    Resolved {
        reconciliation: Option<DeadlineReconciliationReceipt>,
        terminal_evidence_digest: Option<u64>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeadlineRecord {
    stamp: BearerStamp<DeadlineDescriptor>,
    series_nonce: u64,
    quarantine_generation: u64,
    last_reconciliation: Option<DeadlineReconciliationReceipt>,
    terminal_evidence_digest: Option<u64>,
    phase: DeadlinePhase,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevicePhase {
    Reserved,
    Applying {
        apply_generation: u64,
        apply_nonce: u64,
    },
    PreparedRetained {
        owner: PreparedOwner,
    },
    Materialized {
        owner: PreparedOwner,
        cohort_digest: u64,
        preparation_credits_transferred: bool,
    },
    Released {
        owner: PreparedOwner,
        cohort_digest: Option<u64>,
        closure: RegistryDeviceClosureReceipt,
    },
    Cancelled {
        rollback: Option<DeviceRollbackReceipt>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeviceAdoption {
    Reserved(DevicePreparationTicket),
    ReplayApply(DeviceApplyIntent),
    Prepared(DevicePreparationTicket),
    Materialized(MaterializedDeviceTicket),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceRecord {
    stamp: BearerStamp<DeviceReservationCoordinates>,
    apply_generation: u64,
    phase: DevicePhase,
    closure_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyPhase {
    Prepared,
    Claimed {
        claim_generation: u64,
        claim_nonce: u64,
    },
    Publishing {
        claim_generation: u64,
        claim_nonce: u64,
        apply_generation: u64,
        apply_nonce: u64,
    },
    Acknowledged {
        publication_receipt: ReplyPublicationReceipt,
        ack_generation: u64,
        ack_nonce: u64,
    },
    Completed {
        receipt: ReplyCompletionReceipt,
    },
    Cancelled {
        evidence_digest: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplyStateRecord {
    stamp: BearerStamp<ReplyDescriptor>,
    backend_commit: RegistryCommitReceipt,
    claim_generation: u64,
    apply_generation: u64,
    ack_generation: u64,
    phase: ReplyPhase,
    closure_sequence: Option<u64>,
}

trait SlotIdentity {
    fn slot_id(&self) -> u64;
}

impl SlotIdentity for WorkloadRecord {
    fn slot_id(&self) -> u64 {
        self.request.id
    }
}

impl SlotIdentity for TaskRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.work_id
    }
}

impl SlotIdentity for ServiceRequestStateRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.request_id
    }
}

impl SlotIdentity for DelayedCommandStateRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.command_id
    }
}

impl SlotIdentity for FaultStateRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.fault_id
    }
}

impl SlotIdentity for ContinuationRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.continuation_id
    }
}

impl SlotIdentity for DeadlineRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.series_id
    }
}

impl SlotIdentity for DeviceRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.preparation_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReverseParent {
    RootEffect(EffectKey),
    Request(RequestKey),
    Task(TaskWorkDescriptor),
    Effect(EffectKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReverseIndexRecord {
    slot: u64,
    kind: InfrastructureKind,
    root_effect: EffectKey,
    parent: ReverseParent,
    task: Option<TaskKey>,
    domain: DomainKey,
    binding_epoch: u64,
    source_domain: Option<DomainKey>,
    source_binding_epoch: Option<u64>,
    resource: Option<ResourceKey>,
    actor_slot: Option<u32>,
    retry_generation: u64,
}

impl SlotIdentity for ReverseIndexRecord {
    fn slot_id(&self) -> u64 {
        self.slot
    }
}

impl SlotIdentity for ReplyStateRecord {
    fn slot_id(&self) -> u64 {
        self.stamp.identity.reply_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixedSlots<T> {
    slots: Vec<Option<T>>,
}

impl<T> FixedSlots<T> {
    fn try_new(limit: u32) -> Result<Self, InfrastructureError> {
        let limit = usize::try_from(limit).map_err(|_| InfrastructureError::InvalidLimits)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        slots.resize_with(limit, || None);
        Ok(Self { slots })
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(Option::as_ref)
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().filter_map(Option::as_mut)
    }
}

impl<T: Clone> FixedSlots<T> {
    fn try_candidate_clone(&self) -> Result<Self, InfrastructureError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(self.slots.len())
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        for slot in &self.slots {
            slots.push(slot.clone());
        }
        Ok(Self { slots })
    }
}

impl<T: SlotIdentity> FixedSlots<T> {
    fn get(&self, id: u64) -> Option<&T> {
        self.iter().find(|record| record.slot_id() == id)
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        self.iter_mut().find(|record| record.slot_id() == id)
    }

    fn install(
        &mut self,
        record: T,
        quota_kind: InfrastructureKind,
    ) -> Result<(), InfrastructureError> {
        if let Some(existing) = self.slots.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|item| item.slot_id() == record.slot_id())
        }) {
            *existing = Some(record);
            return Ok(());
        }
        let vacant = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(InfrastructureError::QuotaExceeded(quota_kind))?;
        *vacant = Some(record);
        Ok(())
    }

    fn has_vacancy_or_id(&self, id: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_none() || slot.as_ref().is_some_and(|item| item.slot_id() == id))
    }

    fn remove(&mut self, id: u64) -> Option<T> {
        self.slots
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|item| item.slot_id() == id))
            .and_then(Option::take)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventRing {
    slots: Vec<Option<InfrastructureEvent>>,
    next: usize,
    len: usize,
    dropped: u64,
    next_sequence: u64,
}

impl EventRing {
    fn try_new(limit: u32) -> Result<Self, InfrastructureError> {
        let limit = usize::try_from(limit).map_err(|_| InfrastructureError::InvalidLimits)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        slots.resize_with(limit, || None);
        Ok(Self {
            slots,
            next: 0,
            len: 0,
            dropped: 0,
            next_sequence: 1,
        })
    }

    fn push(&mut self, kind: InfrastructureEventKind, id: u64, generation: u64) {
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };
        if self.len == self.slots.len() {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.len += 1;
        }
        self.slots[self.next] = Some(InfrastructureEvent {
            sequence: self.next_sequence,
            kind,
            id,
            generation,
        });
        self.next = (self.next + 1) % self.slots.len();
        self.next_sequence = next_sequence;
    }

    fn snapshot(&self) -> Vec<InfrastructureEvent> {
        let mut events = Vec::with_capacity(self.len);
        let start = if self.len == self.slots.len() {
            self.next
        } else {
            0
        };
        for offset in 0..self.len {
            let index = (start + offset) % self.slots.len();
            if let Some(event) = self.slots[index] {
                events.push(event);
            }
        }
        events
    }

    fn try_candidate_clone(&self) -> Result<Self, InfrastructureError> {
        Ok(Self {
            slots: FixedSlots::<InfrastructureEventSlot>::try_clone_option_vec(&self.slots)?,
            next: self.next,
            len: self.len,
            dropped: self.dropped,
            next_sequence: self.next_sequence,
        })
    }
}

// Type-only helper used to share the fallible Option-vector clone without
// making diagnostic entries into authoritative slots.
struct InfrastructureEventSlot;

impl FixedSlots<InfrastructureEventSlot> {
    fn try_clone_option_vec<T: Clone>(
        source: &[Option<T>],
    ) -> Result<Vec<Option<T>>, InfrastructureError> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(source.len())
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        for entry in source {
            result.push(entry.clone());
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosureRecord {
    sequence: u64,
    nonce: u64,
    finished: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeInfrastructure {
    root: RootStamp,
    active: bool,
    limits: InfrastructureLimits,
    revision: u64,
    next_nonce: u64,
    next_publication_sequence: u64,
    next_closure_sequence: u64,
    domains: Vec<(DomainKey, u64)>,
    workloads: FixedSlots<WorkloadRecord>,
    tasks: FixedSlots<TaskRecord>,
    service_requests: FixedSlots<ServiceRequestStateRecord>,
    delayed_commands: FixedSlots<DelayedCommandStateRecord>,
    faults: FixedSlots<FaultStateRecord>,
    continuations: FixedSlots<ContinuationRecord>,
    deadlines: FixedSlots<DeadlineRecord>,
    devices: FixedSlots<DeviceRecord>,
    replies: FixedSlots<ReplyStateRecord>,
    reverse_indexes: FixedSlots<ReverseIndexRecord>,
    live: InfrastructureLiveCounts,
    closure: Option<ClosureRecord>,
    events: EventRing,
}

impl ScopeInfrastructure {
    fn try_new(
        root: RootStamp,
        limits: InfrastructureLimits,
        domains: &[(DomainKey, u64)],
    ) -> Result<Self, InfrastructureError> {
        let mut domain_slots = Vec::new();
        domain_slots
            .try_reserve_exact(domains.len())
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        for (domain, epoch) in domains {
            if *epoch == 0 || domain_slots.iter().any(|(existing, _)| existing == domain) {
                return Err(InfrastructureError::InvalidIdentity);
            }
            domain_slots.push((*domain, *epoch));
        }
        let index_capacity = limits
            .workloads
            .checked_add(limits.tasks)
            .and_then(|value| value.checked_add(limits.service_requests))
            .and_then(|value| value.checked_add(limits.delayed_commands))
            .and_then(|value| value.checked_add(limits.faults))
            .and_then(|value| value.checked_add(limits.continuations))
            .and_then(|value| value.checked_add(limits.deadline_series))
            .and_then(|value| value.checked_add(limits.device_preparations))
            .and_then(|value| value.checked_add(limits.replies))
            .ok_or(InfrastructureError::CounterOverflow)?;
        Ok(Self {
            root,
            active: true,
            limits,
            revision: 0,
            next_nonce: 1,
            next_publication_sequence: 1,
            next_closure_sequence: 1,
            domains: domain_slots,
            workloads: FixedSlots::try_new(limits.workloads)?,
            tasks: FixedSlots::try_new(limits.tasks)?,
            service_requests: FixedSlots::try_new(limits.service_requests)?,
            delayed_commands: FixedSlots::try_new(limits.delayed_commands)?,
            faults: FixedSlots::try_new(limits.faults)?,
            continuations: FixedSlots::try_new(limits.continuations)?,
            deadlines: FixedSlots::try_new(limits.deadline_series)?,
            devices: FixedSlots::try_new(limits.device_preparations)?,
            replies: FixedSlots::try_new(limits.replies)?,
            reverse_indexes: FixedSlots::try_new(index_capacity)?,
            live: InfrastructureLiveCounts::default(),
            closure: None,
            events: EventRing::try_new(limits.diagnostic_events)?,
        })
    }

    fn binding_epoch(&self, domain: DomainKey) -> Result<u64, InfrastructureError> {
        self.domains
            .iter()
            .find_map(|(candidate, epoch)| (*candidate == domain).then_some(*epoch))
            .ok_or(InfrastructureError::UnknownDomain)
    }

    fn binding_epoch_mut(&mut self, domain: DomainKey) -> Result<&mut u64, InfrastructureError> {
        self.domains
            .iter_mut()
            .find_map(|(candidate, epoch)| (*candidate == domain).then_some(epoch))
            .ok_or(InfrastructureError::UnknownDomain)
    }

    fn try_candidate_clone(&self) -> Result<Self, InfrastructureError> {
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(self.domains.len())
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        domains.extend_from_slice(&self.domains);
        Ok(Self {
            root: self.root,
            active: self.active,
            limits: self.limits,
            revision: self.revision,
            next_nonce: self.next_nonce,
            next_publication_sequence: self.next_publication_sequence,
            next_closure_sequence: self.next_closure_sequence,
            domains,
            workloads: self.workloads.try_candidate_clone()?,
            tasks: self.tasks.try_candidate_clone()?,
            service_requests: self.service_requests.try_candidate_clone()?,
            delayed_commands: self.delayed_commands.try_candidate_clone()?,
            faults: self.faults.try_candidate_clone()?,
            continuations: self.continuations.try_candidate_clone()?,
            deadlines: self.deadlines.try_candidate_clone()?,
            devices: self.devices.try_candidate_clone()?,
            replies: self.replies.try_candidate_clone()?,
            reverse_indexes: self.reverse_indexes.try_candidate_clone()?,
            live: self.live,
            closure: self.closure,
            events: self.events.try_candidate_clone()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DomainFencePlan {
    scope: ScopeKey,
    domain: DomainKey,
    previous: u64,
    next: u64,
    next_revision: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct InfrastructureState {
    registry_instance: u64,
    mode: LedgerMode,
    scopes: Vec<(ScopeKey, ScopeInfrastructure)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InfrastructureRootBinding {
    pub(super) scope: ScopeKey,
    pub(super) authority_epoch: u64,
    pub(super) root_effect: EffectKey,
    pub(super) revision: u64,
}

/// Read-only linkage vocabulary for the outer business Registry invariant.
/// It exposes no bearer and cannot mutate or duplicate infrastructure
/// authority.
pub(super) struct InfrastructureScopeLink<'a> {
    pub(super) scope: ScopeKey,
    pub(super) authority_epoch: u64,
    pub(super) root_effect: EffectKey,
    pub(super) active: bool,
    pub(super) closure_finished: Option<bool>,
    pub(super) domains: &'a [(DomainKey, u64)],
}

/// A fully prevalidated replacement for exactly one infrastructure scope.
/// The slot index and replacement are private so the outer Registry can only
/// install it through the infallible final step below.
#[derive(Debug)]
pub(super) struct InfrastructureScopeInstallPlan {
    slot: usize,
    replacement: ScopeInfrastructure,
}

fn rewrite_scope_stamps(scope: &mut ScopeInfrastructure, registry_instance: u64) {
    for record in scope.tasks.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.service_requests.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.delayed_commands.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.faults.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.continuations.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.deadlines.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.devices.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
    for record in scope.replies.iter_mut() {
        record.stamp.root.registry_instance = registry_instance;
    }
}

fn validate_root_presentation(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    authority_epoch: u64,
    root_effect: EffectKey,
) -> Result<(), InfrastructureError> {
    if scope.root.registry_instance != registry_instance {
        return Err(InfrastructureError::ForeignRegistry);
    }
    if scope.root.authority_epoch != authority_epoch {
        return Err(InfrastructureError::StaleAuthority);
    }
    if scope.root.root_effect != root_effect {
        return Err(InfrastructureError::ForeignRootEffect);
    }
    Ok(())
}

fn validate_active_admission(scope: &ScopeInfrastructure) -> Result<(), InfrastructureError> {
    if !scope.active || scope.closure.is_some() {
        Err(InfrastructureError::ScopeNotActive)
    } else {
        Ok(())
    }
}

fn require_vacancy<T: SlotIdentity>(
    slots: &FixedSlots<T>,
    id: u64,
    kind: InfrastructureKind,
) -> Result<(), InfrastructureError> {
    if slots.has_vacancy_or_id(id) {
        Ok(())
    } else {
        Err(InfrastructureError::QuotaExceeded(kind))
    }
}

fn preview_nonce(scope: &ScopeInfrastructure) -> Result<(u64, u64), InfrastructureError> {
    let nonce = scope.next_nonce;
    let next = nonce
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)?;
    if nonce == 0 {
        return Err(InfrastructureError::Invariant("zero nonce"));
    }
    Ok((nonce, next))
}

fn preview_nonces(
    scope: &ScopeInfrastructure,
    count: usize,
) -> Result<(Vec<u64>, u64), InfrastructureError> {
    let mut nonces = Vec::new();
    nonces
        .try_reserve_exact(count)
        .map_err(|_| InfrastructureError::AllocationFailed)?;
    let mut next = scope.next_nonce;
    for _ in 0..count {
        if next == 0 {
            return Err(InfrastructureError::Invariant("zero nonce"));
        }
        nonces.push(next);
        next = next
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
    }
    Ok((nonces, next))
}

fn preview_revision(scope: &ScopeInfrastructure) -> Result<u64, InfrastructureError> {
    scope
        .revision
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn checked_add(value: u32, amount: u32) -> Result<u32, InfrastructureError> {
    value
        .checked_add(amount)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn checked_sub(value: u32, amount: u32) -> Result<u32, InfrastructureError> {
    value
        .checked_sub(amount)
        .ok_or(InfrastructureError::Invariant("live counter underflow"))
}

fn workload_bearer(
    scope: &ScopeInfrastructure,
    request_id: u64,
) -> Result<WorkloadContext, InfrastructureError> {
    let record = scope
        .workloads
        .get(request_id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    Ok(WorkloadContext {
        root: scope.root,
        domain: DomainStamp {
            domain: record.domain,
            binding_epoch: record.current_binding_epoch,
        },
        workload: WorkloadStamp {
            request: record.request,
            nonce: record.nonce,
            bearer_generation: record.bearer_generation,
        },
        parent: record.parent,
    })
}

fn validate_context(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    context: &WorkloadContext,
) -> Result<(), InfrastructureError> {
    if context.root.registry_instance != registry_instance
        || scope.root.registry_instance != registry_instance
    {
        return Err(InfrastructureError::ForeignRegistry);
    }
    if context.root.scope != scope.root.scope {
        return Err(InfrastructureError::ForeignScope);
    }
    if context.root.root_effect != scope.root.root_effect {
        return Err(InfrastructureError::ForeignRootEffect);
    }
    if context.root.authority_epoch != scope.root.authority_epoch {
        return Err(InfrastructureError::StaleAuthority);
    }
    let record = scope
        .workloads
        .get(context.workload.request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if record.request != context.workload.request
        || record.root_effect != context.root.root_effect
        || record.parent != context.parent
        || record.domain != context.domain.domain
        || record.nonce != context.workload.nonce
    {
        return Err(InfrastructureError::ForeignWorkload);
    }
    if record.bearer_generation != context.workload.bearer_generation {
        return Err(InfrastructureError::StaleGeneration);
    }
    if record.current_binding_epoch != context.domain.binding_epoch
        || scope.binding_epoch(context.domain.domain)? != context.domain.binding_epoch
    {
        return Err(InfrastructureError::StaleBinding);
    }
    if record.phase != WorkloadPhase::Open {
        return Err(InfrastructureError::InvalidState);
    }
    Ok(())
}

fn context_from_stamp(
    scope: &ScopeInfrastructure,
    workload: WorkloadStamp,
) -> Result<WorkloadContext, InfrastructureError> {
    let context = workload_bearer(scope, workload.request.id)?;
    if context.workload != workload {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(context)
}

fn preview_bearer_stamp<I: Copy>(
    scope: &ScopeInfrastructure,
    context: &WorkloadContext,
    identity: I,
    parent: ParentStamp,
) -> Result<(BearerStamp<I>, u64), InfrastructureError> {
    let (nonce, next_nonce) = preview_nonce(scope)?;
    Ok((
        BearerStamp {
            root: context.root,
            domain: context.domain,
            workload: context.workload,
            identity,
            parent,
            nonce,
            bearer_generation: 1,
        },
        next_nonce,
    ))
}

fn preview_workload_child_add(
    scope: &ScopeInfrastructure,
    request: RequestKey,
) -> Result<u32, InfrastructureError> {
    let record = scope
        .workloads
        .get(request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if record.request != request || record.phase != WorkloadPhase::Open {
        return Err(InfrastructureError::ForeignWorkload);
    }
    checked_add(record.live_children, 1)
}

fn preview_workload_child_sub(
    scope: &ScopeInfrastructure,
    request: RequestKey,
) -> Result<u32, InfrastructureError> {
    let record = scope
        .workloads
        .get(request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if record.request != request {
        return Err(InfrastructureError::ForeignWorkload);
    }
    checked_sub(record.live_children, 1)
}

fn preview_task_child_add(
    scope: &ScopeInfrastructure,
    task: TaskWorkDescriptor,
) -> Result<u32, InfrastructureError> {
    let record = scope
        .tasks
        .get(task.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity != task || record.phase != TaskPhase::Entered {
        return Err(InfrastructureError::ForeignParent);
    }
    checked_add(record.live_children, 1)
}

fn preview_task_child_sub(
    scope: &ScopeInfrastructure,
    task: TaskWorkDescriptor,
) -> Result<u32, InfrastructureError> {
    let record = scope
        .tasks
        .get(task.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity != task {
        return Err(InfrastructureError::ForeignParent);
    }
    checked_sub(record.live_children, 1)
}

fn validate_stamp_common<I: Copy + Eq>(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<I>,
) -> Result<(), InfrastructureError> {
    if stamp.root.registry_instance != registry_instance
        || scope.root.registry_instance != registry_instance
    {
        return Err(InfrastructureError::ForeignRegistry);
    }
    if stamp.root.scope != scope.root.scope {
        return Err(InfrastructureError::ForeignScope);
    }
    if stamp.root.root_effect != scope.root.root_effect {
        return Err(InfrastructureError::ForeignRootEffect);
    }
    if stamp.root.authority_epoch != scope.root.authority_epoch {
        return Err(InfrastructureError::StaleAuthority);
    }
    if scope.binding_epoch(stamp.domain.domain)? != stamp.domain.binding_epoch {
        return Err(InfrastructureError::StaleBinding);
    }
    let workload = scope
        .workloads
        .get(stamp.workload.request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if workload.request != stamp.workload.request
        || workload.nonce != stamp.workload.nonce
        || workload.bearer_generation != stamp.workload.bearer_generation
        || workload.domain != stamp.domain.domain
        || workload.current_binding_epoch != stamp.domain.binding_epoch
    {
        return Err(InfrastructureError::ForeignWorkload);
    }
    Ok(())
}

fn validate_task_stamp(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<TaskWorkDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .tasks
        .get(stamp.identity.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity != stamp.identity || record.stamp.parent != stamp.parent {
        return Err(InfrastructureError::ForeignParent);
    }
    if record.stamp.nonce != stamp.nonce
        || record.stamp.bearer_generation != stamp.bearer_generation
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}

fn validate_task_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    lease: &TaskLease,
) -> Result<(), InfrastructureError> {
    validate_task_stamp(scope, registry_instance, &lease.0)
}

fn validate_continuation_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<ContinuationDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .continuations
        .get(stamp.identity.continuation_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_continuation_source(scope, stamp)?;
    validate_continuation_publication_ack(record)?;
    Ok(())
}

fn mint_continuation_key<State: bearer_state::Sealed>(
    record: &ContinuationRecord,
) -> BearerKey<State> {
    BearerKey {
        authority: AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.continuation_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: PhantomData,
    }
}

fn validate_continuation_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a ContinuationRecord, InfrastructureError> {
    if key.authority.registry_instance != registry_instance
        || scope.root.registry_instance != registry_instance
    {
        return Err(InfrastructureError::ForeignRegistry);
    }
    if key.authority.scope != scope.root.scope {
        return Err(InfrastructureError::ForeignScope);
    }
    if key.authority.authority_epoch != scope.root.authority_epoch {
        return Err(InfrastructureError::StaleAuthority);
    }
    let record = scope
        .continuations
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.continuation_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_continuation_bearer(scope, registry_instance, &record.stamp)?;
    Ok(record)
}

fn next_continuation_bearer_generation(
    record: &ContinuationRecord,
) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn validate_continuation_source(
    scope: &ScopeInfrastructure,
    stamp: &BearerStamp<ContinuationDescriptor>,
) -> Result<(), InfrastructureError> {
    if scope.binding_epoch(stamp.identity.source_domain)? != stamp.identity.source_binding_epoch {
        return Err(InfrastructureError::StaleBinding);
    }
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let task = scope
        .tasks
        .get(parent.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if task.stamp.identity != parent
        || task.stamp.root != stamp.root
        || task.stamp.domain != stamp.domain
        || task.stamp.workload != stamp.workload
        || task.phase != TaskPhase::Entered
        || parent.vm.map(VmAuthorityKey::generation) != Some(stamp.identity.vm_generation)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    Ok(())
}

fn validate_deadline_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<DeadlineDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .deadlines
        .get(stamp.identity.series_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}

fn validate_device_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<DeviceReservationCoordinates>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .devices
        .get(stamp.identity.preparation_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}

fn first_live_child_kind(
    scope: &ScopeInfrastructure,
    request: RequestKey,
) -> Result<InfrastructureKind, InfrastructureError> {
    if scope.tasks.iter().any(|record| {
        record.stamp.workload.request == request
            && matches!(record.phase, TaskPhase::Admitted | TaskPhase::Entered)
    }) {
        return Ok(InfrastructureKind::Task);
    }
    if scope.service_requests.iter().any(|record| {
        record.stamp.workload.request == request && service_request_phase_live(record.phase)
    }) {
        return Ok(InfrastructureKind::ServiceRequest);
    }
    if scope.delayed_commands.iter().any(|record| {
        record.stamp.workload.request == request && delayed_command_phase_live(record.phase)
    }) {
        return Ok(InfrastructureKind::DelayedCommand);
    }
    if scope.faults.iter().any(|record| {
        record.stamp.workload.request == request && matches!(record.phase, FaultPhase::Reserved)
    }) {
        return Ok(InfrastructureKind::Fault);
    }
    if scope.continuations.iter().any(|record| {
        record.stamp.workload.request == request
            && !matches!(
                record.phase,
                ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
            )
    }) {
        return Ok(InfrastructureKind::Continuation);
    }
    if scope.deadlines.iter().any(|record| {
        record.stamp.workload.request == request
            && !matches!(
                record.phase,
                DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
            )
    }) {
        return Ok(InfrastructureKind::Deadline);
    }
    if scope
        .devices
        .iter()
        .any(|record| record.stamp.workload.request == request && device_phase_live(record.phase))
    {
        return Ok(InfrastructureKind::DevicePreparation);
    }
    if scope.replies.iter().any(|record| {
        record.stamp.workload.request == request
            && !matches!(
                record.phase,
                ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
            )
    }) {
        return Ok(InfrastructureKind::Reply);
    }
    Err(InfrastructureError::Invariant(
        "workload child count has no live child",
    ))
}

fn first_task_child_kind(
    scope: &ScopeInfrastructure,
    task: TaskWorkDescriptor,
) -> Result<InfrastructureKind, InfrastructureError> {
    let parent = ParentStamp::Task(task);
    if scope
        .service_requests
        .iter()
        .any(|record| record.stamp.parent == parent && service_request_phase_live(record.phase))
    {
        return Ok(InfrastructureKind::ServiceRequest);
    }
    if scope
        .delayed_commands
        .iter()
        .any(|record| record.stamp.parent == parent && delayed_command_phase_live(record.phase))
    {
        return Ok(InfrastructureKind::DelayedCommand);
    }
    if scope
        .faults
        .iter()
        .any(|record| record.stamp.parent == parent && matches!(record.phase, FaultPhase::Reserved))
    {
        return Ok(InfrastructureKind::Fault);
    }
    if scope.continuations.iter().any(|record| {
        record.stamp.parent == parent
            && !matches!(
                record.phase,
                ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
            )
    }) {
        return Ok(InfrastructureKind::Continuation);
    }
    if scope.deadlines.iter().any(|record| {
        record.stamp.parent == parent
            && !matches!(
                record.phase,
                DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
            )
    }) {
        return Ok(InfrastructureKind::Deadline);
    }
    if scope.replies.iter().any(|record| {
        record.stamp.parent == parent
            && !matches!(
                record.phase,
                ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
            )
    }) {
        return Ok(InfrastructureKind::Reply);
    }
    Err(InfrastructureError::Invariant(
        "task child count has no live child",
    ))
}

#[cfg(test)]
mod tests;
