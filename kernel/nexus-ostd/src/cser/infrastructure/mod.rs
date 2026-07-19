// SPDX-License-Identifier: MPL-2.0

//! Root-bound causal infrastructure owned privately by [`super::EffectRegistry`].
//!
//! These records cover kernel execution obligations; they are not business
//! effects. Most infrastructure records do not consume effect credits. Device
//! preparation is the deliberate exception: its immutable record names the
//! exact business-credit classes held by the outer Registry until they are
//! either released or transferred into the materialized effect cohort. The
//! module is a private child of `effect_registry`, so canonical Registry
//! identities are the only vocabulary.
//! Authoritative records are cloneable only into an explicitly
//! non-authoritative transaction candidate. Bearer values are linear Rust
//! values: none implements `Clone` or `Copy`, and a query never recreates one.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::vec::Vec;
use __cser_core::marker::PhantomData;

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
    continuation::validate_continuation_publication_ack, delayed::delayed_command_phase_live,
    device::device_phase_live, invariants::check_scope_invariants,
    service::service_request_phase_live,
};

use super::{
    CommitReceipt as RegistryCommitReceipt, CreditCharge, CreditClass,
    DeviceClosureReceipt as RegistryDeviceClosureReceipt, DeviceEnvelope, DomainKey, EffectKey,
    PortalHandle, ResourceKey, ScopeKey, TaskKey,
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum LedgerMode {
    Authoritative,
    NonAuthoritativeCandidate,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct RootStamp {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    root_effect: EffectKey,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DomainStamp {
    domain: DomainKey,
    binding_epoch: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct WorkloadStamp {
    request: RequestKey,
    nonce: u64,
    bearer_generation: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum ParentStamp {
    RootEffect(EffectKey),
    Request(RequestKey),
    Task(TaskWorkDescriptor),
    Effect(EffectKey),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
struct AuthorityKey {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
}

mod bearer_state {
    extern crate alloc as __cser_alloc;
    extern crate core as __cser_core;

    pub(super) trait Sealed {}

    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ContinuationPending {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ContinuationClaimed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ContinuationPublishing {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ContinuationAcknowledged {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ContinuationResuming {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceReservedUnbound {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceReservedBound {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceEnqueuePublishing {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceQueueWritten {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceArmPublishing {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceArmed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum ServiceChildBound {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum TaskAdmitted {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum TaskEntered {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum TaskFaultReserved {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum TaskFaultArmed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum FaultCrashReceiptClaimed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum FaultIsolateReceiptClaimed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum FaultCrashCauseClaimed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DeadlineArmed {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DeadlineFired {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DeadlineExhausted {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DeadlineQuarantined {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DelayedReserved {}
    #[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
    pub(super) enum DelayedPublishing {}

    impl Sealed for ContinuationPending {}
    impl Sealed for ContinuationClaimed {}
    impl Sealed for ContinuationPublishing {}
    impl Sealed for ContinuationAcknowledged {}
    impl Sealed for ContinuationResuming {}
    impl Sealed for ServiceReservedUnbound {}
    impl Sealed for ServiceReservedBound {}
    impl Sealed for ServiceEnqueuePublishing {}
    impl Sealed for ServiceQueueWritten {}
    impl Sealed for ServiceArmPublishing {}
    impl Sealed for ServiceArmed {}
    impl Sealed for ServiceChildBound {}
    impl Sealed for TaskAdmitted {}
    impl Sealed for TaskEntered {}
    impl Sealed for TaskFaultReserved {}
    impl Sealed for TaskFaultArmed {}
    impl Sealed for FaultCrashReceiptClaimed {}
    impl Sealed for FaultIsolateReceiptClaimed {}
    impl Sealed for FaultCrashCauseClaimed {}
    impl Sealed for DeadlineArmed {}
    impl Sealed for DeadlineFired {}
    impl Sealed for DeadlineExhausted {}
    impl Sealed for DeadlineQuarantined {}
    impl Sealed for DelayedReserved {}
    impl Sealed for DelayedPublishing {}
}

/// Opaque, state-typed authority for one fixed infrastructure slot.
///
/// The key intentionally contains no descriptor, domain, source, parent, or
/// workload snapshot.  Those facts have exactly one authoritative copy in
/// the family record; a key is accepted only after revalidating that full
/// record and matching all of the compact coordinates below.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
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
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct WorkloadContext {
    root: RootStamp,
    domain: DomainStamp,
    workload: WorkloadStamp,
    parent: ParentStamp,
}

impl WorkloadContext {
    pub(super) const fn scope(&self) -> ScopeKey {
        self.root.scope
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum TaskWorkRole {
    GuestSyscallWork,
    ServiceRequest,
    ReplacementRecovery,
    SupervisorControl,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
            || (__cser_core::matches!(
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct TaskLease(BearerKey<bearer_state::TaskAdmitted>);

/// Successor returned exactly once by the entry claim. An admitted lease can
/// no longer be reused to run or reap the work item.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct EnteredTaskLease(BearerKey<bearer_state::TaskEntered>);

/// The admitted service task and its reserved fault slot are one linear
/// authority. There is deliberately no independently usable fault bearer.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ReservedFaultTask(BearerKey<bearer_state::TaskFaultReserved>);

/// The entered service task and armed fault slot are one linear authority.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ArmedFaultTask(BearerKey<bearer_state::TaskFaultArmed>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum TaskRecoveryState {
    Admitted,
    Entered,
    Rejected,
    Isolated,
    Reaped,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct TaskRecoveryProjection {
    pub(crate) descriptor: TaskWorkDescriptor,
    pub(crate) state: TaskRecoveryState,
    pub(crate) live_children: u32,
    pub(crate) anchor: TaskAnchorRecoveryState,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum TaskAnchorRecoveryState {
    Live,
    TerminalRetained,
    TerminalDrained,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum TaskAdoption {
    Admitted(TaskLease),
    Entered(EnteredTaskLease),
    FaultReserved(ReservedFaultTask),
    FaultArmed(ArmedFaultTask),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

/// Compact authority for a reserved service request which owns no response
/// continuation.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct UnboundServiceRequest(BearerKey<bearer_state::ServiceReservedUnbound>);

/// Compact authority for a reserved request and its Registry-owned response
/// continuation. The continuation has no independently minted bearer while
/// this authority is live.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ServiceRequestTicket(ServiceBoundKey<bearer_state::ServiceReservedBound>);

/// Copyable, descriptive causal identity for an external service action.
///
/// This is a complete snapshot of the Registry-owned request coordinates. It
/// carries no bearer state and therefore cannot authorize a transition.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceRequestCausalIdentity {
    pub(crate) registry_instance: u64,
    pub(crate) scope: ScopeKey,
    pub(crate) authority_epoch: u64,
    pub(crate) root_effect: EffectKey,
    pub(crate) workload_request_id: u64,
    pub(crate) workload_request_generation: u64,
    pub(crate) workload_nonce: u64,
    pub(crate) workload_bearer_generation: u64,
    pub(crate) admission_domain: DomainKey,
    pub(crate) admission_binding_epoch: u64,
    pub(crate) parent_task: TaskWorkDescriptor,
    pub(crate) request_nonce: u64,
    pub(crate) descriptor: ServiceRequestDescriptor,
    pub(crate) response: ContinuationDescriptor,
}

/// One-shot authority for acknowledging an externally applied queue write.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ServiceEnqueueAuthority(ServiceBoundKey<bearer_state::ServiceEnqueuePublishing>);

/// Copyable instructions for the external queue write. Copying this plan does
/// not copy authority; acknowledgement consumes [`ServiceEnqueueAuthority`].
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceEnqueuePlan {
    pub(crate) causal: ServiceRequestCausalIdentity,
    pub(crate) bearer_generation: u64,
    pub(crate) apply_generation: u64,
    pub(crate) apply_nonce: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceEnqueueReceipt {
    pub(crate) plan: ServiceEnqueuePlan,
    pub(crate) queue: ResourceKey,
    pub(crate) queue_generation: u64,
    pub(crate) payload_slot: u32,
    pub(crate) payload_generation: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct UnarmedServiceRequest(ServiceBoundKey<bearer_state::ServiceQueueWritten>);

/// One-shot authority for acknowledging external response-slot arming.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ServiceArmAuthority(ServiceBoundKey<bearer_state::ServiceArmPublishing>);

/// Copyable instructions for response-slot arming. The plan is descriptive;
/// acknowledgement consumes the separate compact authority.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceArmPlan {
    pub(crate) causal: ServiceRequestCausalIdentity,
    pub(crate) queue_receipt: ServiceEnqueueReceipt,
    pub(crate) bearer_generation: u64,
    pub(crate) arm_generation: u64,
    pub(crate) arm_nonce: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceArmReceipt {
    pub(crate) plan: ServiceArmPlan,
    pub(crate) response_slot_id: u64,
    pub(crate) response_slot_generation: u64,
    pub(crate) bound_continuation_id: u64,
    pub(crate) bound_continuation_generation: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct EnqueuedServiceRequest(ServiceBoundKey<bearer_state::ServiceArmed>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceChildReceipt {
    pub(crate) child_effect: EffectKey,
    pub(crate) registration_digest: u64,
}

/// Claim-time coordinates of the task which registered a service child.
///
/// This snapshot is descriptive evidence only. In particular, it cannot be
/// converted into an [`EnteredTaskLease`] or used as task authority.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceClaimantSnapshot {
    pub(crate) registry_instance: u64,
    pub(crate) scope: ScopeKey,
    pub(crate) authority_epoch: u64,
    pub(crate) root_effect: EffectKey,
    pub(crate) workload_request_id: u64,
    pub(crate) workload_request_generation: u64,
    pub(crate) workload_nonce: u64,
    pub(crate) workload_bearer_generation: u64,
    pub(crate) domain: DomainKey,
    pub(crate) binding_epoch: u64,
    pub(crate) task: TaskWorkDescriptor,
    pub(crate) task_nonce: u64,
    pub(crate) task_bearer_generation: u64,
}

/// Immutable evidence for the atomic claim-and-child-binding transition.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceChildBindingReceipt {
    pub(crate) request_id: u64,
    pub(crate) generation: u64,
    pub(crate) service_bearer_generation: u64,
    pub(crate) claim_generation: u64,
    pub(crate) claim_nonce: u64,
    pub(crate) claimant: ServiceClaimantSnapshot,
    pub(crate) child: ServiceChildReceipt,
}

/// Temporary proof supplied by the already validated outer Registry
/// transaction. It is not a production source mapping and does not expose an
/// intermediate claimed service authority.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(super) struct ValidatedServiceChildProof {
    receipt: ServiceChildReceipt,
}

impl ValidatedServiceChildProof {
    pub(super) const fn new(receipt: ServiceChildReceipt) -> Self {
        Self { receipt }
    }
}

/// Canonical SHA-256 commitment to one service response lineage.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceLineageCommitment([u8; 32]);

/// Compact authority for every service state after response binding.
///
/// The commitment evolves with the state: exact bind-time response, issued
/// enqueue plan, acknowledged enqueue receipt, issued arm plan, acknowledged
/// queue/arm receipts, then those receipts plus the complete child binding.
/// This detects an active transition presented with a self-consistently
/// substituted Registry record while the independently held opaque authority
/// remains unchanged. It does not claim protection against an attacker able to
/// rewrite both arbitrary kernel memory and the caller-held authority/evidence
/// and recompute every SHA-256 value. The state remains sealed and the key
/// remains non-`Clone`/non-`Copy`.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
struct ServiceBoundKey<State: bearer_state::Sealed> {
    authority: AuthorityKey,
    slot: u64,
    object_generation: u64,
    bearer_generation: u64,
    nonce: u64,
    lineage_commitment: ServiceLineageCommitment,
    state: PhantomData<fn() -> State>,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct BoundServiceRequest(ServiceBoundKey<bearer_state::ServiceChildBound>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceCompletionReceipt {
    pub(crate) request_id: u64,
    pub(crate) generation: u64,
    pub(crate) bearer_generation: u64,
    /// Echoes the final live `ServiceChildBound` lineage commitment.
    pub(crate) lineage_commitment: ServiceLineageCommitment,
    pub(crate) binding_receipt: ServiceChildBindingReceipt,
    pub(crate) child_effect: EffectKey,
    pub(crate) response: ContinuationDescriptor,
    pub(crate) result_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ServiceCompletionOutcome {
    pub(crate) receipt: ServiceCompletionReceipt,
    pub(crate) response: ContinuationLease,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ServiceCancellationPoint {
    ReservedUnbound,
    ReservedBound,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceCancellationReceipt {
    pub(crate) request_id: u64,
    pub(crate) generation: u64,
    pub(crate) bearer_generation: u64,
    pub(crate) evidence_digest: u64,
    pub(crate) point: ServiceCancellationPoint,
    pub(crate) response: Option<ContinuationDescriptor>,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct BoundServiceCancellationOutcome {
    pub(crate) receipt: ServiceCancellationReceipt,
    pub(crate) response: ContinuationLease,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ServiceRequestRecoveryState {
    ReservedUnbound,
    ReservedBound,
    EnqueueUncertain,
    QueueWrittenUnarmed,
    ArmUncertain,
    Armed,
    ChildBound,
    Completed,
    Cancelled,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceRequestRecoveryProjection {
    pub(crate) descriptor: ServiceRequestDescriptor,
    pub(crate) state: ServiceRequestRecoveryState,
    pub(crate) enqueue_receipt: Option<ServiceEnqueueReceipt>,
    pub(crate) arm_receipt: Option<ServiceArmReceipt>,
    pub(crate) child_binding_receipt: Option<ServiceChildBindingReceipt>,
    pub(crate) completion_receipt: Option<ServiceCompletionReceipt>,
    pub(crate) cancellation_receipt: Option<ServiceCancellationReceipt>,
    pub(crate) bearer_generation: u64,
}

const _: () = {
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceReservedBound>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceEnqueuePublishing>>()
            <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceQueueWritten>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmPublishing>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmed>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceChildBound>>() <= 96
    );
    __cser_core::assert!(__cser_core::mem::size_of::<UnboundServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceRequestTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueueAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<UnarmedServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<EnqueuedServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<BoundServiceRequest>() <= 96);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<UnboundServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ServiceRequestTicket>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ServiceEnqueueAuthority>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<UnarmedServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ServiceArmAuthority>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<EnqueuedServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<BoundServiceRequest>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueuePlan>() <= 512);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueueReceipt>() <= 640);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmPlan>() <= 1_280);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmReceipt>() <= 1_408);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceChildBindingReceipt>() <= 384);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceCompletionReceipt>() <= 512);
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
            || self.target.nonce == 0
            || self.command_digest == 0
            || self.actor_generation == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

/// Opaque authority for a delayed command reserved at its exact child portal.
///
/// This bearer can advance or reject that recorded command; it deliberately
/// cannot retarget it during supervisor adoption. Retargeting requires a new
/// independently validated child/portal proof and is outside this tranche.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DelayedCommandTicket(BearerKey<bearer_state::DelayedReserved>);

/// One-shot authority for acknowledging the Registry's current publication
/// record. Apply generation and nonce stay in the authoritative record rather
/// than being duplicated in this compact input.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DelayedCommandIntent(BearerKey<bearer_state::DelayedPublishing>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DelayedCommandReceipt {
    pub(crate) actor_slot: u32,
    pub(crate) actor_generation: u64,
    pub(crate) command_digest: u64,
    pub(crate) transport_receipt_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DelayedCommandRejectionReason {
    StaleTarget,
    RequestAborted,
    ClosureDrain,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DelayedCommandRejectionReceipt {
    pub(crate) reason: DelayedCommandRejectionReason,
    pub(crate) target_effect: EffectKey,
    pub(crate) evidence_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DelayedCommandRecoveryState {
    Reserved,
    PublicationUncertain,
    Issued,
    Rejected,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DelayedCommandRecoveryProjection {
    pub(crate) descriptor: DelayedCommandDescriptor,
    pub(crate) state: DelayedCommandRecoveryState,
    pub(crate) receipt: Option<DelayedCommandReceipt>,
    pub(crate) rejection: Option<DelayedCommandRejectionReceipt>,
}

const _: () = {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DelayedReserved>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<DelayedCommandTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DelayedCommandIntent>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DelayedCommandTicket>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DelayedCommandIntent>>() <= 120);
};

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(super) struct ValidatedAbortProof {
    evidence_digest: u64,
}

impl ValidatedAbortProof {
    pub(super) const fn new(evidence_digest: u64) -> Self {
        Self { evidence_digest }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum FaultAccess {
    Read,
    Write,
    Execute,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct FaultSlotDescriptor {
    pub(crate) fault_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) service_domain: DomainKey,
    pub(crate) admission_binding_epoch: u64,
}

impl FaultSlotDescriptor {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.fault_id == 0
            || self.generation == 0
            || self.task.generation() == 0
            || self.vm_generation == 0
            || self.admission_binding_epoch == 0
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum FaultDisposition {
    CrashService,
    IsolateTask,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct FaultObservation {
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) instruction_pointer: u64,
    pub(crate) address: u64,
    pub(crate) access: FaultAccess,
    pub(crate) architecture_error: u64,
    pub(crate) evidence_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CrashServiceReceipt(BearerKey<bearer_state::FaultCrashReceiptClaimed>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct IsolateTaskReceipt(BearerKey<bearer_state::FaultIsolateReceiptClaimed>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ServiceCrashCause(BearerKey<bearer_state::FaultCrashCauseClaimed>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum FaultClaimProjection {
    Crash(ServiceFaultProjection),
    Isolate(ServiceFaultProjection),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum InstalledFaultObservation {
    Crash(InstalledFaultProjection),
    Isolate(InstalledFaultProjection),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct InstalledFaultProjection {
    pub(crate) projection: ServiceFaultProjection,
    pub(crate) commitment: FaultPlanCommitment,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum FaultReceiptClaimOutcome {
    Crash(CrashServiceReceipt),
    Isolate(IsolateTaskReceipt),
    AlreadyClaimed(FaultClaimProjection),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct FaultRecoveryProjection {
    pub(crate) descriptor: FaultSlotDescriptor,
    pub(crate) receipt: Option<ServiceFaultProjection>,
    /// Descriptive, copyable selector for recovering the first receipt claim
    /// after the install return value was lost.  This carries no bearer
    /// authority; the ledger still decides whether the claim is first or a
    /// duplicate.
    pub(crate) selector: Option<InstalledFaultObservation>,
    pub(crate) consumed: bool,
    pub(crate) awaiting_claim: bool,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainFaultRecoveryProjection {
    pub(crate) fault_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) vm_generation: u64,
    pub(crate) service_domain: DomainKey,
    pub(crate) closed_binding_epoch: u64,
    pub(crate) crash_generation: u64,
    pub(crate) evidence_digest: u64,
    pub(crate) plan_commitment: [u8; 32],
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ServiceTaskExitReceipt {
    pub(crate) fault_id: u64,
    pub(crate) generation: u64,
    pub(crate) task: TaskKey,
    pub(crate) evidence_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct FaultDispositionIntent {
    pub(super) armed: ArmedFaultTask,
    pub(super) commitment: [u8; 32],
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct FaultPlanCommitment(pub(super) [u8; 32]);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct FaultDispositionPlan {
    pub(super) scope: ScopeKey,
    task: TaskWorkDescriptor,
    fault: FaultSlotDescriptor,
    task_nonce: u64,
    task_bearer_generation: u64,
    fault_nonce: u64,
    fault_bearer_generation: u64,
    pub(super) observation: FaultObservation,
    pub(super) projection: ServiceFaultProjection,
    base_revision: u64,
    next_binding_epoch: u64,
    pub(super) business: FaultBusinessPlan,
    pub(super) commitment: FaultPlanCommitment,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) struct FaultBusinessPlan {
    pub(super) scope_revision: u64,
    pub(super) domain_revision: u64,
    pub(super) supervisor: Option<TaskKey>,
    pub(super) fallback_running: bool,
    pub(super) cohort_digest: [u8; 32],
    pub(super) cohort_count: u64,
}

impl FaultBusinessPlan {
    pub(super) const INFRASTRUCTURE_ONLY: Self = Self {
        scope_revision: 0,
        domain_revision: 0,
        supervisor: None,
        fallback_running: false,
        cohort_digest: [0; 32],
        cohort_count: 0,
    };
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) struct AppliedFaultDisposition {
    projection: ServiceFaultProjection,
    commitment: FaultPlanCommitment,
}

const _: () = {
    __cser_core::assert!(__cser_core::mem::size_of::<TaskLease>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<EnteredTaskLease>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ReservedFaultTask>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ArmedFaultTask>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<FaultDispositionIntent>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<TaskLease>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<EnteredTaskLease>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ReservedFaultTask>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ArmedFaultTask>>() <= 120);
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ContinuationLease(BearerKey<bearer_state::ContinuationPending>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct WakeClaim(BearerKey<bearer_state::ContinuationClaimed>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ContinuationPublicationReceipt {
    pub(crate) vm_generation: u64,
    pub(crate) source_domain: DomainKey,
    pub(crate) source_binding_epoch: u64,
    pub(crate) outcome_digest: u64,
}

/// External publication acknowledgement.  This value is descriptive evidence,
/// not authority: only the separate one-shot publication bearer may consume it.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ContinuationPublicationAuthority(BearerKey<bearer_state::ContinuationPublishing>);

/// Copyable instructions for the external publication apply. Copying this
/// value never copies authority; acknowledgement consumes the separate opaque
/// authority exactly once.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ContinuationPublicationPlan {
    pub(crate) descriptor: ContinuationDescriptor,
    pub(crate) claim_generation: u64,
    pub(crate) claim_nonce: u64,
    pub(crate) apply_generation: u64,
    pub(crate) apply_nonce: u64,
    pub(crate) publication_sequence: u64,
    pub(crate) receipt: ContinuationPublicationReceipt,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ContinuationAckReceipt(BearerKey<bearer_state::ContinuationAcknowledged>);

/// Persisted-before-wake successor. Replaying this intent after a fence is
/// idempotent by the Registry-minted publication sequence.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ContinuationResumeAuthority(BearerKey<bearer_state::ContinuationResuming>);

/// Copyable instructions for the external resume apply. Completion consumes
/// the separate linear authority, never this descriptor.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ContinuationRecoveryState {
    Pending,
    Claimed,
    PublicationUncertain,
    AcknowledgedPendingResume { publication_sequence: u64 },
    ResumeUncertain { publication_sequence: u64 },
    Resumed { publication_sequence: u64 },
    Cancelled,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ContinuationRecoveryProjection {
    pub(crate) descriptor: ContinuationDescriptor,
    pub(crate) parent_task: TaskWorkDescriptor,
    pub(crate) state: ContinuationRecoveryState,
    pub(crate) claim_generation: u64,
    pub(crate) publication_ack: Option<ContinuationPublicationAckReceipt>,
    pub(crate) resume_receipt: Option<ContinuationResumeReceipt>,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum ContinuationAdoption {
    Pending(ContinuationLease),
    Claimed(WakeClaim),
    ReplayPublication(ContinuationPublicationIntent),
    Acknowledged(ContinuationAckReceipt),
    ReplayResume(ContinuationResumeIntent),
}

const _: () = {
    __cser_core::assert!(__cser_core::mem::size_of::<AuthorityKey>() <= 32);
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::ContinuationPending>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationLease>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<WakeClaim>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationPublicationAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationPublicationAckReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationAckReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationResumeAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationResumeReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ContinuationLease>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<WakeClaim>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationPublicationAuthority>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationAckReceipt>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationResumeAuthority>>() <= 120
    );
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeadlinePurpose {
    Wait,
    Retry,
    Recovery,
    DeviceClosure,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeadlineClockBasis {
    /// Count observed by the injected timer callback. This tranche does not
    /// claim wall-clock or true monotonic-time semantics.
    ObservedCallbackTick,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
        // Device-closure timers require a device-owned authority edge which
        // does not exist in this infrastructure tranche.  A task-owned timer
        // must never be accepted as an approximation of that edge.
        if self.purpose == DeadlinePurpose::DeviceClosure {
            return Err(InfrastructureError::NotEnabled);
        }
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DeadlineLease(BearerKey<bearer_state::DeadlineArmed>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
enum DeadlineExpiryAuthority {
    Fired(BearerKey<bearer_state::DeadlineFired>),
    Exhausted(BearerKey<bearer_state::DeadlineExhausted>),
}

/// Opaque fired/exhausted authority. The observed tick and expiry nonce have
/// one authoritative copy in `DeadlineRecord`; this value only selects the
/// exact object and bearer generation which may consume them.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DeadlineExpiryReceipt(DeadlineExpiryAuthority);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeadlineRecoveryState {
    Armed,
    Fired,
    ExhaustedRetained,
    QuarantinedRetained,
    Cancelled,
    Resolved,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeadlineRecoveryProjection {
    pub(crate) descriptor: DeadlineDescriptor,
    pub(crate) parent_task: TaskWorkDescriptor,
    pub(crate) state: DeadlineRecoveryState,
    pub(crate) observed_tick: Option<u64>,
    pub(crate) reconciliation: Option<DeadlineReconciliationReceipt>,
    pub(crate) terminal_evidence_digest: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeadlineExhaustedDisposition {
    AbortWork,
    RetryBySupervisor,
    Quarantine,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeadlineReconciliationReceipt {
    pub(crate) disposition: DeadlineExhaustedDisposition,
    /// Opaque evidence selected by the crate-private adapter.
    ///
    /// This logical receipt is not, by itself, proof of a real timer, reset,
    /// device, or persistent supervisor action. A production adapter must
    /// verify such provider evidence before constructing this value.
    pub(crate) evidence_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeadlineSupervisorRetry {
    pub(crate) generation: u64,
    pub(crate) deadline_tick: u64,
    pub(crate) max_attempts: u32,
    pub(crate) backoff_ticks: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DeadlineQuarantineTicket(BearerKey<bearer_state::DeadlineQuarantined>);

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeadlineQuarantineReleaseReceipt {
    /// Opaque evidence selected by the crate-private adapter.
    ///
    /// The same external-verification boundary as
    /// [`DeadlineReconciliationReceipt::evidence_digest`] applies.
    pub(crate) evidence_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum DeadlineReconciliationOutcome {
    Aborted,
    Retried(DeadlineLease),
    Quarantined(DeadlineQuarantineTicket),
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum DeadlineAdoption {
    Armed(DeadlineLease),
    Fired(DeadlineExpiryReceipt),
    Exhausted(DeadlineExpiryReceipt),
    Quarantined(DeadlineQuarantineTicket),
}

const _: () = {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineArmed>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineFired>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineExhausted>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineQuarantined>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineLease>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineExpiryReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineQuarantineTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DeadlineLease>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DeadlineExpiryReceipt>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DeadlineQuarantineTicket>>() <= 120
    );
};

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceReservationCoordinates {
    pub(crate) preparation_id: u64,
    pub(crate) generation: u64,
    /// Registry-owned device/BDF resource. Session and descriptor-token
    /// identity do not exist until the hardware apply succeeds.
    pub(crate) owned_device: ResourceKey,
    pub(crate) queue: u16,
    pub(crate) device_generation: u64,
    pub(crate) operation_digest: u64,
    /// Exact outer-Registry credit classes. Units are fixed by RFC 0003 at
    /// one queue slot and three pinned-page/DMA pairs.
    pub(crate) queue_credit_class: CreditClass,
    pub(crate) pinned_credit_class: CreditClass,
    pub(crate) dma_credit_class: CreditClass,
    /// Index of a preallocated kernel adapter slot which will own the linear
    /// prepared request before hardware success is acknowledged.
    pub(crate) actor_slot: u32,
    /// Generation paired with `actor_slot`; neither coordinate may be reused
    /// while this preparation remains live.
    pub(crate) actor_generation: u64,
}

pub(super) const DEVICE_QUEUE_SLOTS: u32 = 1;
pub(super) const DEVICE_PINNED_PAGES: u32 = 3;
pub(super) const DEVICE_DMA_MAPPINGS: u32 = 3;

impl DeviceReservationCoordinates {
    fn validate(self) -> Result<(), InfrastructureError> {
        if self.preparation_id == 0
            || self.generation == 0
            || self.device_generation == 0
            || self.operation_digest == 0
            || self.actor_generation == 0
            || self.queue_credit_class == self.pinned_credit_class
            || self.queue_credit_class == self.dma_credit_class
            || self.pinned_credit_class == self.dma_credit_class
        {
            return Err(InfrastructureError::InvalidIdentity);
        }
        Ok(())
    }

    pub(super) const fn credit_charges(self) -> [CreditCharge; 3] {
        [
            CreditCharge::new(self.queue_credit_class, DEVICE_QUEUE_SLOTS as u64),
            CreditCharge::new(self.pinned_credit_class, DEVICE_PINNED_PAGES as u64),
            CreditCharge::new(self.dma_credit_class, DEVICE_DMA_MAPPINGS as u64),
        ]
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DevicePreparationTicket(BearerStamp<DeviceReservationCoordinates>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DeviceApplyIntent {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(super) struct DeviceMaterializationPlan {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    owner: PreparedOwner,
    base_revision: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct MaterializedDeviceTicket {
    preparation: BearerStamp<DeviceReservationCoordinates>,
    owner: PreparedOwner,
    cohort_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) struct ValidatedDeviceClosureProof {
    receipt: RegistryDeviceClosureReceipt,
}

impl ValidatedDeviceClosureProof {
    pub(super) const fn new(receipt: RegistryDeviceClosureReceipt) -> Self {
        Self { receipt }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceHardwareReceipt {
    pub(crate) owned_device: ResourceKey,
    pub(crate) device: DeviceEnvelope,
    pub(crate) operation_digest: u64,
    pub(crate) actor_slot: u32,
    pub(crate) actor_generation: u64,
    pub(crate) hardware_receipt_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceRollbackReceipt {
    pub(crate) owned_device: ResourceKey,
    pub(crate) queue: u16,
    pub(crate) device_generation: u64,
    pub(crate) operation_digest: u64,
    pub(crate) actor_slot: u32,
    pub(crate) actor_generation: u64,
    pub(crate) rollback_receipt_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DevicePreparationRecoveryState {
    Reserved,
    ApplyingHardware,
    PreparedRetained,
    Materialized,
    Released,
    Cancelled,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DevicePreparationCreditOwnership {
    HeldByPreparation,
    RetainedByPreparation,
    TransferredToCohort,
    Released,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DevicePreparationRecoveryProjection {
    pub(crate) coordinates: DeviceReservationCoordinates,
    pub(crate) parent_effect: EffectKey,
    pub(crate) state: DevicePreparationRecoveryState,
    pub(crate) credit_ownership: DevicePreparationCreditOwnership,
    pub(crate) prepared_device: Option<DeviceEnvelope>,
    pub(crate) cohort_digest: Option<u64>,
    pub(crate) rollback_receipt: Option<DeviceRollbackReceipt>,
    pub(crate) closure_receipt: Option<RegistryDeviceClosureReceipt>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) struct DevicePreparationCreditProjection {
    pub(super) scope: ScopeKey,
    pub(super) charges: [CreditCharge; 3],
    pub(super) ownership: DevicePreparationCreditOwnership,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct PreparedOwner {
    owned_device: ResourceKey,
    device: DeviceEnvelope,
    operation_digest: u64,
    actor_slot: u32,
    actor_generation: u64,
    hardware_receipt_digest: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ReplyRecord(BearerStamp<ReplyDescriptor>);

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ReplyClaim {
    reply: BearerStamp<ReplyDescriptor>,
    claim_generation: u64,
    claim_nonce: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum ReplyAbortAuthority {
    Prepared(ReplyRecord),
    Claimed(ReplyClaim),
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ReplyPublicationIntent {
    reply: BearerStamp<ReplyDescriptor>,
    claim_generation: u64,
    claim_nonce: u64,
    apply_generation: u64,
    apply_nonce: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ReplyAckReceipt {
    reply: BearerStamp<ReplyDescriptor>,
    backend_effect: EffectKey,
    backend_commit_sequence: u64,
    publication_receipt: ReplyPublicationReceipt,
    ack_generation: u64,
    ack_nonce: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ReplyCompletionReceipt {
    pub(crate) reply_id: u64,
    pub(crate) generation: u64,
    pub(crate) backend_effect: EffectKey,
    pub(crate) backend_commit_sequence: u64,
    pub(crate) external_apply_digest: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(super) struct ValidatedCommitProof {
    receipt: RegistryCommitReceipt,
}

impl ValidatedCommitProof {
    pub(super) fn new(receipt: RegistryCommitReceipt) -> Self {
        Self { receipt }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ReplyRecoveryState {
    Prepared,
    Claimed,
    PublicationUncertain,
    AcknowledgedPendingWake,
    Completed,
    Cancelled,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ReplyRecoveryProjection {
    pub(crate) descriptor: ReplyDescriptor,
    pub(crate) backend_effect: EffectKey,
    pub(crate) backend_commit_sequence: u64,
    pub(crate) state: ReplyRecoveryState,
    pub(crate) claim_generation: u64,
    pub(crate) publication_receipt: Option<ReplyPublicationReceipt>,
    pub(crate) completion_receipt: Option<ReplyCompletionReceipt>,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum ReplyAdoption {
    Prepared(ReplyRecord),
    Claimed(ReplyClaim),
    ReplayPublication(ReplyPublicationIntent),
    Acknowledged(ReplyAckReceipt),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::default::Default,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::default::Default,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ResourceUsage {
    pub(crate) queue_slots: u32,
    pub(crate) pinned_pages: u32,
    pub(crate) dma_mappings: u32,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
    ServiceRequestBound,
    ServiceRequestPublishing,
    ServiceRequestEnqueued,
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct InfrastructureEvent {
    pub(crate) sequence: u64,
    pub(crate) kind: InfrastructureEventKind,
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::default::Default,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) enum InfrastructureHandoffReadiness {
    Ready,
    NeedsAbort,
    PublicationPending,
    BlockedRetained,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct InfrastructureClosureSelection {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    sequence: u64,
    nonce: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum InfrastructureClosureWorkState {
    Cancellable,
    MustIsolate,
    PublicationClaimed,
    PublicationUncertain,
    PreparedRetained,
    ExhaustedRetained,
    Workload,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct InfrastructureClosureWork {
    pub(crate) kind: InfrastructureKind,
    pub(crate) id: u64,
    pub(crate) generation: u64,
    pub(crate) state: InfrastructureClosureWorkState,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum WorkloadPhase {
    Open,
    Closed,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum TaskPhase {
    Admitted,
    Entered,
    Rejected,
    Isolated,
    Reaped,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum TaskAnchorPhase {
    Live,
    TerminalRetained,
    TerminalDrained,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct TaskFaultLink {
    fault_id: u64,
    fault_object_generation: u64,
    fault_bearer_generation: u64,
    fault_nonce: u64,
    terminal_install_digest: Option<[u8; 32]>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct TaskRecord {
    stamp: BearerStamp<TaskWorkDescriptor>,
    phase: TaskPhase,
    anchor: TaskAnchorPhase,
    service_fault: Option<TaskFaultLink>,
    live_children: u32,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
    ChildBound {
        queue_receipt: ServiceEnqueueReceipt,
        arm_receipt: ServiceArmReceipt,
        binding_receipt: ServiceChildBindingReceipt,
    },
    Completed {
        queue_receipt: ServiceEnqueueReceipt,
        arm_receipt: ServiceArmReceipt,
        receipt: ServiceCompletionReceipt,
    },
    Cancelled {
        receipt: ServiceCancellationReceipt,
    },
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct ServiceRequestStateRecord {
    stamp: BearerStamp<ServiceRequestDescriptor>,
    bound_continuation: Option<BearerStamp<ContinuationDescriptor>>,
    response_identity: Option<ContinuationDescriptor>,
    response_commitment: Option<ServiceLineageCommitment>,
    child_binding_commitment: Option<ServiceChildBindingReceipt>,
    bound_commitment: Option<ServiceLineageCommitment>,
    bind_bearer_generation: u64,
    apply_generation: u64,
    apply_bearer_generation: u64,
    apply_nonce_high_water: u64,
    arm_generation: u64,
    arm_bearer_generation: u64,
    arm_nonce_high_water: u64,
    claim_generation: u64,
    claim_bearer_generation: u64,
    claim_nonce_high_water: u64,
    phase: ServiceRequestPhase,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DelayedCommandStateRecord {
    stamp: BearerStamp<DelayedCommandDescriptor>,
    apply_generation: u64,
    phase: DelayedCommandPhase,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum FaultPhase {
    Reserved,
    Armed,
    Exited {
        receipt: ServiceTaskExitReceipt,
    },
    InstalledAwaitingClaim {
        projection: ServiceFaultProjection,
        observation: FaultObservation,
        commitment: FaultPlanCommitment,
    },
    Claimed {
        projection: ServiceFaultProjection,
        observation: FaultObservation,
        commitment: FaultPlanCommitment,
        cause_claimed: bool,
    },
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct FaultTaskOwner {
    task: TaskWorkDescriptor,
    task_object_nonce: u64,
    task_bearer_generation: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct FaultStateRecord {
    stamp: BearerStamp<FaultSlotDescriptor>,
    owner: FaultTaskOwner,
    phase: FaultPhase,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DeadlineRecord {
    stamp: BearerStamp<DeadlineDescriptor>,
    series_nonce: u64,
    quarantine_generation: u64,
    last_reconciliation: Option<DeadlineReconciliationReceipt>,
    terminal_evidence_digest: Option<u64>,
    phase: DeadlinePhase,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum DeviceCreditOwnership {
    Held,
    Retained,
    Transferred,
    Released,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum DeviceAdoption {
    Reserved(DevicePreparationTicket),
    ReplayApply(DeviceApplyIntent),
    Prepared(DevicePreparationTicket),
    Materialized(MaterializedDeviceTicket),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DeviceRecord {
    stamp: BearerStamp<DeviceReservationCoordinates>,
    apply_generation: u64,
    credit_ownership: DeviceCreditOwnership,
    phase: DevicePhase,
    closure_sequence: Option<u64>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum ReverseParent {
    RootEffect(EffectKey),
    Request(RequestKey),
    Task(TaskWorkDescriptor),
    Effect(EffectKey),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
    actor_generation: Option<u64>,
    retry_generation: u64,
}

fn reverse_index_for_task(record: &TaskRecord) -> ReverseIndexRecord {
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::Task,
        root_effect: record.stamp.root.root_effect,
        parent: reverse_parent_from_stamp(record.stamp.parent),
        task: Some(record.stamp.identity.task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: None,
        source_binding_epoch: None,
        resource: None,
        actor_slot: None,
        actor_generation: None,
        retry_generation: record.stamp.identity.generation,
    }
}

fn reverse_index_for_fault(record: &FaultStateRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::Fault,
        root_effect: record.stamp.root.root_effect,
        parent: reverse_parent_from_stamp(record.stamp.parent),
        task: Some(descriptor.task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: None,
        source_binding_epoch: None,
        resource: None,
        actor_slot: None,
        actor_generation: None,
        retry_generation: descriptor.vm_generation,
    }
}

const fn reverse_parent_from_stamp(parent: ParentStamp) -> ReverseParent {
    match parent {
        ParentStamp::RootEffect(effect) => ReverseParent::RootEffect(effect),
        ParentStamp::Request(request) => ReverseParent::Request(request),
        ParentStamp::Task(task) => ReverseParent::Task(task),
        ParentStamp::Effect(effect) => ReverseParent::Effect(effect),
    }
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct ClosureRecord {
    sequence: u64,
    nonce: u64,
    finished: bool,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) struct DomainFencePlan {
    scope: ScopeKey,
    domain: DomainKey,
    previous: u64,
    next: u64,
    next_revision: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(super) struct InfrastructureState {
    registry_instance: u64,
    mode: LedgerMode,
    scopes: Vec<(ScopeKey, ScopeInfrastructure)>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
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
#[derive(__cser_core::fmt::Debug)]
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

/// Validates an observation context for a terminal record whose service-domain
/// binding may already have advanced.  The presented workload authority stays
/// exact; only the enclosing domain epoch may dominate the recorded epoch.
fn validate_recovery_context(
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
        || scope.binding_epoch(context.domain.domain)? < context.domain.binding_epoch
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

/// Validates a retained child against the monotonic coordinates that may have
/// advanced after its owning task became terminal.
///
/// The child's own request, nonce, root effect, domain, and recorded epochs
/// remain exact historical coordinates.  Only the authoritative domain epoch
/// and workload bearer may dominate those coordinates.  Callers must also
/// prove that the parent task is a retained terminal anchor before using this
/// relaxation.
fn validate_stamp_common_historical<I: Copy + Eq>(
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
    if scope.binding_epoch(stamp.domain.domain)? < stamp.domain.binding_epoch {
        return Err(InfrastructureError::StaleBinding);
    }
    let workload = scope
        .workloads
        .get(stamp.workload.request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if workload.request != stamp.workload.request
        || workload.nonce != stamp.workload.nonce
        || workload.bearer_generation < stamp.workload.bearer_generation
        || workload.domain != stamp.domain.domain
        || workload.current_binding_epoch < stamp.domain.binding_epoch
    {
        return Err(InfrastructureError::ForeignWorkload);
    }
    Ok(())
}

/// Validates a task-owned child and reports whether its parent is a retained
/// terminal anchor.  Live parents require exact current coordinates; terminal
/// parents permit only monotonic domination of the child's historic binding
/// and workload bearer.  This function never authorizes allocation of a new
/// child: all creation paths separately require an `EnteredTaskLease` or
/// `ArmedFaultTask` and a live task phase.
fn validate_task_child_stamp<I: Copy + Eq>(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<I>,
) -> Result<bool, InfrastructureError> {
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let task = scope
        .tasks
        .get(parent.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let live = task.phase == TaskPhase::Entered && task.anchor == TaskAnchorPhase::Live;
    let terminal = __cser_core::matches!(
        task.phase,
        TaskPhase::Rejected | TaskPhase::Isolated | TaskPhase::Reaped
    ) && task.anchor != TaskAnchorPhase::Live;
    if !live && !terminal {
        return Err(InfrastructureError::ForeignParent);
    }
    if terminal {
        validate_stamp_common_historical(scope, registry_instance, stamp)?;
    } else {
        validate_stamp_common(scope, registry_instance, stamp)?;
    }
    if task.stamp.identity != parent
        || task.stamp.root != stamp.root
        || task.stamp.domain.domain != stamp.domain.domain
        || task.stamp.domain.binding_epoch < stamp.domain.binding_epoch
        || task.stamp.workload.request != stamp.workload.request
        || task.stamp.workload.nonce != stamp.workload.nonce
        || task.stamp.workload.bearer_generation < stamp.workload.bearer_generation
        || task.stamp.parent != ParentStamp::Request(stamp.workload.request)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    if live && (task.stamp.domain != stamp.domain || task.stamp.workload != stamp.workload) {
        return Err(InfrastructureError::ForeignParent);
    }
    Ok(terminal)
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

fn mint_task_key<State: bearer_state::Sealed>(record: &TaskRecord) -> BearerKey<State> {
    BearerKey {
        authority: AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.work_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: PhantomData,
    }
}

fn validate_task_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a TaskRecord, InfrastructureError> {
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
        .tasks
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.work_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_task_stamp(scope, registry_instance, &record.stamp)?;
    Ok(record)
}

fn validate_task_bearer<'a>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    lease: &TaskLease,
) -> Result<&'a TaskRecord, InfrastructureError> {
    validate_task_key(scope, registry_instance, &lease.0)
}

fn next_task_bearer_generation(record: &TaskRecord) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn install_task_child_count(record: &mut TaskRecord, live_children: u32) {
    record.live_children = live_children;
    if live_children == 0 && record.anchor == TaskAnchorPhase::TerminalRetained {
        record.anchor = TaskAnchorPhase::TerminalDrained;
    }
}

fn validate_continuation_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<ContinuationDescriptor>,
) -> Result<(), InfrastructureError> {
    let terminal_parent = validate_task_child_stamp(scope, registry_instance, stamp)?;
    let record = scope
        .continuations
        .get(stamp.identity.continuation_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_continuation_source(scope, stamp, terminal_parent)?;
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
    terminal_parent: bool,
) -> Result<(), InfrastructureError> {
    let source_binding_epoch = scope.binding_epoch(stamp.identity.source_domain)?;
    if (!terminal_parent && source_binding_epoch != stamp.identity.source_binding_epoch)
        || (terminal_parent && source_binding_epoch < stamp.identity.source_binding_epoch)
    {
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
        || task.stamp.domain.domain != stamp.domain.domain
        || task.stamp.domain.binding_epoch < stamp.domain.binding_epoch
        || task.stamp.workload.request != stamp.workload.request
        || task.stamp.workload.nonce != stamp.workload.nonce
        || task.stamp.workload.bearer_generation < stamp.workload.bearer_generation
        || (!terminal_parent
            && (task.stamp.domain != stamp.domain || task.stamp.workload != stamp.workload))
        || (!terminal_parent && task.phase != TaskPhase::Entered)
        || (terminal_parent
            && (!__cser_core::matches!(
                task.phase,
                TaskPhase::Rejected | TaskPhase::Isolated | TaskPhase::Reaped
            ) || task.anchor == TaskAnchorPhase::Live))
        || parent.vm.map(VmAuthorityKey::generation) != Some(stamp.identity.vm_generation)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    Ok(())
}

fn validate_deadline_record(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &DeadlineRecord,
) -> Result<(), InfrastructureError> {
    let stamp = &record.stamp;
    let terminal_parent = validate_task_child_stamp(scope, registry_instance, stamp)?;
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let task = scope
        .tasks
        .get(parent.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let parent_phase_valid = (task.phase == TaskPhase::Entered
        && task.anchor == TaskAnchorPhase::Live)
        || (__cser_core::matches!(task.phase, TaskPhase::Isolated | TaskPhase::Reaped)
            && task.anchor != TaskAnchorPhase::Live);
    if !parent_phase_valid
        || task.stamp.identity != parent
        || task.stamp.root != stamp.root
        || task.stamp.domain.domain != stamp.domain.domain
        || task.stamp.domain.binding_epoch < stamp.domain.binding_epoch
        || task.stamp.workload.request != stamp.workload.request
        || task.stamp.workload.nonce != stamp.workload.nonce
        || task.stamp.workload.bearer_generation < stamp.workload.bearer_generation
        || task.stamp.parent != ParentStamp::Request(stamp.workload.request)
        || terminal_parent != (task.anchor != TaskAnchorPhase::Live)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    let index =
        scope
            .reverse_indexes
            .get(record.series_nonce)
            .ok_or(InfrastructureError::Invariant(
                "missing deadline reverse index",
            ))?;
    if index.slot != record.series_nonce
        || index.kind != InfrastructureKind::Deadline
        || index.root_effect != stamp.root.root_effect
        || index.parent != ReverseParent::Task(parent)
        || index.task != Some(parent.task)
        || index.domain != stamp.domain.domain
        || index.binding_epoch != stamp.domain.binding_epoch
        || index.source_domain.is_some()
        || index.source_binding_epoch.is_some()
        || index.resource.is_some()
        || index.actor_slot.is_some()
        || index.retry_generation != stamp.identity.generation
    {
        return Err(InfrastructureError::Invariant(
            "deadline reverse index mismatch",
        ));
    }
    Ok(())
}

fn mint_deadline_key<State: bearer_state::Sealed>(record: &DeadlineRecord) -> BearerKey<State> {
    BearerKey {
        authority: AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.series_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: PhantomData,
    }
}

fn validate_deadline_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a DeadlineRecord, InfrastructureError> {
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
        .deadlines
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.series_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_deadline_record(scope, registry_instance, record)?;
    Ok(record)
}

fn next_deadline_bearer_generation(record: &DeadlineRecord) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
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
            && __cser_core::matches!(record.phase, TaskPhase::Admitted | TaskPhase::Entered)
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
        record.stamp.workload.request == request
            && __cser_core::matches!(record.phase, FaultPhase::Reserved | FaultPhase::Armed)
    }) {
        return Ok(InfrastructureKind::Fault);
    }
    if scope.continuations.iter().any(|record| {
        record.stamp.workload.request == request
            && !__cser_core::matches!(
                record.phase,
                ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
            )
    }) {
        return Ok(InfrastructureKind::Continuation);
    }
    if scope.deadlines.iter().any(|record| {
        record.stamp.workload.request == request
            && !__cser_core::matches!(
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
            && !__cser_core::matches!(
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
    if scope.service_requests.iter().any(|record| {
        __cser_core::matches!(
            record.phase,
            ServiceRequestPhase::ChildBound {
                binding_receipt,
                ..
            } if binding_receipt.claimant.task == task
        )
    }) {
        return Ok(InfrastructureKind::ServiceRequest);
    }
    if scope
        .delayed_commands
        .iter()
        .any(|record| record.stamp.parent == parent && delayed_command_phase_live(record.phase))
    {
        return Ok(InfrastructureKind::DelayedCommand);
    }
    if scope.faults.iter().any(|record| {
        record.stamp.parent == parent
            && __cser_core::matches!(record.phase, FaultPhase::Reserved | FaultPhase::Armed)
    }) {
        return Ok(InfrastructureKind::Fault);
    }
    if scope.continuations.iter().any(|record| {
        record.stamp.parent == parent
            && !__cser_core::matches!(
                record.phase,
                ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
            )
    }) {
        return Ok(InfrastructureKind::Continuation);
    }
    if scope.deadlines.iter().any(|record| {
        record.stamp.parent == parent
            && !__cser_core::matches!(
                record.phase,
                DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
            )
    }) {
        return Ok(InfrastructureKind::Deadline);
    }
    if scope.replies.iter().any(|record| {
        record.stamp.parent == parent
            && !__cser_core::matches!(
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
