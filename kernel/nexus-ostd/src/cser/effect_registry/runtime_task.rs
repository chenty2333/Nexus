// SPDX-License-Identifier: MPL-2.0

//! Registry-owned facade for one root-specific task-work admission.
//!
//! This module deliberately has no scheduler dependency.  Reserving work
//! synchronously installs the existing infrastructure `TaskLease`; claiming
//! entry consumes that admitted authority and returns the same opaque facade
//! bearer in its entered state.  A runtime adapter must complete those two
//! calls before it invokes `Task::run` or otherwise makes the exact task
//! runnable.  This core-only tranche does not claim that any OSTD task path is
//! wired yet.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::runtime_causal::{CausalWorkloadError, CausalWorkloadIdentity, CausalWorkloadSession};
use super::{EffectPhase, EffectRegistry, RegistryError, ScopePhase, TaskKey, infrastructure};

/// Descriptive role of one root-owned unit of task work.
///
/// Service and replacement roles require the separate task-plus-fault
/// composite transaction and an explicit service-domain binding. The generic
/// reservation method rejects them before either ledger changes.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalTaskRole {
    GuestSyscallWork,
    ServiceRequest,
    ReplacementRecovery,
    SupervisorControl,
}

impl CausalTaskRole {
    const fn infrastructure(self) -> infrastructure::TaskWorkRole {
        match self {
            Self::GuestSyscallWork => infrastructure::TaskWorkRole::GuestSyscallWork,
            Self::ServiceRequest => infrastructure::TaskWorkRole::ServiceRequest,
            Self::ReplacementRecovery => infrastructure::TaskWorkRole::ReplacementRecovery,
            Self::SupervisorControl => infrastructure::TaskWorkRole::SupervisorControl,
        }
    }

    const fn from_infrastructure(role: infrastructure::TaskWorkRole) -> Self {
        match role {
            infrastructure::TaskWorkRole::GuestSyscallWork => Self::GuestSyscallWork,
            infrastructure::TaskWorkRole::ServiceRequest => Self::ServiceRequest,
            infrastructure::TaskWorkRole::ReplacementRecovery => Self::ReplacementRecovery,
            infrastructure::TaskWorkRole::SupervisorControl => Self::SupervisorControl,
        }
    }
}

/// Copyable VM identity used only as a descriptor coordinate.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalVmIdentity {
    id: u64,
    generation: u64,
}

impl CausalVmIdentity {
    pub(crate) const fn new(id: u64, generation: u64) -> Result<Self, CausalTaskError> {
        if id == 0 || generation == 0 {
            return Err(CausalTaskError::InvalidDescriptor);
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

/// Portable coordinates for one task admission.  This is a selector, never
/// authority; only [`CausalTaskBearer`] can authorize a transition.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalTaskSelector {
    work_id: u64,
    generation: u64,
    task: TaskKey,
}

impl CausalTaskSelector {
    pub(crate) const fn new(
        work_id: u64,
        generation: u64,
        task: TaskKey,
    ) -> Result<Self, CausalTaskError> {
        if work_id == 0 || generation == 0 || task.id() == 0 || task.generation() == 0 {
            return Err(CausalTaskError::InvalidDescriptor);
        }
        Ok(Self {
            work_id,
            generation,
            task,
        })
    }

    pub(crate) const fn work_id(self) -> u64 {
        self.work_id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn task(self) -> TaskKey {
        self.task
    }
}

/// Complete descriptive identity frozen into a Registry-minted task bearer.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalTaskDescriptor {
    selector: CausalTaskSelector,
    role: CausalTaskRole,
    vm: Option<CausalVmIdentity>,
}

impl CausalTaskDescriptor {
    pub(crate) const fn new(
        work_id: u64,
        generation: u64,
        task: TaskKey,
        role: CausalTaskRole,
        vm: Option<CausalVmIdentity>,
    ) -> Result<Self, CausalTaskError> {
        let selector = match CausalTaskSelector::new(work_id, generation, task) {
            Ok(selector) => selector,
            Err(error) => return Err(error),
        };
        if __cser_core::matches!(
            role,
            CausalTaskRole::GuestSyscallWork
                | CausalTaskRole::ServiceRequest
                | CausalTaskRole::ReplacementRecovery
        ) && vm.is_none()
        {
            return Err(CausalTaskError::InvalidDescriptor);
        }
        Ok(Self { selector, role, vm })
    }

    pub(crate) const fn selector(self) -> CausalTaskSelector {
        self.selector
    }

    pub(crate) const fn role(self) -> CausalTaskRole {
        self.role
    }

    pub(crate) const fn vm(self) -> Option<CausalVmIdentity> {
        self.vm
    }

    fn infrastructure(self) -> Result<infrastructure::TaskWorkDescriptor, CausalTaskError> {
        let vm = self
            .vm
            .map(|vm| infrastructure::VmAuthorityKey::new(vm.id, vm.generation))
            .transpose()
            .map_err(CausalTaskError::Infrastructure)?;
        Ok(infrastructure::TaskWorkDescriptor {
            work_id: self.selector.work_id,
            generation: self.selector.generation,
            task: self.selector.task,
            role: self.role.infrastructure(),
            vm,
        })
    }

    const fn from_infrastructure(descriptor: infrastructure::TaskWorkDescriptor) -> Self {
        Self {
            selector: CausalTaskSelector {
                work_id: descriptor.work_id,
                generation: descriptor.generation,
                task: descriptor.task,
            },
            role: CausalTaskRole::from_infrastructure(descriptor.role),
            vm: match descriptor.vm {
                Some(vm) => Some(CausalVmIdentity {
                    id: vm.id(),
                    generation: vm.generation(),
                }),
                None => None,
            },
        }
    }
}

/// Publicly visible phase of the one opaque linear bearer.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalTaskBearerPhase {
    Admitted,
    Entered,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
enum CausalTaskAuthority {
    Admitted(infrastructure::TaskLease),
    Entered(infrastructure::EnteredTaskLease),
}

/// The sole facade authority for one exact Registry/root/workload/task tuple.
///
/// Private fields and the frozen derive set prevent callers from constructing,
/// cloning, or copying authority.  The embedded descriptor is a consistency
/// coordinate only; the infrastructure record remains the sole ledger.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalTaskBearer {
    workload: CausalWorkloadIdentity,
    descriptor: CausalTaskDescriptor,
    authority: CausalTaskAuthority,
}

impl CausalTaskBearer {
    pub(crate) const fn selector(&self) -> CausalTaskSelector {
        self.descriptor.selector
    }

    pub(crate) const fn descriptor(&self) -> CausalTaskDescriptor {
        self.descriptor
    }

    pub(crate) const fn phase(&self) -> CausalTaskBearerPhase {
        match self.authority {
            CausalTaskAuthority::Admitted(_) => CausalTaskBearerPhase::Admitted,
            CausalTaskAuthority::Entered(_) => CausalTaskBearerPhase::Entered,
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalTaskState {
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
pub(crate) enum CausalTaskAnchorState {
    Live,
    TerminalRetained,
    TerminalDrained,
}

/// Read-only authoritative projection.  It carries no transition authority.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalTaskProjection {
    descriptor: CausalTaskDescriptor,
    state: CausalTaskState,
    live_children: u32,
    anchor: CausalTaskAnchorState,
}

impl CausalTaskProjection {
    pub(crate) const fn descriptor(self) -> CausalTaskDescriptor {
        self.descriptor
    }

    pub(crate) const fn state(self) -> CausalTaskState {
        self.state
    }

    pub(crate) const fn live_children(self) -> u32 {
        self.live_children
    }

    pub(crate) const fn anchor(self) -> CausalTaskAnchorState {
        self.anchor
    }

    const fn from_infrastructure(projection: infrastructure::TaskRecoveryProjection) -> Self {
        Self {
            descriptor: CausalTaskDescriptor::from_infrastructure(projection.descriptor),
            state: match projection.state {
                infrastructure::TaskRecoveryState::Admitted => CausalTaskState::Admitted,
                infrastructure::TaskRecoveryState::Entered => CausalTaskState::Entered,
                infrastructure::TaskRecoveryState::Rejected => CausalTaskState::Rejected,
                infrastructure::TaskRecoveryState::Isolated => CausalTaskState::Isolated,
                infrastructure::TaskRecoveryState::Reaped => CausalTaskState::Reaped,
            },
            live_children: projection.live_children,
            anchor: match projection.anchor {
                infrastructure::TaskAnchorRecoveryState::Live => CausalTaskAnchorState::Live,
                infrastructure::TaskAnchorRecoveryState::TerminalRetained => {
                    CausalTaskAnchorState::TerminalRetained
                }
                infrastructure::TaskAnchorRecoveryState::TerminalDrained => {
                    CausalTaskAnchorState::TerminalDrained
                }
            },
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalTaskError {
    InvalidDescriptor,
    RequiresFaultComposite,
    ForeignBearerRegistry,
    ForeignSession,
    SelectorMismatch,
    InvalidBearerState,
    Workload(CausalWorkloadError),
    Infrastructure(infrastructure::InfrastructureError),
}

/// Retry-safe transition failure.  The exact non-cloneable input is returned
/// whenever a bearer has not been consumed by a successful transition.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalTaskFailure {
    error: CausalTaskError,
    bearer: CausalTaskBearer,
}

impl CausalTaskFailure {
    pub(crate) const fn error(&self) -> &CausalTaskError {
        &self.error
    }

    pub(crate) fn into_bearer(self) -> CausalTaskBearer {
        self.bearer
    }

    pub(crate) fn into_parts(self) -> (CausalTaskError, CausalTaskBearer) {
        (self.error, self.bearer)
    }
}

#[derive(__cser_core::clone::Clone, __cser_core::marker::Copy)]
enum TaskSessionAccess {
    Admit,
    Existing,
}

impl EffectRegistry {
    /// Installs an admitted root-specific work lease before task construction
    /// can publish a runnable task.  No OSTD scheduler object is stored here.
    pub(crate) fn reserve_causal_task_work(
        &mut self,
        session: &CausalWorkloadSession,
        descriptor: CausalTaskDescriptor,
    ) -> Result<CausalTaskBearer, CausalTaskError> {
        let identity = self.validate_causal_task_session(session, TaskSessionAccess::Admit)?;
        if __cser_core::matches!(
            descriptor.role,
            CausalTaskRole::ServiceRequest | CausalTaskRole::ReplacementRecovery
        ) {
            return Err(CausalTaskError::RequiresFaultComposite);
        }
        let infrastructure_descriptor = descriptor.infrastructure()?;
        let authority = self
            .infrastructure
            .admit_task(&session.context, infrastructure_descriptor)
            .map_err(CausalTaskError::Infrastructure)?;
        Ok(CausalTaskBearer {
            workload: identity,
            descriptor,
            authority: CausalTaskAuthority::Admitted(authority),
        })
    }

    /// Consumes the admitted lease immediately before the caller's external
    /// `Task::run` boundary.  This function itself neither builds nor runs a
    /// scheduler task.
    #[allow(clippy::result_large_err)]
    pub(crate) fn claim_causal_task_entry(
        &mut self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
        bearer: CausalTaskBearer,
    ) -> Result<CausalTaskBearer, CausalTaskFailure> {
        if let Err(error) = self.validate_causal_task_bearer(session, selector, &bearer) {
            return Err(CausalTaskFailure { error, bearer });
        }
        let CausalTaskBearer {
            workload,
            descriptor,
            authority,
        } = bearer;
        let CausalTaskAuthority::Admitted(authority) = authority else {
            return Err(CausalTaskFailure {
                error: CausalTaskError::InvalidBearerState,
                bearer: CausalTaskBearer {
                    workload,
                    descriptor,
                    authority,
                },
            });
        };
        match self.infrastructure.claim_task_entry(authority) {
            Ok(authority) => Ok(CausalTaskBearer {
                workload,
                descriptor,
                authority: CausalTaskAuthority::Entered(authority),
            }),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalTaskFailure {
                    error: CausalTaskError::Infrastructure(error),
                    bearer: CausalTaskBearer {
                        workload,
                        descriptor,
                        authority: CausalTaskAuthority::Admitted(authority),
                    },
                })
            }
        }
    }

    /// Releases an admitted bearer after exact task construction failed.
    #[allow(clippy::result_large_err)]
    pub(crate) fn reject_causal_task_construction(
        &mut self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
        bearer: CausalTaskBearer,
    ) -> Result<(), CausalTaskFailure> {
        if let Err(error) = self.validate_causal_task_bearer(session, selector, &bearer) {
            return Err(CausalTaskFailure { error, bearer });
        }
        let CausalTaskBearer {
            workload,
            descriptor,
            authority,
        } = bearer;
        let CausalTaskAuthority::Admitted(authority) = authority else {
            return Err(CausalTaskFailure {
                error: CausalTaskError::InvalidBearerState,
                bearer: CausalTaskBearer {
                    workload,
                    descriptor,
                    authority,
                },
            });
        };
        match self.infrastructure.reject_task_construction(authority) {
            Ok(()) => Ok(()),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalTaskFailure {
                    error: CausalTaskError::Infrastructure(error),
                    bearer: CausalTaskBearer {
                        workload,
                        descriptor,
                        authority: CausalTaskAuthority::Admitted(authority),
                    },
                })
            }
        }
    }

    /// Isolates work which already consumed its entry claim.
    #[allow(clippy::result_large_err)]
    pub(crate) fn isolate_entered_causal_task(
        &mut self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
        bearer: CausalTaskBearer,
    ) -> Result<(), CausalTaskFailure> {
        if let Err(error) = self.validate_causal_task_bearer(session, selector, &bearer) {
            return Err(CausalTaskFailure { error, bearer });
        }
        let CausalTaskBearer {
            workload,
            descriptor,
            authority,
        } = bearer;
        let CausalTaskAuthority::Entered(authority) = authority else {
            return Err(CausalTaskFailure {
                error: CausalTaskError::InvalidBearerState,
                bearer: CausalTaskBearer {
                    workload,
                    descriptor,
                    authority,
                },
            });
        };
        match self.infrastructure.isolate_entered_task(authority) {
            Ok(()) => Ok(()),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalTaskFailure {
                    error: CausalTaskError::Infrastructure(error),
                    bearer: CausalTaskBearer {
                        workload,
                        descriptor,
                        authority: CausalTaskAuthority::Entered(authority),
                    },
                })
            }
        }
    }

    /// Reaps work which already consumed its entry claim.
    #[allow(clippy::result_large_err)]
    pub(crate) fn reap_entered_causal_task(
        &mut self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
        bearer: CausalTaskBearer,
    ) -> Result<(), CausalTaskFailure> {
        if let Err(error) = self.validate_causal_task_bearer(session, selector, &bearer) {
            return Err(CausalTaskFailure { error, bearer });
        }
        let CausalTaskBearer {
            workload,
            descriptor,
            authority,
        } = bearer;
        let CausalTaskAuthority::Entered(authority) = authority else {
            return Err(CausalTaskFailure {
                error: CausalTaskError::InvalidBearerState,
                bearer: CausalTaskBearer {
                    workload,
                    descriptor,
                    authority,
                },
            });
        };
        match self.infrastructure.reap_task(authority) {
            Ok(()) => Ok(()),
            Err(failure) => {
                let (error, authority) = failure.into_parts();
                Err(CausalTaskFailure {
                    error: CausalTaskError::Infrastructure(error),
                    bearer: CausalTaskBearer {
                        workload,
                        descriptor,
                        authority: CausalTaskAuthority::Entered(authority),
                    },
                })
            }
        }
    }

    /// Queries one exact task without changing either authoritative ledger.
    pub(crate) fn query_causal_task(
        &self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
    ) -> Result<CausalTaskProjection, CausalTaskError> {
        self.validate_causal_task_session(session, TaskSessionAccess::Existing)?;
        let projection = self
            .infrastructure
            .query_task(&session.context, selector.work_id, selector.generation)
            .map(CausalTaskProjection::from_infrastructure)
            .map_err(CausalTaskError::Infrastructure)?;
        if projection.descriptor.selector != selector {
            return Err(CausalTaskError::SelectorMismatch);
        }
        Ok(projection)
    }

    fn validate_causal_task_bearer(
        &self,
        session: &CausalWorkloadSession,
        selector: CausalTaskSelector,
        bearer: &CausalTaskBearer,
    ) -> Result<(), CausalTaskError> {
        let identity = self.validate_causal_task_session(session, TaskSessionAccess::Existing)?;
        if bearer.workload.registry_instance != self.instance_id {
            return Err(CausalTaskError::ForeignBearerRegistry);
        }
        if bearer.workload != identity {
            return Err(CausalTaskError::ForeignSession);
        }
        if bearer.descriptor.selector != selector {
            return Err(CausalTaskError::SelectorMismatch);
        }
        let projection = self
            .infrastructure
            .query_task(&session.context, selector.work_id, selector.generation)
            .map_err(CausalTaskError::Infrastructure)?;
        if CausalTaskDescriptor::from_infrastructure(projection.descriptor) != bearer.descriptor {
            return Err(CausalTaskError::SelectorMismatch);
        }
        Ok(())
    }

    fn validate_causal_task_session(
        &self,
        session: &CausalWorkloadSession,
        access: TaskSessionAccess,
    ) -> Result<CausalWorkloadIdentity, CausalTaskError> {
        let identity = session.identity;
        if identity.registry_instance != self.instance_id {
            return Err(CausalTaskError::Workload(
                CausalWorkloadError::ForeignRegistry,
            ));
        }
        let scope = self.scopes.get(&identity.scope).ok_or({
            CausalTaskError::Workload(CausalWorkloadError::Registry(RegistryError::UnknownScope))
        })?;
        let lifecycle_matches = match (scope.phase, access) {
            (ScopePhase::Active, _) => scope.authority_epoch == identity.authority_epoch,
            (ScopePhase::Closing, TaskSessionAccess::Existing) => {
                scope.revoke.as_ref().is_some_and(|revoke| {
                    revoke.closed_authority_epoch == identity.authority_epoch
                        && revoke.cohort.contains(&identity.root_effect)
                })
            }
            (ScopePhase::Closing | ScopePhase::Revoked, TaskSessionAccess::Admit)
            | (ScopePhase::Revoked, TaskSessionAccess::Existing) => false,
        };
        if !lifecycle_matches {
            return Err(CausalTaskError::Workload(CausalWorkloadError::StaleScope));
        }
        let binding = scope.domains.get(&identity.domain).ok_or({
            CausalTaskError::Workload(CausalWorkloadError::Registry(RegistryError::UnknownDomain))
        })?;
        if binding.binding_epoch != identity.binding_epoch
            || (__cser_core::matches!(access, TaskSessionAccess::Admit)
                && (binding.quarantine.is_some()
                    || binding.supervisor.is_none()
                    || binding.fallback_running))
        {
            return Err(CausalTaskError::Workload(CausalWorkloadError::StaleDomain));
        }
        let record = self.effects.get(&identity.root_effect).ok_or({
            CausalTaskError::Workload(CausalWorkloadError::Registry(RegistryError::UnknownEffect))
        })?;
        if record.identity.scope != identity.scope
            || record.identity.effect != identity.root_effect
            || record.identity.domain != identity.domain
            || record.identity.authority_epoch != identity.authority_epoch
            || record.identity.binding_epoch != identity.binding_epoch
            || record.identity.parent.is_some()
            || (__cser_core::matches!(scope.phase, ScopePhase::Active)
                && !__cser_core::matches!(
                    record.phase,
                    EffectPhase::Prepared | EffectPhase::Committed
                ))
        {
            return Err(CausalTaskError::Workload(CausalWorkloadError::StaleRoot));
        }
        let verified = self
            .verify_causal_workload_session(session)
            .map_err(CausalTaskError::Workload)?;
        if verified != identity {
            return Err(CausalTaskError::ForeignSession);
        }
        Ok(identity)
    }
}

const _: () = {
    __cser_core::assert!(__cser_core::mem::size_of::<CausalTaskBearer>() <= 256);
    __cser_core::assert!(__cser_core::mem::size_of::<CausalTaskFailure>() <= 384);
};

#[cfg(test)]
pub(super) fn causal_task_facade_self_test() {
    use super::runtime_causal::CausalWorkloadLimits;
    use super::{
        CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest, DomainConfig, DomainKey,
        OperationClass, PublicationMode, RegisterRequest, ScopeConfig, SyscallDescriptor,
    };

    const ROOT_OWNER: TaskKey = TaskKey::new(0xd001, 1);
    const SERVICE: TaskKey = TaskKey::new(0xd002, 1);
    const CREDIT: CreditClass = CreditClass::new(0xd0);

    const fn limits(task_admissions: u32) -> CausalWorkloadLimits {
        CausalWorkloadLimits::new(task_admissions, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 64)
    }

    fn install_session(
        registry: &mut EffectRegistry,
        seed: u64,
        task_admissions: u32,
    ) -> CausalWorkloadSession {
        let scope = super::ScopeKey::new(seed, 1);
        let domain = DomainKey::new(u32::try_from(seed).unwrap());
        registry
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: 7,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 1)],
            })
            .unwrap();
        registry
            .add_domain(
                scope,
                DomainConfig {
                    key: domain,
                    binding_epoch: 3,
                    supervisor: SERVICE,
                },
            )
            .unwrap();
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope,
                    task: SERVICE,
                    operation: OperationClass::new(u32::try_from(seed).unwrap()),
                    descriptor: SyscallDescriptor::new(
                        usize::try_from(seed).unwrap(),
                        [usize::try_from(seed).unwrap(); 6],
                    ),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain,
                parent: None,
            })
            .unwrap();
        registry.prepare(SERVICE, root.handle).unwrap();
        let activation = registry
            .prepare_causal_workload_activation(
                root.handle,
                seed.checked_add(0x100).unwrap(),
                1,
                limits(task_admissions),
            )
            .unwrap();
        registry.activate_causal_workload(activation).unwrap()
    }

    fn descriptor(seed: u64) -> CausalTaskDescriptor {
        CausalTaskDescriptor::new(
            seed,
            1,
            TaskKey::new(seed.checked_add(0x1000).unwrap(), 1),
            CausalTaskRole::GuestSyscallWork,
            Some(CausalVmIdentity::new(seed.checked_add(0x2000).unwrap(), 1).unwrap()),
        )
        .unwrap()
    }

    // Admission is installed before entry, query is read-only, and the
    // entered bearer can be reaped exactly once.
    let mut normal = EffectRegistry::new();
    let normal_session = install_session(&mut normal, 0xd100, 8);
    let normal_descriptor = descriptor(0xd110);
    let normal_selector = normal_descriptor.selector();
    let admitted = normal
        .reserve_causal_task_work(&normal_session, normal_descriptor)
        .unwrap();
    __cser_core::assert_eq!(admitted.phase(), CausalTaskBearerPhase::Admitted);
    let before_query = normal.failure_atomic_projection();
    let projection = normal
        .query_causal_task(&normal_session, normal_selector)
        .unwrap();
    __cser_core::assert_eq!(projection.descriptor(), normal_descriptor);
    __cser_core::assert_eq!(projection.state(), CausalTaskState::Admitted);
    __cser_core::assert_eq!(projection.live_children(), 0);
    __cser_core::assert_eq!(projection.anchor(), CausalTaskAnchorState::Live);
    __cser_core::assert_eq!(normal.failure_atomic_projection(), before_query);
    let entered = normal
        .claim_causal_task_entry(&normal_session, normal_selector, admitted)
        .unwrap();
    __cser_core::assert_eq!(entered.phase(), CausalTaskBearerPhase::Entered);
    __cser_core::assert_eq!(
        normal
            .query_causal_task(&normal_session, normal_selector)
            .unwrap()
            .state(),
        CausalTaskState::Entered
    );
    normal
        .reap_entered_causal_task(&normal_session, normal_selector, entered)
        .unwrap();
    __cser_core::assert_eq!(
        normal
            .query_causal_task(&normal_session, normal_selector)
            .unwrap()
            .state(),
        CausalTaskState::Reaped
    );

    // Failed construction consumes the admitted authority and records the
    // exact Rejected terminal state rather than pretending the task ran.
    let rejected_descriptor = descriptor(0xd120);
    let rejected_selector = rejected_descriptor.selector();
    let rejected = normal
        .reserve_causal_task_work(&normal_session, rejected_descriptor)
        .unwrap();
    normal
        .reject_causal_task_construction(&normal_session, rejected_selector, rejected)
        .unwrap();
    __cser_core::assert_eq!(
        normal
            .query_causal_task(&normal_session, rejected_selector)
            .unwrap()
            .state(),
        CausalTaskState::Rejected
    );

    // Selector substitution is rejected without consuming the exact bearer.
    // The returned input remains usable with its original task selector.
    let isolated_descriptor = descriptor(0xd130);
    let isolated_selector = isolated_descriptor.selector();
    let admitted = normal
        .reserve_causal_task_work(&normal_session, isolated_descriptor)
        .unwrap();
    let stale_selector = CausalTaskSelector::new(
        isolated_selector.work_id(),
        isolated_selector.generation().checked_add(1).unwrap(),
        isolated_selector.task(),
    )
    .unwrap();
    let expected = __cser_alloc::format!("{admitted:?}");
    let before = normal.failure_atomic_projection();
    let failure = normal
        .claim_causal_task_entry(&normal_session, stale_selector, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalTaskError::SelectorMismatch);
    __cser_core::assert_eq!(normal.failure_atomic_projection(), before);
    let admitted = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{admitted:?}"), expected);
    let substituted = CausalTaskSelector::new(
        isolated_selector.work_id(),
        isolated_selector.generation(),
        TaskKey::new(isolated_selector.task().id().checked_add(1).unwrap(), 1),
    )
    .unwrap();
    let expected = __cser_alloc::format!("{admitted:?}");
    let before = normal.failure_atomic_projection();
    let failure = normal
        .claim_causal_task_entry(&normal_session, substituted, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalTaskError::SelectorMismatch);
    __cser_core::assert_eq!(normal.failure_atomic_projection(), before);
    let admitted = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{admitted:?}"), expected);
    let entered = normal
        .claim_causal_task_entry(&normal_session, isolated_selector, admitted)
        .unwrap();

    // An entered bearer cannot use the construction-rejection path. The
    // failure is atomic and returns the same bearer for typed isolation.
    let expected = __cser_alloc::format!("{entered:?}");
    let before = normal.failure_atomic_projection();
    let failure = normal
        .reject_causal_task_construction(&normal_session, isolated_selector, entered)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalTaskError::InvalidBearerState);
    __cser_core::assert_eq!(normal.failure_atomic_projection(), before);
    let entered = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{entered:?}"), expected);
    normal
        .isolate_entered_causal_task(&normal_session, isolated_selector, entered)
        .unwrap();
    __cser_core::assert_eq!(
        normal
            .query_causal_task(&normal_session, isolated_selector)
            .unwrap()
            .state(),
        CausalTaskState::Isolated
    );
    normal.check_invariants().unwrap();

    // Two real sessions in one Registry cannot be substituted even when both
    // remain current. The bearer remains owned by its original workload.
    let mut two_sessions = EffectRegistry::new();
    let left = install_session(&mut two_sessions, 0xd200, 2);
    let right = install_session(&mut two_sessions, 0xd300, 2);
    let left_descriptor = descriptor(0xd210);
    let left_selector = left_descriptor.selector();
    let admitted = two_sessions
        .reserve_causal_task_work(&left, left_descriptor)
        .unwrap();
    let expected = __cser_alloc::format!("{admitted:?}");
    let before = two_sessions.failure_atomic_projection();
    let failure = two_sessions
        .claim_causal_task_entry(&right, left_selector, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalTaskError::ForeignSession);
    __cser_core::assert_eq!(two_sessions.failure_atomic_projection(), before);
    let admitted = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{admitted:?}"), expected);
    let entered = two_sessions
        .claim_causal_task_entry(&left, left_selector, admitted)
        .unwrap();
    two_sessions
        .reap_entered_causal_task(&left, left_selector, entered)
        .unwrap();
    two_sessions.check_invariants().unwrap();

    // Isomorphic Registries do not share bearer authority. Target rejection
    // preserves both its projection and the foreign input for its owner.
    let mut owner = EffectRegistry::new();
    let owner_session = install_session(&mut owner, 0xd400, 2);
    let owner_descriptor = descriptor(0xd410);
    let owner_selector = owner_descriptor.selector();
    let admitted = owner
        .reserve_causal_task_work(&owner_session, owner_descriptor)
        .unwrap();
    let expected = __cser_alloc::format!("{admitted:?}");
    let mut target = EffectRegistry::new();
    let target_session = install_session(&mut target, 0xd400, 2);
    let before = target.failure_atomic_projection();
    let failure = target
        .claim_causal_task_entry(&target_session, owner_selector, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalTaskError::ForeignBearerRegistry);
    __cser_core::assert_eq!(target.failure_atomic_projection(), before);
    let admitted = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{admitted:?}"), expected);
    let entered = owner
        .claim_causal_task_entry(&owner_session, owner_selector, admitted)
        .unwrap();
    owner
        .reap_entered_causal_task(&owner_session, owner_selector, entered)
        .unwrap();
    owner.check_invariants().unwrap();
    target.check_invariants().unwrap();

    // A binding advance after admission is fenced before entry and returns the
    // exact bearer. Restoring the test-only mutation proves no hidden consume.
    let mut stale = EffectRegistry::new();
    let stale_session = install_session(&mut stale, 0xd500, 2);
    let stale_descriptor = descriptor(0xd510);
    let stale_selector = stale_descriptor.selector();
    let admitted = stale
        .reserve_causal_task_work(&stale_session, stale_descriptor)
        .unwrap();
    let expected = __cser_alloc::format!("{admitted:?}");
    stale
        .scopes
        .get_mut(&stale_session.identity.scope)
        .unwrap()
        .domains
        .get_mut(&stale_session.identity.domain)
        .unwrap()
        .binding_epoch += 1;
    let before = stale.failure_atomic_projection();
    let failure = stale
        .claim_causal_task_entry(&stale_session, stale_selector, admitted)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalTaskError::Workload(CausalWorkloadError::StaleDomain)
    );
    __cser_core::assert_eq!(stale.failure_atomic_projection(), before);
    let admitted = failure.into_bearer();
    __cser_core::assert_eq!(__cser_alloc::format!("{admitted:?}"), expected);
    stale
        .scopes
        .get_mut(&stale_session.identity.scope)
        .unwrap()
        .domains
        .get_mut(&stale_session.identity.domain)
        .unwrap()
        .binding_epoch -= 1;
    let entered = stale
        .claim_causal_task_entry(&stale_session, stale_selector, admitted)
        .unwrap();
    stale
        .reap_entered_causal_task(&stale_session, stale_selector, entered)
        .unwrap();
    stale.check_invariants().unwrap();

    // Capacity failure and exact replay are both failure-atomic. Descriptor
    // identity is copyable, so no authority needs to be reconstructed.
    let mut quota = EffectRegistry::new();
    let quota_session = install_session(&mut quota, 0xd600, 1);
    let first_descriptor = descriptor(0xd610);
    let first_selector = first_descriptor.selector();
    let first = quota
        .reserve_causal_task_work(&quota_session, first_descriptor)
        .unwrap();
    let before = quota.failure_atomic_projection();
    __cser_core::assert_eq!(
        quota
            .reserve_causal_task_work(&quota_session, descriptor(0xd620))
            .unwrap_err(),
        CausalTaskError::Infrastructure(infrastructure::InfrastructureError::QuotaExceeded(
            infrastructure::InfrastructureKind::Task
        ))
    );
    __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
    __cser_core::assert_eq!(
        quota
            .reserve_causal_task_work(&quota_session, first_descriptor)
            .unwrap_err(),
        CausalTaskError::Infrastructure(infrastructure::InfrastructureError::ExactReplay)
    );
    __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
    quota
        .reject_causal_task_construction(&quota_session, first_selector, first)
        .unwrap();
    quota.check_invariants().unwrap();

    // A root-workload context does not silently stand in for the filesystem
    // service domain. Both service roles fail before admission and must later
    // enter through the explicit task-plus-fault composite facade.
    for (offset, role) in [
        (0_u64, CausalTaskRole::ServiceRequest),
        (1_u64, CausalTaskRole::ReplacementRecovery),
    ] {
        let service_descriptor = CausalTaskDescriptor::new(
            0xd630 + offset,
            1,
            TaskKey::new(0xe630 + offset, 1),
            role,
            Some(CausalVmIdentity::new(0xf630 + offset, 1).unwrap()),
        )
        .unwrap();
        let before = quota.failure_atomic_projection();
        __cser_core::assert_eq!(
            quota
                .reserve_causal_task_work(&quota_session, service_descriptor)
                .unwrap_err(),
            CausalTaskError::RequiresFaultComposite
        );
        __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
    }

    // Invalid public descriptor coordinates never reach either ledger.
    let before = quota.failure_atomic_projection();
    __cser_core::assert_eq!(
        CausalTaskDescriptor::new(
            0,
            1,
            TaskKey::new(1, 1),
            CausalTaskRole::SupervisorControl,
            None,
        ),
        Err(CausalTaskError::InvalidDescriptor)
    );
    __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
}
