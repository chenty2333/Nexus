// SPDX-License-Identifier: MPL-2.0

//! Narrow production bootstrap for one root-owned causal workload.
//!
//! The public surface deliberately exposes neither `InfrastructureState` nor
//! `WorkloadContext`. A caller receives one opaque, non-cloneable session only
//! after the Registry has atomically installed the preallocated infrastructure
//! root and its first workload.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::vec::Vec;

use super::{
    DomainKey, EffectKey, EffectPhase, EffectRegistry, PortalHandle, RegistryError, ScopeKey,
    ScopePhase, infrastructure,
};

/// Bounded capacity for the seven RFC 0003 obligation families.
///
/// One workload slot is implicit. Service-request and delayed-command capacity
/// remain separate because they have distinct ownership transitions even
/// though they form one implementation tranche.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalWorkloadLimits {
    task_admissions: u32,
    service_requests: u32,
    delayed_commands: u32,
    guest_continuations: u32,
    guest_replies: u32,
    deadlines: u32,
    faults: u32,
    device_preparations: u32,
    queue_slots: u32,
    pinned_pages: u32,
    dma_mappings: u32,
    diagnostic_events: u32,
}

impl CausalWorkloadLimits {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        task_admissions: u32,
        service_requests: u32,
        delayed_commands: u32,
        guest_continuations: u32,
        guest_replies: u32,
        deadlines: u32,
        faults: u32,
        device_preparations: u32,
        queue_slots: u32,
        pinned_pages: u32,
        dma_mappings: u32,
        diagnostic_events: u32,
    ) -> Self {
        Self {
            task_admissions,
            service_requests,
            delayed_commands,
            guest_continuations,
            guest_replies,
            deadlines,
            faults,
            device_preparations,
            queue_slots,
            pinned_pages,
            dma_mappings,
            diagnostic_events,
        }
    }

    fn infrastructure(self) -> Result<infrastructure::InfrastructureLimits, CausalWorkloadError> {
        infrastructure::InfrastructureLimits::new(
            1,
            self.task_admissions,
            self.service_requests,
            self.delayed_commands,
            self.faults,
            self.guest_continuations,
            self.deadlines,
            self.device_preparations,
            self.guest_replies,
            self.queue_slots,
            self.pinned_pages,
            self.dma_mappings,
            self.diagnostic_events,
        )
        .map_err(CausalWorkloadError::Infrastructure)
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalWorkloadIdentity {
    registry_instance: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    root_effect: EffectKey,
    domain: DomainKey,
    binding_epoch: u64,
    request_id: u64,
    request_generation: u64,
}

impl CausalWorkloadIdentity {
    pub(crate) const fn scope(self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn root_effect(self) -> EffectKey {
        self.root_effect
    }

    pub(crate) const fn request_id(self) -> u64 {
        self.request_id
    }

    pub(crate) const fn request_generation(self) -> u64 {
        self.request_generation
    }
}

/// Opaque active authority for one exact Registry/root/workload tuple.
///
/// This type intentionally implements neither `Clone` nor `Copy`. Only the
/// Registry facade can inspect or consume its private infrastructure context.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalWorkloadSession {
    identity: CausalWorkloadIdentity,
    context: infrastructure::WorkloadContext,
}

impl CausalWorkloadSession {
    pub(crate) const fn identity(&self) -> CausalWorkloadIdentity {
        self.identity
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CausalWorkloadError {
    InvalidRequest,
    ForeignRegistry,
    StaleScope,
    StaleRoot,
    StaleDomain,
    AlreadyActive,
    Registry(RegistryError),
    Infrastructure(infrastructure::InfrastructureError),
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalWorkloadCloseFailure {
    error: CausalWorkloadError,
    session: CausalWorkloadSession,
}

impl CausalWorkloadCloseFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_session(self) -> CausalWorkloadSession {
        self.session
    }
}

/// Exact, Registry-bound activation input. It is non-cloneable and is returned
/// unchanged on every failure after preparation.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalActivationRequest {
    registry_instance: u64,
    scope_revision: u64,
    domain_revision: u64,
    root: PortalHandle,
    request_id: u64,
    request_generation: u64,
    limits: infrastructure::InfrastructureLimits,
    domains: Vec<(DomainKey, u64)>,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalActivationFailure {
    error: CausalWorkloadError,
    request: CausalActivationRequest,
}

impl CausalActivationFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_input(self) -> CausalActivationRequest {
        self.request
    }

    pub(crate) fn into_parts(self) -> (CausalWorkloadError, CausalActivationRequest) {
        (self.error, self.request)
    }
}

impl EffectRegistry {
    /// Prepares the exact activation input without changing either ledger.
    pub(crate) fn prepare_causal_workload_activation(
        &self,
        root: PortalHandle,
        request_id: u64,
        request_generation: u64,
        limits: CausalWorkloadLimits,
    ) -> Result<CausalActivationRequest, CausalWorkloadError> {
        if request_id == 0 || request_generation == 0 {
            return Err(CausalWorkloadError::InvalidRequest);
        }
        self.check_invariants()
            .map_err(CausalWorkloadError::Registry)?;
        if self.infrastructure.is_enabled(root.scope) {
            return Err(CausalWorkloadError::AlreadyActive);
        }
        let scope = self
            .scopes
            .get(&root.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        let binding = scope
            .domains
            .get(&root.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        let record = self
            .effects
            .get(&root.effect)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownEffect))?;
        if scope.phase != ScopePhase::Active
            || scope.authority_epoch != root.authority_epoch
            || binding.binding_epoch != root.binding_epoch
            || binding.quarantine.is_some()
            || binding.supervisor.is_none()
            || binding.fallback_running
            || record.handle() != root
            || record.identity.scope != root.scope
            || record.identity.domain != root.domain
            || record.identity.authority_epoch != root.authority_epoch
            || record.identity.binding_epoch != root.binding_epoch
            || record.identity.parent.is_some()
            || record.phase != EffectPhase::Prepared
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(scope.domains.len())
            .map_err(|_| {
                CausalWorkloadError::Infrastructure(
                    infrastructure::InfrastructureError::AllocationFailed,
                )
            })?;
        domains.extend(
            scope
                .domains
                .iter()
                .map(|(domain, binding)| (*domain, binding.binding_epoch)),
        );
        Ok(CausalActivationRequest {
            registry_instance: self.instance_id,
            scope_revision: scope.revision,
            domain_revision: binding.revision,
            root,
            request_id,
            request_generation,
            limits: limits.infrastructure()?,
            domains,
        })
    }

    /// Atomically installs the preallocated infrastructure root plus workload
    /// and mints the non-Copy session only after the authoritative append.
    // The large error is deliberate: boxing it would allocate on a rejected
    // activation before returning the caller's exact linear input.
    #[allow(clippy::result_large_err)]
    pub(crate) fn activate_causal_workload(
        &mut self,
        request: CausalActivationRequest,
    ) -> Result<CausalWorkloadSession, CausalActivationFailure> {
        if let Err(error) = self.validate_causal_workload_activation(&request) {
            return Err(CausalActivationFailure { error, request });
        }
        let root = infrastructure::WorkloadRootPresentation::new(
            request.root.scope,
            request.root.authority_epoch,
            request.root.effect,
        );
        let workload = infrastructure::WorkloadRequestPresentation::new(
            request.root.domain,
            request.root.binding_epoch,
            request.request_id,
            request.request_generation,
        );
        let install = match self.infrastructure.prepare_causal_workload_bootstrap(
            root,
            workload,
            request.limits,
            &request.domains,
        ) {
            Ok(install) => install,
            Err(error) => {
                return Err(CausalActivationFailure {
                    error: CausalWorkloadError::Infrastructure(error),
                    request,
                });
            }
        };
        let context = self
            .infrastructure
            .install_causal_workload_bootstrap(install);
        let identity = CausalWorkloadIdentity {
            registry_instance: self.instance_id,
            scope: request.root.scope,
            authority_epoch: request.root.authority_epoch,
            root_effect: request.root.effect,
            domain: request.root.domain,
            binding_epoch: request.root.binding_epoch,
            request_id: request.request_id,
            request_generation: request.request_generation,
        };
        __cser_core::debug_assert!(self.check_infrastructure_root_links().is_ok());
        Ok(CausalWorkloadSession { identity, context })
    }

    fn validate_causal_workload_activation(
        &self,
        plan: &CausalActivationRequest,
    ) -> Result<(), CausalWorkloadError> {
        if plan.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        if self.infrastructure.is_enabled(plan.root.scope) {
            return Err(CausalWorkloadError::AlreadyActive);
        }
        let scope = self
            .scopes
            .get(&plan.root.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        if scope.phase != ScopePhase::Active
            || scope.authority_epoch != plan.root.authority_epoch
            || scope.revision != plan.scope_revision
            || scope.domains.len() != plan.domains.len()
            || scope.domains.iter().zip(&plan.domains).any(
                |((domain, binding), (expected_domain, expected_epoch))| {
                    domain != expected_domain || binding.binding_epoch != *expected_epoch
                },
            )
        {
            return Err(CausalWorkloadError::StaleScope);
        }
        let binding = scope
            .domains
            .get(&plan.root.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        if binding.binding_epoch != plan.root.binding_epoch
            || binding.revision != plan.domain_revision
            || binding.quarantine.is_some()
            || binding.supervisor.is_none()
            || binding.fallback_running
        {
            return Err(CausalWorkloadError::StaleDomain);
        }
        let record = self
            .effects
            .get(&plan.root.effect)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownEffect))?;
        if record.handle() != plan.root
            || record.identity.scope != plan.root.scope
            || record.identity.domain != plan.root.domain
            || record.identity.authority_epoch != plan.root.authority_epoch
            || record.identity.binding_epoch != plan.root.binding_epoch
            || record.identity.parent.is_some()
            || record.phase != EffectPhase::Prepared
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        Ok(())
    }

    pub(crate) fn verify_causal_workload_session(
        &self,
        session: &CausalWorkloadSession,
    ) -> Result<CausalWorkloadIdentity, CausalWorkloadError> {
        if session.identity.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        match self
            .infrastructure
            .workload_context_is_open(&session.context)
            .map_err(CausalWorkloadError::Infrastructure)?
        {
            true => Ok(session.identity),
            false => Err(CausalWorkloadError::StaleRoot),
        }
    }

    // The large error is deliberate: closure failure must return the exact
    // non-cloneable session without allocating in a terminal failure path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn close_causal_workload(
        &mut self,
        session: CausalWorkloadSession,
    ) -> Result<CausalWorkloadIdentity, CausalWorkloadCloseFailure> {
        if session.identity.registry_instance != self.instance_id {
            return Err(CausalWorkloadCloseFailure {
                error: CausalWorkloadError::ForeignRegistry,
                session,
            });
        }
        match self.infrastructure.close_workload(&session.context) {
            Ok(()) => Ok(session.identity),
            Err(error) => Err(CausalWorkloadCloseFailure {
                error: CausalWorkloadError::Infrastructure(error),
                session,
            }),
        }
    }
}

#[cfg(test)]
pub(super) fn runtime_causal_bootstrap_self_test() {
    use super::{
        CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest, DomainConfig,
        OperationClass, PublicationMode, RegisterRequest, ScopeConfig, SyscallDescriptor, TaskKey,
    };

    const SCOPE: ScopeKey = ScopeKey::new(0xca00, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0xca01, 1);
    const SERVICE: TaskKey = TaskKey::new(0xca02, 1);
    const DOMAIN: DomainKey = DomainKey::new(0xca);
    const CREDIT: CreditClass = CreditClass::new(0xca);

    const fn limits() -> CausalWorkloadLimits {
        CausalWorkloadLimits::new(8, 2, 8, 2, 2, 8, 4, 4, 4, 12, 12, 128)
    }

    fn fixture() -> (EffectRegistry, PortalHandle) {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 7,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 1)],
            })
            .unwrap();
        registry
            .add_domain(
                SCOPE,
                DomainConfig {
                    key: DOMAIN,
                    binding_epoch: 3,
                    supervisor: SERVICE,
                },
            )
            .unwrap();
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: SERVICE,
                    operation: OperationClass::new(0xca10),
                    descriptor: SyscallDescriptor::new(17, [0xca; 6]),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: DOMAIN,
                parent: None,
            })
            .unwrap();
        registry.prepare(SERVICE, root.handle).unwrap();
        registry.check_invariants().unwrap();
        (registry, root.handle)
    }

    let (mut registry, root) = fixture();
    let request = registry
        .prepare_causal_workload_activation(root, 0xca20, 1, limits())
        .unwrap();
    let session = registry.activate_causal_workload(request).unwrap();
    let identity = registry.verify_causal_workload_session(&session).unwrap();
    __cser_core::assert_eq!(identity.scope(), SCOPE);
    __cser_core::assert_eq!(identity.root_effect(), root.effect());
    __cser_core::assert_eq!(identity.request_id(), 0xca20);
    __cser_core::assert_eq!(identity.request_generation(), 1);
    __cser_core::assert!(registry.infrastructure.is_enabled(SCOPE));
    registry.check_invariants().unwrap();
    __cser_core::assert_eq!(registry.close_causal_workload(session), Ok(identity));
    registry.check_invariants().unwrap();

    // A live child blocks close without consuming the opaque session or
    // changing either ledger. Once that exact child terminalizes, the same
    // returned session can close successfully.
    let (mut blocked, blocked_root) = fixture();
    let request = blocked
        .prepare_causal_workload_activation(blocked_root, 0xca26, 1, limits())
        .unwrap();
    let session = blocked.activate_causal_workload(request).unwrap();
    let task = blocked
        .infrastructure
        .admit_task(
            &session.context,
            infrastructure::TaskWorkDescriptor {
                work_id: 0xca27,
                generation: 1,
                task: TaskKey::new(0xca28, 1),
                role: infrastructure::TaskWorkRole::GuestSyscallWork,
                vm: Some(infrastructure::VmAuthorityKey::new(0xca29, 1).unwrap()),
            },
        )
        .unwrap();
    let before = blocked.failure_atomic_projection();
    let failure = blocked.close_causal_workload(session).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Infrastructure(infrastructure::InfrastructureError::ClosureBlocked {
            kind: infrastructure::InfrastructureKind::Task,
            live: 1,
        })
    );
    __cser_core::assert_eq!(blocked.failure_atomic_projection(), before);
    let session = failure.into_session();
    __cser_core::assert!(blocked.verify_causal_workload_session(&session).is_ok());
    blocked
        .infrastructure
        .reject_task_construction(task)
        .unwrap();
    blocked.close_causal_workload(session).unwrap();
    blocked.check_invariants().unwrap();

    // Freeze the selected bounded filesystem profile and exercise its exact
    // deadline-series backpressure. Terminal deadline records deliberately
    // keep occupying their slots until root closure, so this is the relevant
    // capacity shape for poll/ready/stop/reset/IOTLB retry series.
    let raw_limits = limits().infrastructure().unwrap();
    __cser_core::assert_eq!(
        (
            raw_limits.workloads,
            raw_limits.tasks,
            raw_limits.service_requests,
            raw_limits.delayed_commands,
            raw_limits.continuations,
            raw_limits.replies,
            raw_limits.deadline_series,
        ),
        (1, 8, 2, 8, 2, 2, 8)
    );
    __cser_core::assert_eq!(
        (
            raw_limits.faults,
            raw_limits.device_preparations,
            raw_limits.queue_slots,
            raw_limits.pinned_pages,
            raw_limits.dma_mappings,
            raw_limits.diagnostic_events,
        ),
        (4, 4, 4, 12, 12, 128)
    );
    let (mut quota, quota_root) = fixture();
    let request = quota
        .prepare_causal_workload_activation(quota_root, 0xca30, 1, limits())
        .unwrap();
    let session = quota.activate_causal_workload(request).unwrap();
    let task = quota
        .infrastructure
        .admit_task(
            &session.context,
            infrastructure::TaskWorkDescriptor {
                work_id: 0xca31,
                generation: 1,
                task: TaskKey::new(0xca32, 1),
                role: infrastructure::TaskWorkRole::GuestSyscallWork,
                vm: Some(infrastructure::VmAuthorityKey::new(0xca33, 1).unwrap()),
            },
        )
        .unwrap();
    let entered = quota.infrastructure.claim_task_entry(task).unwrap();
    let descriptor = |series_id| infrastructure::DeadlineDescriptor {
        series_id,
        generation: 1,
        purpose: infrastructure::DeadlinePurpose::Wait,
        clock: infrastructure::DeadlineClockBasis::ObservedCallbackTick,
        deadline_tick: 10,
        attempt: 1,
        max_attempts: 2,
        backoff_ticks: 1,
    };
    let mut deadlines = __cser_alloc::vec::Vec::new();
    for series_id in 0xca40..0xca48 {
        deadlines.push(
            quota
                .infrastructure
                .arm_deadline(&entered, descriptor(series_id))
                .unwrap(),
        );
    }
    let before = quota.failure_atomic_projection();
    __cser_core::assert_eq!(
        quota
            .infrastructure
            .arm_deadline(&entered, descriptor(0xca48))
            .unwrap_err(),
        infrastructure::InfrastructureError::QuotaExceeded(
            infrastructure::InfrastructureKind::Deadline
        )
    );
    __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
    __cser_core::assert_eq!(deadlines.len(), 8);
    quota.check_invariants().unwrap();

    // A request prepared by another Registry never installs a fake local
    // session and is returned byte-for-byte through the typed failure.
    let (foreign_owner, foreign_root) = fixture();
    let foreign = foreign_owner
        .prepare_causal_workload_activation(foreign_root, 0xca21, 1, limits())
        .unwrap();
    let expected = __cser_alloc::format!("{foreign:?}");
    let (mut target, _) = fixture();
    let before = target.failure_atomic_projection();
    let failure = target.activate_causal_workload(foreign).unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ForeignRegistry);
    __cser_core::assert_eq!(
        __cser_alloc::format!("{:?}", failure.into_input()),
        expected
    );
    __cser_core::assert_eq!(target.failure_atomic_projection(), before);
    __cser_core::assert!(!target.infrastructure.is_enabled(SCOPE));

    // A scope mutation after preparation is fenced before candidate install;
    // the exact activation input and the mutated live projection survive.
    let (mut stale, stale_root) = fixture();
    let request = stale
        .prepare_causal_workload_activation(stale_root, 0xca22, 1, limits())
        .unwrap();
    let expected = __cser_alloc::format!("{request:?}");
    stale
        .add_domain(
            SCOPE,
            DomainConfig {
                key: DomainKey::new(0xcb),
                binding_epoch: 1,
                supervisor: TaskKey::new(0xca03, 1),
            },
        )
        .unwrap();
    let before = stale.failure_atomic_projection();
    let failure = stale.activate_causal_workload(request).unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::StaleScope);
    __cser_core::assert_eq!(
        __cser_alloc::format!("{:?}", failure.into_input()),
        expected
    );
    __cser_core::assert_eq!(stale.failure_atomic_projection(), before);
    __cser_core::assert!(!stale.infrastructure.is_enabled(SCOPE));

    // Invalid post-preparation request coordinates fail inside off-ledger
    // staging and still return the exact non-cloneable input.
    let (mut invalid, invalid_root) = fixture();
    let mut request = invalid
        .prepare_causal_workload_activation(invalid_root, 0xca23, 1, limits())
        .unwrap();
    request.request_id = 0;
    let expected = __cser_alloc::format!("{request:?}");
    let before = invalid.failure_atomic_projection();
    let failure = invalid.activate_causal_workload(request).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Infrastructure(
            infrastructure::InfrastructureError::InvalidGeneration
        )
    );
    __cser_core::assert_eq!(
        __cser_alloc::format!("{:?}", failure.into_input()),
        expected
    );
    __cser_core::assert_eq!(invalid.failure_atomic_projection(), before);
    __cser_core::assert!(!invalid.infrastructure.is_enabled(SCOPE));

    // Two inputs may be prepared against one base, but only the first can
    // install; the loser is returned exactly and cannot mint another session.
    let (mut duplicate, duplicate_root) = fixture();
    let first = duplicate
        .prepare_causal_workload_activation(duplicate_root, 0xca24, 1, limits())
        .unwrap();
    let second = duplicate
        .prepare_causal_workload_activation(duplicate_root, 0xca25, 1, limits())
        .unwrap();
    let expected = __cser_alloc::format!("{second:?}");
    let session = duplicate.activate_causal_workload(first).unwrap();
    let installed = duplicate.failure_atomic_projection();
    let failure = duplicate.activate_causal_workload(second).unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::AlreadyActive);
    __cser_core::assert_eq!(
        __cser_alloc::format!("{:?}", failure.into_input()),
        expected
    );
    __cser_core::assert_eq!(duplicate.failure_atomic_projection(), installed);

    // A foreign close returns the exact non-Copy session; its owning Registry
    // can still verify and close that same authority afterwards.
    let (mut wrong_registry, _) = fixture();
    let failure = wrong_registry.close_causal_workload(session).unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ForeignRegistry);
    let session = failure.into_session();
    __cser_core::assert!(duplicate.verify_causal_workload_session(&session).is_ok());
    duplicate.close_causal_workload(session).unwrap();
    duplicate.check_invariants().unwrap();
}
