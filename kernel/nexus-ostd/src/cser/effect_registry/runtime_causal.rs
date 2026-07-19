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
    DomainKey, EffectKey, EffectPhase, EffectRegistry, PortalHandle, PublicationTicket,
    RegistryError, RevokeSelection, ScopeKey, ScopePhase, infrastructure,
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
    pub(super) registry_instance: u64,
    pub(super) scope: ScopeKey,
    pub(super) authority_epoch: u64,
    pub(super) root_effect: EffectKey,
    pub(super) domain: DomainKey,
    pub(super) binding_epoch: u64,
    pub(super) request_id: u64,
    pub(super) request_generation: u64,
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
    pub(super) identity: CausalWorkloadIdentity,
    pub(super) context: infrastructure::WorkloadContext,
}

/// Exact two-phase close authority for one session and one pair of Registry
/// revisions. It is intentionally non-Clone and non-Copy.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalWorkloadCloseIntent {
    identity: CausalWorkloadIdentity,
    root: PortalHandle,
    registry_scope_revision: u64,
    infrastructure: infrastructure::WorkloadCloseIntent,
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
    ClosureMismatch,
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

/// Failure before the external publication callback. Both linear close
/// inputs are returned exactly so the caller can retry or re-prepare.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalCombinedCloseFailure {
    error: CausalWorkloadError,
    intent: CausalWorkloadCloseIntent,
    session: CausalWorkloadSession,
}

impl CausalCombinedCloseFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_inputs(self) -> (CausalWorkloadCloseIntent, CausalWorkloadSession) {
        (self.intent, self.session)
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

    /// Prevalidates an exact workload close and returns both the non-Copy
    /// intent and the unchanged session. No authoritative record is changed.
    // The large error is deliberate: a rejected preflight returns the exact
    // non-cloneable session without allocating.
    #[allow(clippy::result_large_err)]
    pub(crate) fn prepare_close_causal_workload(
        &self,
        session: CausalWorkloadSession,
    ) -> Result<(CausalWorkloadCloseIntent, CausalWorkloadSession), CausalWorkloadCloseFailure>
    {
        let (root, registry_scope_revision) =
            match self.validate_causal_workload_close_binding(session.identity) {
                Ok(binding) => binding,
                Err(error) => return Err(CausalWorkloadCloseFailure { error, session }),
            };
        let infrastructure = match self.infrastructure.prepare_workload_close(&session.context) {
            Ok(intent) => intent,
            Err(error) => {
                return Err(CausalWorkloadCloseFailure {
                    error: CausalWorkloadError::Infrastructure(error),
                    session,
                });
            }
        };
        Ok((
            CausalWorkloadCloseIntent {
                identity: session.identity,
                root,
                registry_scope_revision,
                infrastructure,
            },
            session,
        ))
    }

    fn validate_causal_workload_close_binding(
        &self,
        identity: CausalWorkloadIdentity,
    ) -> Result<(PortalHandle, u64), CausalWorkloadError> {
        if identity.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        self.check_invariants()
            .map_err(CausalWorkloadError::Registry)?;
        let scope = self
            .scopes
            .get(&identity.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        let record = self
            .effects
            .get(&identity.root_effect)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownEffect))?;
        let lifecycle_matches = match scope.phase {
            ScopePhase::Active => scope.authority_epoch == identity.authority_epoch,
            ScopePhase::Closing => scope.revoke.as_ref().is_some_and(|revoke| {
                revoke.closed_authority_epoch == identity.authority_epoch
                    && revoke.cohort.contains(&identity.root_effect)
            }),
            ScopePhase::Revoked => false,
        };
        if !lifecycle_matches
            || record.identity.scope != identity.scope
            || record.identity.effect != identity.root_effect
            || record.identity.domain != identity.domain
            || record.identity.authority_epoch != identity.authority_epoch
            || record.identity.binding_epoch != identity.binding_epoch
            || record.identity.parent.is_some()
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        Ok((record.handle(), scope.revision))
    }

    fn validate_prepared_causal_workload_close(
        &self,
        intent: &CausalWorkloadCloseIntent,
        session: &CausalWorkloadSession,
    ) -> Result<CausalWorkloadIdentity, CausalWorkloadError> {
        if intent.identity != session.identity {
            return Err(CausalWorkloadError::ClosureMismatch);
        }
        let (root, registry_scope_revision) =
            self.validate_causal_workload_close_binding(session.identity)?;
        if root != intent.root || registry_scope_revision != intent.registry_scope_revision {
            return Err(CausalWorkloadError::StaleScope);
        }
        self.infrastructure
            .validate_workload_close_intent(&intent.infrastructure, Some(&session.context))
            .map_err(CausalWorkloadError::Infrastructure)?;
        Ok(session.identity)
    }

    /// Allocation-free installation of one internally prevalidated close.
    /// This is private so no caller can swap opaque intents between sessions
    /// and bypass the validation immediately preceding an external boundary.
    fn apply_close_causal_workload(
        &mut self,
        intent: CausalWorkloadCloseIntent,
        session: CausalWorkloadSession,
    ) -> CausalWorkloadIdentity {
        __cser_core::debug_assert_eq!(intent.identity, session.identity);
        let identity = session.identity;
        self.infrastructure
            .apply_workload_close(intent.infrastructure, &session.context);
        identity
    }

    /// Executes the final external publication, publication acknowledgement,
    /// exact workload close, and full Registry/infrastructure-root revoke
    /// completion after one failure-only preflight.
    ///
    /// Every ordinary `Err` returns both linear close inputs and proves the
    /// external callback was not invoked. Once the callback starts, the three
    /// internal applies are allocation-free and infallible under exclusive
    /// Registry access.
    // The large error preserves both linear inputs without allocating on a
    // stale or substituted preflight failure.
    #[allow(clippy::result_large_err)]
    pub(crate) fn acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply<
        T,
    >(
        &mut self,
        ticket: &PublicationTicket,
        selection: &RevokeSelection,
        intent: CausalWorkloadCloseIntent,
        session: CausalWorkloadSession,
        apply_external: impl FnOnce() -> T,
    ) -> Result<(T, CausalWorkloadIdentity), CausalCombinedCloseFailure> {
        let identity = match self.validate_prepared_causal_workload_close(&intent, &session) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(CausalCombinedCloseFailure {
                    error,
                    intent,
                    session,
                });
            }
        };
        if ticket.scope != identity.scope
            || ticket.effect != identity.root_effect
            || selection.scope != identity.scope
            || selection.closed_authority_epoch != identity.authority_epoch
        {
            return Err(CausalCombinedCloseFailure {
                error: CausalWorkloadError::ClosureMismatch,
                intent,
                session,
            });
        }
        let publication = match self.prepare_publication_ack(ticket) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(CausalCombinedCloseFailure {
                    error: CausalWorkloadError::Registry(error),
                    intent,
                    session,
                });
            }
        };
        let revoke = match self.prepare_revoke_complete_apply(
            selection,
            Some(&publication),
            Some(&intent.infrastructure),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(CausalCombinedCloseFailure {
                    error: CausalWorkloadError::Registry(error),
                    intent,
                    session,
                });
            }
        };

        let applied = apply_external();
        self.apply_publication_ack(publication);
        let identity = self.apply_close_causal_workload(intent, session);
        self.apply_revoke_complete(revoke);
        Ok((applied, identity))
    }

    // The large error is deliberate: closure failure must return the exact
    // non-cloneable session without allocating in a terminal failure path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn close_causal_workload(
        &mut self,
        session: CausalWorkloadSession,
    ) -> Result<CausalWorkloadIdentity, CausalWorkloadCloseFailure> {
        match self.prepare_close_causal_workload(session) {
            Ok((intent, session)) => Ok(self.apply_close_causal_workload(intent, session)),
            Err(failure) => Err(failure),
        }
    }
}

#[cfg(test)]
pub(super) fn runtime_causal_bootstrap_self_test() {
    use super::{
        CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest, DomainConfig,
        OperationClass, PublicationMode, RegisterRequest, ScopeClosureProgress, ScopeConfig,
        SyscallDescriptor, TaskKey, TerminalRequest,
    };

    const SCOPE: ScopeKey = ScopeKey::new(0xca00, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0xca01, 1);
    const SERVICE: TaskKey = TaskKey::new(0xca02, 1);
    const DOMAIN: DomainKey = DomainKey::new(0xca);
    const CREDIT: CreditClass = CreditClass::new(0xca);

    const fn limits() -> CausalWorkloadLimits {
        CausalWorkloadLimits::new(8, 2, 8, 2, 2, 8, 4, 4, 4, 12, 12, 128)
    }

    fn fixture_with_publication(publication: PublicationMode) -> (EffectRegistry, PortalHandle) {
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
                    publication,
                },
                domain: DOMAIN,
                parent: None,
            })
            .unwrap();
        registry.prepare(SERVICE, root.handle).unwrap();
        registry.check_invariants().unwrap();
        (registry, root.handle)
    }

    fn fixture() -> (EffectRegistry, PortalHandle) {
        fixture_with_publication(PublicationMode::None)
    }

    fn closing_fixture(
        request_id: u64,
    ) -> (
        EffectRegistry,
        CausalWorkloadSession,
        PublicationTicket,
        RevokeSelection,
    ) {
        let (mut registry, root) = fixture_with_publication(PublicationMode::Required);
        let request = registry
            .prepare_causal_workload_activation(root, request_id, 1, limits())
            .unwrap();
        let session = registry.activate_causal_workload(request).unwrap();
        let selection = registry.revoke_begin(SCOPE).unwrap();
        let selected = registry.revoke_next(&selection).unwrap().unwrap();
        __cser_core::assert_eq!(selected.effect, root.effect());
        let ticket = registry
            .stage_revoke_terminal(&selection, selected.effect, TerminalRequest::aborted(-125))
            .unwrap()
            .publication
            .unwrap();
        __cser_core::assert_eq!(registry.revoke_next(&selection), Ok(None));
        registry.check_invariants().unwrap();
        (registry, session, ticket, selection)
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

    // The closure transaction prevalidates every ordinary failure before its
    // callback, then applies external publication, its acknowledgement, the
    // exact workload close, and both infrastructure/business root finishes.
    let (mut completed, session, ticket, selection) = closing_fixture(0xcac0);
    let identity = session.identity();
    let before_prepare = completed.failure_atomic_projection();
    let (intent, session) = completed.prepare_close_causal_workload(session).unwrap();
    __cser_core::assert_eq!(completed.failure_atomic_projection(), before_prepare);
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let (value, installed_identity) = completed
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &selection,
            intent,
            session,
            || {
                callbacks.set(callbacks.get() + 1);
                0xcafe_u64
            },
        )
        .unwrap();
    __cser_core::assert_eq!(value, 0xcafe);
    __cser_core::assert_eq!(installed_identity, identity);
    __cser_core::assert_eq!(callbacks.get(), 1);
    let receipt = match completed.query_scope_closure(SCOPE).unwrap() {
        ScopeClosureProgress::Closed(receipt) => receipt,
        other => __cser_core::panic!("combined causal close left {other:?}"),
    };
    completed.verify_scope_closure(SCOPE, &receipt).unwrap();
    __cser_core::assert!(__cser_core::matches!(
        completed.infrastructure.closure_progress(SCOPE).unwrap(),
        infrastructure::InfrastructureClosureProgress::Closed(_)
    ));
    completed.check_invariants().unwrap();

    // A stale revoke selector is rejected after the single read-only
    // prevalidation pass. The callback stays untouched and both linear close
    // inputs are returned exactly for a retry with the valid selector.
    let (mut stale_selector, session, ticket, selection) = closing_fixture(0xcac1);
    let (intent, session) = stale_selector
        .prepare_close_causal_workload(session)
        .unwrap();
    let expected_intent = __cser_alloc::format!("{intent:?}");
    let expected_session = __cser_alloc::format!("{session:?}");
    let mut stale = selection.clone();
    stale.sequence += 1;
    let before = stale_selector.failure_atomic_projection();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let failure = stale_selector
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &stale,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Registry(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert_eq!(callbacks.get(), 0);
    __cser_core::assert_eq!(stale_selector.failure_atomic_projection(), before);
    let (intent, session) = failure.into_inputs();
    __cser_core::assert_eq!(__cser_alloc::format!("{intent:?}"), expected_intent);
    __cser_core::assert_eq!(__cser_alloc::format!("{session:?}"), expected_session);
    stale_selector
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 1);
    stale_selector.check_invariants().unwrap();

    // A Registry-bound intent cannot be replayed against an isomorphic local
    // Registry. Rejection happens before either the target callback or target
    // ledger changes; the owner can still consume the returned exact inputs.
    let (mut owner, session, owner_ticket, owner_selection) = closing_fixture(0xcac2);
    let (intent, session) = owner.prepare_close_causal_workload(session).unwrap();
    let expected_intent = __cser_alloc::format!("{intent:?}");
    let expected_session = __cser_alloc::format!("{session:?}");
    let (mut foreign, foreign_session, foreign_ticket, foreign_selection) = closing_fixture(0xcac2);
    let foreign_before = foreign.failure_atomic_projection();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let failure = foreign
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &foreign_ticket,
            &foreign_selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ForeignRegistry);
    __cser_core::assert_eq!(callbacks.get(), 0);
    __cser_core::assert_eq!(foreign.failure_atomic_projection(), foreign_before);
    let (intent, session) = failure.into_inputs();
    __cser_core::assert_eq!(__cser_alloc::format!("{intent:?}"), expected_intent);
    __cser_core::assert_eq!(__cser_alloc::format!("{session:?}"), expected_session);
    owner
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &owner_ticket,
            &owner_selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap();
    let (foreign_intent, foreign_session) = foreign
        .prepare_close_causal_workload(foreign_session)
        .unwrap();
    foreign
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &foreign_ticket,
            &foreign_selection,
            foreign_intent,
            foreign_session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 2);
    owner.check_invariants().unwrap();
    foreign.check_invariants().unwrap();

    // Swapping only the session between two prepared Registries is rejected
    // as an exact close mismatch. Each returned linear authority remains
    // usable only with its originally prepared peer intent.
    let (mut left, left_session, left_ticket, left_selection) = closing_fixture(0xcac3);
    let (left_intent, left_session) = left.prepare_close_causal_workload(left_session).unwrap();
    let (mut right, right_session, right_ticket, right_selection) = closing_fixture(0xcac3);
    let (right_intent, right_session) = right.prepare_close_causal_workload(right_session).unwrap();
    let before = left.failure_atomic_projection();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let failure = left
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &left_ticket,
            &left_selection,
            left_intent,
            right_session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ClosureMismatch);
    __cser_core::assert_eq!(callbacks.get(), 0);
    __cser_core::assert_eq!(left.failure_atomic_projection(), before);
    let (left_intent, right_session) = failure.into_inputs();
    left.acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
        &left_ticket,
        &left_selection,
        left_intent,
        left_session,
        || callbacks.set(callbacks.get() + 1),
    )
    .unwrap();
    right
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &right_ticket,
            &right_selection,
            right_intent,
            right_session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 2);

    // An infrastructure revision change after close preparation makes the
    // intent stale. It is rejected before publication and the returned
    // session may prepare a fresh exact intent against the new revision.
    let (mut stale_intent, session, ticket, selection) = closing_fixture(0xcac4);
    let (intent, session) = stale_intent.prepare_close_causal_workload(session).unwrap();
    stale_intent
        .infrastructure
        .advance_authoritative_scope_revision_for_test(SCOPE);
    let before = stale_intent.failure_atomic_projection();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let failure = stale_intent
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Infrastructure(infrastructure::InfrastructureError::StaleClaim)
    );
    __cser_core::assert_eq!(callbacks.get(), 0);
    __cser_core::assert_eq!(stale_intent.failure_atomic_projection(), before);
    let (_, session) = failure.into_inputs();
    let (intent, session) = stale_intent.prepare_close_causal_workload(session).unwrap();
    stale_intent
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 1);

    // The outer publication/revoke revision pair is also precomputed. With
    // only one increment left, acknowledgement can fit but the root finish
    // cannot, so preflight returns overflow without calling externally.
    let (mut overflow, session, ticket, selection) = closing_fixture(0xcac5);
    overflow.scopes.get_mut(&SCOPE).unwrap().revision = u64::MAX - 1;
    let (intent, session) = overflow.prepare_close_causal_workload(session).unwrap();
    let expected_intent = __cser_alloc::format!("{intent:?}");
    let expected_session = __cser_alloc::format!("{session:?}");
    let before = overflow.failure_atomic_projection();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    let failure = overflow
        .acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
            &ticket,
            &selection,
            intent,
            session,
            || callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Registry(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(callbacks.get(), 0);
    __cser_core::assert_eq!(overflow.failure_atomic_projection(), before);
    let (intent, session) = failure.into_inputs();
    __cser_core::assert_eq!(__cser_alloc::format!("{intent:?}"), expected_intent);
    __cser_core::assert_eq!(__cser_alloc::format!("{session:?}"), expected_session);

    // A live child is caught by the first close preflight, with the exact
    // session and complete Registry projection preserved. Draining that child
    // permits the same session to enter the combined transaction.
    let (mut live, root) = fixture_with_publication(PublicationMode::Required);
    let request = live
        .prepare_causal_workload_activation(root, 0xcac6, 1, limits())
        .unwrap();
    let session = live.activate_causal_workload(request).unwrap();
    let task = live
        .infrastructure
        .admit_task(
            &session.context,
            infrastructure::TaskWorkDescriptor {
                work_id: 0xcad6,
                generation: 1,
                task: TaskKey::new(0xcae6, 1),
                role: infrastructure::TaskWorkRole::GuestSyscallWork,
                vm: Some(infrastructure::VmAuthorityKey::new(0xcaf6, 1).unwrap()),
            },
        )
        .unwrap();
    let selection = live.revoke_begin(SCOPE).unwrap();
    let selected = live.revoke_next(&selection).unwrap().unwrap();
    let ticket = live
        .stage_revoke_terminal(&selection, selected.effect, TerminalRequest::aborted(-125))
        .unwrap()
        .publication
        .unwrap();
    __cser_core::assert_eq!(live.revoke_next(&selection), Ok(None));
    let expected_session = __cser_alloc::format!("{session:?}");
    let before = live.failure_atomic_projection();
    let failure = live.prepare_close_causal_workload(session).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &CausalWorkloadError::Infrastructure(infrastructure::InfrastructureError::ClosureBlocked {
            kind: infrastructure::InfrastructureKind::Task,
            live: 1,
        })
    );
    __cser_core::assert_eq!(live.failure_atomic_projection(), before);
    let session = failure.into_session();
    __cser_core::assert_eq!(__cser_alloc::format!("{session:?}"), expected_session);
    live.infrastructure.reject_task_construction(task).unwrap();
    let (intent, session) = live.prepare_close_causal_workload(session).unwrap();
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    live.acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply(
        &ticket,
        &selection,
        intent,
        session,
        || callbacks.set(callbacks.get() + 1),
    )
    .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 1);
    live.check_invariants().unwrap();

    // Two same-base close intents cannot both apply. The first standalone
    // workload close leaves the full scope Closing; the second is stale, and
    // only the explicit root completion transitions the scope to Revoked.
    let (mut duplicate_close, session, ticket, selection) = closing_fixture(0xcac7);
    let (first, session) = duplicate_close
        .prepare_close_causal_workload(session)
        .unwrap();
    let (replay, session) = duplicate_close
        .prepare_close_causal_workload(session)
        .unwrap();
    duplicate_close.apply_close_causal_workload(first, session);
    __cser_core::assert_eq!(
        duplicate_close.query_scope_closure(SCOPE).unwrap(),
        ScopeClosureProgress::Closing(selection.clone())
    );
    __cser_core::assert_eq!(
        duplicate_close
            .infrastructure
            .validate_workload_close_intent(&replay.infrastructure, None),
        Err(infrastructure::InfrastructureError::InvalidState)
    );
    let callbacks = __cser_core::cell::Cell::new(0_u32);
    duplicate_close
        .acknowledge_publication_and_revoke_complete_with_apply(&ticket, &selection, || {
            callbacks.set(callbacks.get() + 1)
        })
        .unwrap();
    __cser_core::assert_eq!(callbacks.get(), 1);
    __cser_core::assert!(__cser_core::matches!(
        duplicate_close.query_scope_closure(SCOPE).unwrap(),
        ScopeClosureProgress::Closed(_)
    ));
    duplicate_close.check_invariants().unwrap();
}
