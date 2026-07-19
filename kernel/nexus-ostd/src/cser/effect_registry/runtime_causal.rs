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
    DomainKey, DomainRecoverySnapshot, EffectKey, EffectPhase, EffectRegistry, PortalHandle,
    PublicationTicket, RegistryError, RevokeSelection, ScopeKey, ScopePhase, TaskKey,
    domain_recovery_snapshot_digest, infrastructure,
};

/// Bounded capacity for workloads and the seven RFC 0003 obligation families.
///
/// The conservative constructor retains one workload slot. A caller which
/// needs a ledger-owned domain child must opt into additional bounded workload
/// capacity explicitly with [`Self::with_workload_capacity`]. Service-request
/// and delayed-command capacity remain separate because they have distinct
/// ownership transitions even though they form one implementation tranche.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalWorkloadLimits {
    workloads: u32,
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
            workloads: 1,
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

    pub(crate) const fn with_workload_capacity(mut self, workloads: u32) -> Self {
        self.workloads = workloads;
        self
    }

    fn infrastructure(self) -> Result<infrastructure::InfrastructureLimits, CausalWorkloadError> {
        infrastructure::InfrastructureLimits::new(
            self.workloads,
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

/// Descriptive identity of one ledger-owned domain workload below the exact
/// root workload. It is copyable evidence, never bearer authority.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalDomainWorkloadIdentity {
    pub(super) parent: CausalWorkloadIdentity,
    pub(super) domain: DomainKey,
    pub(super) binding_epoch: u64,
    pub(super) request_id: u64,
    pub(super) request_generation: u64,
}

impl CausalDomainWorkloadIdentity {
    pub(crate) const fn parent(self) -> CausalWorkloadIdentity {
        self.parent
    }

    pub(crate) const fn domain(self) -> DomainKey {
        self.domain
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    pub(crate) const fn request_id(self) -> u64 {
        self.request_id
    }

    pub(crate) const fn request_generation(self) -> u64 {
        self.request_generation
    }
}

/// Private origin of one child authority. The portable service descriptor
/// never supplies these coordinates; the Registry derives them from either an
/// active binding or one exact live recovery snapshot.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(super) enum CausalDomainWorkloadProvenance {
    ActiveSupervisor {
        supervisor: TaskKey,
    },
    RecoveryReplacement {
        replacement: TaskKey,
        attempt: u32,
        snapshot_digest: [u8; 32],
    },
}

/// Opaque authority for one child workload admitted into a Registry-owned
/// target domain. This type intentionally implements neither `Clone` nor
/// `Copy`; only the authoritative infrastructure ledger can mint it.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalDomainWorkloadSession {
    pub(super) identity: CausalDomainWorkloadIdentity,
    pub(super) context: infrastructure::WorkloadContext,
    provenance: CausalDomainWorkloadProvenance,
}

impl CausalDomainWorkloadSession {
    pub(crate) const fn identity(&self) -> CausalDomainWorkloadIdentity {
        self.identity
    }

    pub(super) const fn provenance(&self) -> CausalDomainWorkloadProvenance {
        self.provenance
    }
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

    /// Registry-only access to the opaque infrastructure context.
    ///
    /// Personalities can present `&CausalWorkloadSession` to Registry APIs,
    /// but cannot extract or copy this root-bound authority.
    pub(super) const fn infrastructure_context(&self) -> &infrastructure::WorkloadContext {
        &self.context
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
    ParentMismatch,
    DomainMismatch,
    StaleScope,
    StaleRoot,
    StaleDomain,
    RecoveryUnavailable,
    RecoverySnapshotMismatch,
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

/// Exact prepared admission for a child workload. The target binding epoch is
/// captured from the authoritative Registry and cannot be supplied by a
/// caller. The input is deliberately non-Clone/non-Copy and is returned on
/// every failed activation.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalDomainWorkloadRequest {
    registry_instance: u64,
    registry_scope_revision: u64,
    infrastructure_scope_revision: u64,
    domain_revision: u64,
    parent: CausalWorkloadIdentity,
    domain: DomainKey,
    binding_epoch: u64,
    supervisor: TaskKey,
    request_id: u64,
    request_generation: u64,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalDomainWorkloadActivationFailure {
    error: CausalWorkloadError,
    request: CausalDomainWorkloadRequest,
}

impl CausalDomainWorkloadActivationFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_input(self) -> CausalDomainWorkloadRequest {
        self.request
    }
}

/// Copyable, descriptive proof that one exact recovery snapshot is still the
/// manager-owned admission window for a replacement. It carries no workload
/// bearer and cannot be used by the ordinary active-child API.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CausalRecoveryAdmissionFence {
    registry_instance: u64,
    parent: CausalWorkloadIdentity,
    scope: ScopeKey,
    domain: DomainKey,
    replacement: TaskKey,
    attempt: u32,
    authority_epoch: u64,
    binding_epoch: u64,
    root_revision: u64,
    domain_revision: u64,
    infrastructure_scope_revision: u64,
    snapshot_digest: [u8; 32],
}

impl CausalRecoveryAdmissionFence {
    pub(crate) const fn scope(self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn domain(self) -> DomainKey {
        self.domain
    }

    pub(crate) const fn replacement(self) -> TaskKey {
        self.replacement
    }

    pub(crate) const fn attempt(self) -> u32 {
        self.attempt
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    pub(crate) const fn snapshot_digest(self) -> [u8; 32] {
        self.snapshot_digest
    }
}

/// Non-Copy activation input which keeps the recovery fence paired with the
/// portable workload coordinates until the authoritative child append.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalRecoveryWorkloadRequest {
    fence: CausalRecoveryAdmissionFence,
    request_id: u64,
    request_generation: u64,
}

impl CausalRecoveryWorkloadRequest {
    pub(crate) const fn fence(&self) -> CausalRecoveryAdmissionFence {
        self.fence
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalRecoveryFenceFailure {
    error: CausalWorkloadError,
    fence: CausalRecoveryAdmissionFence,
}

impl CausalRecoveryFenceFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) const fn into_input(self) -> CausalRecoveryAdmissionFence {
        self.fence
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalRecoveryWorkloadActivationFailure {
    error: CausalWorkloadError,
    request: CausalRecoveryWorkloadRequest,
}

impl CausalRecoveryWorkloadActivationFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_input(self) -> CausalRecoveryWorkloadRequest {
        self.request
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct CausalDomainWorkloadCloseFailure {
    error: CausalWorkloadError,
    session: CausalDomainWorkloadSession,
}

impl CausalDomainWorkloadCloseFailure {
    pub(crate) const fn error(&self) -> &CausalWorkloadError {
        &self.error
    }

    pub(crate) fn into_session(self) -> CausalDomainWorkloadSession {
        self.session
    }
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
        let identity = session.identity;
        if identity.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        self.validate_causal_workload_close_binding(identity)?;
        let description = self
            .infrastructure
            .describe_open_workload(&session.context)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if description.registry_instance != identity.registry_instance
            || description.scope != identity.scope
            || description.authority_epoch != identity.authority_epoch
            || description.root_effect != identity.root_effect
            || description.domain != identity.domain
            || description.binding_epoch != identity.binding_epoch
            || description.request_id != identity.request_id
            || description.request_generation != identity.request_generation
            || description.parent
                != infrastructure::WorkloadParentDescription::RootEffect(identity.root_effect)
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        Ok(identity)
    }

    /// Captures a child admission from the exact authoritative Registry and
    /// infrastructure revisions. The caller names only the target domain and
    /// portable request coordinates; the binding epoch is never an input.
    pub(crate) fn prepare_causal_domain_workload(
        &self,
        parent: &CausalWorkloadSession,
        target_domain: DomainKey,
        request_id: u64,
        request_generation: u64,
    ) -> Result<CausalDomainWorkloadRequest, CausalWorkloadError> {
        if request_id == 0 || request_generation == 0 {
            return Err(CausalWorkloadError::InvalidRequest);
        }
        let parent_identity = self.verify_causal_workload_session(parent)?;
        self.check_invariants()
            .map_err(CausalWorkloadError::Registry)?;
        let scope = self
            .scopes
            .get(&parent_identity.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        if scope.phase != ScopePhase::Active
            || scope.authority_epoch != parent_identity.authority_epoch
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        let binding = scope
            .domains
            .get(&target_domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        let supervisor = match binding.supervisor {
            Some(supervisor) if binding.quarantine.is_none() && !binding.fallback_running => {
                supervisor
            }
            Some(_) | None => return Err(CausalWorkloadError::StaleDomain),
        };
        let infrastructure = self
            .infrastructure
            .root_binding(parent_identity.scope)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if infrastructure.authority_epoch != parent_identity.authority_epoch
            || infrastructure.root_effect != parent_identity.root_effect
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        Ok(CausalDomainWorkloadRequest {
            registry_instance: self.instance_id,
            registry_scope_revision: scope.revision,
            infrastructure_scope_revision: infrastructure.revision,
            domain_revision: binding.revision,
            parent: parent_identity,
            domain: target_domain,
            binding_epoch: binding.binding_epoch,
            supervisor,
            request_id,
            request_generation,
        })
    }

    /// Installs a prepared child admission only after revalidating its exact
    /// parent, target domain, and both authoritative revisions. The repeated
    /// target-domain argument makes cross-domain plan substitution explicit.
    #[allow(clippy::result_large_err)]
    pub(crate) fn activate_causal_domain_workload(
        &mut self,
        parent: &CausalWorkloadSession,
        target_domain: DomainKey,
        request: CausalDomainWorkloadRequest,
    ) -> Result<CausalDomainWorkloadSession, CausalDomainWorkloadActivationFailure> {
        if let Err(error) =
            self.validate_causal_domain_workload_activation(parent, target_domain, &request)
        {
            return Err(CausalDomainWorkloadActivationFailure { error, request });
        }
        let context = match self.infrastructure.open_child_workload(
            &parent.context,
            target_domain,
            request.request_id,
            request.request_generation,
        ) {
            Ok(context) => context,
            Err(error) => {
                return Err(CausalDomainWorkloadActivationFailure {
                    error: CausalWorkloadError::Infrastructure(error),
                    request,
                });
            }
        };
        let identity = CausalDomainWorkloadIdentity {
            parent: request.parent,
            domain: request.domain,
            binding_epoch: request.binding_epoch,
            request_id: request.request_id,
            request_generation: request.request_generation,
        };
        __cser_core::debug_assert!(self.check_infrastructure_root_links().is_ok());
        Ok(CausalDomainWorkloadSession {
            identity,
            context,
            provenance: CausalDomainWorkloadProvenance::ActiveSupervisor {
                supervisor: request.supervisor,
            },
        })
    }

    fn validate_causal_domain_workload_activation(
        &self,
        parent: &CausalWorkloadSession,
        target_domain: DomainKey,
        request: &CausalDomainWorkloadRequest,
    ) -> Result<(), CausalWorkloadError> {
        if request.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        if target_domain != request.domain {
            return Err(CausalWorkloadError::DomainMismatch);
        }
        let parent_identity = self.verify_causal_workload_session(parent)?;
        if parent_identity != request.parent {
            return Err(CausalWorkloadError::ParentMismatch);
        }
        let scope = self
            .scopes
            .get(&request.parent.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        if scope.phase != ScopePhase::Active
            || scope.authority_epoch != request.parent.authority_epoch
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        let binding = scope
            .domains
            .get(&request.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        if binding.binding_epoch != request.binding_epoch
            || binding.revision != request.domain_revision
            || binding.quarantine.is_some()
            || binding.supervisor != Some(request.supervisor)
            || binding.fallback_running
        {
            return Err(CausalWorkloadError::StaleDomain);
        }
        if scope.revision != request.registry_scope_revision {
            return Err(CausalWorkloadError::StaleScope);
        }
        let infrastructure = self
            .infrastructure
            .root_binding(request.parent.scope)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if infrastructure.authority_epoch != request.parent.authority_epoch
            || infrastructure.root_effect != request.parent.root_effect
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        if infrastructure.revision != request.infrastructure_scope_revision {
            return Err(CausalWorkloadError::StaleScope);
        }
        Ok(())
    }

    /// Derives a copyable admission fence only while the supplied snapshot is
    /// still the exact manager-owned recovery attempt below this root workload.
    /// The infrastructure revision is sampled here so activation cannot race an
    /// unrelated causal child append.
    pub(crate) fn prepare_causal_recovery_admission_fence(
        &self,
        parent: &CausalWorkloadSession,
        snapshot: &DomainRecoverySnapshot,
    ) -> Result<CausalRecoveryAdmissionFence, CausalWorkloadError> {
        if snapshot.registry_instance_id != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        if snapshot.digest != domain_recovery_snapshot_digest(snapshot) {
            return Err(CausalWorkloadError::RecoverySnapshotMismatch);
        }
        let parent_identity = self.verify_causal_workload_session(parent)?;
        let infrastructure = self
            .infrastructure
            .root_binding(parent_identity.scope)
            .map_err(CausalWorkloadError::Infrastructure)?;
        let fence = CausalRecoveryAdmissionFence {
            registry_instance: self.instance_id,
            parent: parent_identity,
            scope: snapshot.scope,
            domain: snapshot.domain,
            replacement: snapshot.replacement,
            attempt: snapshot.attempt,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            root_revision: snapshot.root_revision,
            domain_revision: snapshot.domain_revision,
            infrastructure_scope_revision: infrastructure.revision,
            snapshot_digest: snapshot.digest,
        };
        self.validate_causal_recovery_admission_fence(parent, &fence)?;
        Ok(fence)
    }

    /// Pairs one exact live fence with portable child-workload coordinates.
    /// A rejected prepare returns the identical copyable fence.
    #[allow(clippy::result_large_err)]
    pub(crate) fn prepare_causal_recovery_domain_workload(
        &self,
        parent: &CausalWorkloadSession,
        fence: CausalRecoveryAdmissionFence,
        request_id: u64,
        request_generation: u64,
    ) -> Result<CausalRecoveryWorkloadRequest, CausalRecoveryFenceFailure> {
        if request_id == 0 || request_generation == 0 {
            return Err(CausalRecoveryFenceFailure {
                error: CausalWorkloadError::InvalidRequest,
                fence,
            });
        }
        if let Err(error) = self.validate_causal_recovery_admission_fence(parent, &fence) {
            return Err(CausalRecoveryFenceFailure { error, fence });
        }
        Ok(CausalRecoveryWorkloadRequest {
            fence,
            request_id,
            request_generation,
        })
    }

    /// Opens a recovery-only child after repeating every snapshot, binding,
    /// parent and revision check. The normal child API remains active-only.
    #[allow(clippy::result_large_err)]
    pub(crate) fn activate_causal_recovery_domain_workload(
        &mut self,
        parent: &CausalWorkloadSession,
        request: CausalRecoveryWorkloadRequest,
    ) -> Result<CausalDomainWorkloadSession, CausalRecoveryWorkloadActivationFailure> {
        if request.request_id == 0 || request.request_generation == 0 {
            return Err(CausalRecoveryWorkloadActivationFailure {
                error: CausalWorkloadError::InvalidRequest,
                request,
            });
        }
        if let Err(error) = self.validate_causal_recovery_admission_fence(parent, &request.fence) {
            return Err(CausalRecoveryWorkloadActivationFailure { error, request });
        }
        let context = match self.infrastructure.open_child_workload(
            &parent.context,
            request.fence.domain,
            request.request_id,
            request.request_generation,
        ) {
            Ok(context) => context,
            Err(error) => {
                return Err(CausalRecoveryWorkloadActivationFailure {
                    error: CausalWorkloadError::Infrastructure(error),
                    request,
                });
            }
        };
        let identity = CausalDomainWorkloadIdentity {
            parent: request.fence.parent,
            domain: request.fence.domain,
            binding_epoch: request.fence.binding_epoch,
            request_id: request.request_id,
            request_generation: request.request_generation,
        };
        __cser_core::debug_assert!(self.check_infrastructure_root_links().is_ok());
        Ok(CausalDomainWorkloadSession {
            identity,
            context,
            provenance: CausalDomainWorkloadProvenance::RecoveryReplacement {
                replacement: request.fence.replacement,
                attempt: request.fence.attempt,
                snapshot_digest: request.fence.snapshot_digest,
            },
        })
    }

    fn validate_causal_recovery_admission_fence(
        &self,
        parent: &CausalWorkloadSession,
        fence: &CausalRecoveryAdmissionFence,
    ) -> Result<(), CausalWorkloadError> {
        if fence.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        let parent_identity = self.verify_causal_workload_session(parent)?;
        if parent_identity != fence.parent || fence.scope != parent_identity.scope {
            return Err(CausalWorkloadError::ParentMismatch);
        }
        let scope = self
            .scopes
            .get(&fence.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        if scope.phase != ScopePhase::Active
            || scope.authority_epoch != fence.authority_epoch
            || fence.authority_epoch != parent_identity.authority_epoch
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        if scope.revision != fence.root_revision {
            return Err(CausalWorkloadError::StaleScope);
        }
        let binding = scope
            .domains
            .get(&fence.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        if binding.binding_epoch != fence.binding_epoch || binding.revision != fence.domain_revision
        {
            return Err(CausalWorkloadError::StaleDomain);
        }
        if binding.quarantine.is_some() || !binding.fallback_running || binding.supervisor.is_some()
        {
            return Err(CausalWorkloadError::RecoveryUnavailable);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(CausalWorkloadError::RecoveryUnavailable)?;
        let snapshot = recovery
            .snapshot
            .as_ref()
            .ok_or(CausalWorkloadError::RecoveryUnavailable)?;
        if recovery.ready.is_some()
            || recovery.highest_attempt != fence.attempt
            || snapshot.registry_instance_id != fence.registry_instance
            || snapshot.scope != fence.scope
            || snapshot.domain != fence.domain
            || snapshot.replacement != fence.replacement
            || snapshot.attempt != fence.attempt
            || snapshot.authority_epoch != fence.authority_epoch
            || snapshot.binding_epoch != fence.binding_epoch
            || snapshot.root_revision != fence.root_revision
            || snapshot.domain_revision != fence.domain_revision
            || snapshot.digest != fence.snapshot_digest
            || snapshot.digest != domain_recovery_snapshot_digest(snapshot)
        {
            return Err(CausalWorkloadError::RecoverySnapshotMismatch);
        }
        let infrastructure = self
            .infrastructure
            .root_binding(fence.scope)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if infrastructure.authority_epoch != parent_identity.authority_epoch
            || infrastructure.root_effect != parent_identity.root_effect
        {
            return Err(CausalWorkloadError::StaleRoot);
        }
        if infrastructure.revision != fence.infrastructure_scope_revision {
            return Err(CausalWorkloadError::StaleScope);
        }
        Ok(())
    }

    pub(crate) fn verify_causal_domain_workload_session(
        &self,
        session: &CausalDomainWorkloadSession,
    ) -> Result<CausalDomainWorkloadIdentity, CausalWorkloadError> {
        let identity = session.identity;
        if identity.parent.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        self.validate_causal_workload_close_binding(identity.parent)?;
        let scope = self
            .scopes
            .get(&identity.parent.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        let binding = scope
            .domains
            .get(&identity.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        if binding.binding_epoch != identity.binding_epoch {
            return Err(CausalWorkloadError::StaleDomain);
        }
        let description = self
            .infrastructure
            .describe_open_workload(&session.context)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if description.registry_instance != identity.parent.registry_instance
            || description.scope != identity.parent.scope
            || description.authority_epoch != identity.parent.authority_epoch
            || description.root_effect != identity.parent.root_effect
            || description.domain != identity.domain
            || description.binding_epoch != identity.binding_epoch
            || description.request_id != identity.request_id
            || description.request_generation != identity.request_generation
            || description.parent
                != (infrastructure::WorkloadParentDescription::Request {
                    id: identity.parent.request_id,
                    generation: identity.parent.request_generation,
                })
        {
            return Err(CausalWorkloadError::ParentMismatch);
        }
        Ok(identity)
    }

    fn validate_causal_domain_workload_close(
        &self,
        session: &CausalDomainWorkloadSession,
    ) -> Result<CausalDomainWorkloadIdentity, CausalWorkloadError> {
        let identity = session.identity;
        if identity.parent.registry_instance != self.instance_id {
            return Err(CausalWorkloadError::ForeignRegistry);
        }
        self.validate_causal_workload_close_binding(identity.parent)?;
        let scope = self
            .scopes
            .get(&identity.parent.scope)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownScope))?;
        let binding = scope
            .domains
            .get(&identity.domain)
            .ok_or(CausalWorkloadError::Registry(RegistryError::UnknownDomain))?;
        if binding.binding_epoch < identity.binding_epoch {
            return Err(CausalWorkloadError::StaleDomain);
        }
        let description = self
            .infrastructure
            .describe_closable_workload(&session.context)
            .map_err(CausalWorkloadError::Infrastructure)?;
        if description.registry_instance != identity.parent.registry_instance
            || description.scope != identity.parent.scope
            || description.authority_epoch != identity.parent.authority_epoch
            || description.root_effect != identity.parent.root_effect
            || description.domain != identity.domain
            || description.binding_epoch != identity.binding_epoch
            || description.request_id != identity.request_id
            || description.request_generation != identity.request_generation
            || description.parent
                != (infrastructure::WorkloadParentDescription::Request {
                    id: identity.parent.request_id,
                    generation: identity.parent.request_generation,
                })
        {
            return Err(CausalWorkloadError::ParentMismatch);
        }
        Ok(identity)
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn close_causal_domain_workload(
        &mut self,
        session: CausalDomainWorkloadSession,
    ) -> Result<CausalDomainWorkloadIdentity, CausalDomainWorkloadCloseFailure> {
        let identity = match self.validate_causal_domain_workload_close(&session) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(CausalDomainWorkloadCloseFailure { error, session });
            }
        };
        let intent = match self
            .infrastructure
            .prepare_historical_workload_close(&session.context)
        {
            Ok(intent) => intent,
            Err(error) => {
                return Err(CausalDomainWorkloadCloseFailure {
                    error: CausalWorkloadError::Infrastructure(error),
                    session,
                });
            }
        };
        self.infrastructure
            .apply_workload_close(intent, &session.context);
        Ok(identity)
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
    use super::runtime_service_task::{CausalServiceTaskDescriptor, CausalServiceTaskRole};
    use super::runtime_task::CausalVmIdentity;
    use super::{
        CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest, DomainConfig,
        DomainRecoveryAbortReason, OperationClass, PublicationMode, RegisterRequest,
        ScopeClosureProgress, ScopeConfig, SyscallDescriptor, TaskKey, TerminalRequest,
    };

    const SCOPE: ScopeKey = ScopeKey::new(0xca00, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0xca01, 1);
    const SERVICE: TaskKey = TaskKey::new(0xca02, 1);
    const DOMAIN: DomainKey = DomainKey::new(0xca);
    const TARGET_SERVICE: TaskKey = TaskKey::new(0xca03, 1);
    const REPLACEMENT: TaskKey = TaskKey::new(0xca04, 1);
    const TARGET_DOMAIN: DomainKey = DomainKey::new(0xcc);
    const CREDIT: CreditClass = CreditClass::new(0xca);

    const fn limits() -> CausalWorkloadLimits {
        CausalWorkloadLimits::new(8, 2, 8, 2, 2, 8, 4, 4, 4, 12, 12, 128)
    }

    const fn nested_limits() -> CausalWorkloadLimits {
        limits().with_workload_capacity(3)
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
        registry
            .add_domain(
                SCOPE,
                DomainConfig {
                    key: TARGET_DOMAIN,
                    binding_epoch: 5,
                    supervisor: TARGET_SERVICE,
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

    fn recovery_fixture(
        seed: u64,
    ) -> (
        EffectRegistry,
        CausalWorkloadSession,
        DomainRecoverySnapshot,
    ) {
        let (mut registry, root) = fixture();
        let request = registry
            .prepare_causal_workload_activation(root, seed, 1, nested_limits())
            .unwrap();
        let root_session = registry.activate_causal_workload(request).unwrap();
        let request = registry
            .prepare_causal_domain_workload(
                &root_session,
                TARGET_DOMAIN,
                seed.checked_add(1).unwrap(),
                1,
            )
            .unwrap();
        let child = registry
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap();
        let descriptor = CausalServiceTaskDescriptor::new(
            seed.checked_add(2).unwrap(),
            1,
            CausalServiceTaskRole::ActiveService,
            CausalVmIdentity::new(seed.checked_add(3).unwrap(), 1).unwrap(),
            seed.checked_add(4).unwrap(),
            1,
        )
        .unwrap();
        let admitted = registry
            .admit_causal_service_task(child, descriptor)
            .unwrap();
        let selector = admitted.selector();
        let reserved = registry
            .reserve_causal_service_fault(selector, admitted)
            .unwrap();
        let armed = registry
            .arm_causal_service_task(selector, reserved)
            .unwrap();
        let observation = infrastructure::FaultObservation {
            task: TARGET_SERVICE,
            vm_generation: 1,
            instruction_pointer: seed.checked_add(5).unwrap(),
            address: seed.checked_add(6).unwrap(),
            access: infrastructure::FaultAccess::Read,
            architecture_error: 0,
            evidence_digest: seed.checked_add(7).unwrap(),
        };
        let crash = registry
            .crash_causal_service_task(selector, armed, observation)
            .unwrap();
        crash.close(&mut registry).unwrap();
        let snapshot = registry
            .domain_recovery_snapshot(SCOPE, TARGET_DOMAIN, REPLACEMENT, 1)
            .unwrap();
        registry.check_invariants().unwrap();
        (registry, root_session, snapshot)
    }

    macro_rules! assert_recovery_activation_failure {
        ($registry:expr, $parent:expr, $request:expr, $error:expr) => {{
            let request = $request;
            let expected = __cser_alloc::format!("{request:?}");
            let before = $registry.failure_atomic_projection();
            let failure = $registry
                .activate_causal_recovery_domain_workload($parent, request)
                .unwrap_err();
            __cser_core::assert_eq!(failure.error(), &$error);
            let request = failure.into_input();
            __cser_core::assert_eq!(__cser_alloc::format!("{request:?}"), expected);
            __cser_core::assert_eq!($registry.failure_atomic_projection(), before);
            request
        }};
    }

    fn advance_target_epoch_for_test(registry: &mut EffectRegistry) {
        let scope = registry.scopes.get_mut(&SCOPE).unwrap();
        scope.revision = scope.revision.checked_add(1).unwrap();
        let binding = scope.domains.get_mut(&TARGET_DOMAIN).unwrap();
        binding.binding_epoch = binding.binding_epoch.checked_add(1).unwrap();
        binding.revision = binding.revision.checked_add(1).unwrap();
        registry.infrastructure.corrupt_domain_epoch_for_test(
            SCOPE,
            TARGET_DOMAIN,
            binding.binding_epoch,
        );
        registry.check_invariants().unwrap();
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

    // A child admission captures its target epoch from the Registry, becomes
    // an exact workload child in the infrastructure ledger, and blocks the
    // parent root until the child is closed.
    {
        let (mut nested, nested_root) = fixture();
        let request = nested
            .prepare_causal_workload_activation(nested_root, 0xcb00, 1, nested_limits())
            .unwrap();
        let root_session = nested.activate_causal_workload(request).unwrap();
        let request = nested
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb01, 1)
            .unwrap();
        __cser_core::assert_eq!(request.binding_epoch, 5);
        let child = nested
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap();
        let child_identity = nested
            .verify_causal_domain_workload_session(&child)
            .unwrap();
        __cser_core::assert_eq!(child_identity.parent(), root_session.identity());
        __cser_core::assert_eq!(child_identity.domain(), TARGET_DOMAIN);
        __cser_core::assert_eq!(child_identity.binding_epoch(), 5);
        __cser_core::assert_eq!(child_identity.request_id(), 0xcb01);
        __cser_core::assert_eq!(child_identity.request_generation(), 1);

        let before = nested.failure_atomic_projection();
        let failure = nested.close_causal_workload(root_session).unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &CausalWorkloadError::Infrastructure(
                infrastructure::InfrastructureError::ClosureBlocked {
                    kind: infrastructure::InfrastructureKind::Workload,
                    live: 1,
                }
            )
        );
        __cser_core::assert_eq!(nested.failure_atomic_projection(), before);
        let root_session = failure.into_session();
        __cser_core::assert_eq!(
            nested.close_causal_domain_workload(child),
            Ok(child_identity)
        );
        __cser_core::assert_eq!(
            nested.close_causal_workload(root_session),
            Ok(child_identity.parent())
        );
        nested.check_invariants().unwrap();
    }

    // Domain and parent coordinates are repeated at activation so a prepared
    // request cannot be moved to a different domain or root. Every rejection
    // returns the exact linear request and leaves both ledgers unchanged.
    {
        let (mut substituted, substituted_root) = fixture();
        let request = substituted
            .prepare_causal_workload_activation(substituted_root, 0xcb10, 1, nested_limits())
            .unwrap();
        let root_session = substituted.activate_causal_workload(request).unwrap();
        let request = substituted
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb11, 1)
            .unwrap();
        let expected = __cser_alloc::format!("{request:?}");
        let before = substituted.failure_atomic_projection();
        let failure = substituted
            .activate_causal_domain_workload(&root_session, DomainKey::new(0xcd), request)
            .unwrap_err();
        __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::DomainMismatch);
        let request = failure.into_input();
        __cser_core::assert_eq!(__cser_alloc::format!("{request:?}"), expected);
        __cser_core::assert_eq!(substituted.failure_atomic_projection(), before);

        let child = substituted
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap();
        substituted.close_causal_domain_workload(child).unwrap();

        let mut request = substituted
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb12, 1)
            .unwrap();
        request.parent.root_effect = EffectKey::new(0xcbff, 1);
        let expected = __cser_alloc::format!("{request:?}");
        let before = substituted.failure_atomic_projection();
        let failure = substituted
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap_err();
        __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ParentMismatch);
        __cser_core::assert_eq!(
            __cser_alloc::format!("{:?}", failure.into_input()),
            expected
        );
        __cser_core::assert_eq!(substituted.failure_atomic_projection(), before);
        substituted.close_causal_workload(root_session).unwrap();
        substituted.check_invariants().unwrap();
    }

    // A prepared request and parent from another Registry instance cannot be
    // confused with an otherwise coordinate-identical local root.
    {
        let (mut owner, owner_root) = fixture();
        let owner_request = owner
            .prepare_causal_workload_activation(owner_root, 0xcb20, 1, nested_limits())
            .unwrap();
        let owner_session = owner.activate_causal_workload(owner_request).unwrap();
        let foreign_request = owner
            .prepare_causal_domain_workload(&owner_session, TARGET_DOMAIN, 0xcb21, 1)
            .unwrap();
        let expected = __cser_alloc::format!("{foreign_request:?}");

        let (mut target, target_root) = fixture();
        let target_request = target
            .prepare_causal_workload_activation(target_root, 0xcb20, 1, nested_limits())
            .unwrap();
        let target_session = target.activate_causal_workload(target_request).unwrap();
        __cser_core::assert_eq!(
            target.prepare_causal_domain_workload(&owner_session, TARGET_DOMAIN, 0xcb22, 1,),
            Err(CausalWorkloadError::ForeignRegistry)
        );
        let before = target.failure_atomic_projection();
        let failure = target
            .activate_causal_domain_workload(&target_session, TARGET_DOMAIN, foreign_request)
            .unwrap_err();
        __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::ForeignRegistry);
        __cser_core::assert_eq!(
            __cser_alloc::format!("{:?}", failure.into_input()),
            expected
        );
        __cser_core::assert_eq!(target.failure_atomic_projection(), before);
        target.close_causal_workload(target_session).unwrap();
        owner.close_causal_workload(owner_session).unwrap();
    }

    // Duplicate identity, the conservative default workload quota, and nonce
    // exhaustion all fail before installing either a primary record or reverse
    // index entry.
    {
        let (mut duplicate, duplicate_root) = fixture();
        let request = duplicate
            .prepare_causal_workload_activation(duplicate_root, 0xcb30, 1, nested_limits())
            .unwrap();
        let root_session = duplicate.activate_causal_workload(request).unwrap();
        let request = duplicate
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb31, 1)
            .unwrap();
        let child = duplicate
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap();
        let replay = duplicate
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb31, 1)
            .unwrap();
        let before = duplicate.failure_atomic_projection();
        let failure = duplicate
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, replay)
            .unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &CausalWorkloadError::Infrastructure(infrastructure::InfrastructureError::ExactReplay)
        );
        __cser_core::assert_eq!(duplicate.failure_atomic_projection(), before);
        duplicate.close_causal_domain_workload(child).unwrap();
        duplicate.close_causal_workload(root_session).unwrap();

        let (mut quota, quota_root) = fixture();
        let request = quota
            .prepare_causal_workload_activation(quota_root, 0xcb32, 1, limits())
            .unwrap();
        let root_session = quota.activate_causal_workload(request).unwrap();
        let request = quota
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb33, 1)
            .unwrap();
        let before = quota.failure_atomic_projection();
        let failure = quota
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &CausalWorkloadError::Infrastructure(
                infrastructure::InfrastructureError::QuotaExceeded(
                    infrastructure::InfrastructureKind::Workload
                )
            )
        );
        __cser_core::assert_eq!(quota.failure_atomic_projection(), before);
        quota.close_causal_workload(root_session).unwrap();

        let (mut overflow, overflow_root) = fixture();
        let request = overflow
            .prepare_causal_workload_activation(overflow_root, 0xcb34, 1, nested_limits())
            .unwrap();
        let root_session = overflow.activate_causal_workload(request).unwrap();
        let request = overflow
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb35, 1)
            .unwrap();
        overflow
            .infrastructure
            .set_next_nonce_for_test(SCOPE, u64::MAX);
        let before = overflow.failure_atomic_projection();
        let failure = overflow
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &CausalWorkloadError::Infrastructure(
                infrastructure::InfrastructureError::CounterOverflow
            )
        );
        __cser_core::assert_eq!(overflow.failure_atomic_projection(), before);
        overflow.close_causal_workload(root_session).unwrap();
    }

    // A target epoch advance fences ordinary verification and every new child
    // admission. The exact historical session remains valid only for cleanup;
    // closing it decrements the parent and allows the root to close.
    {
        let (mut historical, historical_root) = fixture();
        let request = historical
            .prepare_causal_workload_activation(historical_root, 0xcb40, 1, nested_limits())
            .unwrap();
        let root_session = historical.activate_causal_workload(request).unwrap();
        let request = historical
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb41, 1)
            .unwrap();
        let child = historical
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap();
        let child_identity = child.identity();
        advance_target_epoch_for_test(&mut historical);
        __cser_core::assert_eq!(
            historical.verify_causal_domain_workload_session(&child),
            Err(CausalWorkloadError::StaleDomain)
        );
        let before = historical.failure_atomic_projection();
        __cser_core::assert_eq!(
            historical.infrastructure.admit_task(
                &child.context,
                infrastructure::TaskWorkDescriptor {
                    work_id: 0xcb42,
                    generation: 1,
                    task: TaskKey::new(0xcb43, 1),
                    role: infrastructure::TaskWorkRole::GuestSyscallWork,
                    vm: Some(infrastructure::VmAuthorityKey::new(0xcb44, 1).unwrap()),
                },
            ),
            Err(infrastructure::InfrastructureError::StaleBinding)
        );
        __cser_core::assert_eq!(
            historical
                .infrastructure
                .open_child_workload(&child.context, TARGET_DOMAIN, 0xcb45, 1,),
            Err(infrastructure::InfrastructureError::StaleBinding)
        );
        __cser_core::assert_eq!(historical.failure_atomic_projection(), before);
        __cser_core::assert_eq!(
            historical.close_causal_domain_workload(child),
            Ok(child_identity)
        );
        __cser_core::assert_eq!(
            historical.close_causal_workload(root_session),
            Ok(child_identity.parent())
        );
        historical.check_invariants().unwrap();

        let (mut stale, stale_root) = fixture();
        let request = stale
            .prepare_causal_workload_activation(stale_root, 0xcb46, 1, nested_limits())
            .unwrap();
        let root_session = stale.activate_causal_workload(request).unwrap();
        let request = stale
            .prepare_causal_domain_workload(&root_session, TARGET_DOMAIN, 0xcb47, 1)
            .unwrap();
        let expected = __cser_alloc::format!("{request:?}");
        advance_target_epoch_for_test(&mut stale);
        let before = stale.failure_atomic_projection();
        let failure = stale
            .activate_causal_domain_workload(&root_session, TARGET_DOMAIN, request)
            .unwrap_err();
        __cser_core::assert_eq!(failure.error(), &CausalWorkloadError::StaleDomain);
        __cser_core::assert_eq!(
            __cser_alloc::format!("{:?}", failure.into_input()),
            expected
        );
        __cser_core::assert_eq!(stale.failure_atomic_projection(), before);
        stale.close_causal_workload(root_session).unwrap();
    }

    // A manager can mint a replacement child only from one exact live recovery
    // snapshot. The replacement task identity comes from its private
    // provenance, survives ready/rebind, and cannot be changed by the portable
    // descriptor.
    {
        let (mut recovery, root_session, snapshot) = recovery_fixture(0xcc00);
        let fence = recovery
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        __cser_core::assert_eq!(fence.scope(), SCOPE);
        __cser_core::assert_eq!(fence.domain(), TARGET_DOMAIN);
        __cser_core::assert_eq!(fence.replacement(), REPLACEMENT);
        __cser_core::assert_eq!(fence.attempt(), 1);
        __cser_core::assert_eq!(fence.binding_epoch(), snapshot.binding_epoch);
        __cser_core::assert_eq!(fence.snapshot_digest(), snapshot.digest());

        let mut substituted_fence = fence;
        substituted_fence.replacement = TaskKey::new(0xcc08, 1);
        let before = recovery.failure_atomic_projection();
        let failure = recovery
            .prepare_causal_recovery_domain_workload(&root_session, substituted_fence, 0xcc09, 1)
            .unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &CausalWorkloadError::RecoverySnapshotMismatch
        );
        __cser_core::assert_eq!(failure.into_input(), substituted_fence);
        __cser_core::assert_eq!(recovery.failure_atomic_projection(), before);

        let request = recovery
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcc10, 1)
            .unwrap();
        let duplicate_request = recovery
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcc18, 1)
            .unwrap();
        __cser_core::assert_eq!(request.fence(), fence);
        let child = recovery
            .activate_causal_recovery_domain_workload(&root_session, request)
            .unwrap();
        let _ = assert_recovery_activation_failure!(
            recovery,
            &root_session,
            duplicate_request,
            CausalWorkloadError::StaleScope
        );
        __cser_core::assert_eq!(
            child.provenance(),
            CausalDomainWorkloadProvenance::RecoveryReplacement {
                replacement: REPLACEMENT,
                attempt: 1,
                snapshot_digest: snapshot.digest(),
            }
        );

        let active_descriptor = CausalServiceTaskDescriptor::new(
            0xcc11,
            1,
            CausalServiceTaskRole::ActiveService,
            CausalVmIdentity::new(0xcc12, 1).unwrap(),
            0xcc13,
            1,
        )
        .unwrap();
        let expected = __cser_alloc::format!("{child:?}");
        let before = recovery.failure_atomic_projection();
        let failure = recovery
            .admit_causal_service_task(child, active_descriptor)
            .unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            &super::runtime_service_task::CausalServiceTaskError::ProvenanceMismatch
        );
        let child = failure.into_session();
        __cser_core::assert_eq!(__cser_alloc::format!("{child:?}"), expected);
        __cser_core::assert_eq!(recovery.failure_atomic_projection(), before);

        let replacement_descriptor = CausalServiceTaskDescriptor::new(
            0xcc14,
            1,
            CausalServiceTaskRole::ReplacementRecovery,
            CausalVmIdentity::new(0xcc15, 1).unwrap(),
            0xcc16,
            1,
        )
        .unwrap();
        let admitted = recovery
            .admit_causal_service_task(child, replacement_descriptor)
            .unwrap();
        let selector = admitted.selector();
        __cser_core::assert_eq!(selector.task(), REPLACEMENT);
        let reserved = recovery
            .reserve_causal_service_fault(selector, admitted)
            .unwrap();
        let armed = recovery
            .arm_causal_service_task(selector, reserved)
            .unwrap();
        recovery
            .domain_ready(SCOPE, TARGET_DOMAIN, REPLACEMENT, &snapshot)
            .unwrap();
        recovery
            .rebind_domain(SCOPE, TARGET_DOMAIN, REPLACEMENT)
            .unwrap();
        let completed = recovery
            .finish_causal_service_task_without_fault(selector, armed, 0xcc17)
            .unwrap();
        completed.close(&mut recovery).unwrap();
        recovery.check_invariants().unwrap();
    }

    // Every forged fence coordinate is rejected before append and the exact
    // non-Copy request is returned unchanged.
    {
        let (mut substituted, root_session, snapshot) = recovery_fixture(0xcd00);
        let fence = substituted
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd10, 1)
            .unwrap();
        request.fence.parent.request_id = request.fence.parent.request_id.checked_add(1).unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::ParentMismatch
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd11, 1)
            .unwrap();
        request.fence.domain = DOMAIN;
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::StaleDomain
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd12, 1)
            .unwrap();
        request.fence.replacement = TaskKey::new(0xcdfe, 1);
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::RecoverySnapshotMismatch
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd13, 1)
            .unwrap();
        request.fence.attempt = 2;
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::RecoverySnapshotMismatch
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd14, 1)
            .unwrap();
        request.fence.snapshot_digest[0] ^= 1;
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::RecoverySnapshotMismatch
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd15, 1)
            .unwrap();
        request.fence.binding_epoch = request.fence.binding_epoch.checked_add(1).unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::StaleDomain
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd16, 1)
            .unwrap();
        request.fence.root_revision = request.fence.root_revision.checked_add(1).unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::StaleScope
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd17, 1)
            .unwrap();
        request.fence.domain_revision = request.fence.domain_revision.checked_add(1).unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::StaleDomain
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd18, 1)
            .unwrap();
        request.fence.infrastructure_scope_revision = request
            .fence
            .infrastructure_scope_revision
            .checked_add(1)
            .unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::StaleScope
        );

        let mut request = substituted
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcd19, 1)
            .unwrap();
        request.fence.registry_instance = request.fence.registry_instance.checked_add(1).unwrap();
        let _ = assert_recovery_activation_failure!(
            substituted,
            &root_session,
            request,
            CausalWorkloadError::ForeignRegistry
        );
        substituted.check_invariants().unwrap();
    }

    // An authentic request cannot move between otherwise coordinate-identical
    // Registry instances.
    {
        let (owner, owner_root, owner_snapshot) = recovery_fixture(0xce00);
        let owner_fence = owner
            .prepare_causal_recovery_admission_fence(&owner_root, &owner_snapshot)
            .unwrap();
        let foreign_request = owner
            .prepare_causal_recovery_domain_workload(&owner_root, owner_fence, 0xce10, 1)
            .unwrap();
        let (mut target, target_root, _) = recovery_fixture(0xce20);
        let _ = assert_recovery_activation_failure!(
            target,
            &target_root,
            foreign_request,
            CausalWorkloadError::ForeignRegistry
        );
        target.check_invariants().unwrap();
        owner.check_invariants().unwrap();
    }

    // State changes after prepare fence the request without adding a workload:
    // aborted/replaced snapshots, root/domain/infrastructure revision changes,
    // rebind, and permanent quarantine are all independently covered.
    {
        let (mut stale, root_session, snapshot) = recovery_fixture(0xcf00);
        let fence = stale
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = stale
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xcf10, 1)
            .unwrap();
        stale
            .abort_domain_recovery_attempt(
                SCOPE,
                TARGET_DOMAIN,
                REPLACEMENT,
                1,
                &snapshot,
                DomainRecoveryAbortReason::ExitedBeforeReady,
            )
            .unwrap();
        stale
            .domain_recovery_snapshot(SCOPE, TARGET_DOMAIN, TaskKey::new(0xcf11, 1), 2)
            .unwrap();
        let _ = assert_recovery_activation_failure!(
            stale,
            &root_session,
            request,
            CausalWorkloadError::RecoverySnapshotMismatch
        );
    }

    {
        let (mut changed_root, root_session, snapshot) = recovery_fixture(0xd000);
        let fence = changed_root
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = changed_root
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xd010, 1)
            .unwrap();
        let scope = changed_root.scopes.get_mut(&SCOPE).unwrap();
        scope.revision = scope.revision.checked_add(1).unwrap();
        scope.invalidate_recovery_readiness();
        let _ = assert_recovery_activation_failure!(
            changed_root,
            &root_session,
            request,
            CausalWorkloadError::StaleScope
        );
        changed_root.check_invariants().unwrap();
    }

    {
        let (mut changed_domain, root_session, snapshot) = recovery_fixture(0xd100);
        let fence = changed_domain
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = changed_domain
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xd110, 1)
            .unwrap();
        let binding = changed_domain
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .domains
            .get_mut(&TARGET_DOMAIN)
            .unwrap();
        binding.revision = binding.revision.checked_add(1).unwrap();
        binding.recovery.as_mut().unwrap().ready = None;
        let _ = assert_recovery_activation_failure!(
            changed_domain,
            &root_session,
            request,
            CausalWorkloadError::StaleDomain
        );
        changed_domain.check_invariants().unwrap();
    }

    {
        let (mut changed_infrastructure, root_session, snapshot) = recovery_fixture(0xd200);
        let fence = changed_infrastructure
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = changed_infrastructure
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xd210, 1)
            .unwrap();
        let _unrelated = changed_infrastructure
            .infrastructure
            .open_child_workload(&root_session.context, DomainKey::LEGACY, 0xd211, 1)
            .unwrap();
        let _ = assert_recovery_activation_failure!(
            changed_infrastructure,
            &root_session,
            request,
            CausalWorkloadError::StaleScope
        );
        changed_infrastructure.check_invariants().unwrap();
    }

    {
        let (mut rebound, root_session, snapshot) = recovery_fixture(0xd300);
        let fence = rebound
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = rebound
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xd310, 1)
            .unwrap();
        rebound
            .domain_ready(SCOPE, TARGET_DOMAIN, REPLACEMENT, &snapshot)
            .unwrap();
        rebound
            .rebind_domain(SCOPE, TARGET_DOMAIN, REPLACEMENT)
            .unwrap();
        let _ = assert_recovery_activation_failure!(
            rebound,
            &root_session,
            request,
            CausalWorkloadError::RecoveryUnavailable
        );
        rebound.check_invariants().unwrap();
    }

    {
        let (mut quarantined, root_session, snapshot) = recovery_fixture(0xd400);
        let fence = quarantined
            .prepare_causal_recovery_admission_fence(&root_session, &snapshot)
            .unwrap();
        let request = quarantined
            .prepare_causal_recovery_domain_workload(&root_session, fence, 0xd410, 1)
            .unwrap();
        __cser_core::assert!(matches!(
            quarantined.isolate_domain_authority(
                SCOPE,
                TARGET_DOMAIN,
                REPLACEMENT,
                Some(snapshot.binding_epoch),
            ),
            super::DomainIsolationOutcome::Isolated(_)
        ));
        let _ = assert_recovery_activation_failure!(
            quarantined,
            &root_session,
            request,
            CausalWorkloadError::RecoveryUnavailable
        );
        quarantined.check_invariants().unwrap();
    }

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
