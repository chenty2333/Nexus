// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::vec::Vec;

#[cfg(test)]
use super::ClosureRecord;
use super::{
    DomainKey, EffectKey, InfrastructureError, InfrastructureEventKind, InfrastructureKind,
    InfrastructureLimits, InfrastructureRootBinding, InfrastructureScopeInstallPlan,
    InfrastructureScopeLink, InfrastructureState, LedgerMode, ParentStamp, RequestKey,
    ReverseIndexRecord, ReverseParent, RootStamp, ScopeInfrastructure, ScopeKey, WorkloadContext,
    WorkloadPhase, WorkloadRecord, WorkloadRequestPresentation, WorkloadRootPresentation,
    check_scope_invariants, checked_add, checked_sub, first_live_child_kind, preview_nonce,
    preview_revision, require_vacancy, rewrite_scope_stamps, validate_active_admission,
    validate_context, validate_root_presentation, workload_bearer,
};

impl InfrastructureState {
    pub(in super::super) fn new(registry_instance: u64) -> Self {
        Self {
            registry_instance,
            mode: LedgerMode::Authoritative,
            scopes: Vec::new(),
        }
    }

    pub(in super::super) fn try_private_candidate(&self) -> Result<Self, InfrastructureError> {
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(self.scopes.len())
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        for (key, scope) in &self.scopes {
            scopes.push((*key, scope.try_candidate_clone()?));
        }
        Ok(Self {
            registry_instance: self.registry_instance,
            mode: LedgerMode::NonAuthoritativeCandidate,
            scopes,
        })
    }

    /// Compatibility for the existing module-private full Registry clone.
    /// This preserves the authority mode so equality remains authority-aware;
    /// unlike exact-scope candidates, it must never cross the module boundary
    /// or be used by the new combined transaction path.
    pub(in super::super) fn private_full_clone(&self) -> Self {
        Self {
            registry_instance: self.registry_instance,
            mode: self.mode,
            scopes: self.scopes.clone(),
        }
    }

    pub(in super::super) fn try_scope_candidate(
        &self,
        scope: ScopeKey,
    ) -> Result<Self, InfrastructureError> {
        let mut scopes = Vec::new();
        if let Some((key, record)) = self
            .scopes
            .iter()
            .find(|(candidate, _)| *candidate == scope)
        {
            scopes
                .try_reserve_exact(1)
                .map_err(|_| InfrastructureError::AllocationFailed)?;
            scopes.push((*key, record.try_candidate_clone()?));
        }
        Ok(Self {
            registry_instance: self.registry_instance,
            mode: LedgerMode::NonAuthoritativeCandidate,
            scopes,
        })
    }

    pub(in super::super) fn rewrite_private_registry_instance(&mut self, registry_instance: u64) {
        __cser_core::debug_assert_ne!(registry_instance, 0);
        self.registry_instance = registry_instance;
        for (_, scope) in &mut self.scopes {
            scope.root.registry_instance = registry_instance;
            rewrite_scope_stamps(scope, registry_instance);
        }
    }

    pub(in super::super) fn root_binding(
        &self,
        scope: ScopeKey,
    ) -> Result<InfrastructureRootBinding, InfrastructureError> {
        let record = self.scope(scope)?;
        Ok(InfrastructureRootBinding {
            scope,
            authority_epoch: record.root.authority_epoch,
            root_effect: record.root.root_effect,
            revision: record.revision,
        })
    }

    pub(in super::super) fn root_bindings(
        &self,
    ) -> impl Iterator<Item = InfrastructureRootBinding> + '_ {
        self.scopes
            .iter()
            .map(|(scope, record)| InfrastructureRootBinding {
                scope: *scope,
                authority_epoch: record.root.authority_epoch,
                root_effect: record.root.root_effect,
                revision: record.revision,
            })
    }

    pub(in super::super) fn scope_links(
        &self,
    ) -> impl Iterator<Item = InfrastructureScopeLink<'_>> + '_ {
        self.scopes
            .iter()
            .map(|(scope, record)| InfrastructureScopeLink {
                scope: *scope,
                authority_epoch: record.root.authority_epoch,
                root_effect: record.root.root_effect,
                active: record.active,
                closure_finished: record.closure.map(|closure| closure.finished),
                domains: &record.domains,
            })
    }

    /// Bounded root/sequence shape shared by the full checker and exact-scope
    /// candidate gate.
    pub(in super::super) fn check_root_shape(&self) -> Result<(), InfrastructureError> {
        if self.registry_instance == 0 {
            return Err(InfrastructureError::Invariant(
                "zero infrastructure Registry instance",
            ));
        }
        for (index, (scope_key, scope)) in self.scopes.iter().enumerate() {
            if scope.root.registry_instance != self.registry_instance
                || scope.root.scope != *scope_key
                || scope_key.generation() == 0
                || scope.root.authority_epoch == 0
                || scope.root.root_effect.generation() == 0
            {
                return Err(InfrastructureError::Invariant(
                    "infrastructure root identity mismatch",
                ));
            }
            if self.scopes[..index]
                .iter()
                .any(|(candidate, _)| candidate == scope_key)
            {
                return Err(InfrastructureError::Invariant(
                    "duplicate infrastructure scope",
                ));
            }
            if scope.next_nonce == 0
                || scope.next_publication_sequence == 0
                || scope.next_closure_sequence == 0
            {
                return Err(InfrastructureError::Invariant(
                    "zero infrastructure sequence",
                ));
            }
            for (domain_index, (domain, epoch)) in scope.domains.iter().enumerate() {
                if *epoch == 0
                    || scope.domains[..domain_index]
                        .iter()
                        .any(|(candidate, _)| candidate == domain)
                {
                    return Err(InfrastructureError::Invariant(
                        "invalid infrastructure domain binding",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Reconstructs every derived infrastructure projection from primary
    /// records.  Diagnostic events are intentionally not read: the ring is
    /// lossy evidence, never authority.
    pub(in super::super) fn check_invariants(&self) -> Result<(), InfrastructureError> {
        self.check_root_shape()?;
        for (_, scope) in &self.scopes {
            check_scope_invariants(scope)?;
        }
        Ok(())
    }

    /// Performs every fallible/stale check for an exact-scope install and
    /// moves the replacement into an opaque plan.  The live ledger remains
    /// authoritative and unchanged on every error.
    pub(in super::super) fn prepare_exact_scope_install(
        &self,
        scope: ScopeKey,
        base: InfrastructureRootBinding,
        candidate: &mut Self,
    ) -> Result<InfrastructureScopeInstallPlan, InfrastructureError> {
        self.require_authoritative()?;
        if candidate.mode != LedgerMode::NonAuthoritativeCandidate
            || candidate.registry_instance != self.registry_instance
            || base.scope != scope
        {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        self.check_root_shape()?;
        candidate.check_root_shape()?;

        let slot = self
            .scopes
            .iter()
            .position(|(candidate, _)| *candidate == scope)
            .ok_or(InfrastructureError::NotEnabled)?;
        let live = &self.scopes[slot].1;
        if live.root.authority_epoch != base.authority_epoch
            || live.root.root_effect != base.root_effect
            || live.revision != base.revision
        {
            return Err(InfrastructureError::StaleAuthority);
        }
        if candidate.scopes.len() != 1 || candidate.scopes[0].0 != scope {
            return Err(InfrastructureError::ForeignScope);
        }
        let replacement = &candidate.scopes[0].1;
        if replacement.root != live.root || replacement.revision < base.revision {
            return Err(InfrastructureError::StaleAuthority);
        }

        // No allocation or validation remains after this move.  The
        // candidate never becomes authoritative; only its one record is
        // transferred into the still-authoritative live ledger.
        let (_, replacement) = candidate
            .scopes
            .pop()
            .ok_or(InfrastructureError::ForeignScope)?;
        Ok(InfrastructureScopeInstallPlan { slot, replacement })
    }

    pub(in super::super) fn install_exact_scope(&mut self, plan: InfrastructureScopeInstallPlan) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::Authoritative);
        __cser_core::debug_assert!(plan.slot < self.scopes.len());
        self.scopes[plan.slot].1 = plan.replacement;
    }

    pub(in super::super) fn advance_candidate_scope_revision(
        &mut self,
        scope: ScopeKey,
    ) -> Result<(), InfrastructureError> {
        if self.mode != LedgerMode::NonAuthoritativeCandidate || self.scopes.len() != 1 {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        let record = self.scope_mut(scope)?;
        record.revision = preview_revision(record)?;
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn corrupt_candidate_root_for_test(
        &mut self,
        scope: ScopeKey,
        root_effect: EffectKey,
    ) {
        __cser_core::assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.scope_mut(scope).unwrap().root.root_effect = root_effect;
    }

    #[cfg(test)]
    pub(in super::super) fn corrupt_candidate_sequence_for_test(&mut self, scope: ScopeKey) {
        __cser_core::assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.scope_mut(scope).unwrap().next_nonce = 0;
    }

    #[cfg(test)]
    pub(in super::super) fn advance_authoritative_scope_revision_for_test(
        &mut self,
        scope: ScopeKey,
    ) {
        __cser_core::assert_eq!(self.mode, LedgerMode::Authoritative);
        let record = self.scope_mut(scope).unwrap();
        record.revision = record.revision.checked_add(1).unwrap();
    }

    #[cfg(test)]
    pub(in super::super) fn corrupt_domain_epoch_for_test(
        &mut self,
        scope: ScopeKey,
        domain: DomainKey,
        epoch: u64,
    ) {
        *self
            .scope_mut(scope)
            .unwrap()
            .binding_epoch_mut(domain)
            .unwrap() = epoch;
    }

    #[cfg(test)]
    pub(in super::super) fn add_domain_for_test(
        &mut self,
        scope: ScopeKey,
        domain: DomainKey,
        epoch: u64,
    ) {
        self.scope_mut(scope).unwrap().domains.push((domain, epoch));
    }

    #[cfg(test)]
    pub(in super::super) fn set_closing_lifecycle_for_test(&mut self, scope: ScopeKey) {
        let record = self.scope_mut(scope).unwrap();
        record.active = false;
        record.closure = Some(ClosureRecord {
            sequence: 1,
            nonce: 1,
            finished: false,
        });
        record.next_nonce = record.next_nonce.max(2);
        record.next_closure_sequence = record.next_closure_sequence.max(2);
    }

    #[cfg(test)]
    pub(in super::super) fn set_revoked_lifecycle_for_test(&mut self, scope: ScopeKey) {
        self.set_closing_lifecycle_for_test(scope);
        self.scope_mut(scope)
            .unwrap()
            .closure
            .as_mut()
            .unwrap()
            .finished = true;
    }

    #[cfg(test)]
    pub(in super::super) fn is_authoritative_for_test(&self) -> bool {
        self.mode == LedgerMode::Authoritative
    }

    pub(in super::super) fn enable(
        &mut self,
        scope: ScopeKey,
        authority_epoch: u64,
        root_effect: EffectKey,
        limits: InfrastructureLimits,
        domains: &[(DomainKey, u64)],
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        if authority_epoch == 0 || root_effect.generation() == 0 {
            return Err(InfrastructureError::InvalidGeneration);
        }
        if self.scopes.iter().any(|(candidate, _)| *candidate == scope) {
            return Err(InfrastructureError::AlreadyEnabled);
        }
        let record = ScopeInfrastructure::try_new(
            RootStamp {
                registry_instance: self.registry_instance,
                scope,
                authority_epoch,
                root_effect,
            },
            limits,
            domains,
        )?;
        self.scopes
            .try_reserve(1)
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        self.scopes.push((scope, record));
        Ok(())
    }

    pub(in super::super) fn is_enabled(&self, scope: ScopeKey) -> bool {
        self.scopes.iter().any(|(candidate, _)| *candidate == scope)
    }

    pub(super) fn require_authoritative(&self) -> Result<(), InfrastructureError> {
        if self.mode == LedgerMode::Authoritative {
            Ok(())
        } else {
            Err(InfrastructureError::CandidateHasNoAuthority)
        }
    }

    pub(super) fn scope(
        &self,
        scope: ScopeKey,
    ) -> Result<&ScopeInfrastructure, InfrastructureError> {
        self.scopes
            .iter()
            .find_map(|(candidate, record)| (*candidate == scope).then_some(record))
            .ok_or(InfrastructureError::NotEnabled)
    }

    pub(super) fn scope_mut(
        &mut self,
        scope: ScopeKey,
    ) -> Result<&mut ScopeInfrastructure, InfrastructureError> {
        self.scopes
            .iter_mut()
            .find_map(|(candidate, record)| (*candidate == scope).then_some(record))
            .ok_or(InfrastructureError::NotEnabled)
    }

    pub(in super::super) fn open_workload(
        &mut self,
        root: WorkloadRootPresentation,
        request: WorkloadRequestPresentation,
    ) -> Result<WorkloadContext, InfrastructureError> {
        self.require_authoritative()?;
        let request_key = RequestKey::new(request.request_id, request.request_generation)?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(root.scope)?;
        validate_root_presentation(
            scope,
            registry_instance,
            root.authority_epoch,
            root.root_effect,
        )?;
        validate_active_admission(scope)?;
        if scope.binding_epoch(request.domain)? != request.binding_epoch {
            return Err(InfrastructureError::StaleBinding);
        }
        if let Some(existing) = scope.workloads.get(request_key.id) {
            return if existing.request == request_key
                && existing.root_effect == root.root_effect
                && existing.domain == request.domain
            {
                Err(InfrastructureError::ExactReplay)
            } else if existing.request.generation > request_key.generation {
                Err(InfrastructureError::StaleGeneration)
            } else {
                Err(InfrastructureError::IdentityConflict)
            };
        }
        require_vacancy(
            &scope.workloads,
            request_key.id,
            InfrastructureKind::Workload,
        )?;
        require_vacancy(
            &scope.reverse_indexes,
            scope.next_nonce,
            InfrastructureKind::Workload,
        )?;
        let (nonce, next_nonce) = preview_nonce(scope)?;
        let next_revision = preview_revision(scope)?;
        let next_workloads = checked_add(scope.live.workloads, 1)?;
        let record = WorkloadRecord {
            request: request_key,
            root_effect: root.root_effect,
            parent: ParentStamp::RootEffect(root.root_effect),
            domain: request.domain,
            admission_binding_epoch: request.binding_epoch,
            current_binding_epoch: request.binding_epoch,
            nonce,
            bearer_generation: 1,
            phase: WorkloadPhase::Open,
            live_children: 0,
            closure_sequence: None,
        };
        let index = ReverseIndexRecord {
            slot: nonce,
            kind: InfrastructureKind::Workload,
            root_effect: root.root_effect,
            parent: ReverseParent::RootEffect(root.root_effect),
            task: None,
            domain: request.domain,
            binding_epoch: request.binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: None,
            actor_slot: None,
            actor_generation: None,
            retry_generation: request.request_generation,
        };
        scope
            .workloads
            .install(record, InfrastructureKind::Workload)?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Workload)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.workloads = next_workloads;
        scope.events.push(
            InfrastructureEventKind::WorkloadOpened,
            request_key.id,
            request_key.generation,
        );
        workload_bearer(scope, request_key.id)
    }

    pub(in super::super) fn adopt_workload_after_fence(
        &mut self,
        root: WorkloadRootPresentation,
        request: WorkloadRequestPresentation,
    ) -> Result<WorkloadContext, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(root.scope)?;
        validate_root_presentation(
            scope,
            registry_instance,
            root.authority_epoch,
            root.root_effect,
        )?;
        if scope.binding_epoch(request.domain)? != request.binding_epoch {
            return Err(InfrastructureError::StaleBinding);
        }
        let request_key = RequestKey::new(request.request_id, request.request_generation)?;
        let existing = scope
            .workloads
            .get(request_key.id)
            .ok_or(InfrastructureError::UnknownWorkload)?;
        if existing.request != request_key {
            return Err(InfrastructureError::StaleGeneration);
        }
        if existing.phase != WorkloadPhase::Open
            || existing.domain != request.domain
            || existing.current_binding_epoch >= request.binding_epoch
        {
            return Err(InfrastructureError::InvalidState);
        }
        let next_bearer_generation = existing
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let next_revision = preview_revision(scope)?;
        let index_slot = existing.nonce;
        let record = scope.workloads.get_mut(request_key.id).unwrap();
        record.current_binding_epoch = request.binding_epoch;
        record.bearer_generation = next_bearer_generation;
        scope
            .reverse_indexes
            .get_mut(index_slot)
            .unwrap()
            .binding_epoch = request.binding_epoch;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::WorkloadAdopted,
            request_key.id,
            request_key.generation,
        );
        workload_bearer(scope, request_key.id)
    }

    pub(in super::super) fn close_workload(
        &mut self,
        context: &WorkloadContext,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope.workloads.get(context.workload.request.id).unwrap();
        if record.phase == WorkloadPhase::Closed {
            return Ok(());
        }
        if record.live_children != 0 {
            return Err(InfrastructureError::ClosureBlocked {
                kind: first_live_child_kind(scope, record.request)?,
                live: record.live_children,
            });
        }
        let next_revision = preview_revision(scope)?;
        let next_live = checked_sub(scope.live.workloads, 1)?;
        scope
            .workloads
            .get_mut(context.workload.request.id)
            .unwrap()
            .phase = WorkloadPhase::Closed;
        scope.live.workloads = next_live;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::WorkloadClosed,
            context.workload.request.id,
            context.workload.request.generation,
        );
        Ok(())
    }
}
