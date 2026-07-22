// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::vec::Vec;

#[cfg(test)]
use super::ClosureRecord;
use super::{
    CausalWorkloadBootstrapInstall, ChildWorkloadOpenPlan, ContinuationPhase, DeadlinePhase,
    DelayedCommandPhase, DeviceCreditOwnership, DevicePhase, DomainFencePlan, DomainKey, EffectKey,
    FaultPhase, InfrastructureClosureFinishPlan, InfrastructureClosureProgress,
    InfrastructureClosureReceipt, InfrastructureClosureSelection, InfrastructureClosureStartPlan,
    InfrastructureError, InfrastructureEventKind, InfrastructureKind, InfrastructureLimits,
    InfrastructureLiveCounts, InfrastructureRootBinding, InfrastructureScopeInstallPlan,
    InfrastructureScopeLink, InfrastructureState, LedgerMode, ParentStamp, PreparedWorkloadMint,
    ReplyPhase, RequestKey, ReverseIndexRecord, ReverseParent, RootStamp, ScopeInfrastructure,
    ScopeKey, ServiceRequestPhase, TaskAnchorPhase, TaskPhase, WorkloadCloseIntent,
    WorkloadContext, WorkloadContextDescription, WorkloadParentDescription, WorkloadPhase,
    WorkloadRecord, WorkloadRequestPresentation, WorkloadRootPresentation, check_scope_invariants,
    checked_add, checked_sub, first_live_child_kind, mint_workload_context, prepare_workload_mint,
    preview_nonce, preview_revision, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, rewrite_scope_stamps, validate_active_admission, validate_context,
    validate_recovery_context, validate_root_presentation, validate_workload_mint, workload_bearer,
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

    /// Converts a module-private full transaction candidate into the
    /// authoritative mode immediately before its containing Registry is
    /// installed. No state allocation or callback occurs in this final step.
    pub(in super::super) fn promote_full_candidate_for_install(
        &mut self,
    ) -> Result<(), InfrastructureError> {
        if self.mode != LedgerMode::NonAuthoritativeCandidate {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        self.mode = LedgerMode::Authoritative;
        Ok(())
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

    /// Prevalidates one outer-Registry supervisor crash against the exact
    /// infrastructure domain binding. The plan is opaque outside the parent
    /// Registry module so an adapter cannot advance infrastructure authority
    /// independently of the business recovery transition.
    pub(in super::super) fn prepare_domain_fence(
        &self,
        scope: ScopeKey,
        domain: DomainKey,
        previous: u64,
        next: u64,
    ) -> Result<DomainFencePlan, InfrastructureError> {
        self.require_authoritative()?;
        let record = self.scope(scope)?;
        validate_active_admission(record)?;
        if record.binding_epoch(domain)? != previous
            || next
                != previous
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
        {
            return Err(InfrastructureError::StaleBinding);
        }
        Ok(DomainFencePlan {
            scope,
            domain,
            previous,
            next,
            next_revision: preview_revision(record)?,
        })
    }

    /// Allocation-free installation of a prevalidated outer domain fence.
    pub(in super::super) fn apply_domain_fence(&mut self, plan: DomainFencePlan) {
        let record = self
            .scope_mut(plan.scope)
            .expect("prevalidated infrastructure scope remains present");
        let epoch = record
            .binding_epoch_mut(plan.domain)
            .expect("prevalidated infrastructure domain remains present");
        __cser_core::debug_assert_eq!(*epoch, plan.previous);
        *epoch = plan.next;
        record.revision = plan.next_revision;
        record.events.push(
            InfrastructureEventKind::DomainFenced,
            u64::from(plan.domain.value()),
            plan.next,
        );
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
    pub(in super::super) fn set_next_nonce_for_test(&mut self, scope: ScopeKey, nonce: u64) {
        __cser_core::assert_eq!(self.mode, LedgerMode::Authoritative);
        __cser_core::assert_ne!(nonce, 0);
        self.scope_mut(scope).unwrap().next_nonce = nonce;
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
        if record.closure.is_none() {
            record.active = false;
            record.closure = Some(ClosureRecord {
                sequence: 1,
                nonce: 1,
                finished: false,
                receipt: None,
            });
            record.next_nonce = record.next_nonce.max(2);
            record.next_closure_sequence = record.next_closure_sequence.max(2);
        }
    }

    #[cfg(test)]
    pub(in super::super) fn set_revoked_lifecycle_for_test(&mut self, scope: ScopeKey) {
        self.set_closing_lifecycle_for_test(scope);
        let registry_instance = self.registry_instance;
        let record = self.scope_mut(scope).unwrap();
        let closure = record.closure.as_mut().unwrap();
        closure.finished = true;
        closure.receipt = Some(InfrastructureClosureReceipt {
            registry_instance,
            scope,
            authority_epoch: record.root.authority_epoch,
            root_effect: record.root.root_effect,
            sequence: closure.sequence,
            nonce: closure.nonce,
            closed_revision: record.revision,
        });
    }

    #[cfg(test)]
    pub(in super::super) fn is_authoritative_for_test(&self) -> bool {
        self.mode == LedgerMode::Authoritative
    }

    #[cfg(test)]
    pub(in super::super) fn scope_state_eq_for_test(&self, other: &Self, scope: ScopeKey) -> bool {
        self.registry_instance == other.registry_instance
            && self.mode == other.mode
            && self.scope(scope).ok() == other.scope(scope).ok()
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

    /// Prevalidates the infrastructure half of a full-scope revoke.
    ///
    /// A private exact-scope candidate may stage this transition, but it does
    /// not gain authority by doing so: only the outer Registry can install its
    /// record. No bearer or selection leaves the Registry module.
    pub(in super::super) fn prepare_closure_start(
        &self,
        scope: ScopeKey,
        authority_epoch: u64,
    ) -> Result<InfrastructureClosureStartPlan, InfrastructureError> {
        if self.mode == LedgerMode::NonAuthoritativeCandidate
            && (self.scopes.len() != 1 || self.scopes[0].0 != scope)
        {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        let record = self.scope(scope)?;
        if record.root.authority_epoch != authority_epoch {
            return Err(InfrastructureError::StaleAuthority);
        }
        if !record.active || record.closure.is_some() {
            return Err(InfrastructureError::ClosureAlreadyStarted);
        }
        let sequence = record.next_closure_sequence;
        if sequence == 0 {
            return Err(InfrastructureError::Invariant(
                "zero infrastructure closure sequence",
            ));
        }
        let next_closure_sequence = sequence
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let (nonce, next_nonce) = preview_nonce(record)?;
        let next_revision = preview_revision(record)?;
        Ok(InfrastructureClosureStartPlan {
            selection: InfrastructureClosureSelection {
                registry_instance: self.registry_instance,
                scope,
                authority_epoch,
                sequence,
                nonce,
            },
            next_nonce,
            next_closure_sequence,
            next_revision,
        })
    }

    /// Allocation-free installation of a prevalidated closure start.
    pub(in super::super) fn apply_closure_start(
        &mut self,
        plan: InfrastructureClosureStartPlan,
    ) -> InfrastructureClosureSelection {
        let InfrastructureClosureStartPlan {
            selection,
            next_nonce,
            next_closure_sequence,
            next_revision,
        } = plan;
        let record = self
            .scope_mut(selection.scope)
            .expect("prevalidated infrastructure scope remains present");
        stamp_live_closure_cohort(record, selection.sequence);
        record.active = false;
        record.closure = Some(super::ClosureRecord {
            sequence: selection.sequence,
            nonce: selection.nonce,
            finished: false,
            receipt: None,
        });
        record.next_nonce = next_nonce;
        record.next_closure_sequence = next_closure_sequence;
        record.revision = next_revision;
        record.events.push(
            InfrastructureEventKind::ClosureStarted,
            selection.scope.id(),
            selection.scope.generation(),
        );
        selection
    }

    pub(in super::super) fn prepare_closure_finish(
        &self,
        selection: InfrastructureClosureSelection,
    ) -> Result<
        (
            InfrastructureClosureFinishPlan,
            InfrastructureClosureReceipt,
        ),
        InfrastructureError,
    > {
        self.prepare_closure_finish_inner(selection, None)
    }

    /// Prevalidates root finish against the exact workload close which the
    /// outer Registry will apply first under the same exclusive transaction.
    /// Neither transition is installed here.
    pub(in super::super) fn prepare_closure_finish_after_workload_close(
        &self,
        selection: InfrastructureClosureSelection,
        close: &WorkloadCloseIntent,
    ) -> Result<
        (
            InfrastructureClosureFinishPlan,
            InfrastructureClosureReceipt,
        ),
        InfrastructureError,
    > {
        self.prepare_closure_finish_inner(selection, Some(close))
    }

    fn prepare_closure_finish_inner(
        &self,
        selection: InfrastructureClosureSelection,
        projected_close: Option<&WorkloadCloseIntent>,
    ) -> Result<
        (
            InfrastructureClosureFinishPlan,
            InfrastructureClosureReceipt,
        ),
        InfrastructureError,
    > {
        if self.mode == LedgerMode::NonAuthoritativeCandidate
            && (self.scopes.len() != 1 || self.scopes[0].0 != selection.scope)
        {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        if selection.registry_instance != self.registry_instance {
            return Err(InfrastructureError::ForeignRegistry);
        }
        let record = self.scope(selection.scope)?;
        if record.root.authority_epoch != selection.authority_epoch {
            return Err(InfrastructureError::StaleAuthority);
        }
        let closure = record
            .closure
            .ok_or(InfrastructureError::ClosureNotStarted)?;
        if closure.sequence != selection.sequence || closure.nonce != selection.nonce {
            return Err(InfrastructureError::StaleClaim);
        }
        if closure.finished || closure.receipt.is_some() {
            return Err(InfrastructureError::InvalidState);
        }
        if has_retained_closure_owner(record) {
            return Err(InfrastructureError::ClosureRetained);
        }
        let (projected_live, closed_revision) = if let Some(close) = projected_close {
            self.validate_workload_close_intent(close, None)?;
            if close.mint.root.scope != selection.scope
                || close.mint.root.authority_epoch != selection.authority_epoch
                || close.mint.root.root_effect != record.root.root_effect
            {
                return Err(InfrastructureError::ForeignRootEffect);
            }
            let mut live = record.live;
            live.workloads = close.next_live_workloads;
            let revision = close
                .next_revision
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            (live, revision)
        } else {
            (record.live, preview_revision(record)?)
        };
        if projected_live != InfrastructureLiveCounts::default() {
            let (kind, live) = first_live_obligation_counts(projected_live).ok_or(
                InfrastructureError::Invariant("live counts lack a closure obligation"),
            )?;
            return Err(InfrastructureError::ClosureBlocked { kind, live });
        }
        let receipt = InfrastructureClosureReceipt {
            registry_instance: self.registry_instance,
            scope: selection.scope,
            authority_epoch: selection.authority_epoch,
            root_effect: record.root.root_effect,
            sequence: selection.sequence,
            nonce: selection.nonce,
            closed_revision,
        };
        Ok((
            InfrastructureClosureFinishPlan { selection, receipt },
            receipt,
        ))
    }

    /// Allocation-free installation of a prevalidated zero-live receipt.
    pub(in super::super) fn apply_closure_finish(
        &mut self,
        plan: InfrastructureClosureFinishPlan,
    ) -> InfrastructureClosureReceipt {
        let InfrastructureClosureFinishPlan { selection, receipt } = plan;
        let record = self
            .scope_mut(selection.scope)
            .expect("prevalidated infrastructure scope remains present");
        let closure = record
            .closure
            .as_mut()
            .expect("prevalidated infrastructure closure remains present");
        closure.finished = true;
        closure.receipt = Some(receipt);
        record.revision = receipt.closed_revision;
        record.events.push(
            InfrastructureEventKind::ClosureFinished,
            selection.scope.id(),
            selection.scope.generation(),
        );
        receipt
    }

    pub(in super::super) fn closure_progress(
        &self,
        scope: ScopeKey,
    ) -> Result<InfrastructureClosureProgress, InfrastructureError> {
        let record = self.scope(scope)?;
        let Some(closure) = record.closure else {
            return if record.active {
                Ok(InfrastructureClosureProgress::Active)
            } else {
                Err(InfrastructureError::Invariant(
                    "inactive infrastructure scope lacks closure",
                ))
            };
        };
        let selection = InfrastructureClosureSelection {
            registry_instance: self.registry_instance,
            scope,
            authority_epoch: record.root.authority_epoch,
            sequence: closure.sequence,
            nonce: closure.nonce,
        };
        if closure.finished {
            return closure
                .receipt
                .map(InfrastructureClosureProgress::Closed)
                .ok_or(InfrastructureError::Invariant(
                    "finished infrastructure closure lacks receipt",
                ));
        }
        if closure.receipt.is_some() {
            return Err(InfrastructureError::Invariant(
                "unfinished infrastructure closure retains receipt",
            ));
        }
        Ok(if has_retained_closure_owner(record) {
            InfrastructureClosureProgress::Retained(selection)
        } else {
            InfrastructureClosureProgress::Closing(selection)
        })
    }

    pub(in super::super) fn verify_closure_receipt(
        &self,
        receipt: InfrastructureClosureReceipt,
    ) -> Result<(), InfrastructureError> {
        if receipt.registry_instance != self.registry_instance {
            return Err(InfrastructureError::ForeignRegistry);
        }
        let record = self.scope(receipt.scope)?;
        if record.root.authority_epoch != receipt.authority_epoch
            || record.root.root_effect != receipt.root_effect
            || record.revision != receipt.closed_revision
            || record
                .closure
                .is_none_or(|closure| !closure.finished || closure.receipt != Some(receipt))
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        Ok(())
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

    /// Preallocates a previously disabled infrastructure root and opens its
    /// first workload entirely off-ledger. The final live append is reserved
    /// only after every identity, quota, counter, and invariant check passes.
    pub(in super::super) fn prepare_causal_workload_bootstrap(
        &mut self,
        root: WorkloadRootPresentation,
        request: WorkloadRequestPresentation,
        limits: InfrastructureLimits,
        domains: &[(DomainKey, u64)],
    ) -> Result<CausalWorkloadBootstrapInstall, InfrastructureError> {
        self.require_authoritative()?;
        if self
            .scopes
            .iter()
            .any(|(candidate, _)| *candidate == root.scope)
        {
            return Err(InfrastructureError::AlreadyEnabled);
        }
        let mut record = ScopeInfrastructure::try_new(
            RootStamp {
                registry_instance: self.registry_instance,
                scope: root.scope,
                authority_epoch: root.authority_epoch,
                root_effect: root.root_effect,
            },
            limits,
            domains,
        )?;
        let mint = open_workload_in_scope(self.registry_instance, &mut record, root, request)?;
        check_scope_invariants(&record)?;

        // This is the final fallible live-ledger operation. The returned plan
        // is Registry-private and is installed immediately while its caller
        // retains the only `&mut EffectRegistry`.
        self.scopes
            .try_reserve(1)
            .map_err(|_| InfrastructureError::AllocationFailed)?;
        Ok(CausalWorkloadBootstrapInstall {
            scope: root.scope,
            record,
            mint,
        })
    }

    /// Installs one fully prepared bootstrap record and releases its opaque
    /// workload context only after the authoritative scope is live.
    pub(in super::super) fn install_causal_workload_bootstrap(
        &mut self,
        install: CausalWorkloadBootstrapInstall,
    ) -> WorkloadContext {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::Authoritative);
        __cser_core::debug_assert!(self.scopes.len() < self.scopes.capacity());
        __cser_core::debug_assert!(
            self.scopes
                .iter()
                .all(|(candidate, _)| *candidate != install.scope)
        );
        let CausalWorkloadBootstrapInstall {
            scope,
            record,
            mint,
        } = install;
        self.scopes.push((scope, record));
        mint_workload_context(mint)
    }

    pub(in super::super) fn workload_context_is_open(
        &self,
        context: &WorkloadContext,
    ) -> Result<bool, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        Ok(scope
            .workloads
            .get(context.workload.request.id)
            .is_some_and(|record| record.phase == WorkloadPhase::Open))
    }

    /// Returns a descriptive view only after revalidating the opaque context
    /// against the authoritative ledger. The outer Registry uses this to bind
    /// its facade identity to the single infrastructure record; the view cannot
    /// be converted back into a bearer.
    pub(in super::super) fn describe_open_workload(
        &self,
        context: &WorkloadContext,
    ) -> Result<WorkloadContextDescription, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let parent = match context.parent {
            ParentStamp::RootEffect(effect) => WorkloadParentDescription::RootEffect(effect),
            ParentStamp::Request(request) => WorkloadParentDescription::Request {
                id: request.id,
                generation: request.generation,
            },
            ParentStamp::Task(_) | ParentStamp::Effect(_) => {
                return Err(InfrastructureError::ForeignParent);
            }
        };
        Ok(WorkloadContextDescription {
            registry_instance: context.root.registry_instance,
            scope: context.root.scope,
            authority_epoch: context.root.authority_epoch,
            root_effect: context.root.root_effect,
            domain: context.domain.domain,
            binding_epoch: context.domain.binding_epoch,
            request_id: context.workload.request.id,
            request_generation: context.workload.request.generation,
            parent,
        })
    }

    /// Describes an exact still-open workload for terminal cleanup after its
    /// domain binding has advanced. The historical bearer must match its
    /// immutable record exactly, while the authoritative domain epoch may only
    /// dominate the captured epoch. This grants no new-admission authority.
    pub(in super::super) fn describe_closable_workload(
        &self,
        context: &WorkloadContext,
    ) -> Result<WorkloadContextDescription, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_recovery_context(scope, self.registry_instance, context)?;
        let parent = match context.parent {
            ParentStamp::RootEffect(effect) => WorkloadParentDescription::RootEffect(effect),
            ParentStamp::Request(request) => WorkloadParentDescription::Request {
                id: request.id,
                generation: request.generation,
            },
            ParentStamp::Task(_) | ParentStamp::Effect(_) => {
                return Err(InfrastructureError::ForeignParent);
            }
        };
        Ok(WorkloadContextDescription {
            registry_instance: context.root.registry_instance,
            scope: context.root.scope,
            authority_epoch: context.root.authority_epoch,
            root_effect: context.root.root_effect,
            domain: context.domain.domain,
            binding_epoch: context.domain.binding_epoch,
            request_id: context.workload.request.id,
            request_generation: context.workload.request.generation,
            parent,
        })
    }

    /// Opens one bounded child workload below an exact root-workload context.
    /// The target binding epoch is read from this authoritative scope; callers
    /// provide only the domain identity and portable request coordinates.
    pub(in super::super) fn open_child_workload(
        &mut self,
        parent: &WorkloadContext,
        target_domain: DomainKey,
        request_id: u64,
        request_generation: u64,
    ) -> Result<WorkloadContext, InfrastructureError> {
        self.require_authoritative()?;
        let plan = {
            let scope = self.scope(parent.root.scope)?;
            prepare_child_workload_open(
                self.registry_instance,
                scope,
                parent,
                target_domain,
                request_id,
                request_generation,
            )?
        };
        Ok(self.apply_child_workload_open(plan))
    }

    fn apply_child_workload_open(&mut self, plan: ChildWorkloadOpenPlan) -> WorkloadContext {
        let ChildWorkloadOpenPlan {
            scope,
            record,
            index,
            mint,
            parent_request,
            next_parent_live_children,
            next_nonce,
            next_revision,
            next_live_workloads,
        } = plan;
        let scope = self
            .scope_mut(scope)
            .expect("prevalidated child-workload scope remains present");
        let parent = scope
            .workloads
            .get_mut(parent_request.id)
            .expect("prevalidated parent workload remains present");
        __cser_core::debug_assert_eq!(parent.request, parent_request);
        __cser_core::debug_assert_eq!(
            parent.live_children.checked_add(1),
            Some(next_parent_live_children)
        );
        parent.live_children = next_parent_live_children;
        scope.workloads.install_vacant_prevalidated(record);
        scope.reverse_indexes.install_vacant_prevalidated(index);
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.workloads = next_live_workloads;
        scope.events.push(
            InfrastructureEventKind::WorkloadOpened,
            mint.workload.request.id,
            mint.workload.request.generation,
        );
        mint_workload_context(mint)
    }

    pub(in super::super) fn open_workload(
        &mut self,
        root: WorkloadRootPresentation,
        request: WorkloadRequestPresentation,
    ) -> Result<WorkloadContext, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(root.scope)?;
        Ok(mint_workload_context(open_workload_in_scope(
            registry_instance,
            scope,
            root,
            request,
        )?))
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

    /// Prepares one exact workload close without changing the authoritative
    /// ledger. Every identity, child, revision, and live-count check is
    /// completed before the non-Copy intent leaves this method.
    pub(in super::super) fn prepare_workload_close(
        &self,
        context: &WorkloadContext,
    ) -> Result<WorkloadCloseIntent, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        check_scope_invariants(scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope.workloads.get(context.workload.request.id).unwrap();
        if record.live_children != 0 {
            return Err(InfrastructureError::ClosureBlocked {
                kind: first_live_child_kind(scope, record.request)?,
                live: record.live_children,
            });
        }
        let next_revision = preview_revision(scope)?;
        let next_live_workloads = checked_sub(scope.live.workloads, 1)?;
        let next_parent_live_children =
            preview_workload_parent_close(scope, record.request, record.parent)?;
        Ok(WorkloadCloseIntent {
            registry_instance: self.registry_instance,
            mint: PreparedWorkloadMint {
                root: context.root,
                domain: context.domain,
                workload: context.workload,
                parent: context.parent,
            },
            base_revision: scope.revision,
            next_revision,
            next_live_workloads,
            next_parent_live_children,
        })
    }

    /// Prepares terminal cleanup for an exact historical workload bearer after
    /// a domain fence. Unlike admission and ordinary verification, this accepts
    /// only monotonic epoch domination and still enforces the same child/count
    /// gates before producing the non-Copy close intent.
    pub(in super::super) fn prepare_historical_workload_close(
        &self,
        context: &WorkloadContext,
    ) -> Result<WorkloadCloseIntent, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        check_scope_invariants(scope)?;
        validate_recovery_context(scope, self.registry_instance, context)?;
        let record = scope.workloads.get(context.workload.request.id).unwrap();
        if record.live_children != 0 {
            return Err(InfrastructureError::ClosureBlocked {
                kind: first_live_child_kind(scope, record.request)?,
                live: record.live_children,
            });
        }
        let next_revision = preview_revision(scope)?;
        let next_live_workloads = checked_sub(scope.live.workloads, 1)?;
        let next_parent_live_children =
            preview_workload_parent_close(scope, record.request, record.parent)?;
        Ok(WorkloadCloseIntent {
            registry_instance: self.registry_instance,
            mint: PreparedWorkloadMint {
                root: context.root,
                domain: context.domain,
                workload: context.workload,
                parent: context.parent,
            },
            base_revision: scope.revision,
            next_revision,
            next_live_workloads,
            next_parent_live_children,
        })
    }

    /// Revalidates an exact prepared close. `context=None` validates the
    /// intent's private descriptive stamps directly for a projected
    /// root-finish preflight; it never constructs a second live bearer.
    pub(in super::super) fn validate_workload_close_intent(
        &self,
        intent: &WorkloadCloseIntent,
        context: Option<&WorkloadContext>,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        if intent.registry_instance != self.registry_instance {
            return Err(InfrastructureError::ForeignRegistry);
        }
        let scope = self.scope(intent.mint.root.scope)?;
        check_scope_invariants(scope)?;
        match context {
            Some(context) => {
                if context.root != intent.mint.root
                    || context.domain != intent.mint.domain
                    || context.workload != intent.mint.workload
                    || context.parent != intent.mint.parent
                {
                    return Err(InfrastructureError::ForeignWorkload);
                }
                validate_context(scope, self.registry_instance, context)?;
            }
            None => validate_workload_mint(scope, self.registry_instance, intent.mint)?,
        }
        let record = scope
            .workloads
            .get(intent.mint.workload.request.id)
            .ok_or(InfrastructureError::UnknownWorkload)?;
        if record.live_children != 0 {
            return Err(InfrastructureError::ClosureBlocked {
                kind: first_live_child_kind(scope, record.request)?,
                live: record.live_children,
            });
        }
        if scope.revision != intent.base_revision
            || preview_revision(scope)? != intent.next_revision
            || checked_sub(scope.live.workloads, 1)? != intent.next_live_workloads
            || preview_workload_parent_close(scope, record.request, record.parent)?
                != intent.next_parent_live_children
        {
            return Err(InfrastructureError::StaleClaim);
        }
        Ok(())
    }

    /// Allocation-free installation of one fully prevalidated workload close.
    pub(in super::super) fn apply_workload_close(
        &mut self,
        intent: WorkloadCloseIntent,
        context: &WorkloadContext,
    ) {
        __cser_core::debug_assert_eq!(intent.registry_instance, self.registry_instance);
        __cser_core::debug_assert_eq!(context.root, intent.mint.root);
        __cser_core::debug_assert_eq!(context.domain, intent.mint.domain);
        __cser_core::debug_assert_eq!(context.workload, intent.mint.workload);
        __cser_core::debug_assert_eq!(context.parent, intent.mint.parent);
        let scope = self
            .scope_mut(intent.mint.root.scope)
            .expect("prevalidated workload scope remains present");
        __cser_core::debug_assert_eq!(scope.revision, intent.base_revision);
        __cser_core::debug_assert_eq!(
            scope.live.workloads.checked_sub(1),
            Some(intent.next_live_workloads)
        );
        let workload = scope
            .workloads
            .get_mut(intent.mint.workload.request.id)
            .expect("prevalidated workload remains present");
        __cser_core::debug_assert_eq!(workload.phase, WorkloadPhase::Open);
        __cser_core::debug_assert_eq!(workload.live_children, 0);
        workload.phase = WorkloadPhase::Closed;
        if let ParentStamp::Request(parent_request) = intent.mint.parent {
            let parent = scope
                .workloads
                .get_mut(parent_request.id)
                .expect("prevalidated parent workload remains present");
            __cser_core::debug_assert_eq!(parent.request, parent_request);
            __cser_core::debug_assert_eq!(
                parent.live_children.checked_sub(1),
                intent.next_parent_live_children
            );
            parent.live_children = intent
                .next_parent_live_children
                .expect("child close prevalidated a parent count");
        } else {
            __cser_core::debug_assert_eq!(intent.next_parent_live_children, None);
        }
        scope.live.workloads = intent.next_live_workloads;
        scope.revision = intent.next_revision;
        scope.events.push(
            InfrastructureEventKind::WorkloadClosed,
            intent.mint.workload.request.id,
            intent.mint.workload.request.generation,
        );
    }

    pub(in super::super) fn close_workload(
        &mut self,
        context: &WorkloadContext,
    ) -> Result<(), InfrastructureError> {
        let intent = self.prepare_workload_close(context)?;
        self.apply_workload_close(intent, context);
        Ok(())
    }
}

fn preview_workload_parent_close(
    scope: &super::ScopeInfrastructure,
    child: RequestKey,
    parent: ParentStamp,
) -> Result<Option<u32>, InfrastructureError> {
    match parent {
        ParentStamp::RootEffect(effect) if effect == scope.root.root_effect => Ok(None),
        ParentStamp::Request(parent) => {
            if parent == child {
                return Err(InfrastructureError::ForeignParent);
            }
            let parent_record = scope
                .workloads
                .get(parent.id)
                .ok_or(InfrastructureError::UnknownWorkload)?;
            if parent_record.request != parent
                || parent_record.parent != ParentStamp::RootEffect(scope.root.root_effect)
                || parent_record.phase != WorkloadPhase::Open
            {
                return Err(InfrastructureError::ForeignParent);
            }
            Ok(Some(preview_workload_child_sub(scope, parent)?))
        }
        ParentStamp::RootEffect(_) | ParentStamp::Task(_) | ParentStamp::Effect(_) => {
            Err(InfrastructureError::ForeignParent)
        }
    }
}

fn prepare_child_workload_open(
    registry_instance: u64,
    scope: &super::ScopeInfrastructure,
    parent: &WorkloadContext,
    target_domain: DomainKey,
    request_id: u64,
    request_generation: u64,
) -> Result<ChildWorkloadOpenPlan, InfrastructureError> {
    check_scope_invariants(scope)?;
    validate_context(scope, registry_instance, parent)?;
    validate_active_admission(scope)?;
    if parent.parent != ParentStamp::RootEffect(parent.root.root_effect) {
        return Err(InfrastructureError::ForeignParent);
    }
    let parent_record = scope
        .workloads
        .get(parent.workload.request.id)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    if parent_record.request != parent.workload.request
        || parent_record.phase != WorkloadPhase::Open
        || parent_record.parent != ParentStamp::RootEffect(parent.root.root_effect)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    let binding_epoch = scope.binding_epoch(target_domain)?;
    let request = RequestKey::new(request_id, request_generation)?;
    if let Some(existing) = scope.workloads.get(request.id) {
        return if existing.request == request
            && existing.root_effect == parent.root.root_effect
            && existing.parent == ParentStamp::Request(parent.workload.request)
            && existing.domain == target_domain
        {
            Err(InfrastructureError::ExactReplay)
        } else if existing.request.generation > request.generation {
            Err(InfrastructureError::StaleGeneration)
        } else {
            Err(InfrastructureError::IdentityConflict)
        };
    }
    require_vacancy(&scope.workloads, request.id, InfrastructureKind::Workload)?;
    require_vacancy(
        &scope.reverse_indexes,
        scope.next_nonce,
        InfrastructureKind::Workload,
    )?;
    let (nonce, next_nonce) = preview_nonce(scope)?;
    let next_revision = preview_revision(scope)?;
    let next_live_workloads = checked_add(scope.live.workloads, 1)?;
    let next_parent_live_children = preview_workload_child_add(scope, parent.workload.request)?;
    let workload = super::WorkloadStamp {
        request,
        nonce,
        bearer_generation: 1,
    };
    let root = parent.root;
    let domain = super::DomainStamp {
        domain: target_domain,
        binding_epoch,
    };
    let parent_stamp = ParentStamp::Request(parent.workload.request);
    Ok(ChildWorkloadOpenPlan {
        scope: root.scope,
        record: WorkloadRecord {
            request,
            root_effect: root.root_effect,
            parent: parent_stamp,
            domain: target_domain,
            admission_binding_epoch: binding_epoch,
            current_binding_epoch: binding_epoch,
            nonce,
            bearer_generation: 1,
            phase: WorkloadPhase::Open,
            live_children: 0,
            closure_sequence: None,
        },
        index: ReverseIndexRecord {
            slot: nonce,
            kind: InfrastructureKind::Workload,
            root_effect: root.root_effect,
            parent: ReverseParent::Request(parent.workload.request),
            task: None,
            domain: target_domain,
            binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: None,
            actor_slot: None,
            actor_generation: None,
            retry_generation: request.generation,
        },
        mint: PreparedWorkloadMint {
            root,
            domain,
            workload,
            parent: parent_stamp,
        },
        parent_request: parent.workload.request,
        next_parent_live_children,
        next_nonce,
        next_revision,
        next_live_workloads,
    })
}

fn open_workload_in_scope(
    registry_instance: u64,
    scope: &mut ScopeInfrastructure,
    root: WorkloadRootPresentation,
    request: WorkloadRequestPresentation,
) -> Result<super::PreparedWorkloadMint, InfrastructureError> {
    let request_key = RequestKey::new(request.request_id, request.request_generation)?;
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
    prepare_workload_mint(scope, request_key.id)
}

fn stamp_live_closure_cohort(scope: &mut ScopeInfrastructure, sequence: u64) {
    for record in scope.workloads.iter_mut() {
        if record.phase == WorkloadPhase::Open {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.tasks.iter_mut() {
        if task_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.service_requests.iter_mut() {
        if service_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.delayed_commands.iter_mut() {
        if delayed_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.faults.iter_mut() {
        if __cser_core::matches!(record.phase, FaultPhase::Reserved | FaultPhase::Armed) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.continuations.iter_mut() {
        if continuation_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.deadlines.iter_mut() {
        if deadline_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.devices.iter_mut() {
        if device_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
    for record in scope.replies.iter_mut() {
        if reply_live(record.phase) {
            record.closure_sequence = Some(sequence);
        }
    }
}

fn has_retained_closure_owner(scope: &ScopeInfrastructure) -> bool {
    scope
        .tasks
        .iter()
        .any(|record| record.anchor == TaskAnchorPhase::TerminalRetained)
        || scope.deadlines.iter().any(|record| {
            __cser_core::matches!(
                record.phase,
                DeadlinePhase::ExhaustedRetained { .. } | DeadlinePhase::QuarantinedRetained { .. }
            )
        })
        || scope
            .devices
            .iter()
            .any(|record| record.credit_ownership == DeviceCreditOwnership::Retained)
}

fn first_live_obligation(scope: &ScopeInfrastructure) -> Option<(InfrastructureKind, u32)> {
    first_live_obligation_counts(scope.live)
}

fn first_live_obligation_counts(
    live: InfrastructureLiveCounts,
) -> Option<(InfrastructureKind, u32)> {
    [
        (InfrastructureKind::ServiceRequest, live.service_requests),
        (InfrastructureKind::DelayedCommand, live.delayed_commands),
        (InfrastructureKind::Fault, live.faults),
        (InfrastructureKind::Continuation, live.continuations),
        (InfrastructureKind::Deadline, live.deadlines),
        (
            InfrastructureKind::DevicePreparation,
            live.device_preparations,
        ),
        (InfrastructureKind::Reply, live.replies),
        (InfrastructureKind::Task, live.tasks),
        (InfrastructureKind::Workload, live.workloads),
    ]
    .into_iter()
    .find(|(_, live)| *live != 0)
}

const fn task_live(phase: TaskPhase) -> bool {
    __cser_core::matches!(phase, TaskPhase::Admitted | TaskPhase::Entered)
}

const fn service_live(phase: ServiceRequestPhase) -> bool {
    !__cser_core::matches!(
        phase,
        ServiceRequestPhase::Completed { .. } | ServiceRequestPhase::Cancelled { .. }
    )
}

const fn delayed_live(phase: DelayedCommandPhase) -> bool {
    __cser_core::matches!(
        phase,
        DelayedCommandPhase::Reserved | DelayedCommandPhase::Publishing { .. }
    )
}

const fn continuation_live(phase: ContinuationPhase) -> bool {
    !__cser_core::matches!(
        phase,
        ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
    )
}

const fn deadline_live(phase: DeadlinePhase) -> bool {
    !__cser_core::matches!(
        phase,
        DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
    )
}

const fn device_live(phase: DevicePhase) -> bool {
    !__cser_core::matches!(
        phase,
        DevicePhase::Released { .. } | DevicePhase::Cancelled { .. }
    )
}

const fn reply_live(phase: ReplyPhase) -> bool {
    !__cser_core::matches!(
        phase,
        ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
    )
}
