// SPDX-License-Identifier: MPL-2.0

//! Stage 7B fixtures and registry self-test evidence entry points.
//!
//! This unit owns only test/fixture evidence: no production `EffectRegistry`
//! state, method, or type authority lives here.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
    CreditState, DerivedRegisterRequest, DeviceBatchCommitOutcome, DeviceBatchCommitReceipt,
    DeviceBatchEnrollmentReceipt, DeviceCloseApplyPlan, DeviceCloseError, DeviceCloseOperationId,
    DeviceCloseOutcome, DeviceClosureResult, DeviceCohortParent, DeviceDerivedCohortEntry,
    DeviceDerivedRegisterRequest, DeviceEnvelope, DevicePublicationMode,
    DevicePublicationProvenance, DevicePublishedStatus, DomainConfig, DomainKey, EffectKey,
    EffectPhase, EffectRegistry, HandoffFreezeReadiness, KernelRootAuthority, OperationClass,
    OwnershipDecision, OwnershipDecisionReceipt, PortalHandle, PrepareIntent,
    ProductionHandoffProgress, PublicationMode, RegisterRequest, RegisteredEffect, RegistryError,
    RegistryProjection, ResourceKey, ResourceMove, RevokeDisposition, RevokeRecordAccess,
    RevokeSelection, RevokeWorkProjection, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor,
    TaskKey, TerminalOutcome, TerminalRequest, instrument_revoke_record_access,
};
use __cser_alloc::{collections::BTreeMap, collections::BTreeSet, string::String, vec::Vec};

#[cfg(test)]
use super::{
    DevicePublishedObligation, DomainFaultRecoveryAnchor, DomainIsolationOutcome,
    DomainRecoveryAbortOutcome, DomainRecoveryAbortReason, DomainRecoveryOrigin,
    ScopeClosureProgress, advance_device_preparation_scope, domain_cohort_identity, infrastructure,
    runtime_causal, runtime_service_task, runtime_task,
};

/// A production-registry fixture used by the Stage 7B structural and timing
/// evaluators. `n` is the total live population, `k` is the target scope's
/// live population, and `h` is retained terminal history.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bFixtureConfig {
    pub(crate) n: usize,
    pub(crate) k: usize,
    pub(crate) h: usize,
}

/// Exact Stage 7B fault-matrix identity.  Credit capacity is frozen here so a
/// fault adapter cannot manufacture a passing ledger from a gate population
/// such as `waiter_count` or `effect_count`.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) enum Stage7bFaultCase {
    SchedulerLeaseExpiryBeforeProposal,
    SchedulerCrashAfterProposalBeforePick,
    SchedulerStaleProposalBeforeRebind,
    SchedulerStaleProposalAfterRebind,
    SchedulerRepeatedCrashFallbackProgress,
    PagerSamePageConcurrentFault,
    PagerCrashBeforePrepare,
    PagerCrashAfterPrepareBeforeCommit,
    PagerCrashAfterCommitBeforeResume,
    PagerTimeoutVsLateReply,
    ReadinessCrashBeforeBackendCommit,
    ReadinessCrashAfterBackendCommit,
    ReadinessReadyVsTimeout,
    ReadinessRevokeVsReady,
    ReadinessStaleDeadlineAfterRearm,
    IoRevokeBeforeDevicePublication,
    IoCompletionVsResetAck,
    IoResetTimeoutRetry,
    IoIotlbTimeoutLateAck,
    IoStaleDuplicateCompletion,
}

impl Stage7bFaultCase {
    pub(crate) const fn tag(self) -> u32 {
        match self {
            Self::SchedulerLeaseExpiryBeforeProposal => 1,
            Self::SchedulerCrashAfterProposalBeforePick => 2,
            Self::SchedulerStaleProposalBeforeRebind => 3,
            Self::SchedulerStaleProposalAfterRebind => 4,
            Self::SchedulerRepeatedCrashFallbackProgress => 5,
            Self::PagerSamePageConcurrentFault => 6,
            Self::PagerCrashBeforePrepare => 7,
            Self::PagerCrashAfterPrepareBeforeCommit => 8,
            Self::PagerCrashAfterCommitBeforeResume => 9,
            Self::PagerTimeoutVsLateReply => 10,
            Self::ReadinessCrashBeforeBackendCommit => 11,
            Self::ReadinessCrashAfterBackendCommit => 12,
            Self::ReadinessReadyVsTimeout => 13,
            Self::ReadinessRevokeVsReady => 14,
            Self::ReadinessStaleDeadlineAfterRearm => 15,
            Self::IoRevokeBeforeDevicePublication => 16,
            Self::IoCompletionVsResetAck => 17,
            Self::IoResetTimeoutRetry => 18,
            Self::IoIotlbTimeoutLateAck => 19,
            Self::IoStaleDuplicateCompletion => 20,
        }
    }

    pub(crate) const fn credit_capacity(self) -> usize {
        match self {
            Self::SchedulerLeaseExpiryBeforeProposal
            | Self::SchedulerCrashAfterProposalBeforePick
            | Self::SchedulerStaleProposalBeforeRebind
            | Self::SchedulerStaleProposalAfterRebind
            | Self::SchedulerRepeatedCrashFallbackProgress => 0,
            Self::PagerSamePageConcurrentFault => 2,
            _ => 1,
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) enum Stage7bFaultOperation {
    SchedulerFallbackPick,
    PagerContinuation,
    ReadinessCompletion,
    IoRequest,
}

impl Stage7bFaultOperation {
    const fn tag(self) -> u32 {
        match self {
            Self::SchedulerFallbackPick => 1,
            Self::PagerContinuation => 2,
            Self::ReadinessCompletion => 3,
            Self::IoRequest => 4,
        }
    }
}

/// The semantic half of a composite credit authority.  The opaque registry
/// handle is held separately in [`Stage7bFaultCredit`]; every commit and
/// terminal transition must present this exact case/operation/identity again.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct Stage7bFaultBinding {
    case: Stage7bFaultCase,
    operation: Stage7bFaultOperation,
    authority: [u64; 5],
}

impl Stage7bFaultBinding {
    pub(crate) const fn new(
        case: Stage7bFaultCase,
        operation: Stage7bFaultOperation,
        authority: [u64; 5],
    ) -> Self {
        Self {
            case,
            operation,
            authority,
        }
    }

    pub(crate) const fn case(self) -> Stage7bFaultCase {
        self.case
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum Stage7bFaultTerminal {
    Aborted(i64),
    Completed(i64),
}

/// Linear pairing of one semantic authority and one opaque production
/// registry handle.  It is intentionally neither `Clone` nor `Copy`.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultCredit {
    instance_id: u64,
    binding: Stage7bFaultBinding,
    handle: PortalHandle,
    commit: Option<CommitReceipt>,
    terminalized: bool,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bFaultBudgetProjection {
    pub(crate) case: Stage7bFaultCase,
    pub(crate) instance_id: u64,
    pub(crate) scope: ScopeKey,
    pub(crate) registry: RegistryProjection,
    pub(crate) reservations: usize,
    pub(crate) commit_operations: usize,
    pub(crate) terminal_operations: usize,
}

impl Stage7bFaultBudgetProjection {
    /// Observes live credit ownership before closure and returned credit after
    /// closure. Capacity is checked separately as an invariant; it is not the
    /// fault counter reported by the evaluator.
    pub(crate) fn observed_credit_units(&self) -> Result<usize, RegistryError> {
        let credits = self.registry.credits;
        let units = match self.registry.phase {
            ScopePhase::Active | ScopePhase::Closing => credits
                .held
                .checked_add(credits.committed)
                .and_then(|owned| owned.checked_add(credits.retained))
                .ok_or(RegistryError::CounterOverflow)?,
            ScopePhase::Revoked => credits.free,
        };
        usize::try_from(units).map_err(|_| RegistryError::CounterOverflow)
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultBudget {
    case: Stage7bFaultCase,
    instance_id: u64,
    registry: EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    bindings: BTreeSet<Stage7bFaultBinding>,
    commit_operations: usize,
    terminal_operations: usize,
}

/// Read-only, complete failure-atomicity snapshot of one case-local ledger.
/// Its fields remain private so cloning this value cannot mint usable Registry
/// handles or transition authority.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultBudgetState {
    case: Stage7bFaultCase,
    instance_id: u64,
    registry: EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    bindings: BTreeSet<Stage7bFaultBinding>,
    commit_operations: usize,
    terminal_operations: usize,
}

impl Clone for Stage7bFaultBudgetState {
    fn clone(&self) -> Self {
        Self {
            case: self.case,
            instance_id: self.instance_id,
            registry: self.registry.clone(),
            scope: self.scope,
            task: self.task,
            credit: self.credit,
            bindings: self.bindings.clone(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        }
    }
}

impl Stage7bFaultBudget {
    /// Creates one case-local evaluation ledger in a caller-allocated instance
    /// namespace. `instance_id` must be nonzero and unique among simultaneously
    /// live fault budgets whose linear credits could meet.
    pub(crate) fn new(case: Stage7bFaultCase, instance_id: u64) -> Result<Self, RegistryError> {
        let capacity = case.credit_capacity();
        if capacity == 0 || instance_id == 0 {
            return Err(RegistryError::InvalidCreditConfiguration);
        }
        let tag = u64::from(case.tag());
        let scope = ScopeKey::new(instance_id, tag);
        let task = TaskKey::new(instance_id, tag);
        let credit = CreditClass::new(
            u16::try_from(0x7b00_u32 + case.tag()).map_err(|_| RegistryError::CounterOverflow)?,
        );
        let units = u64::try_from(capacity).map_err(|_| RegistryError::CounterOverflow)?;
        let mut registry = EffectRegistry::new();
        registry.create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: task,
            credits: __cser_alloc::vec![CreditLimit::new(credit, units)],
        })?;
        registry.check_invariants()?;
        Ok(Self {
            case,
            instance_id,
            registry,
            scope,
            task,
            credit,
            bindings: BTreeSet::new(),
            commit_operations: 0,
            terminal_operations: 0,
        })
    }

    pub(crate) fn reserve(
        &mut self,
        binding: Stage7bFaultBinding,
    ) -> Result<Stage7bFaultCredit, RegistryError> {
        if binding.case != self.case
            || self.bindings.contains(&binding)
            || self.bindings.len() >= self.case.credit_capacity()
        {
            return Err(RegistryError::InvalidState);
        }
        let ordinal = self.bindings.len();
        let resource_id = u64::try_from(ordinal)
            .map_err(|_| RegistryError::CounterOverflow)?
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let namespace = 0x7b10_u32
            .checked_add(self.case.tag())
            .ok_or(RegistryError::CounterOverflow)?;
        let operation = binding.operation.tag();
        let registered = self.registry.register(RegisterRequest {
            scope: self.scope,
            task: self.task,
            operation: OperationClass::new(operation),
            descriptor: SyscallDescriptor::new(
                usize::try_from(0x7b10_u32 + self.case.tag())
                    .map_err(|_| RegistryError::CounterOverflow)?,
                [
                    usize::try_from(self.instance_id)
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[0])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[1])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[2])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[3])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[4])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                ],
            ),
            resources: __cser_alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(self.credit, 1)],
            publication: PublicationMode::None,
        })?;
        self.bindings.insert(binding);
        self.registry.check_invariants()?;
        Ok(Stage7bFaultCredit {
            instance_id: self.instance_id,
            binding,
            handle: registered.handle,
            commit: None,
            terminalized: false,
        })
    }

    pub(crate) fn commit(
        &mut self,
        credit: &mut Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
        result: i64,
    ) -> Result<(), RegistryError> {
        self.validate_credit(credit, binding)?;
        if credit.commit.is_some() || credit.terminalized {
            return Err(RegistryError::InvalidState);
        }
        self.registry.prepare(self.task, credit.handle)?;
        let commit = match self.registry.commit(
            self.task,
            credit.handle,
            CommitMetadata::new(result, u64::from(self.case.tag())),
        )? {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => return Err(RegistryError::CommitConflict),
        };
        credit.commit = Some(commit);
        self.commit_operations = self
            .commit_operations
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.registry.check_invariants()
    }

    pub(crate) fn terminalize(
        &mut self,
        credit: &mut Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
        terminal: Stage7bFaultTerminal,
    ) -> Result<TerminalOutcome, RegistryError> {
        self.validate_credit(credit, binding)?;
        if credit.terminalized {
            return Err(RegistryError::InvalidState);
        }
        let request = match (terminal, credit.commit.clone()) {
            (Stage7bFaultTerminal::Aborted(result), None) => TerminalRequest::aborted(result),
            (Stage7bFaultTerminal::Completed(result), Some(commit)) => {
                TerminalRequest::completed_by(result, commit)
            }
            _ => return Err(RegistryError::InvalidState),
        };
        let terminal = self
            .registry
            .stage_terminal(self.task, credit.handle, request)?;
        if terminal.publication.is_some() {
            return Err(RegistryError::InvalidState);
        }
        credit.terminalized = true;
        self.terminal_operations = self
            .terminal_operations
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.registry.check_invariants()?;
        Ok(terminal.receipt.outcome())
    }

    pub(crate) fn projection(&self) -> Result<Stage7bFaultBudgetProjection, RegistryError> {
        Ok(Stage7bFaultBudgetProjection {
            case: self.case,
            instance_id: self.instance_id,
            scope: self.scope,
            registry: self.registry.scope_projection(self.scope)?,
            reservations: self.bindings.len(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        })
    }

    pub(crate) fn state_snapshot(&self) -> Stage7bFaultBudgetState {
        Stage7bFaultBudgetState {
            case: self.case,
            instance_id: self.instance_id,
            registry: self.registry.clone(),
            scope: self.scope,
            task: self.task,
            credit: self.credit,
            bindings: self.bindings.clone(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        }
    }

    pub(crate) fn finish(&mut self) -> Result<Stage7bFaultBudgetProjection, RegistryError> {
        if self.bindings.len() != self.case.credit_capacity()
            || self.terminal_operations != self.case.credit_capacity()
        {
            return Err(RegistryError::NotQuiescent);
        }
        let active = self.registry.scope_projection(self.scope)?;
        if active.live_effects != 0
            || active.pending_publications != 0
            || active.credits.held != 0
            || active.credits.committed != 0
            || active.credits.free != active.credits.capacity
        {
            return Err(RegistryError::NotQuiescent);
        }
        let selection = self.registry.revoke_begin(self.scope)?;
        if selection.target_count != 0 || self.registry.revoke_next(&selection)?.is_some() {
            return Err(RegistryError::NotQuiescent);
        }
        self.registry.revoke_complete(&selection)?;
        self.registry.check_invariants()?;
        self.projection()
    }

    fn validate_credit(
        &self,
        credit: &Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
    ) -> Result<(), RegistryError> {
        if binding.case != self.case
            || credit.instance_id != self.instance_id
            || credit.binding != binding
            || !self.bindings.contains(&binding)
        {
            return Err(RegistryError::InvalidHandle);
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
pub(crate) struct Stage7bNoCreditProjection {
    pub(crate) case: Stage7bFaultCase,
    pub(crate) binding: Stage7bFaultBinding,
    pub(crate) consumed: bool,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bNoCredit {
    case: Stage7bFaultCase,
    binding: Stage7bFaultBinding,
    consumed: bool,
}

impl Stage7bNoCredit {
    pub(crate) fn new(
        case: Stage7bFaultCase,
        binding: Stage7bFaultBinding,
    ) -> Result<Self, RegistryError> {
        if case.credit_capacity() != 0 || binding.case != case {
            return Err(RegistryError::InvalidCreditConfiguration);
        }
        Ok(Self {
            case,
            binding,
            consumed: false,
        })
    }

    pub(crate) fn consume(&mut self, binding: Stage7bFaultBinding) -> Result<(), RegistryError> {
        if self.consumed || binding != self.binding {
            return Err(RegistryError::InvalidHandle);
        }
        self.consumed = true;
        Ok(())
    }

    pub(crate) const fn projection(&self) -> Stage7bNoCreditProjection {
        Stage7bNoCreditProjection {
            case: self.case,
            binding: self.binding,
            consumed: self.consumed,
        }
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bActiveFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bCompleteFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
    selection: RevokeSelection,
}

impl Clone for Stage7bActiveFixture {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            registry: self.registry.clone(),
            target_scope: self.target_scope,
        }
    }
}

impl Clone for Stage7bCompleteFixture {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            registry: self.registry.clone(),
            target_scope: self.target_scope,
            selection: self.selection.clone(),
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
pub(crate) struct Stage7bScaleObservation {
    pub(crate) config: Stage7bFixtureConfig,
    pub(crate) work: RevokeWorkProjection,
    pub(crate) target: RegistryProjection,
}

impl Stage7bActiveFixture {
    pub(crate) fn new(config: Stage7bFixtureConfig) -> Result<Self, RegistryError> {
        const TARGET_SCOPE: ScopeKey = ScopeKey::new(0x7b01, 1);
        const UNRELATED_SCOPE: ScopeKey = ScopeKey::new(0x7b02, 1);
        const HISTORY_SCOPE: ScopeKey = ScopeKey::new(0x7b03, 1);
        const TARGET_TASK: TaskKey = TaskKey::new(0x7b01, 1);
        const UNRELATED_TASK: TaskKey = TaskKey::new(0x7b02, 1);
        const HISTORY_TASK: TaskKey = TaskKey::new(0x7b03, 1);
        const TARGET_CREDIT: CreditClass = CreditClass::new(0x7b01);
        const UNRELATED_CREDIT: CreditClass = CreditClass::new(0x7b02);
        const HISTORY_CREDIT: CreditClass = CreditClass::new(0x7b03);

        if config.k > config.n {
            return Err(RegistryError::InvalidState);
        }
        let target_capacity =
            u64::try_from(config.k).map_err(|_| RegistryError::CounterOverflow)?;
        let unrelated = config.n - config.k;
        let unrelated_capacity =
            u64::try_from(unrelated.max(1)).map_err(|_| RegistryError::CounterOverflow)?;
        let mut registry = EffectRegistry::new();
        registry.create_scope(ScopeConfig {
            key: TARGET_SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: TARGET_TASK,
            credits: if target_capacity == 0 {
                Vec::new()
            } else {
                __cser_alloc::vec![CreditLimit::new(TARGET_CREDIT, target_capacity)]
            },
        })?;
        for (key, supervisor, credit, units) in [
            (
                UNRELATED_SCOPE,
                UNRELATED_TASK,
                UNRELATED_CREDIT,
                unrelated_capacity,
            ),
            (HISTORY_SCOPE, HISTORY_TASK, HISTORY_CREDIT, 1),
        ] {
            registry.create_scope(ScopeConfig {
                key,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor,
                credits: __cser_alloc::vec![CreditLimit::new(credit, units)],
            })?;
        }

        // History is deliberately older than the live population. One credit
        // is reused sequentially while the terminal records remain retained.
        for ordinal in 0..config.h {
            let registered = register_stage7b_effect(
                &mut registry,
                HISTORY_SCOPE,
                HISTORY_TASK,
                HISTORY_CREDIT,
                0x7b03,
                ordinal,
            )?;
            let terminal = registry.stage_terminal(
                HISTORY_TASK,
                registered.handle,
                TerminalRequest::aborted(-125),
            )?;
            if terminal.publication.is_some() {
                return Err(RegistryError::InvalidState);
            }
        }
        for ordinal in 0..config.k {
            register_stage7b_effect(
                &mut registry,
                TARGET_SCOPE,
                TARGET_TASK,
                TARGET_CREDIT,
                0x7b01,
                ordinal,
            )?;
        }
        for ordinal in 0..unrelated {
            register_stage7b_effect(
                &mut registry,
                UNRELATED_SCOPE,
                UNRELATED_TASK,
                UNRELATED_CREDIT,
                0x7b02,
                ordinal,
            )?;
        }
        registry.check_invariants()?;
        Ok(Self {
            config,
            registry,
            target_scope: TARGET_SCOPE,
        })
    }

    pub(crate) fn begin(&mut self) -> Result<RevokeSelection, RegistryError> {
        self.registry.revoke_begin(self.target_scope)
    }

    /// Prepares the fixture's sole target for the production commit-vs-revoke
    /// Loom race. The caller's modeled outer mutex supplies serialization.
    pub(crate) fn prepare_single_target(&mut self) -> Result<PortalHandle, RegistryError> {
        if self.config.k != 1 {
            return Err(RegistryError::InvalidState);
        }
        let effect = self
            .registry
            .by_scope
            .get(&self.target_scope)
            .and_then(BTreeSet::first)
            .copied()
            .ok_or(RegistryError::UnknownEffect)?;
        let handle = self.registry.effects[&effect].handle();
        self.registry.prepare(TaskKey::new(0x7b01, 1), handle)?;
        Ok(handle)
    }

    pub(crate) fn commit_single_target(
        &mut self,
        handle: PortalHandle,
    ) -> Result<CommitOutcome, RegistryError> {
        self.registry
            .commit(TaskKey::new(0x7b01, 1), handle, CommitMetadata::new(1, 1))
    }

    pub(crate) fn single_target_terminal(
        &self,
        handle: PortalHandle,
    ) -> Result<TerminalOutcome, RegistryError> {
        match self.registry.effect_view(handle.effect)?.phase {
            EffectPhase::Terminal(outcome) => Ok(outcome),
            _ => Err(RegistryError::InvalidState),
        }
    }

    pub(crate) fn finish_revoke(
        &mut self,
        selection: &RevokeSelection,
    ) -> Result<(), RegistryError> {
        drain_stage7b_selection(&mut self.registry, selection)?;
        self.registry.revoke_complete(selection)
    }

    pub(crate) fn prepare_complete_baseline(
        &self,
    ) -> Result<Stage7bCompleteFixture, RegistryError> {
        let mut candidate = self.clone();
        let selection = candidate.begin()?;
        drain_stage7b_selection(&mut candidate.registry, &selection)?;
        Ok(Stage7bCompleteFixture {
            config: candidate.config,
            registry: candidate.registry,
            target_scope: candidate.target_scope,
            selection,
        })
    }

    pub(crate) fn close_all(&mut self) -> Result<RevokeSelection, RegistryError> {
        let selection = self.begin()?;
        self.finish_revoke(&selection)?;
        Ok(selection)
    }

    pub(crate) fn target_projection(&self) -> Result<RegistryProjection, RegistryError> {
        self.registry.scope_projection(self.target_scope)
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.registry.check_invariants()
    }

    pub(crate) fn observation(
        &self,
        selection: &RevokeSelection,
    ) -> Result<Stage7bScaleObservation, RegistryError> {
        Ok(Stage7bScaleObservation {
            config: self.config,
            work: self.registry.revoke_work_projection(selection)?,
            target: self.registry.scope_projection(self.target_scope)?,
        })
    }
}

impl Stage7bCompleteFixture {
    pub(crate) fn complete(&mut self) -> Result<(), RegistryError> {
        self.registry.revoke_complete(&self.selection)
    }

    pub(crate) fn observation(&self) -> Result<Stage7bScaleObservation, RegistryError> {
        Ok(Stage7bScaleObservation {
            config: self.config,
            work: self.registry.revoke_work_projection(&self.selection)?,
            target: self.registry.scope_projection(self.target_scope)?,
        })
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.registry.check_invariants()
    }
}

fn register_stage7b_effect(
    registry: &mut EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    namespace: u32,
    ordinal: usize,
) -> Result<RegisteredEffect, RegistryError> {
    let ordinal_argument = ordinal;
    let ordinal = u64::try_from(ordinal).map_err(|_| RegistryError::CounterOverflow)?;
    let resource_id = ordinal
        .checked_add(1)
        .ok_or(RegistryError::CounterOverflow)?;
    let namespace_argument =
        usize::try_from(namespace).map_err(|_| RegistryError::CounterOverflow)?;
    registry.register(RegisterRequest {
        scope,
        task,
        operation: OperationClass::new(namespace),
        descriptor: SyscallDescriptor::new(
            0x7b00,
            [namespace_argument, ordinal_argument, 0, 0, 0, 0],
        ),
        resources: __cser_alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
        credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
        publication: PublicationMode::None,
    })
}

fn drain_stage7b_selection(
    registry: &mut EffectRegistry,
    selection: &RevokeSelection,
) -> Result<(), RegistryError> {
    while let Some(effect) = registry.revoke_next(selection)? {
        if effect.publication_required {
            return Err(RegistryError::InvalidState);
        }
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(receipt) => TerminalRequest::completed(receipt.result()),
        };
        let terminal = registry.stage_revoke_terminal(selection, effect.effect, request)?;
        if terminal.publication.is_some() {
            return Err(RegistryError::InvalidState);
        }
    }
    Ok(())
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RegistrySelfTestReceipt {
    pub(crate) effects: usize,
    pub(crate) recovery_adoptions: usize,
    pub(crate) committed_drains: usize,
    pub(crate) uncommitted_aborts: usize,
    pub(crate) publication_acks: usize,
    pub(crate) stale_authority_rejected: bool,
    pub(crate) quiescent: bool,
}

fn bounded_kernel_completion_during_recovery_self_test() {
    let scope = ScopeKey::new(51, 1);
    let v1 = TaskKey::new(620, 1);
    let v2 = TaskKey::new(621, 1);
    let task = TaskKey::new(622, 1);
    let credit = CreditClass::new(1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 112,
            binding_epoch: 1,
            supervisor: v1,
            credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let effect = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(9),
            descriptor: SyscallDescriptor::new(202, [0x402020, 129, 1, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(9, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, effect.handle).unwrap();
    let commit = match registry
        .commit(v1, effect.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };

    registry.crash(scope, v1).unwrap();
    let stale_snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &stale_snapshot).unwrap();
    let terminal = registry.stage_kernel_completion(&commit).unwrap();
    registry.check_invariants().unwrap();
    __cser_core::assert_eq!(registry.recovery_remaining(scope), Ok(0));
    __cser_core::assert_eq!(
        registry.rebind(scope, v2),
        Err(RegistryError::RecoveryNotReady),
    );
    registry
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();

    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    __cser_core::assert!(snapshot.effects.is_empty());
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();
    __cser_core::assert!(registry.recover_next(scope, v2).unwrap().is_none());
    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
}

fn committed_causal_test_registry(
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    namespace: u32,
) -> (EffectRegistry, PortalHandle, CommitReceipt) {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: task,
            credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let registered = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(namespace),
            descriptor: SyscallDescriptor::new(namespace as usize, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(namespace, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    registry.prepare(task, registered.handle).unwrap();
    let commit = match registry
        .commit(task, registered.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    registry.check_invariants().unwrap();
    (registry, registered.handle, commit)
}

/// Stage 7B executable checks for the explicit causal completion envelope.
/// They keep legitimate same-scope cross-effect completion while proving that
/// foreign scope and same-value foreign Registry receipts are rejected in both
/// directions without mutating either complete Registry state.
pub(crate) fn stage7b_causal_commit_self_test() {
    const POSITIVE_SCOPE: ScopeKey = ScopeKey::new(0x7bca_0001, 1);
    const POSITIVE_TASK: TaskKey = TaskKey::new(0x7bca_1001, 1);
    const POSITIVE_CREDIT: CreditClass = CreditClass::new(0x7bca);

    let mut positive = EffectRegistry::new();
    positive
        .create_scope(ScopeConfig {
            key: POSITIVE_SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: POSITIVE_TASK,
            credits: __cser_alloc::vec![CreditLimit::new(POSITIVE_CREDIT, 2)],
        })
        .unwrap();
    let source = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(1, [1, 0, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bca, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let target = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(2),
            descriptor: SyscallDescriptor::new(2, [2, 0, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bca, 2, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    positive.prepare(POSITIVE_TASK, source.handle).unwrap();
    let source_commit = match positive
        .commit(POSITIVE_TASK, source.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let target_terminal = positive
        .stage_terminal(
            POSITIVE_TASK,
            target.handle,
            TerminalRequest::completed_by(2, source_commit.clone()),
        )
        .unwrap();
    __cser_core::assert_eq!(
        target_terminal.receipt.outcome(),
        TerminalOutcome::Completed
    );
    positive.stage_kernel_completion(&source_commit).unwrap();
    positive.check_invariants().unwrap();

    const SCOPE_A: ScopeKey = ScopeKey::new(0x7bca_0002, 1);
    const SCOPE_B: ScopeKey = ScopeKey::new(0x7bca_0003, 1);
    const TASK_A: TaskKey = TaskKey::new(0x7bca_1002, 1);
    const TASK_B: TaskKey = TaskKey::new(0x7bca_1003, 1);
    const CREDIT_A: CreditClass = CreditClass::new(0x7bcb);
    const CREDIT_B: CreditClass = CreditClass::new(0x7bcc);

    let mut cross_scope = EffectRegistry::new();
    for (scope, task, credit) in [(SCOPE_A, TASK_A, CREDIT_A), (SCOPE_B, TASK_B, CREDIT_B)] {
        cross_scope
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: task,
                credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
            })
            .unwrap();
    }
    let effect_a = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_A,
            task: TASK_A,
            operation: OperationClass::new(3),
            descriptor: SyscallDescriptor::new(3, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bcb, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT_A, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let effect_b = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_B,
            task: TASK_B,
            operation: OperationClass::new(4),
            descriptor: SyscallDescriptor::new(4, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bcc, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT_B, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    cross_scope.prepare(TASK_A, effect_a.handle).unwrap();
    cross_scope.prepare(TASK_B, effect_b.handle).unwrap();
    let commit_a = match cross_scope
        .commit(TASK_A, effect_a.handle, CommitMetadata::new(3, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let commit_b = match cross_scope
        .commit(TASK_B, effect_b.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let cross_scope_before = cross_scope.clone();
    __cser_core::assert_eq!(
        cross_scope.stage_terminal(
            TASK_A,
            effect_a.handle,
            TerminalRequest::completed_by(3, commit_b.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(cross_scope, cross_scope_before);
    __cser_core::assert_eq!(
        cross_scope.stage_terminal(
            TASK_B,
            effect_b.handle,
            TerminalRequest::completed_by(4, commit_a.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(cross_scope, cross_scope_before);
    cross_scope.stage_kernel_completion(&commit_a).unwrap();
    cross_scope.stage_kernel_completion(&commit_b).unwrap();
    cross_scope.check_invariants().unwrap();

    const SHARED_SCOPE: ScopeKey = ScopeKey::new(0x7bca_0010, 1);
    const SHARED_TASK: TaskKey = TaskKey::new(0x7bca_1010, 1);
    const SHARED_CREDIT: CreditClass = CreditClass::new(0x7bd0);
    let (mut first, first_handle, first_commit) =
        committed_causal_test_registry(SHARED_SCOPE, SHARED_TASK, SHARED_CREDIT, 0x7bd0);
    let (mut second, second_handle, second_commit) =
        committed_causal_test_registry(SHARED_SCOPE, SHARED_TASK, SHARED_CREDIT, 0x7bd0);
    __cser_core::assert_ne!(
        first_commit.registry_instance_id,
        second_commit.registry_instance_id
    );
    __cser_core::assert_eq!(first_commit.effect, second_commit.effect);
    __cser_core::assert_eq!(first_commit.scope, second_commit.scope);
    __cser_core::assert_eq!(first_commit.authority_epoch, second_commit.authority_epoch);
    __cser_core::assert_eq!(first_commit.binding_epoch, second_commit.binding_epoch);
    __cser_core::assert_eq!(first_commit.sequence, second_commit.sequence);
    __cser_core::assert_eq!(first_commit.result, second_commit.result);
    __cser_core::assert_eq!(first_commit.domain_revision, second_commit.domain_revision);
    __cser_core::assert_eq!(
        first_commit.descriptor_digest,
        second_commit.descriptor_digest
    );
    let first_before = first.clone();
    let second_before = second.clone();
    __cser_core::assert_eq!(
        first.stage_terminal(
            SHARED_TASK,
            first_handle,
            TerminalRequest::completed_by(1, second_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(first, first_before);
    __cser_core::assert_eq!(second, second_before);
    __cser_core::assert_eq!(
        second.stage_terminal(
            SHARED_TASK,
            second_handle,
            TerminalRequest::completed_by(1, first_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(first, first_before);
    __cser_core::assert_eq!(second, second_before);
    first.stage_kernel_completion(&first_commit).unwrap();
    second.stage_kernel_completion(&second_commit).unwrap();
    first.check_invariants().unwrap();
    second.check_invariants().unwrap();
}

fn stage7b_registry_refactor_self_test() {
    // Public transition failures must not leave half-applied phase, counter,
    // credit, or index state when the root revision cannot advance.
    let atomic_scope = ScopeKey::new(0x7bf0, 1);
    let atomic_task = TaskKey::new(0x7bf0, 1);
    let atomic_credit = CreditClass::new(0x7bf0);
    let mut atomic = EffectRegistry::new();
    atomic
        .create_scope(ScopeConfig {
            key: atomic_scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: atomic_task,
            credits: __cser_alloc::vec![CreditLimit::new(atomic_credit, 1)],
        })
        .unwrap();
    let request = || RegisterRequest {
        scope: atomic_scope,
        task: atomic_task,
        operation: OperationClass::new(0x7bf0),
        descriptor: SyscallDescriptor::new(0x7bf0, [0; 6]),
        resources: __cser_alloc::vec![ResourceKey::new(0x7bf0, 1, 1)],
        credits: __cser_alloc::vec![CreditCharge::new(atomic_credit, 1)],
        publication: PublicationMode::None,
    };
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.register(request()),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = 0;
    let registered = atomic.register(request()).unwrap();
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.prepare(atomic_task, registered.handle),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = 1;
    atomic.prepare(atomic_task, registered.handle).unwrap();
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.crash(atomic_scope, atomic_task),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    {
        let scope = atomic.scopes.get_mut(&atomic_scope).unwrap();
        scope.revision = 2;
        scope.binding_epoch = u64::MAX;
        scope
            .domains
            .get_mut(&DomainKey::LEGACY)
            .unwrap()
            .binding_epoch = u64::MAX;
    }
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.crash(atomic_scope, atomic_task),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);

    let config = Stage7bFixtureConfig { n: 8, k: 3, h: 2 };
    let fixture = Stage7bActiveFixture::new(config).unwrap();
    __cser_core::assert_eq!(fixture.target_projection().unwrap().live_effects, config.k);
    fixture.check_invariants().unwrap();

    // The three zero-valued scale metrics are real counters, not constants in
    // the projection. Exercise their classification boundary without changing
    // the production close path measured below.
    let mut instrumented = fixture.clone();
    let instrumented_selection = instrumented.begin().unwrap();
    let target = *instrumented
        .registry
        .scopes
        .get(&instrumented.target_scope)
        .unwrap()
        .revoke
        .as_ref()
        .unwrap()
        .cohort
        .first()
        .unwrap();
    let unrelated = instrumented
        .registry
        .effects
        .iter()
        .find_map(|(effect, record)| {
            (record.identity.scope != instrumented.target_scope && !record.phase.is_terminal())
                .then_some(*effect)
        })
        .unwrap();
    let history = instrumented
        .registry
        .effects
        .iter()
        .find_map(|(effect, record)| record.phase.is_terminal().then_some(*effect))
        .unwrap();
    {
        let (scopes, effects) = (
            &mut instrumented.registry.scopes,
            &instrumented.registry.effects,
        );
        let revoke = scopes
            .get_mut(&instrumented.target_scope)
            .unwrap()
            .revoke
            .as_mut()
            .unwrap();
        for (effect, access) in [
            (target, RevokeRecordAccess::Begin),
            (unrelated, RevokeRecordAccess::Transition),
            (history, RevokeRecordAccess::Transition),
        ] {
            instrument_revoke_record_access(
                &mut revoke.work,
                &revoke.cohort,
                effects,
                instrumented.target_scope,
                effect,
                access,
            )
            .unwrap();
        }
    }
    let work = instrumented
        .registry
        .revoke_work_projection(&instrumented_selection)
        .unwrap();
    __cser_core::assert_eq!(work.begin_target_record_visits, 1);
    __cser_core::assert_eq!(work.unrelated_effect_visits, 1);
    __cser_core::assert_eq!(work.history_effect_visits, 1);

    let mut closed = fixture.clone();
    let selection = closed.close_all().unwrap();
    let observation = closed.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.config, config);
    __cser_core::assert_eq!(observation.work.target_count, 3);
    __cser_core::assert_eq!(observation.work.begin_target_record_visits, 0);
    __cser_core::assert_eq!(observation.work.next_calls, 4);
    __cser_core::assert_eq!(observation.work.head_selections, 3);
    __cser_core::assert_eq!(observation.work.terminalized, 3);
    __cser_core::assert_eq!(observation.work.completion_members_checked, 3);
    __cser_core::assert_eq!(observation.work.target_index_removals, 3);
    __cser_core::assert_eq!(observation.work.unrelated_effect_visits, 0);
    __cser_core::assert_eq!(observation.work.history_effect_visits, 0);
    __cser_core::assert_eq!(observation.work.pending_targets, 0);
    __cser_core::assert_eq!(observation.work.target_state, ScopePhase::Revoked);
    __cser_core::assert_eq!(observation.target.phase, ScopePhase::Revoked);
    closed.check_invariants().unwrap();
    let before = closed.registry.clone();
    __cser_core::assert_eq!(closed.begin(), Err(RegistryError::ScopeNotActive));
    __cser_core::assert_eq!(closed.registry, before);

    let mut empty = Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 4, k: 0, h: 3 }).unwrap();
    let empty_active = empty.target_projection().unwrap();
    __cser_core::assert_eq!(empty_active.credits.capacity, 0);
    __cser_core::assert_eq!(empty_active.credits.free, 0);
    __cser_core::assert_eq!(empty_active.credits.held, 0);
    __cser_core::assert_eq!(empty_active.credits.committed, 0);
    let selection = empty.close_all().unwrap();
    let empty_observation = empty.observation(&selection).unwrap();
    __cser_core::assert_eq!(empty_observation.work.target_count, 0);
    __cser_core::assert_eq!(empty_observation.work.next_calls, 1);
    __cser_core::assert_eq!(empty_observation.work.head_selections, 0);
    __cser_core::assert_eq!(empty_observation.work.terminalized, 0);
    __cser_core::assert_eq!(empty_observation.work.completion_members_checked, 0);
    __cser_core::assert_eq!(empty_observation.work.target_state, ScopePhase::Revoked);
    __cser_core::assert_eq!(empty_observation.target.credits, empty_active.credits);
    empty.check_invariants().unwrap();

    // Unknown and overflow failures do not consume the revoke sequence or
    // alter any registry-owned state.
    let mut unknown = fixture.clone();
    let before = unknown.registry.clone();
    __cser_core::assert_eq!(
        unknown.registry.revoke_begin(ScopeKey::new(0xffff, 1)),
        Err(RegistryError::UnknownScope)
    );
    __cser_core::assert_eq!(unknown.registry, before);

    let mut sequence_overflow = fixture.clone();
    sequence_overflow.registry.next_revoke_sequence = u64::MAX;
    let before = sequence_overflow.registry.clone();
    __cser_core::assert_eq!(
        sequence_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(sequence_overflow.registry, before);

    let mut authority_overflow = fixture.clone();
    authority_overflow
        .registry
        .scopes
        .get_mut(&authority_overflow.target_scope)
        .unwrap()
        .authority_epoch = u64::MAX;
    let before = authority_overflow.registry.clone();
    __cser_core::assert_eq!(
        authority_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(authority_overflow.registry, before);

    let mut revision_overflow = fixture.clone();
    revision_overflow
        .registry
        .scopes
        .get_mut(&revision_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = revision_overflow.registry.clone();
    __cser_core::assert_eq!(
        revision_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(revision_overflow.registry, before);

    let mut tampered = fixture.clone();
    let mut selection = tampered.begin().unwrap();
    selection.closed_authority_epoch += 1;
    let before = tampered.registry.clone();
    __cser_core::assert_eq!(
        tampered.registry.revoke_next(&selection),
        Err(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert_eq!(tampered.registry, before);

    let mut complete_overflow = fixture.prepare_complete_baseline().unwrap();
    complete_overflow
        .registry
        .scopes
        .get_mut(&complete_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = complete_overflow.registry.clone();
    __cser_core::assert_eq!(
        complete_overflow.complete(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(complete_overflow.registry, before);

    let mut terminal_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let selection = terminal_overflow.begin().unwrap();
    let effect = terminal_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap()
        .effect;
    terminal_overflow.registry.next_terminal_sequence = u64::MAX;
    let before = terminal_overflow.registry.clone();
    __cser_core::assert_eq!(
        terminal_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(terminal_overflow.registry, before);

    let mut publication_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *publication_overflow
        .registry
        .by_scope
        .get(&publication_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    publication_overflow
        .registry
        .effects
        .get_mut(&effect)
        .unwrap()
        .publication_mode = PublicationMode::Required;
    let selection = publication_overflow.begin().unwrap();
    publication_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap();
    publication_overflow.registry.next_publication_sequence = u64::MAX;
    let before = publication_overflow.registry.clone();
    __cser_core::assert_eq!(
        publication_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(publication_overflow.registry, before);

    let mut revision_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let selection = revision_overflow.begin().unwrap();
    let effect = revision_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap()
        .effect;
    revision_overflow
        .registry
        .scopes
        .get_mut(&revision_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = revision_overflow.registry.clone();
    __cser_core::assert_eq!(
        revision_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(revision_overflow.registry, before);

    let mut ack_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *ack_overflow
        .registry
        .by_scope
        .get(&ack_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    ack_overflow
        .registry
        .effects
        .get_mut(&effect)
        .unwrap()
        .publication_mode = PublicationMode::Required;
    let selection = ack_overflow.begin().unwrap();
    ack_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap();
    let ticket = ack_overflow
        .registry
        .stage_revoke_terminal(&selection, effect, TerminalRequest::aborted(-125))
        .unwrap()
        .publication
        .unwrap();
    __cser_core::assert_eq!(
        ack_overflow
            .target_projection()
            .unwrap()
            .pending_publications,
        1
    );
    ack_overflow
        .registry
        .scopes
        .get_mut(&ack_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = ack_overflow.registry.clone();
    __cser_core::assert_eq!(
        ack_overflow.registry.acknowledge_publication(&ticket),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(ack_overflow.registry, before);

    let mut commit_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *commit_overflow
        .registry
        .by_scope
        .get(&commit_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    let handle = commit_overflow.registry.effects[&effect].handle();
    let supervisor = TaskKey::new(0x7b01, 1);
    commit_overflow
        .registry
        .prepare(supervisor, handle)
        .unwrap();
    commit_overflow
        .registry
        .scopes
        .get_mut(&commit_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = commit_overflow.registry.clone();
    __cser_core::assert_eq!(
        commit_overflow
            .registry
            .commit(supervisor, handle, CommitMetadata::new(1, 1)),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(commit_overflow.registry, before);

    // Re-reading a selected head is idempotent: it neither skips the target
    // nor counts a second head selection.
    let mut duplicate =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 1 }).unwrap();
    let selection = duplicate.begin().unwrap();
    let first = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    let second = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(first, second);
    let work = duplicate
        .registry
        .revoke_work_projection(&selection)
        .unwrap();
    __cser_core::assert_eq!(work.next_calls, 2);
    __cser_core::assert_eq!(work.head_selections, 1);
    duplicate
        .registry
        .stage_revoke_terminal(&selection, first.effect, TerminalRequest::aborted(-125))
        .unwrap();
    __cser_core::assert!(
        duplicate
            .registry
            .revoke_next(&selection)
            .unwrap()
            .is_none()
    );
    duplicate.registry.revoke_complete(&selection).unwrap();
    duplicate.check_invariants().unwrap();

    // The same production methods are included by registry_loom.rs under a
    // modeled outer mutex. These sequential endpoints pin both linearization
    // outcomes before Loom explores their interleavings.
    let mut commit_first =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = commit_first.prepare_single_target().unwrap();
    __cser_core::assert!(__cser_core::matches!(
        commit_first.commit_single_target(handle).unwrap(),
        CommitOutcome::Applied(_)
    ));
    let selection = commit_first.begin().unwrap();
    commit_first.finish_revoke(&selection).unwrap();
    __cser_core::assert_eq!(
        commit_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Completed
    );
    let observation = commit_first.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.target.credits.free, 1);
    __cser_core::assert_eq!(observation.target.credits.held, 0);
    __cser_core::assert_eq!(observation.target.credits.committed, 0);
    commit_first.check_invariants().unwrap();

    let mut revoke_first =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = revoke_first.prepare_single_target().unwrap();
    let selection = revoke_first.begin().unwrap();
    revoke_first.finish_revoke(&selection).unwrap();
    __cser_core::assert_eq!(
        revoke_first.commit_single_target(handle),
        Err(RegistryError::StaleAuthority)
    );
    __cser_core::assert_eq!(
        revoke_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Aborted
    );
    let observation = revoke_first.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.target.credits.free, 1);
    __cser_core::assert_eq!(observation.target.credits.held, 0);
    __cser_core::assert_eq!(observation.target.credits.committed, 0);
    revoke_first.check_invariants().unwrap();
}

fn publication_ack_and_revoke_complete_self_test() {
    use __cser_core::cell::Cell;

    const SCOPE: ScopeKey = ScopeKey::new(0x1f00, 1);
    const SUPERVISOR: TaskKey = TaskKey::new(0x1f00, 1);
    const ROOT_TASK: TaskKey = TaskKey::new(0x1f01, 1);
    const CHILD_TASK: TaskKey = TaskKey::new(0x1f02, 1);
    const CREDIT: CreditClass = CreditClass::new(0x1f0);
    const CHILD_DOMAIN: DomainKey = DomainKey::new(1);

    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: SUPERVISOR,
            credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 2)],
        })
        .unwrap();
    registry
        .add_domain(
            SCOPE,
            DomainConfig {
                key: CHILD_DOMAIN,
                binding_epoch: 1,
                supervisor: SUPERVISOR,
            },
        )
        .unwrap();
    let root = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: ROOT_TASK,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(1, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x1f0, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    let child = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: CHILD_TASK,
                operation: OperationClass::new(2),
                descriptor: SyscallDescriptor::new(2, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x1f0, 2, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                publication: PublicationMode::Required,
            },
            domain: CHILD_DOMAIN,
            parent: Some(root.identity.effect()),
        })
        .unwrap();
    registry.prepare(SUPERVISOR, root.handle).unwrap();
    registry.prepare(SUPERVISOR, child.handle).unwrap();

    let selection = registry.revoke_begin(SCOPE).unwrap();
    let selected_child = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected_child.effect, child.identity.effect());
    let child_ticket = registry
        .stage_revoke_terminal(
            &selection,
            selected_child.effect,
            TerminalRequest::aborted(-125),
        )
        .unwrap()
        .publication
        .unwrap();
    let selected_root = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected_root.effect, root.identity.effect());
    let root_ticket = registry
        .stage_revoke_terminal(
            &selection,
            selected_root.effect,
            TerminalRequest::aborted(-125),
        )
        .unwrap()
        .publication
        .unwrap();
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.check_invariants().unwrap();

    let two_pending_before = registry.clone();
    let two_pending_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        registry.acknowledge_publication_and_revoke_complete_with_apply(
            &child_ticket,
            &selection,
            || two_pending_applies.set(1),
        ),
        Err(RegistryError::NotQuiescent)
    );
    __cser_core::assert_eq!(two_pending_applies.get(), 0);
    __cser_core::assert_eq!(registry, two_pending_before);

    registry.acknowledge_publication(&child_ticket).unwrap();
    registry.check_invariants().unwrap();
    let ready = registry.clone();

    let mut wrong_selection = selection.clone();
    wrong_selection.sequence = wrong_selection.sequence.checked_add(1).unwrap();
    let mut wrong = ready.clone();
    let wrong_before = wrong.clone();
    let wrong_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        wrong.acknowledge_publication_and_revoke_complete_with_apply(
            &root_ticket,
            &wrong_selection,
            || wrong_applies.set(1),
        ),
        Err(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert_eq!(wrong_applies.get(), 0);
    __cser_core::assert_eq!(wrong, wrong_before);

    let mut overflow = ready.clone();
    overflow.scopes.get_mut(&SCOPE).unwrap().revision = u64::MAX - 1;
    let overflow_before = overflow.clone();
    let overflow_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        overflow.acknowledge_publication_and_revoke_complete_with_apply(
            &root_ticket,
            &selection,
            || overflow_applies.set(1),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(overflow_applies.get(), 0);
    __cser_core::assert_eq!(overflow, overflow_before);

    let revision_before = registry.scopes[&SCOPE].revision;
    let successful_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        registry
            .acknowledge_publication_and_revoke_complete_with_apply(
                &root_ticket,
                &selection,
                || {
                    successful_applies.set(1);
                    0x51_u8
                },
            )
            .unwrap(),
        0x51
    );
    __cser_core::assert_eq!(successful_applies.get(), 1);
    __cser_core::assert_eq!(registry.scopes[&SCOPE].revision, revision_before + 2);
    let projection = registry.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(projection.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(projection.pending_publications, 0);
    __cser_core::assert_eq!(projection.credits.free, projection.credits.capacity);
    registry.check_invariants().unwrap();
}

#[cfg(test)]
fn combined_scope_candidate_self_test() {
    const TARGET: ScopeKey = ScopeKey::new(0xc051, 1);
    const UNRELATED: ScopeKey = ScopeKey::new(0xc052, 1);
    const TARGET_OWNER: TaskKey = TaskKey::new(0xc061, 1);
    const UNRELATED_OWNER: TaskKey = TaskKey::new(0xc062, 1);
    const TARGET_CREDIT: CreditClass = CreditClass::new(0xc071);
    const UNRELATED_CREDIT: CreditClass = CreditClass::new(0xc072);

    fn fixture() -> (EffectRegistry, EffectKey, EffectKey) {
        let mut registry = EffectRegistry::new();
        for (scope, owner, credit) in [
            (TARGET, TARGET_OWNER, TARGET_CREDIT),
            (UNRELATED, UNRELATED_OWNER, UNRELATED_CREDIT),
        ] {
            registry
                .create_scope(ScopeConfig {
                    key: scope,
                    authority_epoch: 7,
                    binding_epoch: 1,
                    supervisor: owner,
                    credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
                })
                .unwrap();
        }
        let target_root = registry
            .register(RegisterRequest {
                scope: TARGET,
                task: TARGET_OWNER,
                operation: OperationClass::new(0xc081),
                descriptor: SyscallDescriptor::new(0xc081, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xc081, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(TARGET_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        let unrelated_root = registry
            .register(RegisterRequest {
                scope: UNRELATED,
                task: UNRELATED_OWNER,
                operation: OperationClass::new(0xc082),
                descriptor: SyscallDescriptor::new(0xc082, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xc082, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(UNRELATED_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        let limits =
            infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4)
                .unwrap();
        registry
            .enable_infrastructure_for_scope(TARGET, target_root, limits)
            .unwrap();
        registry
            .enable_infrastructure_for_scope(UNRELATED, unrelated_root, limits)
            .unwrap();
        registry.check_invariants().unwrap();
        (registry, target_root, unrelated_root)
    }

    // The ordinary Registry invariant entry point, not only the combined
    // installer, recomputes infrastructure and checks the exact business
    // domain/lifecycle linkage.  Every rejection is observationally
    // read-only.
    let (mut wrong_domain_epoch, _, _) = fixture();
    wrong_domain_epoch
        .infrastructure
        .corrupt_domain_epoch_for_test(TARGET, DomainKey::LEGACY, 2);
    let before = wrong_domain_epoch.clone();
    __cser_core::assert!(__cser_core::matches!(
        wrong_domain_epoch.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(wrong_domain_epoch, before);

    let (mut extra_domain, _, _) = fixture();
    extra_domain
        .infrastructure
        .add_domain_for_test(TARGET, DomainKey::new(0xc0f0), 1);
    let before = extra_domain.clone();
    __cser_core::assert!(__cser_core::matches!(
        extra_domain.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(extra_domain, before);

    let (mut wrong_lifecycle, _, _) = fixture();
    wrong_lifecycle
        .infrastructure
        .set_closing_lifecycle_for_test(TARGET);
    let before = wrong_lifecycle.clone();
    __cser_core::assert!(__cser_core::matches!(
        wrong_lifecycle.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(wrong_lifecycle, before);

    // Active roots use the current epoch. Closing and revoked roots retain
    // the exact closed epoch while the business scope advances exactly once.
    let (mut closing, target_root, _) = fixture();
    __cser_core::assert_eq!(
        closing.query_scope_closure(TARGET).unwrap(),
        ScopeClosureProgress::Active
    );
    let selection = closing.revoke_begin(TARGET).unwrap();
    __cser_core::assert_eq!(
        closing.query_scope_closure(TARGET).unwrap(),
        ScopeClosureProgress::Closing(selection.clone())
    );
    closing.check_invariants().unwrap();

    let mut rolled_authority = closing.clone();
    rolled_authority
        .scopes
        .get_mut(&TARGET)
        .unwrap()
        .authority_epoch += 1;
    let before = rolled_authority.clone();
    __cser_core::assert!(__cser_core::matches!(
        rolled_authority.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(rolled_authority, before);

    let terminal = closing
        .stage_revoke_terminal(&selection, target_root, TerminalRequest::aborted(-125))
        .unwrap();
    __cser_core::assert!(terminal.publication.is_none());
    // The last member is terminal before revoke completion.  This is a legal
    // public Registry return state: the immutable infrastructure root remains
    // Closing while the business live index has already dropped the root.
    closing.check_invariants().unwrap();
    closing.revoke_complete(&selection).unwrap();
    let receipt = match closing.query_scope_closure(TARGET).unwrap() {
        ScopeClosureProgress::Closed(receipt) => receipt,
        progress => __cser_core::panic!("unexpected closure progress: {progress:?}"),
    };
    __cser_core::assert_eq!(receipt.revoke(), &selection);
    __cser_core::assert!(receipt.infrastructure().is_some());
    closing.verify_scope_closure(TARGET, &receipt).unwrap();
    __cser_core::assert_eq!(
        closing.query_scope_closure(TARGET).unwrap(),
        ScopeClosureProgress::Closed(receipt.clone())
    );
    let mut substituted = receipt.clone();
    substituted.closed_scope_revision += 1;
    __cser_core::assert_eq!(
        closing.verify_scope_closure(TARGET, &substituted),
        Err(RegistryError::InvalidRevokeSelection)
    );
    closing.check_invariants().unwrap();

    let mut selector_drift = closing.clone();
    selector_drift.revoke_begin(UNRELATED).unwrap();
    let unrelated_infrastructure = selector_drift.scopes[&UNRELATED]
        .revoke
        .as_ref()
        .unwrap()
        .infrastructure;
    selector_drift
        .scopes
        .get_mut(&TARGET)
        .unwrap()
        .revoke
        .as_mut()
        .unwrap()
        .infrastructure = unrelated_infrastructure;
    __cser_core::assert_eq!(
        selector_drift.verify_scope_closure(TARGET, &receipt),
        Err(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert!(__cser_core::matches!(
        selector_drift.check_invariants(),
        Err(RegistryError::Invariant(
            "infrastructure closure selector and receipt differ"
        ))
    ));

    let mut missing_infrastructure_owner = closing.clone();
    let target_revoke = missing_infrastructure_owner
        .scopes
        .get_mut(&TARGET)
        .unwrap()
        .revoke
        .as_mut()
        .unwrap();
    target_revoke.infrastructure = None;
    target_revoke.closure.as_mut().unwrap().infrastructure = None;
    let missing_owner_receipt = target_revoke.closure.clone().unwrap();
    __cser_core::assert_eq!(
        missing_infrastructure_owner.verify_scope_closure(TARGET, &missing_owner_receipt),
        Err(RegistryError::InvalidRevokeSelection)
    );

    let mut phase_drift = closing.clone();
    phase_drift.scopes.get_mut(&TARGET).unwrap().phase = ScopePhase::Active;
    __cser_core::assert_eq!(
        phase_drift.verify_scope_closure(TARGET, &receipt),
        Err(RegistryError::InvalidRevokeSelection)
    );

    // A live infrastructure obligation blocks the same final transition
    // without changing either ledger. The pre-revoke workload bearer remains
    // valid in Closing and drains without advancing a domain binding epoch.
    let (mut draining, target_root, _) = fixture();
    let workload = draining
        .infrastructure
        .open_workload(
            infrastructure::WorkloadRootPresentation::new(TARGET, 7, target_root),
            infrastructure::WorkloadRequestPresentation::new(DomainKey::LEGACY, 1, 0xc091, 1),
        )
        .unwrap();
    let domain_epoch = draining
        .infrastructure
        .scope_links()
        .find(|link| link.scope == TARGET)
        .unwrap()
        .domains[0]
        .1;
    let selection = draining.revoke_begin(TARGET).unwrap();
    draining
        .stage_revoke_terminal(&selection, target_root, TerminalRequest::aborted(-125))
        .unwrap();
    let before_blocked_finish = draining.clone();
    __cser_core::assert_eq!(
        draining.revoke_complete(&selection),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::ClosureBlocked {
                kind: infrastructure::InfrastructureKind::Workload,
                live: 1,
            }
        ))
    );
    __cser_core::assert_eq!(draining, before_blocked_finish);
    draining.infrastructure.close_workload(&workload).unwrap();
    __cser_core::assert_eq!(
        draining
            .infrastructure
            .scope_links()
            .find(|link| link.scope == TARGET)
            .unwrap()
            .domains[0]
            .1,
        domain_epoch
    );
    draining.revoke_complete(&selection).unwrap();
    __cser_core::assert!(__cser_core::matches!(
        draining.query_scope_closure(TARGET),
        Ok(ScopeClosureProgress::Closed(_))
    ));
    draining.check_invariants().unwrap();

    // A target business revision change after candidate construction fences
    // the exact-scope candidate.  The failed install leaves both ledgers and
    // the unrelated tenant byte-for-byte (including authority mode) intact.
    let (mut stale, _, _) = fixture();
    let stale_candidate = stale.combined_scope_candidate(TARGET).unwrap();
    stale.scopes.get_mut(&TARGET).unwrap().revision += 1;
    let before_stale_install = stale.clone();
    __cser_core::assert!(__cser_core::matches!(
        stale.prepare_combined_scope_install(stale_candidate),
        Err(RegistryError::CombinedCandidateStale),
    ));
    __cser_core::assert_eq!(stale, before_stale_install);
    __cser_core::assert!(stale.infrastructure.is_authoritative_for_test());

    // Every live reverse-index membership used by the final infallible
    // removal is checked before the first mutation. Internal damage therefore
    // returns a typed shape error instead of reaching remove_index_member's
    // TCB assertion midway through installation.
    let (mut damaged_live, target_root, _) = fixture();
    let mut revoked_candidate = damaged_live.scope_transaction_candidate(TARGET).unwrap();
    let selection = revoked_candidate.revoke_begin(TARGET).unwrap();
    revoked_candidate
        .stage_revoke_terminal(&selection, target_root, TerminalRequest::aborted(-125))
        .unwrap();
    revoked_candidate.revoke_complete(&selection).unwrap();
    damaged_live.by_task.remove(&TARGET_OWNER);
    let before_damaged_install = damaged_live.clone();
    __cser_core::assert_eq!(
        damaged_live.install_revoked_scope_candidate(TARGET, revoked_candidate),
        Err(RegistryError::CombinedCandidateShapeChanged)
    );
    __cser_core::assert_eq!(damaged_live, before_damaged_install);

    // The independent infrastructure base revision is fenced as well; a
    // business revision match cannot authorize an older infrastructure view.
    let (mut stale_infrastructure, _, _) = fixture();
    let stale_candidate = stale_infrastructure
        .combined_scope_candidate(TARGET)
        .unwrap();
    stale_infrastructure
        .infrastructure
        .advance_authoritative_scope_revision_for_test(TARGET);
    let before_stale_install = stale_infrastructure.clone();
    __cser_core::assert!(__cser_core::matches!(
        stale_infrastructure.prepare_combined_scope_install(stale_candidate),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::StaleAuthority
        )),
    ));
    __cser_core::assert_eq!(stale_infrastructure, before_stale_install);
    __cser_core::assert!(
        stale_infrastructure
            .infrastructure
            .is_authoritative_for_test()
    );

    // Infrastructure-side validation happens while live is untouched.
    let (invalid_infrastructure, _, _) = fixture();
    let mut candidate = invalid_infrastructure
        .combined_scope_candidate(TARGET)
        .unwrap();
    candidate
        .replacement
        .infrastructure
        .corrupt_candidate_sequence_for_test(TARGET);
    let before_invalid_infrastructure = invalid_infrastructure.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_infrastructure.prepare_combined_scope_install(candidate),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::Invariant(_)
        )),
    ));
    __cser_core::assert_eq!(invalid_infrastructure, before_invalid_infrastructure);
    __cser_core::assert!(
        invalid_infrastructure
            .infrastructure
            .is_authoritative_for_test()
    );

    // Root binding is part of the exact infrastructure identity, not a
    // caller-supplied scalar that can be rewritten inside a candidate.
    let (invalid_root, _, unrelated_root) = fixture();
    let mut candidate = invalid_root.combined_scope_candidate(TARGET).unwrap();
    candidate
        .replacement
        .infrastructure
        .corrupt_candidate_root_for_test(TARGET, unrelated_root);
    let before_invalid_root = invalid_root.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_root.prepare_combined_scope_install(candidate),
        Err(RegistryError::Invariant(_)),
    ));
    __cser_core::assert_eq!(invalid_root, before_invalid_root);

    // The business Registry's own invariant checker rejects a malformed
    // candidate before either authoritative scope is replaced.
    let (invalid_business, _, _) = fixture();
    let mut candidate = invalid_business.combined_scope_candidate(TARGET).unwrap();
    candidate.replacement.scopes.get_mut(&TARGET).unwrap().key = ScopeKey::new(0xc0ff, 1);
    let before_invalid_business = invalid_business.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_business.prepare_combined_scope_install(candidate),
        Err(RegistryError::Invariant(_)),
    ));
    __cser_core::assert_eq!(invalid_business, before_invalid_business);

    // A fallible staging step is also failure-atomic: no install plan exists
    // until the closure returns success and both validation gates pass.
    let (mut stage_failure, _, _) = fixture();
    let before_stage_failure = stage_failure.clone();
    __cser_core::assert_eq!(
        stage_failure.combined_scope_transaction(TARGET, |_| Err(RegistryError::InvalidState)),
        Err(RegistryError::InvalidState),
    );
    __cser_core::assert_eq!(stage_failure, before_stage_failure);

    // This foundation is deliberately shape-preserving.  A global allocator
    // or target EffectRecord change is rejected rather than partly installed.
    let (changed_shape, _, _) = fixture();
    let mut candidate = changed_shape.combined_scope_candidate(TARGET).unwrap();
    candidate.replacement.next_effect_id += 1;
    let before_changed_shape = changed_shape.clone();
    __cser_core::assert!(__cser_core::matches!(
        changed_shape.prepare_combined_scope_install(candidate),
        Err(RegistryError::CombinedCandidateShapeChanged),
    ));
    __cser_core::assert_eq!(changed_shape, before_changed_shape);

    // Success replaces exactly the target business scope and target
    // infrastructure scope.  Effect records, allocators, and the unrelated
    // business/infrastructure projections remain unchanged.
    let (mut success, target_root, unrelated_root) = fixture();
    let target_effect_before = success.effects[&target_root].clone();
    let unrelated_scope_before = success.scopes[&UNRELATED].clone();
    let unrelated_effect_before = success.effects[&unrelated_root].clone();
    let unrelated_infrastructure_before = success.infrastructure.root_binding(UNRELATED).unwrap();
    let target_registry_revision = success.scopes[&TARGET].revision;
    let target_infrastructure_revision = success
        .infrastructure
        .root_binding(TARGET)
        .unwrap()
        .revision;
    let allocator_projection = (
        success.next_effect_id,
        success.next_nonce,
        success.next_commit_sequence,
        success.next_terminal_sequence,
        success.next_publication_sequence,
        success.next_revoke_sequence,
    );
    success
        .combined_scope_transaction(TARGET, |editor| editor.advance_scope_revisions())
        .unwrap();
    __cser_core::assert_eq!(
        success.scopes[&TARGET].revision,
        target_registry_revision + 1
    );
    __cser_core::assert_eq!(
        success
            .infrastructure
            .root_binding(TARGET)
            .unwrap()
            .revision,
        target_infrastructure_revision + 1,
    );
    __cser_core::assert_eq!(success.effects[&target_root], target_effect_before);
    __cser_core::assert_eq!(success.scopes[&UNRELATED], unrelated_scope_before);
    __cser_core::assert_eq!(success.effects[&unrelated_root], unrelated_effect_before);
    __cser_core::assert_eq!(
        success.infrastructure.root_binding(UNRELATED).unwrap(),
        unrelated_infrastructure_before,
    );
    __cser_core::assert_eq!(
        (
            success.next_effect_id,
            success.next_nonce,
            success.next_commit_sequence,
            success.next_terminal_sequence,
            success.next_publication_sequence,
            success.next_revoke_sequence,
        ),
        allocator_projection,
    );
    __cser_core::assert!(success.infrastructure.is_authoritative_for_test());
    success.check_invariants().unwrap();
}

#[cfg(test)]
fn task_owned_fault_outer_transaction_self_test() {
    const SCOPE: ScopeKey = ScopeKey::new(0xfa01, 1);
    const SERVICE: DomainKey = DomainKey::new(0xfa);
    const ROOT_OWNER: TaskKey = TaskKey::new(0xfa10, 1);
    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfa11, 1);
    const CREDIT: CreditClass = CreditClass::new(0xfa20);
    const WORK_ID: u64 = 0xfa30;
    const FAULT_ID: u64 = 0xfa40;

    fn fixture(
        instance_bias: u64,
    ) -> (
        EffectRegistry,
        infrastructure::WorkloadContext,
        infrastructure::ArmedFaultTask,
        EffectKey,
    ) {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 2)],
            })
            .unwrap();
        registry
            .add_domain(
                SCOPE,
                DomainConfig {
                    key: SERVICE,
                    binding_epoch: 1,
                    supervisor: SERVICE_OWNER,
                },
            )
            .unwrap();
        let root = registry
            .register(RegisterRequest {
                scope: SCOPE,
                task: ROOT_OWNER,
                operation: OperationClass::new(0xfa21),
                descriptor: SyscallDescriptor::new(0xfa21, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xfa, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        let service_effect = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: SERVICE_OWNER,
                    operation: OperationClass::new(0xfa22),
                    descriptor: SyscallDescriptor::new(0xfa22, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0xfa, 2, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: SERVICE,
                parent: Some(root),
            })
            .unwrap()
            .identity
            .effect();
        registry
            .enable_infrastructure_for_scope(
                SCOPE,
                root,
                infrastructure::InfrastructureLimits::new(4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8)
                    .unwrap(),
            )
            .unwrap();
        let workload = registry
            .infrastructure
            .open_workload(
                infrastructure::WorkloadRootPresentation::new(SCOPE, 1, root),
                infrastructure::WorkloadRequestPresentation::new(
                    SERVICE,
                    1,
                    0xfa50 + instance_bias,
                    1,
                ),
            )
            .unwrap();
        let task = registry
            .infrastructure
            .admit_task(
                &workload,
                infrastructure::TaskWorkDescriptor {
                    work_id: WORK_ID + instance_bias,
                    generation: 1,
                    task: SERVICE_OWNER,
                    role: infrastructure::TaskWorkRole::ServiceRequest,
                    vm: Some(
                        infrastructure::VmAuthorityKey::new(0xfa60 + instance_bias, 1).unwrap(),
                    ),
                },
            )
            .unwrap();
        let reserved = registry
            .infrastructure
            .reserve_fault_event(
                task,
                infrastructure::FaultSlotDescriptor {
                    fault_id: FAULT_ID + instance_bias,
                    generation: 1,
                    task: SERVICE_OWNER,
                    vm_generation: 1,
                    service_domain: SERVICE,
                    admission_binding_epoch: 1,
                },
            )
            .unwrap();
        let armed = registry
            .infrastructure
            .claim_service_task_entry(reserved)
            .unwrap();
        registry.check_invariants().unwrap();
        (registry, workload, armed, service_effect)
    }

    let (mut stale, _, stale_armed, _) = fixture(0x200);
    let stale_observation = infrastructure::FaultObservation {
        task: SERVICE_OWNER,
        vm_generation: 1,
        instruction_pointer: 0xfc70,
        address: 0xfc80,
        access: infrastructure::FaultAccess::Write,
        architecture_error: 0xfc90,
        evidence_digest: 0xfca0,
    };
    let (stale_intent, stale_plan) = stale
        .prepare_service_fault_disposition(
            stale_armed,
            stale_observation,
            infrastructure::FaultDisposition::CrashService,
        )
        .unwrap();
    stale.scopes.get_mut(&SCOPE).unwrap().revision += 1;
    let stale_before = stale.clone();
    let stale_failure = stale
        .install_service_fault_disposition(stale_intent, stale_plan)
        .unwrap_err();
    __cser_core::assert_eq!(
        stale_failure.error(),
        &RegistryError::CombinedCandidateStale
    );
    __cser_core::assert_eq!(stale, stale_before);
    let returned_armed = stale_failure.into_input();
    __cser_core::assert!(
        stale
            .prepare_service_fault_disposition(
                returned_armed,
                stale_observation,
                infrastructure::FaultDisposition::CrashService,
            )
            .is_ok()
    );

    let (mut crash, crash_workload, crash_armed, service_effect) = fixture(0);
    let effects_before = crash.effects.clone();
    let (intent, plan) = crash
        .prepare_service_fault_disposition(
            crash_armed,
            infrastructure::FaultObservation {
                task: SERVICE_OWNER,
                vm_generation: 1,
                instruction_pointer: 0xfa70,
                address: 0xfa80,
                access: infrastructure::FaultAccess::Read,
                architecture_error: 0xfa90,
                evidence_digest: 0xfaa0,
            },
            infrastructure::FaultDisposition::CrashService,
        )
        .unwrap();
    let _lost_install_return = crash
        .install_service_fault_disposition(intent, plan)
        .unwrap();
    __cser_core::assert_eq!(crash.effects, effects_before);
    let binding = &crash.scopes[&SCOPE].domains[&SERVICE];
    __cser_core::assert_eq!(binding.binding_epoch, 2);
    __cser_core::assert_eq!(binding.supervisor, None);
    __cser_core::assert!(binding.fallback_running);
    let recovery = binding.recovery.as_ref().unwrap();
    __cser_core::assert_eq!(recovery.cohort, BTreeSet::from([service_effect]));
    __cser_core::assert_eq!(recovery.unadopted, recovery.cohort);
    __cser_core::assert!(__cser_core::matches!(
        recovery.origin,
        DomainRecoveryOrigin::ServiceFault(_)
    ));
    let mut missing_fault_origin = crash.clone();
    missing_fault_origin
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap()
        .recovery
        .as_mut()
        .unwrap()
        .origin = DomainRecoveryOrigin::SupervisorCrash;
    let before = missing_fault_origin.clone();
    __cser_core::assert_eq!(
        missing_fault_origin.check_invariants(),
        Err(RegistryError::Invariant("domain recovery origin mismatch"))
    );
    __cser_core::assert_eq!(missing_fault_origin, before);

    let mut zero_revision = crash.clone();
    zero_revision
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap()
        .recovery
        .as_mut()
        .unwrap()
        .crash_revision = 0;
    let before = zero_revision.clone();
    __cser_core::assert_eq!(
        zero_revision.check_invariants(),
        Err(RegistryError::Invariant("invalid domain recovery state"))
    );
    __cser_core::assert_eq!(zero_revision, before);

    let mut synchronized_zero_origin = crash.clone();
    let binding = synchronized_zero_origin
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap();
    let recovery = binding.recovery.as_mut().unwrap();
    recovery.crash_revision = 0;
    recovery.origin = DomainRecoveryOrigin::SupervisorCrash;
    let before = synchronized_zero_origin.clone();
    __cser_core::assert_eq!(
        synchronized_zero_origin.check_invariants(),
        Err(RegistryError::Invariant("invalid domain recovery state"))
    );
    __cser_core::assert_eq!(synchronized_zero_origin, before);

    let mut wrong_nonzero_revision = crash.clone();
    let binding = wrong_nonzero_revision
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap();
    binding.revision = 2;
    binding.recovery.as_mut().unwrap().crash_revision = 2;
    let before = wrong_nonzero_revision.clone();
    __cser_core::assert_eq!(
        wrong_nonzero_revision.check_invariants(),
        Err(RegistryError::Invariant(
            "domain fault recovery anchor mismatch"
        ))
    );
    __cser_core::assert_eq!(wrong_nonzero_revision, before);

    let mut synchronized_wrong_nonzero_origin = crash.clone();
    let binding = synchronized_wrong_nonzero_origin
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap();
    binding.revision = 2;
    let recovery = binding.recovery.as_mut().unwrap();
    recovery.crash_revision = 2;
    recovery.origin = DomainRecoveryOrigin::SupervisorCrash;
    let before = synchronized_wrong_nonzero_origin.clone();
    __cser_core::assert_eq!(
        synchronized_wrong_nonzero_origin.check_invariants(),
        Err(RegistryError::Invariant("domain recovery origin mismatch"))
    );
    __cser_core::assert_eq!(synchronized_wrong_nonzero_origin, before);

    type MutateAnchor = fn(&mut DomainFaultRecoveryAnchor);
    let anchor_mutations: &[MutateAnchor] = &[
        |anchor| anchor.fault_id += 1,
        |anchor| anchor.generation += 1,
        |anchor| anchor.task = TaskKey::new(anchor.task.id() + 1, anchor.task.generation()),
        |anchor| anchor.vm_generation += 1,
        |anchor| anchor.evidence_digest += 1,
        |anchor| anchor.plan_commitment[0] ^= 1,
    ];
    for mutate in anchor_mutations {
        let mut corrupt = crash.clone();
        let recovery = corrupt
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .domains
            .get_mut(&SERVICE)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap();
        let DomainRecoveryOrigin::ServiceFault(anchor) = &mut recovery.origin else {
            __cser_core::panic!("fault crash changed recovery origin")
        };
        mutate(anchor);
        let before = corrupt.clone();
        __cser_core::assert_eq!(
            corrupt.check_invariants(),
            Err(RegistryError::Invariant(
                "domain fault recovery anchor mismatch"
            ))
        );
        __cser_core::assert_eq!(corrupt, before);
    }
    let recovery_projection = crash
        .infrastructure
        .query_fault(&crash_workload, FAULT_ID, 1)
        .unwrap();
    __cser_core::assert!(recovery_projection.awaiting_claim);
    let installed = recovery_projection
        .selector
        .expect("awaiting fault exposes a descriptive recovery selector");

    type MutateSelector = fn(&mut infrastructure::InstalledFaultProjection);
    let selector_mutations: &[MutateSelector] = &[
        |installed| installed.projection.fault_id += 1,
        |installed| installed.projection.generation += 1,
        |installed| {
            installed.projection.task = TaskKey::new(
                installed.projection.task.id() + 1,
                installed.projection.task.generation(),
            )
        },
        |installed| installed.projection.vm_generation += 1,
        |installed| {
            installed.projection.disposition = infrastructure::FaultDisposition::IsolateTask
        },
        |installed| {
            installed.projection.service_domain =
                DomainKey::new(installed.projection.service_domain.value() + 1)
        },
        |installed| installed.projection.closed_binding_epoch += 1,
        |installed| installed.projection.crash_generation += 1,
        |installed| installed.projection.evidence_digest += 1,
        |installed| installed.commitment.0[0] ^= 1,
    ];
    for mutate in selector_mutations {
        let mut substituted = installed;
        let projection = match &mut substituted {
            infrastructure::InstalledFaultObservation::Crash(projection)
            | infrastructure::InstalledFaultObservation::Isolate(projection) => projection,
        };
        mutate(projection);
        let awaiting_before = crash.infrastructure.private_full_clone();
        __cser_core::assert!(
            crash
                .infrastructure
                .claim_fault_receipt(&crash_workload, substituted)
                .is_err()
        );
        __cser_core::assert_eq!(crash.infrastructure, awaiting_before);
    }
    let projection = match installed {
        infrastructure::InstalledFaultObservation::Crash(projection) => projection,
        infrastructure::InstalledFaultObservation::Isolate(_) => {
            __cser_core::panic!("crash recovery selector has isolate variant")
        }
    };
    let awaiting_before = crash.infrastructure.private_full_clone();
    __cser_core::assert_eq!(
        crash.infrastructure.claim_fault_receipt(
            &crash_workload,
            infrastructure::InstalledFaultObservation::Isolate(projection),
        ),
        Err(infrastructure::InfrastructureError::InvalidReceipt)
    );
    __cser_core::assert_eq!(crash.infrastructure, awaiting_before);
    let receipt = match crash
        .infrastructure
        .claim_fault_receipt(&crash_workload, installed)
        .unwrap()
    {
        infrastructure::FaultReceiptClaimOutcome::Crash(receipt) => receipt,
        _ => __cser_core::panic!("crash install minted the wrong typed receipt"),
    };
    let claimed_before_duplicate = crash.infrastructure.private_full_clone();
    __cser_core::assert!(__cser_core::matches!(
        crash
            .infrastructure
            .claim_fault_receipt(&crash_workload, installed)
            .unwrap(),
        infrastructure::FaultReceiptClaimOutcome::AlreadyClaimed(
            infrastructure::FaultClaimProjection::Crash(_)
        )
    ));
    __cser_core::assert_eq!(crash.infrastructure, claimed_before_duplicate);
    let _cause = crash.infrastructure.consume_service_fault(receipt).unwrap();
    crash.check_invariants().unwrap();

    let (mut isolate, isolate_workload, isolate_armed, _) = fixture(0x100);
    let business_before = isolate.scopes[&SCOPE].clone();
    let effects_before = isolate.effects.clone();
    let (intent, plan) = isolate
        .prepare_service_fault_disposition(
            isolate_armed,
            infrastructure::FaultObservation {
                task: SERVICE_OWNER,
                vm_generation: 1,
                instruction_pointer: 0xfb70,
                address: 0xfb80,
                access: infrastructure::FaultAccess::Execute,
                architecture_error: 0xfb90,
                evidence_digest: 0xfba0,
            },
            infrastructure::FaultDisposition::IsolateTask,
        )
        .unwrap();
    let installed = isolate
        .install_service_fault_disposition(intent, plan)
        .unwrap();
    __cser_core::assert_eq!(isolate.scopes[&SCOPE], business_before);
    __cser_core::assert_eq!(isolate.effects, effects_before);
    __cser_core::assert!(__cser_core::matches!(
        isolate
            .infrastructure
            .claim_fault_receipt(&isolate_workload, installed)
            .unwrap(),
        infrastructure::FaultReceiptClaimOutcome::Isolate(_)
    ));
    isolate.check_invariants().unwrap();
}

#[cfg(test)]
fn ordinary_domain_crash_rejects_a_forged_fault_origin() {
    const SCOPE: ScopeKey = ScopeKey::new(0xfd01, 1);
    const SERVICE: DomainKey = DomainKey::new(0xfd);
    const ROOT_OWNER: TaskKey = TaskKey::new(0xfd10, 1);
    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfd11, 1);

    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: ROOT_OWNER,
            credits: __cser_alloc::vec![CreditLimit::new(CreditClass::new(0xfd20), 1)],
        })
        .unwrap();
    registry
        .add_domain(
            SCOPE,
            DomainConfig {
                key: SERVICE,
                binding_epoch: 1,
                supervisor: SERVICE_OWNER,
            },
        )
        .unwrap();
    let root = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: SERVICE_OWNER,
                operation: OperationClass::new(0xfd30),
                descriptor: SyscallDescriptor::new(0xfd30, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CreditClass::new(0xfd20), 1)],
                publication: PublicationMode::None,
            },
            domain: SERVICE,
            parent: None,
        })
        .unwrap();
    registry.prepare(SERVICE_OWNER, root.handle).unwrap();
    registry
        .enable_infrastructure_for_scope(
            SCOPE,
            root.identity.effect(),
            infrastructure::InfrastructureLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2)
                .unwrap(),
        )
        .unwrap();
    registry
        .crash_domain(SCOPE, SERVICE, SERVICE_OWNER)
        .unwrap();
    registry.check_invariants().unwrap();
    let service_epoch = registry
        .infrastructure
        .scope_links()
        .find(|link| link.scope == SCOPE)
        .unwrap()
        .domains
        .iter()
        .find_map(|(domain, epoch)| (*domain == SERVICE).then_some(*epoch));
    __cser_core::assert_eq!(service_epoch, Some(2));
    __cser_core::assert_eq!(
        registry.scopes[&SCOPE].domains[&SERVICE]
            .recovery
            .as_ref()
            .unwrap()
            .origin,
        DomainRecoveryOrigin::SupervisorCrash
    );

    let mut forged = registry.clone();
    let recovery = forged
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .domains
        .get_mut(&SERVICE)
        .unwrap()
        .recovery
        .as_mut()
        .unwrap();
    recovery.origin = DomainRecoveryOrigin::ServiceFault(DomainFaultRecoveryAnchor {
        fault_id: 0xfd40,
        generation: 1,
        task: SERVICE_OWNER,
        vm_generation: 1,
        evidence_digest: 0xfd50,
        plan_commitment: [0xfd; 32],
    });
    let before = forged.clone();
    __cser_core::assert_eq!(
        forged.check_invariants(),
        Err(RegistryError::Invariant("domain recovery origin mismatch"))
    );
    __cser_core::assert_eq!(forged, before);
}

#[cfg(test)]
fn device_preparation_outer_credit_self_test() {
    const SCOPE: ScopeKey = ScopeKey::new(0xdb01, 1);
    const OWNER: TaskKey = TaskKey::new(0xdb02, 1);
    const UNRELATED_SCOPE: ScopeKey = ScopeKey::new(0xdb03, 1);
    const UNRELATED_OWNER: TaskKey = TaskKey::new(0xdb04, 1);
    const QUEUE: CreditClass = CreditClass::new(0xdb10);
    const PINNED: CreditClass = CreditClass::new(0xdb11);
    const DMA: CreditClass = CreditClass::new(0xdb12);

    fn fixture(
        request_id: u64,
    ) -> (
        EffectRegistry,
        infrastructure::WorkloadContext,
        EffectKey,
        infrastructure::DeviceReservationCoordinates,
    ) {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: OWNER,
                credits: __cser_alloc::vec![
                    CreditLimit::new(QUEUE, 1),
                    CreditLimit::new(PINNED, 3),
                    CreditLimit::new(DMA, 3),
                ],
            })
            .unwrap();
        let root = registry
            .register(RegisterRequest {
                scope: SCOPE,
                task: OWNER,
                operation: OperationClass::new(0xdb20),
                descriptor: SyscallDescriptor::new(0xdb20, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xdb, 1, 1)],
                credits: __cser_alloc::vec![],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        registry
            .enable_infrastructure_for_scope(
                SCOPE,
                root,
                infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 8)
                    .unwrap(),
            )
            .unwrap();
        let workload = registry
            .infrastructure
            .open_workload(
                infrastructure::WorkloadRootPresentation::new(SCOPE, 1, root),
                infrastructure::WorkloadRequestPresentation::new(
                    DomainKey::LEGACY,
                    1,
                    request_id,
                    1,
                ),
            )
            .unwrap();
        registry
            .create_scope(ScopeConfig {
                key: UNRELATED_SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: UNRELATED_OWNER,
                credits: __cser_alloc::vec![],
            })
            .unwrap();
        let unrelated_root = registry
            .register(RegisterRequest {
                scope: UNRELATED_SCOPE,
                task: UNRELATED_OWNER,
                operation: OperationClass::new(0xdb21),
                descriptor: SyscallDescriptor::new(0xdb21, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xdb, 2, 1)],
                credits: __cser_alloc::vec![],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        registry
            .enable_infrastructure_for_scope(
                UNRELATED_SCOPE,
                unrelated_root,
                infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 8)
                    .unwrap(),
            )
            .unwrap();
        let coordinates = infrastructure::DeviceReservationCoordinates {
            preparation_id: request_id + 1,
            generation: 1,
            owned_device: ResourceKey::new(0xdb, request_id, 1),
            queue: 2,
            device_generation: 1,
            operation_digest: request_id + 2,
            queue_credit_class: QUEUE,
            pinned_credit_class: PINNED,
            dma_credit_class: DMA,
            actor_slot: 1,
            actor_generation: 1,
        };
        registry.check_invariants().unwrap();
        (registry, workload, root, coordinates)
    }

    let (mut cancelled, workload, root, coordinates) = fixture(0xdb30);
    let unrelated_business = cancelled.scopes[&UNRELATED_SCOPE].clone();
    let unrelated_infrastructure = cancelled
        .infrastructure
        .root_binding(UNRELATED_SCOPE)
        .unwrap();
    let ticket = cancelled
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let held = cancelled.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((held.free, held.held, held.retained), (0, 7, 0));
    let duplicate_before = cancelled.clone();
    __cser_core::assert_eq!(
        cancelled.reserve_device_preparation(&workload, root, coordinates),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::ExactReplay
        ))
    );
    __cser_core::assert_eq!(cancelled, duplicate_before);
    cancelled.cancel_device_preparation(ticket).unwrap();
    let released = cancelled.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((released.free, released.held, released.retained), (7, 0, 0));
    __cser_core::assert_eq!(cancelled.scopes[&UNRELATED_SCOPE], unrelated_business);
    __cser_core::assert_eq!(
        cancelled
            .infrastructure
            .root_binding(UNRELATED_SCOPE)
            .unwrap(),
        unrelated_infrastructure
    );
    cancelled.check_invariants().unwrap();

    // Revocation wins admission. A Closing scope reports the lifecycle error
    // before reinterpreting its old parent authority as an invalid handle.
    let (mut reserve_closing, workload, root, coordinates) = fixture(0xdb31);
    let selection = reserve_closing.revoke_begin(SCOPE).unwrap();
    __cser_core::assert_eq!(
        reserve_closing.query_scope_closure(SCOPE).unwrap(),
        ScopeClosureProgress::Closing(selection)
    );
    reserve_closing.check_invariants().unwrap();
    let closing_before = reserve_closing.clone();
    __cser_core::assert_eq!(
        reserve_closing.reserve_device_preparation(&workload, root, coordinates),
        Err(RegistryError::ScopeNotActive)
    );
    __cser_core::assert_eq!(reserve_closing, closing_before);

    // A preparation which lost the revoke race remains a linear Reserved
    // owner. Closing may cancel and drain it, but cannot begin new hardware
    // exposure; the rejected begin returns the exact ticket without mutation.
    let (mut revoke_first, workload, root, coordinates) = fixture(0xdb32);
    let ticket = revoke_first
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let selection = revoke_first.revoke_begin(SCOPE).unwrap();
    __cser_core::assert_eq!(
        revoke_first.query_scope_closure(SCOPE).unwrap(),
        ScopeClosureProgress::Closing(selection)
    );
    revoke_first.check_invariants().unwrap();
    let closing_before = revoke_first.clone();
    let failure = revoke_first
        .begin_device_hardware_apply(ticket)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &RegistryError::ScopeNotActive);
    __cser_core::assert_eq!(revoke_first, closing_before);
    let ticket = failure.into_input();
    __cser_core::assert_eq!(
        (ticket.preparation_id(), ticket.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    let projection = revoke_first
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::Reserved
    );
    let held = revoke_first.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((held.free, held.held, held.retained), (0, 7, 0));
    revoke_first.cancel_device_preparation(ticket).unwrap();
    let projection = revoke_first
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::Cancelled
    );
    let released = revoke_first.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((released.free, released.held, released.retained), (7, 0, 0));
    revoke_first.check_invariants().unwrap();

    // Candidate staging borrows the sole input bearer. A rejected install
    // therefore returns no candidate authority and leaves the exact original
    // key valid for the unchanged live Reserved record.
    let (mut stale_install, workload, root, coordinates) = fixture(0xdb35);
    let ticket = stale_install
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let charges = coordinates.credit_charges();
    let mut candidate = stale_install.combined_scope_candidate(SCOPE).unwrap();
    let prepared = candidate
        .replacement
        .infrastructure
        .prepare_begin_device_hardware_apply_in_candidate(&ticket)
        .unwrap();
    let candidate_scope = candidate.replacement.scopes.get_mut(&SCOPE).unwrap();
    candidate_scope
        .credits
        .validate_retain(&charges, CreditState::Held)
        .unwrap();
    candidate_scope
        .credits
        .retain_validated(&charges, CreditState::Held);
    advance_device_preparation_scope(candidate_scope).unwrap();
    candidate
        .replacement
        .infrastructure
        .apply_begin_device_hardware_apply_in_candidate(prepared);
    candidate.base_registry_revision += 1;
    __cser_core::assert!(__cser_core::matches!(
        stale_install.prepare_combined_scope_install(candidate),
        Err(RegistryError::CombinedCandidateStale)
    ));
    __cser_core::assert_eq!(
        stale_install
            .query_device_preparation(
                &workload,
                coordinates.preparation_id,
                coordinates.generation,
            )
            .unwrap()
            .state,
        infrastructure::DevicePreparationRecoveryState::Reserved
    );
    stale_install.cancel_device_preparation(ticket).unwrap();

    let (mut cancel_overflow, workload, root, coordinates) = fixture(0xdb38);
    let ticket = cancel_overflow
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    cancel_overflow.scopes.get_mut(&SCOPE).unwrap().revision = u64::MAX;
    let failure = cancel_overflow
        .cancel_device_preparation(ticket)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &RegistryError::CounterOverflow);
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(
        cancel_overflow
            .query_device_preparation(
                &workload,
                coordinates.preparation_id,
                coordinates.generation,
            )
            .unwrap()
            .state,
        infrastructure::DevicePreparationRecoveryState::Reserved
    );

    let (mut rolled_back, workload, root, coordinates) = fixture(0xdb40);
    let ticket = rolled_back
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let intent = rolled_back.begin_device_hardware_apply(ticket).unwrap();
    let retained = rolled_back.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((retained.free, retained.held, retained.retained), (0, 0, 7));
    let projection = rolled_back
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::ApplyingHardware
    );
    __cser_core::assert_eq!(
        projection.credit_ownership,
        infrastructure::DevicePreparationCreditOwnership::RetainedByPreparation
    );
    let rollback = infrastructure::model_device_rollback_receipt(coordinates, 0xdb50);
    let mut wrong_coordinates = coordinates;
    wrong_coordinates.actor_generation += 1;
    let wrong_actor = infrastructure::model_device_rollback_receipt(wrong_coordinates, 0xdb50);
    let wrong_before = rolled_back.clone();
    let failure = rolled_back
        .acknowledge_device_apply_rollback(intent, wrong_actor)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &RegistryError::Infrastructure(infrastructure::InfrastructureError::InvalidReceipt)
    );
    __cser_core::assert_eq!(rolled_back, wrong_before);
    rolled_back
        .acknowledge_device_apply_rollback(failure.into_input(), rollback)
        .unwrap();
    let released = rolled_back.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((released.free, released.held, released.retained), (7, 0, 0));
    rolled_back.check_invariants().unwrap();

    let (mut rollback_overflow, workload, root, coordinates) = fixture(0xdb55);
    let ticket = rollback_overflow
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let intent = rollback_overflow
        .begin_device_hardware_apply(ticket)
        .unwrap();
    rollback_overflow.scopes.get_mut(&SCOPE).unwrap().revision = u64::MAX;
    let rollback = infrastructure::model_device_rollback_receipt(coordinates, 0xdb56);
    let failure = rollback_overflow
        .acknowledge_device_apply_rollback(intent, rollback)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &RegistryError::CounterOverflow);
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(
        rollback_overflow
            .query_device_preparation(
                &workload,
                coordinates.preparation_id,
                coordinates.generation,
            )
            .unwrap()
            .state,
        infrastructure::DevicePreparationRecoveryState::ApplyingHardware
    );

    let (mut uncertain, workload, root, coordinates) = fixture(0xdb60);
    let ticket = uncertain
        .reserve_device_preparation(&workload, root, coordinates)
        .unwrap();
    let intent = uncertain.begin_device_hardware_apply(ticket).unwrap();
    let device = DeviceEnvelope::new(0xdb70, coordinates.queue, 9, 1).unwrap();
    let receipt = infrastructure::model_device_hardware_receipt(coordinates, device, 0xdb71);
    let mut wrong_coordinates = coordinates;
    wrong_coordinates.actor_generation += 1;
    let wrong_actor =
        infrastructure::model_device_hardware_receipt(wrong_coordinates, device, 0xdb71);
    let wrong_before = uncertain.clone();
    let failure = uncertain
        .acknowledge_device_prepared(intent, wrong_actor)
        .unwrap_err();
    __cser_core::assert_eq!(uncertain, wrong_before);
    let ticket = uncertain
        .acknowledge_device_prepared(failure.into_input(), receipt)
        .unwrap();
    let projection = uncertain
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::PreparedRetained
    );
    __cser_core::assert_eq!(
        projection.credit_ownership,
        infrastructure::DevicePreparationCreditOwnership::RetainedByPreparation
    );
    __cser_core::assert_eq!(
        (ticket.preparation_id(), ticket.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    let selection = uncertain.revoke_begin(SCOPE).unwrap();
    __cser_core::assert_eq!(
        uncertain.query_scope_closure(SCOPE).unwrap(),
        ScopeClosureProgress::Retained(selection)
    );
    uncertain.check_invariants().unwrap();
}

#[cfg(test)]
fn device_preparation_outer_materialization_self_test() {
    const SCOPE: ScopeKey = ScopeKey::new(0xdc01, 1);
    const OWNER: TaskKey = TaskKey::new(0xdc02, 1);
    const ADAPTER: TaskKey = TaskKey::new(0xdc03, 1);
    const ADAPTER_DOMAIN: DomainKey = DomainKey::new(0xdc04);
    const UNRELATED_SCOPE: ScopeKey = ScopeKey::new(0xdc05, 1);
    const UNRELATED_OWNER: TaskKey = TaskKey::new(0xdc06, 1);
    const QUEUE: CreditClass = CreditClass::new(0xdc10);
    const PINNED: CreditClass = CreditClass::new(0xdc11);
    const DMA: CreditClass = CreditClass::new(0xdc12);

    fn fixture(
        request_id: u64,
    ) -> (
        EffectRegistry,
        infrastructure::WorkloadContext,
        infrastructure::PreparedDeviceTicket,
        infrastructure::PreparedDeviceIdentity,
        [DeviceDerivedCohortEntry; 4],
        infrastructure::DeviceReservationCoordinates,
    ) {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: OWNER,
                // Deliberate spare capacity proves materialization does not
                // release and reserve substitute credits from `free`.
                credits: __cser_alloc::vec![
                    CreditLimit::new(QUEUE, 2),
                    CreditLimit::new(PINNED, 6),
                    CreditLimit::new(DMA, 6),
                ],
            })
            .unwrap();
        registry
            .add_domain(
                SCOPE,
                DomainConfig {
                    key: ADAPTER_DOMAIN,
                    binding_epoch: 1,
                    supervisor: ADAPTER,
                },
            )
            .unwrap();
        let root = registry
            .register(RegisterRequest {
                scope: SCOPE,
                task: OWNER,
                operation: OperationClass::new(0xdc20),
                descriptor: SyscallDescriptor::new(0xdc20, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xdc, 1, 1)],
                credits: __cser_alloc::vec![],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        registry
            .enable_infrastructure_for_scope(
                SCOPE,
                root,
                infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 8)
                    .unwrap(),
            )
            .unwrap();
        let workload = registry
            .infrastructure
            .open_workload(
                infrastructure::WorkloadRootPresentation::new(SCOPE, 1, root),
                infrastructure::WorkloadRequestPresentation::new(
                    DomainKey::LEGACY,
                    1,
                    request_id,
                    1,
                ),
            )
            .unwrap();

        registry
            .create_scope(ScopeConfig {
                key: UNRELATED_SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: UNRELATED_OWNER,
                credits: __cser_alloc::vec![],
            })
            .unwrap();
        let unrelated_root = registry
            .register(RegisterRequest {
                scope: UNRELATED_SCOPE,
                task: UNRELATED_OWNER,
                operation: OperationClass::new(0xdc21),
                descriptor: SyscallDescriptor::new(0xdc21, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xdc, request_id, 1)],
                credits: __cser_alloc::vec![],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        registry
            .enable_infrastructure_for_scope(
                UNRELATED_SCOPE,
                unrelated_root,
                infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 8)
                    .unwrap(),
            )
            .unwrap();

        let block_descriptor =
            SyscallDescriptor::new(0xdc30, [request_id as usize, 0, 512, 0, 0, 0]);
        let owned_device = ResourceKey::new(0xdc40, request_id, 1);
        let device = DeviceEnvelope::new(request_id + 0x100, 2, 9, 1).unwrap();
        let coordinates = infrastructure::DeviceReservationCoordinates {
            preparation_id: request_id + 1,
            generation: 1,
            owned_device,
            queue: device.queue(),
            device_generation: device.device_generation(),
            operation_digest: block_descriptor.digest(),
            queue_credit_class: QUEUE,
            pinned_credit_class: PINNED,
            dma_credit_class: DMA,
            actor_slot: 3,
            actor_generation: 7,
        };
        let ticket = registry
            .reserve_device_preparation(&workload, root, coordinates)
            .unwrap();
        let intent = registry.begin_device_hardware_apply(ticket).unwrap();
        let hardware =
            infrastructure::model_device_hardware_receipt(coordinates, device, request_id + 0x200);
        let ticket = registry
            .acknowledge_device_prepared(intent, hardware)
            .unwrap();
        let prepared =
            infrastructure::model_prepared_device_identity(coordinates, device, request_id + 0x200);
        let dma_entry =
            |batch_index: usize, operation: u32, resource_id: u64| DeviceDerivedCohortEntry {
                batch_index,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: ADAPTER,
                    operation: OperationClass::new(operation),
                    descriptor: SyscallDescriptor::new(operation as usize, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0xdc41, resource_id, 1)],
                    credits: __cser_alloc::vec![
                        CreditCharge::new(PINNED, 1),
                        CreditCharge::new(DMA, 1),
                    ],
                    publication: PublicationMode::None,
                },
                domain: ADAPTER_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            };
        let entries = [
            DeviceDerivedCohortEntry {
                batch_index: 0,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: ADAPTER,
                    operation: OperationClass::new(0xdc30),
                    descriptor: block_descriptor,
                    resources: __cser_alloc::vec![owned_device],
                    credits: __cser_alloc::vec![CreditCharge::new(QUEUE, 1)],
                    publication: PublicationMode::None,
                },
                domain: ADAPTER_DOMAIN,
                parent: DeviceCohortParent::Existing(root),
                device,
            },
            dma_entry(1, 0xdc31, request_id + 1),
            dma_entry(2, 0xdc32, request_id + 2),
            dma_entry(3, 0xdc33, request_id + 3),
        ];
        registry.check_invariants().unwrap();
        (registry, workload, ticket, prepared, entries, coordinates)
    }

    fn assert_prepared_retained(
        registry: &EffectRegistry,
        workload: &infrastructure::WorkloadContext,
        coordinates: infrastructure::DeviceReservationCoordinates,
    ) {
        let projection = registry
            .query_device_preparation(workload, coordinates.preparation_id, coordinates.generation)
            .unwrap();
        __cser_core::assert_eq!(
            projection.state,
            infrastructure::DevicePreparationRecoveryState::PreparedRetained
        );
        __cser_core::assert_eq!(
            projection.credit_ownership,
            infrastructure::DevicePreparationCreditOwnership::RetainedByPreparation
        );
        let credits = registry.scope_projection(SCOPE).unwrap().credits;
        __cser_core::assert_eq!((credits.free, credits.held, credits.retained), (7, 0, 7));
    }

    fn assert_unrelated_unchanged(before: &EffectRegistry, after: &EffectRegistry) {
        __cser_core::assert_eq!(
            before.scopes[&UNRELATED_SCOPE],
            after.scopes[&UNRELATED_SCOPE]
        );
        __cser_core::assert_eq!(
            before.by_scope.get(&UNRELATED_SCOPE),
            after.by_scope.get(&UNRELATED_SCOPE)
        );
        __cser_core::assert_eq!(
            before.by_task.get(&UNRELATED_OWNER),
            after.by_task.get(&UNRELATED_OWNER)
        );
        for effect in &before.by_scope[&UNRELATED_SCOPE] {
            __cser_core::assert_eq!(before.effects[effect], after.effects[effect]);
        }
        __cser_core::assert!(
            after
                .infrastructure
                .scope_state_eq_for_test(&before.infrastructure, UNRELATED_SCOPE)
        );
    }

    enum RejectCase {
        Preparation,
        PreparationGeneration,
        ActorSlot,
        ActorGeneration,
        HardwareDigest,
        OwnedDevice,
        OperationDigest,
        CreditClass,
        CreditDuplicate,
        CreditExtra,
        DeviceSession,
        DeviceQueue,
        DescriptorToken,
        DeviceGeneration,
        Domain,
        Task,
        CohortSlot,
        Parent,
        MiddleRegistration,
    }

    fn reject_case(request_id: u64, case: RejectCase) {
        let (mut registry, workload, ticket, mut prepared, mut entries, coordinates) =
            fixture(request_id);
        match case {
            RejectCase::Preparation => prepared.preparation_id += 1,
            RejectCase::PreparationGeneration => prepared.preparation_generation += 1,
            RejectCase::ActorSlot => prepared.actor_slot += 1,
            RejectCase::ActorGeneration => prepared.actor_generation += 1,
            RejectCase::HardwareDigest => prepared.hardware_receipt_digest += 1,
            RejectCase::OwnedDevice => {
                prepared.owned_device = ResourceKey::new(0xdc40, request_id + 1, 1);
            }
            RejectCase::OperationDigest => prepared.operation_digest += 1,
            RejectCase::CreditClass => {
                entries[1].request.credits[0] = CreditCharge::new(QUEUE, 1);
            }
            RejectCase::CreditDuplicate => {
                entries[1].request.credits[1] = CreditCharge::new(PINNED, 1);
            }
            RejectCase::CreditExtra => {
                entries[1].request.credits.push(CreditCharge::new(QUEUE, 1));
            }
            RejectCase::DeviceSession => {
                entries[2].device = DeviceEnvelope::new(
                    prepared.device.device_session() + 1,
                    prepared.device.queue(),
                    prepared.device.descriptor_token(),
                    prepared.device.device_generation(),
                )
                .unwrap();
            }
            RejectCase::DeviceQueue => {
                entries[2].device = DeviceEnvelope::new(
                    prepared.device.device_session(),
                    prepared.device.queue() + 1,
                    prepared.device.descriptor_token(),
                    prepared.device.device_generation(),
                )
                .unwrap();
            }
            RejectCase::DescriptorToken => {
                entries[2].device = DeviceEnvelope::new(
                    prepared.device.device_session(),
                    prepared.device.queue(),
                    prepared.device.descriptor_token() + 1,
                    prepared.device.device_generation(),
                )
                .unwrap();
            }
            RejectCase::DeviceGeneration => {
                entries[2].device = DeviceEnvelope::new(
                    prepared.device.device_session(),
                    prepared.device.queue(),
                    prepared.device.descriptor_token(),
                    prepared.device.device_generation() + 1,
                )
                .unwrap();
            }
            RejectCase::Domain => entries[2].domain = DomainKey::new(0xdc99),
            RejectCase::Task => entries[2].request.task = TaskKey::new(0xdc99, 1),
            RejectCase::CohortSlot => entries[2].batch_index = 1,
            RejectCase::Parent => {
                entries[2].parent = DeviceCohortParent::BatchIndex(1);
            }
            RejectCase::MiddleRegistration => {
                entries[1].request.resources[0] = ResourceKey::new(0xdc41, request_id, 0);
            }
        }
        let before = registry.clone();
        let failure = registry
            .materialize_device_cohort_from_preparation(ticket, prepared, entries)
            .unwrap_err();
        __cser_core::assert_ne!(failure.error(), &RegistryError::ScopeNotActive);
        let returned = failure.into_input();
        __cser_core::assert_eq!(
            (returned.preparation_id(), returned.generation()),
            (coordinates.preparation_id, coordinates.generation)
        );
        __cser_core::assert_eq!(registry, before);
        assert_prepared_retained(&registry, &workload, coordinates);
        registry.check_invariants().unwrap();
    }

    let reject_cases = [
        RejectCase::Preparation,
        RejectCase::PreparationGeneration,
        RejectCase::ActorSlot,
        RejectCase::ActorGeneration,
        RejectCase::HardwareDigest,
        RejectCase::OwnedDevice,
        RejectCase::OperationDigest,
        RejectCase::CreditClass,
        RejectCase::CreditDuplicate,
        RejectCase::CreditExtra,
        RejectCase::DeviceSession,
        RejectCase::DeviceQueue,
        RejectCase::DescriptorToken,
        RejectCase::DeviceGeneration,
        RejectCase::Domain,
        RejectCase::Task,
        RejectCase::CohortSlot,
        RejectCase::Parent,
        RejectCase::MiddleRegistration,
    ];
    for (offset, case) in reject_cases.into_iter().enumerate() {
        reject_case(0xdc80 + offset as u64 * 0x10, case);
    }

    // A forged bearer generation is rejected without consuming the real
    // authority; the exact original ticket can still materialize afterwards.
    let (mut stale, workload, ticket, prepared, entries, coordinates) = fixture(0xde00);
    let stale_ticket = ticket.stale_bearer_for_test();
    let before = stale.clone();
    let failure = stale
        .materialize_device_cohort_from_preparation(stale_ticket, prepared, entries.clone())
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &RegistryError::Infrastructure(infrastructure::InfrastructureError::StaleGeneration)
    );
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(stale, before);
    assert_prepared_retained(&stale, &workload, coordinates);
    stale
        .materialize_device_cohort_from_preparation(ticket, prepared, entries)
        .unwrap();

    // A staged candidate is fenced by any live-base change and returns the
    // exact authority. The live preparation and unrelated tenant are intact.
    let (mut stale_base, workload, ticket, prepared, entries, coordinates) = fixture(0xde20);
    let plan = stale_base
        .prepare_device_cohort_materialization(ticket, prepared, entries.clone())
        .unwrap();
    stale_base.scopes.get_mut(&SCOPE).unwrap().revision += 1;
    let changed_live = stale_base.clone();
    let failure = stale_base
        .apply_device_cohort_materialization(plan)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &RegistryError::CombinedCandidateStale);
    __cser_core::assert_eq!(stale_base, changed_live);
    let ticket = failure.into_input();
    assert_prepared_retained(&stale_base, &workload, coordinates);
    stale_base
        .materialize_device_cohort_from_preparation(ticket, prepared, entries)
        .unwrap();

    // Corruption after all candidate staging is still detected before the
    // authoritative swap; no staged effect, index, or transferred credit leaks.
    let (mut staged_failure, workload, ticket, prepared, entries, coordinates) = fixture(0xde40);
    let mut plan = staged_failure
        .prepare_device_cohort_materialization(ticket, prepared, entries)
        .unwrap();
    plan.candidate
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .credits
        .balances
        .get_mut(&QUEUE)
        .unwrap()
        .held += 1;
    let before = staged_failure.clone();
    let failure = staged_failure
        .apply_device_cohort_materialization(plan)
        .unwrap_err();
    __cser_core::assert!(__cser_core::matches!(
        failure.error(),
        RegistryError::Invariant(_)
    ));
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(staged_failure, before);
    assert_prepared_retained(&staged_failure, &workload, coordinates);

    // The final candidate-to-authoritative cohort binding is checked before
    // the swap. A staged mismatch leaves the exact previous Registry intact
    // and returns authority; post-install mint is then infallible.
    let (mut successor_failure, workload, ticket, prepared, entries, coordinates) = fixture(0xde50);
    let mut plan = successor_failure
        .prepare_device_cohort_materialization(ticket, prepared, entries)
        .unwrap();
    plan.cohort.digest ^= 1;
    let before = successor_failure.clone();
    let failure = successor_failure
        .apply_device_cohort_materialization(plan)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &RegistryError::Infrastructure(infrastructure::InfrastructureError::StaleClaim)
    );
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(successor_failure, before);
    assert_prepared_retained(&successor_failure, &workload, coordinates);

    // Revoke is the competing winner on the same `&mut Registry`
    // linearization. It preserves PreparedRetained for recovery and refuses
    // to expose new hardware-owned business effects.
    let (mut revoke_first, workload, ticket, prepared, entries, coordinates) = fixture(0xde60);
    let plan = revoke_first
        .prepare_device_cohort_materialization(ticket, prepared, entries)
        .unwrap();
    revoke_first.revoke_begin(SCOPE).unwrap();
    revoke_first
        .infrastructure
        .set_closing_lifecycle_for_test(SCOPE);
    revoke_first.check_invariants().unwrap();
    let closing = revoke_first.clone();
    let failure = revoke_first
        .apply_device_cohort_materialization(plan)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), &RegistryError::ScopeNotActive);
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(revoke_first, closing);
    assert_prepared_retained(&revoke_first, &workload, coordinates);

    // Materialization-first installs one exact cohort, transfers retained
    // directly to held while leaving spare free credits untouched, and keeps
    // the infrastructure preparation live until an exact closure proof.
    let (mut materialized, workload, ticket, prepared, entries, coordinates) = fixture(0xdea0);
    let duplicate = ticket.duplicate_for_test();
    let duplicate_entries = entries.clone();
    let before = materialized.clone();
    let outcome = materialized
        .materialize_device_cohort_from_preparation(ticket, prepared, entries)
        .unwrap();
    assert_unrelated_unchanged(&before, &materialized);
    let credits = materialized.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!((credits.free, credits.held, credits.retained), (7, 7, 0));
    __cser_core::assert_eq!(outcome.cohort.ordered_effects().len(), 4);
    __cser_core::assert_eq!(
        outcome.registered[0].identity.effect(),
        outcome.cohort.block
    );
    __cser_core::assert_eq!(
        outcome.registered[1..]
            .iter()
            .map(|effect| effect.identity.effect())
            .collect::<__cser_alloc::vec::Vec<_>>(),
        outcome.cohort.dma
    );
    let projection = materialized
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::Materialized
    );
    __cser_core::assert_eq!(
        projection.credit_ownership,
        infrastructure::DevicePreparationCreditOwnership::TransferredToCohort
    );
    __cser_core::assert_eq!(projection.prepared_identity, Some(prepared));
    __cser_core::assert_eq!(projection.cohort, Some(outcome.cohort));
    __cser_core::assert!(
        materialized
            .infrastructure
            .close_workload(&workload)
            .is_err()
    );
    materialized.check_invariants().unwrap();

    // A test-only duplicate of the consumed bearer cannot create a second
    // cohort, move credits again, release ownership, or advance any counter.
    let after_success = materialized.clone();
    let failure = materialized
        .materialize_device_cohort_from_preparation(duplicate, prepared, duplicate_entries)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        &RegistryError::Infrastructure(infrastructure::InfrastructureError::StaleGeneration)
    );
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (returned.preparation_id(), returned.generation()),
        (coordinates.preparation_id, coordinates.generation)
    );
    __cser_core::assert_eq!(materialized, after_success);

    let selection = materialized.revoke_begin(SCOPE).unwrap();
    __cser_core::assert_eq!(selection.target_count, 5);
    materialized
        .infrastructure
        .set_closing_lifecycle_for_test(SCOPE);
    materialized.check_invariants().unwrap();
    let projection = materialized
        .query_device_preparation(
            &workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    __cser_core::assert_eq!(
        projection.state,
        infrastructure::DevicePreparationRecoveryState::Materialized
    );
}

#[cfg(test)]
fn supervisor_domain_recovery_primitives_self_test() {
    const SCOPE: ScopeKey = ScopeKey::new(0x1a00, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0x1a01, 1);
    const SERVICE_V1: TaskKey = TaskKey::new(0x1a02, 1);
    const SERVICE_V2: TaskKey = TaskKey::new(0x1a02, 2);
    const SERVICE_V3: TaskKey = TaskKey::new(0x1a02, 3);
    const DOMAIN: DomainKey = DomainKey::new(0x1a);
    const CREDIT: CreditClass = CreditClass::new(0x1a03);

    fn fixture(with_device: bool) -> (EffectRegistry, RegisteredEffect, Option<RegisteredEffect>) {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 7,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 2)],
            })
            .unwrap();
        registry
            .add_domain(
                SCOPE,
                DomainConfig {
                    key: DOMAIN,
                    binding_epoch: 1,
                    supervisor: SERVICE_V1,
                },
            )
            .unwrap();
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: SERVICE_V1,
                    operation: OperationClass::new(0x1a10),
                    descriptor: SyscallDescriptor::new(17, [0x1a; 6]),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: DOMAIN,
                parent: None,
            })
            .unwrap();
        let child = with_device.then(|| {
            registry
                .register_device_derived(DeviceDerivedRegisterRequest {
                    derived: DerivedRegisterRequest {
                        request: RegisterRequest {
                            scope: SCOPE,
                            task: SERVICE_V1,
                            operation: OperationClass::new(0x1a11),
                            descriptor: SyscallDescriptor::new(2, [0x1b; 6]),
                            resources: __cser_alloc::vec![],
                            credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                            publication: PublicationMode::None,
                        },
                        domain: DOMAIN,
                        parent: Some(root.identity.effect()),
                    },
                    device: DeviceEnvelope::new(0x1a20, 0, 0, 1).unwrap(),
                })
                .unwrap()
        });
        registry.prepare(SERVICE_V1, root.handle).unwrap();
        if let Some(child) = child.as_ref() {
            registry.prepare(SERVICE_V1, child.handle).unwrap();
        }
        registry.check_invariants().unwrap();
        (registry, root, child)
    }

    // Kernel completion may terminalize an old-binding effect after the
    // recovery snapshot was issued. The member leaves the unadopted work set,
    // but remains in the immutable crash cohort so the stored snapshot keeps
    // the exact identity of what was observed at the crash boundary.
    {
        let (mut completed, root, _) = fixture(false);
        let commit = match completed
            .commit(SERVICE_V1, root.handle, CommitMetadata::new(1, 1))
            .unwrap()
        {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
        };
        completed.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
        let snapshot = completed
            .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1)
            .unwrap();
        let cohort_identity = snapshot.cohort_identity();

        completed.stage_kernel_completion(&commit).unwrap();
        completed.check_invariants().unwrap();
        let recovery = completed.scopes[&SCOPE].domains[&DOMAIN]
            .recovery
            .as_ref()
            .unwrap();
        __cser_core::assert_eq!(recovery.cohort, BTreeSet::from([root.identity.effect()]));
        __cser_core::assert!(recovery.unadopted.is_empty());
        __cser_core::assert_eq!(
            domain_cohort_identity(Some(&recovery.cohort)).unwrap(),
            cohort_identity
        );
        __cser_core::assert_eq!(
            completed.domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1),
            Ok(snapshot)
        );
    }

    let (mut registry, _, _) = fixture(false);
    registry.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
    let snapshot = registry
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1)
        .unwrap();
    __cser_core::assert_eq!(
        registry.domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1),
        Ok(snapshot.clone())
    );
    registry
        .domain_ready(SCOPE, DOMAIN, SERVICE_V2, &snapshot)
        .unwrap();

    let (mut foreign, _, _) = fixture(false);
    foreign.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
    let foreign_snapshot = foreign
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1)
        .unwrap();
    let before = registry.clone();
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &foreign_snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Err(RegistryError::ForeignRecoverySnapshot)
    );
    __cser_core::assert_eq!(registry, before);

    let mut mutated = snapshot.clone();
    mutated.root_revision += 1;
    let before = registry.clone();
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &mutated,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Err(RegistryError::ConflictingRecoveryAttempt)
    );
    __cser_core::assert_eq!(registry, before);

    let before = registry.clone();
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V3,
            1,
            &snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Err(RegistryError::ConflictingRecoveryAttempt)
    );
    __cser_core::assert_eq!(registry, before);

    let (cohort, unadopted, effects) = {
        let recovery = registry.scopes[&SCOPE].domains[&DOMAIN]
            .recovery
            .as_ref()
            .unwrap();
        (
            recovery.cohort.clone(),
            recovery.unadopted.clone(),
            registry.effects.clone(),
        )
    };
    let aborted = registry
        .abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        )
        .unwrap();
    let DomainRecoveryAbortOutcome::Aborted(receipt) = aborted else {
        __cser_core::panic!("first exact abort replayed unexpectedly");
    };
    __cser_core::assert_eq!(receipt.attempt(), 1);
    __cser_core::assert_eq!(receipt.reason(), DomainRecoveryAbortReason::ReadyTimeout);
    let recovery = registry.scopes[&SCOPE].domains[&DOMAIN]
        .recovery
        .as_ref()
        .unwrap();
    __cser_core::assert_eq!(recovery.cohort, cohort);
    __cser_core::assert_eq!(recovery.unadopted, unadopted);
    __cser_core::assert_eq!(registry.effects, effects);
    __cser_core::assert_eq!(recovery.snapshot, None);
    __cser_core::assert_eq!(recovery.ready, None);
    __cser_core::assert_eq!(recovery.last_abort, Some(receipt));
    let projection = registry.domain_projection(SCOPE, DOMAIN).unwrap();
    __cser_core::assert_eq!(projection.recovery_attempt, None);
    __cser_core::assert_eq!(projection.last_aborted_attempt, Some(1));

    let before = registry.clone();
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Ok(DomainRecoveryAbortOutcome::AlreadyAborted(receipt))
    );
    __cser_core::assert_eq!(registry, before);
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &snapshot,
            DomainRecoveryAbortReason::RecoveryRejected,
        ),
        Err(RegistryError::ConflictingRecoveryAttempt)
    );
    __cser_core::assert_eq!(registry, before);

    let retry = registry
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V3, 3)
        .unwrap();
    let before = registry.clone();
    __cser_core::assert_eq!(
        registry.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Err(RegistryError::StaleRecoveryAttempt)
    );
    __cser_core::assert_eq!(registry, before);
    registry
        .abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V3,
            3,
            &retry,
            DomainRecoveryAbortReason::ExitedBeforeReady,
        )
        .unwrap();
    registry.check_invariants().unwrap();

    // Independent registries normalize their private namespaces in diagnostic
    // failure projections, including the new abort receipt provenance.
    let (mut same, _, _) = fixture(false);
    same.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
    let same_snapshot = same
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1)
        .unwrap();
    same.abort_domain_recovery_attempt(
        SCOPE,
        DOMAIN,
        SERVICE_V2,
        1,
        &same_snapshot,
        DomainRecoveryAbortReason::ReadyTimeout,
    )
    .unwrap();
    let (mut same_again, _, _) = fixture(false);
    same_again.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
    let same_again_snapshot = same_again
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 1)
        .unwrap();
    same_again
        .abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            1,
            &same_again_snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        )
        .unwrap();
    __cser_core::assert_eq!(
        same.failure_atomic_projection(),
        same_again.failure_atomic_projection()
    );

    let (mut quarantined, device_root, device_child) = fixture(true);
    quarantined.crash_domain(SCOPE, DOMAIN, SERVICE_V1).unwrap();
    {
        let scope = quarantined.scopes.get_mut(&SCOPE).unwrap();
        scope.revision = u64::MAX;
        let binding = scope.domains.get_mut(&DOMAIN).unwrap();
        binding.binding_epoch = u64::MAX;
        binding.revision = u64::MAX;
    }
    let quarantine_snapshot = quarantined
        .domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V2, 11)
        .unwrap();
    quarantined
        .domain_ready(SCOPE, DOMAIN, SERVICE_V2, &quarantine_snapshot)
        .unwrap();
    let effects_before = quarantined.effects.clone();
    let indexes_before = quarantined.production.clone();
    let device_before = quarantined.scopes[&SCOPE].device_root.clone();
    let recovery_before = quarantined.scopes[&SCOPE].domains[&DOMAIN].recovery.clone();
    let isolated =
        quarantined.isolate_domain_authority(SCOPE, DOMAIN, SERVICE_V2, Some(u64::MAX - 1));
    let DomainIsolationOutcome::Isolated(quarantine) = isolated else {
        __cser_core::panic!("first quarantine fence did not install");
    };
    __cser_core::assert_eq!(quarantine.service(), SERVICE_V2);
    __cser_core::assert_eq!(quarantine.binding_epoch(), u64::MAX);
    __cser_core::assert_eq!(quarantine.observed_binding_epoch(), Some(u64::MAX - 1));
    __cser_core::assert_eq!(quarantined.effects, effects_before);
    __cser_core::assert_eq!(quarantined.production, indexes_before);
    __cser_core::assert_eq!(quarantined.scopes[&SCOPE].device_root, device_before);
    let after_recovery = quarantined.scopes[&SCOPE].domains[&DOMAIN]
        .recovery
        .as_ref()
        .unwrap();
    let before_recovery = recovery_before.as_ref().unwrap();
    __cser_core::assert_eq!(after_recovery.cohort, before_recovery.cohort);
    __cser_core::assert_eq!(after_recovery.unadopted, before_recovery.unadopted);
    __cser_core::assert_eq!(after_recovery.snapshot, before_recovery.snapshot);
    __cser_core::assert_eq!(after_recovery.ready, None);
    let projection = quarantined.domain_projection(SCOPE, DOMAIN).unwrap();
    __cser_core::assert_eq!(projection.supervisor, None);
    __cser_core::assert!(!projection.fallback_running);
    __cser_core::assert_eq!(projection.quarantine, Some(quarantine));
    __cser_core::assert_eq!(projection.live_effects, 2);
    __cser_core::assert_eq!(projection.recovery_remaining, 2);
    __cser_core::assert!(quarantined.device_root_installed(SCOPE).unwrap());

    let before = quarantined.clone();
    __cser_core::assert_eq!(
        quarantined.isolate_domain_authority(SCOPE, DOMAIN, SERVICE_V2, Some(u64::MAX - 1),),
        DomainIsolationOutcome::AlreadyIsolated(quarantine)
    );
    __cser_core::assert_eq!(quarantined, before);
    __cser_core::assert_eq!(
        quarantined.isolate_domain_authority(SCOPE, DOMAIN, SERVICE_V3, None),
        DomainIsolationOutcome::AlreadyIsolated(quarantine)
    );
    __cser_core::assert_eq!(quarantined, before);

    // Marker-first rejection does not allow stale handles or recovery receipts
    // to select a weaker error path after the permanent fence is installed.
    __cser_core::assert_eq!(
        quarantined.descriptor(SERVICE_V2, device_root.handle),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.domain_recovery_snapshot(SCOPE, DOMAIN, SERVICE_V3, 12),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.domain_ready(SCOPE, DOMAIN, SERVICE_V2, &quarantine_snapshot),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.rebind_domain(SCOPE, DOMAIN, SERVICE_V2),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.recover_next_domain(SCOPE, DOMAIN, SERVICE_V2),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.adopt_domain(SCOPE, DOMAIN, SERVICE_V2, device_root.handle),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.abort_domain_recovery_attempt(
            SCOPE,
            DOMAIN,
            SERVICE_V2,
            11,
            &quarantine_snapshot,
            DomainRecoveryAbortReason::ReadyTimeout,
        ),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(
        quarantined.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: SERVICE_V2,
                operation: OperationClass::new(0x1a12),
                descriptor: SyscallDescriptor::new(18, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: DOMAIN,
            parent: Some(device_child.unwrap().identity.effect()),
        }),
        Err(RegistryError::DomainQuarantined)
    );
    __cser_core::assert_eq!(quarantined, before);
    quarantined.check_invariants().unwrap();

    let mut renamespaced = quarantined.clone();
    renamespaced.rewrite_registry_instance(0x1afe);
    renamespaced.check_invariants().unwrap();
    __cser_core::assert_eq!(
        quarantined.failure_atomic_projection(),
        renamespaced.failure_atomic_projection()
    );
}

/// Pins the first registry-native production identity chain independently of
/// the later runtime wiring.  These are real registry records with one shared
/// credit ledger, distinct service bindings, and immutable effect ancestry;
/// no synthetic cohort or side ledger is constructed for the assertion.
pub(crate) fn production_identity_registry_self_test() {
    #[cfg(test)]
    runtime_causal::runtime_causal_bootstrap_self_test();
    #[cfg(test)]
    runtime_task::causal_task_facade_self_test();
    #[cfg(test)]
    runtime_service_task::causal_service_task_facade_self_test();
    #[cfg(test)]
    supervisor_domain_recovery_primitives_self_test();
    #[cfg(test)]
    combined_scope_candidate_self_test();
    #[cfg(test)]
    task_owned_fault_outer_transaction_self_test();
    #[cfg(test)]
    device_preparation_outer_credit_self_test();
    #[cfg(test)]
    device_preparation_outer_materialization_self_test();
    #[cfg(test)]
    ordinary_domain_crash_rejects_a_forged_fault_origin();
    publication_ack_and_revoke_complete_self_test();

    const PERSONALITY_CREDIT: CreditClass = CreditClass::new(0x201);
    const FILESYSTEM_CREDIT: CreditClass = CreditClass::new(0x202);
    const BLOCK_CREDIT: CreditClass = CreditClass::new(0x203);
    const UNRELATED_CREDIT: CreditClass = CreditClass::new(0x204);

    const PERSONALITY_DOMAIN: DomainKey = DomainKey::new(1);
    const FILESYSTEM_DOMAIN: DomainKey = DomainKey::new(2);
    const BLOCK_DOMAIN: DomainKey = DomainKey::new(3);

    let scope = ScopeKey::new(0x200, 1);
    let legacy_supervisor = TaskKey::new(0x200, 1);
    let personality_supervisor = TaskKey::new(0x201, 1);
    let filesystem_v1 = TaskKey::new(0x202, 1);
    let filesystem_v2 = TaskKey::new(0x202, 2);
    let block_supervisor = TaskKey::new(0x203, 1);
    let personality_task = TaskKey::new(0x211, 1);
    let filesystem_task = TaskKey::new(0x212, 1);
    let block_task = TaskKey::new(0x213, 1);
    let personality_resource = ResourceKey::new(0x20, 1, 1);
    let filesystem_resource = ResourceKey::new(0x20, 2, 1);
    let block_resource = ResourceKey::new(0x20, 3, 1);

    let unrelated_scope = ScopeKey::new(0x2ff, 1);
    let unrelated_supervisor = TaskKey::new(0x2ff, 1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor: legacy_supervisor,
            credits: __cser_alloc::vec![
                CreditLimit::new(PERSONALITY_CREDIT, 1),
                CreditLimit::new(FILESYSTEM_CREDIT, 1),
                CreditLimit::new(BLOCK_CREDIT, 1),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: personality_supervisor,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: filesystem_v1,
        },
        DomainConfig {
            key: BLOCK_DOMAIN,
            binding_epoch: 1,
            supervisor: block_supervisor,
        },
    ] {
        registry.add_domain(scope, config).unwrap();
    }
    registry
        .create_scope(ScopeConfig {
            key: unrelated_scope,
            authority_epoch: 9,
            binding_epoch: 1,
            supervisor: unrelated_supervisor,
            credits: __cser_alloc::vec![CreditLimit::new(UNRELATED_CREDIT, 1)],
        })
        .unwrap();
    let unrelated = registry
        .register(RegisterRequest {
            scope: unrelated_scope,
            task: unrelated_supervisor,
            operation: OperationClass::new(0x2ff),
            descriptor: SyscallDescriptor::new(0x2ff, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x2f, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(UNRELATED_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();

    let personality = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: personality_task,
                operation: OperationClass::new(0x201),
                descriptor: SyscallDescriptor::new(0, [17, 0, 0, 0, 0, 0]),
                resources: __cser_alloc::vec![personality_resource],
                credits: __cser_alloc::vec![CreditCharge::new(PERSONALITY_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        })
        .unwrap();
    let filesystem = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: filesystem_task,
                operation: OperationClass::new(0x202),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4096, 0, 0, 0]),
                resources: __cser_alloc::vec![filesystem_resource],
                credits: __cser_alloc::vec![CreditCharge::new(FILESYSTEM_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: FILESYSTEM_DOMAIN,
            parent: Some(personality.identity.effect()),
        })
        .unwrap();
    let block = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: block_task,
                operation: OperationClass::new(0x203),
                descriptor: SyscallDescriptor::new(0x203, [0, 8, 0x1000, 4096, 0, 0]),
                resources: __cser_alloc::vec![block_resource],
                credits: __cser_alloc::vec![CreditCharge::new(BLOCK_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: BLOCK_DOMAIN,
            parent: Some(filesystem.identity.effect()),
        })
        .unwrap();

    __cser_core::assert_eq!(personality.identity.scope(), scope);
    __cser_core::assert_eq!(filesystem.identity.scope(), scope);
    __cser_core::assert_eq!(block.identity.scope(), scope);
    __cser_core::assert_eq!(personality.identity.domain(), PERSONALITY_DOMAIN);
    __cser_core::assert_eq!(filesystem.identity.domain(), FILESYSTEM_DOMAIN);
    __cser_core::assert_eq!(block.identity.domain(), BLOCK_DOMAIN);
    __cser_core::assert_eq!(personality.identity.parent(), None);
    __cser_core::assert_eq!(
        filesystem.identity.parent(),
        Some(personality.identity.effect())
    );
    __cser_core::assert_eq!(block.identity.parent(), Some(filesystem.identity.effect()));

    registry
        .prepare(personality_supervisor, personality.handle)
        .unwrap();
    registry.prepare(filesystem_v1, filesystem.handle).unwrap();
    registry.prepare(block_supervisor, block.handle).unwrap();
    registry.check_invariants().unwrap();

    let before_adopt = registry.effect_view(filesystem.identity.effect()).unwrap();
    let crash = registry
        .crash_domain(scope, FILESYSTEM_DOMAIN, filesystem_v1)
        .unwrap();
    __cser_core::assert_eq!(crash.cohort, BTreeSet::from([filesystem.identity.effect()]));
    let before_stale_parent = registry.clone();
    __cser_core::assert_eq!(
        registry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: block_task,
                operation: OperationClass::new(0x204),
                descriptor: SyscallDescriptor::new(0x204, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x20, 4, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(BLOCK_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: BLOCK_DOMAIN,
            parent: Some(filesystem.identity.effect()),
        }),
        Err(RegistryError::StaleBinding)
    );
    __cser_core::assert_eq!(registry, before_stale_parent);
    __cser_core::assert_eq!(
        registry
            .domain_projection(scope, PERSONALITY_DOMAIN)
            .unwrap()
            .supervisor,
        Some(personality_supervisor)
    );
    __cser_core::assert_eq!(
        registry
            .domain_projection(scope, BLOCK_DOMAIN)
            .unwrap()
            .supervisor,
        Some(block_supervisor)
    );
    let snapshot = registry
        .domain_recovery_snapshot(scope, FILESYSTEM_DOMAIN, filesystem_v2, 1)
        .unwrap();
    __cser_core::assert_eq!(snapshot.effects.len(), 1);
    __cser_core::assert_eq!(snapshot.effects[0].effect, filesystem.identity.effect());
    registry
        .domain_ready(scope, FILESYSTEM_DOMAIN, filesystem_v2, &snapshot)
        .unwrap();
    registry
        .rebind_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2)
        .unwrap();
    let recovery = registry
        .recover_next_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2)
        .unwrap()
        .unwrap();
    __cser_core::assert_eq!(recovery.handle.effect(), filesystem.identity.effect());
    let filesystem_v2_handle = registry
        .adopt_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2, recovery.handle)
        .unwrap();
    __cser_core::assert_eq!(
        registry.domain_recovery_remaining(scope, FILESYSTEM_DOMAIN),
        Ok(0)
    );
    let after_adopt = registry.effect_view(filesystem.identity.effect()).unwrap();
    __cser_core::assert_eq!(
        after_adopt.identity.effect(),
        before_adopt.identity.effect()
    );
    __cser_core::assert_eq!(after_adopt.identity.scope(), before_adopt.identity.scope());
    __cser_core::assert_eq!(
        after_adopt.identity.domain(),
        before_adopt.identity.domain()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.parent(),
        before_adopt.identity.parent()
    );
    __cser_core::assert_eq!(after_adopt.identity.task(), before_adopt.identity.task());
    __cser_core::assert_eq!(
        after_adopt.identity.operation(),
        before_adopt.identity.operation()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.authority_epoch(),
        before_adopt.identity.authority_epoch()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.origin_binding_epoch(),
        before_adopt.identity.origin_binding_epoch()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.resources(),
        before_adopt.identity.resources()
    );
    __cser_core::assert_eq!(
        after_adopt.current_resources,
        before_adopt.current_resources
    );
    __cser_core::assert_eq!(after_adopt.identity.binding_epoch(), 2);
    __cser_core::assert_eq!(
        registry.descriptor(filesystem_v2, filesystem.handle),
        Err(RegistryError::StaleBinding)
    );
    registry
        .descriptor(filesystem_v2, filesystem_v2_handle)
        .unwrap();
    registry
        .descriptor(personality_supervisor, personality.handle)
        .unwrap();
    registry.descriptor(block_supervisor, block.handle).unwrap();
    registry.check_invariants().unwrap();

    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert_eq!(selection.target_count, 3);
    for domain in [PERSONALITY_DOMAIN, FILESYSTEM_DOMAIN, BLOCK_DOMAIN] {
        let projection = registry.domain_projection(scope, domain).unwrap();
        __cser_core::assert_eq!(projection.supervisor, None);
        __cser_core::assert!(!projection.fallback_running);
    }
    let before_rejected_commits = registry.clone();
    for (sender, handle) in [
        (personality_supervisor, personality.handle),
        (filesystem_v2, filesystem_v2_handle),
        (block_supervisor, block.handle),
    ] {
        __cser_core::assert_eq!(
            registry.commit(sender, handle, CommitMetadata::new(0, 0)),
            Err(RegistryError::StaleAuthority)
        );
    }
    __cser_core::assert_eq!(registry, before_rejected_commits);

    for expected in [
        block.identity.effect(),
        filesystem.identity.effect(),
        personality.identity.effect(),
    ] {
        let next = registry.revoke_next(&selection).unwrap().unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        __cser_core::assert_eq!(next.disposition, RevokeDisposition::Abort);
        let terminal = registry
            .stage_revoke_terminal(&selection, expected, TerminalRequest::aborted(-125))
            .unwrap();
        __cser_core::assert_eq!(terminal.receipt.effect(), expected);
        __cser_core::assert!(terminal.publication.is_none());
    }
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    let target = registry.scope_projection(scope).unwrap();
    __cser_core::assert_eq!(target.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(target.credits.capacity, 3);
    __cser_core::assert_eq!(target.credits.free, 3);
    __cser_core::assert_eq!(target.credits.held, 0);
    __cser_core::assert_eq!(target.credits.committed, 0);
    let work = registry.revoke_work_projection(&selection).unwrap();
    __cser_core::assert_eq!(work.target_count, 3);
    __cser_core::assert_eq!(work.terminalized, 3);
    __cser_core::assert_eq!(work.target_index_removals, 3);
    __cser_core::assert_eq!(work.unrelated_effect_visits, 0);
    __cser_core::assert_eq!(work.history_effect_visits, 0);
    __cser_core::assert_eq!(registry.effects_for_scope(unrelated_scope).len(), 1);

    registry
        .stage_terminal(
            unrelated_supervisor,
            unrelated.handle,
            TerminalRequest::aborted(-125),
        )
        .unwrap();
    let unrelated_projection = registry.scope_projection(unrelated_scope).unwrap();
    __cser_core::assert_eq!(unrelated_projection.credits.free, 1);
    __cser_core::assert_eq!(unrelated_projection.credits.held, 0);
    production_device_batch_registry_self_test(&mut registry);
    registry.check_invariants().unwrap();
}

/// Pins the exact production transition source used by the same-boot device
/// successor: six workload effects, four device-enveloped effects, one root
/// authority, and one publish closure. All negative fixtures clone this same
/// registry state; none creates a detached evaluator registry or ledger.
fn production_device_batch_registry_self_test(registry: &mut EffectRegistry) {
    use __cser_core::cell::Cell;

    const SCOPE: ScopeKey = ScopeKey::new(0x300, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0x300, 1);
    const PERSONALITY: TaskKey = TaskKey::new(0x301, 1);
    const FILESYSTEM: TaskKey = TaskKey::new(0x302, 1);
    const VIRTIO: TaskKey = TaskKey::new(0x303, 1);
    const PERSONALITY_DOMAIN: DomainKey = DomainKey::new(1);
    const FILESYSTEM_DOMAIN: DomainKey = DomainKey::new(2);
    const VIRTIO_DOMAIN: DomainKey = DomainKey::new(3);
    const CONTROL: CreditClass = CreditClass::new(0x301);
    const FILESYSTEM_OP: CreditClass = CreditClass::new(0x302);
    const QUEUE_SLOT: CreditClass = CreditClass::new(0x303);
    const DMA_OWNER: CreditClass = CreditClass::new(0x304);

    let device = DeviceEnvelope::new(0x51, 0, 0, 1).unwrap();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 17,
            binding_epoch: 1,
            supervisor: ROOT_OWNER,
            credits: __cser_alloc::vec![
                CreditLimit::new(CONTROL, 2),
                CreditLimit::new(FILESYSTEM_OP, 1),
                CreditLimit::new(QUEUE_SLOT, 1),
                CreditLimit::new(DMA_OWNER, 3),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: PERSONALITY,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: FILESYSTEM,
        },
        DomainConfig {
            key: VIRTIO_DOMAIN,
            binding_epoch: 1,
            supervisor: VIRTIO,
        },
    ] {
        registry.add_domain(SCOPE, config).unwrap();
    }

    let mut non_device_candidate = registry.clone_non_device_candidate().unwrap();
    __cser_core::assert_eq!(
        non_device_candidate.kernel_root_authority(SCOPE, ROOT_OWNER),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    let non_device_before_registration = non_device_candidate.clone();
    __cser_core::assert_eq!(
        non_device_candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(3),
                    descriptor: SyscallDescriptor::new(3, [0, 0, 512, 0, 0, 0]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 3, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(QUEUE_SLOT, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: None,
            },
            device,
        }),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(non_device_candidate, non_device_before_registration);
    non_device_candidate.check_invariants().unwrap();

    let syscall = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(1),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4, 0, 0, 0]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        })
        .unwrap();
    let filesystem = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: FILESYSTEM,
                operation: OperationClass::new(2),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4, 0, 0, 0]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 2, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(FILESYSTEM_OP, 1)],
                publication: PublicationMode::None,
            },
            domain: FILESYSTEM_DOMAIN,
            parent: Some(syscall.identity.effect()),
        })
        .unwrap();
    __cser_core::assert_eq!(registry.device_root_installed(SCOPE), Ok(false));
    __cser_core::assert_eq!(
        registry.device_root_installed(ScopeKey::new(0xdead, 1)),
        Err(RegistryError::UnknownScope)
    );
    let device_cohort = || {
        [
            DeviceDerivedCohortEntry {
                batch_index: 0,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(3),
                    descriptor: SyscallDescriptor::new(3, [0, 0, 512, 0, 0, 0]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 3, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(QUEUE_SLOT, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::Existing(filesystem.identity.effect()),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 1,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(4),
                    descriptor: SyscallDescriptor::new(4, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 4, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 2,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(5),
                    descriptor: SyscallDescriptor::new(5, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 5, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 3,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(6),
                    descriptor: SyscallDescriptor::new(6, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 6, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
        ]
    };
    let reject_cohort =
        |label: &str, entries: [DeviceDerivedCohortEntry; 4], expected: RegistryError| {
            let mut negative = registry.clone();
            let before = negative.clone();
            __cser_core::assert_eq!(
                negative.register_device_derived_cohort(entries),
                Err(expected),
                "{label}"
            );
            __cser_core::assert_eq!(negative, before, "{label}");
        };

    let mut credit_failure = device_cohort();
    credit_failure[1].request.credits = __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 4)];
    reject_cohort(
        "middle credit",
        credit_failure,
        RegistryError::CreditExhausted,
    );

    let mut resource_failure = device_cohort();
    resource_failure[1].request.resources = __cser_alloc::vec![ResourceKey::new(0x31, 4, 0)];
    reject_cohort(
        "middle resource",
        resource_failure,
        RegistryError::InvalidGeneration,
    );

    let mut ancestry_failure = device_cohort();
    ancestry_failure[1].parent = DeviceCohortParent::Existing(filesystem.identity.effect());
    reject_cohort(
        "middle ancestry",
        ancestry_failure,
        RegistryError::InvalidState,
    );

    let mut device_failure = device_cohort();
    device_failure[1].device = DeviceEnvelope::new(0x51, 0, 0, 2).unwrap();
    reject_cohort(
        "middle device",
        device_failure,
        RegistryError::StaleDeviceGeneration,
    );

    let mut forward_parent = device_cohort();
    forward_parent[1].parent = DeviceCohortParent::BatchIndex(2);
    reject_cohort(
        "forward parent",
        forward_parent,
        RegistryError::InvalidState,
    );

    let mut self_parent = device_cohort();
    self_parent[1].parent = DeviceCohortParent::BatchIndex(1);
    reject_cohort("self parent", self_parent, RegistryError::InvalidState);

    let mut invalid_parent = device_cohort();
    invalid_parent[1].parent = DeviceCohortParent::BatchIndex(4);
    reject_cohort(
        "invalid parent",
        invalid_parent,
        RegistryError::InvalidState,
    );

    let mut duplicate_slot = device_cohort();
    duplicate_slot[2].batch_index = 1;
    reject_cohort(
        "duplicate slot",
        duplicate_slot,
        RegistryError::InvalidState,
    );

    let mut missing_slot = device_cohort();
    missing_slot[3].batch_index = 4;
    reject_cohort("missing slot", missing_slot, RegistryError::InvalidState);

    let mut counter_failure = registry.clone();
    counter_failure.next_effect_id = u64::MAX - 1;
    let counter_before = counter_failure.clone();
    __cser_core::assert_eq!(
        counter_failure.register_device_derived_cohort(device_cohort()),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(counter_failure, counter_before);

    let mut disabled_cohort = registry.clone_non_device_candidate().unwrap();
    let disabled_cohort_before = disabled_cohort.clone();
    __cser_core::assert_eq!(
        disabled_cohort.register_device_derived_cohort(device_cohort()),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(disabled_cohort, disabled_cohort_before);

    let [block, dma_a, dma_b, dma_request] = registry
        .register_device_derived_cohort(device_cohort())
        .unwrap();
    __cser_core::assert_eq!(registry.device_root_installed(SCOPE), Ok(true));
    __cser_core::assert!(__cser_core::matches!(
        registry.clone_non_device_candidate(),
        Err(RegistryError::InvalidDeviceEnvelope)
    ));

    let registered = [&syscall, &filesystem, &block, &dma_a, &dma_b, &dma_request];
    __cser_core::assert_eq!(block.identity.parent(), Some(filesystem.identity.effect()));
    for dma in [&dma_a, &dma_b, &dma_request] {
        __cser_core::assert_eq!(dma.identity.parent(), Some(block.identity.effect()));
    }
    for (sender, effect) in [
        (PERSONALITY, &syscall),
        (FILESYSTEM, &filesystem),
        (VIRTIO, &block),
        (VIRTIO, &dma_a),
        (VIRTIO, &dma_b),
        (VIRTIO, &dma_request),
    ] {
        registry.prepare(sender, effect.handle).unwrap();
    }
    __cser_core::assert_eq!(registry.effects_for_scope(SCOPE).len(), 6);
    __cser_core::assert_eq!(
        registered
            .iter()
            .filter(|effect| effect.identity.device.is_some())
            .count(),
        4
    );
    registry.check_invariants().unwrap();

    let authority = registry.kernel_root_authority(SCOPE, ROOT_OWNER).unwrap();
    let commits = [
        (syscall.handle, CommitMetadata::new(4, 1)),
        (filesystem.handle, CommitMetadata::new(4, 1)),
        (block.handle, CommitMetadata::new(512, 1)),
        (dma_a.handle, CommitMetadata::new(1, 1)),
        (dma_b.handle, CommitMetadata::new(1, 1)),
        (dma_request.handle, CommitMetadata::new(1, 1)),
    ];
    let handles = [
        syscall.handle,
        filesystem.handle,
        block.handle,
        dma_a.handle,
        dma_b.handle,
        dma_request.handle,
    ];

    let mut disabled_enrollment = registry.clone();
    disabled_enrollment.device_publication_mode = DevicePublicationMode::DisabledNonDeviceCandidate;
    let disabled_enrollment_before = disabled_enrollment.clone();
    __cser_core::assert_eq!(
        disabled_enrollment.enroll_device_batch(authority, &handles, device),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(disabled_enrollment, disabled_enrollment_before);

    for (label, wrong_device, expected) in [
        (
            "generation",
            DeviceEnvelope::new(0x51, 0, 0, 2).unwrap(),
            RegistryError::StaleDeviceGeneration,
        ),
        (
            "session",
            DeviceEnvelope::new(0x52, 0, 0, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
        (
            "queue",
            DeviceEnvelope::new(0x51, 1, 0, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
        (
            "descriptor",
            DeviceEnvelope::new(0x51, 0, 1, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
    ] {
        let mut negative = registry.clone();
        let before = negative.clone();
        let result = negative.enroll_device_batch(authority, &handles, wrong_device);
        __cser_core::assert!(
            __cser_core::matches!(result, Err(error) if error == expected),
            "{label}"
        );
        __cser_core::assert_eq!(negative, before, "{label}");
    }

    let mut missing = registry.clone();
    let missing_before = missing.clone();
    __cser_core::assert!(__cser_core::matches!(
        missing.enroll_device_batch(authority, &handles[..handles.len() - 1], device),
        Err(RegistryError::InvalidState)
    ));
    __cser_core::assert_eq!(missing, missing_before);

    let mut wrong_ancestry = registry.clone();
    let ancestry_before = wrong_ancestry.clone();
    __cser_core::assert_eq!(
        wrong_ancestry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(7),
                descriptor: SyscallDescriptor::new(7, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 7, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(wrong_ancestry, ancestry_before);

    // Merely deriving a device child reserves the whole root. A non-device
    // ancestor cannot acquire a partial authoritative commit before explicit
    // enrollment or hardware publication.
    let mut split = registry.clone();
    let split_before = split.clone();
    __cser_core::assert_eq!(
        split.commit(PERSONALITY, syscall.handle, commits[0].1),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(split, split_before);

    // Conversely, a service cannot attach a device-derived child beneath an
    // ancestor that was already committed through the generic path.
    let mut attached_after_commit = registry.clone();
    let attach_scope = ScopeKey::new(0x310, 1);
    let attach_owner = TaskKey::new(0x310, 1);
    let attach_service = TaskKey::new(0x311, 1);
    let attach_domain = DomainKey::new(1);
    attached_after_commit
        .create_scope(ScopeConfig {
            key: attach_scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: attach_owner,
            credits: __cser_alloc::vec![CreditLimit::new(CONTROL, 2)],
        })
        .unwrap();
    attached_after_commit
        .add_domain(
            attach_scope,
            DomainConfig {
                key: attach_domain,
                binding_epoch: 1,
                supervisor: attach_service,
            },
        )
        .unwrap();
    let committed_parent = attached_after_commit
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: attach_scope,
                task: attach_service,
                operation: OperationClass::new(1),
                descriptor: SyscallDescriptor::new(1, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: attach_domain,
            parent: None,
        })
        .unwrap();
    attached_after_commit
        .prepare(attach_service, committed_parent.handle)
        .unwrap();
    attached_after_commit
        .commit(
            attach_service,
            committed_parent.handle,
            CommitMetadata::new(0, 0),
        )
        .unwrap();
    let attach_before = attached_after_commit.clone();
    __cser_core::assert_eq!(
        attached_after_commit.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: attach_scope,
                    task: attach_service,
                    operation: OperationClass::new(2),
                    descriptor: SyscallDescriptor::new(2, [0; 6]),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                    publication: PublicationMode::None,
                },
                domain: attach_domain,
                parent: Some(committed_parent.identity.effect()),
            },
            device,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(attached_after_commit, attach_before);

    // If revoke wins the device-root/enrollment window, generic Abort remains
    // blocked. A Closing-only emergency freeze records the exact prepared live
    // cohort as cancel-only before ownership can be retained and closed.
    let mut pending_direct = registry.clone();
    let pending_direct_before = pending_direct.clone();
    __cser_core::assert_eq!(
        pending_direct.stage_terminal(VIRTIO, dma_a.handle, TerminalRequest::aborted(-125),),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(pending_direct, pending_direct_before);

    let assert_pending_precommit_error =
        |candidate: &mut EffectRegistry, expected: RegistryError| {
            let before = candidate.clone();
            let hardware_calls = Cell::new(0_u8);
            __cser_core::assert_eq!(
                candidate.close_pending_device_precommit_with_apply(SCOPE, |_| {
                    hardware_calls.set(hardware_calls.get().checked_add(1).unwrap())
                }),
                Err(expected)
            );
            __cser_core::assert_eq!(hardware_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut compound_pending = registry.clone();
    let compound_pending_before = compound_pending.scope_projection(SCOPE).unwrap();
    let compound_pending_revoke_sequence = compound_pending.next_revoke_sequence;
    let compound_pending_enrollment_sequence = compound_pending.next_device_enrollment_sequence;
    let compound_pending_closure_sequence = compound_pending.next_device_closure_sequence;
    let compound_pending_hardware_calls = Cell::new(0_u8);
    let (compound_pending_close, compound_pending_hardware) = compound_pending
        .close_pending_device_precommit_with_apply(SCOPE, |ticket| {
            compound_pending_hardware_calls.set(
                compound_pending_hardware_calls
                    .get()
                    .checked_add(1)
                    .unwrap(),
            );
            __cser_core::assert_eq!(ticket.batch_sequence, None);
            __cser_core::assert_eq!(ticket.device(), device);
            ticket.sequence
        })
        .unwrap();
    __cser_core::assert_eq!(compound_pending_hardware_calls.get(), 1);
    __cser_core::assert_eq!(
        compound_pending_hardware,
        compound_pending_close.reset_ticket.sequence
    );
    __cser_core::assert_eq!(compound_pending_close.selection.scope, SCOPE);
    __cser_core::assert_eq!(compound_pending_close.selection.target_count, 6);
    __cser_core::assert!(compound_pending_close.enrollment.cancel_only());
    __cser_core::assert_eq!(compound_pending_close.enrollment.effects().len(), 6);
    __cser_core::assert_eq!(
        compound_pending
            .scope_projection(SCOPE)
            .unwrap()
            .authority_epoch,
        compound_pending_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        compound_pending.scope_projection(SCOPE).unwrap().revision,
        compound_pending_before.revision + 3
    );
    __cser_core::assert_eq!(
        compound_pending.next_revoke_sequence,
        compound_pending_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_pending.next_device_enrollment_sequence,
        compound_pending_enrollment_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_pending.next_device_closure_sequence,
        compound_pending_closure_sequence + 1
    );
    let compound_pending_root = compound_pending.scopes[&SCOPE]
        .device_root
        .as_ref()
        .unwrap();
    __cser_core::assert_eq!(
        compound_pending_root.enrollment.as_ref(),
        Some(&compound_pending_close.enrollment)
    );
    __cser_core::assert_eq!(
        compound_pending_root.outcome,
        Some(DeviceClosureResult::AbortedBeforeCommit)
    );
    __cser_core::assert_eq!(
        compound_pending_root.reset_ticket,
        Some(compound_pending_close.reset_ticket)
    );
    let compound_pending_credits = compound_pending.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(compound_pending_credits.held, 0);
    __cser_core::assert_eq!(compound_pending_credits.retained, 6);
    compound_pending.check_invariants().unwrap();

    let mut pending_revoke_overflow = registry.clone();
    pending_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_pending_precommit_error(&mut pending_revoke_overflow, RegistryError::CounterOverflow);

    let mut pending_enrollment_overflow = registry.clone();
    pending_enrollment_overflow.next_device_enrollment_sequence = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_enrollment_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_closure_overflow = registry.clone();
    pending_closure_overflow.next_device_closure_sequence = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_closure_overflow,
        RegistryError::CounterOverflow,
    );

    for revision in [u64::MAX, u64::MAX - 1, u64::MAX - 2] {
        let mut pending_revision_overflow = registry.clone();
        pending_revision_overflow
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .revision = revision;
        assert_pending_precommit_error(
            &mut pending_revision_overflow,
            RegistryError::CounterOverflow,
        );
    }

    let mut pending_authority_overflow = registry.clone();
    pending_authority_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .authority_epoch = u64::MAX;
    let pending_authority_effects: Vec<_> = pending_authority_overflow.by_scope[&SCOPE]
        .iter()
        .copied()
        .collect();
    for effect in pending_authority_effects {
        pending_authority_overflow
            .effects
            .get_mut(&effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    assert_pending_precommit_error(
        &mut pending_authority_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_closing = registry.clone();
    pending_closing.revoke_begin(SCOPE).unwrap();
    assert_pending_precommit_error(&mut pending_closing, RegistryError::ScopeNotActive);

    let mut pending_outcome = registry.clone();
    pending_outcome
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root
        .as_mut()
        .unwrap()
        .outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
    assert_pending_precommit_error(&mut pending_outcome, RegistryError::InvalidState);

    let mut pending_credit_state = registry.clone();
    pending_credit_state
        .effects
        .get_mut(&dma_a.identity.effect())
        .unwrap()
        .credit_state = CreditState::Released;
    assert_pending_precommit_error(&mut pending_credit_state, RegistryError::InvalidState);

    let mut pending_retention_overflow = registry.clone();
    pending_retention_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .credits
        .balances
        .get_mut(&CONTROL)
        .unwrap()
        .retained = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_retention_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_wrong_revoke_cohort = registry.clone();
    let pending_wrong_candidates = &mut pending_wrong_revoke_cohort
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .closure_candidates;
    __cser_core::assert!(pending_wrong_candidates.remove(&dma_a.identity.effect()));
    __cser_core::assert!(pending_wrong_candidates.insert(EffectKey::new(u64::MAX, 1)));
    assert_pending_precommit_error(
        &mut pending_wrong_revoke_cohort,
        RegistryError::InvalidState,
    );

    let mut pending_missing_root = registry.clone();
    pending_missing_root
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root = None;
    assert_pending_precommit_error(
        &mut pending_missing_root,
        RegistryError::DeviceBatchNotEnrolled,
    );

    let mut pending_cancel = registry.clone();
    let pending_selection = pending_cancel.revoke_begin(SCOPE).unwrap();
    let pending_head = pending_cancel
        .revoke_next(&pending_selection)
        .unwrap()
        .unwrap();
    let pending_before_abort = pending_cancel.clone();
    __cser_core::assert_eq!(
        pending_cancel.stage_revoke_terminal(
            &pending_selection,
            pending_head.effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(pending_cancel, pending_before_abort);
    let cancel_enrollment = pending_cancel.freeze_pending_device_cancel(SCOPE).unwrap();
    __cser_core::assert!(cancel_enrollment.cancel_only());
    let cancel_ticket = pending_cancel
        .begin_unpublished_device_cancel(&cancel_enrollment)
        .unwrap();
    __cser_core::assert_eq!(
        pending_cancel
            .scope_projection(SCOPE)
            .unwrap()
            .credits
            .retained,
        6
    );
    let (cancel_reset, ()) = pending_cancel
        .acknowledge_device_reset_with_apply(&cancel_ticket, |_| ())
        .unwrap();
    let cancel_iotlb = pending_cancel.begin_device_iotlb(&cancel_reset).unwrap();
    let (cancel_closure, ()) = pending_cancel
        .acknowledge_device_iotlb_with_apply(&cancel_iotlb, |_| ())
        .unwrap();
    __cser_core::assert_eq!(
        cancel_closure.outcome(),
        DeviceClosureResult::AbortedBeforeCommit
    );
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = pending_cancel
            .revoke_next(&pending_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        pending_cancel
            .stage_device_batch_terminal(&cancel_closure, expected, TerminalRequest::aborted(-125))
            .unwrap();
    }
    pending_cancel.revoke_complete(&pending_selection).unwrap();
    pending_cancel.check_invariants().unwrap();

    let mut registered_cancel = registry.clone();
    let registered_child = registered_cancel
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(8),
                descriptor: SyscallDescriptor::new(8, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: Some(dma_request.identity.effect()),
        })
        .unwrap();
    __cser_core::assert_eq!(
        registered_cancel
            .effect_view(registered_child.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Registered
    );
    let registered_selection = registered_cancel.revoke_begin(SCOPE).unwrap();
    let registered_enrollment = registered_cancel
        .freeze_pending_device_cancel(SCOPE)
        .unwrap();
    __cser_core::assert!(registered_enrollment.cancel_only());
    __cser_core::assert_eq!(registered_enrollment.effects().len(), 7);
    let registered_ticket = registered_cancel
        .begin_unpublished_device_cancel(&registered_enrollment)
        .unwrap();
    __cser_core::assert_eq!(
        registered_cancel
            .scope_projection(SCOPE)
            .unwrap()
            .credits
            .retained,
        7
    );
    let (registered_reset, ()) = registered_cancel
        .acknowledge_device_reset_with_apply(&registered_ticket, |_| ())
        .unwrap();
    let registered_iotlb = registered_cancel
        .begin_device_iotlb(&registered_reset)
        .unwrap();
    let (registered_closure, ()) = registered_cancel
        .acknowledge_device_iotlb_with_apply(&registered_iotlb, |_| ())
        .unwrap();
    let mut registered_closed = 0_usize;
    while let Some(next) = registered_cancel
        .revoke_next(&registered_selection)
        .unwrap()
    {
        registered_cancel
            .stage_device_batch_terminal(
                &registered_closure,
                next.effect,
                TerminalRequest::aborted(-125),
            )
            .unwrap();
        registered_closed += 1;
    }
    __cser_core::assert_eq!(registered_closed, 7);
    registered_cancel
        .revoke_complete(&registered_selection)
        .unwrap();
    registered_cancel.check_invariants().unwrap();

    let enrollment = registry
        .enroll_device_batch(authority, &handles, device)
        .unwrap();
    __cser_core::assert_eq!(enrollment.scope(), SCOPE);
    __cser_core::assert_eq!(enrollment.enrollment_sequence(), 1);
    __cser_core::assert_eq!(enrollment.device(), device);
    __cser_core::assert_eq!(enrollment.effects().len(), 6);

    let assert_enrolled_precommit_error =
        |candidate: &mut EffectRegistry,
         presented: &DeviceBatchEnrollmentReceipt,
         expected: RegistryError| {
            let before = candidate.clone();
            let hardware_calls = Cell::new(0_u8);
            __cser_core::assert_eq!(
                candidate.close_enrolled_device_precommit_with_apply(presented, |_| {
                    hardware_calls.set(hardware_calls.get().checked_add(1).unwrap())
                }),
                Err(expected)
            );
            __cser_core::assert_eq!(hardware_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut compound_enrolled = registry.clone();
    let compound_enrolled_before = compound_enrolled.scope_projection(SCOPE).unwrap();
    let compound_enrolled_revoke_sequence = compound_enrolled.next_revoke_sequence;
    let compound_enrolled_enrollment_sequence = compound_enrolled.next_device_enrollment_sequence;
    let compound_enrolled_closure_sequence = compound_enrolled.next_device_closure_sequence;
    let compound_enrolled_hardware_calls = Cell::new(0_u8);
    let (compound_enrolled_close, compound_enrolled_hardware) = compound_enrolled
        .close_enrolled_device_precommit_with_apply(&enrollment, |ticket| {
            compound_enrolled_hardware_calls.set(
                compound_enrolled_hardware_calls
                    .get()
                    .checked_add(1)
                    .unwrap(),
            );
            __cser_core::assert_eq!(ticket.batch_sequence, None);
            __cser_core::assert_eq!(ticket.device(), device);
            ticket.sequence
        })
        .unwrap();
    __cser_core::assert_eq!(compound_enrolled_hardware_calls.get(), 1);
    __cser_core::assert_eq!(
        compound_enrolled_hardware,
        compound_enrolled_close.reset_ticket.sequence
    );
    __cser_core::assert_eq!(compound_enrolled_close.selection.scope, SCOPE);
    __cser_core::assert_eq!(compound_enrolled_close.selection.target_count, 6);
    __cser_core::assert_eq!(compound_enrolled_close.enrollment, enrollment);
    __cser_core::assert!(!compound_enrolled_close.enrollment.cancel_only());
    __cser_core::assert_eq!(
        compound_enrolled
            .scope_projection(SCOPE)
            .unwrap()
            .authority_epoch,
        compound_enrolled_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        compound_enrolled.scope_projection(SCOPE).unwrap().revision,
        compound_enrolled_before.revision + 2
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_revoke_sequence,
        compound_enrolled_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_device_enrollment_sequence,
        compound_enrolled_enrollment_sequence
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_device_closure_sequence,
        compound_enrolled_closure_sequence + 1
    );
    let compound_enrolled_root = compound_enrolled.scopes[&SCOPE]
        .device_root
        .as_ref()
        .unwrap();
    __cser_core::assert_eq!(
        compound_enrolled_root.enrollment.as_ref(),
        Some(&compound_enrolled_close.enrollment)
    );
    __cser_core::assert_eq!(
        compound_enrolled_root.outcome,
        Some(DeviceClosureResult::AbortedBeforeCommit)
    );
    __cser_core::assert_eq!(
        compound_enrolled_root.reset_ticket,
        Some(compound_enrolled_close.reset_ticket)
    );
    let compound_enrolled_credits = compound_enrolled.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(compound_enrolled_credits.held, 0);
    __cser_core::assert_eq!(compound_enrolled_credits.retained, 6);
    compound_enrolled.check_invariants().unwrap();

    let mut enrolled_revoke_overflow = registry.clone();
    enrolled_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_revoke_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_closure_overflow = registry.clone();
    enrolled_closure_overflow.next_device_closure_sequence = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_closure_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    for revision in [u64::MAX, u64::MAX - 1] {
        let mut enrolled_revision_overflow = registry.clone();
        enrolled_revision_overflow
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .revision = revision;
        assert_enrolled_precommit_error(
            &mut enrolled_revision_overflow,
            &enrollment,
            RegistryError::CounterOverflow,
        );
    }

    let mut enrolled_authority_overflow = registry.clone();
    let mut overflow_enrollment = enrollment.clone();
    overflow_enrollment.authority_epoch = u64::MAX;
    {
        let scope = enrolled_authority_overflow.scopes.get_mut(&SCOPE).unwrap();
        scope.authority_epoch = u64::MAX;
        scope.device_root.as_mut().unwrap().enrollment = Some(overflow_enrollment.clone());
    }
    let enrolled_authority_effects: Vec<_> = enrolled_authority_overflow.by_scope[&SCOPE]
        .iter()
        .copied()
        .collect();
    for effect in enrolled_authority_effects {
        enrolled_authority_overflow
            .effects
            .get_mut(&effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    assert_enrolled_precommit_error(
        &mut enrolled_authority_overflow,
        &overflow_enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_closing = registry.clone();
    enrolled_closing.revoke_begin(SCOPE).unwrap();
    assert_enrolled_precommit_error(
        &mut enrolled_closing,
        &enrollment,
        RegistryError::ScopeNotActive,
    );

    let mut enrolled_wrong_outcome = registry.clone();
    enrolled_wrong_outcome
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root
        .as_mut()
        .unwrap()
        .outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
    assert_enrolled_precommit_error(
        &mut enrolled_wrong_outcome,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut enrolled_credit_state = registry.clone();
    enrolled_credit_state
        .effects
        .get_mut(&dma_a.identity.effect())
        .unwrap()
        .credit_state = CreditState::Released;
    assert_enrolled_precommit_error(
        &mut enrolled_credit_state,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut enrolled_retention_overflow = registry.clone();
    enrolled_retention_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .credits
        .balances
        .get_mut(&CONTROL)
        .unwrap()
        .retained = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_retention_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_wrong_revoke_cohort = registry.clone();
    let enrolled_wrong_candidates = &mut enrolled_wrong_revoke_cohort
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .closure_candidates;
    __cser_core::assert!(enrolled_wrong_candidates.remove(&dma_a.identity.effect()));
    __cser_core::assert!(enrolled_wrong_candidates.insert(EffectKey::new(u64::MAX, 1)));
    assert_enrolled_precommit_error(
        &mut enrolled_wrong_revoke_cohort,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut foreign_close_enrollment = enrollment.clone();
    foreign_close_enrollment.registry_instance_id = foreign_close_enrollment
        .registry_instance_id
        .checked_add(1)
        .unwrap();
    let mut enrolled_foreign_receipt = registry.clone();
    assert_enrolled_precommit_error(
        &mut enrolled_foreign_receipt,
        &foreign_close_enrollment,
        RegistryError::InvalidBatchReceipt,
    );

    let mut pending_with_enrollment = registry.clone();
    assert_pending_precommit_error(&mut pending_with_enrollment, RegistryError::InvalidState);

    let enrollment_before_registration = registry.clone();
    __cser_core::assert_eq!(
        registry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(7),
                descriptor: SyscallDescriptor::new(7, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(*registry, enrollment_before_registration);

    let mut foreign_registry = registry.clone();
    foreign_registry.rewrite_registry_instance(registry.instance_id + 1);
    let foreign_before = foreign_registry.clone();
    let foreign_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        foreign_registry.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            foreign_publications.set(1)
        },),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(foreign_publications.get(), 0);
    __cser_core::assert_eq!(foreign_registry, foreign_before);

    let unrelated_authority = registry
        .kernel_root_authority(ScopeKey::new(0x2ff, 1), TaskKey::new(0x2ff, 1))
        .unwrap();
    let mut wrong_root = registry.clone();
    let wrong_root_before = wrong_root.clone();
    let wrong_root_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        wrong_root.commit_device_batch_with_publish(
            unrelated_authority,
            &enrollment,
            &commits,
            |_| wrong_root_publications.set(1),
        ),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(wrong_root_publications.get(), 0);
    __cser_core::assert_eq!(wrong_root, wrong_root_before);

    let mut forged_enrollment = enrollment.clone();
    forged_enrollment.device.device_generation += 1;
    let forged_before = registry.clone();
    let forged_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        registry.commit_device_batch_with_publish(authority, &forged_enrollment, &commits, |_| {
            forged_publications.set(1)
        },),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(forged_publications.get(), 0);
    __cser_core::assert_eq!(*registry, forged_before);

    let mut overflow = registry.clone();
    overflow.next_device_batch_sequence = u64::MAX;
    let overflow_before = overflow.clone();
    let overflow_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        overflow.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            overflow_publications.set(1)
        },),
        Err(RegistryError::CounterOverflow)
    ));
    __cser_core::assert_eq!(overflow_publications.get(), 0);
    __cser_core::assert_eq!(overflow, overflow_before);

    let mut revoke_first = registry.clone();
    let revoke_first_selection = revoke_first.revoke_begin(SCOPE).unwrap();
    let revoke_first_before = revoke_first.clone();
    let revoke_first_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        revoke_first.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            revoke_first_publications.set(1)
        },),
        Err(RegistryError::StaleAuthority)
    ));
    __cser_core::assert_eq!(revoke_first_publications.get(), 0);
    __cser_core::assert_eq!(revoke_first, revoke_first_before);
    let selected = revoke_first
        .revoke_next(&revoke_first_selection)
        .unwrap()
        .unwrap();
    __cser_core::assert_eq!(selected.disposition, RevokeDisposition::Abort);
    let before_early_abort = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.stage_revoke_terminal(
            &revoke_first_selection,
            selected.effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(revoke_first, before_early_abort);
    let cancel = revoke_first
        .begin_unpublished_device_cancel(&enrollment)
        .unwrap();
    let retained = revoke_first.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(retained.held, 0);
    __cser_core::assert_eq!(retained.retained, 6);
    let mut forged_cancel = cancel;
    forged_cancel.sequence = forged_cancel.sequence.checked_add(1).unwrap();
    let before_forged_cancel = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&forged_cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_forged_cancel);
    let mut foreign_cancel = cancel;
    foreign_cancel.registry_instance_id =
        foreign_cancel.registry_instance_id.checked_add(1).unwrap();
    let before_foreign_cancel = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&foreign_cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_foreign_cancel);
    let mut cancel_overflow = revoke_first.clone();
    cancel_overflow.next_device_closure_sequence = u64::MAX;
    let before_cancel_overflow = cancel_overflow.clone();
    __cser_core::assert_eq!(
        cancel_overflow.retain_device_reset_timeout(&cancel),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(cancel_overflow, before_cancel_overflow);
    let cancel_tombstone = revoke_first.retain_device_reset_timeout(&cancel).unwrap();
    __cser_core::assert_eq!(cancel_tombstone.device(), device);
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits,
        retained
    );
    revoke_first.check_invariants().unwrap();
    let mut mixed_unpublished_retention = revoke_first.clone();
    mixed_unpublished_retention
        .effects
        .get_mut(&enrollment.effects[0])
        .unwrap()
        .credit_state = CreditState::Held;
    __cser_core::assert_eq!(
        mixed_unpublished_retention.check_invariants(),
        Err(RegistryError::Invariant(
            "retained unpublished credits lack uniform closing precommit abort"
        ))
    );
    let mut held_unpublished_abort = revoke_first.clone();
    for effect in &enrollment.effects {
        held_unpublished_abort
            .effects
            .get_mut(effect)
            .unwrap()
            .credit_state = CreditState::Held;
    }
    __cser_core::assert_eq!(
        held_unpublished_abort.check_invariants(),
        Err(RegistryError::Invariant(
            "retained unpublished credits lack uniform closing precommit abort"
        ))
    );
    let before_cancel_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_cancel_replay);
    let mut cancel_retry_overflow = revoke_first.clone();
    cancel_retry_overflow.next_device_closure_sequence = u64::MAX;
    let before_cancel_retry_overflow = cancel_retry_overflow.clone();
    __cser_core::assert_eq!(
        cancel_retry_overflow.retry_device_reset(&cancel_tombstone),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(cancel_retry_overflow, before_cancel_retry_overflow);
    let cancel_retry = revoke_first.retry_device_reset(&cancel_tombstone).unwrap();
    let before_cancel_retry_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retry_device_reset(&cancel_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_cancel_retry_replay);
    let mut final_reset_timeout = revoke_first.clone();
    let final_reset_tombstone = final_reset_timeout
        .retain_device_reset_timeout(&cancel_retry)
        .unwrap();
    final_reset_timeout.check_invariants().unwrap();
    let before_final_reset_retry = final_reset_timeout.clone();
    __cser_core::assert_eq!(
        final_reset_timeout.retry_device_reset(&final_reset_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(final_reset_timeout, before_final_reset_retry);
    let (reset, ()) = revoke_first
        .acknowledge_device_reset_with_apply(&cancel_retry, |_| ())
        .unwrap();
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::AbortedBeforeCommit);
    let iotlb = revoke_first.begin_device_iotlb(&reset).unwrap();
    let mut forged_iotlb = iotlb;
    forged_iotlb.sequence = forged_iotlb.sequence.checked_add(1).unwrap();
    let before_forged_iotlb = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&forged_iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_forged_iotlb);
    let mut foreign_iotlb = iotlb;
    foreign_iotlb.registry_instance_id = foreign_iotlb.registry_instance_id.checked_add(1).unwrap();
    let before_foreign_iotlb = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&foreign_iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_foreign_iotlb);
    let mut iotlb_overflow = revoke_first.clone();
    iotlb_overflow.next_device_closure_sequence = u64::MAX;
    let before_iotlb_overflow = iotlb_overflow.clone();
    __cser_core::assert_eq!(
        iotlb_overflow.retain_device_iotlb_timeout(&iotlb),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(iotlb_overflow, before_iotlb_overflow);
    let iotlb_tombstone = revoke_first.retain_device_iotlb_timeout(&iotlb).unwrap();
    __cser_core::assert_eq!(iotlb_tombstone.device(), reset.new_device());
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits,
        retained
    );
    revoke_first.check_invariants().unwrap();
    let before_iotlb_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_iotlb_replay);
    let mut iotlb_retry_overflow = revoke_first.clone();
    iotlb_retry_overflow.next_device_closure_sequence = u64::MAX;
    let before_iotlb_retry_overflow = iotlb_retry_overflow.clone();
    __cser_core::assert_eq!(
        iotlb_retry_overflow.retry_device_iotlb(&reset, &iotlb_tombstone),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(iotlb_retry_overflow, before_iotlb_retry_overflow);
    let iotlb_retry = revoke_first
        .retry_device_iotlb(&reset, &iotlb_tombstone)
        .unwrap();
    let before_iotlb_retry_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retry_device_iotlb(&reset, &iotlb_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_iotlb_retry_replay);
    let mut final_iotlb_timeout = revoke_first.clone();
    let final_iotlb_tombstone = final_iotlb_timeout
        .retain_device_iotlb_timeout(&iotlb_retry)
        .unwrap();
    final_iotlb_timeout.check_invariants().unwrap();
    let before_final_iotlb_retry = final_iotlb_timeout.clone();
    __cser_core::assert_eq!(
        final_iotlb_timeout.retry_device_iotlb(&reset, &final_iotlb_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(final_iotlb_timeout, before_final_iotlb_retry);
    let (cancelled, ()) = revoke_first
        .acknowledge_device_iotlb_with_apply(&iotlb_retry, |_| ())
        .unwrap();
    __cser_core::assert!(!cancelled.published());
    __cser_core::assert_eq!(
        cancelled.outcome(),
        DeviceClosureResult::AbortedBeforeCommit
    );
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = revoke_first
            .revoke_next(&revoke_first_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        __cser_core::assert_eq!(next.disposition, RevokeDisposition::Abort);
        revoke_first
            .stage_device_batch_terminal(&cancelled, expected, TerminalRequest::aborted(-125))
            .unwrap();
    }
    __cser_core::assert!(
        revoke_first
            .revoke_next(&revoke_first_selection)
            .unwrap()
            .is_none()
    );
    revoke_first
        .revoke_complete(&revoke_first_selection)
        .unwrap();
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits.free,
        7
    );
    revoke_first.check_invariants().unwrap();

    let close_operation = registry
        .mint_device_close_operation(&enrollment, 0x51_0001)
        .unwrap();
    __cser_core::assert_eq!(close_operation.registry_instance_id(), registry.instance_id);
    __cser_core::assert_eq!(close_operation.scope(), SCOPE);
    __cser_core::assert_eq!(close_operation.authority_epoch(), 17);
    __cser_core::assert_eq!(
        close_operation.enrollment_sequence(),
        enrollment.enrollment_sequence()
    );
    __cser_core::assert_eq!(close_operation.device(), device);
    __cser_core::assert_eq!(close_operation.caller_nonce(), 0x51_0001);
    __cser_core::assert_eq!(
        registry.mint_device_close_operation(&enrollment, 0),
        Err(RegistryError::InvalidGeneration)
    );

    // Model an unwind immediately after `Publishing` is installed and before
    // the external publication closure returns. The projected batch remains
    // root-local, the first revision is durable, and every retry is classified
    // as possibly published without entering either publication or precommit
    // hardware closure again.
    let mut interrupted_close = registry.clone();
    let interrupted_before = interrupted_close.scope_projection(SCOPE).unwrap();
    let interrupted_plan = interrupted_close
        .prepare_device_close(close_operation, authority, &enrollment, &commits)
        .unwrap();
    __cser_core::assert_eq!(
        interrupted_plan.publishing_revision,
        interrupted_before.revision + 1
    );
    __cser_core::assert_eq!(
        interrupted_plan.batch.next_scope_revision,
        interrupted_before.revision + 2
    );
    __cser_core::assert_eq!(
        interrupted_plan.revoke.next_scope_revision,
        interrupted_before.revision + 3
    );
    let interrupted_batch = interrupted_plan.stored_batch.clone();
    let abandoned_apply = interrupted_close.install_device_close_publishing(interrupted_plan);
    __cser_core::assert_eq!(
        interrupted_close.scope_projection(SCOPE).unwrap().revision,
        interrupted_before.revision + 1
    );
    __cser_core::assert_eq!(
        interrupted_close.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Active
    );
    __cser_core::assert!(__cser_core::matches!(
        &interrupted_close.scopes[&SCOPE]
            .device_root
            .as_ref()
            .unwrap()
            .publication,
        DevicePublicationProvenance::Publishing { operation, batch }
            if *operation == close_operation && batch == &interrupted_batch
    ));
    interrupted_close.check_invariants().unwrap();
    let publishing_before_revoke = interrupted_close.clone();
    __cser_core::assert_eq!(
        interrupted_close.revoke_begin(SCOPE),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(interrupted_close, publishing_before_revoke);

    // Independently harden the legacy unpublished-cancel API even against an
    // already-corrupt Closing+Publishing state. It must never convert a
    // possibly published operation into AbortedBeforeCommit.
    let DeviceCloseApplyPlan {
        revoke: abandoned_revoke,
        ..
    } = abandoned_apply;
    let mut forced_closing = interrupted_close.clone();
    forced_closing.apply_revoke_begin(abandoned_revoke);
    let forced_closing_before = forced_closing.clone();
    __cser_core::assert_eq!(
        forced_closing.begin_unpublished_device_cancel(&enrollment),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(forced_closing, forced_closing_before);

    let interrupted_retry_before = interrupted_close.clone();
    let interrupted_retry_publications = Cell::new(0_u8);
    match interrupted_close.commit_or_recover_device_close_with_apply(
        close_operation,
        authority,
        &enrollment,
        &commits,
        |_| {
            interrupted_retry_publications
                .set(interrupted_retry_publications.get().checked_add(1).unwrap())
        },
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(
                obligation.status(),
                DevicePublishedStatus::PossiblyPublished
            );
            __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
            __cser_core::assert_eq!(
                obligation.batch_sequence(),
                Some(interrupted_batch.batch_sequence())
            );
            __cser_core::assert_eq!(obligation.phase(), ScopePhase::Active);
            __cser_core::assert_eq!(obligation.revoke(), None);
            __cser_core::assert_eq!(error, RegistryError::InvalidState);
        }
        _ => __cser_core::panic!("interrupted publication was retried or classified unpublished"),
    }
    __cser_core::assert_eq!(interrupted_retry_publications.get(), 0);
    __cser_core::assert_eq!(interrupted_close, interrupted_retry_before);
    let interrupted_cancel_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        interrupted_close.close_enrolled_device_precommit_with_apply(&enrollment, |_| {
            interrupted_cancel_applies.set(1)
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(interrupted_cancel_applies.get(), 0);
    __cser_core::assert_eq!(interrupted_close, interrupted_retry_before);

    let mut fresh_close = registry.clone();
    let fresh_close_before = fresh_close.scope_projection(SCOPE).unwrap();
    let fresh_close_revoke_sequence = fresh_close.next_revoke_sequence;
    let fresh_close_commit_sequence = fresh_close.next_commit_sequence;
    let fresh_close_batch_sequence = fresh_close.next_device_batch_sequence;
    let fresh_close_enrollment_sequence = fresh_close.next_device_enrollment_sequence;
    let fresh_close_closure_sequence = fresh_close.next_device_closure_sequence;
    let fresh_close_publications = Cell::new(0_u8);
    let (fresh_close_receipt, fresh_close_selection) = match fresh_close
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |prepared| {
                fresh_close_publications
                    .set(fresh_close_publications.get().checked_add(1).unwrap());
                prepared.device().descriptor_token()
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Applied {
            receipt,
            publication,
            selection,
        } => {
            __cser_core::assert_eq!(publication, device.descriptor_token());
            (receipt, selection)
        }
        DeviceCloseOutcome::Recovered { .. } => __cser_core::panic!("fresh device close recovered"),
    };
    __cser_core::assert_eq!(fresh_close_publications.get(), 1);
    __cser_core::assert_eq!(fresh_close_receipt.scope(), SCOPE);
    __cser_core::assert_eq!(fresh_close_selection.scope, SCOPE);
    __cser_core::assert_eq!(fresh_close_selection.target_count, 6);
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().authority_epoch,
        fresh_close_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().revision,
        fresh_close_before.revision + 3
    );
    __cser_core::assert_eq!(
        fresh_close.next_revoke_sequence,
        fresh_close_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        fresh_close.next_commit_sequence,
        fresh_close_commit_sequence + 6
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_batch_sequence,
        fresh_close_batch_sequence + 1
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_enrollment_sequence,
        fresh_close_enrollment_sequence
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_closure_sequence,
        fresh_close_closure_sequence
    );
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Closing
    );
    let fresh_close_root = fresh_close.scopes[&SCOPE].device_root.as_ref().unwrap();
    __cser_core::assert!(__cser_core::matches!(
        &fresh_close_root.publication,
        DevicePublicationProvenance::Applied { operation, batch }
            if *operation == close_operation && batch == &fresh_close_receipt
    ));
    fresh_close.check_invariants().unwrap();

    let mut rewritten_close = fresh_close.clone();
    let rewritten_close_id = rewritten_close.instance_id.checked_add(1).unwrap();
    rewritten_close.rewrite_registry_instance(rewritten_close_id);
    let rewritten_root = rewritten_close.scopes[&SCOPE].device_root.as_ref().unwrap();
    let DevicePublicationProvenance::Applied {
        operation: rewritten_operation,
        batch: rewritten_batch,
    } = &rewritten_root.publication
    else {
        __cser_core::panic!("rewritten close lost applied provenance");
    };
    __cser_core::assert_eq!(
        rewritten_operation.registry_instance_id(),
        rewritten_close_id
    );
    __cser_core::assert_eq!(rewritten_operation.scope(), SCOPE);
    __cser_core::assert_eq!(
        rewritten_operation.caller_nonce(),
        close_operation.caller_nonce()
    );
    __cser_core::assert_eq!(rewritten_batch.registry_instance_id(), rewritten_close_id);
    __cser_core::assert!(
        rewritten_batch
            .commits()
            .iter()
            .all(|commit| commit.registry_instance_id == rewritten_close_id)
    );
    rewritten_close.check_invariants().unwrap();

    let before_closing_recovery = fresh_close.clone();
    let closing_recovery_publications = Cell::new(0_u8);
    match fresh_close
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |_| {
                closing_recovery_publications
                    .set(closing_recovery_publications.get().checked_add(1).unwrap())
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Recovered { receipt, selection } => {
            __cser_core::assert_eq!(receipt, fresh_close_receipt);
            __cser_core::assert_eq!(selection, fresh_close_selection);
        }
        DeviceCloseOutcome::Applied { .. } => __cser_core::panic!("same operation republished"),
    }
    __cser_core::assert_eq!(closing_recovery_publications.get(), 0);
    __cser_core::assert_eq!(fresh_close, before_closing_recovery);

    let assert_published_close_error =
        |candidate: &mut EffectRegistry,
         operation: DeviceCloseOperationId,
         presented: &DeviceBatchEnrollmentReceipt,
         presented_commits: &[(PortalHandle, CommitMetadata)]| {
            let before = candidate.clone();
            let publish_calls = Cell::new(0_u8);
            match candidate.commit_or_recover_device_close_with_apply(
                operation,
                authority,
                presented,
                presented_commits,
                |_| publish_calls.set(publish_calls.get().checked_add(1).unwrap()),
            ) {
                Err(DeviceCloseError::Published { obligation, .. }) => {
                    __cser_core::assert_eq!(
                        obligation.registry_instance_id(),
                        registry.instance_id
                    );
                    __cser_core::assert_eq!(obligation.scope(), SCOPE);
                    __cser_core::assert_eq!(obligation.device(), device);
                    __cser_core::assert_eq!(
                        obligation.batch_sequence(),
                        Some(fresh_close_receipt.batch_sequence())
                    );
                    __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
                    __cser_core::assert_eq!(obligation.phase(), ScopePhase::Closing);
                    __cser_core::assert_eq!(obligation.revoke(), Some(&fresh_close_selection));
                    __cser_core::assert_eq!(obligation.reset_ticket(), None);
                    __cser_core::assert_eq!(obligation.reset_tombstone(), None);
                    __cser_core::assert!(!obligation.reset_retry_issued());
                    __cser_core::assert_eq!(obligation.reset_receipt(), None);
                    __cser_core::assert_eq!(obligation.iotlb_ticket(), None);
                    __cser_core::assert_eq!(obligation.iotlb_tombstone(), None);
                    __cser_core::assert!(!obligation.iotlb_retry_issued());
                    __cser_core::assert_eq!(obligation.closure(), None);
                }
                _ => __cser_core::panic!("published input drift lacked ownership obligation"),
            }
            __cser_core::assert_eq!(publish_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut wrong_operation = close_operation;
    wrong_operation.caller_nonce = wrong_operation.caller_nonce.checked_add(1).unwrap();
    let mut wrong_operation_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_operation_candidate,
        wrong_operation,
        &enrollment,
        &commits,
    );

    let mut wrong_operation_registry = close_operation;
    wrong_operation_registry.registry_instance_id = wrong_operation_registry
        .registry_instance_id
        .checked_add(1)
        .unwrap();
    let mut wrong_registry_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_registry_candidate,
        wrong_operation_registry,
        &enrollment,
        &commits,
    );

    let mut wrong_close_enrollment = enrollment.clone();
    wrong_close_enrollment.enrollment_sequence = wrong_close_enrollment
        .enrollment_sequence
        .checked_add(1)
        .unwrap();
    let mut wrong_enrollment_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_enrollment_candidate,
        close_operation,
        &wrong_close_enrollment,
        &commits,
    );

    let mut wrong_close_commits = commits;
    wrong_close_commits[0].1 = CommitMetadata::new(5, 1);
    let mut wrong_metadata_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_metadata_candidate,
        close_operation,
        &enrollment,
        &wrong_close_commits,
    );

    let mut corrupt_operation_state = fresh_close.clone();
    {
        let root = corrupt_operation_state
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .device_root
            .as_mut()
            .unwrap();
        root.batch_sequence = None;
        root.publication = DevicePublicationProvenance::Applied {
            operation: close_operation,
            batch: fresh_close_receipt.clone(),
        };
    }
    let corrupt_before = corrupt_operation_state.clone();
    let corrupt_publish_calls = Cell::new(0_u8);
    match corrupt_operation_state.commit_or_recover_device_close_with_apply(
        close_operation,
        authority,
        &enrollment,
        &commits,
        |_| corrupt_publish_calls.set(corrupt_publish_calls.get().checked_add(1).unwrap()),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(
                obligation.batch_sequence(),
                Some(fresh_close_receipt.batch_sequence())
            );
            __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
            __cser_core::assert_eq!(error, RegistryError::InvalidBatchReceipt);
        }
        _ => __cser_core::panic!("corrupt operation state was misclassified as unpublished"),
    }
    __cser_core::assert_eq!(corrupt_publish_calls.get(), 0);
    __cser_core::assert_eq!(corrupt_operation_state, corrupt_before);

    let assert_fresh_close_overflow = |candidate: &mut EffectRegistry| {
        let before = candidate.clone();
        let publish_calls = Cell::new(0_u8);
        __cser_core::assert!(__cser_core::matches!(
            candidate.commit_or_recover_device_close_with_apply(
                close_operation,
                authority,
                &enrollment,
                &commits,
                |_| publish_calls.set(publish_calls.get().checked_add(1).unwrap()),
            ),
            Err(DeviceCloseError::Unpublished(
                RegistryError::CounterOverflow
            ))
        ));
        __cser_core::assert_eq!(publish_calls.get(), 0);
        __cser_core::assert_eq!(*candidate, before);
    };

    let mut close_revoke_overflow = registry.clone();
    close_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_fresh_close_overflow(&mut close_revoke_overflow);

    let mut close_commit_overflow = registry.clone();
    close_commit_overflow.next_commit_sequence = u64::MAX - 5;
    assert_fresh_close_overflow(&mut close_commit_overflow);

    let mut close_batch_overflow = registry.clone();
    close_batch_overflow.next_device_batch_sequence = u64::MAX;
    assert_fresh_close_overflow(&mut close_batch_overflow);

    let mut close_commit_revision_overflow = registry.clone();
    close_commit_revision_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .revision = u64::MAX;
    assert_fresh_close_overflow(&mut close_commit_revision_overflow);

    let mut close_revoke_revision_overflow = registry.clone();
    close_revoke_revision_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .revision = u64::MAX - 1;
    assert_fresh_close_overflow(&mut close_revoke_revision_overflow);

    let mut close_authority_overflow = registry.clone();
    let mut overflow_enrollment = enrollment.clone();
    overflow_enrollment.authority_epoch = u64::MAX;
    {
        let scope = close_authority_overflow.scopes.get_mut(&SCOPE).unwrap();
        scope.authority_epoch = u64::MAX;
        scope.device_root.as_mut().unwrap().enrollment = Some(overflow_enrollment.clone());
    }
    for effect in &overflow_enrollment.effects {
        close_authority_overflow
            .effects
            .get_mut(effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    let mut overflow_authority = authority;
    overflow_authority.authority_epoch = u64::MAX;
    let mut overflow_commits = commits;
    for (handle, _) in &mut overflow_commits {
        handle.authority_epoch = u64::MAX;
    }
    let overflow_operation = close_authority_overflow
        .mint_device_close_operation(&overflow_enrollment, 0x51_0002)
        .unwrap();
    let close_authority_before = close_authority_overflow.clone();
    let authority_publish_calls = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        close_authority_overflow.commit_or_recover_device_close_with_apply(
            overflow_operation,
            overflow_authority,
            &overflow_enrollment,
            &overflow_commits,
            |_| authority_publish_calls.set(authority_publish_calls.get().checked_add(1).unwrap()),
        ),
        Err(DeviceCloseError::Unpublished(
            RegistryError::CounterOverflow
        ))
    ));
    __cser_core::assert_eq!(authority_publish_calls.get(), 0);
    __cser_core::assert_eq!(close_authority_overflow, close_authority_before);

    let mut revoked_recovery = fresh_close.clone();
    let reset_ticket = revoked_recovery
        .begin_device_reset(&fresh_close_receipt)
        .unwrap();
    let (reset_receipt, ()) = revoked_recovery
        .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())
        .unwrap();
    let iotlb_ticket = revoked_recovery.begin_device_iotlb(&reset_receipt).unwrap();
    let (closure, ()) = revoked_recovery
        .acknowledge_device_iotlb_with_apply(&iotlb_ticket, |_| ())
        .unwrap();
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = revoked_recovery
            .revoke_next(&fresh_close_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        revoked_recovery
            .stage_device_batch_terminal(
                &closure,
                expected,
                TerminalRequest::indeterminate_after_reset(-5),
            )
            .unwrap();
    }
    __cser_core::assert!(
        revoked_recovery
            .revoke_next(&fresh_close_selection)
            .unwrap()
            .is_none()
    );
    revoked_recovery
        .revoke_complete(&fresh_close_selection)
        .unwrap();
    __cser_core::assert_eq!(
        revoked_recovery.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Revoked
    );
    revoked_recovery.check_invariants().unwrap();
    let before_revoked_recovery = revoked_recovery.clone();
    let revoked_recovery_publications = Cell::new(0_u8);
    match revoked_recovery
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |_| {
                revoked_recovery_publications
                    .set(revoked_recovery_publications.get().checked_add(1).unwrap())
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Recovered { receipt, selection } => {
            __cser_core::assert_eq!(receipt, fresh_close_receipt);
            __cser_core::assert_eq!(selection, fresh_close_selection);
        }
        DeviceCloseOutcome::Applied { .. } => __cser_core::panic!("revoked operation republished"),
    }
    __cser_core::assert_eq!(revoked_recovery_publications.get(), 0);
    __cser_core::assert_eq!(revoked_recovery, before_revoked_recovery);

    let legacy_operation = registry
        .mint_device_close_operation(&enrollment, 0x51_1001)
        .unwrap();
    let publications = Cell::new(0_u8);
    let receipt = match registry
        .commit_device_batch_with_publish(authority, &enrollment, &commits, |prepared| {
            __cser_core::assert_eq!(prepared.commits().len(), 6);
            __cser_core::assert_eq!(prepared.device_effects().len(), 4);
            publications.set(publications.get() + 1);
            prepared.device().descriptor_token()
        })
        .unwrap()
    {
        DeviceBatchCommitOutcome::Applied {
            receipt,
            publication,
        } => {
            __cser_core::assert_eq!(publication, 0);
            receipt
        }
        DeviceBatchCommitOutcome::AlreadyCommitted { .. } => {
            __cser_core::panic!("fresh device batch replayed")
        }
    };
    __cser_core::assert_eq!(publications.get(), 1);
    __cser_core::assert_eq!(receipt.registry_instance_id(), registry.instance_id);
    __cser_core::assert_eq!(receipt.scope(), SCOPE);
    __cser_core::assert_eq!(receipt.authority_epoch(), 17);
    __cser_core::assert_eq!(receipt.batch_sequence(), 1);
    __cser_core::assert_eq!(receipt.device(), device);
    __cser_core::assert_eq!(receipt.commits().len(), 6);
    __cser_core::assert_eq!(receipt.device_effects().len(), 4);
    registry.validate_device_batch_receipt(&receipt).unwrap();
    registry.check_invariants().unwrap();
    let committed = registry.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(committed.capacity, 7);
    __cser_core::assert_eq!(committed.free, 1);
    __cser_core::assert_eq!(committed.held, 0);
    __cser_core::assert_eq!(committed.committed, 6);
    __cser_core::assert_eq!(committed.retained, 0);

    let replay_publications = Cell::new(0_u8);
    match registry
        .commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            replay_publications.set(1)
        })
        .unwrap()
    {
        DeviceBatchCommitOutcome::AlreadyCommitted { receipt: replay } => {
            __cser_core::assert_eq!(replay, receipt)
        }
        DeviceBatchCommitOutcome::Applied { .. } => {
            __cser_core::panic!("device batch published twice")
        }
    }
    __cser_core::assert_eq!(replay_publications.get(), 0);

    let legacy_before = registry.clone();
    let legacy_publish_calls = Cell::new(0_u8);
    match registry.commit_or_recover_device_close_with_apply(
        legacy_operation,
        authority,
        &enrollment,
        &commits,
        |_| legacy_publish_calls.set(legacy_publish_calls.get().checked_add(1).unwrap()),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(obligation.registry_instance_id(), registry.instance_id);
            __cser_core::assert_eq!(obligation.scope(), SCOPE);
            __cser_core::assert_eq!(obligation.device(), device);
            __cser_core::assert_eq!(obligation.batch_sequence(), Some(receipt.batch_sequence()));
            __cser_core::assert_eq!(obligation.operation(), None);
            __cser_core::assert_eq!(obligation.phase(), ScopePhase::Active);
            __cser_core::assert_eq!(obligation.revoke(), None);
            __cser_core::assert_eq!(obligation.reset_ticket(), None);
            __cser_core::assert_eq!(obligation.closure(), None);
            __cser_core::assert_eq!(error, RegistryError::InvalidState);
        }
        _ => __cser_core::panic!("legacy committed state was not an honest Published error"),
    }
    __cser_core::assert_eq!(legacy_publish_calls.get(), 0);
    __cser_core::assert_eq!(*registry, legacy_before);

    let replay_before = registry.clone();
    __cser_core::assert_eq!(
        registry.commit(PERSONALITY, syscall.handle, commits[0].1),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(*registry, replay_before);

    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device.device_generation += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::StaleDeviceGeneration)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device.device_session += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.commits.swap(0, 1);
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device_effects.pop();
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.registry_instance_id += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );

    let mut wrong_completion_result = registry.clone();
    let wrong_completion_before = wrong_completion_result.clone();
    __cser_core::assert_eq!(
        wrong_completion_result.record_device_completion(&receipt, device, 512),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(wrong_completion_result, wrong_completion_before);

    // Normal completion still requires whole-device reset and IOTLB closure.
    let mut normal = registry.clone();
    let completion = normal
        .record_device_completion(&receipt, device, 4)
        .unwrap();
    __cser_core::assert_eq!(completion.device(), device);
    __cser_core::assert_eq!(completion.result(), 4);
    __cser_core::assert_eq!(completion.causal_root(), syscall.identity.effect());
    let reset_ticket = normal.begin_device_reset(&receipt).unwrap();
    let reset_applies = Cell::new(0_u8);
    let (reset, ()) = normal
        .acknowledge_device_reset_with_apply(&reset_ticket, |prepared| {
            __cser_core::assert_eq!(prepared.old_device(), device);
            reset_applies.set(1);
        })
        .unwrap();
    __cser_core::assert_eq!(reset_applies.get(), 1);
    __cser_core::assert_eq!(reset.old_device(), device);
    __cser_core::assert_eq!(reset.new_device().device_generation(), 2);
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::Completed(4));
    let iotlb = normal.begin_device_iotlb(&reset).unwrap();
    let mut iotlb_overflow = normal.clone();
    iotlb_overflow.next_device_closure_sequence = u64::MAX;
    let iotlb_overflow_before = iotlb_overflow.clone();
    let overflow_applies = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        iotlb_overflow.acknowledge_device_iotlb_with_apply(&iotlb, |_| { overflow_applies.set(1) }),
        Err(RegistryError::CounterOverflow)
    ));
    __cser_core::assert_eq!(overflow_applies.get(), 0);
    __cser_core::assert_eq!(iotlb_overflow, iotlb_overflow_before);

    let iotlb_applies = Cell::new(0_u8);
    let (normal_closure, ()) = normal
        .acknowledge_device_iotlb_with_apply(&iotlb, |prepared| {
            __cser_core::assert_eq!(prepared.device(), reset.new_device());
            iotlb_applies.set(1);
        })
        .unwrap();
    __cser_core::assert_eq!(iotlb_applies.get(), 1);
    let normal_after_closure = normal.clone();
    let duplicate_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        normal.acknowledge_device_iotlb_with_apply(&iotlb, |_| duplicate_applies.set(1)),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(duplicate_applies.get(), 0);
    __cser_core::assert_eq!(normal, normal_after_closure);
    __cser_core::assert_eq!(normal_closure.outcome(), DeviceClosureResult::Completed(4));
    let normal_before_generic = normal.clone();
    __cser_core::assert_eq!(
        normal.stage_kernel_completion(receipt.commit_for(dma_a.identity.effect()).unwrap()),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(normal, normal_before_generic);
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let commit = receipt.commit_for(expected).unwrap();
        normal
            .stage_device_batch_terminal(
                &normal_closure,
                expected,
                TerminalRequest::completed(commit.result()),
            )
            .unwrap();
    }
    let normal_projection = normal.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(normal_projection.live_effects, 0);
    __cser_core::assert_eq!(normal_projection.credits.free, 7);
    __cser_core::assert_eq!(normal_projection.credits.retained, 0);
    normal.check_invariants().unwrap();

    // Published ownership with no authoritative completion becomes a real
    // indeterminate terminal only when reset advances the device generation.
    let mut indeterminate = registry.clone();
    let reset_ticket = indeterminate.begin_device_reset(&receipt).unwrap();
    __cser_core::assert_eq!(
        indeterminate.scopes[&SCOPE]
            .device_root
            .as_ref()
            .unwrap()
            .outcome,
        None
    );
    let (reset, ()) = indeterminate
        .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())
        .unwrap();
    __cser_core::assert_eq!(
        reset.outcome(),
        DeviceClosureResult::IndeterminateAfterReset
    );
    let iotlb = indeterminate.begin_device_iotlb(&reset).unwrap();
    let (indeterminate_closure, ()) = indeterminate
        .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())
        .unwrap();
    indeterminate
        .stage_device_batch_terminal(
            &indeterminate_closure,
            dma_a.identity.effect(),
            TerminalRequest::indeterminate_after_reset(-5),
        )
        .unwrap();
    __cser_core::assert_eq!(
        indeterminate
            .effect_view(dma_a.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset)
    );
    indeterminate.check_invariants().unwrap();

    let selection = registry.revoke_begin(SCOPE).unwrap();
    registry.validate_device_batch_receipt(&receipt).unwrap();
    let after_revoke = registry.clone();
    let late_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        registry.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            late_publications.set(1)
        },),
        Err(RegistryError::StaleAuthority)
    ));
    __cser_core::assert_eq!(late_publications.get(), 0);
    __cser_core::assert_eq!(*registry, after_revoke);

    let selected = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected.effect, dma_a.identity.effect());
    let before_generic_drain = registry.clone();
    __cser_core::assert_eq!(
        registry.stage_revoke_terminal(
            &selection,
            selected.effect,
            TerminalRequest::completed(match selected.disposition {
                RevokeDisposition::Drain(ref commit) => commit.result(),
                RevokeDisposition::Abort =>
                    __cser_core::panic!("committed device batch became abortable"),
            }),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(*registry, before_generic_drain);
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );

    registry
        .record_device_completion(&receipt, device, 4)
        .unwrap();
    let reset_ticket = registry.begin_device_reset(&receipt).unwrap();
    let reset_tombstone = registry.retain_device_reset_timeout(&reset_ticket).unwrap();
    __cser_core::assert_eq!(reset_tombstone.device(), device);
    let retained = registry.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(retained.free, 1);
    __cser_core::assert_eq!(retained.held, 0);
    __cser_core::assert_eq!(retained.committed, 0);
    __cser_core::assert_eq!(retained.retained, 6);
    registry.check_invariants().unwrap();
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );
    let retry = registry.retry_device_reset(&reset_tombstone).unwrap();
    let reset_applies = Cell::new(0_u8);
    let (reset, ()) = registry
        .acknowledge_device_reset_with_apply(&retry, |_| reset_applies.set(1))
        .unwrap();
    __cser_core::assert_eq!(reset_applies.get(), 1);
    __cser_core::assert_eq!(reset.new_device().device_generation(), 2);
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::Completed(4));
    registry.check_invariants().unwrap();

    let before_late_completion = registry.clone();
    __cser_core::assert_eq!(
        registry.record_device_completion(&receipt, device, 4),
        Err(RegistryError::StaleDeviceGeneration)
    );
    __cser_core::assert_eq!(*registry, before_late_completion);

    let iotlb = registry.begin_device_iotlb(&reset).unwrap();
    let iotlb_tombstone = registry.retain_device_iotlb_timeout(&iotlb).unwrap();
    __cser_core::assert_eq!(iotlb_tombstone.device().device_generation(), 2);
    let iotlb_retry = registry
        .retry_device_iotlb(&reset, &iotlb_tombstone)
        .unwrap();
    let (closure, ()) = registry
        .acknowledge_device_iotlb_with_apply(&iotlb_retry, |_| ())
        .unwrap();
    __cser_core::assert_eq!(closure.device().device_generation(), 2);
    __cser_core::assert_eq!(closure.outcome(), DeviceClosureResult::Completed(4));
    registry.validate_device_closure_receipt(&closure).unwrap();
    registry.check_invariants().unwrap();
    let mut stale_closure = closure;
    stale_closure.device = device;
    let before_stale_closure = registry.clone();
    __cser_core::assert_eq!(
        registry.validate_device_closure_receipt(&stale_closure),
        Err(RegistryError::StaleDeviceGeneration)
    );
    __cser_core::assert_eq!(*registry, before_stale_closure);
    let mut forged_closure = closure;
    forged_closure.batch_sequence = forged_closure
        .batch_sequence
        .and_then(|sequence| sequence.checked_add(1));
    let before_forged_closure = registry.clone();
    __cser_core::assert_eq!(
        registry.stage_device_batch_terminal(
            &forged_closure,
            dma_a.identity.effect(),
            TerminalRequest::completed(1),
        ),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(*registry, before_forged_closure);

    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = registry.revoke_next(&selection).unwrap().unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        let result = match next.disposition {
            RevokeDisposition::Drain(commit) => commit.result(),
            RevokeDisposition::Abort => {
                __cser_core::panic!("committed device batch became abortable")
            }
        };
        registry
            .stage_device_batch_terminal(&closure, expected, TerminalRequest::completed(result))
            .unwrap();
    }
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.validate_device_batch_receipt(&receipt).unwrap();
    let closed = registry.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(closed.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(closed.live_effects, 0);
    __cser_core::assert_eq!(closed.credits.free, 7);
    __cser_core::assert_eq!(closed.credits.held, 0);
    __cser_core::assert_eq!(closed.credits.committed, 0);
    __cser_core::assert_eq!(closed.credits.retained, 0);
    registry.check_invariants().unwrap();
}

/// Exercises the staged registry without changing the kernel's current run
/// sequence.  A later OSTD runner can call this and print the returned receipt.
pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {
    const WAIT_CREDIT: CreditClass = CreditClass::new(1);
    const SYSCALL_CREDIT: CreditClass = CreditClass::new(2);

    bounded_kernel_completion_during_recovery_self_test();
    stage7b_registry_refactor_self_test();
    production_identity_registry_self_test();

    let scope = ScopeKey::new(50, 1);
    let v1 = TaskKey::new(600, 1);
    let v2 = TaskKey::new(601, 1);
    let waiter = TaskKey::new(610, 1);
    let caller = TaskKey::new(611, 1);
    let futex_a = ResourceKey::new(1, 700, 1);
    let futex_b = ResourceKey::new(1, 701, 1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 111,
            binding_epoch: 1,
            supervisor: v1,
            credits: __cser_alloc::vec![
                CreditLimit::new(WAIT_CREDIT, 1),
                CreditLimit::new(SYSCALL_CREDIT, 1),
            ],
        })
        .unwrap();

    let wait = registry
        .register(RegisterRequest {
            scope,
            task: waiter,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(202, [0x402010, 128, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![futex_a],
            credits: __cser_alloc::vec![CreditCharge::new(WAIT_CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, wait.handle).unwrap();

    let requeue = registry
        .register(RegisterRequest {
            scope,
            task: caller,
            operation: OperationClass::new(3),
            descriptor: SyscallDescriptor::new(202, [0x402010, 131, 0, 1, 0x402018, 0]),
            resources: __cser_alloc::vec![futex_a, futex_b],
            credits: __cser_alloc::vec![CreditCharge::new(SYSCALL_CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, requeue.handle).unwrap();
    let committed = match registry
        .commit_with_moves(
            v1,
            &[(requeue.handle, CommitMetadata::new(1, 7))],
            &[ResourceMove {
                handle: wait.handle,
                current_resources: __cser_alloc::vec![futex_b],
            }],
        )
        .unwrap()
        .pop()
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    __cser_core::assert!(
        !registry
            .effects_for_resource(futex_a)
            .contains(&wait.identity.effect())
    );
    __cser_core::assert!(
        registry
            .effects_for_resource(futex_b)
            .contains(&wait.identity.effect())
    );
    registry.check_invariants().unwrap();

    let crash = registry.crash(scope, v1).unwrap();
    __cser_core::assert_eq!(crash.cohort.len(), 2);
    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();

    let mut adopted = BTreeMap::new();
    while let Some(item) = registry.recover_next(scope, v2).unwrap() {
        let effect = item.handle.effect();
        let handle = registry.adopt(scope, v2, item.handle).unwrap();
        adopted.insert(effect, handle);
    }
    __cser_core::assert_eq!(adopted.len(), 2);
    __cser_core::assert_eq!(registry.recovery_remaining(scope).unwrap(), 0);
    __cser_core::assert_eq!(
        registry
            .commit(
                v2,
                *adopted.get(&requeue.identity.effect()).unwrap(),
                CommitMetadata::new(1, 7),
            )
            .unwrap(),
        CommitOutcome::AlreadyCommitted(committed.clone())
    );

    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert_eq!(
        registry.prepare(v2, *adopted.get(&wait.identity.effect()).unwrap()),
        Err(RegistryError::StaleAuthority)
    );

    let mut tickets = Vec::new();
    while let Some(effect) = registry.revoke_next(&selection).unwrap() {
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(ref receipt) => TerminalRequest::completed(receipt.result()),
        };
        let terminal = registry
            .stage_revoke_terminal(&selection, effect.effect, request)
            .unwrap();
        tickets.push(terminal.publication.unwrap());
    }
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );
    for ticket in &tickets {
        registry.acknowledge_publication(ticket).unwrap();
    }
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
    let projection = registry.scope_projection(scope).unwrap();
    __cser_core::assert_eq!(projection.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(projection.live_effects, 0);
    __cser_core::assert_eq!(projection.pending_publications, 0);
    __cser_core::assert_eq!(projection.credits.free, projection.credits.capacity);

    // A diagnostic before/after hash must not depend on how many unrelated
    // negative registries happened to be allocated earlier in the boot. The
    // authoritative live receipts retain their original instance namespace.
    let mut renamespaced = registry.clone();
    let renamespaced_id = registry.instance_id.checked_add(1).unwrap();
    renamespaced.rewrite_registry_instance(renamespaced_id);
    renamespaced.check_invariants().unwrap();
    __cser_core::assert_ne!(registry.instance_id, renamespaced.instance_id);
    __cser_core::assert_ne!(
        __cser_alloc::format!("{registry:?}"),
        __cser_alloc::format!("{renamespaced:?}")
    );
    __cser_core::assert_eq!(
        registry.failure_atomic_projection(),
        renamespaced.failure_atomic_projection()
    );

    RegistrySelfTestReceipt {
        effects: 2,
        recovery_adoptions: adopted.len(),
        committed_drains: 1,
        uncommitted_aborts: 1,
        publication_acks: tickets.len(),
        stale_authority_rejected: true,
        quiescent: true,
    }
}

/// Minimal two-effect harness for exploring the production device
/// enrollment+commit/revoke winner under a modeled outer lock. The six-effect
/// workload population is pinned by `production_device_batch_registry_self_test`;
/// this smaller harness isolates the pending-enrollment publication boundary so
/// Loom does not turn graph construction into the race under test.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ProductionDeviceBatchRaceFixture {
    registry: EffectRegistry,
    scope: ScopeKey,
    authority: KernelRootAuthority,
    enrollment: Option<DeviceBatchEnrollmentReceipt>,
    commits: [(PortalHandle, CommitMetadata); 2],
    device: DeviceEnvelope,
    batch: Option<DeviceBatchCommitReceipt>,
    publications: u8,
    closures: u8,
}

impl ProductionDeviceBatchRaceFixture {
    pub(crate) fn from_empty_registry(mut registry: EffectRegistry) -> Self {
        const SCOPE: ScopeKey = ScopeKey::new(0x3f0, 1);
        const ROOT_OWNER: TaskKey = TaskKey::new(0x3f0, 1);
        const CONTROL: TaskKey = TaskKey::new(0x3f1, 1);
        const DEVICE: TaskKey = TaskKey::new(0x3f2, 1);
        const CONTROL_DOMAIN: DomainKey = DomainKey::new(1);
        const DEVICE_DOMAIN: DomainKey = DomainKey::new(2);
        const CONTROL_CREDIT: CreditClass = CreditClass::new(0x3f1);
        const DEVICE_CREDIT: CreditClass = CreditClass::new(0x3f2);

        __cser_core::assert!(registry.scopes.is_empty());
        let device = DeviceEnvelope::new(0x3f, 0, 0, 1).unwrap();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 31,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![
                    CreditLimit::new(CONTROL_CREDIT, 1),
                    CreditLimit::new(DEVICE_CREDIT, 1),
                ],
            })
            .unwrap();
        for config in [
            DomainConfig {
                key: CONTROL_DOMAIN,
                binding_epoch: 1,
                supervisor: CONTROL,
            },
            DomainConfig {
                key: DEVICE_DOMAIN,
                binding_epoch: 1,
                supervisor: DEVICE,
            },
        ] {
            registry.add_domain(SCOPE, config).unwrap();
        }
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: CONTROL,
                    operation: OperationClass::new(1),
                    descriptor: SyscallDescriptor::new(17, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x3f, 1, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(CONTROL_CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: CONTROL_DOMAIN,
                parent: None,
            })
            .unwrap();
        let child = registry
            .register_device_derived(DeviceDerivedRegisterRequest {
                derived: DerivedRegisterRequest {
                    request: RegisterRequest {
                        scope: SCOPE,
                        task: DEVICE,
                        operation: OperationClass::new(2),
                        descriptor: SyscallDescriptor::new(2, [0; 6]),
                        resources: __cser_alloc::vec![ResourceKey::new(0x3f, 2, 1)],
                        credits: __cser_alloc::vec![CreditCharge::new(DEVICE_CREDIT, 1)],
                        publication: PublicationMode::None,
                    },
                    domain: DEVICE_DOMAIN,
                    parent: Some(root.identity.effect()),
                },
                device,
            })
            .unwrap();
        registry.prepare(CONTROL, root.handle).unwrap();
        registry.prepare(DEVICE, child.handle).unwrap();
        let authority = registry.kernel_root_authority(SCOPE, ROOT_OWNER).unwrap();
        let commits = [
            (root.handle, CommitMetadata::new(1, 1)),
            (child.handle, CommitMetadata::new(1, 1)),
        ];
        registry.check_invariants().unwrap();
        Self {
            registry,
            scope: SCOPE,
            authority,
            enrollment: None,
            commits,
            device,
            batch: None,
            publications: 0,
            closures: 0,
        }
    }

    pub(crate) fn commit(&mut self) -> Result<bool, RegistryError> {
        if self.enrollment.is_none() {
            self.enrollment = Some(self.registry.enroll_device_batch(
                self.authority,
                &[self.commits[0].0, self.commits[1].0],
                self.device,
            )?);
        }
        let outcome = self.registry.commit_device_batch_with_publish(
            self.authority,
            self.enrollment.as_ref().unwrap(),
            &self.commits,
            |_| (),
        )?;
        match outcome {
            DeviceBatchCommitOutcome::Applied { receipt, .. } => {
                self.publications = self
                    .publications
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                self.batch = Some(receipt);
                Ok(true)
            }
            DeviceBatchCommitOutcome::AlreadyCommitted { receipt } => {
                self.batch = Some(receipt);
                Ok(false)
            }
        }
    }

    pub(crate) fn revoke_to_completion(&mut self) -> Result<(), RegistryError> {
        let selection = self.registry.revoke_begin(self.scope)?;
        let closure = if let Some(batch) = self.batch.as_ref() {
            let reset_ticket = self.registry.begin_device_reset(batch)?;
            let (reset, ()) = self
                .registry
                .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())?;
            let iotlb = self.registry.begin_device_iotlb(&reset)?;
            self.registry
                .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())?
                .0
        } else {
            if self.enrollment.is_none() {
                self.enrollment = Some(self.registry.freeze_pending_device_cancel(self.scope)?);
            }
            let reset_ticket = self
                .registry
                .begin_unpublished_device_cancel(self.enrollment.as_ref().unwrap())?;
            let (reset, ()) = self
                .registry
                .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())?;
            let iotlb = self.registry.begin_device_iotlb(&reset)?;
            self.registry
                .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())?
                .0
        };
        self.closures = self
            .closures
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        while let Some(effect) = self.registry.revoke_next(&selection)? {
            match (closure.outcome, effect.disposition) {
                (DeviceClosureResult::AbortedBeforeCommit, RevokeDisposition::Abort) => {
                    self.registry.stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::aborted(-125),
                    )?;
                }
                (DeviceClosureResult::IndeterminateAfterReset, RevokeDisposition::Drain(_)) => {
                    self.registry.stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::indeterminate_after_reset(-5),
                    )?;
                }
                (DeviceClosureResult::Completed(_), RevokeDisposition::Drain(receipt)) => self
                    .registry
                    .stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::completed(receipt.result()),
                    )
                    .map(|_| ())?,
                _ => return Err(RegistryError::InvalidState),
            }
        }
        self.registry.revoke_complete(&selection)?;
        self.registry.check_invariants()
    }

    pub(crate) fn phase(&self) -> ScopePhase {
        self.registry.scope_projection(self.scope).unwrap().phase
    }

    pub(crate) fn publications(&self) -> u8 {
        self.publications
    }

    pub(crate) fn closures(&self) -> u8 {
        self.closures
    }

    pub(crate) fn failure_atomic_projection(&self) -> String {
        __cser_alloc::format!("{self:?}")
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        let projection = self.registry.scope_projection(self.scope).unwrap();
        projection.phase == ScopePhase::Revoked
            && projection.live_effects == 0
            && projection.pending_publications == 0
            && projection.credits.free == projection.credits.capacity
            && projection.credits.held == 0
            && projection.credits.committed == 0
            && projection.credits.retained == 0
    }
}

pub(crate) fn production_handoff_retained_self_test(
    blocked_registry: EffectRegistry,
    retained_registry: EffectRegistry,
) {
    use cser_transition_gates::handoff::{HandoffId, LogPosition};

    fn intent(id: u64) -> PrepareIntent {
        PrepareIntent::new(
            HandoffId::new(id).unwrap(),
            0xa10,
            LogPosition::new(0xa11).unwrap(),
            0xa12,
            0xa13,
            0xa14,
        )
        .unwrap()
    }

    let mut blocked = ProductionDeviceBatchRaceFixture::from_empty_registry(blocked_registry);
    blocked.commit().unwrap();
    let batch = blocked.batch.clone().unwrap();
    let reset = blocked.registry.begin_device_reset(&batch).unwrap();
    blocked
        .registry
        .retain_device_reset_timeout(&reset)
        .unwrap();
    let prepare = intent(0xa20);
    let freeze = blocked
        .registry
        .freeze_admission(blocked.scope, prepare)
        .unwrap();
    __cser_core::assert_eq!(freeze.readiness(), HandoffFreezeReadiness::BlockedRetained);
    let commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0xa21).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let before = blocked.registry.failure_atomic_projection();
    __cser_core::assert_eq!(
        blocked.registry.commit_handoff_close(blocked.scope, commit),
        Err(RegistryError::HandoffNotReady)
    );
    __cser_core::assert_eq!(blocked.registry.failure_atomic_projection(), before);

    let mut retained = ProductionDeviceBatchRaceFixture::from_empty_registry(retained_registry);
    retained.commit().unwrap();
    let batch = retained.batch.clone().unwrap();
    let prepare = intent(0xa30);
    let freeze = retained
        .registry
        .freeze_admission(retained.scope, prepare)
        .unwrap();
    let commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0xa31).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let selection = match retained
        .registry
        .commit_handoff_close(retained.scope, commit)
        .unwrap()
    {
        ProductionHandoffProgress::Closing(selection) => selection,
        other => __cser_core::panic!("unexpected committed handoff progress: {other:?}"),
    };
    let reset_ticket = retained.registry.begin_device_reset(&batch).unwrap();
    let tombstone = retained
        .registry
        .retain_device_reset_timeout(&reset_ticket)
        .unwrap();
    __cser_core::assert_eq!(
        retained
            .registry
            .query_handoff(retained.scope, freeze.freeze())
            .unwrap(),
        ProductionHandoffProgress::Retained(selection.clone())
    );
    __cser_core::assert_eq!(
        retained
            .registry
            .commit_handoff_close(retained.scope, commit)
            .unwrap(),
        ProductionHandoffProgress::Retained(selection.clone())
    );

    let retry = retained.registry.retry_device_reset(&tombstone).unwrap();
    let (reset, ()) = retained
        .registry
        .acknowledge_device_reset_with_apply(&retry, |_| ())
        .unwrap();
    let iotlb = retained.registry.begin_device_iotlb(&reset).unwrap();
    let (closure, ()) = retained
        .registry
        .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())
        .unwrap();
    while let Some(effect) = retained.registry.revoke_next(&selection).unwrap() {
        __cser_core::assert!(__cser_core::matches!(
            effect.disposition,
            RevokeDisposition::Drain(_)
        ));
        retained
            .registry
            .stage_device_batch_terminal(
                &closure,
                effect.effect,
                TerminalRequest::indeterminate_after_reset(-5),
            )
            .unwrap();
    }
    retained.registry.revoke_complete(&selection).unwrap();
    let local_closure = match retained
        .registry
        .query_handoff(retained.scope, freeze.freeze())
        .unwrap()
    {
        ProductionHandoffProgress::Closed(receipt) => receipt,
        other => __cser_core::panic!("unexpected recovered handoff progress: {other:?}"),
    };
    retained
        .registry
        .verify_handoff_closure(retained.scope, &local_closure)
        .unwrap();
    let before_substitution = retained.registry.failure_atomic_projection();
    let mut substituted = local_closure.clone();
    substituted.scope_closure.closed_scope_revision += 1;
    __cser_core::assert_eq!(
        retained
            .registry
            .verify_handoff_closure(retained.scope, &substituted),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    __cser_core::assert_eq!(
        retained.registry.failure_atomic_projection(),
        before_substitution
    );

    let mut stored_drift = retained.registry.clone();
    stored_drift
        .scopes
        .get_mut(&retained.scope)
        .unwrap()
        .handoff
        .as_mut()
        .unwrap()
        .closure
        .as_mut()
        .unwrap()
        .revoke
        .sequence += 1;
    let drifted_receipt = stored_drift.scopes[&retained.scope]
        .handoff
        .as_ref()
        .unwrap()
        .closure
        .clone()
        .unwrap();
    __cser_core::assert_eq!(
        stored_drift.verify_handoff_closure(retained.scope, &drifted_receipt),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    __cser_core::assert_eq!(
        stored_drift.query_handoff(retained.scope, freeze.freeze()),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    __cser_core::assert!(__cser_core::matches!(
        stored_drift.check_invariants(),
        Err(RegistryError::Invariant(
            "stored handoff closure drifted from its authority state"
        ))
    ));
    retained.registry.check_invariants().unwrap();
}

#[cfg(test)]
pub(crate) struct RetainedSemanticTestFixture {
    pub(crate) exact_operation: DeviceCloseOperationId,
    pub(crate) foreign_operation: DeviceCloseOperationId,
    pub(crate) obligation: DevicePublishedObligation,
    pub(crate) error: RegistryError,
}

#[cfg(test)]
pub(crate) fn retained_semantic_test_fixture() -> RetainedSemanticTestFixture {
    let mut fixture = ProductionDeviceBatchRaceFixture::from_empty_registry(EffectRegistry::new());
    let authority = fixture.authority;
    let commits = fixture.commits;
    let enrollment = fixture
        .registry
        .enroll_device_batch(authority, &[commits[0].0, commits[1].0], fixture.device)
        .unwrap();
    let exact_operation = fixture
        .registry
        .mint_device_close_operation(&enrollment, 0x3f_0001)
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        fixture
            .registry
            .commit_or_recover_device_close_with_apply(
                exact_operation,
                authority,
                &enrollment,
                &commits,
                |_| (),
            )
            .unwrap(),
        DeviceCloseOutcome::Applied { .. }
    ));

    let mut foreign_operation = exact_operation;
    foreign_operation.caller_nonce = foreign_operation.caller_nonce.checked_add(1).unwrap();
    let (obligation, error) = match fixture.registry.commit_or_recover_device_close_with_apply(
        foreign_operation,
        authority,
        &enrollment,
        &commits,
        |_| __cser_core::panic!("foreign close operation republished"),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => (obligation, error),
        _ => __cser_core::panic!("foreign close operation lacked authoritative obligation"),
    };
    __cser_core::assert_eq!(obligation.operation(), Some(exact_operation));

    RetainedSemanticTestFixture {
        exact_operation,
        foreign_operation,
        obligation,
        error,
    }
}
