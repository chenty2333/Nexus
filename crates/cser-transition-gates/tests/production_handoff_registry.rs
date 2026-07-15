// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

use cser_transition_gates::handoff::{
    HandoffId, LogPosition, OwnershipDecision, OwnershipDecisionReceipt, PrepareIntent,
};
use effect_registry::{
    CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, DerivedRegisterRequest,
    DeviceBatchEnrollmentReceipt, DeviceDerivedRegisterRequest, DeviceEnvelope, DomainConfig,
    DomainKey, EffectRegistry, HandoffFreezeReadiness, OperationClass, ProductionHandoffProgress,
    PublicationMode, RegisterRequest, RegistryError, RevokeDisposition, ScopeConfig, ScopeKey,
    SyscallDescriptor, TaskKey, TerminalRequest,
};

const SCOPE: ScopeKey = ScopeKey::new(0x901, 1);
const OWNER: TaskKey = TaskKey::new(0x902, 1);
const TASK: TaskKey = TaskKey::new(0x903, 1);
const CREDIT: CreditClass = CreditClass::new(0x904);

fn intent(handoff: u64) -> PrepareIntent {
    PrepareIntent::new(
        HandoffId::new(handoff).unwrap(),
        0x910,
        LogPosition::new(0x911).unwrap(),
        0x912,
        0x913,
        0x914,
    )
    .unwrap()
}

fn registry(publication: PublicationMode) -> (EffectRegistry, effect_registry::RegisteredEffect) {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor: OWNER,
            credits: alloc::vec![CreditLimit::new(CREDIT, 2)],
        })
        .unwrap();
    let effect = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: TASK,
            operation: OperationClass::new(0x901),
            descriptor: SyscallDescriptor::new(17, [1, 2, 3, 4, 5, 6]),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication,
        })
        .unwrap();
    (registry, effect)
}

fn device_registry(enrolled: bool) -> (EffectRegistry, Option<DeviceBatchEnrollmentReceipt>) {
    const SCOPE: ScopeKey = ScopeKey::new(0x951, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0x952, 1);
    const WORKER: TaskKey = TaskKey::new(0x953, 1);
    const DOMAIN: DomainKey = DomainKey::new(1);
    const CREDIT: CreditClass = CreditClass::new(0x954);

    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 9,
            binding_epoch: 1,
            supervisor: ROOT_OWNER,
            credits: alloc::vec![CreditLimit::new(CREDIT, 2)],
        })
        .unwrap();
    registry
        .add_domain(
            SCOPE,
            DomainConfig {
                key: DOMAIN,
                binding_epoch: 1,
                supervisor: WORKER,
            },
        )
        .unwrap();
    let root = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: WORKER,
                operation: OperationClass::new(1),
                descriptor: SyscallDescriptor::new(17, [0; 6]),
                resources: alloc::vec![],
                credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: DOMAIN,
            parent: None,
        })
        .unwrap();
    let device = DeviceEnvelope::new(0x955, 0, 0, 1).unwrap();
    let child = registry
        .register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: WORKER,
                    operation: OperationClass::new(2),
                    descriptor: SyscallDescriptor::new(2, [0; 6]),
                    resources: alloc::vec![],
                    credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: DOMAIN,
                parent: Some(root.identity.effect()),
            },
            device,
        })
        .unwrap();
    registry.prepare(WORKER, root.handle).unwrap();
    registry.prepare(WORKER, child.handle).unwrap();
    let enrollment = enrolled.then(|| {
        let authority = registry.kernel_root_authority(SCOPE, ROOT_OWNER).unwrap();
        registry
            .enroll_device_batch(authority, &[root.handle, child.handle], device)
            .unwrap()
    });
    registry.check_invariants().unwrap();
    (registry, enrollment)
}

#[test]
fn production_freeze_abort_ack_and_thaw_reopen_exact_admission() {
    let (mut registry, effect) = registry(PublicationMode::Required);
    registry.prepare(OWNER, effect.handle).unwrap();
    let first_intent = intent(0x920);
    let freeze = registry.freeze_admission(SCOPE, first_intent).unwrap();
    assert_eq!(freeze.readiness(), HandoffFreezeReadiness::NeedsAbort);
    assert_eq!(freeze.cohort_size(), 1);
    assert_eq!(
        registry.commit(OWNER, effect.handle, CommitMetadata::new(0, 1)),
        Err(RegistryError::HandoffAdmissionFrozen)
    );

    let progress = registry.abort_handoff_uncommitted(SCOPE, freeze).unwrap();
    assert_eq!(progress.aborted, 1);
    assert_eq!(progress.publications.len(), 1);
    assert_eq!(
        progress.readiness,
        HandoffFreezeReadiness::PublicationPending
    );
    registry
        .acknowledge_publication(&progress.publications[0])
        .unwrap();
    assert_eq!(
        registry.query_handoff(SCOPE, freeze.freeze()).unwrap(),
        ProductionHandoffProgress::Frozen(HandoffFreezeReadiness::ReadyToCommit)
    );

    let abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x921).unwrap(),
        first_intent.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let thaw = registry.unfreeze_handoff(SCOPE, abort).unwrap();
    assert!(!thaw.source_recovery_required());
    assert_eq!(registry.unfreeze_handoff(SCOPE, abort), Ok(thaw));

    let next = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: TASK,
            operation: OperationClass::new(0x922),
            descriptor: SyscallDescriptor::new(18, [0; 6]),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    registry.prepare(OWNER, next.handle).unwrap();
    let next_intent = intent(0x923);
    let next_freeze = registry.freeze_admission(SCOPE, next_intent).unwrap();
    assert_eq!(
        next_freeze.freeze().freeze_generation(),
        freeze.freeze().freeze_generation() + 1
    );
    assert_eq!(next_freeze.cohort_size(), 1);
    let frozen_before_old_abort = registry.failure_atomic_projection();
    assert_eq!(
        registry.unfreeze_handoff(SCOPE, abort),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    assert_eq!(
        registry.failure_atomic_projection(),
        frozen_before_old_abort
    );
    let next_progress = registry
        .abort_handoff_uncommitted(SCOPE, next_freeze)
        .unwrap();
    assert_eq!(next_progress.aborted, 1);
    assert!(next_progress.publications.is_empty());
    let next_abort = OwnershipDecisionReceipt::new(
        next_freeze.freeze(),
        LogPosition::new(0x924).unwrap(),
        next_intent.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let next_thaw = registry.unfreeze_handoff(SCOPE, next_abort).unwrap();
    assert_eq!(registry.unfreeze_handoff(SCOPE, next_abort), Ok(next_thaw));
    registry.check_invariants().unwrap();
}

#[test]
fn ordinary_revoke_remains_valid_after_an_aborted_handoff() {
    let (mut registry, _) = registry(PublicationMode::None);
    let prepare = intent(0x925);
    let freeze = registry.freeze_admission(SCOPE, prepare).unwrap();
    registry.abort_handoff_uncommitted(SCOPE, freeze).unwrap();
    let abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x926).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let thaw = registry.unfreeze_handoff(SCOPE, abort).unwrap();
    let next = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: TASK,
            operation: OperationClass::new(0x927),
            descriptor: SyscallDescriptor::new(19, [0; 6]),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    registry.prepare(OWNER, next.handle).unwrap();

    let selection = registry.revoke_begin(SCOPE).unwrap();
    let item = registry.revoke_next(&selection).unwrap().unwrap();
    assert_eq!(item.effect, next.identity.effect());
    assert_eq!(item.disposition, RevokeDisposition::Abort);
    registry
        .stage_revoke_terminal(&selection, item.effect, TerminalRequest::aborted(-125))
        .unwrap();
    registry.revoke_complete(&selection).unwrap();
    assert_eq!(
        registry.query_handoff(SCOPE, freeze.freeze()).unwrap(),
        ProductionHandoffProgress::Aborted(thaw)
    );
    registry.check_invariants().unwrap();
}

#[test]
fn abort_thaw_preserves_the_same_precommit_effect() {
    let (mut registry, effect) = registry(PublicationMode::None);
    let prepare = intent(0x928);
    let freeze = registry.freeze_admission(SCOPE, prepare).unwrap();
    assert_eq!(freeze.readiness(), HandoffFreezeReadiness::NeedsAbort);
    let abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x929).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();

    registry.unfreeze_handoff(SCOPE, abort).unwrap();
    registry.prepare(OWNER, effect.handle).unwrap();
    assert!(matches!(
        registry
            .commit(OWNER, effect.handle, CommitMetadata::new(3, 1))
            .unwrap(),
        CommitOutcome::Applied(_)
    ));
    registry.check_invariants().unwrap();
}

#[test]
fn partial_abort_returns_publication_tickets_until_committed_children_drain() {
    const GRAPH_SCOPE: ScopeKey = ScopeKey::new(0x971, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0x972, 1);
    const WORKER: TaskKey = TaskKey::new(0x973, 1);
    const DOMAIN: DomainKey = DomainKey::new(1);
    const GRAPH_CREDIT: CreditClass = CreditClass::new(0x974);

    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: GRAPH_SCOPE,
            authority_epoch: 5,
            binding_epoch: 1,
            supervisor: ROOT_OWNER,
            credits: alloc::vec![CreditLimit::new(GRAPH_CREDIT, 3)],
        })
        .unwrap();
    registry
        .add_domain(
            GRAPH_SCOPE,
            DomainConfig {
                key: DOMAIN,
                binding_epoch: 1,
                supervisor: WORKER,
            },
        )
        .unwrap();
    let register = |operation, parent, publication| DerivedRegisterRequest {
        request: RegisterRequest {
            scope: GRAPH_SCOPE,
            task: WORKER,
            operation: OperationClass::new(operation),
            descriptor: SyscallDescriptor::new(usize::try_from(operation).unwrap(), [0; 6]),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(GRAPH_CREDIT, 1)],
            publication,
        },
        domain: DOMAIN,
        parent,
    };
    let parent = registry
        .register_derived(register(1, None, PublicationMode::None))
        .unwrap();
    let child = registry
        .register_derived(register(
            2,
            Some(parent.identity.effect()),
            PublicationMode::None,
        ))
        .unwrap();
    let leaf = registry
        .register_derived(register(3, None, PublicationMode::Required))
        .unwrap();
    for effect in [&parent, &child, &leaf] {
        registry.prepare(WORKER, effect.handle).unwrap();
    }
    let child_commit = match registry
        .commit(WORKER, child.handle, CommitMetadata::new(7, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let prepare = intent(0x975);
    let freeze = registry.freeze_admission(GRAPH_SCOPE, prepare).unwrap();

    let first = registry
        .abort_handoff_uncommitted(GRAPH_SCOPE, freeze)
        .unwrap();
    assert_eq!(first.aborted, 1);
    assert_eq!(first.publications.len(), 1);
    assert_eq!(first.readiness, HandoffFreezeReadiness::PublicationPending);
    registry
        .acknowledge_publication(&first.publications[0])
        .unwrap();
    assert_eq!(
        registry
            .query_handoff(GRAPH_SCOPE, freeze.freeze())
            .unwrap(),
        ProductionHandoffProgress::Frozen(HandoffFreezeReadiness::NeedsAbort)
    );

    registry.stage_kernel_completion(&child_commit).unwrap();
    let second = registry
        .abort_handoff_uncommitted(GRAPH_SCOPE, freeze)
        .unwrap();
    assert_eq!(second.aborted, 1);
    assert!(second.publications.is_empty());
    assert_eq!(second.readiness, HandoffFreezeReadiness::ReadyToCommit);
    let abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x976).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    registry.unfreeze_handoff(GRAPH_SCOPE, abort).unwrap();
    registry.check_invariants().unwrap();
}

#[test]
fn partial_abort_returns_prior_ticket_before_a_later_terminal_overflow() {
    let (mut registry, first) = registry(PublicationMode::Required);
    let second = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: TASK,
            operation: OperationClass::new(0x977),
            descriptor: SyscallDescriptor::new(20, [0; 6]),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    for effect in [&first, &second] {
        registry.prepare(OWNER, effect.handle).unwrap();
    }
    registry.set_next_terminal_sequence_for_handoff_test(u64::MAX - 1);
    let freeze = registry.freeze_admission(SCOPE, intent(0x978)).unwrap();

    let progress = registry.abort_handoff_uncommitted(SCOPE, freeze).unwrap();
    assert_eq!(progress.aborted, 1);
    assert_eq!(progress.publications.len(), 1);
    assert_eq!(progress.publications[0].effect(), first.identity.effect());
    assert_eq!(
        progress.readiness,
        HandoffFreezeReadiness::PublicationPending
    );
    registry
        .acknowledge_publication(&progress.publications[0])
        .unwrap();

    let before_retry = registry.failure_atomic_projection();
    assert_eq!(
        registry.abort_handoff_uncommitted(SCOPE, freeze),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(registry.failure_atomic_projection(), before_retry);
    registry.check_invariants().unwrap();
}

#[test]
fn production_commit_reuses_irreversible_revoke_and_mints_one_closure() {
    let (mut registry, effect) = registry(PublicationMode::None);
    registry.prepare(OWNER, effect.handle).unwrap();
    let commit = match registry
        .commit(OWNER, effect.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let intent = intent(0x930);
    let freeze = registry.freeze_admission(SCOPE, intent).unwrap();
    assert_eq!(freeze.readiness(), HandoffFreezeReadiness::ReadyToCommit);
    assert_eq!(freeze.committed_at_freeze(), 1);
    let ownership_commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x931).unwrap(),
        intent.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let selection = match registry
        .commit_handoff_close(SCOPE, ownership_commit)
        .unwrap()
    {
        ProductionHandoffProgress::Closing(selection) => selection,
        other => panic!("unexpected initial close progress: {other:?}"),
    };
    assert_eq!(
        registry.revoke_begin(SCOPE),
        Err(RegistryError::HandoffAdmissionFrozen)
    );
    let next = registry.revoke_next(&selection).unwrap().unwrap();
    assert_eq!(next.effect, effect.identity.effect());
    assert!(matches!(next.disposition, RevokeDisposition::Drain(_)));
    registry
        .stage_revoke_terminal(
            &selection,
            next.effect,
            TerminalRequest::completed_by(commit.result(), commit),
        )
        .unwrap();
    assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    let closure = match registry.query_handoff(SCOPE, freeze.freeze()).unwrap() {
        ProductionHandoffProgress::Closed(receipt) => receipt,
        other => panic!("unexpected terminal close progress: {other:?}"),
    };
    registry.verify_handoff_closure(SCOPE, &closure).unwrap();
    assert_eq!(
        registry
            .commit_handoff_close(SCOPE, ownership_commit)
            .unwrap(),
        ProductionHandoffProgress::Closed(closure.clone())
    );

    let conflicting_abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x932).unwrap(),
        intent.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let before = registry.failure_atomic_projection();
    assert_eq!(
        registry.unfreeze_handoff(SCOPE, conflicting_abort),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    assert_eq!(registry.failure_atomic_projection(), before);
    registry.check_invariants().unwrap();
}

#[test]
fn empty_handoff_close_preflights_terminal_revision_before_commit() {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor: OWNER,
            credits: alloc::vec![CreditLimit::new(CREDIT, 1)],
        })
        .unwrap();
    registry.set_scope_revision_for_handoff_test(SCOPE, u64::MAX - 1);
    let prepare = intent(0x935);
    let freeze = registry.freeze_admission(SCOPE, prepare).unwrap();
    let commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x936).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let before = registry.failure_atomic_projection();

    assert_eq!(
        registry.commit_handoff_close(SCOPE, commit),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(registry.failure_atomic_projection(), before);
    assert_eq!(
        registry.query_handoff(SCOPE, freeze.freeze()).unwrap(),
        ProductionHandoffProgress::Frozen(HandoffFreezeReadiness::ReadyToCommit)
    );
    registry.check_invariants().unwrap();
}

#[test]
fn frozen_source_crash_preserves_cohort_and_abort_requires_recovery() {
    let (mut registry, effect) = registry(PublicationMode::None);
    let intent = intent(0x940);
    let freeze = registry.freeze_admission(SCOPE, intent).unwrap();
    let crash = registry.crash(SCOPE, OWNER).unwrap();
    assert_eq!(crash.cohort.len(), 1);
    assert_eq!(
        registry.prepare(OWNER, effect.handle),
        Err(RegistryError::HandoffAdmissionFrozen)
    );
    let progress = registry.abort_handoff_uncommitted(SCOPE, freeze).unwrap();
    assert_eq!(progress.aborted, 1);
    assert!(progress.publications.is_empty());
    let abort = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0x941).unwrap(),
        intent.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let thaw = registry.unfreeze_handoff(SCOPE, abort).unwrap();
    assert!(thaw.source_recovery_required());
    assert_eq!(
        registry.prepare(OWNER, effect.handle),
        Err(RegistryError::StaleBinding)
    );
    registry.check_invariants().unwrap();
}

#[test]
fn retained_tombstones_block_or_delay_but_never_fabricate_closure() {
    effect_registry::production_handoff_retained_self_test(
        EffectRegistry::new(),
        EffectRegistry::new(),
    );
}

#[test]
fn ownership_decision_cannot_replay_across_registry_or_cohort_identity() {
    let (mut source, _) = registry(PublicationMode::None);
    let (mut target, _) = registry(PublicationMode::None);
    let prepare = intent(0x950);
    let source_freeze = source.freeze_admission(SCOPE, prepare).unwrap();
    let target_freeze = target.freeze_admission(SCOPE, prepare).unwrap();
    source
        .abort_handoff_uncommitted(SCOPE, source_freeze)
        .unwrap();
    target
        .abort_handoff_uncommitted(SCOPE, target_freeze)
        .unwrap();
    let foreign = OwnershipDecisionReceipt::new(
        source_freeze.freeze(),
        LogPosition::new(0x951).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Abort,
    )
    .unwrap();
    let before = target.failure_atomic_projection();

    assert_eq!(
        target.unfreeze_handoff(SCOPE, foreign),
        Err(RegistryError::InvalidHandoffReceipt)
    );
    assert_eq!(target.failure_atomic_projection(), before);
    target.check_invariants().unwrap();
}

#[test]
fn precommit_device_roots_reject_freeze_without_mutation() {
    use core::cell::Cell;

    const DEVICE_SCOPE: ScopeKey = ScopeKey::new(0x951, 1);
    for enrolled in [false, true] {
        let (mut registry, enrollment) = device_registry(enrolled);
        let before = registry.failure_atomic_projection();
        assert_eq!(
            registry.freeze_admission(DEVICE_SCOPE, intent(0x960 + u64::from(enrolled)),),
            Err(RegistryError::HandoffDevicePrecommitPending)
        );
        assert_eq!(registry.failure_atomic_projection(), before);

        let hardware_calls = Cell::new(0_u8);
        let result = match enrollment.as_ref() {
            Some(enrollment) => registry
                .close_enrolled_device_precommit_with_apply(enrollment, |_| {
                    hardware_calls.set(hardware_calls.get() + 1)
                })
                .map(|_| ()),
            None => registry
                .close_pending_device_precommit_with_apply(DEVICE_SCOPE, |_| {
                    hardware_calls.set(hardware_calls.get() + 1)
                })
                .map(|_| ()),
        };

        assert!(result.is_ok());
        assert_eq!(hardware_calls.get(), 1);
        registry.check_invariants().unwrap();
    }
}
