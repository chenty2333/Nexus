use cser_model::pager::{
    FaultAccess, FaultState, FrameId, FrameState, PageAddress, PagerAction, PagerError,
    PagerFallbackState, PagerId, PagerModel, RecoveryTimeoutResult, ThreadId,
};
use cser_model::{Budget, BudgetDisposition, ScopeState};

fn pager(id: u64) -> PagerId {
    PagerId::new(id)
}

fn access() -> FaultAccess {
    FaultAccess::READ.union(FaultAccess::USER)
}

#[test]
fn prepared_fault_survives_crash_and_requires_ready_rebind_and_explicit_adopt() {
    let mut model = PagerModel::new();
    let (scope, address_space, old_binding) = model
        .create_address_space(pager(1), Budget::new(4))
        .unwrap();
    let old_token = model
        .register_fault(
            old_binding,
            ThreadId::new(7),
            PageAddress::new(0x4000),
            access(),
            Budget::new(2),
        )
        .unwrap();
    model
        .prepare_zero(old_binding, old_token, FrameId::new(10))
        .unwrap();

    let before_crash = model.scope(scope).unwrap();
    model.crash(old_binding).unwrap();
    let after_crash = model.scope(scope).unwrap();
    assert_eq!(after_crash.authority_epoch, before_crash.authority_epoch);
    assert_eq!(
        after_crash.address_space_generation,
        before_crash.address_space_generation
    );
    assert_eq!(
        after_crash.binding_epoch.get(),
        before_crash.binding_epoch.get() + 1
    );
    assert_eq!(after_crash.fallback, PagerFallbackState::Required);

    let rejected_state = model.clone();
    assert!(matches!(
        model.commit(old_binding, old_token),
        Err(PagerError::StaleBinding { .. })
    ));
    assert_eq!(model, rejected_state);

    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, pager(2)).unwrap();
    assert_eq!(snapshot.faults().len(), 1);
    assert_eq!(snapshot.faults()[0].token, old_token);
    assert_eq!(snapshot.faults()[0].prepared_frame, Some(FrameId::new(10)));
    let ready = model.ready(&snapshot).unwrap();
    assert_eq!(ready.binding_epoch(), after_crash.binding_epoch);
    let replacement = model.rebind(ready).unwrap();
    assert!(model.scope(scope).unwrap().recovery_deadline_armed);

    // Rebind installs the already advanced crash epoch; it does not advance it again.
    assert_eq!(replacement.binding_epoch(), after_crash.binding_epoch);
    assert!(matches!(
        model.commit(replacement, old_token),
        Err(PagerError::FaultBindingFenced { .. })
    ));
    let adopted = model.adopt(replacement, old_token).unwrap();
    assert_eq!(adopted.binding_epoch(), replacement.binding_epoch());

    let mapping = model.commit(replacement, adopted).unwrap();
    assert_eq!(mapping.address_space, address_space);
    let committed = model.fault(adopted.fault()).unwrap();
    assert_eq!(committed.state, FaultState::Committed);
    assert_eq!(committed.mapping_publications, 1);
    assert_eq!(committed.continuation_consumptions, 1);
    assert_eq!((committed.wakes, committed.resumes), (0, 0));
    assert_eq!(
        model.frame(FrameId::new(10)).unwrap().state,
        FrameState::Mapped {
            key: mapping,
            fault: adopted.fault()
        }
    );
    let after_commit = model.clone();
    assert_eq!(model.abort(adopted), Err(PagerError::AbortNotPermitted));
    assert_eq!(model, after_commit);

    // Mapping publication precedes the only successful wake and same-RIP retry.
    model.complete(adopted.fault()).unwrap();
    let completed = model.fault(adopted.fault()).unwrap();
    assert_eq!(completed.state, FaultState::Completed);
    assert_eq!((completed.wakes, completed.resumes), (1, 1));
    assert_eq!(completed.terminalizations, 1);
    assert_eq!(completed.budget_disposition, BudgetDisposition::Spent);
    assert_eq!(
        model.complete(adopted.fault()),
        Err(PagerError::AlreadyTerminal)
    );

    let scope_view = model.scope(scope).unwrap();
    assert_eq!(scope_view.free_budget, Budget::new(2));
    assert_eq!(scope_view.spent_budget, Budget::new(2));
    assert_eq!(scope_view.live_faults, 0);
    assert!(!scope_view.recovery_deadline_armed);
    let actions: Vec<_> = model.trace().iter().map(|event| event.action).collect();
    for ordered_pair in [
        (PagerAction::Crash, PagerAction::FallbackPick),
        (PagerAction::FallbackPick, PagerAction::Ready),
        (PagerAction::Ready, PagerAction::Rebind),
        (PagerAction::Rebind, PagerAction::Adopt),
        (PagerAction::Adopt, PagerAction::Commit),
        (PagerAction::Commit, PagerAction::Complete),
    ] {
        let left = actions
            .iter()
            .position(|action| *action == ordered_pair.0)
            .unwrap();
        let right = actions
            .iter()
            .position(|action| *action == ordered_pair.1)
            .unwrap();
        assert!(left < right);
    }
    model.check_invariants().unwrap();
}

#[test]
fn timeout_revocation_aborts_every_orphan_and_returns_held_credit() {
    const FAULTS: u64 = 5;

    let mut model = PagerModel::new();
    let (scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(FAULTS))
        .unwrap();
    let mut tokens = Vec::new();
    for index in 0..FAULTS {
        let token = model
            .register_fault(
                binding,
                ThreadId::new(index + 1),
                PageAddress::new(0x1000 * (index + 1)),
                access(),
                Budget::new(1),
            )
            .unwrap();
        if index % 2 == 0 {
            model
                .prepare_zero(binding, token, FrameId::new(index + 1))
                .unwrap();
        }
        tokens.push(token);
    }

    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let binding_after_crash = model.scope(scope).unwrap().binding_epoch;
    model.revoke_begin(scope).unwrap();
    assert_eq!(model.scope(scope).unwrap().authority_epoch.get(), 2);
    assert_eq!(
        model.scope(scope).unwrap().binding_epoch,
        binding_after_crash
    );
    assert_eq!(
        model.revoke_complete(scope),
        Err(PagerError::RevocationNotQuiescent {
            remaining: FAULTS as usize
        })
    );

    let mut steps = 0usize;
    while let Some(step) = model.revoke_next(scope).unwrap() {
        assert_eq!(step.to, FaultState::Aborted);
        assert_eq!(step.returned_budget, Budget::new(1));
        steps += 1;
        model.check_invariants().unwrap();
    }
    assert_eq!(steps, FAULTS as usize);
    model.revoke_complete(scope).unwrap();

    for token in tokens {
        let fault = model.fault(token.fault()).unwrap();
        assert_eq!(fault.state, FaultState::Aborted);
        assert_eq!(fault.continuation_consumptions, 1);
        assert_eq!(fault.terminalizations, 1);
        assert_eq!((fault.wakes, fault.resumes), (1, 0));
        assert_eq!(fault.budget_disposition, BudgetDisposition::Returned);
        assert!(fault.prepared_frame.is_none());
    }
    for frame in [FrameId::new(1), FrameId::new(3), FrameId::new(5)] {
        assert!(matches!(
            model.frame(frame).unwrap().state,
            FrameState::Released(_)
        ));
    }
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.state, ScopeState::Revoked);
    assert_eq!(closed.free_budget, Budget::new(FAULTS));
    assert_eq!(closed.spent_budget, Budget::ZERO);
    assert_eq!(closed.revocation.unwrap().target_count, FAULTS as usize);
    assert_eq!(closed.revocation.unwrap().steps, FAULTS as usize);
    model.check_invariants().unwrap();
}

#[test]
fn crashing_an_empty_scope_does_not_arm_recovery_deadline_work() {
    let mut model = PagerModel::new();
    let (scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(1))
        .unwrap();
    assert!(!model.scope(scope).unwrap().recovery_deadline_armed);
    model.crash(binding).unwrap();
    assert!(!model.scope(scope).unwrap().recovery_deadline_armed);
    assert!(matches!(
        model.register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        ),
        Err(PagerError::StaleBinding { .. })
    ));
    assert_eq!(
        model.recovery_timeout_begin(scope),
        Err(PagerError::RecoveryDeadlineUnavailable)
    );
    model.check_invariants().unwrap();
}

#[test]
fn mapping_slot_identity_prevents_two_publications_for_the_same_generation() {
    let mut model = PagerModel::new();
    let (scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(2))
        .unwrap();
    let first = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x8000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    let second = model
        .register_fault(
            binding,
            ThreadId::new(2),
            PageAddress::new(0x8000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.prepare_zero(binding, first, FrameId::new(1)).unwrap();
    model
        .prepare_zero(binding, second, FrameId::new(2))
        .unwrap();

    let mapping = model.commit(binding, first).unwrap();
    let before_loser = model.clone();
    assert_eq!(
        model.commit(binding, second),
        Err(PagerError::MappingAlreadyPublished(mapping))
    );
    assert_eq!(model, before_loser);
    assert_eq!(model.mapping_count(), 1);

    // The losing candidate remains owned and pending until the kernel
    // coalesces it onto the already published slot.
    let loser = model.fault(second.fault()).unwrap();
    assert_eq!(loser.state, FaultState::Prepared);
    assert_eq!(loser.prepared_frame, Some(FrameId::new(2)));
    assert_eq!(loser.continuation_consumptions, 0);
    assert_eq!(model.satisfy_mapped(second).unwrap(), mapping);
    model.complete(first.fault()).unwrap();
    let loser = model.fault(second.fault()).unwrap();
    assert_eq!(loser.state, FaultState::Completed);
    assert_eq!(loser.resolved_mapping, Some(mapping));
    assert_eq!(loser.mapping_publications, 0);
    assert_eq!(loser.continuation_consumptions, 1);
    assert_eq!((loser.wakes, loser.resumes), (1, 1));
    assert_eq!(loser.budget_disposition, BudgetDisposition::Returned);
    assert_eq!(
        model.frame(FrameId::new(2)).unwrap().state,
        FrameState::Released(second.fault())
    );
    assert_eq!(model.mapping_count(), 1);
    assert_eq!(model.publication_count(), 1);
    assert_eq!(model.scope(scope).unwrap().free_budget, Budget::new(1));
    assert_eq!(model.scope(scope).unwrap().spent_budget, Budget::new(1));
    model.check_invariants().unwrap();
}

#[test]
fn address_space_generation_fences_only_commits_that_are_stale_at_commit_time() {
    let mut model = PagerModel::new();
    let (scope, address_space, binding) = model
        .create_address_space(pager(1), Budget::new(3))
        .unwrap();

    // Mutation cannot pass a mapping whose continuation has not completed.
    let committed = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model
        .prepare_zero(binding, committed, FrameId::new(1))
        .unwrap();
    let generation_one_mapping = model.commit(binding, committed).unwrap();
    let before_early_mutation = model.clone();
    assert_eq!(
        model.advance_address_space_generation(address_space),
        Err(PagerError::CommittedMappingOutstanding { remaining: 1 })
    );
    assert_eq!(model, before_early_mutation);
    model.complete(committed.fault()).unwrap();
    assert_eq!(
        model
            .advance_address_space_generation(address_space)
            .unwrap()
            .get(),
        2
    );
    assert!(model.mapping(generation_one_mapping).is_none());
    assert!(model.publication(generation_one_mapping).is_some());
    assert_eq!(
        model.frame(FrameId::new(1)).unwrap().state,
        FrameState::Released(committed.fault())
    );
    let historical = model.fault(committed.fault()).unwrap();
    assert_eq!(historical.mapped_frame, None);
    assert_eq!(historical.resolved_mapping, Some(generation_one_mapping));
    assert_eq!(historical.mapping_publications, 1);
    assert_eq!(historical.budget_disposition, BudgetDisposition::Returned);
    assert_eq!(model.scope(scope).unwrap().free_budget, Budget::new(3));
    assert_eq!(model.scope(scope).unwrap().spent_budget, Budget::ZERO);

    // A fault still carrying generation 2 is rejected after generation 3 begins.
    let stale = model
        .register_fault(
            binding,
            ThreadId::new(2),
            PageAddress::new(0x2000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.prepare_zero(binding, stale, FrameId::new(2)).unwrap();
    model
        .advance_address_space_generation(address_space)
        .unwrap();
    let before_rejection = model.clone();
    assert!(matches!(
        model.commit(binding, stale),
        Err(PagerError::StaleAddressSpaceGeneration { .. })
    ));
    assert_eq!(model, before_rejection);
    model.abort(stale).unwrap();

    // New work captures generation 3 and may reuse the same virtual page slot.
    let current = model
        .register_fault(
            binding,
            ThreadId::new(3),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model
        .prepare_zero(binding, current, FrameId::new(3))
        .unwrap();
    let generation_three_mapping = model.commit(binding, current).unwrap();
    assert_ne!(generation_one_mapping, generation_three_mapping);
    model.complete(current.fault()).unwrap();
    assert_eq!(model.mapping_count(), 1);
    assert_eq!(model.publication_count(), 2);
    assert!(model.publication(generation_one_mapping).is_some());
    assert!(model.mapping(generation_one_mapping).is_none());
    assert!(model.mapping(generation_three_mapping).is_some());
    model.check_invariants().unwrap();
}

#[test]
fn adoption_and_orphan_abort_have_one_winner_for_the_old_token() {
    let mut model = PagerModel::new();
    let (scope, _address_space, old_binding) = model
        .create_address_space(pager(1), Budget::new(1))
        .unwrap();
    let old_token = model
        .register_fault(
            old_binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, pager(2)).unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();

    let adopted = model.adopt(replacement, old_token).unwrap();
    let after_adoption = model.clone();
    assert!(matches!(
        model.abort(old_token),
        Err(PagerError::FaultBindingFenced { .. })
    ));
    assert_eq!(model, after_adoption);
    assert_eq!(model.abort(adopted), Err(PagerError::AbortNotPermitted));
    assert_eq!(
        model.recovery_timeout_begin(scope).unwrap(),
        RecoveryTimeoutResult::RevocationStarted
    );
    assert_eq!(
        model.revoke_next(scope).unwrap().unwrap().to,
        FaultState::Aborted
    );
    model.revoke_complete(scope).unwrap();
    assert_eq!(
        model.fault(adopted.fault()).unwrap().state,
        FaultState::Aborted
    );
    model.check_invariants().unwrap();
}

#[test]
fn recovery_timeout_closes_faults_whether_or_not_replacement_adopted_them() {
    let mut model = PagerModel::new();
    let (scope, _address_space, old_binding) = model
        .create_address_space(pager(1), Budget::new(2))
        .unwrap();
    let unadopted = model
        .register_fault(
            old_binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    let to_adopt = model
        .register_fault(
            old_binding,
            ThreadId::new(2),
            PageAddress::new(0x2000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model
        .prepare_zero(old_binding, unadopted, FrameId::new(1))
        .unwrap();
    model
        .prepare_zero(old_binding, to_adopt, FrameId::new(2))
        .unwrap();

    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, pager(2)).unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let adopted = model.adopt(replacement, to_adopt).unwrap();
    assert!(model.scope(scope).unwrap().recovery_deadline_armed);

    // The watchdog owns closure and needs neither the stale old token nor the
    // adopted replacement token to terminalize the entire crash cohort.
    assert_eq!(
        model.recovery_timeout_begin(scope).unwrap(),
        RecoveryTimeoutResult::RevocationStarted
    );
    let closing = model.scope(scope).unwrap();
    assert_eq!(closing.state, ScopeState::Closing);
    assert_eq!(closing.pager, None);
    assert_eq!(closing.fallback, PagerFallbackState::Running);
    while model.revoke_next(scope).unwrap().is_some() {}
    model.revoke_complete(scope).unwrap();

    for token in [unadopted, adopted] {
        let fault = model.fault(token.fault()).unwrap();
        assert_eq!(fault.state, FaultState::Aborted);
        assert_eq!(fault.continuation_consumptions, 1);
        assert_eq!(fault.terminalizations, 1);
        assert_eq!((fault.wakes, fault.resumes), (1, 0));
        assert_eq!(fault.budget_disposition, BudgetDisposition::Returned);
        assert!(fault.prepared_frame.is_none());
    }
    assert_eq!(
        model.frame(FrameId::new(1)).unwrap().state,
        FrameState::Released(unadopted.fault())
    );
    assert_eq!(
        model.frame(FrameId::new(2)).unwrap().state,
        FrameState::Released(adopted.fault())
    );
    assert_eq!(model.scope(scope).unwrap().free_budget, Budget::new(2));
    assert!(!model.scope(scope).unwrap().recovery_deadline_armed);
    model.check_invariants().unwrap();
}

#[test]
fn committed_only_deadline_completes_without_revoking_the_scope() {
    let mut model = PagerModel::new();
    let (scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(2))
        .unwrap();
    let token = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.prepare_zero(binding, token, FrameId::new(1)).unwrap();
    model.commit(binding, token).unwrap();
    let authority_before_expiry = model.scope(scope).unwrap().authority_epoch;

    assert_eq!(
        model.recovery_timeout_begin(scope).unwrap(),
        RecoveryTimeoutResult::CompletionPending { committed: 1 }
    );
    let pending = model.scope(scope).unwrap();
    assert_eq!(pending.state, ScopeState::Active);
    assert_eq!(pending.authority_epoch, authority_before_expiry);
    assert_eq!(pending.pager, Some(pager(1)));
    assert!(pending.recovery_deadline_armed);
    assert!(pending.recovery_deadline_completion_pending);
    assert_eq!(
        model.deadline_complete(scope),
        Err(PagerError::RecoveryDeadlineNotComplete)
    );
    assert_eq!(
        model.register_fault(
            binding,
            ThreadId::new(2),
            PageAddress::new(0x2000),
            access(),
            Budget::new(1),
        ),
        Err(PagerError::RecoveryDeadlineCompletionPending)
    );

    model.complete(token.fault()).unwrap();
    let before_deadline_complete = model.scope(scope).unwrap();
    assert_eq!(before_deadline_complete.state, ScopeState::Active);
    assert_eq!(before_deadline_complete.live_faults, 0);
    assert!(before_deadline_complete.recovery_deadline_armed);
    assert!(before_deadline_complete.recovery_deadline_completion_pending);
    model.crash(binding).unwrap();
    let crashed = model.scope(scope).unwrap();
    assert_eq!(crashed.state, ScopeState::Active);
    assert_eq!(crashed.pager, None);
    assert_eq!(crashed.fallback, PagerFallbackState::Required);
    assert!(crashed.recovery_deadline_armed);
    assert!(crashed.recovery_deadline_completion_pending);
    model.deadline_complete(scope).unwrap();

    let idle = model.scope(scope).unwrap();
    assert_eq!(idle.state, ScopeState::Active);
    assert_eq!(idle.authority_epoch, authority_before_expiry);
    assert_eq!(idle.pager, None);
    assert_eq!(idle.fallback, PagerFallbackState::Required);
    assert!(!idle.recovery_deadline_armed);
    assert!(!idle.recovery_deadline_completion_pending);
    assert_eq!(idle.spent_budget, Budget::new(1));
    let actions: Vec<_> = model.trace().iter().map(|event| event.action).collect();
    let expired = actions
        .iter()
        .position(|action| *action == PagerAction::DeadlineCompletionPending)
        .unwrap();
    let complete = actions
        .iter()
        .position(|action| *action == PagerAction::Complete)
        .unwrap();
    let crash = actions
        .iter()
        .position(|action| *action == PagerAction::Crash)
        .unwrap();
    let deadline_complete = actions
        .iter()
        .position(|action| *action == PagerAction::DeadlineComplete)
        .unwrap();
    assert!(expired < complete && complete < crash && crash < deadline_complete);
    model.check_invariants().unwrap();
}

#[test]
fn dead_pager_with_only_committed_faults_uses_completion_only_deadline() {
    let mut model = PagerModel::new();
    let (scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(1))
        .unwrap();
    let token = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.prepare_zero(binding, token, FrameId::new(1)).unwrap();
    model.commit(binding, token).unwrap();
    let authority = model.scope(scope).unwrap().authority_epoch;
    model.crash(binding).unwrap();

    assert_eq!(
        model.recovery_timeout_begin(scope).unwrap(),
        RecoveryTimeoutResult::CompletionPending { committed: 1 }
    );
    let pending = model.scope(scope).unwrap();
    assert_eq!(pending.state, ScopeState::Active);
    assert_eq!(pending.authority_epoch, authority);
    assert_eq!(pending.pager, None);
    assert_eq!(pending.fallback, PagerFallbackState::Required);
    assert!(pending.recovery_deadline_completion_pending);

    model.complete(token.fault()).unwrap();
    model.deadline_complete(scope).unwrap();
    let idle = model.scope(scope).unwrap();
    assert_eq!(idle.state, ScopeState::Active);
    assert_eq!(idle.authority_epoch, authority);
    assert_eq!(idle.pager, None);
    assert_eq!(idle.fallback, PagerFallbackState::Required);
    assert!(!idle.recovery_deadline_armed);
    assert!(!idle.recovery_deadline_completion_pending);
    assert_eq!(idle.spent_budget, Budget::new(1));
    model.check_invariants().unwrap();
}

#[test]
fn a_prepared_frame_has_exactly_one_fault_owner() {
    let mut model = PagerModel::new();
    let (_scope, _address_space, binding) = model
        .create_address_space(pager(1), Budget::new(2))
        .unwrap();
    let first = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    let second = model
        .register_fault(
            binding,
            ThreadId::new(2),
            PageAddress::new(0x2000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.prepare_zero(binding, first, FrameId::new(9)).unwrap();
    let before_rejection = model.clone();
    assert_eq!(
        model.prepare_zero(binding, second, FrameId::new(9)),
        Err(PagerError::FrameAlreadyKnown(FrameId::new(9)))
    );
    assert_eq!(model, before_rejection);
    assert_eq!(
        model.frame(FrameId::new(9)).unwrap().state,
        FrameState::Prepared(first.fault())
    );
    assert_eq!(
        model.fault(second.fault()).unwrap().state,
        FaultState::Registered
    );
    model.check_invariants().unwrap();
}

#[test]
fn a_snapshot_is_invalidated_by_address_space_or_fault_state_change() {
    let mut model = PagerModel::new();
    let (scope, address_space, binding) = model
        .create_address_space(pager(1), Budget::new(1))
        .unwrap();
    let token = model
        .register_fault(
            binding,
            ThreadId::new(1),
            PageAddress::new(0x1000),
            access(),
            Budget::new(1),
        )
        .unwrap();
    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, pager(2)).unwrap();
    model
        .advance_address_space_generation(address_space)
        .unwrap();
    assert!(matches!(
        model.ready(&snapshot),
        Err(PagerError::StaleAddressSpaceGeneration { .. })
    ));

    let fresh = model.recovery_snapshot(scope, pager(2)).unwrap();
    let ready = model.ready(&fresh).unwrap();
    model.abort(token).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().fallback,
        PagerFallbackState::Running
    );
    assert_eq!(model.rebind(ready), Err(PagerError::FallbackUnavailable));
    model.check_invariants().unwrap();
}

#[test]
fn revocation_visits_target_k_without_scanning_global_n() {
    const TARGET: usize = 7;
    const UNRELATED: usize = 37;

    let mut model = PagerModel::new();
    let (target_scope, _target_as, target_binding) = model
        .create_address_space(pager(1), Budget::new(TARGET as u64))
        .unwrap();
    let (other_scope, _other_as, other_binding) = model
        .create_address_space(pager(2), Budget::new(UNRELATED as u64))
        .unwrap();
    for index in 0..TARGET {
        model
            .register_fault(
                target_binding,
                ThreadId::new(index as u64),
                PageAddress::new(0x1000 * (index as u64 + 1)),
                access(),
                Budget::new(1),
            )
            .unwrap();
    }
    for index in 0..UNRELATED {
        model
            .register_fault(
                other_binding,
                ThreadId::new(index as u64),
                PageAddress::new(0x1000 * (index as u64 + 1)),
                access(),
                Budget::new(1),
            )
            .unwrap();
    }

    model.revoke_begin(target_scope).unwrap();
    let mut visited = Vec::new();
    while let Some(step) = model.revoke_next(target_scope).unwrap() {
        visited.push(step.fault);
    }
    model.revoke_complete(target_scope).unwrap();

    assert_eq!(visited.len(), TARGET);
    assert_eq!(model.live_faults(other_scope).unwrap().len(), UNRELATED);
    assert_eq!(model.scope(other_scope).unwrap().state, ScopeState::Active);
    let progress = model.scope(target_scope).unwrap().revocation.unwrap();
    assert_eq!(progress.target_count, TARGET);
    assert_eq!(progress.steps, TARGET);
    model.check_invariants().unwrap();
}
