use cser_model::pager::{
    FaultAccess, FaultState, FrameId, PageAddress, PagerError, PagerId, PagerModel,
    RecoveryTimeoutResult, ThreadId,
};
use cser_model::{Budget, BudgetDisposition, ScopeState};
use proptest::prelude::*;

fn access() -> FaultAccess {
    FaultAccess::WRITE.union(FaultAccess::USER)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bounded_recovery_sequences_preserve_one_shot_and_budget_invariants(
        decisions in prop::collection::vec((any::<bool>(), any::<bool>()), 1..20)
    ) {
        let mut model = PagerModel::new();
        let total = decisions.len() as u64;
        let (scope, _address_space, old_binding) = model
            .create_address_space(PagerId::new(1), Budget::new(total))
            .unwrap();
        let mut faults = Vec::new();
        for (index, (prepare_before_crash, _)) in decisions.iter().enumerate() {
            let token = model
                .register_fault(
                    old_binding,
                    ThreadId::new(index as u64 + 1),
                    PageAddress::new(0x1000 * (index as u64 + 1)),
                    access(),
                    Budget::new(1),
                )
                .unwrap();
            if *prepare_before_crash {
                model
                    .prepare_zero(old_binding, token, FrameId::new(index as u64 + 1))
                    .unwrap();
            }
            faults.push(token);
        }

        model.crash(old_binding).unwrap();
        model.fallback_pick(scope).unwrap();
        let snapshot = model.recovery_snapshot(scope, PagerId::new(2)).unwrap();
        let ready = model.ready(&snapshot).unwrap();
        let replacement = model.rebind(ready).unwrap();

        let mut committed = 0u64;
        let mut pending = 0u64;
        let fault_count = faults.len();
        let mut adopted_faults = Vec::new();
        for (index, (token, (prepared_before_crash, resolve))) in faults
            .into_iter()
            .zip(decisions.iter().copied())
            .enumerate()
        {
            let adopted = model.adopt(replacement, token).unwrap();
            // Keep at least the final fault uncommitted so the kernel timeout,
            // rather than an arbitrary Active-scope abort, closes the remainder.
            let resolve = resolve && index + 1 < fault_count;
            if resolve {
                if !prepared_before_crash {
                    model
                        .prepare_zero(
                            replacement,
                            adopted,
                            FrameId::new(10_000 + index as u64),
                        )
                        .unwrap();
                }
                model.commit(replacement, adopted).unwrap();
                let committed_view = model.fault(adopted.fault()).unwrap();
                prop_assert_eq!((committed_view.wakes, committed_view.resumes), (0, 0));
                model.complete(adopted.fault()).unwrap();
                prop_assert_eq!(
                    model.complete(adopted.fault()),
                    Err(PagerError::AlreadyTerminal)
                );
                committed += 1;
            } else {
                pending += 1;
            }
            let view = model.fault(adopted.fault()).unwrap();
            prop_assert_eq!(view.state.is_terminal(), resolve);
            prop_assert_eq!(view.continuation_consumptions, u8::from(resolve));
            prop_assert_eq!(view.terminalizations, u8::from(resolve));
            prop_assert_eq!(view.wakes, u8::from(resolve));
            prop_assert_eq!(view.resumes, u8::from(resolve));
            adopted_faults.push((adopted, resolve));
            model.check_invariants().unwrap();
        }

        prop_assert!(pending > 0);
        prop_assert_eq!(
            model.recovery_timeout_begin(scope).unwrap(),
            RecoveryTimeoutResult::RevocationStarted
        );
        let mut aborted = 0u64;
        while let Some(step) = model.revoke_next(scope).unwrap() {
            prop_assert_eq!(step.to, FaultState::Aborted);
            aborted += 1;
            model.check_invariants().unwrap();
        }
        prop_assert_eq!(aborted, pending);
        model.revoke_complete(scope).unwrap();

        for (token, resolved) in adopted_faults {
            let view = model.fault(token.fault()).unwrap();
            prop_assert!(view.state.is_terminal());
            prop_assert_eq!(view.continuation_consumptions, 1);
            prop_assert_eq!(view.terminalizations, 1);
            prop_assert_eq!(view.wakes, 1);
            prop_assert_eq!(view.resumes, u8::from(resolved));
            prop_assert!(view.prepared_frame.is_none());
        }
        let scope_view = model.scope(scope).unwrap();
        prop_assert_eq!(scope_view.free_budget, Budget::new(aborted));
        prop_assert_eq!(scope_view.spent_budget, Budget::new(committed));
        prop_assert_eq!(scope_view.live_faults, 0);
        model.check_invariants().unwrap();
    }

    #[test]
    fn commit_and_revoke_begin_choose_one_linearization_order(
        commit_first in any::<bool>()
    ) {
        let mut model = PagerModel::new();
        let (scope, _address_space, binding) = model
            .create_address_space(PagerId::new(1), Budget::new(1))
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
        model
            .prepare_zero(binding, token, FrameId::new(1))
            .unwrap();

        if commit_first {
            model.commit(binding, token).unwrap();
            model.revoke_begin(scope).unwrap();
            let step = model.revoke_next(scope).unwrap().unwrap();
            prop_assert_eq!(step.to, FaultState::Completed);
            let fault = model.fault(token.fault()).unwrap();
            prop_assert_eq!(fault.budget_disposition, BudgetDisposition::Spent);
            prop_assert_eq!((fault.wakes, fault.resumes), (1, 1));
        } else {
            model.revoke_begin(scope).unwrap();
            let before_rejected_commit = model.clone();
            let fenced = matches!(
                model.commit(binding, token),
                Err(PagerError::StaleAuthority { .. })
            );
            prop_assert!(fenced);
            prop_assert_eq!(&model, &before_rejected_commit);
            let step = model.revoke_next(scope).unwrap().unwrap();
            prop_assert_eq!(step.to, FaultState::Aborted);
            let fault = model.fault(token.fault()).unwrap();
            prop_assert_eq!(fault.budget_disposition, BudgetDisposition::Returned);
            prop_assert_eq!((fault.wakes, fault.resumes), (1, 0));
        }
        model.revoke_complete(scope).unwrap();
        prop_assert_eq!(model.scope(scope).unwrap().state, ScopeState::Revoked);
        prop_assert_eq!(model.fault(token.fault()).unwrap().terminalizations, 1);
        model.check_invariants().unwrap();
    }

    #[test]
    fn recovery_timeout_and_replacement_commit_have_one_linearization_order(
        commit_first in any::<bool>()
    ) {
        let mut model = PagerModel::new();
        let (scope, _address_space, old_binding) = model
            .create_address_space(PagerId::new(1), Budget::new(1))
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
        model
            .prepare_zero(old_binding, old_token, FrameId::new(1))
            .unwrap();
        model.crash(old_binding).unwrap();
        model.fallback_pick(scope).unwrap();
        let snapshot = model.recovery_snapshot(scope, PagerId::new(2)).unwrap();
        let ready = model.ready(&snapshot).unwrap();
        let replacement = model.rebind(ready).unwrap();
        let adopted = model.adopt(replacement, old_token).unwrap();

        if commit_first {
            model.commit(replacement, adopted).unwrap();
            prop_assert_eq!(
                model.recovery_timeout_begin(scope).unwrap(),
                RecoveryTimeoutResult::CompletionPending { committed: 1 }
            );
            prop_assert_eq!(model.scope(scope).unwrap().state, ScopeState::Active);
            let registration_is_closed = matches!(
                model.register_fault(
                    replacement,
                    ThreadId::new(2),
                    PageAddress::new(0x2000),
                    access(),
                    Budget::new(1),
                ),
                Err(PagerError::RecoveryDeadlineCompletionPending)
            );
            prop_assert!(registration_is_closed);
            model.complete(adopted.fault()).unwrap();
            let fault = model.fault(adopted.fault()).unwrap();
            prop_assert_eq!(fault.budget_disposition, BudgetDisposition::Spent);
            prop_assert_eq!((fault.wakes, fault.resumes), (1, 1));
            let completion_pending = model.scope(scope).unwrap();
            prop_assert_eq!(completion_pending.state, ScopeState::Active);
            prop_assert!(completion_pending.recovery_deadline_armed);
            prop_assert!(completion_pending.recovery_deadline_completion_pending);
            prop_assert_eq!(completion_pending.live_faults, 0);
            model.deadline_complete(scope).unwrap();
            let idle = model.scope(scope).unwrap();
            prop_assert_eq!(idle.state, ScopeState::Active);
            prop_assert!(!idle.recovery_deadline_armed);
            prop_assert!(!idle.recovery_deadline_completion_pending);
        } else {
            prop_assert_eq!(
                model.recovery_timeout_begin(scope).unwrap(),
                RecoveryTimeoutResult::RevocationStarted
            );
            let before = model.clone();
            let commit_was_fenced = matches!(
                model.commit(replacement, adopted),
                Err(PagerError::StaleAuthority { .. })
            );
            prop_assert!(commit_was_fenced);
            prop_assert_eq!(&model, &before);
            let step = model.revoke_next(scope).unwrap().unwrap();
            prop_assert_eq!(step.to, FaultState::Aborted);
            let fault = model.fault(adopted.fault()).unwrap();
            prop_assert_eq!(fault.budget_disposition, BudgetDisposition::Returned);
            prop_assert_eq!((fault.wakes, fault.resumes), (1, 0));
            model.revoke_complete(scope).unwrap();
        }
        prop_assert_eq!(model.fault(adopted.fault()).unwrap().terminalizations, 1);
        model.check_invariants().unwrap();
    }

    #[test]
    fn one_current_generation_page_slot_has_at_most_one_publication(
        contenders in 1usize..18,
        winner_seed in any::<usize>(),
    ) {
        let winner = winner_seed % contenders;
        let mut model = PagerModel::new();
        let (scope, _address_space, binding) = model
            .create_address_space(PagerId::new(1), Budget::new(contenders as u64))
            .unwrap();
        let mut tokens = Vec::new();
        for index in 0..contenders {
            let token = model
                .register_fault(
                    binding,
                    ThreadId::new(index as u64 + 1),
                    PageAddress::new(0x7000),
                    access(),
                    Budget::new(1),
                )
                .unwrap();
            model
                .prepare_zero(binding, token, FrameId::new(index as u64 + 1))
                .unwrap();
            tokens.push(token);
        }

        let mapping = model.commit(binding, tokens[winner]).unwrap();
        for (index, token) in tokens.iter().copied().enumerate() {
            if index == winner {
                continue;
            }
            prop_assert_eq!(model.satisfy_mapped(token).unwrap(), mapping);
        }
        model.complete(tokens[winner].fault()).unwrap();

        prop_assert_eq!(model.mapping_count(), 1);
        prop_assert_eq!(model.publication_count(), 1);
        let publication_sum: usize = tokens
            .iter()
            .map(|token| {
                usize::from(
                    model
                        .fault(token.fault())
                        .unwrap()
                        .mapping_publications,
                )
            })
            .sum();
        prop_assert_eq!(publication_sum, 1);
        for token in tokens {
            let fault = model.fault(token.fault()).unwrap();
            prop_assert_eq!(fault.state, FaultState::Completed);
            prop_assert_eq!(fault.continuation_consumptions, 1);
            prop_assert_eq!(fault.terminalizations, 1);
            prop_assert_eq!((fault.wakes, fault.resumes), (1, 1));
            prop_assert!(fault.prepared_frame.is_none());
        }
        let scope_view = model.scope(scope).unwrap();
        prop_assert_eq!(scope_view.free_budget, Budget::new(contenders as u64 - 1));
        prop_assert_eq!(scope_view.spent_budget, Budget::new(1));
        model.check_invariants().unwrap();
    }

    #[test]
    fn revocation_steps_depend_only_on_target_reverse_index(
        target in 0usize..24,
        unrelated in 0usize..48,
    ) {
        let mut model = PagerModel::new();
        let (target_scope, _target_as, target_binding) = model
            .create_address_space(PagerId::new(1), Budget::new(target as u64))
            .unwrap();
        let (other_scope, _other_as, other_binding) = model
            .create_address_space(PagerId::new(2), Budget::new(unrelated as u64))
            .unwrap();
        for index in 0..target {
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
        for index in 0..unrelated {
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
        let mut steps = 0usize;
        while model.revoke_next(target_scope).unwrap().is_some() {
            steps += 1;
        }
        model.revoke_complete(target_scope).unwrap();

        prop_assert_eq!(steps, target);
        prop_assert_eq!(model.live_faults(other_scope).unwrap().len(), unrelated);
        prop_assert_eq!(model.scope(other_scope).unwrap().state, ScopeState::Active);
        model.check_invariants().unwrap();
    }
}
