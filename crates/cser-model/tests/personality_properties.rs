use cser_model::ScopeState;
use cser_model::personality::{
    PersonalityError, PersonalityId, PersonalityModel, PreparedReply, SyscallDelivery,
    SyscallOperation, SyscallState, TaskId,
};
use proptest::prelude::*;

fn operation(write: bool) -> SyscallOperation {
    if write {
        SyscallOperation::Write
    } else {
        SyscallOperation::ExitGroup
    }
}

fn reply_for(operation: SyscallOperation) -> PreparedReply {
    match operation {
        SyscallOperation::Write => PreparedReply::WriteReturned,
        SyscallOperation::ExitGroup => PreparedReply::ExitGroupRequested,
    }
}

proptest! {
    #[test]
    fn arbitrary_orphan_cohort_has_one_success_or_abort_delivery(
        cases in prop::collection::vec(
            (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
            1..24,
        )
    ) {
        let mut model = PersonalityModel::new();
        let (scope, old_binding) = model.create_scope(PersonalityId::new(1)).unwrap();
        let mut tokens = Vec::new();

        for (index, (write, prepare_before_crash, commit_before_crash, complete_after_rebind))
            in cases.iter().copied().enumerate()
        {
            let operation = operation(write);
            let token = model
                .capture(old_binding, TaskId::new(index as u64 + 1), operation)
                .unwrap();
            if prepare_before_crash {
                model
                    .prepare_reply(old_binding, token, reply_for(operation))
                    .unwrap();
            }
            let committed_before_crash =
                write && prepare_before_crash && commit_before_crash;
            if committed_before_crash {
                model.commit_backend(old_binding, token).unwrap();
            }
            tokens.push((
                token,
                prepare_before_crash,
                committed_before_crash,
                complete_after_rebind,
            ));
            model.check_invariants().unwrap();
        }

        model.crash(old_binding).unwrap();
        let stale_state = model.clone();
        let stale_was_rejected = matches!(
            model.reply(old_binding, tokens[0].0),
            Err(PersonalityError::StaleBinding { .. })
        );
        prop_assert!(stale_was_rejected);
        prop_assert_eq!(&model, &stale_state);
        model.fallback_pick(scope).unwrap();
        let snapshot = model
            .recovery_snapshot(scope, PersonalityId::new(2))
            .unwrap();
        prop_assert_eq!(snapshot.syscalls().len(), cases.len());
        let ready = model.ready(&snapshot).unwrap();
        let replacement = model.rebind(ready).unwrap();

        let mut adopted = Vec::new();
        let mut completed_count = 0usize;
        for (old_token, was_prepared, was_committed, should_complete) in tokens {
            let token = model.adopt(replacement, old_token).unwrap();
            if !was_prepared {
                model
                    .prepare_reply(replacement, token, reply_for(token.operation()))
                    .unwrap();
            }
            if should_complete {
                if token.operation() == SyscallOperation::Write && !was_committed {
                    model.commit_backend(replacement, token).unwrap();
                }
                let delivery = model.reply(replacement, token).unwrap();
                match token.operation() {
                    SyscallOperation::Write => {
                        prop_assert_eq!(delivery, SyscallDelivery::WriteReturned);
                    }
                    SyscallOperation::ExitGroup => {
                        prop_assert_eq!(delivery, SyscallDelivery::ExitGroupRequested);
                    }
                }
                completed_count += 1;
            }
            adopted.push((token, should_complete || was_committed));
            model.check_invariants().unwrap();
        }

        model.revoke_begin(scope).unwrap();
        let mut closure_count = 0usize;
        while model.revoke_next(scope).unwrap().is_some() {
            closure_count += 1;
            model.check_invariants().unwrap();
        }
        model.revoke_complete(scope).unwrap();
        prop_assert_eq!(completed_count + closure_count, cases.len());

        for (token, completed) in adopted {
            let view = model.syscall(token.syscall()).unwrap();
            prop_assert!(view.state.is_terminal());
            prop_assert_eq!(view.continuation_consumptions, 1);
            prop_assert_eq!(view.terminalizations, 1);
            if completed {
                prop_assert_eq!(view.state, SyscallState::Completed);
                prop_assert_eq!(view.reply_publications, 1);
                match token.operation() {
                    SyscallOperation::Write => {
                        prop_assert_eq!(view.backend_commits, 1);
                        prop_assert_eq!((view.resumes, view.exits, view.aborts), (1, 0, 0));
                    }
                    SyscallOperation::ExitGroup => {
                        prop_assert_eq!(view.backend_commits, 0);
                        prop_assert_eq!((view.resumes, view.exits, view.aborts), (0, 1, 0));
                    }
                }
            } else {
                prop_assert_eq!(view.state, SyscallState::Aborted);
                prop_assert_eq!(view.backend_commits, 0);
                prop_assert_eq!(view.reply_publications, 0);
                prop_assert_eq!((view.resumes, view.exits, view.aborts), (0, 0, 1));
            }
        }
        let scope_view = model.scope(scope).unwrap();
        prop_assert_eq!(scope_view.state, ScopeState::Revoked);
        prop_assert_eq!(scope_view.revocation.unwrap().target_count, closure_count);
        prop_assert_eq!(scope_view.revocation.unwrap().steps, closure_count);
        model.check_invariants().unwrap();
    }

    #[test]
    fn commit_reply_and_revoke_choose_one_linearization_order(
        order in 0u8..3,
        write in any::<bool>(),
    ) {
        let mut model = PersonalityModel::new();
        let (scope, binding) = model.create_scope(PersonalityId::new(1)).unwrap();
        let operation = operation(write);
        let token = model
            .capture(binding, TaskId::new(1), operation)
            .unwrap();
        model
            .prepare_reply(binding, token, reply_for(operation))
            .unwrap();

        if order == 0 {
            model.revoke_begin(scope).unwrap();
            let before_rejected_action = model.clone();
            let action_was_fenced = matches!(
                if write {
                    model.commit_backend(binding, token)
                } else {
                    model.reply(binding, token).map(|_| ())
                },
                Err(PersonalityError::InvalidScopeState {
                    state: ScopeState::Closing
                })
            );
            prop_assert!(action_was_fenced);
            prop_assert_eq!(&model, &before_rejected_action);
            model.revoke_next(scope).unwrap().unwrap();
            let aborted = model.syscall(token.syscall()).unwrap();
            prop_assert_eq!(aborted.state, SyscallState::Aborted);
            prop_assert_eq!(aborted.backend_commits, 0);
            prop_assert_eq!(aborted.reply_publications, 0);
        } else if write && order == 1 {
            model.commit_backend(binding, token).unwrap();
            model.revoke_begin(scope).unwrap();
            let before_rejected_reply = model.clone();
            let reply_was_fenced = matches!(
                model.reply(binding, token),
                Err(PersonalityError::InvalidScopeState {
                    state: ScopeState::Closing
                })
            );
            prop_assert!(reply_was_fenced);
            prop_assert_eq!(&model, &before_rejected_reply);
            let drained = model.revoke_next(scope).unwrap().unwrap();
            prop_assert_eq!(drained.from, SyscallState::BackendCommitted);
            prop_assert_eq!(drained.to, SyscallState::Completed);
        } else {
            if write {
                model.commit_backend(binding, token).unwrap();
            }
            model.reply(binding, token).unwrap();
            model.revoke_begin(scope).unwrap();
            prop_assert_eq!(model.revoke_next(scope).unwrap(), None);
        }
        model.revoke_complete(scope).unwrap();
        let terminal = model.syscall(token.syscall()).unwrap();
        prop_assert_eq!(terminal.backend_commits, u8::from(write && order != 0));
        prop_assert_eq!(terminal.continuation_consumptions, 1);
        prop_assert_eq!(terminal.terminalizations, 1);
        prop_assert_eq!(u16::from(terminal.resumes) + u16::from(terminal.exits) + u16::from(terminal.aborts), 1);
        model.check_invariants().unwrap();
    }

    #[test]
    fn repeated_pre_or_post_commit_crashes_require_adoption_without_duplicate_delivery(
        crash_count in 1u8..6,
        write in any::<bool>(),
        prepare_before_first_crash in any::<bool>(),
        commit_before_first_crash in any::<bool>(),
    ) {
        let mut model = PersonalityModel::new();
        let (scope, mut binding) = model.create_scope(PersonalityId::new(1)).unwrap();
        let operation = operation(write);
        let mut token = model
            .capture(binding, TaskId::new(1), operation)
            .unwrap();
        if prepare_before_first_crash {
            model
                .prepare_reply(binding, token, reply_for(operation))
                .unwrap();
        }
        let mut committed = write && prepare_before_first_crash && commit_before_first_crash;
        if committed {
            model.commit_backend(binding, token).unwrap();
        }
        let first_epoch = binding.binding_epoch().get();

        for crash_index in 0..crash_count {
            let stale_binding = binding;
            let stale_token = token;
            model.crash(binding).unwrap();
            let scope_after_crash = model.scope(scope).unwrap();
            prop_assert_eq!(
                scope_after_crash.binding_epoch.get(),
                first_epoch + u64::from(crash_index) + 1
            );
            let stale_state = model.clone();
            let stale_prepare_was_rejected = matches!(
                model.prepare_reply(stale_binding, stale_token, reply_for(operation)),
                Err(PersonalityError::StaleBinding { .. })
            );
            prop_assert!(stale_prepare_was_rejected);
            let stale_commit_was_rejected = matches!(
                model.commit_backend(stale_binding, stale_token),
                Err(PersonalityError::StaleBinding { .. })
            );
            prop_assert!(stale_commit_was_rejected);
            let stale_reply_was_rejected = matches!(
                model.reply(stale_binding, stale_token),
                Err(PersonalityError::StaleBinding { .. })
            );
            prop_assert!(stale_reply_was_rejected);
            prop_assert_eq!(&model, &stale_state);

            model.fallback_pick(scope).unwrap();
            let snapshot = model
                .recovery_snapshot(scope, PersonalityId::new(u64::from(crash_index) + 2))
                .unwrap();
            let ready = model.ready(&snapshot).unwrap();
            binding = model.rebind(ready).unwrap();
            token = model.adopt(binding, token).unwrap();
            prop_assert_eq!(token.binding_epoch(), binding.binding_epoch());
            model.check_invariants().unwrap();
        }

        if !prepare_before_first_crash {
            model
                .prepare_reply(binding, token, reply_for(operation))
                .unwrap();
        }
        if write && !committed {
            model.commit_backend(binding, token).unwrap();
            committed = true;
        }
        if write {
            let before_duplicate_commit = model.clone();
            let duplicate_was_rejected = model.commit_backend(binding, token)
                == Err(PersonalityError::BackendAlreadyCommitted);
            prop_assert!(duplicate_was_rejected);
            prop_assert_eq!(&model, &before_duplicate_commit);
        }
        model.reply(binding, token).unwrap();
        let completed = model.syscall(token.syscall()).unwrap();
        prop_assert_eq!(completed.state, SyscallState::Completed);
        prop_assert_eq!(completed.backend_commits, u8::from(committed));
        prop_assert_eq!(completed.reply_publications, 1);
        prop_assert_eq!(completed.resumes, u8::from(write));
        prop_assert_eq!(completed.continuation_consumptions, 1);
        prop_assert_eq!(completed.terminalizations, 1);
        model.check_invariants().unwrap();
    }
}
