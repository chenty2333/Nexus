use cser_model::ScopeState;
use cser_model::personality::{
    PersonalityAction, PersonalityError, PersonalityFallbackState, PersonalityId, PersonalityModel,
    PreparedReply, SyscallContinuationState, SyscallDelivery, SyscallOperation, SyscallState,
    TaskId,
};

fn personality(id: u64) -> PersonalityId {
    PersonalityId::new(id)
}

#[test]
fn prepared_write_requires_rebind_adoption_and_one_backend_commit_after_crash() {
    let mut model = PersonalityModel::new();
    let (scope, old_binding) = model.create_scope(personality(1)).unwrap();
    let old_token = model
        .capture(old_binding, TaskId::new(7), SyscallOperation::Write)
        .unwrap();
    model
        .prepare_reply(old_binding, old_token, PreparedReply::WriteReturned)
        .unwrap();

    let before_crash = model.scope(scope).unwrap();
    model.crash(old_binding).unwrap();
    let after_crash = model.scope(scope).unwrap();
    assert_eq!(after_crash.authority_epoch, before_crash.authority_epoch);
    assert_eq!(
        after_crash.binding_epoch.get(),
        before_crash.binding_epoch.get() + 1
    );
    assert_eq!(after_crash.fallback, PersonalityFallbackState::Required);

    let before_stale_reply = model.clone();
    assert!(matches!(
        model.reply(old_binding, old_token),
        Err(PersonalityError::StaleBinding { .. })
    ));
    assert_eq!(model, before_stale_reply);
    assert!(matches!(
        model.commit_backend(old_binding, old_token),
        Err(PersonalityError::StaleBinding { .. })
    ));
    assert_eq!(model, before_stale_reply);

    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, personality(2)).unwrap();
    assert_eq!(snapshot.syscalls().len(), 1);
    assert_eq!(snapshot.syscalls()[0].token, old_token);
    assert_eq!(snapshot.syscalls()[0].state, SyscallState::ReplyPrepared);
    assert_eq!(
        snapshot.syscalls()[0].prepared_reply,
        Some(PreparedReply::WriteReturned)
    );
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    assert_eq!(replacement.binding_epoch(), after_crash.binding_epoch);

    let before_unadopted_reply = model.clone();
    assert!(matches!(
        model.reply(replacement, old_token),
        Err(PersonalityError::SyscallBindingFenced { .. })
    ));
    assert_eq!(model, before_unadopted_reply);

    let adopted = model.adopt(replacement, old_token).unwrap();
    assert_eq!(adopted.binding_epoch(), replacement.binding_epoch());
    let before_uncommitted_reply = model.clone();
    assert_eq!(
        model.reply(replacement, adopted),
        Err(PersonalityError::InvalidSyscallState {
            state: SyscallState::ReplyPrepared
        })
    );
    assert_eq!(model, before_uncommitted_reply);
    model.commit_backend(replacement, adopted).unwrap();
    let committed = model.syscall(adopted.syscall()).unwrap();
    assert_eq!(committed.state, SyscallState::BackendCommitted);
    assert_eq!(committed.backend_commits, 1);
    assert_eq!(committed.reply_publications, 0);
    assert_eq!(committed.resumes, 0);
    assert_eq!(
        model.reply(replacement, adopted).unwrap(),
        SyscallDelivery::WriteReturned
    );
    let completed = model.syscall(adopted.syscall()).unwrap();
    assert_eq!(completed.state, SyscallState::Completed);
    assert_eq!(completed.continuation, SyscallContinuationState::Replied);
    assert_eq!(completed.prepared_reply, Some(PreparedReply::WriteReturned));
    assert_eq!(completed.backend_commits, 1);
    assert_eq!(completed.delivery, Some(SyscallDelivery::WriteReturned));
    assert_eq!(completed.reply_publications, 1);
    assert_eq!(completed.continuation_consumptions, 1);
    assert_eq!(completed.terminalizations, 1);
    assert_eq!(
        (completed.resumes, completed.exits, completed.aborts),
        (1, 0, 0)
    );
    assert_eq!(model.scope(scope).unwrap().live_syscalls, 0);

    let after_completion = model.clone();
    assert_eq!(
        model.reply(replacement, adopted),
        Err(PersonalityError::AlreadyTerminal)
    );
    assert_eq!(model, after_completion);

    let actions: Vec<_> = model.trace().iter().map(|event| event.action).collect();
    for (left, right) in [
        (PersonalityAction::Capture, PersonalityAction::PrepareReply),
        (PersonalityAction::PrepareReply, PersonalityAction::Crash),
        (PersonalityAction::Crash, PersonalityAction::FallbackPick),
        (PersonalityAction::FallbackPick, PersonalityAction::Ready),
        (PersonalityAction::Ready, PersonalityAction::Rebind),
        (PersonalityAction::Rebind, PersonalityAction::Adopt),
        (PersonalityAction::Adopt, PersonalityAction::BackendCommit),
        (PersonalityAction::BackendCommit, PersonalityAction::Reply),
    ] {
        let left = actions.iter().position(|action| *action == left).unwrap();
        let right = actions.iter().position(|action| *action == right).unwrap();
        assert!(left < right);
    }
    model.check_invariants().unwrap();
}

#[test]
fn backend_committed_write_crash_can_only_be_replied_not_recommitted() {
    let mut model = PersonalityModel::new();
    let (scope, old_binding) = model.create_scope(personality(1)).unwrap();
    let old_token = model
        .capture(old_binding, TaskId::new(8), SyscallOperation::Write)
        .unwrap();
    model
        .prepare_reply(old_binding, old_token, PreparedReply::WriteReturned)
        .unwrap();
    model.commit_backend(old_binding, old_token).unwrap();

    let before_crash = model.syscall(old_token.syscall()).unwrap();
    assert_eq!(before_crash.state, SyscallState::BackendCommitted);
    assert_eq!(before_crash.backend_commits, 1);
    assert_eq!(before_crash.reply_publications, 0);
    assert_eq!(before_crash.resumes, 0);

    model.crash(old_binding).unwrap();
    let after_stale_replay = model.clone();
    assert!(matches!(
        model.commit_backend(old_binding, old_token),
        Err(PersonalityError::StaleBinding { .. })
    ));
    assert!(matches!(
        model.reply(old_binding, old_token),
        Err(PersonalityError::StaleBinding { .. })
    ));
    assert_eq!(model, after_stale_replay);

    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, personality(2)).unwrap();
    assert_eq!(snapshot.syscalls()[0].state, SyscallState::BackendCommitted);
    assert_eq!(
        snapshot.syscalls()[0].prepared_reply,
        Some(PreparedReply::WriteReturned)
    );
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let adopted = model.adopt(replacement, old_token).unwrap();

    let before_duplicate_commit = model.clone();
    assert_eq!(
        model.commit_backend(replacement, adopted),
        Err(PersonalityError::BackendAlreadyCommitted)
    );
    assert_eq!(model, before_duplicate_commit);
    assert_eq!(
        model.reply(replacement, adopted).unwrap(),
        SyscallDelivery::WriteReturned
    );

    let completed = model.syscall(adopted.syscall()).unwrap();
    assert_eq!(completed.state, SyscallState::Completed);
    assert_eq!(completed.backend_commits, 1);
    assert_eq!(completed.reply_publications, 1);
    assert_eq!(completed.continuation_consumptions, 1);
    assert_eq!(
        (completed.resumes, completed.exits, completed.aborts),
        (1, 0, 0)
    );

    let after_completion = model.clone();
    assert_eq!(
        model.commit_backend(replacement, adopted),
        Err(PersonalityError::AlreadyTerminal)
    );
    assert_eq!(
        model.reply(replacement, adopted),
        Err(PersonalityError::AlreadyTerminal)
    );
    assert_eq!(model, after_completion);
    model.check_invariants().unwrap();
}

#[test]
fn exit_group_captured_before_crash_can_be_prepared_only_after_adoption() {
    let mut model = PersonalityModel::new();
    let (scope, old_binding) = model.create_scope(personality(1)).unwrap();
    let old_token = model
        .capture(old_binding, TaskId::new(9), SyscallOperation::ExitGroup)
        .unwrap();
    model.crash(old_binding).unwrap();
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, personality(2)).unwrap();
    assert_eq!(snapshot.syscalls()[0].state, SyscallState::Captured);
    assert_eq!(snapshot.syscalls()[0].prepared_reply, None);
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let adopted = model.adopt(replacement, old_token).unwrap();

    model
        .prepare_reply(replacement, adopted, PreparedReply::ExitGroupRequested)
        .unwrap();
    let before_backend_commit = model.clone();
    assert_eq!(
        model.commit_backend(replacement, adopted),
        Err(PersonalityError::BackendCommitNotApplicable)
    );
    assert_eq!(model, before_backend_commit);
    assert_eq!(
        model.reply(replacement, adopted).unwrap(),
        SyscallDelivery::ExitGroupRequested
    );
    let completed = model.syscall(adopted.syscall()).unwrap();
    assert_eq!(completed.state, SyscallState::Completed);
    assert_eq!(completed.backend_commits, 0);
    assert_eq!(
        completed.delivery,
        Some(SyscallDelivery::ExitGroupRequested)
    );
    assert_eq!(
        (completed.resumes, completed.exits, completed.aborts),
        (0, 1, 0)
    );
    assert_eq!(completed.continuation_consumptions, 1);
    assert_eq!(completed.terminalizations, 1);
    model.check_invariants().unwrap();
}

#[test]
fn failed_recovery_revokes_and_aborts_captured_and_prepared_syscalls_once() {
    let mut model = PersonalityModel::new();
    let (scope, binding) = model.create_scope(personality(1)).unwrap();
    let write = model
        .capture(binding, TaskId::new(1), SyscallOperation::Write)
        .unwrap();
    model
        .prepare_reply(binding, write, PreparedReply::WriteReturned)
        .unwrap();
    let exit = model
        .capture(binding, TaskId::new(2), SyscallOperation::ExitGroup)
        .unwrap();
    model.crash(binding).unwrap();
    model.fallback_pick(scope).unwrap();

    model.revoke_begin(scope).unwrap();
    assert_eq!(model.scope(scope).unwrap().state, ScopeState::Closing);
    assert_eq!(
        model.revoke_complete(scope),
        Err(PersonalityError::RevocationNotQuiescent { remaining: 2 })
    );
    let first = model.revoke_next(scope).unwrap().unwrap();
    assert_eq!(first.to, SyscallState::Aborted);
    model.check_invariants().unwrap();
    let second = model.revoke_next(scope).unwrap().unwrap();
    assert_eq!(second.to, SyscallState::Aborted);
    assert_eq!(model.revoke_next(scope).unwrap(), None);
    model.revoke_complete(scope).unwrap();

    for token in [write, exit] {
        let aborted = model.syscall(token.syscall()).unwrap();
        assert_eq!(aborted.state, SyscallState::Aborted);
        assert_eq!(aborted.continuation, SyscallContinuationState::Aborted);
        assert_eq!(aborted.delivery, Some(SyscallDelivery::Aborted));
        assert_eq!(aborted.reply_publications, 0);
        assert_eq!(aborted.backend_commits, 0);
        assert_eq!(aborted.continuation_consumptions, 1);
        assert_eq!(aborted.terminalizations, 1);
        assert_eq!((aborted.resumes, aborted.exits, aborted.aborts), (0, 0, 1));
    }
    let closed = model.scope(scope).unwrap();
    assert_eq!(closed.state, ScopeState::Revoked);
    assert_eq!(closed.live_syscalls, 0);
    assert_eq!(closed.revocation.unwrap().target_count, 2);
    assert_eq!(closed.revocation.unwrap().steps, 2);
    model.check_invariants().unwrap();
}

#[test]
fn wrong_reply_label_and_duplicate_task_capture_are_failure_atomic() {
    let mut model = PersonalityModel::new();
    let (_scope, binding) = model.create_scope(personality(1)).unwrap();
    let write = model
        .capture(binding, TaskId::new(4), SyscallOperation::Write)
        .unwrap();

    let before_mismatch = model.clone();
    assert_eq!(
        model.prepare_reply(binding, write, PreparedReply::ExitGroupRequested),
        Err(PersonalityError::ReplyOperationMismatch)
    );
    assert_eq!(model, before_mismatch);

    let before_duplicate = model.clone();
    assert_eq!(
        model.capture(binding, TaskId::new(4), SyscallOperation::ExitGroup),
        Err(PersonalityError::TaskAlreadyBlocked {
            syscall: write.syscall()
        })
    );
    assert_eq!(model, before_duplicate);

    model
        .prepare_reply(binding, write, PreparedReply::WriteReturned)
        .unwrap();
    model.commit_backend(binding, write).unwrap();
    model.reply(binding, write).unwrap();
    let second = model
        .capture(binding, TaskId::new(4), SyscallOperation::ExitGroup)
        .unwrap();
    assert_ne!(write.syscall(), second.syscall());
    model.check_invariants().unwrap();
}

#[test]
fn backend_commit_and_revoke_preserve_the_winning_linearization_order() {
    let mut commit_first = PersonalityModel::new();
    let (scope, binding) = commit_first.create_scope(personality(1)).unwrap();
    let token = commit_first
        .capture(binding, TaskId::new(3), SyscallOperation::Write)
        .unwrap();
    commit_first
        .prepare_reply(binding, token, PreparedReply::WriteReturned)
        .unwrap();
    commit_first.commit_backend(binding, token).unwrap();
    commit_first.revoke_begin(scope).unwrap();

    let before_fenced_reply = commit_first.clone();
    assert!(matches!(
        commit_first.reply(binding, token),
        Err(PersonalityError::InvalidScopeState {
            state: ScopeState::Closing
        })
    ));
    assert_eq!(commit_first, before_fenced_reply);
    let drained = commit_first.revoke_next(scope).unwrap().unwrap();
    assert_eq!(drained.from, SyscallState::BackendCommitted);
    assert_eq!(drained.to, SyscallState::Completed);
    commit_first.revoke_complete(scope).unwrap();
    let completed = commit_first.syscall(token.syscall()).unwrap();
    assert_eq!(completed.backend_commits, 1);
    assert_eq!(completed.reply_publications, 1);
    assert_eq!(
        (completed.resumes, completed.exits, completed.aborts),
        (1, 0, 0)
    );
    commit_first.check_invariants().unwrap();

    let mut revoke_first = PersonalityModel::new();
    let (scope, binding) = revoke_first.create_scope(personality(1)).unwrap();
    let token = revoke_first
        .capture(binding, TaskId::new(3), SyscallOperation::Write)
        .unwrap();
    revoke_first
        .prepare_reply(binding, token, PreparedReply::WriteReturned)
        .unwrap();
    revoke_first.revoke_begin(scope).unwrap();
    let before_fenced_commit = revoke_first.clone();
    assert!(matches!(
        revoke_first.commit_backend(binding, token),
        Err(PersonalityError::InvalidScopeState {
            state: ScopeState::Closing
        })
    ));
    assert_eq!(revoke_first, before_fenced_commit);
    let aborted = revoke_first.revoke_next(scope).unwrap().unwrap();
    assert_eq!(aborted.from, SyscallState::ReplyPrepared);
    assert_eq!(aborted.to, SyscallState::Aborted);
    revoke_first.revoke_complete(scope).unwrap();
    let aborted = revoke_first.syscall(token.syscall()).unwrap();
    assert_eq!(aborted.backend_commits, 0);
    assert_eq!(aborted.reply_publications, 0);
    assert_eq!((aborted.resumes, aborted.exits, aborted.aborts), (0, 0, 1));
    revoke_first.check_invariants().unwrap();
}

#[test]
fn replacement_cannot_skip_fallback_snapshot_ready_or_adopt() {
    let mut model = PersonalityModel::new();
    let (scope, old_binding) = model.create_scope(personality(1)).unwrap();
    let token = model
        .capture(old_binding, TaskId::new(1), SyscallOperation::Write)
        .unwrap();
    model.crash(old_binding).unwrap();

    assert_eq!(
        model.recovery_snapshot(scope, personality(2)),
        Err(PersonalityError::FallbackUnavailable)
    );
    model.fallback_pick(scope).unwrap();
    let snapshot = model.recovery_snapshot(scope, personality(2)).unwrap();
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    assert!(matches!(
        model.prepare_reply(replacement, token, PreparedReply::WriteReturned),
        Err(PersonalityError::SyscallBindingFenced { .. })
    ));
    let adopted = model.adopt(replacement, token).unwrap();
    assert_eq!(
        model.adopt(replacement, adopted),
        Err(PersonalityError::NotAdoptable)
    );
    model.check_invariants().unwrap();
}
