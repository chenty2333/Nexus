// SPDX-License-Identifier: MPL-2.0

extern crate std;

use std::{collections::VecDeque, vec, vec::Vec};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Crash(ServiceIdentity),
    Isolate(ServiceIdentity, Option<u64>),
    Select(ServiceIdentity, u32),
    Construct(ReplacementLaunch),
    Discard(ServiceIdentity),
    Snapshot(ServiceIdentity),
    Publish(ServiceIdentity),
    RequestStop(ServiceIdentity, StopReason),
    Abort(ServiceIdentity, StopReason),
    Ready(ServiceIdentity),
    Rebind(ServiceIdentity),
    Peek(ServiceIdentity),
    Adopt(ServiceIdentity, u64),
}

struct FakeBackend {
    calls: Vec<Call>,
    binding_epoch: u64,
    next_id: u64,
    live: Vec<u64>,
    recovery: VecDeque<u64>,
    snapshot_active: Option<u64>,
    next_snapshot: u64,
    ready_active: bool,
    rebound: bool,
    authority_active: bool,
    failures: VecDeque<BackendStage>,
    reported_cohort_override: Option<CohortIdentity>,
    snapshot_cohort_override: Option<CohortIdentity>,
    invalid_crash_observation: bool,
    invalid_rebind_observation: bool,
    fail_adopt_after: Option<u32>,
    successful_adopts: u32,
    unpublished: Option<ServiceIdentity>,
    published: Option<ServiceIdentity>,
    stop_requested: Option<(ServiceIdentity, StopReason)>,
}

impl FakeBackend {
    fn new(binding_epoch: u64, recovery: &[u64]) -> Self {
        Self {
            calls: Vec::new(),
            binding_epoch,
            next_id: 20,
            live: recovery.to_vec(),
            recovery: recovery.iter().copied().collect(),
            snapshot_active: None,
            next_snapshot: 0,
            ready_active: false,
            rebound: false,
            authority_active: true,
            failures: VecDeque::new(),
            reported_cohort_override: None,
            snapshot_cohort_override: None,
            invalid_crash_observation: false,
            invalid_rebind_observation: false,
            fail_adopt_after: None,
            successful_adopts: 0,
            unpublished: None,
            published: None,
            stop_requested: None,
        }
    }

    fn with_failures(mut self, failures: &[BackendStage]) -> Self {
        self.failures = failures.iter().copied().collect();
        self
    }

    fn should_fail(&mut self, stage: BackendStage) -> bool {
        if self.failures.front() == Some(&stage) {
            self.failures.pop_front();
            true
        } else {
            false
        }
    }

    fn recovery_cohort(&self) -> CohortIdentity {
        cohort_identity(self.recovery.iter().copied())
    }

    fn mark_reaped(&mut self, replacement: ServiceIdentity) {
        assert_eq!(self.published, Some(replacement));
        self.published = None;
        self.stop_requested = None;
    }
}

fn cohort_identity(items: impl Iterator<Item = u64>) -> CohortIdentity {
    let mut digest = [0u8; 32];
    let mut len = 0u32;
    for (index, item) in items.enumerate() {
        for (offset, byte) in item.to_le_bytes().into_iter().enumerate() {
            let lane = (index.wrapping_mul(11).wrapping_add(offset)) % digest.len();
            digest[lane] = digest[lane]
                .wrapping_add(byte)
                .rotate_left((index % 7) as u32);
        }
        len = len.checked_add(1).expect("test cohort fits in u32");
    }
    digest[31] ^= len as u8;
    CohortIdentity::new(len, digest)
}

impl SupervisorBackend for FakeBackend {
    type Snapshot = u64;
    type RecoveryItem = u64;
    type Error = &'static str;

    fn crash_active(&mut self, service: ServiceIdentity) -> Result<CrashObservation, Self::Error> {
        self.calls.push(Call::Crash(service));
        let rebound = self.rebound;
        let stage = if rebound {
            BackendStage::FenceRecovery
        } else {
            BackendStage::Crash
        };
        if self.should_fail(stage) {
            return Err("injected failure");
        }
        let previous = self.binding_epoch;
        self.binding_epoch += 1;
        self.recovery = self.live.iter().copied().collect();
        self.snapshot_active = None;
        self.ready_active = false;
        self.rebound = false;
        self.authority_active = false;
        if !rebound {
            self.published = None;
            self.stop_requested = None;
        }
        let previous_binding_epoch = if self.invalid_crash_observation {
            previous + 100
        } else {
            previous
        };
        Ok(CrashObservation {
            previous_binding_epoch,
            crashed_binding_epoch: self.binding_epoch,
            cohort: self
                .reported_cohort_override
                .unwrap_or_else(|| self.recovery_cohort()),
        })
    }

    fn isolate_authority(
        &mut self,
        service: ServiceIdentity,
        last_known_binding_epoch: Option<u64>,
    ) {
        self.calls
            .push(Call::Isolate(service, last_known_binding_epoch));
        self.snapshot_active = None;
        self.ready_active = false;
        self.rebound = false;
        self.authority_active = false;
    }

    fn select_replacement(
        &mut self,
        failed: ServiceIdentity,
        attempt: u32,
    ) -> Result<ServiceIdentity, Self::Error> {
        self.calls.push(Call::Select(failed, attempt));
        if self.should_fail(BackendStage::SelectReplacement) {
            return Err("injected failure");
        }
        self.next_id += 1;
        ServiceIdentity::new(self.next_id, failed.generation() + 1).ok_or("identity")
    }

    fn construct_replacement(&mut self, launch: ReplacementLaunch) -> Result<(), Self::Error> {
        self.calls.push(Call::Construct(launch));
        if self.should_fail(BackendStage::ConstructReplacement) {
            return Err("injected failure");
        }
        if self.unpublished.is_some() {
            return Err("unpublished replacement already exists");
        }
        self.unpublished = Some(launch.replacement());
        Ok(())
    }

    fn discard_unpublished_replacement(&mut self, replacement: ServiceIdentity) {
        self.calls.push(Call::Discard(replacement));
        if self.unpublished == Some(replacement) {
            self.unpublished = None;
        }
    }

    fn recovery_snapshot(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<RecoverySnapshot<Self::Snapshot>, Self::Error> {
        self.calls.push(Call::Snapshot(replacement));
        if self.should_fail(BackendStage::Snapshot) {
            return Err("injected failure");
        }
        if self.snapshot_active.is_some() {
            return Err("previous attempt was not aborted");
        }
        self.next_snapshot += 1;
        self.snapshot_active = Some(self.next_snapshot);
        Ok(RecoverySnapshot::new(
            self.next_snapshot,
            self.snapshot_cohort_override
                .or(self.reported_cohort_override)
                .unwrap_or_else(|| self.recovery_cohort()),
        ))
    }

    fn publish_replacement(&mut self, replacement: ServiceIdentity) -> Result<(), Self::Error> {
        self.calls.push(Call::Publish(replacement));
        if self.should_fail(BackendStage::PublishReplacement) {
            return Err("injected failure");
        }
        if self.unpublished != Some(replacement) || self.published.is_some() {
            return Err("invalid publication");
        }
        self.unpublished = None;
        self.published = Some(replacement);
        Ok(())
    }

    fn request_stop_replacement(
        &mut self,
        replacement: ServiceIdentity,
        reason: StopReason,
    ) -> Result<(), Self::Error> {
        self.calls.push(Call::RequestStop(replacement, reason));
        if self.should_fail(BackendStage::RequestStopReplacement) {
            return Err("injected failure");
        }
        if self.published != Some(replacement) {
            return Err("replacement is not published");
        }
        self.stop_requested = Some((replacement, reason));
        Ok(())
    }

    fn abort_recovery_attempt(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &RecoverySnapshot<Self::Snapshot>,
        reason: StopReason,
    ) -> Result<(), Self::Error> {
        self.calls.push(Call::Abort(replacement, reason));
        if self.should_fail(BackendStage::AbortRecoveryAttempt) {
            return Err("injected failure");
        }
        if self.snapshot_active != Some(*snapshot.value()) || self.rebound {
            return Err("invalid abort");
        }
        self.snapshot_active = None;
        self.ready_active = false;
        Ok(())
    }

    fn ready(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &Self::Snapshot,
    ) -> Result<(), Self::Error> {
        self.calls.push(Call::Ready(replacement));
        if self.should_fail(BackendStage::Ready) {
            return Err("injected failure");
        }
        if self.snapshot_active != Some(*snapshot) {
            return Err("stale snapshot");
        }
        self.ready_active = true;
        Ok(())
    }

    fn rebind(&mut self, replacement: ServiceIdentity) -> Result<RebindObservation, Self::Error> {
        self.calls.push(Call::Rebind(replacement));
        if self.should_fail(BackendStage::Rebind) {
            return Err("injected failure");
        }
        if !self.ready_active {
            return Err("not ready");
        }
        self.ready_active = false;
        self.rebound = true;
        self.authority_active = true;
        Ok(RebindObservation {
            binding_epoch: self.binding_epoch,
            supervisor: if self.invalid_rebind_observation {
                ServiceIdentity::new(999, replacement.generation()).unwrap()
            } else {
                replacement
            },
        })
    }

    fn peek_recovery_item(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<Option<Self::RecoveryItem>, Self::Error> {
        self.calls.push(Call::Peek(replacement));
        if self.should_fail(BackendStage::PeekRecoveryItem) {
            return Err("injected failure");
        }
        Ok(self.recovery.front().copied())
    }

    fn adopt(
        &mut self,
        replacement: ServiceIdentity,
        item: Self::RecoveryItem,
    ) -> Result<(), Self::Error> {
        self.calls.push(Call::Adopt(replacement, item));
        if self.should_fail(BackendStage::Adopt)
            || self.fail_adopt_after == Some(self.successful_adopts)
        {
            return Err("injected failure");
        }
        assert_eq!(self.recovery.pop_front(), Some(item));
        self.successful_adopts += 1;
        Ok(())
    }
}

fn service(id: u64, generation: u64) -> ServiceIdentity {
    ServiceIdentity::new(id, generation).unwrap()
}

fn policy() -> SupervisorPolicy {
    SupervisorPolicy {
        max_recovery_attempts: 3,
        initial_backoff_ticks: 2,
        max_backoff_ticks: 8,
        replacement_timeout_ticks: 5,
        stop_timeout_ticks: 3,
        max_adoptions_per_recovery: 4,
    }
}

fn start_scheduled(manager: &mut SupervisorManager<FakeBackend>) -> (ServiceIdentity, u64) {
    let retry_tick = manager
        .health()
        .deadline_tick
        .expect("manager is in backoff");
    let PollProgress::ReplacementStarted {
        replacement,
        deadline_tick,
        ..
    } = manager.poll(retry_tick).unwrap()
    else {
        panic!("replacement did not start")
    };
    (replacement, deadline_tick)
}

fn crash_and_start(
    manager: &mut SupervisorManager<FakeBackend>,
    active: ServiceIdentity,
    now: u64,
    reason: ExitReason,
) -> (ServiceIdentity, u64) {
    manager.observe_exit(now, active, reason).unwrap();
    start_scheduled(manager)
}

fn reap_replacement(
    manager: &mut SupervisorManager<FakeBackend>,
    now: u64,
    replacement: ServiceIdentity,
) -> StopCompletion {
    manager.backend_mut().mark_reaped(replacement);
    manager.replacement_reaped(now, replacement).unwrap()
}

#[test]
fn crash_construct_publish_ready_rebind_and_adopt_are_manager_ordered() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(7, &[31, 32]), policy(), active, 7, 100).unwrap();

    manager
        .observe_exit(101, active, ExitReason::Fault)
        .unwrap();
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
    assert_eq!(manager.poll(102).unwrap(), PollProgress::Idle);
    let PollProgress::ReplacementStarted {
        replacement,
        deadline_tick,
        ..
    } = manager.poll(103).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert_eq!(deadline_tick, 108);
    let completion = manager.replacement_ready(104, replacement).unwrap();
    assert_eq!(completion.adopted, 2);
    assert_eq!(completion.binding_epoch, 8);
    assert_eq!(manager.health().phase, SupervisorPhase::Running);

    assert_eq!(
        manager.backend().calls,
        vec![
            Call::Crash(active),
            Call::Select(active, 1),
            Call::Construct(ReplacementLaunch::new(replacement, 8, 108)),
            Call::Snapshot(replacement),
            Call::Publish(replacement),
            Call::Ready(replacement),
            Call::Rebind(replacement),
            Call::Peek(replacement),
            Call::Adopt(replacement, 31),
            Call::Peek(replacement),
            Call::Adopt(replacement, 32),
            Call::Peek(replacement),
        ]
    );
}

#[test]
fn ready_timeout_reaps_replacement_and_exhausts_bounded_budget() {
    let active = service(10, 1);
    let mut bounded = policy();
    bounded.max_recovery_attempts = 1;
    let mut manager =
        SupervisorManager::new(FakeBackend::new(3, &[]), bounded, active, 3, 0).unwrap();

    manager
        .observe_exit(0, active, ExitReason::Watchdog)
        .unwrap();
    let PollProgress::ReplacementStarted {
        replacement,
        deadline_tick,
        ..
    } = manager.poll(2).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert_eq!(manager.poll(deadline_tick).unwrap(), PollProgress::Idle);
    let PollProgress::ReplacementStopRequested {
        deadline_tick: stop_deadline,
        ..
    } = manager.poll(deadline_tick + 1).unwrap()
    else {
        panic!("replacement was not asked to stop")
    };
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert_eq!(
        reap_replacement(&mut manager, stop_deadline, replacement),
        StopCompletion::Quarantined { replacement }
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(
        manager.health().terminal_failure,
        Some(TerminalFailure::RecoveryAttemptsExhausted)
    );
    assert_eq!(manager.health().retained_task, None);
    assert!(
        manager
            .backend()
            .calls
            .contains(&Call::RequestStop(replacement, StopReason::ReadyTimeout,))
    );
}

#[test]
fn stale_exit_and_ready_events_do_not_mutate_backend_or_state() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(1, &[]), policy(), active, 1, 0).unwrap();
    assert_eq!(
        manager.observe_exit(0, service(99, 1), ExitReason::Fault),
        Err(SupervisorError::StaleServiceEvent)
    );
    assert!(manager.backend().calls.is_empty());

    manager.observe_exit(1, active, ExitReason::Fault).unwrap();
    let PollProgress::ReplacementStarted { replacement, .. } = manager.poll(3).unwrap() else {
        panic!("replacement did not start")
    };
    let before = manager.backend().calls.clone();
    assert_eq!(
        manager.replacement_ready(3, service(88, 2)),
        Err(SupervisorError::StaleServiceEvent)
    );
    assert_eq!(manager.backend().calls, before);
    assert_eq!(manager.health().service, replacement);
}

#[test]
fn repeated_crash_uses_a_fresh_generation_and_next_backoff_attempt() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(4, &[]), policy(), active, 4, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let PollProgress::ReplacementStarted {
        replacement: first, ..
    } = manager.poll(2).unwrap()
    else {
        panic!("first replacement did not start")
    };
    manager.replacement_ready(2, first).unwrap();

    manager.backend_mut().mark_reaped(first);
    manager.observe_exit(3, first, ExitReason::Fault).unwrap();
    assert_eq!(manager.health().deadline_tick, Some(7));
    let PollProgress::ReplacementStarted {
        replacement: second,
        ..
    } = manager.poll(7).unwrap()
    else {
        panic!("second replacement did not start")
    };
    assert!(second.generation() > first.generation());
    assert_eq!(manager.health().recovery_attempts, 2);
}

#[test]
fn partial_adoption_failure_fences_the_rebound_service_before_retry() {
    let active = service(10, 1);
    let backend = FakeBackend::new(9, &[41]).with_failures(&[BackendStage::Adopt]);
    let mut manager = SupervisorManager::new(backend, policy(), active, 9, 0).unwrap();
    manager
        .observe_exit(0, active, ExitReason::ProtocolViolation)
        .unwrap();
    let PollProgress::ReplacementStarted { replacement, .. } = manager.poll(2).unwrap() else {
        panic!("replacement did not start")
    };
    assert_eq!(
        manager.replacement_ready(2, replacement),
        Err(SupervisorError::Backend {
            stage: BackendStage::Adopt,
            source: "injected failure",
        })
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert_eq!(manager.health().binding_epoch, Some(11));
    assert!(manager.backend().calls.ends_with(&[
        Call::Adopt(replacement, 41),
        Call::Crash(replacement),
        Call::RequestStop(replacement, StopReason::PartialRecoveryFailed),
    ]));
    reap_replacement(&mut manager, 3, replacement);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
}

#[test]
fn late_ready_is_stopped_and_cannot_rebind() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(5, &[]), policy(), active, 5, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let PollProgress::ReplacementStarted {
        replacement,
        deadline_tick,
        ..
    } = manager.poll(2).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert_eq!(
        manager.replacement_ready(deadline_tick + 1, replacement),
        Err(SupervisorError::ReadyDeadlineExpired)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert!(
        manager
            .backend()
            .calls
            .ends_with(&[Call::RequestStop(replacement, StopReason::ReadyTimeout),])
    );
    assert!(!manager.backend().calls.contains(&Call::Rebind(replacement)));

    reap_replacement(&mut manager, deadline_tick + 2, replacement);
    assert!(manager.backend().calls.ends_with(&[
        Call::RequestStop(replacement, StopReason::ReadyTimeout),
        Call::Abort(replacement, StopReason::ReadyTimeout),
    ]));
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);

    let (next, next_deadline) = start_scheduled(&mut manager);
    manager.replacement_ready(next_deadline, next).unwrap();
    assert_eq!(manager.health().phase, SupervisorPhase::Running);
}

#[test]
fn truncated_recovery_inventory_is_fenced_before_running() {
    let active = service(10, 1);
    let mut backend = FakeBackend::new(12, &[]);
    backend.reported_cohort_override = Some(cohort_identity([99].into_iter()));
    let mut manager = SupervisorManager::new(backend, policy(), active, 12, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let PollProgress::ReplacementStarted { replacement, .. } = manager.poll(2).unwrap() else {
        panic!("replacement did not start")
    };
    assert_eq!(
        manager.replacement_ready(2, replacement),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert!(manager.backend().calls.ends_with(&[
        Call::Peek(replacement),
        Call::Crash(replacement),
        Call::RequestStop(replacement, StopReason::PartialRecoveryFailed),
    ]));
    reap_replacement(&mut manager, 3, replacement);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
}

#[test]
fn deadline_overflow_quarantines_without_construction() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(1, &[]), policy(), active, 1, u64::MAX - 1)
            .unwrap();
    assert_eq!(
        manager.observe_exit(u64::MAX - 1, active, ExitReason::Fault),
        Err(SupervisorError::CounterOverflow)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(
        manager.backend().calls,
        vec![Call::Crash(active), Call::Isolate(active, Some(2))]
    );
    assert!(!manager.backend().authority_active);
}

#[test]
fn timeout_aborts_one_shot_snapshot_and_next_attempt_can_succeed() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(2, &[71]), policy(), active, 2, 0).unwrap();
    let (first, deadline_tick) = crash_and_start(&mut manager, active, 0, ExitReason::Watchdog);

    assert!(matches!(
        manager.poll(deadline_tick + 1).unwrap(),
        PollProgress::ReplacementStopRequested {
            replacement,
            ..
        } if replacement == first
    ));
    assert!(
        manager
            .backend()
            .calls
            .ends_with(&[Call::RequestStop(first, StopReason::ReadyTimeout),])
    );

    reap_replacement(&mut manager, deadline_tick + 2, first);
    assert!(manager.backend().calls.ends_with(&[
        Call::RequestStop(first, StopReason::ReadyTimeout),
        Call::Abort(first, StopReason::ReadyTimeout),
    ]));

    let (second, second_deadline) = start_scheduled(&mut manager);
    let completion = manager.replacement_ready(second_deadline, second).unwrap();
    assert_eq!(completion.adopted, 1);
    assert_eq!(manager.health().recovery_attempts, 2);
}

#[test]
fn replacement_exit_aborts_snapshot_and_next_attempt_can_succeed() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(3, &[]), policy(), active, 3, 0).unwrap();
    let (first, _) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);

    manager
        .observe_exit(3, first, ExitReason::UnexpectedReturn)
        .unwrap();
    assert!(
        manager
            .backend()
            .calls
            .ends_with(&[Call::RequestStop(first, StopReason::ExitedBeforeReady),])
    );

    reap_replacement(&mut manager, 4, first);
    assert!(manager.backend().calls.ends_with(&[
        Call::RequestStop(first, StopReason::ExitedBeforeReady),
        Call::Abort(first, StopReason::ExitedBeforeReady),
    ]));

    let (second, second_deadline) = start_scheduled(&mut manager);
    manager.replacement_ready(second_deadline, second).unwrap();
    assert_eq!(manager.health().phase, SupervisorPhase::Running);
}

#[test]
fn ready_and_rebind_failures_abort_before_retrying() {
    for stage in [BackendStage::Ready, BackendStage::Rebind] {
        let active = service(10, 1);
        let backend = FakeBackend::new(4, &[]).with_failures(&[stage]);
        let mut manager = SupervisorManager::new(backend, policy(), active, 4, 0).unwrap();
        let (first, first_deadline) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);

        assert_eq!(
            manager.replacement_ready(first_deadline, first),
            Err(SupervisorError::Backend {
                stage,
                source: "injected failure",
            })
        );
        assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
        assert!(
            manager
                .backend()
                .calls
                .ends_with(&[Call::RequestStop(first, StopReason::RecoveryRejected),])
        );

        reap_replacement(&mut manager, first_deadline, first);
        assert!(manager.backend().calls.ends_with(&[
            Call::RequestStop(first, StopReason::RecoveryRejected),
            Call::Abort(first, StopReason::RecoveryRejected),
        ]));
        assert_eq!(manager.health().phase, SupervisorPhase::Backoff);

        let (second, second_deadline) = start_scheduled(&mut manager);
        manager.replacement_ready(second_deadline, second).unwrap();
        assert_eq!(manager.health().phase, SupervisorPhase::Running);
    }
}

#[test]
fn crash_and_snapshot_must_name_the_same_exact_cohort() {
    let active = service(10, 1);
    let mut backend = FakeBackend::new(5, &[81]);
    backend.snapshot_cohort_override = Some(cohort_identity([82].into_iter()));
    let mut manager = SupervisorManager::new(backend, policy(), active, 5, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let retry_tick = manager.health().deadline_tick.unwrap();

    assert_eq!(
        manager.poll(retry_tick),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, Some(6));
    let replacement = manager.health().service;
    assert!(manager.backend().calls.ends_with(&[
        Call::Discard(replacement),
        Call::Abort(replacement, StopReason::RecoveryRejected),
        Call::Isolate(replacement, Some(6)),
    ]));
    assert!(!manager.backend().authority_active);
}

#[test]
fn snapshot_plus_one_member_is_fenced_before_extra_adopt() {
    let active = service(10, 1);
    let mut backend = FakeBackend::new(6, &[91, 92]);
    let claimed = cohort_identity([91].into_iter());
    backend.reported_cohort_override = Some(claimed);
    backend.snapshot_cohort_override = Some(claimed);
    let mut manager = SupervisorManager::new(backend, policy(), active, 6, 0).unwrap();
    let (replacement, deadline_tick) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);

    assert_eq!(
        manager.replacement_ready(deadline_tick, replacement),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert!(
        manager
            .backend()
            .calls
            .contains(&Call::Adopt(replacement, 91))
    );
    assert!(
        !manager
            .backend()
            .calls
            .contains(&Call::Adopt(replacement, 92))
    );
    assert!(manager.backend().calls.ends_with(&[
        Call::Peek(replacement),
        Call::Crash(replacement),
        Call::RequestStop(replacement, StopReason::PartialRecoveryFailed),
    ]));
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    reap_replacement(&mut manager, deadline_tick, replacement);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
}

#[test]
fn second_adopt_failure_recaptures_every_member_for_next_attempt() {
    let active = service(10, 1);
    let mut backend = FakeBackend::new(7, &[101, 102]);
    backend.fail_adopt_after = Some(1);
    let mut manager = SupervisorManager::new(backend, policy(), active, 7, 0).unwrap();
    let (first, first_deadline) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);

    assert_eq!(
        manager.replacement_ready(first_deadline, first),
        Err(SupervisorError::Backend {
            stage: BackendStage::Adopt,
            source: "injected failure",
        })
    );
    assert!(manager.backend().calls.ends_with(&[
        Call::Adopt(first, 102),
        Call::Crash(first),
        Call::RequestStop(first, StopReason::PartialRecoveryFailed),
    ]));
    assert_eq!(
        manager
            .backend()
            .recovery
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![101, 102]
    );

    manager.backend_mut().fail_adopt_after = None;
    reap_replacement(&mut manager, first_deadline, first);
    let (second, second_deadline) = start_scheduled(&mut manager);
    let completion = manager.replacement_ready(second_deadline, second).unwrap();
    assert_eq!(completion.adopted, 2);
}

#[test]
fn peek_is_idempotent_until_adopt_succeeds() {
    let replacement = service(21, 2);
    let mut backend = FakeBackend::new(8, &[111, 112]);
    let crash = backend.crash_active(service(10, 1)).unwrap();
    let snapshot = backend.recovery_snapshot(replacement).unwrap();
    assert_eq!(crash.cohort, snapshot.cohort());
    backend.ready(replacement, snapshot.value()).unwrap();
    backend.rebind(replacement).unwrap();

    let first = backend.peek_recovery_item(replacement).unwrap().unwrap();
    assert_eq!(backend.peek_recovery_item(replacement), Ok(Some(first)));
    assert_eq!(backend.recovery.len(), 2);
    backend.adopt(replacement, first).unwrap();
    assert_eq!(backend.peek_recovery_item(replacement), Ok(Some(112)));
}

#[test]
fn pre_snapshot_backend_failures_restore_state_and_consume_attempt() {
    for stage in [
        BackendStage::SelectReplacement,
        BackendStage::ConstructReplacement,
        BackendStage::Snapshot,
    ] {
        let active = service(10, 1);
        let backend = FakeBackend::new(9, &[]).with_failures(&[stage]);
        let mut manager = SupervisorManager::new(backend, policy(), active, 9, 0).unwrap();
        manager.observe_exit(0, active, ExitReason::Fault).unwrap();
        let retry_tick = manager.health().deadline_tick.unwrap();

        assert_eq!(
            manager.poll(retry_tick),
            Err(SupervisorError::Backend {
                stage,
                source: "injected failure",
            })
        );
        assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
        assert_eq!(manager.health().recovery_attempts, 1);
        assert_eq!(manager.backend().unpublished, None);
        assert_eq!(manager.backend().published, None);
        if stage == BackendStage::Snapshot {
            let replacement = manager.health().service;
            assert!(
                manager
                    .backend()
                    .calls
                    .ends_with(&[Call::Snapshot(replacement), Call::Discard(replacement),])
            );
            assert_eq!(manager.backend().snapshot_active, None);
        }

        let (replacement, deadline_tick) = start_scheduled(&mut manager);
        manager
            .replacement_ready(deadline_tick, replacement)
            .unwrap();
        assert_eq!(manager.health().phase, SupervisorPhase::Running);
    }
}

#[test]
fn construction_receives_exact_manager_launch_and_failure_preserves_fenced_authority() {
    let active = service(10, 1);
    let backend = FakeBackend::new(40, &[]).with_failures(&[BackendStage::ConstructReplacement]);
    let mut manager = SupervisorManager::new(backend, policy(), active, 40, 7).unwrap();

    manager.observe_exit(11, active, ExitReason::Fault).unwrap();
    assert_eq!(manager.health().deadline_tick, Some(13));
    assert_eq!(
        manager.poll(13),
        Err(SupervisorError::Backend {
            stage: BackendStage::ConstructReplacement,
            source: "injected failure",
        })
    );

    let replacement = service(21, 2);
    let launch = match manager.backend().calls.as_slice() {
        [
            Call::Crash(observed),
            Call::Select(failed, 1),
            Call::Construct(launch),
        ] => {
            assert_eq!(*observed, active);
            assert_eq!(*failed, active);
            *launch
        }
        calls => panic!("unexpected construction-failure calls: {calls:?}"),
    };
    assert_eq!(launch.replacement(), replacement);
    assert_eq!(launch.binding_epoch(), 41);
    assert_eq!(launch.ready_deadline_tick(), 18);

    let health = manager.health();
    assert_eq!(health.phase, SupervisorPhase::Backoff);
    assert_eq!(health.service, replacement);
    assert_eq!(health.binding_epoch, Some(41));
    assert_eq!(health.recovery_attempts, 1);
    assert_eq!(health.deadline_tick, Some(17));
    assert!(!manager.backend().authority_active);
    assert_eq!(manager.backend().snapshot_active, None);
}

#[test]
fn crash_and_peek_failures_have_queryable_recovery_states() {
    let active = service(10, 1);
    let backend = FakeBackend::new(10, &[]).with_failures(&[BackendStage::Crash]);
    let mut manager = SupervisorManager::new(backend, policy(), active, 10, 0).unwrap();
    assert_eq!(
        manager.observe_exit(0, active, ExitReason::Fault),
        Err(SupervisorError::Backend {
            stage: BackendStage::Crash,
            source: "injected failure",
        })
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, Some(10));
    assert_eq!(
        manager.backend().calls,
        vec![Call::Crash(active), Call::Isolate(active, Some(10)),]
    );
    assert!(!manager.backend().authority_active);

    let mut manager =
        SupervisorManager::new(FakeBackend::new(10, &[]), policy(), active, 10, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let (replacement, deadline_tick) = start_scheduled(&mut manager);
    manager
        .backend_mut()
        .failures
        .push_back(BackendStage::PeekRecoveryItem);
    assert_eq!(
        manager.replacement_ready(deadline_tick, replacement),
        Err(SupervisorError::Backend {
            stage: BackendStage::PeekRecoveryItem,
            source: "injected failure",
        })
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert!(manager.backend().calls.ends_with(&[
        Call::Peek(replacement),
        Call::Crash(replacement),
        Call::RequestStop(replacement, StopReason::PartialRecoveryFailed),
    ]));
    reap_replacement(&mut manager, deadline_tick, replacement);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
}

#[test]
fn stop_abort_and_fence_failures_quarantine_fail_closed() {
    for cleanup_stage in [
        BackendStage::RequestStopReplacement,
        BackendStage::AbortRecoveryAttempt,
    ] {
        let active = service(10, 1);
        let backend = FakeBackend::new(11, &[]).with_failures(&[cleanup_stage]);
        let mut manager = SupervisorManager::new(backend, policy(), active, 11, 0).unwrap();
        let (replacement, deadline_tick) =
            crash_and_start(&mut manager, active, 0, ExitReason::Fault);
        let stop_result = manager.poll(deadline_tick + 1);
        if cleanup_stage == BackendStage::RequestStopReplacement {
            assert_eq!(
                stop_result,
                Err(SupervisorError::Backend {
                    stage: cleanup_stage,
                    source: "injected failure",
                })
            );
        } else {
            assert!(matches!(
                stop_result,
                Ok(PollProgress::ReplacementStopRequested { .. })
            ));
            manager.backend_mut().mark_reaped(replacement);
            assert_eq!(
                manager.replacement_reaped(deadline_tick + 2, replacement),
                Err(SupervisorError::Backend {
                    stage: cleanup_stage,
                    source: "injected failure",
                })
            );
        }
        assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
        assert_eq!(manager.health().service, replacement);
        assert_eq!(manager.health().binding_epoch, Some(12));
        assert_eq!(
            manager.health().terminal_failure,
            Some(TerminalFailure::BackendFailure(cleanup_stage))
        );
        assert_eq!(
            manager.backend().calls.last(),
            Some(&Call::Isolate(replacement, Some(12)))
        );
        assert!(!manager.backend().authority_active);
        assert_eq!(
            manager.health().retained_task,
            if cleanup_stage == BackendStage::RequestStopReplacement {
                Some(replacement)
            } else {
                None
            }
        );
    }

    let active = service(10, 1);
    let backend = FakeBackend::new(12, &[121])
        .with_failures(&[BackendStage::Adopt, BackendStage::FenceRecovery]);
    let mut manager = SupervisorManager::new(backend, policy(), active, 12, 0).unwrap();
    let (replacement, deadline_tick) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    assert_eq!(
        manager.replacement_ready(deadline_tick, replacement),
        Err(SupervisorError::Backend {
            stage: BackendStage::FenceRecovery,
            source: "injected failure",
        })
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, Some(13));
    assert!(manager.backend().calls.ends_with(&[
        Call::Adopt(replacement, 121),
        Call::Crash(replacement),
        Call::Isolate(replacement, Some(13)),
    ]));
    assert!(!manager.backend().authority_active);
}

#[test]
fn invalid_epoch_is_unknown_but_invalid_rebind_is_fenced_to_known_epoch() {
    let active = service(10, 1);
    let mut backend = FakeBackend::new(13, &[]);
    backend.invalid_crash_observation = true;
    let mut manager = SupervisorManager::new(backend, policy(), active, 13, 0).unwrap();
    assert_eq!(
        manager.observe_exit(0, active, ExitReason::Fault),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, None);

    let mut backend = FakeBackend::new(14, &[]);
    backend.invalid_rebind_observation = true;
    let mut manager = SupervisorManager::new(backend, policy(), active, 14, 0).unwrap();
    let (replacement, deadline_tick) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    assert_eq!(
        manager.replacement_ready(deadline_tick, replacement),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    assert_eq!(manager.health().binding_epoch, Some(16));
    reap_replacement(&mut manager, deadline_tick, replacement);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);

    let mut backend = FakeBackend::new(16, &[]);
    backend.invalid_rebind_observation = true;
    let mut manager = SupervisorManager::new(backend, policy(), active, 16, 0).unwrap();
    let (replacement, deadline_tick) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    manager.backend_mut().invalid_crash_observation = true;
    assert_eq!(
        manager.replacement_ready(deadline_tick, replacement),
        Err(SupervisorError::InvalidBackendObservation)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, None);
}

#[test]
fn recovery_attempt_budget_is_consumed_at_selection_and_exhausts_immediately() {
    let active = service(10, 1);
    let mut one_attempt = policy();
    one_attempt.max_recovery_attempts = 1;
    let backend = FakeBackend::new(15, &[]).with_failures(&[BackendStage::SelectReplacement]);
    let mut manager = SupervisorManager::new(backend, one_attempt, active, 15, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let retry_tick = manager.health().deadline_tick.unwrap();
    assert_eq!(
        manager.poll(retry_tick),
        Err(SupervisorError::Backend {
            stage: BackendStage::SelectReplacement,
            source: "injected failure",
        })
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().recovery_attempts, 1);
    assert_eq!(manager.health().deadline_tick, None);
    assert_eq!(
        manager.health().terminal_failure,
        Some(TerminalFailure::RecoveryAttemptsExhausted)
    );
}

#[test]
fn maximum_attempt_counter_quarantines_without_transition_leak() {
    let active = service(10, 1);
    let mut maximal = policy();
    maximal.max_recovery_attempts = u32::MAX;
    let mut manager =
        SupervisorManager::new(FakeBackend::new(16, &[]), maximal, active, 16, 0).unwrap();
    manager.set_recovery_attempts(u32::MAX);

    assert_eq!(
        manager.observe_exit(0, active, ExitReason::Fault),
        Err(SupervisorError::Quarantined)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, Some(17));
    assert_eq!(manager.health().recovery_attempts, u32::MAX);
}

#[test]
fn oversized_crash_cohort_quarantines_before_replacement_selection() {
    let active = service(10, 1);
    let mut bounded = policy();
    bounded.max_adoptions_per_recovery = 1;
    let mut manager =
        SupervisorManager::new(FakeBackend::new(17, &[131, 132]), bounded, active, 17, 0).unwrap();
    assert_eq!(
        manager.observe_exit(0, active, ExitReason::Fault),
        Err(SupervisorError::RecoveryLimitExceeded)
    );
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(manager.health().binding_epoch, Some(18));
    assert_eq!(
        manager.backend().calls,
        vec![Call::Crash(active), Call::Isolate(active, Some(18))]
    );
    assert!(!manager.backend().authority_active);
}

#[test]
fn time_is_monotonic_and_configuration_is_bounded() {
    let active = service(10, 1);
    let mut invalid = policy();
    invalid.replacement_timeout_ticks = 0;
    assert!(matches!(
        SupervisorManager::new(FakeBackend::new(1, &[]), invalid, active, 1, 0),
        Err(SupervisorError::InvalidConfiguration)
    ));
    let mut invalid_stop = policy();
    invalid_stop.stop_timeout_ticks = 0;
    assert!(matches!(
        SupervisorManager::new(FakeBackend::new(1, &[]), invalid_stop, active, 1, 0),
        Err(SupervisorError::InvalidConfiguration)
    ));

    let mut manager =
        SupervisorManager::new(FakeBackend::new(1, &[]), policy(), active, 1, 5).unwrap();
    assert_eq!(manager.poll(4), Err(SupervisorError::TimeWentBackwards));
    assert_eq!(manager.health().phase, SupervisorPhase::Running);
}

#[test]
fn public_exit_events_are_epoch_fenced_and_stale_events_do_not_advance_time() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(7, &[]), policy(), active, 7, 10).unwrap();

    assert_eq!(
        manager.observe_exit_at_epoch(100, active, 6, ExitReason::Fault),
        Err(SupervisorError::StaleBindingEpoch {
            expected: 7,
            presented: 6,
        })
    );
    assert_eq!(
        manager.observe_exit_at_epoch(100, service(99, 1), 7, ExitReason::Fault),
        Err(SupervisorError::StaleServiceEvent)
    );
    assert!(manager.backend().calls.is_empty());

    manager
        .observe_exit_at_epoch(11, active, 7, ExitReason::Fault)
        .unwrap();
    let PollProgress::ReplacementStarted {
        replacement,
        binding_epoch,
        ..
    } = manager.poll(13).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert_eq!(binding_epoch, 8);
    let before = manager.backend().calls.clone();
    assert_eq!(
        manager.replacement_ready_at_epoch(100, replacement, 7),
        Err(SupervisorError::StaleBindingEpoch {
            expected: 8,
            presented: 7,
        })
    );
    assert_eq!(manager.backend().calls, before);
    manager
        .replacement_ready_at_epoch(13, replacement, binding_epoch)
        .unwrap();
}

#[test]
fn exact_exit_replay_is_idempotent_and_participates_in_monotonic_time() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(9, &[]), policy(), active, 9, 10).unwrap();
    manager
        .observe_exit_at_epoch(11, active, 9, ExitReason::Fault)
        .unwrap();
    let calls = manager.backend().calls.clone();
    let health = manager.health();

    assert_eq!(
        manager.observe_exit_at_epoch(200, active, 9, ExitReason::Watchdog),
        Err(SupervisorError::ConflictingEventReplay),
    );
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(manager.health(), health);

    manager
        .observe_exit_at_epoch(100, active, 9, ExitReason::Fault)
        .unwrap();
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(manager.poll(20), Err(SupervisorError::TimeWentBackwards));
    assert_eq!(
        manager.observe_exit_at_epoch(99, active, 9, ExitReason::Fault),
        Err(SupervisorError::TimeWentBackwards),
    );
    assert_eq!(manager.backend().calls, calls);
}

#[test]
fn exact_ready_replay_returns_the_cached_completion_without_backend_reentry() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(4, &[201]), policy(), active, 4, 0).unwrap();
    manager
        .observe_exit_at_epoch(0, active, 4, ExitReason::Fault)
        .unwrap();
    let PollProgress::ReplacementStarted {
        replacement,
        binding_epoch,
        deadline_tick,
    } = manager.poll(2).unwrap()
    else {
        panic!("replacement did not start")
    };
    let completion = manager
        .replacement_ready_at_epoch(deadline_tick, replacement, binding_epoch)
        .unwrap();
    let calls = manager.backend().calls.clone();

    assert_eq!(
        manager
            .replacement_ready_at_epoch(deadline_tick + 10, replacement, binding_epoch)
            .unwrap(),
        completion,
    );
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(
        manager.replacement_ready_at_epoch(deadline_tick + 100, replacement, binding_epoch - 1),
        Err(SupervisorError::StaleBindingEpoch {
            expected: binding_epoch,
            presented: binding_epoch - 1,
        })
    );
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(
        manager.poll(deadline_tick + 9),
        Err(SupervisorError::TimeWentBackwards),
    );
}

#[test]
fn timed_out_ready_replay_is_stable_and_never_repeats_cleanup() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(5, &[]), policy(), active, 5, 0).unwrap();
    manager
        .observe_exit_at_epoch(0, active, 5, ExitReason::Fault)
        .unwrap();
    let PollProgress::ReplacementStarted {
        replacement,
        binding_epoch,
        deadline_tick,
    } = manager.poll(2).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert!(matches!(
        manager.poll(deadline_tick + 1).unwrap(),
        PollProgress::ReplacementStopRequested { .. }
    ));
    let calls = manager.backend().calls.clone();
    for now in [deadline_tick + 2, deadline_tick + 3] {
        assert_eq!(
            manager.replacement_ready_at_epoch(now, replacement, binding_epoch),
            Err(SupervisorError::ReadyDeadlineExpired),
        );
        assert_eq!(manager.backend().calls, calls);
    }
}

#[test]
fn ready_before_publication_is_rejected_and_same_tick_publication_is_observable() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(1, &[]), policy(), active, 1, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();
    let calls_before = manager.backend().calls.clone();
    let predicted = service(21, 2);

    assert_eq!(
        manager.replacement_ready_at_epoch(1, predicted, 2),
        Err(SupervisorError::StaleServiceEvent)
    );
    assert_eq!(manager.backend().calls, calls_before);

    let PollProgress::ReplacementStarted {
        replacement,
        binding_epoch,
        ..
    } = manager.poll(2).unwrap()
    else {
        panic!("replacement did not start")
    };
    assert_eq!(replacement, predicted);
    assert!(manager.backend().calls.ends_with(&[
        Call::Construct(ReplacementLaunch::new(replacement, binding_epoch, 7)),
        Call::Snapshot(replacement),
        Call::Publish(replacement),
    ]));

    // This models a Ready event enqueued synchronously by task publication and
    // drained by the manager's single-owner event worker at the same tick.
    manager
        .replacement_ready_at_epoch(2, replacement, binding_epoch)
        .unwrap();
    assert_eq!(manager.health().phase, SupervisorPhase::Running);
}

#[test]
fn immediate_exit_wins_over_ready_and_duplicate_exit_does_not_repeat_stop() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(2, &[]), policy(), active, 2, 0).unwrap();
    let (replacement, _) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    let binding_epoch = 3;

    manager
        .observe_exit_at_epoch(2, replacement, binding_epoch, ExitReason::UnexpectedReturn)
        .unwrap();
    assert_eq!(manager.health().phase, SupervisorPhase::Stopping);
    let calls = manager.backend().calls.clone();
    assert_eq!(
        manager.replacement_ready_at_epoch(2, replacement, binding_epoch),
        Err(SupervisorError::ReplacementStopping)
    );
    manager
        .observe_exit_at_epoch(2, replacement, binding_epoch, ExitReason::UnexpectedReturn)
        .unwrap();
    assert_eq!(manager.backend().calls, calls);
    assert!(!manager.backend().calls.contains(&Call::Ready(replacement)));
    assert!(!manager.backend().calls.contains(&Call::Rebind(replacement)));
}

#[test]
fn publication_failure_discards_unpublished_task_and_snapshot_before_retry() {
    let active = service(10, 1);
    let backend = FakeBackend::new(2, &[211]).with_failures(&[BackendStage::PublishReplacement]);
    let mut manager = SupervisorManager::new(backend, policy(), active, 2, 0).unwrap();
    manager.observe_exit(0, active, ExitReason::Fault).unwrap();

    assert_eq!(
        manager.poll(2),
        Err(SupervisorError::Backend {
            stage: BackendStage::PublishReplacement,
            source: "injected failure",
        })
    );
    let replacement = manager.health().service;
    assert!(manager.backend().calls.ends_with(&[
        Call::Snapshot(replacement),
        Call::Publish(replacement),
        Call::Discard(replacement),
        Call::Abort(replacement, StopReason::RecoveryRejected),
    ]));
    assert_eq!(manager.backend().unpublished, None);
    assert_eq!(manager.backend().published, None);
    assert_eq!(manager.backend().snapshot_active, None);
    assert_eq!(manager.health().phase, SupervisorPhase::Backoff);
    assert_eq!(manager.health().terminal_failure, None);
    assert_eq!(manager.health().retained_task, None);
}

#[test]
fn stop_timeout_is_terminal_and_retains_the_exact_published_task() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(3, &[]), policy(), active, 3, 0).unwrap();
    let (replacement, ready_deadline) =
        crash_and_start(&mut manager, active, 0, ExitReason::Watchdog);
    let PollProgress::ReplacementStopRequested {
        deadline_tick: stop_deadline,
        ..
    } = manager.poll(ready_deadline + 1).unwrap()
    else {
        panic!("replacement was not asked to stop")
    };

    assert_eq!(manager.poll(stop_deadline).unwrap(), PollProgress::Idle);
    assert_eq!(
        manager.poll(stop_deadline + 1).unwrap(),
        PollProgress::Quarantined
    );
    let health = manager.health();
    assert_eq!(health.phase, SupervisorPhase::Quarantined);
    assert_eq!(health.terminal_failure, Some(TerminalFailure::StopTimeout));
    assert_eq!(health.retained_task, Some(replacement));
    assert_eq!(manager.backend().published, Some(replacement));
    assert_eq!(
        manager.backend().calls.last(),
        Some(&Call::Isolate(replacement, Some(4)))
    );

    let calls = manager.backend().calls.clone();
    assert_eq!(
        manager.replacement_ready(stop_deadline + 2, replacement),
        Err(SupervisorError::ReadyDeadlineExpired)
    );
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(manager.health(), health);
}

#[test]
fn exact_reaped_event_at_stop_deadline_cleans_once_and_replays() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(4, &[]), policy(), active, 4, 0).unwrap();
    let (replacement, ready_deadline) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    let PollProgress::ReplacementStopRequested {
        deadline_tick: stop_deadline,
        ..
    } = manager.poll(ready_deadline + 1).unwrap()
    else {
        panic!("replacement was not asked to stop")
    };
    let event_epoch = 5;
    manager.backend_mut().mark_reaped(replacement);
    let completion = manager
        .replacement_reaped_at_epoch(stop_deadline, replacement, event_epoch)
        .unwrap();
    assert!(matches!(
        completion,
        StopCompletion::RetryScheduled {
            replacement: observed,
            ..
        } if observed == replacement
    ));
    let calls = manager.backend().calls.clone();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, Call::Abort(observed, _) if *observed == replacement))
            .count(),
        1
    );

    assert_eq!(
        manager
            .replacement_reaped_at_epoch(stop_deadline + 1, replacement, event_epoch)
            .unwrap(),
        completion
    );
    assert_eq!(manager.backend().calls, calls);
    assert_eq!(
        manager.replacement_reaped_at_epoch(stop_deadline + 100, replacement, event_epoch - 1),
        Err(SupervisorError::StaleBindingEpoch {
            expected: event_epoch,
            presented: event_epoch - 1,
        })
    );
    assert_eq!(manager.backend().calls, calls);
}

#[test]
fn reaped_event_after_stop_deadline_quarantines_without_claiming_retention() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(5, &[]), policy(), active, 5, 0).unwrap();
    let (replacement, ready_deadline) = crash_and_start(&mut manager, active, 0, ExitReason::Fault);
    let PollProgress::ReplacementStopRequested {
        deadline_tick: stop_deadline,
        ..
    } = manager.poll(ready_deadline + 1).unwrap()
    else {
        panic!("replacement was not asked to stop")
    };
    manager.backend_mut().mark_reaped(replacement);

    assert_eq!(
        manager.replacement_reaped(stop_deadline + 1, replacement),
        Err(SupervisorError::StopDeadlineExpired)
    );
    assert_eq!(
        manager.health().terminal_failure,
        Some(TerminalFailure::StopTimeout)
    );
    assert_eq!(manager.health().retained_task, None);
    assert!(
        !manager
            .backend()
            .calls
            .iter()
            .any(|call| matches!(call, Call::Abort(observed, _) if *observed == replacement))
    );
    let calls = manager.backend().calls.clone();
    assert_eq!(
        manager.replacement_reaped(stop_deadline + 2, replacement),
        Err(SupervisorError::StopDeadlineExpired)
    );
    assert_eq!(manager.backend().calls, calls);
}

#[test]
fn internal_transition_sentinel_fails_closed_without_production_panic() {
    let active = service(10, 1);
    let mut manager =
        SupervisorManager::new(FakeBackend::new(1, &[]), policy(), active, 1, 0).unwrap();
    manager.force_transitioning();
    assert_eq!(manager.health().phase, SupervisorPhase::AuthorityUnresolved);
    assert_eq!(manager.poll(0), Err(SupervisorError::InternalInvariant));
    assert_eq!(manager.health().phase, SupervisorPhase::Quarantined);
    assert_eq!(
        manager.backend().calls,
        vec![Call::Isolate(active, Some(1))]
    );
    assert!(!manager.backend().authority_active);

    let source = include_str!("manager.rs");
    assert!(!source.contains("unreachable!"));
    assert!(!source.contains("panic!"));
}
