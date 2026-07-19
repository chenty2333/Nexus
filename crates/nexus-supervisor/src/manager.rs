// SPDX-License-Identifier: MPL-2.0

use core::mem;

use crate::{
    BackendStage, CohortIdentity, CrashObservation, ExitReason, PollProgress, RecoveryCompletion,
    RecoverySnapshot, ReplacementLaunch, ServiceIdentity, StopCompletion, StopReason,
    SupervisorBackend, SupervisorError, SupervisorHealth, SupervisorPhase, SupervisorPolicy,
    TerminalFailure,
};

enum StopCleanup<S> {
    PreRebind { snapshot: RecoverySnapshot<S> },
    PostRebind { cohort: CohortIdentity },
}

impl<S> StopCleanup<S> {
    const fn cohort(&self) -> CohortIdentity {
        match self {
            Self::PreRebind { snapshot } => snapshot.cohort(),
            Self::PostRebind { cohort } => *cohort,
        }
    }
}

enum State<S> {
    Running {
        service: ServiceIdentity,
        binding_epoch: u64,
    },
    Backoff {
        failed: ServiceIdentity,
        binding_epoch: u64,
        cohort: CohortIdentity,
        retry_tick: u64,
        reason: ExitReason,
    },
    AwaitingReady {
        replacement: ServiceIdentity,
        binding_epoch: u64,
        deadline_tick: u64,
        reason: ExitReason,
        snapshot: RecoverySnapshot<S>,
    },
    Stopping {
        replacement: ServiceIdentity,
        event_binding_epoch: u64,
        recovery_binding_epoch: u64,
        deadline_tick: u64,
        reason: ExitReason,
        stop_reason: StopReason,
        cleanup: StopCleanup<S>,
    },
    Quarantined {
        service: ServiceIdentity,
        binding_epoch: Option<u64>,
        reason: ExitReason,
        terminal_failure: TerminalFailure,
        retained_task: Option<ServiceIdentity>,
    },
    Transitioning {
        service: ServiceIdentity,
        binding_epoch: Option<u64>,
        reason: Option<ExitReason>,
        retained_task: Option<ServiceIdentity>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryDisposition {
    Scheduled { retry_tick: u64 },
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitReplayOutcome {
    Scheduled,
    Stopping,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExitReplay {
    service: ServiceIdentity,
    binding_epoch: u64,
    reason: ExitReason,
    outcome: ExitReplayOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadyReplay {
    Completed(RecoveryCompletion),
    DeadlineExpired {
        replacement: ServiceIdentity,
        binding_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReapedReplay {
    replacement: ServiceIdentity,
    binding_epoch: u64,
    outcome: ReapedReplayOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReapedReplayOutcome {
    Completed(StopCompletion),
    DeadlineExpired,
}

/// Drives one independently restartable service domain.
///
/// The manager privately owns the backend and therefore retains lifecycle and
/// recovery authority across child-service failure. Its replay state is fixed
/// size: only the most recently accepted exit, terminal Ready event, and exact
/// replacement-reaped event are retained for each event kind.
pub struct SupervisorManager<B>
where
    B: SupervisorBackend,
{
    backend: B,
    policy: SupervisorPolicy,
    state: State<B::Snapshot>,
    recovery_attempts: u32,
    last_tick: u64,
    last_exit_replay: Option<ExitReplay>,
    last_ready_replay: Option<ReadyReplay>,
    last_reaped_replay: Option<ReapedReplay>,
}

impl<B> SupervisorManager<B>
where
    B: SupervisorBackend,
{
    /// Creates a manager for an already active Registry service binding.
    pub fn new(
        backend: B,
        policy: SupervisorPolicy,
        service: ServiceIdentity,
        binding_epoch: u64,
        now: u64,
    ) -> Result<Self, SupervisorError<B::Error>> {
        if !policy.is_valid() || binding_epoch == 0 {
            return Err(SupervisorError::InvalidConfiguration);
        }
        Ok(Self {
            backend,
            policy,
            state: State::Running {
                service,
                binding_epoch,
            },
            recovery_attempts: 0,
            last_tick: now,
            last_exit_replay: None,
            last_ready_replay: None,
            last_reaped_replay: None,
        })
    }

    #[cfg(test)]
    pub(crate) const fn backend(&self) -> &B {
        &self.backend
    }

    #[cfg(test)]
    pub(crate) fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[cfg(test)]
    pub(crate) fn set_recovery_attempts(&mut self, recovery_attempts: u32) {
        self.recovery_attempts = recovery_attempts;
    }

    #[cfg(test)]
    pub(crate) fn force_transitioning(&mut self) {
        let _ = self.take_state();
    }

    /// Returns the current read-only health projection.
    pub fn health(&self) -> SupervisorHealth {
        match &self.state {
            State::Running {
                service,
                binding_epoch,
            } => SupervisorHealth {
                phase: SupervisorPhase::Running,
                service: *service,
                binding_epoch: Some(*binding_epoch),
                recovery_attempts: self.recovery_attempts,
                deadline_tick: None,
                last_exit: None,
                terminal_failure: None,
                retained_task: None,
            },
            State::Backoff {
                failed,
                binding_epoch,
                retry_tick,
                reason,
                ..
            } => SupervisorHealth {
                phase: SupervisorPhase::Backoff,
                service: *failed,
                binding_epoch: Some(*binding_epoch),
                recovery_attempts: self.recovery_attempts,
                deadline_tick: Some(*retry_tick),
                last_exit: Some(*reason),
                terminal_failure: None,
                retained_task: None,
            },
            State::AwaitingReady {
                replacement,
                binding_epoch,
                deadline_tick,
                reason,
                ..
            } => SupervisorHealth {
                phase: SupervisorPhase::AwaitingReady,
                service: *replacement,
                binding_epoch: Some(*binding_epoch),
                recovery_attempts: self.recovery_attempts,
                deadline_tick: Some(*deadline_tick),
                last_exit: Some(*reason),
                terminal_failure: None,
                retained_task: None,
            },
            State::Stopping {
                replacement,
                recovery_binding_epoch,
                deadline_tick,
                reason,
                ..
            } => SupervisorHealth {
                phase: SupervisorPhase::Stopping,
                service: *replacement,
                binding_epoch: Some(*recovery_binding_epoch),
                recovery_attempts: self.recovery_attempts,
                deadline_tick: Some(*deadline_tick),
                last_exit: Some(*reason),
                terminal_failure: None,
                retained_task: None,
            },
            State::Quarantined {
                service,
                binding_epoch,
                reason,
                terminal_failure,
                retained_task,
            } => SupervisorHealth {
                phase: SupervisorPhase::Quarantined,
                service: *service,
                binding_epoch: *binding_epoch,
                recovery_attempts: self.recovery_attempts,
                deadline_tick: None,
                last_exit: Some(*reason),
                terminal_failure: Some(*terminal_failure),
                retained_task: *retained_task,
            },
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => SupervisorHealth {
                phase: SupervisorPhase::AuthorityUnresolved,
                service: *service,
                binding_epoch: *binding_epoch,
                recovery_attempts: self.recovery_attempts,
                deadline_tick: None,
                last_exit: *reason,
                terminal_failure: None,
                retained_task: *retained_task,
            },
        }
    }

    /// Observes an epoch-fenced task exit and schedules bounded replacement recovery.
    ///
    /// An exact replay of the most recently accepted exit returns its cached
    /// disposition without backend re-entry, but still checks and advances the
    /// monotonic time watermark. Stale or conflicting events do neither. A
    /// replacement exit before Ready begins cooperative stopping; only a later
    /// exact reaped event permits cleanup and retry.
    pub fn observe_exit_at_epoch(
        &mut self,
        now: u64,
        service: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        if let Some(replay) = self.last_exit_replay
            && replay.service == service
        {
            if replay.binding_epoch != binding_epoch {
                return Err(SupervisorError::StaleBindingEpoch {
                    expected: replay.binding_epoch,
                    presented: binding_epoch,
                });
            }
            if replay.reason != reason {
                return Err(SupervisorError::ConflictingEventReplay);
            }
            self.observe_time(now)?;
            return match replay.outcome {
                ExitReplayOutcome::Scheduled | ExitReplayOutcome::Stopping => Ok(()),
                ExitReplayOutcome::Quarantined => Err(SupervisorError::Quarantined),
            };
        }

        let (expected_service, expected_binding_epoch) = match &self.state {
            State::Running {
                service,
                binding_epoch,
            } => (*service, *binding_epoch),
            State::AwaitingReady {
                replacement,
                binding_epoch,
                ..
            } => (*replacement, *binding_epoch),
            State::Stopping {
                replacement,
                event_binding_epoch,
                ..
            } => {
                if service != *replacement {
                    return Err(SupervisorError::StaleServiceEvent);
                }
                if binding_epoch != *event_binding_epoch {
                    return Err(SupervisorError::StaleBindingEpoch {
                        expected: *event_binding_epoch,
                        presented: binding_epoch,
                    });
                }
                self.observe_time(now)?;
                return Err(SupervisorError::ReplacementStopping);
            }
            State::Backoff { .. } => return Err(SupervisorError::StaleServiceEvent),
            State::Quarantined { .. } => return Err(SupervisorError::Quarantined),
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => {
                let service = *service;
                let binding_epoch = *binding_epoch;
                let reason = reason.unwrap_or(ExitReason::ProtocolViolation);
                let retained_task = retained_task.or(Some(service));
                self.quarantine(
                    service,
                    binding_epoch,
                    reason,
                    TerminalFailure::InternalInvariant,
                    retained_task,
                );
                return Err(SupervisorError::InternalInvariant);
            }
        };
        if service != expected_service {
            return Err(SupervisorError::StaleServiceEvent);
        }
        if binding_epoch != expected_binding_epoch {
            return Err(SupervisorError::StaleBindingEpoch {
                expected: expected_binding_epoch,
                presented: binding_epoch,
            });
        }

        self.observe_time(now)?;
        let state = self.take_state();
        match state {
            State::Running {
                service: active,
                binding_epoch: active_binding_epoch,
            } => {
                let crash = match self.backend.crash_active(active) {
                    Ok(crash) => crash,
                    Err(source) => {
                        self.quarantine(
                            active,
                            Some(active_binding_epoch),
                            reason,
                            TerminalFailure::BackendFailure(BackendStage::Crash),
                            None,
                        );
                        return Err(SupervisorError::Backend {
                            stage: BackendStage::Crash,
                            source,
                        });
                    }
                };
                let (crashed_binding_epoch, cohort) = self.accept_crash_observation(
                    active,
                    active_binding_epoch,
                    reason,
                    crash,
                    None,
                )?;
                let disposition =
                    self.schedule_backoff(now, active, crashed_binding_epoch, cohort, reason)?;
                let outcome = match disposition {
                    RetryDisposition::Scheduled { .. } => ExitReplayOutcome::Scheduled,
                    RetryDisposition::Exhausted => ExitReplayOutcome::Quarantined,
                };
                self.last_exit_replay = Some(ExitReplay {
                    service,
                    binding_epoch,
                    reason,
                    outcome,
                });
                match disposition {
                    RetryDisposition::Scheduled { .. } => Ok(()),
                    RetryDisposition::Exhausted => Err(SupervisorError::Quarantined),
                }
            }
            State::AwaitingReady {
                replacement,
                binding_epoch,
                deadline_tick: _,
                reason: _,
                snapshot,
            } => {
                self.begin_pre_rebind_stop(
                    now,
                    replacement,
                    binding_epoch,
                    reason,
                    StopReason::ExitedBeforeReady,
                    snapshot,
                )?;
                self.last_exit_replay = Some(ExitReplay {
                    service,
                    binding_epoch,
                    reason,
                    outcome: ExitReplayOutcome::Stopping,
                });
                Ok(())
            }
            unexpected => self.restore_unexpected_state(unexpected),
        }
    }

    #[cfg(test)]
    pub(crate) fn observe_exit(
        &mut self,
        now: u64,
        service: ServiceIdentity,
        reason: ExitReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        let binding_epoch = match &self.state {
            State::Stopping {
                event_binding_epoch,
                ..
            } => *event_binding_epoch,
            _ => self.health().binding_epoch.unwrap_or(0),
        };
        self.observe_exit_at_epoch(now, service, binding_epoch, reason)
    }

    /// Advances recovery backoff, Ready deadlines, and stop deadlines at `now`.
    ///
    /// Ready and stop deadlines are inclusive. A boundary expires only when
    /// this method observes `now` strictly greater than the retained deadline.
    pub fn poll(&mut self, now: u64) -> Result<PollProgress, SupervisorError<B::Error>> {
        self.observe_time(now)?;
        let state = self.take_state();
        match state {
            State::Backoff {
                failed,
                binding_epoch,
                cohort,
                retry_tick,
                reason,
            } => {
                if now < retry_tick {
                    self.state = State::Backoff {
                        failed,
                        binding_epoch,
                        cohort,
                        retry_tick,
                        reason,
                    };
                    return Ok(PollProgress::Idle);
                }
                self.start_replacement(now, failed, binding_epoch, cohort, reason)
            }
            State::AwaitingReady {
                replacement,
                binding_epoch,
                deadline_tick,
                reason,
                snapshot,
            } => {
                if now <= deadline_tick {
                    self.state = State::AwaitingReady {
                        replacement,
                        binding_epoch,
                        deadline_tick,
                        reason,
                        snapshot,
                    };
                    return Ok(PollProgress::Idle);
                }
                let stop_deadline = self.begin_pre_rebind_stop(
                    now,
                    replacement,
                    binding_epoch,
                    reason,
                    StopReason::ReadyTimeout,
                    snapshot,
                )?;
                self.last_ready_replay = Some(ReadyReplay::DeadlineExpired {
                    replacement,
                    binding_epoch,
                });
                Ok(PollProgress::ReplacementStopRequested {
                    replacement,
                    reason: StopReason::ReadyTimeout,
                    deadline_tick: stop_deadline,
                })
            }
            State::Stopping {
                replacement,
                event_binding_epoch,
                recovery_binding_epoch,
                deadline_tick,
                reason,
                stop_reason,
                cleanup,
            } => {
                if now <= deadline_tick {
                    self.state = State::Stopping {
                        replacement,
                        event_binding_epoch,
                        recovery_binding_epoch,
                        deadline_tick,
                        reason,
                        stop_reason,
                        cleanup,
                    };
                    return Ok(PollProgress::Idle);
                }
                self.quarantine(
                    replacement,
                    Some(recovery_binding_epoch),
                    reason,
                    TerminalFailure::StopTimeout,
                    Some(replacement),
                );
                Ok(PollProgress::Quarantined)
            }
            State::Running {
                service,
                binding_epoch,
            } => {
                self.state = State::Running {
                    service,
                    binding_epoch,
                };
                Ok(PollProgress::Idle)
            }
            State::Quarantined {
                service,
                binding_epoch,
                reason,
                terminal_failure,
                retained_task,
            } => {
                self.state = State::Quarantined {
                    service,
                    binding_epoch,
                    reason,
                    terminal_failure,
                    retained_task,
                };
                Ok(PollProgress::Quarantined)
            }
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => {
                self.quarantine(
                    service,
                    binding_epoch,
                    reason.unwrap_or(ExitReason::ProtocolViolation),
                    TerminalFailure::InternalInvariant,
                    retained_task.or(Some(service)),
                );
                Err(SupervisorError::InternalInvariant)
            }
        }
    }

    /// Validates an epoch-fenced Ready event, rebinds, and adopts the exact cohort.
    ///
    /// The method preserves the strict `Ready -> Rebind -> Adopt` order. An
    /// exact replay of the most recently completed or expired Ready event
    /// returns its cached result without backend re-entry while still obeying
    /// the monotonic time watermark. A failure after publication requests
    /// cooperative stop and waits for exact reaping before another attempt.
    pub fn replacement_ready_at_epoch(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        presented_binding_epoch: u64,
    ) -> Result<RecoveryCompletion, SupervisorError<B::Error>> {
        if let Some(replay) = self.last_ready_replay {
            match replay {
                ReadyReplay::Completed(completion) if completion.replacement == replacement => {
                    if completion.binding_epoch != presented_binding_epoch {
                        return Err(SupervisorError::StaleBindingEpoch {
                            expected: completion.binding_epoch,
                            presented: presented_binding_epoch,
                        });
                    }
                    self.observe_time(now)?;
                    return Ok(completion);
                }
                ReadyReplay::DeadlineExpired {
                    replacement: expired,
                    binding_epoch,
                } if expired == replacement => {
                    if binding_epoch != presented_binding_epoch {
                        return Err(SupervisorError::StaleBindingEpoch {
                            expected: binding_epoch,
                            presented: presented_binding_epoch,
                        });
                    }
                    self.observe_time(now)?;
                    return Err(SupervisorError::ReadyDeadlineExpired);
                }
                _ => {}
            }
        }

        let (expected, expected_binding_epoch) = match &self.state {
            State::AwaitingReady {
                replacement,
                binding_epoch,
                ..
            } => (*replacement, *binding_epoch),
            State::Stopping {
                replacement: expected,
                event_binding_epoch,
                ..
            } => {
                if replacement != *expected {
                    return Err(SupervisorError::StaleServiceEvent);
                }
                if presented_binding_epoch != *event_binding_epoch {
                    return Err(SupervisorError::StaleBindingEpoch {
                        expected: *event_binding_epoch,
                        presented: presented_binding_epoch,
                    });
                }
                self.observe_time(now)?;
                return Err(SupervisorError::ReplacementStopping);
            }
            State::Quarantined { .. } => return Err(SupervisorError::Quarantined),
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => {
                let service = *service;
                let binding_epoch = *binding_epoch;
                let reason = reason.unwrap_or(ExitReason::ProtocolViolation);
                let retained_task = retained_task.or(Some(service));
                self.quarantine(
                    service,
                    binding_epoch,
                    reason,
                    TerminalFailure::InternalInvariant,
                    retained_task,
                );
                return Err(SupervisorError::InternalInvariant);
            }
            State::Running { .. } | State::Backoff { .. } => {
                return Err(SupervisorError::StaleServiceEvent);
            }
        };
        if replacement != expected {
            return Err(SupervisorError::StaleServiceEvent);
        }
        if presented_binding_epoch != expected_binding_epoch {
            return Err(SupervisorError::StaleBindingEpoch {
                expected: expected_binding_epoch,
                presented: presented_binding_epoch,
            });
        }

        self.observe_time(now)?;
        let state = self.take_state();
        let State::AwaitingReady {
            replacement,
            binding_epoch,
            deadline_tick,
            reason,
            snapshot,
        } = state
        else {
            return self.restore_unexpected_state(state);
        };

        if now > deadline_tick {
            self.begin_pre_rebind_stop(
                now,
                replacement,
                binding_epoch,
                reason,
                StopReason::ReadyTimeout,
                snapshot,
            )?;
            self.last_ready_replay = Some(ReadyReplay::DeadlineExpired {
                replacement,
                binding_epoch,
            });
            return Err(SupervisorError::ReadyDeadlineExpired);
        }

        if let Err(source) = self.backend.ready(replacement, snapshot.value()) {
            self.begin_pre_rebind_stop(
                now,
                replacement,
                binding_epoch,
                reason,
                StopReason::RecoveryRejected,
                snapshot,
            )?;
            return Err(SupervisorError::Backend {
                stage: BackendStage::Ready,
                source,
            });
        }

        let rebound = match self.backend.rebind(replacement) {
            Ok(rebound) => rebound,
            Err(source) => {
                self.begin_pre_rebind_stop(
                    now,
                    replacement,
                    binding_epoch,
                    reason,
                    StopReason::RecoveryRejected,
                    snapshot,
                )?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::Rebind,
                    source,
                });
            }
        };
        if rebound.supervisor != replacement || rebound.binding_epoch != binding_epoch {
            self.fence_partial_recovery(replacement, binding_epoch, reason)?;
            return Err(SupervisorError::InvalidBackendObservation);
        }

        let expected_adoptions = snapshot.cohort_len();
        let mut adopted = 0u32;
        while adopted < expected_adoptions {
            let item = match self.backend.peek_recovery_item(replacement) {
                Ok(Some(item)) => item,
                Ok(None) => {
                    self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                    return Err(SupervisorError::InvalidBackendObservation);
                }
                Err(source) => {
                    self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                    return Err(SupervisorError::Backend {
                        stage: BackendStage::PeekRecoveryItem,
                        source,
                    });
                }
            };
            if let Err(source) = self.backend.adopt(replacement, item) {
                self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::Adopt,
                    source,
                });
            }
            adopted = match adopted.checked_add(1) {
                Some(adopted) => adopted,
                None => {
                    self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                    return Err(SupervisorError::CounterOverflow);
                }
            };
        }

        match self.backend.peek_recovery_item(replacement) {
            Ok(None) => {}
            Ok(Some(_)) => {
                self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                return Err(SupervisorError::InvalidBackendObservation);
            }
            Err(source) => {
                self.fence_partial_recovery(replacement, binding_epoch, reason)?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::PeekRecoveryItem,
                    source,
                });
            }
        }

        let completion = RecoveryCompletion {
            replacement,
            binding_epoch,
            adopted,
            attempt: self.recovery_attempts,
        };
        self.state = State::Running {
            service: replacement,
            binding_epoch,
        };
        self.last_ready_replay = Some(ReadyReplay::Completed(completion));
        Ok(completion)
    }

    #[cfg(test)]
    pub(crate) fn replacement_ready(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
    ) -> Result<RecoveryCompletion, SupervisorError<B::Error>> {
        let binding_epoch = match &self.state {
            State::Stopping {
                event_binding_epoch,
                ..
            } => *event_binding_epoch,
            _ => self.health().binding_epoch.unwrap_or(0),
        };
        self.replacement_ready_at_epoch(now, replacement, binding_epoch)
    }

    /// Accepts exact proof that a cooperatively stopped replacement is reaped.
    ///
    /// The event must name the manager-selected launch epoch, not a later
    /// Registry crash epoch. At the inclusive stop deadline the event still
    /// wins; after the deadline the manager quarantines. Exact replay returns
    /// the cached completion without repeating snapshot cleanup.
    pub fn replacement_reaped_at_epoch(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        presented_binding_epoch: u64,
    ) -> Result<StopCompletion, SupervisorError<B::Error>> {
        if let Some(replay) = self.last_reaped_replay
            && replay.replacement == replacement
        {
            if replay.binding_epoch != presented_binding_epoch {
                return Err(SupervisorError::StaleBindingEpoch {
                    expected: replay.binding_epoch,
                    presented: presented_binding_epoch,
                });
            }
            self.observe_time(now)?;
            return match replay.outcome {
                ReapedReplayOutcome::Completed(completion) => Ok(completion),
                ReapedReplayOutcome::DeadlineExpired => Err(SupervisorError::StopDeadlineExpired),
            };
        }

        let (expected, expected_binding_epoch) = match &self.state {
            State::Stopping {
                replacement,
                event_binding_epoch,
                ..
            } => (*replacement, *event_binding_epoch),
            State::Quarantined { .. } => return Err(SupervisorError::Quarantined),
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => {
                let service = *service;
                let binding_epoch = *binding_epoch;
                let reason = reason.unwrap_or(ExitReason::ProtocolViolation);
                let retained_task = retained_task.or(Some(service));
                self.quarantine(
                    service,
                    binding_epoch,
                    reason,
                    TerminalFailure::InternalInvariant,
                    retained_task,
                );
                return Err(SupervisorError::InternalInvariant);
            }
            State::Running { .. } | State::Backoff { .. } | State::AwaitingReady { .. } => {
                return Err(SupervisorError::StaleServiceEvent);
            }
        };
        if replacement != expected {
            return Err(SupervisorError::StaleServiceEvent);
        }
        if presented_binding_epoch != expected_binding_epoch {
            return Err(SupervisorError::StaleBindingEpoch {
                expected: expected_binding_epoch,
                presented: presented_binding_epoch,
            });
        }

        self.observe_time(now)?;
        let state = self.take_state();
        let State::Stopping {
            replacement,
            event_binding_epoch,
            recovery_binding_epoch,
            deadline_tick,
            reason,
            stop_reason,
            cleanup,
        } = state
        else {
            return self.restore_unexpected_state(state);
        };

        if now > deadline_tick {
            self.last_reaped_replay = Some(ReapedReplay {
                replacement,
                binding_epoch: event_binding_epoch,
                outcome: ReapedReplayOutcome::DeadlineExpired,
            });
            self.quarantine(
                replacement,
                Some(recovery_binding_epoch),
                reason,
                TerminalFailure::StopTimeout,
                None,
            );
            return Err(SupervisorError::StopDeadlineExpired);
        }

        let cohort = cleanup.cohort();
        if let StopCleanup::PreRebind { snapshot } = cleanup
            && let Err(source) =
                self.backend
                    .abort_recovery_attempt(replacement, &snapshot, stop_reason)
        {
            self.quarantine(
                replacement,
                Some(recovery_binding_epoch),
                reason,
                TerminalFailure::BackendFailure(BackendStage::AbortRecoveryAttempt),
                None,
            );
            return Err(SupervisorError::Backend {
                stage: BackendStage::AbortRecoveryAttempt,
                source,
            });
        }

        let disposition =
            self.schedule_backoff(now, replacement, recovery_binding_epoch, cohort, reason)?;
        let completion = match disposition {
            RetryDisposition::Scheduled { retry_tick } => StopCompletion::RetryScheduled {
                replacement,
                retry_tick,
            },
            RetryDisposition::Exhausted => StopCompletion::Quarantined { replacement },
        };
        self.last_reaped_replay = Some(ReapedReplay {
            replacement,
            binding_epoch: event_binding_epoch,
            outcome: ReapedReplayOutcome::Completed(completion),
        });
        Ok(completion)
    }

    #[cfg(test)]
    pub(crate) fn replacement_reaped(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
    ) -> Result<StopCompletion, SupervisorError<B::Error>> {
        let binding_epoch = match &self.state {
            State::Stopping {
                event_binding_epoch,
                ..
            } => *event_binding_epoch,
            _ => self.health().binding_epoch.unwrap_or(0),
        };
        self.replacement_reaped_at_epoch(now, replacement, binding_epoch)
    }

    fn start_replacement(
        &mut self,
        now: u64,
        failed: ServiceIdentity,
        binding_epoch: u64,
        cohort: CohortIdentity,
        reason: ExitReason,
    ) -> Result<PollProgress, SupervisorError<B::Error>> {
        if self.recovery_attempts >= self.policy.max_recovery_attempts {
            self.quarantine(
                failed,
                Some(binding_epoch),
                reason,
                TerminalFailure::RecoveryAttemptsExhausted,
                None,
            );
            return Ok(PollProgress::Quarantined);
        }
        self.recovery_attempts = match self.recovery_attempts.checked_add(1) {
            Some(attempt) => attempt,
            None => {
                self.quarantine(
                    failed,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::CounterOverflow,
                    None,
                );
                return Err(SupervisorError::CounterOverflow);
            }
        };
        let attempt = self.recovery_attempts;
        let replacement = match self.backend.select_replacement(failed, attempt) {
            Ok(replacement)
                if replacement != failed && replacement.generation() > failed.generation() =>
            {
                replacement
            }
            Ok(_) => {
                self.quarantine(
                    failed,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::InvalidBackendObservation,
                    None,
                );
                return Err(SupervisorError::InvalidBackendObservation);
            }
            Err(source) => {
                self.schedule_backoff(now, failed, binding_epoch, cohort, reason)?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::SelectReplacement,
                    source,
                });
            }
        };
        let deadline_tick = match now.checked_add(self.policy.replacement_timeout_ticks) {
            Some(deadline_tick) => deadline_tick,
            None => {
                self.quarantine(
                    failed,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::CounterOverflow,
                    None,
                );
                return Err(SupervisorError::CounterOverflow);
            }
        };
        let launch = ReplacementLaunch::new(replacement, binding_epoch, deadline_tick);
        if let Err(source) = self.backend.construct_replacement(launch) {
            self.schedule_backoff(now, replacement, binding_epoch, cohort, reason)?;
            return Err(SupervisorError::Backend {
                stage: BackendStage::ConstructReplacement,
                source,
            });
        }

        let snapshot = match self.backend.recovery_snapshot(replacement) {
            Ok(snapshot) => snapshot,
            Err(source) => {
                self.backend.discard_unpublished_replacement(replacement);
                self.schedule_backoff(now, replacement, binding_epoch, cohort, reason)?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::Snapshot,
                    source,
                });
            }
        };
        if snapshot.cohort() != cohort {
            self.discard_and_abort_unpublished(
                replacement,
                binding_epoch,
                reason,
                &snapshot,
                StopReason::RecoveryRejected,
            )?;
            self.quarantine(
                replacement,
                Some(binding_epoch),
                reason,
                TerminalFailure::InvalidBackendObservation,
                None,
            );
            return Err(SupervisorError::InvalidBackendObservation);
        }
        if snapshot.cohort_len() > self.policy.max_adoptions_per_recovery {
            self.discard_and_abort_unpublished(
                replacement,
                binding_epoch,
                reason,
                &snapshot,
                StopReason::RecoveryRejected,
            )?;
            self.quarantine(
                replacement,
                Some(binding_epoch),
                reason,
                TerminalFailure::RecoveryLimitExceeded,
                None,
            );
            return Err(SupervisorError::RecoveryLimitExceeded);
        }

        // This assignment is the core publication fence: all event selectors,
        // snapshot identity, and deadlines are visible before the backend can
        // make the replacement runnable and enqueue an immediate event.
        self.state = State::AwaitingReady {
            replacement,
            binding_epoch,
            deadline_tick,
            reason,
            snapshot,
        };
        if let Err(source) = self.backend.publish_replacement(replacement) {
            let state = self.take_state();
            let State::AwaitingReady {
                replacement,
                binding_epoch,
                reason,
                snapshot,
                ..
            } = state
            else {
                return self.restore_unexpected_state(state);
            };
            self.discard_and_abort_unpublished(
                replacement,
                binding_epoch,
                reason,
                &snapshot,
                StopReason::RecoveryRejected,
            )?;
            self.schedule_backoff(now, replacement, binding_epoch, snapshot.cohort(), reason)?;
            return Err(SupervisorError::Backend {
                stage: BackendStage::PublishReplacement,
                source,
            });
        }

        Ok(PollProgress::ReplacementStarted {
            replacement,
            binding_epoch,
            deadline_tick,
        })
    }

    fn begin_pre_rebind_stop(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
        stop_reason: StopReason,
        snapshot: RecoverySnapshot<B::Snapshot>,
    ) -> Result<u64, SupervisorError<B::Error>> {
        self.begin_stop(
            now,
            replacement,
            binding_epoch,
            binding_epoch,
            reason,
            stop_reason,
            StopCleanup::PreRebind { snapshot },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_stop(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        event_binding_epoch: u64,
        recovery_binding_epoch: u64,
        reason: ExitReason,
        stop_reason: StopReason,
        cleanup: StopCleanup<B::Snapshot>,
    ) -> Result<u64, SupervisorError<B::Error>> {
        let deadline_tick = match now.checked_add(self.policy.stop_timeout_ticks) {
            Some(deadline_tick) => deadline_tick,
            None => {
                self.quarantine(
                    replacement,
                    Some(recovery_binding_epoch),
                    reason,
                    TerminalFailure::CounterOverflow,
                    Some(replacement),
                );
                return Err(SupervisorError::CounterOverflow);
            }
        };
        self.state = State::Stopping {
            replacement,
            event_binding_epoch,
            recovery_binding_epoch,
            deadline_tick,
            reason,
            stop_reason,
            cleanup,
        };
        if let Err(source) = self
            .backend
            .request_stop_replacement(replacement, stop_reason)
        {
            self.quarantine(
                replacement,
                Some(recovery_binding_epoch),
                reason,
                TerminalFailure::BackendFailure(BackendStage::RequestStopReplacement),
                Some(replacement),
            );
            return Err(SupervisorError::Backend {
                stage: BackendStage::RequestStopReplacement,
                source,
            });
        }
        Ok(deadline_tick)
    }

    fn discard_and_abort_unpublished(
        &mut self,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
        snapshot: &RecoverySnapshot<B::Snapshot>,
        stop_reason: StopReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        self.backend.discard_unpublished_replacement(replacement);
        if let Err(source) = self
            .backend
            .abort_recovery_attempt(replacement, snapshot, stop_reason)
        {
            self.quarantine(
                replacement,
                Some(binding_epoch),
                reason,
                TerminalFailure::BackendFailure(BackendStage::AbortRecoveryAttempt),
                None,
            );
            return Err(SupervisorError::Backend {
                stage: BackendStage::AbortRecoveryAttempt,
                source,
            });
        }
        Ok(())
    }

    fn fence_partial_recovery(
        &mut self,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        let crash = match self.backend.crash_active(replacement) {
            Ok(crash) => crash,
            Err(source) => {
                self.quarantine(
                    replacement,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::BackendFailure(BackendStage::FenceRecovery),
                    Some(replacement),
                );
                return Err(SupervisorError::Backend {
                    stage: BackendStage::FenceRecovery,
                    source,
                });
            }
        };
        let (crashed_binding_epoch, cohort) = self.accept_crash_observation(
            replacement,
            binding_epoch,
            reason,
            crash,
            Some(replacement),
        )?;
        self.begin_stop(
            self.last_tick,
            replacement,
            binding_epoch,
            crashed_binding_epoch,
            reason,
            StopReason::PartialRecoveryFailed,
            StopCleanup::PostRebind { cohort },
        )?;
        Ok(())
    }

    fn state_context(
        state: &State<B::Snapshot>,
    ) -> (
        ServiceIdentity,
        Option<u64>,
        Option<ExitReason>,
        Option<ServiceIdentity>,
    ) {
        match state {
            State::Running {
                service,
                binding_epoch,
            } => (*service, Some(*binding_epoch), None, Some(*service)),
            State::Backoff {
                failed,
                binding_epoch,
                reason,
                ..
            } => (*failed, Some(*binding_epoch), Some(*reason), None),
            State::AwaitingReady {
                replacement,
                binding_epoch,
                reason,
                ..
            } => (
                *replacement,
                Some(*binding_epoch),
                Some(*reason),
                Some(*replacement),
            ),
            State::Stopping {
                replacement,
                recovery_binding_epoch,
                reason,
                ..
            } => (
                *replacement,
                Some(*recovery_binding_epoch),
                Some(*reason),
                Some(*replacement),
            ),
            State::Quarantined {
                service,
                binding_epoch,
                reason,
                retained_task,
                ..
            } => (*service, *binding_epoch, Some(*reason), *retained_task),
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            } => (*service, *binding_epoch, *reason, *retained_task),
        }
    }

    fn take_state(&mut self) -> State<B::Snapshot> {
        let (service, binding_epoch, reason, retained_task) = Self::state_context(&self.state);
        mem::replace(
            &mut self.state,
            State::Transitioning {
                service,
                binding_epoch,
                reason,
                retained_task,
            },
        )
    }

    fn restore_unexpected_state<T>(
        &mut self,
        state: State<B::Snapshot>,
    ) -> Result<T, SupervisorError<B::Error>> {
        let (service, binding_epoch, reason, retained_task) = Self::state_context(&state);
        self.quarantine(
            service,
            binding_epoch,
            reason.unwrap_or(ExitReason::ProtocolViolation),
            TerminalFailure::InternalInvariant,
            retained_task.or(Some(service)),
        );
        Err(SupervisorError::InternalInvariant)
    }

    fn observe_time(&mut self, now: u64) -> Result<(), SupervisorError<B::Error>> {
        if now < self.last_tick {
            return Err(SupervisorError::TimeWentBackwards);
        }
        self.last_tick = now;
        Ok(())
    }

    fn backoff_for_attempt(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(63);
        self.policy
            .initial_backoff_ticks
            .saturating_mul(1u64 << shift)
            .min(self.policy.max_backoff_ticks)
    }

    fn schedule_backoff(
        &mut self,
        now: u64,
        failed: ServiceIdentity,
        binding_epoch: u64,
        cohort: CohortIdentity,
        reason: ExitReason,
    ) -> Result<RetryDisposition, SupervisorError<B::Error>> {
        if self.recovery_attempts >= self.policy.max_recovery_attempts {
            self.quarantine(
                failed,
                Some(binding_epoch),
                reason,
                TerminalFailure::RecoveryAttemptsExhausted,
                None,
            );
            return Ok(RetryDisposition::Exhausted);
        }
        let next_attempt = match self.recovery_attempts.checked_add(1) {
            Some(next_attempt) => next_attempt,
            None => {
                self.quarantine(
                    failed,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::CounterOverflow,
                    None,
                );
                return Err(SupervisorError::CounterOverflow);
            }
        };
        let retry_tick = match now.checked_add(self.backoff_for_attempt(next_attempt)) {
            Some(retry_tick) => retry_tick,
            None => {
                self.quarantine(
                    failed,
                    Some(binding_epoch),
                    reason,
                    TerminalFailure::CounterOverflow,
                    None,
                );
                return Err(SupervisorError::CounterOverflow);
            }
        };
        self.state = State::Backoff {
            failed,
            binding_epoch,
            cohort,
            retry_tick,
            reason,
        };
        Ok(RetryDisposition::Scheduled { retry_tick })
    }

    fn accept_crash_observation(
        &mut self,
        service: ServiceIdentity,
        expected_binding_epoch: u64,
        reason: ExitReason,
        crash: CrashObservation,
        retained_task: Option<ServiceIdentity>,
    ) -> Result<(u64, CohortIdentity), SupervisorError<B::Error>> {
        if crash.previous_binding_epoch != expected_binding_epoch
            || crash.crashed_binding_epoch <= expected_binding_epoch
        {
            self.quarantine(
                service,
                None,
                reason,
                TerminalFailure::InvalidBackendObservation,
                retained_task,
            );
            return Err(SupervisorError::InvalidBackendObservation);
        }
        if crash.cohort.len() > self.policy.max_adoptions_per_recovery {
            self.quarantine(
                service,
                Some(crash.crashed_binding_epoch),
                reason,
                TerminalFailure::RecoveryLimitExceeded,
                retained_task,
            );
            return Err(SupervisorError::RecoveryLimitExceeded);
        }
        Ok((crash.crashed_binding_epoch, crash.cohort))
    }

    fn quarantine(
        &mut self,
        service: ServiceIdentity,
        binding_epoch: Option<u64>,
        reason: ExitReason,
        terminal_failure: TerminalFailure,
        retained_task: Option<ServiceIdentity>,
    ) {
        self.backend.isolate_authority(service, binding_epoch);
        self.state = State::Quarantined {
            service,
            binding_epoch,
            reason,
            terminal_failure,
            retained_task,
        };
    }
}
