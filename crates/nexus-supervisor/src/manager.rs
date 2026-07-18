// SPDX-License-Identifier: MPL-2.0

use core::mem;

use crate::{
    BackendStage, CohortIdentity, CrashObservation, ExitReason, PollProgress, RecoveryCompletion,
    RecoverySnapshot, ServiceIdentity, StopReason, SupervisorBackend, SupervisorError,
    SupervisorHealth, SupervisorPhase, SupervisorPolicy,
};

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
    Quarantined {
        service: ServiceIdentity,
        binding_epoch: Option<u64>,
        reason: ExitReason,
    },
    Transitioning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryDisposition {
    Scheduled { retry_tick: u64 },
    Exhausted,
}

/// Drives one independently restartable service domain.
pub struct SupervisorManager<B>
where
    B: SupervisorBackend,
{
    backend: B,
    policy: SupervisorPolicy,
    state: State<B::Snapshot>,
    recovery_attempts: u32,
    last_tick: u64,
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
        })
    }

    /// Returns the backend for read-only diagnostics and tests.
    pub const fn backend(&self) -> &B {
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
            },
            State::Quarantined {
                service,
                binding_epoch,
                reason,
            } => SupervisorHealth {
                phase: SupervisorPhase::Quarantined,
                service: *service,
                binding_epoch: *binding_epoch,
                recovery_attempts: self.recovery_attempts,
                deadline_tick: None,
                last_exit: Some(*reason),
            },
            State::Transitioning => unreachable!("manager state is restored before returning"),
        }
    }

    /// Observes exact task exit and schedules bounded replacement recovery.
    pub fn observe_exit(
        &mut self,
        now: u64,
        service: ServiceIdentity,
        reason: ExitReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        self.observe_time(now)?;
        let state = mem::replace(&mut self.state, State::Transitioning);
        match state {
            State::Running {
                service: active,
                binding_epoch,
            } => {
                if service != active {
                    self.state = State::Running {
                        service: active,
                        binding_epoch,
                    };
                    return Err(SupervisorError::StaleServiceEvent);
                }
                let crash = match self.backend.crash_active(active) {
                    Ok(crash) => crash,
                    Err(source) => {
                        self.state = State::Running {
                            service: active,
                            binding_epoch,
                        };
                        return Err(SupervisorError::Backend {
                            stage: BackendStage::Crash,
                            source,
                        });
                    }
                };
                let (crashed_binding_epoch, cohort) =
                    self.accept_crash_observation(active, binding_epoch, reason, crash)?;
                match self.schedule_backoff(now, active, crashed_binding_epoch, cohort, reason)? {
                    RetryDisposition::Scheduled { .. } => Ok(()),
                    RetryDisposition::Exhausted => Err(SupervisorError::Quarantined),
                }
            }
            State::AwaitingReady {
                replacement,
                binding_epoch,
                deadline_tick,
                reason: prior_reason,
                snapshot,
            } => {
                if service != replacement {
                    self.state = State::AwaitingReady {
                        replacement,
                        binding_epoch,
                        deadline_tick,
                        reason: prior_reason,
                        snapshot,
                    };
                    return Err(SupervisorError::StaleServiceEvent);
                }
                self.stop_and_abort_attempt(
                    replacement,
                    binding_epoch,
                    reason,
                    &snapshot,
                    StopReason::ExitedBeforeReady,
                )?;
                match self.schedule_backoff(
                    now,
                    replacement,
                    binding_epoch,
                    snapshot.cohort(),
                    reason,
                )? {
                    RetryDisposition::Scheduled { .. } => Ok(()),
                    RetryDisposition::Exhausted => Err(SupervisorError::Quarantined),
                }
            }
            State::Backoff {
                failed,
                binding_epoch,
                cohort,
                retry_tick,
                reason: prior_reason,
            } => {
                self.state = State::Backoff {
                    failed,
                    binding_epoch,
                    cohort,
                    retry_tick,
                    reason: prior_reason,
                };
                Err(SupervisorError::StaleServiceEvent)
            }
            State::Quarantined {
                service,
                binding_epoch,
                reason,
            } => {
                self.state = State::Quarantined {
                    service,
                    binding_epoch,
                    reason,
                };
                Err(SupervisorError::Quarantined)
            }
            State::Transitioning => unreachable!(),
        }
    }

    /// Advances recovery backoff and replacement deadlines at `now`.
    pub fn poll(&mut self, now: u64) -> Result<PollProgress, SupervisorError<B::Error>> {
        self.observe_time(now)?;
        let state = mem::replace(&mut self.state, State::Transitioning);
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
                if self.recovery_attempts >= self.policy.max_recovery_attempts {
                    self.quarantine(failed, Some(binding_epoch), reason);
                    return Ok(PollProgress::Quarantined);
                }
                self.recovery_attempts = match self.recovery_attempts.checked_add(1) {
                    Some(attempt) => attempt,
                    None => {
                        self.quarantine(failed, Some(binding_epoch), reason);
                        return Err(SupervisorError::CounterOverflow);
                    }
                };
                let attempt = self.recovery_attempts;
                let replacement = match self.backend.select_replacement(failed, attempt) {
                    Ok(replacement)
                        if replacement != failed
                            && replacement.generation() > failed.generation() =>
                    {
                        replacement
                    }
                    Ok(_) => {
                        self.quarantine(failed, Some(binding_epoch), reason);
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
                        self.quarantine(failed, Some(binding_epoch), reason);
                        return Err(SupervisorError::CounterOverflow);
                    }
                };
                if let Err(source) = self.backend.spawn_replacement(replacement) {
                    self.schedule_backoff(now, replacement, binding_epoch, cohort, reason)?;
                    return Err(SupervisorError::Backend {
                        stage: BackendStage::Spawn,
                        source,
                    });
                }
                let snapshot = match self.backend.recovery_snapshot(replacement) {
                    Ok(snapshot) => snapshot,
                    Err(source) => {
                        self.stop_without_snapshot_and_reschedule(
                            now,
                            replacement,
                            binding_epoch,
                            cohort,
                            reason,
                        )?;
                        return Err(SupervisorError::Backend {
                            stage: BackendStage::Snapshot,
                            source,
                        });
                    }
                };
                if snapshot.cohort() != cohort {
                    self.stop_and_abort_attempt(
                        replacement,
                        binding_epoch,
                        reason,
                        &snapshot,
                        StopReason::RecoveryRejected,
                    )?;
                    self.quarantine(replacement, Some(binding_epoch), reason);
                    return Err(SupervisorError::InvalidBackendObservation);
                }
                if snapshot.cohort_len() > self.policy.max_adoptions_per_recovery {
                    self.stop_and_abort_attempt(
                        replacement,
                        binding_epoch,
                        reason,
                        &snapshot,
                        StopReason::RecoveryRejected,
                    )?;
                    self.quarantine(replacement, Some(binding_epoch), reason);
                    return Err(SupervisorError::RecoveryLimitExceeded);
                }
                self.state = State::AwaitingReady {
                    replacement,
                    binding_epoch,
                    deadline_tick,
                    reason,
                    snapshot,
                };
                Ok(PollProgress::ReplacementStarted {
                    replacement,
                    deadline_tick,
                })
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
                match self.stop_abort_and_reschedule(
                    now,
                    replacement,
                    binding_epoch,
                    reason,
                    &snapshot,
                    StopReason::ReadyTimeout,
                )? {
                    RetryDisposition::Scheduled { retry_tick } => {
                        Ok(PollProgress::ReplacementTimedOut {
                            replacement,
                            retry_tick,
                        })
                    }
                    RetryDisposition::Exhausted => Ok(PollProgress::Quarantined),
                }
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
            } => {
                self.state = State::Quarantined {
                    service,
                    binding_epoch,
                    reason,
                };
                Ok(PollProgress::Quarantined)
            }
            State::Transitioning => unreachable!(),
        }
    }

    /// Validates Ready, rebinds, and explicitly adopts the complete cohort.
    pub fn replacement_ready(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
    ) -> Result<RecoveryCompletion, SupervisorError<B::Error>> {
        self.observe_time(now)?;
        let state = mem::replace(&mut self.state, State::Transitioning);
        let State::AwaitingReady {
            replacement: expected,
            binding_epoch,
            deadline_tick,
            reason,
            snapshot,
        } = state
        else {
            self.state = state;
            return Err(match self.state {
                State::Quarantined { .. } => SupervisorError::Quarantined,
                _ => SupervisorError::StaleServiceEvent,
            });
        };
        if replacement != expected {
            self.state = State::AwaitingReady {
                replacement: expected,
                binding_epoch,
                deadline_tick,
                reason,
                snapshot,
            };
            return Err(SupervisorError::StaleServiceEvent);
        }
        if now > deadline_tick {
            self.stop_abort_and_reschedule(
                now,
                replacement,
                binding_epoch,
                reason,
                &snapshot,
                StopReason::ReadyTimeout,
            )?;
            return Err(SupervisorError::ReadyDeadlineExpired);
        }

        if let Err(source) = self.backend.ready(replacement, snapshot.value()) {
            self.stop_abort_and_reschedule(
                now,
                replacement,
                binding_epoch,
                reason,
                &snapshot,
                StopReason::RecoveryRejected,
            )?;
            return Err(SupervisorError::Backend {
                stage: BackendStage::Ready,
                source,
            });
        }
        let rebound = match self.backend.rebind(replacement) {
            Ok(rebound) => rebound,
            Err(source) => {
                self.stop_abort_and_reschedule(
                    now,
                    replacement,
                    binding_epoch,
                    reason,
                    &snapshot,
                    StopReason::RecoveryRejected,
                )?;
                return Err(SupervisorError::Backend {
                    stage: BackendStage::Rebind,
                    source,
                });
            }
        };
        if rebound.supervisor != replacement || rebound.binding_epoch != binding_epoch {
            return self.fence_invalid_recovery(replacement, binding_epoch, reason);
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

        self.state = State::Running {
            service: replacement,
            binding_epoch,
        };
        Ok(RecoveryCompletion {
            replacement,
            binding_epoch,
            adopted,
            attempt: self.recovery_attempts,
        })
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
            self.quarantine(failed, Some(binding_epoch), reason);
            return Ok(RetryDisposition::Exhausted);
        }
        let next_attempt = match self.recovery_attempts.checked_add(1) {
            Some(next_attempt) => next_attempt,
            None => {
                self.quarantine(failed, Some(binding_epoch), reason);
                return Err(SupervisorError::CounterOverflow);
            }
        };
        let retry_tick = match now.checked_add(self.backoff_for_attempt(next_attempt)) {
            Some(retry_tick) => retry_tick,
            None => {
                self.quarantine(failed, Some(binding_epoch), reason);
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

    fn stop_without_snapshot_and_reschedule(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        cohort: CohortIdentity,
        reason: ExitReason,
    ) -> Result<RetryDisposition, SupervisorError<B::Error>> {
        if let Err(source) = self
            .backend
            .stop_replacement(replacement, StopReason::RecoveryRejected)
        {
            self.quarantine(replacement, Some(binding_epoch), reason);
            return Err(SupervisorError::Backend {
                stage: BackendStage::StopReplacement,
                source,
            });
        }
        self.schedule_backoff(now, replacement, binding_epoch, cohort, reason)
    }

    fn stop_and_abort_attempt(
        &mut self,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
        snapshot: &RecoverySnapshot<B::Snapshot>,
        stop_reason: StopReason,
    ) -> Result<(), SupervisorError<B::Error>> {
        if let Err(source) = self.backend.stop_replacement(replacement, stop_reason) {
            self.quarantine(replacement, Some(binding_epoch), reason);
            return Err(SupervisorError::Backend {
                stage: BackendStage::StopReplacement,
                source,
            });
        }
        if let Err(source) = self
            .backend
            .abort_recovery_attempt(replacement, snapshot, stop_reason)
        {
            self.quarantine(replacement, Some(binding_epoch), reason);
            return Err(SupervisorError::Backend {
                stage: BackendStage::AbortRecoveryAttempt,
                source,
            });
        }
        Ok(())
    }

    fn stop_abort_and_reschedule(
        &mut self,
        now: u64,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
        snapshot: &RecoverySnapshot<B::Snapshot>,
        stop_reason: StopReason,
    ) -> Result<RetryDisposition, SupervisorError<B::Error>> {
        self.stop_and_abort_attempt(replacement, binding_epoch, reason, snapshot, stop_reason)?;
        self.schedule_backoff(now, replacement, binding_epoch, snapshot.cohort(), reason)
    }

    fn fence_partial_recovery(
        &mut self,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    ) -> Result<RetryDisposition, SupervisorError<B::Error>> {
        let crash = match self.backend.crash_active(replacement) {
            Ok(crash) => crash,
            Err(source) => {
                self.quarantine(replacement, Some(binding_epoch), reason);
                return Err(SupervisorError::Backend {
                    stage: BackendStage::FenceRecovery,
                    source,
                });
            }
        };
        let (crashed_binding_epoch, cohort) =
            self.accept_crash_observation(replacement, binding_epoch, reason, crash)?;
        self.schedule_backoff(
            self.last_tick,
            replacement,
            crashed_binding_epoch,
            cohort,
            reason,
        )
    }

    fn fence_invalid_recovery<T>(
        &mut self,
        replacement: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    ) -> Result<T, SupervisorError<B::Error>> {
        self.fence_partial_recovery(replacement, binding_epoch, reason)?;
        Err(SupervisorError::InvalidBackendObservation)
    }

    fn accept_crash_observation(
        &mut self,
        service: ServiceIdentity,
        expected_binding_epoch: u64,
        reason: ExitReason,
        crash: CrashObservation,
    ) -> Result<(u64, CohortIdentity), SupervisorError<B::Error>> {
        if crash.previous_binding_epoch != expected_binding_epoch
            || crash.crashed_binding_epoch <= expected_binding_epoch
        {
            self.quarantine(service, None, reason);
            return Err(SupervisorError::InvalidBackendObservation);
        }
        if crash.cohort.len() > self.policy.max_adoptions_per_recovery {
            self.quarantine(service, Some(crash.crashed_binding_epoch), reason);
            return Err(SupervisorError::RecoveryLimitExceeded);
        }
        Ok((crash.crashed_binding_epoch, crash.cohort))
    }

    fn quarantine(
        &mut self,
        service: ServiceIdentity,
        binding_epoch: Option<u64>,
        reason: ExitReason,
    ) {
        self.state = State::Quarantined {
            service,
            binding_epoch,
            reason,
        };
    }
}
