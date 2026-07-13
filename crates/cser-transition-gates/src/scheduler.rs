// SPDX-License-Identifier: MPL-2.0

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerBinding {
    pub authority_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerMode {
    Bound,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    InvalidConfiguration,
    StaleBinding,
    NoSupervisor,
    UnknownTask,
    AlreadyFallback,
    FallbackNotRunning,
    FallbackPickRequired,
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedProposal {
    pub previous_deadline_tick: u64,
    pub lease_deadline_tick: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerCrashReceipt {
    pub previous_binding_epoch: u64,
    pub binding_epoch: u64,
    pub crash_tick: u64,
    pub pending_cleared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackPick {
    pub tick: u64,
    pub task_id: u64,
    pub selection_attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackEvidence {
    pub lease_deadline_tick: u64,
    pub crash_tick: u64,
    pub pick_tick: u64,
    pub pick_task_id: u64,
    pub pick_selection_attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerProjection<P: Copy + Eq> {
    pub binding: SchedulerBinding,
    pub mode: SchedulerMode,
    pub pending: Option<P>,
    pub tick: u64,
    pub lease_ticks: u64,
    pub lease_deadline_tick: u64,
    pub crash_tick: Option<u64>,
    pub fallback_selection_attempts: u64,
    pub first_fallback_pick: Option<FallbackPick>,
}

/// Scheduler recovery and lease gate. Runnable task payloads remain outside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerGate<P: Copy + Eq> {
    binding: SchedulerBinding,
    mode: SchedulerMode,
    pending: Option<P>,
    tick: u64,
    lease_ticks: u64,
    lease_deadline_tick: u64,
    crash_tick: Option<u64>,
    fallback_selection_attempts: u64,
    first_fallback_pick: Option<FallbackPick>,
}

impl<P: Copy + Eq> SchedulerGate<P> {
    pub fn new(authority_epoch: u64, lease_ticks: u64) -> Result<Self, SchedulerError> {
        if authority_epoch == 0 || lease_ticks == 0 {
            return Err(SchedulerError::InvalidConfiguration);
        }
        Ok(Self {
            binding: SchedulerBinding {
                authority_epoch,
                binding_epoch: 1,
            },
            mode: SchedulerMode::Bound,
            pending: None,
            tick: 0,
            lease_ticks,
            lease_deadline_tick: lease_ticks,
            crash_tick: None,
            fallback_selection_attempts: 0,
            first_fallback_pick: None,
        })
    }

    pub const fn projection(&self) -> SchedulerProjection<P> {
        SchedulerProjection {
            binding: self.binding,
            mode: self.mode,
            pending: self.pending,
            tick: self.tick,
            lease_ticks: self.lease_ticks,
            lease_deadline_tick: self.lease_deadline_tick,
            crash_tick: self.crash_tick,
            fallback_selection_attempts: self.fallback_selection_attempts,
            first_fallback_pick: self.first_fallback_pick,
        }
    }

    pub const fn binding(&self) -> SchedulerBinding {
        self.binding
    }

    pub const fn mode(&self) -> SchedulerMode {
        self.mode
    }

    pub const fn pending(&self) -> Option<P> {
        self.pending
    }

    pub fn prepare(
        &mut self,
        presented: SchedulerBinding,
        known_task: bool,
        proposal: P,
    ) -> Result<PreparedProposal, SchedulerError> {
        if presented != self.binding {
            return Err(SchedulerError::StaleBinding);
        }
        if self.mode != SchedulerMode::Bound {
            return Err(SchedulerError::NoSupervisor);
        }
        if !known_task {
            return Err(SchedulerError::UnknownTask);
        }
        let lease_deadline_tick = self
            .tick
            .checked_add(self.lease_ticks)
            .ok_or(SchedulerError::CounterOverflow)?;
        let receipt = PreparedProposal {
            previous_deadline_tick: self.lease_deadline_tick,
            lease_deadline_tick,
        };
        self.pending = Some(proposal);
        self.lease_deadline_tick = lease_deadline_tick;
        Ok(receipt)
    }

    pub fn take_bound_proposal(&mut self) -> Result<Option<P>, SchedulerError> {
        if self.mode != SchedulerMode::Bound {
            return Err(SchedulerError::NoSupervisor);
        }
        Ok(self.pending.take())
    }

    pub fn tick(&mut self) -> Result<Option<SchedulerCrashReceipt>, SchedulerError> {
        let tick = self
            .tick
            .checked_add(1)
            .ok_or(SchedulerError::CounterOverflow)?;
        if self.mode == SchedulerMode::Bound && tick >= self.lease_deadline_tick {
            let next_binding = self
                .binding
                .binding_epoch
                .checked_add(1)
                .ok_or(SchedulerError::CounterOverflow)?;
            self.tick = tick;
            return Ok(Some(self.commit_fallback(next_binding)));
        }
        self.tick = tick;
        Ok(None)
    }

    pub fn enter_fallback(
        &mut self,
        presented: SchedulerBinding,
    ) -> Result<SchedulerCrashReceipt, SchedulerError> {
        if presented != self.binding {
            return Err(SchedulerError::StaleBinding);
        }
        if self.mode == SchedulerMode::Fallback {
            return Err(SchedulerError::AlreadyFallback);
        }
        let next_binding = self
            .binding
            .binding_epoch
            .checked_add(1)
            .ok_or(SchedulerError::CounterOverflow)?;
        Ok(self.commit_fallback(next_binding))
    }

    pub fn note_fallback_pick(&mut self, task_id: u64) -> Result<FallbackPick, SchedulerError> {
        if self.mode != SchedulerMode::Fallback {
            return Err(SchedulerError::FallbackNotRunning);
        }
        if task_id == 0 {
            return Err(SchedulerError::UnknownTask);
        }
        let selection_attempt = self
            .fallback_selection_attempts
            .checked_add(1)
            .ok_or(SchedulerError::CounterOverflow)?;
        let pick = FallbackPick {
            tick: self.tick,
            task_id,
            selection_attempt,
        };
        self.fallback_selection_attempts = selection_attempt;
        if self.first_fallback_pick.is_none() {
            self.first_fallback_pick = Some(pick);
        }
        Ok(pick)
    }

    pub fn rebind(&mut self, authority_epoch: u64) -> Result<SchedulerBinding, SchedulerError> {
        if authority_epoch != self.binding.authority_epoch {
            return Err(SchedulerError::StaleBinding);
        }
        if self.mode != SchedulerMode::Fallback {
            return Err(SchedulerError::FallbackNotRunning);
        }
        if self.first_fallback_pick.is_none() {
            return Err(SchedulerError::FallbackPickRequired);
        }
        let lease_deadline_tick = self
            .tick
            .checked_add(self.lease_ticks)
            .ok_or(SchedulerError::CounterOverflow)?;
        self.mode = SchedulerMode::Bound;
        self.pending = None;
        self.lease_deadline_tick = lease_deadline_tick;
        Ok(self.binding)
    }

    pub const fn fallback_evidence(&self) -> Option<FallbackEvidence> {
        let pick = match self.first_fallback_pick {
            Some(pick) => pick,
            None => return None,
        };
        let crash_tick = match self.crash_tick {
            Some(tick) => tick,
            None => return None,
        };
        Some(FallbackEvidence {
            lease_deadline_tick: self.lease_deadline_tick,
            crash_tick,
            pick_tick: pick.tick,
            pick_task_id: pick.task_id,
            pick_selection_attempt: pick.selection_attempt,
        })
    }

    fn commit_fallback(&mut self, next_binding: u64) -> SchedulerCrashReceipt {
        let receipt = SchedulerCrashReceipt {
            previous_binding_epoch: self.binding.binding_epoch,
            binding_epoch: next_binding,
            crash_tick: self.tick,
            pending_cleared: self.pending.is_some(),
        };
        self.binding.binding_epoch = next_binding;
        self.mode = SchedulerMode::Fallback;
        self.pending = None;
        self.crash_tick = Some(self.tick);
        self.fallback_selection_attempts = 0;
        self.first_fallback_pick = None;
        receipt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_pick_precedes_rebind_and_repeated_crash_does_not_advance() {
        let mut gate = SchedulerGate::<u64>::new(3, 4).unwrap();
        let binding = gate.binding();
        gate.prepare(binding, true, 9).unwrap();
        let crash = gate.enter_fallback(binding).unwrap();
        assert!(crash.pending_cleared);
        let before = gate;
        assert_eq!(
            gate.enter_fallback(gate.binding()),
            Err(SchedulerError::AlreadyFallback)
        );
        assert_eq!(gate, before);
        assert_eq!(gate.rebind(3), Err(SchedulerError::FallbackPickRequired));
        gate.note_fallback_pick(11).unwrap();
        assert_eq!(gate.rebind(3).unwrap().binding_epoch, 2);
    }
}
