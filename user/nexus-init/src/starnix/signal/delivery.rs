use super::super::*;

pub(in crate::starnix) enum SignalDeliveryAction {
    Ignore,
    Terminate,
    Stop,
    Catch(LinuxSigAction),
}

impl StarnixKernel {
    pub(in crate::starnix) fn apply_signal_delivery(
        &mut self,
        task_id: i32,
        action: SyscallAction,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        if !matches!(action, SyscallAction::Resume) {
            return Ok(action);
        }
        loop {
            let Some(signal) = self.take_deliverable_signal(task_id)? else {
                return Ok(action);
            };
            match self.signal_delivery_action(task_id, signal)? {
                SignalDeliveryAction::Ignore => {}
                SignalDeliveryAction::Terminate => {
                    return Ok(SyscallAction::GroupSignalExit(signal));
                }
                SignalDeliveryAction::Stop => {
                    let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                    self.enter_group_stop(tgid, signal)?;
                    return Ok(SyscallAction::LeaveStopped);
                }
                SignalDeliveryAction::Catch(sigaction) => {
                    let restore_regs = stop_state.regs;
                    self.install_signal_frame(
                        task_id,
                        signal,
                        sigaction,
                        stop_state,
                        ActiveSignalFrame {
                            restore_regs,
                            previous_blocked: self.task_signal_mask(task_id)?,
                        },
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
    }

    pub(in crate::starnix) fn task_signal_mask(&self, task_id: i32) -> Result<u64, zx_status_t> {
        self.tasks
            .get(&task_id)
            .map(|task| task.signals.blocked)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(in crate::starnix) fn install_signal_frame(
        &mut self,
        task_id: i32,
        signal: i32,
        action: LinuxSigAction,
        stop_state: &mut ax_guest_stop_state_t,
        frame: ActiveSignalFrame,
    ) -> Result<(), zx_status_t> {
        let signal_bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let stack_pointer = stop_state
            .regs
            .rsp
            .checked_sub(8)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        write_guest_bytes(session, stack_pointer, &action.restorer.to_ne_bytes())?;

        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        if task.active_signal.is_some() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let mut blocked = frame.previous_blocked | action.mask;
        if (action.flags & LINUX_SA_RESTORER) == 0 || action.restorer == 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        blocked |= signal_bit;
        task.signals.blocked = normalize_signal_mask(blocked);
        task.active_signal = Some(frame);

        stop_state.regs.rsp = stack_pointer;
        stop_state.regs.rip = action.handler;
        stop_state.regs.rdi = signal as u64;
        stop_state.regs.rsi = 0;
        stop_state.regs.rdx = 0;
        Ok(())
    }

    pub(in crate::starnix) fn take_deliverable_signal(
        &mut self,
        task_id: i32,
    ) -> Result<Option<i32>, zx_status_t> {
        let blocked = self.task_signal_mask(task_id)?;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let task_pending = self
            .tasks
            .get(&task_id)
            .map(|task| task.signals.pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(task_pending) {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.signals.pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(signal));
        }

        let shared_pending = self
            .groups
            .get(&tgid)
            .map(|group| group.shared_pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(shared_pending) {
            if let Some(group) = self.groups.get_mut(&tgid) {
                group.shared_pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.clear_shared_signal_state(tgid, signal)?;
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(signal));
        }

        Ok(None)
    }

    pub(in crate::starnix) fn signal_delivery_action(
        &self,
        task_id: i32,
        signal: i32,
    ) -> Result<SignalDeliveryAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let action = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        match action.handler {
            LINUX_SIG_IGN => Ok(SignalDeliveryAction::Ignore),
            LINUX_SIG_DFL => {
                if signal_default_ignored(signal) || signal == LINUX_SIGCONT {
                    Ok(SignalDeliveryAction::Ignore)
                } else if signal_default_stop(signal) {
                    Ok(SignalDeliveryAction::Stop)
                } else {
                    Ok(SignalDeliveryAction::Terminate)
                }
            }
            _ => Ok(SignalDeliveryAction::Catch(action)),
        }
    }
}
