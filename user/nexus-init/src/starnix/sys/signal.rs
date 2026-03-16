use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn sys_rt_sigprocmask(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let how = stop_state.regs.rdi;
        let set_addr = stop_state.regs.rsi;
        let oldset_addr = stop_state.regs.rdx;
        let sigset_size = stop_state.regs.r10;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let old_mask = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        if oldset_addr != 0 {
            match write_guest_signal_mask(session, oldset_addr, old_mask) {
                Ok(()) => {}
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
        if set_addr != 0 {
            let requested = match read_guest_signal_mask(session, set_addr) {
                Ok(mask) => mask,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };
            let requested = normalize_signal_mask(requested);
            let tgid = {
                let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
                task.signals.blocked = match how {
                    LINUX_SIG_BLOCK => task.signals.blocked | requested,
                    LINUX_SIG_UNBLOCK => task.signals.blocked & !requested,
                    LINUX_SIG_SETMASK => requested,
                    _ => {
                        complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                task.tgid
            };
            self.refresh_signalfds_for_group(tgid)?;
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_rt_sigaction(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let signal = stop_state.regs.rdi as u32 as i32;
        let act_addr = stop_state.regs.rsi;
        let oldact_addr = stop_state.regs.rdx;
        let sigset_size = stop_state.regs.r10;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64
            || !linux_signal_is_valid(signal)
            || signal == LINUX_SIGKILL
            || signal == LINUX_SIGSTOP
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let old_action = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        if oldact_addr != 0 {
            match write_guest_sigaction(session, oldact_addr, old_action) {
                Ok(()) => {}
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
        if act_addr != 0 {
            let action = match read_guest_sigaction(session, act_addr) {
                Ok(action) => action,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };
            let supported_flags = LINUX_SA_RESTORER | LINUX_SA_RESTART;
            if (action.flags & !supported_flags) != 0 {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                return Ok(SyscallAction::Resume);
            }
            if action.handler != LINUX_SIG_DFL
                && action.handler != LINUX_SIG_IGN
                && ((action.flags & LINUX_SA_RESTORER) == 0 || action.restorer == 0)
            {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if action.handler == LINUX_SIG_DFL
                && action.flags == 0
                && action.restorer == 0
                && action.mask == 0
            {
                group.sigactions.remove(&signal);
            } else {
                group.sigactions.insert(signal, action);
            }
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_rt_sigreturn(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = {
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let Some(frame) = task.active_signal.take() else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            task.signals.blocked = frame.previous_blocked;
            stop_state.regs = frame.restore_regs;
            task.tgid
        };
        self.refresh_signalfds_for_group(tgid)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_kill(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let pid = stop_state.regs.rdi as u32 as i32;
        let signal = stop_state.regs.rsi as u32 as i32;
        let result = if !linux_signal_is_valid_or_zero(signal) || pid == -1 {
            linux_errno(LINUX_EINVAL)
        } else if pid == 0 {
            self.queue_signal_to_process_group(self.task_pgid(task_id)?, signal, stdout)?
        } else if pid < -1 {
            self.queue_signal_to_process_group(pid.saturating_abs(), signal, stdout)?
        } else {
            self.queue_signal_to_group(pid, signal, stdout)?
        };
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_tgkill(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = stop_state.regs.rdi as u32 as i32;
        let tid = stop_state.regs.rsi as u32 as i32;
        let signal = stop_state.regs.rdx as u32 as i32;
        let result = if tgid <= 0 || tid <= 0 || !linux_signal_is_valid_or_zero(signal) {
            linux_errno(LINUX_EINVAL)
        } else {
            self.queue_signal_to_task(tgid, tid, signal, stdout)?
        };
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }
}
