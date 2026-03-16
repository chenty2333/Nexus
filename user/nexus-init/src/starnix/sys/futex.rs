use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn sys_futex(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let uaddr = stop_state.regs.rdi;
        let futex_op = stop_state.regs.rsi;
        let val = stop_state.regs.rdx;
        let timeout_or_val2 = stop_state.regs.r10;
        let uaddr2 = stop_state.regs.r8;
        let val3 = stop_state.regs.r9;

        if (futex_op
            & !(LINUX_FUTEX_CMD_MASK | LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME))
            != 0
            || (futex_op & LINUX_FUTEX_CLOCK_REALTIME) != 0
            || (futex_op & LINUX_FUTEX_PRIVATE_FLAG) == 0
        {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let command = futex_op & LINUX_FUTEX_CMD_MASK;
        let key = self.private_futex_key(task_id, uaddr)?;
        match command {
            LINUX_FUTEX_WAIT | LINUX_FUTEX_WAIT_BITSET => {
                let bitset = if command == LINUX_FUTEX_WAIT {
                    LINUX_FUTEX_BITSET_MATCH_ANY
                } else {
                    let bitset = val3 as u32;
                    if bitset == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                        return Ok(SyscallAction::Resume);
                    }
                    bitset
                };
                if timeout_or_val2 != 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                    return Ok(SyscallAction::Resume);
                }
                let session = self
                    .tasks
                    .get(&task_id)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .carrier
                    .session_handle;
                let observed = match read_guest_u32(session, uaddr) {
                    Ok(word) => word,
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                let expected = val as u32;
                if observed != expected {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                self.enqueue_futex_waiter(key, LinuxFutexWaiter { task_id, bitset });
                let wait = WaitState {
                    restartable: false,
                    kind: WaitKind::Futex { key },
                };
                self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                    TaskState::Waiting(wait);
                self.deliver_or_interrupt_wait(task_id, wait, stop_state)
            }
            LINUX_FUTEX_WAKE | LINUX_FUTEX_WAKE_BITSET => {
                let wake_mask = if command == LINUX_FUTEX_WAKE {
                    LINUX_FUTEX_BITSET_MATCH_ANY
                } else {
                    let bitset = val3 as u32;
                    if bitset == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                        return Ok(SyscallAction::Resume);
                    }
                    bitset
                };
                let Ok(wake_count) = usize::try_from(val) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let woken = self.wake_futex_waiters(key, wake_count, wake_mask)?;
                complete_syscall(stop_state, woken)?;
                Ok(SyscallAction::Resume)
            }
            LINUX_FUTEX_REQUEUE => {
                if uaddr2 == 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                }
                let Ok(wake_count) = usize::try_from(val) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let Ok(requeue_count) = usize::try_from(timeout_or_val2) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let target = self.private_futex_key(task_id, uaddr2)?;
                if target == key {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                }
                let woken = self.requeue_futex_waiters(key, target, wake_count, requeue_count)?;
                complete_syscall(stop_state, woken)?;
                Ok(SyscallAction::Resume)
            }
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    pub(in crate::starnix) fn sys_set_robust_list(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let head_addr = stop_state.regs.rdi;
        let len = stop_state.regs.rsi;
        if head_addr == 0 || len != LINUX_ROBUST_LIST_HEAD_BYTES {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        task.robust_list = Some(LinuxRobustListState { head_addr, len });
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_get_robust_list(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_tid = stop_state.regs.rdi as u32 as i32;
        let head_addr_ptr = stop_state.regs.rsi;
        let len_ptr = stop_state.regs.rdx;
        if head_addr_ptr == 0 || len_ptr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }

        let resolved_tid = if target_tid == 0 { task_id } else { target_tid };
        let Some(target) = self.tasks.get(&resolved_tid) else {
            complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
            return Ok(SyscallAction::Resume);
        };
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let robust = target.robust_list.unwrap_or(LinuxRobustListState {
            head_addr: 0,
            len: LINUX_ROBUST_LIST_HEAD_BYTES,
        });
        if let Err(status) = write_guest_u64(session, head_addr_ptr, robust.head_addr) {
            complete_syscall(
                stop_state,
                linux_errno(map_guest_write_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }
        if let Err(status) = write_guest_u64(session, len_ptr, robust.len) {
            complete_syscall(
                stop_state,
                linux_errno(map_guest_write_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }
}
