use super::super::*;

pub(in crate::starnix) fn complete_syscall(
    stop_state: &mut ax_guest_stop_state_t,
    result: u64,
) -> Result<(), zx_status_t> {
    stop_state.regs.rax = result;
    stop_state.regs.rip = stop_state
        .regs
        .rip
        .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
        .ok_or(ZX_ERR_INVALID_ARGS)?;
    Ok(())
}

impl StarnixKernel {
    fn queue_wait_signal_wake(&self, task_id: i32) -> Result<(), zx_status_t> {
        let packet = zx_port_packet_t {
            key: STARNIX_SIGNAL_WAKE_PACKET_KEY,
            type_: ZX_PKT_TYPE_USER,
            status: 0,
            user: zx_packet_user_t {
                u64: [STARNIX_WAIT_WAKE_KIND_SIGNAL, task_id as u64, 0, 0],
            },
        };
        zx_status_result(zx_port_queue(self.port, &packet))
    }

    pub(in crate::starnix) fn deliver_or_interrupt_wait(
        &mut self,
        task_id: i32,
        wait: WaitState,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        loop {
            let Some(signal) = self.take_deliverable_signal(task_id)? else {
                return Ok(SyscallAction::LeaveStopped);
            };
            match self.signal_delivery_action(task_id, signal)? {
                SignalDeliveryAction::Ignore => {}
                SignalDeliveryAction::Terminate => {
                    self.cancel_task_wait(task_id, wait);
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.state = TaskState::Running;
                    }
                    return Ok(SyscallAction::GroupSignalExit(signal));
                }
                SignalDeliveryAction::Stop => {
                    let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                    self.enter_group_stop(tgid, signal)?;
                    return Ok(SyscallAction::LeaveStopped);
                }
                SignalDeliveryAction::Catch(sigaction) => {
                    self.cancel_task_wait(task_id, wait);
                    let previous_blocked = self.task_signal_mask(task_id)?;
                    let mut restore_regs = stop_state.regs;
                    if !wait.restartable || (sigaction.flags & LINUX_SA_RESTART) == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINTR))?;
                        restore_regs = stop_state.regs;
                    }
                    self.install_signal_frame(
                        task_id,
                        signal,
                        sigaction,
                        stop_state,
                        ActiveSignalFrame {
                            restore_regs,
                            previous_blocked,
                        },
                    )?;
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.state = TaskState::Running;
                    }
                    return Ok(SyscallAction::Resume);
                }
            }
        }
    }

    fn interrupt_waiting_task(&mut self, task_id: i32) -> Result<(), zx_status_t> {
        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(());
        };
        let TaskState::Waiting(wait) = &task.state else {
            return Ok(());
        };
        let wait = *wait;

        let sidecar = task.carrier.sidecar_vmo;
        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        match self.deliver_or_interrupt_wait(task_id, wait, &mut stop_state)? {
            SyscallAction::Resume => self.writeback_and_resume(task_id, &stop_state),
            SyscallAction::LeaveStopped => Ok(()),
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }

    pub(in crate::starnix) fn service_pending_waiters(&mut self) -> Result<(), zx_status_t> {
        let waiting = self
            .tasks
            .iter()
            .filter_map(|(task_id, task)| match task.state {
                TaskState::Waiting(wait) => Some((*task_id, wait)),
                TaskState::Running => None,
            })
            .collect::<Vec<_>>();
        for (task_id, wait) in waiting {
            if !self.tasks.contains_key(&task_id) {
                continue;
            }
            if wait.packet_key().is_some() {
                self.queue_wait_signal_wake(task_id)?;
            } else {
                self.interrupt_waiting_task(task_id)?;
            }
        }
        Ok(())
    }

    pub(in crate::starnix) fn complete_task_action(
        &mut self,
        task_id: i32,
        action: SyscallAction,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<(), zx_status_t> {
        let action = self.apply_signal_delivery(task_id, action, stop_state)?;
        match action {
            SyscallAction::Resume => self.writeback_and_resume(task_id, stop_state),
            SyscallAction::LeaveStopped => Ok(()),
            SyscallAction::TaskExit(code) => self.exit_task(task_id, code),
            SyscallAction::GroupExit(code) => self.exit_group(task_id, code),
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
        }
    }

    pub(in crate::starnix) fn writeback_and_resume(
        &self,
        task_id: i32,
        stop_state: &ax_guest_stop_state_t,
    ) -> Result<(), zx_status_t> {
        let task = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let write_status = ax_guest_stop_state_write(task.carrier.sidecar_vmo, stop_state);
        zx_status_result(write_status)?;
        let resume_status =
            ax_guest_session_resume(task.carrier.session_handle, stop_state.stop_seq, 0);
        zx_status_result(resume_status)
    }

    pub(in crate::starnix) fn retry_waiting_task(
        &mut self,
        task_id: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<(), zx_status_t> {
        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(());
        };
        let tgid = task.tgid;
        if self
            .groups
            .get(&tgid)
            .is_some_and(|group| matches!(group.state, ThreadGroupState::Stopped))
        {
            return Ok(());
        }
        let TaskState::Waiting(wait) = task.state else {
            return Ok(());
        };

        let mut stop_state = ax_guest_stop_state_read(task.carrier.sidecar_vmo)?;
        match self.deliver_or_interrupt_wait(task_id, wait, &mut stop_state)? {
            SyscallAction::Resume => self.writeback_and_resume(task_id, &stop_state),
            SyscallAction::LeaveStopped => match wait.kind {
                WaitKind::Wait4 { .. } => Ok(()),
                WaitKind::Futex { .. } => Ok(()),
                WaitKind::Epoll { .. } => Ok(()),
                WaitKind::FdRead { fd, buf, len, .. } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = buf;
                    stop_state.regs.rdx = len as u64;
                    let action = self.sys_read(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::FdWrite { fd, buf, len, .. } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = buf;
                    stop_state.regs.rdx = len as u64;
                    let action = self.sys_write(task_id, &mut stop_state, stdout)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::MsgRecv {
                    fd,
                    msg_addr,
                    flags,
                    ..
                } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = msg_addr;
                    stop_state.regs.rdx = flags;
                    let action = self.sys_recvmsg(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::MsgSend {
                    fd,
                    msg_addr,
                    flags,
                    ..
                } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = msg_addr;
                    stop_state.regs.rdx = flags;
                    let action = self.sys_sendmsg(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
            },
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }
}
