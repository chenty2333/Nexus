use super::super::*;

#[derive(Clone, Copy)]
pub(in crate::starnix) enum WaitChildEvent {
    Zombie { status: i32 },
    Stopped { status: i32 },
    Continued,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::starnix) enum LinuxFutexKey {
    Private { tgid: i32, addr: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::starnix) struct LinuxFileDescriptionKey(pub(in crate::starnix) usize);

#[derive(Clone)]
pub(in crate::starnix) struct PendingScmRights {
    pub(in crate::starnix) descriptions: Vec<Arc<OpenFileDescription>>,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxFutexWaiter {
    pub(in crate::starnix) task_id: i32,
    pub(in crate::starnix) bitset: u32,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct WaitState {
    pub(in crate::starnix) restartable: bool,
    pub(in crate::starnix) kind: WaitKind,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) enum FdReadKind {
    Read,
    Readv,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) enum FdWriteKind {
    Write,
    Writev,
}

pub(in crate::starnix) enum BlockedOpResume {
    StillBlocked,
    Restart(SyscallAction),
}

#[derive(Clone, Copy)]
pub(in crate::starnix) enum WaitKind {
    Wait4 {
        target_pid: i32,
        status_addr: u64,
        options: u64,
    },
    Futex {
        key: LinuxFutexKey,
    },
    Epoll {
        epoll_key: LinuxFileDescriptionKey,
        events_addr: u64,
        maxevents: usize,
    },
    FdRead {
        io_kind: FdReadKind,
        fd: i32,
        buf: u64,
        len: usize,
        packet_key: u64,
    },
    FdWrite {
        io_kind: FdWriteKind,
        fd: i32,
        buf: u64,
        len: usize,
        packet_key: u64,
    },
    MsgRecv {
        fd: i32,
        msg_addr: u64,
        flags: u64,
        packet_key: u64,
    },
    MsgSend {
        fd: i32,
        msg_addr: u64,
        flags: u64,
        packet_key: u64,
    },
}

impl WaitState {
    pub(in crate::starnix) const fn packet_key(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { .. } | WaitKind::Futex { .. } | WaitKind::Epoll { .. } => None,
            WaitKind::FdRead { packet_key, .. }
            | WaitKind::FdWrite { packet_key, .. }
            | WaitKind::MsgRecv { packet_key, .. }
            | WaitKind::MsgSend { packet_key, .. } => Some(packet_key),
        }
    }

    pub(in crate::starnix) const fn wait4_target_pid(self) -> Option<i32> {
        match self.kind {
            WaitKind::Wait4 { target_pid, .. } => Some(target_pid),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    pub(in crate::starnix) const fn wait4_status_addr(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { status_addr, .. } => Some(status_addr),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    pub(in crate::starnix) const fn wait4_options(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { options, .. } => Some(options),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    pub(in crate::starnix) const fn futex_key(self) -> Option<LinuxFutexKey> {
        match self.kind {
            WaitKind::Futex { key, .. } => Some(key),
            WaitKind::Wait4 { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    pub(in crate::starnix) const fn epoll_key(self) -> Option<LinuxFileDescriptionKey> {
        match self.kind {
            WaitKind::Epoll { epoll_key, .. } => Some(epoll_key),
            WaitKind::Wait4 { .. }
            | WaitKind::Futex { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct FdWaitPolicy {
    pub(in crate::starnix) nonblock: bool,
    pub(in crate::starnix) wait_interest: Option<WaitSpec>,
}

pub(in crate::starnix) enum ReadAttempt {
    Ready { bytes: Vec<u8>, actual: usize },
    WouldBlock(FdWaitPolicy),
    Err(zx_status_t),
}

pub(in crate::starnix) enum WriteAttempt {
    Ready(usize),
    WouldBlock(FdWaitPolicy),
    Err(zx_status_t),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::starnix) enum FdWaitOp {
    Read,
    Write,
}

impl StarnixKernel {
    pub(in crate::starnix) fn cancel_task_wait(&mut self, task_id: i32, wait: WaitState) {
        if let Some(key) = wait.futex_key() {
            self.remove_task_from_futex_queue(task_id, key);
        }
        if let Some(epoll_key) = wait.epoll_key() {
            let remove_key = match self.epolls.get_mut(&epoll_key) {
                Some(instance) => {
                    if let Some(index) = instance
                        .waiting_tasks
                        .iter()
                        .position(|queued| *queued == task_id)
                    {
                        let _ = instance.waiting_tasks.remove(index);
                    }
                    instance.entries.is_empty() && instance.waiting_tasks.is_empty()
                }
                None => false,
            };
            if remove_key {
                let _ = self.epolls.remove(&epoll_key);
            }
        }
    }

    pub(in crate::starnix) fn write_wait_result(
        &mut self,
        task_id: i32,
        child_tgid: i32,
        status: i32,
    ) -> Result<(), zx_status_t> {
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let TaskState::Waiting(ref wait) = task.state else {
            return Err(ZX_ERR_BAD_STATE);
        };
        let Some(status_addr) = wait.wait4_status_addr() else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if status_addr != 0 {
            write_guest_bytes(
                task.carrier.session_handle,
                status_addr,
                &status.to_ne_bytes(),
            )?;
        }
        let mut stop_state = ax_guest_stop_state_read(task.carrier.sidecar_vmo)?;
        complete_syscall(&mut stop_state, child_tgid as u64)?;
        task.state = TaskState::Running;
        self.writeback_and_resume(task_id, &stop_state)
    }

    pub(in crate::starnix) fn wait_event_for_child(
        &self,
        parent_tgid: i32,
        target_pid: i32,
        child_tgid: i32,
        options: u64,
    ) -> Option<WaitChildEvent> {
        if !self.wait_matches(parent_tgid, target_pid, child_tgid) {
            return None;
        }
        let child_group = self.groups.get(&child_tgid)?;
        match child_group.state {
            ThreadGroupState::Zombie { wait_status, .. } => Some(WaitChildEvent::Zombie {
                status: wait_status,
            }),
            ThreadGroupState::Running | ThreadGroupState::Stopped => {
                if child_group.stop_wait_pending && (options & LINUX_WUNTRACED) != 0 {
                    return Some(WaitChildEvent::Stopped {
                        status: linux_wait_status_stopped(
                            child_group.last_stop_signal.unwrap_or(LINUX_SIGSTOP),
                        ),
                    });
                }
                if child_group.continued_wait_pending && (options & LINUX_WCONTINUED) != 0 {
                    return Some(WaitChildEvent::Continued);
                }
                None
            }
        }
    }

    pub(in crate::starnix) fn consume_wait_event(
        &mut self,
        child_tgid: i32,
        event: WaitChildEvent,
    ) -> Result<(), zx_status_t> {
        match event {
            WaitChildEvent::Zombie { .. } => Ok(()),
            WaitChildEvent::Stopped { .. } => {
                self.groups
                    .get_mut(&child_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .stop_wait_pending = false;
                Ok(())
            }
            WaitChildEvent::Continued => {
                self.groups
                    .get_mut(&child_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .continued_wait_pending = false;
                Ok(())
            }
        }
    }

    pub(in crate::starnix) fn wait_matches(
        &self,
        parent_tgid: i32,
        target_pid: i32,
        child_tgid: i32,
    ) -> bool {
        if target_pid == -1 {
            return true;
        }
        if target_pid > 0 {
            return target_pid == child_tgid;
        }
        let Some(child_group) = self.groups.get(&child_tgid) else {
            return false;
        };
        let Some(parent_group) = self.groups.get(&parent_tgid) else {
            return false;
        };
        if target_pid == 0 {
            return child_group.pgid == parent_group.pgid;
        }
        child_group.pgid == target_pid.saturating_abs()
    }

    pub(in crate::starnix) fn maybe_wake_parent_waiter(
        &mut self,
        child_tgid: i32,
    ) -> Result<(), zx_status_t> {
        let Some(parent_tgid) = self
            .groups
            .get(&child_tgid)
            .and_then(|group| group.parent_tgid)
        else {
            return Ok(());
        };
        let waiter = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .find_map(|task_id| {
                let task = self.tasks.get(task_id)?;
                match task.state {
                    TaskState::Waiting(ref wait) => {
                        let target_pid = wait.wait4_target_pid()?;
                        let options = wait.wait4_options()?;
                        self.wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
                            .map(|_| *task_id)
                    }
                    _ => None,
                }
            });
        let Some(waiter_id) = waiter else {
            return Ok(());
        };
        let (target_pid, options) = {
            let wait = match self.tasks.get(&waiter_id).map(|task| &task.state) {
                Some(TaskState::Waiting(wait)) => *wait,
                _ => return Ok(()),
            };
            (
                wait.wait4_target_pid().ok_or(ZX_ERR_BAD_STATE)?,
                wait.wait4_options().ok_or(ZX_ERR_BAD_STATE)?,
            )
        };
        let event = self
            .wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let status = match event {
            WaitChildEvent::Zombie { status } | WaitChildEvent::Stopped { status } => status,
            WaitChildEvent::Continued => LINUX_WAIT_STATUS_CONTINUED,
        };
        self.consume_wait_event(child_tgid, event)?;
        self.write_wait_result(waiter_id, child_tgid, status)?;
        if matches!(event, WaitChildEvent::Zombie { .. }) {
            self.reap_group(child_tgid)?;
        }
        Ok(())
    }

    pub(in crate::starnix) fn reap_group(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let sid = self.groups.get(&tgid).map(|group| group.sid);
        let parent_tgid = self.groups.get(&tgid).and_then(|group| group.parent_tgid);
        if let Some(parent_tgid) = parent_tgid
            && let Some(parent) = self.groups.get_mut(&parent_tgid)
        {
            parent.child_tgids.remove(&tgid);
        }
        let _ = self.groups.remove(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(sid) = sid {
            self.refresh_session_foreground_pgid(sid);
        }
        Ok(())
    }
}
