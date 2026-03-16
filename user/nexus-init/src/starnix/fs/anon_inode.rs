use super::super::*;

#[derive(Clone)]
pub(in crate::starnix) struct EventFd {
    state: Arc<Mutex<EventFdState>>,
}

#[derive(Clone)]
pub(in crate::starnix) struct TimerFd {
    state: Arc<Mutex<TimerFdState>>,
}

#[derive(Clone)]
pub(in crate::starnix) struct SignalFd {
    state: Arc<Mutex<SignalFdState>>,
}

#[derive(Clone)]
pub(in crate::starnix) struct PidFd {
    state: Arc<Mutex<PidFdState>>,
}

pub(in crate::starnix) struct EventFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    counter: u64,
    semaphore: bool,
    closed: bool,
}

pub(in crate::starnix) struct TimerFdState {
    timer_handle: zx_handle_t,
    armed_deadline_ns: Option<u64>,
    pending_expirations: u64,
    closed: bool,
}

pub(in crate::starnix) struct SignalFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    owner_tid: i32,
    owner_tgid: i32,
    mask: u64,
    closed: bool,
}

pub(in crate::starnix) struct PidFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    target_tgid: i32,
    closed: bool,
}

#[derive(Clone, Copy, Default)]
pub(in crate::starnix) struct LinuxItimerSpec {
    pub(in crate::starnix) interval_ns: u64,
    pub(in crate::starnix) value_ns: u64,
}

#[derive(Clone, Copy)]
struct ConsumedSignal {
    signal: i32,
    sigchld_info: Option<LinuxSigChldInfo>,
}

impl EventFd {
    fn new(initial: u32, semaphore: bool) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(EventFdState {
                wait_handle,
                peer_handle,
                counter: u64::from(initial),
                semaphore,
                closed: false,
            })),
        };
        if let Err(status) = this.refresh_signals() {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn refresh_signals(&self) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        Self::refresh_signals_locked(&state)
    }

    fn refresh_signals_locked(state: &EventFdState) -> Result<(), zx_status_t> {
        if state.closed {
            return Ok(());
        }
        let mut set_mask = 0u32;
        if state.counter != 0 {
            set_mask |= EVENTFD_READABLE_SIGNAL;
        }
        if state.counter < EVENTFD_COUNTER_MAX {
            set_mask |= EVENTFD_WRITABLE_SIGNAL;
        }
        zx_status_result(ax_object_signal(
            state.wait_handle,
            EVENTFD_SIGNAL_MASK,
            set_mask,
        ))
    }
}

impl FdOps for EventFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        if state.counter == 0 {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let value = if state.semaphore {
            state.counter -= 1;
            1u64
        } else {
            let value = state.counter;
            state.counter = 0;
            value
        };
        Self::refresh_signals_locked(&state)?;
        buffer.copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let value = u64::from_ne_bytes(buffer.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
        if value == u64::MAX {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        let remaining = EVENTFD_COUNTER_MAX
            .checked_sub(state.counter)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if value > remaining {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        state.counter = state
            .counter
            .checked_add(value)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Self::refresh_signals_locked(&state)?;
        Ok(8)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, EVENTFD_SIGNAL_MASK))
    }
}

impl TimerFd {
    fn new() -> Result<Self, zx_status_t> {
        let mut timer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_timer_create_monotonic(0, &mut timer_handle))?;
        Ok(Self {
            state: Arc::new(Mutex::new(TimerFdState {
                timer_handle,
                armed_deadline_ns: None,
                pending_expirations: 0,
                closed: false,
            })),
        })
    }

    fn sample_expiration_locked(state: &mut TimerFdState) -> Result<(), zx_status_t> {
        if state.closed || state.pending_expirations != 0 {
            return Ok(());
        }
        let mut observed = 0;
        match ax_object_wait_one(state.timer_handle, ZX_TIMER_SIGNALED, 0, &mut observed) {
            ZX_OK => {
                state.armed_deadline_ns = None;
                state.pending_expirations = 1;
                Ok(())
            }
            ZX_ERR_TIMED_OUT => Ok(()),
            status => Err(status),
        }
    }

    fn settime(&self, flags: u64, new_value: LinuxItimerSpec) -> Result<(), zx_status_t> {
        if (flags & LINUX_TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let allowed = LINUX_TFD_TIMER_ABSTIME | LINUX_TFD_TIMER_CANCEL_ON_SET;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if new_value.interval_ns != 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let mut state = self.state.lock();
        if state.closed {
            return Err(ZX_ERR_BAD_STATE);
        }
        zx_status_result(ax_timer_cancel(state.timer_handle))?;
        state.armed_deadline_ns = None;
        state.pending_expirations = 0;
        if new_value.value_ns == 0 {
            return Ok(());
        }
        if (flags & LINUX_TFD_TIMER_ABSTIME) == 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let deadline = i64::try_from(new_value.value_ns).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        zx_status_result(ax_timer_set(state.timer_handle, deadline, 0))?;
        state.armed_deadline_ns = Some(new_value.value_ns);
        Ok(())
    }
}

impl FdOps for TimerFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        Self::sample_expiration_locked(&mut state)?;
        if state.pending_expirations == 0 {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let expirations = state.pending_expirations;
        state.pending_expirations = 0;
        zx_status_result(ax_timer_cancel(state.timer_handle))?;
        buffer.copy_from_slice(&expirations.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let timer_handle = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.timer_handle
        };
        let _ = ax_timer_cancel(timer_handle);
        let _ = zx_handle_close(timer_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.timer_handle, ZX_TIMER_SIGNALED))
    }
}

impl SignalFd {
    fn new(owner_tid: i32, owner_tgid: i32, mask: u64) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(SignalFdState {
                wait_handle,
                peer_handle,
                owner_tid,
                owner_tgid,
                mask: normalize_signal_mask(mask),
                closed: false,
            })),
        };
        if let Err(status) = this.set_ready(false) {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn snapshot(&self) -> Option<(i32, i32, u64, zx_handle_t)> {
        let state = self.state.lock();
        (!state.closed).then_some((
            state.owner_tid,
            state.owner_tgid,
            state.mask,
            state.wait_handle,
        ))
    }

    fn set_ready(&self, ready: bool) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        if state.closed {
            return Ok(());
        }
        let set_mask = if ready { SIGNALFD_READABLE_SIGNAL } else { 0 };
        zx_status_result(ax_object_signal(
            state.wait_handle,
            SIGNALFD_READABLE_SIGNAL,
            set_mask,
        ))
    }

    fn weak_state(&self) -> Weak<Mutex<SignalFdState>> {
        Arc::downgrade(&self.state)
    }
}

impl FdOps for SignalFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, SIGNALFD_READABLE_SIGNAL))
    }
}

impl PidFd {
    fn new(target_tgid: i32) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(PidFdState {
                wait_handle,
                peer_handle,
                target_tgid,
                closed: false,
            })),
        };
        if let Err(status) = this.set_ready(false) {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn snapshot(&self) -> Option<(i32, zx_handle_t)> {
        let state = self.state.lock();
        (!state.closed).then_some((state.target_tgid, state.wait_handle))
    }

    fn set_ready(&self, ready: bool) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        if state.closed {
            return Ok(());
        }
        let set_mask = if ready { PIDFD_READABLE_SIGNAL } else { 0 };
        zx_status_result(ax_object_signal(
            state.wait_handle,
            PIDFD_READABLE_SIGNAL,
            set_mask,
        ))
    }

    fn weak_state(&self) -> Weak<Mutex<PidFdState>> {
        Arc::downgrade(&self.state)
    }
}

impl FdOps for PidFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, PIDFD_READABLE_SIGNAL))
    }
}

impl StarnixKernel {
    pub(in crate::starnix) fn refresh_signalfds_for_group(
        &mut self,
        tgid: i32,
    ) -> Result<(), zx_status_t> {
        let keys = self.signalfds.keys().copied().collect::<Vec<_>>();
        let mut stale = Vec::new();
        for key in keys {
            let Some(weak) = self.signalfds.get(&key).cloned() else {
                continue;
            };
            let Some(state) = weak.upgrade() else {
                stale.push(key);
                continue;
            };
            let owner_tgid = {
                let guard = state.lock();
                guard.owner_tgid
            };
            if owner_tgid == tgid {
                self.refresh_signalfd_key(key)?;
            }
        }
        for key in stale {
            let _ = self.signalfds.remove(&key);
        }
        Ok(())
    }

    pub(in crate::starnix) fn refresh_pidfds_for_group(
        &mut self,
        tgid: i32,
    ) -> Result<(), zx_status_t> {
        let keys = self.pidfds.keys().copied().collect::<Vec<_>>();
        let mut stale = Vec::new();
        for key in keys {
            let Some(weak) = self.pidfds.get(&key).cloned() else {
                continue;
            };
            let Some(state) = weak.upgrade() else {
                stale.push(key);
                continue;
            };
            let target_tgid = {
                let guard = state.lock();
                guard.target_tgid
            };
            if target_tgid == tgid {
                self.refresh_pidfd_key(key)?;
            }
        }
        for key in stale {
            let _ = self.pidfds.remove(&key);
        }
        Ok(())
    }

    pub(in crate::starnix) fn sys_read_signalfd(
        &mut self,
        task_id: i32,
        fd: i32,
        buf: u64,
        len: usize,
        stop_state: &mut ax_guest_stop_state_t,
        signalfd: SignalFd,
    ) -> Result<SyscallAction, zx_status_t> {
        if len < LINUX_SIGNALFD_SIGINFO_BYTES || !len.is_multiple_of(LINUX_SIGNALFD_SIGINFO_BYTES) {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;
        let (owner_tid, owner_tgid, mask, _wait_handle) =
            signalfd.snapshot().ok_or(ZX_ERR_BAD_STATE)?;
        match self.take_signalfd_signal(owner_tid, mask)? {
            Some(consumed) => {
                let info = encode_signalfd_siginfo(consumed.signal, consumed.sigchld_info);
                match write_guest_bytes(session, buf, &info) {
                    Ok(()) => {
                        complete_syscall(
                            stop_state,
                            u64::try_from(LINUX_SIGNALFD_SIGINFO_BYTES)
                                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                        )?;
                    }
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_write_status_to_errno(status)),
                        )?;
                    }
                }
                self.refresh_signalfds_for_group(owner_tgid)?;
                Ok(SyscallAction::Resume)
            }
            None => {
                if wait_policy.nonblock || wait_policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::FdRead {
                        fd,
                        buf,
                        len,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    wait_policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
        }
    }

    pub(in crate::starnix) fn sys_pidfd_open(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_tgid = linux_arg_i32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        if flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if !self.groups.contains_key(&target_tgid) {
            complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let pidfd = match PidFd::new(target_tgid) {
            Ok(pidfd) => pidfd,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let weak = pidfd.weak_state();
        let created_fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources
                .fs
                .fd_table
                .open(Arc::new(pidfd), OpenFlags::READABLE, FdFlags::empty())
        };
        match created_fd {
            Ok(fd) => {
                let key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.pidfds.insert(key, weak);
                self.refresh_pidfd_key(key)?;
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_pidfd_send_signal(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let pidfd = linux_arg_i32(stop_state.regs.rdi);
        let signal = linux_arg_i32(stop_state.regs.rsi);
        let info = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        if info != 0 || flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let target_tgid = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let fd_entry = resources.fs.fd_table.get(pidfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            let Some(pidfd) = fd_entry
                .description()
                .ops()
                .as_ref()
                .as_any()
                .downcast_ref::<PidFd>()
            else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            pidfd.snapshot().map(|(target_tgid, _)| target_tgid)
        };
        let Some(target_tgid) = target_tgid else {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        };
        let result = self.queue_signal_to_group(target_tgid, signal, stdout)?;
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_timerfd_create(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let clockid = stop_state.regs.rdi as u32 as i32;
        let flags = stop_state.regs.rsi;
        let allowed = LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC;
        if clockid != LINUX_CLOCK_MONOTONIC {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let timerfd = TimerFd::new();
        let fd = match timerfd {
            Ok(timerfd) => {
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                let mut open_flags = OpenFlags::READABLE;
                if (flags & LINUX_TFD_NONBLOCK) != 0 {
                    open_flags |= OpenFlags::NONBLOCK;
                }
                let fd_flags = if (flags & LINUX_TFD_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                resources
                    .fs
                    .fd_table
                    .open(Arc::new(timerfd), open_flags, fd_flags)
            }
            Err(status) => Err(status),
        };

        match fd {
            Ok(fd) => complete_syscall(stop_state, fd as u64)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_timerfd_settime(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        let new_value_addr = stop_state.regs.rdx;
        let old_value_addr = stop_state.regs.r10;
        if new_value_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }
        if old_value_addr != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let new_value = match read_guest_itimerspec(session, new_value_addr) {
            Ok(spec) => spec,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let result = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let Some(entry) = resources.fs.fd_table.get(fd) else {
                complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
                return Ok(SyscallAction::Resume);
            };
            let Some(timerfd) = entry
                .description()
                .ops()
                .as_ref()
                .as_any()
                .downcast_ref::<TimerFd>()
            else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            timerfd.settime(flags, new_value)
        };

        match result {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(ZX_ERR_INVALID_ARGS) => complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?,
            Err(ZX_ERR_NOT_SUPPORTED) => complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_timerfd_gettime(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_signalfd4(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = stop_state.regs.rdi as u32 as i32;
        let mask_addr = stop_state.regs.rsi;
        let sigset_size = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let allowed = LINUX_SFD_NONBLOCK | LINUX_SFD_CLOEXEC;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64 || mask_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let mask = match read_guest_signal_mask(session, mask_addr) {
            Ok(mask) => normalize_signal_mask(mask),
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        if fd != -1 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let signalfd = match SignalFd::new(task_id, tgid, mask) {
            Ok(signalfd) => signalfd,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let weak = signalfd.weak_state();
        let created_fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let mut open_flags = OpenFlags::READABLE;
            if (flags & LINUX_SFD_NONBLOCK) != 0 {
                open_flags |= OpenFlags::NONBLOCK;
            }
            let fd_flags = if (flags & LINUX_SFD_CLOEXEC) != 0 {
                FdFlags::CLOEXEC
            } else {
                FdFlags::empty()
            };
            resources
                .fs
                .fd_table
                .open(Arc::new(signalfd), open_flags, fd_flags)
        };

        match created_fd {
            Ok(fd) => {
                let key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.signalfds.insert(key, weak);
                self.refresh_signalfd_key(key)?;
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_eventfd2(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let initval = linux_arg_u32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        let allowed = LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC;
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let eventfd = EventFd::new(initval, (flags & LINUX_EFD_SEMAPHORE) != 0);
        let fd = match eventfd {
            Ok(eventfd) => {
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                let mut open_flags = OpenFlags::READABLE | OpenFlags::WRITABLE;
                if (flags & LINUX_EFD_NONBLOCK) != 0 {
                    open_flags |= OpenFlags::NONBLOCK;
                }
                let fd_flags = if (flags & LINUX_EFD_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                resources
                    .fs
                    .fd_table
                    .open(Arc::new(eventfd), open_flags, fd_flags)
            }
            Err(status) => Err(status),
        };

        match fd {
            Ok(fd) => complete_syscall(stop_state, fd as u64)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn signalfd_ready_mask(&self, owner_tid: i32, mask: u64) -> Result<u64, zx_status_t> {
        let task = self.tasks.get(&owner_tid).ok_or(ZX_ERR_BAD_STATE)?;
        let blocked = task.signals.blocked;
        let task_pending = task.signals.pending & mask & blocked;
        let shared_pending = self
            .groups
            .get(&task.tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .shared_pending
            & mask
            & blocked;
        Ok(task_pending | shared_pending)
    }

    fn refresh_signalfd_key(&mut self, key: LinuxFileDescriptionKey) -> Result<(), zx_status_t> {
        let Some(weak) = self.signalfds.get(&key).cloned() else {
            return Ok(());
        };
        let Some(state) = weak.upgrade() else {
            let _ = self.signalfds.remove(&key);
            return Ok(());
        };
        let (owner_tid, _owner_tgid, mask, wait_handle, closed) = {
            let guard = state.lock();
            (
                guard.owner_tid,
                guard.owner_tgid,
                guard.mask,
                guard.wait_handle,
                guard.closed,
            )
        };
        if closed {
            let _ = self.signalfds.remove(&key);
            return Ok(());
        }
        let ready = self.signalfd_ready_mask(owner_tid, mask)? != 0;
        zx_status_result(ax_object_signal(
            wait_handle,
            SIGNALFD_READABLE_SIGNAL,
            if ready { SIGNALFD_READABLE_SIGNAL } else { 0 },
        ))
    }

    fn refresh_pidfd_key(&mut self, key: LinuxFileDescriptionKey) -> Result<(), zx_status_t> {
        let Some(weak) = self.pidfds.get(&key).cloned() else {
            return Ok(());
        };
        let Some(state) = weak.upgrade() else {
            let _ = self.pidfds.remove(&key);
            return Ok(());
        };
        let (target_tgid, wait_handle, closed) = {
            let guard = state.lock();
            (guard.target_tgid, guard.wait_handle, guard.closed)
        };
        if closed {
            let _ = self.pidfds.remove(&key);
            return Ok(());
        }
        let ready = self
            .groups
            .get(&target_tgid)
            .is_some_and(|group| matches!(group.state, ThreadGroupState::Zombie { .. }));
        zx_status_result(ax_object_signal(
            wait_handle,
            PIDFD_READABLE_SIGNAL,
            if ready { PIDFD_READABLE_SIGNAL } else { 0 },
        ))
    }

    fn take_signalfd_signal(
        &mut self,
        owner_tid: i32,
        mask: u64,
    ) -> Result<Option<ConsumedSignal>, zx_status_t> {
        let blocked = self.task_signal_mask(owner_tid)?;
        let tgid = self.tasks.get(&owner_tid).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let task_pending = self
            .tasks
            .get(&owner_tid)
            .map(|task| task.signals.pending & mask & blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(task_pending) {
            if let Some(task) = self.tasks.get_mut(&owner_tid) {
                task.signals.pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(ConsumedSignal {
                signal,
                sigchld_info: None,
            }));
        }
        let shared_pending = self
            .groups
            .get(&tgid)
            .map(|group| group.shared_pending & mask & blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(shared_pending) {
            let sigchld_info = self
                .shared_sigchld_info(tgid)
                .filter(|_| signal == LINUX_SIGCHLD);
            if let Some(group) = self.groups.get_mut(&tgid) {
                group.shared_pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.clear_shared_signal_state(tgid, signal)?;
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(ConsumedSignal {
                signal,
                sigchld_info,
            }));
        }
        Ok(None)
    }
}

fn encode_signalfd_siginfo(
    signal: i32,
    sigchld_info: Option<LinuxSigChldInfo>,
) -> [u8; LINUX_SIGNALFD_SIGINFO_BYTES] {
    let mut bytes = [0u8; LINUX_SIGNALFD_SIGINFO_BYTES];
    bytes[0..4].copy_from_slice(&(signal as u32).to_ne_bytes());
    if let Some(info) = sigchld_info {
        bytes[8..12].copy_from_slice(&info.code.to_ne_bytes());
        bytes[12..16].copy_from_slice(&(info.pid as u32).to_ne_bytes());
        bytes[40..44].copy_from_slice(&info.status.to_ne_bytes());
    }
    bytes
}
