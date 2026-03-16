use super::super::*;
use super::readiness::{
    filter_epoll_ready_events, filter_epoll_wait_interest, map_wait_signals_to_epoll,
};

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxEpollEvent {
    pub(in crate::starnix) events: u32,
    pub(in crate::starnix) data: u64,
}

pub(in crate::starnix) struct EpollEntry {
    description: Arc<OpenFileDescription>,
    interest: u32,
    data: u64,
    wait_interest: Option<WaitSpec>,
    packet_key: Option<u64>,
    disabled: bool,
    queued_events: u32,
    observer_armed: bool,
}

pub(in crate::starnix) struct EpollInstance {
    pub(in crate::starnix) entries: BTreeMap<LinuxFileDescriptionKey, EpollEntry>,
    pub(in crate::starnix) ready_list: VecDeque<LinuxFileDescriptionKey>,
    pub(in crate::starnix) ready_set: BTreeSet<LinuxFileDescriptionKey>,
    pub(in crate::starnix) waiting_tasks: VecDeque<i32>,
}

impl EpollInstance {
    pub(in crate::starnix) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            ready_list: VecDeque::new(),
            ready_set: BTreeSet::new(),
            waiting_tasks: VecDeque::new(),
        }
    }
}

pub(in crate::starnix) fn read_guest_epoll_event(
    session: zx_handle_t,
    addr: u64,
) -> Result<LinuxEpollEvent, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_EPOLL_EVENT_BYTES)?;
    let raw = bytes
        .get(..LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxEpollEvent {
        events: u32::from_ne_bytes(raw[0..4].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        data: u64::from_ne_bytes(
            raw[4..12]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
    })
}

pub(in crate::starnix) fn encode_epoll_events(
    events: &[LinuxEpollEvent],
) -> Result<Vec<u8>, zx_status_t> {
    let total = events
        .len()
        .checked_mul(LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(total, 0);
    for (index, event) in events.iter().enumerate() {
        let start = index
            .checked_mul(LINUX_EPOLL_EVENT_BYTES)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        bytes[start..start + 4].copy_from_slice(&event.events.to_ne_bytes());
        bytes[start + 4..start + 12].copy_from_slice(&event.data.to_ne_bytes());
    }
    Ok(bytes)
}

impl StarnixKernel {
    pub(in crate::starnix) fn queue_epoll_ready(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
        ready: u32,
    ) {
        let Some(instance) = self.epolls.get_mut(&epoll_key) else {
            return;
        };
        let Some(entry) = instance.entries.get_mut(&target_key) else {
            return;
        };
        if entry.disabled {
            return;
        }
        let filtered = filter_epoll_ready_events(entry.interest, ready);
        if filtered == 0 {
            return;
        }
        entry.queued_events |= filtered;
        if instance.ready_set.insert(target_key) {
            instance.ready_list.push_back(target_key);
        }
    }

    fn pop_ready_epoll_target(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Option<LinuxFileDescriptionKey> {
        loop {
            let next = {
                let instance = self.epolls.get_mut(&epoll_key)?;
                instance.ready_list.pop_front()
            };
            let Some(target_key) = next else {
                if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                    instance.ready_set.clear();
                }
                return None;
            };
            if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                instance.ready_set.remove(&target_key);
                if instance.entries.contains_key(&target_key) {
                    return Some(target_key);
                }
            }
        }
    }

    pub(in crate::starnix) fn arm_epoll_entry(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let (wait_interest, packet_key, disabled, observer_armed) = {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
            (
                entry.wait_interest,
                entry.packet_key,
                entry.disabled,
                entry.observer_armed,
            )
        };
        if disabled || observer_armed {
            return Ok(());
        }
        let Some(wait_interest) = wait_interest else {
            return Ok(());
        };
        let Some(packet_key) = packet_key else {
            return Ok(());
        };
        let status = ax_object_wait_async(
            wait_interest.handle(),
            self.port,
            packet_key,
            wait_interest.signals(),
            axle_types::wait_async::AX_WAIT_ASYNC_EDGE,
        );
        zx_status_result(status)?;
        let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
        let entry = instance
            .entries
            .get_mut(&target_key)
            .ok_or(ZX_ERR_BAD_STATE)?;
        entry.observer_armed = true;
        Ok(())
    }

    fn sample_epoll_ready_mask(&self, entry: &EpollEntry) -> u32 {
        if let Some(wait_interest) = entry.wait_interest {
            let mut observed = 0;
            match ax_object_wait_one(
                wait_interest.handle(),
                wait_interest.signals(),
                0,
                &mut observed,
            ) {
                ZX_OK => map_wait_signals_to_epoll(observed),
                axle_types::status::AX_ERR_TIMED_OUT => 0,
                _ => LINUX_EPOLLERR | LINUX_EPOLLHUP,
            }
        } else {
            match stat_metadata_for_ops(entry.description.ops().as_ref()) {
                Ok(_) => LINUX_EPOLLIN | LINUX_EPOLLOUT,
                Err(_) => 0,
            }
        }
    }

    pub(in crate::starnix) fn handle_epoll_ready_packet(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        {
            let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance
                .entries
                .get_mut(&target_key)
                .ok_or(ZX_ERR_BAD_STATE)?;
            entry.observer_armed = false;
        }
        let ready = {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
            self.sample_epoll_ready_mask(entry)
        };
        self.queue_epoll_ready(epoll_key, target_key, ready);
        self.wake_one_epoll_waiter(epoll_key)
    }

    pub(in crate::starnix) fn wake_one_epoll_waiter(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        loop {
            let task_id = {
                let Some(instance) = self.epolls.get_mut(&epoll_key) else {
                    return Ok(());
                };
                instance.waiting_tasks.pop_front()
            };
            let Some(task_id) = task_id else {
                return Ok(());
            };
            let Some(task) = self.tasks.get(&task_id) else {
                continue;
            };
            if !matches!(task.state, TaskState::Waiting(wait) if wait.epoll_key() == Some(epoll_key))
            {
                continue;
            }
            return self.resume_epoll_waiter(task_id, epoll_key);
        }
    }

    fn collect_epoll_events(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        maxevents: usize,
    ) -> Result<Vec<LinuxEpollEvent>, zx_status_t> {
        let mut events = Vec::new();
        let mut requeue_after = Vec::new();
        events
            .try_reserve_exact(maxevents)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        requeue_after
            .try_reserve_exact(maxevents)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        while events.len() < maxevents {
            let Some(target_key) = self.pop_ready_epoll_target(epoll_key) else {
                break;
            };
            let (event, requeue_level, rearm) = {
                let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance
                    .entries
                    .get_mut(&target_key)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let event = LinuxEpollEvent {
                    events: entry.queued_events,
                    data: entry.data,
                };
                entry.queued_events = 0;
                if (entry.interest & LINUX_EPOLLONESHOT) != 0 {
                    entry.disabled = true;
                }
                (
                    event,
                    (entry.interest & LINUX_EPOLLET) == 0 && !entry.disabled,
                    !entry.disabled,
                )
            };
            events.push(event);
            if requeue_level {
                requeue_after.push(target_key);
            }
            if rearm {
                self.arm_epoll_entry(epoll_key, target_key)?;
            }
        }
        for target_key in requeue_after {
            let ready = {
                let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                self.sample_epoll_ready_mask(entry)
            };
            self.queue_epoll_ready(epoll_key, target_key, ready);
        }
        Ok(events)
    }

    fn refresh_level_triggered_epoll_ready(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let mut targets = Vec::new();
        {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            targets
                .try_reserve_exact(instance.entries.len())
                .map_err(|_| ZX_ERR_NO_MEMORY)?;
            for (target_key, entry) in &instance.entries {
                if (entry.interest & LINUX_EPOLLET) == 0 && !entry.disabled {
                    targets.push(*target_key);
                }
            }
        }
        for target_key in targets {
            let ready = {
                let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                self.sample_epoll_ready_mask(entry)
            };
            if ready == 0 {
                let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                if let Some(entry) = instance.entries.get_mut(&target_key) {
                    entry.queued_events = 0;
                }
                instance.ready_set.remove(&target_key);
                instance.ready_list.retain(|queued| *queued != target_key);
            } else {
                self.queue_epoll_ready(epoll_key, target_key, ready);
            }
        }
        Ok(())
    }

    pub(in crate::starnix) fn complete_epoll_wait(
        &mut self,
        task_id: i32,
        epoll_key: LinuxFileDescriptionKey,
        events_addr: u64,
        maxevents: usize,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<bool, zx_status_t> {
        self.refresh_level_triggered_epoll_ready(epoll_key)?;
        let events = self.collect_epoll_events(epoll_key, maxevents)?;
        if events.is_empty() {
            return Ok(false);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let bytes = encode_epoll_events(&events)?;
        match write_guest_bytes(session, events_addr, &bytes) {
            Ok(()) => {
                complete_syscall(
                    stop_state,
                    u64::try_from(events.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                )?;
                Ok(true)
            }
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_write_status_to_errno(status)),
                )?;
                Ok(true)
            }
        }
    }

    fn resume_epoll_waiter(
        &mut self,
        task_id: i32,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let (events_addr, maxevents, sidecar) = {
            let task = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let TaskState::Waiting(wait) = task.state else {
                return Err(ZX_ERR_BAD_STATE);
            };
            let WaitKind::Epoll {
                epoll_key: waiting_key,
                events_addr,
                maxevents,
            } = wait.kind
            else {
                return Err(ZX_ERR_BAD_STATE);
            };
            if waiting_key != epoll_key {
                return Err(ZX_ERR_BAD_STATE);
            }
            (events_addr, maxevents, task.carrier.sidecar_vmo)
        };

        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        if !self.complete_epoll_wait(task_id, epoll_key, events_addr, maxevents, &mut stop_state)? {
            return Ok(());
        }
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Running;
        self.writeback_and_resume(task_id, &stop_state)
    }

    pub(in crate::starnix) fn sys_epoll_create1(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let flags = stop_state.regs.rdi;
        if flags != 0 && flags != LINUX_EPOLL_CLOEXEC {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let fd_flags = if flags == LINUX_EPOLL_CLOEXEC {
                FdFlags::CLOEXEC
            } else {
                FdFlags::empty()
            };
            resources.fs.fd_table.open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE,
                fd_flags,
            )
        };
        match fd {
            Ok(fd) => {
                let epoll_key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.epolls.insert(epoll_key, EpollInstance::new());
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_epoll_ctl(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let epfd = linux_arg_i32(stop_state.regs.rdi);
        let op = stop_state.regs.rsi as u32 as i32;
        let fd = linux_arg_i32(stop_state.regs.rdx);
        let event_addr = stop_state.regs.r10;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;

        let (epoll_key, target_description, raw_wait_interest) = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let epoll_entry = resources.fs.fd_table.get(epfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            let epoll_key = file_description_key(epoll_entry.description());
            let target_entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
            (
                epoll_key,
                Arc::clone(target_entry.description()),
                resources.fs.fd_table.wait_interest(fd)?,
            )
        };
        if !self.epolls.contains_key(&epoll_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        }
        let target_key = file_description_key(&target_description);
        if target_key == epoll_key || self.epolls.contains_key(&target_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        match op {
            LINUX_EPOLL_CTL_ADD | LINUX_EPOLL_CTL_MOD => {
                if event_addr == 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
                    return Ok(SyscallAction::Resume);
                }
                let event = match read_guest_epoll_event(session, event_addr) {
                    Ok(event) => event,
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                let unsupported = event.events
                    & !(LINUX_EPOLLIN
                        | LINUX_EPOLLOUT
                        | LINUX_EPOLLERR
                        | LINUX_EPOLLHUP
                        | LINUX_EPOLLONESHOT
                        | LINUX_EPOLLET);
                if unsupported != 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                    return Ok(SyscallAction::Resume);
                }
                let wait_interest = raw_wait_interest
                    .map(|interest| filter_epoll_wait_interest(interest, event.events));
                let exists = self
                    .epolls
                    .get(&epoll_key)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .entries
                    .contains_key(&target_key);
                if op == LINUX_EPOLL_CTL_ADD && exists {
                    complete_syscall(stop_state, linux_errno(LINUX_EEXIST))?;
                    return Ok(SyscallAction::Resume);
                }
                if op == LINUX_EPOLL_CTL_MOD && !exists {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
                    return Ok(SyscallAction::Resume);
                }
                if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                    if let Some(old) = instance.entries.remove(&target_key)
                        && let Some(packet_key) = old.packet_key
                    {
                        let _ = self.epoll_packets.remove(&packet_key);
                    }
                    instance.ready_set.remove(&target_key);
                    instance.ready_list.retain(|queued| *queued != target_key);
                }
                let packet_key = if wait_interest.is_some() {
                    Some(self.alloc_packet_key()?)
                } else {
                    None
                };
                if let Some(packet_key) = packet_key {
                    self.epoll_packets
                        .insert(packet_key, (epoll_key, target_key));
                }
                let entry = EpollEntry {
                    description: target_description,
                    interest: event.events,
                    data: event.data,
                    wait_interest,
                    packet_key,
                    disabled: false,
                    queued_events: 0,
                    observer_armed: false,
                };
                self.epolls
                    .get_mut(&epoll_key)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .entries
                    .insert(target_key, entry);
                let ready = {
                    let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                    self.sample_epoll_ready_mask(entry)
                };
                self.queue_epoll_ready(epoll_key, target_key, ready);
                self.arm_epoll_entry(epoll_key, target_key)?;
                self.wake_one_epoll_waiter(epoll_key)?;
                complete_syscall(stop_state, 0)?;
            }
            LINUX_EPOLL_CTL_DEL => {
                let Some(instance) = self.epolls.get_mut(&epoll_key) else {
                    return Err(ZX_ERR_BAD_STATE);
                };
                let Some(old) = instance.entries.remove(&target_key) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
                    return Ok(SyscallAction::Resume);
                };
                if let Some(packet_key) = old.packet_key {
                    let _ = self.epoll_packets.remove(&packet_key);
                }
                instance.ready_set.remove(&target_key);
                instance.ready_list.retain(|queued| *queued != target_key);
                complete_syscall(stop_state, 0)?;
            }
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_epoll_wait(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let epfd = linux_arg_i32(stop_state.regs.rdi);
        let events_addr = stop_state.regs.rsi;
        let maxevents = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let timeout = stop_state.regs.r10 as u32 as i32;
        if maxevents == 0 || timeout < -1 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let epoll_key = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let epoll_entry = resources.fs.fd_table.get(epfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            file_description_key(epoll_entry.description())
        };
        if !self.epolls.contains_key(&epoll_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        }
        if self.complete_epoll_wait(task_id, epoll_key, events_addr, maxevents, stop_state)? {
            return Ok(SyscallAction::Resume);
        }
        if timeout == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        if timeout != -1 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }
        let wait = WaitState {
            restartable: true,
            kind: WaitKind::Epoll {
                epoll_key,
                events_addr,
                maxevents,
            },
        };
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.epolls
            .get_mut(&epoll_key)
            .ok_or(ZX_ERR_BAD_STATE)?
            .waiting_tasks
            .push_back(task_id);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
    }
}
