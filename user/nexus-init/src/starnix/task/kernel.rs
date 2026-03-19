use super::super::*;

pub(in crate::starnix) enum SyscallAction {
    Resume,
    LeaveStopped,
    TaskExit(i32),
    GroupExit(i32),
    GroupSignalExit(i32),
}

pub(in crate::starnix) struct StarnixKernel {
    pub(in crate::starnix) parent_process: zx_handle_t,
    pub(in crate::starnix) port: zx_handle_t,
    pub(in crate::starnix) next_tid: i32,
    pub(in crate::starnix) next_packet_key: u64,
    pub(in crate::starnix) random_state: u64,
    pub(in crate::starnix) root_tgid: i32,
    pub(in crate::starnix) tasks: BTreeMap<i32, LinuxTask>,
    pub(in crate::starnix) groups: BTreeMap<i32, LinuxThreadGroup>,
    pub(in crate::starnix) foreground_pgid_by_sid: BTreeMap<i32, i32>,
    pub(in crate::starnix) futex_waiters: BTreeMap<LinuxFutexKey, VecDeque<LinuxFutexWaiter>>,
    pub(in crate::starnix) epolls: BTreeMap<LinuxFileDescriptionKey, EpollInstance>,
    pub(in crate::starnix) epoll_packets:
        BTreeMap<u64, (LinuxFileDescriptionKey, LinuxFileDescriptionKey)>,
    pub(in crate::starnix) signalfds: BTreeMap<LinuxFileDescriptionKey, Weak<Mutex<SignalFdState>>>,
    pub(in crate::starnix) pidfds: BTreeMap<LinuxFileDescriptionKey, Weak<Mutex<PidFdState>>>,
    pub(in crate::starnix) unix_socket_peers:
        BTreeMap<LinuxFileDescriptionKey, LinuxFileDescriptionKey>,
    pub(in crate::starnix) unix_socket_rights:
        BTreeMap<LinuxFileDescriptionKey, VecDeque<PendingScmRights>>,
}

impl StarnixKernel {
    pub(in crate::starnix) fn new(
        parent_process: zx_handle_t,
        port: zx_handle_t,
        root_task: LinuxTask,
        root_group: LinuxThreadGroup,
    ) -> Self {
        let root_tgid = root_group.tgid;
        let root_sid = root_group.sid;
        let root_pgid = root_group.pgid;
        let mut tasks = BTreeMap::new();
        tasks.insert(root_task.tid, root_task);
        let mut groups = BTreeMap::new();
        groups.insert(root_group.tgid, root_group);
        let mut foreground_pgid_by_sid = BTreeMap::new();
        foreground_pgid_by_sid.insert(root_sid, root_pgid);
        Self {
            parent_process,
            port,
            next_tid: root_tgid + 1,
            next_packet_key: STARNIX_GUEST_PACKET_KEY_BASE + 1,
            random_state: seed_runtime_random_state(parent_process, port, root_tgid),
            root_tgid,
            tasks,
            groups,
            foreground_pgid_by_sid,
            futex_waiters: BTreeMap::new(),
            epolls: BTreeMap::new(),
            epoll_packets: BTreeMap::new(),
            signalfds: BTreeMap::new(),
            pidfds: BTreeMap::new(),
            unix_socket_peers: BTreeMap::new(),
            unix_socket_rights: BTreeMap::new(),
        }
    }

    pub(in crate::starnix) fn alloc_tid(&mut self) -> Result<i32, zx_status_t> {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(tid)
    }

    pub(in crate::starnix) fn alloc_packet_key(&mut self) -> Result<u64, zx_status_t> {
        let key = self.next_packet_key;
        self.next_packet_key = self
            .next_packet_key
            .checked_add(1)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(key)
    }

    pub(in crate::starnix) fn target_tgid_for_pid_arg(
        &self,
        caller_tgid: i32,
        pid: i32,
    ) -> Result<i32, zx_status_t> {
        if pid == 0 {
            return Ok(caller_tgid);
        }
        if pid < 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if self.groups.contains_key(&pid) {
            Ok(pid)
        } else {
            Err(ZX_ERR_NOT_FOUND)
        }
    }

    pub(in crate::starnix) fn task_pgid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.pgid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(in crate::starnix) fn task_sid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.sid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(in crate::starnix) fn session_has_pgid(&self, sid: i32, pgid: i32) -> bool {
        self.groups
            .values()
            .any(|group| group.sid == sid && group.pgid == pgid)
    }

    pub(in crate::starnix) fn foreground_pgid(&self, sid: i32) -> Option<i32> {
        self.foreground_pgid_by_sid.get(&sid).copied()
    }

    pub(in crate::starnix) fn refresh_session_foreground_pgid(&mut self, sid: i32) {
        let current = self.foreground_pgid_by_sid.get(&sid).copied();
        if current.is_some_and(|pgid| self.session_has_pgid(sid, pgid)) {
            return;
        }
        let replacement = self
            .groups
            .values()
            .find(|group| group.sid == sid)
            .map(|group| group.pgid);
        match replacement {
            Some(pgid) => {
                self.foreground_pgid_by_sid.insert(sid, pgid);
            }
            None => {
                let _ = self.foreground_pgid_by_sid.remove(&sid);
            }
        }
    }

    pub(in crate::starnix) fn private_futex_key(
        &self,
        task_id: i32,
        addr: u64,
    ) -> Result<LinuxFutexKey, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        Ok(LinuxFutexKey::Private { tgid, addr })
    }

    pub(in crate::starnix) const fn private_futex_key_for_tgid(
        tgid: i32,
        addr: u64,
    ) -> LinuxFutexKey {
        LinuxFutexKey::Private { tgid, addr }
    }

    pub(in crate::starnix) fn enqueue_futex_waiter(
        &mut self,
        key: LinuxFutexKey,
        waiter: LinuxFutexWaiter,
    ) {
        self.futex_waiters.entry(key).or_default().push_back(waiter);
    }

    pub(in crate::starnix) fn remove_task_from_futex_queue(
        &mut self,
        task_id: i32,
        key: LinuxFutexKey,
    ) {
        let remove_key = match self.futex_waiters.get_mut(&key) {
            Some(queue) => {
                if let Some(index) = queue.iter().position(|queued| queued.task_id == task_id) {
                    let _ = queue.remove(index);
                }
                queue.is_empty()
            }
            None => false,
        };
        if remove_key {
            let _ = self.futex_waiters.remove(&key);
        }
    }

    pub(in crate::starnix) fn take_futex_waiter(
        &mut self,
        key: LinuxFutexKey,
        wake_mask: u32,
    ) -> Option<LinuxFutexWaiter> {
        let mut queue = self.futex_waiters.remove(&key)?;
        let mut kept = VecDeque::with_capacity(queue.len());
        let mut chosen = None;
        while let Some(waiter) = queue.pop_front() {
            let live = self.tasks.get(&waiter.task_id).is_some_and(|task| {
                matches!(task.state, TaskState::Waiting(wait) if wait.futex_key() == Some(key))
            });
            if !live {
                continue;
            }
            if chosen.is_none() && (waiter.bitset & wake_mask) != 0 {
                chosen = Some(waiter);
                continue;
            }
            kept.push_back(waiter);
        }
        if !kept.is_empty() {
            self.futex_waiters.insert(key, kept);
        }
        chosen
    }

    pub(in crate::starnix) fn resume_futex_waiter(
        &mut self,
        task_id: i32,
        result: u64,
    ) -> Result<(), zx_status_t> {
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let TaskState::Waiting(wait) = task.state else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if wait.futex_key().is_none() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let sidecar = task.carrier.sidecar_vmo;
        task.state = TaskState::Running;
        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        complete_syscall(&mut stop_state, result)?;
        self.writeback_and_resume(task_id, &stop_state)
    }

    pub(in crate::starnix) fn wake_futex_waiters(
        &mut self,
        key: LinuxFutexKey,
        wake_count: usize,
        wake_mask: u32,
    ) -> Result<u64, zx_status_t> {
        let mut woke = 0u64;
        for _ in 0..wake_count {
            let Some(waiter) = self.take_futex_waiter(key, wake_mask) else {
                break;
            };
            self.resume_futex_waiter(waiter.task_id, 0)?;
            woke = woke.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        Ok(woke)
    }

    pub(in crate::starnix) fn requeue_futex_waiters(
        &mut self,
        source: LinuxFutexKey,
        target: LinuxFutexKey,
        wake_count: usize,
        requeue_count: usize,
    ) -> Result<u64, zx_status_t> {
        let woke = self.wake_futex_waiters(source, wake_count, LINUX_FUTEX_BITSET_MATCH_ANY)?;
        for _ in 0..requeue_count {
            let Some(waiter) = self.take_futex_waiter(source, LINUX_FUTEX_BITSET_MATCH_ANY) else {
                break;
            };
            let task = self
                .tasks
                .get_mut(&waiter.task_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let TaskState::Waiting(ref mut wait) = task.state else {
                return Err(ZX_ERR_BAD_STATE);
            };
            *wait = WaitState {
                restartable: wait.restartable,
                kind: WaitKind::Futex { key: target },
            };
            self.enqueue_futex_waiter(target, waiter);
        }
        Ok(woke)
    }

    pub(in crate::starnix) fn handle_syscall(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        match stop_state.regs.rax {
            LINUX_SYSCALL_READ => self.sys_read(task_id, stop_state),
            LINUX_SYSCALL_WRITE => self.sys_write(task_id, stop_state, stdout),
            LINUX_SYSCALL_READV => self.sys_readv(task_id, stop_state),
            LINUX_SYSCALL_WRITEV => self.sys_writev(task_id, stop_state, stdout),
            LINUX_SYSCALL_SENDMSG => self.sys_sendmsg(task_id, stop_state),
            LINUX_SYSCALL_RECVMSG => self.sys_recvmsg(task_id, stop_state),
            LINUX_SYSCALL_LSEEK => self.sys_lseek(task_id, stop_state),
            LINUX_SYSCALL_PREAD64 => self.sys_pread64(task_id, stop_state),
            LINUX_SYSCALL_PWRITE64 => self.sys_pwrite64(task_id, stop_state),
            LINUX_SYSCALL_GETPID => self.sys_getpid(task_id, stop_state),
            LINUX_SYSCALL_GETTID => self.sys_gettid(task_id, stop_state),
            LINUX_SYSCALL_GETPPID => self.sys_getppid(task_id, stop_state),
            LINUX_SYSCALL_GETUID => self.sys_getuid(stop_state),
            LINUX_SYSCALL_GETGID => self.sys_getgid(stop_state),
            LINUX_SYSCALL_GETEUID => self.sys_geteuid(stop_state),
            LINUX_SYSCALL_GETEGID => self.sys_getegid(stop_state),
            LINUX_SYSCALL_ARCH_PRCTL => self.sys_arch_prctl(task_id, stop_state),
            LINUX_SYSCALL_SET_TID_ADDRESS => self.sys_set_tid_address(task_id, stop_state),
            LINUX_SYSCALL_GETPGRP => self.sys_getpgrp(task_id, stop_state),
            LINUX_SYSCALL_GETPGID => self.sys_getpgid(task_id, stop_state),
            LINUX_SYSCALL_GETSID => self.sys_getsid(task_id, stop_state),
            LINUX_SYSCALL_SETPGID => self.sys_setpgid(task_id, stop_state),
            LINUX_SYSCALL_SETSID => self.sys_setsid(task_id, stop_state),
            LINUX_SYSCALL_UNAME => self.sys_uname(task_id, stop_state),
            LINUX_SYSCALL_GETRANDOM => self.sys_getrandom(task_id, stop_state),
            LINUX_SYSCALL_READLINK => self.sys_readlink(task_id, stop_state),
            LINUX_SYSCALL_READLINKAT => self.sys_readlinkat(task_id, stop_state),
            LINUX_SYSCALL_ACCESS => self.sys_access(task_id, stop_state),
            LINUX_SYSCALL_FACCESSAT => self.sys_faccessat(task_id, stop_state),
            LINUX_SYSCALL_FACCESSAT2 => self.sys_faccessat2(task_id, stop_state),
            LINUX_SYSCALL_STATX => self.sys_statx(task_id, stop_state),
            LINUX_SYSCALL_PRLIMIT64 => self.sys_prlimit64(task_id, stop_state),
            LINUX_SYSCALL_SOCKETPAIR => self.sys_socketpair(task_id, stop_state),
            LINUX_SYSCALL_FUTEX => self.sys_futex(task_id, stop_state),
            LINUX_SYSCALL_SET_ROBUST_LIST => self.sys_set_robust_list(task_id, stop_state),
            LINUX_SYSCALL_GET_ROBUST_LIST => self.sys_get_robust_list(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_CREATE => self.sys_timerfd_create(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_SETTIME => self.sys_timerfd_settime(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_GETTIME => self.sys_timerfd_gettime(stop_state),
            LINUX_SYSCALL_SIGNALFD4 => self.sys_signalfd4(task_id, stop_state),
            LINUX_SYSCALL_EVENTFD2 => self.sys_eventfd2(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_WAIT => self.sys_epoll_wait(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_CTL => self.sys_epoll_ctl(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_CREATE1 => self.sys_epoll_create1(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGACTION => self.sys_rt_sigaction(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGPROCMASK => self.sys_rt_sigprocmask(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGRETURN => self.sys_rt_sigreturn(task_id, stop_state),
            LINUX_SYSCALL_CLONE => self.sys_clone(task_id, stop_state),
            LINUX_SYSCALL_FORK => self.sys_fork(task_id, stop_state),
            LINUX_SYSCALL_EXECVE => self.sys_execve(task_id, stop_state),
            LINUX_SYSCALL_WAIT4 => self.sys_wait4(task_id, stop_state),
            LINUX_SYSCALL_KILL => self.sys_kill(task_id, stop_state, stdout),
            LINUX_SYSCALL_TGKILL => self.sys_tgkill(stop_state, stdout),
            LINUX_SYSCALL_PIDFD_SEND_SIGNAL => {
                self.sys_pidfd_send_signal(task_id, stop_state, stdout)
            }
            LINUX_SYSCALL_PIDFD_OPEN => self.sys_pidfd_open(task_id, stop_state),
            LINUX_SYSCALL_OPENAT => self.sys_openat(task_id, stop_state),
            LINUX_SYSCALL_NEWFSTATAT => self.sys_newfstatat(task_id, stop_state),
            _ => {
                let session = self
                    .tasks
                    .get(&task_id)
                    .map(|task| task.carrier.session_handle)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                emulate_common_syscall(session, stop_state, resources, stdout)
            }
        }
    }

    pub(in crate::starnix) fn lookup_socket_keys(
        &self,
        tgid: i32,
        fd: i32,
    ) -> Result<(LinuxFileDescriptionKey, LinuxFileDescriptionKey), zx_status_t> {
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        let key = file_description_key(entry.description());
        let Some(peer_key) = self.unix_socket_peers.get(&key).copied() else {
            return Err(ZX_ERR_NOT_SUPPORTED);
        };
        Ok((key, peer_key))
    }

    pub(in crate::starnix) fn peek_socket_rights(
        &self,
        key: LinuxFileDescriptionKey,
    ) -> Option<&PendingScmRights> {
        self.unix_socket_rights.get(&key).and_then(VecDeque::front)
    }

    pub(in crate::starnix) fn take_socket_rights(
        &mut self,
        key: LinuxFileDescriptionKey,
    ) -> Option<PendingScmRights> {
        let rights = self
            .unix_socket_rights
            .get_mut(&key)
            .and_then(VecDeque::pop_front);
        if self
            .unix_socket_rights
            .get(&key)
            .is_some_and(VecDeque::is_empty)
        {
            let _ = self.unix_socket_rights.remove(&key);
        }
        rights
    }

    pub(in crate::starnix) fn fd_wait_policy(
        &self,
        task_id: i32,
        fd: i32,
    ) -> Result<FdWaitPolicy, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let resources = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .resources
            .as_ref()
            .ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        Ok(FdWaitPolicy {
            nonblock: entry.description().flags().contains(OpenFlags::NONBLOCK),
            wait_interest: resources.fs.fd_table.wait_interest(fd)?,
        })
    }

    pub(in crate::starnix) fn fd_wait_policy_for_op(
        &self,
        task_id: i32,
        fd: i32,
        op: FdWaitOp,
    ) -> Result<FdWaitPolicy, zx_status_t> {
        let mut policy = self.fd_wait_policy(task_id, fd)?;
        policy.wait_interest = policy.wait_interest.and_then(|interest| {
            let filtered = filter_wait_interest(interest, op);
            (filtered.signals() != 0).then_some(filtered)
        });
        Ok(policy)
    }

    pub(in crate::starnix) fn arm_fd_wait(
        &mut self,
        task_id: i32,
        wait: WaitState,
        wait_interest: WaitSpec,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        self.begin_async_wait(task_id, wait, wait_interest, stop_state)
    }
}

pub(in crate::starnix) fn file_description_key(
    description: &Arc<OpenFileDescription>,
) -> LinuxFileDescriptionKey {
    LinuxFileDescriptionKey(Arc::as_ptr(description) as usize)
}
