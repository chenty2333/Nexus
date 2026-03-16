use super::super::*;

impl StarnixKernel {
    pub(in crate::starnix) fn read_sys_iovecs(
        &self,
        task_id: i32,
        iov_addr: u64,
        iov_len: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<Option<Vec<LinuxIovec>>, zx_status_t> {
        if iov_len < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(None);
        }
        let iov_len = usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        match read_guest_iovecs(session, iov_addr, iov_len) {
            Ok(iovecs) => Ok(Some(iovecs)),
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                Ok(None)
            }
        }
    }

    pub(in crate::starnix) fn sys_sendmsg(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let msg_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        if flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let msg = match read_guest_msghdr(session, msg_addr) {
            Ok(msg) => msg,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if msg.name_addr != 0 || msg.name_len != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let iovecs = match read_guest_iovecs(session, msg.iov_addr, msg.iov_len) {
            Ok(iovecs) => iovecs,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let payload = match read_guest_iovec_payload(session, &iovecs) {
            Ok(payload) => payload,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let (_socket_key, peer_key) = match self.lookup_socket_keys(tgid, fd) {
            Ok(keys) => keys,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Write)?;
        let parsed_rights = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match parse_scm_rights(session, &resources.fs.fd_table, &msg) {
                Ok(rights) => rights,
                Err(status) => {
                    complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if parsed_rights
            .as_ref()
            .is_some_and(|rights| !rights.descriptions.is_empty() && payload.is_empty())
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.write(fd, &payload) {
                Ok(actual) => WriteAttempt::Ready(actual),
                Err(ZX_ERR_SHOULD_WAIT) => WriteAttempt::WouldBlock(wait_policy),
                Err(status) => WriteAttempt::Err(status),
            }
        };

        match attempt {
            WriteAttempt::Ready(actual) => {
                if actual != 0
                    && let Some(rights) =
                        parsed_rights.filter(|rights| !rights.descriptions.is_empty())
                {
                    self.unix_socket_rights
                        .entry(peer_key)
                        .or_default()
                        .push_back(rights);
                }
                complete_syscall(
                    stop_state,
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                )?;
                Ok(SyscallAction::Resume)
            }
            WriteAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::MsgSend {
                        fd,
                        msg_addr,
                        flags,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            WriteAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    pub(in crate::starnix) fn sys_recvmsg(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let msg_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        if flags & !LINUX_MSG_CMSG_CLOEXEC != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let msg = match read_guest_msghdr(session, msg_addr) {
            Ok(msg) => msg,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if msg.name_addr != 0 || msg.name_len != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let iovecs = match read_guest_iovecs(session, msg.iov_addr, msg.iov_len) {
            Ok(iovecs) => iovecs,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let total_len = total_iovec_len(&iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let (socket_key, _) = match self.lookup_socket_keys(tgid, fd) {
            Ok(keys) => keys,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if let Some(rights) = self.peek_socket_rights(socket_key) {
            let required = scm_rights_control_bytes(rights.descriptions.len())?;
            if msg.control_len < required {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
        }

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(total_len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        payload.resize(total_len, 0);
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.read(fd, &mut payload) {
                Ok(actual) => ReadAttempt::Ready {
                    bytes: payload,
                    actual,
                },
                Err(ZX_ERR_SHOULD_WAIT) => ReadAttempt::WouldBlock(wait_policy),
                Err(ZX_ERR_PEER_CLOSED) => ReadAttempt::Ready {
                    bytes: payload,
                    actual: 0,
                },
                Err(status) => ReadAttempt::Err(status),
            }
        };

        match attempt {
            ReadAttempt::Ready { bytes, actual } => {
                let rights_bundle = if actual != 0 {
                    self.peek_socket_rights(socket_key).cloned()
                } else {
                    None
                };
                let received_flags = if (flags & LINUX_MSG_CMSG_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                let mut installed_fds = Vec::new();
                let control_bytes = if let Some(rights) = rights_bundle.as_ref() {
                    let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                    installed_fds
                        .try_reserve_exact(rights.descriptions.len())
                        .map_err(|_| ZX_ERR_NO_MEMORY)?;
                    for description in &rights.descriptions {
                        installed_fds.push(
                            resources
                                .fs
                                .fd_table
                                .install(Arc::clone(description), received_flags),
                        );
                    }
                    Some(encode_scm_rights_control(&installed_fds)?)
                } else {
                    None
                };
                let guest_result = (|| -> Result<u64, zx_status_t> {
                    let wrote = write_guest_iovec_payload(session, &iovecs, &bytes[..actual])?;
                    if wrote != actual {
                        return Err(ZX_ERR_IO_DATA_INTEGRITY);
                    }
                    if let Some(control) = control_bytes.as_ref() {
                        write_guest_bytes(session, msg.control_addr, control)?;
                        write_guest_recv_msghdr(session, msg_addr, control.len(), 0)?;
                    } else {
                        write_guest_recv_msghdr(session, msg_addr, 0, 0)?;
                    }
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)
                })();
                match guest_result {
                    Ok(result) => {
                        if rights_bundle.is_some() {
                            let _ = self.take_socket_rights(socket_key);
                        }
                        complete_syscall(stop_state, result)?;
                    }
                    Err(status) => {
                        if let Some(group) = self.groups.get_mut(&tgid)
                            && let Some(resources) = group.resources.as_mut()
                        {
                            for fd in installed_fds {
                                let _ = resources.fs.fd_table.close(fd);
                            }
                        }
                        complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                    }
                }
                Ok(SyscallAction::Resume)
            }
            ReadAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::MsgRecv {
                        fd,
                        msg_addr,
                        flags,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            ReadAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    pub(in crate::starnix) fn sys_socketpair(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let domain = stop_state.regs.rdi;
        let socket_type = stop_state.regs.rsi;
        let protocol = stop_state.regs.rdx;
        let pair_addr = stop_state.regs.r10;
        if domain != LINUX_AF_UNIX || socket_type != LINUX_SOCK_STREAM || protocol != 0 {
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

        let mut left = ZX_HANDLE_INVALID;
        let mut right = ZX_HANDLE_INVALID;
        let status = zx_socket_create(0, &mut left, &mut right);
        if status != ZX_OK {
            complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            return Ok(SyscallAction::Resume);
        }

        let created = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let left_fd = resources.fs.fd_table.open(
                Arc::new(SocketFd::new(left)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            );
            let right_fd = resources.fs.fd_table.open(
                Arc::new(SocketFd::new(right)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            );
            match (left_fd, right_fd) {
                (Ok(left_fd), Ok(right_fd)) => {
                    let left_key = resources
                        .fs
                        .fd_table
                        .get(left_fd)
                        .map(|entry| file_description_key(entry.description()))
                        .ok_or(ZX_ERR_BAD_STATE)?;
                    let right_key = resources
                        .fs
                        .fd_table
                        .get(right_fd)
                        .map(|entry| file_description_key(entry.description()))
                        .ok_or(ZX_ERR_BAD_STATE)?;
                    Ok((left_fd, right_fd, left_key, right_key))
                }
                (Ok(left_fd), Err(status)) => {
                    let _ = resources.fs.fd_table.close(left_fd);
                    Err(status)
                }
                (Err(status), _) => Err(status),
            }
        };

        match created {
            Ok((left_fd, right_fd, left_key, right_key)) => {
                if let Err(status) = write_guest_fd_pair(session, pair_addr, left_fd, right_fd) {
                    if let Some(group) = self.groups.get_mut(&tgid)
                        && let Some(resources) = group.resources.as_mut()
                    {
                        let _ = resources.fs.fd_table.close(left_fd);
                        let _ = resources.fs.fd_table.close(right_fd);
                    }
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
                self.unix_socket_peers.insert(left_key, right_key);
                self.unix_socket_peers.insert(right_key, left_key);
                complete_syscall(stop_state, 0)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }
}
