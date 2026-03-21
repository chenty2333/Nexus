use super::super::*;

fn decode_socket_open_flags(socket_type: u64) -> (u64, OpenFlags, FdFlags) {
    let mut open_flags = OpenFlags::READABLE | OpenFlags::WRITABLE;
    if (socket_type & LINUX_SOCK_NONBLOCK) != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let mut fd_flags = FdFlags::empty();
    if (socket_type & LINUX_SOCK_CLOEXEC) != 0 {
        fd_flags |= FdFlags::CLOEXEC;
    }
    let base_type = socket_type & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
    (base_type, open_flags, fd_flags)
}

fn read_loopback_sockaddr(
    session: zx_handle_t,
    addr: u64,
    len: usize,
) -> Result<LoopbackSocketAddr, zx_status_t> {
    if addr == 0 || len < LINUX_SOCKADDR_IN_BYTES {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let bytes = read_guest_bytes(session, addr, LINUX_SOCKADDR_IN_BYTES)?;
    let raw = bytes
        .get(..LINUX_SOCKADDR_IN_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let family = u16::from_ne_bytes(raw[0..2].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
    if u64::from(family) != LINUX_AF_INET {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    Ok(LoopbackSocketAddr {
        port: u16::from_be_bytes(raw[2..4].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        ip: u32::from_be_bytes(raw[4..8].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
    })
}

fn encode_loopback_sockaddr(addr: LoopbackSocketAddr) -> [u8; LINUX_SOCKADDR_IN_BYTES] {
    let mut bytes = [0u8; LINUX_SOCKADDR_IN_BYTES];
    bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&addr.port.to_be_bytes());
    bytes[4..8].copy_from_slice(&addr.ip.to_be_bytes());
    bytes
}

fn write_loopback_sockaddr(
    session: zx_handle_t,
    addr_addr: u64,
    addrlen_addr: u64,
    addr: LoopbackSocketAddr,
) -> Result<(), zx_status_t> {
    if addr_addr == 0 {
        return Ok(());
    }
    if addrlen_addr == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let guest_len = read_guest_u32(session, addrlen_addr)? as usize;
    let encoded = encode_loopback_sockaddr(addr);
    let write_len = guest_len.min(encoded.len());
    write_guest_bytes(session, addr_addr, &encoded[..write_len])?;
    write_guest_u32(session, addrlen_addr, encoded.len() as u32)
}

fn map_sockopt_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_NOT_SUPPORTED => LINUX_EOPNOTSUPP,
        _ => map_fd_status_to_errno(status),
    }
}

impl StarnixKernel {
    fn inet_socket_fd(&self, task_id: i32, fd: i32) -> Result<InetSocketFd, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        entry
            .description()
            .ops()
            .as_any()
            .downcast_ref::<InetSocketFd>()
            .cloned()
            .ok_or(ZX_ERR_NOT_SUPPORTED)
    }

    fn install_inet_socket(
        &mut self,
        task_id: i32,
        socket: InetSocketFd,
        open_flags: OpenFlags,
        fd_flags: FdFlags,
    ) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
        resources
            .fs
            .fd_table
            .open(Arc::new(socket), open_flags, fd_flags)
    }

    pub(in crate::starnix) fn sys_socket(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let domain = stop_state.regs.rdi;
        let socket_type = stop_state.regs.rsi;
        let protocol = linux_arg_i32(stop_state.regs.rdx);
        if domain != LINUX_AF_INET {
            complete_syscall(stop_state, linux_errno(LINUX_EAFNOSUPPORT))?;
            return Ok(SyscallAction::Resume);
        }
        let (base_type, open_flags, fd_flags) = decode_socket_open_flags(socket_type);
        if base_type != LINUX_SOCK_STREAM {
            complete_syscall(stop_state, linux_errno(LINUX_EOPNOTSUPP))?;
            return Ok(SyscallAction::Resume);
        }
        if protocol != 0 && protocol != LINUX_IPPROTO_TCP {
            complete_syscall(stop_state, linux_errno(LINUX_EOPNOTSUPP))?;
            return Ok(SyscallAction::Resume);
        }
        match self.install_inet_socket(task_id, InetSocketFd::new_stream(), open_flags, fd_flags) {
            Ok(fd) => complete_syscall(
                stop_state,
                u64::try_from(fd).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            )?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_bind(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let addr_addr = stop_state.regs.rsi;
        let addr_len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let requested = match read_loopback_sockaddr(session, addr_addr, addr_len) {
            Ok(addr) => addr,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_EAFNOSUPPORT))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.bind(&mut self.loopback_net, requested) {
            Ok(_) => complete_syscall(stop_state, 0)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_listen(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let backlog = linux_arg_i32(stop_state.regs.rsi);
        let backlog = usize::try_from(backlog.max(0)).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.listen(&mut self.loopback_net, backlog) {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_connect(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let addr_addr = stop_state.regs.rsi;
        let addr_len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let remote = match read_loopback_sockaddr(session, addr_addr, addr_len) {
            Ok(addr) => addr,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_EAFNOSUPPORT))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.connect(&mut self.loopback_net, remote) {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(ZX_ERR_BAD_STATE) if socket.getpeername().is_ok() => {
                complete_syscall(stop_state, linux_errno(LINUX_EISCONN))?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_accept(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        stop_state.regs.r10 = 0;
        self.sys_accept4(task_id, stop_state)
    }

    pub(in crate::starnix) fn sys_accept4(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let addr_addr = stop_state.regs.rsi;
        let addrlen_addr = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let allowed_flags = LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC;
        if flags & !allowed_flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;
        match socket.accept() {
            Ok(accepted) => {
                let session = self
                    .tasks
                    .get(&task_id)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .carrier
                    .session_handle;
                let peer_addr = accepted.getpeername()?;
                let (_, open_flags, fd_flags) = decode_socket_open_flags(flags | LINUX_SOCK_STREAM);
                match self.install_inet_socket(task_id, accepted, open_flags, fd_flags) {
                    Ok(new_fd) => {
                        if (addr_addr != 0 || addrlen_addr != 0)
                            && let Err(status) =
                                write_loopback_sockaddr(session, addr_addr, addrlen_addr, peer_addr)
                        {
                            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                            if let Some(group) = self.groups.get_mut(&tgid)
                                && let Some(resources) = group.resources.as_mut()
                            {
                                let _ = resources.fs.fd_table.close(new_fd);
                            }
                            complete_syscall(
                                stop_state,
                                linux_errno(map_guest_memory_status_to_errno(status)),
                            )?;
                            return Ok(SyscallAction::Resume);
                        }
                        complete_syscall(
                            stop_state,
                            u64::try_from(new_fd).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                        )?;
                    }
                    Err(status) => {
                        complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                    }
                }
                Ok(SyscallAction::Resume)
            }
            Err(ZX_ERR_SHOULD_WAIT) => {
                if wait_policy.nonblock || wait_policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::SocketAccept {
                        fd,
                        addr_addr,
                        addrlen_addr,
                        flags,
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
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    pub(in crate::starnix) fn sys_shutdown(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let how = linux_arg_i32(stop_state.regs.rsi);
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.shutdown(how) {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getsockname(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let addr_addr = stop_state.regs.rsi;
        let addrlen_addr = stop_state.regs.rdx;
        if addr_addr == 0 || addrlen_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.getsockname() {
            Ok(addr) => match write_loopback_sockaddr(session, addr_addr, addrlen_addr, addr) {
                Ok(()) => complete_syscall(stop_state, 0)?,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                }
            },
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getpeername(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let addr_addr = stop_state.regs.rsi;
        let addrlen_addr = stop_state.regs.rdx;
        if addr_addr == 0 || addrlen_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.getpeername() {
            Ok(addr) => match write_loopback_sockaddr(session, addr_addr, addrlen_addr, addr) {
                Ok(()) => complete_syscall(stop_state, 0)?,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                }
            },
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_setsockopt(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let level = linux_arg_i32(stop_state.regs.rsi);
        let optname = linux_arg_i32(stop_state.regs.rdx);
        let optval_addr = stop_state.regs.r10;
        let optlen = usize::try_from(stop_state.regs.r8).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let value = match read_guest_bytes(session, optval_addr, optlen) {
            Ok(value) => value,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.setsockopt(level, optname, &value) {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_sockopt_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getsockopt(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let level = linux_arg_i32(stop_state.regs.rsi);
        let optname = linux_arg_i32(stop_state.regs.rdx);
        let optval_addr = stop_state.regs.r10;
        let optlen_addr = stop_state.regs.r8;
        if optval_addr == 0 || optlen_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let socket = match self.inet_socket_fd(task_id, fd) {
            Ok(socket) => socket,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        match socket.getsockopt(level, optname) {
            Ok(value) => {
                let guest_len = match read_guest_u32(session, optlen_addr) {
                    Ok(len) => len as usize,
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                let encoded = value.to_ne_bytes();
                let write_len = guest_len.min(encoded.len());
                match write_guest_bytes(session, optval_addr, &encoded[..write_len]) {
                    Ok(()) => match write_guest_u32(session, optlen_addr, encoded.len() as u32) {
                        Ok(()) => complete_syscall(stop_state, 0)?,
                        Err(status) => {
                            complete_syscall(
                                stop_state,
                                linux_errno(map_guest_memory_status_to_errno(status)),
                            )?;
                        }
                    },
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                    }
                }
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_sockopt_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

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
        let zx_socket_options = match socket_type {
            LINUX_SOCK_STREAM => ZX_SOCKET_STREAM,
            LINUX_SOCK_DGRAM => ZX_SOCKET_DATAGRAM,
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if domain != LINUX_AF_UNIX || protocol != 0 {
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
        let status = zx_socket_create(zx_socket_options, &mut left, &mut right);
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
