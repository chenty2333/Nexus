use super::super::fs::tty::{
    LINUX_TIOCGPGRP, LINUX_TIOCNOTTY, LINUX_TIOCSCTTY, LINUX_TIOCSPGRP, PtySlaveFd,
    tty_endpoint_identity,
};
use super::super::*;

fn write_linux_uname_field(field: &mut [u8], value: &str) {
    let limit = field.len().saturating_sub(1);
    let actual = value.len().min(limit);
    field[..actual].copy_from_slice(&value.as_bytes()[..actual]);
}

fn build_linux_uname_bytes() -> [u8; LINUX_UTSNAME_BYTES] {
    let mut bytes = [0u8; LINUX_UTSNAME_BYTES];
    write_linux_uname_field(&mut bytes[0..LINUX_UTSNAME_FIELD_BYTES], "NexusOS");
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES..LINUX_UTSNAME_FIELD_BYTES * 2],
        "nexus",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 2..LINUX_UTSNAME_FIELD_BYTES * 3],
        "0.1",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 3..LINUX_UTSNAME_FIELD_BYTES * 4],
        "#1 Axle",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 4..LINUX_UTSNAME_FIELD_BYTES * 5],
        "x86_64",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 5..LINUX_UTSNAME_BYTES],
        "localdomain",
    );
    bytes
}

impl StarnixKernel {
    pub(in crate::starnix) fn sys_readlink(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let path_addr = stop_state.regs.rdi;
        let buf_addr = stop_state.regs.rsi;
        let buf_len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        self.sys_readlink_common(
            task_id,
            LINUX_AT_FDCWD,
            path_addr,
            buf_addr,
            buf_len,
            stop_state,
        )
    }

    pub(in crate::starnix) fn sys_readlinkat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let buf_addr = stop_state.regs.rdx;
        let buf_len = usize::try_from(stop_state.regs.r10).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        self.sys_readlink_common(task_id, dirfd, path_addr, buf_addr, buf_len, stop_state)
    }

    fn sys_readlink_common(
        &mut self,
        task_id: i32,
        dirfd: i32,
        path_addr: u64,
        buf_addr: u64,
        buf_len: usize,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        if buf_len == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let result = match self.resolve_readlink_target(task_id, dirfd, path.as_str()) {
            Ok(target) => {
                let bytes = target.as_bytes();
                let actual = bytes.len().min(buf_len);
                match write_guest_bytes(session, buf_addr, &bytes[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                }
            }
            Err(status) => linux_errno(map_readlink_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_access(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let mode = stop_state.regs.rsi;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = read_guest_c_string(session, stop_state.regs.rdi, LINUX_PATH_MAX).ok();
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let _ = path;
            resources.accessat(session, LINUX_AT_FDCWD, stop_state.regs.rdi, mode, 0)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_faccessat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let mode = stop_state.regs.rdx;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.accessat(session, dirfd, stop_state.regs.rsi, mode, 0)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_faccessat2(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let mode = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.accessat(session, dirfd, stop_state.regs.rsi, mode, flags)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn lookup_stat_metadata(
        &self,
        task_id: i32,
        dirfd: i32,
        path: &str,
        flags: u64,
    ) -> Result<LinuxStatMetadata, zx_status_t> {
        let allowed = LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        if path.is_empty() {
            if (flags & LINUX_AT_EMPTY_PATH) == 0 {
                return Err(ZX_ERR_NOT_FOUND);
            }
            return resources.stat_metadata_for_fd(dirfd);
        }
        if path.starts_with("/proc") {
            let ops = self.open_proc_absolute(task_id, path)?;
            return stat_metadata_for_ops(ops.as_ref());
        }
        resources.stat_metadata_at_path(dirfd, path, flags)
    }

    pub(in crate::starnix) fn sys_statx(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        let mask = linux_arg_u32(stop_state.regs.r10);
        let statx_addr = stop_state.regs.r8;
        let allowed_flags = LINUX_AT_EMPTY_PATH
            | LINUX_AT_SYMLINK_NOFOLLOW
            | LINUX_AT_STATX_FORCE_SYNC
            | LINUX_AT_STATX_DONT_SYNC;
        if (flags & !allowed_flags) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let path_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let result = match self.lookup_stat_metadata(task_id, dirfd, path.as_str(), path_flags) {
            Ok(metadata) => write_guest_statx(session, statx_addr, metadata, None, mask)?,
            Err(status) => linux_errno(map_fd_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_openat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        let mode = stop_state.regs.r10;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        if path.is_empty() {
            complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
            return Ok(SyscallAction::Resume);
        }
        let result = if path.starts_with("/proc") {
            let (open_flags, fd_flags) = decode_open_flags(flags);
            match self.open_proc_absolute(task_id, path.as_str()) {
                Ok(ops) => {
                    let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                    match resources.fs.fd_table.open(ops, open_flags, fd_flags) {
                        Ok(fd) => fd as u64,
                        Err(status) => linux_errno(map_fd_status_to_errno(status)),
                    }
                }
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            }
        } else {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let _ = path;
            resources.openat(session, dirfd, path_addr, flags, mode)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_ioctl(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let request = stop_state.regs.rsi;
        let arg = stop_state.regs.rdx;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;

        let ops = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            Arc::clone(
                resources
                    .fs
                    .fd_table
                    .get(fd)
                    .ok_or(ZX_ERR_BAD_HANDLE)?
                    .description()
                    .ops(),
            )
        };

        let result = match request {
            LINUX_TIOCGPGRP => {
                let Some((tty_id, is_slave)) = tty_endpoint_identity(ops.as_ref()) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOTTY))?;
                    return Ok(SyscallAction::Resume);
                };
                let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                if !is_slave || resources.fs.controlling_tty_id() != Some(tty_id) {
                    linux_errno(LINUX_ENOTTY)
                } else {
                    let sid = self.task_sid(task_id)?;
                    let pgid = self
                        .foreground_pgid(sid)
                        .unwrap_or_else(|| self.groups.get(&tgid).map_or(tgid, |group| group.pgid));
                    match write_guest_u32(session, arg, pgid as u32) {
                        Ok(()) => 0,
                        Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                    }
                }
            }
            LINUX_TIOCSPGRP => {
                let Some((tty_id, is_slave)) = tty_endpoint_identity(ops.as_ref()) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOTTY))?;
                    return Ok(SyscallAction::Resume);
                };
                let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                if !is_slave || resources.fs.controlling_tty_id() != Some(tty_id) {
                    linux_errno(LINUX_ENOTTY)
                } else {
                    if let Some(action) =
                        self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Write, stop_state)?
                    {
                        return Ok(action);
                    }
                    let sid = self.task_sid(task_id)?;
                    let pgid = match read_guest_u32(session, arg) {
                        Ok(value) => value as i32,
                        Err(status) => {
                            complete_syscall(
                                stop_state,
                                linux_errno(map_guest_memory_status_to_errno(status)),
                            )?;
                            return Ok(SyscallAction::Resume);
                        }
                    };
                    if !self.session_has_pgid(sid, pgid) {
                        linux_errno(LINUX_EPERM)
                    } else {
                        self.foreground_pgid_by_sid.insert(sid, pgid);
                        0
                    }
                }
            }
            LINUX_TIOCSCTTY => {
                let Some((_tty_id, is_slave)) = tty_endpoint_identity(ops.as_ref()) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOTTY))?;
                    return Ok(SyscallAction::Resume);
                };
                if !is_slave {
                    linux_errno(LINUX_ENOTTY)
                } else {
                    let sid = self.task_sid(task_id)?;
                    let caller_pgid = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?.pgid;
                    if sid != tgid || caller_pgid != tgid {
                        linux_errno(LINUX_EPERM)
                    } else if let Some(slave) = ops.as_any().downcast_ref::<PtySlaveFd>() {
                        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                        let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                        resources
                            .fs
                            .set_controlling_tty(Some(Arc::new(slave.clone())));
                        self.foreground_pgid_by_sid.insert(sid, caller_pgid);
                        0
                    } else {
                        linux_errno(LINUX_ENOTTY)
                    }
                }
            }
            LINUX_TIOCNOTTY => {
                let Some((tty_id, is_slave)) = tty_endpoint_identity(ops.as_ref()) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOTTY))?;
                    return Ok(SyscallAction::Resume);
                };
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                if !is_slave || resources.fs.controlling_tty_id() != Some(tty_id) {
                    linux_errno(LINUX_ENOTTY)
                } else {
                    resources.fs.set_controlling_tty(None);
                    0
                }
            }
            _ => {
                let result = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    resources.fs.fd_table.ioctl(fd, session, request, arg)
                };
                match result {
                    Ok(value) => value,
                    Err(status) => linux_errno(map_ioctl_status_to_errno(status)),
                }
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_mkdir(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.mkdirat(
                session,
                LINUX_AT_FDCWD,
                stop_state.regs.rdi,
                stop_state.regs.rsi,
            )?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_mkdirat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.mkdirat(session, dirfd, stop_state.regs.rsi, stop_state.regs.rdx)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_unlink(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.unlinkat(session, LINUX_AT_FDCWD, stop_state.regs.rdi, 0)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_rmdir(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.unlinkat(
                session,
                LINUX_AT_FDCWD,
                stop_state.regs.rdi,
                LINUX_AT_REMOVEDIR,
            )?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_unlinkat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let flags = stop_state.regs.rdx;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.unlinkat(session, dirfd, stop_state.regs.rsi, flags)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_newfstatat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let stat_addr = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let result = match self.lookup_stat_metadata(task_id, dirfd, path.as_str(), flags) {
            Ok(metadata) => write_guest_stat(session, stat_addr, metadata, None)?,
            Err(status) => linux_errno(map_fd_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_read(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;

        let signalfd = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.fs.fd_table.get(fd).and_then(|entry| {
                entry
                    .description()
                    .ops()
                    .as_ref()
                    .as_any()
                    .downcast_ref::<SignalFd>()
                    .cloned()
            })
        };
        if let Some(signalfd) = signalfd {
            return self.sys_read_signalfd(task_id, fd, buf, len, stop_state, signalfd);
        }

        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Read, stop_state)?
        {
            return Ok(action);
        }

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(len, 0);
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.read(fd, &mut bytes) {
                Ok(actual) => ReadAttempt::Ready { bytes, actual },
                Err(ZX_ERR_SHOULD_WAIT) => ReadAttempt::WouldBlock(wait_policy),
                Err(ZX_ERR_PEER_CLOSED) => ReadAttempt::Ready { bytes, actual: 0 },
                Err(status) => ReadAttempt::Err(status),
            }
        };

        match attempt {
            ReadAttempt::Ready { bytes, actual } => {
                let result = match write_guest_bytes(session, buf, &bytes[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                };
                complete_syscall(stop_state, result)?;
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
                    kind: WaitKind::FdRead {
                        io_kind: FdReadKind::Read,
                        fd,
                        buf,
                        len,
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

    pub(in crate::starnix) fn sys_write(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let bytes = match read_guest_bytes(session, buf, len) {
            Ok(bytes) => bytes,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Write, stop_state)?
        {
            return Ok(action);
        }
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Write)?;
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.write(fd, &bytes) {
                Ok(actual) => WriteAttempt::Ready(actual),
                Err(ZX_ERR_SHOULD_WAIT) => WriteAttempt::WouldBlock(wait_policy),
                Err(status) => WriteAttempt::Err(status),
            }
        };

        match attempt {
            WriteAttempt::Ready(actual) => {
                if fd == 1 || fd == 2 {
                    stdout.extend_from_slice(&bytes[..actual]);
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
                    kind: WaitKind::FdWrite {
                        io_kind: FdWriteKind::Write,
                        fd,
                        buf,
                        len,
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

    pub(in crate::starnix) fn sys_readv(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let iov_addr = stop_state.regs.rsi;
        let iov_len = linux_arg_i32(stop_state.regs.rdx);
        let iovecs = match self.read_sys_iovecs(task_id, iov_addr, iov_len, stop_state)? {
            Some(iovecs) => iovecs,
            None => return Ok(SyscallAction::Resume),
        };
        let total_len = total_iovec_len(&iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if total_len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total_len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(total_len, 0);
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.read(fd, &mut bytes) {
                Ok(actual) => ReadAttempt::Ready { bytes, actual },
                Err(ZX_ERR_SHOULD_WAIT) => ReadAttempt::WouldBlock(wait_policy),
                Err(ZX_ERR_PEER_CLOSED) => ReadAttempt::Ready { bytes, actual: 0 },
                Err(status) => ReadAttempt::Err(status),
            }
        };

        match attempt {
            ReadAttempt::Ready { bytes, actual } => {
                let result = match write_guest_iovec_payload(session, &iovecs, &bytes[..actual]) {
                    Ok(wrote) => u64::try_from(wrote).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                };
                complete_syscall(stop_state, result)?;
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
                    kind: WaitKind::FdRead {
                        io_kind: FdReadKind::Readv,
                        fd,
                        buf: iov_addr,
                        len: usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?,
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

    pub(in crate::starnix) fn sys_writev(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let iov_addr = stop_state.regs.rsi;
        let iov_len = linux_arg_i32(stop_state.regs.rdx);
        let iovecs = match self.read_sys_iovecs(task_id, iov_addr, iov_len, stop_state)? {
            Some(iovecs) => iovecs,
            None => return Ok(SyscallAction::Resume),
        };
        let bytes = match read_guest_iovec_payload(
            self.tasks
                .get(&task_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .carrier
                .session_handle,
            &iovecs,
        ) {
            Ok(bytes) => bytes,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Write, stop_state)?
        {
            return Ok(action);
        }
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Write)?;
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.write(fd, &bytes) {
                Ok(actual) => WriteAttempt::Ready(actual),
                Err(ZX_ERR_SHOULD_WAIT) => WriteAttempt::WouldBlock(wait_policy),
                Err(status) => WriteAttempt::Err(status),
            }
        };

        match attempt {
            WriteAttempt::Ready(actual) => {
                if fd == 1 || fd == 2 {
                    stdout.extend_from_slice(&bytes[..actual]);
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
                    kind: WaitKind::FdWrite {
                        io_kind: FdWriteKind::Writev,
                        fd,
                        buf: iov_addr,
                        len: usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?,
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

    pub(in crate::starnix) fn sys_lseek(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let offset = i64::from_ne_bytes(stop_state.regs.rsi.to_ne_bytes());
        let whence = linux_arg_i32(stop_state.regs.rdx);
        let origin = match whence {
            LINUX_SEEK_SET => SeekOrigin::Start,
            LINUX_SEEK_CUR => SeekOrigin::Current,
            LINUX_SEEK_END => SeekOrigin::End,
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let result = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fs.fd_table.seek(fd, origin, offset) {
                Ok(new_offset) => new_offset,
                Err(status) => linux_errno(map_seek_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_pread64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf_addr = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let offset = i64::from_ne_bytes(stop_state.regs.r10.to_ne_bytes());
        if offset < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        buffer.resize(len, 0);
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.pread(fd, offset as u64, &mut buffer) {
                Ok(actual) => match write_guest_bytes(session, buf_addr, &buffer[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                },
                Err(status) => linux_errno(map_rw_at_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_pwrite64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf_addr = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let offset = i64::from_ne_bytes(stop_state.regs.r10.to_ne_bytes());
        if offset < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let bytes = match read_guest_bytes(session, buf_addr, len) {
            Ok(bytes) => bytes,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.pwrite(fd, offset as u64, &bytes) {
                Ok(actual) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                Err(status) => linux_errno(map_rw_at_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_uname(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let addr = stop_state.regs.rdi;
        let bytes = build_linux_uname_bytes();
        let result = match write_guest_bytes(session, addr, &bytes) {
            Ok(()) => 0,
            Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    pub(in crate::starnix) fn sys_getrandom(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let buf_addr = stop_state.regs.rdi;
        let len = usize::try_from(stop_state.regs.rsi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let flags = stop_state.regs.rdx;
        if (flags & !LINUX_GRND_NONBLOCK) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(len, 0);
        fill_random_bytes(&mut self.random_state, &mut bytes);
        let result = match write_guest_bytes(session, buf_addr, &bytes) {
            Ok(()) => u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }
}
