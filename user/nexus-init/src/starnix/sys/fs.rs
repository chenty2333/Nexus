use super::super::*;

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
}
