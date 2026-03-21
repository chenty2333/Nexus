use super::super::*;
use super::devfs::{DevDirFd, NullFd, ZeroFd};

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxStatMetadata {
    pub(in crate::starnix) mode: u32,
    pub(in crate::starnix) size_bytes: u64,
    pub(in crate::starnix) inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::starnix) enum StdioMode {
    Socket,
    Console,
}

impl StdioMode {
    pub(in crate::starnix) fn from_env(env: &[String]) -> Self {
        env.iter()
            .find_map(|entry| entry.strip_prefix("NEXUS_STARNIX_STDIO="))
            .map_or(Self::Socket, |value| match value {
                "console" => Self::Console,
                _ => Self::Socket,
            })
    }
}

pub(in crate::starnix) struct FsContext {
    pub(in crate::starnix) fd_table: FdTable,
    pub(in crate::starnix) namespace: nexus_io::ProcessNamespace,
    pub(in crate::starnix) directory_offsets: BTreeMap<u64, usize>,
}

pub(in crate::starnix) struct ProcessResources {
    pub(in crate::starnix) process_handle: zx_handle_t,
    pub(in crate::starnix) fs: FsContext,
    pub(in crate::starnix) mm: LinuxMm,
}

impl FsContext {
    fn new(
        stdio_mode: StdioMode,
        stdout_handle: Option<zx_handle_t>,
        namespace: nexus_io::ProcessNamespace,
    ) -> Result<Self, zx_status_t> {
        let mut fd_table = FdTable::new();
        let namespace = match stdio_mode {
            StdioMode::Socket => {
                let stdin_fd = fd_table.open(
                    Arc::new(PseudoNodeFd::new(None)),
                    OpenFlags::READABLE,
                    FdFlags::empty(),
                )?;
                if stdin_fd != 0 {
                    return Err(ZX_ERR_BAD_STATE);
                }
                if let Some(handle) = stdout_handle {
                    let install_result = (|| {
                        install_stdio_fd(&mut fd_table, handle, 1)?;
                        install_stdio_fd(&mut fd_table, handle, 2)?;
                        Ok::<(), zx_status_t>(())
                    })();
                    let _ = zx_handle_close(handle);
                    install_result?;
                }
                namespace
            }
            StdioMode::Console => {
                let tty = Arc::new(ConsoleFd::new());
                let null_fd: Arc<dyn FdOps> = Arc::new(NullFd);
                let zero_fd: Arc<dyn FdOps> = Arc::new(ZeroFd);
                let dev_root: Arc<dyn FdOps> = Arc::new(DevDirFd::new(
                    tty.clone(),
                    Arc::clone(&null_fd),
                    Arc::clone(&zero_fd),
                ));
                let mut mounts = namespace.mounts().clone();
                mounts.insert("/dev", dev_root)?;
                let namespace = nexus_io::ProcessNamespace::new(mounts);
                install_console_stdio_fd(&mut fd_table, tty.clone(), OpenFlags::READABLE, 0)?;
                install_console_stdio_fd(
                    &mut fd_table,
                    tty.clone(),
                    OpenFlags::READABLE | OpenFlags::WRITABLE,
                    1,
                )?;
                install_console_stdio_fd(
                    &mut fd_table,
                    tty,
                    OpenFlags::READABLE | OpenFlags::WRITABLE,
                    2,
                )?;
                if let Some(handle) = stdout_handle {
                    let _ = zx_handle_close(handle);
                }
                namespace
            }
        };
        Ok(Self {
            fd_table,
            namespace,
            directory_offsets: BTreeMap::new(),
        })
    }

    pub(in crate::starnix) fn fork_clone(&self) -> Self {
        Self {
            fd_table: self.fd_table.clone(),
            namespace: self.namespace.clone(),
            directory_offsets: self.directory_offsets.clone(),
        }
    }

    pub(in crate::starnix) fn exec_replace(&self) -> Self {
        let mut fd_table = self.fd_table.clone();
        let mut seen = 0usize;
        let live = self.fd_table.len();
        let mut fd = 0i32;
        while seen < live {
            if let Some(entry) = self.fd_table.get(fd) {
                seen += 1;
                if entry.flags().contains(FdFlags::CLOEXEC) {
                    let _ = fd_table.close(fd);
                }
            }
            fd = fd.saturating_add(1);
        }
        Self {
            fd_table,
            namespace: self.namespace.clone(),
            directory_offsets: BTreeMap::new(),
        }
    }
}

impl ProcessResources {
    pub(in crate::starnix) fn new(
        process_handle: zx_handle_t,
        root_vmar: zx_handle_t,
        stdio_mode: StdioMode,
        stdout_handle: Option<zx_handle_t>,
        namespace: nexus_io::ProcessNamespace,
    ) -> Result<Self, zx_status_t> {
        Ok(Self {
            process_handle,
            fs: FsContext::new(stdio_mode, stdout_handle, namespace)?,
            mm: LinuxMm::new(root_vmar)?,
        })
    }

    pub(in crate::starnix) fn fork_clone(
        &self,
        child_process: zx_handle_t,
        child_root_vmar: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        Ok(Self {
            process_handle: child_process,
            fs: self.fs.fork_clone(),
            mm: self.mm.fork_clone(child_root_vmar)?,
        })
    }

    pub(in crate::starnix) fn exec_replace(
        &self,
        process_handle: zx_handle_t,
        root_vmar: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        Ok(Self {
            process_handle,
            fs: self.fs.exec_replace(),
            mm: LinuxMm::new(root_vmar)?,
        })
    }

    pub(in crate::starnix) fn getcwd(
        &self,
        session: zx_handle_t,
        guest_addr: u64,
        size: usize,
    ) -> Result<u64, zx_status_t> {
        if size == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let cwd = self.fs.namespace.cwd();
        let needed = cwd.len().checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if needed > size {
            return Ok(linux_errno(LINUX_ERANGE));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(needed)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.extend_from_slice(cwd.as_bytes());
        bytes.push(0);
        match write_guest_bytes(session, guest_addr, &bytes) {
            Ok(()) => Ok(needed as u64),
            Err(status) => Ok(linux_errno(map_guest_write_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn chdir(
        &mut self,
        session: zx_handle_t,
        path_addr: u64,
    ) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }
        match self.fs.namespace.set_cwd(path.as_str()) {
            Ok(()) => Ok(0),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn dup2(&mut self, oldfd: i32, newfd: i32) -> Result<u64, zx_status_t> {
        if oldfd == newfd {
            return if self.fs.fd_table.get(oldfd).is_some() {
                Ok(newfd as u64)
            } else {
                Ok(linux_errno(LINUX_EBADF))
            };
        }
        if newfd < 0 {
            return Ok(linux_errno(LINUX_EBADF));
        }
        match self
            .fs
            .fd_table
            .duplicate_to(oldfd, newfd, FdFlags::empty())
        {
            Ok(fd) => Ok(fd as u64),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn dup3(
        &mut self,
        oldfd: i32,
        newfd: i32,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        if oldfd == newfd {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        if newfd < 0 {
            return Ok(linux_errno(LINUX_EBADF));
        }
        if flags & !LINUX_O_CLOEXEC != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let fd_flags = if (flags & LINUX_O_CLOEXEC) != 0 {
            FdFlags::CLOEXEC
        } else {
            FdFlags::empty()
        };
        match self.fs.fd_table.duplicate_to(oldfd, newfd, fd_flags) {
            Ok(fd) => Ok(fd as u64),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn fcntl(
        &mut self,
        fd: i32,
        cmd: i32,
        arg: u64,
    ) -> Result<u64, zx_status_t> {
        match cmd {
            LINUX_F_GETFD => {
                let Some(entry) = self.fs.fd_table.get(fd) else {
                    return Ok(linux_errno(LINUX_EBADF));
                };
                Ok(encode_linux_fd_flags(entry.flags()))
            }
            LINUX_F_SETFD => {
                let flags = FdFlags::from_bits_truncate(arg as u32);
                match self.fs.fd_table.set_fd_flags(fd, flags) {
                    Ok(()) => Ok(0),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_GETFL => {
                let Some(entry) = self.fs.fd_table.get(fd) else {
                    return Ok(linux_errno(LINUX_EBADF));
                };
                Ok(encode_linux_open_flags(entry.description().flags()))
            }
            LINUX_F_DUPFD => {
                let min_fd = linux_arg_i32(arg);
                if min_fd < 0 {
                    return Ok(linux_errno(LINUX_EINVAL));
                }
                match self
                    .fs
                    .fd_table
                    .duplicate_from_min(fd, min_fd, FdFlags::empty())
                {
                    Ok(new_fd) => Ok(new_fd as u64),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_DUPFD_CLOEXEC => {
                let min_fd = linux_arg_i32(arg);
                if min_fd < 0 {
                    return Ok(linux_errno(LINUX_EINVAL));
                }
                match self
                    .fs
                    .fd_table
                    .duplicate_from_min(fd, min_fd, FdFlags::CLOEXEC)
                {
                    Ok(new_fd) => Ok(new_fd as u64),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_SETFL => Ok(linux_errno(LINUX_ENOSYS)),
            _ => Ok(linux_errno(LINUX_EINVAL)),
        }
    }

    pub(in crate::starnix) fn create_pipe(
        &mut self,
        session: zx_handle_t,
        guest_addr: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        if flags != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let mut read_end = ZX_HANDLE_INVALID;
        let mut write_end = ZX_HANDLE_INVALID;
        let status = zx_socket_create(0, &mut read_end, &mut write_end);
        if status != ZX_OK {
            return Ok(linux_errno(map_fd_status_to_errno(status)));
        }
        let read_fd = self.fs.fd_table.open(
            Arc::new(PipeFd::new(read_end)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        let write_fd = self.fs.fd_table.open(
            Arc::new(PipeFd::new(write_end)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        match (read_fd, write_fd) {
            (Ok(read_fd), Ok(write_fd)) => {
                if let Err(status) = write_guest_fd_pair(session, guest_addr, read_fd, write_fd) {
                    let _ = self.fs.fd_table.close(read_fd);
                    let _ = self.fs.fd_table.close(write_fd);
                    return Ok(linux_errno(map_guest_write_status_to_errno(status)));
                }
                Ok(0)
            }
            (Ok(read_fd), Err(status)) => {
                let _ = self.fs.fd_table.close(read_fd);
                Ok(linux_errno(map_fd_status_to_errno(status)))
            }
            (Err(status), _) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn create_socketpair(
        &mut self,
        session: zx_handle_t,
        domain: u64,
        socket_type: u64,
        protocol: u64,
        guest_addr: u64,
    ) -> Result<u64, zx_status_t> {
        let zx_socket_options = match socket_type {
            LINUX_SOCK_STREAM => ZX_SOCKET_STREAM,
            LINUX_SOCK_DGRAM => ZX_SOCKET_DATAGRAM,
            _ => return Ok(linux_errno(LINUX_EINVAL)),
        };
        if domain != LINUX_AF_UNIX || protocol != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let mut left = ZX_HANDLE_INVALID;
        let mut right = ZX_HANDLE_INVALID;
        let status = zx_socket_create(zx_socket_options, &mut left, &mut right);
        if status != ZX_OK {
            return Ok(linux_errno(map_fd_status_to_errno(status)));
        }
        let left_fd = self.fs.fd_table.open(
            Arc::new(SocketFd::new(left)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        let right_fd = self.fs.fd_table.open(
            Arc::new(SocketFd::new(right)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        match (left_fd, right_fd) {
            (Ok(left_fd), Ok(right_fd)) => {
                if let Err(status) = write_guest_fd_pair(session, guest_addr, left_fd, right_fd) {
                    let _ = self.fs.fd_table.close(left_fd);
                    let _ = self.fs.fd_table.close(right_fd);
                    return Ok(linux_errno(map_guest_write_status_to_errno(status)));
                }
                Ok(0)
            }
            (Ok(left_fd), Err(status)) => {
                let _ = self.fs.fd_table.close(left_fd);
                Ok(linux_errno(map_fd_status_to_errno(status)))
            }
            (Err(status), _) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    pub(in crate::starnix) fn openat(
        &mut self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        flags: u64,
        _mode: u64,
    ) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }

        let (open_flags, fd_flags) = decode_open_flags(flags);
        if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            match self.fs.namespace.open(path.as_str(), open_flags) {
                Ok(ops) => self
                    .fs
                    .fd_table
                    .open(ops, open_flags, fd_flags)
                    .map(|fd| fd as u64)
                    .or_else(|status| Ok(linux_errno(map_fd_status_to_errno(status)))),
                Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
            }
        } else {
            match self
                .fs
                .fd_table
                .openat(dirfd, path.as_str(), open_flags, fd_flags)
            {
                Ok(fd) => Ok(fd as u64),
                Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
            }
        }
    }

    pub(in crate::starnix) fn mkdirat(
        &mut self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        _mode: u64,
    ) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }
        let open_flags =
            OpenFlags::READABLE | OpenFlags::WRITABLE | OpenFlags::CREATE | OpenFlags::DIRECTORY;
        let result = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            self.fs
                .namespace
                .open(path.as_str(), open_flags)
                .map(|_| 0u64)
                .or_else(|status| {
                    Ok::<u64, zx_status_t>(linux_errno(map_fd_status_to_errno(status)))
                })
        } else {
            self.fs
                .fd_table
                .openat(dirfd, path.as_str(), open_flags, FdFlags::empty())
                .map(|fd| {
                    let _ = self.fs.fd_table.close(fd);
                    0u64
                })
                .or_else(|status| {
                    Ok::<u64, zx_status_t>(linux_errno(map_fd_status_to_errno(status)))
                })
        }?;
        Ok(result)
    }

    pub(in crate::starnix) fn unlinkat(
        &mut self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        if (flags & !LINUX_AT_REMOVEDIR) != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }
        let metadata = match self.stat_metadata_at_path(dirfd, path.as_str(), 0) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        let removing_dir = (flags & LINUX_AT_REMOVEDIR) != 0;
        let is_dir = (metadata.mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
        if removing_dir && !is_dir {
            return Ok(linux_errno(LINUX_ENOTDIR));
        }
        if !removing_dir && is_dir {
            return Ok(linux_errno(LINUX_EISDIR));
        }
        let result = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            self.fs
                .namespace
                .unlink(path.as_str())
                .map(|()| 0u64)
                .or_else(|status| {
                    Ok::<u64, zx_status_t>(linux_errno(map_fd_status_to_errno(status)))
                })
        } else {
            let entry = self.fs.fd_table.get(dirfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            entry
                .description()
                .ops()
                .unlinkat(path.as_str())
                .map(|()| 0u64)
                .or_else(|status| {
                    Ok::<u64, zx_status_t>(linux_errno(map_fd_status_to_errno(status)))
                })
        }?;
        Ok(result)
    }

    pub(in crate::starnix) fn stat_fd(
        &self,
        session: zx_handle_t,
        fd: i32,
        stat_addr: u64,
    ) -> Result<u64, zx_status_t> {
        let metadata = match self.stat_metadata_for_fd(fd) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, None)
    }

    pub(in crate::starnix) fn pread(
        &self,
        fd: i32,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, zx_status_t> {
        let entry = self.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !entry.description().flags().contains(OpenFlags::READABLE) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        pread_from_ops(entry.description().ops().as_ref(), offset, buffer)
    }

    pub(in crate::starnix) fn pwrite(
        &self,
        fd: i32,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize, zx_status_t> {
        let entry = self.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !entry.description().flags().contains(OpenFlags::WRITABLE) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        pwrite_to_ops(entry.description().ops().as_ref(), offset, buffer)
    }

    pub(in crate::starnix) fn stat_metadata_for_fd(
        &self,
        fd: i32,
    ) -> Result<LinuxStatMetadata, zx_status_t> {
        let entry = self.fs.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        stat_metadata_for_ops(entry.description().ops().as_ref())
    }

    pub(in crate::starnix) fn stat_metadata_at_path(
        &self,
        dirfd: i32,
        path: &str,
        flags: u64,
    ) -> Result<LinuxStatMetadata, zx_status_t> {
        let allowed = LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if path.is_empty() {
            if (flags & LINUX_AT_EMPTY_PATH) == 0 {
                return Err(ZX_ERR_NOT_FOUND);
            }
            return self.stat_metadata_for_fd(dirfd);
        }
        let opened = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            self.fs.namespace.open(path, OpenFlags::READABLE)
        } else {
            self.fs
                .fd_table
                .get(dirfd)
                .ok_or(ZX_ERR_BAD_HANDLE)
                .and_then(|entry| {
                    entry
                        .description()
                        .ops()
                        .openat(path, OpenFlags::READABLE | OpenFlags::PATH)
                })
        };
        let ops = opened?;
        stat_metadata_for_ops(ops.as_ref())
    }

    pub(in crate::starnix) fn statat(
        &self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        stat_addr: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        let stat_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let metadata = match self.stat_metadata_at_path(dirfd, path.as_str(), stat_flags) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, None)
    }

    pub(in crate::starnix) fn accessat(
        &self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        mode: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        let allowed_mode = LINUX_R_OK | LINUX_W_OK | LINUX_X_OK;
        if mode & !allowed_mode != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let allowed_flags = LINUX_AT_EMPTY_PATH | LINUX_AT_EACCESS | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed_flags) != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        let stat_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let metadata = match self.stat_metadata_at_path(dirfd, path.as_str(), stat_flags) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        if mode == LINUX_F_OK {
            return Ok(0);
        }
        let permissions = metadata.mode & 0o777;
        if (mode & LINUX_R_OK) != 0 && (permissions & 0o444) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        if (mode & LINUX_W_OK) != 0 && (permissions & 0o222) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        if (mode & LINUX_X_OK) != 0 && (permissions & 0o111) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        Ok(0)
    }

    pub(in crate::starnix) fn prlimit64(
        &self,
        session: zx_handle_t,
        current_tgid: i32,
        pid: i32,
        resource: i32,
        new_limit_addr: u64,
        old_limit_addr: u64,
    ) -> Result<u64, zx_status_t> {
        if pid != 0 && pid != current_tgid {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if new_limit_addr != 0 {
            return Ok(linux_errno(LINUX_EPERM));
        }
        let (current, maximum) = match resource {
            LINUX_RLIMIT_STACK => (LINUX_BOOTSTRAP_STACK_LIMIT, LINUX_BOOTSTRAP_STACK_LIMIT),
            LINUX_RLIMIT_NOFILE => (LINUX_BOOTSTRAP_NOFILE_LIMIT, LINUX_BOOTSTRAP_NOFILE_LIMIT),
            _ => return Ok(linux_errno(LINUX_EINVAL)),
        };
        if old_limit_addr != 0
            && let Err(status) = write_guest_rlimit(session, old_limit_addr, current, maximum)
        {
            return Ok(linux_errno(map_guest_write_status_to_errno(status)));
        }
        Ok(0)
    }

    pub(in crate::starnix) fn getdents64(
        &mut self,
        session: zx_handle_t,
        fd: i32,
        dirent_addr: u64,
        count: usize,
    ) -> Result<u64, zx_status_t> {
        if count == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(entry) = self.fs.fd_table.get(fd) else {
            return Ok(linux_errno(LINUX_EBADF));
        };
        let description_id = entry.description().id().raw();
        let entries = match self.fs.fd_table.readdir(fd) {
            Ok(entries) => entries,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        let mut cursor = *self.fs.directory_offsets.get(&description_id).unwrap_or(&0);
        if cursor >= entries.len() {
            return Ok(0);
        }

        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(count)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        while cursor < entries.len() {
            let record = encode_linux_dirent64(&entries[cursor], cursor + 1)?;
            if encoded.is_empty() && record.len() > count {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            if encoded
                .len()
                .checked_add(record.len())
                .ok_or(ZX_ERR_OUT_OF_RANGE)?
                > count
            {
                break;
            }
            encoded.extend_from_slice(&record);
            cursor += 1;
        }

        match write_guest_bytes(session, dirent_addr, &encoded) {
            Ok(()) => {
                self.fs.directory_offsets.insert(description_id, cursor);
                Ok(encoded.len() as u64)
            }
            Err(status) => Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        }
    }
}

pub(in crate::starnix) fn install_stdio_fd(
    table: &mut FdTable,
    handle: zx_handle_t,
    expected_fd: i32,
) -> Result<(), zx_status_t> {
    let mut duplicated = ZX_HANDLE_INVALID;
    let status = zx_handle_duplicate(handle, ZX_RIGHT_SAME_RIGHTS, &mut duplicated);
    if status != ZX_OK {
        return Err(status);
    }
    let fd = table.open(
        Arc::new(SocketFd::new(duplicated)),
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    )?;
    if fd != expected_fd {
        let _ = table.close(fd);
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(())
}

fn install_console_stdio_fd(
    table: &mut FdTable,
    ops: Arc<dyn FdOps>,
    open_flags: OpenFlags,
    expected_fd: i32,
) -> Result<(), zx_status_t> {
    let fd = table.open(ops, open_flags, FdFlags::empty())?;
    if fd != expected_fd {
        let _ = table.close(fd);
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(())
}

pub(in crate::starnix) fn write_guest_fd_pair(
    session: zx_handle_t,
    guest_addr: u64,
    left: i32,
    right: i32,
) -> Result<(), zx_status_t> {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&left.to_ne_bytes());
    bytes[4..].copy_from_slice(&right.to_ne_bytes());
    write_guest_bytes(session, guest_addr, &bytes)
}

pub(in crate::starnix) fn decode_open_flags(flags: u64) -> (OpenFlags, FdFlags) {
    let mut open_flags = OpenFlags::empty();
    match flags & LINUX_O_ACCMODE {
        0 => open_flags |= OpenFlags::READABLE,
        LINUX_O_WRONLY => open_flags |= OpenFlags::WRITABLE,
        LINUX_O_RDWR => open_flags |= OpenFlags::READABLE | OpenFlags::WRITABLE,
        _ => {}
    }
    if (flags & LINUX_O_CREAT) != 0 {
        open_flags |= OpenFlags::CREATE;
    }
    if (flags & LINUX_O_TRUNC) != 0 {
        open_flags |= OpenFlags::TRUNCATE;
    }
    if (flags & LINUX_O_APPEND) != 0 {
        open_flags |= OpenFlags::APPEND;
    }
    if (flags & LINUX_O_NONBLOCK) != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    if (flags & LINUX_O_DIRECTORY) != 0 {
        open_flags |= OpenFlags::DIRECTORY;
    }
    if (flags & LINUX_O_PATH) != 0 {
        open_flags |= OpenFlags::PATH;
    }
    let _ignored = flags & (LINUX_O_NOCTTY | LINUX_O_LARGEFILE | LINUX_O_NOFOLLOW);

    let mut fd_flags = FdFlags::empty();
    if (flags & LINUX_O_CLOEXEC) != 0 {
        fd_flags |= FdFlags::CLOEXEC;
    }
    (open_flags, fd_flags)
}

pub(in crate::starnix) fn encode_linux_fd_flags(flags: FdFlags) -> u64 {
    let mut bits = 0u64;
    if flags.contains(FdFlags::CLOEXEC) {
        bits |= LINUX_FD_CLOEXEC;
    }
    bits
}

pub(in crate::starnix) fn encode_linux_open_flags(flags: OpenFlags) -> u64 {
    let mut bits = match (
        flags.contains(OpenFlags::READABLE),
        flags.contains(OpenFlags::WRITABLE),
    ) {
        (true, true) => LINUX_O_RDWR,
        (false, true) => LINUX_O_WRONLY,
        _ => 0,
    };
    if flags.contains(OpenFlags::APPEND) {
        bits |= LINUX_O_APPEND;
    }
    if flags.contains(OpenFlags::NONBLOCK) {
        bits |= LINUX_O_NONBLOCK;
    }
    if flags.contains(OpenFlags::DIRECTORY) {
        bits |= LINUX_O_DIRECTORY;
    }
    if flags.contains(OpenFlags::PATH) {
        bits |= LINUX_O_PATH;
    }
    bits
}

pub(in crate::starnix) fn encode_linux_dirent64(
    entry: &DirectoryEntry,
    next_offset: usize,
) -> Result<Vec<u8>, zx_status_t> {
    let name = entry.name.as_bytes();
    let header_bytes = 19usize;
    let record_len = align_up(
        header_bytes
            .checked_add(name.len())
            .and_then(|len| len.checked_add(1))
            .ok_or(ZX_ERR_OUT_OF_RANGE)?,
        8,
    )?;
    let mut record = Vec::new();
    record
        .try_reserve_exact(record_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    record.resize(record_len, 0);
    record[0..8].copy_from_slice(&(next_offset as u64).to_ne_bytes());
    record[8..16].copy_from_slice(&(next_offset as i64).to_ne_bytes());
    record[16..18].copy_from_slice(&(record_len as u16).to_ne_bytes());
    record[18] = match entry.kind {
        DirectoryEntryKind::Directory => LINUX_DT_DIR,
        DirectoryEntryKind::File => LINUX_DT_REG,
        DirectoryEntryKind::Symlink => LINUX_DT_LNK,
        DirectoryEntryKind::Socket => LINUX_DT_SOCK,
        DirectoryEntryKind::Service | DirectoryEntryKind::Unknown => LINUX_DT_UNKNOWN,
    };
    let name_start = 19usize;
    let name_end = name_start
        .checked_add(name.len())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    record[name_start..name_end].copy_from_slice(name);
    Ok(record)
}

pub(in crate::starnix) fn write_guest_stat(
    session: zx_handle_t,
    addr: u64,
    metadata: LinuxStatMetadata,
    ino_seed: Option<u64>,
) -> Result<u64, zx_status_t> {
    let mut bytes = [0u8; LINUX_STAT_STRUCT_BYTES];
    let ino = ino_seed.unwrap_or(metadata.inode);
    bytes[8..16].copy_from_slice(&ino.to_ne_bytes());
    bytes[16..24].copy_from_slice(&1u64.to_ne_bytes());
    bytes[24..28].copy_from_slice(&metadata.mode.to_ne_bytes());
    bytes[48..56].copy_from_slice(&(metadata.size_bytes as i64).to_ne_bytes());
    bytes[56..64].copy_from_slice(&4096i64.to_ne_bytes());
    bytes[64..72].copy_from_slice(&(metadata.size_bytes.div_ceil(512) as i64).to_ne_bytes());
    match write_guest_bytes(session, addr, &bytes) {
        Ok(()) => Ok(0),
        Err(status) => Ok(linux_errno(map_guest_memory_status_to_errno(status))),
    }
}

pub(in crate::starnix) fn write_guest_rlimit(
    session: zx_handle_t,
    addr: u64,
    current: u64,
    maximum: u64,
) -> Result<(), zx_status_t> {
    let mut bytes = [0u8; LINUX_RLIMIT_BYTES];
    bytes[..8].copy_from_slice(&current.to_ne_bytes());
    bytes[8..].copy_from_slice(&maximum.to_ne_bytes());
    write_guest_bytes(session, addr, &bytes)
}

pub(in crate::starnix) fn write_guest_statx(
    session: zx_handle_t,
    addr: u64,
    metadata: LinuxStatMetadata,
    ino_seed: Option<u64>,
    requested_mask: u32,
) -> Result<u64, zx_status_t> {
    let supported_mask = LINUX_STATX_BASIC_STATS | LINUX_STATX_MNT_ID;
    let mask = if requested_mask == 0 {
        supported_mask
    } else {
        supported_mask & requested_mask
    };
    let ino = ino_seed.unwrap_or(metadata.inode);
    let mut bytes = [0u8; LINUX_STATX_BYTES];
    bytes[0..4].copy_from_slice(&mask.to_ne_bytes());
    bytes[4..8].copy_from_slice(&4096u32.to_ne_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_ne_bytes());
    bytes[20..24].copy_from_slice(&0u32.to_ne_bytes());
    bytes[24..28].copy_from_slice(&0u32.to_ne_bytes());
    bytes[28..30].copy_from_slice(&(metadata.mode as u16).to_ne_bytes());
    bytes[32..40].copy_from_slice(&ino.to_ne_bytes());
    bytes[40..48].copy_from_slice(&metadata.size_bytes.to_ne_bytes());
    bytes[48..56].copy_from_slice(&(metadata.size_bytes.div_ceil(512)).to_ne_bytes());
    bytes[144..152].copy_from_slice(&1u64.to_ne_bytes());
    match write_guest_bytes(session, addr, &bytes) {
        Ok(()) => Ok(0),
        Err(status) => Ok(linux_errno(map_guest_write_status_to_errno(status))),
    }
}
