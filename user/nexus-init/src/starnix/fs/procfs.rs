use super::super::*;

#[derive(Clone)]
pub(in crate::starnix) struct ProcRootFd {
    self_tgid: i32,
    tasks: BTreeMap<i32, ProcTaskSnapshot>,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcTaskDirFd {
    snapshot: ProcTaskSnapshot,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcTaskListFd {
    tgid: i32,
    threads: BTreeMap<i32, ProcThreadSnapshot>,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcThreadDirFd {
    snapshot: ProcThreadSnapshot,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcFdDirFd {
    tgid: i32,
    entries: BTreeMap<String, Arc<OpenFileDescription>>,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcTextFd {
    bytes: Arc<Vec<u8>>,
    cursor: Arc<Mutex<usize>>,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcProxyFd {
    description: Arc<OpenFileDescription>,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcThreadSnapshot {
    tid: i32,
    tgid: i32,
    parent_tgid: i32,
    pgid: i32,
    sid: i32,
    state: char,
    name: String,
}

#[derive(Clone)]
pub(in crate::starnix) struct ProcTaskSnapshot {
    tgid: i32,
    parent_tgid: i32,
    pgid: i32,
    sid: i32,
    threads: BTreeMap<i32, ProcThreadSnapshot>,
    state: char,
    name: String,
    cmdline: Vec<u8>,
    fds: BTreeMap<String, Arc<OpenFileDescription>>,
}

impl ProcTextFd {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(bytes),
            cursor: Arc::new(Mutex::new(0)),
        }
    }
}

fn split_proc_path(path: &str) -> Result<Vec<&str>, zx_status_t> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in path.trim_matches('/').split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(ZX_ERR_BAD_PATH);
        }
        components.push(component);
    }
    Ok(components)
}

fn join_proc_relative_path(base: &str, path: &str) -> Result<String, zx_status_t> {
    let components = split_proc_path(path)?;
    if components.is_empty() {
        return Ok(String::from(base.trim_end_matches('/')));
    }
    let mut resolved = String::from(base.trim_end_matches('/'));
    for component in components {
        resolved.push('/');
        resolved.push_str(component);
    }
    Ok(resolved)
}

impl FdOps for ProcRootFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.tasks.len().checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        entries.push(DirectoryEntry {
            name: String::from("self"),
            kind: DirectoryEntryKind::Directory,
        });
        for tgid in self.tasks.keys() {
            entries.push(DirectoryEntry {
                name: format!("{tgid}"),
                kind: DirectoryEntryKind::Directory,
            });
        }
        Ok(entries)
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        open_proc_root_snapshot(self, path)
    }
}

impl FdOps for ProcTaskDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok([
            ("cmdline", DirectoryEntryKind::File),
            ("comm", DirectoryEntryKind::File),
            ("fd", DirectoryEntryKind::Directory),
            ("stat", DirectoryEntryKind::File),
            ("status", DirectoryEntryKind::File),
            ("task", DirectoryEntryKind::Directory),
        ]
        .into_iter()
        .map(|(name, kind)| DirectoryEntry {
            name: String::from(name),
            kind,
        })
        .collect())
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        open_proc_task_snapshot(&self.snapshot, path)
    }
}

impl FdOps for ProcTaskListFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.threads.len())
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        for tid in self.threads.keys() {
            entries.push(DirectoryEntry {
                name: format!("{tid}"),
                kind: DirectoryEntryKind::Directory,
            });
        }
        Ok(entries)
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let components = split_proc_path(path)?;
        if components.is_empty() {
            return Ok(Arc::new(self.clone()));
        }
        let tid = components[0].parse::<i32>().map_err(|_| ZX_ERR_NOT_FOUND)?;
        let snapshot = self.threads.get(&tid).cloned().ok_or(ZX_ERR_NOT_FOUND)?;
        let thread_dir = Arc::new(ProcThreadDirFd { snapshot });
        if components.len() == 1 {
            return Ok(thread_dir);
        }
        thread_dir.openat(&components[1..].join("/"), OpenFlags::READABLE)
    }
}

impl FdOps for ProcThreadDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok([
            ("comm", DirectoryEntryKind::File),
            ("stat", DirectoryEntryKind::File),
            ("status", DirectoryEntryKind::File),
        ]
        .into_iter()
        .map(|(name, kind)| DirectoryEntry {
            name: String::from(name),
            kind,
        })
        .collect())
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let components = split_proc_path(path)?;
        if components.is_empty() {
            return Ok(Arc::new(self.clone()));
        }
        if components.len() != 1 {
            return Err(ZX_ERR_BAD_PATH);
        }
        match components[0] {
            "comm" => Ok(Arc::new(ProcTextFd::new(build_proc_comm_bytes(
                &self.snapshot.name,
            )))),
            "stat" => Ok(Arc::new(ProcTextFd::new(build_proc_thread_stat_bytes(
                &self.snapshot,
            )))),
            "status" => Ok(Arc::new(ProcTextFd::new(build_proc_thread_status_bytes(
                &self.snapshot,
            )))),
            _ => Err(ZX_ERR_NOT_FOUND),
        }
    }
}

impl FdOps for ProcFdDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        for name in self.entries.keys() {
            entries.push(DirectoryEntry {
                name: name.clone(),
                kind: DirectoryEntryKind::Symlink,
            });
        }
        Ok(entries)
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let components = split_proc_path(path)?;
        if components.is_empty() {
            return Ok(Arc::new(self.clone()));
        }
        if components.len() != 1 {
            return Err(ZX_ERR_BAD_PATH);
        }
        let description = self
            .entries
            .get(components[0])
            .cloned()
            .ok_or(ZX_ERR_NOT_FOUND)?;
        Ok(Arc::new(ProcProxyFd { description }))
    }
}

impl FdOps for ProcTextFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let mut cursor = self.cursor.lock();
        let bytes = self.bytes.as_slice();
        if *cursor >= bytes.len() {
            return Ok(0);
        }
        let remaining = &bytes[*cursor..];
        let actual = remaining.len().min(buffer.len());
        buffer[..actual].copy_from_slice(&remaining[..actual]);
        *cursor = cursor.checked_add(actual).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(actual)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_ACCESS_DENIED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(Self::new(self.bytes.as_slice().to_vec())))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }
}

impl FdOps for ProcProxyFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        self.description.ops().read(buffer)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.description.ops().write(buffer)
    }

    fn seek(&self, origin: nexus_io::SeekOrigin, offset: i64) -> Result<u64, zx_status_t> {
        self.description.ops().seek(origin, offset)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        self.description.ops().wait_interest()
    }

    fn as_vmo(&self, flags: nexus_io::VmoFlags) -> Result<zx_handle_t, zx_status_t> {
        self.description.ops().as_vmo(flags)
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        self.description.ops().readdir()
    }

    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        self.description.ops().openat(path, flags)
    }
}

impl StarnixKernel {
    fn group_name(group: &LinuxThreadGroup) -> String {
        group.image.as_ref().map_or_else(
            || String::from("unknown"),
            |image| proc_task_name_from_path(&image.path),
        )
    }

    const fn group_state_char(group: &LinuxThreadGroup) -> char {
        match group.state {
            ThreadGroupState::Running => 'R',
            ThreadGroupState::Stopped => 'T',
            ThreadGroupState::Zombie { .. } => 'Z',
        }
    }

    const fn thread_state_char(task: &LinuxTask, group: &LinuxThreadGroup) -> char {
        match group.state {
            ThreadGroupState::Zombie { .. } => 'Z',
            ThreadGroupState::Stopped => 'T',
            ThreadGroupState::Running => match task.state {
                TaskState::Running => 'R',
                TaskState::Waiting(_) => 'S',
            },
        }
    }

    fn snapshot_fd_descriptions(
        resources: &ProcessResources,
    ) -> Result<BTreeMap<String, Arc<OpenFileDescription>>, zx_status_t> {
        let mut entries = BTreeMap::new();
        let target_hits = resources
            .fs
            .fd_table
            .len()
            .checked_add(32)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let mut hits = 0usize;
        let mut misses_after_hits = 0usize;
        let mut fd = 0i32;
        while hits < target_hits && misses_after_hits < 64 {
            if let Some(entry) = resources.fs.fd_table.get(fd) {
                entries.insert(format!("{fd}"), Arc::clone(entry.description()));
                hits = hits.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
                misses_after_hits = 0;
            } else if hits != 0 {
                misses_after_hits = misses_after_hits
                    .checked_add(1)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            }
            fd = fd.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        Ok(entries)
    }

    fn proc_task_snapshot(&self, tgid: i32) -> Result<ProcTaskSnapshot, zx_status_t> {
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_NOT_FOUND)?;
        let fds = group
            .resources
            .as_ref()
            .map_or_else(|| Ok(BTreeMap::new()), Self::snapshot_fd_descriptions)?;
        let mut threads = BTreeMap::new();
        for tid in &group.task_ids {
            let task = self.tasks.get(tid).ok_or(ZX_ERR_BAD_STATE)?;
            threads.insert(
                *tid,
                ProcThreadSnapshot {
                    tid: *tid,
                    tgid,
                    parent_tgid: group.parent_tgid.unwrap_or(0),
                    pgid: group.pgid,
                    sid: group.sid,
                    state: Self::thread_state_char(task, group),
                    name: Self::group_name(group),
                },
            );
        }
        Ok(ProcTaskSnapshot {
            tgid,
            parent_tgid: group.parent_tgid.unwrap_or(0),
            pgid: group.pgid,
            sid: group.sid,
            threads,
            state: Self::group_state_char(group),
            name: Self::group_name(group),
            cmdline: group
                .image
                .as_ref()
                .map_or_else(Vec::new, |image| image.cmdline.clone()),
            fds,
        })
    }

    pub(in crate::starnix) fn proc_root_fd(
        &self,
        self_tgid: i32,
    ) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let mut tasks = BTreeMap::new();
        for tgid in self.groups.keys().copied() {
            tasks.insert(tgid, self.proc_task_snapshot(tgid)?);
        }
        Ok(Arc::new(ProcRootFd { self_tgid, tasks }))
    }

    pub(in crate::starnix) fn open_proc_absolute(
        &self,
        task_id: i32,
        path: &str,
    ) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let self_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let root = self.proc_root_fd(self_tgid)?;
        if path == "/proc" || path == "/proc/" {
            return Ok(root);
        }
        let suffix = path.strip_prefix("/proc/").ok_or(ZX_ERR_BAD_PATH)?;
        root.openat(suffix, OpenFlags::READABLE)
    }

    pub(in crate::starnix) fn resolve_proc_readlink_target(
        &self,
        task_id: i32,
        path: &str,
    ) -> Result<String, zx_status_t> {
        let suffix = path.strip_prefix("/proc/").ok_or(ZX_ERR_BAD_PATH)?;
        let components = split_proc_path(suffix)?;
        if components.is_empty() {
            return Err(ZX_ERR_NOT_FOUND);
        }
        let target_tgid = match components[0] {
            "self" => self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid,
            raw => raw.parse::<i32>().map_err(|_| ZX_ERR_NOT_FOUND)?,
        };
        let group = self.groups.get(&target_tgid).ok_or(ZX_ERR_NOT_FOUND)?;
        match components.as_slice() {
            [_, "exe"] => group
                .image
                .as_ref()
                .map(|image| image.path.clone())
                .ok_or(ZX_ERR_NOT_FOUND),
            [_, "cwd"] => group
                .resources
                .as_ref()
                .map(|resources| String::from(resources.fs.namespace.cwd()))
                .ok_or(ZX_ERR_NOT_FOUND),
            [_, "fd", raw_fd] => {
                let fd = raw_fd.parse::<i32>().map_err(|_| ZX_ERR_NOT_FOUND)?;
                self.proc_fd_readlink_target(target_tgid, fd)
            }
            _ => Err(ZX_ERR_NOT_FOUND),
        }
    }

    fn proc_fd_readlink_target(&self, tgid: i32, fd: i32) -> Result<String, zx_status_t> {
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_NOT_FOUND)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_NOT_FOUND)?;
        let entry = resources.fs.fd_table.get(fd).ok_or(ZX_ERR_NOT_FOUND)?;
        let description = entry.description();
        let description_key = file_description_key(description);
        if self.epolls.contains_key(&description_key) {
            return Ok(String::from("anon_inode:[eventpoll]"));
        }
        if self.signalfds.contains_key(&description_key)
            || description.ops().as_any().is::<SignalFd>()
        {
            return Ok(String::from("anon_inode:[signalfd]"));
        }
        if self.pidfds.contains_key(&description_key) || description.ops().as_any().is::<PidFd>() {
            return Ok(String::from("anon_inode:[pidfd]"));
        }
        if description.ops().as_any().is::<EventFd>() {
            return Ok(String::from("anon_inode:[eventfd]"));
        }
        if description.ops().as_any().is::<TimerFd>() {
            return Ok(String::from("anon_inode:[timerfd]"));
        }
        if description.ops().as_any().is::<PipeFd>() {
            return Ok(format!("pipe:[{}]", description.id().raw()));
        }
        if description.ops().as_any().is::<SocketFd>() {
            return Ok(format!("socket:[{}]", description.id().raw()));
        }
        match fd {
            0 => Ok(String::from("/dev/stdin")),
            1 => Ok(String::from("/dev/stdout")),
            2 => Ok(String::from("/dev/stderr")),
            _ => Err(ZX_ERR_NOT_SUPPORTED),
        }
    }

    fn proc_readlink_base_for_dirfd(
        &self,
        task_id: i32,
        dirfd: i32,
    ) -> Result<Option<String>, zx_status_t> {
        if dirfd == LINUX_AT_FDCWD {
            return Ok(None);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fs.fd_table.get(dirfd).ok_or(ZX_ERR_BAD_HANDLE)?;
        let ops = entry.description().ops().as_ref();
        if ops.as_any().is::<ProcRootFd>() {
            return Ok(Some(String::from("/proc")));
        }
        if let Some(task_dir) = ops.as_any().downcast_ref::<ProcTaskDirFd>() {
            return Ok(Some(format!("/proc/{}", task_dir.snapshot.tgid)));
        }
        if let Some(task_list) = ops.as_any().downcast_ref::<ProcTaskListFd>() {
            return Ok(Some(format!("/proc/{}/task", task_list.tgid)));
        }
        if let Some(thread_dir) = ops.as_any().downcast_ref::<ProcThreadDirFd>() {
            return Ok(Some(format!(
                "/proc/{}/task/{}",
                thread_dir.snapshot.tgid, thread_dir.snapshot.tid
            )));
        }
        if let Some(fd_dir) = ops.as_any().downcast_ref::<ProcFdDirFd>() {
            return Ok(Some(format!("/proc/{}/fd", fd_dir.tgid)));
        }
        Ok(None)
    }

    pub(in crate::starnix) fn resolve_readlink_target(
        &self,
        task_id: i32,
        dirfd: i32,
        path: &str,
    ) -> Result<String, zx_status_t> {
        if path.is_empty() {
            return Err(ZX_ERR_NOT_FOUND);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        let resolved = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            resources.fs.namespace.resolve_path(path)?
        } else if let Some(base) = self.proc_readlink_base_for_dirfd(task_id, dirfd)? {
            join_proc_relative_path(base.as_str(), path)?
        } else {
            return Err(ZX_ERR_NOT_SUPPORTED);
        };
        if !resolved.starts_with("/proc/") {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        self.resolve_proc_readlink_target(task_id, resolved.as_str())
    }
}

fn proc_task_name_from_path(path: &str) -> String {
    path.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(String::from)
        .unwrap_or_else(|| String::from(path))
}

fn build_proc_comm_bytes(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(b'\n');
    bytes
}

fn build_proc_status_bytes(snapshot: &ProcTaskSnapshot) -> Vec<u8> {
    format!(
        "Name:\t{}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nPgid:\t{}\nSid:\t{}\nThreads:\t{}\n",
        snapshot.name,
        snapshot.state,
        snapshot.tgid,
        snapshot.tgid,
        snapshot.parent_tgid,
        snapshot.pgid,
        snapshot.sid,
        snapshot.threads.len().max(1),
    )
    .into_bytes()
}

fn build_proc_stat_bytes(snapshot: &ProcTaskSnapshot) -> Vec<u8> {
    format!(
        "{} ({}) {} {} {} {} 0 0 0 0 0 0 0 0 0 0 20 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        snapshot.tgid,
        snapshot.name,
        snapshot.state,
        snapshot.parent_tgid,
        snapshot.pgid,
        snapshot.sid,
        snapshot.threads.len().max(1),
    )
    .into_bytes()
}

fn build_proc_thread_status_bytes(snapshot: &ProcThreadSnapshot) -> Vec<u8> {
    format!(
        "Name:\t{}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nPgid:\t{}\nSid:\t{}\nThreads:\t1\n",
        snapshot.name,
        snapshot.state,
        snapshot.tgid,
        snapshot.tid,
        snapshot.parent_tgid,
        snapshot.pgid,
        snapshot.sid,
    )
    .into_bytes()
}

fn build_proc_thread_stat_bytes(snapshot: &ProcThreadSnapshot) -> Vec<u8> {
    format!(
        "{} ({}) {} {} {} {} 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        snapshot.tid,
        snapshot.name,
        snapshot.state,
        snapshot.parent_tgid,
        snapshot.pgid,
        snapshot.sid,
    )
    .into_bytes()
}

fn open_proc_root_snapshot(root: &ProcRootFd, path: &str) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let components = split_proc_path(path)?;
    if components.is_empty() {
        return Ok(Arc::new(root.clone()));
    }
    let target = match components[0] {
        "self" => root.self_tgid,
        raw => raw.parse::<i32>().map_err(|_| ZX_ERR_NOT_FOUND)?,
    };
    let snapshot = root.tasks.get(&target).cloned().ok_or(ZX_ERR_NOT_FOUND)?;
    let task_dir = Arc::new(ProcTaskDirFd { snapshot });
    if components.len() == 1 {
        return Ok(task_dir);
    }
    task_dir.openat(&components[1..].join("/"), OpenFlags::READABLE)
}

fn open_proc_task_snapshot(
    snapshot: &ProcTaskSnapshot,
    path: &str,
) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let components = split_proc_path(path)?;
    if components.is_empty() {
        return Ok(Arc::new(ProcTaskDirFd {
            snapshot: snapshot.clone(),
        }));
    }
    match components[0] {
        "cmdline" if components.len() == 1 => {
            Ok(Arc::new(ProcTextFd::new(snapshot.cmdline.clone())))
        }
        "comm" if components.len() == 1 => Ok(Arc::new(ProcTextFd::new(build_proc_comm_bytes(
            &snapshot.name,
        )))),
        "status" if components.len() == 1 => {
            Ok(Arc::new(ProcTextFd::new(build_proc_status_bytes(snapshot))))
        }
        "stat" if components.len() == 1 => {
            Ok(Arc::new(ProcTextFd::new(build_proc_stat_bytes(snapshot))))
        }
        "task" => {
            let task_dir = Arc::new(ProcTaskListFd {
                tgid: snapshot.tgid,
                threads: snapshot.threads.clone(),
            });
            if components.len() == 1 {
                Ok(task_dir)
            } else {
                task_dir.openat(&components[1..].join("/"), OpenFlags::READABLE)
            }
        }
        "fd" => {
            let fd_dir = Arc::new(ProcFdDirFd {
                tgid: snapshot.tgid,
                entries: snapshot.fds.clone(),
            });
            if components.len() == 1 {
                Ok(fd_dir)
            } else {
                fd_dir.openat(&components[1..].join("/"), OpenFlags::READABLE)
            }
        }
        _ => Err(ZX_ERR_NOT_FOUND),
    }
}

pub(in crate::starnix) fn stat_metadata_for_ops(
    ops: &dyn FdOps,
) -> Result<LinuxStatMetadata, zx_status_t> {
    if let Some(metadata) = local_fd_metadata(ops) {
        return Ok(match metadata.kind {
            LocalFdMetadataKind::Directory => LinuxStatMetadata {
                mode: LINUX_S_IFDIR | 0o555,
                size_bytes: metadata.size_bytes,
            },
            LocalFdMetadataKind::RegularFile => LinuxStatMetadata {
                mode: LINUX_S_IFREG | 0o444,
                size_bytes: metadata.size_bytes,
            },
        });
    }
    if ops.as_any().is::<PipeFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFIFO | 0o666,
            size_bytes: 0,
        });
    }
    if ops.as_any().is::<SocketFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFSOCK | 0o666,
            size_bytes: 0,
        });
    }
    if ops.as_any().is::<PseudoNodeFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFREG | 0o444,
            size_bytes: 0,
        });
    }
    if ops.as_any().is::<ProcRootFd>()
        || ops.as_any().is::<ProcTaskDirFd>()
        || ops.as_any().is::<ProcTaskListFd>()
        || ops.as_any().is::<ProcThreadDirFd>()
        || ops.as_any().is::<ProcFdDirFd>()
    {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFDIR | 0o555,
            size_bytes: 0,
        });
    }
    if let Some(text) = ops.as_any().downcast_ref::<ProcTextFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFREG | 0o444,
            size_bytes: text.bytes.len() as u64,
        });
    }
    if let Some(proxy) = ops.as_any().downcast_ref::<ProcProxyFd>() {
        return stat_metadata_for_ops(proxy.description.ops().as_ref());
    }
    if ops.as_any().is::<SignalFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFREG | 0o444,
            size_bytes: 0,
        });
    }
    if ops.as_any().is::<PidFd>() {
        return Ok(LinuxStatMetadata {
            mode: LINUX_S_IFREG | 0o444,
            size_bytes: 0,
        });
    }
    Err(ZX_ERR_NOT_SUPPORTED)
}

pub(in crate::starnix) fn pread_from_ops(
    ops: &dyn FdOps,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, zx_status_t> {
    if let Some(result) = local_fd_pread(ops, offset, buffer) {
        return result;
    }
    if let Some(text) = ops.as_any().downcast_ref::<ProcTextFd>() {
        return proc_text_pread(text, offset, buffer);
    }
    if let Some(proxy) = ops.as_any().downcast_ref::<ProcProxyFd>() {
        return pread_from_ops(proxy.description.ops().as_ref(), offset, buffer);
    }
    Err(ZX_ERR_NOT_SUPPORTED)
}

pub(in crate::starnix) fn pwrite_to_ops(
    ops: &dyn FdOps,
    offset: u64,
    buffer: &[u8],
) -> Result<usize, zx_status_t> {
    if let Some(result) = local_fd_pwrite(ops, offset, buffer) {
        return result;
    }
    if ops.as_any().is::<ProcTextFd>() {
        return Err(ZX_ERR_ACCESS_DENIED);
    }
    if let Some(proxy) = ops.as_any().downcast_ref::<ProcProxyFd>() {
        return pwrite_to_ops(proxy.description.ops().as_ref(), offset, buffer);
    }
    Err(ZX_ERR_NOT_SUPPORTED)
}

fn proc_text_pread(
    text: &ProcTextFd,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, zx_status_t> {
    let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let bytes = text.bytes.as_slice();
    if start >= bytes.len() {
        return Ok(0);
    }
    let actual = (bytes.len() - start).min(buffer.len());
    buffer[..actual].copy_from_slice(&bytes[start..start + actual]);
    Ok(actual)
}
