use super::super::fs::fd::FsContext;
use super::super::fs::tty::PtyRegistry;
use super::super::*;
use super::std::sync::Mutex as StdMutex;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use nexus_io::{NamespaceTrie, ProcessNamespace, PseudoNodeFd, SeekOrigin};

#[derive(Clone, Default)]
pub(super) struct RecordingFd {
    writes: Arc<StdMutex<Vec<u8>>>,
}

impl RecordingFd {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        self.writes.lock().expect("writes lock").clone()
    }
}

impl FdOps for RecordingFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.writes
            .lock()
            .expect("writes lock")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
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
}

pub(super) struct SyntheticWaitFd;

impl FdOps for SyntheticWaitFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(Self))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        Some(WaitSpec::new(
            ZX_HANDLE_INVALID,
            EVENTFD_READABLE_SIGNAL | EVENTFD_WRITABLE_SIGNAL,
        ))
    }
}

pub(super) fn test_linux_mm() -> LinuxMm {
    LinuxMm::empty_for_tests()
}

pub(super) fn test_kernel_with_stdio(stdout: RecordingFd) -> StarnixKernel {
    let mut fd_table = FdTable::new();
    let stdin_fd = fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE,
            FdFlags::empty(),
        )
        .expect("stdin open");
    let stdout_fd = fd_table
        .open(Arc::new(stdout), OpenFlags::WRITABLE, FdFlags::empty())
        .expect("stdout open");
    let stderr_fd = fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::WRITABLE,
            FdFlags::empty(),
        )
        .expect("stderr open");
    assert_eq!(stdin_fd, 0);
    assert_eq!(stdout_fd, 1);
    assert_eq!(stderr_fd, 2);

    let resources = ProcessResources {
        process_handle: ZX_HANDLE_INVALID,
        fs: FsContext {
            fd_table,
            base_namespace: ProcessNamespace::new(NamespaceTrie::new()),
            namespace: ProcessNamespace::new(NamespaceTrie::new()),
            directory_offsets: BTreeMap::new(),
            pty_registry: Arc::new(PtyRegistry::new()),
            controlling_tty: Arc::new(Mutex::new(None)),
            tty_bridge: None,
        },
        mm: test_linux_mm(),
    };
    let root_task = LinuxTask {
        tid: 1,
        tgid: 1,
        carrier: TaskCarrier {
            thread_handle: ZX_HANDLE_INVALID,
            session_handle: ZX_HANDLE_INVALID,
            sidecar_vmo: ZX_HANDLE_INVALID,
            packet_key: 1,
        },
        state: TaskState::Running,
        signals: TaskSignals::default(),
        clear_child_tid: 0,
        robust_list: None,
        active_signal: None,
    };
    let root_group = LinuxThreadGroup {
        tgid: 1,
        leader_tid: 1,
        parent_tgid: None,
        pgid: 1,
        sid: 1,
        child_tgids: BTreeSet::new(),
        task_ids: BTreeSet::from([1]),
        state: ThreadGroupState::Running,
        last_stop_signal: None,
        stop_wait_pending: false,
        continued_wait_pending: false,
        shared_pending: 0,
        sigchld_info: None,
        sigactions: BTreeMap::new(),
        image: Some(TaskImage {
            path: String::from("/bin/linux-round6-proc-job-smoke"),
            cmdline: b"linux-round6-proc-job-smoke\0".to_vec(),
            exec_blob: Vec::new(),
            initial_tls_modules: Vec::new(),
            runtime_random: [0; 16],
            writable_ranges: Vec::new(),
        }),
        resources: Some(resources),
    };
    StarnixKernel::new(ZX_HANDLE_INVALID, ZX_HANDLE_INVALID, root_task, root_group)
        .expect("test kernel")
}

pub(super) fn insert_test_child(kernel: &mut StarnixKernel, task_state: TaskState, pgid: i32) {
    kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .child_tgids
        .insert(2);
    kernel.tasks.insert(
        2,
        LinuxTask {
            tid: 2,
            tgid: 2,
            carrier: TaskCarrier {
                thread_handle: ZX_HANDLE_INVALID,
                session_handle: ZX_HANDLE_INVALID,
                sidecar_vmo: ZX_HANDLE_INVALID,
                packet_key: 2,
            },
            state: task_state,
            signals: TaskSignals::default(),
            clear_child_tid: 0,
            robust_list: None,
            active_signal: None,
        },
    );
    kernel.groups.insert(
        2,
        LinuxThreadGroup {
            tgid: 2,
            leader_tid: 2,
            parent_tgid: Some(1),
            pgid,
            sid: 1,
            child_tgids: BTreeSet::new(),
            task_ids: BTreeSet::from([2]),
            state: ThreadGroupState::Running,
            last_stop_signal: None,
            stop_wait_pending: false,
            continued_wait_pending: false,
            shared_pending: 0,
            sigchld_info: None,
            sigactions: BTreeMap::new(),
            image: Some(TaskImage {
                path: String::from("bin/linux-round6-proc-control-smoke"),
                cmdline: b"linux-round6-proc-control-smoke\0".to_vec(),
                exec_blob: Vec::new(),
                initial_tls_modules: Vec::new(),
                runtime_random: [0; 16],
                writable_ranges: Vec::new(),
            }),
            resources: None,
        },
    );
}
