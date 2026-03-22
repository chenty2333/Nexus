use super::super::fs::fd::FsContext;
use super::super::fs::tty::PtyRegistry;
use super::super::*;
use super::support::{RecordingFd, insert_test_child, test_kernel_with_stdio};
use alloc::sync::Arc;
use nexus_io::{NamespaceTrie, ProcessNamespace};

#[test]
fn wait_matches_tracks_same_group_and_explicit_pgid_targets() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    insert_test_child(&mut kernel, TaskState::Running, 7);

    assert!(kernel.wait_matches(1, -1, 2));
    assert!(kernel.wait_matches(1, 2, 2));
    assert!(!kernel.wait_matches(1, 0, 2));
    assert!(kernel.wait_matches(1, -7, 2));
    assert!(!kernel.wait_matches(1, -9, 2));

    kernel.groups.get_mut(&2).expect("child group").pgid = 1;
    assert!(kernel.wait_matches(1, 0, 2));
}

#[test]
fn setsid_rehomes_group_and_updates_foreground_mapping() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    kernel.groups.get_mut(&1).expect("root group").pgid = 7;

    let mut stop_state = ax_guest_stop_state_t::default();
    let action = kernel.sys_setsid(1, &mut stop_state).expect("setsid");
    assert!(matches!(action, SyscallAction::Resume));
    assert_eq!(stop_state.regs.rax, 1);
    let root = kernel.groups.get(&1).expect("root group");
    assert_eq!(root.sid, 1);
    assert_eq!(root.pgid, 1);
    assert_eq!(kernel.foreground_pgid(1), Some(1));
}

#[test]
fn parent_sigchld_info_tracks_stop_and_continue() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    insert_test_child(&mut kernel, TaskState::Running, 2);
    kernel.groups.get_mut(&2).expect("child group").image = None;

    kernel
        .enter_group_stop(2, LINUX_SIGTSTP)
        .expect("stop child group");
    let root = kernel.groups.get(&1).expect("root group");
    assert_ne!(
        root.shared_pending & linux_signal_bit(LINUX_SIGCHLD).expect("sigchld bit"),
        0
    );
    assert_eq!(
        root.sigchld_info,
        Some(LinuxSigChldInfo {
            pid: 2,
            status: LINUX_SIGTSTP,
            code: LINUX_CLD_STOPPED,
        })
    );

    kernel
        .queue_sigchld_to_parent(
            2,
            LinuxSigChldInfo {
                pid: 2,
                status: LINUX_SIGCONT,
                code: LINUX_CLD_CONTINUED,
            },
        )
        .expect("queue continued sigchld");
    let root = kernel.groups.get(&1).expect("root group");
    assert_eq!(
        root.sigchld_info,
        Some(LinuxSigChldInfo {
            pid: 2,
            status: LINUX_SIGCONT,
            code: LINUX_CLD_CONTINUED,
        })
    );
}

#[test]
fn tty_job_control_marks_background_stdio_access() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let tty = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let registry = Arc::new(PtyRegistry::new());
        let (_master, slave) = registry.allocate_unbridged_pair();
        resources.fs.fd_table.close(0).expect("close stdin");
        resources.fs.fd_table.close(1).expect("close stdout");
        resources.fs.fd_table.close(2).expect("close stderr");
        let stdin_fd = resources
            .fs
            .fd_table
            .open(slave.clone(), OpenFlags::READABLE, FdFlags::empty())
            .expect("tty stdin");
        let stdout_fd = resources
            .fs
            .fd_table
            .open(
                slave.clone(),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("tty stdout");
        let stderr_fd = resources
            .fs
            .fd_table
            .open(slave.clone(), OpenFlags::WRITABLE, FdFlags::empty())
            .expect("tty stderr");
        assert_eq!((stdin_fd, stdout_fd, stderr_fd), (0, 1, 2));
        resources.fs.pty_registry = registry;
        resources.fs.set_controlling_tty(Some(slave.clone()));
        slave
    };
    insert_test_child(&mut kernel, TaskState::Running, 2);
    let child = kernel.groups.get_mut(&2).expect("child group");
    child.state = ThreadGroupState::Stopped;
    child.last_stop_signal = Some(LINUX_SIGTTIN);
    child.stop_wait_pending = true;
    child.resources = Some(ProcessResources {
        process_handle: ZX_HANDLE_INVALID,
        fs: FsContext {
            fd_table: {
                let mut table = FdTable::new();
                table
                    .open(tty.clone(), OpenFlags::READABLE, FdFlags::empty())
                    .expect("child tty stdin");
                table
                    .open(
                        tty.clone(),
                        OpenFlags::READABLE | OpenFlags::WRITABLE,
                        FdFlags::empty(),
                    )
                    .expect("child tty stdout");
                table
                    .open(tty.clone(), OpenFlags::WRITABLE, FdFlags::empty())
                    .expect("child tty stderr");
                table
            },
            base_namespace: ProcessNamespace::new(NamespaceTrie::new()),
            namespace: ProcessNamespace::new(NamespaceTrie::new()),
            directory_offsets: BTreeMap::new(),
            pty_registry: Arc::new(PtyRegistry::new()),
            controlling_tty: Arc::new(Mutex::new(Some(tty.clone()))),
            tty_bridge: None,
        },
        mm: super::support::test_linux_mm(),
    });

    assert_eq!(kernel.foreground_pgid(1), Some(1));
    assert_eq!(
        kernel
            .tty_job_control_signal(2, 0, FdWaitOp::Read)
            .expect("tty read signal"),
        Some(LINUX_SIGTTIN)
    );
    assert_eq!(
        kernel
            .tty_job_control_signal(2, 1, FdWaitOp::Write)
            .expect("tty write signal"),
        Some(LINUX_SIGTTOU)
    );

    let mut stop_state = ax_guest_stop_state_t::default();
    stop_state.regs.rdi = 2;
    stop_state.regs.rsi = 1;
    stop_state.regs.rip = 0x1000;
    let action = kernel
        .sys_setpgid(1, &mut stop_state)
        .expect("setpgid stopped child");
    assert!(matches!(action, SyscallAction::Resume));
    assert_eq!(kernel.groups.get(&2).expect("child group").pgid, 1);
    assert_eq!(
        kernel
            .tty_job_control_signal(2, 0, FdWaitOp::Read)
            .expect("foreground tty read"),
        None
    );
}

#[test]
fn tty_background_read_stop_advances_syscall_as_eintr() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let tty = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let registry = Arc::new(PtyRegistry::new());
        let (_master, slave) = registry.allocate_unbridged_pair();
        resources.fs.fd_table.close(0).expect("close stdin");
        resources.fs.fd_table.close(1).expect("close stdout");
        resources.fs.fd_table.close(2).expect("close stderr");
        let stdin_fd = resources
            .fs
            .fd_table
            .open(slave.clone(), OpenFlags::READABLE, FdFlags::empty())
            .expect("tty stdin");
        let stdout_fd = resources
            .fs
            .fd_table
            .open(
                slave.clone(),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("tty stdout");
        let stderr_fd = resources
            .fs
            .fd_table
            .open(slave.clone(), OpenFlags::WRITABLE, FdFlags::empty())
            .expect("tty stderr");
        assert_eq!((stdin_fd, stdout_fd, stderr_fd), (0, 1, 2));
        resources.fs.pty_registry = registry;
        resources.fs.set_controlling_tty(Some(slave.clone()));
        slave
    };
    insert_test_child(&mut kernel, TaskState::Running, 2);
    let child = kernel.groups.get_mut(&2).expect("child group");
    child.resources = Some(ProcessResources {
        process_handle: ZX_HANDLE_INVALID,
        fs: FsContext {
            fd_table: {
                let mut table = FdTable::new();
                table
                    .open(tty.clone(), OpenFlags::READABLE, FdFlags::empty())
                    .expect("child tty stdin");
                table
                    .open(
                        tty.clone(),
                        OpenFlags::READABLE | OpenFlags::WRITABLE,
                        FdFlags::empty(),
                    )
                    .expect("child tty stdout");
                table
                    .open(tty.clone(), OpenFlags::WRITABLE, FdFlags::empty())
                    .expect("child tty stderr");
                table
            },
            base_namespace: ProcessNamespace::new(NamespaceTrie::new()),
            namespace: ProcessNamespace::new(NamespaceTrie::new()),
            directory_offsets: BTreeMap::new(),
            pty_registry: Arc::new(PtyRegistry::new()),
            controlling_tty: Arc::new(Mutex::new(Some(tty.clone()))),
            tty_bridge: None,
        },
        mm: super::support::test_linux_mm(),
    });

    let mut stop_state = ax_guest_stop_state_t::default();
    stop_state.regs.rax = LINUX_SYSCALL_READ;
    stop_state.regs.rdi = 0;
    stop_state.regs.rsi = 0x2000;
    stop_state.regs.rdx = 1;
    stop_state.regs.rip = 0x4000;

    let action = kernel
        .maybe_apply_tty_job_control(2, 0, FdWaitOp::Read, &mut stop_state)
        .expect("background tty read")
        .expect("stop action");
    assert!(matches!(action, SyscallAction::LeaveStopped));
    assert_eq!(stop_state.regs.rax, linux_errno(LINUX_EINTR));
    assert_eq!(stop_state.regs.rip, 0x4000 + AX_GUEST_X64_SYSCALL_INSN_LEN);
    let child = kernel.groups.get(&2).expect("child group");
    assert!(matches!(child.state, ThreadGroupState::Stopped));
    assert_eq!(child.last_stop_signal, Some(LINUX_SIGTTIN));
}
