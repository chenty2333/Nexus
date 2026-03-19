use super::super::fs::procfs::ProcFdDirFd;
use super::super::*;
use super::support::{RecordingFd, insert_test_child, test_kernel_with_stdio};
use alloc::sync::Weak;
use alloc::vec;

#[test]
fn proc_self_fd_opens_as_directory_and_lists_stdio() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);
    let opened = kernel
        .open_proc_absolute(1, "/proc/self/fd")
        .expect("open /proc/self/fd");
    let entries = opened.readdir().expect("readdir /proc/self/fd");
    let names: Vec<_> = entries.into_iter().map(|entry| entry.name).collect();
    assert!(opened.as_any().is::<ProcFdDirFd>());
    assert_eq!(names, vec!["0", "1", "2"]);
}

#[test]
fn proc_self_fd_stdout_proxies_live_description() {
    let stdout = RecordingFd::new();
    let expected = b"proc-fd bridge ok\n";
    let kernel = test_kernel_with_stdio(stdout.clone());
    let opened = kernel
        .open_proc_absolute(1, "/proc/self/fd/1")
        .expect("open /proc/self/fd/1");
    let written = opened.write(expected).expect("write proxied stdout");
    assert_eq!(written, expected.len());
    assert_eq!(stdout.bytes(), expected);
}

#[test]
fn proc_self_task_comm_and_cmdline_are_available() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);

    let comm = kernel
        .open_proc_absolute(1, "/proc/self/comm")
        .expect("open /proc/self/comm");
    let mut comm_bytes = [0u8; 128];
    let comm_len = comm.read(&mut comm_bytes).expect("read /proc/self/comm");
    assert_eq!(&comm_bytes[..comm_len], b"linux-round6-proc-job-smoke\n");

    let cmdline = kernel
        .open_proc_absolute(1, "/proc/self/cmdline")
        .expect("open /proc/self/cmdline");
    let mut cmdline_bytes = [0u8; 128];
    let cmdline_len = cmdline
        .read(&mut cmdline_bytes)
        .expect("read /proc/self/cmdline");
    assert_eq!(
        &cmdline_bytes[..cmdline_len],
        b"linux-round6-proc-job-smoke\0"
    );

    let task_dir = kernel
        .open_proc_absolute(1, "/proc/self/task")
        .expect("open /proc/self/task");
    let task_entries = task_dir.readdir().expect("readdir /proc/self/task");
    let task_names: Vec<_> = task_entries.into_iter().map(|entry| entry.name).collect();
    assert_eq!(task_names, vec!["1"]);

    let task_status = kernel
        .open_proc_absolute(1, "/proc/self/task/1/status")
        .expect("open /proc/self/task/1/status");
    let mut status_bytes = [0u8; 256];
    let status_len = task_status
        .read(&mut status_bytes)
        .expect("read /proc/self/task/1/status");
    let status = core::str::from_utf8(&status_bytes[..status_len]).expect("utf8 status");
    assert!(status.contains("Pid:\t1\n"));
    assert!(status.contains("Tgid:\t1\n"));
}

#[test]
fn proc_status_reflects_stopped_group_state() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let group = kernel.groups.get_mut(&1).expect("root group");
    group.state = ThreadGroupState::Stopped;
    group.last_stop_signal = Some(LINUX_SIGSTOP);
    group.stop_wait_pending = true;

    let status = kernel
        .open_proc_absolute(1, "/proc/self/status")
        .expect("open /proc/self/status");
    let mut bytes = [0u8; 256];
    let len = status.read(&mut bytes).expect("read /proc/self/status");
    let text = core::str::from_utf8(&bytes[..len]).expect("utf8 status");
    assert!(text.contains("State:\tT\n"));
}

#[test]
fn proc_self_readlink_targets_report_exe_and_cwd() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, "/proc/self/exe")
            .expect("proc exe target"),
        "/bin/linux-round6-proc-job-smoke"
    );
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, "/proc/self/cwd")
            .expect("proc cwd target"),
        "/"
    );
}

#[test]
fn proc_self_fd_readlink_reports_stdio_targets() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, "/proc/self/fd/0")
            .expect("stdin target"),
        "/dev/stdin"
    );
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, "/proc/self/fd/1")
            .expect("stdout target"),
        "/dev/stdout"
    );
}

#[test]
fn proc_self_fd_readlink_reports_anon_inode_targets() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);

    let mut stop_state = ax_guest_stop_state_t::default();
    let epollfd = {
        stop_state.regs.rdi = 0;
        let action = kernel
            .sys_epoll_create1(1, &mut stop_state)
            .expect("epoll_create1");
        assert!(matches!(action, SyscallAction::Resume));
        stop_state.regs.rax as i32
    };
    let (signalfd, pidfd) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let signalfd = resources
            .fs
            .fd_table
            .open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE,
                FdFlags::empty(),
            )
            .expect("open synthetic signalfd");
        let signalfd_key = {
            let entry = resources
                .fs
                .fd_table
                .get(signalfd)
                .expect("synthetic signalfd entry");
            file_description_key(entry.description())
        };
        kernel
            .signalfds
            .insert(signalfd_key, Weak::<Mutex<SignalFdState>>::new());

        let pidfd = resources
            .fs
            .fd_table
            .open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE,
                FdFlags::empty(),
            )
            .expect("open synthetic pidfd");
        let pidfd_key = {
            let entry = resources
                .fs
                .fd_table
                .get(pidfd)
                .expect("synthetic pidfd entry");
            file_description_key(entry.description())
        };
        kernel
            .pidfds
            .insert(pidfd_key, Weak::<Mutex<PidFdState>>::new());
        (signalfd, pidfd)
    };

    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, format!("/proc/self/fd/{epollfd}").as_str())
            .expect("epoll target"),
        "anon_inode:[eventpoll]"
    );
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, format!("/proc/self/fd/{signalfd}").as_str())
            .expect("signalfd target"),
        "anon_inode:[signalfd]"
    );
    assert_eq!(
        kernel
            .resolve_proc_readlink_target(1, format!("/proc/self/fd/{pidfd}").as_str())
            .expect("pidfd target"),
        "anon_inode:[pidfd]"
    );
}

#[test]
fn proc_child_task_views_are_available() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    insert_test_child(&mut kernel, TaskState::Running, 2);

    let task_dir = kernel
        .open_proc_absolute(1, "/proc/2/task")
        .expect("open /proc/2/task");
    let task_entries = task_dir.readdir().expect("readdir /proc/2/task");
    let task_names: Vec<_> = task_entries.into_iter().map(|entry| entry.name).collect();
    assert_eq!(task_names, vec!["2"]);

    let task_comm = kernel
        .open_proc_absolute(1, "/proc/2/task/2/comm")
        .expect("open /proc/2/task/2/comm");
    let mut comm = [0u8; 128];
    let comm_len = task_comm.read(&mut comm).expect("read task comm");
    assert_eq!(&comm[..comm_len], b"linux-round6-proc-control-smoke\n");

    let task_status = kernel
        .open_proc_absolute(1, "/proc/2/task/2/status")
        .expect("open /proc/2/task/2/status");
    let mut status = [0u8; 256];
    let status_len = task_status.read(&mut status).expect("read task status");
    let text = core::str::from_utf8(&status[..status_len]).expect("utf8 task status");
    assert!(text.contains("Pid:\t2\n"));
    assert!(text.contains("Tgid:\t2\n"));
}

#[test]
fn proc_child_thread_stat_reflects_waiting_and_stopped_states() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    insert_test_child(
        &mut kernel,
        TaskState::Waiting(WaitState {
            restartable: true,
            kind: WaitKind::Futex {
                key: LinuxFutexKey::Private {
                    tgid: 2,
                    addr: 0x1000,
                },
            },
        }),
        2,
    );

    let thread_stat = kernel
        .open_proc_absolute(1, "/proc/2/task/2/stat")
        .expect("open /proc/2/task/2/stat");
    let mut stat = [0u8; 256];
    let stat_len = thread_stat.read(&mut stat).expect("read task stat");
    let stat_text = core::str::from_utf8(&stat[..stat_len]).expect("utf8 task stat");
    assert!(stat_text.contains(") S "));

    let child = kernel.groups.get_mut(&2).expect("child group");
    child.state = ThreadGroupState::Stopped;
    child.last_stop_signal = Some(LINUX_SIGTTIN);
    child.stop_wait_pending = true;
    let thread_status = kernel
        .open_proc_absolute(1, "/proc/2/task/2/status")
        .expect("open /proc/2/task/2/status");
    let mut status = [0u8; 256];
    let status_len = thread_status.read(&mut status).expect("read task status");
    let status_text = core::str::from_utf8(&status[..status_len]).expect("utf8 task status");
    assert!(status_text.contains("State:\tT\n"));

    let thread_stat = kernel
        .open_proc_absolute(1, "/proc/2/task/2/stat")
        .expect("reopen /proc/2/task/2/stat");
    let stat_len = thread_stat.read(&mut stat).expect("read stopped task stat");
    let stat_text = core::str::from_utf8(&stat[..stat_len]).expect("utf8 stopped task stat");
    assert!(stat_text.contains(") T "));
}
