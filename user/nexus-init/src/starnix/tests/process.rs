use super::super::*;
use super::support::{RecordingFd, insert_test_child, test_kernel_with_stdio};

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
    insert_test_child(&mut kernel, TaskState::Running, 2);
    let child = kernel.groups.get_mut(&2).expect("child group");
    child.state = ThreadGroupState::Stopped;
    child.last_stop_signal = Some(LINUX_SIGTTIN);
    child.stop_wait_pending = true;

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
