use super::super::*;
use super::support::{RecordingFd, test_kernel_with_stdio};

#[test]
fn wait_signal_frame_without_sa_restart_reports_eintr() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);
    let wait = WaitState {
        restartable: true,
        kind: WaitKind::Wait4 {
            target_pid: -1,
            status_addr: 0,
            options: 0,
        },
    };
    let mut stop_state = ax_guest_stop_state_t::default();
    stop_state.regs.rip = 0x4000;
    let frame = kernel
        .prepare_wait_signal_frame(
            WaitState {
                restartable: false,
                ..wait
            },
            LinuxSigAction {
                handler: 0x1000,
                flags: LINUX_SA_RESTORER,
                restorer: 0x2000,
                mask: 0,
            },
            &mut stop_state,
            0x55,
        )
        .expect("prepare frame");
    assert_eq!(stop_state.regs.rax, linux_errno(LINUX_EINTR));
    assert_eq!(stop_state.regs.rip, 0x4000 + AX_GUEST_X64_SYSCALL_INSN_LEN);
    assert_eq!(frame.restore_regs.rax, linux_errno(LINUX_EINTR));
    assert_eq!(
        frame.restore_regs.rip,
        0x4000 + AX_GUEST_X64_SYSCALL_INSN_LEN
    );
    assert_eq!(frame.previous_blocked, 0x55);
}

#[test]
fn wait_signal_frame_with_sa_restart_keeps_original_resume_state() {
    let stdout = RecordingFd::new();
    let kernel = test_kernel_with_stdio(stdout);
    let wait = WaitState {
        restartable: true,
        kind: WaitKind::Futex {
            key: LinuxFutexKey::Private {
                tgid: 1,
                addr: 0x1000,
            },
        },
    };
    let mut stop_state = ax_guest_stop_state_t::default();
    stop_state.regs.rax = 99;
    stop_state.regs.rip = 0x9000;
    let frame = kernel
        .prepare_wait_signal_frame(
            wait,
            LinuxSigAction {
                handler: 0x1000,
                flags: LINUX_SA_RESTORER | LINUX_SA_RESTART,
                restorer: 0x2000,
                mask: 0,
            },
            &mut stop_state,
            0xaa,
        )
        .expect("prepare frame");
    assert_eq!(stop_state.regs.rax, 99);
    assert_eq!(stop_state.regs.rip, 0x9000);
    assert_eq!(frame.restore_regs.rax, 99);
    assert_eq!(frame.restore_regs.rip, 0x9000);
    assert_eq!(frame.previous_blocked, 0xaa);
}

#[test]
fn rt_sigreturn_restores_registers_and_signal_mask() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let restore_regs = ax_guest_x64_regs_t {
        rax: 42,
        rcx: 7,
        rip: 0x1234,
        rsp: 0x5678,
        ..Default::default()
    };
    {
        let task = kernel.tasks.get_mut(&1).expect("root task");
        task.signals.blocked = linux_signal_bit(LINUX_SIGSTOP).expect("sigstop bit");
        task.active_signal = Some(ActiveSignalFrame {
            restore_regs,
            previous_blocked: linux_signal_bit(LINUX_SIGCONT).expect("sigcont bit"),
        });
    }

    let mut stop_state = ax_guest_stop_state_t::default();
    let action = kernel
        .sys_rt_sigreturn(1, &mut stop_state)
        .expect("rt_sigreturn");
    assert!(matches!(action, SyscallAction::Resume));
    assert_eq!(stop_state.regs.rax, restore_regs.rax);
    assert_eq!(stop_state.regs.rcx, restore_regs.rcx);
    assert_eq!(stop_state.regs.rip, restore_regs.rip);
    assert_eq!(stop_state.regs.rsp, restore_regs.rsp);
    let task = kernel.tasks.get(&1).expect("root task after sigreturn");
    assert_eq!(
        task.signals.blocked,
        linux_signal_bit(LINUX_SIGCONT).expect("sigcont bit")
    );
    assert!(task.active_signal.is_none());
}

#[test]
fn fork_sigactions_clone_is_independent_of_parent_mutation() {
    let mut parent = BTreeMap::new();
    parent.insert(
        10,
        LinuxSigAction {
            handler: 0x4000,
            flags: LINUX_SA_RESTORER,
            restorer: 0x5000,
            mask: 0,
        },
    );

    let cloned = super::super::sys::process::fork_sigactions(&parent);
    parent.clear();
    assert_eq!(cloned.len(), 1);
    assert_eq!(cloned.get(&10).expect("cloned action").handler, 0x4000);
}

#[test]
fn fork_and_exec_signal_helpers_preserve_and_reset_expected_state() {
    const TEST_SIGUSR1: i32 = 10;
    const TEST_SIGUSR2: i32 = 12;
    let parent_blocked = linux_signal_bit(LINUX_SIGSTOP).expect("sigstop bit");
    let inherited = super::super::sys::process::fork_task_signals(parent_blocked);
    assert_eq!(inherited.blocked, parent_blocked);
    assert_eq!(inherited.pending, 0);

    let mut sigactions = BTreeMap::new();
    sigactions.insert(
        TEST_SIGUSR1,
        LinuxSigAction {
            handler: 0x4000,
            flags: LINUX_SA_RESTORER | LINUX_SA_RESTART,
            restorer: 0x5000,
            mask: 0,
        },
    );
    sigactions.insert(
        TEST_SIGUSR2,
        LinuxSigAction {
            handler: LINUX_SIG_IGN,
            flags: 0,
            restorer: 0,
            mask: 0,
        },
    );
    let cloned = super::super::sys::process::fork_sigactions(&sigactions);
    assert_eq!(cloned.len(), 2);
    super::super::sys::process::reset_exec_sigactions(&mut sigactions);
    assert_eq!(sigactions.len(), 1);
    assert_eq!(
        sigactions
            .get(&TEST_SIGUSR2)
            .expect("ignored signal survives")
            .handler,
        LINUX_SIG_IGN
    );

    let mut task = LinuxTask {
        tid: 1,
        tgid: 1,
        carrier: TaskCarrier {
            thread_handle: ZX_HANDLE_INVALID,
            session_handle: ZX_HANDLE_INVALID,
            sidecar_vmo: ZX_HANDLE_INVALID,
            packet_key: 1,
        },
        state: TaskState::Running,
        signals: TaskSignals {
            blocked: parent_blocked,
            pending: linux_signal_bit(LINUX_SIGCONT).expect("sigcont bit"),
        },
        clear_child_tid: 0xdead_beef,
        robust_list: Some(LinuxRobustListState {
            head_addr: 0x1000,
            len: 24,
        }),
        active_signal: Some(ActiveSignalFrame {
            restore_regs: ax_guest_x64_regs_t::default(),
            previous_blocked: 0,
        }),
    };
    super::super::sys::process::reset_task_after_exec(&mut task);
    assert_eq!(task.signals.blocked, parent_blocked);
    assert_eq!(
        task.signals.pending,
        linux_signal_bit(LINUX_SIGCONT).expect("sigcont bit")
    );
    assert_eq!(task.clear_child_tid, 0);
    assert!(task.robust_list.is_none());
    assert!(task.active_signal.is_none());
}
