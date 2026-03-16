use super::super::*;

#[derive(Clone, Copy)]
pub(in crate::starnix) struct TaskCarrier {
    pub(in crate::starnix) thread_handle: zx_handle_t,
    pub(in crate::starnix) session_handle: zx_handle_t,
    pub(in crate::starnix) sidecar_vmo: zx_handle_t,
    pub(in crate::starnix) packet_key: u64,
}

pub(in crate::starnix) enum TaskState {
    Running,
    Waiting(WaitState),
}

#[derive(Clone, Copy, Default)]
pub(in crate::starnix) struct TaskSignals {
    pub(in crate::starnix) blocked: u64,
    pub(in crate::starnix) pending: u64,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct LinuxRobustListState {
    pub(in crate::starnix) head_addr: u64,
    pub(in crate::starnix) len: u64,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) struct ActiveSignalFrame {
    pub(in crate::starnix) restore_regs: ax_guest_x64_regs_t,
    pub(in crate::starnix) previous_blocked: u64,
}

pub(in crate::starnix) struct LinuxTask {
    pub(in crate::starnix) tid: i32,
    pub(in crate::starnix) tgid: i32,
    pub(in crate::starnix) carrier: TaskCarrier,
    pub(in crate::starnix) state: TaskState,
    pub(in crate::starnix) signals: TaskSignals,
    pub(in crate::starnix) clear_child_tid: u64,
    pub(in crate::starnix) robust_list: Option<LinuxRobustListState>,
    pub(in crate::starnix) active_signal: Option<ActiveSignalFrame>,
}

impl TaskCarrier {
    pub(in crate::starnix) fn close(self) {
        let _ = zx_handle_close(self.session_handle);
        let _ = zx_handle_close(self.sidecar_vmo);
        let _ = zx_handle_close(self.thread_handle);
    }

    pub(in crate::starnix) fn kill_and_close(self) {
        let _ = zx_task_kill(self.thread_handle);
        self.close();
    }
}
