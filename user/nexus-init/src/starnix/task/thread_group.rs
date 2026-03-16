use super::super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::starnix) struct LinuxSigChldInfo {
    pub(in crate::starnix) pid: i32,
    pub(in crate::starnix) status: i32,
    pub(in crate::starnix) code: i32,
}

#[derive(Clone, Copy)]
pub(in crate::starnix) enum ThreadGroupState {
    Running,
    Stopped,
    Zombie { wait_status: i32, exit_code: i32 },
}

pub(in crate::starnix) struct LinuxThreadGroup {
    pub(in crate::starnix) tgid: i32,
    pub(in crate::starnix) leader_tid: i32,
    pub(in crate::starnix) parent_tgid: Option<i32>,
    pub(in crate::starnix) pgid: i32,
    pub(in crate::starnix) sid: i32,
    pub(in crate::starnix) child_tgids: BTreeSet<i32>,
    pub(in crate::starnix) task_ids: BTreeSet<i32>,
    pub(in crate::starnix) state: ThreadGroupState,
    pub(in crate::starnix) last_stop_signal: Option<i32>,
    pub(in crate::starnix) stop_wait_pending: bool,
    pub(in crate::starnix) continued_wait_pending: bool,
    pub(in crate::starnix) shared_pending: u64,
    pub(in crate::starnix) sigchld_info: Option<LinuxSigChldInfo>,
    pub(in crate::starnix) sigactions: BTreeMap<i32, LinuxSigAction>,
    pub(in crate::starnix) image: Option<TaskImage>,
    pub(in crate::starnix) resources: Option<ProcessResources>,
}
