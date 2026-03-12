use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_types::guest::{
    AX_GUEST_STOP_REASON_X64_SYSCALL, AX_GUEST_X64_SYSCALL_INSN_LEN, AX_LINUX_EXEC_SPEC_V1,
};
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH,
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NO_MEMORY, ZX_ERR_NOT_DIR, ZX_ERR_NOT_FILE, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_VMAR_ALLOCATE, AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP,
};
use axle_types::vm::{
    ZX_VM_CAN_MAP_EXECUTE, ZX_VM_CAN_MAP_READ, ZX_VM_CAN_MAP_SPECIFIC, ZX_VM_CAN_MAP_WRITE,
    ZX_VM_COMPACT, ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_SPECIFIC,
};
use axle_types::{
    ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_linux_exec_spec_header_t, zx_handle_t,
    zx_status_t,
};
use libzircon::{
    ZX_TIME_INFINITE, ax_guest_session_create, ax_guest_session_read_memory,
    ax_guest_session_resume, ax_guest_session_write_memory, ax_guest_stop_state_read,
    ax_guest_stop_state_write, ax_linux_exec_spec_blob, ax_process_prepare_linux_exec,
    ax_process_start_guest, ax_thread_start_guest, zx_handle_close, zx_handle_duplicate,
    zx_port_create, zx_port_packet_t, zx_port_wait, zx_process_create, zx_socket_create,
    zx_status_result, zx_task_kill, zx_thread_create, zx_vmo_create,
};
use nexus_component::{ComponentStartInfo, NumberedHandle};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFlags, PipeFd, PseudoNodeFd,
    SocketFd,
};

use crate::lifecycle::{read_channel_alloc_blocking, send_controller_event, send_status_event};
use crate::services::{BootAssetEntry, BootstrapNamespace, LocalFdMetadataKind, local_fd_metadata};
use crate::{
    LINUX_FD_SMOKE_BINARY_PATH, LINUX_FD_SMOKE_BYTES, LINUX_FD_SMOKE_DECL_BYTES,
    LINUX_HELLO_BINARY_PATH, LINUX_HELLO_BYTES, LINUX_HELLO_DECL_BYTES, LINUX_ROUND2_BINARY_PATH,
    LINUX_ROUND2_BYTES, LINUX_ROUND2_DECL_BYTES, LINUX_ROUND3_BINARY_PATH, LINUX_ROUND3_BYTES,
    LINUX_ROUND3_DECL_BYTES, LINUX_ROUND4_SIGNAL_BINARY_PATH, LINUX_ROUND4_SIGNAL_BYTES,
    LINUX_ROUND4_SIGNAL_DECL_BYTES, STARTUP_HANDLE_COMPONENT_STATUS,
    STARTUP_HANDLE_STARNIX_IMAGE_VMO, STARTUP_HANDLE_STARNIX_PARENT_PROCESS,
    STARTUP_HANDLE_STARNIX_STDOUT,
};

const USER_PAGE_BYTES: u64 = 0x1000;
// Keep this Linux guest bootstrap layout in sync with
// `kernel/axle-kernel/src/userspace.rs`.
const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * 448;
const USER_SHARED_BYTES: u64 = USER_PAGE_BYTES * 2;
const USER_STACK_BYTES: u64 = USER_PAGE_BYTES * 16;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000;
const USER_STACK_VA: u64 = USER_CODE_VA + USER_CODE_BYTES + USER_SHARED_BYTES;
const LINUX_HEAP_REGION_BYTES: u64 = 16 * 1024 * 1024;
const LINUX_HEAP_VMO_BYTES: u64 = 16 * 1024 * 1024;
const LINUX_MMAP_REGION_BYTES: u64 = 64 * 1024 * 1024;
const STARNIX_GUEST_PACKET_KEY_BASE: u64 = 0x5354_4e58_0000_0001;
const STARNIX_GUEST_PACKET_KEY: u64 = STARNIX_GUEST_PACKET_KEY_BASE;
const LINUX_SYSCALL_READ: u64 = 0;
const LINUX_SYSCALL_WRITE: u64 = 1;
const LINUX_SYSCALL_CLOSE: u64 = 3;
const LINUX_SYSCALL_FSTAT: u64 = 5;
const LINUX_SYSCALL_MMAP: u64 = 9;
const LINUX_SYSCALL_MPROTECT: u64 = 10;
const LINUX_SYSCALL_MUNMAP: u64 = 11;
const LINUX_SYSCALL_RT_SIGACTION: u64 = 13;
const LINUX_SYSCALL_RT_SIGPROCMASK: u64 = 14;
const LINUX_SYSCALL_RT_SIGRETURN: u64 = 15;
const LINUX_SYSCALL_BRK: u64 = 12;
const LINUX_SYSCALL_GETPID: u64 = 39;
const LINUX_SYSCALL_SOCKETPAIR: u64 = 53;
const LINUX_SYSCALL_CLONE: u64 = 56;
const LINUX_SYSCALL_FORK: u64 = 57;
const LINUX_SYSCALL_EXECVE: u64 = 59;
const LINUX_SYSCALL_WAIT4: u64 = 61;
const LINUX_SYSCALL_KILL: u64 = 62;
const LINUX_SYSCALL_GETTID: u64 = 186;
const LINUX_SYSCALL_TGKILL: u64 = 234;
const LINUX_SYSCALL_GETDENTS64: u64 = 217;
const LINUX_SYSCALL_EXIT: u64 = 60;
const LINUX_SYSCALL_OPENAT: u64 = 257;
const LINUX_SYSCALL_NEWFSTATAT: u64 = 262;
const LINUX_SYSCALL_EXIT_GROUP: u64 = 231;
const LINUX_SYSCALL_PIPE2: u64 = 293;
const LINUX_AF_UNIX: u64 = 1;
const LINUX_SOCK_STREAM: u64 = 1;
const LINUX_AT_FDCWD: i32 = -100;
const LINUX_O_ACCMODE: u64 = 0x3;
const LINUX_O_WRONLY: u64 = 0x1;
const LINUX_O_RDWR: u64 = 0x2;
const LINUX_O_CREAT: u64 = 0x40;
const LINUX_O_NOCTTY: u64 = 0x100;
const LINUX_O_TRUNC: u64 = 0x200;
const LINUX_O_APPEND: u64 = 0x400;
const LINUX_O_NONBLOCK: u64 = 0x800;
const LINUX_O_LARGEFILE: u64 = 0x8000;
const LINUX_O_DIRECTORY: u64 = 0x1_0000;
const LINUX_O_NOFOLLOW: u64 = 0x2_0000;
const LINUX_O_CLOEXEC: u64 = 0x8_0000;
const LINUX_O_PATH: u64 = 0x20_0000;
const LINUX_PROT_READ: u64 = 0x1;
const LINUX_PROT_WRITE: u64 = 0x2;
const LINUX_PROT_EXEC: u64 = 0x4;
const LINUX_MAP_SHARED: u64 = 0x01;
const LINUX_MAP_PRIVATE: u64 = 0x02;
const LINUX_MAP_FIXED: u64 = 0x10;
const LINUX_MAP_ANONYMOUS: u64 = 0x20;
const LINUX_CLONE_VM: u64 = 0x0000_0100;
const LINUX_CLONE_FS: u64 = 0x0000_0200;
const LINUX_CLONE_FILES: u64 = 0x0000_0400;
const LINUX_CLONE_SIGHAND: u64 = 0x0000_0800;
const LINUX_CLONE_THREAD: u64 = 0x0001_0000;
const LINUX_DT_UNKNOWN: u8 = 0;
const LINUX_DT_DIR: u8 = 4;
const LINUX_DT_REG: u8 = 8;
const LINUX_DT_LNK: u8 = 10;
const LINUX_DT_SOCK: u8 = 12;
const LINUX_S_IFIFO: u32 = 0o010000;
const LINUX_S_IFDIR: u32 = 0o040000;
const LINUX_S_IFREG: u32 = 0o100000;
const LINUX_S_IFSOCK: u32 = 0o140000;
const LINUX_STAT_STRUCT_BYTES: usize = 144;
const LINUX_PATH_MAX: usize = 4096;
const LINUX_EINTR: i32 = 4;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EAGAIN: i32 = 11;
const LINUX_EACCES: i32 = 13;
const LINUX_ESRCH: i32 = 3;
const LINUX_EFAULT: i32 = 14;
const LINUX_EEXIST: i32 = 17;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOMEM: i32 = 12;
const LINUX_EPIPE: i32 = 32;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENODEV: i32 = 19;
const LINUX_ECHILD: i32 = 10;
const LINUX_SIG_BLOCK: u64 = 0;
const LINUX_SIG_UNBLOCK: u64 = 1;
const LINUX_SIG_SETMASK: u64 = 2;
const LINUX_SIG_DFL: u64 = 0;
const LINUX_SIG_IGN: u64 = 1;
const LINUX_SA_RESTORER: u64 = 0x0400_0000;
const LINUX_SA_RESTART: u64 = 0x1000_0000;
const LINUX_SIGKILL: i32 = 9;
const LINUX_SIGCHLD: i32 = 17;
const LINUX_SIGSTOP: i32 = 19;
const LINUX_SIGNAL_SET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LE: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
pub(crate) fn starnix_kernel_program_start(bootstrap_channel: zx_handle_t) -> ! {
    let mut status_handle = None;
    let mut controller_handle = None;
    let return_code = match read_start_info(bootstrap_channel) {
        Ok(start_info) => {
            status_handle = start_info.status_handle;
            controller_handle = start_info.controller_handle;
            run_executive(start_info)
        }
        Err(status) => map_status_to_return_code(status),
    };

    if let Some(handle) = status_handle {
        let _ = send_status_event(handle, return_code);
        let _ = zx_handle_close(handle);
    }
    if let Some(handle) = controller_handle {
        let _ = send_controller_event(handle, return_code);
        let _ = zx_handle_close(handle);
    }
    loop {
        core::hint::spin_loop();
    }
}

struct StarnixStartInfo {
    args: Vec<String>,
    env: Vec<String>,
    parent_process: zx_handle_t,
    linux_image_vmo: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
    status_handle: Option<zx_handle_t>,
    controller_handle: Option<zx_handle_t>,
}

struct PreparedLinuxStack {
    stack_pointer: u64,
    stack_vmo_offset: u64,
    image: Vec<u8>,
}

#[derive(Clone, Copy)]
struct LinuxLoadSegment {
    vaddr: u64,
    mem_size: usize,
    flags: u32,
    file_offset: usize,
    file_size: usize,
}

struct LinuxElf<'a> {
    entry: u64,
    phdr_vaddr: Option<u64>,
    phent: u16,
    phnum: u16,
    segments: Vec<LinuxLoadSegment>,
    bytes: &'a [u8],
}

enum SyscallAction {
    Resume,
    LeaveStopped,
    TaskExit(i32),
    GroupExit(i32),
    GroupSignalExit(i32),
}

enum SignalDeliveryAction {
    Ignore,
    Terminate,
    Catch(LinuxSigAction),
}

struct ExecutiveState {
    process_handle: zx_handle_t,
    fd_table: FdTable,
    namespace: nexus_io::ProcessNamespace,
    directory_offsets: BTreeMap<u64, usize>,
    linux_mm: LinuxMm,
}

#[derive(Clone, Copy)]
enum LinuxMapBacking {
    Anonymous { vmo: zx_handle_t },
    File { vmo: zx_handle_t, offset: u64 },
}

#[derive(Clone, Copy)]
struct LinuxMapEntry {
    base: u64,
    len: u64,
    prot: u64,
    backing: LinuxMapBacking,
}

struct LinuxMm {
    root_vmar: zx_handle_t,
    heap_vmar: zx_handle_t,
    heap_base: u64,
    heap_limit: u64,
    heap_vmo: zx_handle_t,
    heap_break: u64,
    heap_mapped_len: u64,
    mmap_vmar: zx_handle_t,
    mmap_base: u64,
    map_tree: BTreeMap<u64, LinuxMapEntry>,
}

#[derive(Clone)]
struct LinuxWritableRange {
    base: u64,
    len: u64,
}

#[derive(Clone)]
struct TaskImage {
    path: String,
    args: Vec<String>,
    env: Vec<String>,
    exec_blob: Vec<u8>,
    writable_ranges: Vec<LinuxWritableRange>,
}

#[derive(Clone, Copy, Default)]
struct LinuxSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[derive(Clone, Copy, Default)]
struct TaskSignals {
    blocked: u64,
    pending: u64,
}

#[derive(Clone, Copy)]
struct ActiveSignalFrame {
    restore_regs: ax_guest_x64_regs_t,
    previous_blocked: u64,
}

#[derive(Clone, Copy)]
struct TaskCarrier {
    thread_handle: zx_handle_t,
    session_handle: zx_handle_t,
    sidecar_vmo: zx_handle_t,
    packet_key: u64,
}

enum TaskState {
    Running,
    Waiting(WaitRequest),
}

#[derive(Clone, Copy)]
struct WaitRequest {
    target_pid: i32,
    status_addr: u64,
    restartable: bool,
}

struct LinuxTask {
    tid: i32,
    tgid: i32,
    carrier: TaskCarrier,
    state: TaskState,
    signals: TaskSignals,
    active_signal: Option<ActiveSignalFrame>,
}

enum ThreadGroupState {
    Running,
    Zombie { wait_status: i32, exit_code: i32 },
}

struct LinuxThreadGroup {
    tgid: i32,
    leader_tid: i32,
    parent_tgid: Option<i32>,
    child_tgids: BTreeSet<i32>,
    task_ids: BTreeSet<i32>,
    state: ThreadGroupState,
    shared_pending: u64,
    sigactions: BTreeMap<i32, LinuxSigAction>,
    image: Option<TaskImage>,
    resources: Option<ExecutiveState>,
}

struct StarnixKernel {
    parent_process: zx_handle_t,
    port: zx_handle_t,
    next_tid: i32,
    next_packet_key: u64,
    root_tgid: i32,
    tasks: BTreeMap<i32, LinuxTask>,
    groups: BTreeMap<i32, LinuxThreadGroup>,
}

struct PreparedProcessCarrier {
    process_handle: zx_handle_t,
    root_vmar: zx_handle_t,
    carrier: TaskCarrier,
    prepared_entry: u64,
    prepared_stack: u64,
}

impl TaskCarrier {
    fn close(self) {
        let _ = zx_handle_close(self.session_handle);
        let _ = zx_handle_close(self.sidecar_vmo);
        let _ = zx_handle_close(self.thread_handle);
    }

    fn kill_and_close(self) {
        let _ = zx_task_kill(self.thread_handle);
        self.close();
    }
}

impl PreparedProcessCarrier {
    fn close(self) {
        self.carrier.close();
        let _ = zx_handle_close(self.root_vmar);
        let _ = zx_handle_close(self.process_handle);
    }
}

impl StarnixKernel {
    fn new(
        parent_process: zx_handle_t,
        port: zx_handle_t,
        root_task: LinuxTask,
        root_group: LinuxThreadGroup,
    ) -> Self {
        let root_tgid = root_group.tgid;
        let mut tasks = BTreeMap::new();
        tasks.insert(root_task.tid, root_task);
        let mut groups = BTreeMap::new();
        groups.insert(root_group.tgid, root_group);
        Self {
            parent_process,
            port,
            next_tid: root_tgid + 1,
            next_packet_key: STARNIX_GUEST_PACKET_KEY_BASE + 1,
            root_tgid,
            tasks,
            groups,
        }
    }

    fn alloc_tid(&mut self) -> Result<i32, zx_status_t> {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(tid)
    }

    fn alloc_packet_key(&mut self) -> Result<u64, zx_status_t> {
        let key = self.next_packet_key;
        self.next_packet_key = self
            .next_packet_key
            .checked_add(1)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(key)
    }

    fn task_id_for_packet_key(&self, packet_key: u64) -> Option<i32> {
        self.tasks
            .iter()
            .find_map(|(tid, task)| (task.carrier.packet_key == packet_key).then_some(*tid))
    }

    fn run(&mut self) -> i32 {
        let mut stdout = Vec::new();
        loop {
            if let Some(status) = self.root_group_status() {
                return status;
            }
            let mut packet = zx_port_packet_t::default();
            let wait_status = zx_port_wait(self.port, ZX_TIME_INFINITE, &mut packet);
            if wait_status != ZX_OK {
                return map_status_to_return_code(wait_status);
            }
            if packet.type_ != ZX_PKT_TYPE_USER {
                return map_status_to_return_code(ZX_ERR_BAD_STATE);
            }
            let Some(task_id) = self.task_id_for_packet_key(packet.key) else {
                return map_status_to_return_code(ZX_ERR_BAD_STATE);
            };
            let reason = packet.user.u64[1] as u16;
            if reason != AX_GUEST_STOP_REASON_X64_SYSCALL {
                return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
            }
            let sidecar = self
                .tasks
                .get(&task_id)
                .map(|task| task.carrier.sidecar_vmo);
            let Some(sidecar) = sidecar else {
                return map_status_to_return_code(ZX_ERR_BAD_STATE);
            };
            let mut stop_state = match ax_guest_stop_state_read(sidecar) {
                Ok(stop_state) => stop_state,
                Err(status) => return map_status_to_return_code(status),
            };
            let action = match self.handle_syscall(task_id, &mut stop_state, &mut stdout) {
                Ok(action) => action,
                Err(status) => return map_status_to_return_code(status),
            };
            let action = match self.apply_signal_delivery(task_id, action, &mut stop_state) {
                Ok(action) => action,
                Err(status) => return map_status_to_return_code(status),
            };
            match action {
                SyscallAction::Resume => {
                    if let Err(status) = self.writeback_and_resume(task_id, &stop_state) {
                        return map_status_to_return_code(status);
                    }
                }
                SyscallAction::LeaveStopped => {}
                SyscallAction::TaskExit(code) => {
                    if let Err(status) = self.exit_task(task_id, code) {
                        return map_status_to_return_code(status);
                    }
                }
                SyscallAction::GroupExit(code) => {
                    if let Err(status) = self.exit_group(task_id, code) {
                        return map_status_to_return_code(status);
                    }
                }
                SyscallAction::GroupSignalExit(signal) => {
                    if let Err(status) = self.exit_group_from_signal(task_id, signal) {
                        return map_status_to_return_code(status);
                    }
                }
            }
        }
    }

    fn root_group_status(&self) -> Option<i32> {
        self.groups
            .get(&self.root_tgid)
            .and_then(|group| match group.state {
                ThreadGroupState::Zombie { exit_code, .. } => Some(exit_code),
                ThreadGroupState::Running => None,
            })
    }

    fn handle_syscall(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        match stop_state.regs.rax {
            LINUX_SYSCALL_GETPID => self.sys_getpid(task_id, stop_state),
            LINUX_SYSCALL_GETTID => self.sys_gettid(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGACTION => self.sys_rt_sigaction(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGPROCMASK => self.sys_rt_sigprocmask(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGRETURN => self.sys_rt_sigreturn(task_id, stop_state),
            LINUX_SYSCALL_CLONE => self.sys_clone(task_id, stop_state),
            LINUX_SYSCALL_FORK => self.sys_fork(task_id, stop_state),
            LINUX_SYSCALL_EXECVE => self.sys_execve(task_id, stop_state),
            LINUX_SYSCALL_WAIT4 => self.sys_wait4(task_id, stop_state),
            LINUX_SYSCALL_KILL => self.sys_kill(stop_state),
            LINUX_SYSCALL_TGKILL => self.sys_tgkill(stop_state),
            _ => {
                let session = self
                    .tasks
                    .get(&task_id)
                    .map(|task| task.carrier.session_handle)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                emulate_common_syscall(session, stop_state, resources, stdout)
            }
        }
    }

    fn apply_signal_delivery(
        &mut self,
        task_id: i32,
        action: SyscallAction,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        if !matches!(action, SyscallAction::Resume) {
            return Ok(action);
        }
        loop {
            let Some(signal) = self.take_deliverable_signal(task_id)? else {
                return Ok(action);
            };
            match self.signal_delivery_action(task_id, signal)? {
                SignalDeliveryAction::Ignore => {}
                SignalDeliveryAction::Terminate => {
                    return Ok(SyscallAction::GroupSignalExit(signal));
                }
                SignalDeliveryAction::Catch(sigaction) => {
                    let restore_regs = stop_state.regs;
                    self.install_signal_frame(
                        task_id,
                        signal,
                        sigaction,
                        stop_state,
                        ActiveSignalFrame {
                            restore_regs,
                            previous_blocked: self.task_signal_mask(task_id)?,
                        },
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
    }

    fn writeback_and_resume(
        &self,
        task_id: i32,
        stop_state: &ax_guest_stop_state_t,
    ) -> Result<(), zx_status_t> {
        let task = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let write_status = ax_guest_stop_state_write(task.carrier.sidecar_vmo, stop_state);
        zx_status_result(write_status)?;
        let resume_status =
            ax_guest_session_resume(task.carrier.session_handle, stop_state.stop_seq, 0);
        zx_status_result(resume_status)
    }

    fn write_wait_result(
        &mut self,
        task_id: i32,
        child_tgid: i32,
        status: i32,
    ) -> Result<(), zx_status_t> {
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let TaskState::Waiting(ref wait) = task.state else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if wait.status_addr != 0 {
            write_guest_bytes(
                task.carrier.session_handle,
                wait.status_addr,
                &status.to_ne_bytes(),
            )?;
        }
        let mut stop_state = ax_guest_stop_state_read(task.carrier.sidecar_vmo)?;
        complete_syscall(&mut stop_state, child_tgid as u64)?;
        task.state = TaskState::Running;
        self.writeback_and_resume(task_id, &stop_state)
    }

    fn wait_matches(target_pid: i32, child_tgid: i32) -> bool {
        target_pid == -1 || target_pid == child_tgid
    }

    fn maybe_wake_parent_waiter(
        &mut self,
        child_tgid: i32,
        status: i32,
    ) -> Result<(), zx_status_t> {
        let Some(parent_tgid) = self
            .groups
            .get(&child_tgid)
            .and_then(|group| group.parent_tgid)
        else {
            return Ok(());
        };
        let waiter = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .find_map(|task_id| {
                let task = self.tasks.get(task_id)?;
                match task.state {
                    TaskState::Waiting(ref wait)
                        if Self::wait_matches(wait.target_pid, child_tgid) =>
                    {
                        Some(*task_id)
                    }
                    _ => None,
                }
            });
        let Some(waiter_id) = waiter else {
            return Ok(());
        };
        self.write_wait_result(waiter_id, child_tgid, status)?;
        self.reap_group(child_tgid)
    }

    fn reap_group(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let parent_tgid = self.groups.get(&tgid).and_then(|group| group.parent_tgid);
        if let Some(parent_tgid) = parent_tgid
            && let Some(parent) = self.groups.get_mut(&parent_tgid)
        {
            parent.child_tgids.remove(&tgid);
        }
        let _ = self.groups.remove(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        Ok(())
    }

    fn finalize_group_zombie(
        &mut self,
        tgid: i32,
        wait_status: i32,
        exit_code: i32,
    ) -> Result<(), zx_status_t> {
        let child_tgids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        if tgid != self.root_tgid {
            for child_tgid in child_tgids {
                if child_tgid == self.root_tgid {
                    continue;
                }
                if let Some(root) = self.groups.get_mut(&self.root_tgid) {
                    root.child_tgids.insert(child_tgid);
                }
                if let Some(child) = self.groups.get_mut(&child_tgid) {
                    child.parent_tgid = Some(self.root_tgid);
                }
            }
        }
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(resources) = group.resources.take() {
            let _ = zx_task_kill(resources.process_handle);
            let _ = zx_handle_close(resources.process_handle);
            drop(resources);
        }
        group.image = None;
        group.shared_pending = 0;
        group.state = ThreadGroupState::Zombie {
            wait_status,
            exit_code,
        };
        self.maybe_wake_parent_waiter(tgid, wait_status)
    }

    fn finalize_group_exit(&mut self, tgid: i32, code: i32) -> Result<(), zx_status_t> {
        let wait_status = (code & 0xff) << 8;
        self.finalize_group_zombie(tgid, wait_status, code)
    }

    fn finalize_group_signal_exit(&mut self, tgid: i32, signal: i32) -> Result<(), zx_status_t> {
        let wait_status = signal & 0x7f;
        let exit_code = 128 + signal;
        self.finalize_group_zombie(tgid, wait_status, exit_code)
    }

    fn remove_group_tasks(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for member_id in &task_ids {
            if let Some(task) = self.tasks.remove(member_id) {
                task.carrier.kill_and_close();
            }
        }
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .clear();
        Ok(())
    }

    fn exit_task(&mut self, task_id: i32, code: i32) -> Result<(), zx_status_t> {
        let task = self.tasks.remove(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        task.carrier.kill_and_close();
        let tgid = task.tgid;
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        group.task_ids.remove(&task_id);
        if group.task_ids.is_empty() {
            self.finalize_group_exit(tgid, code)?;
        }
        Ok(())
    }

    fn exit_group(&mut self, task_id: i32, code: i32) -> Result<(), zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.remove_group_tasks(tgid)?;
        self.finalize_group_exit(tgid, code)
    }

    fn exit_group_from_signal(&mut self, task_id: i32, signal: i32) -> Result<(), zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.remove_group_tasks(tgid)?;
        self.finalize_group_signal_exit(tgid, signal)
    }

    fn task_signal_mask(&self, task_id: i32) -> Result<u64, zx_status_t> {
        self.tasks
            .get(&task_id)
            .map(|task| task.signals.blocked)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn install_signal_frame(
        &mut self,
        task_id: i32,
        signal: i32,
        action: LinuxSigAction,
        stop_state: &mut ax_guest_stop_state_t,
        frame: ActiveSignalFrame,
    ) -> Result<(), zx_status_t> {
        let signal_bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let stack_pointer = stop_state
            .regs
            .rsp
            .checked_sub(8)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        write_guest_bytes(session, stack_pointer, &action.restorer.to_ne_bytes())?;

        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        if task.active_signal.is_some() {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let mut blocked = frame.previous_blocked | action.mask;
        if (action.flags & LINUX_SA_RESTORER) == 0 || action.restorer == 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        blocked |= signal_bit;
        task.signals.blocked = normalize_signal_mask(blocked);
        task.active_signal = Some(frame);

        stop_state.regs.rsp = stack_pointer;
        stop_state.regs.rip = action.handler;
        stop_state.regs.rdi = signal as u64;
        stop_state.regs.rsi = 0;
        stop_state.regs.rdx = 0;
        Ok(())
    }

    fn deliver_or_interrupt_wait(
        &mut self,
        task_id: i32,
        wait: WaitRequest,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        loop {
            let Some(signal) = self.take_deliverable_signal(task_id)? else {
                return Ok(SyscallAction::LeaveStopped);
            };
            match self.signal_delivery_action(task_id, signal)? {
                SignalDeliveryAction::Ignore => {}
                SignalDeliveryAction::Terminate => {
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.state = TaskState::Running;
                    }
                    return Ok(SyscallAction::GroupSignalExit(signal));
                }
                SignalDeliveryAction::Catch(sigaction) => {
                    let previous_blocked = self.task_signal_mask(task_id)?;
                    let mut restore_regs = stop_state.regs;
                    if !wait.restartable || (sigaction.flags & LINUX_SA_RESTART) == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINTR))?;
                        restore_regs = stop_state.regs;
                    }
                    self.install_signal_frame(
                        task_id,
                        signal,
                        sigaction,
                        stop_state,
                        ActiveSignalFrame {
                            restore_regs,
                            previous_blocked,
                        },
                    )?;
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.state = TaskState::Running;
                    }
                    return Ok(SyscallAction::Resume);
                }
            }
        }
    }

    fn interrupt_waiting_task(&mut self, task_id: i32) -> Result<(), zx_status_t> {
        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(());
        };
        let TaskState::Waiting(wait) = &task.state else {
            return Ok(());
        };
        let wait = *wait;

        let sidecar = task.carrier.sidecar_vmo;
        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        match self.deliver_or_interrupt_wait(task_id, wait, &mut stop_state)? {
            SyscallAction::Resume => self.writeback_and_resume(task_id, &stop_state),
            SyscallAction::LeaveStopped => Ok(()),
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }

    fn service_pending_waiters(&mut self) -> Result<(), zx_status_t> {
        let waiting = self
            .tasks
            .iter()
            .filter_map(|(task_id, task)| {
                matches!(task.state, TaskState::Waiting(_)).then_some(*task_id)
            })
            .collect::<Vec<_>>();
        for task_id in waiting {
            if self.tasks.contains_key(&task_id) {
                self.interrupt_waiting_task(task_id)?;
            }
        }
        Ok(())
    }

    fn take_deliverable_signal(&mut self, task_id: i32) -> Result<Option<i32>, zx_status_t> {
        let blocked = self.task_signal_mask(task_id)?;
        let task_pending = self
            .tasks
            .get(&task_id)
            .map(|task| task.signals.pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(task_pending) {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.signals.pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            return Ok(Some(signal));
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let shared_pending = self
            .groups
            .get(&tgid)
            .map(|group| group.shared_pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(shared_pending) {
            if let Some(group) = self.groups.get_mut(&tgid) {
                group.shared_pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            return Ok(Some(signal));
        }

        Ok(None)
    }

    fn signal_delivery_action(
        &self,
        task_id: i32,
        signal: i32,
    ) -> Result<SignalDeliveryAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let action = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        match action.handler {
            LINUX_SIG_IGN => Ok(SignalDeliveryAction::Ignore),
            LINUX_SIG_DFL => {
                if signal_default_ignored(signal) {
                    Ok(SignalDeliveryAction::Ignore)
                } else {
                    Ok(SignalDeliveryAction::Terminate)
                }
            }
            _ => Ok(SignalDeliveryAction::Catch(action)),
        }
    }

    fn queue_signal_to_group(&mut self, tgid: i32, signal: i32) -> Result<u64, zx_status_t> {
        if signal == 0 {
            return Ok(0);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        let Some(group) = self.groups.get_mut(&tgid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if !matches!(group.state, ThreadGroupState::Running) {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        group.shared_pending |= bit;
        Ok(0)
    }

    fn queue_signal_to_task(
        &mut self,
        tgid: i32,
        tid: i32,
        signal: i32,
    ) -> Result<u64, zx_status_t> {
        if signal == 0 {
            return Ok(0);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        let Some(task) = self.tasks.get_mut(&tid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if task.tgid != tgid {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        task.signals.pending |= bit;
        Ok(0)
    }

    fn sys_getpid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        complete_syscall(stop_state, tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_gettid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, task_id as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_rt_sigprocmask(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let how = stop_state.regs.rdi;
        let set_addr = stop_state.regs.rsi;
        let oldset_addr = stop_state.regs.rdx;
        let sigset_size = stop_state.regs.r10;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let old_mask = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        if oldset_addr != 0 {
            match write_guest_signal_mask(session, oldset_addr, old_mask) {
                Ok(()) => {}
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
        if set_addr != 0 {
            let requested = match read_guest_signal_mask(session, set_addr) {
                Ok(mask) => mask,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };
            let requested = normalize_signal_mask(requested);
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            task.signals.blocked = match how {
                LINUX_SIG_BLOCK => task.signals.blocked | requested,
                LINUX_SIG_UNBLOCK => task.signals.blocked & !requested,
                LINUX_SIG_SETMASK => requested,
                _ => {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                }
            };
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_rt_sigaction(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let signal = stop_state.regs.rdi as u32 as i32;
        let act_addr = stop_state.regs.rsi;
        let oldact_addr = stop_state.regs.rdx;
        let sigset_size = stop_state.regs.r10;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64
            || !linux_signal_is_valid(signal)
            || signal == LINUX_SIGKILL
            || signal == LINUX_SIGSTOP
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let old_action = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        if oldact_addr != 0 {
            match write_guest_sigaction(session, oldact_addr, old_action) {
                Ok(()) => {}
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            }
        }
        if act_addr != 0 {
            let action = match read_guest_sigaction(session, act_addr) {
                Ok(action) => action,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };
            let supported_flags = LINUX_SA_RESTORER | LINUX_SA_RESTART;
            if (action.flags & !supported_flags) != 0 {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                return Ok(SyscallAction::Resume);
            }
            if action.handler != LINUX_SIG_DFL
                && action.handler != LINUX_SIG_IGN
                && ((action.flags & LINUX_SA_RESTORER) == 0 || action.restorer == 0)
            {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if action.handler == LINUX_SIG_DFL
                && action.flags == 0
                && action.restorer == 0
                && action.mask == 0
            {
                group.sigactions.remove(&signal);
            } else {
                group.sigactions.insert(signal, action);
            }
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_rt_sigreturn(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(frame) = task.active_signal.take() else {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        };
        task.signals.blocked = frame.previous_blocked;
        stop_state.regs = frame.restore_regs;
        Ok(SyscallAction::Resume)
    }

    fn sys_kill(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let pid = stop_state.regs.rdi as u32 as i32;
        let signal = stop_state.regs.rsi as u32 as i32;
        let result = if pid <= 0 || !linux_signal_is_valid_or_zero(signal) {
            linux_errno(LINUX_EINVAL)
        } else {
            self.queue_signal_to_group(pid, signal)?
        };
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_tgkill(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = stop_state.regs.rdi as u32 as i32;
        let tid = stop_state.regs.rsi as u32 as i32;
        let signal = stop_state.regs.rdx as u32 as i32;
        let result = if tgid <= 0 || tid <= 0 || !linux_signal_is_valid_or_zero(signal) {
            linux_errno(LINUX_EINVAL)
        } else {
            self.queue_signal_to_task(tgid, tid, signal)?
        };
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_clone(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let flags = stop_state.regs.rdi;
        let child_stack = stop_state.regs.rsi;
        let parent_tid_addr = stop_state.regs.rdx;
        let child_tid_addr = stop_state.regs.r10;
        let tls = stop_state.regs.r8;
        let exit_signal = flags & 0xff;
        let supported = LINUX_CLONE_VM
            | LINUX_CLONE_FS
            | LINUX_CLONE_FILES
            | LINUX_CLONE_SIGHAND
            | LINUX_CLONE_THREAD;
        let required = supported;
        if (flags & required) != required
            || (flags & !(supported | 0xff)) != 0
            || exit_signal != 0
            || parent_tid_addr != 0
            || child_tid_addr != 0
            || tls != 0
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let process_handle = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .resources
            .as_ref()
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_handle;
        let packet_key = self.alloc_packet_key()?;
        let child_tid = self.alloc_tid()?;
        let parent_blocked = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        let child_carrier = match create_thread_carrier(process_handle, self.port, packet_key) {
            Ok(carrier) => carrier,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };

        let mut child_regs = stop_state.regs;
        child_regs.rax = 0;
        child_regs.rip = child_regs
            .rip
            .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if child_stack != 0 {
            child_regs.rsp = child_stack;
        }
        let start_status = ax_thread_start_guest(child_carrier.thread_handle, &child_regs, 0);
        if let Err(status) = zx_status_result(start_status) {
            child_carrier.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        self.tasks.insert(
            child_tid,
            LinuxTask {
                tid: child_tid,
                tgid,
                carrier: child_carrier,
                state: TaskState::Running,
                signals: TaskSignals {
                    blocked: parent_blocked,
                    pending: 0,
                },
                active_signal: None,
            },
        );
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .insert(child_tid);
        complete_syscall(stop_state, child_tid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_fork(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let parent_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let parent_session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let parent_blocked = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .blocked;
        let (task_image, namespace) = {
            let group = self.groups.get(&parent_tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let image = group.image.clone().ok_or(ZX_ERR_BAD_STATE)?;
            let namespace = group
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?
                .namespace
                .clone();
            (image, namespace)
        };
        let parent_sigactions = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .sigactions
            .clone();
        let (_, _, image_vmo) = match open_exec_image_from_namespace(&namespace, &task_image.path) {
            Ok(opened) => opened,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };

        let child_tgid = self.alloc_tid()?;
        let packet_key = self.alloc_packet_key()?;
        let prepared = match prepare_process_carrier(
            self.parent_process,
            self.port,
            packet_key,
            image_vmo,
            &task_image.exec_blob,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);

        let child_resources = {
            let parent_resources = self
                .groups
                .get(&parent_tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?;
            match parent_resources.fork_clone(
                prepared.process_handle,
                prepared.root_vmar,
                parent_session,
                prepared.carrier.session_handle,
            ) {
                Ok(resources) => resources,
                Err(status) => {
                    prepared.close();
                    complete_syscall(stop_state, linux_errno(map_vm_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };

        for range in &task_image.writable_ranges {
            if let Err(status) = copy_guest_region(
                parent_session,
                prepared.carrier.session_handle,
                range.base,
                range.len,
            ) {
                prepared.close();
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        }
        if let Err(status) = copy_guest_region(
            parent_session,
            prepared.carrier.session_handle,
            USER_STACK_VA,
            USER_STACK_BYTES,
        ) {
            prepared.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_memory_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

        let mut child_regs = stop_state.regs;
        child_regs.rax = 0;
        child_regs.rip = child_regs
            .rip
            .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let (child_resources, child_carrier) =
            match start_prepared_carrier_guest(prepared, &child_regs, child_resources) {
                Ok(started) => started,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_start_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };

        let mut task_ids = BTreeSet::new();
        task_ids.insert(child_tgid);
        self.tasks.insert(
            child_tgid,
            LinuxTask {
                tid: child_tgid,
                tgid: child_tgid,
                carrier: child_carrier,
                state: TaskState::Running,
                signals: TaskSignals {
                    blocked: parent_blocked,
                    pending: 0,
                },
                active_signal: None,
            },
        );
        self.groups.insert(
            child_tgid,
            LinuxThreadGroup {
                tgid: child_tgid,
                leader_tid: child_tgid,
                parent_tgid: Some(parent_tgid),
                child_tgids: BTreeSet::new(),
                task_ids,
                state: ThreadGroupState::Running,
                shared_pending: 0,
                sigactions: parent_sigactions,
                image: Some(task_image),
                resources: Some(child_resources),
            },
        );
        self.groups
            .get_mut(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .insert(child_tgid);
        complete_syscall(stop_state, child_tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_execve(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if group.leader_tid != task_id || group.task_ids.len() != 1 {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                return Ok(SyscallAction::Resume);
            }
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, stop_state.regs.rdi, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let mut args = match read_guest_string_array(session, stop_state.regs.rsi, 128) {
            Ok(args) => args,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let env = match read_guest_string_array(session, stop_state.regs.rdx, 128) {
            Ok(env) => env,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let (resolved_path, image_bytes, image_vmo) = {
            let namespace = &self
                .groups
                .get(&tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?
                .namespace;
            match open_exec_image_from_namespace(namespace, &path) {
                Ok((resolved_path, image_bytes, image_vmo)) => {
                    (resolved_path, image_bytes, image_vmo)
                }
                Err(status) => {
                    complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if args.is_empty() {
            args.push(resolved_path.clone());
        }
        let task_image = match build_task_image(&resolved_path, &args, &env, &image_bytes) {
            Ok(image) => image,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                complete_syscall(stop_state, linux_errno(map_exec_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let packet_key = self.alloc_packet_key()?;
        let prepared = match prepare_process_carrier(
            self.parent_process,
            self.port,
            packet_key,
            image_vmo,
            &task_image.exec_blob,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);

        let new_resources = {
            let resources = self
                .groups
                .get(&tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .resources
                .as_ref()
                .ok_or(ZX_ERR_BAD_STATE)?;
            match resources.exec_replace(prepared.process_handle, prepared.root_vmar) {
                Ok(resources) => resources,
                Err(status) => {
                    prepared.close();
                    complete_syscall(stop_state, linux_errno(map_vm_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
        let (new_resources, new_carrier) =
            match start_prepared_carrier_guest(prepared, &regs, new_resources) {
                Ok(started) => started,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_start_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };

        let old_carrier = {
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let old_carrier = task.carrier;
            task.carrier = new_carrier;
            task.active_signal = None;
            old_carrier
        };
        let old_resources = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            group.image = Some(task_image);
            group
                .resources
                .replace(new_resources)
                .ok_or(ZX_ERR_BAD_STATE)?
        };
        let _ = zx_task_kill(old_resources.process_handle);
        old_carrier.close();
        drop(old_resources);
        Ok(SyscallAction::LeaveStopped)
    }

    fn sys_wait4(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_pid = stop_state.regs.rdi as u32 as i32;
        let status_addr = stop_state.regs.rsi;
        let options = stop_state.regs.rdx;
        let rusage_addr = stop_state.regs.r10;
        if options != 0 || rusage_addr != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if target_pid == 0 || target_pid < -1 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let parent_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let child_tgids = self
            .groups
            .get(&parent_tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .child_tgids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut has_match = false;
        for child_tgid in child_tgids {
            if !Self::wait_matches(target_pid, child_tgid) {
                continue;
            }
            has_match = true;
            let Some(child_group) = self.groups.get(&child_tgid) else {
                continue;
            };
            if let ThreadGroupState::Zombie { wait_status, .. } = child_group.state {
                if status_addr != 0 {
                    write_guest_bytes(
                        self.tasks
                            .get(&task_id)
                            .ok_or(ZX_ERR_BAD_STATE)?
                            .carrier
                            .session_handle,
                        status_addr,
                        &wait_status.to_ne_bytes(),
                    )
                    .map_err(|status| {
                        linux_status_from_errno(map_guest_write_status_to_errno(status))
                    })?;
                }
                complete_syscall(stop_state, child_tgid as u64)?;
                self.reap_group(child_tgid)?;
                return Ok(SyscallAction::Resume);
            }
        }
        if !has_match {
            complete_syscall(stop_state, linux_errno(LINUX_ECHILD))?;
            return Ok(SyscallAction::Resume);
        }

        let wait = WaitRequest {
            target_pid,
            status_addr,
            restartable: true,
        };
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
    }
}

fn read_start_info(bootstrap_channel: zx_handle_t) -> Result<StarnixStartInfo, zx_status_t> {
    let (bytes, handles) = read_channel_alloc_blocking(bootstrap_channel)?;
    let start_info = ComponentStartInfo::decode_channel_message(&bytes, &handles)
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    let mut linux_image_vmo = ZX_HANDLE_INVALID;
    let mut parent_process = ZX_HANDLE_INVALID;
    let mut stdout_handle = None;
    let mut status_handle = None;
    for NumberedHandle { id, handle } in start_info.numbered_handles {
        if id == STARTUP_HANDLE_COMPONENT_STATUS {
            status_handle = Some(handle);
        } else if id == STARTUP_HANDLE_STARNIX_IMAGE_VMO {
            linux_image_vmo = handle;
        } else if id == STARTUP_HANDLE_STARNIX_PARENT_PROCESS {
            parent_process = handle;
        } else if id == STARTUP_HANDLE_STARNIX_STDOUT {
            stdout_handle = Some(handle);
        }
    }
    if linux_image_vmo == ZX_HANDLE_INVALID || parent_process == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_NOT_FOUND);
    }
    Ok(StarnixStartInfo {
        args: start_info.args,
        env: start_info.env,
        parent_process,
        linux_image_vmo,
        stdout_handle,
        status_handle,
        controller_handle: start_info.controller_channel,
    })
}

fn run_executive(start_info: StarnixStartInfo) -> i32 {
    let StarnixStartInfo {
        args,
        env,
        parent_process,
        linux_image_vmo,
        stdout_handle,
        status_handle: _,
        controller_handle: _,
    } = start_info;
    let Some(payload_path) = payload_path_for(&args) else {
        return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
    };
    let Some(payload_bytes) = payload_bytes_for(&args) else {
        return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
    };
    let mut port = ZX_HANDLE_INVALID;
    if zx_port_create(0, &mut port) != ZX_OK {
        let _ = zx_handle_close(linux_image_vmo);
        let _ = zx_handle_close(parent_process);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return 1;
    }
    let task_image = match build_task_image(payload_path, &args, &env, payload_bytes) {
        Ok(image) => image,
        Err(status) => return map_status_to_return_code(status),
    };
    let prepared = match prepare_process_carrier(
        parent_process,
        port,
        STARNIX_GUEST_PACKET_KEY,
        linux_image_vmo,
        &task_image.exec_blob,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            let _ = zx_handle_close(linux_image_vmo);
            let _ = zx_handle_close(port);
            let _ = zx_handle_close(parent_process);
            if let Some(stdout) = stdout_handle {
                let _ = zx_handle_close(stdout);
            }
            return map_status_to_return_code(status);
        }
    };
    let _ = zx_handle_close(linux_image_vmo);
    let resources =
        match ExecutiveState::new(prepared.process_handle, prepared.root_vmar, stdout_handle) {
            Ok(resources) => resources,
            Err(status) => {
                prepared.close();
                let _ = zx_handle_close(port);
                let _ = zx_handle_close(parent_process);
                if let Some(stdout) = stdout_handle {
                    let _ = zx_handle_close(stdout);
                }
                return map_status_to_return_code(status);
            }
        };
    let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
    let (resources, carrier) = match start_prepared_carrier_guest(prepared, &regs, resources) {
        Ok(started) => started,
        Err(status) => {
            let _ = zx_handle_close(port);
            let _ = zx_handle_close(parent_process);
            if let Some(stdout) = stdout_handle {
                let _ = zx_handle_close(stdout);
            }
            return map_status_to_return_code(status);
        }
    };
    let root_task = LinuxTask {
        tid: 1,
        tgid: 1,
        carrier,
        state: TaskState::Running,
        signals: TaskSignals::default(),
        active_signal: None,
    };
    let mut task_ids = BTreeSet::new();
    task_ids.insert(1);
    let root_group = LinuxThreadGroup {
        tgid: 1,
        leader_tid: 1,
        parent_tgid: None,
        child_tgids: BTreeSet::new(),
        task_ids,
        state: ThreadGroupState::Running,
        shared_pending: 0,
        sigactions: BTreeMap::new(),
        image: Some(task_image),
        resources: Some(resources),
    };
    let mut kernel = StarnixKernel::new(parent_process, port, root_task, root_group);
    let result = kernel.run();
    let _ = zx_handle_close(port);
    let _ = zx_handle_close(parent_process);
    result
}

fn supervise_guest(
    _process: zx_handle_t,
    _root_vmar: zx_handle_t,
    _session: zx_handle_t,
    _port: zx_handle_t,
    _sidecar: zx_handle_t,
    _stdout_handle: Option<zx_handle_t>,
) -> i32 {
    map_status_to_return_code(ZX_ERR_NOT_SUPPORTED)
}

fn emulate_common_syscall(
    session: zx_handle_t,
    stop_state: &mut ax_guest_stop_state_t,
    executive: &mut ExecutiveState,
    stdout: &mut Vec<u8>,
) -> Result<SyscallAction, zx_status_t> {
    match stop_state.regs.rax {
        LINUX_SYSCALL_READ => {
            let fd = i32::try_from(stop_state.regs.rdi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let buf = stop_state.regs.rsi;
            let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
            bytes.resize(len, 0);
            let result = match executive.fd_table.read(fd, &mut bytes) {
                Ok(actual) => match write_guest_bytes(session, buf, &bytes[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                },
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            };
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_WRITE => {
            let fd = i32::try_from(stop_state.regs.rdi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let buf = stop_state.regs.rsi;
            let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let bytes = match read_guest_bytes(session, buf, len) {
                Ok(bytes) => bytes,
                Err(status) => {
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_memory_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
            };
            let result = match executive.fd_table.write(fd, &bytes) {
                Ok(actual) => {
                    if fd == 1 || fd == 2 {
                        stdout.extend_from_slice(&bytes[..actual]);
                    }
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?
                }
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            };
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_CLOSE => {
            let fd = i32::try_from(stop_state.regs.rdi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let result = match executive.fd_table.close(fd) {
                Ok(()) => 0,
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            };
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_FSTAT => {
            let fd = i32::try_from(stop_state.regs.rdi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let stat_addr = stop_state.regs.rsi;
            let result = executive.stat_fd(session, fd, stat_addr)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_MMAP => {
            let addr = stop_state.regs.rdi;
            let len = stop_state.regs.rsi;
            let prot = stop_state.regs.rdx;
            let flags = stop_state.regs.r10;
            let fd = stop_state.regs.r8 as i32;
            let offset = stop_state.regs.r9;
            let result = executive.mmap(addr, len, prot, flags, fd, offset)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_MPROTECT => {
            let addr = stop_state.regs.rdi;
            let len = stop_state.regs.rsi;
            let prot = stop_state.regs.rdx;
            let result = executive.mprotect(addr, len, prot)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_MUNMAP => {
            let addr = stop_state.regs.rdi;
            let len = stop_state.regs.rsi;
            let result = executive.munmap(addr, len)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_BRK => {
            let addr = stop_state.regs.rdi;
            let result = executive.brk(addr)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_GETDENTS64 => {
            let fd = i32::try_from(stop_state.regs.rdi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let dirent_addr = stop_state.regs.rsi;
            let count = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let result = executive.getdents64(session, fd, dirent_addr, count)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_PIPE2 => {
            let pipefd = stop_state.regs.rdi;
            let flags = stop_state.regs.rsi;
            let result = executive.create_pipe(session, pipefd, flags)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_OPENAT => {
            let dirfd = stop_state.regs.rdi as i32;
            let path = stop_state.regs.rsi;
            let flags = stop_state.regs.rdx;
            let mode = stop_state.regs.r10;
            let result = executive.openat(session, dirfd, path, flags, mode)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_NEWFSTATAT => {
            let dirfd = stop_state.regs.rdi as i32;
            let path = stop_state.regs.rsi;
            let stat_addr = stop_state.regs.rdx;
            let flags = stop_state.regs.r10;
            let result = executive.statat(session, dirfd, path, stat_addr, flags)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_SOCKETPAIR => {
            let domain = stop_state.regs.rdi;
            let socket_type = stop_state.regs.rsi;
            let protocol = stop_state.regs.rdx;
            let pair = stop_state.regs.r10;
            let result =
                executive.create_socketpair(session, domain, socket_type, protocol, pair)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_EXIT => {
            let code =
                i32::try_from(stop_state.regs.rdi & 0xff).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            Ok(SyscallAction::TaskExit(code))
        }
        LINUX_SYSCALL_EXIT_GROUP => {
            let code =
                i32::try_from(stop_state.regs.rdi & 0xff).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            Ok(SyscallAction::GroupExit(code))
        }
        _ => {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            Ok(SyscallAction::Resume)
        }
    }
}

fn payload_bytes_for(args: &[String]) -> Option<&'static [u8]> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BYTES),
        Some("linux-fd-smoke") => Some(LINUX_FD_SMOKE_BYTES),
        Some("linux-round2-smoke") => Some(LINUX_ROUND2_BYTES),
        Some("linux-round3-smoke") => Some(LINUX_ROUND3_BYTES),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BYTES),
        Some(_) => None,
    }
}

fn payload_path_for(args: &[String]) -> Option<&'static str> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BINARY_PATH),
        Some("linux-fd-smoke") => Some(LINUX_FD_SMOKE_BINARY_PATH),
        Some("linux-round2-smoke") => Some(LINUX_ROUND2_BINARY_PATH),
        Some("linux-round3-smoke") => Some(LINUX_ROUND3_BINARY_PATH),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BINARY_PATH),
        Some(_) => None,
    }
}

fn build_task_image(
    path: &str,
    args: &[String],
    env: &[String],
    bytes: &[u8],
) -> Result<TaskImage, zx_status_t> {
    let elf = parse_elf(bytes)?;
    let stack = build_initial_stack(args, env, &elf)?;
    let exec_blob = ax_linux_exec_spec_blob(
        ax_linux_exec_spec_header_t {
            version: AX_LINUX_EXEC_SPEC_V1,
            flags: 0,
            entry: elf.entry,
            stack_pointer: stack.stack_pointer,
            stack_vmo_offset: stack.stack_vmo_offset,
            stack_bytes_len: stack.image.len() as u64,
        },
        &stack.image,
    )?;
    let mut writable_ranges = Vec::new();
    for segment in &elf.segments {
        if (segment.flags & 0x2) == 0 {
            continue;
        }
        let map_base = segment.vaddr & !(USER_PAGE_BYTES - 1);
        let page_delta = segment
            .vaddr
            .checked_sub(map_base)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let len = align_up_u64(
            page_delta
                .checked_add(segment.mem_size as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            USER_PAGE_BYTES,
        )
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if len == 0 {
            continue;
        }
        writable_ranges
            .try_reserve(1)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        writable_ranges.push(LinuxWritableRange {
            base: map_base,
            len,
        });
    }
    Ok(TaskImage {
        path: String::from(path),
        args: args.to_vec(),
        env: env.to_vec(),
        exec_blob,
        writable_ranges,
    })
}

fn parse_elf(bytes: &[u8]) -> Result<LinuxElf<'_>, zx_status_t> {
    if bytes.len() < ELF64_EHDR_SIZE || &bytes[..4] != b"\x7fELF" {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    if bytes[4] != ELF_CLASS_64 || bytes[5] != ELF_DATA_LE {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    if read_u16(bytes, 16)? != ET_EXEC || read_u16(bytes, 18)? != EM_X86_64 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let entry = read_u64(bytes, 24)?;
    let phoff = usize::try_from(read_u64(bytes, 32)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    let phentsize = read_u16(bytes, 54)?;
    let phnum = read_u16(bytes, 56)?;
    if phentsize as usize != ELF64_PHDR_SIZE {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let phdr_table_bytes = usize::from(phnum)
        .checked_mul(ELF64_PHDR_SIZE)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let phdr_end = phoff
        .checked_add(phdr_table_bytes)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    if phdr_end > bytes.len() {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }

    let mut phdr_vaddr = None;
    let mut segments = Vec::new();
    for index in 0..usize::from(phnum) {
        let base = phoff + index * ELF64_PHDR_SIZE;
        let p_type = read_u32(bytes, base)?;
        let p_offset =
            usize::try_from(read_u64(bytes, base + 8)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_vaddr = read_u64(bytes, base + 16)?;
        let p_filesz =
            usize::try_from(read_u64(bytes, base + 32)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_memsz =
            usize::try_from(read_u64(bytes, base + 40)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        if p_type == PT_PHDR {
            phdr_vaddr = Some(p_vaddr);
        }
        if p_type == PT_LOAD {
            let file_end = p_offset
                .checked_add(p_filesz)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            if file_end > bytes.len() {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            if phdr_vaddr.is_none() && p_offset <= phoff && phdr_end <= file_end {
                phdr_vaddr = Some(
                    p_vaddr
                        .checked_add(
                            u64::try_from(phoff - p_offset)
                                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
                        )
                        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?,
                );
            }
            segments.try_reserve(1).map_err(|_| ZX_ERR_INTERNAL)?;
            segments.push(LinuxLoadSegment {
                vaddr: p_vaddr,
                mem_size: p_memsz,
                flags: read_u32(bytes, base + 4)?,
                file_offset: p_offset,
                file_size: p_filesz,
            });
        }
    }
    if segments.is_empty() {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    Ok(LinuxElf {
        entry,
        phdr_vaddr,
        phent: phentsize,
        phnum,
        segments,
        bytes,
    })
}

fn build_initial_stack(
    args: &[String],
    env: &[String],
    elf: &LinuxElf<'_>,
) -> Result<PreparedLinuxStack, zx_status_t> {
    let argv = if args.is_empty() {
        let mut argv = Vec::new();
        argv.try_reserve_exact(1).map_err(|_| ZX_ERR_INTERNAL)?;
        argv.push(String::from("linux-hello"));
        argv
    } else {
        args.to_vec()
    };
    let envv = env.to_vec();
    let mut auxv = Vec::new();
    auxv.try_reserve_exact(6).map_err(|_| ZX_ERR_INTERNAL)?;
    auxv.push((AT_PAGESZ, USER_PAGE_BYTES));
    auxv.push((AT_ENTRY, elf.entry));
    if let Some(phdr_vaddr) = elf.phdr_vaddr {
        auxv.push((AT_PHDR, phdr_vaddr));
        auxv.push((AT_PHENT, u64::from(elf.phent)));
        auxv.push((AT_PHNUM, u64::from(elf.phnum)));
    }
    auxv.push((AT_NULL, 0));

    let stack_len = usize::try_from(USER_STACK_BYTES).map_err(|_| ZX_ERR_INTERNAL)?;
    let mut cursor = stack_len;
    let mut string_ptrs = Vec::new();
    let total_strings = argv.len().checked_add(envv.len()).ok_or(ZX_ERR_INTERNAL)?;
    string_ptrs
        .try_reserve_exact(total_strings)
        .map_err(|_| ZX_ERR_INTERNAL)?;

    for value in envv.iter().rev().chain(argv.iter().rev()) {
        let bytes = value.as_bytes();
        cursor = cursor
            .checked_sub(bytes.len().checked_add(1).ok_or(ZX_ERR_INTERNAL)?)
            .ok_or(ZX_ERR_INTERNAL)?;
        string_ptrs.push((
            USER_STACK_VA
                .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?)
                .ok_or(ZX_ERR_INTERNAL)?,
            bytes,
        ));
    }
    string_ptrs.reverse();

    let argv_ptrs = &string_ptrs[..argv.len()];
    let env_ptrs = &string_ptrs[argv.len()..];
    let mut words = Vec::new();
    let word_count = 1usize
        .checked_add(argv_ptrs.len())
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(env_ptrs.len()))
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(auxv.len().checked_mul(2)?))
        .ok_or(ZX_ERR_INTERNAL)?;
    words
        .try_reserve_exact(word_count)
        .map_err(|_| ZX_ERR_INTERNAL)?;
    words.push(argv.len() as u64);
    for (ptr, _) in argv_ptrs {
        words.push(*ptr);
    }
    words.push(0);
    for (ptr, _) in env_ptrs {
        words.push(*ptr);
    }
    words.push(0);
    for (key, value) in auxv {
        words.push(key);
        words.push(value);
    }

    let words_bytes = words.len().checked_mul(8).ok_or(ZX_ERR_INTERNAL)?;
    cursor = cursor.checked_sub(words_bytes).ok_or(ZX_ERR_INTERNAL)?;
    cursor &= !0xFusize;
    let total_bytes = stack_len.checked_sub(cursor).ok_or(ZX_ERR_INTERNAL)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(total_bytes)
        .map_err(|_| ZX_ERR_INTERNAL)?;
    image.resize(total_bytes, 0);

    let words_offset = 0usize;
    for (index, word) in words.iter().enumerate() {
        let start = words_offset + index * 8;
        image[start..start + 8].copy_from_slice(&word.to_ne_bytes());
    }
    for (ptr, bytes) in &string_ptrs {
        let guest_offset = usize::try_from(ptr.checked_sub(USER_STACK_VA).ok_or(ZX_ERR_INTERNAL)?)
            .map_err(|_| ZX_ERR_INTERNAL)?;
        let local_offset = guest_offset.checked_sub(cursor).ok_or(ZX_ERR_INTERNAL)?;
        let end = local_offset
            .checked_add(bytes.len())
            .ok_or(ZX_ERR_INTERNAL)?;
        image[local_offset..end].copy_from_slice(bytes);
        image[end] = 0;
    }

    Ok(PreparedLinuxStack {
        stack_pointer: USER_STACK_VA
            .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?)
            .ok_or(ZX_ERR_INTERNAL)?,
        stack_vmo_offset: u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?,
        image,
    })
}

fn read_guest_bytes(session: zx_handle_t, addr: u64, len: usize) -> Result<Vec<u8>, zx_status_t> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_INTERNAL)?;
    bytes.resize(len, 0);
    let status = ax_guest_session_read_memory(session, addr, &mut bytes);
    if status != ZX_OK {
        return Err(status);
    }
    Ok(bytes)
}

fn write_guest_bytes(session: zx_handle_t, addr: u64, bytes: &[u8]) -> Result<(), zx_status_t> {
    let status = ax_guest_session_write_memory(session, addr, bytes);
    if status == ZX_OK { Ok(()) } else { Err(status) }
}

fn copy_guest_region(
    src_session: zx_handle_t,
    dst_session: zx_handle_t,
    base: u64,
    len: u64,
) -> Result<(), zx_status_t> {
    let mut offset = 0u64;
    let chunk = [0u8; 4096];
    while offset < len {
        let remaining = len - offset;
        let chunk_len = remaining.min(chunk.len() as u64) as usize;
        let bytes = read_guest_bytes(src_session, base + offset, chunk_len)?;
        write_guest_bytes(dst_session, base + offset, &bytes)?;
        offset = offset
            .checked_add(chunk_len as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    Ok(())
}

fn read_all_fd_bytes(ops: &dyn FdOps) -> Result<Vec<u8>, zx_status_t> {
    let metadata = local_fd_metadata(ops).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let len = usize::try_from(metadata.size_bytes).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(len, 0);
    let actual = ops.read(&mut bytes)?;
    bytes.truncate(actual);
    Ok(bytes)
}

fn open_exec_image_from_namespace(
    namespace: &nexus_io::ProcessNamespace,
    path: &str,
) -> Result<(String, Vec<u8>, zx_handle_t), zx_status_t> {
    let resolved = namespace.resolve_path(path)?;
    let ops = namespace.open(resolved.as_str(), OpenFlags::READABLE)?;
    let bytes = read_all_fd_bytes(ops.as_ref())?;
    let vmo = ops.as_vmo(nexus_io::VmoFlags::READ | nexus_io::VmoFlags::EXECUTE)?;
    Ok((resolved, bytes, vmo))
}

fn prepare_process_carrier(
    parent_process: zx_handle_t,
    port: zx_handle_t,
    packet_key: u64,
    image_vmo: zx_handle_t,
    exec_blob: &[u8],
) -> Result<PreparedProcessCarrier, zx_status_t> {
    let mut process = ZX_HANDLE_INVALID;
    let mut root_vmar = ZX_HANDLE_INVALID;
    zx_status_result(zx_process_create(
        parent_process,
        0,
        &mut process,
        &mut root_vmar,
    ))?;
    let mut thread = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_thread_create(process, 0, &mut thread)) {
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut sidecar = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_vmo_create(
        ax_guest_stop_state_t::BYTE_LEN as u64,
        0,
        &mut sidecar,
    )) {
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut session = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(ax_guest_session_create(
        thread,
        sidecar,
        port,
        packet_key,
        0,
        &mut session,
    )) {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut prepared_entry = 0u64;
    let mut prepared_stack = 0u64;
    let prepare_status = ax_process_prepare_linux_exec(
        process,
        image_vmo,
        0,
        exec_blob,
        &mut prepared_entry,
        &mut prepared_stack,
    );
    if prepare_status != ZX_OK {
        let carrier = TaskCarrier {
            thread_handle: thread,
            session_handle: session,
            sidecar_vmo: sidecar,
            packet_key,
        };
        carrier.close();
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(prepare_status);
    }
    Ok(PreparedProcessCarrier {
        process_handle: process,
        root_vmar,
        carrier: TaskCarrier {
            thread_handle: thread,
            session_handle: session,
            sidecar_vmo: sidecar,
            packet_key,
        },
        prepared_entry,
        prepared_stack,
    })
}

fn linux_guest_initial_regs(entry: u64, stack: u64) -> ax_guest_x64_regs_t {
    ax_guest_x64_regs_t {
        rax: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        r10: 0,
        r8: 0,
        r9: 0,
        rcx: 0,
        r11: 0,
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: entry,
        rsp: stack,
        rflags: 0x202,
    }
}

fn start_prepared_carrier_guest(
    prepared: PreparedProcessCarrier,
    regs: &ax_guest_x64_regs_t,
    resources: ExecutiveState,
) -> Result<(ExecutiveState, TaskCarrier), zx_status_t> {
    let start_status = ax_process_start_guest(
        prepared.process_handle,
        prepared.carrier.thread_handle,
        regs,
        0,
    );
    if let Err(status) = zx_status_result(start_status) {
        prepared.close();
        return Err(status);
    }
    Ok((resources, prepared.carrier))
}

fn create_thread_carrier(
    process_handle: zx_handle_t,
    port: zx_handle_t,
    packet_key: u64,
) -> Result<TaskCarrier, zx_status_t> {
    let mut thread = ZX_HANDLE_INVALID;
    zx_status_result(zx_thread_create(process_handle, 0, &mut thread))?;

    let mut sidecar = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_vmo_create(
        ax_guest_stop_state_t::BYTE_LEN as u64,
        0,
        &mut sidecar,
    )) {
        let _ = zx_handle_close(thread);
        return Err(status);
    }

    let mut session = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(ax_guest_session_create(
        thread,
        sidecar,
        port,
        packet_key,
        0,
        &mut session,
    )) {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(thread);
        return Err(status);
    }

    Ok(TaskCarrier {
        thread_handle: thread,
        session_handle: session,
        sidecar_vmo: sidecar,
        packet_key,
    })
}

fn complete_syscall(
    stop_state: &mut ax_guest_stop_state_t,
    result: u64,
) -> Result<(), zx_status_t> {
    stop_state.regs.rax = result;
    stop_state.regs.rip = stop_state
        .regs
        .rip
        .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
        .ok_or(ZX_ERR_INVALID_ARGS)?;
    Ok(())
}

fn linux_signal_is_valid(signal: i32) -> bool {
    (1..=64).contains(&signal)
}

fn linux_signal_is_valid_or_zero(signal: i32) -> bool {
    signal == 0 || linux_signal_is_valid(signal)
}

fn linux_signal_bit(signal: i32) -> Option<u64> {
    if !linux_signal_is_valid(signal) {
        return None;
    }
    Some(1u64 << ((signal - 1) as u32))
}

fn lowest_signal(mask: u64) -> Option<i32> {
    if mask == 0 {
        None
    } else {
        Some(mask.trailing_zeros() as i32 + 1)
    }
}

fn signal_default_ignored(signal: i32) -> bool {
    signal == LINUX_SIGCHLD
}

fn normalize_signal_mask(mask: u64) -> u64 {
    let mut normalized = mask;
    if let Some(bit) = linux_signal_bit(LINUX_SIGKILL) {
        normalized &= !bit;
    }
    if let Some(bit) = linux_signal_bit(LINUX_SIGSTOP) {
        normalized &= !bit;
    }
    normalized
}

fn read_guest_signal_mask(session: zx_handle_t, addr: u64) -> Result<u64, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_SIGNAL_SET_BYTES)?;
    let raw = bytes
        .get(..LINUX_SIGNAL_SET_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u64::from_ne_bytes(
        raw.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
}

fn write_guest_signal_mask(session: zx_handle_t, addr: u64, mask: u64) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &mask.to_ne_bytes())
}

fn read_guest_sigaction(session: zx_handle_t, addr: u64) -> Result<LinuxSigAction, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_SIGACTION_BYTES)?;
    let raw = bytes
        .get(..LINUX_SIGACTION_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxSigAction {
        handler: u64::from_ne_bytes(raw[0..8].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        flags: u64::from_ne_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
        restorer: u64::from_ne_bytes(
            raw[16..24]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
        mask: u64::from_ne_bytes(
            raw[24..32]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
    })
}

fn write_guest_sigaction(
    session: zx_handle_t,
    addr: u64,
    action: LinuxSigAction,
) -> Result<(), zx_status_t> {
    let mut bytes = [0u8; LINUX_SIGACTION_BYTES];
    bytes[0..8].copy_from_slice(&action.handler.to_ne_bytes());
    bytes[8..16].copy_from_slice(&action.flags.to_ne_bytes());
    bytes[16..24].copy_from_slice(&action.restorer.to_ne_bytes());
    bytes[24..32].copy_from_slice(&action.mask.to_ne_bytes());
    write_guest_bytes(session, addr, &bytes)
}

fn linux_errno(errno: i32) -> u64 {
    (-(i64::from(errno))) as u64
}

fn map_fd_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_ALREADY_EXISTS => LINUX_EEXIST,
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_IO_DATA_INTEGRITY => LINUX_EIO,
        ZX_ERR_NOT_DIR => LINUX_ENOTDIR,
        ZX_ERR_NOT_FILE => LINUX_EISDIR,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        ZX_ERR_PEER_CLOSED => LINUX_EPIPE,
        ZX_ERR_SHOULD_WAIT => LINUX_EAGAIN,
        _ => LINUX_EBADF,
    }
}

#[derive(Clone, Copy)]
struct LinuxStatMetadata {
    mode: u32,
    size_bytes: u64,
}

impl ExecutiveState {
    fn new(
        process_handle: zx_handle_t,
        root_vmar: zx_handle_t,
        stdout_handle: Option<zx_handle_t>,
    ) -> Result<Self, zx_status_t> {
        let mut fd_table = FdTable::new();
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
        Ok(Self {
            process_handle,
            fd_table,
            namespace: build_starnix_namespace()?,
            directory_offsets: BTreeMap::new(),
            linux_mm: LinuxMm::new(root_vmar)?,
        })
    }

    fn fork_clone(
        &self,
        child_process: zx_handle_t,
        child_root_vmar: zx_handle_t,
        parent_session: zx_handle_t,
        child_session: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        Ok(Self {
            process_handle: child_process,
            fd_table: self.fd_table.clone(),
            namespace: self.namespace.clone(),
            directory_offsets: self.directory_offsets.clone(),
            linux_mm: self
                .linux_mm
                .fork_clone(child_root_vmar, parent_session, child_session)?,
        })
    }

    fn exec_replace(
        &self,
        process_handle: zx_handle_t,
        root_vmar: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        Ok(Self {
            process_handle,
            fd_table: self.fd_table.clone(),
            namespace: self.namespace.clone(),
            directory_offsets: BTreeMap::new(),
            linux_mm: LinuxMm::new(root_vmar)?,
        })
    }

    fn brk(&mut self, addr: u64) -> Result<u64, zx_status_t> {
        Ok(self.linux_mm.brk(addr))
    }

    fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i32,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        self.linux_mm
            .mmap(&self.fd_table, addr, len, prot, flags, fd, offset)
    }

    fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
        self.linux_mm.munmap(addr, len)
    }

    fn mprotect(&mut self, addr: u64, len: u64, prot: u64) -> Result<u64, zx_status_t> {
        self.linux_mm.mprotect(addr, len, prot)
    }

    fn create_pipe(
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
        let read_fd = self.fd_table.open(
            Arc::new(PipeFd::new(read_end)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        let write_fd = self.fd_table.open(
            Arc::new(PipeFd::new(write_end)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        match (read_fd, write_fd) {
            (Ok(read_fd), Ok(write_fd)) => {
                if let Err(status) = write_guest_fd_pair(session, guest_addr, read_fd, write_fd) {
                    let _ = self.fd_table.close(read_fd);
                    let _ = self.fd_table.close(write_fd);
                    return Ok(linux_errno(map_guest_write_status_to_errno(status)));
                }
                Ok(0)
            }
            (Ok(read_fd), Err(status)) => {
                let _ = self.fd_table.close(read_fd);
                Ok(linux_errno(map_fd_status_to_errno(status)))
            }
            (Err(status), _) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    fn create_socketpair(
        &mut self,
        session: zx_handle_t,
        domain: u64,
        socket_type: u64,
        protocol: u64,
        guest_addr: u64,
    ) -> Result<u64, zx_status_t> {
        if domain != LINUX_AF_UNIX || socket_type != LINUX_SOCK_STREAM || protocol != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let mut left = ZX_HANDLE_INVALID;
        let mut right = ZX_HANDLE_INVALID;
        let status = zx_socket_create(0, &mut left, &mut right);
        if status != ZX_OK {
            return Ok(linux_errno(map_fd_status_to_errno(status)));
        }
        let left_fd = self.fd_table.open(
            Arc::new(SocketFd::new(left)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        let right_fd = self.fd_table.open(
            Arc::new(SocketFd::new(right)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        );
        match (left_fd, right_fd) {
            (Ok(left_fd), Ok(right_fd)) => {
                if let Err(status) = write_guest_fd_pair(session, guest_addr, left_fd, right_fd) {
                    let _ = self.fd_table.close(left_fd);
                    let _ = self.fd_table.close(right_fd);
                    return Ok(linux_errno(map_guest_write_status_to_errno(status)));
                }
                Ok(0)
            }
            (Ok(left_fd), Err(status)) => {
                let _ = self.fd_table.close(left_fd);
                Ok(linux_errno(map_fd_status_to_errno(status)))
            }
            (Err(status), _) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    fn openat(
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
            match self.namespace.open(path.as_str(), open_flags) {
                Ok(ops) => self
                    .fd_table
                    .open(ops, open_flags, fd_flags)
                    .map(|fd| fd as u64)
                    .or_else(|status| Ok(linux_errno(map_fd_status_to_errno(status)))),
                Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
            }
        } else {
            match self
                .fd_table
                .openat(dirfd, path.as_str(), open_flags, fd_flags)
            {
                Ok(fd) => Ok(fd as u64),
                Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
            }
        }
    }

    fn stat_fd(&self, session: zx_handle_t, fd: i32, stat_addr: u64) -> Result<u64, zx_status_t> {
        let metadata = match self
            .fd_table
            .get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)
            .and_then(|entry| stat_metadata_for_ops(entry.description().ops().as_ref()))
        {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, Some(fd as u64))
    }

    fn statat(
        &self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        stat_addr: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        if flags != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }
        let opened = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            self.namespace.open(path.as_str(), OpenFlags::READABLE)
        } else {
            self.fd_table
                .get(dirfd)
                .ok_or(ZX_ERR_BAD_HANDLE)
                .and_then(|entry| {
                    entry
                        .description()
                        .ops()
                        .openat(path.as_str(), OpenFlags::READABLE)
                })
        };
        let metadata = match opened.and_then(|ops| stat_metadata_for_ops(ops.as_ref())) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, None)
    }

    fn getdents64(
        &mut self,
        session: zx_handle_t,
        fd: i32,
        dirent_addr: u64,
        count: usize,
    ) -> Result<u64, zx_status_t> {
        if count == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(entry) = self.fd_table.get(fd) else {
            return Ok(linux_errno(LINUX_EBADF));
        };
        let description_id = entry.description().id().raw();
        let entries = match self.fd_table.readdir(fd) {
            Ok(entries) => entries,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        let mut cursor = *self.directory_offsets.get(&description_id).unwrap_or(&0);
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
                self.directory_offsets.insert(description_id, cursor);
                Ok(encoded.len() as u64)
            }
            Err(status) => Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        }
    }
}

impl Drop for LinuxMm {
    fn drop(&mut self) {
        for entry in self.map_tree.values() {
            let handle = match entry.backing {
                LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
            };
            if handle != ZX_HANDLE_INVALID {
                let _ = zx_handle_close(handle);
            }
        }
        for handle in [
            self.heap_vmo,
            self.heap_vmar,
            self.mmap_vmar,
            self.root_vmar,
        ] {
            if handle != ZX_HANDLE_INVALID {
                let _ = zx_handle_close(handle);
            }
        }
    }
}

impl LinuxMm {
    fn new(root_vmar: zx_handle_t) -> Result<Self, zx_status_t> {
        let (heap_vmar, heap_base) = allocate_child_vmar(
            root_vmar,
            ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_SPECIFIC | ZX_VM_COMPACT,
            LINUX_HEAP_REGION_BYTES,
        )?;
        let (mmap_vmar, mmap_base) = allocate_child_vmar(
            root_vmar,
            ZX_VM_CAN_MAP_READ
                | ZX_VM_CAN_MAP_WRITE
                | ZX_VM_CAN_MAP_EXECUTE
                | ZX_VM_CAN_MAP_SPECIFIC
                | ZX_VM_COMPACT,
            LINUX_MMAP_REGION_BYTES,
        )?;
        let mut heap_vmo = ZX_HANDLE_INVALID;
        let status = zx_vmo_create(LINUX_HEAP_VMO_BYTES, 0, &mut heap_vmo);
        if status != ZX_OK {
            let _ = zx_handle_close(heap_vmar);
            let _ = zx_handle_close(mmap_vmar);
            let _ = zx_handle_close(root_vmar);
            return Err(status);
        }
        Ok(Self {
            root_vmar,
            heap_vmar,
            heap_base,
            heap_limit: heap_base
                .checked_add(LINUX_HEAP_REGION_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            heap_vmo,
            heap_break: heap_base,
            heap_mapped_len: 0,
            mmap_vmar,
            mmap_base,
            map_tree: BTreeMap::new(),
        })
    }

    fn fork_clone(
        &self,
        child_root_vmar: zx_handle_t,
        parent_session: zx_handle_t,
        child_session: zx_handle_t,
    ) -> Result<Self, zx_status_t> {
        let heap_options =
            ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_SPECIFIC | ZX_VM_SPECIFIC;
        let mmap_options = ZX_VM_CAN_MAP_READ
            | ZX_VM_CAN_MAP_WRITE
            | ZX_VM_CAN_MAP_EXECUTE
            | ZX_VM_CAN_MAP_SPECIFIC
            | ZX_VM_SPECIFIC;
        let heap_vmar = allocate_child_vmar_fixed(
            child_root_vmar,
            heap_options,
            self.heap_base,
            LINUX_HEAP_REGION_BYTES,
        )?;
        let mmap_vmar = allocate_child_vmar_fixed(
            child_root_vmar,
            mmap_options,
            self.mmap_base,
            LINUX_MMAP_REGION_BYTES,
        )?;
        let mut child_heap_vmo = ZX_HANDLE_INVALID;
        zx_status_result(zx_vmo_create(LINUX_HEAP_VMO_BYTES, 0, &mut child_heap_vmo))?;
        if self.heap_mapped_len != 0 {
            let mut mapped_addr = 0u64;
            zx_status_result(zx_vmar_map_local(
                heap_vmar,
                ZX_VM_SPECIFIC | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
                0,
                child_heap_vmo,
                0,
                self.heap_mapped_len,
                &mut mapped_addr,
            ))?;
            copy_guest_region(
                parent_session,
                child_session,
                self.heap_base,
                self.heap_mapped_len,
            )?;
        }

        let mut map_tree = BTreeMap::new();
        for entry in self.map_tree.values() {
            match entry.backing {
                LinuxMapBacking::Anonymous { .. } => {
                    let mut child_vmo = ZX_HANDLE_INVALID;
                    zx_status_result(zx_vmo_create(entry.len, 0, &mut child_vmo))?;
                    let mut mapped_addr = 0u64;
                    zx_status_result(zx_vmar_map_local(
                        mmap_vmar,
                        map_linux_prot_to_vm_options(entry.prot)
                            .map_err(|errno| linux_status_from_errno(errno))?
                            | ZX_VM_SPECIFIC,
                        entry
                            .base
                            .checked_sub(self.mmap_base)
                            .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                        child_vmo,
                        0,
                        entry.len,
                        &mut mapped_addr,
                    ))?;
                    copy_guest_region(parent_session, child_session, entry.base, entry.len)?;
                    map_tree.insert(
                        entry.base,
                        LinuxMapEntry {
                            base: entry.base,
                            len: entry.len,
                            prot: entry.prot,
                            backing: LinuxMapBacking::Anonymous { vmo: child_vmo },
                        },
                    );
                }
                LinuxMapBacking::File { vmo, offset } => {
                    let mut duplicated = ZX_HANDLE_INVALID;
                    zx_status_result(zx_handle_duplicate(
                        vmo,
                        ZX_RIGHT_SAME_RIGHTS,
                        &mut duplicated,
                    ))?;
                    let mut mapped_addr = 0u64;
                    zx_status_result(zx_vmar_map_local(
                        mmap_vmar,
                        map_linux_prot_to_vm_options(entry.prot)
                            .map_err(|errno| linux_status_from_errno(errno))?
                            | ZX_VM_SPECIFIC,
                        entry
                            .base
                            .checked_sub(self.mmap_base)
                            .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                        duplicated,
                        offset,
                        entry.len,
                        &mut mapped_addr,
                    ))?;
                    map_tree.insert(
                        entry.base,
                        LinuxMapEntry {
                            base: entry.base,
                            len: entry.len,
                            prot: entry.prot,
                            backing: LinuxMapBacking::File {
                                vmo: duplicated,
                                offset,
                            },
                        },
                    );
                }
            }
        }

        Ok(Self {
            root_vmar: child_root_vmar,
            heap_vmar,
            heap_base: self.heap_base,
            heap_limit: self.heap_limit,
            heap_vmo: child_heap_vmo,
            heap_break: self.heap_break,
            heap_mapped_len: self.heap_mapped_len,
            mmap_vmar,
            mmap_base: self.mmap_base,
            map_tree,
        })
    }

    fn brk(&mut self, requested: u64) -> u64 {
        if requested == 0 {
            return self.heap_break;
        }
        if requested < self.heap_base || requested > self.heap_limit {
            return self.heap_break;
        }
        let Some(target_mapped_len) =
            align_up_u64(requested.saturating_sub(self.heap_base), USER_PAGE_BYTES)
        else {
            return self.heap_break;
        };
        if target_mapped_len > LINUX_HEAP_VMO_BYTES {
            return self.heap_break;
        }

        if target_mapped_len > self.heap_mapped_len {
            let delta = target_mapped_len - self.heap_mapped_len;
            let heap_offset = self.heap_mapped_len;
            let map_options = ZX_VM_SPECIFIC | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE;
            let mut mapped_addr = 0u64;
            let status = zx_vmar_map_local(
                self.heap_vmar,
                map_options,
                heap_offset,
                self.heap_vmo,
                heap_offset,
                delta,
                &mut mapped_addr,
            );
            if status != ZX_OK {
                return self.heap_break;
            }
        } else if target_mapped_len < self.heap_mapped_len {
            let new_end = self.heap_base + target_mapped_len;
            let delta = self.heap_mapped_len - target_mapped_len;
            let status = zx_vmar_unmap_local(self.heap_vmar, new_end, delta);
            if status != ZX_OK {
                return self.heap_break;
            }
        }

        self.heap_mapped_len = target_mapped_len;
        self.heap_break = requested;
        requested
    }

    fn mmap(
        &mut self,
        fd_table: &FdTable,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i32,
        offset: u64,
    ) -> Result<u64, zx_status_t> {
        if len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_ENOMEM));
        };
        let map_options = match map_linux_prot_to_vm_options(prot) {
            Ok(options) => options,
            Err(errno) => return Ok(linux_errno(errno)),
        };
        let shared = (flags & LINUX_MAP_SHARED) != 0;
        let private = (flags & LINUX_MAP_PRIVATE) != 0;
        if shared == private {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        if (flags & LINUX_MAP_FIXED) != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }

        let anonymous = (flags & LINUX_MAP_ANONYMOUS) != 0;
        let mut vmo = ZX_HANDLE_INVALID;
        if anonymous {
            if fd != -1 || offset != 0 {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            let status = zx_vmo_create(aligned_len, 0, &mut vmo);
            if status != ZX_OK {
                return Ok(linux_errno(map_vm_status_to_errno(status)));
            }
        } else {
            if offset % USER_PAGE_BYTES != 0 {
                return Ok(linux_errno(LINUX_EINVAL));
            }
            if (prot & LINUX_PROT_WRITE) != 0 {
                return Ok(linux_errno(LINUX_EACCES));
            }
            let mut vmo_flags = nexus_io::VmoFlags::READ;
            if (prot & LINUX_PROT_EXEC) != 0 {
                vmo_flags |= nexus_io::VmoFlags::EXECUTE;
            }
            vmo = match fd_table.as_vmo(fd, vmo_flags) {
                Ok(vmo) => vmo,
                Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
            };
        }

        let mut mapped_addr = 0u64;
        let status = zx_vmar_map_local(
            self.mmap_vmar,
            map_options,
            0,
            vmo,
            offset,
            aligned_len,
            &mut mapped_addr,
        );
        if status != ZX_OK {
            let _ = zx_handle_close(vmo);
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }

        self.map_tree.insert(
            mapped_addr,
            LinuxMapEntry {
                base: mapped_addr,
                len: aligned_len,
                prot,
                backing: if anonymous {
                    LinuxMapBacking::Anonymous { vmo }
                } else {
                    LinuxMapBacking::File { vmo, offset }
                },
            },
        );
        let _ = addr;
        Ok(mapped_addr)
    }

    fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, zx_status_t> {
        if addr % USER_PAGE_BYTES != 0 || len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let end = addr.checked_add(aligned_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let Some(overlaps) = self.covered_mappings(addr, end)? else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let status = zx_vmar_unmap_local(self.mmap_vmar, addr, aligned_len);
        if status != ZX_OK {
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }
        for entry in overlaps {
            let _ = self.map_tree.remove(&entry.base);
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let keep_left = entry.base < addr;
            let keep_right = end < entry_end;
            if keep_left {
                let backing = if keep_right {
                    duplicate_linux_map_backing(entry.backing)?
                } else {
                    entry.backing
                };
                self.map_tree.insert(
                    entry.base,
                    LinuxMapEntry {
                        base: entry.base,
                        len: addr - entry.base,
                        prot: entry.prot,
                        backing,
                    },
                );
            }
            if keep_right {
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        backing: entry.backing,
                    },
                );
            }
            if !keep_left && !keep_right {
                let handle = match entry.backing {
                    LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
                };
                let _ = zx_handle_close(handle);
            }
        }
        Ok(0)
    }

    fn mprotect(&mut self, addr: u64, len: u64, prot: u64) -> Result<u64, zx_status_t> {
        if addr % USER_PAGE_BYTES != 0 || len == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let Some(aligned_len) = align_up_u64(len, USER_PAGE_BYTES) else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let map_options = match map_linux_prot_to_vm_options(prot) {
            Ok(options) => options,
            Err(errno) => return Ok(linux_errno(errno)),
        };
        let end = addr.checked_add(aligned_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if addr >= self.heap_base && end <= self.heap_base + self.heap_mapped_len {
            let status = zx_vmar_protect_local(self.heap_vmar, map_options, addr, aligned_len);
            return Ok(if status == ZX_OK {
                0
            } else {
                linux_errno(map_vm_status_to_errno(status))
            });
        }
        let Some(overlaps) = self.covered_mappings(addr, end)? else {
            return Ok(linux_errno(LINUX_EINVAL));
        };
        let status = zx_vmar_protect_local(self.mmap_vmar, map_options, addr, aligned_len);
        if status != ZX_OK {
            return Ok(linux_errno(map_vm_status_to_errno(status)));
        }
        for entry in overlaps {
            let _ = self.map_tree.remove(&entry.base);
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if entry.base < addr {
                self.map_tree.insert(
                    entry.base,
                    LinuxMapEntry {
                        base: entry.base,
                        len: addr - entry.base,
                        prot: entry.prot,
                        backing: duplicate_linux_map_backing(entry.backing)?,
                    },
                );
            }
            let protected_end = end.min(entry_end);
            let protected_start = addr.max(entry.base);
            self.map_tree.insert(
                protected_start,
                LinuxMapEntry {
                    base: protected_start,
                    len: protected_end - protected_start,
                    prot,
                    backing: entry.backing,
                },
            );
            if end < entry_end {
                self.map_tree.insert(
                    end,
                    LinuxMapEntry {
                        base: end,
                        len: entry_end - end,
                        prot: entry.prot,
                        backing: duplicate_linux_map_backing(entry.backing)?,
                    },
                );
            }
        }
        Ok(0)
    }

    fn covered_mappings(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<Option<Vec<LinuxMapEntry>>, zx_status_t> {
        let mut overlaps = Vec::new();
        let mut cursor = addr;

        if let Some((_, entry)) = self.map_tree.range(..=addr).next_back() {
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if addr < entry_end {
                overlaps.push(*entry);
                cursor = entry_end;
            }
        }

        for (_, entry) in self.map_tree.range(addr..) {
            if entry.base >= end {
                break;
            }
            if entry.base > cursor {
                return Ok(None);
            }
            if overlaps
                .last()
                .map(|last| last.base != entry.base)
                .unwrap_or(true)
            {
                overlaps.push(*entry);
            }
            let entry_end = entry
                .base
                .checked_add(entry.len)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if entry_end > cursor {
                cursor = entry_end;
            }
            if cursor >= end {
                return Ok(Some(overlaps));
            }
        }

        if cursor >= end {
            Ok(Some(overlaps))
        } else {
            Ok(None)
        }
    }
}

fn build_starnix_namespace() -> Result<nexus_io::ProcessNamespace, zx_status_t> {
    let mut assets = Vec::new();
    if !LINUX_HELLO_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_HELLO_BINARY_PATH,
            LINUX_HELLO_BYTES,
        ));
    }
    if !LINUX_FD_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_FD_SMOKE_BINARY_PATH,
            LINUX_FD_SMOKE_BYTES,
        ));
    }
    if !LINUX_ROUND2_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND2_BINARY_PATH,
            LINUX_ROUND2_BYTES,
        ));
    }
    if !LINUX_ROUND3_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND3_BINARY_PATH,
            LINUX_ROUND3_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND4_SIGNAL_BINARY_PATH,
            LINUX_ROUND4_SIGNAL_BYTES,
        ));
    }
    if !LINUX_HELLO_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-hello.nxcd",
            LINUX_HELLO_DECL_BYTES,
        ));
    }
    if !LINUX_FD_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-fd-smoke.nxcd",
            LINUX_FD_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND2_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round2-smoke.nxcd",
            LINUX_ROUND2_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND3_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round3-smoke.nxcd",
            LINUX_ROUND3_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round4-signal-smoke.nxcd",
            LINUX_ROUND4_SIGNAL_DECL_BYTES,
        ));
    }
    let bootstrap = BootstrapNamespace::build(&assets)?;
    let mut mounts = bootstrap.namespace().mounts().clone();
    mounts.insert("/", bootstrap.boot_root())?;
    Ok(nexus_io::ProcessNamespace::new(mounts))
}

fn stat_metadata_for_ops(ops: &dyn FdOps) -> Result<LinuxStatMetadata, zx_status_t> {
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
    Err(ZX_ERR_NOT_SUPPORTED)
}

fn install_stdio_fd(
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

fn write_guest_fd_pair(
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

fn duplicate_linux_map_backing(backing: LinuxMapBacking) -> Result<LinuxMapBacking, zx_status_t> {
    let handle = match backing {
        LinuxMapBacking::Anonymous { vmo } | LinuxMapBacking::File { vmo, .. } => vmo,
    };
    let mut duplicated = ZX_HANDLE_INVALID;
    zx_status_result(zx_handle_duplicate(
        handle,
        ZX_RIGHT_SAME_RIGHTS,
        &mut duplicated,
    ))?;
    Ok(match backing {
        LinuxMapBacking::Anonymous { .. } => LinuxMapBacking::Anonymous { vmo: duplicated },
        LinuxMapBacking::File { offset, .. } => LinuxMapBacking::File {
            vmo: duplicated,
            offset,
        },
    })
}

fn read_guest_c_string(
    session: zx_handle_t,
    addr: u64,
    limit: usize,
) -> Result<String, zx_status_t> {
    let mut out = Vec::new();
    out.try_reserve_exact(limit.min(256))
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..limit {
        let mut byte = [0u8; 1];
        let status = ax_guest_session_read_memory(session, addr + index as u64, &mut byte);
        if status != ZX_OK {
            return Err(status);
        }
        if byte[0] == 0 {
            return String::from_utf8(out).map_err(|_| ZX_ERR_BAD_PATH);
        }
        out.push(byte[0]);
    }
    Err(ZX_ERR_OUT_OF_RANGE)
}

fn read_guest_u64(session: zx_handle_t, addr: u64) -> Result<u64, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, 8)?;
    Ok(u64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_guest_string_array(
    session: zx_handle_t,
    addr: u64,
    max_entries: usize,
) -> Result<Vec<String>, zx_status_t> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    out.try_reserve(max_entries.min(8))
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..max_entries {
        let entry_addr = addr
            .checked_add((index * 8) as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let value = read_guest_u64(session, entry_addr)?;
        if value == 0 {
            return Ok(out);
        }
        out.push(read_guest_c_string(session, value, LINUX_PATH_MAX)?);
    }
    Err(ZX_ERR_OUT_OF_RANGE)
}

fn decode_open_flags(flags: u64) -> (OpenFlags, FdFlags) {
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

fn encode_linux_dirent64(
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

fn write_guest_stat(
    session: zx_handle_t,
    addr: u64,
    metadata: LinuxStatMetadata,
    ino_seed: Option<u64>,
) -> Result<u64, zx_status_t> {
    let mut bytes = [0u8; LINUX_STAT_STRUCT_BYTES];
    let ino = ino_seed.unwrap_or(1);
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

fn allocate_child_vmar(
    parent_vmar: zx_handle_t,
    options: u32,
    size: u64,
) -> Result<(zx_handle_t, u64), zx_status_t> {
    let mut child_vmar = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(
        parent_vmar,
        options,
        0,
        size,
        &mut child_vmar,
        &mut child_addr,
    );
    if status == ZX_OK {
        Ok((child_vmar, child_addr))
    } else {
        Err(status)
    }
}

fn allocate_child_vmar_fixed(
    parent_vmar: zx_handle_t,
    options: u32,
    base: u64,
    size: u64,
) -> Result<zx_handle_t, zx_status_t> {
    let offset = base.checked_sub(USER_CODE_VA).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut child_vmar = ZX_HANDLE_INVALID;
    let mut child_addr = 0u64;
    let status = zx_vmar_allocate_local(
        parent_vmar,
        options,
        offset,
        size,
        &mut child_vmar,
        &mut child_addr,
    );
    if status != ZX_OK {
        return Err(status);
    }
    if child_addr != base {
        let _ = zx_handle_close(child_vmar);
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(child_vmar)
}

fn map_linux_prot_to_vm_options(prot: u64) -> Result<u32, i32> {
    if prot == 0 || (prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC)) != 0 {
        return Err(LINUX_EINVAL);
    }
    let mut options = ZX_VM_PERM_READ;
    if (prot & LINUX_PROT_WRITE) != 0 {
        options |= ZX_VM_PERM_WRITE;
    }
    if (prot & LINUX_PROT_EXEC) != 0 {
        options |= ZX_VM_PERM_EXECUTE;
    }
    Ok(options)
}

fn align_up(value: usize, alignment: usize) -> Result<usize, zx_status_t> {
    let mask = alignment.checked_sub(1).ok_or(ZX_ERR_INVALID_ARGS)?;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(ZX_ERR_OUT_OF_RANGE)
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|rounded| rounded & !mask)
}

fn map_guest_memory_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EFAULT,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        _ => LINUX_EFAULT,
    }
}

fn map_guest_write_status_to_errno(status: zx_status_t) -> i32 {
    map_guest_memory_status_to_errno(status)
}

fn map_guest_start_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EFAULT,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        ZX_ERR_NOT_SUPPORTED => LINUX_ENOSYS,
        _ => LINUX_EIO,
    }
}

fn map_exec_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_INVALID_ARGS | ZX_ERR_IO_DATA_INTEGRITY | ZX_ERR_NOT_SUPPORTED => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY | ZX_ERR_INTERNAL | ZX_ERR_OUT_OF_RANGE => LINUX_ENOMEM,
        _ => LINUX_EIO,
    }
}

fn map_vm_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_ALREADY_EXISTS => LINUX_EEXIST,
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_INVALID_ARGS => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY | ZX_ERR_OUT_OF_RANGE => LINUX_ENOMEM,
        ZX_ERR_NOT_SUPPORTED => LINUX_ENODEV,
        _ => LINUX_EINVAL,
    }
}

fn linux_status_from_errno(errno: i32) -> zx_status_t {
    match errno {
        LINUX_EACCES => ZX_ERR_ACCESS_DENIED,
        LINUX_EBADF => ZX_ERR_BAD_HANDLE,
        LINUX_EINVAL => ZX_ERR_INVALID_ARGS,
        LINUX_ENOMEM => ZX_ERR_NO_MEMORY,
        LINUX_ENODEV => ZX_ERR_NOT_SUPPORTED,
        _ => ZX_ERR_BAD_STATE,
    }
}

fn map_status_to_return_code(status: zx_status_t) -> i32 {
    if status == ZX_OK {
        0
    } else if status < 0 {
        -status
    } else {
        status
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, zx_status_t> {
    let end = offset.checked_add(2).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, zx_status_t> {
    let end = offset.checked_add(4).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, zx_status_t> {
    let end = offset.checked_add(8).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn zx_vmar_allocate_local(
    parent_vmar: zx_handle_t,
    options: u32,
    offset: u64,
    size: u64,
    out_child_vmar: &mut zx_handle_t,
    out_child_addr: &mut u64,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMAR_ALLOCATE as u64,
        [
            parent_vmar as u64,
            options as u64,
            offset,
            size,
            out_child_vmar as *mut zx_handle_t as u64,
            out_child_addr as *mut u64 as u64,
        ],
    )
}

fn zx_vmar_map_local(
    vmar: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo: zx_handle_t,
    vmo_offset: u64,
    len: u64,
    mapped_addr: &mut u64,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall8(
        AXLE_SYS_VMAR_MAP as u64,
        [
            vmar as u64,
            options as u64,
            vmar_offset,
            vmo as u64,
            vmo_offset,
            len,
            mapped_addr as *mut u64 as u64,
            0,
        ],
    )
}

fn zx_vmar_unmap_local(vmar: zx_handle_t, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMAR_UNMAP as u64,
        [vmar as u64, addr, len, 0, 0, 0],
    )
}

fn zx_vmar_protect_local(vmar: zx_handle_t, options: u32, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMAR_PROTECT as u64,
        [vmar as u64, options as u64, addr, len, 0, 0],
    )
}
