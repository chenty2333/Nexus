use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use axle_types::guest::{
    AX_GUEST_STOP_REASON_X64_SYSCALL, AX_GUEST_X64_SYSCALL_INSN_LEN, AX_LINUX_EXEC_SPEC_V1,
};
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::signals::{
    AX_USER_SIGNAL_0, AX_USER_SIGNAL_1, ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE,
    ZX_CHANNEL_WRITABLE, ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE, ZX_SOCKET_WRITABLE,
    ZX_TIMER_SIGNALED,
};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH,
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NO_MEMORY, ZX_ERR_NOT_DIR, ZX_ERR_NOT_FILE, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_OUT_OF_RANGE, ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_OK,
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
use libax::{
    AX_TIME_INFINITE, ax_eventpair_create, ax_guest_session_create, ax_guest_session_read_memory,
    ax_guest_session_resume, ax_guest_session_write_memory, ax_guest_stop_state_read,
    ax_guest_stop_state_write, ax_handle_close as zx_handle_close,
    ax_handle_duplicate as zx_handle_duplicate, ax_linux_exec_spec_blob, ax_object_signal,
    ax_object_wait_async, ax_object_wait_one, ax_packet_user_t as zx_packet_user_t,
    ax_port_create as zx_port_create, ax_port_packet_t as zx_port_packet_t,
    ax_port_queue as zx_port_queue, ax_port_wait as zx_port_wait,
    ax_process_create as zx_process_create, ax_process_prepare_linux_exec, ax_process_start_guest,
    ax_socket_create as zx_socket_create, ax_status_result as zx_status_result,
    ax_task_kill as zx_task_kill, ax_thread_create as zx_thread_create, ax_thread_start_guest,
    ax_timer_cancel, ax_timer_create_monotonic, ax_timer_set, ax_vmo_create as zx_vmo_create,
};
use nexus_component::{ComponentStartInfo, NumberedHandle};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFileDescription, OpenFlags,
    PipeFd, PseudoNodeFd, SocketFd, WaitSpec,
};
use spin::Mutex;

use crate::lifecycle::{read_channel_alloc_blocking, send_controller_event, send_status_event};
use crate::services::{BootAssetEntry, BootstrapNamespace, LocalFdMetadataKind, local_fd_metadata};
use crate::{
    LINUX_FD_SMOKE_BINARY_PATH, LINUX_FD_SMOKE_BYTES, LINUX_FD_SMOKE_DECL_BYTES,
    LINUX_HELLO_BINARY_PATH, LINUX_HELLO_BYTES, LINUX_HELLO_DECL_BYTES, LINUX_ROUND2_BINARY_PATH,
    LINUX_ROUND2_BYTES, LINUX_ROUND2_DECL_BYTES, LINUX_ROUND3_BINARY_PATH, LINUX_ROUND3_BYTES,
    LINUX_ROUND3_DECL_BYTES, LINUX_ROUND4_FUTEX_BINARY_PATH, LINUX_ROUND4_FUTEX_BYTES,
    LINUX_ROUND4_FUTEX_DECL_BYTES, LINUX_ROUND4_SIGNAL_BINARY_PATH, LINUX_ROUND4_SIGNAL_BYTES,
    LINUX_ROUND4_SIGNAL_DECL_BYTES, LINUX_ROUND5_EPOLL_BINARY_PATH, LINUX_ROUND5_EPOLL_BYTES,
    LINUX_ROUND5_EPOLL_DECL_BYTES, LINUX_ROUND6_EVENTFD_BINARY_PATH, LINUX_ROUND6_EVENTFD_BYTES,
    LINUX_ROUND6_EVENTFD_DECL_BYTES, LINUX_ROUND6_FUTEX_BINARY_PATH, LINUX_ROUND6_FUTEX_BYTES,
    LINUX_ROUND6_FUTEX_DECL_BYTES, LINUX_ROUND6_PIDFD_BINARY_PATH, LINUX_ROUND6_PIDFD_BYTES,
    LINUX_ROUND6_PIDFD_DECL_BYTES, LINUX_ROUND6_PROC_CONTROL_BINARY_PATH,
    LINUX_ROUND6_PROC_CONTROL_BYTES, LINUX_ROUND6_PROC_CONTROL_DECL_BYTES,
    LINUX_ROUND6_PROC_JOB_BINARY_PATH, LINUX_ROUND6_PROC_JOB_BYTES,
    LINUX_ROUND6_PROC_JOB_DECL_BYTES, LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH,
    LINUX_ROUND6_SCM_RIGHTS_BYTES, LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
    LINUX_ROUND6_SIGNALFD_BINARY_PATH, LINUX_ROUND6_SIGNALFD_BYTES,
    LINUX_ROUND6_SIGNALFD_DECL_BYTES, LINUX_ROUND6_TIMERFD_BINARY_PATH, LINUX_ROUND6_TIMERFD_BYTES,
    LINUX_ROUND6_TIMERFD_DECL_BYTES, STARTUP_HANDLE_COMPONENT_STATUS,
    STARTUP_HANDLE_STARNIX_IMAGE_VMO, STARTUP_HANDLE_STARNIX_PARENT_PROCESS,
    STARTUP_HANDLE_STARNIX_STDOUT,
};

const USER_PAGE_BYTES: u64 = 0x1000;
// Keep this Linux guest bootstrap layout in sync with
// `kernel/axle-kernel/src/userspace.rs`.
const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * 1024;
const USER_SHARED_BYTES: u64 = USER_PAGE_BYTES * 2;
const USER_STACK_BYTES: u64 = USER_PAGE_BYTES * 16;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000;
const USER_STACK_VA: u64 = USER_CODE_VA + USER_CODE_BYTES + USER_SHARED_BYTES;
const LINUX_HEAP_REGION_BYTES: u64 = 16 * 1024 * 1024;
const LINUX_HEAP_VMO_BYTES: u64 = 16 * 1024 * 1024;
const LINUX_MMAP_REGION_BYTES: u64 = 64 * 1024 * 1024;
const STARNIX_GUEST_PACKET_KEY_BASE: u64 = 0x5354_4e58_0000_0001;
const STARNIX_GUEST_PACKET_KEY: u64 = STARNIX_GUEST_PACKET_KEY_BASE;
const STARNIX_SIGNAL_WAKE_PACKET_KEY: u64 = 0x5354_4e58_ffff_0001;
const STARNIX_WAIT_WAKE_KIND_SIGNAL: u64 = 1;
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
const LINUX_SYSCALL_SETPGID: u64 = 109;
const LINUX_SYSCALL_GETPGRP: u64 = 111;
const LINUX_SYSCALL_SETSID: u64 = 112;
const LINUX_SYSCALL_GETPGID: u64 = 121;
const LINUX_SYSCALL_GETSID: u64 = 124;
const LINUX_SYSCALL_SENDMSG: u64 = 46;
const LINUX_SYSCALL_RECVMSG: u64 = 47;
const LINUX_SYSCALL_SOCKETPAIR: u64 = 53;
const LINUX_SYSCALL_CLONE: u64 = 56;
const LINUX_SYSCALL_FORK: u64 = 57;
const LINUX_SYSCALL_EXECVE: u64 = 59;
const LINUX_SYSCALL_WAIT4: u64 = 61;
const LINUX_SYSCALL_KILL: u64 = 62;
const LINUX_SYSCALL_SET_ROBUST_LIST: u64 = 273;
const LINUX_SYSCALL_GET_ROBUST_LIST: u64 = 274;
const LINUX_SYSCALL_TIMERFD_CREATE: u64 = 283;
const LINUX_SYSCALL_TIMERFD_SETTIME: u64 = 286;
const LINUX_SYSCALL_TIMERFD_GETTIME: u64 = 287;
const LINUX_SYSCALL_SIGNALFD4: u64 = 289;
const LINUX_SYSCALL_EVENTFD2: u64 = 290;
const LINUX_SYSCALL_EPOLL_WAIT: u64 = 232;
const LINUX_SYSCALL_EPOLL_CTL: u64 = 233;
const LINUX_SYSCALL_GETTID: u64 = 186;
const LINUX_SYSCALL_FUTEX: u64 = 202;
const LINUX_SYSCALL_TGKILL: u64 = 234;
const LINUX_SYSCALL_GETDENTS64: u64 = 217;
const LINUX_SYSCALL_PIDFD_SEND_SIGNAL: u64 = 424;
const LINUX_SYSCALL_EXIT: u64 = 60;
const LINUX_SYSCALL_OPENAT: u64 = 257;
const LINUX_SYSCALL_NEWFSTATAT: u64 = 262;
const LINUX_SYSCALL_EPOLL_CREATE1: u64 = 291;
const LINUX_SYSCALL_EXIT_GROUP: u64 = 231;
const LINUX_SYSCALL_PIPE2: u64 = 293;
const LINUX_SYSCALL_PIDFD_OPEN: u64 = 434;
const LINUX_AF_UNIX: u64 = 1;
const LINUX_SOCK_STREAM: u64 = 1;
const LINUX_SOL_SOCKET: i32 = 1;
const LINUX_SCM_RIGHTS: i32 = 1;
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
const LINUX_FUTEX_CMD_MASK: u64 = 0x7f;
const LINUX_FUTEX_WAIT: u64 = 0;
const LINUX_FUTEX_WAKE: u64 = 1;
const LINUX_FUTEX_REQUEUE: u64 = 3;
const LINUX_FUTEX_WAIT_BITSET: u64 = 9;
const LINUX_FUTEX_WAKE_BITSET: u64 = 10;
const LINUX_FUTEX_PRIVATE_FLAG: u64 = 0x80;
const LINUX_FUTEX_CLOCK_REALTIME: u64 = 0x100;
const LINUX_FUTEX_WAITERS: u32 = 0x8000_0000;
const LINUX_FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const LINUX_FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const LINUX_FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;
const LINUX_ROBUST_LIST_HEAD_BYTES: u64 = 24;
const LINUX_ROBUST_LIST_LIMIT: usize = 2048;
const LINUX_EPOLL_CTL_ADD: i32 = 1;
const LINUX_EPOLL_CTL_DEL: i32 = 2;
const LINUX_EPOLL_CTL_MOD: i32 = 3;
const LINUX_EPOLLIN: u32 = 0x001;
const LINUX_EPOLLOUT: u32 = 0x004;
const LINUX_EPOLLERR: u32 = 0x008;
const LINUX_EPOLLHUP: u32 = 0x010;
const LINUX_EPOLLONESHOT: u32 = 1 << 30;
const LINUX_EPOLLET: u32 = 1 << 31;
const LINUX_EPOLL_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_EFD_SEMAPHORE: u64 = 0x1;
const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_EFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_SFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_SFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const LINUX_SIGNALFD_SIGINFO_BYTES: usize = 128;
const LINUX_TFD_TIMER_ABSTIME: u64 = 0x1;
const LINUX_TFD_TIMER_CANCEL_ON_SET: u64 = 0x2;
const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_TFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_CLOCK_MONOTONIC: i32 = 1;
const LINUX_EPOLL_EVENT_BYTES: usize = 12;
const LINUX_TIMESPEC_BYTES: usize = 16;
const LINUX_ITIMERSPEC_BYTES: usize = 32;
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
const LINUX_MSGHDR_BYTES: usize = 56;
const LINUX_IOVEC_BYTES: usize = 16;
const LINUX_CMSGHDR_BYTES: usize = 16;
const LINUX_IOV_MAX: usize = 1024;
const LINUX_PATH_MAX: usize = 4096;
const LINUX_EINTR: i32 = 4;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EAGAIN: i32 = 11;
const LINUX_EACCES: i32 = 13;
const LINUX_ESRCH: i32 = 3;
const LINUX_EPERM: i32 = 1;
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
const LINUX_ENOTSOCK: i32 = 88;
const LINUX_WNOHANG: u64 = 1;
const LINUX_WUNTRACED: u64 = 2;
const LINUX_WCONTINUED: u64 = 8;
const LINUX_SIG_BLOCK: u64 = 0;
const LINUX_SIG_UNBLOCK: u64 = 1;
const LINUX_SIG_SETMASK: u64 = 2;
const LINUX_SIG_DFL: u64 = 0;
const LINUX_SIG_IGN: u64 = 1;
const LINUX_SA_RESTORER: u64 = 0x0400_0000;
const LINUX_SA_RESTART: u64 = 0x1000_0000;
const LINUX_SIGCONT: i32 = 18;
const LINUX_SIGKILL: i32 = 9;
const LINUX_SIGCHLD: i32 = 17;
const LINUX_SIGSTOP: i32 = 19;
const LINUX_SIGTSTP: i32 = 20;
const LINUX_SIGTTIN: i32 = 21;
const LINUX_SIGTTOU: i32 = 22;
const LINUX_CLD_EXITED: i32 = 1;
const LINUX_CLD_KILLED: i32 = 2;
const LINUX_CLD_STOPPED: i32 = 5;
const LINUX_CLD_CONTINUED: i32 = 6;
const LINUX_SIGNAL_SET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;
const LINUX_WAIT_STATUS_CONTINUED: i32 = 0xffff;
const EVENTFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
const EVENTFD_WRITABLE_SIGNAL: u32 = AX_USER_SIGNAL_1;
const EVENTFD_SIGNAL_MASK: u32 = EVENTFD_READABLE_SIGNAL | EVENTFD_WRITABLE_SIGNAL;
const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;
const SIGNALFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
const PIDFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
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
}

struct LinuxElf<'a> {
    entry: u64,
    phdr_vaddr: Option<u64>,
    phent: u16,
    phnum: u16,
    segments: Vec<LinuxLoadSegment>,
    _bytes: &'a [u8],
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
    Stop,
    Catch(LinuxSigAction),
}

#[derive(Clone, Copy)]
enum WaitChildEvent {
    Zombie { status: i32 },
    Stopped { status: i32 },
    Continued,
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
    cmdline: Vec<u8>,
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
struct LinuxRobustListState {
    head_addr: u64,
    len: u64,
}

#[derive(Clone, Copy)]
struct ActiveSignalFrame {
    restore_regs: ax_guest_x64_regs_t,
    previous_blocked: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxSigChldInfo {
    pid: i32,
    status: i32,
    code: i32,
}

#[derive(Clone, Copy)]
struct TaskCarrier {
    thread_handle: zx_handle_t,
    session_handle: zx_handle_t,
    sidecar_vmo: zx_handle_t,
    packet_key: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LinuxFutexKey {
    Private { tgid: i32, addr: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LinuxFileDescriptionKey(usize);

#[derive(Clone, Copy)]
struct LinuxEpollEvent {
    events: u32,
    data: u64,
}

struct EpollEntry {
    description: Arc<OpenFileDescription>,
    interest: u32,
    data: u64,
    wait_interest: Option<WaitSpec>,
    packet_key: Option<u64>,
    disabled: bool,
    queued_events: u32,
    observer_armed: bool,
}

struct EpollInstance {
    entries: BTreeMap<LinuxFileDescriptionKey, EpollEntry>,
    ready_list: VecDeque<LinuxFileDescriptionKey>,
    ready_set: BTreeSet<LinuxFileDescriptionKey>,
    waiting_tasks: VecDeque<i32>,
}

#[derive(Clone)]
struct EventFd {
    state: Arc<Mutex<EventFdState>>,
}

#[derive(Clone)]
struct TimerFd {
    state: Arc<Mutex<TimerFdState>>,
}

#[derive(Clone)]
struct SignalFd {
    state: Arc<Mutex<SignalFdState>>,
}

#[derive(Clone)]
struct PidFd {
    state: Arc<Mutex<PidFdState>>,
}

#[derive(Clone)]
struct ProcRootFd {
    self_tgid: i32,
    tasks: BTreeMap<i32, ProcTaskSnapshot>,
}

#[derive(Clone)]
struct ProcTaskDirFd {
    snapshot: ProcTaskSnapshot,
}

#[derive(Clone)]
struct ProcTaskListFd {
    threads: BTreeMap<i32, ProcThreadSnapshot>,
}

#[derive(Clone)]
struct ProcThreadDirFd {
    snapshot: ProcThreadSnapshot,
}

#[derive(Clone)]
struct ProcFdDirFd {
    entries: BTreeMap<String, Arc<OpenFileDescription>>,
}

#[derive(Clone)]
struct ProcTextFd {
    bytes: Arc<Vec<u8>>,
    cursor: Arc<Mutex<usize>>,
}

#[derive(Clone)]
struct ProcProxyFd {
    description: Arc<OpenFileDescription>,
}

struct EventFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    counter: u64,
    semaphore: bool,
    closed: bool,
}

struct TimerFdState {
    timer_handle: zx_handle_t,
    armed_deadline_ns: Option<u64>,
    pending_expirations: u64,
    closed: bool,
}

struct SignalFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    owner_tid: i32,
    owner_tgid: i32,
    mask: u64,
    closed: bool,
}

struct PidFdState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    target_tgid: i32,
    closed: bool,
}

#[derive(Clone, Copy)]
struct LinuxMsgHdr {
    name_addr: u64,
    name_len: u32,
    iov_addr: u64,
    iov_len: usize,
    control_addr: u64,
    control_len: usize,
}

#[derive(Clone, Copy)]
struct LinuxIovec {
    base: u64,
    len: usize,
}

#[derive(Clone)]
struct PendingScmRights {
    descriptions: Vec<Arc<OpenFileDescription>>,
}

#[derive(Clone, Copy)]
struct ConsumedSignal {
    signal: i32,
    sigchld_info: Option<LinuxSigChldInfo>,
}

#[derive(Clone)]
struct ProcThreadSnapshot {
    tid: i32,
    tgid: i32,
    parent_tgid: i32,
    pgid: i32,
    sid: i32,
    state: char,
    name: String,
}

#[derive(Clone)]
struct ProcTaskSnapshot {
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

#[derive(Clone, Copy)]
struct LinuxFutexWaiter {
    task_id: i32,
    bitset: u32,
}

#[derive(Clone, Copy, Default)]
struct LinuxItimerSpec {
    interval_ns: u64,
    value_ns: u64,
}

enum TaskState {
    Running,
    Waiting(WaitState),
}

#[derive(Clone, Copy)]
struct WaitState {
    restartable: bool,
    kind: WaitKind,
}

#[derive(Clone, Copy)]
enum WaitKind {
    Wait4 {
        target_pid: i32,
        status_addr: u64,
        options: u64,
    },
    Futex {
        key: LinuxFutexKey,
    },
    Epoll {
        epoll_key: LinuxFileDescriptionKey,
        events_addr: u64,
        maxevents: usize,
    },
    FdRead {
        fd: i32,
        buf: u64,
        len: usize,
        packet_key: u64,
    },
    FdWrite {
        fd: i32,
        buf: u64,
        len: usize,
        packet_key: u64,
    },
    MsgRecv {
        fd: i32,
        msg_addr: u64,
        flags: u64,
        packet_key: u64,
    },
    MsgSend {
        fd: i32,
        msg_addr: u64,
        flags: u64,
        packet_key: u64,
    },
}

impl WaitState {
    const fn packet_key(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { .. } | WaitKind::Futex { .. } | WaitKind::Epoll { .. } => None,
            WaitKind::FdRead { packet_key, .. }
            | WaitKind::FdWrite { packet_key, .. }
            | WaitKind::MsgRecv { packet_key, .. }
            | WaitKind::MsgSend { packet_key, .. } => Some(packet_key),
        }
    }

    const fn wait4_target_pid(self) -> Option<i32> {
        match self.kind {
            WaitKind::Wait4 { target_pid, .. } => Some(target_pid),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    const fn wait4_status_addr(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { status_addr, .. } => Some(status_addr),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    const fn wait4_options(self) -> Option<u64> {
        match self.kind {
            WaitKind::Wait4 { options, .. } => Some(options),
            WaitKind::Futex { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    const fn futex_key(self) -> Option<LinuxFutexKey> {
        match self.kind {
            WaitKind::Futex { key, .. } => Some(key),
            WaitKind::Wait4 { .. }
            | WaitKind::Epoll { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }

    const fn epoll_key(self) -> Option<LinuxFileDescriptionKey> {
        match self.kind {
            WaitKind::Epoll { epoll_key, .. } => Some(epoll_key),
            WaitKind::Wait4 { .. }
            | WaitKind::Futex { .. }
            | WaitKind::FdRead { .. }
            | WaitKind::FdWrite { .. }
            | WaitKind::MsgRecv { .. }
            | WaitKind::MsgSend { .. } => None,
        }
    }
}

#[derive(Clone, Copy)]
struct FdWaitPolicy {
    nonblock: bool,
    wait_interest: Option<WaitSpec>,
}

enum ReadAttempt {
    Ready { bytes: Vec<u8>, actual: usize },
    WouldBlock(FdWaitPolicy),
    Err(zx_status_t),
}

enum WriteAttempt {
    Ready(usize),
    WouldBlock(FdWaitPolicy),
    Err(zx_status_t),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdWaitOp {
    Read,
    Write,
}

struct LinuxTask {
    tid: i32,
    tgid: i32,
    carrier: TaskCarrier,
    state: TaskState,
    signals: TaskSignals,
    robust_list: Option<LinuxRobustListState>,
    active_signal: Option<ActiveSignalFrame>,
}

#[derive(Clone, Copy)]
enum ThreadGroupState {
    Running,
    Stopped,
    Zombie { wait_status: i32, exit_code: i32 },
}

struct LinuxThreadGroup {
    tgid: i32,
    leader_tid: i32,
    parent_tgid: Option<i32>,
    pgid: i32,
    sid: i32,
    child_tgids: BTreeSet<i32>,
    task_ids: BTreeSet<i32>,
    state: ThreadGroupState,
    last_stop_signal: Option<i32>,
    stop_wait_pending: bool,
    continued_wait_pending: bool,
    shared_pending: u64,
    sigchld_info: Option<LinuxSigChldInfo>,
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
    futex_waiters: BTreeMap<LinuxFutexKey, VecDeque<LinuxFutexWaiter>>,
    epolls: BTreeMap<LinuxFileDescriptionKey, EpollInstance>,
    epoll_packets: BTreeMap<u64, (LinuxFileDescriptionKey, LinuxFileDescriptionKey)>,
    signalfds: BTreeMap<LinuxFileDescriptionKey, Weak<Mutex<SignalFdState>>>,
    pidfds: BTreeMap<LinuxFileDescriptionKey, Weak<Mutex<PidFdState>>>,
    unix_socket_peers: BTreeMap<LinuxFileDescriptionKey, LinuxFileDescriptionKey>,
    unix_socket_rights: BTreeMap<LinuxFileDescriptionKey, VecDeque<PendingScmRights>>,
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

impl EpollInstance {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            ready_list: VecDeque::new(),
            ready_set: BTreeSet::new(),
            waiting_tasks: VecDeque::new(),
        }
    }
}

impl EventFd {
    fn new(initial: u32, semaphore: bool) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(EventFdState {
                wait_handle,
                peer_handle,
                counter: u64::from(initial),
                semaphore,
                closed: false,
            })),
        };
        if let Err(status) = this.refresh_signals() {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn refresh_signals(&self) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        Self::refresh_signals_locked(&state)
    }

    fn refresh_signals_locked(state: &EventFdState) -> Result<(), zx_status_t> {
        if state.closed {
            return Ok(());
        }
        let mut set_mask = 0u32;
        if state.counter != 0 {
            set_mask |= EVENTFD_READABLE_SIGNAL;
        }
        if state.counter < EVENTFD_COUNTER_MAX {
            set_mask |= EVENTFD_WRITABLE_SIGNAL;
        }
        zx_status_result(ax_object_signal(
            state.wait_handle,
            EVENTFD_SIGNAL_MASK,
            set_mask,
        ))
    }
}

impl FdOps for EventFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        if state.counter == 0 {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let value = if state.semaphore {
            state.counter -= 1;
            1u64
        } else {
            let value = state.counter;
            state.counter = 0;
            value
        };
        Self::refresh_signals_locked(&state)?;
        buffer.copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let value = u64::from_ne_bytes(buffer.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
        if value == u64::MAX {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        let remaining = EVENTFD_COUNTER_MAX
            .checked_sub(state.counter)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if value > remaining {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        state.counter = state
            .counter
            .checked_add(value)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Self::refresh_signals_locked(&state)?;
        Ok(8)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, EVENTFD_SIGNAL_MASK))
    }
}

impl TimerFd {
    fn new() -> Result<Self, zx_status_t> {
        let mut timer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_timer_create_monotonic(0, &mut timer_handle))?;
        Ok(Self {
            state: Arc::new(Mutex::new(TimerFdState {
                timer_handle,
                armed_deadline_ns: None,
                pending_expirations: 0,
                closed: false,
            })),
        })
    }

    fn sample_expiration_locked(state: &mut TimerFdState) -> Result<(), zx_status_t> {
        if state.closed || state.pending_expirations != 0 {
            return Ok(());
        }
        let mut observed = 0;
        match ax_object_wait_one(state.timer_handle, ZX_TIMER_SIGNALED, 0, &mut observed) {
            ZX_OK => {
                state.armed_deadline_ns = None;
                state.pending_expirations = 1;
                Ok(())
            }
            ZX_ERR_TIMED_OUT => Ok(()),
            status => Err(status),
        }
    }

    fn settime(&self, flags: u64, new_value: LinuxItimerSpec) -> Result<(), zx_status_t> {
        if (flags & LINUX_TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let allowed = LINUX_TFD_TIMER_ABSTIME | LINUX_TFD_TIMER_CANCEL_ON_SET;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if new_value.interval_ns != 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let mut state = self.state.lock();
        if state.closed {
            return Err(ZX_ERR_BAD_STATE);
        }
        zx_status_result(ax_timer_cancel(state.timer_handle))?;
        state.armed_deadline_ns = None;
        state.pending_expirations = 0;
        if new_value.value_ns == 0 {
            return Ok(());
        }
        if (flags & LINUX_TFD_TIMER_ABSTIME) == 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let deadline = i64::try_from(new_value.value_ns).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        zx_status_result(ax_timer_set(state.timer_handle, deadline, 0))?;
        state.armed_deadline_ns = Some(new_value.value_ns);
        Ok(())
    }
}

impl FdOps for TimerFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.len() != 8 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut state = self.state.lock();
        Self::sample_expiration_locked(&mut state)?;
        if state.pending_expirations == 0 {
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let expirations = state.pending_expirations;
        state.pending_expirations = 0;
        zx_status_result(ax_timer_cancel(state.timer_handle))?;
        buffer.copy_from_slice(&expirations.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let timer_handle = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.timer_handle
        };
        let _ = ax_timer_cancel(timer_handle);
        let _ = zx_handle_close(timer_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.timer_handle, ZX_TIMER_SIGNALED))
    }
}

impl SignalFd {
    fn new(owner_tid: i32, owner_tgid: i32, mask: u64) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(SignalFdState {
                wait_handle,
                peer_handle,
                owner_tid,
                owner_tgid,
                mask: normalize_signal_mask(mask),
                closed: false,
            })),
        };
        if let Err(status) = this.set_ready(false) {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn snapshot(&self) -> Option<(i32, i32, u64, zx_handle_t)> {
        let state = self.state.lock();
        (!state.closed).then_some((
            state.owner_tid,
            state.owner_tgid,
            state.mask,
            state.wait_handle,
        ))
    }

    fn set_ready(&self, ready: bool) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        if state.closed {
            return Ok(());
        }
        let set_mask = if ready { SIGNALFD_READABLE_SIGNAL } else { 0 };
        zx_status_result(ax_object_signal(
            state.wait_handle,
            SIGNALFD_READABLE_SIGNAL,
            set_mask,
        ))
    }

    fn weak_state(&self) -> Weak<Mutex<SignalFdState>> {
        Arc::downgrade(&self.state)
    }
}

impl FdOps for SignalFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, SIGNALFD_READABLE_SIGNAL))
    }
}

impl PidFd {
    fn new(target_tgid: i32) -> Result<Self, zx_status_t> {
        let mut wait_handle = ZX_HANDLE_INVALID;
        let mut peer_handle = ZX_HANDLE_INVALID;
        zx_status_result(ax_eventpair_create(0, &mut wait_handle, &mut peer_handle))?;
        let this = Self {
            state: Arc::new(Mutex::new(PidFdState {
                wait_handle,
                peer_handle,
                target_tgid,
                closed: false,
            })),
        };
        if let Err(status) = this.set_ready(false) {
            let _ = zx_handle_close(wait_handle);
            let _ = zx_handle_close(peer_handle);
            return Err(status);
        }
        Ok(this)
    }

    fn snapshot(&self) -> Option<(i32, zx_handle_t)> {
        let state = self.state.lock();
        (!state.closed).then_some((state.target_tgid, state.wait_handle))
    }

    fn set_ready(&self, ready: bool) -> Result<(), zx_status_t> {
        let state = self.state.lock();
        if state.closed {
            return Ok(());
        }
        let set_mask = if ready { PIDFD_READABLE_SIGNAL } else { 0 };
        zx_status_result(ax_object_signal(
            state.wait_handle,
            PIDFD_READABLE_SIGNAL,
            set_mask,
        ))
    }

    fn weak_state(&self) -> Weak<Mutex<PidFdState>> {
        Arc::downgrade(&self.state)
    }
}

impl FdOps for PidFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: nexus_io::SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let (wait_handle, peer_handle) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.wait_handle, state.peer_handle)
        };
        let _ = zx_handle_close(peer_handle);
        let _ = zx_handle_close(wait_handle);
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let state = self.state.lock();
        (!state.closed).then_some(WaitSpec::new(state.wait_handle, PIDFD_READABLE_SIGNAL))
    }
}

impl ProcTextFd {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(bytes),
            cursor: Arc::new(Mutex::new(0)),
        }
    }
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
            futex_waiters: BTreeMap::new(),
            epolls: BTreeMap::new(),
            epoll_packets: BTreeMap::new(),
            signalfds: BTreeMap::new(),
            pidfds: BTreeMap::new(),
            unix_socket_peers: BTreeMap::new(),
            unix_socket_rights: BTreeMap::new(),
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

    fn snapshot_fd_descriptions(
        resources: &ExecutiveState,
    ) -> Result<BTreeMap<String, Arc<OpenFileDescription>>, zx_status_t> {
        let mut entries = BTreeMap::new();
        let target_hits = resources
            .fd_table
            .len()
            .checked_add(32)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let mut hits = 0usize;
        let mut misses_after_hits = 0usize;
        let mut fd = 0i32;
        while hits < target_hits && misses_after_hits < 64 {
            if let Some(entry) = resources.fd_table.get(fd) {
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
            threads.insert(
                *tid,
                ProcThreadSnapshot {
                    tid: *tid,
                    tgid,
                    parent_tgid: group.parent_tgid.unwrap_or(0),
                    pgid: group.pgid,
                    sid: group.sid,
                    state: Self::group_state_char(group),
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

    fn proc_root_fd(&self, self_tgid: i32) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let mut tasks = BTreeMap::new();
        for tgid in self.groups.keys().copied() {
            tasks.insert(tgid, self.proc_task_snapshot(tgid)?);
        }
        Ok(Arc::new(ProcRootFd { self_tgid, tasks }))
    }

    fn open_proc_absolute(&self, task_id: i32, path: &str) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let self_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let root = self.proc_root_fd(self_tgid)?;
        if path == "/proc" || path == "/proc/" {
            return Ok(root);
        }
        let suffix = path.strip_prefix("/proc/").ok_or(ZX_ERR_BAD_PATH)?;
        root.openat(suffix, OpenFlags::READABLE)
    }

    fn target_tgid_for_pid_arg(&self, caller_tgid: i32, pid: i32) -> Result<i32, zx_status_t> {
        if pid == 0 {
            return Ok(caller_tgid);
        }
        if pid < 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if self.groups.contains_key(&pid) {
            Ok(pid)
        } else {
            Err(ZX_ERR_NOT_FOUND)
        }
    }

    fn task_pgid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.pgid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn task_sid(&self, task_id: i32) -> Result<i32, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        self.groups
            .get(&tgid)
            .map(|group| group.sid)
            .ok_or(ZX_ERR_BAD_STATE)
    }

    fn session_has_pgid(&self, sid: i32, pgid: i32) -> bool {
        self.groups
            .values()
            .any(|group| group.sid == sid && group.pgid == pgid)
    }

    fn private_futex_key(&self, task_id: i32, addr: u64) -> Result<LinuxFutexKey, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        Ok(LinuxFutexKey::Private { tgid, addr })
    }

    const fn private_futex_key_for_tgid(tgid: i32, addr: u64) -> LinuxFutexKey {
        LinuxFutexKey::Private { tgid, addr }
    }

    fn enqueue_futex_waiter(&mut self, key: LinuxFutexKey, waiter: LinuxFutexWaiter) {
        self.futex_waiters.entry(key).or_default().push_back(waiter);
    }

    fn remove_task_from_futex_queue(&mut self, task_id: i32, key: LinuxFutexKey) {
        let remove_key = match self.futex_waiters.get_mut(&key) {
            Some(queue) => {
                if let Some(index) = queue.iter().position(|queued| queued.task_id == task_id) {
                    let _ = queue.remove(index);
                }
                queue.is_empty()
            }
            None => false,
        };
        if remove_key {
            let _ = self.futex_waiters.remove(&key);
        }
    }

    fn cancel_task_wait(&mut self, task_id: i32, wait: WaitState) {
        if let Some(key) = wait.futex_key() {
            self.remove_task_from_futex_queue(task_id, key);
        }
        if let Some(epoll_key) = wait.epoll_key() {
            let remove_key = match self.epolls.get_mut(&epoll_key) {
                Some(instance) => {
                    if let Some(index) = instance
                        .waiting_tasks
                        .iter()
                        .position(|queued| *queued == task_id)
                    {
                        let _ = instance.waiting_tasks.remove(index);
                    }
                    instance.entries.is_empty() && instance.waiting_tasks.is_empty()
                }
                None => false,
            };
            if remove_key {
                let _ = self.epolls.remove(&epoll_key);
            }
        }
    }

    fn take_futex_waiter(
        &mut self,
        key: LinuxFutexKey,
        wake_mask: u32,
    ) -> Option<LinuxFutexWaiter> {
        let mut queue = self.futex_waiters.remove(&key)?;
        let mut kept = VecDeque::with_capacity(queue.len());
        let mut chosen = None;
        while let Some(waiter) = queue.pop_front() {
            let live = self.tasks.get(&waiter.task_id).is_some_and(|task| {
                matches!(task.state, TaskState::Waiting(wait) if wait.futex_key() == Some(key))
            });
            if !live {
                continue;
            }
            if chosen.is_none() && (waiter.bitset & wake_mask) != 0 {
                chosen = Some(waiter);
                continue;
            }
            kept.push_back(waiter);
        }
        if !kept.is_empty() {
            self.futex_waiters.insert(key, kept);
        }
        chosen
    }

    fn resume_futex_waiter(&mut self, task_id: i32, result: u64) -> Result<(), zx_status_t> {
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        let TaskState::Waiting(wait) = task.state else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if wait.futex_key().is_none() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let sidecar = task.carrier.sidecar_vmo;
        task.state = TaskState::Running;
        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        complete_syscall(&mut stop_state, result)?;
        self.writeback_and_resume(task_id, &stop_state)
    }

    fn wake_futex_waiters(
        &mut self,
        key: LinuxFutexKey,
        wake_count: usize,
        wake_mask: u32,
    ) -> Result<u64, zx_status_t> {
        let mut woke = 0u64;
        for _ in 0..wake_count {
            let Some(waiter) = self.take_futex_waiter(key, wake_mask) else {
                break;
            };
            self.resume_futex_waiter(waiter.task_id, 0)?;
            woke = woke.checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        Ok(woke)
    }

    fn requeue_futex_waiters(
        &mut self,
        source: LinuxFutexKey,
        target: LinuxFutexKey,
        wake_count: usize,
        requeue_count: usize,
    ) -> Result<u64, zx_status_t> {
        let woke = self.wake_futex_waiters(source, wake_count, LINUX_FUTEX_BITSET_MATCH_ANY)?;
        for _ in 0..requeue_count {
            let Some(waiter) = self.take_futex_waiter(source, LINUX_FUTEX_BITSET_MATCH_ANY) else {
                break;
            };
            let task = self
                .tasks
                .get_mut(&waiter.task_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let TaskState::Waiting(ref mut wait) = task.state else {
                return Err(ZX_ERR_BAD_STATE);
            };
            *wait = WaitState {
                restartable: wait.restartable,
                kind: WaitKind::Futex { key: target },
            };
            self.enqueue_futex_waiter(target, waiter);
        }
        Ok(woke)
    }

    fn queue_epoll_ready(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
        ready: u32,
    ) {
        let Some(instance) = self.epolls.get_mut(&epoll_key) else {
            return;
        };
        let Some(entry) = instance.entries.get_mut(&target_key) else {
            return;
        };
        if entry.disabled {
            return;
        }
        let filtered = filter_epoll_ready_events(entry.interest, ready);
        if filtered == 0 {
            return;
        }
        entry.queued_events |= filtered;
        if instance.ready_set.insert(target_key) {
            instance.ready_list.push_back(target_key);
        }
    }

    fn pop_ready_epoll_target(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Option<LinuxFileDescriptionKey> {
        loop {
            let next = {
                let instance = self.epolls.get_mut(&epoll_key)?;
                instance.ready_list.pop_front()
            };
            let Some(target_key) = next else {
                if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                    instance.ready_set.clear();
                }
                return None;
            };
            if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                instance.ready_set.remove(&target_key);
                if instance.entries.contains_key(&target_key) {
                    return Some(target_key);
                }
            }
        }
    }

    fn arm_epoll_entry(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let (wait_interest, packet_key, disabled, observer_armed) = {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
            (
                entry.wait_interest,
                entry.packet_key,
                entry.disabled,
                entry.observer_armed,
            )
        };
        if disabled || observer_armed {
            return Ok(());
        }
        let Some(wait_interest) = wait_interest else {
            return Ok(());
        };
        let Some(packet_key) = packet_key else {
            return Ok(());
        };
        let status = ax_object_wait_async(
            wait_interest.handle(),
            self.port,
            packet_key,
            wait_interest.signals(),
            axle_types::wait_async::AX_WAIT_ASYNC_EDGE,
        );
        zx_status_result(status)?;
        let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
        let entry = instance
            .entries
            .get_mut(&target_key)
            .ok_or(ZX_ERR_BAD_STATE)?;
        entry.observer_armed = true;
        Ok(())
    }

    fn sample_epoll_ready_mask(&self, entry: &EpollEntry) -> u32 {
        if let Some(wait_interest) = entry.wait_interest {
            let mut observed = 0;
            match ax_object_wait_one(
                wait_interest.handle(),
                wait_interest.signals(),
                0,
                &mut observed,
            ) {
                ZX_OK => map_wait_signals_to_epoll(observed),
                axle_types::status::AX_ERR_TIMED_OUT => 0,
                _ => LINUX_EPOLLERR | LINUX_EPOLLHUP,
            }
        } else {
            match stat_metadata_for_ops(entry.description.ops().as_ref()) {
                Ok(_) => LINUX_EPOLLIN | LINUX_EPOLLOUT,
                Err(_) => 0,
            }
        }
    }

    fn handle_epoll_ready_packet(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        target_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        {
            let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance
                .entries
                .get_mut(&target_key)
                .ok_or(ZX_ERR_BAD_STATE)?;
            entry.observer_armed = false;
        }
        let ready = {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
            self.sample_epoll_ready_mask(entry)
        };
        self.queue_epoll_ready(epoll_key, target_key, ready);
        self.wake_one_epoll_waiter(epoll_key)
    }

    fn wake_one_epoll_waiter(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        loop {
            let task_id = {
                let Some(instance) = self.epolls.get_mut(&epoll_key) else {
                    return Ok(());
                };
                instance.waiting_tasks.pop_front()
            };
            let Some(task_id) = task_id else {
                return Ok(());
            };
            let Some(task) = self.tasks.get(&task_id) else {
                continue;
            };
            if !matches!(task.state, TaskState::Waiting(wait) if wait.epoll_key() == Some(epoll_key))
            {
                continue;
            }
            return self.resume_epoll_waiter(task_id, epoll_key);
        }
    }

    fn collect_epoll_events(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
        maxevents: usize,
    ) -> Result<Vec<LinuxEpollEvent>, zx_status_t> {
        let mut events = Vec::new();
        let mut requeue_after = Vec::new();
        events
            .try_reserve_exact(maxevents)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        requeue_after
            .try_reserve_exact(maxevents)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        while events.len() < maxevents {
            let Some(target_key) = self.pop_ready_epoll_target(epoll_key) else {
                break;
            };
            let (event, requeue_level, rearm) = {
                let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance
                    .entries
                    .get_mut(&target_key)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let event = LinuxEpollEvent {
                    events: entry.queued_events,
                    data: entry.data,
                };
                entry.queued_events = 0;
                if (entry.interest & LINUX_EPOLLONESHOT) != 0 {
                    entry.disabled = true;
                }
                (
                    event,
                    (entry.interest & LINUX_EPOLLET) == 0 && !entry.disabled,
                    !entry.disabled,
                )
            };
            events.push(event);
            if requeue_level {
                requeue_after.push(target_key);
            }
            if rearm {
                self.arm_epoll_entry(epoll_key, target_key)?;
            }
        }
        for target_key in requeue_after {
            let ready = {
                let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                self.sample_epoll_ready_mask(entry)
            };
            self.queue_epoll_ready(epoll_key, target_key, ready);
        }
        Ok(events)
    }

    fn refresh_level_triggered_epoll_ready(
        &mut self,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let mut targets = Vec::new();
        {
            let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
            targets
                .try_reserve_exact(instance.entries.len())
                .map_err(|_| ZX_ERR_NO_MEMORY)?;
            for (target_key, entry) in &instance.entries {
                if (entry.interest & LINUX_EPOLLET) == 0 && !entry.disabled {
                    targets.push(*target_key);
                }
            }
        }
        for target_key in targets {
            let ready = {
                let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                self.sample_epoll_ready_mask(entry)
            };
            if ready == 0 {
                let instance = self.epolls.get_mut(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                if let Some(entry) = instance.entries.get_mut(&target_key) {
                    entry.queued_events = 0;
                }
                instance.ready_set.remove(&target_key);
                instance.ready_list.retain(|queued| *queued != target_key);
            } else {
                self.queue_epoll_ready(epoll_key, target_key, ready);
            }
        }
        Ok(())
    }

    fn complete_epoll_wait(
        &mut self,
        task_id: i32,
        epoll_key: LinuxFileDescriptionKey,
        events_addr: u64,
        maxevents: usize,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<bool, zx_status_t> {
        self.refresh_level_triggered_epoll_ready(epoll_key)?;
        let events = self.collect_epoll_events(epoll_key, maxevents)?;
        if events.is_empty() {
            return Ok(false);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let bytes = encode_epoll_events(&events)?;
        match write_guest_bytes(session, events_addr, &bytes) {
            Ok(()) => {
                complete_syscall(
                    stop_state,
                    u64::try_from(events.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                )?;
                Ok(true)
            }
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_write_status_to_errno(status)),
                )?;
                Ok(true)
            }
        }
    }

    fn resume_epoll_waiter(
        &mut self,
        task_id: i32,
        epoll_key: LinuxFileDescriptionKey,
    ) -> Result<(), zx_status_t> {
        let (events_addr, maxevents, sidecar) = {
            let task = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let TaskState::Waiting(wait) = task.state else {
                return Err(ZX_ERR_BAD_STATE);
            };
            let WaitKind::Epoll {
                epoll_key: waiting_key,
                events_addr,
                maxevents,
            } = wait.kind
            else {
                return Err(ZX_ERR_BAD_STATE);
            };
            if waiting_key != epoll_key {
                return Err(ZX_ERR_BAD_STATE);
            }
            (events_addr, maxevents, task.carrier.sidecar_vmo)
        };

        let mut stop_state = ax_guest_stop_state_read(sidecar)?;
        if !self.complete_epoll_wait(task_id, epoll_key, events_addr, maxevents, &mut stop_state)? {
            return Ok(());
        }
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Running;
        self.writeback_and_resume(task_id, &stop_state)
    }

    fn task_id_for_packet_key(&self, packet_key: u64) -> Option<i32> {
        self.tasks
            .iter()
            .find_map(|(tid, task)| (task.carrier.packet_key == packet_key).then_some(*tid))
    }

    fn waiting_task_id_for_packet_key(&self, packet_key: u64) -> Option<i32> {
        self.tasks.iter().find_map(|(tid, task)| match task.state {
            TaskState::Waiting(wait) if wait.packet_key() == Some(packet_key) => Some(*tid),
            TaskState::Running | TaskState::Waiting(_) => None,
        })
    }

    fn queue_wait_signal_wake(&self, task_id: i32) -> Result<(), zx_status_t> {
        let packet = zx_port_packet_t {
            key: STARNIX_SIGNAL_WAKE_PACKET_KEY,
            type_: ZX_PKT_TYPE_USER,
            status: 0,
            user: zx_packet_user_t {
                u64: [STARNIX_WAIT_WAKE_KIND_SIGNAL, task_id as u64, 0, 0],
            },
        };
        zx_status_result(zx_port_queue(self.port, &packet))
    }

    fn run(&mut self) -> i32 {
        let mut stdout = Vec::new();
        loop {
            if let Some(status) = self.root_group_status() {
                return status;
            }
            let mut packet = zx_port_packet_t::default();
            let wait_status = zx_port_wait(self.port, AX_TIME_INFINITE, &mut packet);
            if wait_status != ZX_OK {
                return map_status_to_return_code(wait_status);
            }
            match packet.type_ {
                ZX_PKT_TYPE_USER => {
                    if packet.key == STARNIX_SIGNAL_WAKE_PACKET_KEY
                        && packet.user.u64[0] == STARNIX_WAIT_WAKE_KIND_SIGNAL
                    {
                        let task_id =
                            i32::try_from(packet.user.u64[1]).map_err(|_| ZX_ERR_BAD_STATE);
                        let Ok(task_id) = task_id else {
                            return map_status_to_return_code(ZX_ERR_BAD_STATE);
                        };
                        if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    }
                    if let Some(task_id) = self.waiting_task_id_for_packet_key(packet.key) {
                        if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                            return map_status_to_return_code(status);
                        }
                        continue;
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
                    if let Err(status) = self.complete_task_action(task_id, action, &mut stop_state)
                    {
                        return map_status_to_return_code(status);
                    }
                }
                ZX_PKT_TYPE_SIGNAL_ONE => {
                    let Some(task_id) = self.waiting_task_id_for_packet_key(packet.key) else {
                        if let Some((epoll_key, target_key)) =
                            self.epoll_packets.get(&packet.key).copied()
                            && let Err(status) =
                                self.handle_epoll_ready_packet(epoll_key, target_key)
                        {
                            return map_status_to_return_code(status);
                        }
                        continue;
                    };
                    if let Err(status) = self.retry_waiting_task(task_id, &mut stdout) {
                        return map_status_to_return_code(status);
                    }
                }
                _ => return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED),
            }
        }
    }

    fn root_group_status(&self) -> Option<i32> {
        self.groups
            .get(&self.root_tgid)
            .and_then(|group| match group.state {
                ThreadGroupState::Zombie { exit_code, .. } => Some(exit_code),
                ThreadGroupState::Running | ThreadGroupState::Stopped => None,
            })
    }

    fn handle_syscall(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        match stop_state.regs.rax {
            LINUX_SYSCALL_READ => self.sys_read(task_id, stop_state),
            LINUX_SYSCALL_WRITE => self.sys_write(task_id, stop_state, stdout),
            LINUX_SYSCALL_SENDMSG => self.sys_sendmsg(task_id, stop_state),
            LINUX_SYSCALL_RECVMSG => self.sys_recvmsg(task_id, stop_state),
            LINUX_SYSCALL_GETPID => self.sys_getpid(task_id, stop_state),
            LINUX_SYSCALL_GETTID => self.sys_gettid(task_id, stop_state),
            LINUX_SYSCALL_GETPGRP => self.sys_getpgrp(task_id, stop_state),
            LINUX_SYSCALL_GETPGID => self.sys_getpgid(task_id, stop_state),
            LINUX_SYSCALL_GETSID => self.sys_getsid(task_id, stop_state),
            LINUX_SYSCALL_SETPGID => self.sys_setpgid(task_id, stop_state),
            LINUX_SYSCALL_SETSID => self.sys_setsid(task_id, stop_state),
            LINUX_SYSCALL_SOCKETPAIR => self.sys_socketpair(task_id, stop_state),
            LINUX_SYSCALL_FUTEX => self.sys_futex(task_id, stop_state),
            LINUX_SYSCALL_SET_ROBUST_LIST => self.sys_set_robust_list(task_id, stop_state),
            LINUX_SYSCALL_GET_ROBUST_LIST => self.sys_get_robust_list(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_CREATE => self.sys_timerfd_create(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_SETTIME => self.sys_timerfd_settime(task_id, stop_state),
            LINUX_SYSCALL_TIMERFD_GETTIME => self.sys_timerfd_gettime(stop_state),
            LINUX_SYSCALL_SIGNALFD4 => self.sys_signalfd4(task_id, stop_state),
            LINUX_SYSCALL_EVENTFD2 => self.sys_eventfd2(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_WAIT => self.sys_epoll_wait(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_CTL => self.sys_epoll_ctl(task_id, stop_state),
            LINUX_SYSCALL_EPOLL_CREATE1 => self.sys_epoll_create1(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGACTION => self.sys_rt_sigaction(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGPROCMASK => self.sys_rt_sigprocmask(task_id, stop_state),
            LINUX_SYSCALL_RT_SIGRETURN => self.sys_rt_sigreturn(task_id, stop_state),
            LINUX_SYSCALL_CLONE => self.sys_clone(task_id, stop_state),
            LINUX_SYSCALL_FORK => self.sys_fork(task_id, stop_state),
            LINUX_SYSCALL_EXECVE => self.sys_execve(task_id, stop_state),
            LINUX_SYSCALL_WAIT4 => self.sys_wait4(task_id, stop_state),
            LINUX_SYSCALL_KILL => self.sys_kill(task_id, stop_state, stdout),
            LINUX_SYSCALL_TGKILL => self.sys_tgkill(stop_state, stdout),
            LINUX_SYSCALL_PIDFD_SEND_SIGNAL => {
                self.sys_pidfd_send_signal(task_id, stop_state, stdout)
            }
            LINUX_SYSCALL_PIDFD_OPEN => self.sys_pidfd_open(task_id, stop_state),
            LINUX_SYSCALL_OPENAT => self.sys_openat(task_id, stop_state),
            LINUX_SYSCALL_NEWFSTATAT => self.sys_newfstatat(task_id, stop_state),
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
                SignalDeliveryAction::Stop => {
                    let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                    self.enter_group_stop(tgid, signal)?;
                    return Ok(SyscallAction::LeaveStopped);
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

    fn complete_task_action(
        &mut self,
        task_id: i32,
        action: SyscallAction,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<(), zx_status_t> {
        let action = self.apply_signal_delivery(task_id, action, stop_state)?;
        match action {
            SyscallAction::Resume => self.writeback_and_resume(task_id, stop_state),
            SyscallAction::LeaveStopped => Ok(()),
            SyscallAction::TaskExit(code) => self.exit_task(task_id, code),
            SyscallAction::GroupExit(code) => self.exit_group(task_id, code),
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
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
        let Some(status_addr) = wait.wait4_status_addr() else {
            return Err(ZX_ERR_BAD_STATE);
        };
        if status_addr != 0 {
            write_guest_bytes(
                task.carrier.session_handle,
                status_addr,
                &status.to_ne_bytes(),
            )?;
        }
        let mut stop_state = ax_guest_stop_state_read(task.carrier.sidecar_vmo)?;
        complete_syscall(&mut stop_state, child_tgid as u64)?;
        task.state = TaskState::Running;
        self.writeback_and_resume(task_id, &stop_state)
    }

    fn wait_event_for_child(
        &self,
        parent_tgid: i32,
        target_pid: i32,
        child_tgid: i32,
        options: u64,
    ) -> Option<WaitChildEvent> {
        if !self.wait_matches(parent_tgid, target_pid, child_tgid) {
            return None;
        }
        let child_group = self.groups.get(&child_tgid)?;
        match child_group.state {
            ThreadGroupState::Zombie { wait_status, .. } => Some(WaitChildEvent::Zombie {
                status: wait_status,
            }),
            ThreadGroupState::Running | ThreadGroupState::Stopped => {
                if child_group.stop_wait_pending && (options & LINUX_WUNTRACED) != 0 {
                    return Some(WaitChildEvent::Stopped {
                        status: linux_wait_status_stopped(
                            child_group.last_stop_signal.unwrap_or(LINUX_SIGSTOP),
                        ),
                    });
                }
                if child_group.continued_wait_pending && (options & LINUX_WCONTINUED) != 0 {
                    return Some(WaitChildEvent::Continued);
                }
                None
            }
        }
    }

    fn consume_wait_event(
        &mut self,
        child_tgid: i32,
        event: WaitChildEvent,
    ) -> Result<(), zx_status_t> {
        match event {
            WaitChildEvent::Zombie { .. } => Ok(()),
            WaitChildEvent::Stopped { .. } => {
                self.groups
                    .get_mut(&child_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .stop_wait_pending = false;
                Ok(())
            }
            WaitChildEvent::Continued => {
                self.groups
                    .get_mut(&child_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .continued_wait_pending = false;
                Ok(())
            }
        }
    }

    fn wait_matches(&self, parent_tgid: i32, target_pid: i32, child_tgid: i32) -> bool {
        if target_pid == -1 {
            return true;
        }
        if target_pid > 0 {
            return target_pid == child_tgid;
        }
        let Some(child_group) = self.groups.get(&child_tgid) else {
            return false;
        };
        let Some(parent_group) = self.groups.get(&parent_tgid) else {
            return false;
        };
        if target_pid == 0 {
            return child_group.pgid == parent_group.pgid;
        }
        child_group.pgid == target_pid.saturating_abs()
    }

    fn maybe_wake_parent_waiter(&mut self, child_tgid: i32) -> Result<(), zx_status_t> {
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
                    TaskState::Waiting(ref wait) => {
                        let target_pid = wait.wait4_target_pid()?;
                        let options = wait.wait4_options()?;
                        self.wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
                            .map(|_| *task_id)
                    }
                    _ => None,
                }
            });
        let Some(waiter_id) = waiter else {
            return Ok(());
        };
        let (target_pid, options) = {
            let wait = match self.tasks.get(&waiter_id).map(|task| &task.state) {
                Some(TaskState::Waiting(wait)) => *wait,
                _ => return Ok(()),
            };
            (
                wait.wait4_target_pid().ok_or(ZX_ERR_BAD_STATE)?,
                wait.wait4_options().ok_or(ZX_ERR_BAD_STATE)?,
            )
        };
        let event = self
            .wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
            .ok_or(ZX_ERR_BAD_STATE)?;
        let status = match event {
            WaitChildEvent::Zombie { status } | WaitChildEvent::Stopped { status } => status,
            WaitChildEvent::Continued => LINUX_WAIT_STATUS_CONTINUED,
        };
        self.consume_wait_event(child_tgid, event)?;
        self.write_wait_result(waiter_id, child_tgid, status)?;
        if matches!(event, WaitChildEvent::Zombie { .. }) {
            self.reap_group(child_tgid)?;
        }
        Ok(())
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
        group.last_stop_signal = None;
        group.stop_wait_pending = false;
        group.continued_wait_pending = false;
        group.sigchld_info = None;
        self.refresh_pidfds_for_group(tgid)?;
        self.maybe_wake_parent_waiter(tgid)
    }

    fn finalize_group_exit(&mut self, tgid: i32, code: i32) -> Result<(), zx_status_t> {
        let wait_status = (code & 0xff) << 8;
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: code,
                code: LINUX_CLD_EXITED,
            },
        )?;
        self.finalize_group_zombie(tgid, wait_status, code)?;
        self.service_pending_waiters()
    }

    fn finalize_group_signal_exit(&mut self, tgid: i32, signal: i32) -> Result<(), zx_status_t> {
        let wait_status = signal & 0x7f;
        let exit_code = 128 + signal;
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: signal,
                code: LINUX_CLD_KILLED,
            },
        )?;
        self.finalize_group_zombie(tgid, wait_status, exit_code)?;
        self.service_pending_waiters()
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
            if let Some(task) = self.tasks.get(member_id)
                && let TaskState::Waiting(wait) = task.state
            {
                self.cancel_task_wait(*member_id, wait);
            }
            self.process_robust_list_on_exit(*member_id);
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
        if let Some(task) = self.tasks.get(&task_id)
            && let TaskState::Waiting(wait) = task.state
        {
            self.cancel_task_wait(task_id, wait);
        }
        self.process_robust_list_on_exit(task_id);
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

    fn process_robust_list_on_exit(&mut self, task_id: i32) {
        let Some((tgid, session, robust)) = self.tasks.get(&task_id).and_then(|task| {
            task.robust_list
                .map(|robust| (task.tgid, task.carrier.session_handle, robust))
        }) else {
            return;
        };
        let Ok((mut next, futex_offset, list_op_pending)) =
            read_guest_robust_list_head(session, robust.head_addr)
        else {
            return;
        };

        let mut walked = 0usize;
        while next != 0 && next != robust.head_addr && walked < LINUX_ROBUST_LIST_LIMIT {
            let entry_addr = next;
            next = match read_guest_u64(session, entry_addr) {
                Ok(next) => next,
                Err(_) => break,
            };
            self.process_robust_entry_on_exit(task_id, tgid, session, entry_addr, futex_offset);
            walked += 1;
        }

        if list_op_pending != 0 && list_op_pending != robust.head_addr {
            self.process_robust_entry_on_exit(
                task_id,
                tgid,
                session,
                list_op_pending,
                futex_offset,
            );
        }
    }

    fn process_robust_entry_on_exit(
        &mut self,
        task_id: i32,
        tgid: i32,
        session: zx_handle_t,
        entry_addr: u64,
        futex_offset: i64,
    ) {
        let futex_addr = if futex_offset >= 0 {
            entry_addr.checked_add(futex_offset as u64)
        } else {
            entry_addr.checked_sub(futex_offset.unsigned_abs())
        };
        let Some(futex_addr) = futex_addr else {
            return;
        };
        let Ok(word) = read_guest_u32(session, futex_addr) else {
            return;
        };
        if (word & LINUX_FUTEX_TID_MASK) != (task_id as u32 & LINUX_FUTEX_TID_MASK) {
            return;
        }
        let new_word = (word & LINUX_FUTEX_WAITERS) | LINUX_FUTEX_OWNER_DIED;
        if write_guest_u32(session, futex_addr, new_word).is_err() {
            return;
        }
        let key = Self::private_futex_key_for_tgid(tgid, futex_addr);
        let _ = self.wake_futex_waiters(key, 1, LINUX_FUTEX_BITSET_MATCH_ANY);
    }

    fn signalfd_ready_mask(&self, owner_tid: i32, mask: u64) -> Result<u64, zx_status_t> {
        let task = self.tasks.get(&owner_tid).ok_or(ZX_ERR_BAD_STATE)?;
        let blocked = task.signals.blocked;
        let task_pending = task.signals.pending & mask & blocked;
        let shared_pending = self
            .groups
            .get(&task.tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .shared_pending
            & mask
            & blocked;
        Ok(task_pending | shared_pending)
    }

    fn refresh_signalfd_key(&mut self, key: LinuxFileDescriptionKey) -> Result<(), zx_status_t> {
        let Some(weak) = self.signalfds.get(&key).cloned() else {
            return Ok(());
        };
        let Some(state) = weak.upgrade() else {
            let _ = self.signalfds.remove(&key);
            return Ok(());
        };
        let (owner_tid, _owner_tgid, mask, wait_handle, closed) = {
            let guard = state.lock();
            (
                guard.owner_tid,
                guard.owner_tgid,
                guard.mask,
                guard.wait_handle,
                guard.closed,
            )
        };
        if closed {
            let _ = self.signalfds.remove(&key);
            return Ok(());
        }
        let ready = self.signalfd_ready_mask(owner_tid, mask)? != 0;
        zx_status_result(ax_object_signal(
            wait_handle,
            SIGNALFD_READABLE_SIGNAL,
            if ready { SIGNALFD_READABLE_SIGNAL } else { 0 },
        ))
    }

    fn refresh_signalfds_for_group(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let keys = self.signalfds.keys().copied().collect::<Vec<_>>();
        let mut stale = Vec::new();
        for key in keys {
            let Some(weak) = self.signalfds.get(&key).cloned() else {
                continue;
            };
            let Some(state) = weak.upgrade() else {
                stale.push(key);
                continue;
            };
            let owner_tgid = {
                let guard = state.lock();
                guard.owner_tgid
            };
            if owner_tgid == tgid {
                self.refresh_signalfd_key(key)?;
            }
        }
        for key in stale {
            let _ = self.signalfds.remove(&key);
        }
        Ok(())
    }

    fn refresh_pidfd_key(&mut self, key: LinuxFileDescriptionKey) -> Result<(), zx_status_t> {
        let Some(weak) = self.pidfds.get(&key).cloned() else {
            return Ok(());
        };
        let Some(state) = weak.upgrade() else {
            let _ = self.pidfds.remove(&key);
            return Ok(());
        };
        let (target_tgid, wait_handle, closed) = {
            let guard = state.lock();
            (guard.target_tgid, guard.wait_handle, guard.closed)
        };
        if closed {
            let _ = self.pidfds.remove(&key);
            return Ok(());
        }
        let ready = self
            .groups
            .get(&target_tgid)
            .is_some_and(|group| matches!(group.state, ThreadGroupState::Zombie { .. }));
        zx_status_result(ax_object_signal(
            wait_handle,
            PIDFD_READABLE_SIGNAL,
            if ready { PIDFD_READABLE_SIGNAL } else { 0 },
        ))
    }

    fn refresh_pidfds_for_group(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let keys = self.pidfds.keys().copied().collect::<Vec<_>>();
        let mut stale = Vec::new();
        for key in keys {
            let Some(weak) = self.pidfds.get(&key).cloned() else {
                continue;
            };
            let Some(state) = weak.upgrade() else {
                stale.push(key);
                continue;
            };
            let target_tgid = {
                let guard = state.lock();
                guard.target_tgid
            };
            if target_tgid == tgid {
                self.refresh_pidfd_key(key)?;
            }
        }
        for key in stale {
            let _ = self.pidfds.remove(&key);
        }
        Ok(())
    }

    fn shared_sigchld_info(&self, tgid: i32) -> Option<LinuxSigChldInfo> {
        self.groups.get(&tgid).and_then(|group| group.sigchld_info)
    }

    fn clear_shared_signal_state(&mut self, tgid: i32, signal: i32) -> Result<(), zx_status_t> {
        if signal == LINUX_SIGCHLD
            && let Some(group) = self.groups.get_mut(&tgid)
        {
            group.sigchld_info = None;
        }
        Ok(())
    }

    fn queue_sigchld_to_parent(
        &mut self,
        child_tgid: i32,
        info: LinuxSigChldInfo,
    ) -> Result<(), zx_status_t> {
        let Some(parent_tgid) = self
            .groups
            .get(&child_tgid)
            .and_then(|group| group.parent_tgid)
        else {
            return Ok(());
        };
        let bit = linux_signal_bit(LINUX_SIGCHLD).ok_or(ZX_ERR_INVALID_ARGS)?;
        let Some(parent) = self.groups.get_mut(&parent_tgid) else {
            return Ok(());
        };
        if matches!(parent.state, ThreadGroupState::Zombie { .. }) {
            return Ok(());
        }
        parent.shared_pending |= bit;
        parent.sigchld_info = Some(info);
        self.refresh_signalfds_for_group(parent_tgid)
    }

    fn lookup_socket_keys(
        &self,
        tgid: i32,
        fd: i32,
    ) -> Result<(LinuxFileDescriptionKey, LinuxFileDescriptionKey), zx_status_t> {
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        let key = file_description_key(entry.description());
        let Some(peer_key) = self.unix_socket_peers.get(&key).copied() else {
            return Err(ZX_ERR_NOT_SUPPORTED);
        };
        Ok((key, peer_key))
    }

    fn peek_socket_rights(&self, key: LinuxFileDescriptionKey) -> Option<&PendingScmRights> {
        self.unix_socket_rights.get(&key).and_then(VecDeque::front)
    }

    fn take_socket_rights(&mut self, key: LinuxFileDescriptionKey) -> Option<PendingScmRights> {
        let rights = self
            .unix_socket_rights
            .get_mut(&key)
            .and_then(VecDeque::pop_front);
        if self
            .unix_socket_rights
            .get(&key)
            .is_some_and(VecDeque::is_empty)
        {
            let _ = self.unix_socket_rights.remove(&key);
        }
        rights
    }

    fn take_signalfd_signal(
        &mut self,
        owner_tid: i32,
        mask: u64,
    ) -> Result<Option<ConsumedSignal>, zx_status_t> {
        let blocked = self.task_signal_mask(owner_tid)?;
        let tgid = self.tasks.get(&owner_tid).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let task_pending = self
            .tasks
            .get(&owner_tid)
            .map(|task| task.signals.pending & mask & blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(task_pending) {
            if let Some(task) = self.tasks.get_mut(&owner_tid) {
                task.signals.pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(ConsumedSignal {
                signal,
                sigchld_info: None,
            }));
        }
        let shared_pending = self
            .groups
            .get(&tgid)
            .map(|group| group.shared_pending & mask & blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(shared_pending) {
            let sigchld_info = self
                .shared_sigchld_info(tgid)
                .filter(|_| signal == LINUX_SIGCHLD);
            if let Some(group) = self.groups.get_mut(&tgid) {
                group.shared_pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.clear_shared_signal_state(tgid, signal)?;
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(ConsumedSignal {
                signal,
                sigchld_info,
            }));
        }
        Ok(None)
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
        wait: WaitState,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        loop {
            let Some(signal) = self.take_deliverable_signal(task_id)? else {
                return Ok(SyscallAction::LeaveStopped);
            };
            match self.signal_delivery_action(task_id, signal)? {
                SignalDeliveryAction::Ignore => {}
                SignalDeliveryAction::Terminate => {
                    self.cancel_task_wait(task_id, wait);
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.state = TaskState::Running;
                    }
                    return Ok(SyscallAction::GroupSignalExit(signal));
                }
                SignalDeliveryAction::Stop => {
                    let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                    self.enter_group_stop(tgid, signal)?;
                    return Ok(SyscallAction::LeaveStopped);
                }
                SignalDeliveryAction::Catch(sigaction) => {
                    self.cancel_task_wait(task_id, wait);
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
            .filter_map(|(task_id, task)| match task.state {
                TaskState::Waiting(wait) => Some((*task_id, wait)),
                TaskState::Running => None,
            })
            .collect::<Vec<_>>();
        for (task_id, wait) in waiting {
            if !self.tasks.contains_key(&task_id) {
                continue;
            }
            if wait.packet_key().is_some() {
                self.queue_wait_signal_wake(task_id)?;
            } else {
                self.interrupt_waiting_task(task_id)?;
            }
        }
        Ok(())
    }

    fn take_deliverable_signal(&mut self, task_id: i32) -> Result<Option<i32>, zx_status_t> {
        let blocked = self.task_signal_mask(task_id)?;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let task_pending = self
            .tasks
            .get(&task_id)
            .map(|task| task.signals.pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(task_pending) {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.signals.pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.refresh_signalfds_for_group(tgid)?;
            return Ok(Some(signal));
        }

        let shared_pending = self
            .groups
            .get(&tgid)
            .map(|group| group.shared_pending & !blocked)
            .ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(signal) = lowest_signal(shared_pending) {
            if let Some(group) = self.groups.get_mut(&tgid) {
                group.shared_pending &= !linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
            }
            self.clear_shared_signal_state(tgid, signal)?;
            self.refresh_signalfds_for_group(tgid)?;
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
                if signal_default_ignored(signal) || signal == LINUX_SIGCONT {
                    Ok(SignalDeliveryAction::Ignore)
                } else if signal_default_stop(signal) {
                    Ok(SignalDeliveryAction::Stop)
                } else {
                    Ok(SignalDeliveryAction::Terminate)
                }
            }
            _ => Ok(SignalDeliveryAction::Catch(action)),
        }
    }

    fn clear_job_control_pending(&mut self, tgid: i32) -> Result<(), zx_status_t> {
        let mask = job_control_signal_mask();
        if let Some(group) = self.groups.get_mut(&tgid) {
            group.shared_pending &= !mask;
        }
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for task_id in task_ids {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.signals.pending &= !mask;
            }
        }
        Ok(())
    }

    fn enter_group_stop(&mut self, tgid: i32, signal: i32) -> Result<(), zx_status_t> {
        {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if matches!(group.state, ThreadGroupState::Zombie { .. }) {
                return Ok(());
            }
            group.state = ThreadGroupState::Stopped;
            group.last_stop_signal = Some(signal);
            group.stop_wait_pending = true;
            group.continued_wait_pending = false;
        }
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: signal,
                code: LINUX_CLD_STOPPED,
            },
        )?;
        self.refresh_pidfds_for_group(tgid)?;
        self.refresh_signalfds_for_group(tgid)?;
        self.maybe_wake_parent_waiter(tgid)?;
        self.service_pending_waiters()
    }

    fn continue_thread_group(
        &mut self,
        tgid: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let was_stopped = {
            let Some(group) = self.groups.get_mut(&tgid) else {
                return Ok(linux_errno(LINUX_ESRCH));
            };
            match group.state {
                ThreadGroupState::Zombie { .. } => return Ok(linux_errno(LINUX_ESRCH)),
                ThreadGroupState::Running => false,
                ThreadGroupState::Stopped => {
                    group.state = ThreadGroupState::Running;
                    group.continued_wait_pending = true;
                    true
                }
            }
        };
        self.clear_job_control_pending(tgid)?;
        self.refresh_pidfds_for_group(tgid)?;
        self.refresh_signalfds_for_group(tgid)?;
        if !was_stopped {
            return Ok(0);
        }
        self.queue_sigchld_to_parent(
            tgid,
            LinuxSigChldInfo {
                pid: tgid,
                status: LINUX_SIGCONT,
                code: LINUX_CLD_CONTINUED,
            },
        )?;
        self.maybe_wake_parent_waiter(tgid)?;
        self.service_pending_waiters()?;
        let task_ids = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .task_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut running_tasks = Vec::new();
        let mut waiting_tasks = Vec::new();
        for task_id in task_ids {
            match self.tasks.get(&task_id).map(|task| &task.state) {
                Some(TaskState::Running) => running_tasks.push(task_id),
                Some(TaskState::Waiting(_)) => waiting_tasks.push(task_id),
                None => {}
            }
        }
        for task_id in running_tasks {
            let sidecar = self
                .tasks
                .get(&task_id)
                .map(|task| task.carrier.sidecar_vmo)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let stop_state = ax_guest_stop_state_read(sidecar)?;
            self.writeback_and_resume(task_id, &stop_state)?;
        }
        for task_id in waiting_tasks {
            self.retry_waiting_task(task_id, stdout)?;
        }
        Ok(0)
    }

    fn queue_signal_to_group(
        &mut self,
        tgid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let Some(group) = self.groups.get(&tgid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if matches!(group.state, ThreadGroupState::Zombie { .. }) {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            return self.continue_thread_group(tgid, stdout);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        self.groups
            .get_mut(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .shared_pending |= bit;
        self.refresh_signalfds_for_group(tgid)?;
        Ok(0)
    }

    fn queue_signal_to_process_group(
        &mut self,
        pgid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let target_tgids = self
            .groups
            .iter()
            .filter_map(|(tgid, group)| {
                (group.pgid == pgid && !matches!(group.state, ThreadGroupState::Zombie { .. }))
                    .then_some(*tgid)
            })
            .collect::<Vec<_>>();
        if target_tgids.is_empty() {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            for tgid in target_tgids {
                let _ = self.continue_thread_group(tgid, stdout)?;
            }
            return Ok(0);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        for tgid in &target_tgids {
            self.groups
                .get_mut(tgid)
                .ok_or(ZX_ERR_BAD_STATE)?
                .shared_pending |= bit;
        }
        for tgid in target_tgids {
            self.refresh_signalfds_for_group(tgid)?;
        }
        Ok(0)
    }

    fn queue_signal_to_task(
        &mut self,
        tgid: i32,
        tid: i32,
        signal: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<u64, zx_status_t> {
        let Some(task) = self.tasks.get(&tid) else {
            return Ok(linux_errno(LINUX_ESRCH));
        };
        if task.tgid != tgid
            || self
                .groups
                .get(&tgid)
                .is_some_and(|group| matches!(group.state, ThreadGroupState::Zombie { .. }))
        {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if signal == 0 {
            return Ok(0);
        }
        if signal == LINUX_SIGCONT {
            return self.continue_thread_group(tgid, stdout);
        }
        let bit = linux_signal_bit(signal).ok_or(ZX_ERR_INVALID_ARGS)?;
        self.tasks
            .get_mut(&tid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .signals
            .pending |= bit;
        self.refresh_signalfds_for_group(tgid)?;
        Ok(0)
    }

    fn fd_wait_policy(&self, task_id: i32, fd: i32) -> Result<FdWaitPolicy, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let resources = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .resources
            .as_ref()
            .ok_or(ZX_ERR_BAD_STATE)?;
        let entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        Ok(FdWaitPolicy {
            nonblock: entry.description().flags().contains(OpenFlags::NONBLOCK),
            wait_interest: resources.fd_table.wait_interest(fd)?,
        })
    }

    fn fd_wait_policy_for_op(
        &self,
        task_id: i32,
        fd: i32,
        op: FdWaitOp,
    ) -> Result<FdWaitPolicy, zx_status_t> {
        let mut policy = self.fd_wait_policy(task_id, fd)?;
        policy.wait_interest = policy.wait_interest.and_then(|interest| {
            let filtered = filter_wait_interest(interest, op);
            (filtered.signals() != 0).then_some(filtered)
        });
        Ok(policy)
    }

    fn arm_fd_wait(
        &mut self,
        task_id: i32,
        wait: WaitState,
        wait_interest: WaitSpec,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let status = ax_object_wait_async(
            wait_interest.handle(),
            self.port,
            wait.packet_key().ok_or(ZX_ERR_BAD_STATE)?,
            wait_interest.signals(),
            0,
        );
        zx_status_result(status)?;
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
    }

    fn sys_read(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;

        let signalfd = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.fd_table.get(fd).and_then(|entry| {
                entry
                    .description()
                    .ops()
                    .as_ref()
                    .as_any()
                    .downcast_ref::<SignalFd>()
                    .cloned()
            })
        };
        if let Some(signalfd) = signalfd {
            return self.sys_read_signalfd(task_id, fd, buf, len, stop_state, signalfd);
        }

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(len, 0);
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fd_table.read(fd, &mut bytes) {
                Ok(actual) => ReadAttempt::Ready { bytes, actual },
                Err(ZX_ERR_SHOULD_WAIT) => ReadAttempt::WouldBlock(wait_policy),
                Err(ZX_ERR_PEER_CLOSED) => ReadAttempt::Ready { bytes, actual: 0 },
                Err(status) => ReadAttempt::Err(status),
            }
        };

        match attempt {
            ReadAttempt::Ready { bytes, actual } => {
                let result = match write_guest_bytes(session, buf, &bytes[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                };
                complete_syscall(stop_state, result)?;
                Ok(SyscallAction::Resume)
            }
            ReadAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::FdRead {
                        fd,
                        buf,
                        len,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            ReadAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    fn sys_read_signalfd(
        &mut self,
        task_id: i32,
        fd: i32,
        buf: u64,
        len: usize,
        stop_state: &mut ax_guest_stop_state_t,
        signalfd: SignalFd,
    ) -> Result<SyscallAction, zx_status_t> {
        if len < LINUX_SIGNALFD_SIGINFO_BYTES || !len.is_multiple_of(LINUX_SIGNALFD_SIGINFO_BYTES) {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;
        let (owner_tid, owner_tgid, mask, _wait_handle) =
            signalfd.snapshot().ok_or(ZX_ERR_BAD_STATE)?;
        match self.take_signalfd_signal(owner_tid, mask)? {
            Some(consumed) => {
                let info = encode_signalfd_siginfo(consumed.signal, consumed.sigchld_info);
                match write_guest_bytes(session, buf, &info) {
                    Ok(()) => {
                        complete_syscall(
                            stop_state,
                            u64::try_from(LINUX_SIGNALFD_SIGINFO_BYTES)
                                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                        )?;
                    }
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_write_status_to_errno(status)),
                        )?;
                    }
                }
                self.refresh_signalfds_for_group(owner_tgid)?;
                Ok(SyscallAction::Resume)
            }
            None => {
                if wait_policy.nonblock || wait_policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::FdRead {
                        fd,
                        buf,
                        len,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    wait_policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
        }
    }

    fn sys_write(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
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
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Write)?;
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fd_table.write(fd, &bytes) {
                Ok(actual) => WriteAttempt::Ready(actual),
                Err(ZX_ERR_SHOULD_WAIT) => WriteAttempt::WouldBlock(wait_policy),
                Err(status) => WriteAttempt::Err(status),
            }
        };

        match attempt {
            WriteAttempt::Ready(actual) => {
                if fd == 1 || fd == 2 {
                    stdout.extend_from_slice(&bytes[..actual]);
                }
                complete_syscall(
                    stop_state,
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                )?;
                Ok(SyscallAction::Resume)
            }
            WriteAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::FdWrite {
                        fd,
                        buf,
                        len,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            WriteAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    fn sys_sendmsg(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let msg_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        if flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let msg = match read_guest_msghdr(session, msg_addr) {
            Ok(msg) => msg,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if msg.name_addr != 0 || msg.name_len != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let iovecs = match read_guest_iovecs(session, msg.iov_addr, msg.iov_len) {
            Ok(iovecs) => iovecs,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let payload = match read_guest_iovec_payload(session, &iovecs) {
            Ok(payload) => payload,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let (_socket_key, peer_key) = match self.lookup_socket_keys(tgid, fd) {
            Ok(keys) => keys,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Write)?;
        let parsed_rights = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match parse_scm_rights(session, &resources.fd_table, &msg) {
                Ok(rights) => rights,
                Err(status) => {
                    complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if parsed_rights
            .as_ref()
            .is_some_and(|rights| !rights.descriptions.is_empty() && payload.is_empty())
        {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fd_table.write(fd, &payload) {
                Ok(actual) => WriteAttempt::Ready(actual),
                Err(ZX_ERR_SHOULD_WAIT) => WriteAttempt::WouldBlock(wait_policy),
                Err(status) => WriteAttempt::Err(status),
            }
        };

        match attempt {
            WriteAttempt::Ready(actual) => {
                if actual != 0
                    && let Some(rights) =
                        parsed_rights.filter(|rights| !rights.descriptions.is_empty())
                {
                    self.unix_socket_rights
                        .entry(peer_key)
                        .or_default()
                        .push_back(rights);
                }
                complete_syscall(
                    stop_state,
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                )?;
                Ok(SyscallAction::Resume)
            }
            WriteAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::MsgSend {
                        fd,
                        msg_addr,
                        flags,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            WriteAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    fn sys_recvmsg(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let msg_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        if flags & !LINUX_MSG_CMSG_CLOEXEC != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let msg = match read_guest_msghdr(session, msg_addr) {
            Ok(msg) => msg,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if msg.name_addr != 0 || msg.name_len != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let iovecs = match read_guest_iovecs(session, msg.iov_addr, msg.iov_len) {
            Ok(iovecs) => iovecs,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let total_len = total_iovec_len(&iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let (socket_key, _) = match self.lookup_socket_keys(tgid, fd) {
            Ok(keys) => keys,
            Err(ZX_ERR_NOT_SUPPORTED) => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOTSOCK))?;
                return Ok(SyscallAction::Resume);
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        if let Some(rights) = self.peek_socket_rights(socket_key) {
            let required = scm_rights_control_bytes(rights.descriptions.len())?;
            if msg.control_len < required {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
        }

        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(total_len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        payload.resize(total_len, 0);
        let attempt = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fd_table.read(fd, &mut payload) {
                Ok(actual) => ReadAttempt::Ready {
                    bytes: payload,
                    actual,
                },
                Err(ZX_ERR_SHOULD_WAIT) => ReadAttempt::WouldBlock(wait_policy),
                Err(ZX_ERR_PEER_CLOSED) => ReadAttempt::Ready {
                    bytes: payload,
                    actual: 0,
                },
                Err(status) => ReadAttempt::Err(status),
            }
        };

        match attempt {
            ReadAttempt::Ready { bytes, actual } => {
                let rights_bundle = if actual != 0 {
                    self.peek_socket_rights(socket_key).cloned()
                } else {
                    None
                };
                let received_flags = if (flags & LINUX_MSG_CMSG_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                let mut installed_fds = Vec::new();
                let control_bytes = if let Some(rights) = rights_bundle.as_ref() {
                    let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                    installed_fds
                        .try_reserve_exact(rights.descriptions.len())
                        .map_err(|_| ZX_ERR_NO_MEMORY)?;
                    for description in &rights.descriptions {
                        installed_fds.push(
                            resources
                                .fd_table
                                .install(Arc::clone(description), received_flags),
                        );
                    }
                    Some(encode_scm_rights_control(&installed_fds)?)
                } else {
                    None
                };
                let guest_result = (|| -> Result<u64, zx_status_t> {
                    let wrote = write_guest_iovec_payload(session, &iovecs, &bytes[..actual])?;
                    if wrote != actual {
                        return Err(ZX_ERR_IO_DATA_INTEGRITY);
                    }
                    if let Some(control) = control_bytes.as_ref() {
                        write_guest_bytes(session, msg.control_addr, control)?;
                        write_guest_recv_msghdr(session, msg_addr, control.len(), 0)?;
                    } else {
                        write_guest_recv_msghdr(session, msg_addr, 0, 0)?;
                    }
                    u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)
                })();
                match guest_result {
                    Ok(result) => {
                        if rights_bundle.is_some() {
                            let _ = self.take_socket_rights(socket_key);
                        }
                        complete_syscall(stop_state, result)?;
                    }
                    Err(status) => {
                        if let Some(group) = self.groups.get_mut(&tgid)
                            && let Some(resources) = group.resources.as_mut()
                        {
                            for fd in installed_fds {
                                let _ = resources.fd_table.close(fd);
                            }
                        }
                        complete_syscall(stop_state, linux_errno(map_msg_status_to_errno(status)))?;
                    }
                }
                Ok(SyscallAction::Resume)
            }
            ReadAttempt::WouldBlock(policy) => {
                if policy.nonblock || policy.wait_interest.is_none() {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                let packet_key = self.alloc_packet_key()?;
                let wait = WaitState {
                    restartable: true,
                    kind: WaitKind::MsgRecv {
                        fd,
                        msg_addr,
                        flags,
                        packet_key,
                    },
                };
                self.arm_fd_wait(
                    task_id,
                    wait,
                    policy.wait_interest.ok_or(ZX_ERR_BAD_STATE)?,
                    stop_state,
                )
            }
            ReadAttempt::Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    fn retry_waiting_task(
        &mut self,
        task_id: i32,
        stdout: &mut Vec<u8>,
    ) -> Result<(), zx_status_t> {
        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(());
        };
        let tgid = task.tgid;
        if self
            .groups
            .get(&tgid)
            .is_some_and(|group| matches!(group.state, ThreadGroupState::Stopped))
        {
            return Ok(());
        }
        let TaskState::Waiting(wait) = task.state else {
            return Ok(());
        };

        let mut stop_state = ax_guest_stop_state_read(task.carrier.sidecar_vmo)?;
        match self.deliver_or_interrupt_wait(task_id, wait, &mut stop_state)? {
            SyscallAction::Resume => self.writeback_and_resume(task_id, &stop_state),
            SyscallAction::LeaveStopped => match wait.kind {
                WaitKind::Wait4 { .. } => Ok(()),
                WaitKind::Futex { .. } => Ok(()),
                WaitKind::Epoll { .. } => Ok(()),
                WaitKind::FdRead { fd, buf, len, .. } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = buf;
                    stop_state.regs.rdx = len as u64;
                    let action = self.sys_read(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::FdWrite { fd, buf, len, .. } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = buf;
                    stop_state.regs.rdx = len as u64;
                    let action = self.sys_write(task_id, &mut stop_state, stdout)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::MsgRecv {
                    fd,
                    msg_addr,
                    flags,
                    ..
                } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = msg_addr;
                    stop_state.regs.rdx = flags;
                    let action = self.sys_recvmsg(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
                WaitKind::MsgSend {
                    fd,
                    msg_addr,
                    flags,
                    ..
                } => {
                    self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                        TaskState::Running;
                    stop_state.regs.rdi = fd as u64;
                    stop_state.regs.rsi = msg_addr;
                    stop_state.regs.rdx = flags;
                    let action = self.sys_sendmsg(task_id, &mut stop_state)?;
                    self.complete_task_action(task_id, action, &mut stop_state)
                }
            },
            SyscallAction::GroupSignalExit(signal) => self.exit_group_from_signal(task_id, signal),
            SyscallAction::TaskExit(_) | SyscallAction::GroupExit(_) => Err(ZX_ERR_BAD_STATE),
        }
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

    fn sys_getpgrp(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let pgid = self.task_pgid(task_id)?;
        complete_syscall(stop_state, pgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getpgid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let caller_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let pid = stop_state.regs.rdi as u32 as i32;
        let result = match self.target_tgid_for_pid_arg(caller_tgid, pid) {
            Ok(target_tgid) => self
                .groups
                .get(&target_tgid)
                .map(|group| group.pgid as u64)
                .ok_or(ZX_ERR_NOT_FOUND)
                .unwrap_or_else(|_| linux_errno(LINUX_ESRCH)),
            Err(ZX_ERR_INVALID_ARGS) => linux_errno(LINUX_EINVAL),
            Err(_) => linux_errno(LINUX_ESRCH),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getsid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let caller_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let pid = stop_state.regs.rdi as u32 as i32;
        let result = match self.target_tgid_for_pid_arg(caller_tgid, pid) {
            Ok(target_tgid) => self
                .groups
                .get(&target_tgid)
                .map(|group| group.sid as u64)
                .ok_or(ZX_ERR_NOT_FOUND)
                .unwrap_or_else(|_| linux_errno(LINUX_ESRCH)),
            Err(ZX_ERR_INVALID_ARGS) => linux_errno(LINUX_EINVAL),
            Err(_) => linux_errno(LINUX_ESRCH),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_setpgid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let caller_tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let caller_sid = self.task_sid(task_id)?;
        let pid = stop_state.regs.rdi as u32 as i32;
        let pgid = stop_state.regs.rsi as u32 as i32;
        let target_tgid = if pid == 0 { caller_tgid } else { pid };
        let new_pgid = if pgid == 0 { target_tgid } else { pgid };
        let result = if target_tgid <= 0 || new_pgid <= 0 {
            linux_errno(LINUX_EINVAL)
        } else {
            let target_group = match self.groups.get(&target_tgid) {
                Some(group) => group,
                None => {
                    complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
                    return Ok(SyscallAction::Resume);
                }
            };
            if target_group.sid != caller_sid {
                linux_errno(LINUX_EPERM)
            } else if !matches!(target_group.state, ThreadGroupState::Running)
                || (target_tgid != caller_tgid && target_group.parent_tgid != Some(caller_tgid))
            {
                linux_errno(LINUX_ESRCH)
            } else if target_group.sid == target_tgid
                || (new_pgid != target_tgid && !self.session_has_pgid(caller_sid, new_pgid))
            {
                linux_errno(LINUX_EPERM)
            } else {
                self.groups
                    .get_mut(&target_tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .pgid = new_pgid;
                0
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_setsid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let result = if group.pgid == tgid {
            linux_errno(LINUX_EPERM)
        } else {
            group.sid = tgid;
            group.pgid = tgid;
            tgid as u64
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_socketpair(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let domain = stop_state.regs.rdi;
        let socket_type = stop_state.regs.rsi;
        let protocol = stop_state.regs.rdx;
        let pair_addr = stop_state.regs.r10;
        if domain != LINUX_AF_UNIX || socket_type != LINUX_SOCK_STREAM || protocol != 0 {
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

        let mut left = ZX_HANDLE_INVALID;
        let mut right = ZX_HANDLE_INVALID;
        let status = zx_socket_create(0, &mut left, &mut right);
        if status != ZX_OK {
            complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            return Ok(SyscallAction::Resume);
        }

        let created = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let left_fd = resources.fd_table.open(
                Arc::new(SocketFd::new(left)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            );
            let right_fd = resources.fd_table.open(
                Arc::new(SocketFd::new(right)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            );
            match (left_fd, right_fd) {
                (Ok(left_fd), Ok(right_fd)) => {
                    let left_key = resources
                        .fd_table
                        .get(left_fd)
                        .map(|entry| file_description_key(entry.description()))
                        .ok_or(ZX_ERR_BAD_STATE)?;
                    let right_key = resources
                        .fd_table
                        .get(right_fd)
                        .map(|entry| file_description_key(entry.description()))
                        .ok_or(ZX_ERR_BAD_STATE)?;
                    Ok((left_fd, right_fd, left_key, right_key))
                }
                (Ok(left_fd), Err(status)) => {
                    let _ = resources.fd_table.close(left_fd);
                    Err(status)
                }
                (Err(status), _) => Err(status),
            }
        };

        match created {
            Ok((left_fd, right_fd, left_key, right_key)) => {
                if let Err(status) = write_guest_fd_pair(session, pair_addr, left_fd, right_fd) {
                    if let Some(group) = self.groups.get_mut(&tgid)
                        && let Some(resources) = group.resources.as_mut()
                    {
                        let _ = resources.fd_table.close(left_fd);
                        let _ = resources.fd_table.close(right_fd);
                    }
                    complete_syscall(
                        stop_state,
                        linux_errno(map_guest_write_status_to_errno(status)),
                    )?;
                    return Ok(SyscallAction::Resume);
                }
                self.unix_socket_peers.insert(left_key, right_key);
                self.unix_socket_peers.insert(right_key, left_key);
                complete_syscall(stop_state, 0)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_pidfd_open(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_tgid = linux_arg_i32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        if flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if !self.groups.contains_key(&target_tgid) {
            complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let pidfd = match PidFd::new(target_tgid) {
            Ok(pidfd) => pidfd,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let weak = pidfd.weak_state();
        let created_fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources
                .fd_table
                .open(Arc::new(pidfd), OpenFlags::READABLE, FdFlags::empty())
        };
        match created_fd {
            Ok(fd) => {
                let key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.pidfds.insert(key, weak);
                self.refresh_pidfd_key(key)?;
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_pidfd_send_signal(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let pidfd = linux_arg_i32(stop_state.regs.rdi);
        let signal = linux_arg_i32(stop_state.regs.rsi);
        let info = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        if info != 0 || flags != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let target_tgid = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let fd_entry = resources.fd_table.get(pidfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            let Some(pidfd) = fd_entry
                .description()
                .ops()
                .as_ref()
                .as_any()
                .downcast_ref::<PidFd>()
            else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            pidfd.snapshot().map(|(target_tgid, _)| target_tgid)
        };
        let Some(target_tgid) = target_tgid else {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        };
        let result = self.queue_signal_to_group(target_tgid, signal, stdout)?;
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_futex(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let uaddr = stop_state.regs.rdi;
        let futex_op = stop_state.regs.rsi;
        let val = stop_state.regs.rdx;
        let timeout_or_val2 = stop_state.regs.r10;
        let uaddr2 = stop_state.regs.r8;
        let val3 = stop_state.regs.r9;

        if (futex_op
            & !(LINUX_FUTEX_CMD_MASK | LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME))
            != 0
            || (futex_op & LINUX_FUTEX_CLOCK_REALTIME) != 0
            || (futex_op & LINUX_FUTEX_PRIVATE_FLAG) == 0
        {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let command = futex_op & LINUX_FUTEX_CMD_MASK;
        let key = self.private_futex_key(task_id, uaddr)?;
        match command {
            LINUX_FUTEX_WAIT | LINUX_FUTEX_WAIT_BITSET => {
                let bitset = if command == LINUX_FUTEX_WAIT {
                    LINUX_FUTEX_BITSET_MATCH_ANY
                } else {
                    let bitset = val3 as u32;
                    if bitset == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                        return Ok(SyscallAction::Resume);
                    }
                    bitset
                };
                if timeout_or_val2 != 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                    return Ok(SyscallAction::Resume);
                }
                let session = self
                    .tasks
                    .get(&task_id)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .carrier
                    .session_handle;
                let observed = match read_guest_u32(session, uaddr) {
                    Ok(word) => word,
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                let expected = val as u32;
                if observed != expected {
                    complete_syscall(stop_state, linux_errno(LINUX_EAGAIN))?;
                    return Ok(SyscallAction::Resume);
                }
                self.enqueue_futex_waiter(key, LinuxFutexWaiter { task_id, bitset });
                let wait = WaitState {
                    restartable: false,
                    kind: WaitKind::Futex { key },
                };
                self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state =
                    TaskState::Waiting(wait);
                self.deliver_or_interrupt_wait(task_id, wait, stop_state)
            }
            LINUX_FUTEX_WAKE | LINUX_FUTEX_WAKE_BITSET => {
                let wake_mask = if command == LINUX_FUTEX_WAKE {
                    LINUX_FUTEX_BITSET_MATCH_ANY
                } else {
                    let bitset = val3 as u32;
                    if bitset == 0 {
                        complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                        return Ok(SyscallAction::Resume);
                    }
                    bitset
                };
                let Ok(wake_count) = usize::try_from(val) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let woken = self.wake_futex_waiters(key, wake_count, wake_mask)?;
                complete_syscall(stop_state, woken)?;
                Ok(SyscallAction::Resume)
            }
            LINUX_FUTEX_REQUEUE => {
                if uaddr2 == 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                }
                let Ok(wake_count) = usize::try_from(val) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let Ok(requeue_count) = usize::try_from(timeout_or_val2) else {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                };
                let target = self.private_futex_key(task_id, uaddr2)?;
                if target == key {
                    complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                    return Ok(SyscallAction::Resume);
                }
                let woken = self.requeue_futex_waiters(key, target, wake_count, requeue_count)?;
                complete_syscall(stop_state, woken)?;
                Ok(SyscallAction::Resume)
            }
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                Ok(SyscallAction::Resume)
            }
        }
    }

    fn sys_set_robust_list(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let head_addr = stop_state.regs.rdi;
        let len = stop_state.regs.rsi;
        if head_addr == 0 || len != LINUX_ROBUST_LIST_HEAD_BYTES {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
        task.robust_list = Some(LinuxRobustListState { head_addr, len });
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_get_robust_list(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let target_tid = stop_state.regs.rdi as u32 as i32;
        let head_addr_ptr = stop_state.regs.rsi;
        let len_ptr = stop_state.regs.rdx;
        if head_addr_ptr == 0 || len_ptr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }

        let resolved_tid = if target_tid == 0 { task_id } else { target_tid };
        let Some(target) = self.tasks.get(&resolved_tid) else {
            complete_syscall(stop_state, linux_errno(LINUX_ESRCH))?;
            return Ok(SyscallAction::Resume);
        };
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let robust = target.robust_list.unwrap_or(LinuxRobustListState {
            head_addr: 0,
            len: LINUX_ROBUST_LIST_HEAD_BYTES,
        });
        if let Err(status) = write_guest_u64(session, head_addr_ptr, robust.head_addr) {
            complete_syscall(
                stop_state,
                linux_errno(map_guest_write_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }
        if let Err(status) = write_guest_u64(session, len_ptr, robust.len) {
            complete_syscall(
                stop_state,
                linux_errno(map_guest_write_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_epoll_create1(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let flags = stop_state.regs.rdi;
        if flags != 0 && flags != LINUX_EPOLL_CLOEXEC {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let fd_flags = if flags == LINUX_EPOLL_CLOEXEC {
                FdFlags::CLOEXEC
            } else {
                FdFlags::empty()
            };
            resources.fd_table.open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE,
                fd_flags,
            )
        };
        match fd {
            Ok(fd) => {
                let epoll_key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.epolls.insert(epoll_key, EpollInstance::new());
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_timerfd_create(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let clockid = stop_state.regs.rdi as u32 as i32;
        let flags = stop_state.regs.rsi;
        let allowed = LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC;
        if clockid != LINUX_CLOCK_MONOTONIC {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let timerfd = TimerFd::new();
        let fd = match timerfd {
            Ok(timerfd) => {
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                let mut open_flags = OpenFlags::READABLE;
                if (flags & LINUX_TFD_NONBLOCK) != 0 {
                    open_flags |= OpenFlags::NONBLOCK;
                }
                let fd_flags = if (flags & LINUX_TFD_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                resources
                    .fd_table
                    .open(Arc::new(timerfd), open_flags, fd_flags)
            }
            Err(status) => Err(status),
        };

        match fd {
            Ok(fd) => complete_syscall(stop_state, fd as u64)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_timerfd_settime(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        let new_value_addr = stop_state.regs.rdx;
        let old_value_addr = stop_state.regs.r10;
        if new_value_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
            return Ok(SyscallAction::Resume);
        }
        if old_value_addr != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let new_value = match read_guest_itimerspec(session, new_value_addr) {
            Ok(spec) => spec,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let result = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let Some(entry) = resources.fd_table.get(fd) else {
                complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
                return Ok(SyscallAction::Resume);
            };
            let Some(timerfd) = entry
                .description()
                .ops()
                .as_ref()
                .as_any()
                .downcast_ref::<TimerFd>()
            else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            timerfd.settime(flags, new_value)
        };

        match result {
            Ok(()) => complete_syscall(stop_state, 0)?,
            Err(ZX_ERR_INVALID_ARGS) => complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?,
            Err(ZX_ERR_NOT_SUPPORTED) => complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_timerfd_gettime(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
        Ok(SyscallAction::Resume)
    }

    fn sys_signalfd4(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = stop_state.regs.rdi as u32 as i32;
        let mask_addr = stop_state.regs.rsi;
        let sigset_size = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let allowed = LINUX_SFD_NONBLOCK | LINUX_SFD_CLOEXEC;
        if sigset_size != LINUX_SIGNAL_SET_BYTES as u64 || mask_addr == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let mask = match read_guest_signal_mask(session, mask_addr) {
            Ok(mask) => normalize_signal_mask(mask),
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        if fd != -1 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let signalfd = match SignalFd::new(task_id, tgid, mask) {
            Ok(signalfd) => signalfd,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let weak = signalfd.weak_state();
        let created_fd = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            let mut open_flags = OpenFlags::READABLE;
            if (flags & LINUX_SFD_NONBLOCK) != 0 {
                open_flags |= OpenFlags::NONBLOCK;
            }
            let fd_flags = if (flags & LINUX_SFD_CLOEXEC) != 0 {
                FdFlags::CLOEXEC
            } else {
                FdFlags::empty()
            };
            resources
                .fd_table
                .open(Arc::new(signalfd), open_flags, fd_flags)
        };

        match created_fd {
            Ok(fd) => {
                let key = {
                    let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                    file_description_key(entry.description())
                };
                self.signalfds.insert(key, weak);
                self.refresh_signalfd_key(key)?;
                complete_syscall(stop_state, fd as u64)?;
            }
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_eventfd2(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let initval = linux_arg_u32(stop_state.regs.rdi);
        let flags = stop_state.regs.rsi;
        let allowed = LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC;
        if (flags & !allowed) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let eventfd = EventFd::new(initval, (flags & LINUX_EFD_SEMAPHORE) != 0);
        let fd = match eventfd {
            Ok(eventfd) => {
                let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                let mut open_flags = OpenFlags::READABLE | OpenFlags::WRITABLE;
                if (flags & LINUX_EFD_NONBLOCK) != 0 {
                    open_flags |= OpenFlags::NONBLOCK;
                }
                let fd_flags = if (flags & LINUX_EFD_CLOEXEC) != 0 {
                    FdFlags::CLOEXEC
                } else {
                    FdFlags::empty()
                };
                resources
                    .fd_table
                    .open(Arc::new(eventfd), open_flags, fd_flags)
            }
            Err(status) => Err(status),
        };

        match fd {
            Ok(fd) => complete_syscall(stop_state, fd as u64)?,
            Err(status) => {
                complete_syscall(stop_state, linux_errno(map_fd_status_to_errno(status)))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_epoll_ctl(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let epfd = linux_arg_i32(stop_state.regs.rdi);
        let op = stop_state.regs.rsi as u32 as i32;
        let fd = linux_arg_i32(stop_state.regs.rdx);
        let event_addr = stop_state.regs.r10;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;

        let (epoll_key, target_description, raw_wait_interest) = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let epoll_entry = resources.fd_table.get(epfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            let epoll_key = file_description_key(epoll_entry.description());
            let target_entry = resources.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
            (
                epoll_key,
                Arc::clone(target_entry.description()),
                resources.fd_table.wait_interest(fd)?,
            )
        };
        if !self.epolls.contains_key(&epoll_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        }
        let target_key = file_description_key(&target_description);
        if target_key == epoll_key || self.epolls.contains_key(&target_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }

        match op {
            LINUX_EPOLL_CTL_ADD | LINUX_EPOLL_CTL_MOD => {
                if event_addr == 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_EFAULT))?;
                    return Ok(SyscallAction::Resume);
                }
                let event = match read_guest_epoll_event(session, event_addr) {
                    Ok(event) => event,
                    Err(status) => {
                        complete_syscall(
                            stop_state,
                            linux_errno(map_guest_memory_status_to_errno(status)),
                        )?;
                        return Ok(SyscallAction::Resume);
                    }
                };
                let unsupported = event.events
                    & !(LINUX_EPOLLIN
                        | LINUX_EPOLLOUT
                        | LINUX_EPOLLERR
                        | LINUX_EPOLLHUP
                        | LINUX_EPOLLONESHOT
                        | LINUX_EPOLLET);
                if unsupported != 0 {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
                    return Ok(SyscallAction::Resume);
                }
                let wait_interest = raw_wait_interest
                    .map(|interest| filter_epoll_wait_interest(interest, event.events));
                let exists = self
                    .epolls
                    .get(&epoll_key)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .entries
                    .contains_key(&target_key);
                if op == LINUX_EPOLL_CTL_ADD && exists {
                    complete_syscall(stop_state, linux_errno(LINUX_EEXIST))?;
                    return Ok(SyscallAction::Resume);
                }
                if op == LINUX_EPOLL_CTL_MOD && !exists {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
                    return Ok(SyscallAction::Resume);
                }
                if let Some(instance) = self.epolls.get_mut(&epoll_key) {
                    if let Some(old) = instance.entries.remove(&target_key)
                        && let Some(packet_key) = old.packet_key
                    {
                        let _ = self.epoll_packets.remove(&packet_key);
                    }
                    instance.ready_set.remove(&target_key);
                    instance.ready_list.retain(|queued| *queued != target_key);
                }
                let packet_key = if wait_interest.is_some() {
                    Some(self.alloc_packet_key()?)
                } else {
                    None
                };
                if let Some(packet_key) = packet_key {
                    self.epoll_packets
                        .insert(packet_key, (epoll_key, target_key));
                }
                let entry = EpollEntry {
                    description: target_description,
                    interest: event.events,
                    data: event.data,
                    wait_interest,
                    packet_key,
                    disabled: false,
                    queued_events: 0,
                    observer_armed: false,
                };
                self.epolls
                    .get_mut(&epoll_key)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .entries
                    .insert(target_key, entry);
                let ready = {
                    let instance = self.epolls.get(&epoll_key).ok_or(ZX_ERR_BAD_STATE)?;
                    let entry = instance.entries.get(&target_key).ok_or(ZX_ERR_BAD_STATE)?;
                    self.sample_epoll_ready_mask(entry)
                };
                self.queue_epoll_ready(epoll_key, target_key, ready);
                self.arm_epoll_entry(epoll_key, target_key)?;
                self.wake_one_epoll_waiter(epoll_key)?;
                complete_syscall(stop_state, 0)?;
            }
            LINUX_EPOLL_CTL_DEL => {
                let Some(instance) = self.epolls.get_mut(&epoll_key) else {
                    return Err(ZX_ERR_BAD_STATE);
                };
                let Some(old) = instance.entries.remove(&target_key) else {
                    complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
                    return Ok(SyscallAction::Resume);
                };
                if let Some(packet_key) = old.packet_key {
                    let _ = self.epoll_packets.remove(&packet_key);
                }
                instance.ready_set.remove(&target_key);
                instance.ready_list.retain(|queued| *queued != target_key);
                complete_syscall(stop_state, 0)?;
            }
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            }
        }
        Ok(SyscallAction::Resume)
    }

    fn sys_epoll_wait(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let epfd = linux_arg_i32(stop_state.regs.rdi);
        let events_addr = stop_state.regs.rsi;
        let maxevents = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let timeout = stop_state.regs.r10 as u32 as i32;
        if maxevents == 0 || timeout < -1 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let epoll_key = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let epoll_entry = resources.fd_table.get(epfd).ok_or(ZX_ERR_BAD_HANDLE)?;
            file_description_key(epoll_entry.description())
        };
        if !self.epolls.contains_key(&epoll_key) {
            complete_syscall(stop_state, linux_errno(LINUX_EBADF))?;
            return Ok(SyscallAction::Resume);
        }
        if self.complete_epoll_wait(task_id, epoll_key, events_addr, maxevents, stop_state)? {
            return Ok(SyscallAction::Resume);
        }
        if timeout == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        if timeout != -1 {
            complete_syscall(stop_state, linux_errno(LINUX_ENOSYS))?;
            return Ok(SyscallAction::Resume);
        }
        let wait = WaitState {
            restartable: true,
            kind: WaitKind::Epoll {
                epoll_key,
                events_addr,
                maxevents,
            },
        };
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.epolls
            .get_mut(&epoll_key)
            .ok_or(ZX_ERR_BAD_STATE)?
            .waiting_tasks
            .push_back(task_id);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
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
            let tgid = {
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
                task.tgid
            };
            self.refresh_signalfds_for_group(tgid)?;
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
        let tgid = {
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let Some(frame) = task.active_signal.take() else {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            };
            task.signals.blocked = frame.previous_blocked;
            stop_state.regs = frame.restore_regs;
            task.tgid
        };
        self.refresh_signalfds_for_group(tgid)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_kill(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let pid = stop_state.regs.rdi as u32 as i32;
        let signal = stop_state.regs.rsi as u32 as i32;
        let result = if !linux_signal_is_valid_or_zero(signal) || pid == -1 {
            linux_errno(LINUX_EINVAL)
        } else if pid == 0 {
            self.queue_signal_to_process_group(self.task_pgid(task_id)?, signal, stdout)?
        } else if pid < -1 {
            self.queue_signal_to_process_group(pid.saturating_abs(), signal, stdout)?
        } else {
            self.queue_signal_to_group(pid, signal, stdout)?
        };
        self.service_pending_waiters()?;
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_tgkill(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = stop_state.regs.rdi as u32 as i32;
        let tid = stop_state.regs.rsi as u32 as i32;
        let signal = stop_state.regs.rdx as u32 as i32;
        let result = if tgid <= 0 || tid <= 0 || !linux_signal_is_valid_or_zero(signal) {
            linux_errno(LINUX_EINVAL)
        } else {
            self.queue_signal_to_task(tgid, tid, signal, stdout)?
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
                robust_list: None,
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
        let (parent_pgid, parent_sid) = {
            let parent_group = self.groups.get(&parent_tgid).ok_or(ZX_ERR_BAD_STATE)?;
            (parent_group.pgid, parent_group.sid)
        };
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
                robust_list: None,
                active_signal: None,
            },
        );
        self.groups.insert(
            child_tgid,
            LinuxThreadGroup {
                tgid: child_tgid,
                leader_tid: child_tgid,
                parent_tgid: Some(parent_tgid),
                pgid: parent_pgid,
                sid: parent_sid,
                child_tgids: BTreeSet::new(),
                task_ids,
                state: ThreadGroupState::Running,
                last_stop_signal: None,
                stop_wait_pending: false,
                continued_wait_pending: false,
                shared_pending: 0,
                sigchld_info: None,
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
            task.robust_list = None;
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
        let supported_options = LINUX_WNOHANG | LINUX_WUNTRACED | LINUX_WCONTINUED;
        if (options & !supported_options) != 0 || rusage_addr != 0 {
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
            if !self.wait_matches(parent_tgid, target_pid, child_tgid) {
                continue;
            }
            has_match = true;
            if let Some(event) =
                self.wait_event_for_child(parent_tgid, target_pid, child_tgid, options)
            {
                let wait_status = match event {
                    WaitChildEvent::Zombie { status } | WaitChildEvent::Stopped { status } => {
                        status
                    }
                    WaitChildEvent::Continued => LINUX_WAIT_STATUS_CONTINUED,
                };
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
                self.consume_wait_event(child_tgid, event)?;
                complete_syscall(stop_state, child_tgid as u64)?;
                if matches!(event, WaitChildEvent::Zombie { .. }) {
                    self.reap_group(child_tgid)?;
                }
                return Ok(SyscallAction::Resume);
            }
        }
        if !has_match {
            complete_syscall(stop_state, linux_errno(LINUX_ECHILD))?;
            return Ok(SyscallAction::Resume);
        }
        if (options & LINUX_WNOHANG) != 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }

        let wait = WaitState {
            restartable: true,
            kind: WaitKind::Wait4 {
                target_pid,
                status_addr,
                options,
            },
        };
        self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?.state = TaskState::Waiting(wait);
        self.deliver_or_interrupt_wait(task_id, wait, stop_state)
    }

    fn sys_openat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        let mode = stop_state.regs.r10;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        if path.is_empty() {
            complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
            return Ok(SyscallAction::Resume);
        }
        let result = if path.starts_with("/proc") {
            let (open_flags, fd_flags) = decode_open_flags(flags);
            match self.open_proc_absolute(task_id, path.as_str()) {
                Ok(ops) => {
                    let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
                    let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
                    match resources.fd_table.open(ops, open_flags, fd_flags) {
                        Ok(fd) => fd as u64,
                        Err(status) => linux_errno(map_fd_status_to_errno(status)),
                    }
                }
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            }
        } else {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_mut().ok_or(ZX_ERR_BAD_STATE)?;
            resources.openat(session, dirfd, path_addr, flags, mode)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_newfstatat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let stat_addr = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        if path.is_empty() {
            complete_syscall(stop_state, linux_errno(LINUX_ENOENT))?;
            return Ok(SyscallAction::Resume);
        }
        let result = if path.starts_with("/proc") {
            if flags != 0 {
                linux_errno(LINUX_EINVAL)
            } else {
                match self.open_proc_absolute(task_id, path.as_str()) {
                    Ok(ops) => match stat_metadata_for_ops(ops.as_ref()) {
                        Ok(metadata) => write_guest_stat(session, stat_addr, metadata, None)?,
                        Err(status) => linux_errno(map_fd_status_to_errno(status)),
                    },
                    Err(status) => linux_errno(map_fd_status_to_errno(status)),
                }
            }
        } else {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.statat(session, dirfd, path_addr, stat_addr, flags)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
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
        robust_list: None,
        active_signal: None,
    };
    let mut task_ids = BTreeSet::new();
    task_ids.insert(1);
    let root_group = LinuxThreadGroup {
        tgid: 1,
        leader_tid: 1,
        parent_tgid: None,
        pgid: 1,
        sid: 1,
        child_tgids: BTreeSet::new(),
        task_ids,
        state: ThreadGroupState::Running,
        last_stop_signal: None,
        stop_wait_pending: false,
        continued_wait_pending: false,
        shared_pending: 0,
        sigchld_info: None,
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

fn emulate_common_syscall(
    session: zx_handle_t,
    stop_state: &mut ax_guest_stop_state_t,
    executive: &mut ExecutiveState,
    stdout: &mut Vec<u8>,
) -> Result<SyscallAction, zx_status_t> {
    match stop_state.regs.rax {
        LINUX_SYSCALL_READ => {
            let fd = linux_arg_i32(stop_state.regs.rdi);
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
            let fd = linux_arg_i32(stop_state.regs.rdi);
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
            let fd = linux_arg_i32(stop_state.regs.rdi);
            let result = match executive.fd_table.close(fd) {
                Ok(()) => 0,
                Err(status) => linux_errno(map_fd_status_to_errno(status)),
            };
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_FSTAT => {
            let fd = linux_arg_i32(stop_state.regs.rdi);
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
            let fd = linux_arg_i32(stop_state.regs.r8);
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
            let fd = linux_arg_i32(stop_state.regs.rdi);
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
            let dirfd = linux_arg_i32(stop_state.regs.rdi);
            let path = stop_state.regs.rsi;
            let flags = stop_state.regs.rdx;
            let mode = stop_state.regs.r10;
            let result = executive.openat(session, dirfd, path, flags, mode)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_NEWFSTATAT => {
            let dirfd = linux_arg_i32(stop_state.regs.rdi);
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
        Some("linux-round4-futex-smoke") => Some(LINUX_ROUND4_FUTEX_BYTES),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BYTES),
        Some("linux-round5-epoll-smoke") => Some(LINUX_ROUND5_EPOLL_BYTES),
        Some("linux-round6-eventfd-smoke") => Some(LINUX_ROUND6_EVENTFD_BYTES),
        Some("linux-round6-timerfd-smoke") => Some(LINUX_ROUND6_TIMERFD_BYTES),
        Some("linux-round6-signalfd-smoke") => Some(LINUX_ROUND6_SIGNALFD_BYTES),
        Some("linux-round6-futex-smoke") => Some(LINUX_ROUND6_FUTEX_BYTES),
        Some("linux-round6-scm-rights-smoke") => Some(LINUX_ROUND6_SCM_RIGHTS_BYTES),
        Some("linux-round6-pidfd-smoke") => Some(LINUX_ROUND6_PIDFD_BYTES),
        Some("linux-round6-proc-job-smoke") => Some(LINUX_ROUND6_PROC_JOB_BYTES),
        Some("linux-round6-proc-control-smoke") => Some(LINUX_ROUND6_PROC_CONTROL_BYTES),
        Some(_) => None,
    }
}

fn payload_path_for(args: &[String]) -> Option<&'static str> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BINARY_PATH),
        Some("linux-fd-smoke") => Some(LINUX_FD_SMOKE_BINARY_PATH),
        Some("linux-round2-smoke") => Some(LINUX_ROUND2_BINARY_PATH),
        Some("linux-round3-smoke") => Some(LINUX_ROUND3_BINARY_PATH),
        Some("linux-round4-futex-smoke") => Some(LINUX_ROUND4_FUTEX_BINARY_PATH),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BINARY_PATH),
        Some("linux-round5-epoll-smoke") => Some(LINUX_ROUND5_EPOLL_BINARY_PATH),
        Some("linux-round6-eventfd-smoke") => Some(LINUX_ROUND6_EVENTFD_BINARY_PATH),
        Some("linux-round6-timerfd-smoke") => Some(LINUX_ROUND6_TIMERFD_BINARY_PATH),
        Some("linux-round6-signalfd-smoke") => Some(LINUX_ROUND6_SIGNALFD_BINARY_PATH),
        Some("linux-round6-futex-smoke") => Some(LINUX_ROUND6_FUTEX_BINARY_PATH),
        Some("linux-round6-scm-rights-smoke") => Some(LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH),
        Some("linux-round6-pidfd-smoke") => Some(LINUX_ROUND6_PIDFD_BINARY_PATH),
        Some("linux-round6-proc-job-smoke") => Some(LINUX_ROUND6_PROC_JOB_BINARY_PATH),
        Some("linux-round6-proc-control-smoke") => Some(LINUX_ROUND6_PROC_CONTROL_BINARY_PATH),
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
    let mut cmdline = Vec::new();
    for arg in args {
        cmdline
            .try_reserve_exact(arg.len().checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        cmdline.extend_from_slice(arg.as_bytes());
        cmdline.push(0);
    }
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
        cmdline,
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
        _bytes: bytes,
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

fn read_guest_u32(session: zx_handle_t, addr: u64) -> Result<u32, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, 4)?;
    let raw = bytes.get(..4).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u32::from_ne_bytes(
        raw.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
}

fn read_guest_msghdr(session: zx_handle_t, addr: u64) -> Result<LinuxMsgHdr, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_MSGHDR_BYTES)?;
    let name_addr = u64::from_ne_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let name_len = u32::from_ne_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let iov_addr = u64::from_ne_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let iov_len = usize::try_from(u64::from_ne_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
    .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let control_addr = u64::from_ne_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let control_len = usize::try_from(u64::from_ne_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
    .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let _flags = u32::from_ne_bytes(
        bytes[48..52]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    Ok(LinuxMsgHdr {
        name_addr,
        name_len,
        iov_addr,
        iov_len,
        control_addr,
        control_len,
    })
}

fn read_guest_iovecs(
    session: zx_handle_t,
    addr: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, zx_status_t> {
    if count > LINUX_IOV_MAX {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    let mut iovecs = Vec::new();
    iovecs
        .try_reserve_exact(count)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..count {
        let base = addr
            .checked_add(
                u64::try_from(
                    index
                        .checked_mul(LINUX_IOVEC_BYTES)
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                )
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            )
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let bytes = read_guest_bytes(session, base, LINUX_IOVEC_BYTES)?;
        iovecs.push(LinuxIovec {
            base: u64::from_ne_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
            ),
            len: usize::try_from(u64::from_ne_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
            ))
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        });
    }
    Ok(iovecs)
}

fn total_iovec_len(iovecs: &[LinuxIovec]) -> Option<usize> {
    iovecs
        .iter()
        .try_fold(0usize, |total, iovec| total.checked_add(iovec.len))
}

fn read_guest_iovec_payload(
    session: zx_handle_t,
    iovecs: &[LinuxIovec],
) -> Result<Vec<u8>, zx_status_t> {
    let total_len = total_iovec_len(iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(total_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for iovec in iovecs {
        if iovec.len == 0 {
            continue;
        }
        let bytes = read_guest_bytes(session, iovec.base, iovec.len)?;
        payload.extend_from_slice(&bytes);
    }
    Ok(payload)
}

fn write_guest_iovec_payload(
    session: zx_handle_t,
    iovecs: &[LinuxIovec],
    payload: &[u8],
) -> Result<usize, zx_status_t> {
    let mut written = 0usize;
    for iovec in iovecs {
        if written >= payload.len() {
            break;
        }
        let chunk_len = (payload.len() - written).min(iovec.len);
        if chunk_len == 0 {
            continue;
        }
        write_guest_bytes(session, iovec.base, &payload[written..written + chunk_len])?;
        written = written.checked_add(chunk_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    Ok(written)
}

fn parse_scm_rights(
    session: zx_handle_t,
    fd_table: &FdTable,
    msg: &LinuxMsgHdr,
) -> Result<Option<PendingScmRights>, zx_status_t> {
    if msg.control_addr == 0 || msg.control_len == 0 {
        return Ok(None);
    }
    let control = read_guest_bytes(session, msg.control_addr, msg.control_len)?;
    let mut offset = 0usize;
    let mut descriptions = Vec::new();
    while offset
        .checked_add(LINUX_CMSGHDR_BYTES)
        .is_some_and(|end| end <= control.len())
    {
        let len = usize::try_from(u64::from_ne_bytes(
            control[offset..offset + 8]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ))
        .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let level = i32::from_ne_bytes(
            control[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        );
        let kind = i32::from_ne_bytes(
            control[offset + 12..offset + 16]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        );
        if len < LINUX_CMSGHDR_BYTES {
            return Err(ZX_ERR_IO_DATA_INTEGRITY);
        }
        let end = offset.checked_add(len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if end > control.len() {
            return Err(ZX_ERR_IO_DATA_INTEGRITY);
        }
        if level == LINUX_SOL_SOCKET && kind == LINUX_SCM_RIGHTS {
            let data = &control[offset + LINUX_CMSGHDR_BYTES..end];
            if !data.len().is_multiple_of(4) {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            descriptions
                .try_reserve_exact(data.len() / 4)
                .map_err(|_| ZX_ERR_NO_MEMORY)?;
            for raw_fd in data.chunks_exact(4) {
                let fd =
                    i32::from_ne_bytes(raw_fd.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
                let entry = fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                descriptions.push(Arc::clone(entry.description()));
            }
        }
        let step = align_up(len, 8)?;
        offset = offset.checked_add(step).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    if descriptions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PendingScmRights { descriptions }))
    }
}

fn write_guest_u32(session: zx_handle_t, addr: u64, value: u32) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &value.to_ne_bytes())
}

fn write_guest_bytes(session: zx_handle_t, addr: u64, bytes: &[u8]) -> Result<(), zx_status_t> {
    let status = ax_guest_session_write_memory(session, addr, bytes);
    if status == ZX_OK { Ok(()) } else { Err(status) }
}

fn write_guest_recv_msghdr(
    session: zx_handle_t,
    msg_addr: u64,
    control_len: usize,
    flags: u32,
) -> Result<(), zx_status_t> {
    write_guest_u32(session, msg_addr + 8, 0)?;
    write_guest_u64(
        session,
        msg_addr + 40,
        u64::try_from(control_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
    )?;
    write_guest_u32(session, msg_addr + 48, flags)?;
    Ok(())
}

fn scm_rights_control_bytes(fd_count: usize) -> Result<usize, zx_status_t> {
    let raw_len = LINUX_CMSGHDR_BYTES
        .checked_add(fd_count.checked_mul(4).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    align_up(raw_len, 8)
}

fn encode_scm_rights_control(fds: &[i32]) -> Result<Vec<u8>, zx_status_t> {
    let raw_len = LINUX_CMSGHDR_BYTES
        .checked_add(fds.len().checked_mul(4).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let total_len = scm_rights_control_bytes(fds.len())?;
    let mut control = Vec::new();
    control
        .try_reserve_exact(total_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    control.resize(total_len, 0);
    control[0..8].copy_from_slice(
        &u64::try_from(raw_len)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?
            .to_ne_bytes(),
    );
    control[8..12].copy_from_slice(&LINUX_SOL_SOCKET.to_ne_bytes());
    control[12..16].copy_from_slice(&LINUX_SCM_RIGHTS.to_ne_bytes());
    let mut cursor = LINUX_CMSGHDR_BYTES;
    for fd in fds {
        control[cursor..cursor + 4].copy_from_slice(&fd.to_ne_bytes());
        cursor += 4;
    }
    Ok(control)
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

fn file_description_key(description: &Arc<OpenFileDescription>) -> LinuxFileDescriptionKey {
    LinuxFileDescriptionKey(Arc::as_ptr(description) as usize)
}

fn map_wait_signals_to_epoll(signals: u32) -> u32 {
    let mut events = 0u32;
    if (signals
        & (ZX_CHANNEL_READABLE
            | ZX_SOCKET_READABLE
            | EVENTFD_READABLE_SIGNAL
            | SIGNALFD_READABLE_SIGNAL
            | PIDFD_READABLE_SIGNAL
            | ZX_TIMER_SIGNALED))
        != 0
    {
        events |= LINUX_EPOLLIN;
    }
    if (signals & (ZX_CHANNEL_WRITABLE | ZX_SOCKET_WRITABLE | EVENTFD_WRITABLE_SIGNAL)) != 0 {
        events |= LINUX_EPOLLOUT;
    }
    if (signals & (ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED)) != 0 {
        events |= LINUX_EPOLLHUP;
    }
    events
}

fn filter_epoll_ready_events(interest: u32, ready: u32) -> u32 {
    let requested = interest & (LINUX_EPOLLIN | LINUX_EPOLLOUT);
    (ready & requested) | (ready & (LINUX_EPOLLERR | LINUX_EPOLLHUP))
}

fn filter_epoll_wait_interest(interest: WaitSpec, epoll_interest: u32) -> WaitSpec {
    let peer_closed = ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED;
    let mut signals = 0;
    if (epoll_interest & LINUX_EPOLLIN) != 0 {
        signals |= interest.signals()
            & (ZX_CHANNEL_READABLE
                | ZX_SOCKET_READABLE
                | EVENTFD_READABLE_SIGNAL
                | SIGNALFD_READABLE_SIGNAL
                | ZX_TIMER_SIGNALED);
    }
    if (epoll_interest & LINUX_EPOLLOUT) != 0 {
        signals |= interest.signals()
            & (ZX_CHANNEL_WRITABLE | ZX_SOCKET_WRITABLE | EVENTFD_WRITABLE_SIGNAL);
    }
    if signals != 0 || (epoll_interest & LINUX_EPOLLHUP) != 0 {
        signals |= interest.signals() & peer_closed;
    }
    WaitSpec::new(interest.handle(), signals)
}

fn read_guest_epoll_event(session: zx_handle_t, addr: u64) -> Result<LinuxEpollEvent, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_EPOLL_EVENT_BYTES)?;
    let raw = bytes
        .get(..LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxEpollEvent {
        events: u32::from_ne_bytes(raw[0..4].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        data: u64::from_ne_bytes(
            raw[4..12]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
    })
}

fn encode_epoll_events(events: &[LinuxEpollEvent]) -> Result<Vec<u8>, zx_status_t> {
    let total = events
        .len()
        .checked_mul(LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(total, 0);
    for (index, event) in events.iter().enumerate() {
        let start = index
            .checked_mul(LINUX_EPOLL_EVENT_BYTES)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        bytes[start..start + 4].copy_from_slice(&event.events.to_ne_bytes());
        bytes[start + 4..start + 12].copy_from_slice(&event.data.to_ne_bytes());
    }
    Ok(bytes)
}

fn filter_wait_interest(interest: WaitSpec, op: FdWaitOp) -> WaitSpec {
    let peer_closed = ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED;
    let signals = match op {
        FdWaitOp::Read => {
            interest.signals()
                & (ZX_CHANNEL_READABLE
                    | ZX_SOCKET_READABLE
                    | EVENTFD_READABLE_SIGNAL
                    | SIGNALFD_READABLE_SIGNAL
                    | ZX_TIMER_SIGNALED
                    | peer_closed)
        }
        FdWaitOp::Write => {
            interest.signals()
                & (ZX_CHANNEL_WRITABLE | ZX_SOCKET_WRITABLE | EVENTFD_WRITABLE_SIGNAL | peer_closed)
        }
    };
    WaitSpec::new(interest.handle(), signals)
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

fn signal_default_stop(signal: i32) -> bool {
    matches!(
        signal,
        LINUX_SIGSTOP | LINUX_SIGTSTP | LINUX_SIGTTIN | LINUX_SIGTTOU
    )
}

const fn job_control_stop_mask() -> u64 {
    (1u64 << ((LINUX_SIGSTOP - 1) as u32))
        | (1u64 << ((LINUX_SIGTSTP - 1) as u32))
        | (1u64 << ((LINUX_SIGTTIN - 1) as u32))
        | (1u64 << ((LINUX_SIGTTOU - 1) as u32))
}

fn job_control_signal_mask() -> u64 {
    job_control_stop_mask() | linux_signal_bit(LINUX_SIGCONT).unwrap_or(0)
}

const fn linux_wait_status_stopped(signal: i32) -> i32 {
    ((signal & 0xff) << 8) | 0x7f
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

fn map_msg_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EFAULT,
        ZX_ERR_IO_DATA_INTEGRITY | ZX_ERR_NOT_SUPPORTED | ZX_ERR_BAD_STATE => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY | ZX_ERR_INTERNAL => LINUX_ENOMEM,
        _ => LINUX_EINVAL,
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
                            .map_err(linux_status_from_errno)?
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
                            .map_err(linux_status_from_errno)?
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

    #[allow(clippy::too_many_arguments)]
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
            if !offset.is_multiple_of(USER_PAGE_BYTES) {
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
        if !addr.is_multiple_of(USER_PAGE_BYTES) || len == 0 {
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
        if !addr.is_multiple_of(USER_PAGE_BYTES) || len == 0 {
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
    if !LINUX_ROUND4_FUTEX_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND4_FUTEX_BINARY_PATH,
            LINUX_ROUND4_FUTEX_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND4_SIGNAL_BINARY_PATH,
            LINUX_ROUND4_SIGNAL_BYTES,
        ));
    }
    if !LINUX_ROUND5_EPOLL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND5_EPOLL_BINARY_PATH,
            LINUX_ROUND5_EPOLL_BYTES,
        ));
    }
    if !LINUX_ROUND6_EVENTFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_EVENTFD_BINARY_PATH,
            LINUX_ROUND6_EVENTFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_TIMERFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_TIMERFD_BINARY_PATH,
            LINUX_ROUND6_TIMERFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_SIGNALFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_SIGNALFD_BINARY_PATH,
            LINUX_ROUND6_SIGNALFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_FUTEX_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_FUTEX_BINARY_PATH,
            LINUX_ROUND6_FUTEX_BYTES,
        ));
    }
    if !LINUX_ROUND6_SCM_RIGHTS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH,
            LINUX_ROUND6_SCM_RIGHTS_BYTES,
        ));
    }
    if !LINUX_ROUND6_PIDFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PIDFD_BINARY_PATH,
            LINUX_ROUND6_PIDFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_JOB_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_JOB_BINARY_PATH,
            LINUX_ROUND6_PROC_JOB_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_CONTROL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_CONTROL_BINARY_PATH,
            LINUX_ROUND6_PROC_CONTROL_BYTES,
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
    if !LINUX_ROUND4_FUTEX_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round4-futex-smoke.nxcd",
            LINUX_ROUND4_FUTEX_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round4-signal-smoke.nxcd",
            LINUX_ROUND4_SIGNAL_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND5_EPOLL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round5-epoll-smoke.nxcd",
            LINUX_ROUND5_EPOLL_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_EVENTFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-eventfd-smoke.nxcd",
            LINUX_ROUND6_EVENTFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_TIMERFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-timerfd-smoke.nxcd",
            LINUX_ROUND6_TIMERFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_SIGNALFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-signalfd-smoke.nxcd",
            LINUX_ROUND6_SIGNALFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_FUTEX_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-futex-smoke.nxcd",
            LINUX_ROUND6_FUTEX_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-scm-rights-smoke.nxcd",
            LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PIDFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-pidfd-smoke.nxcd",
            LINUX_ROUND6_PIDFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_JOB_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-job-smoke.nxcd",
            LINUX_ROUND6_PROC_JOB_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_CONTROL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-control-smoke.nxcd",
            LINUX_ROUND6_PROC_CONTROL_DECL_BYTES,
        ));
    }
    let bootstrap = BootstrapNamespace::build(&assets)?;
    let mut mounts = bootstrap.namespace().mounts().clone();
    mounts.insert("/", bootstrap.boot_root())?;
    Ok(nexus_io::ProcessNamespace::new(mounts))
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

fn encode_signalfd_siginfo(
    signal: i32,
    sigchld_info: Option<LinuxSigChldInfo>,
) -> [u8; LINUX_SIGNALFD_SIGINFO_BYTES] {
    let mut bytes = [0u8; LINUX_SIGNALFD_SIGINFO_BYTES];
    bytes[0..4].copy_from_slice(&(signal as u32).to_ne_bytes());
    if let Some(info) = sigchld_info {
        bytes[8..12].copy_from_slice(&info.code.to_ne_bytes());
        bytes[12..16].copy_from_slice(&(info.pid as u32).to_ne_bytes());
        bytes[40..44].copy_from_slice(&info.status.to_ne_bytes());
    }
    bytes
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

fn linux_arg_i32(raw: u64) -> i32 {
    raw as u32 as i32
}

fn linux_arg_u32(raw: u64) -> u32 {
    raw as u32
}

fn write_guest_u64(session: zx_handle_t, addr: u64, value: u64) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &value.to_ne_bytes())
}

fn read_guest_i64(session: zx_handle_t, addr: u64) -> Result<i64, zx_status_t> {
    let value = read_guest_u64(session, addr)?;
    Ok(i64::from_ne_bytes(value.to_ne_bytes()))
}

fn read_guest_robust_list_head(
    session: zx_handle_t,
    head_addr: u64,
) -> Result<(u64, i64, u64), zx_status_t> {
    Ok((
        read_guest_u64(session, head_addr)?,
        read_guest_i64(session, head_addr + 8)?,
        read_guest_u64(session, head_addr + 16)?,
    ))
}

fn parse_linux_timespec_ns(raw: &[u8]) -> Result<u64, zx_status_t> {
    if raw.len() < LINUX_TIMESPEC_BYTES {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    let seconds = i64::from_ne_bytes(raw[0..8].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
    let nanos = i64::from_ne_bytes(
        raw[8..16]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let seconds = u64::try_from(seconds).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let nanos = u64::try_from(nanos).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or(ZX_ERR_OUT_OF_RANGE)
}

fn read_guest_itimerspec(session: zx_handle_t, addr: u64) -> Result<LinuxItimerSpec, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_ITIMERSPEC_BYTES)?;
    let raw = bytes
        .get(..LINUX_ITIMERSPEC_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxItimerSpec {
        interval_ns: parse_linux_timespec_ns(&raw[..LINUX_TIMESPEC_BYTES])?,
        value_ns: parse_linux_timespec_ns(&raw[LINUX_TIMESPEC_BYTES..LINUX_ITIMERSPEC_BYTES])?,
    })
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::any::Any;
    use nexus_io::{NamespaceTrie, ProcessNamespace, PseudoNodeFd, SeekOrigin};
    use std::sync::Mutex as StdMutex;

    #[derive(Clone, Default)]
    struct RecordingFd {
        writes: Arc<StdMutex<Vec<u8>>>,
    }

    impl RecordingFd {
        fn new() -> Self {
            Self::default()
        }

        fn bytes(&self) -> Vec<u8> {
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

    fn test_linux_mm() -> LinuxMm {
        LinuxMm {
            root_vmar: ZX_HANDLE_INVALID,
            heap_vmar: ZX_HANDLE_INVALID,
            heap_base: 0,
            heap_limit: 0,
            heap_vmo: ZX_HANDLE_INVALID,
            heap_break: 0,
            heap_mapped_len: 0,
            mmap_vmar: ZX_HANDLE_INVALID,
            mmap_base: 0,
            map_tree: BTreeMap::new(),
        }
    }

    fn test_kernel_with_stdio(stdout: RecordingFd) -> StarnixKernel {
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

        let resources = ExecutiveState {
            process_handle: ZX_HANDLE_INVALID,
            fd_table,
            namespace: ProcessNamespace::new(NamespaceTrie::new()),
            directory_offsets: BTreeMap::new(),
            linux_mm: test_linux_mm(),
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
                path: String::from("bin/linux-round6-proc-job-smoke"),
                cmdline: b"linux-round6-proc-job-smoke\0".to_vec(),
                exec_blob: Vec::new(),
                writable_ranges: Vec::new(),
            }),
            resources: Some(resources),
        };
        StarnixKernel::new(ZX_HANDLE_INVALID, ZX_HANDLE_INVALID, root_task, root_group)
    }

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
    fn proc_child_task_views_are_available() {
        let stdout = RecordingFd::new();
        let mut kernel = test_kernel_with_stdio(stdout);
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
                state: TaskState::Running,
                signals: TaskSignals::default(),
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
                pgid: 2,
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
                    writable_ranges: Vec::new(),
                }),
                resources: None,
            },
        );

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
    fn parent_sigchld_info_tracks_stop_and_continue() {
        let stdout = RecordingFd::new();
        let mut kernel = test_kernel_with_stdio(stdout);
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
                state: TaskState::Running,
                signals: TaskSignals::default(),
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
                pgid: 2,
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
                image: None,
                resources: None,
            },
        );

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
            parent_vmar,
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
            vmar,
            options as u64,
            vmar_offset,
            vmo,
            vmo_offset,
            len,
            mapped_addr as *mut u64 as u64,
            0,
        ],
    )
}

fn zx_vmar_unmap_local(vmar: zx_handle_t, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(AXLE_SYS_VMAR_UNMAP as u64, [vmar, addr, len, 0, 0, 0])
}

fn zx_vmar_protect_local(vmar: zx_handle_t, options: u32, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMAR_PROTECT as u64,
        [vmar, options as u64, addr, len, 0, 0],
    )
}
