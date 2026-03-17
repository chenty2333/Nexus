mod bootstrap;
mod fs;
mod mm;
mod poll;
mod signal;
mod substrate;
mod sys;
mod task;

#[allow(unused_imports)]
pub(in crate::starnix) use self::fs::anon_inode::LinuxItimerSpec;
use self::fs::anon_inode::{EventFd, PidFd, PidFdState, SignalFd, SignalFdState, TimerFd};
use self::fs::fd::{LinuxStatMetadata, ProcessResources};
#[allow(unused_imports)]
pub(in crate::starnix) use self::fs::fd::{
    decode_open_flags, encode_linux_dirent64, encode_linux_fd_flags, encode_linux_open_flags,
    install_stdio_fd, write_guest_fd_pair, write_guest_rlimit, write_guest_stat, write_guest_statx,
};
use self::fs::procfs::{pread_from_ops, pwrite_to_ops, stat_metadata_for_ops};
#[allow(unused_imports)]
pub(in crate::starnix) use self::fs::unix::{LinuxIovec, LinuxMsgHdr};
use self::fs::unix::{
    encode_scm_rights_control, parse_scm_rights, read_guest_iovec_payload, read_guest_iovecs,
    read_guest_msghdr, scm_rights_control_bytes, total_iovec_len, write_guest_iovec_payload,
    write_guest_recv_msghdr,
};
#[allow(unused_imports)]
pub(in crate::starnix) use self::mm::exec::{
    LinuxElf, LinuxLoadSegment, LinuxTlsSegment, PreparedLinuxStack,
};
use self::mm::exec::{
    TaskImage, build_task_image, open_exec_image_from_namespace,
    read_exec_image_bytes_from_namespace, read_guest_string_array,
};
use self::mm::mmap::{LinuxMm, LinuxWritableRange};
use self::poll::epoll::EpollInstance;
use self::poll::readiness::filter_wait_interest;
use self::signal::action::{
    LinuxSigAction, read_guest_sigaction, read_guest_signal_mask, write_guest_sigaction,
    write_guest_signal_mask,
};
use self::signal::delivery::SignalDeliveryAction;
use self::substrate::guest::{
    copy_guest_region, create_thread_carrier, linux_guest_initial_regs, prepare_process_carrier,
    read_guest_bytes, read_guest_c_string, read_guest_i64, read_guest_u32, read_guest_u64,
    start_prepared_carrier_guest, write_guest_bytes, write_guest_u32, write_guest_u64,
};
use self::substrate::restart::complete_syscall;
use self::sys::table::{emulate_common_syscall, linux_arg_i32, linux_arg_u32};
use self::task::kernel::{StarnixKernel, SyscallAction, file_description_key};
use self::task::task::{
    ActiveSignalFrame, LinuxRobustListState, LinuxTask, TaskCarrier, TaskSignals, TaskState,
};
use self::task::thread_group::{LinuxSigChldInfo, LinuxThreadGroup, ThreadGroupState};
use self::task::wait::{
    FdWaitOp, FdWaitPolicy, LinuxFileDescriptionKey, LinuxFutexKey, LinuxFutexWaiter,
    PendingScmRights, ReadAttempt, WaitChildEvent, WaitKind, WaitState, WriteAttempt,
};

#[cfg(test)]
use self::fs::fd::FsContext;
#[cfg(test)]
use self::fs::procfs::ProcFdDirFd;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use crate::services::{LocalFdMetadataKind, local_fd_metadata, local_fd_pread, local_fd_pwrite};
use crate::{
    LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH, LINUX_DYNAMIC_ELF_SMOKE_BYTES,
    LINUX_DYNAMIC_INTERP_BINARY_PATH, LINUX_DYNAMIC_INTERP_BYTES, LINUX_DYNAMIC_MAIN_BINARY_PATH,
    LINUX_DYNAMIC_MAIN_BYTES, LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH, LINUX_DYNAMIC_PIE_INTERP_BYTES,
    LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH, LINUX_DYNAMIC_PIE_MAIN_BYTES,
    LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH, LINUX_DYNAMIC_PIE_SMOKE_BYTES,
    LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES, LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH,
    LINUX_DYNAMIC_RUNTIME_INTERP_BYTES, LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH,
    LINUX_DYNAMIC_RUNTIME_MAIN_BYTES, LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH,
    LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES, LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES,
    LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH, LINUX_DYNAMIC_TLS_INTERP_BYTES,
    LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH, LINUX_DYNAMIC_TLS_MAIN_BYTES,
    LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH, LINUX_DYNAMIC_TLS_SMOKE_BYTES, LINUX_FD_SMOKE_BINARY_PATH,
    LINUX_FD_SMOKE_BYTES, LINUX_FD_SMOKE_DECL_BYTES, LINUX_GLIBC_HELLO_BINARY_PATH,
    LINUX_GLIBC_HELLO_BYTES, LINUX_GLIBC_HELLO_DECL_BYTES, LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
    LINUX_GLIBC_RUNTIME_INTERP_BYTES, LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
    LINUX_GLIBC_RUNTIME_LIBC_BYTES, LINUX_HELLO_BINARY_PATH, LINUX_HELLO_BYTES,
    LINUX_HELLO_DECL_BYTES, LINUX_ROUND2_BINARY_PATH, LINUX_ROUND2_BYTES, LINUX_ROUND2_DECL_BYTES,
    LINUX_ROUND3_BINARY_PATH, LINUX_ROUND3_BYTES, LINUX_ROUND3_DECL_BYTES,
    LINUX_ROUND4_FUTEX_BINARY_PATH, LINUX_ROUND4_FUTEX_BYTES, LINUX_ROUND4_FUTEX_DECL_BYTES,
    LINUX_ROUND4_SIGNAL_BINARY_PATH, LINUX_ROUND4_SIGNAL_BYTES, LINUX_ROUND4_SIGNAL_DECL_BYTES,
    LINUX_ROUND5_EPOLL_BINARY_PATH, LINUX_ROUND5_EPOLL_BYTES, LINUX_ROUND5_EPOLL_DECL_BYTES,
    LINUX_ROUND6_EVENTFD_BINARY_PATH, LINUX_ROUND6_EVENTFD_BYTES, LINUX_ROUND6_EVENTFD_DECL_BYTES,
    LINUX_ROUND6_FUTEX_BINARY_PATH, LINUX_ROUND6_FUTEX_BYTES, LINUX_ROUND6_FUTEX_DECL_BYTES,
    LINUX_ROUND6_PIDFD_BINARY_PATH, LINUX_ROUND6_PIDFD_BYTES, LINUX_ROUND6_PIDFD_DECL_BYTES,
    LINUX_ROUND6_PROC_CONTROL_BINARY_PATH, LINUX_ROUND6_PROC_CONTROL_BYTES,
    LINUX_ROUND6_PROC_CONTROL_DECL_BYTES, LINUX_ROUND6_PROC_JOB_BINARY_PATH,
    LINUX_ROUND6_PROC_JOB_BYTES, LINUX_ROUND6_PROC_JOB_DECL_BYTES,
    LINUX_ROUND6_PROC_TTY_BINARY_PATH, LINUX_ROUND6_PROC_TTY_BYTES,
    LINUX_ROUND6_PROC_TTY_DECL_BYTES, LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH,
    LINUX_ROUND6_SCM_RIGHTS_BYTES, LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
    LINUX_ROUND6_SIGNALFD_BINARY_PATH, LINUX_ROUND6_SIGNALFD_BYTES,
    LINUX_ROUND6_SIGNALFD_DECL_BYTES, LINUX_ROUND6_TIMERFD_BINARY_PATH, LINUX_ROUND6_TIMERFD_BYTES,
    LINUX_ROUND6_TIMERFD_DECL_BYTES, LINUX_RUNTIME_FD_BINARY_PATH, LINUX_RUNTIME_FD_BYTES,
    LINUX_RUNTIME_FS_BINARY_PATH, LINUX_RUNTIME_FS_BYTES, LINUX_RUNTIME_FS_DECL_BYTES,
    LINUX_RUNTIME_MISC_BINARY_PATH, LINUX_RUNTIME_MISC_BYTES, LINUX_RUNTIME_MISC_DECL_BYTES,
    LINUX_RUNTIME_PROCESS_BINARY_PATH, LINUX_RUNTIME_PROCESS_BYTES,
    LINUX_RUNTIME_PROCESS_DECL_BYTES, LINUX_RUNTIME_TLS_BINARY_PATH, LINUX_RUNTIME_TLS_BYTES,
    LINUX_RUNTIME_TLS_DECL_BYTES, STARTUP_HANDLE_COMPONENT_STATUS,
    STARTUP_HANDLE_STARNIX_IMAGE_VMO, STARTUP_HANDLE_STARNIX_PARENT_PROCESS,
    STARTUP_HANDLE_STARNIX_STDOUT,
};
use axle_types::guest::{
    AX_GUEST_STOP_REASON_X64_SYSCALL, AX_GUEST_X64_SYSCALL_INSN_LEN, AX_LINUX_EXEC_SPEC_F_INTERP,
    AX_LINUX_EXEC_SPEC_V1, AX_LINUX_EXEC_SPEC_V2,
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
    ZX_VM_COMPACT, ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_PRIVATE_CLONE,
    ZX_VM_SPECIFIC,
};
use axle_types::{
    ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_linux_exec_interp_header_t,
    ax_linux_exec_spec_header_t, zx_handle_t, zx_status_t,
};
use libax::{
    AX_TIME_INFINITE, ax_eventpair_create, ax_guest_session_create, ax_guest_session_read_memory,
    ax_guest_session_resume, ax_guest_session_write_memory, ax_guest_stop_state_read,
    ax_guest_stop_state_write, ax_handle_close as zx_handle_close,
    ax_handle_duplicate as zx_handle_duplicate, ax_linux_exec_spec_blob,
    ax_linux_exec_spec_blob_with_interp, ax_object_signal, ax_object_wait_async,
    ax_object_wait_one, ax_packet_user_t as zx_packet_user_t, ax_port_create as zx_port_create,
    ax_port_packet_t as zx_port_packet_t, ax_port_queue as zx_port_queue,
    ax_port_wait as zx_port_wait, ax_process_create as zx_process_create,
    ax_process_prepare_linux_exec, ax_process_start_guest, ax_socket_create as zx_socket_create,
    ax_status_result as zx_status_result, ax_task_kill as zx_task_kill,
    ax_thread_create as zx_thread_create, ax_thread_get_guest_x64_fs_base,
    ax_thread_set_guest_x64_fs_base, ax_thread_start_guest, ax_timer_cancel,
    ax_timer_create_monotonic, ax_timer_set, ax_vmo_create as zx_vmo_create,
    ax_vmo_read as zx_vmo_read, ax_vmo_write as zx_vmo_write,
};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFileDescription, OpenFlags,
    PipeFd, PseudoNodeFd, SeekOrigin, SocketFd, WaitSpec,
};
use spin::Mutex;

const USER_PAGE_BYTES: u64 = 0x1000;
// Keep this Linux guest bootstrap layout in sync with
// `kernel/axle-kernel/src/userspace.rs`.
const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * 4096;
const USER_SHARED_BYTES: u64 = USER_PAGE_BYTES * 2;
const USER_STACK_BYTES: u64 = USER_PAGE_BYTES * 16;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000;
const USER_MAIN_ET_DYN_LOAD_BIAS: u64 = USER_CODE_VA;
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
const LINUX_SYSCALL_LSEEK: u64 = 8;
const LINUX_SYSCALL_READV: u64 = 19;
const LINUX_SYSCALL_WRITEV: u64 = 20;
const LINUX_SYSCALL_ACCESS: u64 = 21;
const LINUX_SYSCALL_PREAD64: u64 = 17;
const LINUX_SYSCALL_PWRITE64: u64 = 18;
const LINUX_SYSCALL_DUP2: u64 = 33;
const LINUX_SYSCALL_MMAP: u64 = 9;
const LINUX_SYSCALL_MPROTECT: u64 = 10;
const LINUX_SYSCALL_MUNMAP: u64 = 11;
const LINUX_SYSCALL_RT_SIGACTION: u64 = 13;
const LINUX_SYSCALL_RT_SIGPROCMASK: u64 = 14;
const LINUX_SYSCALL_RT_SIGRETURN: u64 = 15;
const LINUX_SYSCALL_BRK: u64 = 12;
const LINUX_SYSCALL_FCNTL: u64 = 72;
const LINUX_SYSCALL_GETCWD: u64 = 79;
const LINUX_SYSCALL_CHDIR: u64 = 80;
const LINUX_SYSCALL_READLINK: u64 = 89;
const LINUX_SYSCALL_GETPID: u64 = 39;
const LINUX_SYSCALL_UNAME: u64 = 63;
const LINUX_SYSCALL_GETUID: u64 = 102;
const LINUX_SYSCALL_GETGID: u64 = 104;
const LINUX_SYSCALL_GETEUID: u64 = 107;
const LINUX_SYSCALL_GETEGID: u64 = 108;
const LINUX_SYSCALL_GETPPID: u64 = 110;
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
const LINUX_SYSCALL_SET_TID_ADDRESS: u64 = 218;
const LINUX_SYSCALL_ARCH_PRCTL: u64 = 158;
const LINUX_SYSCALL_TGKILL: u64 = 234;
const LINUX_SYSCALL_GETDENTS64: u64 = 217;
const LINUX_SYSCALL_READLINKAT: u64 = 267;
const LINUX_SYSCALL_FACCESSAT: u64 = 269;
const LINUX_SYSCALL_PRLIMIT64: u64 = 302;
const LINUX_SYSCALL_STATX: u64 = 332;
const LINUX_SYSCALL_PIDFD_SEND_SIGNAL: u64 = 424;
const LINUX_SYSCALL_FACCESSAT2: u64 = 439;
const LINUX_SYSCALL_EXIT: u64 = 60;
const LINUX_SYSCALL_OPENAT: u64 = 257;
const LINUX_SYSCALL_NEWFSTATAT: u64 = 262;
const LINUX_SYSCALL_EPOLL_CREATE1: u64 = 291;
const LINUX_SYSCALL_DUP3: u64 = 292;
const LINUX_SYSCALL_EXIT_GROUP: u64 = 231;
const LINUX_SYSCALL_PIPE2: u64 = 293;
const LINUX_SYSCALL_GETRANDOM: u64 = 318;
const LINUX_SYSCALL_PIDFD_OPEN: u64 = 434;
const LINUX_AF_UNIX: u64 = 1;
const LINUX_SOCK_STREAM: u64 = 1;
const LINUX_SOL_SOCKET: i32 = 1;
const LINUX_SCM_RIGHTS: i32 = 1;
const LINUX_AT_FDCWD: i32 = -100;
const LINUX_AT_EACCESS: u64 = 0x200;
const LINUX_AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
const LINUX_AT_STATX_FORCE_SYNC: u64 = 0x2000;
const LINUX_AT_STATX_DONT_SYNC: u64 = 0x4000;
const LINUX_F_OK: u64 = 0;
const LINUX_X_OK: u64 = 1;
const LINUX_W_OK: u64 = 2;
const LINUX_R_OK: u64 = 4;
const LINUX_SEEK_SET: i32 = 0;
const LINUX_SEEK_CUR: i32 = 1;
const LINUX_SEEK_END: i32 = 2;
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
const LINUX_CLONE_SETTLS: u64 = 0x0008_0000;
const LINUX_CLONE_THREAD: u64 = 0x0001_0000;
const LINUX_ARCH_SET_GS: u64 = 0x1001;
const LINUX_ARCH_SET_FS: u64 = 0x1002;
const LINUX_ARCH_GET_FS: u64 = 0x1003;
const LINUX_ARCH_GET_GS: u64 = 0x1004;
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
const LINUX_F_DUPFD: i32 = 0;
const LINUX_F_GETFD: i32 = 1;
const LINUX_F_SETFD: i32 = 2;
const LINUX_F_GETFL: i32 = 3;
const LINUX_F_SETFL: i32 = 4;
const LINUX_F_DUPFD_CLOEXEC: i32 = 1030;
const LINUX_FD_CLOEXEC: u64 = 1;
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
const LINUX_GRND_NONBLOCK: u64 = 0x1;
const LINUX_EPOLL_EVENT_BYTES: usize = 12;
const LINUX_TIMESPEC_BYTES: usize = 16;
const LINUX_ITIMERSPEC_BYTES: usize = 32;
const LINUX_RLIMIT_BYTES: usize = 16;
const LINUX_UTSNAME_FIELD_BYTES: usize = 65;
const LINUX_UTSNAME_BYTES: usize = LINUX_UTSNAME_FIELD_BYTES * 6;
const LINUX_STATX_BYTES: usize = 256;
const LINUX_DT_UNKNOWN: u8 = 0;
const LINUX_DT_DIR: u8 = 4;
const LINUX_DT_REG: u8 = 8;
const LINUX_DT_LNK: u8 = 10;
const LINUX_DT_SOCK: u8 = 12;
const LINUX_S_IFIFO: u32 = 0o010000;
const LINUX_S_IFDIR: u32 = 0o040000;
const LINUX_S_IFREG: u32 = 0o100000;
const LINUX_S_IFSOCK: u32 = 0o140000;
const LINUX_STATX_BASIC_STATS: u32 = 0x0000_07ff;
const LINUX_STATX_MNT_ID: u32 = 0x0000_1000;
const LINUX_STAT_STRUCT_BYTES: usize = 144;
const LINUX_MSGHDR_BYTES: usize = 56;
const LINUX_IOVEC_BYTES: usize = 16;
const LINUX_CMSGHDR_BYTES: usize = 16;
const LINUX_IOV_MAX: usize = 1024;
const LINUX_PATH_MAX: usize = 4096;
const LINUX_EINTR: i32 = 4;
const LINUX_EIO: i32 = 5;
const LINUX_ENOEXEC: i32 = 8;
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
const LINUX_ESPIPE: i32 = 29;
const LINUX_ENOMEM: i32 = 12;
const LINUX_EPIPE: i32 = 32;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENODEV: i32 = 19;
const LINUX_ECHILD: i32 = 10;
const LINUX_ENOTSOCK: i32 = 88;
const LINUX_ERANGE: i32 = 34;
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
const LINUX_RLIMIT_STACK: i32 = 3;
const LINUX_RLIMIT_NOFILE: i32 = 7;
const LINUX_BOOTSTRAP_STACK_LIMIT: u64 = 8 * 1024 * 1024;
const LINUX_BOOTSTRAP_NOFILE_LIMIT: u64 = 1024;
const EVENTFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
const EVENTFD_WRITABLE_SIGNAL: u32 = AX_USER_SIGNAL_1;
const EVENTFD_SIGNAL_MASK: u32 = EVENTFD_READABLE_SIGNAL | EVENTFD_WRITABLE_SIGNAL;
const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;
const SIGNALFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
const PIDFD_READABLE_SIGNAL: u32 = AX_USER_SIGNAL_0;
const AT_NULL: u64 = 0;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;
const AT_PHDR: u64 = 3;
const AT_BASE: u64 = 7;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LE: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const X64_TLS_TCB_BYTES: u64 = 0x80;
const X64_TLS_DTV_PREFIX_WORDS: u64 = 2;
const X64_TLS_DTV_HEADER_WORDS: u64 = 2;
const X64_TLS_DTV_WORDS_PER_MODULE: u64 = 2;
const X64_TLS_DTV_MIN_MODULE_SLOTS: u64 = 4;
const LINUX_AUX_PLATFORM: &[u8] = b"x86_64";
const LINUX_AUX_CLKTCK: u64 = 100;
const LINUX_AUX_HWCAP: u64 = 0;
const LINUX_AUX_HWCAP2: u64 = 0;
pub(crate) fn starnix_kernel_program_start(bootstrap_channel: zx_handle_t) -> ! {
    bootstrap::program_start(bootstrap_channel)
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

fn seed_runtime_random_state(
    parent_process: zx_handle_t,
    port: zx_handle_t,
    root_tgid: i32,
) -> u64 {
    let seed = parent_process
        ^ port.rotate_left(17)
        ^ (root_tgid as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ USER_CODE_VA;
    if seed == 0 {
        0x7f4a_7c15_d1ce_beef
    } else {
        seed
    }
}

fn next_random_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn fill_random_bytes(state: &mut u64, bytes: &mut [u8]) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let chunk = next_random_u64(state).to_ne_bytes();
        let actual = (bytes.len() - offset).min(chunk.len());
        bytes[offset..offset + actual].copy_from_slice(&chunk[..actual]);
        offset += actual;
    }
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
        ZX_ERR_INVALID_ARGS => LINUX_EINVAL,
        ZX_ERR_OUT_OF_RANGE => LINUX_EFAULT,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        ZX_ERR_NOT_SUPPORTED => LINUX_ENOSYS,
        _ => LINUX_EIO,
    }
}

fn map_exec_prepare_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_INVALID_ARGS | ZX_ERR_IO_DATA_INTEGRITY | ZX_ERR_NOT_SUPPORTED => LINUX_ENOEXEC,
        ZX_ERR_OUT_OF_RANGE | ZX_ERR_NO_MEMORY | ZX_ERR_INTERNAL => LINUX_ENOMEM,
        _ => LINUX_EIO,
    }
}

fn map_exec_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_INVALID_ARGS | ZX_ERR_IO_DATA_INTEGRITY | ZX_ERR_NOT_SUPPORTED => LINUX_ENOEXEC,
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

fn map_seek_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EINVAL,
        ZX_ERR_NOT_SUPPORTED => LINUX_ESPIPE,
        _ => LINUX_EINVAL,
    }
}

fn map_rw_at_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_BAD_HANDLE | ZX_ERR_ACCESS_DENIED => LINUX_EBADF,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EINVAL,
        ZX_ERR_NOT_SUPPORTED => LINUX_ESPIPE,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        _ => LINUX_EINVAL,
    }
}

fn map_readlink_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_NOT_SUPPORTED | ZX_ERR_INVALID_ARGS => LINUX_EINVAL,
        ZX_ERR_OUT_OF_RANGE => LINUX_EFAULT,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
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
#[allow(clippy::items_after_test_module)]
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
        LinuxMm::empty_for_tests()
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

        let resources = ProcessResources {
            process_handle: ZX_HANDLE_INVALID,
            fs: FsContext {
                fd_table,
                namespace: ProcessNamespace::new(NamespaceTrie::new()),
                directory_offsets: BTreeMap::new(),
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
    }

    fn insert_test_child(kernel: &mut StarnixKernel, task_state: TaskState, pgid: i32) {
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
