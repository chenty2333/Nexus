mod fs;
mod mm;
mod poll;
mod signal;
mod substrate;
mod sys;
mod task;

use self::fs::anon_inode::{
    EventFd, LinuxItimerSpec, PidFd, PidFdState, SignalFd, SignalFdState, TimerFd,
};
use self::fs::procfs::{pread_from_ops, pwrite_to_ops, stat_metadata_for_ops};
use self::fs::unix::{
    encode_scm_rights_control, parse_scm_rights, read_guest_iovec_payload, read_guest_iovecs,
    read_guest_msghdr, scm_rights_control_bytes, total_iovec_len, write_guest_iovec_payload,
    write_guest_recv_msghdr,
};
use self::mm::exec::{
    build_task_image, open_exec_image_from_namespace, read_exec_image_bytes_from_namespace,
    read_guest_string_array,
};
use self::mm::mmap::{LinuxMm, LinuxWritableRange};
use self::poll::epoll::EpollInstance;
use self::poll::readiness::filter_wait_interest;
use self::signal::action::{
    read_guest_sigaction, read_guest_signal_mask, write_guest_sigaction, write_guest_signal_mask,
};
use self::substrate::guest::{
    copy_guest_region, create_thread_carrier, linux_guest_initial_regs, prepare_process_carrier,
    read_guest_bytes, read_guest_c_string, read_guest_i64, read_guest_u32, read_guest_u64,
    start_prepared_carrier_guest, write_guest_bytes, write_guest_u32, write_guest_u64,
};
use self::substrate::restart::complete_syscall;

#[cfg(test)]
use self::fs::procfs::ProcFdDirFd;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

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
    ZX_VM_COMPACT, ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_SPECIFIC,
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
use nexus_component::{ComponentStartInfo, NumberedHandle};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFileDescription, OpenFlags,
    PipeFd, PseudoNodeFd, SeekOrigin, SocketFd, WaitSpec,
};
use spin::Mutex;

use crate::lifecycle::{read_channel_alloc_blocking, send_controller_event, send_status_event};
use crate::services::{
    BootAssetEntry, BootstrapNamespace, LocalFdMetadataKind, local_fd_metadata, local_fd_pread,
    local_fd_pwrite,
};
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

#[derive(Clone, Copy)]
struct LinuxTlsSegment {
    file_offset: usize,
    file_size: usize,
    mem_size: u64,
    align: u64,
}

struct LinuxElf<'a> {
    entry: u64,
    phdr_vaddr: Option<u64>,
    phent: u16,
    phnum: u16,
    image_end: u64,
    interp_path: Option<String>,
    tls: Option<LinuxTlsSegment>,
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

#[derive(Clone)]
struct TaskImage {
    path: String,
    cmdline: Vec<u8>,
    exec_blob: Vec<u8>,
    initial_tls_modules: Vec<LinuxInitialTls>,
    runtime_random: [u8; 16],
    writable_ranges: Vec<LinuxWritableRange>,
}

#[derive(Clone)]
struct LinuxInitialTls {
    init_image: Vec<u8>,
    mem_size: u64,
    align: u64,
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
struct LinuxFutexWaiter {
    task_id: i32,
    bitset: u32,
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
    clear_child_tid: u64,
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
    random_state: u64,
    root_tgid: i32,
    tasks: BTreeMap<i32, LinuxTask>,
    groups: BTreeMap<i32, LinuxThreadGroup>,
    foreground_pgid_by_sid: BTreeMap<i32, i32>,
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

impl StarnixKernel {
    fn new(
        parent_process: zx_handle_t,
        port: zx_handle_t,
        root_task: LinuxTask,
        root_group: LinuxThreadGroup,
    ) -> Self {
        let root_tgid = root_group.tgid;
        let root_sid = root_group.sid;
        let root_pgid = root_group.pgid;
        let mut tasks = BTreeMap::new();
        tasks.insert(root_task.tid, root_task);
        let mut groups = BTreeMap::new();
        groups.insert(root_group.tgid, root_group);
        let mut foreground_pgid_by_sid = BTreeMap::new();
        foreground_pgid_by_sid.insert(root_sid, root_pgid);
        Self {
            parent_process,
            port,
            next_tid: root_tgid + 1,
            next_packet_key: STARNIX_GUEST_PACKET_KEY_BASE + 1,
            random_state: seed_runtime_random_state(parent_process, port, root_tgid),
            root_tgid,
            tasks,
            groups,
            foreground_pgid_by_sid,
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

    fn foreground_pgid(&self, sid: i32) -> Option<i32> {
        self.foreground_pgid_by_sid.get(&sid).copied()
    }

    fn refresh_session_foreground_pgid(&mut self, sid: i32) {
        let current = self.foreground_pgid_by_sid.get(&sid).copied();
        if current.is_some_and(|pgid| self.session_has_pgid(sid, pgid)) {
            return;
        }
        let replacement = self
            .groups
            .values()
            .find(|group| group.sid == sid)
            .map(|group| group.pgid);
        match replacement {
            Some(pgid) => {
                self.foreground_pgid_by_sid.insert(sid, pgid);
            }
            None => {
                let _ = self.foreground_pgid_by_sid.remove(&sid);
            }
        }
    }

    fn tty_job_control_signal(
        &self,
        task_id: i32,
        fd: i32,
        op: FdWaitOp,
    ) -> Result<Option<i32>, zx_status_t> {
        let signal = match (fd, op) {
            (0, FdWaitOp::Read) => LINUX_SIGTTIN,
            (1 | 2, FdWaitOp::Write) => LINUX_SIGTTOU,
            _ => return Ok(None),
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(foreground_pgid) = self.foreground_pgid(group.sid) else {
            return Ok(None);
        };
        if foreground_pgid == group.pgid {
            Ok(None)
        } else {
            Ok(Some(signal))
        }
    }

    fn maybe_apply_tty_job_control(
        &mut self,
        task_id: i32,
        fd: i32,
        op: FdWaitOp,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<Option<SyscallAction>, zx_status_t> {
        let Some(signal) = self.tty_job_control_signal(task_id, fd, op)? else {
            return Ok(None);
        };
        match self.signal_delivery_action(task_id, signal)? {
            SignalDeliveryAction::Ignore => Ok(None),
            SignalDeliveryAction::Terminate => Ok(Some(SyscallAction::GroupSignalExit(signal))),
            SignalDeliveryAction::Stop => {
                let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
                self.enter_group_stop(tgid, signal)?;
                Ok(Some(SyscallAction::LeaveStopped))
            }
            SignalDeliveryAction::Catch(sigaction) => {
                let restore_regs = stop_state.regs;
                let previous_blocked = self.task_signal_mask(task_id)?;
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
                Ok(Some(SyscallAction::Resume))
            }
        }
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

    fn handle_syscall(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        match stop_state.regs.rax {
            LINUX_SYSCALL_READ => self.sys_read(task_id, stop_state),
            LINUX_SYSCALL_WRITE => self.sys_write(task_id, stop_state, stdout),
            LINUX_SYSCALL_READV => self.sys_readv(task_id, stop_state),
            LINUX_SYSCALL_WRITEV => self.sys_writev(task_id, stop_state, stdout),
            LINUX_SYSCALL_SENDMSG => self.sys_sendmsg(task_id, stop_state),
            LINUX_SYSCALL_RECVMSG => self.sys_recvmsg(task_id, stop_state),
            LINUX_SYSCALL_LSEEK => self.sys_lseek(task_id, stop_state),
            LINUX_SYSCALL_PREAD64 => self.sys_pread64(task_id, stop_state),
            LINUX_SYSCALL_PWRITE64 => self.sys_pwrite64(task_id, stop_state),
            LINUX_SYSCALL_GETPID => self.sys_getpid(task_id, stop_state),
            LINUX_SYSCALL_GETTID => self.sys_gettid(task_id, stop_state),
            LINUX_SYSCALL_GETPPID => self.sys_getppid(task_id, stop_state),
            LINUX_SYSCALL_GETUID => self.sys_getuid(stop_state),
            LINUX_SYSCALL_GETGID => self.sys_getgid(stop_state),
            LINUX_SYSCALL_GETEUID => self.sys_geteuid(stop_state),
            LINUX_SYSCALL_GETEGID => self.sys_getegid(stop_state),
            LINUX_SYSCALL_ARCH_PRCTL => self.sys_arch_prctl(task_id, stop_state),
            LINUX_SYSCALL_SET_TID_ADDRESS => self.sys_set_tid_address(task_id, stop_state),
            LINUX_SYSCALL_GETPGRP => self.sys_getpgrp(task_id, stop_state),
            LINUX_SYSCALL_GETPGID => self.sys_getpgid(task_id, stop_state),
            LINUX_SYSCALL_GETSID => self.sys_getsid(task_id, stop_state),
            LINUX_SYSCALL_SETPGID => self.sys_setpgid(task_id, stop_state),
            LINUX_SYSCALL_SETSID => self.sys_setsid(task_id, stop_state),
            LINUX_SYSCALL_UNAME => self.sys_uname(task_id, stop_state),
            LINUX_SYSCALL_GETRANDOM => self.sys_getrandom(task_id, stop_state),
            LINUX_SYSCALL_READLINK => self.sys_readlink(task_id, stop_state),
            LINUX_SYSCALL_READLINKAT => self.sys_readlinkat(task_id, stop_state),
            LINUX_SYSCALL_ACCESS => self.sys_access(task_id, stop_state),
            LINUX_SYSCALL_FACCESSAT => self.sys_faccessat(task_id, stop_state),
            LINUX_SYSCALL_FACCESSAT2 => self.sys_faccessat2(task_id, stop_state),
            LINUX_SYSCALL_STATX => self.sys_statx(task_id, stop_state),
            LINUX_SYSCALL_PRLIMIT64 => self.sys_prlimit64(task_id, stop_state),
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
        let sid = self.groups.get(&tgid).map(|group| group.sid);
        let parent_tgid = self.groups.get(&tgid).and_then(|group| group.parent_tgid);
        if let Some(parent_tgid) = parent_tgid
            && let Some(parent) = self.groups.get_mut(&parent_tgid)
        {
            parent.child_tgids.remove(&tgid);
        }
        let _ = self.groups.remove(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        if let Some(sid) = sid {
            self.refresh_session_foreground_pgid(sid);
        }
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
            self.process_clear_child_tid_on_exit(*member_id);
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
        self.process_clear_child_tid_on_exit(task_id);
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

    fn process_clear_child_tid_on_exit(&mut self, task_id: i32) {
        let Some((tgid, session, clear_child_tid)) = self.tasks.get(&task_id).and_then(|task| {
            (task.clear_child_tid != 0).then_some((
                task.tgid,
                task.carrier.session_handle,
                task.clear_child_tid,
            ))
        }) else {
            return;
        };
        if write_guest_u32(session, clear_child_tid, 0).is_err() {
            return;
        }
        let key = Self::private_futex_key_for_tgid(tgid, clear_child_tid);
        let _ = self.wake_futex_waiters(key, 1, LINUX_FUTEX_BITSET_MATCH_ANY);
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

        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Read, stop_state)?
        {
            return Ok(action);
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
        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Write, stop_state)?
        {
            return Ok(action);
        }
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

    fn sys_readv(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let iov_addr = stop_state.regs.rsi;
        let iov_len = linux_arg_i32(stop_state.regs.rdx);
        let iovecs = match self.read_sys_iovecs(task_id, iov_addr, iov_len, stop_state)? {
            Some(iovecs) => iovecs,
            None => return Ok(SyscallAction::Resume),
        };
        let total_len = total_iovec_len(&iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if total_len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }

        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let wait_policy = self.fd_wait_policy_for_op(task_id, fd, FdWaitOp::Read)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total_len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(total_len, 0);
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
                let result = match write_guest_iovec_payload(session, &iovecs, &bytes[..actual]) {
                    Ok(wrote) => u64::try_from(wrote).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
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
                        buf: iov_addr,
                        len: usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?,
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

    fn sys_writev(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
        stdout: &mut Vec<u8>,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let iov_addr = stop_state.regs.rsi;
        let iov_len = linux_arg_i32(stop_state.regs.rdx);
        let iovecs = match self.read_sys_iovecs(task_id, iov_addr, iov_len, stop_state)? {
            Some(iovecs) => iovecs,
            None => return Ok(SyscallAction::Resume),
        };
        let bytes = match read_guest_iovec_payload(
            self.tasks
                .get(&task_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .carrier
                .session_handle,
            &iovecs,
        ) {
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
        if let Some(action) =
            self.maybe_apply_tty_job_control(task_id, fd, FdWaitOp::Write, stop_state)?
        {
            return Ok(action);
        }
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
                        buf: iov_addr,
                        len: usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?,
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

    fn sys_getpid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        complete_syscall(stop_state, tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getppid(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let parent_tgid = self
            .groups
            .get(&tgid)
            .ok_or(ZX_ERR_BAD_STATE)?
            .parent_tgid
            .unwrap_or(0);
        complete_syscall(stop_state, parent_tgid as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getuid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getgid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_geteuid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getegid(
        &mut self,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        complete_syscall(stop_state, 0)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_lseek(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let offset = i64::from_ne_bytes(stop_state.regs.rsi.to_ne_bytes());
        let whence = linux_arg_i32(stop_state.regs.rdx);
        let origin = match whence {
            LINUX_SEEK_SET => SeekOrigin::Start,
            LINUX_SEEK_CUR => SeekOrigin::Current,
            LINUX_SEEK_END => SeekOrigin::End,
            _ => {
                complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let result = {
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.fd_table.seek(fd, origin, offset) {
                Ok(new_offset) => new_offset,
                Err(status) => linux_errno(map_seek_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_pread64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf_addr = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let offset = i64::from_ne_bytes(stop_state.regs.r10.to_ne_bytes());
        if offset < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        buffer.resize(len, 0);
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.pread(fd, offset as u64, &mut buffer) {
                Ok(actual) => match write_guest_bytes(session, buf_addr, &buffer[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                },
                Err(status) => linux_errno(map_rw_at_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_pwrite64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let fd = linux_arg_i32(stop_state.regs.rdi);
        let buf_addr = stop_state.regs.rsi;
        let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let offset = i64::from_ne_bytes(stop_state.regs.r10.to_ne_bytes());
        if offset < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let bytes = match read_guest_bytes(session, buf_addr, len) {
            Ok(bytes) => bytes,
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            match resources.pwrite(fd, offset as u64, &bytes) {
                Ok(actual) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                Err(status) => linux_errno(map_rw_at_status_to_errno(status)),
            }
        };
        complete_syscall(stop_state, result)?;
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

    fn sys_arch_prctl(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let code = stop_state.regs.rdi;
        let addr = stop_state.regs.rsi;
        let thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;

        let result = match code {
            LINUX_ARCH_SET_FS => {
                match zx_status_result(ax_thread_set_guest_x64_fs_base(thread_handle, addr, 0)) {
                    Ok(()) => 0,
                    Err(status) => linux_errno(map_guest_start_status_to_errno(status)),
                }
            }
            LINUX_ARCH_GET_FS => {
                let mut fs_base = 0u64;
                match zx_status_result(ax_thread_get_guest_x64_fs_base(
                    thread_handle,
                    0,
                    &mut fs_base,
                )) {
                    Ok(()) => match write_guest_u64(session, addr, fs_base) {
                        Ok(()) => 0,
                        Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                    },
                    Err(status) => linux_errno(map_guest_start_status_to_errno(status)),
                }
            }
            LINUX_ARCH_SET_GS | LINUX_ARCH_GET_GS => linux_errno(LINUX_EINVAL),
            _ => linux_errno(LINUX_EINVAL),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_set_tid_address(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let clear_child_tid = stop_state.regs.rdi;
        self.tasks
            .get_mut(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .clear_child_tid = clear_child_tid;
        complete_syscall(stop_state, task_id as u64)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_readlink(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let path_addr = stop_state.regs.rdi;
        let buf_addr = stop_state.regs.rsi;
        let buf_len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        self.sys_readlink_common(
            task_id,
            LINUX_AT_FDCWD,
            path_addr,
            buf_addr,
            buf_len,
            stop_state,
        )
    }

    fn sys_readlinkat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let buf_addr = stop_state.regs.rdx;
        let buf_len = usize::try_from(stop_state.regs.r10).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        self.sys_readlink_common(task_id, dirfd, path_addr, buf_addr, buf_len, stop_state)
    }

    fn sys_readlink_common(
        &mut self,
        task_id: i32,
        dirfd: i32,
        path_addr: u64,
        buf_addr: u64,
        buf_len: usize,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        if buf_len == 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
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
        let result = match self.resolve_readlink_target(task_id, dirfd, path.as_str()) {
            Ok(target) => {
                let bytes = target.as_bytes();
                let actual = bytes.len().min(buf_len);
                match write_guest_bytes(session, buf_addr, &bytes[..actual]) {
                    Ok(()) => u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                    Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
                }
            }
            Err(status) => linux_errno(map_readlink_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_access(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let mode = stop_state.regs.rsi;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let path = read_guest_c_string(session, stop_state.regs.rdi, LINUX_PATH_MAX).ok();
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            let _ = path;
            resources.accessat(session, LINUX_AT_FDCWD, stop_state.regs.rdi, mode, 0)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_faccessat(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let mode = stop_state.regs.rdx;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.accessat(session, dirfd, stop_state.regs.rsi, mode, 0)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_faccessat2(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let mode = stop_state.regs.rdx;
        let flags = stop_state.regs.r10;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.accessat(session, dirfd, stop_state.regs.rsi, mode, flags)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn lookup_stat_metadata(
        &self,
        task_id: i32,
        dirfd: i32,
        path: &str,
        flags: u64,
    ) -> Result<LinuxStatMetadata, zx_status_t> {
        let allowed = LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
        let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
        let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
        if path.is_empty() {
            if (flags & LINUX_AT_EMPTY_PATH) == 0 {
                return Err(ZX_ERR_NOT_FOUND);
            }
            return resources.stat_metadata_for_fd(dirfd);
        }
        if path.starts_with("/proc") {
            let ops = self.open_proc_absolute(task_id, path)?;
            return stat_metadata_for_ops(ops.as_ref());
        }
        resources.stat_metadata_at_path(dirfd, path, flags)
    }

    fn sys_statx(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let dirfd = linux_arg_i32(stop_state.regs.rdi);
        let path_addr = stop_state.regs.rsi;
        let flags = stop_state.regs.rdx;
        let mask = linux_arg_u32(stop_state.regs.r10);
        let statx_addr = stop_state.regs.r8;
        let allowed_flags = LINUX_AT_EMPTY_PATH
            | LINUX_AT_SYMLINK_NOFOLLOW
            | LINUX_AT_STATX_FORCE_SYNC
            | LINUX_AT_STATX_DONT_SYNC;
        if (flags & !allowed_flags) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
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
        let path_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let result = match self.lookup_stat_metadata(task_id, dirfd, path.as_str(), path_flags) {
            Ok(metadata) => write_guest_statx(session, statx_addr, metadata, None, mask)?,
            Err(status) => linux_errno(map_fd_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_prlimit64(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let pid = linux_arg_i32(stop_state.regs.rdi);
        let resource = linux_arg_i32(stop_state.regs.rsi);
        let new_limit_addr = stop_state.regs.rdx;
        let old_limit_addr = stop_state.regs.r10;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let result = {
            let tgid = self.tasks.get(&task_id).ok_or(ZX_ERR_BAD_STATE)?.tgid;
            let group = self.groups.get(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            let resources = group.resources.as_ref().ok_or(ZX_ERR_BAD_STATE)?;
            resources.prlimit64(session, tgid, pid, resource, new_limit_addr, old_limit_addr)?
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_uname(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let addr = stop_state.regs.rdi;
        let bytes = build_linux_uname_bytes();
        let result = match write_guest_bytes(session, addr, &bytes) {
            Ok(()) => 0,
            Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
        Ok(SyscallAction::Resume)
    }

    fn sys_getrandom(
        &mut self,
        task_id: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<SyscallAction, zx_status_t> {
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        let buf_addr = stop_state.regs.rdi;
        let len = usize::try_from(stop_state.regs.rsi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let flags = stop_state.regs.rdx;
        if (flags & !LINUX_GRND_NONBLOCK) != 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(SyscallAction::Resume);
        }
        if len == 0 {
            complete_syscall(stop_state, 0)?;
            return Ok(SyscallAction::Resume);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.resize(len, 0);
        fill_random_bytes(&mut self.random_state, &mut bytes);
        let result = match write_guest_bytes(session, buf_addr, &bytes) {
            Ok(()) => u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            Err(status) => linux_errno(map_guest_write_status_to_errno(status)),
        };
        complete_syscall(stop_state, result)?;
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
            } else if matches!(target_group.state, ThreadGroupState::Zombie { .. })
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
                self.refresh_session_foreground_pgid(caller_sid);
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
        let result = {
            let group = self.groups.get_mut(&tgid).ok_or(ZX_ERR_BAD_STATE)?;
            if group.pgid == tgid {
                linux_errno(LINUX_EPERM)
            } else {
                group.sid = tgid;
                group.pgid = tgid;
                tgid as u64
            }
        };
        if result == tgid as u64 {
            self.foreground_pgid_by_sid.insert(tgid, tgid);
        }
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

    fn read_sys_iovecs(
        &self,
        task_id: i32,
        iov_addr: u64,
        iov_len: i32,
        stop_state: &mut ax_guest_stop_state_t,
    ) -> Result<Option<Vec<LinuxIovec>>, zx_status_t> {
        if iov_len < 0 {
            complete_syscall(stop_state, linux_errno(LINUX_EINVAL))?;
            return Ok(None);
        }
        let iov_len = usize::try_from(iov_len).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        let session = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .session_handle;
        match read_guest_iovecs(session, iov_addr, iov_len) {
            Ok(iovecs) => Ok(Some(iovecs)),
            Err(status) => {
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_memory_status_to_errno(status)),
                )?;
                Ok(None)
            }
        }
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
            | LINUX_CLONE_SETTLS
            | LINUX_CLONE_THREAD;
        let required = LINUX_CLONE_VM
            | LINUX_CLONE_FS
            | LINUX_CLONE_FILES
            | LINUX_CLONE_SIGHAND
            | LINUX_CLONE_THREAD;
        if (flags & required) != required
            || (flags & !(supported | 0xff)) != 0
            || exit_signal != 0
            || parent_tid_addr != 0
            || child_tid_addr != 0
            || ((flags & LINUX_CLONE_SETTLS) == 0 && tls != 0)
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
        let parent_thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
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
        let child_fs_base = if (flags & LINUX_CLONE_SETTLS) != 0 {
            tls
        } else {
            let mut inherited = 0u64;
            if let Err(status) = zx_status_result(ax_thread_get_guest_x64_fs_base(
                parent_thread_handle,
                0,
                &mut inherited,
            )) {
                child_carrier.close();
                complete_syscall(
                    stop_state,
                    linux_errno(map_guest_start_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
            inherited
        };
        if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
            child_carrier.thread_handle,
            child_fs_base,
            0,
        )) {
            child_carrier.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

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
                clear_child_tid: 0,
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
        let parent_thread_handle = self
            .tasks
            .get(&task_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .carrier
            .thread_handle;
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
        let mut inherited_fs_base = 0u64;
        if let Err(status) = zx_status_result(ax_thread_get_guest_x64_fs_base(
            parent_thread_handle,
            0,
            &mut inherited_fs_base,
        )) {
            let _ = zx_handle_close(image_vmo);
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

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
                    linux_errno(map_exec_prepare_status_to_errno(status)),
                )?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);
        if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
            prepared.carrier.thread_handle,
            inherited_fs_base,
            0,
        )) {
            prepared.close();
            complete_syscall(
                stop_state,
                linux_errno(map_guest_start_status_to_errno(status)),
            )?;
            return Ok(SyscallAction::Resume);
        }

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
                clear_child_tid: 0,
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
        let mut stack_random = [0u8; 16];
        fill_random_bytes(&mut self.random_state, &mut stack_random);
        let task_image = match build_task_image(
            &resolved_path,
            &args,
            &env,
            &image_bytes,
            stack_random,
            |interp_path| {
                let namespace = &self
                    .groups
                    .get(&tgid)
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .resources
                    .as_ref()
                    .ok_or(ZX_ERR_BAD_STATE)?
                    .namespace;
                read_exec_image_bytes_from_namespace(namespace, interp_path).map(|(_, bytes)| bytes)
            },
        ) {
            Ok(image) => image,
            Err(status) => {
                let _ = zx_handle_close(image_vmo);
                let errno = map_exec_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
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
                let errno = map_exec_prepare_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
                return Ok(SyscallAction::Resume);
            }
        };
        let _ = zx_handle_close(image_vmo);

        let mut new_resources = {
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
                    let errno = map_vm_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            }
        };
        if let Err(status) = new_resources.install_exec_writable_ranges(&task_image.writable_ranges)
        {
            prepared.close();
            let errno = map_vm_status_to_errno(status);
            complete_syscall(stop_state, linux_errno(errno))?;
            return Ok(SyscallAction::Resume);
        }
        match new_resources.install_initial_tls(prepared.carrier.session_handle, &task_image) {
            Ok(Some(fs_base)) => {
                if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
                    prepared.carrier.thread_handle,
                    fs_base,
                    0,
                )) {
                    prepared.close();
                    let errno = map_guest_start_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            }
            Ok(None) => {}
            Err(status) => {
                prepared.close();
                let errno = map_vm_status_to_errno(status);
                complete_syscall(stop_state, linux_errno(errno))?;
                return Ok(SyscallAction::Resume);
            }
        }
        let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
        let (new_resources, new_carrier) =
            match start_prepared_carrier_guest(prepared, &regs, new_resources) {
                Ok(started) => started,
                Err(status) => {
                    let errno = map_guest_start_status_to_errno(status);
                    complete_syscall(stop_state, linux_errno(errno))?;
                    return Ok(SyscallAction::Resume);
                }
            };

        let old_carrier = {
            let task = self.tasks.get_mut(&task_id).ok_or(ZX_ERR_BAD_STATE)?;
            let old_carrier = task.carrier;
            task.carrier = new_carrier;
            task.clear_child_tid = 0;
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
            let _ = path;
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
        let result = match self.lookup_stat_metadata(task_id, dirfd, path.as_str(), flags) {
            Ok(metadata) => write_guest_stat(session, stat_addr, metadata, None)?,
            Err(status) => linux_errno(map_fd_status_to_errno(status)),
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

struct ExecutiveBootstrapCleanup {
    parent_process: zx_handle_t,
    linux_image_vmo: zx_handle_t,
    port: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
}

impl ExecutiveBootstrapCleanup {
    const fn new(
        parent_process: zx_handle_t,
        linux_image_vmo: zx_handle_t,
        stdout_handle: Option<zx_handle_t>,
    ) -> Self {
        Self {
            parent_process,
            linux_image_vmo,
            port: ZX_HANDLE_INVALID,
            stdout_handle,
        }
    }
}

impl Drop for ExecutiveBootstrapCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.stdout_handle.take() {
            let _ = zx_handle_close(handle);
        }
        if self.port != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.port);
        }
        if self.linux_image_vmo != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.linux_image_vmo);
        }
        if self.parent_process != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.parent_process);
        }
    }
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
    let mut cleanup =
        ExecutiveBootstrapCleanup::new(parent_process, linux_image_vmo, stdout_handle);
    let namespace = match build_starnix_namespace() {
        Ok(namespace) => namespace,
        Err(status) => return map_status_to_return_code(status),
    };
    let (payload_path, payload_bytes) = match resolve_exec_payload_source(&namespace, &args) {
        Ok(payload) => payload,
        Err(status) => return map_status_to_return_code(status),
    };
    let mut port = ZX_HANDLE_INVALID;
    if zx_port_create(0, &mut port) != ZX_OK {
        return 1;
    }
    cleanup.port = port;
    let mut stack_random_state = seed_runtime_random_state(parent_process, port, 1);
    let mut stack_random = [0u8; 16];
    fill_random_bytes(&mut stack_random_state, &mut stack_random);
    let task_image = match build_task_image(
        payload_path.as_str(),
        &args,
        &env,
        payload_bytes.as_slice(),
        stack_random,
        |interp_path| {
            read_exec_image_bytes_from_namespace(&namespace, interp_path)
                .map(|(_resolved, bytes)| bytes)
        },
    ) {
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
        Err(status) => return map_status_to_return_code(status),
    };
    let _ = zx_handle_close(linux_image_vmo);
    cleanup.linux_image_vmo = ZX_HANDLE_INVALID;
    let stdout_handle = cleanup.stdout_handle.take();
    let mut resources = match ExecutiveState::new(
        prepared.process_handle,
        prepared.root_vmar,
        stdout_handle,
        namespace,
    ) {
        Ok(resources) => resources,
        Err(status) => {
            prepared.close();
            return map_status_to_return_code(status);
        }
    };
    if let Err(status) = resources.install_exec_writable_ranges(&task_image.writable_ranges) {
        prepared.close();
        return map_status_to_return_code(status);
    }
    match resources.install_initial_tls(prepared.carrier.session_handle, &task_image) {
        Ok(Some(fs_base)) => {
            if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
                prepared.carrier.thread_handle,
                fs_base,
                0,
            )) {
                prepared.close();
                return map_status_to_return_code(status);
            }
        }
        Ok(None) => {}
        Err(status) => {
            prepared.close();
            return map_status_to_return_code(status);
        }
    }
    let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
    let (resources, carrier) = match start_prepared_carrier_guest(prepared, &regs, resources) {
        Ok(started) => started,
        Err(status) => return map_status_to_return_code(status),
    };
    let root_task = LinuxTask {
        tid: 1,
        tgid: 1,
        carrier,
        state: TaskState::Running,
        signals: TaskSignals::default(),
        clear_child_tid: 0,
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
    kernel.run()
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
        LINUX_SYSCALL_DUP2 => {
            let oldfd = linux_arg_i32(stop_state.regs.rdi);
            let newfd = linux_arg_i32(stop_state.regs.rsi);
            let result = executive.dup2(oldfd, newfd)?;
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
        LINUX_SYSCALL_FCNTL => {
            let fd = linux_arg_i32(stop_state.regs.rdi);
            let cmd = linux_arg_i32(stop_state.regs.rsi);
            let arg = stop_state.regs.rdx;
            let result = executive.fcntl(fd, cmd, arg)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_GETCWD => {
            let buf = stop_state.regs.rdi;
            let size = usize::try_from(stop_state.regs.rsi).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let result = executive.getcwd(session, buf, size)?;
            complete_syscall(stop_state, result)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_CHDIR => {
            let path = stop_state.regs.rdi;
            let result = executive.chdir(session, path)?;
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
        LINUX_SYSCALL_DUP3 => {
            let oldfd = linux_arg_i32(stop_state.regs.rdi);
            let newfd = linux_arg_i32(stop_state.regs.rsi);
            let flags = stop_state.regs.rdx;
            let result = executive.dup3(oldfd, newfd, flags)?;
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

// Legacy embedded smoke payloads remain only as a bootstrap fallback while
// production exec is resolved from the startup namespace.
fn bootstrap_payload_bytes_for(args: &[String]) -> Option<&'static [u8]> {
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
        Some("linux-round6-proc-tty-smoke") => Some(LINUX_ROUND6_PROC_TTY_BYTES),
        Some("linux-runtime-fd-smoke") => Some(LINUX_RUNTIME_FD_BYTES),
        Some("linux-runtime-misc-smoke") => Some(LINUX_RUNTIME_MISC_BYTES),
        Some("linux-runtime-process-smoke") => Some(LINUX_RUNTIME_PROCESS_BYTES),
        Some("linux-runtime-fs-smoke") => Some(LINUX_RUNTIME_FS_BYTES),
        Some("linux-runtime-tls-smoke") => Some(LINUX_RUNTIME_TLS_BYTES),
        Some("linux-dynamic-elf-smoke") => Some(LINUX_DYNAMIC_ELF_SMOKE_BYTES),
        Some("linux-dynamic-tls-smoke") => Some(LINUX_DYNAMIC_TLS_SMOKE_BYTES),
        Some("linux-dynamic-runtime-smoke") => Some(LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES),
        Some("linux-dynamic-pie-smoke") => Some(LINUX_DYNAMIC_PIE_SMOKE_BYTES),
        Some("linux-glibc-hello") => Some(LINUX_GLIBC_HELLO_BYTES),
        Some(_) => None,
    }
}

fn bootstrap_payload_path_for(args: &[String]) -> Option<&'static str> {
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
        Some("linux-round6-proc-tty-smoke") => Some(LINUX_ROUND6_PROC_TTY_BINARY_PATH),
        Some("linux-runtime-fd-smoke") => Some(LINUX_RUNTIME_FD_BINARY_PATH),
        Some("linux-runtime-misc-smoke") => Some(LINUX_RUNTIME_MISC_BINARY_PATH),
        Some("linux-runtime-process-smoke") => Some(LINUX_RUNTIME_PROCESS_BINARY_PATH),
        Some("linux-runtime-fs-smoke") => Some(LINUX_RUNTIME_FS_BINARY_PATH),
        Some("linux-runtime-tls-smoke") => Some(LINUX_RUNTIME_TLS_BINARY_PATH),
        Some("linux-dynamic-elf-smoke") => Some(LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH),
        Some("linux-dynamic-tls-smoke") => Some(LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH),
        Some("linux-dynamic-runtime-smoke") => Some(LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH),
        Some("linux-dynamic-pie-smoke") => Some(LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH),
        Some("linux-glibc-hello") => Some(LINUX_GLIBC_HELLO_BINARY_PATH),
        Some(_) => None,
    }
}

fn requested_exec_path(args: &[String]) -> Option<String> {
    match args.first().map(String::as_str) {
        Some("") => None,
        Some(path) if path.contains('/') => Some(String::from(path)),
        Some(name) => Some(format!("bin/{name}")),
        None => None,
    }
}

fn resolve_exec_payload_source(
    namespace: &nexus_io::ProcessNamespace,
    args: &[String],
) -> Result<(String, Vec<u8>), zx_status_t> {
    if let Some(path) = requested_exec_path(args) {
        match read_exec_image_bytes_from_namespace(namespace, path.as_str()) {
            Ok(source) => return Ok(source),
            Err(ZX_ERR_NOT_FOUND | ZX_ERR_NOT_DIR | ZX_ERR_BAD_PATH) => {}
            Err(status) => return Err(status),
        }
    }

    let path = bootstrap_payload_path_for(args).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let bytes = bootstrap_payload_bytes_for(args).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    owned.extend_from_slice(bytes);
    let stored_path = namespace
        .resolve_path(path)
        .unwrap_or_else(|_| String::from(path));
    Ok((stored_path, owned))
}

fn file_description_key(description: &Arc<OpenFileDescription>) -> LinuxFileDescriptionKey {
    LinuxFileDescriptionKey(Arc::as_ptr(description) as usize)
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
        namespace: nexus_io::ProcessNamespace,
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
            namespace,
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

    fn getcwd(
        &self,
        session: zx_handle_t,
        guest_addr: u64,
        size: usize,
    ) -> Result<u64, zx_status_t> {
        if size == 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let cwd = self.namespace.cwd();
        let needed = cwd.len().checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if needed > size {
            return Ok(linux_errno(LINUX_ERANGE));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(needed)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        bytes.extend_from_slice(cwd.as_bytes());
        bytes.push(0);
        match write_guest_bytes(session, guest_addr, &bytes) {
            Ok(()) => Ok(needed as u64),
            Err(status) => Ok(linux_errno(map_guest_write_status_to_errno(status))),
        }
    }

    fn chdir(&mut self, session: zx_handle_t, path_addr: u64) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        if path.is_empty() {
            return Ok(linux_errno(LINUX_ENOENT));
        }
        match self.namespace.set_cwd(path.as_str()) {
            Ok(()) => Ok(0),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    fn dup2(&mut self, oldfd: i32, newfd: i32) -> Result<u64, zx_status_t> {
        if oldfd == newfd {
            return if self.fd_table.get(oldfd).is_some() {
                Ok(newfd as u64)
            } else {
                Ok(linux_errno(LINUX_EBADF))
            };
        }
        if newfd < 0 {
            return Ok(linux_errno(LINUX_EBADF));
        }
        match self.fd_table.duplicate_to(oldfd, newfd, FdFlags::empty()) {
            Ok(fd) => Ok(fd as u64),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    fn dup3(&mut self, oldfd: i32, newfd: i32, flags: u64) -> Result<u64, zx_status_t> {
        if oldfd == newfd {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        if newfd < 0 {
            return Ok(linux_errno(LINUX_EBADF));
        }
        if flags & !LINUX_O_CLOEXEC != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let fd_flags = if (flags & LINUX_O_CLOEXEC) != 0 {
            FdFlags::CLOEXEC
        } else {
            FdFlags::empty()
        };
        match self.fd_table.duplicate_to(oldfd, newfd, fd_flags) {
            Ok(fd) => Ok(fd as u64),
            Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
        }
    }

    fn fcntl(&mut self, fd: i32, cmd: i32, arg: u64) -> Result<u64, zx_status_t> {
        match cmd {
            LINUX_F_GETFD => {
                let Some(entry) = self.fd_table.get(fd) else {
                    return Ok(linux_errno(LINUX_EBADF));
                };
                Ok(encode_linux_fd_flags(entry.flags()))
            }
            LINUX_F_SETFD => {
                let flags = FdFlags::from_bits_truncate(arg as u32);
                match self.fd_table.set_fd_flags(fd, flags) {
                    Ok(()) => Ok(0),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_GETFL => {
                let Some(entry) = self.fd_table.get(fd) else {
                    return Ok(linux_errno(LINUX_EBADF));
                };
                Ok(encode_linux_open_flags(entry.description().flags()))
            }
            LINUX_F_DUPFD => {
                let min_fd = linux_arg_i32(arg);
                if min_fd < 0 {
                    return Ok(linux_errno(LINUX_EINVAL));
                }
                match self
                    .fd_table
                    .duplicate_from_min(fd, min_fd, FdFlags::empty())
                {
                    Ok(new_fd) => Ok(new_fd as u64),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_DUPFD_CLOEXEC => {
                let min_fd = linux_arg_i32(arg);
                if min_fd < 0 {
                    return Ok(linux_errno(LINUX_EINVAL));
                }
                match self
                    .fd_table
                    .duplicate_from_min(fd, min_fd, FdFlags::CLOEXEC)
                {
                    Ok(new_fd) => Ok(new_fd as u64),
                    Err(status) => Ok(linux_errno(map_fd_status_to_errno(status))),
                }
            }
            LINUX_F_SETFL => Ok(linux_errno(LINUX_ENOSYS)),
            _ => Ok(linux_errno(LINUX_EINVAL)),
        }
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
        let metadata = match self.stat_metadata_for_fd(fd) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, Some(fd as u64))
    }

    fn pread(&self, fd: i32, offset: u64, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let entry = self.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !entry.description().flags().contains(OpenFlags::READABLE) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        pread_from_ops(entry.description().ops().as_ref(), offset, buffer)
    }

    fn pwrite(&self, fd: i32, offset: u64, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let entry = self.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        if !entry.description().flags().contains(OpenFlags::WRITABLE) {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        pwrite_to_ops(entry.description().ops().as_ref(), offset, buffer)
    }

    fn stat_metadata_for_fd(&self, fd: i32) -> Result<LinuxStatMetadata, zx_status_t> {
        let entry = self.fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        stat_metadata_for_ops(entry.description().ops().as_ref())
    }

    fn stat_metadata_at_path(
        &self,
        dirfd: i32,
        path: &str,
        flags: u64,
    ) -> Result<LinuxStatMetadata, zx_status_t> {
        let allowed = LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        if path.is_empty() {
            if (flags & LINUX_AT_EMPTY_PATH) == 0 {
                return Err(ZX_ERR_NOT_FOUND);
            }
            return self.stat_metadata_for_fd(dirfd);
        }
        let opened = if path.starts_with('/') || dirfd == LINUX_AT_FDCWD {
            self.namespace.open(path, OpenFlags::READABLE)
        } else {
            self.fd_table
                .get(dirfd)
                .ok_or(ZX_ERR_BAD_HANDLE)
                .and_then(|entry| {
                    entry
                        .description()
                        .ops()
                        .openat(path, OpenFlags::READABLE | OpenFlags::PATH)
                })
        };
        let ops = opened?;
        stat_metadata_for_ops(ops.as_ref())
    }

    fn statat(
        &self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        stat_addr: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        let stat_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let metadata = match self.stat_metadata_at_path(dirfd, path.as_str(), stat_flags) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        write_guest_stat(session, stat_addr, metadata, None)
    }

    fn accessat(
        &self,
        session: zx_handle_t,
        dirfd: i32,
        path_addr: u64,
        mode: u64,
        flags: u64,
    ) -> Result<u64, zx_status_t> {
        let allowed_mode = LINUX_R_OK | LINUX_W_OK | LINUX_X_OK;
        if mode & !allowed_mode != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let allowed_flags = LINUX_AT_EMPTY_PATH | LINUX_AT_EACCESS | LINUX_AT_SYMLINK_NOFOLLOW;
        if (flags & !allowed_flags) != 0 {
            return Ok(linux_errno(LINUX_EINVAL));
        }
        let path = match read_guest_c_string(session, path_addr, LINUX_PATH_MAX) {
            Ok(path) => path,
            Err(status) => return Ok(linux_errno(map_guest_memory_status_to_errno(status))),
        };
        let stat_flags = flags & (LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
        let metadata = match self.stat_metadata_at_path(dirfd, path.as_str(), stat_flags) {
            Ok(metadata) => metadata,
            Err(status) => return Ok(linux_errno(map_fd_status_to_errno(status))),
        };
        if mode == LINUX_F_OK {
            return Ok(0);
        }
        let permissions = metadata.mode & 0o777;
        if (mode & LINUX_R_OK) != 0 && (permissions & 0o444) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        if (mode & LINUX_W_OK) != 0 && (permissions & 0o222) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        if (mode & LINUX_X_OK) != 0 && (permissions & 0o111) == 0 {
            return Ok(linux_errno(LINUX_EACCES));
        }
        Ok(0)
    }

    fn prlimit64(
        &self,
        session: zx_handle_t,
        current_tgid: i32,
        pid: i32,
        resource: i32,
        new_limit_addr: u64,
        old_limit_addr: u64,
    ) -> Result<u64, zx_status_t> {
        if pid != 0 && pid != current_tgid {
            return Ok(linux_errno(LINUX_ESRCH));
        }
        if new_limit_addr != 0 {
            return Ok(linux_errno(LINUX_EPERM));
        }
        let (current, maximum) = match resource {
            LINUX_RLIMIT_STACK => (LINUX_BOOTSTRAP_STACK_LIMIT, LINUX_BOOTSTRAP_STACK_LIMIT),
            LINUX_RLIMIT_NOFILE => (LINUX_BOOTSTRAP_NOFILE_LIMIT, LINUX_BOOTSTRAP_NOFILE_LIMIT),
            _ => return Ok(linux_errno(LINUX_EINVAL)),
        };
        if old_limit_addr != 0
            && let Err(status) = write_guest_rlimit(session, old_limit_addr, current, maximum)
        {
            return Ok(linux_errno(map_guest_write_status_to_errno(status)));
        }
        Ok(0)
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
    if !LINUX_ROUND6_PROC_TTY_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_TTY_BINARY_PATH,
            LINUX_ROUND6_PROC_TTY_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_FD_BINARY_PATH,
            LINUX_RUNTIME_FD_BYTES,
        ));
    }
    if !LINUX_RUNTIME_MISC_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_MISC_BINARY_PATH,
            LINUX_RUNTIME_MISC_BYTES,
        ));
    }
    if !LINUX_RUNTIME_PROCESS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_PROCESS_BINARY_PATH,
            LINUX_RUNTIME_PROCESS_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_FS_BINARY_PATH,
            LINUX_RUNTIME_FS_BYTES,
        ));
    }
    if !LINUX_RUNTIME_TLS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_TLS_BINARY_PATH,
            LINUX_RUNTIME_TLS_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_ELF_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_ELF_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_TLS_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_TLS_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_TLS_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_TLS_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_PIE_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_PIE_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_PIE_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_PIE_INTERP_BYTES,
        ));
    }
    if !LINUX_GLIBC_HELLO_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_HELLO_BINARY_PATH,
            LINUX_GLIBC_HELLO_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
            LINUX_GLIBC_RUNTIME_LIBC_BYTES,
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
    if !LINUX_ROUND6_PROC_TTY_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-tty-smoke.nxcd",
            LINUX_ROUND6_PROC_TTY_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_MISC_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-misc-smoke.nxcd",
            LINUX_RUNTIME_MISC_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_PROCESS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-process-smoke.nxcd",
            LINUX_RUNTIME_PROCESS_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-fs-smoke.nxcd",
            LINUX_RUNTIME_FS_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_TLS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-tls-smoke.nxcd",
            LINUX_RUNTIME_TLS_DECL_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-runtime-smoke.nxcd",
            LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-pie-smoke.nxcd",
            LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_GLIBC_HELLO_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-glibc-hello.nxcd",
            LINUX_GLIBC_HELLO_DECL_BYTES,
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

fn linux_arg_i32(raw: u64) -> i32 {
    raw as u32 as i32
}

fn linux_arg_u32(raw: u64) -> u32 {
    raw as u32
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

fn encode_linux_fd_flags(flags: FdFlags) -> u64 {
    let mut bits = 0u64;
    if flags.contains(FdFlags::CLOEXEC) {
        bits |= LINUX_FD_CLOEXEC;
    }
    bits
}

fn encode_linux_open_flags(flags: OpenFlags) -> u64 {
    let mut bits = match (
        flags.contains(OpenFlags::READABLE),
        flags.contains(OpenFlags::WRITABLE),
    ) {
        (true, true) => LINUX_O_RDWR,
        (false, true) => LINUX_O_WRONLY,
        _ => 0,
    };
    if flags.contains(OpenFlags::APPEND) {
        bits |= LINUX_O_APPEND;
    }
    if flags.contains(OpenFlags::NONBLOCK) {
        bits |= LINUX_O_NONBLOCK;
    }
    if flags.contains(OpenFlags::DIRECTORY) {
        bits |= LINUX_O_DIRECTORY;
    }
    if flags.contains(OpenFlags::PATH) {
        bits |= LINUX_O_PATH;
    }
    bits
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

fn join_proc_relative_path(base: &str, path: &str) -> Result<String, zx_status_t> {
    let components = split_proc_path(path)?;
    if components.is_empty() {
        return Ok(String::from(base.trim_end_matches('/')));
    }
    let mut resolved = String::from(base.trim_end_matches('/'));
    for component in components {
        resolved.push('/');
        resolved.push_str(component);
    }
    Ok(resolved)
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

fn write_guest_rlimit(
    session: zx_handle_t,
    addr: u64,
    current: u64,
    maximum: u64,
) -> Result<(), zx_status_t> {
    let mut bytes = [0u8; LINUX_RLIMIT_BYTES];
    bytes[..8].copy_from_slice(&current.to_ne_bytes());
    bytes[8..].copy_from_slice(&maximum.to_ne_bytes());
    write_guest_bytes(session, addr, &bytes)
}

fn write_guest_statx(
    session: zx_handle_t,
    addr: u64,
    metadata: LinuxStatMetadata,
    ino_seed: Option<u64>,
    requested_mask: u32,
) -> Result<u64, zx_status_t> {
    let supported_mask = LINUX_STATX_BASIC_STATS | LINUX_STATX_MNT_ID;
    let mask = if requested_mask == 0 {
        supported_mask
    } else {
        supported_mask & requested_mask
    };
    let ino = ino_seed.unwrap_or(1);
    let mut bytes = [0u8; LINUX_STATX_BYTES];
    bytes[0..4].copy_from_slice(&mask.to_ne_bytes());
    bytes[4..8].copy_from_slice(&4096u32.to_ne_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_ne_bytes());
    bytes[20..24].copy_from_slice(&0u32.to_ne_bytes());
    bytes[24..28].copy_from_slice(&0u32.to_ne_bytes());
    bytes[28..30].copy_from_slice(&(metadata.mode as u16).to_ne_bytes());
    bytes[32..40].copy_from_slice(&ino.to_ne_bytes());
    bytes[40..48].copy_from_slice(&metadata.size_bytes.to_ne_bytes());
    bytes[48..56].copy_from_slice(&(metadata.size_bytes.div_ceil(512)).to_ne_bytes());
    bytes[144..152].copy_from_slice(&1u64.to_ne_bytes());
    match write_guest_bytes(session, addr, &bytes) {
        Ok(()) => Ok(0),
        Err(status) => Ok(linux_errno(map_guest_write_status_to_errno(status))),
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

fn write_linux_uname_field(field: &mut [u8], value: &str) {
    let limit = field.len().saturating_sub(1);
    let actual = value.len().min(limit);
    field[..actual].copy_from_slice(&value.as_bytes()[..actual]);
}

fn build_linux_uname_bytes() -> [u8; LINUX_UTSNAME_BYTES] {
    let mut bytes = [0u8; LINUX_UTSNAME_BYTES];
    write_linux_uname_field(&mut bytes[0..LINUX_UTSNAME_FIELD_BYTES], "NexusOS");
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES..LINUX_UTSNAME_FIELD_BYTES * 2],
        "nexus",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 2..LINUX_UTSNAME_FIELD_BYTES * 3],
        "0.1",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 3..LINUX_UTSNAME_FIELD_BYTES * 4],
        "#1 Axle",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 4..LINUX_UTSNAME_FIELD_BYTES * 5],
        "x86_64",
    );
    write_linux_uname_field(
        &mut bytes[LINUX_UTSNAME_FIELD_BYTES * 5..LINUX_UTSNAME_BYTES],
        "localdomain",
    );
    bytes
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
