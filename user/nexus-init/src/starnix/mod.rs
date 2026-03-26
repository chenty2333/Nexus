mod abi;
mod bootstrap;
mod fs;
mod mm;
mod net;
mod poll;
mod signal;
mod substrate;
mod sys;
mod task;

pub(in crate::starnix) use self::abi::*;
use self::fs::anon_inode::{EventFd, PidFd, PidFdState, SignalFd, SignalFdState, TimerFd};
use self::fs::fd::{LinuxStatMetadata, ProcessResources};
pub(in crate::starnix) use self::fs::fd::{
    decode_open_flags, write_guest_fd_pair, write_guest_stat, write_guest_statx,
};
use self::fs::procfs::{pread_from_ops, pwrite_to_ops, stat_metadata_for_ops};
use self::fs::tty::RemoteTtyBridge;
pub(in crate::starnix) use self::fs::unix::LinuxIovec;
use self::fs::unix::{
    encode_scm_rights_control, parse_scm_rights, read_guest_iovec_payload, read_guest_iovecs,
    read_guest_msghdr, scm_rights_control_bytes, total_iovec_len, write_guest_iovec_payload,
    write_guest_recv_msghdr,
};
use self::mm::context::{LinuxMm, LinuxWritableRange};
use self::mm::exec::{
    TaskImage, build_task_image, open_exec_image_from_namespace,
    read_exec_image_bytes_from_namespace, read_guest_string_array,
};
use self::net::{InetSocketFd, LoopbackNetStack, LoopbackSocketAddr};
use self::poll::epoll::EpollInstance;
use self::poll::readiness::filter_wait_interest;
use self::signal::action::{
    LinuxSigAction, read_guest_sigaction, read_guest_signal_mask, write_guest_sigaction,
    write_guest_signal_mask,
};
use self::signal::delivery::SignalDeliveryAction;
use self::substrate::guest::{
    create_thread_carrier, linux_guest_initial_regs, prepare_process_carrier, read_guest_bytes,
    read_guest_c_string, read_guest_i64, read_guest_u32, read_guest_u64,
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
    BlockedOpResume, FdReadKind, FdWaitOp, FdWaitPolicy, FdWriteKind, LinuxFileDescriptionKey,
    LinuxFutexKey, LinuxFutexWaiter, PendingScmRights, ReadAttempt, WaitKind, WaitState,
    WriteAttempt,
};

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use crate::services::{LocalFdMetadataKind, local_fd_metadata, local_fd_pread, local_fd_pwrite};
use crate::{
    STARTUP_HANDLE_COMPONENT_STATUS, STARTUP_HANDLE_STARNIX_IMAGE_VMO,
    STARTUP_HANDLE_STARNIX_PARENT_PROCESS, STARTUP_HANDLE_STARNIX_STDIN,
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
    AX_USER_SIGNAL_0, AX_USER_SIGNAL_1, AX_USER_SIGNAL_2, ZX_CHANNEL_PEER_CLOSED,
    ZX_CHANNEL_READABLE, ZX_CHANNEL_WRITABLE, ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE,
    ZX_SOCKET_WRITABLE, ZX_TIMER_SIGNALED,
};
use axle_types::socket::{ZX_SOCKET_DATAGRAM, ZX_SOCKET_STREAM};
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ADDRESS_IN_USE, ZX_ERR_ADDRESS_UNREACHABLE, ZX_ERR_ALREADY_BOUND,
    ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH, ZX_ERR_BAD_STATE,
    ZX_ERR_CONNECTION_ABORTED, ZX_ERR_CONNECTION_REFUSED, ZX_ERR_CONNECTION_RESET, ZX_ERR_INTERNAL,
    ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NO_MEMORY, ZX_ERR_NOT_CONNECTED,
    ZX_ERR_NOT_DIR, ZX_ERR_NOT_FILE, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE,
    ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_VMAR_CLONE_MAPPINGS, AXLE_SYS_AX_VMAR_GET_MAPPING_VMO, AXLE_SYS_VMAR_ALLOCATE,
    AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP,
};
use axle_types::vm::{
    ZX_VM_CAN_MAP_EXECUTE, ZX_VM_CAN_MAP_READ, ZX_VM_CAN_MAP_SPECIFIC, ZX_VM_CAN_MAP_WRITE,
    ZX_VM_CLONE_COW, ZX_VM_CLONE_SHARE, ZX_VM_COMPACT, ZX_VM_PERM_EXECUTE, ZX_VM_PERM_READ,
    ZX_VM_PERM_WRITE, ZX_VM_PRIVATE_CLONE, ZX_VM_SPECIFIC,
};
use axle_types::{
    ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_linux_exec_interp_header_t,
    ax_linux_exec_spec_header_t, zx_handle_t, zx_status_t,
};
use libax::{
    AX_TIME_INFINITE, ax_console_read, ax_console_write, ax_eventpair_create,
    ax_guest_session_create, ax_guest_session_read_memory, ax_guest_session_resume,
    ax_guest_session_write_memory, ax_guest_stop_state_read, ax_guest_stop_state_write,
    ax_handle_close as zx_handle_close, ax_handle_duplicate as zx_handle_duplicate,
    ax_linux_exec_spec_blob, ax_linux_exec_spec_blob_with_interp, ax_object_signal,
    ax_object_wait_async, ax_object_wait_one, ax_packet_user_t as zx_packet_user_t,
    ax_port_create as zx_port_create, ax_port_packet_t as zx_port_packet_t,
    ax_port_queue as zx_port_queue, ax_port_wait as zx_port_wait,
    ax_process_create as zx_process_create, ax_process_prepare_linux_exec, ax_process_start_guest,
    ax_socket_create as zx_socket_create, ax_status_result as zx_status_result,
    ax_task_kill as zx_task_kill, ax_thread_create as zx_thread_create,
    ax_thread_get_guest_x64_fs_base, ax_thread_set_guest_x64_fs_base, ax_thread_start_guest,
    ax_timer_cancel, ax_timer_create_monotonic, ax_timer_set, ax_vmo_create as zx_vmo_create,
};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFileDescription, OpenFlags,
    PipeFd, PseudoNodeFd, SeekOrigin, SocketFd, WaitSpec,
};
use spin::Mutex;

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
        ZX_ERR_ADDRESS_IN_USE | ZX_ERR_ALREADY_BOUND => LINUX_EADDRINUSE,
        ZX_ERR_ADDRESS_UNREACHABLE => LINUX_EADDRNOTAVAIL,
        ZX_ERR_ALREADY_EXISTS => LINUX_EEXIST,
        ZX_ERR_BAD_PATH | ZX_ERR_NOT_FOUND => LINUX_ENOENT,
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_IO_DATA_INTEGRITY => LINUX_EIO,
        ZX_ERR_NOT_DIR => LINUX_ENOTDIR,
        ZX_ERR_NOT_FILE => LINUX_EISDIR,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        ZX_ERR_NOT_CONNECTED => LINUX_ENOTCONN,
        ZX_ERR_CONNECTION_REFUSED => LINUX_ECONNREFUSED,
        ZX_ERR_CONNECTION_RESET => LINUX_ECONNRESET,
        ZX_ERR_CONNECTION_ABORTED => LINUX_ECONNABORTED,
        ZX_ERR_PEER_CLOSED => LINUX_EPIPE,
        ZX_ERR_SHOULD_WAIT => LINUX_EAGAIN,
        _ => LINUX_EBADF,
    }
}

fn map_ioctl_status_to_errno(status: zx_status_t) -> i32 {
    match status {
        ZX_ERR_BAD_HANDLE => LINUX_EBADF,
        ZX_ERR_NOT_SUPPORTED => LINUX_ENOTTY,
        ZX_ERR_ACCESS_DENIED => LINUX_EACCES,
        ZX_ERR_INVALID_ARGS | ZX_ERR_OUT_OF_RANGE => LINUX_EINVAL,
        ZX_ERR_NO_MEMORY => LINUX_ENOMEM,
        _ => LINUX_EIO,
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
mod tests;

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
    axle_arch_x86_64::native_syscall(
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
    axle_arch_x86_64::native_syscall8(
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
    axle_arch_x86_64::native_syscall(AXLE_SYS_VMAR_UNMAP as u64, [vmar, addr, len, 0, 0, 0])
}

fn zx_vmar_protect_local(vmar: zx_handle_t, options: u32, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::native_syscall(
        AXLE_SYS_VMAR_PROTECT as u64,
        [vmar, options as u64, addr, len, 0, 0],
    )
}

fn ax_vmar_clone_mappings_local(src_vmar: zx_handle_t, dst_vmar: zx_handle_t) -> zx_status_t {
    axle_arch_x86_64::native_syscall(
        AXLE_SYS_AX_VMAR_CLONE_MAPPINGS as u64,
        [src_vmar, dst_vmar, 0, 0, 0, 0],
    )
}

fn ax_vmar_get_mapping_vmo_local(
    vmar: zx_handle_t,
    addr: u64,
    out_vmo: &mut zx_handle_t,
) -> zx_status_t {
    axle_arch_x86_64::native_syscall(
        AXLE_SYS_AX_VMAR_GET_MAPPING_VMO as u64,
        [vmar, addr, out_vmo as *mut zx_handle_t as u64, 0, 0, 0],
    )
}
