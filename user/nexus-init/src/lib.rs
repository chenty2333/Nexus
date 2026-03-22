//! Minimal `nexus-init` bootstrap userspace binary and shared manager logic.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod fs;
mod lifecycle;
mod namespace;
mod net;
mod remote_net;
mod resolver;
mod runner;
mod services;
mod starnix;
mod vmo;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};
#[cfg(not(test))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE};
use axle_types::status::{ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_NOT_FOUND, ZX_OK};
use axle_types::{zx_handle_t, zx_status_t};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_create, zx_handle_close, zx_object_wait_one, zx_socket_read,
    zx_task_kill,
};
#[cfg(not(test))]
use linked_list_allocator::LockedHeap;
use nexus_component::{ControllerRequest, NamespaceEntry, ResolvedComponent, StartupMode};
use nexus_io::{FdFlags, FdOps, FdTable, OpenFlags, ProcessNamespace, RemoteDir};

use crate::fs::{
    proxy_directory_requests_until_peer_closed, read_directory_request_for_launch,
    root_directory_descriptor, run_echo_fs_provider,
};
use crate::lifecycle::{
    MinimalRole, read_component_start_info_minimal, read_controller_event_blocking,
    read_controller_request_blocking, run_controller_lifecycle_step, send_controller_event,
    send_status_event,
};

use crate::namespace::{CapabilityRegistry, build_namespace_entries, publish_protocols};
use crate::resolver::{ResolverRegistry, resolve_root_child};
use crate::runner::{ElfRunner, RunnerRegistry, StarnixRunner};
use crate::services::{BootAssetEntry, BootstrapNamespace, run_socket_fd_smoke, run_tmpfs_smoke};

// Keep this bootstrap shared-slot VA in sync with
// `kernel/axle-kernel/src/userspace.rs`.
const USER_PAGE_BYTES: u64 = 0x1000;
const USER_CODE_PAGE_COUNT: u64 = 4096;
const USER_CODE_BASE: u64 = 0x0000_0001_0000_0000;
const USER_SHARED_BASE: u64 = USER_CODE_BASE + (USER_PAGE_BYTES * USER_CODE_PAGE_COUNT);
const SLOT_OK: usize = 0;
pub(crate) const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_PROCESS_H: usize = 396;
pub(crate) const SLOT_T0_NS: usize = 511;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_BOOT_IMAGE_ECHO_PROVIDER_VMO_H: usize = 604;
const SLOT_BOOT_IMAGE_ECHO_CLIENT_VMO_H: usize = 605;
const SLOT_BOOT_IMAGE_CONTROLLER_WORKER_VMO_H: usize = 606;
const SLOT_BOOT_IMAGE_STARNIX_KERNEL_VMO_H: usize = 607;

const SLOT_COMPONENT_FAILURE_STEP: usize = 578;
const SLOT_COMPONENT_RESOLVE_ROOT: usize = 579;
const SLOT_COMPONENT_RESOLVE_PROVIDER: usize = 580;
const SLOT_COMPONENT_RESOLVE_CLIENT: usize = 581;
const SLOT_COMPONENT_PROVIDER_OUTGOING_PAIR: usize = 582;
const SLOT_COMPONENT_PROVIDER_LAUNCH: usize = 583;
const SLOT_COMPONENT_CLIENT_ROUTE: usize = 584;
const SLOT_COMPONENT_CLIENT_LAUNCH: usize = 585;
const SLOT_COMPONENT_PROVIDER_EVENT_READ: usize = 586;
const SLOT_COMPONENT_PROVIDER_EVENT_CODE: usize = 587;
const SLOT_COMPONENT_CLIENT_EVENT_READ: usize = 588;
const SLOT_COMPONENT_CLIENT_EVENT_CODE: usize = 589;
const SLOT_COMPONENT_LAZY_PROVIDER_PRELAUNCH: usize = 590;
const SLOT_COMPONENT_LAZY_PROVIDER_ROUTE_LAUNCH: usize = 591;
const SLOT_COMPONENT_STOP_REQUEST: usize = 592;
const SLOT_COMPONENT_STOP_EVENT_READ: usize = 593;
const SLOT_COMPONENT_STOP_EVENT_CODE: usize = 594;
const SLOT_COMPONENT_STOP_WAIT_OBSERVED: usize = 595;
const SLOT_COMPONENT_KILL_REQUEST: usize = 596;
const SLOT_COMPONENT_KILL_EVENT_READ: usize = 597;
const SLOT_COMPONENT_KILL_EVENT_CODE: usize = 598;
const SLOT_COMPONENT_KILL_WAIT_OBSERVED: usize = 599;
const SLOT_COMPONENT_PROVIDER_OUTPUT_LEN: usize = 694;
const SLOT_COMPONENT_PROVIDER_OUTPUT_WORD_BASE: usize = 695;
const COMPONENT_PROVIDER_OUTPUT_WORDS: usize = 64;

const STEP_RESOLVE_ROOT: u64 = 1;
const STEP_RESOLVE_PROVIDER: u64 = 2;
const STEP_PROVIDER_OUTGOING_PAIR: u64 = 3;
const STEP_PROVIDER_LAUNCH: u64 = 4;
const STEP_CLIENT_ROUTE: u64 = 5;
const STEP_CLIENT_LAUNCH: u64 = 6;
const STEP_PROVIDER_EVENT: u64 = 7;
const STEP_CLIENT_EVENT: u64 = 8;
const STEP_BOOTSTRAP_NAMESPACE: u64 = 9;
const STEP_TMPFS_SMOKE: u64 = 10;
const STEP_SOCKET_SMOKE: u64 = 11;
const STEP_STARNIX_STDOUT: u64 = 12;
const STEP_ROOT_PANIC: u64 = u64::MAX;

const ROLE_NONE: usize = 0;
const ROLE_ROOT: usize = 1;
const ROLE_CHILD: usize = 2;

const ROOT_DECL_EAGER_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component.nxcd"));
const ROOT_DECL_ROUND3_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_round3.nxcd"));
const ROOT_DECL_STARNIX_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_starnix.nxcd"));
const ROOT_DECL_STARNIX_FD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_starnix_fd.nxcd"));
const ROOT_DECL_STARNIX_ROUND2_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round2.nxcd"
));
const ROOT_DECL_STARNIX_ROUND3_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round3.nxcd"
));
const ROOT_DECL_STARNIX_ROUND4_FUTEX_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round4_futex.nxcd"
));
const ROOT_DECL_STARNIX_ROUND4_SIGNAL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round4_signal.nxcd"
));
const ROOT_DECL_STARNIX_ROUND5_EPOLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round5_epoll.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_EVENTFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_eventfd.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_TIMERFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_timerfd.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_SIGNALFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_signalfd.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_FUTEX_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_futex.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_SCM_RIGHTS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_scm_rights.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_PIDFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_pidfd.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_PROC_JOB_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_job.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_PROC_CONTROL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_control.nxcd"
));
const ROOT_DECL_STARNIX_ROUND6_PROC_TTY_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_tty.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_FD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_fd.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_MISC_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_misc.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_PROCESS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_process.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_NET_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_net.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_FS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_fs.nxcd"
));
const ROOT_DECL_STARNIX_RUNTIME_TLS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_tls.nxcd"
));
const ROOT_DECL_STARNIX_DYNAMIC_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic.nxcd"
));
const ROOT_DECL_STARNIX_DYNAMIC_TLS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_tls.nxcd"
));
const ROOT_DECL_STARNIX_DYNAMIC_RUNTIME_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_runtime.nxcd"
));
const ROOT_DECL_STARNIX_DYNAMIC_PIE_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_pie.nxcd"
));
const ROOT_DECL_STARNIX_GLIBC_HELLO_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_glibc_hello.nxcd"
));
const ROOT_DECL_STARNIX_SHELL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_shell.nxcd"
));
const ROOT_DECL_STARNIX_NET_SHELL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_net_shell.nxcd"
));
const ROOT_DECL_NET_DATAPLANE_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_net_dataplane.nxcd"
));
const ROOT_DECL_VMO_SHARED_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_vmo_shared.nxcd"));
const PROVIDER_DECL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/echo_provider.nxcd"));
const CLIENT_DECL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/echo_client.nxcd"));
const CONTROLLER_WORKER_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/controller_worker.nxcd"));
#[cfg(nexus_init_embed_starnix_hello)]
const LINUX_HELLO_DECL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/linux_hello.nxcd"));
#[cfg(not(nexus_init_embed_starnix_hello))]
const LINUX_HELLO_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_fd)]
const LINUX_FD_SMOKE_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_fd_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_fd))]
const LINUX_FD_SMOKE_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round2)]
pub(crate) const LINUX_ROUND2_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round2_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round2))]
pub(crate) const LINUX_ROUND2_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round3)]
pub(crate) const LINUX_ROUND3_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round3_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round3))]
pub(crate) const LINUX_ROUND3_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round4_futex)]
pub(crate) const LINUX_ROUND4_FUTEX_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round4_futex_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round4_futex))]
pub(crate) const LINUX_ROUND4_FUTEX_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round4_signal)]
pub(crate) const LINUX_ROUND4_SIGNAL_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round4_signal_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round4_signal))]
pub(crate) const LINUX_ROUND4_SIGNAL_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round5_epoll)]
pub(crate) const LINUX_ROUND5_EPOLL_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round5_epoll_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round5_epoll))]
pub(crate) const LINUX_ROUND5_EPOLL_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_eventfd)]
pub(crate) const LINUX_ROUND6_EVENTFD_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round6_eventfd_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round6_eventfd))]
pub(crate) const LINUX_ROUND6_EVENTFD_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_timerfd)]
pub(crate) const LINUX_ROUND6_TIMERFD_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round6_timerfd_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round6_timerfd))]
pub(crate) const LINUX_ROUND6_TIMERFD_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_signalfd)]
pub(crate) const LINUX_ROUND6_SIGNALFD_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_round6_signalfd_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_round6_signalfd))]
pub(crate) const LINUX_ROUND6_SIGNALFD_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_futex)]
pub(crate) const LINUX_ROUND6_FUTEX_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round6_futex_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round6_futex))]
pub(crate) const LINUX_ROUND6_FUTEX_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_scm_rights)]
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_round6_scm_rights_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_round6_scm_rights))]
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_pidfd)]
pub(crate) const LINUX_ROUND6_PIDFD_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_round6_pidfd_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_round6_pidfd))]
pub(crate) const LINUX_ROUND6_PIDFD_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_job)]
pub(crate) const LINUX_ROUND6_PROC_JOB_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_round6_proc_job_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_round6_proc_job))]
pub(crate) const LINUX_ROUND6_PROC_JOB_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_control)]
pub(crate) const LINUX_ROUND6_PROC_CONTROL_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_round6_proc_control_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_round6_proc_control))]
pub(crate) const LINUX_ROUND6_PROC_CONTROL_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_tty)]
pub(crate) const LINUX_ROUND6_PROC_TTY_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_round6_proc_tty_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_round6_proc_tty))]
pub(crate) const LINUX_ROUND6_PROC_TTY_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_fd)]
pub(crate) const LINUX_RUNTIME_FD_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_runtime_fd_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_runtime_fd))]
pub(crate) const LINUX_RUNTIME_FD_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_misc)]
pub(crate) const LINUX_RUNTIME_MISC_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_runtime_misc_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_runtime_misc))]
pub(crate) const LINUX_RUNTIME_MISC_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_process)]
pub(crate) const LINUX_RUNTIME_PROCESS_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_runtime_process_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_runtime_process))]
pub(crate) const LINUX_RUNTIME_PROCESS_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_net)]
pub(crate) const LINUX_RUNTIME_NET_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_runtime_net_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_runtime_net))]
pub(crate) const LINUX_RUNTIME_NET_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_fs)]
pub(crate) const LINUX_RUNTIME_FS_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_runtime_fs_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_runtime_fs))]
pub(crate) const LINUX_RUNTIME_FS_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_tls)]
pub(crate) const LINUX_RUNTIME_TLS_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_runtime_tls_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_runtime_tls))]
pub(crate) const LINUX_RUNTIME_TLS_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic)]
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_dynamic_elf_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_dynamic))]
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_tls)]
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_dynamic_tls_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_dynamic_tls))]
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_runtime)]
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/linux_dynamic_runtime_smoke.nxcd"
));
#[cfg(not(nexus_init_embed_starnix_dynamic_runtime))]
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_pie)]
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_dynamic_pie_smoke.nxcd"));
#[cfg(not(nexus_init_embed_starnix_dynamic_pie))]
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_glibc_hello)]
pub(crate) const LINUX_GLIBC_HELLO_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_glibc_hello.nxcd"));
#[cfg(not(nexus_init_embed_starnix_glibc_hello))]
pub(crate) const LINUX_GLIBC_HELLO_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_shell)]
pub(crate) const LINUX_BUSYBOX_SHELL_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_busybox_shell.nxcd"));
#[cfg(not(nexus_init_embed_starnix_shell))]
pub(crate) const LINUX_BUSYBOX_SHELL_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_net_shell)]
pub(crate) const LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux_busybox_socket_shell.nxcd"));
#[cfg(not(nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_hello)]
pub(crate) const LINUX_HELLO_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-hello"));
#[cfg(not(nexus_init_embed_starnix_hello))]
pub(crate) const LINUX_HELLO_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_fd)]
pub(crate) const LINUX_FD_SMOKE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-fd-smoke"));
#[cfg(not(nexus_init_embed_starnix_fd))]
pub(crate) const LINUX_FD_SMOKE_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round2)]
pub(crate) const LINUX_ROUND2_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round2-smoke"));
#[cfg(not(nexus_init_embed_starnix_round2))]
pub(crate) const LINUX_ROUND2_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round3)]
pub(crate) const LINUX_ROUND3_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round3-smoke"));
#[cfg(not(nexus_init_embed_starnix_round3))]
pub(crate) const LINUX_ROUND3_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round4_futex)]
pub(crate) const LINUX_ROUND4_FUTEX_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round4-futex-smoke"));
#[cfg(not(nexus_init_embed_starnix_round4_futex))]
pub(crate) const LINUX_ROUND4_FUTEX_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round4_signal)]
pub(crate) const LINUX_ROUND4_SIGNAL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round4-signal-smoke"));
#[cfg(not(nexus_init_embed_starnix_round4_signal))]
pub(crate) const LINUX_ROUND4_SIGNAL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round5_epoll)]
pub(crate) const LINUX_ROUND5_EPOLL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round5-epoll-smoke"));
#[cfg(not(nexus_init_embed_starnix_round5_epoll))]
pub(crate) const LINUX_ROUND5_EPOLL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_eventfd)]
pub(crate) const LINUX_ROUND6_EVENTFD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-eventfd-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_eventfd))]
pub(crate) const LINUX_ROUND6_EVENTFD_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_timerfd)]
pub(crate) const LINUX_ROUND6_TIMERFD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-timerfd-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_timerfd))]
pub(crate) const LINUX_ROUND6_TIMERFD_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_signalfd)]
pub(crate) const LINUX_ROUND6_SIGNALFD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-signalfd-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_signalfd))]
pub(crate) const LINUX_ROUND6_SIGNALFD_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_futex)]
pub(crate) const LINUX_ROUND6_FUTEX_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-futex-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_futex))]
pub(crate) const LINUX_ROUND6_FUTEX_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_scm_rights)]
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-scm-rights-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_scm_rights))]
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_pidfd)]
pub(crate) const LINUX_ROUND6_PIDFD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-pidfd-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_pidfd))]
pub(crate) const LINUX_ROUND6_PIDFD_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_job)]
pub(crate) const LINUX_ROUND6_PROC_JOB_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-proc-job-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_proc_job))]
pub(crate) const LINUX_ROUND6_PROC_JOB_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_control)]
pub(crate) const LINUX_ROUND6_PROC_CONTROL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-proc-control-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_proc_control))]
pub(crate) const LINUX_ROUND6_PROC_CONTROL_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_round6_proc_tty)]
pub(crate) const LINUX_ROUND6_PROC_TTY_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-round6-proc-tty-smoke"));
#[cfg(not(nexus_init_embed_starnix_round6_proc_tty))]
pub(crate) const LINUX_ROUND6_PROC_TTY_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_fd)]
pub(crate) const LINUX_RUNTIME_FD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-fd-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_fd))]
pub(crate) const LINUX_RUNTIME_FD_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_misc)]
pub(crate) const LINUX_RUNTIME_MISC_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-misc-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_misc))]
pub(crate) const LINUX_RUNTIME_MISC_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_process)]
pub(crate) const LINUX_RUNTIME_PROCESS_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-process-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_process))]
pub(crate) const LINUX_RUNTIME_PROCESS_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_net)]
pub(crate) const LINUX_RUNTIME_NET_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-net-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_net))]
pub(crate) const LINUX_RUNTIME_NET_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_fs)]
pub(crate) const LINUX_RUNTIME_FS_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-fs-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_fs))]
pub(crate) const LINUX_RUNTIME_FS_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_runtime_tls)]
pub(crate) const LINUX_RUNTIME_TLS_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-runtime-tls-smoke"));
#[cfg(not(nexus_init_embed_starnix_runtime_tls))]
pub(crate) const LINUX_RUNTIME_TLS_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic)]
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-elf-smoke"));
#[cfg(not(nexus_init_embed_starnix_dynamic))]
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic)]
pub(crate) const LINUX_DYNAMIC_MAIN_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-main"));
#[cfg(not(nexus_init_embed_starnix_dynamic))]
pub(crate) const LINUX_DYNAMIC_MAIN_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic)]
pub(crate) const LINUX_DYNAMIC_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-dynamic-smoke.so"));
#[cfg(not(nexus_init_embed_starnix_dynamic))]
pub(crate) const LINUX_DYNAMIC_INTERP_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_tls)]
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-tls-smoke"));
#[cfg(not(nexus_init_embed_starnix_dynamic_tls))]
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_tls)]
pub(crate) const LINUX_DYNAMIC_TLS_MAIN_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-tls-main"));
#[cfg(not(nexus_init_embed_starnix_dynamic_tls))]
pub(crate) const LINUX_DYNAMIC_TLS_MAIN_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_tls)]
pub(crate) const LINUX_DYNAMIC_TLS_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-dynamic-tls.so"));
#[cfg(not(nexus_init_embed_starnix_dynamic_tls))]
pub(crate) const LINUX_DYNAMIC_TLS_INTERP_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_runtime)]
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-runtime-smoke"));
#[cfg(not(nexus_init_embed_starnix_dynamic_runtime))]
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_runtime)]
pub(crate) const LINUX_DYNAMIC_RUNTIME_MAIN_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-runtime-main"));
#[cfg(not(nexus_init_embed_starnix_dynamic_runtime))]
pub(crate) const LINUX_DYNAMIC_RUNTIME_MAIN_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_runtime)]
pub(crate) const LINUX_DYNAMIC_RUNTIME_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-dynamic-runtime.so"));
#[cfg(not(nexus_init_embed_starnix_dynamic_runtime))]
pub(crate) const LINUX_DYNAMIC_RUNTIME_INTERP_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_pie)]
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-pie-smoke"));
#[cfg(not(nexus_init_embed_starnix_dynamic_pie))]
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_pie)]
pub(crate) const LINUX_DYNAMIC_PIE_MAIN_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-dynamic-pie-main"));
#[cfg(not(nexus_init_embed_starnix_dynamic_pie))]
pub(crate) const LINUX_DYNAMIC_PIE_MAIN_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_dynamic_pie)]
pub(crate) const LINUX_DYNAMIC_PIE_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-dynamic-runtime.so"));
#[cfg(not(nexus_init_embed_starnix_dynamic_pie))]
pub(crate) const LINUX_DYNAMIC_PIE_INTERP_BYTES: &[u8] = &[];
#[cfg(nexus_init_embed_starnix_glibc_hello)]
pub(crate) const LINUX_GLIBC_HELLO_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/linux-glibc-hello"));
#[cfg(not(nexus_init_embed_starnix_glibc_hello))]
pub(crate) const LINUX_GLIBC_HELLO_BYTES: &[u8] = &[];
#[cfg(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
))]
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-glibc.so"));
#[cfg(not(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
)))]
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BYTES: &[u8] = &[];
#[cfg(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libc.so.6"));
#[cfg(not(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
)))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BYTES: &[u8] = &[];
#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_BUSYBOX_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/busybox"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_BUSYBOX_BYTES: &[u8] = &[];
#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libm.so.6"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BYTES: &[u8] = &[];
#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libresolv.so.2"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BYTES: &[u8] = &[];

pub(crate) const CHILD_ROLE_PROVIDER: &str = "echo-provider";
pub(crate) const CHILD_ROLE_CLIENT: &str = "echo-client";
pub(crate) const CHILD_ROLE_CONTROLLER_WORKER: &str = "controller-worker";
const ROOT_COMPONENT_URL: &str = env!("NEXUS_INIT_ROOT_URL");
const _: &str = env!("NEXUS_INIT_EMBED_STAMP");
pub(crate) const ROOT_BINARY_PATH: &str = "bin/nexus-init";
pub(crate) const PROVIDER_BINARY_PATH: &str = "bin/echo-provider";
pub(crate) const CLIENT_BINARY_PATH: &str = "bin/echo-client";
pub(crate) const CONTROLLER_WORKER_BINARY_PATH: &str = "bin/controller-worker";
pub(crate) const STARNIX_KERNEL_BINARY_PATH: &str = "bin/starnix-kernel";
pub(crate) const LINUX_HELLO_BINARY_PATH: &str = "bin/linux-hello";
pub(crate) const LINUX_FD_SMOKE_BINARY_PATH: &str = "bin/linux-fd-smoke";
pub(crate) const LINUX_ROUND2_BINARY_PATH: &str = "bin/linux-round2-smoke";
pub(crate) const LINUX_ROUND3_BINARY_PATH: &str = "bin/linux-round3-smoke";
pub(crate) const LINUX_ROUND4_FUTEX_BINARY_PATH: &str = "bin/linux-round4-futex-smoke";
pub(crate) const LINUX_ROUND4_SIGNAL_BINARY_PATH: &str = "bin/linux-round4-signal-smoke";
pub(crate) const LINUX_ROUND5_EPOLL_BINARY_PATH: &str = "bin/linux-round5-epoll-smoke";
pub(crate) const LINUX_ROUND6_EVENTFD_BINARY_PATH: &str = "bin/linux-round6-eventfd-smoke";
pub(crate) const LINUX_ROUND6_TIMERFD_BINARY_PATH: &str = "bin/linux-round6-timerfd-smoke";
pub(crate) const LINUX_ROUND6_SIGNALFD_BINARY_PATH: &str = "bin/linux-round6-signalfd-smoke";
pub(crate) const LINUX_ROUND6_FUTEX_BINARY_PATH: &str = "bin/linux-round6-futex-smoke";
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH: &str = "bin/linux-round6-scm-rights-smoke";
pub(crate) const LINUX_ROUND6_PIDFD_BINARY_PATH: &str = "bin/linux-round6-pidfd-smoke";
pub(crate) const LINUX_ROUND6_PROC_JOB_BINARY_PATH: &str = "bin/linux-round6-proc-job-smoke";
pub(crate) const LINUX_ROUND6_PROC_CONTROL_BINARY_PATH: &str =
    "bin/linux-round6-proc-control-smoke";
pub(crate) const LINUX_ROUND6_PROC_TTY_BINARY_PATH: &str = "bin/linux-round6-proc-tty-smoke";
pub(crate) const LINUX_RUNTIME_FD_BINARY_PATH: &str = "bin/linux-runtime-fd-smoke";
pub(crate) const LINUX_RUNTIME_MISC_BINARY_PATH: &str = "bin/linux-runtime-misc-smoke";
pub(crate) const LINUX_RUNTIME_PROCESS_BINARY_PATH: &str = "bin/linux-runtime-process-smoke";
pub(crate) const LINUX_RUNTIME_NET_BINARY_PATH: &str = "bin/linux-runtime-net-smoke";
pub(crate) const LINUX_RUNTIME_FS_BINARY_PATH: &str = "bin/linux-runtime-fs-smoke";
pub(crate) const LINUX_RUNTIME_TLS_BINARY_PATH: &str = "bin/linux-runtime-tls-smoke";
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-elf-smoke";
pub(crate) const LINUX_DYNAMIC_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-main";
pub(crate) const LINUX_DYNAMIC_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-smoke.so";
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-tls-smoke";
pub(crate) const LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-tls-main";
pub(crate) const LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-tls.so";
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-runtime-smoke";
pub(crate) const LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-runtime-main";
pub(crate) const LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-runtime.so";
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-pie-smoke";
pub(crate) const LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-pie-main";
pub(crate) const LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-runtime.so";
pub(crate) const LINUX_GLIBC_HELLO_BINARY_PATH: &str = "bin/linux-glibc-hello";
pub(crate) const LINUX_BUSYBOX_BINARY_PATH: &str = "bin/busybox";
pub(crate) const LINUX_BUSYBOX_SHELL_BINARY_PATH: &str = "bin/sh";
pub(crate) const LINUX_BUSYBOX_LS_BINARY_PATH: &str = "bin/ls";
pub(crate) const LINUX_BUSYBOX_CAT_BINARY_PATH: &str = "bin/cat";
pub(crate) const LINUX_BUSYBOX_ECHO_BINARY_PATH: &str = "bin/echo";
pub(crate) const LINUX_BUSYBOX_MKDIR_BINARY_PATH: &str = "bin/mkdir";
pub(crate) const LINUX_BUSYBOX_RM_BINARY_PATH: &str = "bin/rm";
pub(crate) const LINUX_BUSYBOX_PS_BINARY_PATH: &str = "bin/ps";
pub(crate) const LINUX_BUSYBOX_PASSWD_PATH: &str = "etc/passwd";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH: &str = "lib/ld-nexus-glibc.so";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH: &str = "lib/ld-linux-x86-64.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH: &str = "lib64/ld-linux-x86-64.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH: &str = "lib/libc.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH: &str = "lib64/libc.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BINARY_PATH: &str = "lib/libm.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_LIB64_PATH: &str = "lib64/libm.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BINARY_PATH: &str = "lib/libresolv.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_LIB64_PATH: &str = "lib64/libresolv.so.2";
pub(crate) const SVC_NAMESPACE_PATH: &str = "/svc";
pub(crate) const ECHO_PROTOCOL_NAME: &str = "nexus.echo.Echo";
const ECHO_REQUEST: &[u8] = b"hello";
pub(crate) const CHILD_MARKER_PROVIDER: u64 = 0x4e58_4300_0000_0001;
pub(crate) const CHILD_MARKER_CLIENT: u64 = 0x4e58_4300_0000_0002;
pub(crate) const CHILD_MARKER_CONTROLLER_WORKER: u64 = 0x4e58_4300_0000_0003;
pub(crate) const CHILD_MARKER_STARNIX_KERNEL: u64 = 0x4e58_4300_0000_0004;
pub(crate) const STARTUP_HANDLE_COMPONENT_STATUS: u32 = 1;
pub(crate) const STARTUP_HANDLE_STARNIX_IMAGE_VMO: u32 = 2;
pub(crate) const STARTUP_HANDLE_STARNIX_PARENT_PROCESS: u32 = 3;
pub(crate) const STARTUP_HANDLE_STARNIX_STDOUT: u32 = 4;
pub(crate) const STARTUP_HANDLE_STARNIX_STDIN: u32 = 5;
pub(crate) const MAX_SMALL_CHANNEL_BYTES: usize = 128;
pub(crate) const MAX_SMALL_CHANNEL_HANDLES: usize = 1;
const STARNIX_HELLO_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\n";
const STARNIX_FD_SMOKE_EXPECTED_STDOUT: &[u8] = b"pipe\nsock\n";
const STARNIX_ROUND2_EXPECTED_STDOUT: &[u8] = b"round2 ok\n";
const STARNIX_ROUND3_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\nround3 ok\n";
const STARNIX_ROUND4_FUTEX_EXPECTED_STDOUT: &[u8] = b"round4 futex ok\n";
const STARNIX_ROUND4_SIGNAL_EXPECTED_STDOUT: &[u8] = b"round4 signal ok\n";
const STARNIX_ROUND5_EPOLL_EXPECTED_STDOUT: &[u8] = b"round5 epoll ok\n";
const STARNIX_ROUND6_EVENTFD_EXPECTED_STDOUT: &[u8] = b"round6 eventfd ok\n";
const STARNIX_ROUND6_TIMERFD_EXPECTED_STDOUT: &[u8] = b"round6 timerfd ok\n";
const STARNIX_ROUND6_SIGNALFD_EXPECTED_STDOUT: &[u8] = b"round6 signalfd ok\n";
const STARNIX_ROUND6_FUTEX_EXPECTED_STDOUT: &[u8] = b"round6 futex ok\n";
const STARNIX_ROUND6_SCM_RIGHTS_EXPECTED_STDOUT: &[u8] = b"round6 scm_rights ok\n";
const STARNIX_ROUND6_PIDFD_EXPECTED_STDOUT: &[u8] = b"round6 pidfd ok\n";
const STARNIX_ROUND6_PROC_JOB_EXPECTED_STDOUT: &[u8] = b"proc-fd bridge ok\nround6 proc_job ok\n";
const STARNIX_ROUND6_PROC_CONTROL_EXPECTED_STDOUT: &[u8] = b"round6 proc_control ok\n";
const STARNIX_ROUND6_PROC_TTY_EXPECTED_STDOUT: &[u8] = b"tround6 proc_tty ok\n";
const STARNIX_RUNTIME_FD_EXPECTED_STDOUT: &[u8] = b"runtime fd ok\n";
const STARNIX_RUNTIME_MISC_EXPECTED_STDOUT: &[u8] = b"runtime misc ok\n";
const STARNIX_RUNTIME_PROCESS_EXPECTED_STDOUT: &[u8] = b"runtime process ok\n";
const STARNIX_RUNTIME_NET_EXPECTED_STDOUT: &[u8] = b"runtime net ok\n";
const STARNIX_RUNTIME_FS_EXPECTED_STDOUT: &[u8] = b"runtime fs ok\n";
const STARNIX_RUNTIME_TLS_EXPECTED_STDOUT: &[u8] = b"runtime tls ok\n";
const STARNIX_DYNAMIC_ELF_EXPECTED_STDOUT: &[u8] = b"dynamic interp ok\n";
const STARNIX_DYNAMIC_TLS_EXPECTED_STDOUT: &[u8] = b"dynamic tls ok\n";
const STARNIX_DYNAMIC_RUNTIME_EXPECTED_STDOUT: &[u8] = b"dynamic runtime ok\n";
const STARNIX_DYNAMIC_PIE_EXPECTED_STDOUT: &[u8] = b"dynamic pie ok\n";
const STARNIX_GLIBC_HELLO_EXPECTED_STDOUT: &[u8] = b"glibc hello\n";
const STARNIX_SHELL_EXPECTED_STDOUT: &[u8] = b"";
const LINUX_BUSYBOX_PASSWD_BYTES: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n";

pub(crate) fn push_busybox_shell_runtime_assets(assets: &mut Vec<BootAssetEntry>) {
    if LINUX_BUSYBOX_BYTES.is_empty() {
        return;
    }
    for path in [
        LINUX_BUSYBOX_BINARY_PATH,
        LINUX_BUSYBOX_SHELL_BINARY_PATH,
        LINUX_BUSYBOX_LS_BINARY_PATH,
        LINUX_BUSYBOX_CAT_BINARY_PATH,
        LINUX_BUSYBOX_ECHO_BINARY_PATH,
        LINUX_BUSYBOX_MKDIR_BINARY_PATH,
        LINUX_BUSYBOX_RM_BINARY_PATH,
        LINUX_BUSYBOX_PS_BINARY_PATH,
    ] {
        assets.push(BootAssetEntry::bytes(path, LINUX_BUSYBOX_BYTES));
    }
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_LIBC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_LIBC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBM_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_LIBM_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBM_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_LIBM_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_RESOLV_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_RESOLV_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_RESOLV_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_RESOLV_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_BUSYBOX_PASSWD_PATH,
        LINUX_BUSYBOX_PASSWD_BYTES,
    ));
}

pub(crate) fn push_busybox_shell_decl_assets(assets: &mut Vec<BootAssetEntry>) {
    if !LINUX_BUSYBOX_SHELL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-busybox-shell.nxcd",
            LINUX_BUSYBOX_SHELL_DECL_BYTES,
        ));
    }
    if !LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-busybox-socket-shell.nxcd",
            LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES,
        ));
    }
}

#[cfg(not(test))]
#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

#[cfg(not(test))]
const HEAP_BYTES: usize = 4 * 1024 * 1024;
#[cfg(not(test))]
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);
#[cfg(not(test))]
static HEAP_READY: AtomicBool = AtomicBool::new(false);
static ROLE: AtomicUsize = AtomicUsize::new(ROLE_NONE);

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

#[cfg(not(test))]
fn init_heap_once() {
    if HEAP_READY
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // SAFETY: `HEAP` is the dedicated backing storage for this userspace process.
        // Initialization happens exactly once under `HEAP_READY`, and the memory range
        // remains reserved for the allocator for the entire process lifetime.
        unsafe {
            ALLOCATOR
                .lock()
                .init(core::ptr::addr_of_mut!(HEAP.0).cast::<u8>(), HEAP_BYTES);
        }
    }
}

#[cfg(test)]
fn init_heap_once() {}

#[derive(Clone, Copy, Default)]
struct ComponentSummary {
    failure_step: u64,
    resolve_root: i64,
    resolve_provider: i64,
    resolve_client: i64,
    provider_outgoing_pair: i64,
    provider_launch: i64,
    client_route: i64,
    client_launch: i64,
    provider_event_read: i64,
    provider_event_code: i64,
    client_event_read: i64,
    client_event_code: i64,
    lazy_provider_prelaunch: i64,
    lazy_provider_route_launch: i64,
    stop_request: i64,
    stop_event_read: i64,
    stop_event_code: i64,
    stop_wait_observed: u64,
    kill_request: i64,
    kill_event_read: i64,
    kill_event_code: i64,
    kill_wait_observed: u64,
}

pub fn program_start(bootstrap_channel: zx_handle_t, arg1: u64) -> ! {
    init_heap_once();
    if arg1 == CHILD_MARKER_STARNIX_KERNEL {
        ROLE.store(ROLE_CHILD, Ordering::Relaxed);
        starnix::starnix_kernel_program_start(bootstrap_channel);
    }
    let _ = bootstrap_channel;
    ROLE.store(ROLE_ROOT, Ordering::Relaxed);
    let mut summary = ComponentSummary {
        failure_step: STEP_RESOLVE_ROOT,
        ..ComponentSummary::default()
    };
    write_summary(&summary);
    summary.failure_step = 0;
    let status = run_component_manager(&mut summary);
    write_summary(&summary);
    write_slot(SLOT_OK, u64::from(status == 0));
    axle_arch_x86_64::debug_break()
}

pub fn program_end() {}

struct PanicPrefix<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> PanicPrefix<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> fmt::Write for PanicPrefix<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let available = N.saturating_sub(self.len);
        if available == 0 {
            return Ok(());
        }
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(available);
        self.bytes[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

pub fn report_panic_with_info(info: &core::panic::PanicInfo<'_>) -> ! {
    if ROLE.load(Ordering::Relaxed) == ROLE_ROOT {
        let mut prefix = PanicPrefix::<128>::new();
        let _ = write!(&mut prefix, "panic: {}", info);
        write_component_output_prefix(prefix.as_bytes());
        write_slot(SLOT_COMPONENT_FAILURE_STEP, STEP_ROOT_PANIC);
        write_slot(SLOT_OK, 0);
        axle_arch_x86_64::debug_break()
    }
    loop {
        core::hint::spin_loop();
    }
}

pub fn report_panic() -> ! {
    if ROLE.load(Ordering::Relaxed) == ROLE_ROOT {
        write_component_output_prefix(b"panic");
        write_slot(SLOT_COMPONENT_FAILURE_STEP, STEP_ROOT_PANIC);
        write_slot(SLOT_OK, 0);
        axle_arch_x86_64::debug_break()
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Start the dedicated `echo-provider` component image.
pub fn echo_provider_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    run_dedicated_child_component(
        bootstrap_channel,
        MinimalRole::Provider,
        CHILD_MARKER_PROVIDER,
    )
}

/// Start the dedicated `echo-client` component image.
pub fn echo_client_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    run_dedicated_child_component(bootstrap_channel, MinimalRole::Client, CHILD_MARKER_CLIENT)
}

/// Start the dedicated `controller-worker` component image.
pub fn controller_worker_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    run_dedicated_child_component(
        bootstrap_channel,
        MinimalRole::ControllerWorker,
        CHILD_MARKER_CONTROLLER_WORKER,
    )
}

/// Report a panic from one dedicated child component image.
pub fn child_report_panic() -> ! {
    ROLE.store(ROLE_CHILD, Ordering::Relaxed);
    loop {
        core::hint::spin_loop();
    }
}

fn build_runner_registry(
    parent_process: zx_handle_t,
    boot_root: Arc<dyn FdOps>,
) -> Result<RunnerRegistry, zx_status_t> {
    let mut runners = RunnerRegistry::new();
    runners.insert_elf(
        "elf",
        ElfRunner {
            parent_process,
            boot_root: Arc::clone(&boot_root),
        },
    );
    runners.insert_starnix(
        "starnix",
        StarnixRunner {
            parent_process,
            boot_root,
        },
    );
    Ok(runners)
}

fn build_bootstrap_namespace() -> Result<BootstrapNamespace, zx_status_t> {
    let self_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    let provider_image_vmo = read_slot(SLOT_BOOT_IMAGE_ECHO_PROVIDER_VMO_H) as zx_handle_t;
    let client_image_vmo = read_slot(SLOT_BOOT_IMAGE_ECHO_CLIENT_VMO_H) as zx_handle_t;
    let controller_worker_image_vmo =
        read_slot(SLOT_BOOT_IMAGE_CONTROLLER_WORKER_VMO_H) as zx_handle_t;
    let starnix_kernel_image_vmo = read_slot(SLOT_BOOT_IMAGE_STARNIX_KERNEL_VMO_H) as zx_handle_t;
    if self_code_vmo == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_INTERNAL);
    }

    let mut assets = Vec::new();
    assets.push(BootAssetEntry::vmo(ROOT_BINARY_PATH, self_code_vmo));
    assets.push(BootAssetEntry::vmo(
        STARNIX_KERNEL_BINARY_PATH,
        if starnix_kernel_image_vmo != ZX_HANDLE_INVALID {
            starnix_kernel_image_vmo
        } else {
            self_code_vmo
        },
    ));
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
    if !LINUX_RUNTIME_NET_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_NET_BINARY_PATH,
            LINUX_RUNTIME_NET_BYTES,
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
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH,
            LINUX_GLIBC_RUNTIME_LIBC_BYTES,
        ));
    }
    push_busybox_shell_runtime_assets(&mut assets);
    assets.push(BootAssetEntry::bytes(
        "manifests/root.nxcd",
        ROOT_DECL_EAGER_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-round3.nxcd",
        ROOT_DECL_ROUND3_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix.nxcd",
        ROOT_DECL_STARNIX_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-fd.nxcd",
        ROOT_DECL_STARNIX_FD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round2.nxcd",
        ROOT_DECL_STARNIX_ROUND2_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round3.nxcd",
        ROOT_DECL_STARNIX_ROUND3_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round4-futex.nxcd",
        ROOT_DECL_STARNIX_ROUND4_FUTEX_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round4-signal.nxcd",
        ROOT_DECL_STARNIX_ROUND4_SIGNAL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round5-epoll.nxcd",
        ROOT_DECL_STARNIX_ROUND5_EPOLL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-eventfd.nxcd",
        ROOT_DECL_STARNIX_ROUND6_EVENTFD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-timerfd.nxcd",
        ROOT_DECL_STARNIX_ROUND6_TIMERFD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-signalfd.nxcd",
        ROOT_DECL_STARNIX_ROUND6_SIGNALFD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-futex.nxcd",
        ROOT_DECL_STARNIX_ROUND6_FUTEX_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-scm-rights.nxcd",
        ROOT_DECL_STARNIX_ROUND6_SCM_RIGHTS_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-pidfd.nxcd",
        ROOT_DECL_STARNIX_ROUND6_PIDFD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-proc-job.nxcd",
        ROOT_DECL_STARNIX_ROUND6_PROC_JOB_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-proc-control.nxcd",
        ROOT_DECL_STARNIX_ROUND6_PROC_CONTROL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-round6-proc-tty.nxcd",
        ROOT_DECL_STARNIX_ROUND6_PROC_TTY_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-fd.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_FD_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-misc.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_MISC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-process.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_PROCESS_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-net.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_NET_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-fs.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_FS_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-runtime-tls.nxcd",
        ROOT_DECL_STARNIX_RUNTIME_TLS_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-dynamic.nxcd",
        ROOT_DECL_STARNIX_DYNAMIC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-dynamic-tls.nxcd",
        ROOT_DECL_STARNIX_DYNAMIC_TLS_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-dynamic-runtime.nxcd",
        ROOT_DECL_STARNIX_DYNAMIC_RUNTIME_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-dynamic-pie.nxcd",
        ROOT_DECL_STARNIX_DYNAMIC_PIE_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-glibc-hello.nxcd",
        ROOT_DECL_STARNIX_GLIBC_HELLO_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-shell.nxcd",
        ROOT_DECL_STARNIX_SHELL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-starnix-net-shell.nxcd",
        ROOT_DECL_STARNIX_NET_SHELL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-net-dataplane.nxcd",
        ROOT_DECL_NET_DATAPLANE_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/root-vmo-shared.nxcd",
        ROOT_DECL_VMO_SHARED_BYTES,
    ));
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
    if !LINUX_RUNTIME_FD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-fd-smoke.nxcd",
            LINUX_RUNTIME_FD_DECL_BYTES,
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
    if !LINUX_RUNTIME_NET_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-net-smoke.nxcd",
            LINUX_RUNTIME_NET_DECL_BYTES,
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
    if !LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-elf-smoke.nxcd",
            LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-tls-smoke.nxcd",
            LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES,
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
    push_busybox_shell_decl_assets(&mut assets);
    assets.push(BootAssetEntry::bytes(
        "manifests/echo-provider.nxcd",
        PROVIDER_DECL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/echo-client.nxcd",
        CLIENT_DECL_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        "manifests/controller-worker.nxcd",
        CONTROLLER_WORKER_DECL_BYTES,
    ));
    if provider_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(
            PROVIDER_BINARY_PATH,
            provider_image_vmo,
        ));
    }
    if client_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(CLIENT_BINARY_PATH, client_image_vmo));
    }
    if controller_worker_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(
            CONTROLLER_WORKER_BINARY_PATH,
            controller_worker_image_vmo,
        ));
    }

    BootstrapNamespace::build(&assets)
}

fn build_resolver_registry(boot_root: Arc<dyn FdOps>) -> ResolverRegistry {
    ResolverRegistry::new(boot_root)
}

fn resolve_root_component(resolvers: &ResolverRegistry) -> Result<ResolvedComponent, zx_status_t> {
    resolvers.resolve("boot-resolver", ROOT_COMPONENT_URL)
}

fn resolve_optional_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    name: &str,
) -> Result<Option<(ResolvedComponent, StartupMode)>, zx_status_t> {
    match resolve_root_child(root, resolvers, name) {
        Ok(component) => Ok(Some(component)),
        Err(ZX_ERR_NOT_FOUND) => Ok(None),
        Err(status) => Err(status),
    }
}

fn run_component_manager(summary: &mut ComponentSummary) -> i32 {
    *summary = ComponentSummary::default();
    let parent_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    if parent_process == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_RESOLVE_ROOT;
        summary.resolve_root = ZX_ERR_INTERNAL as i64;
        return 1;
    }

    let bootstrap_namespace = match build_bootstrap_namespace() {
        Ok(namespace) => namespace,
        Err(status) => {
            summary.failure_step = STEP_BOOTSTRAP_NAMESPACE;
            summary.resolve_root = status as i64;
            return 1;
        }
    };
    if let Err(status) = run_tmpfs_smoke(bootstrap_namespace.namespace()) {
        summary.failure_step = STEP_TMPFS_SMOKE;
        summary.resolve_root = status as i64;
        return 1;
    }
    if let Err(status) = run_socket_fd_smoke() {
        summary.failure_step = STEP_SOCKET_SMOKE;
        summary.resolve_root = status as i64;
        return 1;
    }

    let resolvers = build_resolver_registry(bootstrap_namespace.boot_root());
    let root = match resolve_root_component(&resolvers) {
        Ok(component) => {
            summary.resolve_root = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };
    let runners = match build_runner_registry(parent_process, bootstrap_namespace.boot_root()) {
        Ok(runners) => runners,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };

    if root.decl.url == "boot://root-starnix" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_hello",
            STARNIX_HELLO_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-fd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_fd_smoke",
            STARNIX_FD_SMOKE_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round2" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round2_smoke",
            STARNIX_ROUND2_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round3" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round3_smoke",
            STARNIX_ROUND3_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round4-futex" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round4_futex_smoke",
            STARNIX_ROUND4_FUTEX_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round4-signal" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round4_signal_smoke",
            STARNIX_ROUND4_SIGNAL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round5-epoll" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round5_epoll_smoke",
            STARNIX_ROUND5_EPOLL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-eventfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_eventfd_smoke",
            STARNIX_ROUND6_EVENTFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-timerfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_timerfd_smoke",
            STARNIX_ROUND6_TIMERFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-signalfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_signalfd_smoke",
            STARNIX_ROUND6_SIGNALFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-futex" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_futex_smoke",
            STARNIX_ROUND6_FUTEX_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-scm-rights" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_scm_rights_smoke",
            STARNIX_ROUND6_SCM_RIGHTS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-pidfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_pidfd_smoke",
            STARNIX_ROUND6_PIDFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-job" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_job_smoke",
            STARNIX_ROUND6_PROC_JOB_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-control" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_control_smoke",
            STARNIX_ROUND6_PROC_CONTROL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-tty" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_tty_smoke",
            STARNIX_ROUND6_PROC_TTY_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-fd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_fd_smoke",
            STARNIX_RUNTIME_FD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-misc" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_misc_smoke",
            STARNIX_RUNTIME_MISC_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-process" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_process_smoke",
            STARNIX_RUNTIME_PROCESS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-net" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_net_smoke",
            STARNIX_RUNTIME_NET_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-fs" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_fs_smoke",
            STARNIX_RUNTIME_FS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-tls" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_tls_smoke",
            STARNIX_RUNTIME_TLS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_elf_smoke",
            STARNIX_DYNAMIC_ELF_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-tls" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_tls_smoke",
            STARNIX_DYNAMIC_TLS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-runtime" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_runtime_smoke",
            STARNIX_DYNAMIC_RUNTIME_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-pie" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_pie_smoke",
            STARNIX_DYNAMIC_PIE_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-glibc-hello" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_glibc_hello",
            STARNIX_GLIBC_HELLO_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-shell" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_busybox_shell",
            STARNIX_SHELL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-net-shell" {
        return run_starnix_remote_shell_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_busybox_socket_shell",
            summary,
        );
    }
    if root.decl.url == "boot://root-net-dataplane" {
        return net::run_root_dataplane();
    }
    if root.decl.url == "boot://root-vmo-shared" {
        return vmo::run_root_shared_source_contract();
    }

    let (provider, provider_startup) = match resolve_root_child(&root, &resolvers, "echo_provider")
    {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let (client, _client_startup) = match resolve_root_child(&root, &resolvers, "echo_client") {
        Ok(component) => {
            summary.resolve_client = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_client = status as i64;
            return 1;
        }
    };

    if root.decl.url == "boot://root" {
        let mut capability_registry = CapabilityRegistry::new();
        let mut outgoing_client = ZX_HANDLE_INVALID;
        let mut outgoing_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut outgoing_client, &mut outgoing_server);
        if status != ZX_OK {
            summary.provider_outgoing_pair = status as i64;
            summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
            write_summary(summary);
            return 1;
        }
        summary.provider_outgoing_pair = ZX_OK as i64;
        write_summary(summary);
        publish_protocols(&provider.decl, &mut capability_registry, outgoing_client);

        let client_namespace = match build_namespace_entries(&client.decl, &mut capability_registry)
        {
            Ok(entries) => {
                summary.client_route = ZX_OK as i64;
                write_summary(summary);
                entries
            }
            Err(status) => {
                summary.client_route = status as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
        };

        let provider_running = match runners.launch(
            &root.decl,
            &provider,
            Vec::new(),
            Some(outgoing_server),
            CHILD_MARKER_PROVIDER,
        ) {
            Ok(running) => {
                summary.provider_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.provider_launch = status as i64;
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                return 1;
            }
        };

        let client_running = match runners.launch(
            &root.decl,
            &client,
            client_namespace,
            None,
            CHILD_MARKER_CLIENT,
        ) {
            Ok(running) => {
                summary.client_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.client_launch = status as i64;
                summary.failure_step = STEP_CLIENT_LAUNCH;
                return 1;
            }
        };

        match read_controller_event_blocking(client_running.controller, ZX_TIME_INFINITE) {
            Ok(return_code) => {
                summary.client_event_read = ZX_OK as i64;
                summary.client_event_code = return_code;
                if return_code != 0 {
                    summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                    return 1;
                }
            }
            Err(status) => {
                summary.client_event_read = status as i64;
                summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                return 1;
            }
        }
        match read_controller_event_blocking(provider_running.controller, ZX_TIME_INFINITE) {
            Ok(return_code) => {
                summary.provider_event_read = ZX_OK as i64;
                summary.provider_event_code = return_code;
                if return_code != 0 {
                    summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                    return 1;
                }
            }
            Err(status) => {
                summary.provider_event_read = status as i64;
                summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                return 1;
            }
        }
        return 0;
    }

    let stop_worker_decl = match resolve_optional_root_child(&root, &resolvers, "stop_worker") {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let kill_worker_decl = match resolve_optional_root_child(&root, &resolvers, "kill_worker") {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_CLIENT_LAUNCH;
            summary.client_launch = status as i64;
            return 1;
        }
    };

    let mut stop_worker = if let Some((component, startup)) = stop_worker_decl {
        if !matches!(startup, StartupMode::Eager) {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = ZX_ERR_BAD_STATE as i64;
            return 1;
        }
        match runners.launch(
            &root.decl,
            &component,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => Some(running),
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                summary.provider_launch = status as i64;
                return 1;
            }
        }
    } else {
        None
    };
    let mut kill_worker = if let Some((component, startup)) = kill_worker_decl {
        if !matches!(startup, StartupMode::Eager) {
            summary.failure_step = STEP_CLIENT_LAUNCH;
            summary.client_launch = ZX_ERR_BAD_STATE as i64;
            return 1;
        }
        match runners.launch(
            &root.decl,
            &component,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => Some(running),
            Err(status) => {
                summary.failure_step = STEP_CLIENT_LAUNCH;
                summary.client_launch = status as i64;
                return 1;
            }
        }
    } else {
        None
    };

    summary.lazy_provider_prelaunch = i64::from(matches!(provider_startup, StartupMode::Eager));

    let (client_running, provider_running) = if matches!(provider_startup, StartupMode::Eager) {
        let mut capability_registry = CapabilityRegistry::new();
        let mut outgoing_client = ZX_HANDLE_INVALID;
        let mut outgoing_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut outgoing_client, &mut outgoing_server);
        if status != ZX_OK {
            summary.provider_outgoing_pair = status as i64;
            summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
            write_summary(summary);
            return 1;
        }
        summary.provider_outgoing_pair = ZX_OK as i64;
        write_summary(summary);
        publish_protocols(&provider.decl, &mut capability_registry, outgoing_client);

        let client_namespace = match build_namespace_entries(&client.decl, &mut capability_registry)
        {
            Ok(entries) => {
                summary.client_route = ZX_OK as i64;
                write_summary(summary);
                entries
            }
            Err(status) => {
                summary.client_route = status as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
        };

        let provider_running = match runners.launch(
            &root.decl,
            &provider,
            Vec::new(),
            Some(outgoing_server),
            CHILD_MARKER_PROVIDER,
        ) {
            Ok(running) => {
                summary.provider_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.provider_launch = status as i64;
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                return 1;
            }
        };

        let client_running = match runners.launch(
            &root.decl,
            &client,
            client_namespace,
            None,
            CHILD_MARKER_CLIENT,
        ) {
            Ok(running) => {
                summary.client_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.client_launch = status as i64;
                summary.failure_step = STEP_CLIENT_LAUNCH;
                return 1;
            }
        };

        (client_running, provider_running)
    } else {
        let mut svc_client = ZX_HANDLE_INVALID;
        let mut svc_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut svc_client, &mut svc_server);
        if status != ZX_OK {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            write_summary(summary);
            return 1;
        }
        summary.client_route = ZX_OK as i64;
        write_summary(summary);

        let client_running = match runners.launch(
            &root.decl,
            &client,
            vec![NamespaceEntry {
                path: String::from(SVC_NAMESPACE_PATH),
                handle: svc_client,
            }],
            None,
            CHILD_MARKER_CLIENT,
        ) {
            Ok(running) => {
                summary.client_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.client_launch = status as i64;
                summary.failure_step = STEP_CLIENT_LAUNCH;
                return 1;
            }
        };

        let first_request = match read_directory_request_for_launch(svc_server) {
            Ok(Some(request)) => request,
            Ok(None) => {
                summary.client_route = ZX_ERR_BAD_STATE as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
            Err(status) => {
                summary.client_route = status as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
        };

        let mut provider_outgoing_client = ZX_HANDLE_INVALID;
        let mut provider_outgoing_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(
            0,
            &mut provider_outgoing_client,
            &mut provider_outgoing_server,
        );
        if status != ZX_OK {
            summary.provider_outgoing_pair = status as i64;
            summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
            write_summary(summary);
            return 1;
        }
        summary.provider_outgoing_pair = ZX_OK as i64;
        write_summary(summary);

        let provider_running = match runners.launch(
            &root.decl,
            &provider,
            Vec::new(),
            Some(provider_outgoing_server),
            CHILD_MARKER_PROVIDER,
        ) {
            Ok(running) => {
                summary.provider_launch = ZX_OK as i64;
                summary.lazy_provider_route_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.provider_launch = status as i64;
                summary.lazy_provider_route_launch = status as i64;
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                return 1;
            }
        };

        if let Err(status) = proxy_directory_requests_until_peer_closed(
            svc_server,
            provider_outgoing_client,
            Some(first_request),
        ) {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            return 1;
        }
        let _ = zx_handle_close(provider_outgoing_client);
        let _ = zx_handle_close(svc_server);

        (client_running, provider_running)
    };

    match read_controller_event_blocking(client_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.client_event_read = ZX_OK as i64;
            summary.client_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = STEP_CLIENT_EVENT;
                return 1;
            }
        }
        Err(status) => {
            summary.client_event_read = status as i64;
            summary.failure_step = STEP_CLIENT_EVENT;
            return 1;
        }
    }
    match read_controller_event_blocking(provider_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = STEP_PROVIDER_EVENT;
                return 1;
            }
        }
        Err(status) => {
            summary.provider_event_read = status as i64;
            summary.failure_step = STEP_PROVIDER_EVENT;
            return 1;
        }
    }

    if let Some(component) = stop_worker.as_mut() {
        match run_controller_lifecycle_step(component, ControllerRequest::Stop) {
            Ok(code) => {
                summary.stop_request = ZX_OK as i64;
                summary.stop_event_read = ZX_OK as i64;
                summary.stop_event_code = code;
            }
            Err(status) => {
                summary.stop_request = status as i64;
                summary.failure_step = STEP_PROVIDER_EVENT;
                return 1;
            }
        }
    }
    if let Some(component) = kill_worker.as_mut() {
        match run_controller_lifecycle_step(component, ControllerRequest::Kill) {
            Ok(code) => {
                summary.kill_request = ZX_OK as i64;
                summary.kill_event_read = ZX_OK as i64;
                summary.kill_event_code = code;
            }
            Err(status) => {
                summary.kill_request = status as i64;
                summary.failure_step = STEP_CLIENT_EVENT;
                return 1;
            }
        }
    }

    0
}

fn run_starnix_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    runners: &RunnerRegistry,
    child_name: &str,
    expected_stdout: &[u8],
    summary: &mut ComponentSummary,
) -> i32 {
    let (child, _startup) = match resolve_root_child(root, resolvers, child_name) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let running = match runners.launch(
        &root.decl,
        &child,
        Vec::new(),
        None,
        CHILD_MARKER_STARNIX_KERNEL,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let return_code = match read_controller_event_blocking(running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            return_code
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_EVENT;
            summary.provider_event_read = status as i64;
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            if let Some(stdout) = running.stdout {
                let _ = zx_handle_close(stdout);
            }
            return 1;
        }
    };
    let stdout = match running.stdout {
        Some(stdout) => stdout,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    match read_socket_to_end(stdout) {
        Ok(bytes) => {
            if return_code != 0 {
                summary.failure_step = STEP_PROVIDER_EVENT;
                write_component_output_prefix(&bytes);
                let _ = zx_handle_close(stdout);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                return 1;
            }
            if bytes != expected_stdout {
                summary.failure_step = STEP_STARNIX_STDOUT;
                write_component_output_prefix(&bytes);
                let _ = zx_handle_close(stdout);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                return 1;
            }
        }
        Err(status) => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            summary.client_route = status as i64;
            let _ = zx_handle_close(stdout);
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    }
    let _ = zx_handle_close(stdout);
    let _ = zx_handle_close(running.status);
    let _ = zx_handle_close(running.controller);
    0
}

fn run_starnix_remote_shell_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    runners: &RunnerRegistry,
    child_name: &str,
    summary: &mut ComponentSummary,
) -> i32 {
    let (child, _startup) = match resolve_root_child(root, resolvers, child_name) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let stdout_mode = if child
        .decl
        .program
        .env
        .iter()
        .any(|entry| entry == "NEXUS_STARNIX_STDIO=channel-tty")
    {
        remote_net::ShellStdoutMode::Channel
    } else {
        remote_net::ShellStdoutMode::Socket
    };
    let running = match runners.launch(
        &root.decl,
        &child,
        Vec::new(),
        None,
        CHILD_MARKER_STARNIX_KERNEL,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let stdout = match running.stdout {
        Some(stdout) => stdout,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            if let Some(stdin) = running.stdin {
                let _ = zx_handle_close(stdin);
            }
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    let stdin = match running.stdin {
        Some(stdin) => stdin,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            let _ = zx_handle_close(stdout);
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    let remote_result =
        match remote_net::run_remote_shell(stdin, stdout, running.controller, stdout_mode) {
            Ok(result) => result,
            Err(status) => {
                summary.failure_step = STEP_STARNIX_STDOUT;
                summary.client_route = status as i64;
                let _ = zx_handle_close(stdin);
                let _ = zx_handle_close(stdout);
                let _ = zx_task_kill(running.process);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                let _ = zx_handle_close(running.process);
                return 1;
            }
        };
    let _ = zx_handle_close(stdin);
    let _ = zx_handle_close(stdout);
    let return_code = match remote_result {
        Some(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            return_code
        }
        None => match read_controller_event_blocking(running.controller, ZX_TIME_INFINITE) {
            Ok(return_code) => {
                summary.provider_event_read = ZX_OK as i64;
                summary.provider_event_code = return_code;
                return_code
            }
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_EVENT;
                summary.provider_event_read = status as i64;
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                let _ = zx_handle_close(running.process);
                return 1;
            }
        },
    };
    let _ = zx_handle_close(running.status);
    let _ = zx_handle_close(running.controller);
    let _ = zx_handle_close(running.process);
    i32::from(return_code != 0)
}

fn read_socket_to_end(handle: zx_handle_t) -> Result<Vec<u8>, zx_status_t> {
    let mut out = Vec::new();
    let mut scratch = [0u8; 128];
    loop {
        let mut actual = 0usize;
        let status = zx_socket_read(handle, 0, scratch.as_mut_ptr(), scratch.len(), &mut actual);
        if status == ZX_OK {
            out.extend_from_slice(&scratch[..actual]);
            continue;
        }
        if status == axle_types::status::ZX_ERR_SHOULD_WAIT {
            let mut observed = 0;
            let wait_status = zx_object_wait_one(
                handle,
                ZX_SOCKET_READABLE | ZX_SOCKET_PEER_CLOSED,
                ZX_TIME_INFINITE,
                &mut observed,
            );
            if wait_status != ZX_OK {
                return Err(wait_status);
            }
            if (observed & ZX_SOCKET_READABLE) != 0 {
                continue;
            }
            if (observed & ZX_SOCKET_PEER_CLOSED) != 0 {
                return Ok(out);
            }
            return Err(axle_types::status::ZX_ERR_BAD_STATE);
        }
        if status == axle_types::status::ZX_ERR_PEER_CLOSED {
            return Ok(out);
        }
        return Err(status);
    }
}

fn write_component_output_prefix(bytes: &[u8]) {
    let prefix_len = core::cmp::min(bytes.len(), COMPONENT_PROVIDER_OUTPUT_WORDS * 8);
    write_slot(SLOT_COMPONENT_PROVIDER_OUTPUT_LEN, prefix_len as u64);
    for index in 0..COMPONENT_PROVIDER_OUTPUT_WORDS {
        let start = index * 8;
        let end = core::cmp::min(start + 8, prefix_len);
        let mut word = [0u8; 8];
        if start < end {
            word[..end - start].copy_from_slice(&bytes[start..end]);
        }
        write_slot(
            SLOT_COMPONENT_PROVIDER_OUTPUT_WORD_BASE + index,
            u64::from_le_bytes(word),
        );
    }
}

fn run_dedicated_child_component(
    bootstrap_channel: zx_handle_t,
    expected_role: MinimalRole,
    child_marker: u64,
) -> ! {
    ROLE.store(ROLE_CHILD, Ordering::Relaxed);
    record_child_stage(child_marker, 1, ZX_OK);
    let _ = run_dedicated_child_component_inner(bootstrap_channel, expected_role, child_marker);
    loop {
        core::hint::spin_loop();
    }
}

fn run_dedicated_child_component_inner(
    bootstrap_channel: zx_handle_t,
    expected_role: MinimalRole,
    child_marker: u64,
) -> i64 {
    let start_info = match read_component_start_info_minimal(bootstrap_channel) {
        Ok(start_info) => start_info,
        Err(status) => {
            record_child_stage(child_marker, 2, status);
            return 1;
        }
    };
    if start_info.role != expected_role {
        record_child_stage(child_marker, 2, ZX_ERR_BAD_STATE);
        return 1;
    }
    record_child_stage(child_marker, 3, ZX_OK);
    let status_channel = start_info.status;
    let controller = start_info.controller;

    let code = match expected_role {
        MinimalRole::Provider => run_echo_provider(&start_info),
        MinimalRole::Client => run_echo_client(&start_info),
        MinimalRole::ControllerWorker => run_controller_worker(&start_info),
        MinimalRole::Unknown => 1,
    };
    record_child_stage(child_marker, 7, code as zx_status_t);
    if let Some(handle) = status_channel {
        let _ = send_status_event(handle, code);
    }
    if let Some(handle) = controller {
        let send_status = send_controller_event(handle, code);
        record_child_stage(child_marker, 8, send_status);
    }
    i64::from(code)
}

fn run_echo_provider(start_info: &lifecycle::MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_PROVIDER, 4, ZX_OK);
    let Some(outgoing) = start_info.outgoing else {
        return 1;
    };
    record_child_stage(CHILD_MARKER_PROVIDER, 5, ZX_OK);
    let code = run_echo_fs_provider(outgoing, ECHO_REQUEST);
    if code == 0 {
        record_child_stage(CHILD_MARKER_PROVIDER, 6, ZX_OK);
    }
    code
}

fn run_echo_client(start_info: &lifecycle::MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_CLIENT, 4, ZX_OK);
    let svc = match start_info.svc {
        Some(handle) => handle,
        None => return 11,
    };
    let mut fd_table = FdTable::new();
    let svc_fd = match fd_table.open(
        Arc::new(RemoteDir::from_descriptor(svc, root_directory_descriptor())),
        OpenFlags::READABLE | OpenFlags::DIRECTORY,
        FdFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return 12,
    };

    let mut mounts = nexus_io::NamespaceTrie::<Arc<dyn FdOps>>::new();
    let svc_mount = match fd_table.get(svc_fd) {
        Some(entry) => Arc::clone(entry.description().ops()),
        None => return 14,
    };
    if mounts.insert(SVC_NAMESPACE_PATH, svc_mount).is_err() {
        return 15;
    }
    let namespace = ProcessNamespace::new(mounts);
    record_child_stage(CHILD_MARKER_CLIENT, 5, ZX_OK);

    let echo = match namespace.open(
        "/svc/nexus.echo.Echo",
        OpenFlags::READABLE | OpenFlags::WRITABLE,
    ) {
        Ok(ops) => ops,
        Err(_) => return 16,
    };
    let echo_fd = match fd_table.open(
        echo,
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return 17,
    };
    let echo_clone_fd = match fd_table.clone_fd(echo_fd, FdFlags::empty()) {
        Ok(fd) => fd,
        Err(_) => return 18,
    };

    if fd_table.write(echo_clone_fd, ECHO_REQUEST).is_err() {
        return 19;
    }
    let mut reply = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let reply_len = match fd_table.read(echo_clone_fd, &mut reply) {
        Ok(actual) => actual,
        Err(_) => return 20,
    };
    record_child_stage(CHILD_MARKER_CLIENT, 6, ZX_OK);
    if &reply[..reply_len] != ECHO_REQUEST {
        return 21;
    }

    let _ = fd_table.close(echo_clone_fd);
    let _ = fd_table.close(echo_fd);
    let _ = fd_table.close(svc_fd);
    0
}

fn run_controller_worker(start_info: &lifecycle::MinimalStartInfo) -> i32 {
    let Some(controller) = start_info.controller else {
        return 1;
    };
    match read_controller_request_blocking(controller, ZX_TIME_INFINITE) {
        Ok(ControllerRequest::Stop) => 0,
        Ok(ControllerRequest::Kill) => 137,
        Err(_) => 1,
    }
}

fn record_child_stage(child_marker: u64, stage: u64, status: zx_status_t) {
    let _ = (child_marker, stage, status);
}

fn write_summary(summary: &ComponentSummary) {
    write_slot(SLOT_COMPONENT_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_COMPONENT_RESOLVE_ROOT, summary.resolve_root as u64);
    write_slot(
        SLOT_COMPONENT_RESOLVE_PROVIDER,
        summary.resolve_provider as u64,
    );
    write_slot(SLOT_COMPONENT_RESOLVE_CLIENT, summary.resolve_client as u64);
    write_slot(
        SLOT_COMPONENT_PROVIDER_OUTGOING_PAIR,
        summary.provider_outgoing_pair as u64,
    );
    write_slot(
        SLOT_COMPONENT_PROVIDER_LAUNCH,
        summary.provider_launch as u64,
    );
    write_slot(SLOT_COMPONENT_CLIENT_ROUTE, summary.client_route as u64);
    write_slot(SLOT_COMPONENT_CLIENT_LAUNCH, summary.client_launch as u64);
    write_slot(
        SLOT_COMPONENT_PROVIDER_EVENT_READ,
        summary.provider_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_PROVIDER_EVENT_CODE,
        summary.provider_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_CLIENT_EVENT_READ,
        summary.client_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_CLIENT_EVENT_CODE,
        summary.client_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_LAZY_PROVIDER_PRELAUNCH,
        summary.lazy_provider_prelaunch as u64,
    );
    write_slot(
        SLOT_COMPONENT_LAZY_PROVIDER_ROUTE_LAUNCH,
        summary.lazy_provider_route_launch as u64,
    );
    write_slot(SLOT_COMPONENT_STOP_REQUEST, summary.stop_request as u64);
    write_slot(
        SLOT_COMPONENT_STOP_EVENT_READ,
        summary.stop_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_STOP_EVENT_CODE,
        summary.stop_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_STOP_WAIT_OBSERVED,
        summary.stop_wait_observed,
    );
    write_slot(SLOT_COMPONENT_KILL_REQUEST, summary.kill_request as u64);
    write_slot(
        SLOT_COMPONENT_KILL_EVENT_READ,
        summary.kill_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_KILL_EVENT_CODE,
        summary.kill_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_KILL_WAIT_OBSERVED,
        summary.kill_wait_observed,
    );
}

pub(crate) fn read_slot(index: usize) -> u64 {
    // SAFETY: the kernel maps one shared result page at `USER_SHARED_BASE` for
    // the bootstrap userspace runner, and all indices in this file are within
    // the fixed slot table exported by `kernel/axle-kernel/src/userspace.rs`.
    unsafe { slot_ptr(index).read_volatile() }
}

pub(crate) fn write_slot(index: usize, value: u64) {
    // SAFETY: the kernel-owned shared result page is writable by the bootstrap
    // userspace runner for these fixed diagnostic slots.
    unsafe { slot_ptr(index).write_volatile(value) }
}

fn slot_ptr(index: usize) -> *mut u64 {
    (USER_SHARED_BASE as *mut u64).wrapping_add(index)
}
