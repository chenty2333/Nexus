//! Minimal `nexus-init` bootstrap userspace binary and shared manager logic.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod fs;
mod lifecycle;
mod namespace;
mod resolver;
mod runner;
mod services;
mod starnix;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE};
use axle_types::status::{ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_NOT_FOUND, ZX_OK};
use axle_types::{zx_handle_t, zx_status_t};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_create, zx_handle_close, zx_object_wait_one, zx_socket_read,
};
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
const USER_CODE_PAGE_COUNT: u64 = 1024;
const USER_CODE_BASE: u64 = 0x0000_0001_0000_0000;
const USER_SHARED_BASE: u64 = USER_CODE_BASE + (USER_PAGE_BYTES * USER_CODE_PAGE_COUNT);
const SLOT_OK: usize = 0;
const SLOT_SELF_PROCESS_H: usize = 396;
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

pub(crate) const CHILD_ROLE_PROVIDER: &str = "echo-provider";
pub(crate) const CHILD_ROLE_CLIENT: &str = "echo-client";
pub(crate) const CHILD_ROLE_CONTROLLER_WORKER: &str = "controller-worker";
const ROOT_COMPONENT_URL: &str = env!("NEXUS_INIT_ROOT_URL");
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
pub(crate) const MAX_BOOTSTRAP_MESSAGE_BYTES: usize = 512;
pub(crate) const MAX_BOOTSTRAP_MESSAGE_HANDLES: usize = 8;
pub(crate) const MAX_SMALL_CHANNEL_BYTES: usize = 128;
pub(crate) const MAX_SMALL_CHANNEL_HANDLES: usize = 1;
const STARNIX_HELLO_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\n";
const STARNIX_FD_SMOKE_EXPECTED_STDOUT: &[u8] = b"pipe\nsock\n";
const STARNIX_ROUND2_EXPECTED_STDOUT: &[u8] = b"round2 ok\n";
const STARNIX_ROUND3_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\nround3 ok\n";
const STARNIX_ROUND4_FUTEX_EXPECTED_STDOUT: &[u8] = b"round4 futex ok\n";
const STARNIX_ROUND4_SIGNAL_EXPECTED_STDOUT: &[u8] = b"round4 signal ok\n";
const STARNIX_ROUND5_EPOLL_EXPECTED_STDOUT: &[u8] = b"round5 epoll ok\n";

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

const HEAP_BYTES: usize = 512 * 1024;
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static ROLE: AtomicUsize = AtomicUsize::new(ROLE_NONE);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// SAFETY: this allocator serves the single-threaded bootstrap component smoke in
// one process at a time. Allocations come from one fixed static buffer,
// deallocation is a no-op, and alignment is preserved by monotonic bumping.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(size) else {
                return core::ptr::null_mut();
            };
            if next > HEAP_BYTES {
                return core::ptr::null_mut();
            }
            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: `HEAP` is the dedicated backing storage for this bump allocator.
                    // Allocation is serialized by the atomic bump pointer, and callers only
                    // receive disjoint regions within this static buffer.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

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

pub fn report_panic() -> ! {
    if ROLE.load(Ordering::Relaxed) == ROLE_ROOT {
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
    run_dedicated_child_component(
        bootstrap_channel,
        MinimalRole::Provider,
        CHILD_MARKER_PROVIDER,
    )
}

/// Start the dedicated `echo-client` component image.
pub fn echo_client_program_start(bootstrap_channel: zx_handle_t) -> ! {
    run_dedicated_child_component(bootstrap_channel, MinimalRole::Client, CHILD_MARKER_CLIENT)
}

/// Start the dedicated `controller-worker` component image.
pub fn controller_worker_program_start(bootstrap_channel: zx_handle_t) -> ! {
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
                let _ = zx_handle_close(stdout);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                return 1;
            }
            if bytes != expected_stdout {
                summary.failure_step = STEP_STARNIX_STDOUT;
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

fn read_slot(index: usize) -> u64 {
    // SAFETY: the kernel maps one shared result page at `USER_SHARED_BASE` for
    // the bootstrap userspace runner, and all indices in this file are within
    // the fixed slot table exported by `kernel/axle-kernel/src/userspace.rs`.
    unsafe { slot_ptr(index).read_volatile() }
}

fn write_slot(index: usize, value: u64) {
    // SAFETY: the kernel-owned shared result page is writable by the bootstrap
    // userspace runner for these fixed diagnostic slots.
    unsafe { slot_ptr(index).write_volatile(value) }
}

fn slot_ptr(index: usize) -> *mut u64 {
    (USER_SHARED_BASE as *mut u64).wrapping_add(index)
}
