//! Minimal `nexus-init` bootstrap userspace binary and shared manager logic.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod assets;
mod fs;
mod lifecycle;
mod namespace;
mod net;
mod orchestrator;
mod remote_net;
mod resolver;
mod runner;
mod services;
mod starnix;
mod vmo;

use core::fmt::{self, Write as _};
#[cfg(not(test))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_types::zx_handle_t;
#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

pub(crate) use crate::assets::*;

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

const ROLE_NONE: usize = 0;
const ROLE_ROOT: usize = 1;
const ROLE_CHILD: usize = 2;

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

pub fn program_start(bootstrap_channel: zx_handle_t, arg1: u64) -> ! {
    init_heap_once();
    if arg1 == CHILD_MARKER_STARNIX_KERNEL {
        ROLE.store(ROLE_CHILD, Ordering::Relaxed);
        starnix::starnix_kernel_program_start(bootstrap_channel);
    }
    let _ = bootstrap_channel;
    ROLE.store(ROLE_ROOT, Ordering::Relaxed);
    let mut summary = orchestrator::ComponentSummary::bootstrap();
    orchestrator::write_summary(&summary);
    summary.failure_step = 0;
    let status = orchestrator::run_component_manager(&mut summary);
    orchestrator::write_summary(&summary);
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
        orchestrator::report_root_panic(prefix.as_bytes())
    }
    loop {
        core::hint::spin_loop();
    }
}

pub fn report_panic() -> ! {
    if ROLE.load(Ordering::Relaxed) == ROLE_ROOT {
        orchestrator::report_root_panic(b"panic")
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Start the dedicated `echo-provider` component image.
pub fn echo_provider_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    orchestrator::run_dedicated_child_component(
        bootstrap_channel,
        lifecycle::MinimalRole::Provider,
        CHILD_MARKER_PROVIDER,
    )
}

/// Start the dedicated `echo-client` component image.
pub fn echo_client_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    orchestrator::run_dedicated_child_component(
        bootstrap_channel,
        lifecycle::MinimalRole::Client,
        CHILD_MARKER_CLIENT,
    )
}

/// Start the dedicated `controller-worker` component image.
pub fn controller_worker_program_start(bootstrap_channel: zx_handle_t) -> ! {
    init_heap_once();
    orchestrator::run_dedicated_child_component(
        bootstrap_channel,
        lifecycle::MinimalRole::ControllerWorker,
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
