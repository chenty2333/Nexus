//! Minimal ring3 bring-up for the userspace conformance runner.
//!
//! This is intentionally a bootstrap bridge:
//! - single address space (kernel + one userspace image mapped into same CR3)
//! - userspace calls syscalls via `int 0x80`
//! - userspace signals completion via `int3`
//!
//! The immediate purpose is to force correctness work in:
//! - copyin/copyout validation
//! - user pointer boundaries
//! - ring3 -> ring0 transitions (TSS/RSP0)

extern crate alloc;

use alloc::vec::Vec;
use axle_types::status::{
    ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE,
};
use axle_types::zx_status_t;
use x86_64::instructions::segmentation::Segment;

// --- Userspace virtual layout (in current single-address-space model) ---

pub(crate) const USER_PAGE_BYTES: u64 = 0x1000;
pub(crate) const USER_CODE_PAGE_COUNT: usize = 4096;
const USER_SHARED_PAGE_COUNT: usize = 2;
pub(crate) const USER_STACK_PAGE_COUNT: usize = 16;
pub(crate) const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * USER_CODE_PAGE_COUNT as u64;
const USER_SHARED_BYTES: u64 = USER_PAGE_BYTES * USER_SHARED_PAGE_COUNT as u64;
pub(crate) const USER_STACK_BYTES: u64 = USER_PAGE_BYTES * USER_STACK_PAGE_COUNT as u64;
pub(crate) const USER_CODE_VA: u64 = 0x0000_0001_0000_0000; // 4 GiB
pub(crate) const USER_WINDOW_TOP: u64 = 0x0000_8000_0000_0000; // lower canonical half limit
pub(crate) const USER_REGION_BYTES: u64 = USER_WINDOW_TOP - USER_CODE_VA;
const BOOTSTRAP_USER_PT_ENTRY_COUNT: usize = 512;
const BOOTSTRAP_USER_PAGE_COUNT: usize =
    USER_CODE_PAGE_COUNT + USER_SHARED_PAGE_COUNT + USER_STACK_PAGE_COUNT;
pub(crate) const BOOTSTRAP_USER_PT_COUNT: usize =
    BOOTSTRAP_USER_PAGE_COUNT.div_ceil(BOOTSTRAP_USER_PT_ENTRY_COUNT);
pub(crate) const BOOTSTRAP_USER_PT_BYTES: u64 =
    USER_PAGE_BYTES * BOOTSTRAP_USER_PT_ENTRY_COUNT as u64;
pub(crate) const USER_SHARED_VA: u64 = USER_CODE_VA + USER_CODE_BYTES;
pub(crate) const USER_STACK_VA: u64 = USER_SHARED_VA + USER_SHARED_BYTES;
const USER_STACK_TOP: u64 = USER_STACK_VA + USER_STACK_BYTES;
pub(crate) const USER_VM_TEST_VA: u64 = USER_CODE_VA + 0x10_000;

// --- QEMU loader handoff for external userspace runner ELF ---
//
// Conformance harness uses `-device loader,file=...,addr=...` to drop the ELF bytes
// into guest RAM, plus a second loader device to write the byte length.
#[derive(Clone, Copy)]
struct QemuLoaderImage {
    paddr: u64,
    size_paddr: u64,
}

const USER_RUNNER_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0700_0000,
    size_paddr: 0x0700_0000 - 8,
};
const ECHO_PROVIDER_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0200_0000,
    size_paddr: 0x0200_0000 - 8,
};
const ECHO_CLIENT_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0300_0000,
    size_paddr: 0x0300_0000 - 8,
};
const CONTROLLER_WORKER_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0400_0000,
    size_paddr: 0x0400_0000 - 8,
};
const STARNIX_KERNEL_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0500_0000,
    size_paddr: 0x0500_0000 - 8,
};
const LINUX_HELLO_IMAGE: QemuLoaderImage = QemuLoaderImage {
    paddr: 0x0600_0000,
    size_paddr: 0x0600_0000 - 8,
};
// Raw QEMU loader input is the full ELF file, including debug sections in
// dev builds. Keep this bound separate from the mapped code window size.
const USER_RUNNER_ELF_MAX_BYTES: usize = 16 * 1024 * 1024;

// --- Shared summary slots (u64) written by userspace ---

const SLOT_OK: usize = 0;

// Match the existing kernel bring-up summary keys so `specs/conformance/scenarios/*.toml`
// don't need churn when we move execution from ring0 to ring3.
const SLOT_UNKNOWN: usize = 1;
const SLOT_CLOSE_INVALID: usize = 2;
const SLOT_PORT_CREATE_BAD_OPTS: usize = 3;
const SLOT_PORT_CREATE_NULL_OUT: usize = 4;
const SLOT_BAD_WAIT: usize = 5;
const SLOT_PORT_WAIT_NULL_OUT: usize = 6;
const SLOT_EMPTY_WAIT: usize = 7;
const SLOT_PORT_QUEUE_NULL_PKT: usize = 8;
const SLOT_PORT_QUEUE_BAD_TYPE: usize = 9;
const SLOT_QUEUE: usize = 10;
const SLOT_WAIT: usize = 11;
const SLOT_TIMER_CREATE_BAD_OPTS: usize = 12;
const SLOT_TIMER_CREATE_BAD_CLOCK: usize = 13;
const SLOT_TIMER_CREATE_NULL_OUT: usize = 14;
const SLOT_PORT_WAIT_WRONG_TYPE: usize = 15;
const SLOT_PORT_QUEUE_WRONG_TYPE: usize = 16;
const SLOT_TIMER_SET_WRONG_TYPE: usize = 17;
const SLOT_TIMER_CANCEL_WRONG_TYPE: usize = 18;
const SLOT_WAIT_ONE_UNSIGNALED: usize = 19;
const SLOT_WAIT_ONE_UNSIGNALED_OBS: usize = 20;
const SLOT_WAIT_ASYNC: usize = 21;
const SLOT_TIMER_SET_IMMEDIATE: usize = 22;
const SLOT_WAIT_SIGNAL: usize = 23;
const SLOT_SIGNAL_TRIGGER: usize = 24;
const SLOT_SIGNAL_OBSERVED: usize = 25;
const SLOT_SIGNAL_COUNT: usize = 26;
const SLOT_WAIT_ONE_SIGNALED: usize = 27;
const SLOT_WAIT_ONE_SIGNALED_OBS: usize = 28;
const SLOT_TIMER_SET: usize = 29;
const SLOT_TIMER_CANCEL: usize = 30;
const SLOT_TIMER_CLOSE: usize = 31;
const SLOT_TIMER_CLOSE_AGAIN: usize = 32;
const SLOT_CLOSE: usize = 33;
const SLOT_CLOSE_AGAIN: usize = 34;
const SLOT_PORT_H: usize = 35;
const SLOT_TIMER_H: usize = 36;
const SLOT_WAIT_ONE_FUTURE_TIMEOUT: usize = 37;
const SLOT_WAIT_ONE_FUTURE_TIMEOUT_OBS: usize = 38;
const SLOT_WAIT_ONE_FUTURE_OK: usize = 39;
const SLOT_WAIT_ONE_FUTURE_OK_OBS: usize = 40;
const SLOT_WAIT_ASYNC_BAD_OPTIONS: usize = 41;
const SLOT_WAIT_ASYNC_TS: usize = 42;
const SLOT_WAIT_SIGNAL_TS: usize = 43;
const SLOT_SIGNAL_TIMESTAMP: usize = 44;
const SLOT_SIGNAL_TIMESTAMP_OK: usize = 45;
const SLOT_WAIT_ASYNC_BOOT: usize = 46;
const SLOT_WAIT_SIGNAL_BOOT: usize = 47;
const SLOT_SIGNAL_BOOT_TIMESTAMP: usize = 48;
const SLOT_SIGNAL_BOOT_TIMESTAMP_OK: usize = 49;
const SLOT_EDGE_WAIT_ASYNC: usize = 50;
const SLOT_EDGE_EMPTY_WAIT: usize = 51;
const SLOT_EDGE_SIGNAL_WAIT: usize = 52;
const SLOT_EDGE_SIGNAL_KEY: usize = 53;
const SLOT_RESERVE_QUEUE_FULL: usize = 54;
const SLOT_RESERVE_WAIT_ASYNC: usize = 55;
const SLOT_RESERVE_SIGNAL_AFTER_USERS_OK: usize = 56;
const SLOT_RESERVE_SIGNAL_TYPE: usize = 57;
const SLOT_PENDING_WAIT_ASYNC: usize = 58;
const SLOT_PENDING_SIGNAL_WAIT: usize = 59;
const SLOT_PENDING_SIGNAL_COUNT: usize = 60;
const SLOT_PENDING_MERGE_OK: usize = 61;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_VMO_CREATE_BAD_OPTS: usize = 63;
const SLOT_VMO_CREATE_NULL_OUT: usize = 64;
const SLOT_VMO_CREATE: usize = 65;
const SLOT_VMO_H: usize = 66;
const SLOT_VMAR_MAP_BAD_TYPE: usize = 67;
const SLOT_VMAR_MAP_BAD_OPTS: usize = 68;
const SLOT_VMAR_MAP: usize = 69;
const SLOT_VMAR_MAP_ADDR: usize = 70;
const SLOT_VMAR_MAP_WRITE_OK: usize = 71;
const SLOT_VMAR_OVERLAP: usize = 72;
const SLOT_VMAR_PROTECT: usize = 73;
const SLOT_VMAR_REPROTECT: usize = 74;
const SLOT_VMAR_UNMAP: usize = 75;
const SLOT_VMAR_REMAP: usize = 76;
const SLOT_CHANNEL_CREATE_BAD_OPTS: usize = 77;
const SLOT_CHANNEL_CREATE_NULL_OUT0: usize = 78;
const SLOT_CHANNEL_CREATE_NULL_OUT1: usize = 79;
const SLOT_CHANNEL_CREATE: usize = 80;
const SLOT_CHANNEL_H0: usize = 81;
const SLOT_CHANNEL_H1: usize = 82;
const SLOT_CHANNEL_READ_EMPTY: usize = 83;
const SLOT_CHANNEL_WRITE: usize = 84;
const SLOT_CHANNEL_WAIT_READABLE: usize = 85;
const SLOT_CHANNEL_WAIT_READABLE_OK: usize = 86;
const SLOT_CHANNEL_READ: usize = 87;
const SLOT_CHANNEL_READ_ACTUAL_BYTES: usize = 88;
const SLOT_CHANNEL_READ_ACTUAL_HANDLES: usize = 89;
const SLOT_CHANNEL_READ_MATCH: usize = 90;
const SLOT_CHANNEL_CLOSE_PEER: usize = 91;
const SLOT_CHANNEL_WRITE_PEER_CLOSED: usize = 92;
const SLOT_CHANNEL_READ_PEER_CLOSED: usize = 93;
const SLOT_CHANNEL_WAIT_PEER_CLOSED: usize = 94;
const SLOT_CHANNEL_WAIT_PEER_CLOSED_OBS: usize = 95;
const SLOT_EVENTPAIR_CREATE_BAD_OPTS: usize = 96;
const SLOT_EVENTPAIR_CREATE_NULL_OUT0: usize = 97;
const SLOT_EVENTPAIR_CREATE_NULL_OUT1: usize = 98;
const SLOT_EVENTPAIR_CREATE: usize = 99;
const SLOT_EVENTPAIR_H0: usize = 100;
const SLOT_EVENTPAIR_H1: usize = 101;
const SLOT_EVENTPAIR_SIGNAL_BAD_MASK: usize = 102;
const SLOT_EVENTPAIR_SIGNAL_PEER: usize = 103;
const SLOT_EVENTPAIR_WAIT_SIGNAL: usize = 104;
const SLOT_EVENTPAIR_WAIT_SIGNAL_OBS: usize = 105;
const SLOT_EVENTPAIR_CLOSE_PEER: usize = 106;
const SLOT_EVENTPAIR_WAIT_PEER_CLOSED: usize = 107;
const SLOT_EVENTPAIR_WAIT_PEER_CLOSED_OBS: usize = 108;
const SLOT_CHANNEL_LOAN_TX_VMO_CREATE: usize = 109;
const SLOT_CHANNEL_LOAN_TX_MAP: usize = 110;
const SLOT_CHANNEL_LOAN_RX_VMO_CREATE: usize = 111;
const SLOT_CHANNEL_LOAN_RX_MAP: usize = 112;
const SLOT_CHANNEL_LOAN_CREATE: usize = 113;
const SLOT_CHANNEL_LOAN_WRITE: usize = 114;
const SLOT_CHANNEL_LOAN_READ: usize = 115;
const SLOT_CHANNEL_LOAN_ACTUAL_BYTES: usize = 116;
const SLOT_CHANNEL_LOAN_SNAPSHOT_OK: usize = 117;
const SLOT_HANDLE_DUPLICATE: usize = 118;
const SLOT_HANDLE_DUPLICATE_DISTINCT: usize = 119;
const SLOT_HANDLE_DUPLICATE_SIGNAL: usize = 120;
const SLOT_HANDLE_DUPLICATE_WAIT: usize = 121;
const SLOT_HANDLE_DUPLICATE_WAIT_OBS: usize = 122;
const SLOT_HANDLE_DUP_REDUCED: usize = 123;
const SLOT_HANDLE_DUP_REDUCED_DENIED: usize = 124;
const SLOT_HANDLE_REPLACE: usize = 125;
const SLOT_HANDLE_REPLACE_OLD_BAD: usize = 126;
const SLOT_HANDLE_REPLACE_SIGNAL: usize = 127;
const SLOT_HANDLE_REPLACE_WAIT: usize = 128;
const SLOT_HANDLE_REPLACE_WAIT_OBS: usize = 129;
const SLOT_OBJECT_SIGNAL_BAD_MASK: usize = 130;
const SLOT_OBJECT_SIGNAL_WAIT_ASYNC: usize = 131;
const SLOT_OBJECT_SIGNAL_SELF: usize = 132;
const SLOT_OBJECT_SIGNAL_PORT_WAIT: usize = 133;
const SLOT_OBJECT_SIGNAL_KEY: usize = 134;
const SLOT_SELF_THREAD_H: usize = 135;
const SLOT_FUTEX_WAIT_BAD_STATE: usize = 136;
const SLOT_FUTEX_WAIT_SELF_OWNER: usize = 137;
const SLOT_FUTEX_WAIT_TIMEOUT: usize = 138;
const SLOT_FUTEX_GET_OWNER_INITIAL: usize = 139;
const SLOT_FUTEX_OWNER_INITIAL: usize = 140;
const SLOT_FUTEX_GET_OWNER_TIMEOUT: usize = 141;
const SLOT_FUTEX_OWNER_TIMEOUT: usize = 142;
const SLOT_FUTEX_REQUEUE_SAME_KEY: usize = 143;
const SLOT_FUTEX_REQUEUE_WRONG_TYPE: usize = 144;
const SLOT_FUTEX_REQUEUE_OK: usize = 145;
const SLOT_FUTEX_GET_OWNER_REQUEUE: usize = 146;
const SLOT_FUTEX_OWNER_MATCH_SELF: usize = 147;
const SLOT_FUTEX_WAKE_ZERO: usize = 148;
const SLOT_FUTEX_GET_OWNER_WAKE: usize = 149;
const SLOT_FUTEX_OWNER_WAKE: usize = 150;
const SLOT_SELF_THREAD_KOID: usize = 151;
const SLOT_CHANNEL_TRANSFER_CREATE: usize = 152;
const SLOT_CHANNEL_TRANSFER_EVENTPAIR_CREATE: usize = 153;
const SLOT_CHANNEL_TRANSFER_WRITE: usize = 154;
const SLOT_CHANNEL_TRANSFER_CLOSE_OLD: usize = 155;
const SLOT_CHANNEL_TRANSFER_READ: usize = 156;
const SLOT_CHANNEL_TRANSFER_ACTUAL_BYTES: usize = 157;
const SLOT_CHANNEL_TRANSFER_ACTUAL_HANDLES: usize = 158;
const SLOT_CHANNEL_TRANSFER_SIGNAL: usize = 159;
const SLOT_CHANNEL_TRANSFER_WAIT: usize = 160;
const SLOT_CHANNEL_TRANSFER_WAIT_OBS: usize = 161;
const SLOT_TASK_KILL_PROCESS: usize = 162;
const SLOT_TASK_KILL_THREAD_CREATE_AFTER: usize = 163;
const SLOT_TASK_SUSPEND_PROCESS: usize = 164;
const SLOT_TASK_SUSPEND_TOKEN_PRESENT: usize = 165;
const SLOT_TASK_SUSPEND_CLOSE_TOKEN: usize = 166;
const SLOT_TASK_SUSPEND_RESUMED: usize = 167;
const SLOT_TASK_SUSPEND_HELD: usize = 168;
const SLOT_TASK_SUSPEND_READY: usize = 169;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_THREAD_CREATE: usize = 397;
const SLOT_THREAD_START: usize = 398;
const SLOT_THREAD_CHILD_RAN: usize = 399;
const SLOT_THREAD_FUTEX_WAIT: usize = 400;
const SLOT_THREAD_WAKE_STATUS: usize = 401;
const SLOT_THREAD_RESUMED: usize = 402;
const SLOT_THREAD_WORK_CMD: usize = 403;
const SLOT_THREAD_WORK_ARG0: usize = 404;
const SLOT_THREAD_WAIT_ONE: usize = 405;
const SLOT_THREAD_WAIT_ONE_OBS: usize = 406;
const SLOT_THREAD_SIGNAL_STATUS: usize = 407;
const SLOT_THREAD_PORT_WAIT: usize = 408;
const SLOT_THREAD_PORT_PACKET_KEY: usize = 409;
const SLOT_THREAD_PORT_PACKET_TYPE: usize = 410;
const SLOT_THREAD_PORT_QUEUE_STATUS: usize = 411;
pub(crate) const SLOT_VM_COW_FAULT_COUNT: usize = 412;
const SLOT_CHANNEL_LOAN_REMAP_COW_OK: usize = 413;
const SLOT_CHANNEL_CLOSE_READ_CREATE: usize = 414;
const SLOT_CHANNEL_CLOSE_READ_WRITE: usize = 415;
const SLOT_CHANNEL_CLOSE_READ_CLOSE: usize = 416;
const SLOT_CHANNEL_CLOSE_READ_WAIT: usize = 417;
const SLOT_CHANNEL_CLOSE_READ_WAIT_OBS: usize = 418;
const SLOT_CHANNEL_LOAN_REMAP_SOURCE_RMAP_COUNT: usize = 419;
const SLOT_CHANNEL_CLOSE_READ_STATUS: usize = 323;
const SLOT_CHANNEL_CLOSE_READ_ACTUAL_BYTES: usize = 324;
const SLOT_CHANNEL_CLOSE_READ_MATCH: usize = 325;
const SLOT_CHANNEL_CLOSE_DRAIN_WAIT: usize = 326;
const SLOT_CHANNEL_CLOSE_DRAIN_WAIT_OBS: usize = 327;
const SLOT_CHANNEL_CLOSE_DRAIN_READ: usize = 328;
const SLOT_CHANNEL_WRITABLE_RECOVERY_CREATE: usize = 329;
const SLOT_CHANNEL_WRITABLE_RECOVERY_FILL: usize = 330;
const SLOT_CHANNEL_WRITABLE_RECOVERY_FULL_WRITE: usize = 331;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_FULL: usize = 332;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_FULL_OBS: usize = 333;
const SLOT_CHANNEL_WRITABLE_RECOVERY_READ: usize = 334;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_RESTORED: usize = 335;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_RESTORED_OBS: usize = 336;
const SLOT_CHANNEL_WRITABLE_RECOVERY_CLOSE: usize = 337;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_CLOSED: usize = 338;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_CLOSED_OBS: usize = 339;
const SLOT_CHANNEL_WRITABLE_RECOVERY_WRITE_CLOSED: usize = 340;
const SLOT_VM_LAST_REMAP_SOURCE_RMAP_COUNT: usize = 341;
const SLOT_VM_LAST_COW_OLD_RMAP_COUNT: usize = 342;
const SLOT_VM_LAST_COW_NEW_RMAP_COUNT: usize = 343;
const SLOT_PROCESS_CREATE: usize = 344;
const SLOT_PROCESS_MAP_PARENT_CODE: usize = 345;
const SLOT_PROCESS_MAP_PARENT_SHARED: usize = 346;
const SLOT_PROCESS_MAP_CHILD_CODE: usize = 347;
const SLOT_PROCESS_MAP_CHILD_SHARED: usize = 348;
const SLOT_PROCESS_MAP_CHILD_STACK: usize = 349;
const SLOT_PROCESS_THREAD_CREATE: usize = 350;
const SLOT_PROCESS_START: usize = 351;
const SLOT_PROCESS_CHILD_RAN: usize = 352;
const SLOT_PROCESS_PARENT_FUTEX_WAIT: usize = 353;
const SLOT_VMAR_FAR_VMO_CREATE: usize = 354;
const SLOT_VMAR_FAR_MAP: usize = 355;
const SLOT_VMAR_FAR_MAP_ADDR: usize = 356;
const SLOT_VMAR_FAR_WRITE_OK: usize = 357;
const SLOT_VMAR_FAR_UNMAP: usize = 358;
const SLOT_VMAR_ALLOCATE_BAD_TYPE: usize = 359;
const SLOT_VMAR_ALLOCATE_BAD_OPTS: usize = 360;
const SLOT_VMAR_ALLOCATE: usize = 361;
const SLOT_VMAR_ALLOCATE_HANDLE_OK: usize = 362;
const SLOT_VMAR_ALLOCATE_ADDR_NONZERO: usize = 363;
const SLOT_VMAR_ALLOCATE_MAP: usize = 364;
const SLOT_VMAR_ALLOCATE_MAP_MATCH: usize = 365;
const SLOT_VMAR_ALLOCATE_NO_SPECIFIC: usize = 366;
const SLOT_VMAR_ALLOCATE_SPECIFIC_DENIED: usize = 367;
const SLOT_VMAR_ALLOCATE_NONSPECIFIC_MAP: usize = 368;
const SLOT_VMAR_ALLOCATE_NONSPECIFIC_MATCH: usize = 369;
const SLOT_VMAR_DESTROY: usize = 370;
const SLOT_VMAR_DESTROY_REMAP: usize = 371;
const SLOT_VMAR_ALLOCATE_GRANDCHILD: usize = 372;
const SLOT_VMAR_ALLOCATE_GRANDCHILD_MATCH: usize = 373;
const SLOT_VMAR_ALLOCATE_GRANDCHILD_MAP: usize = 374;
const SLOT_VMAR_ALLOCATE_GRANDCHILD_MAP_MATCH: usize = 375;
const SLOT_VMAR_ALLOCATE_UPPER_LIMIT: usize = 376;
const SLOT_VMAR_ALLOCATE_UPPER_LIMIT_MATCH: usize = 377;
const SLOT_VMAR_ALLOCATE_GRANDCHILD_COMPACT: usize = 378;
const SLOT_VMAR_ALLOCATE_GRANDCHILD_COMPACT_MATCH: usize = 379;
const SLOT_VMAR_ALLOCATE_ALIGN: usize = 380;
const SLOT_VMAR_ALLOCATE_ALIGN_OK: usize = 381;
const SLOT_VMAR_ALLOCATE_SPECIFIC_ALIGN_BAD: usize = 382;
const SLOT_PROCESS_MAP_PARENT_LAZY_SHARED: usize = 383;
const SLOT_PROCESS_MAP_CHILD_LAZY_SHARED: usize = 384;
const SLOT_PROCESS_LAZY_SHARED_MATCH: usize = 385;
const SLOT_VM_PRIVATE_COW_PAGES_CURRENT: usize = 386;
const SLOT_VM_PRIVATE_COW_PAGES_PEAK: usize = 387;
const SLOT_VM_PRIVATE_COW_QUOTA_HITS: usize = 388;
const SLOT_VM_INFLIGHT_LOAN_PAGES_CURRENT: usize = 389;
const SLOT_VM_INFLIGHT_LOAN_PAGES_PEAK: usize = 390;
const SLOT_VM_INFLIGHT_LOAN_QUOTA_HITS: usize = 391;
const SLOT_CHANNEL_LOAN_QUOTA_FILL: usize = 392;
const SLOT_CHANNEL_LOAN_QUOTA_WRITE_LIMIT: usize = 393;
const SLOT_CHANNEL_LOAN_QUOTA_READ: usize = 394;
const SLOT_CHANNEL_LOAN_QUOTA_WRITE_RECOVER: usize = 395;
const SLOT_VM_FAULT_LEADER_CLAIMS: usize = 420;
const SLOT_VM_FAULT_WAIT_CLAIMS: usize = 421;
const SLOT_VM_FAULT_WAIT_SPIN_LOOPS: usize = 422;
const SLOT_VM_FAULT_RETRY_TOTAL: usize = 423;
const SLOT_VM_FAULT_COMMIT_RESOLVED: usize = 424;
const SLOT_VM_FAULT_COMMIT_RETRY: usize = 425;
const SLOT_VM_FAULT_PREPARE_COW: usize = 426;
const SLOT_VM_FAULT_PREPARE_LAZY_ANON: usize = 427;
const SLOT_VM_FAULT_PREPARE_LAZY_VMO_ALLOC: usize = 428;
const SLOT_TIMER_WAIT_FOREVER: usize = 429;
const SLOT_TIMER_WAIT_FOREVER_OBS: usize = 430;
const SLOT_VM_FAULT_TEST_HOOK_ARM: usize = 431;
const SLOT_VM_FAULT_LOCAL_WAIT_OK: usize = 432;
const SLOT_VM_FAULT_SHARED_WAIT_OK: usize = 433;
const SLOT_VM_FAULT_LOCAL_DONE: usize = 434;
const SLOT_VM_FAULT_SHARED_DONE: usize = 435;
const SLOT_TASK_WAIT_THREAD_TERMINATED: usize = 436;
const SLOT_TASK_WAIT_THREAD_TERMINATED_OBS: usize = 437;
const SLOT_TASK_WAIT_PROCESS_TERMINATED: usize = 438;
const SLOT_TASK_WAIT_PROCESS_TERMINATED_OBS: usize = 439;
const SLOT_TASK_REAP_CLOSE_THREAD: usize = 440;
const SLOT_TASK_REAP_CLOSE_PROCESS: usize = 441;
const SLOT_PORT_WAIT_WRITABLE: usize = 442;
const SLOT_PORT_WAIT_WRITABLE_OBS: usize = 443;
const SLOT_PORT_WAIT_READABLE: usize = 444;
const SLOT_PORT_WAIT_READABLE_OBS: usize = 445;
const SLOT_VMO_RW_CREATE: usize = 446;
const SLOT_VMO_WRITE: usize = 447;
const SLOT_VMO_READ: usize = 448;
const SLOT_VMO_READ_MATCH: usize = 449;
const SLOT_VMO_SET_SIZE_GROW: usize = 450;
const SLOT_VMO_SET_SIZE_MAP: usize = 451;
const SLOT_VMO_SET_SIZE_MAP_MATCH: usize = 452;
const SLOT_VMO_SET_SIZE_SHRINK_BUSY: usize = 453;
const SLOT_VMO_SET_SIZE_SHRINK: usize = 454;
const SLOT_VMO_WRITE_OUT_OF_RANGE: usize = 455;
const SLOT_SOCKET_CREATE: usize = 456;
const SLOT_SOCKET_WAIT_WRITABLE: usize = 457;
const SLOT_SOCKET_WAIT_WRITABLE_OBS: usize = 458;
const SLOT_SOCKET_WRITE: usize = 459;
const SLOT_SOCKET_WAIT_READABLE: usize = 460;
const SLOT_SOCKET_WAIT_READABLE_OBS: usize = 461;
const SLOT_SOCKET_PEEK: usize = 462;
const SLOT_SOCKET_PEEK_MATCH: usize = 463;
const SLOT_SOCKET_READ: usize = 464;
const SLOT_SOCKET_READ_MATCH: usize = 465;
const SLOT_SOCKET_CLOSE_PEER: usize = 466;
const SLOT_SOCKET_WAIT_PEER_CLOSED: usize = 467;
const SLOT_SOCKET_WAIT_PEER_CLOSED_OBS: usize = 468;
const SLOT_SOCKET_WRITE_PEER_CLOSED: usize = 469;
const SLOT_SOCKET_READ_PEER_CLOSED: usize = 470;
const SLOT_SOCKET_FILL_SHORT_WRITE: usize = 471;
const SLOT_SOCKET_FILL_SHORT_ACTUAL: usize = 472;
const SLOT_SOCKET_FILL_WAIT_FULL: usize = 473;
const SLOT_SOCKET_FILL_DRAIN: usize = 474;
const SLOT_SOCKET_FILL_RECOVER: usize = 475;
const SLOT_SOCKET_DUPLICATE: usize = 476;
const SLOT_SOCKET_DUP_CLOSE_ORIGINAL: usize = 477;
const SLOT_SOCKET_DUP_WAIT_OPEN: usize = 478;
const SLOT_SOCKET_DUP_CLOSE_LAST: usize = 479;
const SLOT_SOCKET_DUP_WAIT_PEER_CLOSED: usize = 480;
const SLOT_SOCKET_DUP_WAIT_PEER_CLOSED_OBS: usize = 481;
const SLOT_SOCKET_CREATE_DATAGRAM: usize = 482;
const SLOT_SOCKET_CREATE_BAD_OPTS: usize = 483;
const SLOT_SOCKET_WRITE_ZERO_NULL: usize = 484;
const SLOT_SOCKET_READ_BAD_NULL: usize = 485;
const SLOT_SOCKET_WRITE_BAD_OPTS: usize = 486;
const SLOT_SOCKET_READ_BAD_OPTS: usize = 487;
const SLOT_SOCKET_READ_ACTUAL_NULL: usize = 488;
const SLOT_SOCKET_WAIT_ASYNC: usize = 489;
const SLOT_SOCKET_WAIT_ASYNC_WRITE: usize = 490;
const SLOT_SOCKET_WAIT_ASYNC_PORT_WAIT: usize = 491;
const SLOT_SOCKET_WAIT_ASYNC_KEY: usize = 492;
const SLOT_SOCKET_WAIT_ASYNC_TYPE: usize = 493;
const SLOT_SOCKET_WAIT_ASYNC_OBSERVED: usize = 494;
const SLOT_SOCKET_WAIT_ASYNC_WRITABLE: usize = 495;
const SLOT_SOCKET_WAIT_ASYNC_WRITABLE_PORT_WAIT: usize = 496;
const SLOT_SOCKET_DUP_WRITE_AFTER_CLOSE: usize = 497;
const SLOT_SOCKET_DUP_READ_AFTER_CLOSE: usize = 498;
const SLOT_SOCKET_DUP_READ_AFTER_CLOSE_MATCH: usize = 499;
const SLOT_SOCKET_BUFFERED_CURRENT: usize = 500;
const SLOT_SOCKET_BUFFERED_PEAK: usize = 501;
const SLOT_SOCKET_SHORT_WRITES: usize = 502;
const SLOT_SOCKET_WRITE_SHOULD_WAIT: usize = 503;
const SLOT_SOCKET_DUP_WRITE_AFTER_CLOSE_ACTUAL: usize = 504;
const SLOT_SOCKET_DUP_READ_AFTER_CLOSE_ACTUAL: usize = 505;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_BOOTSTRAP_HEAP_USED: usize = 507;
const SLOT_BOOTSTRAP_HEAP_PEAK: usize = 508;
const SLOT_BOOTSTRAP_HEAP_ALLOC_FAILS: usize = 509;
const SLOT_SELF_CODE_VMO_SIZE: usize = 510;
const SLOT_T0_NS: usize = 511;
const SLOT_CHANNEL_FRAGMENTED_CREATE: usize = 512;
const SLOT_CHANNEL_FRAGMENTED_TX_VMO_CREATE: usize = 513;
const SLOT_CHANNEL_FRAGMENTED_TX_MAP: usize = 514;
const SLOT_CHANNEL_FRAGMENTED_RX_REMAP_VMO_CREATE: usize = 515;
const SLOT_CHANNEL_FRAGMENTED_RX_REMAP_MAP: usize = 516;
const SLOT_CHANNEL_FRAGMENTED_RX_COPY_VMO_CREATE: usize = 517;
const SLOT_CHANNEL_FRAGMENTED_RX_COPY_MAP: usize = 518;
const SLOT_CHANNEL_FRAGMENTED_WRITE_REMAP: usize = 519;
const SLOT_CHANNEL_FRAGMENTED_READ_REMAP: usize = 520;
const SLOT_CHANNEL_FRAGMENTED_ACTUAL_BYTES_REMAP: usize = 521;
const SLOT_CHANNEL_FRAGMENTED_MATCH_REMAP: usize = 522;
const SLOT_CHANNEL_FRAGMENTED_WRITE_COPY: usize = 523;
const SLOT_CHANNEL_FRAGMENTED_READ_COPY: usize = 524;
const SLOT_CHANNEL_FRAGMENTED_ACTUAL_BYTES_COPY: usize = 525;
const SLOT_CHANNEL_FRAGMENTED_MATCH_COPY: usize = 526;
const SLOT_CHANNEL_WAIT_ASYNC_PORT_CREATE: usize = 527;
const SLOT_CHANNEL_WAIT_ASYNC_CREATE: usize = 528;
const SLOT_CHANNEL_WAIT_ASYNC_FILL: usize = 529;
const SLOT_CHANNEL_WAIT_ASYNC_FULL_WRITE: usize = 530;
const SLOT_CHANNEL_WAIT_ASYNC_ARM_WRITABLE: usize = 531;
const SLOT_CHANNEL_WAIT_ASYNC_READ: usize = 532;
const SLOT_CHANNEL_WAIT_ASYNC_PORT_WAIT_WRITABLE: usize = 533;
const SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_KEY: usize = 534;
const SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_TYPE: usize = 535;
const SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_OBSERVED: usize = 536;
const SLOT_CHANNEL_WAIT_ASYNC_ARM_PEER_CLOSED: usize = 537;
const SLOT_CHANNEL_WAIT_ASYNC_CLOSE_PEER: usize = 538;
const SLOT_CHANNEL_WAIT_ASYNC_PORT_WAIT_CLOSED: usize = 539;
const SLOT_CHANNEL_WAIT_ASYNC_CLOSED_KEY: usize = 540;
const SLOT_CHANNEL_WAIT_ASYNC_CLOSED_TYPE: usize = 541;
const SLOT_CHANNEL_WAIT_ASYNC_CLOSED_OBSERVED: usize = 542;
const SLOT_RUNTIME_FAILURE_STEP: usize = 543;
const SLOT_RUNTIME_DISPATCHER_CREATE: usize = 544;
const SLOT_RUNTIME_REG_CREATE_FIRST: usize = 545;
const SLOT_RUNTIME_REG_CANCEL_FIRST: usize = 546;
const SLOT_RUNTIME_REG_CREATE_SECOND: usize = 547;
const SLOT_RUNTIME_REG_SLOT_REUSED: usize = 548;
const SLOT_RUNTIME_REG_GEN_ADVANCED: usize = 549;
const SLOT_RUNTIME_CHANNEL_CREATE: usize = 550;
const SLOT_RUNTIME_CHANNEL_SEED_WRITE: usize = 551;
const SLOT_RUNTIME_CHANNEL_RECV: usize = 552;
const SLOT_RUNTIME_CHANNEL_RECV_ACTUAL_BYTES: usize = 553;
const SLOT_RUNTIME_CHANNEL_RECV_MATCH: usize = 554;
const SLOT_RUNTIME_SLEEP_CREATE: usize = 555;
const SLOT_RUNTIME_SLEEP_WAIT: usize = 556;
const SLOT_RUNTIME_CHANNEL_CALL_CREATE: usize = 557;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_SPAWN: usize = 558;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_RECV: usize = 559;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_MATCH: usize = 560;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_REPLY: usize = 561;
const SLOT_RUNTIME_CHANNEL_CALL: usize = 562;
const SLOT_RUNTIME_CHANNEL_CALL_ACTUAL_BYTES: usize = 563;
const SLOT_RUNTIME_CHANNEL_CALL_MATCH: usize = 564;
const SLOT_RUNTIME_SOCKET_CREATE: usize = 565;
const SLOT_RUNTIME_SOCKET_SEED_WRITE: usize = 566;
const SLOT_RUNTIME_SOCKET_WAIT_READABLE: usize = 567;
const SLOT_RUNTIME_SOCKET_WAIT_OBSERVED: usize = 568;
const SLOT_RUNTIME_SOCKET_READ: usize = 569;
const SLOT_RUNTIME_SOCKET_READ_ACTUAL_BYTES: usize = 570;
const SLOT_RUNTIME_SOCKET_READ_MATCH: usize = 571;
const SLOT_RUNTIME_CLOSE_SEED_TX: usize = 572;
const SLOT_RUNTIME_CLOSE_SEED_RX: usize = 573;
const SLOT_RUNTIME_CLOSE_CALL_CLIENT: usize = 574;
const SLOT_RUNTIME_CLOSE_CALL_SERVER: usize = 575;
const SLOT_RUNTIME_CLOSE_SOCKET_TX: usize = 576;
const SLOT_RUNTIME_CLOSE_SOCKET_RX: usize = 577;
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
const SLOT_COMPONENT_PROVIDER_STAGE: usize = 600;
const SLOT_COMPONENT_PROVIDER_STATUS: usize = 601;
const SLOT_COMPONENT_CLIENT_STAGE: usize = 602;
const SLOT_COMPONENT_CLIENT_STATUS: usize = 603;
const SLOT_BOOT_IMAGE_ECHO_PROVIDER_VMO_H: usize = 604;
const SLOT_BOOT_IMAGE_ECHO_CLIENT_VMO_H: usize = 605;
const SLOT_BOOT_IMAGE_CONTROLLER_WORKER_VMO_H: usize = 606;
const SLOT_BOOT_IMAGE_STARNIX_KERNEL_VMO_H: usize = 607;
const SLOT_BOOT_IMAGE_LINUX_HELLO_VMO_H: usize = 608;
const SLOT_TRACE_VMO_H: usize = 609;
const SLOT_TRACE_PHASE: usize = 610;
const SLOT_PERF_FAILURE_STEP: usize = 611;
const SLOT_PERF_NULL_STATUS: usize = 612;
const SLOT_PERF_NULL_ITERS: usize = 613;
const SLOT_PERF_NULL_CYCLES: usize = 614;
const SLOT_PERF_WAIT_STATUS: usize = 615;
const SLOT_PERF_WAIT_ITERS: usize = 616;
const SLOT_PERF_WAIT_CYCLES: usize = 617;
const SLOT_PERF_WAKE_STATUS: usize = 618;
const SLOT_PERF_WAKE_ITERS: usize = 619;
const SLOT_PERF_WAKE_CYCLES: usize = 620;
const SLOT_TRACE_RECORDS: usize = 621;
const SLOT_TRACE_DROPPED: usize = 622;
const SLOT_TRACE_EXPORTED_BYTES: usize = 623;
const SLOT_TRACE_REMOTE_WAKE_PHASE3: usize = 624;
const SLOT_PERF_THREAD_CREATE: usize = 625;
const SLOT_PERF_THREAD_START: usize = 626;
const SLOT_PERF_EVENTPAIR_CREATE: usize = 627;
const SLOT_PERF_TLB_STATUS: usize = 628;
const SLOT_PERF_TLB_ITERS: usize = 629;
const SLOT_PERF_TLB_CYCLES: usize = 630;
const SLOT_TRACE_TIMER_REPROGRAM: usize = 631;
const SLOT_TRACE_TLB_SYNC_PLANS: usize = 632;
const SLOT_TRACE_TLB_LOCAL_PAGE_FLUSH: usize = 633;
const SLOT_TRACE_TLB_LOCAL_FULL_FLUSH: usize = 634;
const SLOT_TRACE_TLB_SHOOTDOWN_PAGE: usize = 635;
const SLOT_TRACE_TLB_SHOOTDOWN_FULL: usize = 636;
const SLOT_TRACE_TLB_SHOOTDOWN_TARGET_CPUS: usize = 637;
const SLOT_TRACE_TLB_MAX_ACTIVE_CPUS: usize = 638;
const SLOT_TRACE_TLB_LAST_ACTIVE_MASK: usize = 639;
const SLOT_TRACE_TLB_PAGE_FLUSH_PHASE4: usize = 640;
const SLOT_TRACE_TLB_FULL_FLUSH_PHASE4: usize = 641;
const SLOT_TRACE_TLB_SYNC_PLAN_PHASE4: usize = 642;
const SLOT_PERF_TLB_PEER_STATUS: usize = 643;
const SLOT_PERF_TLB_PEER_ITERS: usize = 644;
const SLOT_PERF_TLB_PEER_CYCLES: usize = 645;
const SLOT_TRACE_TLB_SYNC_PLAN_PHASE5: usize = 646;
const SLOT_TRACE_TLB_SHOOTDOWN_FULL_PHASE5: usize = 647;
const SLOT_PERF_FAULT_STATUS: usize = 662;
const SLOT_PERF_FAULT_ITERS: usize = 663;
const SLOT_PERF_FAULT_CYCLES: usize = 664;
const SLOT_TRACE_FAULT_ENTER_PHASE6: usize = 665;
const SLOT_TRACE_FAULT_HANDLED_PHASE6: usize = 666;
const SLOT_TRACE_FAULT_BLOCK_PHASE6: usize = 667;
const SLOT_TRACE_FAULT_RESUME_PHASE6: usize = 668;
const SLOT_TRACE_FAULT_UNHANDLED_PHASE6: usize = 669;
const SLOT_TRACE_SCHED_MAX_RQ_DEPTH: usize = 670;
const SLOT_TRACE_SCHED_STEALS: usize = 671;
const SLOT_TRACE_SCHED_HANDOFFS: usize = 672;
const SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT: usize = 673;
const SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS: usize = 674;
const SLOT_TRACE_SCHED_STEAL_PHASE3: usize = 675;
const SLOT_TRACE_SCHED_HANDOFF_PHASE3: usize = 676;
const SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3: usize = 677;
const SLOT_TRACE_SCHED_STEAL_PHASE5: usize = 678;
const SLOT_PERF_CHANNEL_FRAGMENT_STATUS: usize = 679;
const SLOT_PERF_CHANNEL_FRAGMENT_ITERS: usize = 680;
const SLOT_PERF_CHANNEL_FRAGMENT_CYCLES: usize = 681;
const SLOT_TRACE_IPC_CHANNEL_ENQUEUE_PHASE7: usize = 682;
const SLOT_TRACE_IPC_CHANNEL_DEQUEUE_PHASE7: usize = 683;
const SLOT_TRACE_IPC_CHANNEL_RECLAIM_PHASE7: usize = 684;
const SLOT_CHANNEL_FRAGMENT_POOL_NEW: usize = 685;
const SLOT_CHANNEL_FRAGMENT_POOL_REUSE: usize = 686;
const SLOT_CHANNEL_FRAGMENT_POOL_LOCAL_FREE: usize = 687;
const SLOT_CHANNEL_FRAGMENT_POOL_REMOTE_FREE: usize = 688;
const SLOT_CHANNEL_FRAGMENT_POOL_CACHED_CURRENT: usize = 689;
const SLOT_CHANNEL_FRAGMENT_POOL_CACHED_PEAK: usize = 690;
const SLOT_CHANNEL_FRAGMENTED_DESC_COUNT: usize = 691;
const SLOT_CHANNEL_FRAGMENTED_BYTES_TOTAL: usize = 692;
const SLOT_TRACE_SCHED_PHASE3_OK: usize = 693;
const SLOT_TRACE_SYS_ENTER_PHASE1: usize = 654;
const SLOT_TRACE_SYS_EXIT_PHASE1: usize = 655;
const SLOT_TRACE_SYS_RETIRE_PHASE1: usize = 656;
const SLOT_TRACE_CONTEXT_SWITCHES: usize = 657;
const SLOT_MAX: usize = SLOT_TRACE_SCHED_PHASE3_OK;
const SLOT_VMAR_DESTROY_STALE_MAP: usize = SLOT_SELF_CODE_VMO_H;
const SLOT_VMAR_DESTROY_STALE_CLOSE: usize = SLOT_T0_NS;

#[repr(align(4096))]
#[derive(Clone, Copy)]
struct AlignedPage([u8; 4096]);
#[repr(align(4096))]
#[derive(Clone, Copy)]
struct AlignedPageTable([u64; 512]);

static mut USER_CODE_PAGES: [AlignedPage; USER_CODE_PAGE_COUNT] =
    [AlignedPage([0; 4096]); USER_CODE_PAGE_COUNT];
static mut USER_SHARED_PAGES: [AlignedPage; USER_SHARED_PAGE_COUNT] =
    [AlignedPage([0; 4096]); USER_SHARED_PAGE_COUNT];
static mut USER_STACK_PAGES: [AlignedPage; USER_STACK_PAGE_COUNT] =
    [AlignedPage([0; 4096]); USER_STACK_PAGE_COUNT];

static mut USER_PD: AlignedPageTable = AlignedPageTable([0; 512]);
static mut USER_PTS: [AlignedPageTable; BOOTSTRAP_USER_PT_COUNT] =
    [AlignedPageTable([0; 512]); BOOTSTRAP_USER_PT_COUNT];

// PVH boot page tables (identity-mapped, used as the active CR3).
unsafe extern "C" {
    static mut pvh_pml4: [u64; 512];
    static mut pvh_pdpt: [u64; 512];
}

// Page table flag bits (x86_64).
const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserPageFrame {
    paddr: u64,
    writable: bool,
}

impl UserPageFrame {
    pub(crate) const fn paddr(self) -> u64 {
        self.paddr
    }

    pub(crate) const fn writable(self) -> bool {
        self.writable
    }
}

fn phys_of<T>(p: *const T) -> u64 {
    // In the current PVH identity mapping, physical == virtual for kernel static data.
    p as u64
}

pub(crate) fn user_code_page_paddr(index: usize) -> u64 {
    assert!(index < USER_CODE_PAGE_COUNT);
    phys_of(core::ptr::addr_of!(USER_CODE_PAGES)) + (index as u64) * USER_PAGE_BYTES
}

pub(crate) fn user_shared_page_paddr(index: usize) -> u64 {
    // SAFETY: callers only pass bootstrap shared-page indices in-bounds for the static array.
    let page = unsafe { core::ptr::addr_of!(USER_SHARED_PAGES[index]) };
    phys_of(page)
}

pub(crate) fn user_stack_page_paddr(index: usize) -> u64 {
    assert!(index < USER_STACK_PAGE_COUNT);
    let page = unsafe { core::ptr::addr_of!(USER_STACK_PAGES[index]) };
    phys_of(page)
}

pub(crate) fn bootstrap_user_pd_paddr() -> u64 {
    phys_of(core::ptr::addr_of!(USER_PD))
}

pub(crate) fn bootstrap_user_pt_paddrs() -> [u64; BOOTSTRAP_USER_PT_COUNT] {
    core::array::from_fn(user_pt_paddr)
}

pub(crate) fn bootstrap_user_pt_paddr(index: usize) -> u64 {
    user_pt_paddr(index)
}

fn user_pt_paddr(index: usize) -> u64 {
    assert!(index < BOOTSTRAP_USER_PT_COUNT);
    let pt = unsafe {
        // SAFETY: callers only request one fixed bootstrap PT slot. Reading the address of one
        // static table page does not mutate the bootstrap mapping state.
        core::ptr::addr_of!(USER_PTS[index])
    };
    phys_of(pt)
}

fn bootstrap_user_page_slot(user_va: u64) -> Option<(usize, usize)> {
    if user_va < USER_CODE_VA || user_va >= USER_STACK_TOP {
        return None;
    }
    if user_va & (USER_PAGE_BYTES - 1) != 0 {
        return None;
    }
    let page_index = usize::try_from((user_va - USER_CODE_VA) / USER_PAGE_BYTES).ok()?;
    Some((
        page_index / BOOTSTRAP_USER_PT_ENTRY_COUNT,
        page_index % BOOTSTRAP_USER_PT_ENTRY_COUNT,
    ))
}

pub(crate) fn alloc_bootstrap_cow_page(src_paddr: u64) -> Option<u64> {
    let dst = alloc_bootstrap_zeroed_page()?;
    unsafe {
        // SAFETY: both the source physical address and destination pointer are currently
        // identity-mapped kernel addresses spanning one bootstrap page.
        core::ptr::copy_nonoverlapping(
            src_paddr as *const u8,
            dst as *mut u8,
            USER_PAGE_BYTES as usize,
        );
    }
    Some(dst)
}

pub(crate) fn alloc_bootstrap_zeroed_page() -> Option<u64> {
    alloc_bootstrap_zeroed_pages(1)
}

pub(crate) fn alloc_bootstrap_zeroed_pages(page_count: usize) -> Option<u64> {
    if page_count == 0 {
        return None;
    }
    crate::pmm::alloc_zeroed_pages(page_count)
}

pub(crate) fn free_bootstrap_page(paddr: u64) {
    free_bootstrap_pages(paddr, 1);
}

pub(crate) fn free_bootstrap_pages(paddr: u64, page_count: usize) {
    if page_count == 0 || paddr == 0 || (paddr & (USER_PAGE_BYTES - 1)) != 0 {
        return;
    }
    crate::pmm::free_pages(paddr, page_count);
}

pub(crate) fn write_bootstrap_value<T: Copy>(
    base_paddr: u64,
    byte_offset: usize,
    value: &T,
) -> Option<()> {
    let dst = base_paddr.checked_add(byte_offset as u64)? as *mut T;
    unsafe {
        // SAFETY: callers only use bootstrap-owned contiguous allocations. `byte_offset`
        // stays within the allocated backing store and `dst` therefore points into valid
        // writable kernel memory. `write_unaligned` tolerates packet slots that are only
        // naturally aligned to the port packet stride.
        core::ptr::write_unaligned(dst, *value);
    }
    Some(())
}

pub(crate) fn write_bootstrap_bytes(base_paddr: u64, byte_offset: usize, src: &[u8]) -> Option<()> {
    if src.is_empty() {
        return Some(());
    }
    let dst = base_paddr.checked_add(byte_offset as u64)? as *mut u8;
    unsafe {
        // SAFETY: callers only use bootstrap-owned or identity-mapped physical pages that are
        // directly writable in the current kernel address space. `byte_offset..byte_offset+len`
        // stays inside the selected page-backed range and `src` is a valid source slice.
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
    Some(())
}

pub(crate) fn read_bootstrap_value<T: Copy>(base_paddr: u64, byte_offset: usize) -> Option<T> {
    let src = base_paddr.checked_add(byte_offset as u64)? as *const T;
    Some(unsafe {
        // SAFETY: callers only read values previously written into the same bootstrap-owned
        // contiguous allocation. `read_unaligned` tolerates packet slots that are only
        // naturally aligned to the port packet stride.
        core::ptr::read_unaligned(src)
    })
}

pub(crate) fn read_bootstrap_bytes(
    base_paddr: u64,
    byte_offset: usize,
    dst: &mut [u8],
) -> Option<()> {
    if dst.is_empty() {
        return Some(());
    }
    let src = base_paddr.checked_add(byte_offset as u64)? as *const u8;
    unsafe {
        // SAFETY: callers only read bootstrap-owned or identity-mapped physical pages that are
        // directly readable in the current kernel address space. `byte_offset..byte_offset+len`
        // stays inside the selected page-backed range and `dst` is a valid destination slice.
        core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len());
    }
    Some(())
}

pub(crate) fn query_user_page_frame(user_va: u64) -> Result<Option<UserPageFrame>, ()> {
    let (pt_index, entry_index) = bootstrap_user_page_slot(user_va).ok_or(())?;
    // SAFETY: USER_PTS are the active page table pages for the fixed bootstrap user region.
    let entry = unsafe { USER_PTS[pt_index].0[entry_index] };
    if (entry & PTE_P) == 0 {
        return Ok(None);
    }
    Ok(Some(UserPageFrame {
        paddr: entry & !(USER_PAGE_BYTES - 1),
        writable: (entry & PTE_W) != 0,
    }))
}

pub(crate) fn install_user_page_frame(user_va: u64, paddr: u64, writable: bool) -> Result<(), ()> {
    if paddr & (USER_PAGE_BYTES - 1) != 0 {
        return Err(());
    }
    let (pt_index, entry_index) = bootstrap_user_page_slot(user_va).ok_or(())?;
    let mut entry = paddr | (PTE_P | PTE_U);
    if writable {
        entry |= PTE_W;
    }

    unsafe {
        // SAFETY: USER_PTS are the active page table pages for the fixed bootstrap user region.
        USER_PTS[pt_index].0[entry_index] = entry;
    }
    Ok(())
}

pub(crate) fn clear_user_page_frame(user_va: u64) -> Result<(), ()> {
    let (pt_index, entry_index) = bootstrap_user_page_slot(user_va).ok_or(())?;
    unsafe {
        // SAFETY: USER_PTS are the active page table pages for the fixed bootstrap user region.
        USER_PTS[pt_index].0[entry_index] = 0;
    }
    Ok(())
}

pub(crate) fn set_user_page_writable(user_va: u64, writable: bool) -> Result<(), ()> {
    let (pt_index, entry_index) = bootstrap_user_page_slot(user_va).ok_or(())?;
    unsafe {
        // SAFETY: USER_PTS are the active page table pages for the fixed bootstrap user region.
        let entry = &mut USER_PTS[pt_index].0[entry_index];
        if (*entry & PTE_P) == 0 {
            return Err(());
        }
        if writable {
            *entry |= PTE_W;
        } else {
            *entry &= !PTE_W;
        }
    }
    Ok(())
}

fn map_userspace_pages() {
    fn install_bootstrap_pte(page_index: usize, paddr: u64, writable: bool) {
        let pt_index = page_index / BOOTSTRAP_USER_PT_ENTRY_COUNT;
        let entry_index = page_index % BOOTSTRAP_USER_PT_ENTRY_COUNT;
        let mut entry = paddr | (PTE_P | PTE_U);
        if writable {
            entry |= PTE_W;
        }
        unsafe {
            // SAFETY: early bring-up is single-core; bootstrap page tables are only mutated here.
            USER_PTS[pt_index].0[entry_index] = entry;
        }
    }

    // SAFETY: early bring-up is single-core; page table mutation is serialized.
    unsafe {
        let pml4 = core::ptr::addr_of_mut!(pvh_pml4).cast::<u64>();
        let pdpt = core::ptr::addr_of_mut!(pvh_pdpt).cast::<u64>();
        let user_pd = core::ptr::addr_of_mut!(USER_PD).cast::<u64>();

        // Allow user mappings under PML4[0] by setting U=1 at the top level.
        *pml4.add(0) |= PTE_U;

        // Install PDPT[4] -> USER_PD (maps VA 4GiB..5GiB).
        *pdpt.add(4) = phys_of(core::ptr::addr_of!(USER_PD)) | (PTE_P | PTE_W | PTE_U);

        for index in 0..BOOTSTRAP_USER_PT_COUNT {
            *user_pd.add(index) = user_pt_paddr(index) | (PTE_P | PTE_W | PTE_U);
        }

        // Map the user code pages, followed by the shared region and stack page.
        for index in 0..USER_CODE_PAGE_COUNT {
            install_bootstrap_pte(index, user_code_page_paddr(index), true);
        }
        for index in 0..USER_SHARED_PAGE_COUNT {
            install_bootstrap_pte(
                USER_CODE_PAGE_COUNT + index,
                phys_of(core::ptr::addr_of!(USER_SHARED_PAGES[index])),
                true,
            );
        }
        for index in 0..USER_STACK_PAGE_COUNT {
            install_bootstrap_pte(
                USER_CODE_PAGE_COUNT + USER_SHARED_PAGE_COUNT + index,
                user_stack_page_paddr(index),
                false,
            );
        }

        // Flush TLB by reloading CR3.
        crate::arch::tlb::flush_all_local();
    }
}

unsafe extern "C" {
    static axle_user_prog_start: u8;
    static axle_user_prog_end: u8;
}

fn load_user_program_embedded() {
    // SAFETY: symbols are defined by `global_asm!` below and form a contiguous region.
    unsafe {
        let start = core::ptr::addr_of!(axle_user_prog_start);
        let end = core::ptr::addr_of!(axle_user_prog_end);
        let len = end.offset_from(start) as usize;
        let src = core::slice::from_raw_parts(start, len);

        if len > USER_CODE_BYTES as usize {
            panic!(
                "userspace: program too large for bootstrap code region (len={})",
                len
            );
        }

        let dst = core::ptr::addr_of_mut!(USER_CODE_PAGES).cast::<u8>();
        // Use `ptr::copy` (memmove semantics) to avoid relying on non-overlap
        // across toolchain/linker layouts during bring-up.
        core::ptr::copy(src.as_ptr(), dst, len);
        core::ptr::write_bytes(dst.add(len), 0, USER_CODE_BYTES as usize - len);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn try_load_user_program_from_qemu_loader() -> Result<Option<u64>, zx_status_t> {
    let Some(image_size) =
        crate::task::bootstrap_user_runner_source_size().or_else(qemu_loader_user_runner_size)
    else {
        return Ok(None);
    };
    let layout = parse_elf_process_image_layout(image_size, |offset, len| {
        read_bootstrap_user_runner_bytes(offset, len).ok_or(ZX_ERR_IO_DATA_INTEGRITY)
    })?;
    load_bootstrap_process_image_into_current_mapping(&layout).map(Some)
}

fn load_bootstrap_process_image_into_current_mapping(
    layout: &crate::task::ProcessImageLayout,
) -> Result<u64, zx_status_t> {
    for segment in layout.segments() {
        let file_sz =
            usize::try_from(segment.file_size_bytes()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let mem_sz = usize::try_from(segment.mem_size_bytes()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let file_bytes = read_bootstrap_user_runner_bytes(segment.vmo_offset(), file_sz)
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
        crate::copy::write_current_mapping_bytes(segment.vaddr(), &file_bytes);
        if mem_sz > file_sz {
            let zero_base = segment
                .vaddr()
                .checked_add(file_sz as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            crate::copy::zero_current_mapping_bytes(zero_base, mem_sz - file_sz);
        }
    }

    Ok(layout.entry())
}

pub(crate) fn parse_elf_process_image_layout(
    image_size: u64,
    mut read_bytes: impl FnMut(u64, usize) -> Result<Vec<u8>, zx_status_t>,
) -> Result<crate::task::ProcessImageLayout, zx_status_t> {
    parse_elf_process_image_layout_with_load_bias(image_size, &mut read_bytes, None)
}

pub(crate) fn parse_elf_process_image_layout_with_load_bias(
    image_size: u64,
    mut read_bytes: impl FnMut(u64, usize) -> Result<Vec<u8>, zx_status_t>,
    load_bias: Option<u64>,
) -> Result<crate::task::ProcessImageLayout, zx_status_t> {
    if image_size < core::mem::size_of::<Elf64Ehdr>() as u64 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let ehdr_bytes = read_bytes(0, core::mem::size_of::<Elf64Ehdr>())?;
    if &ehdr_bytes[0..4] != b"\x7FELF" {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    // SAFETY: the buffer is at least one ELF header long and we only read a plain old data
    // struct from it without assuming alignment.
    let ehdr = unsafe { core::ptr::read_unaligned(ehdr_bytes.as_ptr() as *const Elf64Ehdr) };
    if ehdr.e_ident[4] != 2 || ehdr.e_ident[5] != 1 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    if ehdr.e_machine != 0x3E {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let image_bias = match (ehdr.e_type, load_bias) {
        (ET_EXEC, None) => 0,
        (ET_DYN, None) => USER_CODE_VA,
        (ET_DYN, Some(load_bias)) if (load_bias & (USER_PAGE_BYTES - 1)) == 0 => load_bias,
        _ => return Err(ZX_ERR_NOT_SUPPORTED),
    };
    if ehdr.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phsize = phnum
        .checked_mul(core::mem::size_of::<Elf64Phdr>())
        .and_then(|n| n.checked_add(phoff))
        .unwrap_or(usize::MAX);
    if u64::try_from(phsize).map_err(|_| ZX_ERR_OUT_OF_RANGE)? > image_size {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let ph_table = read_bytes(ehdr.e_phoff, phnum * core::mem::size_of::<Elf64Phdr>())?;

    let mut segments = Vec::new();
    let mut min_vaddr = u64::MAX;
    let mut max_vend = 0u64;
    let mut phdr_vaddr = None;
    for i in 0..phnum {
        let off = i * core::mem::size_of::<Elf64Phdr>();
        // SAFETY: `off` stays within the already-fetched program-header table and the target
        // type is a plain old data ELF header.
        let ph =
            unsafe { core::ptr::read_unaligned(ph_table.as_ptr().add(off) as *const Elf64Phdr) };
        const PT_LOAD: u32 = 1;
        if ph.p_type != PT_LOAD {
            continue;
        }

        let file_end = ph.p_offset.checked_add(ph.p_filesz).unwrap_or(u64::MAX);
        if file_end > image_size {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let vaddr = ph
            .p_vaddr
            .checked_add(image_bias)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let vend = vaddr.checked_add(ph.p_memsz).unwrap_or(u64::MAX);
        if vaddr < USER_CODE_VA || vend > USER_SHARED_VA {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if (vaddr & (USER_PAGE_BYTES - 1)) != (ph.p_offset & (USER_PAGE_BYTES - 1)) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let mut perms = crate::task::process_image_default_code_perms();
        if (ph.p_flags & 0x2) != 0 {
            perms |= axle_mm::MappingPerms::WRITE;
        }
        let segment = crate::task::ProcessImageSegment::new(
            vaddr,
            ph.p_offset,
            ph.p_filesz,
            ph.p_memsz,
            perms,
        );
        segments.push(segment);
        min_vaddr = min_vaddr.min(vaddr);
        max_vend = max_vend.max(vend);
        let phdr_end = ehdr
            .e_phoff
            .checked_add((phnum as u64) * (core::mem::size_of::<Elf64Phdr>() as u64))
            .unwrap_or(u64::MAX);
        if phdr_vaddr.is_none() && ehdr.e_phoff >= ph.p_offset && phdr_end <= file_end {
            phdr_vaddr = vaddr.checked_add(ehdr.e_phoff - ph.p_offset);
        }
    }

    if segments.is_empty() {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let entry = ehdr
        .e_entry
        .checked_add(image_bias)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if entry < min_vaddr || entry >= max_vend {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }

    let code_base = min_vaddr;
    let code_size_bytes = align_up(
        max_vend.checked_sub(code_base).unwrap_or(0),
        USER_PAGE_BYTES,
    );
    crate::task::ProcessImageLayout::with_segments_and_elf(
        code_base,
        code_size_bytes,
        entry,
        &segments,
        phdr_vaddr.map(|vaddr| {
            crate::task::ProcessImageElfInfo::new(vaddr, ehdr.e_phentsize, ehdr.e_phnum)
        }),
    )
}

pub(crate) fn bootstrap_process_image_layout() -> Option<crate::task::ProcessImageLayout> {
    let image_size =
        crate::task::bootstrap_user_runner_source_size().or_else(qemu_loader_user_runner_size)?;
    parse_elf_process_image_layout(image_size, |offset, len| {
        read_bootstrap_user_runner_bytes(offset, len).ok_or(ZX_ERR_IO_DATA_INTEGRITY)
    })
    .ok()
}

fn read_bootstrap_user_runner_bytes(offset: u64, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(len).ok()?;
    out.resize(len, 0);
    if crate::task::read_bootstrap_user_runner_source_at(offset, &mut out).is_ok() {
        return Some(out);
    }
    read_qemu_loader_user_runner_at(offset, &mut out).ok()?;
    Some(out)
}

pub(crate) fn qemu_loader_user_runner_size() -> Option<u64> {
    qemu_loader_image_size(USER_RUNNER_IMAGE)
}

pub(crate) fn qemu_loader_echo_provider_size() -> Option<u64> {
    qemu_loader_image_size(ECHO_PROVIDER_IMAGE)
}

pub(crate) fn qemu_loader_echo_client_size() -> Option<u64> {
    qemu_loader_image_size(ECHO_CLIENT_IMAGE)
}

pub(crate) fn qemu_loader_controller_worker_size() -> Option<u64> {
    qemu_loader_image_size(CONTROLLER_WORKER_IMAGE)
}

pub(crate) fn qemu_loader_starnix_kernel_size() -> Option<u64> {
    qemu_loader_image_size(STARNIX_KERNEL_IMAGE)
}

pub(crate) fn qemu_loader_linux_hello_size() -> Option<u64> {
    qemu_loader_image_size(LINUX_HELLO_IMAGE)
}

fn qemu_loader_image_size(image: QemuLoaderImage) -> Option<u64> {
    let blob_len = qemu_loader_image_blob(image).and_then(|blob| u64::try_from(blob.len()).ok())?;
    let page = USER_PAGE_BYTES;
    let padded = blob_len.checked_add(page - 1)? & !(page - 1);
    Some(padded)
}

pub(crate) fn qemu_loader_reserved_floor() -> u64 {
    [
        USER_RUNNER_IMAGE,
        ECHO_PROVIDER_IMAGE,
        ECHO_CLIENT_IMAGE,
        CONTROLLER_WORKER_IMAGE,
        STARNIX_KERNEL_IMAGE,
        LINUX_HELLO_IMAGE,
    ]
    .into_iter()
    .filter_map(|image| {
        qemu_loader_image_size(image).and_then(|size| image.paddr.checked_add(size))
    })
    .max()
    .unwrap_or(0)
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

pub(crate) fn read_qemu_loader_user_runner_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(USER_RUNNER_IMAGE, offset, dst)
}

pub(crate) fn read_qemu_loader_echo_provider_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(ECHO_PROVIDER_IMAGE, offset, dst)
}

pub(crate) fn read_qemu_loader_echo_client_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(ECHO_CLIENT_IMAGE, offset, dst)
}

pub(crate) fn read_qemu_loader_controller_worker_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(CONTROLLER_WORKER_IMAGE, offset, dst)
}

pub(crate) fn read_qemu_loader_starnix_kernel_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(STARNIX_KERNEL_IMAGE, offset, dst)
}

pub(crate) fn read_qemu_loader_linux_hello_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    read_qemu_loader_image_at(LINUX_HELLO_IMAGE, offset, dst)
}

fn read_qemu_loader_image_at(
    image: QemuLoaderImage,
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    let blob = qemu_loader_image_blob(image).ok_or(ZX_ERR_NOT_FOUND)?;
    let padded_size = qemu_loader_image_size(image).ok_or(ZX_ERR_NOT_FOUND)?;
    let end = offset
        .checked_add(dst.len() as u64)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if end > padded_size {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    crate::copy::zero_fill(dst);
    let actual_end = core::cmp::min(end, blob.len() as u64);
    if actual_end <= offset {
        return Ok(());
    }
    let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let actual_end = usize::try_from(actual_end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let len = actual_end - start;
    let src = blob.get(start..actual_end).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    crate::copy::copy_kernel_bytes(&mut dst[..len], src)
}

pub(crate) fn read_bootstrap_user_code_image_at(
    offset: u64,
    dst: &mut [u8],
) -> Result<(), zx_status_t> {
    let end = offset
        .checked_add(dst.len() as u64)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if end > USER_CODE_BYTES {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let end = usize::try_from(end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    // SAFETY: `USER_CODE_PAGES` is one contiguous static array covering `USER_CODE_BYTES`.
    let src = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(USER_CODE_PAGES).cast::<u8>(),
            USER_CODE_BYTES as usize,
        )
    };
    crate::copy::copy_kernel_bytes(dst, src.get(start..end).ok_or(ZX_ERR_OUT_OF_RANGE)?)
}

fn qemu_loader_image_blob(image: QemuLoaderImage) -> Option<&'static [u8]> {
    // SAFETY: conformance harness loads these bytes into identity-mapped RAM.
    let size = unsafe { core::ptr::read_unaligned(image.size_paddr as *const u64) };
    if size == 0 || size as usize > USER_RUNNER_ELF_MAX_BYTES {
        return None;
    }

    // SAFETY: we trust the loader-provided size bound above.
    Some(unsafe { core::slice::from_raw_parts(image.paddr as *const u8, size as usize) })
}

/// Validate a user pointer for a copyin/copyout of `len` bytes.
///
/// Bring-up rule: pointers must be fully contained within the mapped shared region
/// or the mapped stack page (so the kernel never faults on bad pointers).
pub fn validate_user_ptr(ptr: u64, len: usize) -> bool {
    if bootstrap_user_window_contains(ptr, len) {
        return true;
    }
    crate::fault::validate_current_user_ptr(ptr, len)
}

/// Ensure a current-thread user range is resident before direct kernel access.
pub fn ensure_user_range_resident(
    ptr: u64,
    len: usize,
    for_write: bool,
) -> Result<(), zx_status_t> {
    crate::fault::ensure_current_user_range_resident(ptr, len, for_write)
}

/// Copy bytes from a validated and resident current-process user range into a kernel buffer.
pub(crate) fn read_validated_user_bytes(ptr: u64, dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    unsafe {
        // SAFETY: callers validate the current-process user range and make it resident before
        // calling this helper. `dst` is a valid writable kernel slice for `dst.len()` bytes.
        core::ptr::copy_nonoverlapping(ptr as *const u8, dst.as_mut_ptr(), dst.len());
    }
}

/// Copy bytes from a kernel slice into a validated and resident current-process user range.
pub(crate) fn write_validated_user_bytes(ptr: u64, src: &[u8]) {
    if src.is_empty() {
        return;
    }
    unsafe {
        // SAFETY: callers validate the current-process user range and make it resident before
        // calling this helper. `src` is a valid readable kernel slice for `src.len()` bytes.
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr as *mut u8, src.len());
    }
}

/// Zero-fill a validated and resident current-process user range.
pub(crate) fn zero_validated_user_bytes(ptr: u64, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        // SAFETY: callers validate the current-process user range and make it resident before
        // calling this helper. The destination region is writable for `len` bytes.
        core::ptr::write_bytes(ptr as *mut u8, 0, len);
    }
}

/// Copy bytes from one bootstrap-backed frame into a validated and resident user range.
pub(crate) fn copy_bootstrap_frame_into_validated_user(dst_ptr: u64, src_paddr: u64, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        // SAFETY: callers validate the current-process user destination and make it resident
        // before calling this helper. Bootstrap guest memory is identity-mapped, so `src_paddr`
        // is directly readable as a kernel virtual address for `len` bytes.
        core::ptr::copy_nonoverlapping(src_paddr as *const u8, dst_ptr as *mut u8, len);
    }
}

/// Copy bytes into the currently mapped bootstrap user window without extra validation.
pub(crate) fn write_current_mapping_bytes(dst_ptr: u64, src: &[u8]) {
    if src.is_empty() {
        return;
    }
    unsafe {
        // SAFETY: callers only use this helper for bootstrap process image ranges already mapped
        // into the current address space, so the destination range is writable for `src.len()`
        // bytes.
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr as *mut u8, src.len());
    }
}

/// Zero-fill bytes in the currently mapped bootstrap user window without extra validation.
pub(crate) fn zero_current_mapping_bytes(dst_ptr: u64, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        // SAFETY: callers only use this helper for bootstrap process image ranges already mapped
        // into the current address space, so the destination range is writable for `len` bytes.
        core::ptr::write_bytes(dst_ptr as *mut u8, 0, len);
    }
}

fn shared_slots() -> &'static mut [u64] {
    // SAFETY: the bootstrap ring3 bridge summary window is backed by the static
    // `USER_SHARED_PAGES` array. The bootstrap runner reads and writes the same
    // backing pages through its user mapping, but kernel-side telemetry must not
    // depend on the current thread's address space also mapping `USER_SHARED_VA`.
    // Component and child process faults can arrive while a different address
    // space is active; reaching through the user VA there would fault in-kernel.
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(USER_SHARED_PAGES) as *mut u64,
            (USER_SHARED_PAGE_COUNT * 4096) / core::mem::size_of::<u64>(),
        )
    }
}

fn bootstrap_user_window_contains(ptr: u64, len: usize) -> bool {
    if len == 0 {
        return ptr >= USER_CODE_VA && ptr < USER_STACK_TOP;
    }
    let end = match ptr.checked_add(len as u64) {
        Some(end) => end,
        None => return false,
    };
    ptr >= USER_CODE_VA && end <= USER_STACK_TOP && ptr < end
}

pub(crate) fn record_vm_cow_fault_count(count: u64) {
    shared_slots()[SLOT_VM_COW_FAULT_COUNT] = count;
}

pub(crate) fn record_vm_last_remap_source_rmap_count(count: u64) {
    shared_slots()[SLOT_VM_LAST_REMAP_SOURCE_RMAP_COUNT] = count;
}

pub(crate) fn record_vm_last_cow_rmap_counts(old_count: u64, new_count: u64) {
    let slots = shared_slots();
    slots[SLOT_VM_LAST_COW_OLD_RMAP_COUNT] = old_count;
    slots[SLOT_VM_LAST_COW_NEW_RMAP_COUNT] = new_count;
}

pub(crate) fn record_vm_resource_accounting(
    private_cow_current: u64,
    private_cow_peak: u64,
    private_cow_quota_hits: u64,
    inflight_loan_current: u64,
    inflight_loan_peak: u64,
    inflight_loan_quota_hits: u64,
) {
    let slots = shared_slots();
    slots[SLOT_VM_PRIVATE_COW_PAGES_CURRENT] = private_cow_current;
    slots[SLOT_VM_PRIVATE_COW_PAGES_PEAK] = private_cow_peak;
    slots[SLOT_VM_PRIVATE_COW_QUOTA_HITS] = private_cow_quota_hits;
    slots[SLOT_VM_INFLIGHT_LOAN_PAGES_CURRENT] = inflight_loan_current;
    slots[SLOT_VM_INFLIGHT_LOAN_PAGES_PEAK] = inflight_loan_peak;
    slots[SLOT_VM_INFLIGHT_LOAN_QUOTA_HITS] = inflight_loan_quota_hits;
}

pub(crate) fn record_fault_contention_telemetry(
    leader_claims: u64,
    wait_claims: u64,
    wait_spin_loops: u64,
    retry_total: u64,
    commit_resolved: u64,
    commit_retry: u64,
    prepare_cow: u64,
    prepare_lazy_anon: u64,
    prepare_lazy_vmo_alloc: u64,
) {
    let slots = shared_slots();
    slots[SLOT_VM_FAULT_LEADER_CLAIMS] = leader_claims;
    slots[SLOT_VM_FAULT_WAIT_CLAIMS] = wait_claims;
    slots[SLOT_VM_FAULT_WAIT_SPIN_LOOPS] = wait_spin_loops;
    slots[SLOT_VM_FAULT_RETRY_TOTAL] = retry_total;
    slots[SLOT_VM_FAULT_COMMIT_RESOLVED] = commit_resolved;
    slots[SLOT_VM_FAULT_COMMIT_RETRY] = commit_retry;
    slots[SLOT_VM_FAULT_PREPARE_COW] = prepare_cow;
    slots[SLOT_VM_FAULT_PREPARE_LAZY_ANON] = prepare_lazy_anon;
    slots[SLOT_VM_FAULT_PREPARE_LAZY_VMO_ALLOC] = prepare_lazy_vmo_alloc;
}

pub(crate) fn consume_vm_fault_leader_pause_hook() -> bool {
    let slots = shared_slots();
    if slots[SLOT_VM_FAULT_TEST_HOOK_ARM] == 0 {
        return false;
    }
    slots[SLOT_VM_FAULT_TEST_HOOK_ARM] = 0;
    true
}

pub(crate) fn bootstrap_trace_phase() -> u64 {
    shared_slots()[SLOT_TRACE_PHASE]
}

pub(crate) fn component_summary_snapshot() -> Option<(u64, i64, i64, i64, i64, i64)> {
    let slots = shared_slots();
    let failure_step = slots[SLOT_COMPONENT_FAILURE_STEP];
    let resolve_root = slots[SLOT_COMPONENT_RESOLVE_ROOT] as i64;
    let provider_launch = slots[SLOT_COMPONENT_PROVIDER_LAUNCH] as i64;
    let client_launch = slots[SLOT_COMPONENT_CLIENT_LAUNCH] as i64;
    let stop_request = slots[SLOT_COMPONENT_STOP_REQUEST] as i64;
    let kill_request = slots[SLOT_COMPONENT_KILL_REQUEST] as i64;
    if failure_step == 0
        && resolve_root == 0
        && provider_launch == 0
        && client_launch == 0
        && stop_request == 0
        && kill_request == 0
    {
        return None;
    }
    Some((
        failure_step,
        resolve_root,
        provider_launch,
        client_launch,
        stop_request,
        kill_request,
    ))
}

fn perf_summary_present(slots: &[u64]) -> bool {
    slots[SLOT_PERF_NULL_ITERS] != 0
        || slots[SLOT_PERF_WAIT_ITERS] != 0
        || slots[SLOT_PERF_WAKE_ITERS] != 0
        || slots[SLOT_PERF_TLB_ITERS] != 0
        || slots[SLOT_PERF_TLB_PEER_ITERS] != 0
        || slots[SLOT_PERF_FAULT_ITERS] != 0
        || slots[SLOT_PERF_CHANNEL_FRAGMENT_ITERS] != 0
        || slots[SLOT_PERF_FAILURE_STEP] != 0
}

fn update_perf_trace_slots(slots: &mut [u64]) {
    let channel = crate::object::transport::channel_telemetry_snapshot();
    slots[SLOT_TRACE_RECORDS] = crate::trace::bootstrap_trace_record_count();
    slots[SLOT_TRACE_DROPPED] = crate::trace::bootstrap_trace_dropped_count();
    slots[SLOT_TRACE_EXPORTED_BYTES] = crate::trace::bootstrap_trace_exported_bytes();
    slots[SLOT_TRACE_REMOTE_WAKE_PHASE3] = crate::trace::bootstrap_trace_remote_wake_phase3();
    slots[SLOT_TRACE_SCHED_MAX_RQ_DEPTH] =
        crate::trace::bootstrap_trace_sched_max_run_queue_depth();
    slots[SLOT_TRACE_SCHED_STEALS] = crate::trace::bootstrap_trace_sched_steal_count();
    slots[SLOT_TRACE_SCHED_HANDOFFS] = crate::trace::bootstrap_trace_sched_handoff_count();
    slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT] =
        crate::trace::bootstrap_trace_sched_remote_wake_latency_count();
    slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS] =
        crate::trace::bootstrap_trace_sched_remote_wake_latency_max_ns();
    slots[SLOT_TRACE_SCHED_STEAL_PHASE3] = crate::trace::bootstrap_trace_sched_steal_phase3();
    slots[SLOT_TRACE_SCHED_HANDOFF_PHASE3] = crate::trace::bootstrap_trace_sched_handoff_phase3();
    slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3] =
        crate::trace::bootstrap_trace_sched_remote_wake_latency_phase3();
    slots[SLOT_TRACE_SCHED_STEAL_PHASE5] = crate::trace::bootstrap_trace_sched_steal_phase5();
    slots[SLOT_TRACE_SCHED_PHASE3_OK] = u64::from(
        slots[SLOT_TRACE_REMOTE_WAKE_PHASE3] >= 63
            && slots[SLOT_TRACE_SCHED_HANDOFF_PHASE3] >= 63
            && slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3] >= 63,
    );
    slots[SLOT_TRACE_SYS_ENTER_PHASE1] = crate::trace::bootstrap_trace_sys_enter_phase1();
    slots[SLOT_TRACE_SYS_EXIT_PHASE1] = crate::trace::bootstrap_trace_sys_exit_phase1();
    slots[SLOT_TRACE_SYS_RETIRE_PHASE1] = crate::trace::bootstrap_trace_sys_retire_phase1();
    slots[SLOT_TRACE_CONTEXT_SWITCHES] = crate::trace::bootstrap_trace_context_switch_count();
    slots[SLOT_TRACE_TIMER_REPROGRAM] = crate::trace::bootstrap_trace_timer_reprogram_count();
    slots[SLOT_TRACE_TLB_SYNC_PLANS] = crate::trace::bootstrap_trace_tlb_sync_plan_count();
    slots[SLOT_TRACE_TLB_LOCAL_PAGE_FLUSH] =
        crate::trace::bootstrap_trace_tlb_local_page_flush_count();
    slots[SLOT_TRACE_TLB_LOCAL_FULL_FLUSH] =
        crate::trace::bootstrap_trace_tlb_local_full_flush_count();
    slots[SLOT_TRACE_TLB_SHOOTDOWN_PAGE] = crate::trace::bootstrap_trace_tlb_shootdown_page_count();
    slots[SLOT_TRACE_TLB_SHOOTDOWN_FULL] = crate::trace::bootstrap_trace_tlb_shootdown_full_count();
    slots[SLOT_TRACE_TLB_SHOOTDOWN_TARGET_CPUS] =
        crate::trace::bootstrap_trace_tlb_shootdown_target_cpu_total();
    slots[SLOT_TRACE_TLB_MAX_ACTIVE_CPUS] = crate::trace::bootstrap_trace_tlb_max_active_cpus();
    slots[SLOT_TRACE_TLB_LAST_ACTIVE_MASK] = crate::trace::bootstrap_trace_tlb_last_active_mask();
    slots[SLOT_TRACE_TLB_PAGE_FLUSH_PHASE4] = crate::trace::bootstrap_trace_tlb_page_flush_phase4();
    slots[SLOT_TRACE_TLB_FULL_FLUSH_PHASE4] = crate::trace::bootstrap_trace_tlb_full_flush_phase4();
    slots[SLOT_TRACE_TLB_SYNC_PLAN_PHASE4] = crate::trace::bootstrap_trace_tlb_sync_plan_phase4();
    slots[SLOT_TRACE_TLB_SYNC_PLAN_PHASE5] = crate::trace::bootstrap_trace_tlb_sync_plan_phase5();
    slots[SLOT_TRACE_TLB_SHOOTDOWN_FULL_PHASE5] =
        crate::trace::bootstrap_trace_tlb_shootdown_full_phase5();
    slots[SLOT_TRACE_FAULT_ENTER_PHASE6] = crate::trace::bootstrap_trace_fault_enter_phase6();
    slots[SLOT_TRACE_FAULT_HANDLED_PHASE6] = crate::trace::bootstrap_trace_fault_handled_phase6();
    slots[SLOT_TRACE_FAULT_BLOCK_PHASE6] = crate::trace::bootstrap_trace_fault_block_phase6();
    slots[SLOT_TRACE_FAULT_RESUME_PHASE6] = crate::trace::bootstrap_trace_fault_resume_phase6();
    slots[SLOT_TRACE_FAULT_UNHANDLED_PHASE6] =
        crate::trace::bootstrap_trace_fault_unhandled_phase6();
    slots[SLOT_TRACE_IPC_CHANNEL_ENQUEUE_PHASE7] =
        crate::trace::bootstrap_trace_ipc_channel_enqueue_phase7();
    slots[SLOT_TRACE_IPC_CHANNEL_DEQUEUE_PHASE7] =
        crate::trace::bootstrap_trace_ipc_channel_dequeue_phase7();
    slots[SLOT_TRACE_IPC_CHANNEL_RECLAIM_PHASE7] =
        crate::trace::bootstrap_trace_ipc_channel_reclaim_phase7();
    slots[SLOT_CHANNEL_FRAGMENT_POOL_NEW] = channel.fragment_pool_new_count;
    slots[SLOT_CHANNEL_FRAGMENT_POOL_REUSE] = channel.fragment_pool_reuse_count;
    slots[SLOT_CHANNEL_FRAGMENT_POOL_LOCAL_FREE] = channel.fragment_pool_local_free_count;
    slots[SLOT_CHANNEL_FRAGMENT_POOL_REMOTE_FREE] = channel.fragment_pool_remote_free_count;
    slots[SLOT_CHANNEL_FRAGMENT_POOL_CACHED_CURRENT] = channel.fragment_pool_cached_current;
    slots[SLOT_CHANNEL_FRAGMENT_POOL_CACHED_PEAK] = channel.fragment_pool_cached_peak;
    slots[SLOT_CHANNEL_FRAGMENTED_DESC_COUNT] = channel.fragmented_desc_count;
    slots[SLOT_CHANNEL_FRAGMENTED_BYTES_TOTAL] = channel.fragmented_bytes_total;
}

fn print_perf_summary(slots: &mut [u64]) {
    crate::trace::flush_bootstrap_trace();
    update_perf_trace_slots(slots);
    crate::kprintln!(
        "kernel: bootstrap perf smoke (perf_failure_step={}, perf_thread_create={}, perf_thread_start={}, perf_eventpair_create={}, perf_null_status={}, perf_null_iters={}, perf_null_cycles={}, perf_wait_status={}, perf_wait_iters={}, perf_wait_cycles={}, perf_wake_status={}, perf_wake_iters={}, perf_wake_cycles={}, perf_tlb_status={}, perf_tlb_iters={}, perf_tlb_cycles={}, perf_tlb_peer_status={}, perf_tlb_peer_iters={}, perf_tlb_peer_cycles={}, perf_fault_status={}, perf_fault_iters={}, perf_fault_cycles={}, perf_channel_fragment_status={}, perf_channel_fragment_iters={}, perf_channel_fragment_cycles={}, trace_vmo_h={}, trace_records={}, trace_dropped={}, trace_export_bytes={}, trace_remote_wake_phase3={}, trace_sched_max_rq_depth={}, trace_sched_steals={}, trace_sched_handoffs={}, trace_sched_remote_wake_latency_count={}, trace_sched_remote_wake_latency_max_ns={}, trace_sched_steal_phase3={}, trace_sched_handoff_phase3={}, trace_sched_remote_wake_latency_phase3={}, trace_sched_steal_phase5={}, trace_sched_phase3_ok={}, trace_sys_enter_phase1={}, trace_sys_exit_phase1={}, trace_sys_retire_phase1={}, trace_context_switches={}, trace_timer_reprogram={}, trace_tlb_sync_plans={}, trace_tlb_local_page_flush={}, trace_tlb_local_full_flush={}, trace_tlb_shootdown_page={}, trace_tlb_shootdown_full={}, trace_tlb_shootdown_target_cpus={}, trace_tlb_max_active_cpus={}, trace_tlb_last_active_mask={}, trace_tlb_page_flush_phase4={}, trace_tlb_full_flush_phase4={}, trace_tlb_sync_plan_phase4={}, trace_tlb_sync_plan_phase5={}, trace_tlb_shootdown_full_phase5={}, trace_fault_enter_phase6={}, trace_fault_handled_phase6={}, trace_fault_block_phase6={}, trace_fault_resume_phase6={}, trace_fault_unhandled_phase6={}, trace_ipc_channel_enqueue_phase7={}, trace_ipc_channel_dequeue_phase7={}, trace_ipc_channel_reclaim_phase7={}, channel_fragment_pool_new={}, channel_fragment_pool_reuse={}, channel_fragment_pool_local_free={}, channel_fragment_pool_remote_free={}, channel_fragment_pool_cached_current={}, channel_fragment_pool_cached_peak={}, channel_fragmented_desc_count={}, channel_fragmented_bytes_total={})",
        slots[SLOT_PERF_FAILURE_STEP],
        slots[SLOT_PERF_THREAD_CREATE] as i64,
        slots[SLOT_PERF_THREAD_START] as i64,
        slots[SLOT_PERF_EVENTPAIR_CREATE] as i64,
        slots[SLOT_PERF_NULL_STATUS] as i64,
        slots[SLOT_PERF_NULL_ITERS],
        slots[SLOT_PERF_NULL_CYCLES],
        slots[SLOT_PERF_WAIT_STATUS] as i64,
        slots[SLOT_PERF_WAIT_ITERS],
        slots[SLOT_PERF_WAIT_CYCLES],
        slots[SLOT_PERF_WAKE_STATUS] as i64,
        slots[SLOT_PERF_WAKE_ITERS],
        slots[SLOT_PERF_WAKE_CYCLES],
        slots[SLOT_PERF_TLB_STATUS] as i64,
        slots[SLOT_PERF_TLB_ITERS],
        slots[SLOT_PERF_TLB_CYCLES],
        slots[SLOT_PERF_TLB_PEER_STATUS] as i64,
        slots[SLOT_PERF_TLB_PEER_ITERS],
        slots[SLOT_PERF_TLB_PEER_CYCLES],
        slots[SLOT_PERF_FAULT_STATUS] as i64,
        slots[SLOT_PERF_FAULT_ITERS],
        slots[SLOT_PERF_FAULT_CYCLES],
        slots[SLOT_PERF_CHANNEL_FRAGMENT_STATUS] as i64,
        slots[SLOT_PERF_CHANNEL_FRAGMENT_ITERS],
        slots[SLOT_PERF_CHANNEL_FRAGMENT_CYCLES],
        slots[SLOT_TRACE_VMO_H],
        slots[SLOT_TRACE_RECORDS],
        slots[SLOT_TRACE_DROPPED],
        slots[SLOT_TRACE_EXPORTED_BYTES],
        slots[SLOT_TRACE_REMOTE_WAKE_PHASE3],
        slots[SLOT_TRACE_SCHED_MAX_RQ_DEPTH],
        slots[SLOT_TRACE_SCHED_STEALS],
        slots[SLOT_TRACE_SCHED_HANDOFFS],
        slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT],
        slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS],
        slots[SLOT_TRACE_SCHED_STEAL_PHASE3],
        slots[SLOT_TRACE_SCHED_HANDOFF_PHASE3],
        slots[SLOT_TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3],
        slots[SLOT_TRACE_SCHED_STEAL_PHASE5],
        slots[SLOT_TRACE_SCHED_PHASE3_OK],
        slots[SLOT_TRACE_SYS_ENTER_PHASE1],
        slots[SLOT_TRACE_SYS_EXIT_PHASE1],
        slots[SLOT_TRACE_SYS_RETIRE_PHASE1],
        slots[SLOT_TRACE_CONTEXT_SWITCHES],
        slots[SLOT_TRACE_TIMER_REPROGRAM],
        slots[SLOT_TRACE_TLB_SYNC_PLANS],
        slots[SLOT_TRACE_TLB_LOCAL_PAGE_FLUSH],
        slots[SLOT_TRACE_TLB_LOCAL_FULL_FLUSH],
        slots[SLOT_TRACE_TLB_SHOOTDOWN_PAGE],
        slots[SLOT_TRACE_TLB_SHOOTDOWN_FULL],
        slots[SLOT_TRACE_TLB_SHOOTDOWN_TARGET_CPUS],
        slots[SLOT_TRACE_TLB_MAX_ACTIVE_CPUS],
        slots[SLOT_TRACE_TLB_LAST_ACTIVE_MASK],
        slots[SLOT_TRACE_TLB_PAGE_FLUSH_PHASE4],
        slots[SLOT_TRACE_TLB_FULL_FLUSH_PHASE4],
        slots[SLOT_TRACE_TLB_SYNC_PLAN_PHASE4],
        slots[SLOT_TRACE_TLB_SYNC_PLAN_PHASE5],
        slots[SLOT_TRACE_TLB_SHOOTDOWN_FULL_PHASE5],
        slots[SLOT_TRACE_FAULT_ENTER_PHASE6],
        slots[SLOT_TRACE_FAULT_HANDLED_PHASE6],
        slots[SLOT_TRACE_FAULT_BLOCK_PHASE6],
        slots[SLOT_TRACE_FAULT_RESUME_PHASE6],
        slots[SLOT_TRACE_FAULT_UNHANDLED_PHASE6],
        slots[SLOT_TRACE_IPC_CHANNEL_ENQUEUE_PHASE7],
        slots[SLOT_TRACE_IPC_CHANNEL_DEQUEUE_PHASE7],
        slots[SLOT_TRACE_IPC_CHANNEL_RECLAIM_PHASE7],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_NEW],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_REUSE],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_LOCAL_FREE],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_REMOTE_FREE],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_CACHED_CURRENT],
        slots[SLOT_CHANNEL_FRAGMENT_POOL_CACHED_PEAK],
        slots[SLOT_CHANNEL_FRAGMENTED_DESC_COUNT],
        slots[SLOT_CHANNEL_FRAGMENTED_BYTES_TOTAL]
    );
}

/// Called by the breakpoint handler to print the userspace-produced summary.
pub fn on_breakpoint(frame: *const crate::arch::int80::TrapFrame) -> ! {
    let slots = shared_slots();
    if slots[SLOT_OK] != 1 {
        let (trap_rax, trap_rbx, trap_rip) = if frame.is_null() {
            (0, 0, 0)
        } else {
            // SAFETY: the breakpoint entry path passes a valid pointer to a saved register frame
            // with the same layout as `int80::TrapFrame`.
            let frame = unsafe { &*frame };
            (frame.rax as i64, frame.rbx, frame.rcx)
        };
        crate::kprintln!(
            "userspace: conformance reported failure (ok=0, trap_rax={}, trap_rbx={:#x}, trap_rcx={:#x}, unknown={}, close_invalid={}, port_create_bad_opts={}, port_create_null_out={}, queue={}, wait={}, port_wait_readable={}, port_wait_readable_observed={}, t0_ns={}, tx=[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}], rx=[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}], component_failure_step={}, provider_stage={}, provider_status={}, client_stage={}, client_status={}, provider_event_read={}, provider_event_code={}, client_event_read={}, client_event_code={}, stop_request={}, stop_event_read={}, stop_event_code={}, stop_wait_observed={}, kill_request={}, kill_event_read={}, kill_event_code={}, kill_wait_observed={})",
            trap_rax,
            trap_rbx,
            trap_rip,
            slots[SLOT_UNKNOWN] as i64,
            slots[SLOT_CLOSE_INVALID] as i64,
            slots[SLOT_PORT_CREATE_BAD_OPTS] as i64,
            slots[SLOT_PORT_CREATE_NULL_OUT] as i64,
            slots[SLOT_QUEUE] as i64,
            slots[SLOT_WAIT] as i64,
            slots[SLOT_PORT_WAIT_READABLE] as i64,
            slots[SLOT_PORT_WAIT_READABLE_OBS],
            slots[SLOT_T0_NS],
            slots[648],
            slots[649],
            slots[650],
            slots[651],
            slots[652],
            slots[653],
            slots[656],
            slots[657],
            slots[658],
            slots[659],
            slots[660],
            slots[661],
            slots[SLOT_COMPONENT_FAILURE_STEP],
            slots[SLOT_COMPONENT_PROVIDER_STAGE],
            slots[SLOT_COMPONENT_PROVIDER_STATUS] as i64,
            slots[SLOT_COMPONENT_CLIENT_STAGE],
            slots[SLOT_COMPONENT_CLIENT_STATUS] as i64,
            slots[SLOT_COMPONENT_PROVIDER_EVENT_READ] as i64,
            slots[SLOT_COMPONENT_PROVIDER_EVENT_CODE] as i64,
            slots[SLOT_COMPONENT_CLIENT_EVENT_READ] as i64,
            slots[SLOT_COMPONENT_CLIENT_EVENT_CODE] as i64,
            slots[SLOT_COMPONENT_STOP_REQUEST] as i64,
            slots[SLOT_COMPONENT_STOP_EVENT_READ] as i64,
            slots[SLOT_COMPONENT_STOP_EVENT_CODE] as i64,
            slots[SLOT_COMPONENT_STOP_WAIT_OBSERVED],
            slots[SLOT_COMPONENT_KILL_REQUEST] as i64,
            slots[SLOT_COMPONENT_KILL_EVENT_READ] as i64,
            slots[SLOT_COMPONENT_KILL_EVENT_CODE] as i64,
            slots[SLOT_COMPONENT_KILL_WAIT_OBSERVED]
        );
        crate::kprintln!(
            "userspace: early slots queue={} wait={} tx=[{:016x} {:016x} {:016x} {:016x} {:016x} {:016x}] rx=[{:016x} {:016x} {:016x} {:016x} {:016x} {:016x}]",
            slots[SLOT_QUEUE] as i64,
            slots[SLOT_WAIT] as i64,
            slots[136],
            slots[137],
            slots[138],
            slots[139],
            slots[140],
            slots[141],
            slots[144],
            slots[145],
            slots[146],
            slots[147],
            slots[148],
            slots[149],
        );
        if perf_summary_present(slots) {
            print_perf_summary(slots);
        }
        crate::arch::qemu::exit_failure();
    }
    let socket_stats = crate::object::transport::socket_telemetry_snapshot();
    let channel_stats = crate::object::transport::channel_telemetry_snapshot();
    slots[SLOT_SOCKET_BUFFERED_CURRENT] = socket_stats.current_buffered_bytes;
    slots[SLOT_SOCKET_BUFFERED_PEAK] = socket_stats.peak_buffered_bytes;
    slots[SLOT_SOCKET_SHORT_WRITES] = socket_stats.short_write_count;
    slots[SLOT_SOCKET_WRITE_SHOULD_WAIT] = socket_stats.write_should_wait_count;
    let heap_stats = crate::kalloc::bootstrap_heap_stats();
    slots[SLOT_BOOTSTRAP_HEAP_USED] = heap_stats.used_bytes as u64;
    slots[SLOT_BOOTSTRAP_HEAP_PEAK] = heap_stats.peak_bytes as u64;
    slots[SLOT_BOOTSTRAP_HEAP_ALLOC_FAILS] = heap_stats.alloc_fail_count as u64;

    crate::kprintln!(
        "kernel: bootstrap heap used={} peak={} capacity={} alloc_failures={}",
        heap_stats.used_bytes,
        heap_stats.peak_bytes,
        heap_stats.capacity_bytes,
        heap_stats.alloc_fail_count
    );

    if perf_summary_present(slots) {
        print_perf_summary(slots);
    }

    crate::kprintln!(
        "kernel: int80 conformance ok (unknown={}, close_invalid={}, port_create_bad_opts={}, port_create_null_out={}, bad_wait={}, port_wait_null_out={}, empty_wait={}, port_queue_null_pkt={}, port_queue_bad_type={}, queue={}, wait={}, timer_create_bad_opts={}, timer_create_bad_clock={}, timer_create_null_out={}, port_wait_wrong_type={}, port_queue_wrong_type={}, timer_set_wrong_type={}, timer_cancel_wrong_type={}, wait_one_unsignaled={}, wait_one_unsignaled_observed={}, wait_async={}, timer_set_immediate={}, wait_signal={}, signal_trigger={}, signal_observed={}, signal_count={}, wait_one_signaled={}, wait_one_signaled_observed={}, wait_one_future_timeout={}, wait_one_future_timeout_observed={}, wait_one_future_ok={}, wait_one_future_ok_observed={}, wait_async_bad_options={}, wait_async_ts={}, wait_signal_ts={}, signal_timestamp={}, signal_timestamp_ok={}, wait_async_boot={}, wait_signal_boot={}, signal_boot_timestamp={}, signal_boot_timestamp_ok={}, edge_wait_async={}, edge_empty_wait={}, edge_signal_wait={}, edge_signal_key={}, reserve_queue_full={}, reserve_wait_async={}, reserve_signal_after_users_ok={}, reserve_signal_type={}, pending_wait_async={}, pending_signal_wait={}, pending_signal_count={}, pending_merge_ok={}, vmo_create_bad_opts={}, vmo_create_null_out={}, vmo_create={}, vmar_map_bad_type={}, vmar_map_bad_opts={}, vmar_map={}, vmar_map_addr={}, vmar_map_write_ok={}, vmar_overlap={}, vmar_protect={}, vmar_reprotect={}, vmar_unmap={}, vmar_remap={}, channel_create_bad_opts={}, channel_create_null_out0={}, channel_create_null_out1={}, channel_create={}, channel_read_empty={}, channel_write={}, channel_wait_readable={}, channel_wait_readable_ok={}, channel_read={}, channel_read_actual_bytes={}, channel_read_actual_handles={}, channel_read_match={}, channel_close_peer={}, channel_write_peer_closed={}, channel_read_peer_closed={}, channel_wait_peer_closed={}, channel_wait_peer_closed_observed={}, eventpair_create_bad_opts={}, eventpair_create_null_out0={}, eventpair_create_null_out1={}, eventpair_create={}, eventpair_signal_bad_mask={}, eventpair_signal_peer={}, eventpair_wait_signal={}, eventpair_wait_signal_observed={}, eventpair_close_peer={}, eventpair_wait_peer_closed={}, eventpair_wait_peer_closed_observed={}, channel_loan_tx_vmo_create={}, channel_loan_tx_map={}, channel_loan_rx_vmo_create={}, channel_loan_rx_map={}, channel_loan_create={}, channel_loan_write={}, channel_loan_read={}, channel_loan_actual_bytes={}, channel_loan_snapshot_ok={}, handle_duplicate={}, handle_duplicate_distinct={}, handle_duplicate_signal={}, handle_duplicate_wait={}, handle_duplicate_wait_observed={}, handle_dup_reduced={}, handle_dup_reduced_denied={}, handle_replace={}, handle_replace_old_bad={}, handle_replace_signal={}, handle_replace_wait={}, handle_replace_wait_observed={}, object_signal_bad_mask={}, object_signal_wait_async={}, object_signal_self={}, object_signal_port_wait={}, object_signal_key={}, futex_wait_bad_state={}, futex_wait_self_owner={}, futex_wait_timeout={}, futex_get_owner_initial={}, futex_owner_initial={}, futex_get_owner_timeout={}, futex_owner_timeout={}, futex_requeue_same_key={}, futex_requeue_wrong_type={}, futex_requeue_ok={}, futex_get_owner_requeue={}, futex_owner_match_self={}, futex_wake_zero={}, futex_get_owner_wake={}, futex_owner_wake={}, channel_transfer_create={}, channel_transfer_eventpair_create={}, channel_transfer_write={}, channel_transfer_close_old={}, channel_transfer_read={}, channel_transfer_actual_bytes={}, channel_transfer_actual_handles={}, channel_transfer_signal={}, channel_transfer_wait={}, channel_transfer_wait_observed={}, task_kill_process={}, task_kill_thread_create_after={}, task_wait_thread_terminated={}, task_wait_thread_terminated_observed={}, task_wait_process_terminated={}, task_wait_process_terminated_observed={}, task_reap_close_thread={}, task_reap_close_process={}, task_suspend_process={}, task_suspend_token_present={}, task_suspend_close_token={}, task_suspend_resumed={}, task_suspend_held={}, thread_create={}, thread_start={}, thread_child_ran={}, thread_futex_wait={}, thread_wake_status={}, thread_resumed={}, thread_wait_one={}, thread_wait_one_observed={}, thread_signal_status={}, thread_port_wait={}, thread_port_packet_key={}, thread_port_packet_type={}, thread_port_queue_status={}, timer_set={}, timer_cancel={}, timer_close={}, timer_close_again={}, close={}, close_again={}, root_vmar_h={}, port_h={}, timer_h={}, vmo_h={}, channel_h0={}, channel_h1={}, eventpair_h0={}, eventpair_h1={}, channel_loan_remap_cow_ok={}, channel_loan_remap_source_rmap_count={}, vm_cow_fault_count={}, vm_last_remap_source_rmap_count={}, vm_last_cow_old_rmap_count={}, vm_last_cow_new_rmap_count={}, channel_close_read_create={}, channel_close_read_write={}, channel_close_read_close={}, channel_close_read_wait={}, channel_close_read_wait_observed={}, channel_close_read_status={}, channel_close_read_actual_bytes={}, channel_close_read_match={}, channel_close_drain_wait={}, channel_close_drain_wait_observed={}, channel_close_drain_read={}, channel_writable_recovery_create={}, channel_writable_recovery_fill={}, channel_writable_recovery_full_write={}, channel_writable_recovery_wait_full={}, channel_writable_recovery_wait_full_observed={}, channel_writable_recovery_read={}, channel_writable_recovery_wait_restored={}, channel_writable_recovery_wait_restored_observed={}, channel_writable_recovery_close={}, channel_writable_recovery_wait_closed={}, channel_writable_recovery_wait_closed_observed={}, channel_writable_recovery_write_closed={}, process_create={}, process_map_parent_code={}, process_map_parent_shared={}, process_map_child_code={}, process_map_child_shared={}, process_map_child_stack={}, process_thread_create={}, process_start={}, process_child_ran={}, process_parent_futex_wait={}, vmar_far_vmo_create={}, vmar_far_map={}, vmar_far_map_addr={}, vmar_far_write_ok={}, vmar_far_unmap={}, vmar_allocate_bad_type={}, vmar_allocate_bad_opts={}, vmar_allocate={}, vmar_allocate_handle_ok={}, vmar_allocate_addr_nonzero={}, vmar_allocate_map={}, vmar_allocate_map_match={}, vmar_allocate_no_specific={}, vmar_allocate_specific_denied={}, vmar_allocate_nonspecific_map={}, vmar_allocate_nonspecific_match={}, vmar_destroy={}, vmar_destroy_remap={}, vmar_allocate_grandchild={}, vmar_allocate_grandchild_match={}, vmar_allocate_grandchild_map={}, vmar_allocate_grandchild_map_match={}, vmar_allocate_upper_limit={}, vmar_allocate_upper_limit_match={}, vmar_allocate_grandchild_compact={}, vmar_allocate_grandchild_compact_match={}, vmar_allocate_align={}, vmar_allocate_align_ok={}, vmar_allocate_specific_align_bad={}, vmar_destroy_stale_map={}, vmar_destroy_stale_close={}, process_map_parent_lazy_shared={}, process_map_child_lazy_shared={}, process_lazy_shared_match={}, vm_private_cow_pages_current={}, vm_private_cow_pages_peak={}, vm_private_cow_quota_hits={}, vm_inflight_loan_pages_current={}, vm_inflight_loan_pages_peak={}, vm_inflight_loan_quota_hits={}, channel_loan_quota_fill={}, channel_loan_quota_write_limit={}, channel_loan_quota_read={}, channel_loan_quota_write_recover={}, vm_fault_leader_claims={}, vm_fault_wait_claims={}, vm_fault_wait_spin_loops={}, vm_fault_retry_total={}, vm_fault_commit_resolved={}, vm_fault_commit_retry={}, vm_fault_prepare_cow={}, vm_fault_prepare_lazy_anon={}, vm_fault_prepare_lazy_vmo_alloc={}, timer_wait_forever={}, timer_wait_forever_observed={}, vm_fault_local_wait_ok={}, vm_fault_shared_wait_ok={}, port_wait_writable={}, port_wait_writable_observed={}, port_wait_readable={}, port_wait_readable_observed={}, vmo_rw_create={}, vmo_write={}, vmo_read={}, vmo_read_match={}, vmo_set_size_grow={}, vmo_set_size_map={}, vmo_set_size_map_match={}, vmo_set_size_shrink_busy={}, vmo_set_size_shrink={}, vmo_write_out_of_range={}, socket_create={}, socket_wait_writable={}, socket_wait_writable_observed={}, socket_write={}, socket_wait_readable={}, socket_wait_readable_observed={}, socket_peek={}, socket_peek_match={}, socket_read={}, socket_read_match={}, socket_close_peer={}, socket_wait_peer_closed={}, socket_wait_peer_closed_observed={}, socket_write_peer_closed={}, socket_read_peer_closed={}, socket_fill_short_write={}, socket_fill_short_actual={}, socket_fill_wait_full={}, socket_fill_drain={}, socket_fill_recover={}, socket_duplicate={}, socket_dup_close_original={}, socket_dup_wait_open={}, socket_dup_close_last={}, socket_dup_wait_peer_closed={}, socket_dup_wait_peer_closed_observed={}, socket_create_datagram={}, socket_create_bad_opts={}, socket_write_zero_null={}, socket_read_bad_null={}, socket_write_bad_opts={}, socket_read_bad_opts={}, socket_read_actual_null={}, socket_wait_async={}, socket_wait_async_write={}, socket_wait_async_port_wait={}, socket_wait_async_key={}, socket_wait_async_type={}, socket_wait_async_observed={}, socket_wait_async_writable={}, socket_wait_async_writable_port_wait={}, socket_dup_write_after_close={}, socket_dup_read_after_close={}, socket_dup_read_after_close_match={}, socket_buffered_current={}, socket_buffered_peak={}, socket_short_writes={}, socket_write_should_wait={}, socket_dup_write_after_close_actual={}, socket_dup_read_after_close_actual={})",
        slots[SLOT_UNKNOWN] as i64,
        slots[SLOT_CLOSE_INVALID] as i64,
        slots[SLOT_PORT_CREATE_BAD_OPTS] as i64,
        slots[SLOT_PORT_CREATE_NULL_OUT] as i64,
        slots[SLOT_BAD_WAIT] as i64,
        slots[SLOT_PORT_WAIT_NULL_OUT] as i64,
        slots[SLOT_EMPTY_WAIT] as i64,
        slots[SLOT_PORT_QUEUE_NULL_PKT] as i64,
        slots[SLOT_PORT_QUEUE_BAD_TYPE] as i64,
        slots[SLOT_QUEUE] as i64,
        slots[SLOT_WAIT] as i64,
        slots[SLOT_TIMER_CREATE_BAD_OPTS] as i64,
        slots[SLOT_TIMER_CREATE_BAD_CLOCK] as i64,
        slots[SLOT_TIMER_CREATE_NULL_OUT] as i64,
        slots[SLOT_PORT_WAIT_WRONG_TYPE] as i64,
        slots[SLOT_PORT_QUEUE_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_SET_WRONG_TYPE] as i64,
        slots[SLOT_TIMER_CANCEL_WRONG_TYPE] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED] as i64,
        slots[SLOT_WAIT_ONE_UNSIGNALED_OBS] as i64,
        slots[SLOT_WAIT_ASYNC] as i64,
        slots[SLOT_TIMER_SET_IMMEDIATE] as i64,
        slots[SLOT_WAIT_SIGNAL] as i64,
        slots[SLOT_SIGNAL_TRIGGER] as i64,
        slots[SLOT_SIGNAL_OBSERVED] as i64,
        slots[SLOT_SIGNAL_COUNT],
        slots[SLOT_WAIT_ONE_SIGNALED] as i64,
        slots[SLOT_WAIT_ONE_SIGNALED_OBS] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_TIMEOUT] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_TIMEOUT_OBS] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_OK] as i64,
        slots[SLOT_WAIT_ONE_FUTURE_OK_OBS] as i64,
        slots[SLOT_WAIT_ASYNC_BAD_OPTIONS] as i64,
        slots[SLOT_WAIT_ASYNC_TS] as i64,
        slots[SLOT_WAIT_SIGNAL_TS] as i64,
        slots[SLOT_SIGNAL_TIMESTAMP] as i64,
        slots[SLOT_SIGNAL_TIMESTAMP_OK] as i64,
        slots[SLOT_WAIT_ASYNC_BOOT] as i64,
        slots[SLOT_WAIT_SIGNAL_BOOT] as i64,
        slots[SLOT_SIGNAL_BOOT_TIMESTAMP] as i64,
        slots[SLOT_SIGNAL_BOOT_TIMESTAMP_OK] as i64,
        slots[SLOT_EDGE_WAIT_ASYNC] as i64,
        slots[SLOT_EDGE_EMPTY_WAIT] as i64,
        slots[SLOT_EDGE_SIGNAL_WAIT] as i64,
        slots[SLOT_EDGE_SIGNAL_KEY] as i64,
        slots[SLOT_RESERVE_QUEUE_FULL] as i64,
        slots[SLOT_RESERVE_WAIT_ASYNC] as i64,
        slots[SLOT_RESERVE_SIGNAL_AFTER_USERS_OK] as i64,
        slots[SLOT_RESERVE_SIGNAL_TYPE] as i64,
        slots[SLOT_PENDING_WAIT_ASYNC] as i64,
        slots[SLOT_PENDING_SIGNAL_WAIT] as i64,
        slots[SLOT_PENDING_SIGNAL_COUNT] as i64,
        slots[SLOT_PENDING_MERGE_OK] as i64,
        slots[SLOT_VMO_CREATE_BAD_OPTS] as i64,
        slots[SLOT_VMO_CREATE_NULL_OUT] as i64,
        slots[SLOT_VMO_CREATE] as i64,
        slots[SLOT_VMAR_MAP_BAD_TYPE] as i64,
        slots[SLOT_VMAR_MAP_BAD_OPTS] as i64,
        slots[SLOT_VMAR_MAP] as i64,
        slots[SLOT_VMAR_MAP_ADDR] as i64,
        slots[SLOT_VMAR_MAP_WRITE_OK] as i64,
        slots[SLOT_VMAR_OVERLAP] as i64,
        slots[SLOT_VMAR_PROTECT] as i64,
        slots[SLOT_VMAR_REPROTECT] as i64,
        slots[SLOT_VMAR_UNMAP] as i64,
        slots[SLOT_VMAR_REMAP] as i64,
        slots[SLOT_CHANNEL_CREATE_BAD_OPTS] as i64,
        slots[SLOT_CHANNEL_CREATE_NULL_OUT0] as i64,
        slots[SLOT_CHANNEL_CREATE_NULL_OUT1] as i64,
        slots[SLOT_CHANNEL_CREATE] as i64,
        slots[SLOT_CHANNEL_READ_EMPTY] as i64,
        slots[SLOT_CHANNEL_WRITE] as i64,
        slots[SLOT_CHANNEL_WAIT_READABLE] as i64,
        slots[SLOT_CHANNEL_WAIT_READABLE_OK] as i64,
        slots[SLOT_CHANNEL_READ] as i64,
        slots[SLOT_CHANNEL_READ_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_READ_ACTUAL_HANDLES] as i64,
        slots[SLOT_CHANNEL_READ_MATCH] as i64,
        slots[SLOT_CHANNEL_CLOSE_PEER] as i64,
        slots[SLOT_CHANNEL_WRITE_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_READ_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_EVENTPAIR_CREATE_BAD_OPTS] as i64,
        slots[SLOT_EVENTPAIR_CREATE_NULL_OUT0] as i64,
        slots[SLOT_EVENTPAIR_CREATE_NULL_OUT1] as i64,
        slots[SLOT_EVENTPAIR_CREATE] as i64,
        slots[SLOT_EVENTPAIR_SIGNAL_BAD_MASK] as i64,
        slots[SLOT_EVENTPAIR_SIGNAL_PEER] as i64,
        slots[SLOT_EVENTPAIR_WAIT_SIGNAL] as i64,
        slots[SLOT_EVENTPAIR_WAIT_SIGNAL_OBS] as i64,
        slots[SLOT_EVENTPAIR_CLOSE_PEER] as i64,
        slots[SLOT_EVENTPAIR_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_EVENTPAIR_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_CHANNEL_LOAN_TX_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_TX_MAP] as i64,
        slots[SLOT_CHANNEL_LOAN_RX_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_RX_MAP] as i64,
        slots[SLOT_CHANNEL_LOAN_CREATE] as i64,
        slots[SLOT_CHANNEL_LOAN_WRITE] as i64,
        slots[SLOT_CHANNEL_LOAN_READ] as i64,
        slots[SLOT_CHANNEL_LOAN_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_LOAN_SNAPSHOT_OK] as i64,
        slots[SLOT_HANDLE_DUPLICATE] as i64,
        slots[SLOT_HANDLE_DUPLICATE_DISTINCT] as i64,
        slots[SLOT_HANDLE_DUPLICATE_SIGNAL] as i64,
        slots[SLOT_HANDLE_DUPLICATE_WAIT] as i64,
        slots[SLOT_HANDLE_DUPLICATE_WAIT_OBS] as i64,
        slots[SLOT_HANDLE_DUP_REDUCED] as i64,
        slots[SLOT_HANDLE_DUP_REDUCED_DENIED] as i64,
        slots[SLOT_HANDLE_REPLACE] as i64,
        slots[SLOT_HANDLE_REPLACE_OLD_BAD] as i64,
        slots[SLOT_HANDLE_REPLACE_SIGNAL] as i64,
        slots[SLOT_HANDLE_REPLACE_WAIT] as i64,
        slots[SLOT_HANDLE_REPLACE_WAIT_OBS] as i64,
        slots[SLOT_OBJECT_SIGNAL_BAD_MASK] as i64,
        slots[SLOT_OBJECT_SIGNAL_WAIT_ASYNC] as i64,
        slots[SLOT_OBJECT_SIGNAL_SELF] as i64,
        slots[SLOT_OBJECT_SIGNAL_PORT_WAIT] as i64,
        slots[SLOT_OBJECT_SIGNAL_KEY] as i64,
        slots[SLOT_FUTEX_WAIT_BAD_STATE] as i64,
        slots[SLOT_FUTEX_WAIT_SELF_OWNER] as i64,
        slots[SLOT_FUTEX_WAIT_TIMEOUT] as i64,
        slots[SLOT_FUTEX_GET_OWNER_INITIAL] as i64,
        slots[SLOT_FUTEX_OWNER_INITIAL] as i64,
        slots[SLOT_FUTEX_GET_OWNER_TIMEOUT] as i64,
        slots[SLOT_FUTEX_OWNER_TIMEOUT] as i64,
        slots[SLOT_FUTEX_REQUEUE_SAME_KEY] as i64,
        slots[SLOT_FUTEX_REQUEUE_WRONG_TYPE] as i64,
        slots[SLOT_FUTEX_REQUEUE_OK] as i64,
        slots[SLOT_FUTEX_GET_OWNER_REQUEUE] as i64,
        slots[SLOT_FUTEX_OWNER_MATCH_SELF] as i64,
        slots[SLOT_FUTEX_WAKE_ZERO] as i64,
        slots[SLOT_FUTEX_GET_OWNER_WAKE] as i64,
        slots[SLOT_FUTEX_OWNER_WAKE] as i64,
        slots[SLOT_CHANNEL_TRANSFER_CREATE] as i64,
        slots[SLOT_CHANNEL_TRANSFER_EVENTPAIR_CREATE] as i64,
        slots[SLOT_CHANNEL_TRANSFER_WRITE] as i64,
        slots[SLOT_CHANNEL_TRANSFER_CLOSE_OLD] as i64,
        slots[SLOT_CHANNEL_TRANSFER_READ] as i64,
        slots[SLOT_CHANNEL_TRANSFER_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_TRANSFER_ACTUAL_HANDLES] as i64,
        slots[SLOT_CHANNEL_TRANSFER_SIGNAL] as i64,
        slots[SLOT_CHANNEL_TRANSFER_WAIT] as i64,
        slots[SLOT_CHANNEL_TRANSFER_WAIT_OBS] as i64,
        slots[SLOT_TASK_KILL_PROCESS] as i64,
        slots[SLOT_TASK_KILL_THREAD_CREATE_AFTER] as i64,
        slots[SLOT_TASK_WAIT_THREAD_TERMINATED] as i64,
        slots[SLOT_TASK_WAIT_THREAD_TERMINATED_OBS] as i64,
        slots[SLOT_TASK_WAIT_PROCESS_TERMINATED] as i64,
        slots[SLOT_TASK_WAIT_PROCESS_TERMINATED_OBS] as i64,
        slots[SLOT_TASK_REAP_CLOSE_THREAD] as i64,
        slots[SLOT_TASK_REAP_CLOSE_PROCESS] as i64,
        slots[SLOT_TASK_SUSPEND_PROCESS] as i64,
        slots[SLOT_TASK_SUSPEND_TOKEN_PRESENT] as i64,
        slots[SLOT_TASK_SUSPEND_CLOSE_TOKEN] as i64,
        slots[SLOT_TASK_SUSPEND_RESUMED] as i64,
        slots[SLOT_TASK_SUSPEND_HELD] as i64,
        slots[SLOT_THREAD_CREATE] as i64,
        slots[SLOT_THREAD_START] as i64,
        slots[SLOT_THREAD_CHILD_RAN] as i64,
        slots[SLOT_THREAD_FUTEX_WAIT] as i64,
        slots[SLOT_THREAD_WAKE_STATUS] as i64,
        slots[SLOT_THREAD_RESUMED] as i64,
        slots[SLOT_THREAD_WAIT_ONE] as i64,
        slots[SLOT_THREAD_WAIT_ONE_OBS] as i64,
        slots[SLOT_THREAD_SIGNAL_STATUS] as i64,
        slots[SLOT_THREAD_PORT_WAIT] as i64,
        slots[SLOT_THREAD_PORT_PACKET_KEY] as i64,
        slots[SLOT_THREAD_PORT_PACKET_TYPE] as i64,
        slots[SLOT_THREAD_PORT_QUEUE_STATUS] as i64,
        slots[SLOT_TIMER_SET] as i64,
        slots[SLOT_TIMER_CANCEL] as i64,
        slots[SLOT_TIMER_CLOSE] as i64,
        slots[SLOT_TIMER_CLOSE_AGAIN] as i64,
        slots[SLOT_CLOSE] as i64,
        slots[SLOT_CLOSE_AGAIN] as i64,
        slots[SLOT_ROOT_VMAR_H],
        slots[SLOT_PORT_H],
        slots[SLOT_TIMER_H],
        slots[SLOT_VMO_H],
        slots[SLOT_CHANNEL_H0],
        slots[SLOT_CHANNEL_H1],
        slots[SLOT_EVENTPAIR_H0],
        slots[SLOT_EVENTPAIR_H1],
        slots[SLOT_CHANNEL_LOAN_REMAP_COW_OK] as i64,
        slots[SLOT_CHANNEL_LOAN_REMAP_SOURCE_RMAP_COUNT],
        slots[SLOT_VM_COW_FAULT_COUNT],
        slots[SLOT_VM_LAST_REMAP_SOURCE_RMAP_COUNT],
        slots[SLOT_VM_LAST_COW_OLD_RMAP_COUNT],
        slots[SLOT_VM_LAST_COW_NEW_RMAP_COUNT],
        slots[SLOT_CHANNEL_CLOSE_READ_CREATE] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_WRITE] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_CLOSE] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_WAIT] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_WAIT_OBS] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_STATUS] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_ACTUAL_BYTES] as i64,
        slots[SLOT_CHANNEL_CLOSE_READ_MATCH] as i64,
        slots[SLOT_CHANNEL_CLOSE_DRAIN_WAIT] as i64,
        slots[SLOT_CHANNEL_CLOSE_DRAIN_WAIT_OBS] as i64,
        slots[SLOT_CHANNEL_CLOSE_DRAIN_READ] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_CREATE] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_FILL] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_FULL_WRITE] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_FULL] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_FULL_OBS] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_READ] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_RESTORED] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_RESTORED_OBS] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_CLOSE] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_CLOSED] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WAIT_CLOSED_OBS] as i64,
        slots[SLOT_CHANNEL_WRITABLE_RECOVERY_WRITE_CLOSED] as i64,
        slots[SLOT_PROCESS_CREATE] as i64,
        slots[SLOT_PROCESS_MAP_PARENT_CODE] as i64,
        slots[SLOT_PROCESS_MAP_PARENT_SHARED] as i64,
        slots[SLOT_PROCESS_MAP_CHILD_CODE] as i64,
        slots[SLOT_PROCESS_MAP_CHILD_SHARED] as i64,
        slots[SLOT_PROCESS_MAP_CHILD_STACK] as i64,
        slots[SLOT_PROCESS_THREAD_CREATE] as i64,
        slots[SLOT_PROCESS_START] as i64,
        slots[SLOT_PROCESS_CHILD_RAN] as i64,
        slots[SLOT_PROCESS_PARENT_FUTEX_WAIT] as i64,
        slots[SLOT_VMAR_FAR_VMO_CREATE] as i64,
        slots[SLOT_VMAR_FAR_MAP] as i64,
        slots[SLOT_VMAR_FAR_MAP_ADDR] as i64,
        slots[SLOT_VMAR_FAR_WRITE_OK] as i64,
        slots[SLOT_VMAR_FAR_UNMAP] as i64,
        slots[SLOT_VMAR_ALLOCATE_BAD_TYPE] as i64,
        slots[SLOT_VMAR_ALLOCATE_BAD_OPTS] as i64,
        slots[SLOT_VMAR_ALLOCATE] as i64,
        slots[SLOT_VMAR_ALLOCATE_HANDLE_OK] as i64,
        slots[SLOT_VMAR_ALLOCATE_ADDR_NONZERO] as i64,
        slots[SLOT_VMAR_ALLOCATE_MAP] as i64,
        slots[SLOT_VMAR_ALLOCATE_MAP_MATCH] as i64,
        slots[SLOT_VMAR_ALLOCATE_NO_SPECIFIC] as i64,
        slots[SLOT_VMAR_ALLOCATE_SPECIFIC_DENIED] as i64,
        slots[SLOT_VMAR_ALLOCATE_NONSPECIFIC_MAP] as i64,
        slots[SLOT_VMAR_ALLOCATE_NONSPECIFIC_MATCH] as i64,
        slots[SLOT_VMAR_DESTROY] as i64,
        slots[SLOT_VMAR_DESTROY_REMAP] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD_MATCH] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD_MAP] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD_MAP_MATCH] as i64,
        slots[SLOT_VMAR_ALLOCATE_UPPER_LIMIT] as i64,
        slots[SLOT_VMAR_ALLOCATE_UPPER_LIMIT_MATCH] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD_COMPACT] as i64,
        slots[SLOT_VMAR_ALLOCATE_GRANDCHILD_COMPACT_MATCH] as i64,
        slots[SLOT_VMAR_ALLOCATE_ALIGN] as i64,
        slots[SLOT_VMAR_ALLOCATE_ALIGN_OK] as i64,
        slots[SLOT_VMAR_ALLOCATE_SPECIFIC_ALIGN_BAD] as i64,
        slots[SLOT_VMAR_DESTROY_STALE_MAP] as i64,
        slots[SLOT_VMAR_DESTROY_STALE_CLOSE] as i64,
        slots[SLOT_PROCESS_MAP_PARENT_LAZY_SHARED] as i64,
        slots[SLOT_PROCESS_MAP_CHILD_LAZY_SHARED] as i64,
        slots[SLOT_PROCESS_LAZY_SHARED_MATCH] as i64,
        slots[SLOT_VM_PRIVATE_COW_PAGES_CURRENT],
        slots[SLOT_VM_PRIVATE_COW_PAGES_PEAK],
        slots[SLOT_VM_PRIVATE_COW_QUOTA_HITS],
        slots[SLOT_VM_INFLIGHT_LOAN_PAGES_CURRENT],
        slots[SLOT_VM_INFLIGHT_LOAN_PAGES_PEAK],
        slots[SLOT_VM_INFLIGHT_LOAN_QUOTA_HITS],
        slots[SLOT_CHANNEL_LOAN_QUOTA_FILL] as i64,
        slots[SLOT_CHANNEL_LOAN_QUOTA_WRITE_LIMIT] as i64,
        slots[SLOT_CHANNEL_LOAN_QUOTA_READ] as i64,
        slots[SLOT_CHANNEL_LOAN_QUOTA_WRITE_RECOVER] as i64,
        slots[SLOT_VM_FAULT_LEADER_CLAIMS],
        slots[SLOT_VM_FAULT_WAIT_CLAIMS],
        slots[SLOT_VM_FAULT_WAIT_SPIN_LOOPS],
        slots[SLOT_VM_FAULT_RETRY_TOTAL],
        slots[SLOT_VM_FAULT_COMMIT_RESOLVED],
        slots[SLOT_VM_FAULT_COMMIT_RETRY],
        slots[SLOT_VM_FAULT_PREPARE_COW],
        slots[SLOT_VM_FAULT_PREPARE_LAZY_ANON],
        slots[SLOT_VM_FAULT_PREPARE_LAZY_VMO_ALLOC],
        slots[SLOT_TIMER_WAIT_FOREVER] as i64,
        slots[SLOT_TIMER_WAIT_FOREVER_OBS] as i64,
        slots[SLOT_VM_FAULT_LOCAL_WAIT_OK] as i64,
        slots[SLOT_VM_FAULT_SHARED_WAIT_OK] as i64,
        slots[SLOT_PORT_WAIT_WRITABLE] as i64,
        slots[SLOT_PORT_WAIT_WRITABLE_OBS] as i64,
        slots[SLOT_PORT_WAIT_READABLE] as i64,
        slots[SLOT_PORT_WAIT_READABLE_OBS] as i64,
        slots[SLOT_VMO_RW_CREATE] as i64,
        slots[SLOT_VMO_WRITE] as i64,
        slots[SLOT_VMO_READ] as i64,
        slots[SLOT_VMO_READ_MATCH] as i64,
        slots[SLOT_VMO_SET_SIZE_GROW] as i64,
        slots[SLOT_VMO_SET_SIZE_MAP] as i64,
        slots[SLOT_VMO_SET_SIZE_MAP_MATCH] as i64,
        slots[SLOT_VMO_SET_SIZE_SHRINK_BUSY] as i64,
        slots[SLOT_VMO_SET_SIZE_SHRINK] as i64,
        slots[SLOT_VMO_WRITE_OUT_OF_RANGE] as i64,
        slots[SLOT_SOCKET_CREATE] as i64,
        slots[SLOT_SOCKET_WAIT_WRITABLE] as i64,
        slots[SLOT_SOCKET_WAIT_WRITABLE_OBS] as i64,
        slots[SLOT_SOCKET_WRITE] as i64,
        slots[SLOT_SOCKET_WAIT_READABLE] as i64,
        slots[SLOT_SOCKET_WAIT_READABLE_OBS] as i64,
        slots[SLOT_SOCKET_PEEK] as i64,
        slots[SLOT_SOCKET_PEEK_MATCH] as i64,
        slots[SLOT_SOCKET_READ] as i64,
        slots[SLOT_SOCKET_READ_MATCH] as i64,
        slots[SLOT_SOCKET_CLOSE_PEER] as i64,
        slots[SLOT_SOCKET_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_SOCKET_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_SOCKET_WRITE_PEER_CLOSED] as i64,
        slots[SLOT_SOCKET_READ_PEER_CLOSED] as i64,
        slots[SLOT_SOCKET_FILL_SHORT_WRITE] as i64,
        slots[SLOT_SOCKET_FILL_SHORT_ACTUAL] as i64,
        slots[SLOT_SOCKET_FILL_WAIT_FULL] as i64,
        slots[SLOT_SOCKET_FILL_DRAIN] as i64,
        slots[SLOT_SOCKET_FILL_RECOVER] as i64,
        slots[SLOT_SOCKET_DUPLICATE] as i64,
        slots[SLOT_SOCKET_DUP_CLOSE_ORIGINAL] as i64,
        slots[SLOT_SOCKET_DUP_WAIT_OPEN] as i64,
        slots[SLOT_SOCKET_DUP_CLOSE_LAST] as i64,
        slots[SLOT_SOCKET_DUP_WAIT_PEER_CLOSED] as i64,
        slots[SLOT_SOCKET_DUP_WAIT_PEER_CLOSED_OBS] as i64,
        slots[SLOT_SOCKET_CREATE_DATAGRAM] as i64,
        slots[SLOT_SOCKET_CREATE_BAD_OPTS] as i64,
        slots[SLOT_SOCKET_WRITE_ZERO_NULL] as i64,
        slots[SLOT_SOCKET_READ_BAD_NULL] as i64,
        slots[SLOT_SOCKET_WRITE_BAD_OPTS] as i64,
        slots[SLOT_SOCKET_READ_BAD_OPTS] as i64,
        slots[SLOT_SOCKET_READ_ACTUAL_NULL] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_WRITE] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_PORT_WAIT] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_KEY] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_TYPE] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_OBSERVED] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_WRITABLE] as i64,
        slots[SLOT_SOCKET_WAIT_ASYNC_WRITABLE_PORT_WAIT] as i64,
        slots[SLOT_SOCKET_DUP_WRITE_AFTER_CLOSE] as i64,
        slots[SLOT_SOCKET_DUP_READ_AFTER_CLOSE] as i64,
        slots[SLOT_SOCKET_DUP_READ_AFTER_CLOSE_MATCH] as i64,
        slots[SLOT_SOCKET_BUFFERED_CURRENT] as i64,
        slots[SLOT_SOCKET_BUFFERED_PEAK] as i64,
        slots[SLOT_SOCKET_SHORT_WRITES] as i64,
        slots[SLOT_SOCKET_WRITE_SHOULD_WAIT] as i64,
        slots[SLOT_SOCKET_DUP_WRITE_AFTER_CLOSE_ACTUAL] as i64,
        slots[SLOT_SOCKET_DUP_READ_AFTER_CLOSE_ACTUAL] as i64
    );

    crate::kprintln!(
        "kernel: channel fragmented payload (channel_fragmented_create={}, channel_fragmented_tx_vmo_create={}, channel_fragmented_tx_map={}, channel_fragmented_rx_remap_vmo_create={}, channel_fragmented_rx_remap_map={}, channel_fragmented_rx_copy_vmo_create={}, channel_fragmented_rx_copy_map={}, channel_fragmented_write_remap={}, channel_fragmented_read_remap={}, channel_fragmented_actual_bytes_remap={}, channel_fragmented_match_remap={}, channel_fragmented_write_copy={}, channel_fragmented_read_copy={}, channel_fragmented_actual_bytes_copy={}, channel_fragmented_match_copy={}, channel_desc_enqueued={}, channel_desc_dequeued={}, channel_desc_reclaimed={}, channel_desc_drained={}, channel_fragmented_desc_count={}, channel_fragmented_bytes_total={}, channel_fragment_pool_new={}, channel_fragment_pool_reuse={}, channel_fragment_pool_local_free={}, channel_fragment_pool_remote_free={}, channel_fragment_pool_cached_current={}, channel_fragment_pool_cached_peak={})",
        slots[SLOT_CHANNEL_FRAGMENTED_CREATE] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_TX_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_TX_MAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_RX_REMAP_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_RX_REMAP_MAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_RX_COPY_VMO_CREATE] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_RX_COPY_MAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_WRITE_REMAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_READ_REMAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_ACTUAL_BYTES_REMAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_MATCH_REMAP] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_WRITE_COPY] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_READ_COPY] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_ACTUAL_BYTES_COPY] as i64,
        slots[SLOT_CHANNEL_FRAGMENTED_MATCH_COPY] as i64,
        channel_stats.desc_enqueued_count as i64,
        channel_stats.desc_dequeued_count as i64,
        channel_stats.desc_reclaimed_count as i64,
        channel_stats.desc_drained_count as i64,
        channel_stats.fragmented_desc_count as i64,
        channel_stats.fragmented_bytes_total as i64,
        channel_stats.fragment_pool_new_count as i64,
        channel_stats.fragment_pool_reuse_count as i64,
        channel_stats.fragment_pool_local_free_count as i64,
        channel_stats.fragment_pool_remote_free_count as i64,
        channel_stats.fragment_pool_cached_current as i64,
        channel_stats.fragment_pool_cached_peak as i64
    );

    crate::kprintln!(
        "kernel: channel wait_async signals (channel_wait_async_port_create={}, channel_wait_async_create={}, channel_wait_async_fill={}, channel_wait_async_full_write={}, channel_wait_async_arm_writable={}, channel_wait_async_read={}, channel_wait_async_port_wait_writable={}, channel_wait_async_writable_key={}, channel_wait_async_writable_type={}, channel_wait_async_writable_observed={}, channel_wait_async_arm_peer_closed={}, channel_wait_async_close_peer={}, channel_wait_async_port_wait_closed={}, channel_wait_async_closed_key={}, channel_wait_async_closed_type={}, channel_wait_async_closed_observed={})",
        slots[SLOT_CHANNEL_WAIT_ASYNC_PORT_CREATE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_CREATE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_FILL] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_FULL_WRITE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_ARM_WRITABLE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_READ] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_PORT_WAIT_WRITABLE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_KEY] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_TYPE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_WRITABLE_OBSERVED] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_ARM_PEER_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_CLOSE_PEER] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_PORT_WAIT_CLOSED] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_CLOSED_KEY] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_CLOSED_TYPE] as i64,
        slots[SLOT_CHANNEL_WAIT_ASYNC_CLOSED_OBSERVED] as i64
    );

    crate::kprintln!(
        "kernel: userspace runtime dispatcher (rt_failure_step={}, rt_dispatcher_create={}, rt_reg_create_first={}, rt_reg_cancel_first={}, rt_reg_create_second={}, rt_reg_slot_reused={}, rt_reg_generation_advanced={}, rt_channel_create={}, rt_channel_seed_write={}, rt_channel_recv={}, rt_channel_recv_actual_bytes={}, rt_channel_recv_match={}, rt_sleep_create={}, rt_sleep_wait={}, rt_channel_call_create={}, rt_channel_call_server_spawn={}, rt_channel_call_server_recv={}, rt_channel_call_server_match={}, rt_channel_call_server_reply={}, rt_channel_call={}, rt_channel_call_actual_bytes={}, rt_channel_call_match={}, rt_socket_create={}, rt_socket_seed_write={}, rt_socket_wait_readable={}, rt_socket_wait_observed={}, rt_socket_read={}, rt_socket_read_actual_bytes={}, rt_socket_read_match={}, rt_close_seed_tx={}, rt_close_seed_rx={}, rt_close_call_client={}, rt_close_call_server={}, rt_close_socket_tx={}, rt_close_socket_rx={})",
        slots[SLOT_RUNTIME_FAILURE_STEP],
        slots[SLOT_RUNTIME_DISPATCHER_CREATE] as i64,
        slots[SLOT_RUNTIME_REG_CREATE_FIRST] as i64,
        slots[SLOT_RUNTIME_REG_CANCEL_FIRST] as i64,
        slots[SLOT_RUNTIME_REG_CREATE_SECOND] as i64,
        slots[SLOT_RUNTIME_REG_SLOT_REUSED],
        slots[SLOT_RUNTIME_REG_GEN_ADVANCED],
        slots[SLOT_RUNTIME_CHANNEL_CREATE] as i64,
        slots[SLOT_RUNTIME_CHANNEL_SEED_WRITE] as i64,
        slots[SLOT_RUNTIME_CHANNEL_RECV] as i64,
        slots[SLOT_RUNTIME_CHANNEL_RECV_ACTUAL_BYTES],
        slots[SLOT_RUNTIME_CHANNEL_RECV_MATCH],
        slots[SLOT_RUNTIME_SLEEP_CREATE] as i64,
        slots[SLOT_RUNTIME_SLEEP_WAIT] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL_CREATE] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL_SERVER_SPAWN] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL_SERVER_RECV] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL_SERVER_MATCH],
        slots[SLOT_RUNTIME_CHANNEL_CALL_SERVER_REPLY] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL] as i64,
        slots[SLOT_RUNTIME_CHANNEL_CALL_ACTUAL_BYTES],
        slots[SLOT_RUNTIME_CHANNEL_CALL_MATCH],
        slots[SLOT_RUNTIME_SOCKET_CREATE] as i64,
        slots[SLOT_RUNTIME_SOCKET_SEED_WRITE] as i64,
        slots[SLOT_RUNTIME_SOCKET_WAIT_READABLE] as i64,
        slots[SLOT_RUNTIME_SOCKET_WAIT_OBSERVED],
        slots[SLOT_RUNTIME_SOCKET_READ] as i64,
        slots[SLOT_RUNTIME_SOCKET_READ_ACTUAL_BYTES],
        slots[SLOT_RUNTIME_SOCKET_READ_MATCH],
        slots[SLOT_RUNTIME_CLOSE_SEED_TX] as i64,
        slots[SLOT_RUNTIME_CLOSE_SEED_RX] as i64,
        slots[SLOT_RUNTIME_CLOSE_CALL_CLIENT] as i64,
        slots[SLOT_RUNTIME_CLOSE_CALL_SERVER] as i64,
        slots[SLOT_RUNTIME_CLOSE_SOCKET_TX] as i64,
        slots[SLOT_RUNTIME_CLOSE_SOCKET_RX] as i64
    );

    crate::kprintln!(
        "kernel: component manager bootstrap (failure_step={}, resolve_root={}, resolve_provider={}, resolve_client={}, provider_outgoing_pair={}, provider_launch={}, client_route={}, client_launch={}, provider_event_read={}, provider_event_code={}, client_event_read={}, client_event_code={}, lazy_provider_prelaunch={}, lazy_provider_route_launch={}, stop_request={}, stop_event_read={}, stop_event_code={}, stop_wait_observed={}, kill_request={}, kill_event_read={}, kill_event_code={}, kill_wait_observed={}, provider_stage={}, provider_status={}, client_stage={}, client_status={})",
        slots[SLOT_COMPONENT_FAILURE_STEP],
        slots[SLOT_COMPONENT_RESOLVE_ROOT] as i64,
        slots[SLOT_COMPONENT_RESOLVE_PROVIDER] as i64,
        slots[SLOT_COMPONENT_RESOLVE_CLIENT] as i64,
        slots[SLOT_COMPONENT_PROVIDER_OUTGOING_PAIR] as i64,
        slots[SLOT_COMPONENT_PROVIDER_LAUNCH] as i64,
        slots[SLOT_COMPONENT_CLIENT_ROUTE] as i64,
        slots[SLOT_COMPONENT_CLIENT_LAUNCH] as i64,
        slots[SLOT_COMPONENT_PROVIDER_EVENT_READ] as i64,
        slots[SLOT_COMPONENT_PROVIDER_EVENT_CODE] as i64,
        slots[SLOT_COMPONENT_CLIENT_EVENT_READ] as i64,
        slots[SLOT_COMPONENT_CLIENT_EVENT_CODE] as i64,
        slots[SLOT_COMPONENT_LAZY_PROVIDER_PRELAUNCH] as i64,
        slots[SLOT_COMPONENT_LAZY_PROVIDER_ROUTE_LAUNCH] as i64,
        slots[SLOT_COMPONENT_STOP_REQUEST] as i64,
        slots[SLOT_COMPONENT_STOP_EVENT_READ] as i64,
        slots[SLOT_COMPONENT_STOP_EVENT_CODE] as i64,
        slots[SLOT_COMPONENT_STOP_WAIT_OBSERVED],
        slots[SLOT_COMPONENT_KILL_REQUEST] as i64,
        slots[SLOT_COMPONENT_KILL_EVENT_READ] as i64,
        slots[SLOT_COMPONENT_KILL_EVENT_CODE] as i64,
        slots[SLOT_COMPONENT_KILL_WAIT_OBSERVED],
        slots[SLOT_COMPONENT_PROVIDER_STAGE],
        slots[SLOT_COMPONENT_PROVIDER_STATUS] as i64,
        slots[SLOT_COMPONENT_CLIENT_STAGE],
        slots[SLOT_COMPONENT_CLIENT_STATUS] as i64
    );

    crate::arch::qemu::exit_success();
}

/// Enter ring3 and run the embedded userspace conformance program.
pub fn prepare() -> u64 {
    map_userspace_pages();
    let entry = match try_load_user_program_from_qemu_loader() {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            load_user_program_embedded();
            USER_CODE_VA
        }
        Err(status) => {
            crate::kprintln!(
                "userspace: bootstrap runner import failed status={}",
                status
            );
            panic!("userspace: bootstrap runner import failed");
        }
    };

    // Zero shared slots and set `ok=0` pessimistically.
    let slots = shared_slots();
    for i in 0..=SLOT_MAX {
        slots[i] = 0;
    }
    slots[SLOT_ROOT_VMAR_H] = crate::object::vm::bootstrap_root_vmar_handle().unwrap_or(0) as u64;
    slots[SLOT_SELF_THREAD_H] =
        crate::object::process::bootstrap_self_thread_handle().unwrap_or(0) as u64;
    slots[SLOT_SELF_THREAD_KOID] =
        crate::object::process::bootstrap_self_thread_koid().unwrap_or(0);
    slots[SLOT_SELF_PROCESS_H] =
        crate::object::process::bootstrap_self_process_handle().unwrap_or(0) as u64;
    slots[SLOT_SELF_CODE_VMO_H] =
        crate::object::vm::bootstrap_self_code_vmo_handle().unwrap_or(0) as u64;
    slots[SLOT_BOOT_IMAGE_ECHO_PROVIDER_VMO_H] =
        crate::object::vm::bootstrap_echo_provider_code_vmo_handle().unwrap_or(0) as u64;
    slots[SLOT_BOOT_IMAGE_ECHO_CLIENT_VMO_H] =
        crate::object::vm::bootstrap_echo_client_code_vmo_handle().unwrap_or(0) as u64;
    slots[SLOT_BOOT_IMAGE_CONTROLLER_WORKER_VMO_H] =
        crate::object::vm::bootstrap_controller_worker_code_vmo_handle().unwrap_or(0) as u64;
    slots[SLOT_BOOT_IMAGE_STARNIX_KERNEL_VMO_H] =
        crate::object::vm::bootstrap_starnix_kernel_code_vmo_handle().unwrap_or(0) as u64;
    slots[SLOT_BOOT_IMAGE_LINUX_HELLO_VMO_H] =
        crate::object::vm::bootstrap_linux_hello_code_vmo_handle().unwrap_or(0) as u64;
    crate::trace::init_bootstrap_trace();
    slots[SLOT_TRACE_VMO_H] = u64::from(crate::trace::bootstrap_trace_vmo_handle());
    slots[SLOT_TRACE_PHASE] = 0;
    // Keep the exported bootstrap code-image VMO span stable for the runner ABI. The parsed
    // image layout is an internal loader detail; the bootstrap code window is still the legacy
    // fixed-size mapping.
    slots[SLOT_SELF_CODE_VMO_SIZE] = USER_CODE_BYTES;
    slots[SLOT_BOOTSTRAP_HEAP_USED] = 0;
    slots[SLOT_BOOTSTRAP_HEAP_PEAK] = 0;
    slots[SLOT_BOOTSTRAP_HEAP_ALLOC_FAILS] = 0;

    entry
}

/// Enter ring3 at `entry` and run until the conformance runner exits via `int3`.
pub fn enter(entry: u64) -> ! {
    // Provide the runner baseline as late as possible so "future deadline" checks are relative
    // to actual ring3 start, not earlier bootstrap work like SMP bring-up.
    shared_slots()[SLOT_T0_NS] = crate::time::now_ns() as u64;
    let selectors = crate::arch::gdt::init();

    // SAFETY: we build a valid iret frame to transition to ring3 using the installed GDT selectors.
    unsafe {
        use x86_64::instructions::segmentation::{DS, ES};

        DS::set_reg(selectors.user_data);
        ES::set_reg(selectors.user_data);

        let stack = USER_STACK_TOP;
        // The bootstrap ring3 bridge still enters outside the generic scheduler/launch path, so
        // keep IF masked here. Threads started through `start_thread()` / `start_process()`
        // receive IF=1 via `UserContext::new_user_entry()`.
        let rflags: u64 = 0x002; // bit1 set, IF=0

        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) selectors.user_data.0 as u64,
            rsp = in(reg) stack,
            rflags = in(reg) rflags,
            cs = in(reg) selectors.user_code.0 as u64,
            rip = in(reg) entry,
            options(noreturn),
        );
    }
}

/// Convenience wrapper (prepare + enter).
pub fn run() -> ! {
    let entry = prepare();
    enter(entry)
}

// --- Embedded userspace program (one page) ---

core::arch::global_asm!(
    include_str!("../../../specs/conformance/runner/int80_conformance.S"),
    options(att_syntax)
);

// Compile-time witness: slot indices must fit in the shared two-page u64 slot window.
const _: () = assert!(SLOT_MAX < 1024);
