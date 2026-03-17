extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::__cpuid;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use libzircon::signals::{ZX_TASK_TERMINATED, ZX_USER_SIGNAL_0};
use libzircon::status::{ZX_ERR_BAD_SYSCALL, ZX_OK};
use libzircon::syscall_numbers::{AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP};
use libzircon::vm::{ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    zx_channel_create, zx_channel_read, zx_channel_write, zx_eventpair_create, zx_handle_close,
    zx_handle_t, zx_object_signal, zx_object_signal_peer, zx_object_wait_one, zx_signals_t,
    zx_status_t, zx_task_kill, zx_thread_create, zx_thread_start, zx_vmo_create, zx_vmo_write,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;

const SLOT_OK: usize = 0;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_T0_NS: usize = 511;
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
const SLOT_PERF_THREAD_CREATE: usize = 625;
const SLOT_PERF_THREAD_START: usize = 626;
const SLOT_PERF_EVENTPAIR_CREATE: usize = 627;
const SLOT_PERF_TLB_STATUS: usize = 628;
const SLOT_PERF_TLB_ITERS: usize = 629;
const SLOT_PERF_TLB_CYCLES: usize = 630;
const SLOT_VM_FAULT_TEST_HOOK_ARM: usize = 431;
const SLOT_PERF_TLB_PEER_STATUS: usize = 643;
const SLOT_PERF_TLB_PEER_ITERS: usize = 644;
const SLOT_PERF_TLB_PEER_CYCLES: usize = 645;
const SLOT_PERF_FAULT_STATUS: usize = 662;
const SLOT_PERF_FAULT_ITERS: usize = 663;
const SLOT_PERF_FAULT_CYCLES: usize = 664;
const SLOT_PERF_CHANNEL_FRAGMENT_STATUS: usize = 679;
const SLOT_PERF_CHANNEL_FRAGMENT_ITERS: usize = 680;
const SLOT_PERF_CHANNEL_FRAGMENT_CYCLES: usize = 681;

const STEP_NULL_SYSCALL: u64 = 1;
const STEP_WAIT_PING_PONG: u64 = 2;
const STEP_WAKEUP: u64 = 3;
const STEP_TLB_CHURN: u64 = 4;
const STEP_TLB_ACTIVE_PEER: u64 = 5;
const STEP_FAULT_TIMELINE: u64 = 6;
const STEP_CHANNEL_FRAGMENT: u64 = 7;
const STEP_PANIC: u64 = u64::MAX;

const PHASE_NULL_SYSCALL: u64 = 1;
const PHASE_WAIT_PING_PONG: u64 = 2;
const PHASE_WAKEUP: u64 = 3;
const PHASE_TLB_CHURN: u64 = 4;
const PHASE_TLB_ACTIVE_PEER: u64 = 5;
const PHASE_FAULT_TIMELINE: u64 = 6;
const PHASE_CHANNEL_FRAGMENT: u64 = 7;

const NULL_SYSCALL_ITERS: u64 = 64;
const WAIT_PING_PONG_ITERS: u64 = 32;
const WAKE_ITERS: u64 = 32;
const TLB_ITERS: u64 = 8;
const TLB_ACTIVE_PEER_ITERS: u64 = 8;
const FAULT_TIMELINE_ITERS: u64 = 1;
const CHANNEL_FRAGMENT_ITERS: u64 = 8;
const TLB_CHURN_BYTES: u64 = 4096;
const CHANNEL_FRAGMENT_MAPPING_BYTES: u64 = 3 * 4096;
const CHANNEL_FRAGMENT_BYTES: usize = 2 * 4096;
const CHANNEL_FRAGMENT_OFFSET: usize = 64;
const WORKER_STACK_BYTES: usize = 4096;
const HEAP_BYTES: usize = 64 * 1024;
const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const CROSS_CORE_START_ATTEMPTS: usize = 8;
const CPU_ID_UNKNOWN: u64 = u64::MAX;
const WORKER_MODE_ROUNDTRIP: u64 = 0;
const WORKER_MODE_FAULT_TIMELINE: u64 = 1;
const WORKER_WAIT_STATE_UNKNOWN: u64 = 0;
const WORKER_WAIT_STATE_PARKED: u64 = 1;
const WORKER_WAIT_STATE_RUNNING: u64 = 2;
#[repr(align(16))]
struct WorkerStack([u8; WORKER_STACK_BYTES]);
#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static ROUNDTRIP_WORKER_CPU: AtomicU64 = AtomicU64::new(CPU_ID_UNKNOWN);
static ROUNDTRIP_WORKER_MODE: AtomicU64 = AtomicU64::new(WORKER_MODE_ROUNDTRIP);
static ROUNDTRIP_WORKER_WAIT_STATE: AtomicU64 = AtomicU64::new(WORKER_WAIT_STATE_UNKNOWN);
static ROUNDTRIP_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static mut WAIT_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut WAKE_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

// SAFETY: this allocator only serves the single-process bootstrap perf smoke.
// It monotonically carves out disjoint regions from one fixed static buffer,
// honors alignment, and never reuses freed memory.
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
                    // SAFETY: `HEAP` is the dedicated backing storage for this allocator.
                    // The atomic bump pointer grants each caller a unique, non-overlapping
                    // range within the static heap.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    let summary = run_perf_smoke();
    write_summary(&summary);
    write_slot(SLOT_TRACE_PHASE, 0);
    write_slot(SLOT_OK, 1);
    axle_arch_x86_64::debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_PERF_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_TRACE_PHASE, 0);
    write_slot(SLOT_OK, 1);
    axle_arch_x86_64::debug_break()
}

#[derive(Clone, Copy, Default)]
struct PerfSummary {
    failure_step: u64,
    null_status: i64,
    null_iters: u64,
    null_cycles: u64,
    wait_status: i64,
    wait_iters: u64,
    wait_cycles: u64,
    wake_status: i64,
    wake_iters: u64,
    wake_cycles: u64,
    tlb_status: i64,
    tlb_iters: u64,
    tlb_cycles: u64,
    tlb_peer_status: i64,
    tlb_peer_iters: u64,
    tlb_peer_cycles: u64,
    fault_status: i64,
    fault_iters: u64,
    fault_cycles: u64,
    channel_fragment_status: i64,
    channel_fragment_iters: u64,
    channel_fragment_cycles: u64,
    thread_create: i64,
    thread_start: i64,
    eventpair_create: i64,
}

#[derive(Clone, Copy, Default)]
struct RoundtripResult {
    status: i64,
    cycles: u64,
    thread_create: i64,
    thread_start: i64,
    eventpair_create: i64,
}

#[derive(Clone, Copy, Default)]
struct CrossCoreWorker {
    worker_thread: zx_handle_t,
    main_ep: zx_handle_t,
    worker_ep: zx_handle_t,
}

#[derive(Clone, Copy, Default)]
struct CrossCoreRoundtrip {
    result: RoundtripResult,
    worker: CrossCoreWorker,
}

fn run_perf_smoke() -> PerfSummary {
    let mut summary = PerfSummary::default();
    let self_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    let root_vmar = read_slot(SLOT_ROOT_VMAR_H) as zx_handle_t;

    summary.null_iters = NULL_SYSCALL_ITERS;
    write_slot(SLOT_TRACE_PHASE, PHASE_NULL_SYSCALL);
    let null_start = axle_arch_x86_64::rdtsc();
    for _ in 0..NULL_SYSCALL_ITERS {
        let status = axle_arch_x86_64::int80_syscall(u64::MAX, [0; 6]);
        if status != ZX_ERR_BAD_SYSCALL {
            summary.null_status = i64::from(status);
            summary.failure_step = STEP_NULL_SYSCALL;
            write_slot(SLOT_TRACE_PHASE, 0);
            return summary;
        }
    }
    summary.null_cycles = axle_arch_x86_64::rdtsc().wrapping_sub(null_start);
    summary.null_status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);

    let wait = run_cross_core_eventpair_roundtrip(
        self_process,
        PHASE_WAIT_PING_PONG,
        WAIT_PING_PONG_ITERS,
        wait_worker_stack_top(),
    );
    summary.thread_create = wait.result.thread_create;
    summary.thread_start = wait.result.thread_start;
    summary.eventpair_create = wait.result.eventpair_create;
    summary.wait_status = wait.result.status;
    summary.wait_iters = WAIT_PING_PONG_ITERS;
    summary.wait_cycles = wait.result.cycles;
    if wait.result.status != ZX_OK as i64 {
        close_cross_core_worker(wait.worker);
        summary.failure_step = STEP_WAIT_PING_PONG;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let wake_worker = wait.worker;
    let wake = run_cross_core_eventpair_phase(wake_worker, PHASE_WAKEUP, WAKE_ITERS);
    summary.wake_status = wake.status;
    summary.wake_iters = WAKE_ITERS;
    summary.wake_cycles = wake.cycles;
    if wake.status != ZX_OK as i64 {
        close_cross_core_worker(wake_worker);
        summary.failure_step = STEP_WAKEUP;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let tlb = run_tlb_churn(root_vmar, TLB_ITERS);
    summary.tlb_status = tlb.status;
    summary.tlb_iters = TLB_ITERS;
    summary.tlb_cycles = tlb.cycles;
    if tlb.status != ZX_OK as i64 {
        close_cross_core_worker(wake_worker);
        summary.failure_step = STEP_TLB_CHURN;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let tlb_peer = run_tlb_active_peer(root_vmar, TLB_ACTIVE_PEER_ITERS);
    summary.tlb_peer_status = tlb_peer.status;
    summary.tlb_peer_iters = TLB_ACTIVE_PEER_ITERS;
    summary.tlb_peer_cycles = tlb_peer.cycles;
    if tlb_peer.status != ZX_OK as i64 {
        close_cross_core_worker(wake_worker);
        summary.failure_step = STEP_TLB_ACTIVE_PEER;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let fault = run_fault_timeline(wake_worker, root_vmar, FAULT_TIMELINE_ITERS);
    summary.fault_status = fault.status;
    summary.fault_iters = FAULT_TIMELINE_ITERS;
    summary.fault_cycles = fault.cycles;
    close_cross_core_worker(wake_worker);
    if fault.status != ZX_OK as i64 {
        summary.failure_step = STEP_FAULT_TIMELINE;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    write_slot(SLOT_TRACE_PHASE, 0);

    let channel_fragment = run_channel_fragment(root_vmar, CHANNEL_FRAGMENT_ITERS);
    summary.channel_fragment_status = channel_fragment.status;
    summary.channel_fragment_iters = CHANNEL_FRAGMENT_ITERS;
    summary.channel_fragment_cycles = channel_fragment.cycles;
    if channel_fragment.status != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_FRAGMENT;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    summary
}

fn run_eventpair_roundtrip_phase(
    main_ep: zx_handle_t,
    phase: u64,
    iterations: u64,
) -> RoundtripResult {
    let mut result = RoundtripResult::default();
    wait_for_worker_parked();
    write_slot(SLOT_TRACE_PHASE, phase);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        if zx_object_signal_peer(main_ep, 0, ZX_USER_SIGNAL_0) != ZX_OK {
            result.status = -1;
            write_slot(SLOT_TRACE_PHASE, 0);
            return result;
        }
        let mut observed: zx_signals_t = 0;
        let status = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            return result;
        }
        if zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0) != ZX_OK {
            result.status = -2;
            write_slot(SLOT_TRACE_PHASE, 0);
            return result;
        }
        wait_for_worker_parked();
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);
    result
}

fn close_roundtrip_worker(
    worker_thread: zx_handle_t,
    worker_ep: zx_handle_t,
    main_ep: zx_handle_t,
) {
    if worker_thread != 0 {
        let _ = zx_task_kill(worker_thread);
        let mut terminated_observed: zx_signals_t = 0;
        let _ = zx_object_wait_one(
            worker_thread,
            ZX_TASK_TERMINATED,
            wait_deadline(),
            &mut terminated_observed,
        );
        let _ = zx_handle_close(worker_thread);
    }
    if worker_ep != 0 {
        let _ = zx_handle_close(worker_ep);
    }
    if main_ep != 0 {
        let _ = zx_handle_close(main_ep);
    }
}

fn run_cross_core_eventpair_roundtrip(
    process: zx_handle_t,
    phase: u64,
    iterations: u64,
    worker_stack_top: u64,
) -> CrossCoreRoundtrip {
    let mut result = RoundtripResult::default();
    let mut worker = CrossCoreWorker::default();
    for attempt in 0..CROSS_CORE_START_ATTEMPTS {
        let mut main_ep: zx_handle_t = 0;
        let mut worker_ep: zx_handle_t = 0;
        result.eventpair_create = zx_eventpair_create(0, &mut main_ep, &mut worker_ep) as i64;
        if result.eventpair_create != ZX_OK as i64 {
            result.status = result.eventpair_create;
            return CrossCoreRoundtrip { result, worker };
        }

        let mut worker_thread: zx_handle_t = 0;
        result.thread_create = zx_thread_create(process, 0, &mut worker_thread) as i64;
        if result.thread_create != ZX_OK as i64 {
            result.status = result.thread_create;
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            return CrossCoreRoundtrip { result, worker };
        }

        ROUNDTRIP_WORKER_CPU.store(CPU_ID_UNKNOWN, Ordering::Release);
        ROUNDTRIP_WORKER_WAIT_STATE.store(WORKER_WAIT_STATE_UNKNOWN, Ordering::Release);
        result.thread_start = zx_thread_start(
            worker_thread,
            cross_core_roundtrip_worker_entry as *const () as usize as u64,
            worker_stack_top,
            worker_ep,
            iterations,
        ) as i64;
        if result.thread_start != ZX_OK as i64 {
            result.status = result.thread_start;
            let _ = zx_handle_close(worker_thread);
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            return CrossCoreRoundtrip { result, worker };
        }

        let mut observed: zx_signals_t = 0;
        let ready = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if ready != ZX_OK {
            result.status = -11;
            close_roundtrip_worker(worker_thread, worker_ep, main_ep);
            return CrossCoreRoundtrip { result, worker };
        }
        let _ = zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0);

        if ROUNDTRIP_WORKER_CPU.load(Ordering::Acquire) == current_cpu_apic_id() {
            close_roundtrip_worker(worker_thread, worker_ep, main_ep);
            if attempt + 1 == CROSS_CORE_START_ATTEMPTS {
                result.status = -12;
                return CrossCoreRoundtrip { result, worker };
            }
            continue;
        }

        let phase_result = run_eventpair_roundtrip_phase(main_ep, phase, iterations);
        result.status = phase_result.status;
        result.cycles = phase_result.cycles;
        if result.status != ZX_OK as i64 {
            close_roundtrip_worker(worker_thread, worker_ep, main_ep);
            return CrossCoreRoundtrip { result, worker };
        }
        worker = CrossCoreWorker {
            worker_thread,
            main_ep,
            worker_ep,
        };
        return CrossCoreRoundtrip { result, worker };
    }

    result.status = -12;
    CrossCoreRoundtrip { result, worker }
}

fn run_cross_core_eventpair_phase(
    worker: CrossCoreWorker,
    phase: u64,
    iterations: u64,
) -> RoundtripResult {
    if worker.main_ep == 0 || worker.worker_ep == 0 || worker.worker_thread == 0 {
        return RoundtripResult {
            status: -11,
            ..RoundtripResult::default()
        };
    }
    run_eventpair_roundtrip_phase(worker.main_ep, phase, iterations)
}

fn close_cross_core_worker(worker: CrossCoreWorker) {
    if worker.worker_thread != 0 {
        let _ = zx_task_kill(worker.worker_thread);
        let mut terminated_observed: zx_signals_t = 0;
        let _ = zx_object_wait_one(
            worker.worker_thread,
            ZX_TASK_TERMINATED,
            wait_deadline(),
            &mut terminated_observed,
        );
        let _ = zx_handle_close(worker.worker_thread);
    }
    if worker.worker_ep != 0 {
        let _ = zx_handle_close(worker.worker_ep);
    }
    if worker.main_ep != 0 {
        let _ = zx_handle_close(worker.main_ep);
    }
}

extern "C" fn cross_core_roundtrip_worker_entry(worker_ep: u64, _iterations: u64) -> ! {
    let worker_ep = worker_ep as zx_handle_t;
    ROUNDTRIP_WORKER_CPU.store(current_cpu_apic_id(), Ordering::Release);
    let _ = zx_object_signal_peer(worker_ep, 0, ZX_USER_SIGNAL_0);
    loop {
        ROUNDTRIP_WORKER_WAIT_STATE.store(WORKER_WAIT_STATE_PARKED, Ordering::Release);
        let mut observed: zx_signals_t = 0;
        let status =
            zx_object_wait_one(worker_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if status != ZX_OK {
            park_forever(worker_ep);
        }
        ROUNDTRIP_WORKER_WAIT_STATE.store(WORKER_WAIT_STATE_RUNNING, Ordering::Release);
        let _ = zx_object_signal(worker_ep, ZX_USER_SIGNAL_0, 0);
        if ROUNDTRIP_WORKER_MODE.swap(WORKER_MODE_ROUNDTRIP, Ordering::AcqRel)
            == WORKER_MODE_FAULT_TIMELINE
        {
            let mapped_addr = ROUNDTRIP_FAULT_ADDR.load(Ordering::Acquire);
            volatile_write_u8(mapped_addr, 0xa5);
        }
        let _ = zx_object_signal_peer(worker_ep, 0, ZX_USER_SIGNAL_0);
    }
}

fn park_forever(handle: zx_handle_t) -> ! {
    loop {
        let mut observed: zx_signals_t = 0;
        let _ = zx_object_wait_one(handle, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        let _ = zx_object_signal(handle, ZX_USER_SIGNAL_0, 0);
    }
}

fn run_tlb_churn(root_vmar: zx_handle_t, iterations: u64) -> RoundtripResult {
    let mut result = RoundtripResult::default();
    let mut vmo: zx_handle_t = 0;
    result.status = zx_vmo_create(TLB_CHURN_BYTES, 0, &mut vmo) as i64;
    if result.status != ZX_OK as i64 {
        return result;
    }

    let seed = [0x5Au8; 64];
    result.status = zx_vmo_write(vmo, &seed, 0) as i64;
    if result.status != ZX_OK as i64 {
        let _ = zx_handle_close(vmo);
        return result;
    }

    write_slot(SLOT_TRACE_PHASE, PHASE_TLB_CHURN);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        let mut mapped_addr = 0_u64;
        let status = zx_vmar_map_local(
            root_vmar,
            (ZX_VM_PERM_READ | ZX_VM_PERM_WRITE) as u32,
            0,
            vmo,
            0,
            TLB_CHURN_BYTES,
            &mut mapped_addr,
        );
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_handle_close(vmo);
            return result;
        }

        let status = zx_vmar_protect_local(
            root_vmar,
            ZX_VM_PERM_READ as u32,
            mapped_addr,
            TLB_CHURN_BYTES,
        );
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_handle_close(vmo);
            return result;
        }

        let status = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_handle_close(vmo);
            return result;
        }
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);
    let _ = zx_handle_close(vmo);
    result
}

fn run_tlb_active_peer(root_vmar: zx_handle_t, iterations: u64) -> RoundtripResult {
    let mut result = RoundtripResult::default();
    let mut vmo: zx_handle_t = 0;
    result.status = zx_vmo_create(TLB_CHURN_BYTES, 0, &mut vmo) as i64;
    if result.status != ZX_OK as i64 {
        return result;
    }

    let seed = [0xA5_u8; 64];
    result.status = zx_vmo_write(vmo, &seed, 0) as i64;
    if result.status != ZX_OK as i64 {
        let _ = zx_handle_close(vmo);
        return result;
    }
    write_slot(SLOT_TRACE_PHASE, PHASE_TLB_ACTIVE_PEER);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        let mut mapped_addr = 0_u64;
        let status = zx_vmar_map_local(
            root_vmar,
            (ZX_VM_PERM_READ | ZX_VM_PERM_WRITE) as u32,
            0,
            vmo,
            0,
            TLB_CHURN_BYTES,
            &mut mapped_addr,
        );
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_handle_close(vmo);
            return result;
        }

        let status = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_handle_close(vmo);
            return result;
        }
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);
    let _ = zx_handle_close(vmo);
    result
}

fn run_fault_timeline(
    worker: CrossCoreWorker,
    root_vmar: zx_handle_t,
    iterations: u64,
) -> RoundtripResult {
    let mut result = RoundtripResult::default();
    let mut vmo: zx_handle_t = 0;
    result.status = zx_vmo_create(TLB_CHURN_BYTES, 0, &mut vmo) as i64;
    if result.status != ZX_OK as i64 {
        return result;
    }

    let mut mapped_addr = 0_u64;
    let status = zx_vmar_map_local(
        root_vmar,
        (ZX_VM_PERM_READ | ZX_VM_PERM_WRITE) as u32,
        0,
        vmo,
        0,
        TLB_CHURN_BYTES,
        &mut mapped_addr,
    );
    if status != ZX_OK {
        result.status = status as i64;
        let _ = zx_handle_close(vmo);
        return result;
    }
    if worker.main_ep == 0 || worker.worker_ep == 0 || worker.worker_thread == 0 {
        result.status = -22;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        let _ = zx_handle_close(vmo);
        return result;
    }

    write_slot(SLOT_VM_FAULT_TEST_HOOK_ARM, 1);
    write_slot(SLOT_TRACE_PHASE, PHASE_FAULT_TIMELINE);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        ROUNDTRIP_FAULT_ADDR.store(mapped_addr, Ordering::Release);
        ROUNDTRIP_WORKER_MODE.store(WORKER_MODE_FAULT_TIMELINE, Ordering::Release);
        if zx_object_signal_peer(worker.main_ep, 0, ZX_USER_SIGNAL_0) != ZX_OK {
            write_slot(SLOT_TRACE_PHASE, 0);
            result.status = -20;
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
            let _ = zx_handle_close(vmo);
            return result;
        }
        volatile_write_u8(mapped_addr, 0x5a);
        let mut observed: zx_signals_t = 0;
        let status = zx_object_wait_one(
            worker.main_ep,
            ZX_USER_SIGNAL_0,
            wait_deadline(),
            &mut observed,
        );
        if status != ZX_OK {
            write_slot(SLOT_TRACE_PHASE, 0);
            result.status = status as i64;
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
            let _ = zx_handle_close(vmo);
            return result;
        }
        let _ = zx_object_signal(worker.main_ep, ZX_USER_SIGNAL_0, 0);
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);
    let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
    let _ = zx_handle_close(vmo);
    result
}

fn run_channel_fragment(root_vmar: zx_handle_t, iterations: u64) -> RoundtripResult {
    let mut result = RoundtripResult::default();
    let mut tx: zx_handle_t = 0;
    let mut rx: zx_handle_t = 0;
    let mut vmo: zx_handle_t = 0;
    let mut mapped_addr = 0_u64;

    result.status = zx_channel_create(0, &mut tx, &mut rx) as i64;
    if result.status != ZX_OK as i64 {
        return result;
    }

    result.status = zx_vmo_create(CHANNEL_FRAGMENT_MAPPING_BYTES, 0, &mut vmo) as i64;
    if result.status != ZX_OK as i64 {
        close_channel_pair(tx, rx);
        return result;
    }

    let status = zx_vmar_map_local(
        root_vmar,
        (ZX_VM_PERM_READ | ZX_VM_PERM_WRITE) as u32,
        0,
        vmo,
        0,
        CHANNEL_FRAGMENT_MAPPING_BYTES,
        &mut mapped_addr,
    );
    if status != ZX_OK {
        result.status = status as i64;
        let _ = zx_handle_close(vmo);
        close_channel_pair(tx, rx);
        return result;
    }

    let expected = match seed_channel_fragment_payload(mapped_addr) {
        Ok(expected) => expected,
        Err(status) => {
            result.status = status;
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
            let _ = zx_handle_close(vmo);
            close_channel_pair(tx, rx);
            return result;
        }
    };
    let mut received = Vec::new();
    if received.try_reserve_exact(CHANNEL_FRAGMENT_BYTES).is_err() {
        result.status = -30;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
        let _ = zx_handle_close(vmo);
        close_channel_pair(tx, rx);
        return result;
    }
    received.resize(CHANNEL_FRAGMENT_BYTES, 0);

    write_slot(SLOT_TRACE_PHASE, PHASE_CHANNEL_FRAGMENT);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        let status = zx_channel_write(
            tx,
            0,
            (mapped_addr + CHANNEL_FRAGMENT_OFFSET as u64) as *const u8,
            CHANNEL_FRAGMENT_BYTES as u32,
            ptr::null(),
            0,
        );
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
            let _ = zx_handle_close(vmo);
            close_channel_pair(tx, rx);
            return result;
        }

        let mut actual_bytes = 0_u32;
        let mut actual_handles = 0_u32;
        let status = zx_channel_read(
            rx,
            0,
            received.as_mut_ptr(),
            ptr::null_mut(),
            CHANNEL_FRAGMENT_BYTES as u32,
            0,
            &mut actual_bytes,
            &mut actual_handles,
        );
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
            let _ = zx_handle_close(vmo);
            close_channel_pair(tx, rx);
            return result;
        }
        if actual_bytes != CHANNEL_FRAGMENT_BYTES as u32 || actual_handles != 0 {
            result.status = -31;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
            let _ = zx_handle_close(vmo);
            close_channel_pair(tx, rx);
            return result;
        }
        if received != expected {
            result.status = -32;
            write_slot(SLOT_TRACE_PHASE, 0);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
            let _ = zx_handle_close(vmo);
            close_channel_pair(tx, rx);
            return result;
        }
    }

    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);
    let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, CHANNEL_FRAGMENT_MAPPING_BYTES);
    let _ = zx_handle_close(vmo);
    close_channel_pair(tx, rx);
    result
}

fn seed_channel_fragment_payload(mapped_addr: u64) -> Result<Vec<u8>, i64> {
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(CHANNEL_FRAGMENT_BYTES)
        .map_err(|_| -29)?;
    for index in 0..CHANNEL_FRAGMENT_BYTES {
        let value = (index as u8).wrapping_mul(17).wrapping_add(3);
        expected.push(value);
        // SAFETY: `run_channel_fragment()` maps `CHANNEL_FRAGMENT_MAPPING_BYTES`
        // bytes of writable user memory and only asks this helper to seed the
        // `CHANNEL_FRAGMENT_OFFSET..OFFSET+BYTES` subrange within that mapping.
        unsafe {
            ptr::write_volatile(
                (mapped_addr + CHANNEL_FRAGMENT_OFFSET as u64 + index as u64) as *mut u8,
                value,
            );
        }
    }
    Ok(expected)
}

fn close_channel_pair(tx: zx_handle_t, rx: zx_handle_t) {
    if tx != 0 {
        let _ = zx_handle_close(tx);
    }
    if rx != 0 {
        let _ = zx_handle_close(rx);
    }
}

fn current_cpu_apic_id() -> u64 {
    // SAFETY: CPUID leaf 1 is always available on the x86_64 bootstrap target used by this
    // perf runner, and reading the APIC id is side-effect free.
    unsafe { u64::from((__cpuid(1).ebx >> 24) & 0xff) }
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

fn zx_vmar_protect_local(vmar: zx_handle_t, options: u32, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMAR_PROTECT as u64,
        [vmar, options as u64, addr, len, 0, 0],
    )
}

fn zx_vmar_unmap_local(vmar: zx_handle_t, addr: u64, len: u64) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(AXLE_SYS_VMAR_UNMAP as u64, [vmar, addr, len, 0, 0, 0])
}

fn wait_deadline() -> i64 {
    read_slot(SLOT_T0_NS)
        .saturating_add(WAIT_TIMEOUT_NS)
        .min(i64::MAX as u64) as i64
}

fn wait_for_worker_parked() {
    while ROUNDTRIP_WORKER_WAIT_STATE.load(Ordering::Acquire) != WORKER_WAIT_STATE_PARKED {
        core::hint::spin_loop();
    }
}

fn wait_worker_stack_top() -> u64 {
    // SAFETY: the perf smoke owns this dedicated bootstrap worker stack and
    // only hands its top address to `zx_thread_start`.
    let base = unsafe { ptr::addr_of_mut!(WAIT_WORKER_STACK.0) as *mut u8 as usize };
    (base + WORKER_STACK_BYTES) as u64
}

fn wake_worker_stack_top() -> u64 {
    // SAFETY: the perf smoke owns this dedicated bootstrap worker stack and
    // only hands its top address to `zx_thread_start`.
    let base = unsafe { ptr::addr_of_mut!(WAKE_WORKER_STACK.0) as *mut u8 as usize };
    (base + WORKER_STACK_BYTES) as u64
}

fn volatile_write_u8(addr: u64, value: u8) {
    // SAFETY: `run_fault_timeline()` only passes a valid writable user mapping
    // returned by `zx_vmar_map_local`, and the benchmark writes a single byte
    // within that one-page mapping to trigger a deterministic user fault.
    unsafe {
        ptr::write_volatile(addr as *mut u8, value);
    }
}

fn write_summary(summary: &PerfSummary) {
    write_slot(SLOT_PERF_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_PERF_NULL_STATUS, summary.null_status as u64);
    write_slot(SLOT_PERF_NULL_ITERS, summary.null_iters);
    write_slot(SLOT_PERF_NULL_CYCLES, summary.null_cycles);
    write_slot(SLOT_PERF_WAIT_STATUS, summary.wait_status as u64);
    write_slot(SLOT_PERF_WAIT_ITERS, summary.wait_iters);
    write_slot(SLOT_PERF_WAIT_CYCLES, summary.wait_cycles);
    write_slot(SLOT_PERF_WAKE_STATUS, summary.wake_status as u64);
    write_slot(SLOT_PERF_WAKE_ITERS, summary.wake_iters);
    write_slot(SLOT_PERF_WAKE_CYCLES, summary.wake_cycles);
    write_slot(SLOT_PERF_TLB_STATUS, summary.tlb_status as u64);
    write_slot(SLOT_PERF_TLB_ITERS, summary.tlb_iters);
    write_slot(SLOT_PERF_TLB_CYCLES, summary.tlb_cycles);
    write_slot(SLOT_PERF_TLB_PEER_STATUS, summary.tlb_peer_status as u64);
    write_slot(SLOT_PERF_TLB_PEER_ITERS, summary.tlb_peer_iters);
    write_slot(SLOT_PERF_TLB_PEER_CYCLES, summary.tlb_peer_cycles);
    write_slot(SLOT_PERF_FAULT_STATUS, summary.fault_status as u64);
    write_slot(SLOT_PERF_FAULT_ITERS, summary.fault_iters);
    write_slot(SLOT_PERF_FAULT_CYCLES, summary.fault_cycles);
    write_slot(
        SLOT_PERF_CHANNEL_FRAGMENT_STATUS,
        summary.channel_fragment_status as u64,
    );
    write_slot(
        SLOT_PERF_CHANNEL_FRAGMENT_ITERS,
        summary.channel_fragment_iters,
    );
    write_slot(
        SLOT_PERF_CHANNEL_FRAGMENT_CYCLES,
        summary.channel_fragment_cycles,
    );
    write_slot(SLOT_PERF_THREAD_CREATE, summary.thread_create as u64);
    write_slot(SLOT_PERF_THREAD_START, summary.thread_start as u64);
    write_slot(SLOT_PERF_EVENTPAIR_CREATE, summary.eventpair_create as u64);
}

fn read_slot(slot: usize) -> u64 {
    let slots = USER_SHARED_BASE as *const u64;
    // SAFETY: the bootstrap runner maps the fixed shared-page window at
    // `USER_SHARED_BASE`. Bench helpers only touch known slot indices.
    unsafe { ptr::read_volatile(slots.add(slot)) }
}

fn write_slot(slot: usize, value: u64) {
    let slots = USER_SHARED_BASE as *mut u64;
    // SAFETY: the bootstrap runner maps the fixed shared-page window at
    // `USER_SHARED_BASE`. Bench helpers only touch known slot indices.
    unsafe { ptr::write_volatile(slots.add(slot), value) }
}
