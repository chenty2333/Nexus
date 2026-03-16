use core::alloc::{GlobalAlloc, Layout};
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use libzircon::signals::{ZX_TASK_TERMINATED, ZX_USER_SIGNAL_0};
use libzircon::status::{ZX_ERR_BAD_SYSCALL, ZX_OK};
use libzircon::syscall_numbers::{AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP};
use libzircon::vm::{ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    zx_eventpair_create, zx_handle_close, zx_handle_t, zx_object_signal, zx_object_signal_peer,
    zx_object_wait_one, zx_signals_t, zx_status_t, zx_task_kill, zx_thread_create, zx_thread_start,
    zx_vmo_create, zx_vmo_write,
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

const STEP_NULL_SYSCALL: u64 = 1;
const STEP_WAIT_PING_PONG: u64 = 2;
const STEP_WAKEUP: u64 = 3;
const STEP_TLB_CHURN: u64 = 4;
const STEP_TLB_ACTIVE_PEER: u64 = 5;
const STEP_FAULT_TIMELINE: u64 = 6;
const STEP_PANIC: u64 = u64::MAX;

const PHASE_NULL_SYSCALL: u64 = 1;
const PHASE_WAIT_PING_PONG: u64 = 2;
const PHASE_WAKEUP: u64 = 3;
const PHASE_TLB_CHURN: u64 = 4;
const PHASE_TLB_ACTIVE_PEER: u64 = 5;
const PHASE_FAULT_TIMELINE: u64 = 6;

const NULL_SYSCALL_ITERS: u64 = 64;
const WAIT_PING_PONG_ITERS: u64 = 32;
const WAKE_ITERS: u64 = 32;
const TLB_ITERS: u64 = 8;
const TLB_ACTIVE_PEER_ITERS: u64 = 8;
const FAULT_TIMELINE_ITERS: u64 = 1;
const TLB_CHURN_BYTES: u64 = 4096;
const WORKER_STACK_BYTES: usize = 4096;
const HEAP_BYTES: usize = 64 * 1024;
const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const TLB_WORKER_STATE_INIT: u64 = 0;
const TLB_WORKER_STATE_READY: u64 = 1;
const TLB_WORKER_STATE_STOP: u64 = 2;

#[repr(align(16))]
struct WorkerStack([u8; WORKER_STACK_BYTES]);
#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static TLB_WORKER_STATE: AtomicU64 = AtomicU64::new(TLB_WORKER_STATE_INIT);
static mut WAIT_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut WAKE_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut TLB_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
static mut FAULT_WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_BYTES]);
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

    let wait = run_eventpair_roundtrip(
        self_process,
        PHASE_WAIT_PING_PONG,
        WAIT_PING_PONG_ITERS,
        wait_worker_stack_top(),
    );
    summary.thread_create = wait.thread_create;
    summary.thread_start = wait.thread_start;
    summary.eventpair_create = wait.eventpair_create;
    summary.wait_status = wait.status;
    summary.wait_iters = WAIT_PING_PONG_ITERS;
    summary.wait_cycles = wait.cycles;
    if wait.status != ZX_OK as i64 {
        summary.failure_step = STEP_WAIT_PING_PONG;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let wake = run_eventpair_roundtrip(
        self_process,
        PHASE_WAKEUP,
        WAKE_ITERS,
        wake_worker_stack_top(),
    );
    summary.thread_create = wake.thread_create;
    summary.thread_start = wake.thread_start;
    summary.eventpair_create = wake.eventpair_create;
    summary.wake_status = wake.status;
    summary.wake_iters = WAKE_ITERS;
    summary.wake_cycles = wake.cycles;
    if wake.status != ZX_OK as i64 {
        summary.failure_step = STEP_WAKEUP;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let tlb = run_tlb_churn(root_vmar, TLB_ITERS);
    summary.tlb_status = tlb.status;
    summary.tlb_iters = TLB_ITERS;
    summary.tlb_cycles = tlb.cycles;
    if tlb.status != ZX_OK as i64 {
        summary.failure_step = STEP_TLB_CHURN;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let tlb_peer = run_tlb_active_peer(self_process, root_vmar, TLB_ACTIVE_PEER_ITERS);
    summary.tlb_peer_status = tlb_peer.status;
    summary.tlb_peer_iters = TLB_ACTIVE_PEER_ITERS;
    summary.tlb_peer_cycles = tlb_peer.cycles;
    if tlb_peer.status != ZX_OK as i64 {
        summary.failure_step = STEP_TLB_ACTIVE_PEER;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    let fault = run_fault_timeline(self_process, root_vmar, FAULT_TIMELINE_ITERS);
    summary.thread_create = fault.thread_create;
    summary.thread_start = fault.thread_start;
    summary.eventpair_create = fault.eventpair_create;
    summary.fault_status = fault.status;
    summary.fault_iters = FAULT_TIMELINE_ITERS;
    summary.fault_cycles = fault.cycles;
    if fault.status != ZX_OK as i64 {
        summary.failure_step = STEP_FAULT_TIMELINE;
        write_slot(SLOT_TRACE_PHASE, 0);
        return summary;
    }

    write_slot(SLOT_TRACE_PHASE, 0);
    summary
}

fn run_eventpair_roundtrip(
    process: zx_handle_t,
    phase: u64,
    iterations: u64,
    worker_stack_top: u64,
) -> RoundtripResult {
    let mut result = RoundtripResult::default();

    let mut main_ep: zx_handle_t = 0;
    let mut worker_ep: zx_handle_t = 0;
    result.eventpair_create = zx_eventpair_create(0, &mut main_ep, &mut worker_ep) as i64;
    if result.eventpair_create != ZX_OK as i64 {
        result.status = result.eventpair_create;
        return result;
    }

    let mut worker_thread: zx_handle_t = 0;
    result.thread_create = zx_thread_create(process, 0, &mut worker_thread) as i64;
    if result.thread_create != ZX_OK as i64 {
        result.status = result.thread_create;
        return result;
    }

    result.thread_start = zx_thread_start(
        worker_thread,
        roundtrip_worker_entry as *const () as usize as u64,
        worker_stack_top,
        worker_ep,
        iterations,
    ) as i64;
    if result.thread_start != ZX_OK as i64 {
        result.status = result.thread_start;
        return result;
    }

    write_slot(SLOT_TRACE_PHASE, phase);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        if zx_object_signal_peer(main_ep, 0, ZX_USER_SIGNAL_0) != ZX_OK {
            result.status = -1;
            return result;
        }
        let mut observed: zx_signals_t = 0;
        let status = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if status != ZX_OK {
            result.status = status as i64;
            return result;
        }
        if zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0) != ZX_OK {
            result.status = -2;
            return result;
        }
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    result
}

extern "C" fn roundtrip_worker_entry(worker_ep: u64, iterations: u64) -> ! {
    let worker_ep = worker_ep as zx_handle_t;
    for _ in 0..iterations {
        let mut observed: zx_signals_t = 0;
        let status =
            zx_object_wait_one(worker_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if status != ZX_OK {
            park_forever(worker_ep);
        }
        let _ = zx_object_signal(worker_ep, ZX_USER_SIGNAL_0, 0);
        let _ = zx_object_signal_peer(worker_ep, 0, ZX_USER_SIGNAL_0);
    }
    park_forever(worker_ep)
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

fn run_tlb_active_peer(
    process: zx_handle_t,
    root_vmar: zx_handle_t,
    iterations: u64,
) -> RoundtripResult {
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

    let mut main_ep: zx_handle_t = 0;
    let mut worker_ep: zx_handle_t = 0;
    result.eventpair_create = zx_eventpair_create(0, &mut main_ep, &mut worker_ep) as i64;
    if result.eventpair_create != ZX_OK as i64 {
        result.status = result.eventpair_create;
        let _ = zx_handle_close(vmo);
        return result;
    }

    let mut worker_thread: zx_handle_t = 0;
    result.thread_create = zx_thread_create(process, 0, &mut worker_thread) as i64;
    if result.thread_create != ZX_OK as i64 {
        result.status = result.thread_create;
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_handle_close(vmo);
        return result;
    }

    TLB_WORKER_STATE.store(TLB_WORKER_STATE_INIT, Ordering::Release);
    result.thread_start = zx_thread_start(
        worker_thread,
        tlb_worker_entry as *const () as usize as u64,
        tlb_worker_stack_top(),
        worker_ep,
        0,
    ) as i64;
    if result.thread_start != ZX_OK as i64 {
        result.status = result.thread_start;
        let _ = zx_handle_close(worker_thread);
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_handle_close(vmo);
        return result;
    }

    let mut observed: zx_signals_t = 0;
    let ready = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
    if ready != ZX_OK || TLB_WORKER_STATE.load(Ordering::Acquire) != TLB_WORKER_STATE_READY {
        result.status = if ready == ZX_OK { -10 } else { ready as i64 };
        let _ = zx_task_kill(worker_thread);
        let _ = zx_handle_close(worker_thread);
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_handle_close(vmo);
        return result;
    }
    let _ = zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0);

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
            TLB_WORKER_STATE.store(TLB_WORKER_STATE_STOP, Ordering::Release);
            let _ = zx_task_kill(worker_thread);
            let _ = zx_handle_close(worker_thread);
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            let _ = zx_handle_close(vmo);
            return result;
        }

        let status = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        if status != ZX_OK {
            result.status = status as i64;
            write_slot(SLOT_TRACE_PHASE, 0);
            TLB_WORKER_STATE.store(TLB_WORKER_STATE_STOP, Ordering::Release);
            let _ = zx_task_kill(worker_thread);
            let _ = zx_handle_close(worker_thread);
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            let _ = zx_handle_close(vmo);
            return result;
        }
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);

    TLB_WORKER_STATE.store(TLB_WORKER_STATE_STOP, Ordering::Release);
    let _ = zx_task_kill(worker_thread);
    let mut terminated_observed: zx_signals_t = 0;
    let _ = zx_object_wait_one(
        worker_thread,
        ZX_TASK_TERMINATED,
        wait_deadline(),
        &mut terminated_observed,
    );
    let _ = zx_handle_close(worker_thread);
    let _ = zx_handle_close(worker_ep);
    let _ = zx_handle_close(main_ep);
    let _ = zx_handle_close(vmo);
    result
}

fn run_fault_timeline(
    process: zx_handle_t,
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

    let mut main_ep: zx_handle_t = 0;
    let mut worker_ep: zx_handle_t = 0;
    result.eventpair_create = zx_eventpair_create(0, &mut main_ep, &mut worker_ep) as i64;
    if result.eventpair_create != ZX_OK as i64 {
        result.status = result.eventpair_create;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        let _ = zx_handle_close(vmo);
        return result;
    }

    let mut worker_thread: zx_handle_t = 0;
    result.thread_create = zx_thread_create(process, 0, &mut worker_thread) as i64;
    if result.thread_create != ZX_OK as i64 {
        result.status = result.thread_create;
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        let _ = zx_handle_close(vmo);
        return result;
    }

    result.thread_start = zx_thread_start(
        worker_thread,
        fault_worker_entry as *const () as usize as u64,
        fault_worker_stack_top(),
        worker_ep,
        mapped_addr,
    ) as i64;
    if result.thread_start != ZX_OK as i64 {
        result.status = result.thread_start;
        let _ = zx_handle_close(worker_thread);
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        let _ = zx_handle_close(vmo);
        return result;
    }

    let mut observed: zx_signals_t = 0;
    let ready = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
    if ready != ZX_OK {
        result.status = ready as i64;
        let _ = zx_task_kill(worker_thread);
        let _ = zx_handle_close(worker_thread);
        let _ = zx_handle_close(worker_ep);
        let _ = zx_handle_close(main_ep);
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
        let _ = zx_handle_close(vmo);
        return result;
    }
    let _ = zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0);

    write_slot(SLOT_VM_FAULT_TEST_HOOK_ARM, 1);
    write_slot(SLOT_TRACE_PHASE, PHASE_FAULT_TIMELINE);
    let start = axle_arch_x86_64::rdtsc();
    for _ in 0..iterations {
        if zx_object_signal_peer(main_ep, 0, ZX_USER_SIGNAL_0) != ZX_OK {
            write_slot(SLOT_TRACE_PHASE, 0);
            result.status = -20;
            let _ = zx_task_kill(worker_thread);
            let _ = zx_handle_close(worker_thread);
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
            let _ = zx_handle_close(vmo);
            return result;
        }
        volatile_write_u8(mapped_addr, 0x5a);
        let status = zx_object_wait_one(main_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
        if status != ZX_OK {
            write_slot(SLOT_TRACE_PHASE, 0);
            result.status = status as i64;
            let _ = zx_task_kill(worker_thread);
            let _ = zx_handle_close(worker_thread);
            let _ = zx_handle_close(worker_ep);
            let _ = zx_handle_close(main_ep);
            let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
            let _ = zx_handle_close(vmo);
            return result;
        }
        let _ = zx_object_signal(main_ep, ZX_USER_SIGNAL_0, 0);
    }
    result.cycles = axle_arch_x86_64::rdtsc().wrapping_sub(start);
    result.status = ZX_OK as i64;
    write_slot(SLOT_TRACE_PHASE, 0);

    let _ = zx_task_kill(worker_thread);
    let mut terminated_observed: zx_signals_t = 0;
    let _ = zx_object_wait_one(
        worker_thread,
        ZX_TASK_TERMINATED,
        wait_deadline(),
        &mut terminated_observed,
    );
    let _ = zx_handle_close(worker_thread);
    let _ = zx_handle_close(worker_ep);
    let _ = zx_handle_close(main_ep);
    let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, TLB_CHURN_BYTES);
    let _ = zx_handle_close(vmo);
    result
}

extern "C" fn tlb_worker_entry(ready_ep: u64, _unused: u64) -> ! {
    let ready_ep = ready_ep as zx_handle_t;
    TLB_WORKER_STATE.store(TLB_WORKER_STATE_READY, Ordering::Release);
    let _ = zx_object_signal_peer(ready_ep, 0, ZX_USER_SIGNAL_0);
    while TLB_WORKER_STATE.load(Ordering::Acquire) != TLB_WORKER_STATE_STOP {
        spin_loop();
    }
    park_forever(ready_ep)
}

extern "C" fn fault_worker_entry(worker_ep: u64, mapped_addr: u64) -> ! {
    let worker_ep = worker_ep as zx_handle_t;
    let _ = zx_object_signal_peer(worker_ep, 0, ZX_USER_SIGNAL_0);
    let mut observed: zx_signals_t = 0;
    let status = zx_object_wait_one(worker_ep, ZX_USER_SIGNAL_0, wait_deadline(), &mut observed);
    if status != ZX_OK {
        park_forever(worker_ep);
    }
    let _ = zx_object_signal(worker_ep, ZX_USER_SIGNAL_0, 0);
    volatile_write_u8(mapped_addr, 0xa5);
    let _ = zx_object_signal_peer(worker_ep, 0, ZX_USER_SIGNAL_0);
    park_forever(worker_ep)
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

fn tlb_worker_stack_top() -> u64 {
    // SAFETY: the perf smoke owns this dedicated bootstrap worker stack and
    // only hands its top address to `zx_thread_start`.
    let base = unsafe { ptr::addr_of_mut!(TLB_WORKER_STACK.0) as *mut u8 as usize };
    (base + WORKER_STACK_BYTES) as u64
}

fn fault_worker_stack_top() -> u64 {
    // SAFETY: the perf smoke owns this dedicated bootstrap worker stack and
    // only hands its top address to `zx_thread_start`.
    let base = unsafe { ptr::addr_of_mut!(FAULT_WORKER_STACK.0) as *mut u8 as usize };
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
