extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use axle_types::zx_handle_t;

const TRACE_RECORD_CAPACITY: usize = 4096;
const TRACE_VMO_BYTES: u64 = 256 * 1024;
const TRACE_MAGIC: u64 = u64::from_le_bytes(*b"AXLTRC01");
const TRACE_VERSION: u64 = 1;
const TRACE_RECORD_WORDS: u64 = 6;
const TRACE_LOG_LIMIT: usize = 128;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceCategory {
    Syscall = 1,
    Sched = 2,
    Timer = 3,
    Tlb = 4,
    Fault = 5,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceEvent {
    SysEnter = 1,
    SysExit = 2,
    SysRetire = 3,
    RemoteWake = 4,
    ReschedIpi = 5,
    TimerFire = 6,
    TimerReprogram = 7,
    TlbSyncPlan = 8,
    TlbFlushPage = 9,
    TlbFlushAll = 10,
    TlbShootdownPage = 11,
    TlbShootdownAll = 12,
    IrqEnter = 13,
    IrqExit = 14,
    ContextSwitch = 15,
    FaultEnter = 16,
    FaultHandled = 17,
    FaultBlock = 18,
    FaultResume = 19,
    FaultUnhandled = 20,
    RunQueueDepth = 21,
    Steal = 22,
    Handoff = 23,
    RemoteWakeLatency = 24,
}

#[derive(Clone, Copy, Debug, Default)]
struct TraceRecord {
    ts_ns: u64,
    seq: u64,
    phase: u64,
    meta: u64,
    arg0: u64,
    arg1: u64,
}

impl TraceRecord {
    const ZERO: Self = Self {
        ts_ns: 0,
        seq: 0,
        phase: 0,
        meta: 0,
        arg0: 0,
        arg1: 0,
    };

    const fn cpu_id(self) -> usize {
        ((self.meta >> 32) & 0xffff) as usize
    }

    const fn category(self) -> TraceCategory {
        match ((self.meta >> 16) & 0xffff) as u16 {
            1 => TraceCategory::Syscall,
            2 => TraceCategory::Sched,
            3 => TraceCategory::Timer,
            4 => TraceCategory::Tlb,
            5 => TraceCategory::Fault,
            _ => TraceCategory::Syscall,
        }
    }

    const fn event(self) -> TraceEvent {
        match (self.meta & 0xffff) as u16 {
            1 => TraceEvent::SysEnter,
            2 => TraceEvent::SysExit,
            3 => TraceEvent::SysRetire,
            4 => TraceEvent::RemoteWake,
            5 => TraceEvent::ReschedIpi,
            6 => TraceEvent::TimerFire,
            7 => TraceEvent::TimerReprogram,
            8 => TraceEvent::TlbSyncPlan,
            9 => TraceEvent::TlbFlushPage,
            10 => TraceEvent::TlbFlushAll,
            11 => TraceEvent::TlbShootdownPage,
            12 => TraceEvent::TlbShootdownAll,
            13 => TraceEvent::IrqEnter,
            14 => TraceEvent::IrqExit,
            15 => TraceEvent::ContextSwitch,
            16 => TraceEvent::FaultEnter,
            17 => TraceEvent::FaultHandled,
            18 => TraceEvent::FaultBlock,
            19 => TraceEvent::FaultResume,
            20 => TraceEvent::FaultUnhandled,
            21 => TraceEvent::RunQueueDepth,
            22 => TraceEvent::Steal,
            23 => TraceEvent::Handoff,
            24 => TraceEvent::RemoteWakeLatency,
            _ => TraceEvent::SysEnter,
        }
    }
}

static TRACE_VMO_HANDLE: AtomicU64 = AtomicU64::new(0);
static TRACE_RECORD_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_DROPPED_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_EXPORTED_BYTES: AtomicU64 = AtomicU64::new(0);
static TRACE_REMOTE_WAKE_PHASE3: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_MAX_RUN_QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_STEAL_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_HANDOFF_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS: AtomicU64 = AtomicU64::new(0);
static TRACE_SYS_ENTER_PHASE1: AtomicU64 = AtomicU64::new(0);
static TRACE_SYS_EXIT_PHASE1: AtomicU64 = AtomicU64::new(0);
static TRACE_SYS_RETIRE_PHASE1: AtomicU64 = AtomicU64::new(0);
static TRACE_CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TIMER_REPROGRAM_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SYNC_PLAN_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_LOCAL_PAGE_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_LOCAL_FULL_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SHOOTDOWN_PAGE_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SHOOTDOWN_FULL_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SHOOTDOWN_TARGET_CPU_TOTAL: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_MAX_ACTIVE_CPUS: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_LAST_ACTIVE_MASK: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_PAGE_FLUSH_PHASE4: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_FULL_FLUSH_PHASE4: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SYNC_PLAN_PHASE4: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SYNC_PLAN_PHASE5: AtomicU64 = AtomicU64::new(0);
static TRACE_TLB_SHOOTDOWN_FULL_PHASE5: AtomicU64 = AtomicU64::new(0);
static TRACE_FAULT_ENTER_PHASE6: AtomicU64 = AtomicU64::new(0);
static TRACE_FAULT_HANDLED_PHASE6: AtomicU64 = AtomicU64::new(0);
static TRACE_FAULT_BLOCK_PHASE6: AtomicU64 = AtomicU64::new(0);
static TRACE_FAULT_RESUME_PHASE6: AtomicU64 = AtomicU64::new(0);
static TRACE_FAULT_UNHANDLED_PHASE6: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_STEAL_PHASE3: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_HANDOFF_PHASE3: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3: AtomicU64 = AtomicU64::new(0);
static TRACE_SCHED_STEAL_PHASE5: AtomicU64 = AtomicU64::new(0);
static mut TRACE_RECORDS: [TraceRecord; TRACE_RECORD_CAPACITY] =
    [TraceRecord::ZERO; TRACE_RECORD_CAPACITY];

fn pack_meta(cpu_id: usize, category: TraceCategory, event: TraceEvent) -> u64 {
    (u64::from(cpu_id as u16) << 32) | (u64::from(category as u16) << 16) | u64::from(event as u16)
}

pub(crate) fn bootstrap_trace_vmo_handle() -> zx_handle_t {
    TRACE_VMO_HANDLE.load(Ordering::Acquire) as zx_handle_t
}

pub(crate) fn bootstrap_trace_record_count() -> u64 {
    TRACE_RECORD_COUNT
        .load(Ordering::Acquire)
        .min(TRACE_RECORD_CAPACITY as u64)
}

pub(crate) fn bootstrap_trace_dropped_count() -> u64 {
    TRACE_DROPPED_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_exported_bytes() -> u64 {
    TRACE_EXPORTED_BYTES.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_remote_wake_phase3() -> u64 {
    TRACE_REMOTE_WAKE_PHASE3.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_max_run_queue_depth() -> u64 {
    TRACE_SCHED_MAX_RUN_QUEUE_DEPTH.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_steal_count() -> u64 {
    TRACE_SCHED_STEAL_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_handoff_count() -> u64 {
    TRACE_SCHED_HANDOFF_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_remote_wake_latency_count() -> u64 {
    TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_remote_wake_latency_max_ns() -> u64 {
    TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sys_enter_phase1() -> u64 {
    TRACE_SYS_ENTER_PHASE1.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sys_exit_phase1() -> u64 {
    TRACE_SYS_EXIT_PHASE1.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sys_retire_phase1() -> u64 {
    TRACE_SYS_RETIRE_PHASE1.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_context_switch_count() -> u64 {
    TRACE_CONTEXT_SWITCH_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_timer_reprogram_count() -> u64 {
    TRACE_TIMER_REPROGRAM_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_sync_plan_count() -> u64 {
    TRACE_TLB_SYNC_PLAN_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_local_page_flush_count() -> u64 {
    TRACE_TLB_LOCAL_PAGE_FLUSH_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_local_full_flush_count() -> u64 {
    TRACE_TLB_LOCAL_FULL_FLUSH_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_shootdown_page_count() -> u64 {
    TRACE_TLB_SHOOTDOWN_PAGE_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_shootdown_full_count() -> u64 {
    TRACE_TLB_SHOOTDOWN_FULL_COUNT.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_shootdown_target_cpu_total() -> u64 {
    TRACE_TLB_SHOOTDOWN_TARGET_CPU_TOTAL.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_max_active_cpus() -> u64 {
    TRACE_TLB_MAX_ACTIVE_CPUS.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_last_active_mask() -> u64 {
    TRACE_TLB_LAST_ACTIVE_MASK.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_page_flush_phase4() -> u64 {
    TRACE_TLB_PAGE_FLUSH_PHASE4.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_full_flush_phase4() -> u64 {
    TRACE_TLB_FULL_FLUSH_PHASE4.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_sync_plan_phase4() -> u64 {
    TRACE_TLB_SYNC_PLAN_PHASE4.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_sync_plan_phase5() -> u64 {
    TRACE_TLB_SYNC_PLAN_PHASE5.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_tlb_shootdown_full_phase5() -> u64 {
    TRACE_TLB_SHOOTDOWN_FULL_PHASE5.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_fault_enter_phase6() -> u64 {
    TRACE_FAULT_ENTER_PHASE6.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_fault_handled_phase6() -> u64 {
    TRACE_FAULT_HANDLED_PHASE6.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_fault_block_phase6() -> u64 {
    TRACE_FAULT_BLOCK_PHASE6.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_fault_resume_phase6() -> u64 {
    TRACE_FAULT_RESUME_PHASE6.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_fault_unhandled_phase6() -> u64 {
    TRACE_FAULT_UNHANDLED_PHASE6.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_steal_phase3() -> u64 {
    TRACE_SCHED_STEAL_PHASE3.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_handoff_phase3() -> u64 {
    TRACE_SCHED_HANDOFF_PHASE3.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_remote_wake_latency_phase3() -> u64 {
    TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3.load(Ordering::Acquire)
}

pub(crate) fn bootstrap_trace_sched_steal_phase5() -> u64 {
    TRACE_SCHED_STEAL_PHASE5.load(Ordering::Acquire)
}

pub(crate) fn note_tlb_active_mask(active_cpu_mask: u64) {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_LAST_ACTIVE_MASK.store(active_cpu_mask, Ordering::Release);
    let active_cpu_count = active_cpu_mask.count_ones() as u64;
    let _ = TRACE_TLB_MAX_ACTIVE_CPUS.fetch_max(active_cpu_count, Ordering::AcqRel);
}

pub(crate) fn init_bootstrap_trace() {
    let trace_vmo_handle = crate::object::vm::create_vmo(TRACE_VMO_BYTES, 0).unwrap_or(0);
    TRACE_VMO_HANDLE.store(u64::from(trace_vmo_handle), Ordering::Release);
    TRACE_RECORD_COUNT.store(0, Ordering::Release);
    TRACE_DROPPED_COUNT.store(0, Ordering::Release);
    TRACE_EXPORTED_BYTES.store(0, Ordering::Release);
    TRACE_REMOTE_WAKE_PHASE3.store(0, Ordering::Release);
    TRACE_SCHED_MAX_RUN_QUEUE_DEPTH.store(0, Ordering::Release);
    TRACE_SCHED_STEAL_COUNT.store(0, Ordering::Release);
    TRACE_SCHED_HANDOFF_COUNT.store(0, Ordering::Release);
    TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT.store(0, Ordering::Release);
    TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS.store(0, Ordering::Release);
    TRACE_SYS_ENTER_PHASE1.store(0, Ordering::Release);
    TRACE_SYS_EXIT_PHASE1.store(0, Ordering::Release);
    TRACE_SYS_RETIRE_PHASE1.store(0, Ordering::Release);
    TRACE_CONTEXT_SWITCH_COUNT.store(0, Ordering::Release);
    TRACE_TIMER_REPROGRAM_COUNT.store(0, Ordering::Release);
    TRACE_TLB_SYNC_PLAN_COUNT.store(0, Ordering::Release);
    TRACE_TLB_LOCAL_PAGE_FLUSH_COUNT.store(0, Ordering::Release);
    TRACE_TLB_LOCAL_FULL_FLUSH_COUNT.store(0, Ordering::Release);
    TRACE_TLB_SHOOTDOWN_PAGE_COUNT.store(0, Ordering::Release);
    TRACE_TLB_SHOOTDOWN_FULL_COUNT.store(0, Ordering::Release);
    TRACE_TLB_SHOOTDOWN_TARGET_CPU_TOTAL.store(0, Ordering::Release);
    TRACE_TLB_MAX_ACTIVE_CPUS.store(0, Ordering::Release);
    TRACE_TLB_LAST_ACTIVE_MASK.store(0, Ordering::Release);
    TRACE_TLB_PAGE_FLUSH_PHASE4.store(0, Ordering::Release);
    TRACE_TLB_FULL_FLUSH_PHASE4.store(0, Ordering::Release);
    TRACE_TLB_SYNC_PLAN_PHASE4.store(0, Ordering::Release);
    TRACE_TLB_SYNC_PLAN_PHASE5.store(0, Ordering::Release);
    TRACE_TLB_SHOOTDOWN_FULL_PHASE5.store(0, Ordering::Release);
    TRACE_FAULT_ENTER_PHASE6.store(0, Ordering::Release);
    TRACE_FAULT_HANDLED_PHASE6.store(0, Ordering::Release);
    TRACE_FAULT_BLOCK_PHASE6.store(0, Ordering::Release);
    TRACE_FAULT_RESUME_PHASE6.store(0, Ordering::Release);
    TRACE_FAULT_UNHANDLED_PHASE6.store(0, Ordering::Release);
    TRACE_SCHED_STEAL_PHASE3.store(0, Ordering::Release);
    TRACE_SCHED_HANDOFF_PHASE3.store(0, Ordering::Release);
    TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3.store(0, Ordering::Release);
    TRACE_SCHED_STEAL_PHASE5.store(0, Ordering::Release);
    // SAFETY: resetting the bootstrap trace ring happens before userspace starts
    // producing trace records for this run, so no concurrent writers can observe
    // partially cleared records. Each slot is written through a raw pointer to
    // avoid forming a mutable reference to the `static mut` array.
    unsafe {
        let base = core::ptr::addr_of_mut!(TRACE_RECORDS).cast::<TraceRecord>();
        for index in 0..TRACE_RECORD_CAPACITY {
            core::ptr::write(base.add(index), TraceRecord::ZERO);
        }
    }
}

fn trace_enabled() -> bool {
    crate::userspace::bootstrap_trace_phase() != 0
}

fn record(category: TraceCategory, event: TraceEvent, arg0: u64, arg1: u64) {
    if !trace_enabled() {
        return;
    }

    let index = TRACE_RECORD_COUNT.fetch_add(1, Ordering::AcqRel);
    if index >= TRACE_RECORD_CAPACITY as u64 {
        TRACE_DROPPED_COUNT.fetch_add(1, Ordering::AcqRel);
        return;
    }

    let phase = crate::userspace::bootstrap_trace_phase();
    let cpu_id = crate::arch::apic::this_apic_id() as usize;
    let record = TraceRecord {
        ts_ns: crate::time::now_ns().max(0) as u64,
        seq: index,
        phase,
        meta: pack_meta(cpu_id, category, event),
        arg0,
        arg1,
    };

    // SAFETY: each writer reserves a unique `index` via `TRACE_RECORD_COUNT`,
    // and the trace ring never wraps for this minimal bootstrap recorder.
    unsafe {
        TRACE_RECORDS[index as usize] = record;
    }
}

pub(crate) fn record_sys_enter(syscall_nr: u64) {
    record(TraceCategory::Syscall, TraceEvent::SysEnter, syscall_nr, 0);
}

pub(crate) fn record_sys_exit(syscall_nr: u64, status: axle_types::zx_status_t) {
    record(
        TraceCategory::Syscall,
        TraceEvent::SysExit,
        syscall_nr,
        (status as i64) as u64,
    );
}

pub(crate) fn record_sys_retire(syscall_nr: u64, status: axle_types::zx_status_t) {
    record(
        TraceCategory::Syscall,
        TraceEvent::SysRetire,
        syscall_nr,
        (status as i64) as u64,
    );
}

pub(crate) fn record_remote_wake(thread_id: u64, target_cpu: usize) {
    record(
        TraceCategory::Sched,
        TraceEvent::RemoteWake,
        thread_id,
        target_cpu as u64,
    );
}

pub(crate) fn record_run_queue_depth(thread_id: u64, queue_cpu_id: usize, depth: usize, op: u16) {
    if !trace_enabled() {
        return;
    }
    let _ = TRACE_SCHED_MAX_RUN_QUEUE_DEPTH.fetch_max(depth as u64, Ordering::AcqRel);
    record(
        TraceCategory::Sched,
        TraceEvent::RunQueueDepth,
        thread_id,
        u64::from(queue_cpu_id as u16) | (u64::from(op) << 16) | ((depth as u64) << 32),
    );
}

pub(crate) fn record_sched_steal(
    thread_id: u64,
    donor_cpu_id: usize,
    receiver_cpu_id: usize,
    donor_depth_after: usize,
) {
    if !trace_enabled() {
        return;
    }
    TRACE_SCHED_STEAL_COUNT.fetch_add(1, Ordering::AcqRel);
    record(
        TraceCategory::Sched,
        TraceEvent::Steal,
        thread_id,
        u64::from(donor_cpu_id as u16)
            | (u64::from(receiver_cpu_id as u16) << 16)
            | ((donor_depth_after as u64) << 32),
    );
}

pub(crate) fn record_sched_handoff(thread_id: u64, target_cpu_id: usize, queue_depth: usize) {
    if !trace_enabled() {
        return;
    }
    TRACE_SCHED_HANDOFF_COUNT.fetch_add(1, Ordering::AcqRel);
    record(
        TraceCategory::Sched,
        TraceEvent::Handoff,
        thread_id,
        u64::from(target_cpu_id as u16) | ((queue_depth as u64) << 32),
    );
}

pub(crate) fn record_remote_wake_latency(
    thread_id: u64,
    source_cpu_id: usize,
    target_cpu_id: usize,
    latency_ns: u64,
) {
    if !trace_enabled() {
        return;
    }
    TRACE_SCHED_REMOTE_WAKE_LATENCY_COUNT.fetch_add(1, Ordering::AcqRel);
    let _ = TRACE_SCHED_REMOTE_WAKE_LATENCY_MAX_NS.fetch_max(latency_ns, Ordering::AcqRel);
    record(
        TraceCategory::Sched,
        TraceEvent::RemoteWakeLatency,
        thread_id,
        u64::from(source_cpu_id as u16)
            | (u64::from(target_cpu_id as u16) << 16)
            | ((latency_ns & 0xffff_ffff) << 32),
    );
}

pub(crate) fn record_resched_ipi(from_user: bool) {
    record(
        TraceCategory::Sched,
        TraceEvent::ReschedIpi,
        u64::from(from_user),
        0,
    );
}

pub(crate) fn record_context_switch(
    previous_thread_id: Option<u64>,
    next_thread_id: u64,
    address_space_switched: bool,
) {
    if !trace_enabled() {
        return;
    }
    TRACE_CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::AcqRel);
    record(
        TraceCategory::Sched,
        TraceEvent::ContextSwitch,
        previous_thread_id.unwrap_or(u64::MAX),
        next_thread_id | (u64::from(u8::from(address_space_switched)) << 63),
    );
}

pub(crate) fn record_timer_fire(from_user: bool, needs_trap_exit: bool) {
    record(
        TraceCategory::Timer,
        TraceEvent::TimerFire,
        u64::from(from_user),
        u64::from(needs_trap_exit),
    );
}

pub(crate) fn record_timer_irq_enter(from_user: bool) {
    record(
        TraceCategory::Timer,
        TraceEvent::IrqEnter,
        u64::from(from_user),
        0,
    );
}

pub(crate) fn record_timer_irq_exit(from_user: bool, trap_exit_taken: bool) {
    record(
        TraceCategory::Timer,
        TraceEvent::IrqExit,
        u64::from(from_user),
        u64::from(trap_exit_taken),
    );
}

pub(crate) fn record_timer_reprogram(deadline_tsc: u64) {
    if !trace_enabled() {
        return;
    }
    TRACE_TIMER_REPROGRAM_COUNT.fetch_add(1, Ordering::AcqRel);
    record(
        TraceCategory::Timer,
        TraceEvent::TimerReprogram,
        deadline_tsc,
        0,
    );
}

pub(crate) fn record_tlb_sync_plan(
    address_space_id: u64,
    active_cpu_mask: u64,
    remote_cpu_count: usize,
    local_needs_flush: bool,
) {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_SYNC_PLAN_COUNT.fetch_add(1, Ordering::AcqRel);
    note_tlb_active_mask(active_cpu_mask);
    let flags = ((remote_cpu_count as u64) << 1) | u64::from(u8::from(local_needs_flush));
    record(
        TraceCategory::Tlb,
        TraceEvent::TlbSyncPlan,
        address_space_id,
        (active_cpu_mask & 0xffff_ffff) | (flags << 32),
    );
}

pub(crate) fn record_tlb_flush_page(va: u64) {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_LOCAL_PAGE_FLUSH_COUNT.fetch_add(1, Ordering::AcqRel);
    record(TraceCategory::Tlb, TraceEvent::TlbFlushPage, va, 0);
}

pub(crate) fn record_tlb_flush_all() {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_LOCAL_FULL_FLUSH_COUNT.fetch_add(1, Ordering::AcqRel);
    record(TraceCategory::Tlb, TraceEvent::TlbFlushAll, 0, 0);
}

pub(crate) fn record_tlb_shootdown_page(va: u64, target_cpu_mask: u64) {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_SHOOTDOWN_PAGE_COUNT.fetch_add(1, Ordering::AcqRel);
    TRACE_TLB_SHOOTDOWN_TARGET_CPU_TOTAL
        .fetch_add(target_cpu_mask.count_ones() as u64, Ordering::AcqRel);
    record(
        TraceCategory::Tlb,
        TraceEvent::TlbShootdownPage,
        va,
        target_cpu_mask,
    );
}

pub(crate) fn record_tlb_shootdown_all(target_cpu_mask: u64) {
    if !trace_enabled() {
        return;
    }
    TRACE_TLB_SHOOTDOWN_FULL_COUNT.fetch_add(1, Ordering::AcqRel);
    TRACE_TLB_SHOOTDOWN_TARGET_CPU_TOTAL
        .fetch_add(target_cpu_mask.count_ones() as u64, Ordering::AcqRel);
    record(
        TraceCategory::Tlb,
        TraceEvent::TlbShootdownAll,
        target_cpu_mask,
        0,
    );
}

pub(crate) fn record_sched_irq_enter(from_user: bool) {
    record(
        TraceCategory::Sched,
        TraceEvent::IrqEnter,
        u64::from(from_user),
        0,
    );
}

pub(crate) fn record_sched_irq_exit(from_user: bool, trap_exit_taken: bool) {
    record(
        TraceCategory::Sched,
        TraceEvent::IrqExit,
        u64::from(from_user),
        u64::from(trap_exit_taken),
    );
}

pub(crate) fn record_fault_enter(fault_va: u64, error: u64) {
    record(
        TraceCategory::Fault,
        TraceEvent::FaultEnter,
        fault_va,
        error,
    );
}

pub(crate) fn record_fault_handled(fault_va: u64, error: u64) {
    record(
        TraceCategory::Fault,
        TraceEvent::FaultHandled,
        fault_va,
        error,
    );
}

pub(crate) fn record_fault_block(fault_va: u64, flags: u64) {
    record(
        TraceCategory::Fault,
        TraceEvent::FaultBlock,
        fault_va,
        flags,
    );
}

pub(crate) fn record_fault_resume(fault_va: u64, error: u64) {
    record(
        TraceCategory::Fault,
        TraceEvent::FaultResume,
        fault_va,
        error,
    );
}

pub(crate) fn record_fault_unhandled(fault_va: u64, error: u64) {
    record(
        TraceCategory::Fault,
        TraceEvent::FaultUnhandled,
        fault_va,
        error,
    );
}

fn snapshot_records() -> Vec<TraceRecord> {
    let record_count = bootstrap_trace_record_count() as usize;
    let mut snapshot = Vec::with_capacity(record_count);
    // SAFETY: callers snapshot only after the runner has set phase=0 and
    // stopped generating trace records, so copying the written prefix is stable.
    unsafe {
        snapshot.extend_from_slice(&TRACE_RECORDS[..record_count]);
    }
    snapshot
}

fn encode_snapshot(records: &[TraceRecord]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        ((6 + records.len() * TRACE_RECORD_WORDS as usize) * core::mem::size_of::<u64>()) + 16,
    );
    for word in [
        TRACE_MAGIC,
        TRACE_VERSION,
        records.len() as u64,
        bootstrap_trace_dropped_count(),
        TRACE_RECORD_WORDS,
        TRACE_RECORD_CAPACITY as u64,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for record in records {
        for word in [
            record.ts_ns,
            record.seq,
            record.phase,
            record.meta,
            record.arg0,
            record.arg1,
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    bytes
}

fn category_name(category: TraceCategory) -> &'static str {
    match category {
        TraceCategory::Syscall => "ax_syscall",
        TraceCategory::Sched => "ax_sched",
        TraceCategory::Timer => "ax_timer",
        TraceCategory::Tlb => "ax_tlb",
        TraceCategory::Fault => "ax_fault",
    }
}

fn event_name(event: TraceEvent) -> &'static str {
    match event {
        TraceEvent::SysEnter => "sys_enter",
        TraceEvent::SysExit => "sys_exit",
        TraceEvent::SysRetire => "sys_retire",
        TraceEvent::RemoteWake => "remote_wake",
        TraceEvent::ReschedIpi => "resched_ipi",
        TraceEvent::TimerFire => "timer_fire",
        TraceEvent::TimerReprogram => "timer_reprogram",
        TraceEvent::TlbSyncPlan => "tlb_sync_plan",
        TraceEvent::TlbFlushPage => "tlb_flush_page",
        TraceEvent::TlbFlushAll => "tlb_flush_all",
        TraceEvent::TlbShootdownPage => "tlb_shootdown_page",
        TraceEvent::TlbShootdownAll => "tlb_shootdown_all",
        TraceEvent::IrqEnter => "irq_enter",
        TraceEvent::IrqExit => "irq_exit",
        TraceEvent::ContextSwitch => "context_switch",
        TraceEvent::FaultEnter => "fault_enter",
        TraceEvent::FaultHandled => "fault_handled",
        TraceEvent::FaultBlock => "fault_block",
        TraceEvent::FaultResume => "fault_resume",
        TraceEvent::FaultUnhandled => "fault_unhandled",
        TraceEvent::RunQueueDepth => "rq_depth",
        TraceEvent::Steal => "steal",
        TraceEvent::Handoff => "handoff",
        TraceEvent::RemoteWakeLatency => "remote_wake_latency",
    }
}

pub(crate) fn flush_bootstrap_trace() {
    let records = snapshot_records();

    let remote_wake_phase3 = records
        .iter()
        .filter(|record| record.phase == 3 && record.event() == TraceEvent::RemoteWake)
        .count() as u64;
    TRACE_REMOTE_WAKE_PHASE3.store(remote_wake_phase3, Ordering::Release);
    TRACE_SCHED_STEAL_PHASE3.store(
        records
            .iter()
            .filter(|record| record.phase == 3 && record.event() == TraceEvent::Steal)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SCHED_HANDOFF_PHASE3.store(
        records
            .iter()
            .filter(|record| record.phase == 3 && record.event() == TraceEvent::Handoff)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SCHED_REMOTE_WAKE_LATENCY_PHASE3.store(
        records
            .iter()
            .filter(|record| record.phase == 3 && record.event() == TraceEvent::RemoteWakeLatency)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SYS_ENTER_PHASE1.store(
        records
            .iter()
            .filter(|record| record.phase == 1 && record.event() == TraceEvent::SysEnter)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SYS_EXIT_PHASE1.store(
        records
            .iter()
            .filter(|record| record.phase == 1 && record.event() == TraceEvent::SysExit)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SYS_RETIRE_PHASE1.store(
        records
            .iter()
            .filter(|record| record.phase == 1 && record.event() == TraceEvent::SysRetire)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_TLB_PAGE_FLUSH_PHASE4.store(
        records
            .iter()
            .filter(|record| record.phase == 4 && record.event() == TraceEvent::TlbFlushPage)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_TLB_FULL_FLUSH_PHASE4.store(
        records
            .iter()
            .filter(|record| record.phase == 4 && record.event() == TraceEvent::TlbFlushAll)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_TLB_SYNC_PLAN_PHASE4.store(
        records
            .iter()
            .filter(|record| record.phase == 4 && record.event() == TraceEvent::TlbSyncPlan)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_TLB_SYNC_PLAN_PHASE5.store(
        records
            .iter()
            .filter(|record| record.phase == 5 && record.event() == TraceEvent::TlbSyncPlan)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_TLB_SHOOTDOWN_FULL_PHASE5.store(
        records
            .iter()
            .filter(|record| record.phase == 5 && record.event() == TraceEvent::TlbShootdownAll)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_SCHED_STEAL_PHASE5.store(
        records
            .iter()
            .filter(|record| record.phase == 5 && record.event() == TraceEvent::Steal)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_FAULT_ENTER_PHASE6.store(
        records
            .iter()
            .filter(|record| record.phase == 6 && record.event() == TraceEvent::FaultEnter)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_FAULT_HANDLED_PHASE6.store(
        records
            .iter()
            .filter(|record| record.phase == 6 && record.event() == TraceEvent::FaultHandled)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_FAULT_BLOCK_PHASE6.store(
        records
            .iter()
            .filter(|record| record.phase == 6 && record.event() == TraceEvent::FaultBlock)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_FAULT_RESUME_PHASE6.store(
        records
            .iter()
            .filter(|record| record.phase == 6 && record.event() == TraceEvent::FaultResume)
            .count() as u64,
        Ordering::Release,
    );
    TRACE_FAULT_UNHANDLED_PHASE6.store(
        records
            .iter()
            .filter(|record| record.phase == 6 && record.event() == TraceEvent::FaultUnhandled)
            .count() as u64,
        Ordering::Release,
    );

    let encoded = encode_snapshot(&records);
    TRACE_EXPORTED_BYTES.store(encoded.len() as u64, Ordering::Release);

    let trace_vmo_handle = bootstrap_trace_vmo_handle();
    if trace_vmo_handle != 0 {
        let _ = crate::object::vm::vmo_write(trace_vmo_handle, 0, &encoded);
    }

    crate::kprintln!(
        "kernel: bootstrap trace summary (trace_vmo_h={}, trace_records={}, trace_dropped={}, trace_export_bytes={}, trace_remote_wake_phase3={})",
        trace_vmo_handle,
        records.len(),
        bootstrap_trace_dropped_count(),
        encoded.len(),
        remote_wake_phase3
    );

    for record in records.iter().take(TRACE_LOG_LIMIT) {
        crate::kprintln!(
            "trace: seq={} ts_ns={} phase={} cpu={} cat={} ev={} arg0={} arg1={}",
            record.seq,
            record.ts_ns,
            record.phase,
            record.cpu_id(),
            category_name(record.category()),
            event_name(record.event()),
            record.arg0,
            record.arg1 as i64
        );
    }
    if records.len() > TRACE_LOG_LIMIT {
        crate::kprintln!(
            "trace: truncated logged_records={} remaining={}",
            TRACE_LOG_LIMIT,
            records.len() - TRACE_LOG_LIMIT
        );
    }
}
