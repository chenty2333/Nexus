extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use axle_types::zx_handle_t;

const TRACE_RECORD_CAPACITY: usize = 1280;
const TRACE_VMO_BYTES: u64 = 64 * 1024;
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
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceEvent {
    SysEnter = 1,
    SysExit = 2,
    RemoteWake = 3,
    ReschedIpi = 4,
    TimerFire = 5,
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
            _ => TraceCategory::Syscall,
        }
    }

    const fn event(self) -> TraceEvent {
        match (self.meta & 0xffff) as u16 {
            1 => TraceEvent::SysEnter,
            2 => TraceEvent::SysExit,
            3 => TraceEvent::RemoteWake,
            4 => TraceEvent::ReschedIpi,
            5 => TraceEvent::TimerFire,
            _ => TraceEvent::SysEnter,
        }
    }
}

static TRACE_VMO_HANDLE: AtomicU64 = AtomicU64::new(0);
static TRACE_RECORD_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_DROPPED_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_EXPORTED_BYTES: AtomicU64 = AtomicU64::new(0);
static TRACE_REMOTE_WAKE_PHASE3: AtomicU64 = AtomicU64::new(0);
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

pub(crate) fn init_bootstrap_trace() {
    let trace_vmo_handle = crate::object::vm::create_vmo(TRACE_VMO_BYTES, 0).unwrap_or(0);
    TRACE_VMO_HANDLE.store(u64::from(trace_vmo_handle), Ordering::Release);
    TRACE_RECORD_COUNT.store(0, Ordering::Release);
    TRACE_DROPPED_COUNT.store(0, Ordering::Release);
    TRACE_EXPORTED_BYTES.store(0, Ordering::Release);
    TRACE_REMOTE_WAKE_PHASE3.store(0, Ordering::Release);
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

pub(crate) fn record_remote_wake(thread_id: u64, target_cpu: usize) {
    record(
        TraceCategory::Sched,
        TraceEvent::RemoteWake,
        thread_id,
        target_cpu as u64,
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

pub(crate) fn record_timer_fire(from_user: bool, needs_trap_exit: bool) {
    record(
        TraceCategory::Timer,
        TraceEvent::TimerFire,
        u64::from(from_user),
        u64::from(needs_trap_exit),
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
    }
}

fn event_name(event: TraceEvent) -> &'static str {
    match event {
        TraceEvent::SysEnter => "sys_enter",
        TraceEvent::SysExit => "sys_exit",
        TraceEvent::RemoteWake => "remote_wake",
        TraceEvent::ReschedIpi => "resched_ipi",
        TraceEvent::TimerFire => "timer_fire",
    }
}

pub(crate) fn flush_bootstrap_trace() {
    let records = snapshot_records();

    let remote_wake_phase3 = records
        .iter()
        .filter(|record| record.phase == 3 && record.event() == TraceEvent::RemoteWake)
        .count() as u64;
    TRACE_REMOTE_WAKE_PHASE3.store(remote_wake_phase3, Ordering::Release);

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
