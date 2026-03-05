//! Monotonic time for bring-up.
//!
//! Goals (sweet spot):
//! - provide `now_ns()` for Zircon-style deadlines
//! - keep wakeup source (APIC timer) separate from time source
//!
//! Implementation:
//! - Prefer TSC converted to nanoseconds using CPUID leaf 0x15 when available.
//! - Fall back to tick counting if TSC frequency isn't enumerated.

use core::sync::atomic::{AtomicU64, Ordering};

use raw_cpuid::CpuId;
use spin::Once;

struct TimeState {
    tsc_base: u64,
    tsc_hz: u64,
    ticks: AtomicU64,
}

static STATE: Once<TimeState> = Once::new();

/// Initialize time state on BSP.
pub fn init() {
    let cpuid = CpuId::new();

    let mut tsc_hz = cpuid
        .get_tsc_info()
        .and_then(|t| t.tsc_frequency())
        .or_else(|| {
            cpuid
                .get_processor_frequency_info()
                .map(|f| u64::from(f.processor_base_frequency()) * 1_000_000)
                .filter(|&hz| hz != 0)
        })
        .unwrap_or(0);

    // Many QEMU CPU models don't enumerate a TSC frequency. We only need a
    // stable linear scale for Zircon-style relative deadlines; use a
    // conservative default so `now_ns()` remains monotonic and usable.
    if tsc_hz == 0 {
        tsc_hz = 1_000_000_000; // 1 GHz (fallback scale)
        crate::kprintln!("time: CPUID didn't report TSC frequency; assuming 1GHz");
    }

    let base = rdtsc();

    let st = STATE.call_once(|| TimeState {
        tsc_base: base,
        tsc_hz,
        ticks: AtomicU64::new(0),
    });

    crate::kprintln!("time: init tsc_hz={} base_tsc={}", st.tsc_hz, st.tsc_base);
}

/// Read the raw TSC value.
pub fn rdtsc() -> u64 {
    // SAFETY: rdtsc has no memory safety hazards; it only reads a CPU register.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Convert nanoseconds to TSC ticks.
///
/// Returns 0 if the TSC frequency isn't known.
pub fn ns_to_tsc(ns: u64) -> u64 {
    let Some(st) = STATE.get() else {
        return 0;
    };
    if st.tsc_hz == 0 {
        return 0;
    }
    let v = (ns as u128)
        .saturating_mul(st.tsc_hz as u128)
        .saturating_div(1_000_000_000u128);
    v as u64
}

/// Current monotonic time in nanoseconds.
pub fn now_ns() -> i64 {
    let Some(st) = STATE.get() else {
        return 0;
    };

    if st.tsc_hz != 0 {
        let tsc = rdtsc();
        let delta = tsc.wrapping_sub(st.tsc_base);
        let ns = (delta as u128)
            .saturating_mul(1_000_000_000u128)
            .saturating_div(st.tsc_hz as u128);
        return ns.min(i64::MAX as u128) as i64;
    }

    // Fallback: tick counting. (Coarse but monotonic.)
    st.ticks
        .load(Ordering::Relaxed)
        .saturating_mul(crate::arch::timer::tick_ns())
        .min(i64::MAX as u64) as i64
}

/// Called from the timer interrupt handler.
pub fn on_tick() {
    if let Some(st) = STATE.get() {
        let _ = st.ticks.fetch_add(1, Ordering::Relaxed);
    }
}
