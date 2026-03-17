//! Minimal architectural PMU bring-up for perf smoke and bare-metal baselines.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;

const IA32_FIXED_CTR0: u32 = 0x309;
const IA32_FIXED_CTR1: u32 = 0x30A;
const IA32_FIXED_CTR2: u32 = 0x30B;
const IA32_FIXED_CTR_CTRL: u32 = 0x38D;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;

const FIXED_CTR_CTRL_ENABLE_OS_USR: u64 = 0b0011;
const FIXED_CTRS_ENABLE_MASK: u64 = (1_u64 << 32) | (1_u64 << 33) | (1_u64 << 34);

static PMU_SUPPORTED: AtomicU64 = AtomicU64::new(0);
static PMU_VERSION: AtomicU64 = AtomicU64::new(0);
static PMU_FIXED_COUNTERS: AtomicU64 = AtomicU64::new(0);

pub fn supported() -> bool {
    PMU_SUPPORTED.load(Ordering::Acquire) != 0
}

pub fn version() -> u64 {
    PMU_VERSION.load(Ordering::Acquire)
}

pub fn fixed_counter_count() -> u64 {
    PMU_FIXED_COUNTERS.load(Ordering::Acquire)
}

pub fn init_cpu() {
    let supported = crate::arch::cpuid::supports_pmu();
    PMU_SUPPORTED.store(u64::from(supported), Ordering::Release);
    PMU_VERSION.store(
        u64::from(crate::arch::cpuid::pmu_version()),
        Ordering::Release,
    );
    PMU_FIXED_COUNTERS.store(
        u64::from(crate::arch::cpuid::pmu_fixed_counter_count()),
        Ordering::Release,
    );
    if !supported {
        return;
    }

    // SAFETY: enabling CR4.PCE only allows ring3 to read already-enabled PMU
    // counters with `RDPMC`; it does not change paging or memory translation.
    unsafe {
        Cr4::update(|flags| flags.insert(Cr4Flags::PERFORMANCE_MONITOR_COUNTER));
    }

    let fixed_ctrl = FIXED_CTR_CTRL_ENABLE_OS_USR
        | (FIXED_CTR_CTRL_ENABLE_OS_USR << 4)
        | (FIXED_CTR_CTRL_ENABLE_OS_USR << 8);

    // SAFETY: these MSRs are the architected fixed-counter controls. We only
    // enable the first three fixed counters when CPUID reported the PMU shape
    // and ring3 `RDPMC` access was explicitly enabled above.
    unsafe {
        Msr::new(IA32_FIXED_CTR0).write(0);
        Msr::new(IA32_FIXED_CTR1).write(0);
        Msr::new(IA32_FIXED_CTR2).write(0);
        Msr::new(IA32_FIXED_CTR_CTRL).write(fixed_ctrl);
        Msr::new(IA32_PERF_GLOBAL_CTRL).write(FIXED_CTRS_ENABLE_MASK);
    }
}
