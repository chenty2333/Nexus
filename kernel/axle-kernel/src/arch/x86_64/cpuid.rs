//! Boot CPU feature detection.

use bitflags::bitflags;
use core::fmt::Write;
use heapless::String;
use raw_cpuid::{CpuId, CpuIdReader};

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CpuCaps: u32 {
        const SSE2 = 1 << 0;
        const APIC = 1 << 1;
        const TSC = 1 << 2;
        const X2APIC = 1 << 3;
        const SYSCALL = 1 << 4;
        const PCID = 1 << 5;
        const INVPCID = 1 << 6;
        const PMU = 1 << 7;
        const TSC_DEADLINE = 1 << 8;
    }
}

fn detect_caps<R: CpuIdReader>(cpuid: &CpuId<R>) -> CpuCaps {
    let mut caps = CpuCaps::empty();

    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_sse2() {
            caps |= CpuCaps::SSE2;
        }
        if fi.has_apic() {
            caps |= CpuCaps::APIC;
        }
        if fi.has_tsc() {
            caps |= CpuCaps::TSC;
        }
        if fi.has_x2apic() {
            caps |= CpuCaps::X2APIC;
        }
        if fi.has_pcid() {
            caps |= CpuCaps::PCID;
        }
        if fi.has_tsc_deadline() {
            caps |= CpuCaps::TSC_DEADLINE;
        }
    }

    if cpuid
        .get_extended_processor_and_feature_identifiers()
        .is_some_and(|e| e.has_syscall_sysret())
    {
        caps |= CpuCaps::SYSCALL;
    }

    if cpuid
        .get_extended_feature_info()
        .is_some_and(|features| features.has_invpcid())
    {
        caps |= CpuCaps::INVPCID;
    }

    if cpuid.get_performance_monitoring_info().is_some_and(|info| {
        info.version_id() >= 2
            && info.fixed_function_counters() >= 3
            && !info.is_core_cyc_ev_unavailable()
            && !info.is_inst_ret_ev_unavailable()
            && !info.is_ref_cycle_ev_unavailable()
    }) {
        caps |= CpuCaps::PMU;
    }

    caps
}

pub fn supports_native_syscall() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::SYSCALL)
}

pub fn supports_pcid() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::PCID)
}

pub fn supports_invpcid() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::INVPCID)
}

pub fn supports_pmu() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::PMU)
}

pub fn supports_tsc_deadline() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::TSC_DEADLINE)
}

pub fn pmu_version() -> u8 {
    CpuId::new()
        .get_performance_monitoring_info()
        .map(|info| info.version_id())
        .unwrap_or(0)
}

pub fn pmu_fixed_counter_count() -> u8 {
    CpuId::new()
        .get_performance_monitoring_info()
        .map(|info| info.fixed_function_counters())
        .unwrap_or(0)
}

pub fn log_boot_cpu_info() {
    let cpuid = CpuId::new();

    let mut vendor = String::<16>::new();
    if let Some(vendor_info) = cpuid.get_vendor_info() {
        let _ = write!(&mut vendor, "{}", vendor_info.as_str());
    } else {
        let _ = write!(&mut vendor, "unknown");
    }

    let caps = detect_caps(&cpuid);

    crate::kprintln!(
        "cpu: vendor={} caps=[sse2={},apic={},tsc={},x2apic={},syscall={},pcid={},invpcid={},tsc_deadline={},pmu={}]",
        vendor,
        caps.contains(CpuCaps::SSE2),
        caps.contains(CpuCaps::APIC),
        caps.contains(CpuCaps::TSC),
        caps.contains(CpuCaps::X2APIC),
        caps.contains(CpuCaps::SYSCALL),
        caps.contains(CpuCaps::PCID),
        caps.contains(CpuCaps::INVPCID),
        caps.contains(CpuCaps::TSC_DEADLINE),
        caps.contains(CpuCaps::PMU),
    );
}
