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
    }

    if cpuid
        .get_extended_processor_and_feature_identifiers()
        .is_some_and(|e| e.has_syscall_sysret())
    {
        caps |= CpuCaps::SYSCALL;
    }

    caps
}

pub fn supports_native_syscall() -> bool {
    detect_caps(&CpuId::new()).contains(CpuCaps::SYSCALL)
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
        "cpu: vendor={} caps=[sse2={},apic={},tsc={},x2apic={},syscall={}]",
        vendor,
        caps.contains(CpuCaps::SSE2),
        caps.contains(CpuCaps::APIC),
        caps.contains(CpuCaps::TSC),
        caps.contains(CpuCaps::X2APIC),
        caps.contains(CpuCaps::SYSCALL),
    );
}
