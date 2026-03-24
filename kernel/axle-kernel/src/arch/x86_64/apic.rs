//! Local APIC (x2APIC) bring-up.
//!
//! Sweet-spot goals:
//! - enable x2APIC on BSP/AP
//! - send INIT/SIPI during SMP bring-up
//! - provide EOI for timer/spurious/error handlers
//!
//! We prefer x2APIC when available, but fall back to xAPIC MMIO mode when the
//! CPU doesn't advertise x2APIC support.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use raw_cpuid::CpuId;
use x2apic::lapic::{IpiDestMode, LocalApic, LocalApicBuilder, TimerDivide, TimerMode};
use x86_64::registers::model_specific::Msr;

pub const TIMER_VECTOR: usize = 0x20;
pub const ERROR_VECTOR: usize = 0x21;
pub const SPURIOUS_VECTOR: usize = 0xFF;
const PERIODIC_TIMER_INITIAL: u32 = 5_000_000;

const XAPIC_ICR_LOW_OFF: u64 = 0x300;
const XAPIC_ICR_HIGH_OFF: u64 = 0x310;

// xAPIC base defaults to 0xFEE0_0000; it sits below 4GiB but above our initial
// 0..1GiB identity map, so we install a minimal mapping for it when needed.
const XAPIC_MMIO_REGION_SIZE: u64 = 2 * 1024 * 1024;

const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_PS: u64 = 1 << 7;

#[repr(align(4096))]
struct AlignedPageTable([u64; 512]);

static mut XAPIC_PD: AlignedPageTable = AlignedPageTable([0; 512]);

// PVH boot page tables (identity-mapped, used as the active CR3).
unsafe extern "C" {
    static mut pvh_pdpt: [u64; 512];
}

const MODE_XAPIC: u8 = 0;
const MODE_X2APIC: u8 = 1;

static APIC_MODE: AtomicU8 = AtomicU8::new(MODE_XAPIC);
static XAPIC_BASE: AtomicU64 = AtomicU64::new(0);

// x2APIC MSR numbers used for EOI.
const IA32_X2APIC_EOI: u32 = 0x80B;

struct BspLapicCell(UnsafeCell<Option<LocalApic>>);

// SAFETY: we only access BSP_LAPIC on the BSP and with interrupts disabled
// during early bring-up.
unsafe impl Sync for BspLapicCell {}

static BSP_LAPIC: BspLapicCell = BspLapicCell(UnsafeCell::new(None));

#[derive(Clone, Copy)]
enum XapicIpiDeliveryMode {
    Fixed = 0b000,
    Init = 0b101,
    StartUp = 0b110,
}

fn cpu_has_x2apic() -> bool {
    crate::arch::cpuid::supports_x2apic()
}

fn cpu_has_tsc_deadline() -> bool {
    crate::arch::cpuid::supports_tsc_deadline()
}

/// Enable and configure the BSP local APIC.
///
/// Must be called before sending IPIs or enabling interrupts that rely on APIC.
pub fn init_bsp() {
    let timer_mode = if cpu_has_tsc_deadline() {
        TimerMode::TscDeadline
    } else {
        TimerMode::Periodic
    };
    let timer_initial = if matches!(timer_mode, TimerMode::Periodic) {
        // Without calibration the APIC timer frequency is model-dependent.
        // Bias toward a coarse tick: it is enough for phase-one timeouts/slicing while keeping
        // QEMU/TCG from spending most of its time in the timer ISR.
        PERIODIC_TIMER_INITIAL
    } else {
        0
    };

    if !cpu_has_x2apic() {
        // Bring up xAPIC MMIO mode.
        let base = unsafe { x2apic::lapic::xapic_base() };
        map_xapic_mmio(base);
        XAPIC_BASE.store(base, Ordering::Relaxed);
        APIC_MODE.store(MODE_XAPIC, Ordering::Relaxed);
    } else {
        APIC_MODE.store(MODE_X2APIC, Ordering::Relaxed);
    }

    let mut b = LocalApicBuilder::new();
    if APIC_MODE.load(Ordering::Relaxed) == MODE_XAPIC {
        b.set_xapic_base(XAPIC_BASE.load(Ordering::Relaxed));
    }

    let lapic = b
        .timer_vector(TIMER_VECTOR)
        .error_vector(ERROR_VECTOR)
        .spurious_vector(SPURIOUS_VECTOR)
        .timer_mode(timer_mode)
        // Divider/initial are ignored for TSC-deadline mode; keep deterministic defaults.
        .timer_divide(TimerDivide::Div1)
        .timer_initial(timer_initial)
        .ipi_destination_mode(IpiDestMode::Physical)
        .build()
        .expect("apic: LocalApicBuilder build failed");

    // SAFETY: enabling local APIC mutates CPU-local registers and must be done
    // exactly once per CPU during early boot. We only call this on the BSP.
    let mut lapic = lapic;
    unsafe {
        lapic.enable();
    }

    // SAFETY: BSP-only bring-up state.
    unsafe { *BSP_LAPIC.0.get() = Some(lapic) }
}

/// Enable x2APIC on an AP and optionally leave its local timer running.
pub fn init_ap(enable_timer: bool) {
    let timer_mode = if cpu_has_tsc_deadline() {
        TimerMode::TscDeadline
    } else {
        TimerMode::Periodic
    };
    let timer_initial = if matches!(timer_mode, TimerMode::Periodic) {
        PERIODIC_TIMER_INITIAL
    } else {
        0
    };

    // The BSP has already set APIC_MODE in init_bsp(). APs only verify the
    // mode matches their hardware; they do not re-store the global.
    if !cpu_has_x2apic() {
        assert_eq!(
            APIC_MODE.load(Ordering::Relaxed),
            MODE_XAPIC,
            "apic: AP detects xAPIC but BSP set x2APIC mode"
        );
        let base = XAPIC_BASE.load(Ordering::Relaxed);
        if base == 0 {
            panic!("apic: xapic base not mapped; call init_bsp first");
        }
    } else {
        assert_eq!(
            APIC_MODE.load(Ordering::Relaxed),
            MODE_X2APIC,
            "apic: AP detects x2APIC but BSP set xAPIC mode"
        );
    }

    let mut b = LocalApicBuilder::new();
    if APIC_MODE.load(Ordering::Relaxed) == MODE_XAPIC {
        b.set_xapic_base(XAPIC_BASE.load(Ordering::Relaxed));
    }

    let mut lapic = b
        .timer_vector(TIMER_VECTOR)
        .error_vector(ERROR_VECTOR)
        .spurious_vector(SPURIOUS_VECTOR)
        .timer_mode(timer_mode)
        .timer_divide(TimerDivide::Div1)
        .timer_initial(timer_initial)
        .ipi_destination_mode(IpiDestMode::Physical)
        .build()
        .expect("apic: LocalApicBuilder build failed");

    // SAFETY: CPU-local register programming during AP bring-up.
    unsafe {
        lapic.enable();
        if !enable_timer {
            lapic.disable_timer();
        }
    }
}

fn with_bsp_lapic<R>(f: impl FnOnce(&mut LocalApic) -> R) -> R {
    // SAFETY: BSP_LAPIC is initialized exactly once on the BSP. We only call
    // this helper on BSP code paths and with interrupts disabled.
    let slot = unsafe { &mut *BSP_LAPIC.0.get() };
    let lapic = slot.as_mut().expect("apic: BSP LAPIC not initialized");
    f(lapic)
}

fn xapic_send_ipi(dest: u32, mode: XapicIpiDeliveryMode, vector: u8) {
    let base = XAPIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }

    let icr_low = base + XAPIC_ICR_LOW_OFF;
    let icr_high = base + XAPIC_ICR_HIGH_OFF;

    // Wait for any prior IPI to complete.
    loop {
        // SAFETY: `icr_low` points into the xAPIC MMIO page.
        let v = unsafe { core::ptr::read_volatile(icr_low as *const u32) };
        if (v & (1 << 12)) == 0 {
            break;
        }
        core::hint::spin_loop();
    }

    let dest_hi = (dest & 0xFF) << 24;
    // SAFETY: `icr_high` points into the xAPIC MMIO page.
    unsafe {
        core::ptr::write_volatile(icr_high as *mut u32, dest_hi);
    }

    let mut lo = (vector as u32) | ((mode as u32) << 8);
    // Assert level. (INIT wants trigger=level; SIPI is edge-triggered.)
    lo |= 1 << 14;
    if matches!(mode, XapicIpiDeliveryMode::Init) {
        lo |= 1 << 15;
    }

    // SAFETY: `icr_low` points into the xAPIC MMIO page.
    unsafe {
        core::ptr::write_volatile(icr_low as *mut u32, lo);
    }
}

/// Send an INIT IPI to `dest` APIC id.
pub fn send_init_ipi(dest: u32) {
    match APIC_MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => with_bsp_lapic(|lapic| unsafe {
            lapic.send_init_ipi(dest);
        }),
        _ => xapic_send_ipi(dest, XapicIpiDeliveryMode::Init, 0),
    }
}

/// Send a SIPI to `dest` APIC id, starting execution at `vector * 4096`.
pub fn send_startup_ipi(dest: u32, vector: u8) {
    match APIC_MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => with_bsp_lapic(|lapic| unsafe {
            lapic.send_sipi(vector, dest);
        }),
        _ => xapic_send_ipi(dest, XapicIpiDeliveryMode::StartUp, vector),
    }
}

/// Send a fixed-vector IPI to `dest` APIC id.
///
/// In x2APIC mode we write the ICR MSR directly -- this avoids the data race
/// of borrowing the BSP `LocalApic` from an arbitrary CPU.
pub fn send_fixed_ipi(dest: u32, vector: u8) {
    match APIC_MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => {
            // x2APIC ICR MSR (0x830) format: bits [31:0] = dest APIC id in
            // bits [63:32], delivery mode + vector in bits [19:0].
            const IA32_X2APIC_ICR: u32 = 0x830;
            let icr_val = (u64::from(dest) << 32)
                | u64::from(vector);
            // SAFETY: writing the x2APIC ICR MSR sends a fixed IPI. Requires
            // x2APIC to be enabled on the current CPU.
            unsafe {
                Msr::new(IA32_X2APIC_ICR).write(icr_val);
            }
        }
        _ => xapic_send_ipi(dest, XapicIpiDeliveryMode::Fixed, vector),
    }
}

/// Local APIC EOI.
pub fn eoi() {
    match APIC_MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => {
            // SAFETY: writing x2APIC EOI MSR acknowledges the current in-service
            // interrupt on this CPU. Requires x2APIC enabled on the current CPU.
            unsafe {
                Msr::new(IA32_X2APIC_EOI).write(0);
            }
        }
        _ => {
            let base = XAPIC_BASE.load(Ordering::Relaxed);
            if base == 0 {
                return;
            }
            // SAFETY: xAPIC base was mapped into the address space and EOI is a
            // fixed MMIO register at base+0xB0.
            unsafe {
                core::ptr::write_volatile((base + 0xB0) as *mut u32, 0);
            }
        }
    }
}

/// Current CPU initial APIC id (CPUID leaf 1).
pub fn this_apic_id() -> u32 {
    crate::arch::percpu::try_current_apic_id().unwrap_or_else(|| {
        CpuId::new()
            .get_feature_info()
            .map(|fi| u32::from(fi.initial_local_apic_id()))
            .unwrap_or(0)
    })
}

// --- Spurious/error interrupt stubs (kernel-only) ---

core::arch::global_asm!(
    r#"
    .global axle_apic_spurious_entry
    .type axle_apic_spurious_entry, @function
axle_apic_spurious_entry:
    // Save a conservative snapshot of registers.
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    push r11
    push rcx
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax

    mov rdi, rsp
    call {rust_handler}

    mov rax, [rsp + 0]
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rcx
    pop r11
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    iretq
    .size axle_apic_spurious_entry, .-axle_apic_spurious_entry
    "#,
    rust_handler = sym axle_apic_spurious_rust,
);

core::arch::global_asm!(
    r#"
    .global axle_apic_error_entry
    .type axle_apic_error_entry, @function
axle_apic_error_entry:
    // Save a conservative snapshot of registers.
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    push r11
    push rcx
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax

    mov rdi, rsp
    call {rust_handler}

    mov rax, [rsp + 0]
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rcx
    pop r11
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    iretq
    .size axle_apic_error_entry, .-axle_apic_error_entry
    "#,
    rust_handler = sym axle_apic_error_rust,
);

unsafe extern "C" {
    fn axle_apic_spurious_entry();
    fn axle_apic_error_entry();
}

/// IDT handler entry address for spurious interrupts.
pub fn spurious_entry_addr() -> usize {
    axle_apic_spurious_entry as *const () as usize
}

/// IDT handler entry address for APIC error interrupts.
pub fn error_entry_addr() -> usize {
    axle_apic_error_entry as *const () as usize
}

extern "C" fn axle_apic_spurious_rust(_frame: *const u8) {
    // Intel SDM vol. 3A, 11.9: "No EOI should be sent for the spurious
    // interrupt." Sending EOI for a spurious vector can confuse the APIC
    // priority state machine.
}

extern "C" fn axle_apic_error_rust(_frame: *const u8) {
    // Keep it minimal: acknowledge and continue.
    eoi();
}

fn map_xapic_mmio(base: u64) {
    // xAPIC base is 4KiB aligned; our early mapper installs a single 2MiB page.
    if (base % XAPIC_MMIO_REGION_SIZE) != 0 {
        panic!("apic: xapic base not 2MiB aligned: {:#x}", base);
    }

    let pdpt_index = ((base >> 30) & 0x1FF) as usize;
    let pd_index = ((base >> 21) & 0x1FF) as usize;

    // SAFETY: early boot, single core; we mutate the static PVH page tables and
    // flush TLB by reloading CR3. This mapping is kernel-only (U=0).
    unsafe {
        let pd_phys = core::ptr::addr_of!(XAPIC_PD) as u64;
        pvh_pdpt[pdpt_index] = pd_phys | (PTE_P | PTE_W);
        // xAPIC MMIO must be mapped uncacheable (UC). Set PCD + PWT to force
        // UC memory type regardless of MTRRs.
        XAPIC_PD.0[pd_index] = base | (PTE_P | PTE_W | PTE_PS | PTE_PCD | PTE_PWT);

        crate::arch::tlb::flush_all_local();
    }
}
use core::cell::UnsafeCell;
