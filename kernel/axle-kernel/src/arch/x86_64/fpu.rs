//! x86_64 FPU state management with XSAVE/AVX support.
//!
//! At boot, `init_cpu()` enables legacy x87/SSE and probes CPUID for XSAVE
//! support.  When available it enables `CR4.OSXSAVE`, programmes XCR0 for
//! x87+SSE+AVX (and AVX-512 components when present), and records the
//! resulting state-area size.  Save/restore helpers then use `xsave64`/
//! `xrstor64` when supported, falling back to `fxsave64`/`fxrstor64`.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use raw_cpuid::CpuId;
use spin::Once;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

const DEFAULT_MXCSR: u32 = 0x1f80;

/// Maximum XSAVE area size (covers AVX-512 with all components).
const MAX_XSAVE_AREA: usize = 2688;

// ── XSAVE detection state (shared across all CPUs) ─────────────────────

static XSAVE_SUPPORTED: AtomicBool = AtomicBool::new(false);
static XSAVE_AREA_SIZE: AtomicUsize = AtomicUsize::new(512);
static XSAVE_FEATURE_MASK: AtomicU64 = AtomicU64::new(0x3); // x87 + SSE

static CLEAN_STATE: Once<FpuState> = Once::new();

// ── FpuState ────────────────────────────────────────────────────────────

/// Extended FPU state buffer, large enough for XSAVE with AVX-512.
/// Falls back to using only the first 512 bytes for legacy FXSAVE.
#[repr(C, align(64))]
#[derive(Clone)]
pub(crate) struct FpuState {
    bytes: [u8; MAX_XSAVE_AREA],
}

impl FpuState {
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_XSAVE_AREA],
        }
    }
}

// Manual Debug impl — printing 2688 bytes is not useful.
impl core::fmt::Debug for FpuState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpuState")
            .field("len", &self.bytes.len())
            .finish()
    }
}

// ── Public helpers ──────────────────────────────────────────────────────

/// Enable legacy x87/SSE execution on the current CPU, probe for XSAVE/AVX
/// support, and seed the clean state template (once).
pub(crate) fn init_cpu() {
    // SAFETY: Axle already runs in long mode on x86_64 CPUs here.  We preserve
    // unrelated CR0/CR4 bits and only enable the architectural x87/SSE flags
    // required for user-space legacy SSE.
    unsafe {
        Cr0::update(|flags| {
            flags.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
        });
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }

    // ── Detect and enable XSAVE ─────────────────────────────────────
    detect_and_enable_xsave();

    reset_current_cpu_state();
    CLEAN_STATE.call_once(|| {
        let mut state = FpuState::zeroed();
        save_current(&mut state);
        state
    });
}

/// Return the clean architectural FPU state for a new user thread.
pub(crate) fn clean_state() -> FpuState {
    if CLEAN_STATE.get().is_none() {
        // Keep thread creation robust against any caller that reaches the
        // FPU template before the boot path has explicitly seeded it.
        init_cpu();
    }
    CLEAN_STATE
        .get()
        .expect("x86_64 fpu state must be initialized before threads are created")
        .clone()
}

/// Save the current CPU's FPU state (XSAVE when available, FXSAVE otherwise).
pub(crate) fn save_current(state: &mut FpuState) {
    if XSAVE_SUPPORTED.load(Ordering::Relaxed) {
        let mask = XSAVE_FEATURE_MASK.load(Ordering::Relaxed);
        // SAFETY: `FpuState` is 64-byte aligned and `MAX_XSAVE_AREA` bytes
        // long, satisfying the `xsave64` memory-operand requirements.
        // CR4.OSXSAVE is enabled and XCR0 has been programmed.
        unsafe {
            asm!(
                "xsave64 [{state}]",
                state = in(reg) state.bytes.as_mut_ptr(),
                in("eax") mask as u32,
                in("edx") (mask >> 32) as u32,
                options(nostack, preserves_flags),
            );
        }
    } else {
        // SAFETY: `FpuState` is 64-byte aligned (>= 16) and at least 512
        // bytes, matching the `fxsave64` architectural memory operand.
        // CR4.OSFXSR is enabled.
        unsafe {
            asm!(
                "fxsave64 [{state}]",
                state = in(reg) state.bytes.as_mut_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Restore the current CPU's FPU state (XRSTOR when available, FXRSTOR
/// otherwise).
pub(crate) fn restore_current(state: &FpuState) {
    if XSAVE_SUPPORTED.load(Ordering::Relaxed) {
        let mask = XSAVE_FEATURE_MASK.load(Ordering::Relaxed);
        // SAFETY: `state` was produced by `save_current` or the clean
        // template.  The buffer is 64-byte aligned and large enough.
        unsafe {
            asm!(
                "xrstor64 [{state}]",
                state = in(reg) state.bytes.as_ptr(),
                in("eax") mask as u32,
                in("edx") (mask >> 32) as u32,
                options(nostack, preserves_flags),
            );
        }
    } else {
        // SAFETY: valid `fxsave64` image, buffer is properly aligned.
        unsafe {
            asm!(
                "fxrstor64 [{state}]",
                state = in(reg) state.bytes.as_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }
}

// ── Internals ───────────────────────────────────────────────────────────

/// Probe CPUID for XSAVE support and, when found, enable CR4.OSXSAVE and
/// programme XCR0 with the largest supported feature set.
///
/// Safe to call on every CPU — the first call sets the atomics; subsequent
/// calls just re-enable CR4.OSXSAVE and re-programme XCR0 from the cached
/// feature mask (both are per-CPU registers).
fn detect_and_enable_xsave() {
    let cpuid = CpuId::new();
    let fi = match cpuid.get_feature_info() {
        Some(fi) => fi,
        None => return,
    };

    if !fi.has_xsave() {
        return;
    }

    // Enable CR4.OSXSAVE so that XCR0 reads/writes and XSAVE/XRSTOR work.
    // SAFETY: we only set a single additional bit; all other CR4 bits are
    // preserved.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSXSAVE);
        });
    }

    // Build the feature mask.  x87 + SSE are always present when XSAVE is
    // supported.
    let mut feature_mask: u64 = 0x3; // bits 0 (x87) + 1 (SSE)

    // Query CPUID leaf 0xD sub-leaf 0 for the supported XCR0 bits.
    let xsave_info = core::arch::x86_64::__cpuid_count(0x0D, 0);
    let xcr0_supported = (xsave_info.eax as u64) | ((xsave_info.edx as u64) << 32);

    // AVX (bit 2)
    if xcr0_supported & (1 << 2) != 0 {
        feature_mask |= 1 << 2;
    }

    // AVX-512 components: opmask (5), ZMM_Hi256 (6), Hi16_ZMM (7)
    const AVX512_BITS: u64 = (1 << 5) | (1 << 6) | (1 << 7);
    if xcr0_supported & AVX512_BITS == AVX512_BITS {
        feature_mask |= AVX512_BITS;
    }

    // Programme XCR0 with the chosen feature mask.
    // SAFETY: we only enable features reported as supported by CPUID, and
    // CR4.OSXSAVE is already set.
    unsafe {
        asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") feature_mask as u32,
            in("edx") (feature_mask >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }

    // Query the required XSAVE area size for the enabled feature set.
    // Sub-leaf 0, ECX = max size for all supported components.
    let size_info = core::arch::x86_64::__cpuid_count(0x0D, 0);
    let area_size = (size_info.ecx as usize).min(MAX_XSAVE_AREA);

    XSAVE_SUPPORTED.store(true, Ordering::Relaxed);
    XSAVE_AREA_SIZE.store(area_size, Ordering::Relaxed);
    XSAVE_FEATURE_MASK.store(feature_mask, Ordering::Relaxed);
}

fn reset_current_cpu_state() {
    let mxcsr = DEFAULT_MXCSR;
    // SAFETY: after enabling x87/SSE in CR0/CR4, `fninit` resets the x87 state for the current
    // CPU and `ldmxcsr` installs the architectural default SSE control word for that CPU only.
    unsafe {
        asm!(
            "fninit",
            "ldmxcsr [{mxcsr}]",
            mxcsr = in(reg) &mxcsr,
            options(nostack, preserves_flags)
        );
    }
}
