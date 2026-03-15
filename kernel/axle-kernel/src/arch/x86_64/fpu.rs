//! Minimal x86_64 x87/SSE enablement and per-thread FXSAVE state helpers.

use core::arch::asm;

use spin::Once;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

const DEFAULT_MXCSR: u32 = 0x1f80;

static CLEAN_FX_STATE: Once<FxState> = Once::new();

/// 16-byte-aligned FXSAVE image used for per-thread x87/SSE state.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FxState {
    bytes: [u8; 512],
}

impl FxState {
    const fn zeroed() -> Self {
        Self { bytes: [0; 512] }
    }

    fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

/// Enable legacy x87/SSE execution on the current CPU and seed the clean FXSAVE template.
pub(crate) fn init_cpu() {
    // SAFETY: Axle already runs in long mode on x86_64 CPUs here. We preserve unrelated CR0/CR4
    // bits and only enable the architectural x87/SSE flags required for user-space legacy SSE.
    unsafe {
        Cr0::update(|flags| {
            flags.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
        });
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }

    reset_current_cpu_state();
    CLEAN_FX_STATE.call_once(|| {
        let mut state = FxState::zeroed();
        save_current(&mut state);
        state
    });
}

/// Return the clean architectural x87/SSE state for a new user thread.
pub(crate) fn clean_state() -> FxState {
    *CLEAN_FX_STATE
        .get()
        .expect("x86_64 fpu state must be initialized before threads are created")
}

/// Save the current CPU's x87/SSE state.
pub(crate) fn save_current(state: &mut FxState) {
    // SAFETY: `FxState` is 16-byte aligned and 512 bytes long, matching the `fxsave64`
    // architectural memory operand. The current CPU already has `CR4.OSFXSR` enabled.
    unsafe {
        asm!(
            "fxsave64 [{state}]",
            state = in(reg) state.as_mut_ptr(),
            options(nostack, preserves_flags)
        );
    }
}

/// Restore the current CPU's x87/SSE state.
pub(crate) fn restore_current(state: &FxState) {
    // SAFETY: `FxState` is a valid `fxsave64` image produced either from the clean template or by
    // `save_current`, so `fxrstor64` may restore it on the current CPU.
    unsafe {
        asm!(
            "fxrstor64 [{state}]",
            state = in(reg) state.as_ptr(),
            options(nostack, preserves_flags)
        );
    }
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
