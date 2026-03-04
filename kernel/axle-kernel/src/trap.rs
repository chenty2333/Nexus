//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build full fault handlers, IRQ handlers, and IPI handling.

use nexus_test_runner::run_int80_smoke;

use crate::arch;

pub fn init() {
    arch::idt::init_int80_gate(arch::int80::entry_addr());
    run_bootstrap_smoke();
}

fn run_bootstrap_smoke() {
    match run_int80_smoke() {
        Ok(summary) => crate::kprintln!(
            "runner: int80 smoke ok (unknown={}, bad_wait={}, empty_wait={}, queue={}, wait={}, timer_set={}, timer_cancel={}, close={}, close_again={}, port_h={}, timer_h={})",
            summary.unknown,
            summary.bad_wait,
            summary.empty_wait,
            summary.queue,
            summary.wait,
            summary.timer_set,
            summary.timer_cancel,
            summary.close,
            summary.close_again,
            summary.port_h,
            summary.timer_h
        ),
        Err(failure) => panic!(
            "runner: int80 smoke failed (step={}, expected={}, got={})",
            failure.step, failure.expected, failure.got
        ),
    }
}
