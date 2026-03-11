#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use axle_types::zx_handle_t;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    nexus_init::child_report_panic()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start(bootstrap_channel: zx_handle_t, _arg1: u64) -> ! {
    nexus_init::echo_provider_program_start(bootstrap_channel)
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}
