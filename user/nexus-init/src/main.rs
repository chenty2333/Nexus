#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

use axle_types::zx_handle_t;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    nexus_init::report_panic_with_info(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start(bootstrap_channel: zx_handle_t, arg1: u64) -> ! {
    nexus_init::program_start(bootstrap_channel, arg1)
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {
    nexus_init::program_end()
}
