#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
use axle_types::zx_handle_t;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    nexus_init::report_panic_with_info(info)
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start(bootstrap_channel: zx_handle_t, arg1: u64) -> ! {
    nexus_init::program_start(bootstrap_channel, arg1)
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {
    nexus_init::program_end()
}

#[cfg(not(target_os = "none"))]
fn main() {}
