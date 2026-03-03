//! Architecture glue.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("axle-kernel currently only supports x86_64 bring-up");
