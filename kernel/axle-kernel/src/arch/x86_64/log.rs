//! Minimal `print!`/`println!` backed by serial.

use core::fmt;

use super::serial;

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::log::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => { $crate::kprint!("{}\n", format_args!($($arg)*)) };
}

pub fn _print(args: fmt::Arguments<'_>) {
    serial::_print(args);
}
