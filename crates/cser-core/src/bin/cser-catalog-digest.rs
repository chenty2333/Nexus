// SPDX-License-Identifier: MPL-2.0

#![forbid(unsafe_code)]

use cser_core::standard_catalog;

fn main() {
    for byte in standard_catalog().digest().bytes() {
        print!("{byte:02x}");
    }
    println!();
}
