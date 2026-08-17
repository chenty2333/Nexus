// SPDX-License-Identifier: MPL-2.0

#![forbid(unsafe_code)]

use cser_core::{CatalogSet, standard_catalog, tool_dma_catalog};

fn main() {
    let catalog = match std::env::args().nth(1).as_deref() {
        None | Some("standard") => standard_catalog(),
        Some("tool-dma") => tool_dma_catalog(),
        Some(other) => {
            eprintln!("usage: cser-catalog-digest [standard|tool-dma]; unknown catalog: {other}");
            std::process::exit(2);
        }
    };
    let catalogs = CatalogSet::new(&[catalog]).expect("built-in catalog set is valid");
    for byte in catalogs.digest().bytes() {
        print!("{byte:02x}");
    }
    println!();
}
