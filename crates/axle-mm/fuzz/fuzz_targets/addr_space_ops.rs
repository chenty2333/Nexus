#![no_main]

use axle_mm::{AddressSpace, MappingPerms, PAGE_SIZE, VmoKind};
use libfuzzer_sys::fuzz_target;

const ROOT_BASE: u64 = 0x1_0000_0000;
const ROOT_LEN: u64 = 16 * PAGE_SIZE;

fuzz_target!(|data: &[u8]| {
    let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
    let mut vmos = [None; 8];

    for chunk in data.chunks(8) {
        match chunk.first().copied().unwrap_or(0) % 5 {
            0 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmos.len() as u8);
                let pages = u64::from((chunk.get(2).copied().unwrap_or(0) % 4) + 1);
                let kind = match chunk.get(3).copied().unwrap_or(0) % 3 {
                    0 => VmoKind::Anonymous,
                    1 => VmoKind::Physical,
                    _ => VmoKind::Contiguous,
                };
                vmos[slot] = space.create_vmo(kind, pages * PAGE_SIZE).ok();
            }
            1 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmos.len() as u8);
                let Some(vmo_id) = vmos[slot] else {
                    continue;
                };
                let page_index = u64::from(chunk.get(2).copied().unwrap_or(0) % 16);
                let pages = u64::from((chunk.get(3).copied().unwrap_or(0) % 2) + 1);
                let perms = decode_perms(chunk.get(4).copied().unwrap_or(0));
                let _ = space.map_fixed(
                    ROOT_BASE + (page_index * PAGE_SIZE),
                    pages * PAGE_SIZE,
                    vmo_id,
                    0,
                    perms,
                    perms,
                );
            }
            2 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let pages = u64::from((chunk.get(2).copied().unwrap_or(0) % 2) + 1);
                let _ = space.unmap(ROOT_BASE + (page_index * PAGE_SIZE), pages * PAGE_SIZE);
            }
            3 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let perms = decode_perms(chunk.get(2).copied().unwrap_or(0));
                let _ = space.protect(ROOT_BASE + (page_index * PAGE_SIZE), PAGE_SIZE, perms);
            }
            _ => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let _ = space.lookup(ROOT_BASE + (page_index * PAGE_SIZE));
            }
        }
    }

    let vmas = space.vmas();
    for pair in vmas.windows(2) {
        assert!(pair[0].base() + pair[0].len() <= pair[1].base());
    }
});

fn decode_perms(bits: u8) -> MappingPerms {
    let mut perms = MappingPerms::USER;
    if bits & 0b001 != 0 {
        perms |= MappingPerms::READ;
    }
    if bits & 0b010 != 0 {
        perms |= MappingPerms::WRITE;
    }
    if bits & 0b100 != 0 {
        perms |= MappingPerms::EXECUTE;
    }
    perms
}
