#![no_main]

use axle_mm::{AddressSpace, FrameTable, GlobalVmoId, MappingPerms, PAGE_SIZE, VmarId, VmoKind};
use libfuzzer_sys::fuzz_target;

const ROOT_BASE: u64 = 0x1_0000_0000;
const ROOT_LEN: u64 = 0x40_0000;

fuzz_target!(|data: &[u8]| {
    let mut space = AddressSpace::new(ROOT_BASE, ROOT_LEN).unwrap();
    let mut frames = FrameTable::new();
    let mut vmos = [None; 8];
    let mut vmars: [Option<VmarId>; 8] = [None; 8];

    for chunk in data.chunks(8) {
        match chunk.first().copied().unwrap_or(0) % 11 {
            0 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmos.len() as u8);
                let pages = u64::from((chunk.get(2).copied().unwrap_or(0) % 4) + 1);
                let kind = match chunk.get(3).copied().unwrap_or(0) % 3 {
                    0 => VmoKind::Anonymous,
                    1 => VmoKind::Physical,
                    _ => VmoKind::Contiguous,
                };
                vmos[slot] = space
                    .create_vmo(kind, pages * PAGE_SIZE, GlobalVmoId::new((slot as u64) + 1))
                    .ok();
            }
            1 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmos.len() as u8);
                let Some(vmo_id) = vmos[slot] else {
                    continue;
                };
                let page_index = u64::from(chunk.get(2).copied().unwrap_or(0) % 4);
                let frame_addr = 0x2000_0000 + (u64::from(chunk.get(3).copied().unwrap_or(0)) * PAGE_SIZE);
                let frame_id = match frames.register_existing(frame_addr) {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };
                let _ = space.bind_vmo_frame(vmo_id, page_index * PAGE_SIZE, frame_id);
            }
            2 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmos.len() as u8);
                let Some(vmo_id) = vmos[slot] else {
                    continue;
                };
                let page_index = u64::from(chunk.get(2).copied().unwrap_or(0) % 16);
                let pages = u64::from((chunk.get(3).copied().unwrap_or(0) % 2) + 1);
                let perms = decode_perms(chunk.get(4).copied().unwrap_or(0));
                let _ = space.map_fixed(
                    &mut frames,
                    ROOT_BASE + (page_index * PAGE_SIZE),
                    pages * PAGE_SIZE,
                    vmo_id,
                    0,
                    perms,
                    perms,
                );
            }
            3 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let pages = u64::from((chunk.get(2).copied().unwrap_or(0) % 2) + 1);
                let _ = space.unmap(&mut frames, ROOT_BASE + (page_index * PAGE_SIZE), pages * PAGE_SIZE);
            }
            4 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let perms = decode_perms(chunk.get(2).copied().unwrap_or(0));
                let _ = space.protect(ROOT_BASE + (page_index * PAGE_SIZE), PAGE_SIZE, perms);
            }
            5 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let _ = space.lookup(ROOT_BASE + (page_index * PAGE_SIZE));
            }
            6 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let _ = space.mark_copy_on_write(ROOT_BASE + (page_index * PAGE_SIZE), PAGE_SIZE);
            }
            7 => {
                let page_index = u64::from(chunk.get(1).copied().unwrap_or(0) % 16);
                let frame_addr =
                    0x3000_0000 + (u64::from(chunk.get(2).copied().unwrap_or(0)) * PAGE_SIZE);
                let frame_id = match frames.register_existing(frame_addr) {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };
                let _ = space.resolve_cow_fault(
                    &mut frames,
                    ROOT_BASE + (page_index * PAGE_SIZE),
                    frame_id,
                );
            }
            8 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmars.len() as u8);
                let cpu_id = usize::from(chunk.get(2).copied().unwrap_or(0) % 4);
                let pages = u64::from((chunk.get(3).copied().unwrap_or(0) % 4) + 1);
                let align_pages = 1_u64 << u64::from(chunk.get(4).copied().unwrap_or(0) % 3);
                vmars[slot] = space
                    .allocate_subvmar_for_cpu(cpu_id, pages * PAGE_SIZE, align_pages * PAGE_SIZE)
                    .ok()
                    .map(|vmar| vmar.id());
            }
            9 => {
                let slot = usize::from(chunk.get(1).copied().unwrap_or(0) % vmars.len() as u8);
                let Some(vmar_id) = vmars[slot] else {
                    continue;
                };
                let _ = space.destroy_vmar(vmar_id);
                vmars[slot] = None;
            }
            _ => {
                let frame_addr = 0x2000_0000 + (u64::from(chunk.get(1).copied().unwrap_or(0)) * PAGE_SIZE);
                if let Ok(frame_id) = frames.register_existing(frame_addr) {
                    let _ = frames.pin(frame_id);
                    let _ = frames.unpin(frame_id);
                }
            }
        }
    }

    let vmas = space.vmas();
    for pair in vmas.windows(2) {
        assert!(pair[0].base() + pair[0].len() <= pair[1].base());
    }
    let vmars = space.child_vmars();
    for pair in vmars.windows(2) {
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
