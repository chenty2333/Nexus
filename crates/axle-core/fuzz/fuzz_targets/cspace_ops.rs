#![no_main]

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cs = CSpace::new(64, 8);
    let mut active: Vec<Handle> = Vec::new();
    let mut closed: Vec<Handle> = Vec::new();

    for chunk in data.chunks(16) {
        if chunk.is_empty() {
            continue;
        }

        match chunk[0] % 3 {
            0 => {
                let object_id = le_u64(chunk.get(0..8).unwrap_or(&[]));
                let rights = le_u32(chunk.get(8..12).unwrap_or(&[]));
                let generation = le_u32(chunk.get(12..16).unwrap_or(&[]));
                if let Ok(h) = cs.alloc(Capability::new(object_id, rights, generation)) {
                    active.push(h);
                }
            }
            1 => {
                if !active.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % active.len();
                    let h = active.swap_remove(idx);
                    if cs.close(h).is_ok() {
                        closed.push(h);
                    }
                }
            }
            2 => {
                if !active.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % active.len();
                    if let Ok(h) = cs.duplicate(active[idx]) {
                        active.push(h);
                    }
                }
            }
            _ => unreachable!(),
        }

        for &h in &closed {
            assert!(matches!(cs.get(h), Err(CSpaceError::BadHandle)));
        }
    }
});

fn le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

fn le_u32(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    u32::from_le_bytes(buf)
}
