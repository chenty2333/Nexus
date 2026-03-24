#![no_main]

use axle_core::handle::Handle;
use axle_core::{CSpace, CSpaceError, Capability, RevocationManager, TransferredCap};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cs = CSpace::new(64, 8);
    let mut revocations = RevocationManager::new();
    let mut active: Vec<Handle> = Vec::new();
    let mut closed: Vec<Handle> = Vec::new();
    let mut transferred: Vec<TransferredCap> = Vec::new();
    let mut groups = Vec::new();

    for chunk in data.chunks(16) {
        if chunk.is_empty() {
            continue;
        }

        match chunk[0] % 10 {
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
            3 => {
                if !active.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % active.len();
                    let rights = le_u32(chunk.get(8..12).unwrap_or(&[]));
                    if let Ok(h) = cs.duplicate_derived(active[idx], rights) {
                        active.push(h);
                    }
                }
            }
            4 => {
                if !active.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % active.len();
                    let rights = le_u32(chunk.get(8..12).unwrap_or(&[]));
                    let old = active.swap_remove(idx);
                    match cs.replace_derived(old, rights) {
                        Ok(h) => {
                            active.push(h);
                            closed.push(old);
                        }
                        Err(CSpaceError::BadHandle) => closed.push(old),
                        Err(_) => {
                            // AccessDenied: old handle is still valid, push it back.
                            active.push(old);
                        }
                    }
                }
            }
            5 => {
                if !active.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % active.len();
                    let h = active.swap_remove(idx);
                    match cs.snapshot_checked(h, &revocations) {
                        Ok(entry) => {
                            transferred.push(entry);
                            if cs.close(h).is_ok() {
                                closed.push(h);
                            }
                        }
                        Err(CSpaceError::BadHandle) => closed.push(h),
                        Err(_) => {
                            // Handle still valid, push it back.
                            active.push(h);
                        }
                    }
                }
            }
            6 => {
                if !transferred.is_empty() {
                    let idx = usize::from(chunk.get(1).copied().unwrap_or(0)) % transferred.len();
                    let entry = transferred.swap_remove(idx);
                    if let Ok(h) = cs.install_transfer(entry) {
                        active.push(h);
                    }
                }
            }
            7 => {
                // Create a revocation group.
                let grp = revocations.create_group();
                groups.push(grp);
            }
            8 => {
                // Alloc a revocable handle using an existing group.
                if !groups.is_empty() {
                    let gidx = usize::from(chunk.get(1).copied().unwrap_or(0)) % groups.len();
                    let grp = groups[gidx];
                    let object_id = le_u64(chunk.get(2..10).unwrap_or(&[]));
                    let rights = le_u32(chunk.get(10..14).unwrap_or(&[]));
                    let generation = le_u32(chunk.get(14..16).unwrap_or(&[]));
                    if let Ok(h) = cs.alloc_revocable(
                        Capability::new(object_id, rights, generation),
                        &revocations,
                        grp,
                    ) {
                        active.push(h);
                    }
                }
            }
            9 => {
                // Revoke a group.
                if !groups.is_empty() {
                    let gidx = usize::from(chunk.get(1).copied().unwrap_or(0)) % groups.len();
                    let grp = groups[gidx];
                    let _ = revocations.revoke(grp);
                }
            }
            _ => unreachable!(),
        }

        // Verify active handles are still resolvable.
        for &h in &active {
            assert!(cs.get(h).is_ok(), "active handle must be resolvable");
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
