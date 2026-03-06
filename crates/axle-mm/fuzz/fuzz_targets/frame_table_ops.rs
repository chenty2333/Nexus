#![no_main]

use axle_mm::{FrameTable, PAGE_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut frames = FrameTable::new();

    for chunk in data.chunks(4) {
        let page = u64::from(chunk.get(1).copied().unwrap_or(0));
        let paddr = 0x4000_0000 + (page * PAGE_SIZE);
        match chunk.first().copied().unwrap_or(0) % 5 {
            0 => {
                let _ = frames.register_existing(paddr);
            }
            1 => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    let _ = frames.inc_ref(frame_id);
                }
            }
            2 => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    let _ = frames.dec_ref(frame_id);
                }
            }
            3 => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    let _ = frames.pin(frame_id);
                }
            }
            _ => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    let _ = frames.unpin(frame_id);
                }
            }
        }
    }
});
