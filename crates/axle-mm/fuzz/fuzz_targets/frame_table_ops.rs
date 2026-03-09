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
                    if let Ok(frame_ref) = frames.acquire_frame_ref(frame_id) {
                        let _ = frame_ref.release(&mut frames);
                    }
                }
            }
            2 => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    if let Ok(frame_ref) = frames.acquire_frame_ref(frame_id) {
                        let _ = frame_ref.release(&mut frames);
                    }
                }
            }
            3 => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    if let Ok(pin) = frames.pin_frame(frame_id) {
                        pin.release(&mut frames);
                    }
                }
            }
            _ => {
                if let Ok(frame_id) = frames.register_existing(paddr) {
                    if let Ok(pin) = frames.pin_frame(frame_id)
                        && let Ok(loan) = pin.into_loan(&mut frames)
                    {
                        loan.release(&mut frames);
                    }
                }
            }
        }
    }
});
