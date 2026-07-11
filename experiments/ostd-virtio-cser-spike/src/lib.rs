// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use ostd::{
    mm::{HasDaddr, HasPaddr, HasSize, dma::DmaCoherent},
    power::{ExitCode, poweroff},
    prelude::*,
};

const DMA_PAGES: usize = 1;

#[ostd::main]
fn kernel_main() {
    println!("DMA_CLOSURE BEGIN ostd=0.18.0 device_dma=false reset=false scope=single_coherent");
    println!(
        "DMA_CLOSURE Boundary api=one_page begin_bounded=true poll_bounded=true iommu_lock_wait=false init_handshake_sync=true smp=not_proven"
    );

    // This probe never publishes the IOVA to a device.  The unsafe
    // device-quiescence precondition therefore holds vacuously; it does not
    // constitute evidence for VirtIO reset or DMA drain.
    let first = DmaCoherent::alloc(DMA_PAGES, true).expect("allocate first coherent DMA page");
    let first_paddr = first.paddr();
    let first_daddr = first.daddr();
    let first_size = first.size();
    assert!(DmaCoherent::stage5a_local_irq_enabled());
    assert_ne!(
        first_daddr, first_paddr,
        "probe requires active VT-d remapping, not identity DMA"
    );
    println!(
        "DMA_CLOSURE Alloc remapped=true paddr={:#x} daddr={:#x} size={}",
        first_paddr, first_daddr, first_size
    );

    // SAFETY: `first_daddr` was never given to a device, so no device can
    // issue a new transaction through this mapping.
    let mut pending_owner = unsafe { first.begin_unmap_invalidate() };
    assert!(DmaCoherent::stage5a_local_irq_enabled());
    assert_eq!(pending_owner.retained_paddr(), first_paddr);
    assert_eq!(pending_owner.retained_daddr(), Some(first_daddr));
    assert_eq!(pending_owner.retained_size(), first_size);
    println!("DMA_CLOSURE Begin pte_removed=true iotlb_submitted=true owner_retained=true");

    pending_owner.inject_one_pending_poll();
    let mut pending_owner = match pending_owner.poll_complete() {
        Ok(_) => panic!("injected first poll must retain the DMA owner"),
        Err(pending) => pending,
    };
    assert!(DmaCoherent::stage5a_local_irq_enabled());
    assert!(pending_owner.failure().is_none());
    println!(
        "DMA_CLOSURE Pending injected=true result=Pending owner_retained=true iova_retained=true backing_retained=true credit_retained=true"
    );

    let unmapped = loop {
        pending_owner = match pending_owner.poll_complete() {
            Ok(unmapped) => break unmapped,
            Err(pending) => {
                assert!(DmaCoherent::stage5a_local_irq_enabled());
                assert!(
                    pending.failure().is_none(),
                    "IOMMU engine entered a retained failure state"
                );
                core::hint::spin_loop();
                pending
            }
        };
    };
    assert_eq!(unmapped.original_paddr(), first_paddr);
    assert_eq!(unmapped.original_daddr(), Some(first_daddr));
    assert_eq!(unmapped.size(), first_size);
    assert!(DmaCoherent::stage5a_local_irq_enabled());
    println!(
        "DMA_CLOSURE Ack observed=true iotlb_complete=true iova_freed=true paddr_tracking_released=true"
    );

    drop(unmapped);
    assert!(DmaCoherent::stage5a_local_irq_enabled());
    println!("DMA_CLOSURE BackingDrop after_ack=true");
    println!(
        "DMA_CLOSURE IrqGuard paired=true begin_return=true pending_return=true completion_return=true backing_drop=true"
    );

    let second = DmaCoherent::alloc(DMA_PAGES, true).expect("allocate replacement DMA page");
    let second_daddr = second.daddr();
    assert_eq!(
        second_daddr, first_daddr,
        "completed invalidation must return the exact IOVA range"
    );
    println!(
        "DMA_CLOSURE IovaReuse same_size=true old={:#x} new={:#x} reused=true",
        first_daddr, second_daddr
    );

    // Ordinary Drop now uses the patched synchronous fail-closed path.  This
    // still has no device-side reset claim because the second IOVA was never
    // exposed to hardware either.
    drop(second);
    println!(
        "DMA_CLOSURE PASS queued_iotlb=true wait_completion=true pending_owner=true iova_reuse=true device_dma=false device_reset=false"
    );
    poweroff(ExitCode::Success);
}
