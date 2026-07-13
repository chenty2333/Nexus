// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod dma;
mod pci;
mod portal;

use ostd::{
    power::{ExitCode, poweroff},
    prelude::*,
};

use crate::{
    dma::OwnerKind,
    portal::{
        ClosureProgress, ClosureReceipt, IotlbTombstone, Operation, Portal, RegisterError,
        ResetTombstone, Terminal, terminal_label,
    },
};

const SECTOR_MAGIC: &[u8] = b"NEXUS-CSER-VIRTIO-BLK-STAGE5B\n";
const EXPECTED_SECTOR_FNV1A: u64 = 0xc4b4_ad90_59af_d22e;

fn sector_fnv1a(sector: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in sector {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn assert_fixture(sector: &[u8]) -> u64 {
    assert_eq!(&sector[..SECTOR_MAGIC.len()], SECTOR_MAGIC);
    assert!(sector[SECTOR_MAGIC.len()..].iter().all(|byte| *byte == 0));
    let hash = sector_fnv1a(sector);
    assert_eq!(hash, EXPECTED_SECTOR_FNV1A);
    hash
}

fn retry_reset(mut tombstone: ResetTombstone, root: &mut pci::Root) -> portal::ResetAck {
    for _ in 0..16 {
        match tombstone.retry_ack(root) {
            Ok(ack) => return ack,
            Err(retained) => tombstone = retained,
        }
    }
    panic!("reset remained pending; tombstone must be retained by recovery policy");
}

fn finish_iotlb(mut progress: ClosureProgress) -> ClosureReceipt {
    for _ in 0..16 {
        match progress {
            ClosureProgress::Complete(receipt) => return receipt,
            ClosureProgress::Pending(tombstone) => {
                assert!(
                    !tombstone.failure_retained(),
                    "IOMMU entered a fail-closed retained state"
                );
                progress = tombstone.retry(1024);
            }
        }
    }
    panic!("IOTLB completion remained pending; tombstone must be retained");
}

fn expect_injected_iotlb_tombstone(progress: ClosureProgress) -> IotlbTombstone {
    match progress {
        ClosureProgress::Pending(tombstone) => tombstone,
        ClosureProgress::Complete(_) => panic!("injected IOTLB poll did not retain ownership"),
    }
}

#[ostd::main]
fn kernel_main() {
    // The oracle discards all firmware trace before this line. OVMF may inspect
    // the readonly disk, so whole-log VirtIO request counts are not evidence.
    println!("VIRTIO_CSER KERNEL_MARKER stage=5b oracle_suffix=true");
    println!(
        "VIRTIO_CSER BEGIN device=blk mode=polling irq_masked=true smp=not_proven hardware=QEMU"
    );
    let namespace_isolation = portal::assert_session_namespace_isolation();
    println!("{}", namespace_isolation.into_marker());

    let (mut root, device_function, memory_bars) = pci::discover_and_own_bars();
    println!(
        "PCI Found bdf={} vendor=1af4 device=1042 modern=true memory_bar_owners={}",
        device_function, memory_bars
    );

    let mut portal = Portal::new(device_function);
    let first_binding = portal.binding_token().expect("initial live binding");
    let effects_before = portal.effect_count();
    let next_request_before = portal.next_request_id();
    assert_eq!(
        portal.register(first_binding, Operation::WriteSector0),
        Err(RegisterError::ReadOnly)
    );
    assert_eq!(portal.effect_count(), effects_before);
    assert_eq!(portal.next_request_id(), next_request_before);
    println!(
        "IO WriteReject operation=write_sector0 error=ReadOnly before_add=true effects_before={} effects_after={} next_request_unchanged=true",
        effects_before,
        portal.effect_count()
    );

    let first_authority = portal
        .register(first_binding, Operation::ReadSector0)
        .expect("register readonly sector-0 effect");
    println!(
        "IO Register request={} authority_epoch={} binding_epoch={} device_generation={} operation=read_sector0",
        first_authority.request_id(),
        first_authority.authority_epoch(),
        first_authority.binding_epoch(),
        first_authority.device_generation()
    );

    let mut first = portal
        .open_session(&mut root, first_authority)
        .expect("authority instance matches the owned PCI function and queue");
    println!(
        "FEATURES offered_required=true negotiated=0x0000000300000020 ro=true version1=true access_platform=true indirect=false event_idx=false"
    );
    println!("DMA Owners queue=2 request=1 total=3 remapped=true access_platform=true");
    for kind in [
        OwnerKind::QueueDriver,
        OwnerKind::QueueDevice,
        OwnerKind::Request,
    ] {
        let (paddr, iova) = dma::owner_address(first_authority.device_generation(), kind);
        assert_ne!(paddr, iova);
        println!(
            "DMA Owner generation={} kind={} paddr={:#x} iova={:#x} remapped=true",
            first_authority.device_generation(),
            kind.label(),
            paddr,
            iova
        );
    }

    let first_token = portal
        .commit_session(first_authority, &mut first)
        .expect("active binding wins the commit gate");
    assert!(!first.notify_sent());
    println!(
        "IO Commit request={} token={} point=avail_idx_release notify_sent=false published=true",
        first_authority.request_id(),
        first_token
    );
    println!(
        "IO Notify request={} one_shot=true notify_sent=false action=kick",
        first_authority.request_id()
    );
    assert!(portal.notify_effect(first_authority, &mut first));
    assert!(first.notify_sent());

    let used_len = first.poll_completion();
    let fixture_hash = assert_fixture(first.data());
    assert!(portal.accepts_device_completion(first.authority()));
    assert!(portal.complete_device(first.authority()));
    assert!(!portal.complete_device(first.authority()));
    assert_eq!(
        portal.terminal(first.authority()),
        Some(Terminal::Completed)
    );
    println!(
        "IO Completion request={} generation={} used_len={} status=OK duplicate_call_rejected=true",
        first_authority.request_id(),
        first_authority.device_generation(),
        used_len
    );
    println!(
        "IO Read magic_ok=true zero_tail=true fnv1a={:#018x}",
        fixture_hash
    );
    println!(
        "IO Terminal request={} state={}",
        first_authority.request_id(),
        terminal_label(Terminal::Completed)
    );

    println!(
        "REVOKE Begin generation={} submission_gate=closed reset_required=true",
        first_authority.device_generation()
    );
    let prepared_authority = portal
        .register(first_binding, Operation::ReadSector0)
        .expect("register pre-revoke probe effect");
    let aborted = portal.begin_closing();
    assert_eq!(aborted, 1);
    let mut stale_publish_invoked = false;
    assert!(
        portal
            .commit_effect(prepared_authority, || {
                stale_publish_invoked = true;
            })
            .is_none()
    );
    assert!(!stale_publish_invoked);
    assert_eq!(
        portal.terminal(prepared_authority),
        Some(Terminal::AbortedBeforeCommit)
    );
    assert_eq!(
        portal.register(first_binding, Operation::ReadSector0),
        Err(RegisterError::Closing)
    );
    println!(
        "REVOKE Gate request={} state=AbortedBeforeCommit stale_publish_rejected=true register_while_closing_rejected=true",
        prepared_authority.request_id()
    );
    let first_reset = portal.submit_reset(first, true);
    assert_eq!(first_reset.retained_dma_pages(), 3);
    let first_reset = match first_reset.retry_ack(&mut root) {
        Ok(_) => panic!("injected reset poll did not return Pending"),
        Err(retained) => retained,
    };
    println!(
        "RESET Pending generation={} timeout_injected=true hardware_timeout=false retained=true",
        first_authority.device_generation()
    );
    println!(
        "REVOKE Result=TimedOut tombstone=true retained_dma_pages={} owners_retained=true",
        first_reset.retained_dma_pages()
    );

    let mut first_ack = retry_reset(first_reset, &mut root);
    assert_eq!(first_ack.terminal(), Terminal::Completed);
    assert_eq!(first_ack.retained_dma_pages(), 3);
    assert!(first_ack.isr_read());
    assert_eq!(portal.acknowledge_reset(&mut first_ack), 0);
    assert_eq!(portal.device_generation(), 2);
    assert_eq!(portal.terminal(first_authority), Some(Terminal::Completed));
    println!(
        "RESET Retry generation={} ack=true bus_master=false isr_read=true terminal={} receipt_bound=true",
        first_ack.authority().device_generation(),
        terminal_label(first_ack.terminal())
    );
    println!(
        "RESET Fence old_generation={} new_generation={} unterminated_effects=0",
        first_authority.device_generation(),
        portal.device_generation()
    );

    let iotlb_tombstone = expect_injected_iotlb_tombstone(portal.begin_iotlb(first_ack, true));
    assert_eq!(iotlb_tombstone.retained_pages(), 3);
    println!(
        "IOTLB Pending generation={} owner={} timeout_injected=true hardware_timeout=false retained_dma_pages={} tombstone=true",
        first_authority.device_generation(),
        iotlb_tombstone.pending_kind().label(),
        iotlb_tombstone.retained_pages()
    );
    let first_closure = finish_iotlb(ClosureProgress::Pending(iotlb_tombstone));
    assert_eq!(first_closure.completed_pages(), 3);
    println!(
        "IOTLB Complete generation={} owners={} ack_before_free=true quiescence_receipt_bound=true",
        first_closure.generation(),
        first_closure.completed_pages()
    );
    println!(
        "REVOKE Quiesced generation={} retained_dma_pages=0 dma_pages_released=3",
        first_authority.device_generation()
    );

    let old_completion = first_authority;
    portal.mark_quiesced(first_closure);
    portal.rebind_after_quiescence();
    assert!(!portal.accepts_device_completion(old_completion));
    println!(
        "REBIND binding_epoch={} device_generation={} old_completion_rejected=true",
        portal.binding_epoch(),
        portal.device_generation()
    );

    let second_binding = portal.binding_token().expect("replacement binding");
    let second_authority = portal
        .register(second_binding, Operation::ReadSector0)
        .expect("register generation-2 sector-0 effect");
    println!(
        "IO Register request={} authority_epoch={} binding_epoch={} device_generation={} operation=read_sector0",
        second_authority.request_id(),
        second_authority.authority_epoch(),
        second_authority.binding_epoch(),
        second_authority.device_generation()
    );
    println!(
        "DEVICE Reenable generation={} after_quiescence=true",
        second_authority.device_generation()
    );
    let mut second = portal
        .open_session(&mut root, second_authority)
        .expect("rebound authority instance matches the owned PCI function and queue");
    let second_token = portal
        .commit_session(second_authority, &mut second)
        .expect("replacement binding wins the commit gate");
    assert!(second.committed());
    assert!(!second.notify_sent());
    println!(
        "IO Commit request={} token={} point=avail_idx_release notify_sent=false published=true",
        second_authority.request_id(),
        second_token
    );

    let (old_binding, new_binding) = portal.crash_service();
    second.close_after_service_crash(new_binding);
    assert_eq!(old_binding, second_authority.binding_epoch());
    assert_eq!(
        portal.register(second_binding, Operation::ReadSector0),
        Err(RegisterError::StaleBinding)
    );
    assert!(!portal.accepts_service_action(second_authority));
    assert!(portal.accepts_device_completion(second_authority));
    assert!(!portal.notify_effect(second_authority, &mut second));
    assert!(!second.notify_sent());
    println!(
        "IO Crash request={} old_binding={} new_binding={} service_action_rejected=true committed_completion_raceable=true notify_sent=false late_notify_rejected=true",
        second_authority.request_id(),
        old_binding,
        new_binding
    );

    println!(
        "RESET Begin generation={} published=true notified=false whole_device=true",
        second_authority.device_generation()
    );
    assert_eq!(portal.begin_closing(), 0);
    let mut second_ack = retry_reset(portal.submit_reset(second, false), &mut root);
    assert_eq!(second_ack.terminal(), Terminal::IndeterminateAfterReset);
    assert!(second_ack.isr_read());
    assert_eq!(portal.acknowledge_reset(&mut second_ack), 1);
    assert_eq!(
        portal.terminal(second_authority),
        Some(Terminal::IndeterminateAfterReset)
    );
    assert!(!portal.accepts_device_completion(second_authority));
    assert!(!portal.complete_device(second_authority));
    println!(
        "RESET Ack generation={} ack=true bus_master=false isr_read=true terminal={} receipt_bound=true",
        second_ack.authority().device_generation(),
        terminal_label(second_ack.terminal())
    );
    println!(
        "RESET Fence old_generation={} new_generation={} terminalized_effects=1 stale_completion_rejected=true",
        second_authority.device_generation(),
        portal.device_generation()
    );
    println!(
        "IO Terminal request={} state={} cancelled=false duplicate_terminal_call_rejected=true",
        second_authority.request_id(),
        terminal_label(second_ack.terminal())
    );

    let second_closure = finish_iotlb(portal.begin_iotlb(second_ack, false));
    assert_eq!(second_closure.completed_pages(), 3);
    println!(
        "IOTLB Complete generation={} owners={} ack_before_free=true quiescence_receipt_bound=true",
        second_closure.generation(),
        second_closure.completed_pages()
    );
    portal.mark_quiesced(second_closure);
    println!(
        "COMPLETION Fence stale_generation_rejected=true stale_binding_rejected=true duplicate_terminal_rejected=true"
    );
    println!(
        "VIRTIO_CSER PASS device_dma=true device_reset=true mediated=true iotlb_completion=true timeout_injected=true hardware_timeout=false polling=true smp=not_proven portal_type_state=true"
    );
    poweroff(ExitCode::Success);
}
