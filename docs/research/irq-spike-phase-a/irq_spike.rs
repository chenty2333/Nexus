// SPDX-License-Identifier: MPL-2.0

//! Phase A IRQ spike: observe one real legacy INTx delivery.
//!
//! This lane is a spike in the sense of
//! `docs/research/irq-path-plan.md`. It answers two questions empirically and
//! claims nothing else:
//!
//! 1. which Global System Interrupt the fixed VirtIO block function's INTA#
//!    pin actually reaches, and whether the firmware-programmed PCI interrupt
//!    line at configuration offset `0x3c` predicts it;
//! 2. whether an I/O APIC mapping delivers at all while
//!    `intel-iommu,intremap=on` is active.
//!
//! Completion is still taken from the polling probe. The interrupt callback
//! only records that a delivery happened. This lane therefore observes
//! interrupt *delivery*; it does not establish interrupt-driven completion,
//! fence enforcement, exactly-once delivery, deadline policy, SMP safety, or
//! any production-identity property, and it must not be read as a checkpoint.
//!
//! Because the used-ring notification suppression is chosen before queue
//! exposure, this lane prepares through `prepare_read_sector0_irq`. That is the
//! only difference from the Stage 5B preparation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use nexus_ostd_virtio::{
    CompletionMode, CompletionProgress, ProductionDevice, discover_and_own_bars,
};
use ostd::{
    arch::irq::{GsiConfig, GsiPolarity, GsiTriggerMode, IRQ_CHIP, MappedIrqLine},
    irq::IrqLine,
    power::{ExitCode, poweroff},
    prelude::*,
};

/// One past the highest Global System Interrupt this spike will probe.
///
/// The pinned q35 machine exposes a single I/O APIC whose redirection entries
/// cover GSI 0..=23. PCI INTx for the root complex is routed into the
/// PIRQA..PIRQH block at the top of that range.
const GSI_LIMIT: usize = 24;

/// First GSI of the q35 PIRQA..PIRQH block.
const PIRQ_BASE: u32 = 16;

/// Bounded budget for the unmasked observation window.
///
/// This is an iteration count, not a deadline. The spike deliberately does not
/// introduce a clock: choosing a deadline policy is Phase C work, and inventing
/// one here would let a later phase inherit an unexamined number.
const OBSERVE_LIMIT: usize = 20_000_000;

/// Per-GSI delivery counters written by the hard-IRQ top half.
///
/// The callback does nothing else. It performs no allocation, no logging, no
/// device access, and no descriptor work, so it is safe in the interrupt
/// context that OSTD invokes with local interrupts disabled.
static DELIVERIES: [AtomicU32; GSI_LIMIT] = [const { AtomicU32::new(0) }; GSI_LIMIT];

fn deliveries(gsi: u32) -> u32 {
    DELIVERIES[gsi as usize].load(Ordering::Relaxed)
}

fn total_deliveries() -> u32 {
    (0..GSI_LIMIT as u32).map(deliveries).sum()
}

/// One armed candidate line, retained so its I/O APIC entry stays enabled.
struct ArmedGsi {
    gsi: u32,
    vector: u8,
    remapping_index: Option<u16>,
    _mapped: MappedIrqLine,
}

/// Arms every candidate GSI so that one delivery identifies the real route.
///
/// Candidates are the firmware-programmed interrupt line, when it names a
/// routable entry, followed by the whole PIRQA..PIRQH block. Arming the block
/// rather than trusting one number is what turns open question 1 into an
/// observation: whichever entry fires identifies the real route.
///
/// A candidate that cannot be mapped is reported and skipped. An I/O APIC entry
/// already in use by the platform is an ordinary outcome here, not a failure.
fn arm_candidates(firmware_line: u8) -> Vec<ArmedGsi> {
    let mut candidates: Vec<u32> = Vec::new();
    if u32::from(firmware_line) < GSI_LIMIT as u32 {
        candidates.push(u32::from(firmware_line));
    }
    for gsi in PIRQ_BASE..GSI_LIMIT as u32 {
        if !candidates.contains(&gsi) {
            candidates.push(gsi);
        }
    }

    // Edge, not level. Legacy PCI INTx is electrically level/active-low, and
    // this lane first ran with `GsiTriggerMode::Level`. That configuration
    // livelocks: nothing in Phase A reads the VirtIO ISR, so the line stays
    // asserted, the handler re-enters on every IRET, and the guest makes no
    // observable forward progress (recorded in the Phase A outcome section of
    // `docs/research/irq-path-plan.md`). An edge mapping fires once per
    // assertion, which is exactly and only what a delivery observation needs.
    // Deasserting the line is the completion actor's job, and that actor is
    // Phase B work; this lane must not pretend to do it.
    let config = GsiConfig::new(GsiPolarity::ActiveHigh, GsiTriggerMode::Edge);
    let mut armed = Vec::new();
    for gsi in candidates {
        let mut line = match IrqLine::alloc() {
            Ok(line) => line,
            Err(error) => {
                println!(
                    "IRQ_SPIKE ArmSkip gsi={} stage=alloc error={:?}",
                    gsi, error
                );
                continue;
            }
        };
        let vector = line.num();
        let remapping_index = line.remapping_index();
        line.on_active(move |_| {
            DELIVERIES[gsi as usize].fetch_add(1, Ordering::Relaxed);
        });
        let chip = IRQ_CHIP.get().expect("IRQ chip is initialized");
        match chip.map_gsi_pin_to_with_config(line, gsi, config) {
            Ok(mapped) => {
                println!(
                    "IRQ_SPIKE Armed gsi={} vector={} remapping_index={:?} trigger=edge polarity=active_high",
                    gsi, vector, remapping_index,
                );
                armed.push(ArmedGsi {
                    gsi,
                    vector,
                    remapping_index,
                    _mapped: mapped,
                });
            }
            Err(error) => {
                println!("IRQ_SPIKE ArmSkip gsi={} stage=map error={:?}", gsi, error);
            }
        }
    }
    armed
}

/// Runs the bounded Phase A observation and powers the machine off.
pub(crate) fn run() -> ! {
    println!("IRQ_SPIKE KERNEL_MARKER stage=phase_a oracle_suffix=true");
    println!(
        "IRQ_SPIKE BEGIN device=blk completion=polling delivery=intx trigger=edge polarity=active_high intremap=on claim=none"
    );

    let mut root = match discover_and_own_bars() {
        Ok(root) => root,
        Err(error) => {
            println!("IRQ_SPIKE FAIL stage=discovery error={:?}", error);
            poweroff(ExitCode::Failure)
        }
    };
    let route = root.intx_route();
    println!(
        "IRQ_SPIKE Route bdf={} firmware_line={} pin={} source=pci_config_0x3c",
        root.device_bdf(),
        route.line(),
        route.pin(),
    );

    // Claim the linear INTx lifecycle before the device is enabled. Preparation
    // is allowed to keep asserting `INTERRUPT_DISABLE` underneath a claimed
    // masked token; it is only an unmasked or poisoned token that would refuse.
    let masked = match root.claim_masked_intx() {
        Ok(masked) => masked,
        Err(error) => {
            println!("IRQ_SPIKE FAIL stage=claim_masked_intx error={:?}", error);
            poweroff(ExitCode::Failure)
        }
    };
    println!(
        "IRQ_SPIKE Masked stage=claimed line={}",
        masked.route().line()
    );

    let armed = arm_candidates(route.line());
    if armed.is_empty() {
        println!("IRQ_SPIKE FAIL stage=arm reason=no_candidate_gsi_mapped");
        poweroff(ExitCode::Failure)
    }

    let mut device = match ProductionDevice::for_owned_device(&mut root) {
        Ok(device) => device,
        Err(error) => {
            println!("IRQ_SPIKE FAIL stage=claim_device error={:?}", error);
            poweroff(ExitCode::Failure)
        }
    };

    // Interrupt mode differs from the Stage 5B preparation only in enabling
    // used-buffer notifications before publication.
    let prepared = match device.prepare_read_sector0_irq(&mut root) {
        Ok(prepared) => prepared,
        Err(error) => {
            println!("IRQ_SPIKE FAIL stage=prepare error={:?}", error);
            poweroff(ExitCode::Failure)
        }
    };
    let receipted = match device.issue_preparation_receipt(prepared) {
        Ok(receipted) => receipted,
        Err(failure) => {
            println!("IRQ_SPIKE FAIL stage=receipt error={:?}", failure.error());
            poweroff(ExitCode::Failure)
        }
    };
    let identity = receipted.identity();
    let mode = receipted.completion_mode();
    println!(
        "IRQ_SPIKE Prepared session={:#018x} generation={} queue={} descriptor={} notifications_enabled={}",
        identity.device_session(),
        identity.device_generation(),
        identity.queue(),
        identity.descriptor_token(),
        mode == CompletionMode::Interrupt,
    );

    let intent = match device.preflight_publish(receipted, identity) {
        Ok(intent) => intent,
        Err(failure) => {
            println!(
                "IRQ_SPIKE FAIL stage=preflight_publish error={:?}",
                failure.error()
            );
            poweroff(ExitCode::Failure)
        }
    };
    let mut published = intent.apply();
    let notification = published.notify();
    println!(
        "IRQ_SPIKE Published commit_point=avail_idx_release notification={:?}",
        notification,
    );

    // Unmask only after the request is device-visible and every callback is
    // installed. `ack_interrupt` is deliberately not called: this lane observes
    // delivery, and reading the ISR here would make the observation depend on
    // the completion actor that Phase B introduces.
    //
    // Leaving the VirtIO ISR unread means a level-triggered INTx line stays
    // asserted after the first delivery, so the handler re-enters immediately
    // on every IRET. Everything between unmask and remask therefore runs under
    // a re-entering interrupt and must be as short as possible: no serial
    // output, no allocation, only the counter poll. Announce the window before
    // opening it and report the result after closing it.
    println!(
        "IRQ_SPIKE Unmasking stage=window_open line={} isr_unread=true reentry_expected=true",
        masked.route().line()
    );
    let unmasked = match root.unmask_intx(masked) {
        Ok(unmasked) => unmasked,
        Err(failure) => {
            println!("IRQ_SPIKE FAIL stage=unmask error={:?}", failure.error());
            poweroff(ExitCode::Failure)
        }
    };

    let mut observed_iterations = 0usize;
    while observed_iterations < OBSERVE_LIMIT && total_deliveries() == 0 {
        observed_iterations += 1;
        core::hint::spin_loop();
    }
    let remasked = match root.mask_intx(unmasked) {
        Ok(masked) => masked,
        Err(failure) => {
            println!("IRQ_SPIKE FAIL stage=remask error={:?}", failure.error());
            poweroff(ExitCode::Failure)
        }
    };
    let total = total_deliveries();
    println!(
        "IRQ_SPIKE Remasked stage=window_closed line={} iterations={} deliveries={}",
        remasked.route().line(),
        observed_iterations,
        total,
    );

    for entry in &armed {
        println!(
            "IRQ_SPIKE Candidate gsi={} vector={} remapping_index={:?} deliveries={}",
            entry.gsi,
            entry.vector,
            entry.remapping_index,
            deliveries(entry.gsi),
        );
    }

    // Completion still comes from the polling probe, which runs its own bounded
    // loop. This keeps the spike's single new claim confined to delivery.
    let completion_observed = match published.poll_completion() {
        CompletionProgress::Complete(done) => {
            println!(
                "IRQ_SPIKE Completion source=polling observed=true used_len={}",
                done.used_len(),
            );
            true
        }
        CompletionProgress::Pending(_) => {
            println!("IRQ_SPIKE Completion source=polling observed=false reason=pending");
            false
        }
        CompletionProgress::Failed(_) => {
            println!("IRQ_SPIKE Completion source=polling observed=false reason=failed");
            false
        }
    };

    // Under q35 the same INTA# assertion reaches the I/O APIC twice: once on
    // the ISA-compatibility line the firmware programmed into configuration
    // offset 0x3c, and once on the PCI link entry in the PIRQA..PIRQH block.
    // Arming both is what makes that visible; a driver must choose one route
    // and leave the other masked, or it will take two interrupts per assertion.
    let firmware_gsi = u32::from(route.line());
    let firmware_delivered = deliveries(firmware_gsi) > 0;
    let pirq_gsi = (PIRQ_BASE..GSI_LIMIT as u32).find(|gsi| deliveries(*gsi) > 0);

    if total == 0 {
        println!(
            "IRQ_SPIKE NEGATIVE delivery=none firmware_line={} candidates={} iterations={} intremap=on trigger=edge polarity=active_high completion_observed={} claim=none",
            route.line(),
            armed.len(),
            observed_iterations,
            completion_observed,
        );
        poweroff(ExitCode::Failure)
    }

    println!(
        "IRQ_SPIKE PASS delivery=observed deliveries={} firmware_line={} firmware_line_delivered={} pirq_gsi={:?} iterations={} candidates={} intremap=on trigger=edge polarity=active_high completion=polling completion_observed={} claim=none",
        total,
        route.line(),
        firmware_delivered,
        pirq_gsi,
        observed_iterations,
        armed.len(),
        completion_observed,
    );
    poweroff(ExitCode::Success)
}
