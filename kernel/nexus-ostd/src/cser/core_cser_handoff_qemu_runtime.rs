// SPDX-License-Identifier: MPL-2.0

//! Real-QEMU launcher for the bounded logical CSER3 handoff lane.
//!
//! The source and child are both catalog-defined one-component logical
//! composites.  In particular, this module never opens a DMA publication and
//! its receipt always reports `device_actions:0`.

use core::fmt;

use cser_core::{
    CatalogSet, ChargeAccountId, ClaimId, CoreLimits, EffectId, ExecutorCoordinate,
    ExecutorGeneration, ExecutorId, OperationId, RecoveryBinding, RecoveryProfile,
    RegistryInstance, ResourceGeneration, ResourceId, SingleHopHandoffProjection,
    TOOL_HANDOFF_COMPONENT, TOOL_HANDOFF_SOURCE_COMPONENT, WorldId, tool_dma_catalog,
};
use ostd::{
    power::{ExitCode, poweroff},
    prelude::println,
    task::Task,
};

use super::{
    core_crash_probe::{
        CrashCutpoint, CrashProbe, CrashProbeError, CrashRunId, ExperimentIdentity,
    },
    core_cser_handoff_experiment::{
        HandoffBarrier, HandoffSourceCoordinates, acknowledge_source, arm_handoff_source,
        descriptor_digest, install_child, release_source_and_record_child_intent,
        settle_and_retire,
    },
    core_qemu_persistent_boot::{
        PreparedQemuPersistentBoot, QemuPersistentAnchor, QemuPersistentBoot,
    },
    core_runtime::OstdCserRuntime,
    core_tool_adapter::{
        DurableToolObservation, ToolEndpointObservation, ToolOperationPlan, ToolTransportError,
        UartToolEndpoint,
    },
    core_tool_dma_runtime::ToolDmaRuntime,
    core_tool_uart::{ToolRunId, ToolUart, ToolV2Identity},
};

const EFFECT_ROOT: u64 = 0x4841_4e44;
const EFFECT_SEQUENCE: u64 = 1;
const SOURCE_CLAIM: u64 = 0x6501;
const SOURCE_RESOURCE: u64 = 0x6601;
const SOURCE_CHARGE: u64 = 0x6701;
const MAX_GET_POLLS: usize = 4;

type HandoffRuntime = OstdCserRuntime<
    cser_core::CoordinatedPersistence<super::core_pio_journal::AtaPioJournal, QemuPersistentAnchor>,
>;

/// Entry point wired by the experiment launcher feature.  It intentionally
/// owns COM2 only while doing an exact source/child POST or GET and COM3 only
/// for the numeric crash barriers below.
pub(crate) fn run() {
    let catalog = tool_dma_catalog();
    let catalogs = CatalogSet::new(core::slice::from_ref(&catalog))
        .expect("handoff catalog set is non-empty and canonical");
    let catalog_set_digest = catalogs.digest();
    let identity = acquire_identity(catalog.digest());
    let run_id = identity.run_id().bytes();
    let binding = RecoveryBinding::new(
        RecoveryProfile::current(),
        WorldId::new(1).expect("handoff world is non-zero"),
        catalog_set_digest,
        RegistryInstance::new(1).expect("handoff registry"),
    )
    .expect("handoff binding");
    let boot = PreparedQemuPersistentBoot::acquire()
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=boot-acquire"))
        .recover(catalogs, CoreLimits::bounded_default(), binding)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=boot-recover"));
    let source = source_plan(fixed_effect(), run_id, identity);
    let source_runtime = ToolDmaRuntime::new(source, 1).expect("handoff source verifier");
    let parent = fixed_effect();
    if boot
        .observe(|engine| engine.composite_effect(parent))
        .is_none()
    {
        run_initial(boot, source, source_runtime, identity);
    }
    run_recovery(boot, source, source_runtime, identity);
}

fn run_initial(
    boot: QemuPersistentBoot,
    source: ToolOperationPlan,
    source_runtime: ToolDmaRuntime,
    identity: ExperimentIdentity,
) -> ! {
    let run_id = source.run_id();
    let activated = boot
        .try_activate()
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=activate"));
    let (engine, persistence, _devices) = activated.into_parts();
    let mut runtime = OstdCserRuntime::from_engine(engine, persistence);
    let coordinates = source_coordinates(source.effect());
    let intent = arm_handoff_source(&mut runtime, coordinates, source)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=source-arm error={e:?}"));
    let observation = get_or_post_source(source_runtime)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=source-post error={e:?}"));
    let mut barriers = HandoffBarriers::acquire(run_id);
    barriers.reached(HandoffBarrier::DescriptorDiscovered);
    let descriptor = acknowledge_source(&mut runtime, source_runtime, intent, &observation)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=source-ack error={e:?}"));
    barriers.reached(HandoffBarrier::ParentAcknowledged);
    let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
        .expect("CSER_HANDOFF_FAIL stage=child-plan");
    let installed = install_child(
        &mut runtime,
        source_runtime,
        &observation,
        fixed_actor(1),
        nz(SOURCE_CHARGE + 1),
    )
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=child-install error={e:?}"));
    assert_eq!(
        installed, descriptor,
        "CSER_HANDOFF_FAIL stage=child-descriptor"
    );
    barriers.reached(HandoffBarrier::ChildInstalled);
    // The source and installed child now overlap. The source terminal record
    // is still the sole evidence used to retire its exact logical claim.
    settle_and_retire(
        &mut runtime,
        source.effect(),
        TOOL_HANDOFF_SOURCE_COMPONENT,
        fixed_actor(1),
        source_runtime,
        &observation,
    )
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=source-retire error={e:?}"));
    let child_intent = release_source_and_record_child_intent(
        &mut runtime,
        source_runtime,
        &observation,
        child,
        fixed_actor(1),
    )
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=handoff-commit error={e:?}"));
    assert_eq!(child_intent.effect(), child.effect());
    // This is the only point at which an external child operation is legal.
    barriers.reached(HandoffBarrier::HandoffCommittedBeforeChildPost);
    let retained_gate = rejected_gate(&runtime, descriptor);
    let child_runtime = ToolDmaRuntime::new(child, 1).expect("handoff child verifier");
    let child_observation = initial_child_observation(child_runtime, || {
        // Match the independent baseline: crash after the first child
        // endpoint response (GET terminal/nonterminal, or POST after GET
        // absent), before any child core acknowledgement or settlement.
        barriers.reached(HandoffBarrier::TerminalReceipt);
    })
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=child-observation error={e:?}"));
    let command = runtime
        .observe(|engine| {
            child_runtime.acknowledge_commit(engine, child_intent, &child_observation)
        })
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=child-ack-verify"));
    expect_none("initial-child-ack", runtime.transact(command));
    settle_and_retire(
        &mut runtime,
        child.effect(),
        TOOL_HANDOFF_COMPONENT,
        fixed_actor(1),
        child_runtime,
        &child_observation,
    )
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=child-retire error={e:?}"));
    emit_terminal(
        &runtime,
        run_id,
        descriptor,
        true,
        true,
        true,
        true,
        retained_gate,
        0,
    );
    poweroff(ExitCode::Success)
}

/// Replay resumes from core projections only.  A persisted descriptor is
/// re-fetched and re-verified through `acknowledge_source`; COM3 carries no
/// recovery data and there is no guest side log.
fn run_recovery(
    mut boot: QemuPersistentBoot,
    source: ToolOperationPlan,
    source_runtime: ToolDmaRuntime,
    _identity: ExperimentIdentity,
) -> ! {
    let run_id = source.run_id();
    let projection = boot
        .observe(|engine| engine.composite_effect(source.effect()))
        .expect("CSER_HANDOFF_FAIL stage=recovery-parent-projection");
    let (persisted_descriptor, parent_says_child_installed) = match projection.handoff {
        SingleHopHandoffProjection::Source {
            descriptor,
            child_installed,
            ..
        } => (Some(*descriptor), child_installed),
        SingleHopHandoffProjection::None => (None, false),
        SingleHopHandoffProjection::Target { .. } => {
            panic!("CSER_HANDOFF_FAIL stage=recovery-parent-role")
        }
    };
    let source_observation = get_terminal(source_runtime)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=recovery-source-get error={e:?}"));
    // Re-verification is required before using the recovered descriptor.  If
    // the parent commit is still outstanding this call consumes it; otherwise
    // it validates that the recovered descriptor still matches the endpoint.
    let parent_component = boot
        .observe(|engine| engine.component(source.effect(), TOOL_HANDOFF_SOURCE_COMPONENT))
        .expect("CSER_HANDOFF_FAIL stage=recovery-source-component");
    let descriptor = if matches!(
        parent_component.commit,
        cser_core::CommitState::CommitIntentDurable
    ) {
        let intent = boot
            .observe(|engine| engine.outstanding_component_commit_intents(source.effect()))
            .expect("CSER_HANDOFF_FAIL stage=recovery-source-intents")
            .into_iter()
            .find(|intent| intent.component() == TOOL_HANDOFF_SOURCE_COMPONENT)
            .expect("CSER_HANDOFF_FAIL stage=recovery-source-intent");
        let (command, recovered) = boot
            .observe(|engine| {
                source_runtime.acknowledge_handoff_parent_success(
                    engine,
                    intent,
                    &source_observation,
                )
            })
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=recovery-source-ack-verify"));
        expect_none("recovery-source-ack", boot.recovery_transact(command));
        if let Some(persisted) = persisted_descriptor {
            assert_eq!(
                recovered, persisted,
                "CSER_HANDOFF_FAIL stage=recovery-descriptor-mismatch"
            );
        }
        recovered
    } else if persisted_descriptor.is_none()
        && parent_component.commit == cser_core::CommitState::Committed
        && parent_component.commit_operation == Some(source.operation_digest())
        && parent_component.outcome
            == cser_core::OutcomeState::Indeterminate(source.operation_digest())
    {
        // CheckpointRecovery deliberately destroyed the crashed executor's
        // nonce and fenced the parent.  This dedicated resolution proves the
        // same terminal success and descriptor without recreating that nonce,
        // activating the operation, creating the child, or releasing any claim.
        let (command, recovered) = boot
            .observe(|engine| {
                source_runtime
                    .resolve_indeterminate_handoff_parent_success(engine, &source_observation)
            })
            .unwrap_or_else(|_| {
                panic!("CSER_HANDOFF_FAIL stage=recovery-source-indeterminate-verify")
            });
        expect_none(
            "recovery-source-resolution",
            boot.recovery_transact(command),
        );
        recovered
    } else {
        // This call validates descriptor binding against the fresh terminal
        // record without authorizing a duplicate core transition.
        let verifier = super::core_tool_adapter::ToolChildDescriptorVerifier::new(source)
            .expect("CSER_HANDOFF_FAIL stage=recovery-descriptor-verifier");
        let decoded = verifier
            .decode(source_observation)
            .expect("CSER_HANDOFF_FAIL stage=recovery-descriptor-decode");
        let descriptor =
            persisted_descriptor.expect("CSER_HANDOFF_FAIL stage=recovery-no-handoff-descriptor");
        assert_eq!(
            decoded, descriptor,
            "CSER_HANDOFF_FAIL stage=recovery-descriptor-reverify"
        );
        descriptor
    };
    // cut25 may have a durable child endpoint success while checkpoint fencing
    // consumed its nonce. Resolve it while the root is still fenced, before
    // rebind can make any settlement authority available.
    let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
        .expect("CSER_HANDOFF_FAIL stage=recovery-child-plan-before-rebind");
    let fenced_child =
        boot.observe(|engine| engine.component(child.effect(), TOOL_HANDOFF_COMPONENT));
    let mut resolved_child_observation = None;
    if matches!(fenced_child, Some(component) if component.commit == cser_core::CommitState::Committed
        && component.commit_operation == Some(child.operation_digest())
        && component.outcome == cser_core::OutcomeState::Indeterminate(child.operation_digest()))
    {
        let child_runtime = ToolDmaRuntime::new(child, 1).expect("handoff child verifier");
        // The durable child intent exists, but cut24 deliberately precedes
        // its first POST.  GET is still mandatory; only its exact Absent/404
        // result may authorize this immutable same-key POST while the root
        // remains fenced. Every other transport/endpoint result fails closed.
        let child_observation =
            get_or_post_child_after_absent(child_runtime, true).unwrap_or_else(|e| {
                panic!("CSER_HANDOFF_FAIL stage=recovery-child-resolution-get error={e:?}")
            });
        let command = boot.observe(|engine| {
            child_runtime.resolve_indeterminate_handoff_child_success(
                engine,
                source_runtime,
                descriptor,
                &source_observation,
                &child_observation,
            )
        });
        let command = command.unwrap_or_else(|e| {
            panic!("CSER_HANDOFF_FAIL stage=recovery-child-indeterminate-verify error={e:?}")
        });
        expect_none("recovery-child-resolution", boot.recovery_transact(command));
        resolved_child_observation = Some(child_observation);
    }
    let successor = rebind_handoff_root(&mut boot, source.effect().operation());
    let activated = boot
        .try_activate()
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=recovery-activate"));
    let (engine, persistence, _devices) = activated.into_parts();
    let mut runtime = OstdCserRuntime::from_engine(engine, persistence);
    let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
        .expect("CSER_HANDOFF_FAIL stage=recovery-child-plan");
    let child_component =
        runtime.observe(|engine| engine.component(child.effect(), TOOL_HANDOFF_COMPONENT));
    assert_eq!(
        parent_says_child_installed,
        child_component.is_some(),
        "CSER_HANDOFF_FAIL stage=recovery-child-install-projection"
    );
    if child_component.is_none() {
        let installed = install_child(
            &mut runtime,
            source_runtime,
            &source_observation,
            successor,
            nz(SOURCE_CHARGE + 1),
        )
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=recovery-child-install error={e:?}"));
        assert_eq!(
            installed, descriptor,
            "CSER_HANDOFF_FAIL stage=recovery-child-descriptor"
        );
    }
    let source_component = runtime
        .observe(|engine| engine.component(source.effect(), TOOL_HANDOFF_SOURCE_COMPONENT))
        .expect("CSER_HANDOFF_FAIL stage=recovery-source-component-after-rebind");
    match source_component.retirement {
        cser_core::RetirementState::Retired => {}
        cser_core::RetirementState::Released => {
            let parent = runtime
                .observe(|engine| engine.composite_effect(source.effect()))
                .expect("CSER_HANDOFF_FAIL stage=recovery-released-source-parent");
            assert!(
                parent.authority == cser_core::AuthorityState::Revoked
                    && parent.custodian == cser_core::CustodyState::Released
                    && parent.escape == cser_core::EffectEscapeState::Released,
                "CSER_HANDOFF_FAIL stage=recovery-released-source-state"
            );
        }
        _ => settle_and_retire(
            &mut runtime,
            source.effect(),
            TOOL_HANDOFF_SOURCE_COMPONENT,
            successor,
            source_runtime,
            &source_observation,
        )
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=recovery-source-retire error={e:?}")),
    }
    let mut component = runtime
        .observe(|engine| engine.component(child.effect(), TOOL_HANDOFF_COMPONENT))
        .expect("CSER_HANDOFF_FAIL stage=recovery-child-component");
    if matches!(component.commit, cser_core::CommitState::Prepared) {
        let target = runtime
            .observe(|engine| engine.composite_effect(child.effect()))
            .expect("CSER_HANDOFF_FAIL stage=recovery-child-target");
        assert!(
            matches!(
                target.handoff,
                SingleHopHandoffProjection::Target { parent, .. } if parent == source.effect()
            ) && component.outcome == cser_core::OutcomeState::Pending
                && component.settlement == cser_core::SettlementState::Unavailable,
            "CSER_HANDOFF_FAIL stage=recovery-child-target-phase"
        );
        match (target.authority, target.custodian) {
            // A child installed on the prior boot was fenced with its operation
            // and its live logical claim is therefore RetirementPending until
            // AdoptEffect restores active custody, at which point rebase
            // refreshes the precommit claim to Held.
            (cser_core::AuthorityState::Fenced, cser_core::CustodyState::CoreOwned) => {
                assert_eq!(
                    component.retirement,
                    cser_core::RetirementState::RetirementPending,
                    "CSER_HANDOFF_FAIL stage=recovery-fenced-child-retirement"
                );
                expect_none(
                    "recovery-child-adopt",
                    runtime.transact(cser_core::CommandRequest::AdoptEffect {
                        effect: child.effect(),
                        successor,
                    }),
                );
                expect_none(
                    "recovery-child-rebase",
                    runtime.transact(cser_core::CommandRequest::RebaseCompositePrecommitClaims {
                        effect: child.effect(),
                        actor: successor,
                    }),
                );
            }
            // This recovery just installed the missing child under the
            // rebound successor. Re-adopting it would be a stale transition.
            (cser_core::AuthorityState::Active, cser_core::CustodyState::Executor(actor))
                if actor == successor =>
            {
                assert_eq!(
                    component.retirement,
                    cser_core::RetirementState::Held,
                    "CSER_HANDOFF_FAIL stage=recovery-new-child-retirement"
                );
            }
            _ => panic!("CSER_HANDOFF_FAIL stage=recovery-child-custody-phase"),
        }
        let intent = release_source_and_record_child_intent(
            &mut runtime,
            source_runtime,
            &source_observation,
            child,
            successor,
        )
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=recovery-handoff-commit error={e:?}"));
        assert_eq!(intent.effect(), child.effect());
        component = runtime
            .observe(|engine| engine.component(child.effect(), TOOL_HANDOFF_COMPONENT))
            .expect("CSER_HANDOFF_FAIL stage=recovery-child-component-after-intent");
    }
    let child_runtime = ToolDmaRuntime::new(child, 1).expect("handoff child verifier");
    let terminal = runtime.observe(|engine| {
        let parent = engine
            .composite_effect(source.effect())
            .expect("CSER_HANDOFF_FAIL stage=recovery-terminal-parent");
        parent.authority == cser_core::AuthorityState::Revoked
            && parent.custodian == cser_core::CustodyState::Released
            && parent.escape == cser_core::EffectEscapeState::Released
            && component.commit == cser_core::CommitState::Committed
            && matches!(component.outcome, cser_core::OutcomeState::KnownSuccess(_))
            && component.settlement == cser_core::SettlementState::Settled
            && matches!(
                component.retirement,
                cser_core::RetirementState::Retired | cser_core::RetirementState::Released
            )
            && component.retained_claims == 0
    });
    if terminal {
        // A terminal replay only cross-checks both endpoint records; it never
        // reconstructs a settlement authority or reissues a child action.
        let _ = get_terminal(child_runtime).unwrap_or_else(|e| {
            panic!("CSER_HANDOFF_FAIL stage=recovery-terminal-child-get error={e:?}")
        });
        let retained_gate = RejectedGate::not_observed();
        emit_terminal(
            &runtime,
            run_id,
            descriptor,
            true,
            true,
            true,
            true,
            retained_gate,
            1,
        );
        poweroff(ExitCode::Success)
    }
    let retained_gate = rejected_gate(&runtime, descriptor);
    // Boot fencing conservatively turns a durable child intent into a
    // committed/indeterminate component. The exact operation digest remains
    // durable, so a checksum-bound GET/404 may still authorize the same-key
    // POST. No other committed or prepared state receives retry authority.
    let child_operation = child.operation_digest();
    let post_authorized = matches!(
        component.commit,
        cser_core::CommitState::CommitIntentDurable
    ) || (component.commit == cser_core::CommitState::Committed
        && component.commit_operation == Some(child_operation)
        && matches!(
            component.outcome,
            cser_core::OutcomeState::Indeterminate(reason) if reason == child_operation
        ));
    let child_observation = resolved_child_observation.unwrap_or_else(|| {
        get_or_post_child_after_absent(child_runtime, post_authorized).unwrap_or_else(|e| {
            panic!("CSER_HANDOFF_FAIL stage=recovery-child-observation error={e:?}")
        })
    });
    if matches!(
        component.commit,
        cser_core::CommitState::CommitIntentDurable
    ) {
        let intent = runtime
            .observe(|engine| engine.outstanding_component_commit_intents(child.effect()))
            .expect("CSER_HANDOFF_FAIL stage=recovery-child-intents")
            .into_iter()
            .find(|intent| intent.component() == TOOL_HANDOFF_COMPONENT)
            .expect("CSER_HANDOFF_FAIL stage=recovery-child-intent");
        let command = runtime
            .observe(|engine| child_runtime.acknowledge_commit(engine, intent, &child_observation))
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=recovery-child-ack"));
        expect_none("recovery-child-ack", runtime.transact(command));
    }
    settle_and_retire(
        &mut runtime,
        child.effect(),
        TOOL_HANDOFF_COMPONENT,
        successor,
        child_runtime,
        &child_observation,
    )
    .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=recovery-child-retire error={e:?}"));
    emit_terminal(
        &runtime,
        run_id,
        descriptor,
        true,
        true,
        true,
        true,
        retained_gate,
        1,
    );
    poweroff(ExitCode::Success)
}

fn source_plan(
    effect: EffectId,
    run_id: [u8; 16],
    identity: ExperimentIdentity,
) -> ToolOperationPlan {
    let payload = handoff_source_payload(effect);
    ToolOperationPlan::handoff_source(
        run_id,
        effect,
        nz(SOURCE_CLAIM),
        nz(SOURCE_RESOURCE),
        nz(1),
        tool_dma_catalog().digest(),
        &payload,
    )
    .expect("fixed source plan")
    .bind_cser3(
        ToolV2Identity::new(
            identity.namespace(),
            ToolRunId::new(identity.authority_id().bytes()),
            ToolRunId::new(identity.effect_id().bytes()),
            identity.catalog_digest(),
        )
        .expect("CSER3 identity"),
    )
}

/// Matches the provider's fixed descriptor-discovery input exactly. This is a
/// stack-only canonical encoding, so no diagnostic allocator state becomes a
/// part of the source operation identity.
fn handoff_source_payload(effect: EffectId) -> [u8; 60] {
    const PREFIX: &[u8; 18] = b"discover-child-v1:";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut payload = [0_u8; 60];
    payload[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut at = PREFIX.len();
    for value in [effect.operation().get(), effect.sequence()] {
        for shift in (0..16).rev() {
            payload[at] = HEX[((value >> (shift * 4)) & 0x0f) as usize];
            at += 1;
        }
        if at == 34 || at == 51 {
            payload[at] = b':';
            at += 1;
        }
    }
    let component = TOOL_HANDOFF_SOURCE_COMPONENT.get();
    for shift in (0..8).rev() {
        payload[at] = HEX[((component >> (shift * 4)) & 0x0f) as usize];
        at += 1;
    }
    debug_assert_eq!(at, payload.len());
    payload
}

fn source_coordinates(effect: EffectId) -> HandoffSourceCoordinates {
    HandoffSourceCoordinates {
        effect,
        actor: fixed_actor(1),
        charge_account: nz(SOURCE_CHARGE),
        claim: nz(SOURCE_CLAIM),
        resource: nz(SOURCE_RESOURCE),
        resource_generation: nz(1),
    }
}

/// Recovery fencing is core authority, not a COM3 protocol.  The same operation
/// owns both fixed parent and descriptor-derived child, so one snapshot/ready
/// /rebind establishes the successor before it settles either component.
fn rebind_handoff_root(
    boot: &mut QemuPersistentBoot,
    operation: OperationId,
) -> ExecutorCoordinate {
    let cser_core::OperationRecoveryState::Fenced {
        crashed,
        crash_generation,
    } = boot
        .observe(|engine| engine.operation(operation))
        .expect("CSER_HANDOFF_FAIL stage=recovery-root")
    else {
        panic!("CSER_HANDOFF_FAIL stage=recovery-root-not-fenced")
    };
    let successor_generation = crashed
        .generation()
        .get()
        .checked_add(1)
        .and_then(|value| ExecutorGeneration::new(value).ok())
        .unwrap_or_else(|| panic!("CSER_HANDOFF_FAIL stage=recovery-successor-overflow"));
    let successor = ExecutorCoordinate::new(crashed.executor(), successor_generation);
    let snapshot = cser_core::SnapshotId::new(crash_generation)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=recovery-snapshot-invalid"));
    let command = boot
        .observe(|engine| engine.snapshot_operation(operation, snapshot))
        .expect("CSER_HANDOFF_FAIL stage=recovery-snapshot-build")
        .record();
    expect_none("recovery-root-snapshot", boot.recovery_transact(command));
    expect_none(
        "recovery-root-ready",
        boot.recovery_transact(cser_core::CommandRequest::Ready {
            operation,
            snapshot,
            successor,
        }),
    );
    expect_none(
        "recovery-root-rebind",
        boot.recovery_transact(cser_core::CommandRequest::Rebind {
            operation,
            snapshot,
            successor,
        }),
    );
    successor
}

fn get_terminal(tool: ToolDmaRuntime) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=com2-get");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    poll_terminal_on_endpoint(tool, &mut endpoint)
}

/// A fresh source operation is still queried before its first POST.  Only the
/// endpoint's checksum-bound exact-key 404 authorizes the same durable plan to
/// be submitted; every other nonterminal or tombstone remains fail-closed.
fn get_or_post_source(tool: ToolDmaRuntime) -> Result<DurableToolObservation, ToolTransportError> {
    match get_terminal(tool) {
        Ok(observation) => Ok(observation),
        Err(ToolTransportError::NoTerminalRecord { status: 404 }) => post_then_poll(tool),
        Err(error) => Err(error),
    }
}

fn poll_terminal_on_endpoint(
    tool: ToolDmaRuntime,
    endpoint: &mut UartToolEndpoint<'_>,
) -> Result<DurableToolObservation, ToolTransportError> {
    for attempt in 0..MAX_GET_POLLS {
        match tool.recover(endpoint)? {
            ToolEndpointObservation::Terminal(value) => return Ok(value),
            ToolEndpointObservation::Nonterminal(_) if attempt + 1 < MAX_GET_POLLS => {
                Task::yield_now()
            }
            ToolEndpointObservation::Absent => {
                return Err(ToolTransportError::NoTerminalRecord { status: 404 });
            }
            ToolEndpointObservation::Expired => {
                return Err(ToolTransportError::NoTerminalRecord { status: 410 });
            }
            ToolEndpointObservation::Nonterminal(_) => {
                return Err(ToolTransportError::NoTerminalRecord { status: 202 });
            }
        }
    }
    unreachable!()
}

fn post_then_poll(tool: ToolDmaRuntime) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=com2-post");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    match tool.submit(&mut endpoint)? {
        ToolEndpointObservation::Terminal(value) => Ok(value),
        ToolEndpointObservation::Nonterminal(_) => poll_terminal_on_endpoint(tool, &mut endpoint),
        ToolEndpointObservation::Absent => {
            Err(ToolTransportError::NoTerminalRecord { status: 404 })
        }
        ToolEndpointObservation::Expired => {
            Err(ToolTransportError::NoTerminalRecord { status: 410 })
        }
    }
}

/// The child has no authority for a blind first POST. It first GETs the exact
/// descriptor-derived operation and only an explicit `Absent` response may
/// authorize the durable intent's same-key POST.
fn get_or_post_child_after_absent(
    tool: ToolDmaRuntime,
    post_authorized: bool,
) -> Result<DurableToolObservation, ToolTransportError> {
    match get_terminal(tool) {
        Ok(observation) => Ok(observation),
        Err(ToolTransportError::NoTerminalRecord { status: 404 }) if post_authorized => {
            post_then_poll(tool)
        }
        Err(error) => Err(error),
    }
}

/// Initial child dispatch with an exactly-once barrier at the first endpoint
/// observation.  The normal helper cannot provide this cut because it polls
/// Accepted/Pending internally before returning a terminal observation.
fn initial_child_observation(
    tool: ToolDmaRuntime,
    barrier: impl FnOnce(),
) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=child-com2");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    match tool.recover(&mut endpoint)? {
        ToolEndpointObservation::Terminal(observation) => {
            barrier();
            Ok(observation)
        }
        ToolEndpointObservation::Absent => match tool.submit(&mut endpoint)? {
            ToolEndpointObservation::Terminal(observation) => {
                barrier();
                Ok(observation)
            }
            ToolEndpointObservation::Nonterminal(_) => {
                barrier();
                poll_terminal_on_endpoint(tool, &mut endpoint)
            }
            ToolEndpointObservation::Absent => {
                barrier();
                Err(ToolTransportError::NoTerminalRecord { status: 404 })
            }
            ToolEndpointObservation::Expired => {
                barrier();
                Err(ToolTransportError::NoTerminalRecord { status: 410 })
            }
        },
        ToolEndpointObservation::Nonterminal(_) => {
            barrier();
            poll_terminal_on_endpoint(tool, &mut endpoint)
        }
        ToolEndpointObservation::Expired => {
            barrier();
            Err(ToolTransportError::NoTerminalRecord { status: 410 })
        }
    }
}

#[derive(Clone, Copy)]
struct RejectedGate {
    observed: bool,
    rejected: Option<bool>,
    revision_unchanged: Option<bool>,
    head_unchanged: Option<bool>,
}

impl RejectedGate {
    const fn not_observed() -> Self {
        Self {
            observed: false,
            rejected: None,
            revision_unchanged: None,
            head_unchanged: None,
        }
    }
}

fn rejected_gate(
    runtime: &HandoffRuntime,
    descriptor: cser_core::ChildDescriptorV1,
) -> RejectedGate {
    let (revision, head) = runtime.observe(|engine| (engine.revision(), engine.head()));
    let rejected = runtime.observe(|engine| {
        engine
            .check_reusable(descriptor.resource, descriptor.resource_generation)
            .is_err()
    });
    let (after_revision, after_head) = runtime.observe(|engine| (engine.revision(), engine.head()));
    assert_eq!(
        revision, after_revision,
        "CSER_HANDOFF_FAIL stage=gate-reject-revision"
    );
    assert_eq!(head, after_head, "CSER_HANDOFF_FAIL stage=gate-reject-head");
    RejectedGate {
        observed: true,
        rejected: Some(rejected),
        revision_unchanged: Some(revision == after_revision),
        head_unchanged: Some(head == after_head),
    }
}

fn emit_terminal(
    runtime: &HandoffRuntime,
    run_id: [u8; 16],
    descriptor: cser_core::ChildDescriptorV1,
    parent_transferred: bool,
    child_installed: bool,
    child_intent: bool,
    child_terminal: bool,
    retained_gate: RejectedGate,
    recovery_steps: u64,
) {
    let admit = runtime.observe(|engine| {
        engine
            .check_reusable(descriptor.resource, descriptor.resource_generation)
            .is_ok()
    });
    println!(
        "CSER_HANDOFF_TERMINAL {{\"version\":1,\"variant\":\"cser\",\"run_id\":\"{}\",\"descriptor_digest\":\"{}\",\"parent_transferred\":{},\"child_installed\":{},\"child_intent\":{},\"child_terminal\":{},\"coordinate_gate\":{{\"live_gate_observed\":{},\"reject_while_live\":{},\"admit_after_terminal\":{},\"revision_unchanged\":{},\"head_unchanged\":{}}},\"recovery_steps\":{},\"scope\":\"logical\",\"device_actions\":0}}",
        Hex(run_id),
        HexDigest(descriptor_digest(descriptor)),
        parent_transferred,
        child_installed,
        child_intent,
        child_terminal,
        retained_gate.observed,
        nullable_bool(retained_gate.rejected),
        admit,
        nullable_bool(retained_gate.revision_unchanged),
        nullable_bool(retained_gate.head_unchanged),
        recovery_steps
    );
}

fn nullable_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn expect_none<E: core::fmt::Debug>(
    stage: &'static str,
    result: Result<cser_core::TransitionReceipt, cser_core::TxError<E>>,
) {
    let receipt =
        result.unwrap_or_else(|error| panic!("CSER_HANDOFF_FAIL stage={stage} error={error:?}"));
    assert!(matches!(
        receipt.into_output(),
        cser_core::TransitionOutput::None
    ));
}
fn acquire_identity(expected: cser_core::Digest) -> ExperimentIdentity {
    let mut probe = CrashProbe::acquire().expect("CSER_HANDOFF_FAIL stage=com3-identity");
    let identity = probe
        .experiment_identity()
        .expect("CSER_HANDOFF_FAIL stage=identity");
    assert_eq!(identity.catalog_digest(), expected.bytes());
    identity
}
struct HandoffBarriers {
    probe: CrashProbe,
    run_id: [u8; 16],
}
impl HandoffBarriers {
    fn acquire(run_id: [u8; 16]) -> Self {
        Self {
            probe: CrashProbe::acquire().expect("CSER_HANDOFF_FAIL stage=com3-barriers"),
            run_id,
        }
    }
    fn reached(&mut self, barrier: HandoffBarrier) {
        self.probe
            .barrier(
                CrashRunId::new(self.run_id),
                CrashCutpoint::new(u16::from(barrier.wire_id())),
            )
            .unwrap_or_else(|e: CrashProbeError| {
                panic!("CSER_HANDOFF_FAIL stage=barrier error={e:?}")
            });
    }
}
fn fixed_effect() -> EffectId {
    EffectId::new(nz::<OperationId>(EFFECT_ROOT), EFFECT_SEQUENCE).expect("handoff effect")
}
fn fixed_actor(generation: u64) -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        nz::<ExecutorId>(EFFECT_ROOT),
        nz::<ExecutorGeneration>(generation),
    )
}
trait NonZeroId: Sized {
    fn from_nonzero(value: u64) -> Self;
}
macro_rules! nonzero { ($($t:ty),+ $(,)?) => { $(impl NonZeroId for $t { fn from_nonzero(value: u64) -> Self { <$t>::new(value).expect("fixed nonzero handoff id") } })+ }; }
nonzero!(
    ChargeAccountId,
    ClaimId,
    ExecutorGeneration,
    ExecutorId,
    OperationId,
    ResourceGeneration,
    ResourceId,
);
fn nz<T: NonZeroId>(value: u64) -> T {
    T::from_nonzero(value)
}
struct Hex([u8; 16]);
impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
struct HexDigest(cser_core::Digest);
impl fmt::Display for HexDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
