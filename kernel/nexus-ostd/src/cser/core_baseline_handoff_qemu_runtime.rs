// SPDX-License-Identifier: MPL-2.0

//! Real-QEMU logical CSER3 handoff lane for the independent finalizer.
//!
//! This is intentionally a small, workload-specific coordinator.  Its only
//! durable authority is [`AtaTpmBaselineHandoffStore`]; it neither constructs
//! nor invokes CSER engine commands, verified descriptors, or reuse permits.

use core::fmt;

use cser_core::{
    ChildDescriptorV1, ClaimId, Digest, EffectId, OperationId, ResourceGeneration, ResourceId,
    TOOL_HANDOFF_SOURCE_COMPONENT, tool_dma_catalog,
};
use ostd::{
    power::{ExitCode, poweroff},
    prelude::println,
    task::Task,
};
use sha2::{Digest as _, Sha256};

use super::{
    core_baseline_handoff::{
        AtaTpmBaselineHandoffStore, ChildPostPermit, DurableHandoffRecord, HandoffClaimCoordinate,
        HandoffPhase,
    },
    core_crash_probe::{
        CrashCutpoint, CrashProbe, CrashProbeError, CrashRunId, ExperimentIdentity,
    },
    core_pio_journal::AtaJournalFixture,
    core_tool_adapter::{
        DurableToolObservation, ToolEndpoint, ToolEndpointObservation, ToolNonterminalState,
        ToolOperationPlan, ToolTransportError, UartToolEndpoint,
    },
    core_tool_uart::{ToolRunId, ToolUart, ToolV2Identity},
};

const EFFECT_ROOT: u64 = 0x4841_4e44;
const EFFECT_SEQUENCE: u64 = 1;
const SOURCE_CLAIM: u64 = 0x6501;
const SOURCE_RESOURCE: u64 = 0x6601;
const MAX_GET_POLLS: usize = 4;

pub(crate) fn run() {
    let identity = acquire_identity(tool_dma_catalog().digest());
    let source = source_plan(fixed_effect(), identity.run_id().bytes(), identity);
    let mut store =
        AtaTpmBaselineHandoffStore::acquire_qemu_fixture(AtaJournalFixture::PrimaryMaster)
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-store-open"));
    match store
        .load()
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-store-load"))
    {
        None => run_fresh(&mut store, source),
        Some(record) => run_recovery(&mut store, record),
    }
}

fn run_fresh(store: &mut AtaTpmBaselineHandoffStore, source: ToolOperationPlan) -> ! {
    let mut barriers = Barriers::acquire(source.run_id());
    let record = store
        .initialize_parent_intent(source)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-parent-intent"));
    let source_observation = get_or_post_source(source)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=baseline-source-post error={e:?}"));
    barriers.reached(21); // descriptor discovered, before it is adopted.
    let descriptor = decode_descriptor(source_observation);
    let record = store
        .persist(
            record
                .record_descriptor(descriptor.encode_wire().as_ref(), source_observation)
                .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-descriptor-record")),
        )
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-descriptor-persist"));
    barriers.reached(22); // optional: descriptor receipt is now anchored.
    let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
        .expect("CSER_HANDOFF_FAIL stage=baseline-child-plan");
    let record = store
        .persist(
            record
                .prepare_child(child)
                .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-child-prepare")),
        )
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-child-persist"));
    barriers.reached(23);
    let (record, permit) = store
        .release_parent_and_record_child_intent(record)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-handoff-release"));
    barriers.reached(24);
    finish_child(store, record, permit, Some(&mut barriers), 0)
}

/// Recovery first obtains and validates the source endpoint record.  Only then
/// may it complete an incomplete durable phase, so COM3 never substitutes for
/// descriptor or receipt evidence.
fn run_recovery(store: &mut AtaTpmBaselineHandoffStore, mut record: DurableHandoffRecord) -> ! {
    let source = record
        .source_plan()
        .expect("CSER_HANDOFF_FAIL stage=baseline-recovery-source-plan");
    let source_observation = recover_source_observation(record.phase, source).unwrap_or_else(|e| {
        panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-source-get error={e:?}")
    });
    let descriptor = decode_descriptor(source_observation);
    if record.phase == HandoffPhase::ParentIntentDurable {
        record = store
            .persist(
                record
                    .record_descriptor(descriptor.encode_wire().as_ref(), source_observation)
                    .unwrap_or_else(|_| {
                        panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-descriptor-record")
                    }),
            )
            .unwrap_or_else(|_| {
                panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-descriptor-persist")
            });
    } else {
        record
            .reverify_source_descriptor(descriptor.encode_wire().as_ref(), source_observation)
            .unwrap_or_else(|_| {
                panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-source-reverify")
            });
    }
    if record.phase == HandoffPhase::ChildTerminal {
        let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
            .expect("CSER_HANDOFF_FAIL stage=baseline-recovery-child-plan");
        let child_observation = get_terminal(child).unwrap_or_else(|e| {
            panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-child-get error={e:?}")
        });
        record
            .reverify_child_terminal(child_observation)
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-child-reverify"));
        emit_terminal(store, record, descriptor, None, 1);
        poweroff(ExitCode::Success)
    }
    let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor)
        .expect("CSER_HANDOFF_FAIL stage=baseline-recovery-child-plan-derive");
    if record.phase == HandoffPhase::DescriptorDurable {
        record = store
            .persist(record.prepare_child(child).unwrap_or_else(|_| {
                panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-child-prepare")
            }))
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-child-persist"));
    }
    let (record, permit) = if record.phase == HandoffPhase::ChildPrepared {
        store
            .release_parent_and_record_child_intent(record)
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-release"))
    } else {
        store
            .recover_child_post_permit()
            .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-recovery-permit"))
    };
    finish_child(store, record, permit, None, 1)
}

/// A parent intent has no durable source terminal fact, so only that phase may
/// create the exact source operation after an authoritative 404.  Once the
/// descriptor and source receipt are anchored, recovery is revalidation only:
/// a missing record is fail-closed and cannot replay the source action.
fn recover_source_observation(
    phase: HandoffPhase,
    source: ToolOperationPlan,
) -> Result<DurableToolObservation, ToolTransportError> {
    match phase {
        HandoffPhase::ParentIntentDurable => get_or_post_source(source),
        HandoffPhase::DescriptorDurable
        | HandoffPhase::ChildPrepared
        | HandoffPhase::ParentReleasedChildIntentDurable
        | HandoffPhase::ChildTerminal => get_terminal(source),
    }
}

fn finish_child(
    store: &mut AtaTpmBaselineHandoffStore,
    record: DurableHandoffRecord,
    permit: ChildPostPermit,
    barriers: Option<&mut Barriers>,
    recovery_steps: u64,
) -> ! {
    // The permit is consumed to obtain the exact durable plan before GET.  A
    // GET is still mandatory, and a POST follows only an exact 404 response.
    let child = permit
        .into_child_plan(&record)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-child-permit"));
    let descriptor = decode_descriptor_from_record(&record);
    assert!(
        store
            .check_reusable(HandoffClaimCoordinate {
                resource: descriptor.resource.get(),
                generation: descriptor.resource_generation.get(),
            })
            .is_err(),
        "CSER_HANDOFF_FAIL stage=baseline-live-coordinate-gate"
    );
    let child_observation = get_or_post_child(child, barriers)
        .unwrap_or_else(|e| panic!("CSER_HANDOFF_FAIL stage=baseline-child-observe error={e:?}"));
    let record = store
        .persist(
            record
                .record_child_terminal(child_observation)
                .unwrap_or_else(|_| {
                    panic!("CSER_HANDOFF_FAIL stage=baseline-child-terminal-record")
                }),
        )
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=baseline-child-terminal-persist"));
    emit_terminal(store, record, descriptor, Some(true), recovery_steps);
    poweroff(ExitCode::Success)
}

fn get_or_post_source(
    plan: ToolOperationPlan,
) -> Result<DurableToolObservation, ToolTransportError> {
    match get_terminal(plan) {
        Ok(value) => Ok(value),
        Err(ToolTransportError::NoTerminalRecord { status: 404 }) => post_then_poll(plan),
        Err(error) => Err(error),
    }
}

fn get_or_post_child(
    plan: ToolOperationPlan,
    mut barriers: Option<&mut Barriers>,
) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=baseline-child-com2");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    match endpoint.get(plan)? {
        ToolEndpointObservation::Terminal(value) => {
            // This GET observes a child that was posted before this boot. It
            // is still the first child evidence of this execution and must
            // have the same crash cut as a direct POST terminal.
            reach_optional(&mut barriers, 25);
            Ok(value)
        }
        ToolEndpointObservation::Absent => match endpoint.post(plan)? {
            ToolEndpointObservation::Terminal(value) => {
                // A synchronously completed POST is still the first external
                // child observation.  The crash cut must cover it just as it
                // covers Accepted/Pending before polling.
                reach_optional(&mut barriers, 25);
                Ok(value)
            }
            ToolEndpointObservation::Nonterminal(ToolNonterminalState::Accepted)
            | ToolEndpointObservation::Nonterminal(ToolNonterminalState::Pending) => {
                reach_optional(&mut barriers, 25);
                poll_terminal(&mut endpoint, plan)
            }
            ToolEndpointObservation::Absent => {
                Err(ToolTransportError::NoTerminalRecord { status: 404 })
            }
            ToolEndpointObservation::Expired => {
                Err(ToolTransportError::NoTerminalRecord { status: 410 })
            }
        },
        ToolEndpointObservation::Nonterminal(_) => {
            // A previous boot may have durably received Accepted/Pending and
            // crashed at barrier 25.  Recovery stays on the same UART session
            // and exact key until that existing operation becomes terminal;
            // it never turns a nonterminal GET into a second POST.
            reach_optional(&mut barriers, 25);
            poll_terminal(&mut endpoint, plan)
        }
        ToolEndpointObservation::Expired => {
            Err(ToolTransportError::NoTerminalRecord { status: 410 })
        }
    }
}

fn reach_optional(barriers: &mut Option<&mut Barriers>, id: u8) {
    if let Some(barriers) = barriers.as_deref_mut() {
        barriers.reached(id);
    }
}

fn post_then_poll(plan: ToolOperationPlan) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=baseline-post-com2");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    match endpoint.post(plan)? {
        ToolEndpointObservation::Terminal(value) => Ok(value),
        ToolEndpointObservation::Nonterminal(_) => poll_terminal(&mut endpoint, plan),
        ToolEndpointObservation::Absent => {
            Err(ToolTransportError::NoTerminalRecord { status: 404 })
        }
        ToolEndpointObservation::Expired => {
            Err(ToolTransportError::NoTerminalRecord { status: 410 })
        }
    }
}

fn get_terminal(plan: ToolOperationPlan) -> Result<DurableToolObservation, ToolTransportError> {
    let mut uart = ToolUart::acquire().expect("CSER_HANDOFF_FAIL stage=baseline-get-com2");
    let mut endpoint = UartToolEndpoint::new(&mut uart);
    poll_terminal(&mut endpoint, plan)
}

fn poll_terminal(
    endpoint: &mut UartToolEndpoint<'_>,
    plan: ToolOperationPlan,
) -> Result<DurableToolObservation, ToolTransportError> {
    for attempt in 0..MAX_GET_POLLS {
        match endpoint.get(plan)? {
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

fn decode_descriptor(observation: DurableToolObservation) -> ChildDescriptorV1 {
    ChildDescriptorV1::decode_wire(observation.terminal_output().bytes())
        .expect("CSER_HANDOFF_FAIL stage=baseline-descriptor-decode")
}

fn decode_descriptor_from_record(record: &DurableHandoffRecord) -> ChildDescriptorV1 {
    ChildDescriptorV1::decode_wire(
        record
            .descriptor
            .expect("terminal record has descriptor")
            .as_ref(),
    )
    .expect("CSER_HANDOFF_FAIL stage=baseline-record-descriptor-decode")
}

fn emit_terminal(
    store: &mut AtaTpmBaselineHandoffStore,
    record: DurableHandoffRecord,
    descriptor: ChildDescriptorV1,
    live_gate_rejected: Option<bool>,
    recovery_steps: u64,
) {
    let coordinate = HandoffClaimCoordinate {
        resource: descriptor.resource.get(),
        generation: descriptor.resource_generation.get(),
    };
    // A terminal-only reopen has no live gate observation to report.  A
    // resumed pre-terminal phase performs the exact retained-coordinate probe
    // immediately before its child observation.
    let admitted = store.check_reusable(coordinate).is_ok();
    let descriptor_digest: [u8; 32] = Sha256::digest(descriptor.encode_wire()).into();
    println!(
        "CSER_HANDOFF_TERMINAL {{\"version\":1,\"variant\":\"baseline\",\"run_id\":\"{}\",\"descriptor_digest\":\"{}\",\"parent_transferred\":true,\"child_installed\":true,\"child_intent\":true,\"child_terminal\":{},\"coordinate_gate\":{{\"live_gate_observed\":{},\"reject_while_live\":{},\"admit_after_terminal\":{},\"revision_unchanged\":null,\"head_unchanged\":null}},\"recovery_steps\":{},\"scope\":\"logical\",\"device_actions\":0}}",
        Hex(record.source.run_id),
        HexDigest(Digest::new(descriptor_digest)),
        record.phase == HandoffPhase::ChildTerminal,
        live_gate_rejected.is_some(),
        nullable_bool(live_gate_rejected),
        admitted,
        recovery_steps,
    );
}

fn nullable_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
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
        nz::<ClaimId>(SOURCE_CLAIM),
        nz::<ResourceId>(SOURCE_RESOURCE),
        nz::<ResourceGeneration>(1),
        tool_dma_catalog().digest(),
        &payload,
    )
    .expect("fixed baseline handoff source")
    .bind_cser3(
        ToolV2Identity::new(
            identity.namespace(),
            ToolRunId::new(identity.authority_id().bytes()),
            ToolRunId::new(identity.effect_id().bytes()),
            identity.catalog_digest(),
        )
        .expect("baseline CSER3 identity"),
    )
}

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
    for shift in (0..8).rev() {
        payload[at] = HEX[((TOOL_HANDOFF_SOURCE_COMPONENT.get() >> (shift * 4)) & 0x0f) as usize];
        at += 1;
    }
    debug_assert_eq!(at, payload.len());
    payload
}

fn acquire_identity(expected: Digest) -> ExperimentIdentity {
    let mut probe = CrashProbe::acquire().expect("CSER_HANDOFF_FAIL stage=baseline-com3-identity");
    let identity = probe
        .experiment_identity()
        .expect("CSER_HANDOFF_FAIL stage=baseline-identity");
    assert_eq!(identity.catalog_digest(), expected.bytes());
    identity
}

struct Barriers {
    probe: CrashProbe,
    run_id: [u8; 16],
}
impl Barriers {
    fn acquire(run_id: [u8; 16]) -> Self {
        Self {
            probe: CrashProbe::acquire().expect("CSER_HANDOFF_FAIL stage=baseline-com3"),
            run_id,
        }
    }
    fn reached(&mut self, id: u8) {
        self.probe
            .barrier(
                CrashRunId::new(self.run_id),
                CrashCutpoint::new(u16::from(id)),
            )
            .unwrap_or_else(|e: CrashProbeError| {
                panic!("CSER_HANDOFF_FAIL stage=baseline-barrier error={e:?}")
            });
    }
}

fn fixed_effect() -> EffectId {
    EffectId::new(nz::<OperationId>(EFFECT_ROOT), EFFECT_SEQUENCE).expect("baseline handoff effect")
}
trait NonZeroId: Sized {
    fn from_nonzero(value: u64) -> Self;
}
macro_rules! nonzero { ($($t:ty),+ $(,)?) => { $(impl NonZeroId for $t { fn from_nonzero(value: u64) -> Self { <$t>::new(value).expect("fixed nonzero baseline handoff id") } })+ }; }
nonzero!(ClaimId, OperationId, ResourceGeneration, ResourceId);
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
struct HexDigest(Digest);
impl fmt::Display for HexDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
