#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, AuthorityState, ClaimId,
    ClaimScope, Command as AuthorizedCommand, CommandRequest as Command, CommitState,
    ComponentCommitOperation, ComponentId, CoreError, CoreLimits, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_COMMIT_RECEIPT_SCHEMA,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE, DeviceScopeId, EffectId,
    Engine, EvidenceKindId, ExternalOutcome, Freshness, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_EVIDENCE_PUBLICATION_ACK,
    REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA, REPLY_VERIFIER, ReceiptBinding,
    RecoveryAnchor, ResourceId, SettlementState, TransitionOutput, standard_catalog,
};
use cser_model::EffectId as OracleEffectId;
use cser_model::composite_effect_oracle::{
    ClaimKind as OracleClaimKind, ClaimState as OracleClaimState, ComponentId as OracleComponentId,
    CompositeAuthority as OracleAuthority, CompositeEffectOracle, CompositeResources,
    DmaOutcome as OracleDmaOutcome, EscapeState as OracleEscape, ReplyState as OracleReplyState,
    ResourceId as OracleResourceId,
};
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, digest, effect, freshness, principal,
    resource, resource_generation, snapshot, verified_apply_completion, verified_commit_outcome,
    verified_settlement_ack,
};

const ROOT: u64 = 0xce07;
const ORACLE_EFFECT: OracleEffectId = OracleEffectId::new(0xce07_0001);
const DEVICE_SCOPE_RAW: u64 = 0xce07;
const FIRST_SNAPSHOT_RAW: u64 = 0x00ce_0701;
const SECOND_SNAPSHOT_RAW: u64 = 0x00ce_0702;
const PROBE_SNAPSHOT_RAW: u64 = 0x00ce_0703;

const REPLY_CLAIM_RAW: u64 = 1;
const QUEUE_CLAIM_RAW: u64 = 2;
const PAGE_CLAIM_RAW: u64 = 3;
const IOVA_CLAIM_RAW: u64 = 4;
const REUSE_QUEUE_CLAIM_RAW: u64 = 12;
const REUSE_PAGE_CLAIM_RAW: u64 = 13;
const REUSE_IOVA_CLAIM_RAW: u64 = 14;

const REPLY_RESOURCE_RAW: u64 = 0xce07_1001;
const QUEUE_RESOURCE_RAW: u64 = 0xce07_1002;
const PAGE_RESOURCE_RAW: u64 = 0xce07_1003;
const IOVA_RESOURCE_RAW: u64 = 0xce07_1004;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedAuthority {
    Active,
    Fenced,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedReply {
    Staged,
    Open(u64),
    Claimed { claimant: u64, generation: u64 },
    IntentDurable { claimant: u64, generation: u64 },
    Applied { claimant: u64, generation: u64 },
    Reconcile { generation: u64, applied: bool },
    Settled,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedClaimLifecycle {
    Absent,
    Retained,
    Discharged,
    ReservedNext,
    ActiveNext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedEscape {
    Unescaped,
    Escaped,
    PartiallyDischarged,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalizedClaim {
    resource: Option<u64>,
    old_generation: Option<u64>,
    high_water: Option<u64>,
    units: u64,
    old_tombstone: bool,
    lifecycle: NormalizedClaimLifecycle,
    permit: Option<NormalizedPermitOwner>,
}

impl NormalizedClaim {
    const ABSENT: Self = Self {
        resource: None,
        old_generation: None,
        high_water: None,
        units: 0,
        old_tombstone: false,
        lifecycle: NormalizedClaimLifecycle::Absent,
        permit: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalizedPermitOwner {
    actor: u64,
    binding_generation: u64,
    next_generation: u64,
    device_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalizedDmaClosure {
    device_generation: u64,
    reset: bool,
    irq_drained: bool,
    iotlb_invalidated: bool,
    allocator_released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalizedProjection {
    effect: (u64, u64),
    authority: NormalizedAuthority,
    authority_epoch: u64,
    reply_committed: bool,
    dma_committed: bool,
    reply: NormalizedReply,
    dma: NormalizedDmaClosure,
    claims: [NormalizedClaim; 4],
    escape: NormalizedEscape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReuseStage {
    None,
    Reserved,
    Active,
}

#[derive(Clone, Copy, Debug)]
struct DifferentialContext {
    registered: [bool; 4],
    reuse: [ReuseStage; 3],
    permit: [Option<NormalizedPermitOwner>; 3],
    target: Option<EffectId>,
}

impl DifferentialContext {
    const fn new() -> Self {
        Self {
            registered: [false; 4],
            reuse: [ReuseStage::None; 3],
            permit: [None; 3],
            target: None,
        }
    }
}

#[derive(Clone, Copy)]
struct ClaimCoordinates {
    oracle_kind: OracleClaimKind,
    original_claim: ClaimId,
    reuse_claim: Option<ClaimId>,
    resource: ResourceId,
}

fn claim_coordinates(index: usize) -> ClaimCoordinates {
    match index {
        0 => ClaimCoordinates {
            oracle_kind: OracleClaimKind::ReplyOutput,
            original_claim: claim(REPLY_CLAIM_RAW),
            reuse_claim: None,
            resource: resource(REPLY_RESOURCE_RAW),
        },
        1 => ClaimCoordinates {
            oracle_kind: OracleClaimKind::QueueSlot,
            original_claim: claim(QUEUE_CLAIM_RAW),
            reuse_claim: Some(claim(REUSE_QUEUE_CLAIM_RAW)),
            resource: resource(QUEUE_RESOURCE_RAW),
        },
        2 => ClaimCoordinates {
            oracle_kind: OracleClaimKind::PinnedPage,
            original_claim: claim(PAGE_CLAIM_RAW),
            reuse_claim: Some(claim(REUSE_PAGE_CLAIM_RAW)),
            resource: resource(PAGE_RESOURCE_RAW),
        },
        3 => ClaimCoordinates {
            oracle_kind: OracleClaimKind::IovaMapping,
            original_claim: claim(IOVA_CLAIM_RAW),
            reuse_claim: Some(claim(REUSE_IOVA_CLAIM_RAW)),
            resource: resource(IOVA_RESOURCE_RAW),
        },
        _ => unreachable!("the frozen composite profile has four claims"),
    }
}

fn reuse_index(claim_index: usize) -> Option<usize> {
    claim_index.checked_sub(1)
}

fn device_scope() -> DeviceScopeId {
    DeviceScopeId::new(DEVICE_SCOPE_RAW).unwrap()
}

fn oracle_resources() -> CompositeResources {
    CompositeResources {
        reply_output: OracleResourceId::new(REPLY_RESOURCE_RAW),
        queue_slot: OracleResourceId::new(QUEUE_RESOURCE_RAW),
        pinned_page: OracleResourceId::new(PAGE_RESOURCE_RAW),
        iova_mapping: OracleResourceId::new(IOVA_RESOURCE_RAW),
    }
}

fn next_device_freshness(current: Freshness) -> Freshness {
    freshness(
        current.boot().get(),
        current.registry().get(),
        current.binding(),
        current.device().get() + 1,
        current.journal().get(),
    )
}

#[allow(clippy::too_many_arguments)]
fn component_evidence_command(
    harness: &Harness,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    kind: EvidenceKindId,
    observation: Freshness,
    marker: u8,
) -> AuthorizedCommand {
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, component, claim, kind)
        .unwrap();
    let binding = if component == AGENT_COMPONENT_REPLY {
        ReceiptBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA)
    } else {
        ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA)
    };
    let verifier = ExactTestVerifier::new(binding.verifier(), binding.receipt_schema());
    let receipt = TestReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation,
        digest: digest(marker),
    };
    harness
        .engine
        .verify_component_retirement_evidence(effect, component, claim, kind, &verifier, &receipt)
        .unwrap()
        .submit()
}

fn current_component_evidence_command(
    harness: &Harness,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    kind: EvidenceKindId,
    marker: u8,
) -> AuthorizedCommand {
    let observation = harness
        .engine
        .component_evidence_challenge(effect, component, claim, kind)
        .unwrap()
        .current_observation();
    component_evidence_command(harness, effect, component, claim, kind, observation, marker)
}

fn reset_component_command(
    harness: &Harness,
    effect: EffectId,
    claim: ClaimId,
    marker: u8,
) -> AuthorizedCommand {
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, AGENT_COMPONENT_DMA, claim, DEVICE_EVIDENCE_RESET)
        .unwrap();
    let current = challenge.current_observation();
    let observation = if current.device() == challenge.subject().device() {
        next_device_freshness(current)
    } else {
        current
    };
    component_evidence_command(
        harness,
        effect,
        AGENT_COMPONENT_DMA,
        claim,
        DEVICE_EVIDENCE_RESET,
        observation,
        marker,
    )
}

fn core_authority(authority: AuthorityState) -> NormalizedAuthority {
    match authority {
        AuthorityState::Active => NormalizedAuthority::Active,
        AuthorityState::Fenced => NormalizedAuthority::Fenced,
        AuthorityState::Revoked => NormalizedAuthority::Revoked,
    }
}

fn oracle_authority(authority: OracleAuthority) -> NormalizedAuthority {
    match authority {
        OracleAuthority::Active => NormalizedAuthority::Active,
        OracleAuthority::Fenced => NormalizedAuthority::Fenced,
        OracleAuthority::Revoked => NormalizedAuthority::Revoked,
    }
}

fn core_reply(committed: bool, settlement: SettlementState) -> NormalizedReply {
    if !committed {
        return NormalizedReply::Staged;
    }
    match settlement {
        SettlementState::Unavailable => NormalizedReply::Open(1),
        SettlementState::Open { generation } => NormalizedReply::Open(generation),
        SettlementState::Claimed {
            claimant,
            generation,
        } => NormalizedReply::Claimed {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => NormalizedReply::IntentDurable {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => NormalizedReply::Applied {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => NormalizedReply::Reconcile {
            generation,
            applied,
        },
        SettlementState::Settled => NormalizedReply::Settled,
        SettlementState::Revoked => NormalizedReply::Tombstoned,
        SettlementState::NotRequired => unreachable!("reply settlement is successor-owned"),
    }
}

fn oracle_reply(reply: OracleReplyState) -> NormalizedReply {
    match reply {
        OracleReplyState::Staged => NormalizedReply::Staged,
        OracleReplyState::Open { generation } => NormalizedReply::Open(generation),
        OracleReplyState::Claimed {
            claimant,
            generation,
        } => NormalizedReply::Claimed {
            claimant,
            generation,
        },
        OracleReplyState::ApplyIntentDurable {
            claimant,
            generation,
        } => NormalizedReply::IntentDurable {
            claimant,
            generation,
        },
        OracleReplyState::AppliedUnacknowledged {
            claimant,
            generation,
        } => NormalizedReply::Applied {
            claimant,
            generation,
        },
        OracleReplyState::ReconciliationRequired {
            generation,
            applied,
        } => NormalizedReply::Reconcile {
            generation,
            applied,
        },
        OracleReplyState::Settled => NormalizedReply::Settled,
        OracleReplyState::Tombstoned | OracleReplyState::Aborted => NormalizedReply::Tombstoned,
    }
}

fn normalized_escape(
    reply_committed: bool,
    dma_committed: bool,
    reply: NormalizedReply,
    claims: &[NormalizedClaim; 4],
) -> NormalizedEscape {
    if !reply_committed && !dma_committed {
        return NormalizedEscape::Unescaped;
    }
    let reply_terminal = matches!(
        reply,
        NormalizedReply::Settled | NormalizedReply::Tombstoned
    );
    if reply_terminal && claims.iter().all(|claim| claim.old_tombstone) {
        return NormalizedEscape::Retired;
    }
    if reply_terminal || claims.iter().any(|claim| claim.old_tombstone) {
        NormalizedEscape::PartiallyDischarged
    } else {
        NormalizedEscape::Escaped
    }
}

fn core_claim(
    engine: &Engine,
    original: EffectId,
    context: DifferentialContext,
    index: usize,
) -> NormalizedClaim {
    if !context.registered[index] {
        return NormalizedClaim::ABSENT;
    }
    let coordinates = claim_coordinates(index);
    let component = if index == 0 {
        AGENT_COMPONENT_REPLY
    } else {
        AGENT_COMPONENT_DMA
    };
    let original_claim = engine
        .component_claims(original, component)
        .unwrap()
        .into_iter()
        .find(|projection| projection.claim == coordinates.original_claim)
        .expect("the original component claim remains projected as a tombstone");
    assert_eq!(original_claim.resource, coordinates.resource);
    assert_eq!(original_claim.resource_generation, resource_generation(1));
    assert_eq!(original_claim.units, 1);

    let stage = reuse_index(index)
        .map(|reuse| context.reuse[reuse])
        .unwrap_or(ReuseStage::None);
    let lifecycle = if !original_claim.retired {
        assert_eq!(stage, ReuseStage::None);
        NormalizedClaimLifecycle::Retained
    } else {
        match stage {
            ReuseStage::None => NormalizedClaimLifecycle::Discharged,
            ReuseStage::Reserved => NormalizedClaimLifecycle::ReservedNext,
            ReuseStage::Active => NormalizedClaimLifecycle::ActiveNext,
        }
    };
    let high_water = match stage {
        ReuseStage::None => {
            if let Some(reuse) = reuse_index(index) {
                assert_eq!(context.permit[reuse], None);
            }
            1
        }
        ReuseStage::Reserved | ReuseStage::Active => {
            let reuse = reuse_index(index).unwrap();
            assert_eq!(
                context.permit[reuse].is_some(),
                stage == ReuseStage::Reserved,
                "only an unconsumed reservation has a live bearer"
            );
            let target = context.target.expect("reuse has one explicit lease effect");
            assert_eq!(target.root(), original.root());
            assert_eq!(target.sequence(), original.sequence() + 1);
            let target_projection = engine.composite_effect(target).unwrap();
            assert_eq!(target_projection.kind, DMA_ARENA_REUSE_COMPOSITE);
            assert_eq!(target_projection.component_count, 1);
            let next = engine
                .component_claims(target, AGENT_COMPONENT_DMA)
                .unwrap()
                .into_iter()
                .find(|projection| projection.claim == coordinates.reuse_claim.unwrap())
                .expect("the generation+1 lease claim remains projected");
            assert_eq!(next.resource, coordinates.resource);
            assert_eq!(next.resource_generation, resource_generation(2));
            assert!(!next.retired);
            2
        }
    };

    NormalizedClaim {
        resource: Some(coordinates.resource.get()),
        old_generation: Some(1),
        high_water: Some(high_water),
        units: original_claim.units,
        old_tombstone: original_claim.retired,
        lifecycle,
        permit: reuse_index(index).and_then(|reuse| context.permit[reuse]),
    }
}

fn oracle_claim(
    oracle: &CompositeEffectOracle,
    context: DifferentialContext,
    index: usize,
) -> NormalizedClaim {
    if !context.registered[index] {
        return NormalizedClaim::ABSENT;
    }
    let coordinates = claim_coordinates(index);
    let projection = oracle.claim(coordinates.oracle_kind);
    assert_eq!(
        projection.resource,
        OracleResourceId::new(coordinates.resource.get())
    );
    assert_eq!(projection.enrolled_generation, 1);
    let (lifecycle, old_tombstone, high_water) = match projection.state {
        OracleClaimState::Staged | OracleClaimState::Live => {
            (NormalizedClaimLifecycle::Retained, false, 1)
        }
        OracleClaimState::Discharged => (NormalizedClaimLifecycle::Discharged, true, 1),
        OracleClaimState::ReusePermitted { next_generation } => {
            assert_eq!(next_generation, 2);
            (NormalizedClaimLifecycle::ReservedNext, true, 2)
        }
        OracleClaimState::Reused { generation } => {
            assert_eq!(generation, 2);
            (NormalizedClaimLifecycle::ActiveNext, true, 2)
        }
    };
    NormalizedClaim {
        resource: Some(coordinates.resource.get()),
        old_generation: Some(projection.enrolled_generation),
        high_water: Some(high_water),
        units: 1,
        old_tombstone,
        lifecycle,
        permit: projection
            .pending_reuse
            .map(|pending| NormalizedPermitOwner {
                actor: pending.actor,
                binding_generation: pending.binding_generation,
                next_generation: pending.next_generation,
                device_generation: pending.device_generation,
            }),
    }
}

fn normalize_core(
    engine: &Engine,
    original: EffectId,
    context: DifferentialContext,
) -> NormalizedProjection {
    let parent = engine.composite_effect(original).unwrap();
    let reply_component = engine.component(original, AGENT_COMPONENT_REPLY).unwrap();
    let dma_component = engine.component(original, AGENT_COMPONENT_DMA).unwrap();
    let reply_committed = reply_component.commit == CommitState::Committed;
    let dma_committed = dma_component.commit == CommitState::Committed;
    let claims = core::array::from_fn(|index| core_claim(engine, original, context, index));
    let reply = core_reply(reply_committed, reply_component.settlement);
    let evidence = |claim_id, kind| {
        engine
            .component_retirement_evidence_accepted(original, AGENT_COMPONENT_DMA, claim_id, kind)
            .unwrap_or(false)
    };
    let dma = NormalizedDmaClosure {
        device_generation: engine
            .device_generation(device_scope())
            .map_or(1, |generation| generation.get()),
        reset: evidence(claim(QUEUE_CLAIM_RAW), DEVICE_EVIDENCE_RESET),
        irq_drained: evidence(claim(QUEUE_CLAIM_RAW), DEVICE_EVIDENCE_IRQ_DRAINED),
        iotlb_invalidated: evidence(claim(IOVA_CLAIM_RAW), DEVICE_EVIDENCE_IOTLB),
        // The profile-2 core carries this as the pinned-page-specific terminal
        // IOTLB receipt; the oracle deliberately names the allocator boundary.
        allocator_released: evidence(claim(PAGE_CLAIM_RAW), DEVICE_EVIDENCE_IOTLB),
    };
    NormalizedProjection {
        effect: (original.root().get(), original.sequence()),
        authority: core_authority(parent.authority),
        authority_epoch: parent.authority_epoch,
        reply_committed,
        dma_committed,
        reply,
        dma,
        claims,
        escape: normalized_escape(reply_committed, dma_committed, reply, &claims),
    }
}

fn normalize_oracle(
    oracle: &CompositeEffectOracle,
    original: EffectId,
    context: DifferentialContext,
) -> NormalizedProjection {
    let projection = oracle.projection();
    assert_eq!(projection.effect, ORACLE_EFFECT);
    let reply_component = oracle.component(OracleComponentId::Reply);
    let dma_component = oracle.component(OracleComponentId::Dma);
    let claims = core::array::from_fn(|index| oracle_claim(oracle, context, index));
    let reply = oracle_reply(projection.reply);
    let dma = NormalizedDmaClosure {
        device_generation: projection.active_device_generation,
        reset: projection.reset_accepted,
        irq_drained: projection.irq_drained,
        iotlb_invalidated: projection.iotlb_invalidated,
        allocator_released: projection.allocator_released,
    };
    NormalizedProjection {
        effect: (original.root().get(), original.sequence()),
        authority: oracle_authority(projection.authority),
        authority_epoch: projection.authority_epoch,
        reply_committed: reply_component.committed,
        dma_committed: dma_component.committed,
        reply,
        dma,
        claims,
        escape: normalized_escape(
            reply_component.committed,
            dma_component.committed,
            reply,
            &claims,
        ),
    }
}

fn assert_exact_effect_replay(
    live: &Engine,
    recovered: &Engine,
    effect: EffectId,
    components: &[ComponentId],
    label: &str,
) {
    assert_eq!(
        recovered.composite_effect(effect),
        live.composite_effect(effect),
        "{label}: parent projection"
    );
    for component in components {
        assert_eq!(
            recovered.component(effect, *component),
            live.component(effect, *component),
            "{label}: component projection {component:?}"
        );
        assert_eq!(
            recovered.component_claims(effect, *component),
            live.component_claims(effect, *component),
            "{label}: component claims {component:?}"
        );
    }
}

fn recover_prefix(harness: &Harness, label: &str) -> Engine {
    let committed = harness.engine.freshness();
    let next = freshness(
        committed.boot().get() + 1,
        committed.registry().get(),
        committed.binding(),
        committed.device().get() + 98,
        committed.journal().get() + 1,
    );
    let anchor = || {
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            committed,
            next,
            harness.engine.revision(),
            harness.engine.head(),
        )
        .unwrap()
    };
    let first = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor(),
        &harness.journal,
    )
    .unwrap_or_else(|error| panic!("{label}: first recovery failed: {error:?}"));
    assert_eq!(
        first.acknowledged_revision(),
        harness.engine.revision(),
        "{label}"
    );
    assert_eq!(first.acknowledged_head(), harness.engine.head(), "{label}");
    let first = first.into_engine();
    let second = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        anchor(),
        &harness.journal,
    )
    .unwrap_or_else(|error| panic!("{label}: second recovery failed: {error:?}"))
    .into_engine();
    assert_eq!(
        first.projection_digest(),
        second.projection_digest(),
        "{label}: same prefix and trusted anchor must be deterministic"
    );
    first
}

fn assert_checkpoint(
    harness: &Harness,
    oracle: &CompositeEffectOracle,
    original: EffectId,
    context: DifferentialContext,
    label: &str,
) {
    let expected = normalize_oracle(oracle, original, context);
    assert_eq!(
        normalize_core(&harness.engine, original, context),
        expected,
        "{label}: live normalized projection"
    );

    let recovered = recover_prefix(harness, label);
    assert_exact_effect_replay(
        &harness.engine,
        &recovered,
        original,
        &[AGENT_COMPONENT_REPLY, AGENT_COMPONENT_DMA],
        label,
    );
    if let Some(target) = context.target {
        assert_exact_effect_replay(
            &harness.engine,
            &recovered,
            target,
            &[AGENT_COMPONENT_DMA],
            label,
        );
    }
    assert_eq!(
        recovered.device_generation(device_scope()),
        harness.engine.device_generation(device_scope()),
        "{label}: device generation"
    );
    assert_eq!(
        normalize_core(&recovered, original, context),
        expected,
        "{label}: recovered normalized projection"
    );
}

fn assert_failed_core_command_is_atomic(
    harness: &mut Harness,
    command: AuthorizedCommand,
    label: &str,
) {
    let before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
        harness.journal.len(),
    );
    assert!(
        matches!(
            harness.tx(command),
            Err(CoreError::StaleIncarnation | CoreError::StaleAuthorityEpoch)
        ),
        "{label}: an old reuse bearer must fail closed"
    );
    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
            harness.journal.len(),
        ),
        before,
        "{label}: rejected bearer must not mutate or append"
    );
}

fn record_snapshot(harness: &mut Harness, root_effect: EffectId, id: u64) -> AuthorizedCommand {
    let recovery = harness
        .engine
        .snapshot_root(root_effect.root(), snapshot(id))
        .unwrap();
    let items = recovery.component_items();
    assert_eq!(items[0].component, AGENT_COMPONENT_REPLY);
    assert_eq!(items[1].component, AGENT_COMPONENT_DMA);
    recovery.record()
}

#[test]
fn profile2_core_and_independent_oracle_match_every_durable_prefix() {
    let original = effect(ROOT, 1);
    let origin = principal(ROOT, 1);
    let first_successor = principal(ROOT, 2);
    let second_successor = principal(ROOT, 3);
    let mut harness = Harness::new_profile_two();
    let mut oracle = CompositeEffectOracle::new(
        ORACLE_EFFECT,
        origin.generation(),
        1,
        1,
        1,
        oracle_resources(),
    );
    let mut context = DifferentialContext::new();

    harness
        .tx(Command::CreateCompositeEffect {
            effect: original,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(ROOT),
        })
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "composite-created");

    let enrollments = [
        (
            AGENT_COMPONENT_REPLY,
            claim(REPLY_CLAIM_RAW),
            REPLY_CLAIM_PUBLICATION_SLOT,
            ClaimScope::Logical,
            resource(REPLY_RESOURCE_RAW),
        ),
        (
            AGENT_COMPONENT_DMA,
            claim(QUEUE_CLAIM_RAW),
            DEVICE_CLAIM_QUEUE_SLOT,
            ClaimScope::Device(device_scope()),
            resource(QUEUE_RESOURCE_RAW),
        ),
        (
            AGENT_COMPONENT_DMA,
            claim(PAGE_CLAIM_RAW),
            DEVICE_CLAIM_PINNED_PAGE,
            ClaimScope::Device(device_scope()),
            resource(PAGE_RESOURCE_RAW),
        ),
        (
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM_RAW),
            DEVICE_CLAIM_IOVA,
            ClaimScope::Device(device_scope()),
            resource(IOVA_RESOURCE_RAW),
        ),
    ];
    for (index, (component, claim_id, kind, scope, resource_id)) in
        enrollments.into_iter().enumerate()
    {
        harness
            .tx(Command::AddComponentClaim {
                effect: original,
                component,
                actor: origin,
                binding_generation: 1,
                claim: claim_id,
                kind,
                scope,
                resource: resource_id,
                resource_generation: resource_generation(1),
                units: 1,
            })
            .unwrap();
        context.registered[index] = true;
        assert_checkpoint(
            &harness,
            &oracle,
            original,
            context,
            match index {
                0 => "reply-claim-enrolled",
                1 => "queue-claim-enrolled",
                2 => "page-claim-enrolled",
                _ => "iova-claim-enrolled",
            },
        );
    }

    harness
        .tx(Command::FenceIncarnation {
            root: original.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();
    oracle.fence_incarnation(origin.generation(), 1).unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "precommit-fence");

    let snapshot_record = record_snapshot(&mut harness, original, FIRST_SNAPSHOT_RAW);
    harness.tx(snapshot_record).unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "precommit-snapshot");
    harness
        .tx(Command::Ready {
            root: original.root(),
            snapshot: snapshot(FIRST_SNAPSHOT_RAW),
            successor: first_successor,
        })
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "precommit-ready");
    harness
        .tx(Command::Rebind {
            root: original.root(),
            snapshot: snapshot(FIRST_SNAPSHOT_RAW),
            successor: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    oracle.rebind(first_successor.generation(), 2).unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "precommit-rebind");
    harness
        .tx(Command::AdoptEffect {
            effect: original,
            successor: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    oracle
        .adopt_effect(oracle.observe_authority().unwrap())
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "precommit-adopt");
    harness
        .tx(Command::RebaseCompositePrecommitClaims {
            effect: original,
            actor: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "precommit-claim-rebase",
    );

    harness
        .tx(Command::PrepareCompositeEffect {
            effect: original,
            actor: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "prepared");

    let mut intents = match harness.output(Command::RecordCompositeCommitIntents {
        effect: original,
        actor: first_successor,
        binding_generation: 2,
        operations: vec![
            ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(20)),
            ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(21)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected the complete atomic intent cohort, got {other:?}"),
    };
    assert_eq!(
        harness.engine.composite_effect(original).unwrap().escape,
        cser_core::EffectEscapeState::Escaped,
        "the core preserves its write-ahead intent stage outside the shared normal form"
    );
    assert_eq!(
        oracle.projection().escape,
        OracleEscape::Unescaped,
        "the independent oracle starts its commit transition at external acknowledgement"
    );
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "atomic-intents-durable",
    );

    let reply_intent = intents.remove(0);
    assert_eq!(reply_intent.component(), Some(AGENT_COMPONENT_REPLY));
    let reply_outcome = verified_commit_outcome(
        &harness,
        &reply_intent,
        REPLY_VERIFIER,
        REPLY_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(22),
    );
    harness
        .tx(reply_intent.acknowledge(reply_outcome).unwrap())
        .unwrap();
    oracle
        .commit_reply(oracle.observe_authority().unwrap())
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reply-commit-acknowledged",
    );

    let dma_intent = intents.remove(0);
    assert_eq!(dma_intent.component(), Some(AGENT_COMPONENT_DMA));
    let dma_outcome = verified_commit_outcome(
        &harness,
        &dma_intent,
        DEVICE_VERIFIER,
        DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(23),
    );
    harness
        .tx(dma_intent.acknowledge(dma_outcome).unwrap())
        .unwrap();
    oracle
        .commit_dma(oracle.observe_authority().unwrap())
        .unwrap();
    assert!(intents.is_empty());
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "dma-commit-acknowledged",
    );

    harness
        .tx(reset_component_command(
            &harness,
            original,
            claim(QUEUE_CLAIM_RAW),
            30,
        ))
        .unwrap();
    oracle.advance_device_generation(2).unwrap();
    oracle
        .accept_reset(oracle.dma_retirement_evidence())
        .unwrap();
    assert_eq!(
        harness.engine.composite_effect(original).unwrap().escape,
        cser_core::EffectEscapeState::Escaped,
        "core aggregate partial discharge starts when custody actually shrinks"
    );
    assert_eq!(
        oracle.projection().escape,
        OracleEscape::PartiallyDischarged,
        "oracle separately terminalizes the logical DMA outcome at reset"
    );
    assert_checkpoint(&harness, &oracle, original, context, "queue-reset");
    harness
        .tx(current_component_evidence_command(
            &harness,
            original,
            AGENT_COMPONENT_DMA,
            claim(QUEUE_CLAIM_RAW),
            DEVICE_EVIDENCE_IRQ_DRAINED,
            31,
        ))
        .unwrap();
    oracle
        .accept_irq_drain(oracle.dma_retirement_evidence())
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "queue-irq-drained");

    harness
        .tx(reset_component_command(
            &harness,
            original,
            claim(IOVA_CLAIM_RAW),
            32,
        ))
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "iova-reset");
    harness
        .tx(current_component_evidence_command(
            &harness,
            original,
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM_RAW),
            DEVICE_EVIDENCE_IOTLB,
            33,
        ))
        .unwrap();
    oracle
        .accept_iotlb_invalidation(oracle.dma_retirement_evidence())
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "iova-retired");

    harness
        .tx(reset_component_command(
            &harness,
            original,
            claim(PAGE_CLAIM_RAW),
            34,
        ))
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "page-reset");
    harness
        .tx(current_component_evidence_command(
            &harness,
            original,
            AGENT_COMPONENT_DMA,
            claim(PAGE_CLAIM_RAW),
            DEVICE_EVIDENCE_IOTLB,
            35,
        ))
        .unwrap();
    oracle
        .accept_allocator_release(oracle.dma_retirement_evidence())
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "page-retired");
    assert_eq!(
        harness
            .engine
            .component(original, AGENT_COMPONENT_REPLY)
            .unwrap()
            .retained_claims,
        1,
        "physical closure must not discharge the logical output claim"
    );

    let target = effect(ROOT, 2);
    context.target = Some(target);
    harness
        .tx(Command::CreateCompositeEffect {
            effect: target,
            origin: first_successor,
            binding_generation: 2,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(ROOT),
        })
        .unwrap();
    assert_eq!(
        harness
            .engine
            .composite_effect(target)
            .unwrap()
            .authority_epoch,
        1,
        "core reuse authority belongs to the explicit seq=2 lease effect"
    );
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reuse-lease-effect-created",
    );

    let reuse_specs = [
        (
            OracleClaimKind::QueueSlot,
            claim(REUSE_QUEUE_CLAIM_RAW),
            DEVICE_CLAIM_QUEUE_SLOT,
            resource(QUEUE_RESOURCE_RAW),
        ),
        (
            OracleClaimKind::PinnedPage,
            claim(REUSE_PAGE_CLAIM_RAW),
            DEVICE_CLAIM_PINNED_PAGE,
            resource(PAGE_RESOURCE_RAW),
        ),
        (
            OracleClaimKind::IovaMapping,
            claim(REUSE_IOVA_CLAIM_RAW),
            DEVICE_CLAIM_IOVA,
            resource(IOVA_RESOURCE_RAW),
        ),
    ];
    let mut old_core_activation = Vec::new();
    let mut old_oracle_permits = Vec::new();
    let mut reuse_retirement_digests = Vec::new();
    for (reuse, (oracle_kind, claim_id, kind, resource_id)) in reuse_specs.into_iter().enumerate() {
        assert!(oracle.reuse_is_admissible(oracle_kind, 2));
        let core_permit = match harness.output(Command::ReserveComponentReuse {
            effect: target,
            component: AGENT_COMPONENT_DMA,
            actor: first_successor,
            binding_generation: 2,
            claim: claim_id,
            kind,
            scope: ClaimScope::Device(device_scope()),
            resource: resource_id,
            expected_generation: resource_generation(1),
            units: 1,
            reuse_contract: digest(40 + reuse as u8),
        }) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected generation+1 core permit, got {other:?}"),
        };
        let oracle_permit = oracle
            .issue_reuse_permit(oracle.observe_authority().unwrap(), oracle_kind, 2)
            .unwrap();
        assert_eq!(core_permit.effect(), target);
        assert_eq!(core_permit.component(), Some(AGENT_COMPONENT_DMA));
        assert_eq!(core_permit.claim(), claim_id);
        assert_eq!(core_permit.resource(), resource_id);
        assert_eq!(core_permit.previous_generation(), resource_generation(1));
        assert_eq!(core_permit.generation(), resource_generation(2));
        assert_eq!(core_permit.catalog_digest(), standard_catalog().digest());
        assert!(!core_permit.retirement_digest().is_zero());
        assert_eq!(core_permit.reuse_contract(), digest(40 + reuse as u8));
        assert_eq!(core_permit.freshness().binding(), 2);
        assert_eq!(oracle_permit.effect(), ORACLE_EFFECT);
        assert_eq!(oracle_permit.resource().get(), resource_id.get());
        assert_eq!(oracle_permit.retired_generation(), 1);
        assert_eq!(oracle_permit.next_generation(), 2);
        assert_eq!(oracle_permit.actor(), first_successor.generation());
        assert_eq!(oracle_permit.binding_generation(), 2);
        assert_eq!(oracle_permit.device_generation(), 2);
        assert_eq!(
            oracle_permit.authority_epoch(),
            oracle.projection().authority_epoch,
            "oracle reuse authority remains on its single modeled effect"
        );
        context.reuse[reuse] = ReuseStage::Reserved;
        context.permit[reuse] = Some(NormalizedPermitOwner {
            actor: first_successor.generation(),
            binding_generation: 2,
            next_generation: 2,
            device_generation: core_permit.freshness().device().get(),
        });
        reuse_retirement_digests.push(core_permit.retirement_digest());
        old_core_activation.push(core_permit.activate());
        old_oracle_permits.push(oracle_permit);
        assert_checkpoint(
            &harness,
            &oracle,
            original,
            context,
            match reuse {
                0 => "queue-reuse-reserved",
                1 => "page-reuse-reserved",
                _ => "iova-reuse-reserved",
            },
        );
    }

    harness
        .tx(Command::FenceIncarnation {
            root: original.root(),
            crashed: first_successor,
            binding_generation: 2,
        })
        .unwrap();
    oracle
        .fence_incarnation(first_successor.generation(), 2)
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "second-crash-with-pending-reuse",
    );
    let snapshot_record = record_snapshot(&mut harness, original, SECOND_SNAPSHOT_RAW);
    harness.tx(snapshot_record).unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "second-crash-snapshot",
    );
    harness
        .tx(Command::Ready {
            root: original.root(),
            snapshot: snapshot(SECOND_SNAPSHOT_RAW),
            successor: second_successor,
        })
        .unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "second-crash-ready");
    harness
        .tx(Command::Rebind {
            root: original.root(),
            snapshot: snapshot(SECOND_SNAPSHOT_RAW),
            successor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    oracle.rebind(second_successor.generation(), 3).unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "second-crash-rebind");
    harness
        .tx(Command::AdoptEffect {
            effect: target,
            successor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reuse-lease-effect-adopted",
    );

    // Public claim projections deliberately do not expose a live bearer nonce.
    // Probe a separately recovered engine through the supported reclaim path so
    // the test observes the persisted catalog, retirement and provider
    // contracts instead of copying them from the live permit into its oracle
    // normalization. Successful activation also checks the recovered
    // effect/component/claim, authority, nonce and freshness tuple as one unit.
    let mut recovered_probe = recover_prefix(&harness, "pending-reuse-contract-probe");
    let committed = harness.engine.freshness();
    let probe_freshness = freshness(
        committed.boot().get() + 1,
        committed.registry().get(),
        committed.binding(),
        committed.device().get() + 98,
        committed.journal().get() + 1,
    );
    recovered_probe
        .transact_volatile(Command::CheckpointRecovery {
            boot: probe_freshness.boot(),
            journal: probe_freshness.journal(),
            device: probe_freshness.device(),
        })
        .unwrap();
    let probe_successor = principal(ROOT, 4);
    let probe_snapshot = recovered_probe
        .snapshot_root(target.root(), snapshot(PROBE_SNAPSHOT_RAW))
        .unwrap();
    recovered_probe
        .transact_volatile(probe_snapshot.record())
        .unwrap();
    recovered_probe
        .transact_volatile(Command::Ready {
            root: target.root(),
            snapshot: snapshot(PROBE_SNAPSHOT_RAW),
            successor: probe_successor,
        })
        .unwrap();
    recovered_probe
        .transact_volatile(Command::Rebind {
            root: target.root(),
            snapshot: snapshot(PROBE_SNAPSHOT_RAW),
            successor: probe_successor,
            binding_generation: 4,
        })
        .unwrap();
    recovered_probe
        .transact_volatile(Command::AdoptEffect {
            effect: target,
            successor: probe_successor,
            binding_generation: 4,
        })
        .unwrap();
    recovered_probe
        .transact_volatile(Command::RebaseCompositePrecommitClaims {
            effect: target,
            actor: probe_successor,
            binding_generation: 4,
        })
        .unwrap();
    for (reuse, (_, claim_id, _, resource_id)) in reuse_specs.into_iter().enumerate() {
        let reclaim = recovered_probe
            .reclaim_component_resource_reuse(
                target,
                AGENT_COMPONENT_DMA,
                probe_successor,
                4,
                resource_id,
                resource_generation(2),
            )
            .unwrap();
        let permit = match recovered_probe
            .transact_volatile(reclaim)
            .unwrap()
            .into_output()
        {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected recovered reuse permit, got {other:?}"),
        };
        assert_eq!(permit.effect(), target);
        assert_eq!(permit.component(), Some(AGENT_COMPONENT_DMA));
        assert_eq!(permit.claim(), claim_id);
        assert_eq!(permit.resource(), resource_id);
        assert_eq!(permit.previous_generation(), resource_generation(1));
        assert_eq!(permit.generation(), resource_generation(2));
        assert_eq!(permit.catalog_digest(), standard_catalog().digest());
        assert_eq!(permit.retirement_digest(), reuse_retirement_digests[reuse]);
        assert_eq!(permit.reuse_contract(), digest(40 + reuse as u8));
        assert_eq!(permit.freshness().binding(), 4);
        assert_eq!(permit.freshness().device(), probe_freshness.device());
        recovered_probe
            .transact_volatile(permit.activate())
            .unwrap();
    }

    harness
        .tx(Command::RebaseCompositePrecommitClaims {
            effect: target,
            actor: second_successor,
            binding_generation: 3,
        })
        .unwrap();
    assert_eq!(
        harness
            .engine
            .composite_effect(target)
            .unwrap()
            .authority_epoch,
        3,
        "target fence plus explicit adoption advances the core lease authority"
    );
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reuse-lease-claims-rebased",
    );

    for (index, command) in old_core_activation.into_iter().enumerate() {
        assert_failed_core_command_is_atomic(
            &mut harness,
            command,
            match index {
                0 => "old queue permit",
                1 => "old page permit",
                _ => "old IOVA permit",
            },
        );
        let before = oracle;
        assert_eq!(
            oracle.activate_reuse(old_oracle_permits[index]),
            Err(cser_model::composite_effect_oracle::CompositeError::StaleReusePermit)
        );
        assert_eq!(
            oracle, before,
            "rejected oracle bearer must be failure-atomic"
        );
    }

    let mut reclaimed_core_activation = Vec::new();
    let mut reclaimed_oracle_permits = Vec::new();
    for (reuse, (oracle_kind, _, _, resource_id)) in reuse_specs.into_iter().enumerate() {
        let command = harness
            .engine
            .reclaim_component_resource_reuse(
                target,
                AGENT_COMPONENT_DMA,
                second_successor,
                3,
                resource_id,
                resource_generation(2),
            )
            .unwrap();
        let core_permit = match harness.output(command) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected reclaimed core permit, got {other:?}"),
        };
        let oracle_permit = oracle
            .reclaim_reuse_permit(oracle.observe_authority().unwrap(), oracle_kind)
            .unwrap();
        assert_eq!(core_permit.effect(), target);
        assert_eq!(core_permit.resource(), resource_id);
        assert_eq!(core_permit.generation(), resource_generation(2));
        assert_eq!(core_permit.freshness().binding(), 3);
        assert_eq!(oracle_permit.actor(), second_successor.generation());
        assert_eq!(oracle_permit.binding_generation(), 3);
        assert_eq!(oracle_permit.device_generation(), 2);
        assert!(oracle_permit.authority_epoch() > old_oracle_permits[reuse].authority_epoch());
        context.permit[reuse] = Some(NormalizedPermitOwner {
            actor: second_successor.generation(),
            binding_generation: 3,
            next_generation: 2,
            device_generation: core_permit.freshness().device().get(),
        });
        reclaimed_core_activation.push(core_permit.activate());
        reclaimed_oracle_permits.push(oracle_permit);
        assert_checkpoint(
            &harness,
            &oracle,
            original,
            context,
            match reuse {
                0 => "queue-reuse-reclaimed",
                1 => "page-reuse-reclaimed",
                _ => "iova-reuse-reclaimed",
            },
        );
    }

    for (reuse, (core_activation, oracle_permit)) in reclaimed_core_activation
        .into_iter()
        .zip(reclaimed_oracle_permits)
        .enumerate()
    {
        harness.tx(core_activation).unwrap();
        oracle.activate_reuse(oracle_permit).unwrap();
        context.reuse[reuse] = ReuseStage::Active;
        context.permit[reuse] = None;
        assert_checkpoint(
            &harness,
            &oracle,
            original,
            context,
            match reuse {
                0 => "queue-generation-two-active",
                1 => "page-generation-two-active",
                _ => "iova-generation-two-active",
            },
        );
    }

    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect: original,
        component: AGENT_COMPONENT_REPLY,
        claimant: second_successor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected a reply component settlement claim, got {other:?}"),
    };
    let oracle_reply_claim = oracle
        .claim_reply(oracle.observe_authority().unwrap())
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reply-settlement-claimed",
    );

    let settlement = match harness.output(settlement.record_apply_intent(digest(60)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage settlement claim, got {other:?}"),
    };
    oracle
        .record_reply_apply_intent(oracle_reply_claim)
        .unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reply-apply-intent-durable",
    );

    let applied = verified_apply_completion(
        &harness,
        &settlement,
        REPLY_VERIFIER,
        REPLY_APPLY_RECEIPT_SCHEMA,
        digest(61),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied-stage settlement claim, got {other:?}"),
    };
    oracle.record_reply_applied(oracle_reply_claim).unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reply-applied-unacknowledged",
    );

    let acknowledgement = verified_settlement_ack(
        &harness,
        &settlement,
        REPLY_VERIFIER,
        REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(62),
    );
    harness
        .tx(settlement.settle(acknowledgement).unwrap())
        .unwrap();
    oracle.accept_reply_ack(oracle_reply_claim).unwrap();
    assert_checkpoint(
        &harness,
        &oracle,
        original,
        context,
        "reply-settled-claim-retained",
    );

    harness
        .tx(current_component_evidence_command(
            &harness,
            original,
            AGENT_COMPONENT_REPLY,
            claim(REPLY_CLAIM_RAW),
            REPLY_EVIDENCE_PUBLICATION_ACK,
            63,
        ))
        .unwrap();
    oracle.retire_reply_output().unwrap();
    assert_checkpoint(&harness, &oracle, original, context, "reply-output-retired");

    assert_eq!(
        harness.engine.composite_effect(original).unwrap().escape,
        cser_core::EffectEscapeState::Retired
    );
    assert_eq!(oracle.projection().escape, OracleEscape::Retired);
    assert_eq!(
        oracle.projection().dma,
        OracleDmaOutcome::IndeterminateAfterReset
    );
    for coordinates in reuse_specs {
        let claim = harness
            .engine
            .component_claims(target, AGENT_COMPONENT_DMA)
            .unwrap()
            .into_iter()
            .find(|projection| projection.resource == coordinates.3)
            .unwrap();
        assert_eq!(claim.resource_generation, resource_generation(2));
        assert!(!claim.retired);
    }
}
