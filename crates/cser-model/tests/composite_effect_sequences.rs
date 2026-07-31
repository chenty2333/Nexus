use cser_model::EffectId;
use cser_model::composite_effect_oracle::{
    ClaimKind, ClaimState, ComponentId, CompositeAuthority, CompositeEffectOracle, CompositeError,
    CompositeResources, DmaOutcome, EscapeState, ReplyClaim, ReplyState, ResourceId, ReusePermit,
};

const EFFECT: EffectId = EffectId::new(0xce01);

fn resources() -> CompositeResources {
    CompositeResources {
        reply_output: ResourceId::new(11),
        queue_slot: ResourceId::new(12),
        pinned_page: ResourceId::new(13),
        iova_mapping: ResourceId::new(14),
    }
}

fn staged() -> CompositeEffectOracle {
    CompositeEffectOracle::new(EFFECT, 1, 1, 1, 1, resources())
}

fn committed() -> CompositeEffectOracle {
    let mut model = staged();
    let authority = model.observe_authority().unwrap();
    model.commit_dma(authority).unwrap();
    model.commit_reply(authority).unwrap();
    model
}

fn recovered() -> CompositeEffectOracle {
    let mut model = committed();
    model.fence_incarnation(1, 1).unwrap();
    model.rebind(2, 2).unwrap();
    model
}

fn claim_applied(model: &mut CompositeEffectOracle) -> ReplyClaim {
    let successor = model.observe_authority().unwrap();
    let claim = model.claim_reply(successor).unwrap();
    model.record_reply_apply_intent(claim).unwrap();
    model.record_reply_applied(claim).unwrap();
    claim
}

fn advance_and_reset(model: &mut CompositeEffectOracle) {
    model.advance_device_generation(2).unwrap();
    let evidence = model.dma_retirement_evidence();
    model.accept_reset(evidence).unwrap();
}

fn issue_reuse(
    model: &mut CompositeEffectOracle,
    kind: ClaimKind,
    next_generation: u64,
) -> Result<ReusePermit, CompositeError> {
    let authority = model.observe_authority()?;
    model.issue_reuse_permit(authority, kind, next_generation)
}

fn reclaim_reuse(
    model: &mut CompositeEffectOracle,
    kind: ClaimKind,
) -> Result<ReusePermit, CompositeError> {
    let authority = model.observe_authority()?;
    model.reclaim_reuse_permit(authority, kind)
}

#[derive(Clone, Copy, Debug)]
enum ReplyBoundary {
    Open,
    Claimed,
    IntentDurable,
    Applied,
    Settled,
    Retired,
}

impl ReplyBoundary {
    const ALL: [Self; 6] = [
        Self::Open,
        Self::Claimed,
        Self::IntentDurable,
        Self::Applied,
        Self::Settled,
        Self::Retired,
    ];
}

#[derive(Clone, Copy, Debug)]
enum DmaBoundary {
    Pending,
    Reset,
    QueueDischarged,
    QueuePermitIssued,
    QueueReused,
    IovaDischarged,
    IovaPermitIssued,
    IovaReused,
    PageDischarged,
    PagePermitIssued,
    PageReused,
}

impl DmaBoundary {
    const ALL: [Self; 11] = [
        Self::Pending,
        Self::Reset,
        Self::QueueDischarged,
        Self::QueuePermitIssued,
        Self::QueueReused,
        Self::IovaDischarged,
        Self::IovaPermitIssued,
        Self::IovaReused,
        Self::PageDischarged,
        Self::PagePermitIssued,
        Self::PageReused,
    ];
}

fn at_reply_boundary(
    model: &mut CompositeEffectOracle,
    boundary: ReplyBoundary,
) -> Option<ReplyClaim> {
    if matches!(boundary, ReplyBoundary::Open) {
        return None;
    }
    let authority = model.observe_authority().unwrap();
    let claim = model.claim_reply(authority).unwrap();
    if matches!(
        boundary,
        ReplyBoundary::IntentDurable
            | ReplyBoundary::Applied
            | ReplyBoundary::Settled
            | ReplyBoundary::Retired
    ) {
        model.record_reply_apply_intent(claim).unwrap();
    }
    if matches!(
        boundary,
        ReplyBoundary::Applied | ReplyBoundary::Settled | ReplyBoundary::Retired
    ) {
        model.record_reply_applied(claim).unwrap();
    }
    if matches!(boundary, ReplyBoundary::Settled | ReplyBoundary::Retired) {
        model.accept_reply_ack(claim).unwrap();
    }
    if matches!(boundary, ReplyBoundary::Retired) {
        model.retire_reply_output().unwrap();
    }
    Some(claim)
}

fn at_dma_boundary(
    model: &mut CompositeEffectOracle,
    boundary: DmaBoundary,
) -> Option<ReusePermit> {
    if matches!(boundary, DmaBoundary::Pending) {
        return None;
    }
    advance_and_reset(model);
    if matches!(boundary, DmaBoundary::Reset) {
        return None;
    }

    let evidence = model.dma_retirement_evidence();
    model.accept_irq_drain(evidence).unwrap();
    if matches!(boundary, DmaBoundary::QueueDischarged) {
        return None;
    }
    let queue = issue_reuse(model, ClaimKind::QueueSlot, 2).unwrap();
    if matches!(boundary, DmaBoundary::QueuePermitIssued) {
        return Some(queue);
    }
    model.activate_reuse(queue).unwrap();
    if matches!(boundary, DmaBoundary::QueueReused) {
        return None;
    }

    model.accept_iotlb_invalidation(evidence).unwrap();
    if matches!(boundary, DmaBoundary::IovaDischarged) {
        return None;
    }
    let iova = issue_reuse(model, ClaimKind::IovaMapping, 2).unwrap();
    if matches!(boundary, DmaBoundary::IovaPermitIssued) {
        return Some(iova);
    }
    model.activate_reuse(iova).unwrap();
    if matches!(boundary, DmaBoundary::IovaReused) {
        return None;
    }

    model.accept_allocator_release(evidence).unwrap();
    if matches!(boundary, DmaBoundary::PageDischarged) {
        return None;
    }
    let page = issue_reuse(model, ClaimKind::PinnedPage, 2).unwrap();
    if matches!(boundary, DmaBoundary::PagePermitIssued) {
        return Some(page);
    }
    model.activate_reuse(page).unwrap();
    None
}

#[test]
fn one_effect_identity_owns_both_component_local_claim_sets() {
    let model = committed();
    let projection = model.projection();
    let reply = model.component(ComponentId::Reply);
    let dma = model.component(ComponentId::Dma);

    assert_eq!(projection.effect, EFFECT);
    assert_eq!(projection.escape, EscapeState::Escaped);
    assert_eq!(reply.effect, EFFECT);
    assert_eq!(reply.component, ComponentId::Reply);
    assert_eq!(reply.live_claims, 1);
    assert_eq!(dma.effect, EFFECT);
    assert_eq!(dma.component, ComponentId::Dma);
    assert_eq!(dma.live_claims, 3);

    for kind in ClaimKind::ALL {
        let claim = model.claim(kind);
        assert_eq!(claim.effect, EFFECT);
        assert_eq!(claim.component, kind.component());
        assert_eq!(claim.state, ClaimState::Live);
    }
    assert!(model.check_invariants());
}

#[test]
fn recovered_effect_partially_discharges_and_reuses_physical_claims_before_reply_ack() {
    let mut model = recovered();
    assert_eq!(model.projection().authority, CompositeAuthority::Fenced);
    let stale_irq = model.dma_completion_event().unwrap();
    let reply = claim_applied(&mut model);
    assert_eq!(model.projection().authority, CompositeAuthority::Fenced);

    advance_and_reset(&mut model);
    assert_eq!(
        model.accept_dma_completion(stale_irq),
        Err(CompositeError::StaleDeviceEvidence)
    );
    let evidence = model.dma_retirement_evidence();
    model.accept_irq_drain(evidence).unwrap();

    assert!(model.reuse_is_admissible(ClaimKind::QueueSlot, 2));
    let queue = issue_reuse(&mut model, ClaimKind::QueueSlot, 2).unwrap();
    model.activate_reuse(queue).unwrap();

    let partial = model.projection();
    assert_eq!(partial.escape, EscapeState::PartiallyDischarged);
    assert_eq!(
        partial.reply,
        ReplyState::AppliedUnacknowledged {
            claimant: 2,
            generation: 1,
        }
    );
    assert_eq!(
        model.claim(ClaimKind::QueueSlot).state,
        ClaimState::Reused { generation: 2 }
    );
    assert_eq!(model.claim(ClaimKind::PinnedPage).state, ClaimState::Live);
    assert_eq!(model.claim(ClaimKind::IovaMapping).state, ClaimState::Live);

    model.accept_iotlb_invalidation(evidence).unwrap();
    let iova = issue_reuse(&mut model, ClaimKind::IovaMapping, 2).unwrap();
    model.activate_reuse(iova).unwrap();
    model.accept_allocator_release(evidence).unwrap();
    let page = issue_reuse(&mut model, ClaimKind::PinnedPage, 2).unwrap();
    model.activate_reuse(page).unwrap();

    assert_eq!(model.projection().escape, EscapeState::PartiallyDischarged);
    assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
    model.accept_reply_ack(reply).unwrap();
    assert_eq!(model.projection().escape, EscapeState::PartiallyDischarged);
    assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
    model.retire_reply_output().unwrap();
    assert_eq!(model.projection().escape, EscapeState::Retired);
    assert_eq!(model.projection().authority, CompositeAuthority::Fenced);
    model.release_effect().unwrap();
    assert_eq!(model.projection().escape, EscapeState::Released);
    assert!(model.check_invariants());
}

#[test]
fn reply_first_settlement_leaves_dma_claims_live_and_parent_unreleased() {
    let mut model = recovered();
    let physical_before = [
        model.claim(ClaimKind::QueueSlot),
        model.claim(ClaimKind::PinnedPage),
        model.claim(ClaimKind::IovaMapping),
    ];
    let reply = claim_applied(&mut model);
    model.accept_reply_ack(reply).unwrap();

    assert_eq!(model.projection().reply, ReplyState::Settled);
    assert_eq!(model.projection().escape, EscapeState::PartiallyDischarged);
    assert_eq!(model.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
    assert_eq!(
        [
            model.claim(ClaimKind::QueueSlot),
            model.claim(ClaimKind::PinnedPage),
            model.claim(ClaimKind::IovaMapping),
        ],
        physical_before
    );
    let before_release = model.projection();
    assert_eq!(
        model.release_effect(),
        Err(CompositeError::EffectNotRetired)
    );
    assert_eq!(model.projection(), before_release);

    model.retire_reply_output().unwrap();
    advance_and_reset(&mut model);
    let evidence = model.dma_retirement_evidence();
    model.accept_irq_drain(evidence).unwrap();
    model.accept_iotlb_invalidation(evidence).unwrap();
    model.accept_allocator_release(evidence).unwrap();
    assert_eq!(model.projection().escape, EscapeState::Retired);
    model.release_effect().unwrap();
    let released = model.projection();
    assert_eq!(released.escape, EscapeState::Released);
    assert_eq!(model.release_effect(), Err(CompositeError::GateClosed));
    assert_eq!(model.projection(), released);
    assert!(model.check_invariants());
}

#[test]
fn reply_and_dma_fence_commit_orders_preserve_exactly_the_linearized_component() {
    let mut reply_commit_first = staged();
    let old = reply_commit_first.observe_authority().unwrap();
    reply_commit_first.commit_reply(old).unwrap();
    reply_commit_first.fence_incarnation(1, 1).unwrap();
    assert!(reply_commit_first.component(ComponentId::Reply).committed);
    assert_eq!(
        reply_commit_first.projection().authority,
        CompositeAuthority::Fenced
    );

    let mut reply_fence_first = staged();
    let stale = reply_fence_first.observe_authority().unwrap();
    reply_fence_first.fence_incarnation(1, 1).unwrap();
    let fenced = reply_fence_first.projection();
    assert_eq!(
        reply_fence_first.commit_reply(stale),
        Err(CompositeError::WrongAuthorityState)
    );
    assert_eq!(reply_fence_first.projection(), fenced);
    assert!(!reply_fence_first.component(ComponentId::Reply).committed);

    let mut commit_first = staged();
    let old = commit_first.observe_authority().unwrap();
    commit_first.commit_dma(old).unwrap();
    commit_first.fence_incarnation(1, 1).unwrap();
    assert!(commit_first.component(ComponentId::Dma).committed);
    assert_eq!(
        commit_first.projection().authority,
        CompositeAuthority::Fenced
    );

    let mut fence_first = staged();
    let stale = fence_first.observe_authority().unwrap();
    fence_first.fence_incarnation(1, 1).unwrap();
    let fenced = fence_first.projection();
    assert_eq!(
        fence_first.commit_dma(stale),
        Err(CompositeError::WrongAuthorityState)
    );
    assert_eq!(fence_first.projection(), fenced);
    assert!(!fence_first.component(ComponentId::Dma).committed);
    assert!(reply_commit_first.check_invariants());
    assert!(reply_fence_first.check_invariants());
    assert!(commit_first.check_invariants());
    assert!(fence_first.check_invariants());
}

#[test]
fn adopt_and_revoke_share_the_parent_authority_epoch_before_escape() {
    let mut adopt_first = staged();
    adopt_first.fence_incarnation(1, 1).unwrap();
    adopt_first.rebind(2, 2).unwrap();
    let observed = adopt_first.observe_authority().unwrap();
    adopt_first.adopt_effect(observed).unwrap();
    let adopted_projection = adopt_first.projection();
    assert_eq!(
        adopt_first.begin_revoke(observed),
        Err(CompositeError::StaleAuthority)
    );
    assert_eq!(adopt_first.projection(), adopted_projection);
    assert_eq!(
        adopt_first.projection().authority,
        CompositeAuthority::Active
    );

    let mut revoke_first = staged();
    revoke_first.fence_incarnation(1, 1).unwrap();
    revoke_first.rebind(2, 2).unwrap();
    let observed = revoke_first.observe_authority().unwrap();
    revoke_first.begin_revoke(observed).unwrap();
    let revoked_projection = revoke_first.projection();
    assert_eq!(
        revoke_first.adopt_effect(observed),
        Err(CompositeError::StaleAuthority)
    );
    assert_eq!(revoke_first.projection(), revoked_projection);
    assert_eq!(
        revoke_first.projection().authority,
        CompositeAuthority::Revoked
    );
    assert_eq!(
        revoke_first.claim(ClaimKind::ReplyOutput).state,
        ClaimState::Discharged
    );
    assert_eq!(
        revoke_first.claim(ClaimKind::QueueSlot).state,
        ClaimState::Discharged
    );
    assert!(adopt_first.check_invariants());
    assert!(revoke_first.check_invariants());
}

#[test]
fn any_committed_component_makes_parent_adoption_fail_closed_and_failure_atomic() {
    for committed_components in [(true, false), (false, true), (true, true)] {
        let mut model = staged();
        let authority = model.observe_authority().unwrap();
        if committed_components.0 {
            model.commit_reply(authority).unwrap();
        }
        if committed_components.1 {
            model.commit_dma(authority).unwrap();
        }
        model.fence_incarnation(1, 1).unwrap();
        model.rebind(2, 2).unwrap();
        let successor = model.observe_authority().unwrap();
        let before = model.projection();

        assert_eq!(
            model.adopt_effect(successor),
            Err(CompositeError::WrongComponentState),
            "reply_committed={}, dma_committed={}",
            committed_components.0,
            committed_components.1
        );
        assert_eq!(model.projection(), before);
        assert_eq!(model.projection().authority, CompositeAuthority::Fenced);
        assert!(model.check_invariants());
    }
}

#[test]
fn stale_reply_ack_irq_and_retirement_coordinates_are_failure_atomic() {
    let mut model = recovered();
    let old_irq = model.dma_completion_event().unwrap();
    let claim = claim_applied(&mut model);
    model.fence_incarnation(2, 2).unwrap();
    let after_crash = model.projection();

    assert_eq!(
        model.accept_reply_ack(claim),
        Err(CompositeError::StaleReplyClaim)
    );
    assert_eq!(model.projection(), after_crash);

    model.rebind(3, 3).unwrap();
    let replacement = model
        .claim_reply(model.observe_authority().unwrap())
        .unwrap();
    assert_eq!(model.projection().authority, CompositeAuthority::Fenced);
    let replacement_projection = model.projection();
    for _ in 0..2 {
        assert_eq!(
            model.accept_reply_ack(claim),
            Err(CompositeError::StaleReplyClaim)
        );
        assert_eq!(model.projection(), replacement_projection);
    }
    model.accept_reply_ack(replacement).unwrap();
    let settled = model.projection();
    assert_eq!(settled.reply, ReplyState::Settled);
    for duplicate in [claim, replacement] {
        assert_eq!(
            model.accept_reply_ack(duplicate),
            Err(CompositeError::StaleReplyClaim)
        );
        assert_eq!(model.projection(), settled);
    }

    model.advance_device_generation(2).unwrap();
    let evidence = model.dma_retirement_evidence();
    let before_stale = model.projection();

    assert_eq!(
        model.accept_dma_completion(old_irq),
        Err(CompositeError::StaleDeviceEvidence)
    );
    assert_eq!(
        model.accept_reset(evidence.with_effect(EffectId::new(EFFECT.get() + 1))),
        Err(CompositeError::StaleDeviceEvidence)
    );
    assert_eq!(
        model.accept_reset(evidence.with_resource_generation(2)),
        Err(CompositeError::StaleDeviceEvidence)
    );
    assert_eq!(
        model.accept_reset(evidence.with_subject_device_generation(2)),
        Err(CompositeError::StaleDeviceEvidence)
    );
    assert_eq!(
        model.accept_reset(evidence.with_observation_device_generation(1)),
        Err(CompositeError::StaleDeviceEvidence)
    );
    assert_eq!(model.projection(), before_stale);
    assert!(model.check_invariants());
}

#[test]
fn fenced_composite_does_not_block_an_unrelated_composite() {
    let mut quarantined = committed();
    quarantined.fence_incarnation(1, 1).unwrap();
    let quarantined_projection = quarantined.projection();

    let unrelated_resources = CompositeResources {
        reply_output: ResourceId::new(101),
        queue_slot: ResourceId::new(102),
        pinned_page: ResourceId::new(103),
        iova_mapping: ResourceId::new(104),
    };
    let mut unrelated =
        CompositeEffectOracle::new(EffectId::new(0xce02), 7, 9, 1, 1, unrelated_resources);
    let authority = unrelated.observe_authority().unwrap();
    unrelated.commit_reply(authority).unwrap();
    unrelated.commit_dma(authority).unwrap();
    let reply = claim_applied(&mut unrelated);
    unrelated.accept_reply_ack(reply).unwrap();

    assert_eq!(quarantined.projection(), quarantined_projection);
    assert_eq!(
        quarantined.projection().authority,
        CompositeAuthority::Fenced
    );
    assert_eq!(unrelated.projection().effect, EffectId::new(0xce02));
    assert_eq!(unrelated.projection().reply, ReplyState::Settled);
    assert_eq!(
        unrelated.claim(ClaimKind::QueueSlot).state,
        ClaimState::Live
    );
    assert!(quarantined.check_invariants());
    assert!(unrelated.check_invariants());
}

#[test]
fn device_freshness_invalidates_an_unactivated_permit_without_reviving_the_old_claim() {
    let mut model = recovered();
    advance_and_reset(&mut model);
    let evidence = model.dma_retirement_evidence();
    model.accept_irq_drain(evidence).unwrap();
    let stale = issue_reuse(&mut model, ClaimKind::QueueSlot, 2).unwrap();

    model.advance_device_generation(3).unwrap();
    assert_eq!(
        model.claim(ClaimKind::QueueSlot).state,
        ClaimState::Discharged
    );
    let after_freshness = model.projection();
    assert_eq!(
        model.activate_reuse(stale),
        Err(CompositeError::StaleReusePermit)
    );
    assert_eq!(model.projection(), after_freshness);

    let fresh = issue_reuse(&mut model, ClaimKind::QueueSlot, 2).unwrap();
    assert_eq!(fresh.device_generation(), 3);
    model.activate_reuse(fresh).unwrap();
    assert_eq!(
        model.claim(ClaimKind::QueueSlot).state,
        ClaimState::Reused { generation: 2 }
    );
    assert!(model.check_invariants());
}

#[test]
fn second_crash_preserves_every_modeled_reply_dma_partial_boundary() {
    for reply_boundary in ReplyBoundary::ALL {
        for dma_boundary in DmaBoundary::ALL {
            let mut model = recovered();
            let old_reply_claim = at_reply_boundary(&mut model, reply_boundary);
            let outstanding_permit = at_dma_boundary(&mut model, dma_boundary);
            let before = model.projection();
            let physical_before = [
                model.claim(ClaimKind::QueueSlot),
                model.claim(ClaimKind::PinnedPage),
                model.claim(ClaimKind::IovaMapping),
            ];

            model.fence_incarnation(2, 2).unwrap();
            let after = model.projection();
            let physical_after = [
                model.claim(ClaimKind::QueueSlot),
                model.claim(ClaimKind::PinnedPage),
                model.claim(ClaimKind::IovaMapping),
            ];
            let coordinates = format!("reply={reply_boundary:?}, dma={dma_boundary:?}");

            assert_eq!(physical_after, physical_before, "{coordinates}");
            assert_eq!(after.dma, before.dma, "{coordinates}");
            assert_eq!(
                (
                    after.reset_accepted,
                    after.irq_drained,
                    after.iotlb_invalidated,
                    after.allocator_released,
                ),
                (
                    before.reset_accepted,
                    before.irq_drained,
                    before.iotlb_invalidated,
                    before.allocator_released,
                ),
                "{coordinates}"
            );

            model.rebind(3, 3).unwrap();

            if let Some(stale) = old_reply_claim {
                if matches!(
                    reply_boundary,
                    ReplyBoundary::Claimed | ReplyBoundary::IntentDurable | ReplyBoundary::Applied
                ) {
                    model
                        .claim_reply(model.observe_authority().unwrap())
                        .unwrap();
                }
                let successor_projection = model.projection();
                for _ in 0..2 {
                    assert_eq!(
                        model.accept_reply_ack(stale),
                        Err(CompositeError::StaleReplyClaim),
                        "{coordinates}"
                    );
                    assert_eq!(model.projection(), successor_projection, "{coordinates}");
                }
            }
            if let Some(permit) = outstanding_permit {
                let retained = model.projection();
                assert_eq!(
                    model.activate_reuse(permit),
                    Err(CompositeError::StaleReusePermit),
                    "{coordinates}"
                );
                assert_eq!(model.projection(), retained, "{coordinates}");
                let replacement = reclaim_reuse(&mut model, permit.kind()).unwrap();
                assert_eq!(replacement.actor(), 3, "{coordinates}");
                assert_eq!(replacement.binding_generation(), 3, "{coordinates}");
                assert_eq!(
                    replacement.authority_epoch(),
                    model.projection().authority_epoch,
                    "{coordinates}"
                );
                assert_ne!(replacement.nonce(), permit.nonce(), "{coordinates}");
                let reclaimed = model.projection();
                assert_eq!(
                    model.activate_reuse(permit),
                    Err(CompositeError::StaleReusePermit),
                    "{coordinates}"
                );
                assert_eq!(model.projection(), reclaimed, "{coordinates}");
                model.activate_reuse(replacement).unwrap();
            }
            assert!(model.check_invariants(), "{coordinates}");
        }
    }
}

#[test]
fn second_crash_preserves_tombstoned_reply_across_every_dma_partial_boundary() {
    for dma_boundary in DmaBoundary::ALL {
        let mut model = committed();
        model.fence_incarnation(1, 1).unwrap();
        model.tombstone_reply().unwrap();
        model.rebind(2, 2).unwrap();
        let outstanding_permit = at_dma_boundary(&mut model, dma_boundary);
        let before = model.projection();
        let physical_before = [
            model.claim(ClaimKind::QueueSlot),
            model.claim(ClaimKind::PinnedPage),
            model.claim(ClaimKind::IovaMapping),
        ];

        model.fence_incarnation(2, 2).unwrap();
        let after = model.projection();
        let coordinates = format!("tombstone,dma={dma_boundary:?}");
        assert_eq!(after.reply, ReplyState::Tombstoned, "{coordinates}");
        assert_eq!(after.dma, before.dma, "{coordinates}");
        assert_eq!(
            [
                model.claim(ClaimKind::QueueSlot),
                model.claim(ClaimKind::PinnedPage),
                model.claim(ClaimKind::IovaMapping),
            ],
            physical_before,
            "{coordinates}"
        );

        model.rebind(3, 3).unwrap();
        if let Some(permit) = outstanding_permit {
            let retained = model.projection();
            assert_eq!(
                model.activate_reuse(permit),
                Err(CompositeError::StaleReusePermit),
                "{coordinates}"
            );
            assert_eq!(model.projection(), retained, "{coordinates}");
            let replacement = reclaim_reuse(&mut model, permit.kind()).unwrap();
            assert_ne!(replacement.nonce(), permit.nonce(), "{coordinates}");
            model.activate_reuse(replacement).unwrap();
        }
        assert!(model.check_invariants(), "{coordinates}");
    }
}

#[test]
fn second_crash_preserves_completed_dma_without_releasing_its_physical_claims() {
    for reply_boundary in ReplyBoundary::ALL {
        let mut model = recovered();
        let old_reply_claim = at_reply_boundary(&mut model, reply_boundary);
        let completion = model.dma_completion_event().unwrap();
        model.accept_dma_completion(completion).unwrap();
        let physical_before = [
            model.claim(ClaimKind::QueueSlot),
            model.claim(ClaimKind::PinnedPage),
            model.claim(ClaimKind::IovaMapping),
        ];

        model.fence_incarnation(2, 2).unwrap();
        let coordinates = format!("completed-dma,reply={reply_boundary:?}");
        assert_eq!(
            model.projection().dma,
            DmaOutcome::Completed,
            "{coordinates}"
        );
        assert_eq!(
            [
                model.claim(ClaimKind::QueueSlot),
                model.claim(ClaimKind::PinnedPage),
                model.claim(ClaimKind::IovaMapping),
            ],
            physical_before,
            "{coordinates}"
        );

        model.rebind(3, 3).unwrap();
        if let Some(stale) = old_reply_claim {
            assert_eq!(
                model.accept_reply_ack(stale),
                Err(CompositeError::StaleReplyClaim),
                "{coordinates}"
            );
        }
        assert!(model.check_invariants(), "{coordinates}");
    }
}

#[test]
fn reply_discharge_interleaves_with_every_dma_retirement_prefix() {
    for reply_insert in 0..=4 {
        let mut model = recovered();
        let evidence = {
            model.advance_device_generation(2).unwrap();
            model.dma_retirement_evidence()
        };
        for step in 0..=3 {
            if step == reply_insert {
                let reply = claim_applied(&mut model);
                model.accept_reply_ack(reply).unwrap();
                model.retire_reply_output().unwrap();
            }
            match step {
                0 => model.accept_reset(evidence).unwrap(),
                1 => model.accept_irq_drain(evidence).unwrap(),
                2 => model.accept_iotlb_invalidation(evidence).unwrap(),
                3 => model.accept_allocator_release(evidence).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                model.check_invariants(),
                "reply insert at {reply_insert}, step {step}"
            );
        }
        if reply_insert == 4 {
            let reply = claim_applied(&mut model);
            model.accept_reply_ack(reply).unwrap();
            model.retire_reply_output().unwrap();
        }
        assert_eq!(model.projection().escape, EscapeState::Retired);
        model.release_effect().unwrap();
        assert_eq!(model.projection().escape, EscapeState::Released);
    }
}
