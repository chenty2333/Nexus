//! Bounded Loom schedules over the independent composite-effect oracle.
//!
//! Every test executes the real safe-Rust oracle behind a modeled outer writer
//! mutex.  This checks gate winner sets, not a production lock implementation,
//! device memory ordering, or hardware DMA quiescence.

use cser_model::composite_effect_oracle::{
    ClaimKind, ClaimState, ComponentId, CompositeAuthority, CompositeEffectOracle, CompositeError,
    CompositeResources, DmaEvent, DmaOutcome, EscapeState, ReplyClaim, ReplyState, ResourceId,
    ReusePermit,
};
use cser_model::{EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId, OperationId};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
};

fn executor(id: u64, generation: u64) -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        ExecutorId::new(id).unwrap(),
        ExecutorGeneration::new(generation).unwrap(),
    )
}

fn resources() -> CompositeResources {
    CompositeResources {
        reply_output: ResourceId::new(11),
        queue_slot: ResourceId::new(12),
        pinned_page: ResourceId::new(13),
        iova_mapping: ResourceId::new(14),
    }
}

fn staged() -> CompositeEffectOracle {
    CompositeEffectOracle::new(
        EffectId::new(OperationId::new(0xce01).unwrap(), 1).unwrap(),
        executor(1, 1),
        1,
        1,
        resources(),
    )
}

fn committed() -> CompositeEffectOracle {
    let mut oracle = staged();
    let authority = oracle.observe_authority().unwrap();
    oracle.commit_dma(authority).unwrap();
    oracle.commit_reply(authority).unwrap();
    oracle
}

fn recovered() -> CompositeEffectOracle {
    let mut oracle = committed();
    oracle.fence_executor(executor(1, 1)).unwrap();
    oracle.rebind(executor(1, 2)).unwrap();
    oracle
}

#[test]
fn loom_rebind_requires_origin_id_and_newer_generation() {
    model(|| {
        let mut oracle = staged();
        oracle.fence_executor(executor(1, 1)).unwrap();
        let before = oracle.projection();

        assert_eq!(
            oracle.rebind(executor(9, 2)),
            Err(CompositeError::StaleAuthority)
        );
        assert_eq!(oracle.projection(), before);
        assert_eq!(
            oracle.rebind(executor(1, 1)),
            Err(CompositeError::StaleAuthority)
        );
        assert_eq!(oracle.projection(), before);
        oracle.rebind(executor(1, 2)).unwrap();
        assert_eq!(oracle.projection().live_executor, Some(executor(1, 2)));
        assert!(oracle.check_invariants());
    });
}

fn issue_reuse(
    oracle: &mut CompositeEffectOracle,
    kind: ClaimKind,
    next_generation: u64,
) -> Result<ReusePermit, CompositeError> {
    let authority = oracle.observe_authority()?;
    oracle.issue_reuse_permit(authority, kind, next_generation)
}

fn reclaim_reuse(
    oracle: &mut CompositeEffectOracle,
    kind: ClaimKind,
) -> Result<ReusePermit, CompositeError> {
    let authority = oracle.observe_authority()?;
    oracle.reclaim_reuse_permit(authority, kind)
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

#[derive(Clone, Copy)]
struct PermitBearer {
    permit: ReusePermit,
    live: bool,
}

#[derive(Clone, Copy)]
struct DmaBoundaryState {
    completion_before_reset: DmaEvent,
    permits: [Option<PermitBearer>; 3],
}

fn at_reply_boundary(
    oracle: &mut CompositeEffectOracle,
    boundary: ReplyBoundary,
) -> Option<ReplyClaim> {
    if matches!(boundary, ReplyBoundary::Open) {
        return None;
    }
    let authority = oracle.observe_authority().unwrap();
    let claim = oracle.claim_reply(authority).unwrap();
    if matches!(
        boundary,
        ReplyBoundary::IntentDurable
            | ReplyBoundary::Applied
            | ReplyBoundary::Settled
            | ReplyBoundary::Retired
    ) {
        oracle.record_reply_apply_intent(claim).unwrap();
    }
    if matches!(
        boundary,
        ReplyBoundary::Applied | ReplyBoundary::Settled | ReplyBoundary::Retired
    ) {
        oracle.record_reply_applied(claim).unwrap();
    }
    if matches!(boundary, ReplyBoundary::Settled | ReplyBoundary::Retired) {
        oracle.accept_reply_ack(claim).unwrap();
    }
    if matches!(boundary, ReplyBoundary::Retired) {
        oracle.retire_reply_output().unwrap();
    }
    Some(claim)
}

fn at_dma_boundary(oracle: &mut CompositeEffectOracle, boundary: DmaBoundary) -> DmaBoundaryState {
    let completion_before_reset = oracle.dma_completion_event().unwrap();
    let mut permits = [None; 3];
    if matches!(boundary, DmaBoundary::Pending) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }

    oracle.advance_device_generation(2).unwrap();
    let evidence = oracle.dma_retirement_evidence();
    oracle.accept_reset(evidence).unwrap();
    if matches!(boundary, DmaBoundary::Reset) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }

    oracle.accept_irq_drain(evidence).unwrap();
    if matches!(boundary, DmaBoundary::QueueDischarged) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    let queue = issue_reuse(oracle, ClaimKind::QueueSlot, 2).unwrap();
    permits[0] = Some(PermitBearer {
        permit: queue,
        live: true,
    });
    if matches!(boundary, DmaBoundary::QueuePermitIssued) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    oracle.activate_reuse(queue).unwrap();
    permits[0].as_mut().unwrap().live = false;
    if matches!(boundary, DmaBoundary::QueueReused) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }

    oracle.accept_iotlb_invalidation(evidence).unwrap();
    if matches!(boundary, DmaBoundary::IovaDischarged) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    let iova = issue_reuse(oracle, ClaimKind::IovaMapping, 2).unwrap();
    permits[1] = Some(PermitBearer {
        permit: iova,
        live: true,
    });
    if matches!(boundary, DmaBoundary::IovaPermitIssued) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    oracle.activate_reuse(iova).unwrap();
    permits[1].as_mut().unwrap().live = false;
    if matches!(boundary, DmaBoundary::IovaReused) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }

    oracle.accept_allocator_release(evidence).unwrap();
    if matches!(boundary, DmaBoundary::PageDischarged) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    let page = issue_reuse(oracle, ClaimKind::PinnedPage, 2).unwrap();
    permits[2] = Some(PermitBearer {
        permit: page,
        live: true,
    });
    if matches!(boundary, DmaBoundary::PagePermitIssued) {
        return DmaBoundaryState {
            completion_before_reset,
            permits,
        };
    }
    oracle.activate_reuse(page).unwrap();
    permits[2].as_mut().unwrap().live = false;
    DmaBoundaryState {
        completion_before_reset,
        permits,
    }
}

fn reply_after_fence(reply: ReplyState) -> ReplyState {
    match reply {
        ReplyState::Claimed { generation, .. } => ReplyState::Open {
            generation: generation + 1,
        },
        ReplyState::ApplyIntentDurable { generation, .. } => ReplyState::ReconciliationRequired {
            generation: generation + 1,
            applied: false,
        },
        ReplyState::AppliedUnacknowledged { generation, .. } => {
            ReplyState::ReconciliationRequired {
                generation: generation + 1,
                applied: true,
            }
        }
        state => state,
    }
}

#[test]
fn loom_dma_commit_and_fence_preserve_the_only_linearized_commit() {
    model(|| {
        let initial = staged();
        let authority = initial.observe_authority().unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let commit_oracle = Arc::clone(&shared);
        let commit = thread::spawn(move || commit_oracle.lock().unwrap().commit_dma(authority));
        let fence_oracle = Arc::clone(&shared);
        let fence =
            thread::spawn(move || fence_oracle.lock().unwrap().fence_executor(executor(1, 1)));

        let commit_result = commit.join().unwrap();
        assert_eq!(fence.join().unwrap(), Ok(()));
        let oracle = shared.lock().unwrap();
        let projection = oracle.projection();
        assert_eq!(projection.authority, CompositeAuthority::Fenced);
        match commit_result {
            Ok(()) => assert_eq!(projection.dma, DmaOutcome::Pending),
            Err(CompositeError::WrongAuthorityState) => {
                assert_eq!(projection.dma, DmaOutcome::Staged);
            }
            other => panic!("unexpected commit/fence outcome: {other:?}"),
        }
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_reply_commit_and_fence_preserve_the_only_linearized_commit() {
    model(|| {
        let initial = staged();
        let authority = initial.observe_authority().unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let commit_oracle = Arc::clone(&shared);
        let commit = thread::spawn(move || commit_oracle.lock().unwrap().commit_reply(authority));
        let fence_oracle = Arc::clone(&shared);
        let fence =
            thread::spawn(move || fence_oracle.lock().unwrap().fence_executor(executor(1, 1)));

        let commit_result = commit.join().unwrap();
        assert_eq!(fence.join().unwrap(), Ok(()));
        let oracle = shared.lock().unwrap();
        let projection = oracle.projection();
        assert_eq!(projection.authority, CompositeAuthority::Fenced);
        match commit_result {
            Ok(()) => assert_eq!(projection.reply, ReplyState::Open { generation: 1 }),
            Err(CompositeError::WrongAuthorityState) => {
                assert_eq!(projection.reply, ReplyState::Staged);
            }
            other => panic!("unexpected reply commit/fence outcome: {other:?}"),
        }
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_adopt_and_revoke_have_one_parent_epoch_winner() {
    model(|| {
        let mut initial = staged();
        initial.fence_executor(executor(1, 1)).unwrap();
        initial.rebind(executor(1, 2)).unwrap();
        let observed = initial.observe_authority().unwrap();
        let revision = initial.projection().revision;
        let shared = Arc::new(Mutex::new(initial));

        let adopt_oracle = Arc::clone(&shared);
        let adopt = thread::spawn(move || adopt_oracle.lock().unwrap().adopt_effect(observed));
        let revoke_oracle = Arc::clone(&shared);
        let revoke = thread::spawn(move || revoke_oracle.lock().unwrap().begin_revoke(observed));

        let adopt_result = adopt.join().unwrap();
        let revoke_result = revoke.join().unwrap();
        let oracle = shared.lock().unwrap();
        let projection = oracle.projection();
        assert_eq!(projection.revision, revision + 1);
        match (adopt_result, revoke_result) {
            (Ok(()), Err(CompositeError::StaleAuthority)) => {
                assert_eq!(projection.authority, CompositeAuthority::Active);
                assert_eq!(
                    oracle.claim(ClaimKind::ReplyOutput).state,
                    ClaimState::Staged
                );
                assert_eq!(oracle.claim(ClaimKind::QueueSlot).state, ClaimState::Staged);
            }
            (Err(CompositeError::StaleAuthority), Ok(())) => {
                assert_eq!(projection.authority, CompositeAuthority::Revoked);
                assert_eq!(
                    oracle.claim(ClaimKind::ReplyOutput).state,
                    ClaimState::Discharged
                );
                assert_eq!(
                    oracle.claim(ClaimKind::QueueSlot).state,
                    ClaimState::Discharged
                );
            }
            other => panic!("adopt/revoke did not have one winner: {other:?}"),
        }
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_second_crash_preserves_every_reply_dma_partial_state() {
    for reply_boundary in ReplyBoundary::ALL {
        for dma_boundary in DmaBoundary::ALL {
            let mut builder = loom::model::Builder::new();
            builder.max_threads = 3;
            builder.preemption_bound = Some(2);
            builder.check(move || {
                let mut initial = recovered();
                let old_reply_claim = at_reply_boundary(&mut initial, reply_boundary);
                let dma_state = at_dma_boundary(&mut initial, dma_boundary);
                let before = initial.projection();
                let reply_component_before = initial.component(ComponentId::Reply);
                let dma_component_before = initial.component(ComponentId::Dma);
                let stale_authority = initial.observe_authority().unwrap();
                let shared = Arc::new(Mutex::new(initial));

                let stale_oracle = Arc::clone(&shared);
                let stale = thread::spawn(move || {
                    stale_oracle.lock().unwrap().claim_reply(
                        stale_authority.with_operation(OperationId::new(0xdead).unwrap()),
                    )
                });
                let crash_oracle = Arc::clone(&shared);
                let crash = thread::spawn(move || {
                    crash_oracle.lock().unwrap().fence_executor(executor(1, 2))
                });

                assert!(matches!(
                    stale.join().unwrap(),
                    Err(CompositeError::StaleAuthority | CompositeError::WrongAuthorityState)
                ));
                assert_eq!(crash.join().unwrap(), Ok(()));

                let mut oracle = shared.lock().unwrap();
                let fenced = oracle.projection();
                let coordinates = format!("reply={reply_boundary:?}, dma={dma_boundary:?}");
                assert_eq!(
                    fenced.authority,
                    CompositeAuthority::Fenced,
                    "{coordinates}"
                );
                assert_eq!(fenced.authority_epoch, before.authority_epoch + 1);
                assert_eq!(fenced.crash_generation, before.crash_generation + 1);
                assert_eq!(fenced.live_executor, None, "{coordinates}");
                assert_eq!(fenced.revision, before.revision + 1, "{coordinates}");
                assert_eq!(
                    fenced.reply,
                    reply_after_fence(before.reply),
                    "{coordinates}"
                );
                assert_eq!(fenced.dma, before.dma, "{coordinates}");
                assert_eq!(fenced.escape, before.escape, "{coordinates}");
                assert_eq!(
                    (
                        fenced.enrolled_device_generation,
                        fenced.active_device_generation,
                        fenced.reset_accepted,
                        fenced.irq_drained,
                        fenced.iotlb_invalidated,
                        fenced.allocator_released,
                    ),
                    (
                        before.enrolled_device_generation,
                        before.active_device_generation,
                        before.reset_accepted,
                        before.irq_drained,
                        before.iotlb_invalidated,
                        before.allocator_released,
                    ),
                    "{coordinates}"
                );
                assert_eq!(fenced.claims, before.claims, "{coordinates}");
                assert_eq!(
                    oracle.component(ComponentId::Reply),
                    reply_component_before,
                    "{coordinates}"
                );
                assert_eq!(
                    oracle.component(ComponentId::Dma),
                    dma_component_before,
                    "{coordinates}"
                );
                assert_ne!(fenced.escape, EscapeState::Released, "{coordinates}");
                assert!(oracle.check_invariants(), "{coordinates}");

                oracle.rebind(executor(1, 3)).unwrap();
                let rebound = oracle.projection();
                assert_eq!(rebound.authority, CompositeAuthority::Fenced);
                assert_eq!(rebound.authority_epoch, fenced.authority_epoch);
                assert_eq!(rebound.crash_generation, fenced.crash_generation);
                assert_eq!(rebound.live_executor, Some(executor(1, 3)), "{coordinates}");
                assert_eq!(rebound.revision, fenced.revision + 1, "{coordinates}");
                assert_eq!(rebound.reply, fenced.reply, "{coordinates}");
                assert_eq!(rebound.dma, fenced.dma, "{coordinates}");
                assert_eq!(rebound.escape, fenced.escape, "{coordinates}");
                assert_eq!(rebound.claims, fenced.claims, "{coordinates}");

                let unchanged = oracle.projection();
                assert_eq!(
                    oracle.claim_reply(stale_authority),
                    Err(CompositeError::StaleAuthority),
                    "{coordinates}"
                );
                assert_eq!(oracle.projection(), unchanged, "{coordinates}");

                if let Some(claim) = old_reply_claim {
                    assert_eq!(
                        oracle.accept_reply_ack(claim),
                        Err(CompositeError::StaleReplyClaim),
                        "{coordinates}"
                    );
                    assert_eq!(oracle.projection(), unchanged, "{coordinates}");
                }

                let late_completion = if matches!(dma_boundary, DmaBoundary::Pending) {
                    dma_state.completion_before_reset.with_device_generation(
                        dma_state.completion_before_reset.device_generation() + 1,
                    )
                } else {
                    dma_state.completion_before_reset
                };
                assert_eq!(
                    oracle.accept_dma_completion(late_completion),
                    Err(CompositeError::StaleDeviceEvidence),
                    "{coordinates}"
                );
                assert_eq!(oracle.projection(), unchanged, "{coordinates}");

                for bearer in dma_state.permits.into_iter().flatten() {
                    assert_eq!(
                        oracle.activate_reuse(bearer.permit),
                        Err(CompositeError::StaleReusePermit),
                        "{coordinates}"
                    );
                    assert_eq!(oracle.projection(), unchanged, "{coordinates}");
                    assert_eq!(
                        oracle.claim(bearer.permit.kind()).pending_reuse.is_some(),
                        bearer.live,
                        "{coordinates}"
                    );
                }

                if rebound.escape != EscapeState::Retired {
                    assert_eq!(
                        oracle.release_effect(),
                        Err(CompositeError::EffectNotRetired),
                        "{coordinates}"
                    );
                    assert_eq!(oracle.projection(), unchanged, "{coordinates}");
                }
                assert_ne!(
                    oracle.projection().escape,
                    EscapeState::Released,
                    "{coordinates}"
                );
                assert_eq!(
                    oracle.component(ComponentId::Dma),
                    dma_component_before,
                    "{coordinates}"
                );
                assert_eq!(
                    [
                        oracle.claim(ClaimKind::QueueSlot),
                        oracle.claim(ClaimKind::PinnedPage),
                        oracle.claim(ClaimKind::IovaMapping),
                    ],
                    [before.claims[1], before.claims[2], before.claims[3],],
                    "{coordinates}"
                );
                assert!(oracle.check_invariants(), "{coordinates}");
            });
        }
    }
}

#[test]
fn loom_successor_must_reclaim_a_pending_reuse_reservation_after_crash() {
    for kind in [
        ClaimKind::QueueSlot,
        ClaimKind::IovaMapping,
        ClaimKind::PinnedPage,
    ] {
        model(move || {
            let mut initial = recovered();
            initial.advance_device_generation(2).unwrap();
            let evidence = initial.dma_retirement_evidence();
            initial.accept_reset(evidence).unwrap();
            initial.accept_irq_drain(evidence).unwrap();
            if matches!(kind, ClaimKind::IovaMapping | ClaimKind::PinnedPage) {
                initial.accept_iotlb_invalidation(evidence).unwrap();
            }
            if matches!(kind, ClaimKind::PinnedPage) {
                initial.accept_allocator_release(evidence).unwrap();
            }
            let old_permit = issue_reuse(&mut initial, kind, 2).unwrap();
            let retained_before = initial.claim(kind);
            let reply_before = initial.component(ComponentId::Reply);
            let shared = Arc::new(Mutex::new(initial));

            let observer_oracle = Arc::clone(&shared);
            let observer = thread::spawn(move || observer_oracle.lock().unwrap().claim(kind));
            let crash_oracle = Arc::clone(&shared);
            let crash =
                thread::spawn(move || crash_oracle.lock().unwrap().fence_executor(executor(1, 2)));

            assert_eq!(observer.join().unwrap(), retained_before);
            assert_eq!(crash.join().unwrap(), Ok(()));
            let mut oracle = shared.lock().unwrap();
            let fenced = oracle.projection();
            assert_eq!(oracle.claim(kind), retained_before);
            assert_eq!(
                oracle.activate_reuse(old_permit),
                Err(CompositeError::StaleReusePermit)
            );
            assert_eq!(oracle.projection(), fenced);

            oracle.rebind(executor(1, 3)).unwrap();
            let rebound = oracle.projection();
            assert_eq!(
                oracle.activate_reuse(old_permit),
                Err(CompositeError::StaleReusePermit)
            );
            assert_eq!(oracle.projection(), rebound);

            let replacement = reclaim_reuse(&mut oracle, kind).unwrap();
            assert_eq!(replacement.operation(), old_permit.operation());
            assert_eq!(replacement.kind(), old_permit.kind());
            assert_eq!(replacement.resource(), old_permit.resource());
            assert_eq!(
                replacement.retired_generation(),
                old_permit.retired_generation()
            );
            assert_eq!(replacement.next_generation(), old_permit.next_generation());
            assert_eq!(replacement.actor(), executor(1, 3));
            assert_eq!(
                replacement.authority_epoch(),
                oracle.projection().authority_epoch
            );
            assert_ne!(replacement.nonce(), old_permit.nonce());
            assert_eq!(oracle.component(ComponentId::Reply), reply_before);
            assert_eq!(oracle.claim(kind).state, retained_before.state);
            assert_eq!(
                oracle.claim(kind).pending_reuse.unwrap().actor,
                replacement.actor()
            );
            let reclaimed = oracle.projection();
            assert_eq!(
                oracle.activate_reuse(old_permit),
                Err(CompositeError::StaleReusePermit)
            );
            assert_eq!(oracle.projection(), reclaimed);

            oracle.activate_reuse(replacement).unwrap();
            assert_eq!(
                oracle.claim(kind).state,
                ClaimState::Reused { generation: 2 }
            );
            assert_eq!(oracle.claim(kind).pending_reuse, None);
            assert_eq!(oracle.component(ComponentId::Reply), reply_before);
            assert!(oracle.check_invariants());
        });
    }
}

#[test]
fn loom_stale_reply_ack_cannot_mutate_a_new_claimant_or_duplicate_settlement() {
    model(|| {
        let mut initial = recovered();
        let authority = initial.observe_authority().unwrap();
        let old_claim = initial.claim_reply(authority).unwrap();
        initial.record_reply_apply_intent(old_claim).unwrap();
        initial.record_reply_applied(old_claim).unwrap();
        initial.fence_executor(executor(1, 2)).unwrap();
        initial.rebind(executor(1, 3)).unwrap();
        let new_claim = initial
            .claim_reply(initial.observe_authority().unwrap())
            .unwrap();
        let physical = [
            initial.claim(ClaimKind::QueueSlot),
            initial.claim(ClaimKind::PinnedPage),
            initial.claim(ClaimKind::IovaMapping),
        ];
        let shared = Arc::new(Mutex::new(initial));

        let stale_oracle = Arc::clone(&shared);
        let stale = thread::spawn(move || stale_oracle.lock().unwrap().accept_reply_ack(old_claim));
        let exact_oracle = Arc::clone(&shared);
        let exact = thread::spawn(move || exact_oracle.lock().unwrap().accept_reply_ack(new_claim));

        assert_eq!(stale.join().unwrap(), Err(CompositeError::StaleReplyClaim));
        assert_eq!(exact.join().unwrap(), Ok(()));
        let mut oracle = shared.lock().unwrap();
        assert_eq!(oracle.projection().authority, CompositeAuthority::Fenced);
        assert_eq!(oracle.projection().reply, ReplyState::Settled);
        assert_eq!(
            [
                oracle.claim(ClaimKind::QueueSlot),
                oracle.claim(ClaimKind::PinnedPage),
                oracle.claim(ClaimKind::IovaMapping),
            ],
            physical
        );
        let settled = oracle.projection();
        for duplicate in [old_claim, new_claim] {
            assert_eq!(
                oracle.accept_reply_ack(duplicate),
                Err(CompositeError::StaleReplyClaim)
            );
            assert_eq!(oracle.projection(), settled);
        }
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_old_irq_and_reset_choose_completed_or_indeterminate_once() {
    model(|| {
        let initial = committed();
        let old_irq = initial.dma_completion_event().unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let irq_oracle = Arc::clone(&shared);
        let irq = thread::spawn(move || irq_oracle.lock().unwrap().accept_dma_completion(old_irq));
        let reset_oracle = Arc::clone(&shared);
        let reset = thread::spawn(move || {
            let mut oracle = reset_oracle.lock().unwrap();
            oracle.advance_device_generation(2)?;
            let evidence = oracle.dma_retirement_evidence();
            oracle.accept_reset(evidence)
        });

        let irq_result = irq.join().unwrap();
        assert_eq!(reset.join().unwrap(), Ok(()));
        let oracle = shared.lock().unwrap();
        assert!(oracle.projection().reset_accepted);
        match irq_result {
            Ok(()) => assert_eq!(oracle.projection().dma, DmaOutcome::Completed),
            Err(CompositeError::StaleDeviceEvidence) => {
                assert_eq!(oracle.projection().dma, DmaOutcome::IndeterminateAfterReset);
            }
            other => panic!("unexpected IRQ/reset outcome: {other:?}"),
        }
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_reuse_permit_requires_irq_drain_to_linearize_first() {
    model(|| {
        let mut initial = recovered();
        initial.advance_device_generation(2).unwrap();
        let evidence = initial.dma_retirement_evidence();
        initial.accept_reset(evidence).unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let drain_oracle = Arc::clone(&shared);
        let drain = thread::spawn(move || drain_oracle.lock().unwrap().accept_irq_drain(evidence));
        let permit_oracle = Arc::clone(&shared);
        let permit = thread::spawn(move || {
            let mut oracle = permit_oracle.lock().unwrap();
            issue_reuse(&mut oracle, ClaimKind::QueueSlot, 2)
        });

        assert_eq!(drain.join().unwrap(), Ok(()));
        let permit_result = permit.join().unwrap();
        let oracle = shared.lock().unwrap();
        match permit_result {
            Ok(permit) => {
                assert_eq!(permit.kind(), ClaimKind::QueueSlot);
                assert_eq!(
                    oracle.claim(ClaimKind::QueueSlot).state,
                    ClaimState::ReusePermitted { next_generation: 2 }
                );
            }
            Err(CompositeError::ClaimStillLive) => {
                assert_eq!(
                    oracle.claim(ClaimKind::QueueSlot).state,
                    ClaimState::Discharged
                );
            }
            other => panic!("unexpected drain/reuse outcome: {other:?}"),
        }
        assert_eq!(oracle.claim(ClaimKind::ReplyOutput).state, ClaimState::Live);
        assert!(oracle.check_invariants());
    });
}

#[test]
fn loom_quarantined_composite_does_not_freeze_an_unrelated_effect() {
    model(|| {
        let quarantined = committed();
        let unrelated_resources = CompositeResources {
            reply_output: ResourceId::new(101),
            queue_slot: ResourceId::new(102),
            pinned_page: ResourceId::new(103),
            iova_mapping: ResourceId::new(104),
        };
        let unrelated = CompositeEffectOracle::new(
            EffectId::new(OperationId::new(0xce02).unwrap(), 1).unwrap(),
            executor(7, 9),
            1,
            1,
            unrelated_resources,
        );
        let unrelated_authority = unrelated.observe_authority().unwrap();
        let quarantined = Arc::new(Mutex::new(quarantined));
        let unrelated = Arc::new(Mutex::new(unrelated));

        let fence_oracle = Arc::clone(&quarantined);
        let fence =
            thread::spawn(move || fence_oracle.lock().unwrap().fence_executor(executor(1, 1)));
        let progress_oracle = Arc::clone(&unrelated);
        let progress = thread::spawn(move || {
            let mut oracle = progress_oracle.lock().unwrap();
            oracle.commit_reply(unrelated_authority)?;
            oracle.commit_dma(unrelated_authority)
        });

        assert_eq!(fence.join().unwrap(), Ok(()));
        assert_eq!(progress.join().unwrap(), Ok(()));
        let quarantined = quarantined.lock().unwrap();
        let unrelated = unrelated.lock().unwrap();
        assert_eq!(
            quarantined.projection().authority,
            CompositeAuthority::Fenced
        );
        assert_eq!(
            unrelated.projection().reply,
            ReplyState::Open { generation: 1 }
        );
        assert_eq!(unrelated.projection().dma, DmaOutcome::Pending);
        assert!(quarantined.check_invariants());
        assert!(unrelated.check_invariants());
    });
}
