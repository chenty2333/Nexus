#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CommandRequest as Command, CoreError, EffectId,
    ExecutorCoordinate as CoreExecutorCoordinate, SettlementClaim, SettlementState,
    TransitionOutput,
};
use cser_model::{
    EffectId as OracleEffectId, ExecutorCoordinate as OracleExecutorCoordinate, ExecutorGeneration,
    ExecutorId, OperationId,
    composite_effect_oracle::{CompositeEffectOracle, ReplyState},
};
use proptest::prelude::*;
use support::{
    EFFECT_APPLY_RECEIPT_SCHEMA, EFFECT_COMPONENT, EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
    EFFECT_VERIFIER, Harness, committed_reply, digest, executor, fence_and_rebind,
    verified_apply_completion, verified_settlement_ack,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedSettlement {
    Open(u64),
    Claimed {
        claimant: OracleExecutorCoordinate,
        generation: u64,
    },
    IntentDurable {
        claimant: OracleExecutorCoordinate,
        generation: u64,
    },
    Applied {
        claimant: OracleExecutorCoordinate,
        generation: u64,
    },
    Reconcile {
        generation: u64,
        applied: bool,
    },
    Settled,
    Tombstoned,
}

fn oracle_resources() -> cser_model::composite_effect_oracle::CompositeResources {
    use cser_model::composite_effect_oracle::{CompositeResources, ResourceId};

    CompositeResources {
        reply_output: ResourceId::new(1),
        queue_slot: ResourceId::new(2),
        pinned_page: ResourceId::new(3),
        iova_mapping: ResourceId::new(4),
    }
}

fn oracle_executor(executor: CoreExecutorCoordinate) -> OracleExecutorCoordinate {
    OracleExecutorCoordinate::new(
        ExecutorId::new(executor.executor().get()).expect("property executors are non-zero"),
        ExecutorGeneration::new(executor.generation().get())
            .expect("property generations are non-zero"),
    )
}

fn oracle_effect(effect: EffectId) -> OracleEffectId {
    OracleEffectId::new(
        OperationId::new(effect.operation().get()).expect("property operations are non-zero"),
        effect.sequence(),
    )
    .expect("property effect sequences are non-zero")
}

fn normalize_settlement(harness: &Harness, effect: EffectId) -> NormalizedSettlement {
    let composite = harness.engine.composite_effect(effect).unwrap();
    if composite.authority == AuthorityState::Revoked {
        return NormalizedSettlement::Tombstoned;
    }
    match harness
        .engine
        .component(effect, EFFECT_COMPONENT)
        .expect("the one-component composite keeps its reply component")
        .settlement
    {
        SettlementState::Open { generation } => NormalizedSettlement::Open(generation),
        SettlementState::Claimed {
            claimant,
            generation,
        } => NormalizedSettlement::Claimed {
            claimant: oracle_executor(claimant),
            generation,
        },
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => NormalizedSettlement::IntentDurable {
            claimant: oracle_executor(claimant),
            generation,
        },
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => NormalizedSettlement::Applied {
            claimant: oracle_executor(claimant),
            generation,
        },
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => NormalizedSettlement::Reconcile {
            generation,
            applied,
        },
        SettlementState::Settled => NormalizedSettlement::Settled,
        SettlementState::Revoked => NormalizedSettlement::Tombstoned,
        SettlementState::Unavailable | SettlementState::NotRequired => {
            panic!("property fixture requires successor settlement")
        }
    }
}

fn normalize_oracle(oracle: &CompositeEffectOracle) -> NormalizedSettlement {
    match oracle.projection().reply {
        ReplyState::Open { generation } => NormalizedSettlement::Open(generation),
        ReplyState::Claimed {
            claimant,
            generation,
        } => NormalizedSettlement::Claimed {
            claimant,
            generation,
        },
        ReplyState::ApplyIntentDurable {
            claimant,
            generation,
        } => NormalizedSettlement::IntentDurable {
            claimant,
            generation,
        },
        ReplyState::AppliedUnacknowledged {
            claimant,
            generation,
        } => NormalizedSettlement::Applied {
            claimant,
            generation,
        },
        ReplyState::ReconciliationRequired {
            generation,
            applied,
        } => NormalizedSettlement::Reconcile {
            generation,
            applied,
        },
        ReplyState::Settled => NormalizedSettlement::Settled,
        ReplyState::Tombstoned | ReplyState::Aborted => NormalizedSettlement::Tombstoned,
        ReplyState::Staged => panic!("property fixture commits the reply component"),
    }
}

fn claim_settlement(
    harness: &mut Harness,
    effect: EffectId,
    claimant: CoreExecutorCoordinate,
) -> SettlementClaim {
    match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected component settlement claim, got {other:?}"),
    }
}

fn record_intent(harness: &mut Harness, claim: SettlementClaim, marker: u8) -> SettlementClaim {
    match harness.output(claim.record_apply_intent(digest(marker)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage claim, got {other:?}"),
    }
}

fn record_applied(harness: &mut Harness, claim: SettlementClaim, marker: u8) -> SettlementClaim {
    let evidence = verified_apply_completion(
        harness,
        &claim,
        EFFECT_VERIFIER,
        EFFECT_APPLY_RECEIPT_SCHEMA,
        digest(marker),
    );
    match harness.output(claim.record_applied(evidence).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied-stage claim, got {other:?}"),
    }
}

fn settle(harness: &mut Harness, claim: SettlementClaim, marker: u8) {
    let evidence = verified_settlement_ack(
        harness,
        &claim,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(marker),
    );
    harness.tx(claim.settle(evidence).unwrap()).unwrap();
}

fn crash_and_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: CoreExecutorCoordinate,
    successor_generation: u64,
    snapshot_marker: u64,
) -> CoreExecutorCoordinate {
    let successor = executor(effect.operation().get(), successor_generation);
    fence_and_rebind(harness, effect, crashed, successor, snapshot_marker);
    successor
}

fn crash_oracle_and_rebind(
    oracle: &mut CompositeEffectOracle,
    crashed: CoreExecutorCoordinate,
    successor: CoreExecutorCoordinate,
) {
    oracle.fence_executor(oracle_executor(crashed)).unwrap();
    oracle.rebind(oracle_executor(successor)).unwrap();
}

fn assert_settlement_matches(harness: &Harness, effect: EffectId, oracle: &CompositeEffectOracle) {
    assert_eq!(oracle.projection().effect, oracle_effect(effect));
    assert_eq!(
        normalize_settlement(harness, effect),
        normalize_oracle(oracle)
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        max_shrink_iters: 2_048,
        .. ProptestConfig::default()
    })]

    #[test]
    fn repeated_crash_windows_match_the_provider_scoped_composite_oracle(
        first_window in 0u8..3,
        second_window in 0u8..3,
    ) {
        let operation_value = 800 + u64::from(first_window) * 10 + u64::from(second_window);
        let mut harness = Harness::new();
        let (effect, origin) = committed_reply(&mut harness, operation_value);
        assert_eq!(
            harness.engine.composite_effect(effect).unwrap().component_count,
            1,
            "the property fixture must exercise a one-component composite"
        );

        let mut oracle = CompositeEffectOracle::new(
            oracle_effect(effect),
            oracle_executor(origin),
            1,
            1,
            oracle_resources(),
        );
        oracle
            .commit_reply(oracle.observe_authority().unwrap())
            .unwrap();

        let second = executor(operation_value, 2);
        fence_and_rebind(&mut harness, effect, origin, second, operation_value * 10);
        crash_oracle_and_rebind(&mut oracle, origin, second);

        let mut claim = claim_settlement(&mut harness, effect, second);
        let mut oracle_claim = oracle
            .claim_reply(oracle.observe_authority().unwrap())
            .unwrap();
        assert_settlement_matches(&harness, effect, &oracle);

        if first_window >= 1 {
            claim = record_intent(&mut harness, claim, 101);
            oracle.record_reply_apply_intent(oracle_claim).unwrap();
            assert_settlement_matches(&harness, effect, &oracle);
        }
        if first_window >= 2 {
            claim = record_applied(&mut harness, claim, 102);
            oracle.record_reply_applied(oracle_claim).unwrap();
            assert_settlement_matches(&harness, effect, &oracle);
        }
        let _lost_with_second_executor = claim;

        let third = crash_and_rebind(
            &mut harness,
            effect,
            second,
            3,
            operation_value * 10 + 1,
        );
        crash_oracle_and_rebind(&mut oracle, second, third);
        assert_settlement_matches(&harness, effect, &oracle);

        let mut claim = claim_settlement(&mut harness, effect, third);
        oracle_claim = oracle
            .claim_reply(oracle.observe_authority().unwrap())
            .unwrap();
        assert_settlement_matches(&harness, effect, &oracle);

        match first_window {
            0 => {
                if second_window >= 1 {
                    claim = record_intent(&mut harness, claim, 103);
                    oracle.record_reply_apply_intent(oracle_claim).unwrap();
                }
                if second_window >= 2 {
                    claim = record_applied(&mut harness, claim, 104);
                    oracle.record_reply_applied(oracle_claim).unwrap();
                }
            }
            1 => {
                if second_window >= 1 {
                    claim = record_applied(&mut harness, claim, 105);
                    oracle.record_reply_applied(oracle_claim).unwrap();
                }
                if second_window >= 2 {
                    settle(&mut harness, claim, 106);
                    oracle.accept_reply_ack(oracle_claim).unwrap();
                    let fourth = crash_and_rebind(
                        &mut harness,
                        effect,
                        third,
                        4,
                        operation_value * 10 + 2,
                    );
                    crash_oracle_and_rebind(&mut oracle, third, fourth);
                    assert_settlement_matches(&harness, effect, &oracle);
                    let before = harness.engine.projection_digest();
                    let revision = harness.engine.revision();
                    prop_assert_eq!(
                        harness.tx(Command::ClaimComponentSettlement {
                            effect,
                            component: EFFECT_COMPONENT,
                            claimant: fourth,
                        }),
                        Err(CoreError::GateClosed)
                    );
                    prop_assert_eq!(harness.engine.projection_digest(), before);
                    prop_assert_eq!(harness.engine.revision(), revision);
                    prop_assert_eq!(
                        oracle.claim_reply(oracle.observe_authority().unwrap()),
                        Err(cser_model::composite_effect_oracle::CompositeError::WrongComponentState)
                    );
                    return Ok(());
                }
            }
            2 => {
                if second_window >= 1 {
                    settle(&mut harness, claim, 107);
                    oracle.accept_reply_ack(oracle_claim).unwrap();
                    let fourth = crash_and_rebind(
                        &mut harness,
                        effect,
                        third,
                        4,
                        operation_value * 10 + 2,
                    );
                    crash_oracle_and_rebind(&mut oracle, third, fourth);
                    assert_settlement_matches(&harness, effect, &oracle);
                    let before = harness.engine.projection_digest();
                    let revision = harness.engine.revision();
                    prop_assert_eq!(
                        harness.tx(Command::ClaimComponentSettlement {
                            effect,
                            component: EFFECT_COMPONENT,
                            claimant: fourth,
                        }),
                        Err(CoreError::GateClosed)
                    );
                    prop_assert_eq!(harness.engine.projection_digest(), before);
                    prop_assert_eq!(harness.engine.revision(), revision);
                    prop_assert_eq!(
                        oracle.claim_reply(oracle.observe_authority().unwrap()),
                        Err(cser_model::composite_effect_oracle::CompositeError::WrongComponentState)
                    );
                    return Ok(());
                }
            }
            _ => unreachable!(),
        }
        assert_settlement_matches(&harness, effect, &oracle);
        let _lost_with_third_executor = claim;

        let fourth = crash_and_rebind(
            &mut harness,
            effect,
            third,
            4,
            operation_value * 10 + 2,
        );
        crash_oracle_and_rebind(&mut oracle, third, fourth);
        assert_settlement_matches(&harness, effect, &oracle);
        let _next_claim = claim_settlement(&mut harness, effect, fourth);
        oracle
            .claim_reply(oracle.observe_authority().unwrap())
            .unwrap();
        assert_settlement_matches(&harness, effect, &oracle);
    }
}
