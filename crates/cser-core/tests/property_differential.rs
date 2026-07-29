#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CommandRequest as Command, CoreError, EffectId, PrincipalIncarnation,
    SettlementClaim, SettlementState, TransitionOutput,
};
use cser_model::core_rebaseline_oracle::{OracleSettlement, SettlementOracle};
use proptest::prelude::*;
use support::{
    Harness, committed_reply, digest, fence_and_rebind, principal, snapshot, snapshot_command,
    verified_apply_completion, verified_settlement_ack,
};

fn normalize_settlement(harness: &Harness, effect: EffectId) -> OracleSettlement {
    let estate = harness.engine.estate(effect).unwrap();
    if estate.authority == AuthorityState::Revoked {
        return OracleSettlement::Revoked;
    }
    match estate.settlement {
        SettlementState::Open { generation } => OracleSettlement::Open { generation },
        SettlementState::Claimed {
            claimant,
            generation,
        } => OracleSettlement::Claimed {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => OracleSettlement::ApplyIntentDurable {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => OracleSettlement::AppliedUnacknowledged {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => OracleSettlement::ReconciliationRequired {
            generation,
            applied,
        },
        SettlementState::Settled => OracleSettlement::Settled,
        SettlementState::Revoked => OracleSettlement::Revoked,
        SettlementState::Unavailable | SettlementState::NotRequired => {
            panic!("property fixture requires successor settlement")
        }
    }
}

fn claim_settlement(
    harness: &mut Harness,
    effect: EffectId,
    claimant: PrincipalIncarnation,
) -> SettlementClaim {
    match harness.output(Command::ClaimSettlement { effect, claimant }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
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
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(marker),
    );
    harness.tx(claim.settle(evidence).unwrap()).unwrap();
}

fn crash_and_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: PrincipalIncarnation,
    binding_generation: u64,
    successor_generation: u64,
    snapshot_marker: u64,
) -> PrincipalIncarnation {
    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed,
            binding_generation,
        })
        .unwrap();
    let successor = principal(effect.root().get(), successor_generation);
    let snapshot_id = snapshot(snapshot_marker);
    let record = snapshot_command(harness, effect.root(), snapshot_id);
    harness.tx(record).unwrap();
    harness
        .tx(Command::Ready {
            root: effect.root(),
            snapshot: snapshot_id,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            root: effect.root(),
            snapshot: snapshot_id,
            successor,
            binding_generation: successor_generation,
        })
        .unwrap();
    successor
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        max_shrink_iters: 2_048,
        .. ProptestConfig::default()
    })]

    #[test]
    fn repeated_crash_windows_match_the_independent_settlement_oracle(
        first_window in 0u8..3,
        second_window in 0u8..3,
    ) {
        let root_value = 800 + u64::from(first_window) * 10 + u64::from(second_window);
        let mut harness = Harness::new();
        let (effect, origin) = committed_reply(&mut harness, root_value);
        let second = principal(root_value, 2);
        fence_and_rebind(&mut harness, effect, origin, second, 1, 2, root_value * 10);

        let mut oracle = SettlementOracle::open(1);
        let mut claim = claim_settlement(&mut harness, effect, second);
        oracle.claim(2).unwrap();
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());

        if first_window >= 1 {
            claim = record_intent(&mut harness, claim, 101);
            oracle.record_apply_intent(2).unwrap();
            prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
        }
        if first_window >= 2 {
            claim = record_applied(&mut harness, claim, 102);
            oracle.record_applied(2).unwrap();
            prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
        }
        let _lost_with_second_incarnation = claim;

        let third = crash_and_rebind(&mut harness, effect, second, 2, 3, root_value * 10 + 1);
        oracle.crash();
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());

        let mut claim = claim_settlement(&mut harness, effect, third);
        oracle.claim(3).unwrap();
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());

        match first_window {
            0 => {
                if second_window >= 1 {
                    claim = record_intent(&mut harness, claim, 103);
                    oracle.record_apply_intent(3).unwrap();
                }
                if second_window >= 2 {
                    claim = record_applied(&mut harness, claim, 104);
                    oracle.record_applied(3).unwrap();
                }
            }
            1 => {
                if second_window >= 1 {
                    claim = record_applied(&mut harness, claim, 105);
                    oracle.record_applied(3).unwrap();
                }
                if second_window >= 2 {
                    settle(&mut harness, claim, 106);
                    oracle.settle(3).unwrap();
                    let fourth =
                        crash_and_rebind(&mut harness, effect, third, 3, 4, root_value * 10 + 2);
                    oracle.crash();
                    prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
                    let before = harness.engine.projection_digest();
                    let revision = harness.engine.revision();
                    prop_assert_eq!(
                        harness.tx(Command::ClaimSettlement {
                            effect,
                            claimant: fourth,
                        }),
                        Err(CoreError::GateClosed)
                    );
                    prop_assert_eq!(harness.engine.projection_digest(), before);
                    prop_assert_eq!(harness.engine.revision(), revision);
                    return Ok(());
                }
            }
            2 => {
                if second_window >= 1 {
                    settle(&mut harness, claim, 107);
                    oracle.settle(3).unwrap();
                    let fourth =
                        crash_and_rebind(&mut harness, effect, third, 3, 4, root_value * 10 + 2);
                    oracle.crash();
                    prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
                    let before = harness.engine.projection_digest();
                    let revision = harness.engine.revision();
                    prop_assert_eq!(
                        harness.tx(Command::ClaimSettlement {
                            effect,
                            claimant: fourth,
                        }),
                        Err(CoreError::GateClosed)
                    );
                    prop_assert_eq!(harness.engine.projection_digest(), before);
                    prop_assert_eq!(harness.engine.revision(), revision);
                    return Ok(());
                }
            }
            _ => unreachable!(),
        }
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
        let _lost_with_third_incarnation = claim;

        let fourth = crash_and_rebind(&mut harness, effect, third, 3, 4, root_value * 10 + 2);
        oracle.crash();
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
        let _next_claim = claim_settlement(&mut harness, effect, fourth);
        oracle.claim(4).unwrap();
        prop_assert_eq!(normalize_settlement(&harness, effect), oracle.projection());
    }
}
