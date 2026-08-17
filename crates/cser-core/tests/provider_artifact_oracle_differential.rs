//! Small lifecycle differentials for provider generations and recovery roots.
//!
//! These tests intentionally keep the core scenario bounded and use the
//! clean-room model for the lifecycle ordering. Required-artifact coverage
//! lives with the custom required-artifact catalog in
//! `recovery_artifact_engine.rs`.

#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, CommandRequest,
    ProviderEffectState, TransitionOutput,
};
use cser_model::provider_lifecycle_oracle::ProviderLifecycleOracle;
use cser_model::{
    ComponentId as OracleComponentId, EffectId as OracleEffectId, OperationId as OracleOperationId,
    ProviderGeneration as OracleProviderGeneration, ProviderId as OracleProviderId,
    WorldId as OracleWorldId,
};
use support::{
    EFFECT_COMPONENT, EFFECT_EVIDENCE_KIND, EFFECT_RECEIPT_SCHEMA,
    EFFECT_SETTLEMENT_RECEIPT_SCHEMA, EFFECT_VERIFIER, Harness, charge, claim, committed_reply,
    current_evidence_command, digest, effect, executor, provider, verified_apply_completion,
    verified_settlement_ack,
};

#[test]
fn provider_lifecycle_oracle_matches_core_fence_abort_release_retire() {
    let mut harness = Harness::standard();
    let effect = effect(0xa801, 1);
    let origin = executor(0xa801, 1);
    let coordinate = provider();
    let mut oracle = ProviderLifecycleOracle::new(OracleWorldId::new(1).unwrap());
    let oracle_provider = OracleProviderId::new(coordinate.provider().get()).unwrap();
    let oracle_generation = OracleProviderGeneration::new(coordinate.generation().get()).unwrap();
    let oracle_coordinate = oracle
        .register_provider(oracle_provider, oracle_generation)
        .unwrap();
    let oracle_effect = OracleEffectId::new(
        OracleOperationId::new(effect.operation().get()).unwrap(),
        effect.sequence(),
    )
    .unwrap();
    let oracle_components = [OracleComponentId::Reply, OracleComponentId::Dma];

    harness
        .tx(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xa801),
            bindings: vec![
                cser_core::ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, coordinate),
                cser_core::ComponentProviderBinding::new(AGENT_COMPONENT_DMA, coordinate),
            ],
        })
        .unwrap();
    oracle
        .admit_effect(oracle_effect, oracle_coordinate, &oracle_components)
        .unwrap();
    assert_eq!(
        harness
            .engine
            .provider_generation_projection(coordinate)
            .unwrap()
            .live_component_bindings,
        oracle.projection().providers[0].live_components as usize
    );

    harness
        .tx(CommandRequest::FenceProviderEffects {
            coordinate,
            expected_epoch: 1,
        })
        .unwrap();
    oracle.fence_provider(oracle_coordinate).unwrap();
    harness
        .tx(CommandRequest::AbortUnescapedEffect { effect })
        .unwrap();
    for component in oracle_components {
        oracle.release(oracle_effect, component).unwrap();
    }
    // AbortUnescapedEffect is the core's atomic precommit release path: with
    // no required artifact leases it closes the scoped binding as part of the
    // same durable transition, so a second explicit release is correctly
    // rejected rather than double-decrementing provider custody.
    assert_eq!(
        harness.engine.composite_effect(effect).unwrap().escape,
        cser_core::EffectEscapeState::Released
    );
    harness
        .tx(CommandRequest::EnterProviderSettlementOnly {
            coordinate,
            expected_epoch: 2,
        })
        .unwrap();
    harness
        .tx(CommandRequest::RetireProviderEffects {
            coordinate,
            expected_epoch: 3,
        })
        .unwrap();
    oracle.enter_settlement_only(oracle_coordinate).unwrap();
    oracle.retire_provider(oracle_coordinate).unwrap();

    let core_provider = harness
        .engine
        .provider_generation_projection(coordinate)
        .unwrap();
    let model_provider = &oracle.projection().providers[0];
    assert_eq!(core_provider.live_component_bindings, 0);
    assert!(matches!(
        core_provider.state,
        ProviderEffectState::Retired { epoch: 4 }
    ));
    assert_eq!(model_provider.live_components, 0);
    assert_eq!(model_provider.live_effects, 0);
    assert_eq!(oracle.high_water(oracle_provider), Some(oracle_generation));
    assert!(oracle.check_invariants());
}

#[test]
fn provider_lifecycle_oracle_tracks_escaped_outcome_settlement_and_release() {
    let mut harness = Harness::new();
    let (effect, actor) = committed_reply(&mut harness, 0xa802);
    let coordinate = provider();
    let mut oracle = ProviderLifecycleOracle::new(cser_model::WorldId::new(1).unwrap());
    let oracle_provider = cser_model::ProviderId::new(coordinate.provider().get()).unwrap();
    let oracle_generation =
        cser_model::ProviderGeneration::new(coordinate.generation().get()).unwrap();
    let oracle_coordinate = oracle
        .register_provider(oracle_provider, oracle_generation)
        .unwrap();
    let oracle_effect = cser_model::EffectId::new(
        cser_model::OperationId::new(effect.operation().get()).unwrap(),
        effect.sequence(),
    )
    .unwrap();
    let oracle_component = cser_model::ComponentId::Reply;
    oracle
        .admit_effect(oracle_effect, oracle_coordinate, &[oracle_component])
        .unwrap();
    oracle
        .commit_intent(oracle_effect, oracle_component)
        .unwrap();
    oracle.execute(oracle_effect, oracle_component).unwrap();
    oracle
        .record_outcome(oracle_effect, oracle_component)
        .unwrap();

    harness
        .tx(CommandRequest::FenceProviderEffects {
            coordinate,
            expected_epoch: 1,
        })
        .unwrap();
    oracle.fence_provider(oracle_coordinate).unwrap();
    harness
        .tx(CommandRequest::EnterProviderSettlementOnly {
            coordinate,
            expected_epoch: 2,
        })
        .unwrap();
    oracle.enter_settlement_only(oracle_coordinate).unwrap();

    let settlement = match harness.output(CommandRequest::ClaimComponentSettlement {
        effect,
        component: EFFECT_COMPONENT,
        claimant: actor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let settlement = match harness.output(settlement.record_apply_intent(digest(0xa8)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected apply-intent claim, got {other:?}"),
    };
    let applied = verified_apply_completion(
        &harness,
        &settlement,
        EFFECT_VERIFIER,
        cser_core::TOOL_APPLY_RECEIPT_SCHEMA,
        digest(0xa9),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        &harness,
        &settlement,
        EFFECT_VERIFIER,
        EFFECT_SETTLEMENT_RECEIPT_SCHEMA,
        digest(0xaa),
    );
    harness
        .tx(settlement.settle(acknowledgement).unwrap())
        .unwrap();
    oracle.settle(oracle_effect, oracle_component).unwrap();

    harness
        .tx(current_evidence_command(
            &harness,
            effect,
            claim(0xa802),
            EFFECT_EVIDENCE_KIND,
            cser_core::ReceiptBinding::new(EFFECT_VERIFIER, EFFECT_RECEIPT_SCHEMA),
            digest(0xab),
        ))
        .unwrap();
    oracle.release(oracle_effect, oracle_component).unwrap();
    harness
        .tx(CommandRequest::ReleaseCompositeEffect { effect })
        .unwrap();

    harness
        .tx(CommandRequest::RetireProviderEffects {
            coordinate,
            expected_epoch: 3,
        })
        .unwrap();
    oracle.retire_provider(oracle_coordinate).unwrap();

    let core_provider = harness
        .engine
        .provider_generation_projection(coordinate)
        .unwrap();
    let model_provider = &oracle.projection().providers[0];
    assert_eq!(core_provider.live_component_bindings, 0);
    assert!(matches!(
        core_provider.state,
        ProviderEffectState::Retired { epoch: 4 }
    ));
    assert_eq!(model_provider.live_components, 0);
    assert_eq!(model_provider.live_effects, 0);
    assert!(oracle.check_invariants());
}
