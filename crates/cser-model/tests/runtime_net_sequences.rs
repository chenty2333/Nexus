use cser_model::{
    ScopeId, ScopeState,
    runtime_net::{
        LOOPBACK_PAYLOAD, NetCreditClass, NetCredits, NetDomain, NetEffectKind, NetEffectPhase,
        NetServiceId, RuntimeNetBindings, RuntimeNetClosureStep, RuntimeNetError, RuntimeNetModel,
        RuntimeNetServices, RuntimeNetToken,
    },
};

fn services() -> RuntimeNetServices {
    RuntimeNetServices::new(
        NetServiceId::new(1),
        NetServiceId::new(2),
        NetServiceId::new(3),
    )
}

fn setup() -> (
    RuntimeNetModel,
    ScopeId,
    RuntimeNetBindings,
    RuntimeNetToken,
) {
    let mut model = RuntimeNetModel::new();
    let (scope, bindings) = model
        .create_scope(services(), NetCredits::ONE_REQUEST)
        .unwrap();
    let token = model.register_loopback(bindings).unwrap();
    (model, scope, bindings, token)
}

fn prepare_all(model: &mut RuntimeNetModel, bindings: RuntimeNetBindings, token: RuntimeNetToken) {
    model
        .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    model
        .prepare_buffer(bindings.get(NetDomain::Network), token.buffer())
        .unwrap();
    model
        .prepare_readiness(bindings.get(NetDomain::Readiness), token.readiness())
        .unwrap();
}

fn close_scope(model: &mut RuntimeNetModel, scope: ScopeId) {
    let ticket = model.revoke_begin(scope).unwrap();
    let mut steps = 0usize;
    loop {
        steps += 1;
        assert!(steps <= 16, "the fixed graph must close in bounded steps");
        match model.revoke_next(ticket).unwrap() {
            Some(RuntimeNetClosureStep::Aborted(_) | RuntimeNetClosureStep::Drained(_)) => {}
            Some(RuntimeNetClosureStep::AwaitingGuestReply(publication)) => {
                model.publish_guest_reply(publication).unwrap();
            }
            None => break,
        }
        model.check_invariants().unwrap();
    }
    model.revoke_complete(ticket).unwrap();
    model.check_invariants().unwrap();
}

#[test]
fn successful_loopback_has_fixed_graph_three_publications_and_full_credit_return() {
    let (mut model, scope, bindings, token) = setup();
    assert_eq!(token.syscall().kind(), NetEffectKind::Syscall);
    assert_eq!(token.syscall().parent(), None);
    assert_eq!(token.network().parent(), Some(token.syscall().effect()));
    assert_eq!(token.readiness().parent(), Some(token.network().effect()));
    assert_eq!(token.buffer().parent(), Some(token.network().effect()));
    assert_eq!(
        model.effect(token.buffer().effect()).unwrap().credit,
        NetCreditClass::Buffer
    );

    prepare_all(&mut model, bindings, token);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();
    assert_eq!(net.payload(), LOOPBACK_PAYLOAD);
    let after_net = model.scope(scope).unwrap();
    assert_eq!(after_net.network_publications, 1);
    assert_eq!(after_net.readiness_publications, 0);
    assert_eq!(after_net.guest_replies, 0);
    assert_eq!(after_net.visible_buffers, 1);
    assert_eq!(after_net.free_credits.buffer(), 0);

    let ready = model
        .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
        .unwrap();
    assert!(ready.sequence() > net.sequence());
    assert_eq!(ready.network_sequence(), net.sequence());
    assert_eq!(model.scope(scope).unwrap().readiness_publications, 1);

    assert_eq!(
        model
            .consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net)
            .unwrap(),
        LOOPBACK_PAYLOAD
    );
    assert_eq!(model.scope(scope).unwrap().free_credits.buffer(), 1);
    model.deliver_ready(ready).unwrap();
    model
        .complete_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    let publication = model
        .commit_guest_reply(
            bindings.get(NetDomain::Personality),
            token.syscall(),
            ready,
            4,
        )
        .unwrap();
    let syscall = model.effect(token.syscall().effect()).unwrap();
    assert!(syscall.commit_sequence.unwrap() > ready.sequence());
    assert!(syscall.publication_pending);
    assert_eq!(model.scope(scope).unwrap().guest_replies, 0);
    model.publish_guest_reply(publication).unwrap();

    let view = model.scope(scope).unwrap();
    assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
    assert_eq!(view.live_effects, 0);
    assert_eq!(view.pending_publications, 0);
    assert_eq!(view.network_publications, 1);
    assert_eq!(view.readiness_publications, 1);
    assert_eq!(view.ready_deliveries, 1);
    assert_eq!(view.guest_replies, 1);
    assert_eq!(view.buffer_consumptions, 1);
    model.check_invariants().unwrap();
}

#[test]
fn revoke_before_net_commit_aborts_every_effect_without_publication() {
    let (mut model, scope, bindings, token) = setup();
    prepare_all(&mut model, bindings, token);
    close_scope(&mut model, scope);

    let view = model.scope(scope).unwrap();
    assert_eq!(view.state, ScopeState::Revoked);
    assert_eq!(view.network_publications, 0);
    assert_eq!(view.readiness_publications, 0);
    assert_eq!(view.guest_replies, 0);
    assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
    for effect in [
        token.syscall(),
        token.network(),
        token.readiness(),
        token.buffer(),
    ] {
        let effect = model.effect(effect.effect()).unwrap();
        assert_eq!(effect.phase, NetEffectPhase::Aborted);
        assert_eq!(effect.terminalizations, 1);
    }
}

#[test]
fn net_commit_can_remain_visible_while_revoke_suppresses_ready_and_reply() {
    let (mut model, scope, bindings, token) = setup();
    prepare_all(&mut model, bindings, token);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();
    assert_eq!(
        model
            .buffer_payload(scope, token.buffer().effect())
            .unwrap(),
        Some(LOOPBACK_PAYLOAD)
    );
    close_scope(&mut model, scope);

    let view = model.scope(scope).unwrap();
    assert_eq!(view.network_publications, 1);
    assert_eq!(view.readiness_publications, 0);
    assert_eq!(view.ready_deliveries, 0);
    assert_eq!(view.guest_replies, 0);
    assert_eq!(view.visible_buffers, 0);
    assert_eq!(view.buffer_consumptions, 0);
    assert_eq!(
        model.effect(net.effect()).unwrap().phase,
        NetEffectPhase::Completed
    );
    assert_eq!(
        model.effect(token.readiness().effect()).unwrap().phase,
        NetEffectPhase::Aborted
    );
}

#[test]
fn ready_wins_before_revoke_but_guest_reply_remains_absent() {
    let (mut model, scope, bindings, token) = setup();
    prepare_all(&mut model, bindings, token);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();
    let ready = model
        .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
        .unwrap();
    close_scope(&mut model, scope);

    let view = model.scope(scope).unwrap();
    assert_eq!(view.network_publications, 1);
    assert_eq!(view.readiness_publications, 1);
    assert_eq!(view.ready_deliveries, 1);
    assert_eq!(view.guest_replies, 0);
    assert_eq!(model.ready_receipt(ready.effect()).unwrap(), Some(ready));
    assert_eq!(
        model.effect(token.readiness().effect()).unwrap().phase,
        NetEffectPhase::Completed
    );
    assert_eq!(
        model.effect(token.syscall().effect()).unwrap().phase,
        NetEffectPhase::Aborted
    );
}

#[test]
fn netd_crash_rebind_and_explicit_adoption_preserve_peer_bindings() {
    let (mut model, scope, bindings, token) = setup();
    model
        .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    model
        .prepare_buffer(bindings.get(NetDomain::Network), token.buffer())
        .unwrap();
    let personality_before = model.domain(scope, NetDomain::Personality).unwrap();
    let readiness_before = model.domain(scope, NetDomain::Readiness).unwrap();
    let old_network = bindings.get(NetDomain::Network);
    model.crash(old_network).unwrap();

    let before_reject = model.clone();
    assert!(matches!(
        model.prepare_network(old_network, token.network()),
        Err(RuntimeNetError::StaleBinding { .. })
    ));
    assert_eq!(model, before_reject);

    model.fallback_pick(scope, NetDomain::Network).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, NetDomain::Network, NetServiceId::new(20))
        .unwrap();
    assert_eq!(snapshot.cohort().len(), 2);
    let ready = model.ready(&snapshot).unwrap();
    let replacement = model.rebind(ready).unwrap();
    let first = model.recover_next(replacement).unwrap().unwrap();
    let adopted_network = model.adopt(replacement, first).unwrap();
    assert_eq!(adopted_network.kind(), NetEffectKind::NetOperation);
    let second = model.recover_next(replacement).unwrap().unwrap();
    let adopted_buffer = model.adopt(replacement, second).unwrap();
    assert_eq!(adopted_buffer.kind(), NetEffectKind::BufferLease);
    assert_eq!(model.recover_next(replacement).unwrap(), None);
    assert_eq!(
        model.domain(scope, NetDomain::Personality).unwrap(),
        personality_before
    );
    assert_eq!(
        model.domain(scope, NetDomain::Readiness).unwrap(),
        readiness_before
    );

    model
        .prepare_readiness(bindings.get(NetDomain::Readiness), token.readiness())
        .unwrap();
    let net = model
        .commit_network(replacement, adopted_network, adopted_buffer)
        .unwrap();
    let ready = model
        .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
        .unwrap();
    model
        .consume_buffer(replacement, adopted_buffer, net)
        .unwrap();
    model.deliver_ready(ready).unwrap();
    model
        .complete_network(replacement, adopted_network)
        .unwrap();
    let reply = model
        .commit_guest_reply(
            bindings.get(NetDomain::Personality),
            token.syscall(),
            ready,
            4,
        )
        .unwrap();
    model.publish_guest_reply(reply).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_credits,
        NetCredits::ONE_REQUEST
    );
}

#[test]
fn committed_guest_reply_survives_personality_crash_and_closure_publishes_once() {
    let (mut model, scope, bindings, token) = setup();
    prepare_all(&mut model, bindings, token);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();
    let ready = model
        .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
        .unwrap();
    model.crash(bindings.get(NetDomain::Readiness)).unwrap();
    model
        .consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net)
        .unwrap();
    model.deliver_ready(ready).unwrap();
    assert_eq!(model.scope(scope).unwrap().ready_deliveries, 1);
    model
        .complete_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    let publication = model
        .commit_guest_reply(
            bindings.get(NetDomain::Personality),
            token.syscall(),
            ready,
            4,
        )
        .unwrap();
    model.crash(bindings.get(NetDomain::Personality)).unwrap();
    assert!(
        model
            .domain(scope, NetDomain::Personality)
            .unwrap()
            .recovery_cohort
            .is_empty()
    );

    let ticket = model.revoke_begin(scope).unwrap();
    assert_eq!(
        model.revoke_next(ticket).unwrap(),
        Some(RuntimeNetClosureStep::AwaitingGuestReply(publication))
    );
    model.publish_guest_reply(publication).unwrap();
    assert_eq!(model.revoke_next(ticket).unwrap(), None);
    model.revoke_complete(ticket).unwrap();
    assert_eq!(model.scope(scope).unwrap().guest_replies, 1);

    let before = model.clone();
    assert_eq!(
        model.publish_guest_reply(publication),
        Err(RuntimeNetError::AlreadyPublished)
    );
    assert_eq!(model, before);
}

#[test]
fn recovery_ready_rejects_a_snapshot_invalidated_by_socket_publication() {
    let (mut model, scope, bindings, token) = setup();
    model
        .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall())
        .unwrap();
    model
        .prepare_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    model
        .prepare_buffer(bindings.get(NetDomain::Network), token.buffer())
        .unwrap();
    model.crash(bindings.get(NetDomain::Readiness)).unwrap();
    model.fallback_pick(scope, NetDomain::Readiness).unwrap();
    let snapshot = model
        .recovery_snapshot(scope, NetDomain::Readiness, NetServiceId::new(30))
        .unwrap();
    model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();

    let before = model.clone();
    assert_eq!(
        model.ready(&snapshot),
        Err(RuntimeNetError::StaleRecoverySnapshot)
    );
    assert_eq!(model, before);
    close_scope(&mut model, scope);
}

#[test]
fn stale_socket_source_and_authority_reject_with_full_model_equality() {
    let mut model = RuntimeNetModel::new();
    let (scope, bindings) = model
        .create_scope(services(), NetCredits::new(2, 2, 2, 2))
        .unwrap();
    let stale = model.register_loopback(bindings).unwrap();
    let live = model.register_loopback(bindings).unwrap();
    prepare_all(&mut model, bindings, live);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            live.network(),
            live.buffer(),
        )
        .unwrap();
    let ready = model
        .commit_ready(bindings.get(NetDomain::Readiness), live.readiness(), net)
        .unwrap();

    let before_socket = model.clone();
    assert!(matches!(
        model.prepare_network(bindings.get(NetDomain::Network), stale.network()),
        Err(RuntimeNetError::StaleSocketGeneration { .. })
    ));
    assert_eq!(model, before_socket);
    let before_source = model.clone();
    assert!(matches!(
        model.prepare_readiness(bindings.get(NetDomain::Readiness), stale.readiness()),
        Err(RuntimeNetError::StaleSourceGeneration { .. })
    ));
    assert_eq!(model, before_source);

    model
        .consume_buffer(bindings.get(NetDomain::Network), live.buffer(), net)
        .unwrap();
    model.deliver_ready(ready).unwrap();
    model
        .complete_network(bindings.get(NetDomain::Network), live.network())
        .unwrap();
    let reply = model
        .commit_guest_reply(
            bindings.get(NetDomain::Personality),
            live.syscall(),
            ready,
            4,
        )
        .unwrap();
    model.publish_guest_reply(reply).unwrap();

    let ticket = model.revoke_begin(scope).unwrap();
    let before_authority = model.clone();
    assert!(matches!(
        model.prepare_syscall(bindings.get(NetDomain::Personality), stale.syscall()),
        Err(RuntimeNetError::StaleAuthority { .. })
    ));
    assert_eq!(model, before_authority);
    while model.revoke_next(ticket).unwrap().is_some() {}
    model.revoke_complete(ticket).unwrap();
    assert_eq!(
        model.scope(scope).unwrap().free_credits,
        NetCredits::new(2, 2, 2, 2)
    );
}

#[test]
fn buffer_credit_is_retained_until_exact_consume_and_duplicate_consume_is_atomic() {
    let (mut model, scope, bindings, token) = setup();
    prepare_all(&mut model, bindings, token);
    let net = model
        .commit_network(
            bindings.get(NetDomain::Network),
            token.network(),
            token.buffer(),
        )
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().free_credits.buffer(), 0);
    model
        .consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net)
        .unwrap();
    assert_eq!(model.scope(scope).unwrap().free_credits.buffer(), 1);

    let before_ready = model.clone();
    assert_eq!(
        model.commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net,),
        Err(RuntimeNetError::InvalidBufferLease)
    );
    assert_eq!(model, before_ready);

    let before = model.clone();
    assert!(matches!(
        model.consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net),
        Err(RuntimeNetError::InvalidEffectState(
            NetEffectPhase::Completed
        )) | Err(RuntimeNetError::InvalidBufferLease)
    ));
    assert_eq!(model, before);
    close_scope(&mut model, scope);
}

#[test]
fn receipt_from_another_scope_cannot_authorize_ready_commit() {
    let mut model = RuntimeNetModel::new();
    let (scope_a, bindings_a) = model
        .create_scope(services(), NetCredits::ONE_REQUEST)
        .unwrap();
    let services_b = RuntimeNetServices::new(
        NetServiceId::new(11),
        NetServiceId::new(12),
        NetServiceId::new(13),
    );
    let (scope_b, bindings_b) = model
        .create_scope(services_b, NetCredits::ONE_REQUEST)
        .unwrap();
    let token_a = model.register_loopback(bindings_a).unwrap();
    let token_b = model.register_loopback(bindings_b).unwrap();
    prepare_all(&mut model, bindings_a, token_a);
    prepare_all(&mut model, bindings_b, token_b);
    let receipt_a = model
        .commit_network(
            bindings_a.get(NetDomain::Network),
            token_a.network(),
            token_a.buffer(),
        )
        .unwrap();

    let before = model.clone();
    assert_eq!(
        model.commit_ready(
            bindings_b.get(NetDomain::Readiness),
            token_b.readiness(),
            receipt_a,
        ),
        Err(RuntimeNetError::InvalidNetReceipt)
    );
    assert_eq!(model, before);
    close_scope(&mut model, scope_a);
    close_scope(&mut model, scope_b);
}
