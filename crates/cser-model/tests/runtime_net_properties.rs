use cser_model::{
    ScopeId, ScopeState,
    runtime_net::{
        GuestReplyTicket, NetCommitReceipt, NetCredits, NetDomain, NetServiceId,
        ReadyCommitReceipt, RuntimeNetBindings, RuntimeNetClosureStep, RuntimeNetError,
        RuntimeNetModel, RuntimeNetServices, RuntimeNetToken,
    },
};
use proptest::prelude::*;

fn services() -> RuntimeNetServices {
    RuntimeNetServices::new(
        NetServiceId::new(1),
        NetServiceId::new(2),
        NetServiceId::new(3),
    )
}

fn close_scope(model: &mut RuntimeNetModel, scope: ScopeId) {
    let ticket = model.revoke_begin(scope).unwrap();
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        assert!(
            iterations <= 128,
            "bounded batch closure must make progress"
        );
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

#[derive(Default)]
struct Receipts {
    net: Option<NetCommitReceipt>,
    ready: Option<ReadyCommitReceipt>,
    guest: Option<GuestReplyTicket>,
}

fn attempt_action(
    model: &mut RuntimeNetModel,
    scope: ScopeId,
    bindings: RuntimeNetBindings,
    token: RuntimeNetToken,
    receipts: &mut Receipts,
    action: u8,
) -> Result<(), RuntimeNetError> {
    match action % 16 {
        0 => model.prepare_syscall(bindings.get(NetDomain::Personality), token.syscall()),
        1 => model.prepare_network(bindings.get(NetDomain::Network), token.network()),
        2 => model.prepare_readiness(bindings.get(NetDomain::Readiness), token.readiness()),
        3 => model.prepare_buffer(bindings.get(NetDomain::Network), token.buffer()),
        4 => model
            .commit_network(
                bindings.get(NetDomain::Network),
                token.network(),
                token.buffer(),
            )
            .map(|receipt| receipts.net = Some(receipt)),
        5 => {
            let Some(net) = receipts.net else {
                return model
                    .commit_network(
                        bindings.get(NetDomain::Network),
                        token.network(),
                        token.buffer(),
                    )
                    .map(|receipt| receipts.net = Some(receipt));
            };
            model
                .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
                .map(|receipt| receipts.ready = Some(receipt))
        }
        6 => {
            let Some(net) = receipts.net else {
                return model.prepare_buffer(bindings.get(NetDomain::Network), token.buffer());
            };
            model
                .consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net)
                .map(|_| ())
        }
        7 => {
            let Some(ready) = receipts.ready else {
                return model
                    .prepare_readiness(bindings.get(NetDomain::Readiness), token.readiness());
            };
            model.deliver_ready(ready)
        }
        8 => model.complete_network(bindings.get(NetDomain::Network), token.network()),
        9 => {
            let Some(ready) = receipts.ready else {
                return model.complete_network(bindings.get(NetDomain::Network), token.network());
            };
            model
                .commit_guest_reply(
                    bindings.get(NetDomain::Personality),
                    token.syscall(),
                    ready,
                    4,
                )
                .map(|publication| receipts.guest = Some(publication))
        }
        10 => {
            let Some(publication) = receipts.guest else {
                return model
                    .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall());
            };
            model
                .publish_guest_reply(publication)
                .map(|()| receipts.guest = None)
        }
        11..=13 => {
            let domain = NetDomain::ALL[usize::from(action % 3)];
            model.crash(bindings.get(domain))
        }
        _ => {
            let domain = NetDomain::ALL[usize::from(action % 3)];
            model.fallback_pick(scope, domain)
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn bounded_actions_preserve_invariants_reject_atomically_and_close(
        actions in prop::collection::vec(any::<u8>(), 1..48),
    ) {
        let mut model = RuntimeNetModel::new();
        let (scope, bindings) = model
            .create_scope(services(), NetCredits::ONE_REQUEST)
            .unwrap();
        let token = model.register_loopback(bindings).unwrap();
        let mut receipts = Receipts::default();

        for action in actions {
            let before = model.clone();
            let result = attempt_action(
                &mut model,
                scope,
                bindings,
                token,
                &mut receipts,
                action,
            );
            if result.is_err() {
                prop_assert_eq!(&model, &before);
            }
            model.check_invariants().unwrap();
        }

        close_scope(&mut model, scope);
        let view = model.scope(scope).unwrap();
        prop_assert_eq!(view.state, ScopeState::Revoked);
        prop_assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
        prop_assert_eq!(view.live_effects, 0);
        prop_assert_eq!(view.visible_buffers, 0);
        prop_assert_eq!(view.pending_publications, 0);
        prop_assert_eq!(view.closure_steps, view.closure_target_count);
        for effect in [
            token.syscall(),
            token.network(),
            token.readiness(),
            token.buffer(),
        ] {
            prop_assert_eq!(model.effect(effect.effect()).unwrap().terminalizations, 1);
        }
    }

    #[test]
    fn bounded_batches_conserve_all_four_credit_classes(
        count in 1usize..6,
        actions in prop::collection::vec(any::<u8>(), 1..40),
    ) {
        let capacity = count as u64;
        let initial = NetCredits::new(capacity, capacity, capacity, capacity);
        let mut model = RuntimeNetModel::new();
        let (scope, bindings) = model.create_scope(services(), initial).unwrap();
        let tokens: Vec<_> = (0..count)
            .map(|_| model.register_loopback(bindings).unwrap())
            .collect();
        let mut receipts: Vec<_> = (0..count).map(|_| Receipts::default()).collect();

        for action in actions {
            let index = usize::from(action) % count;
            let before = model.clone();
            let result = attempt_action(
                &mut model,
                scope,
                bindings,
                tokens[index],
                &mut receipts[index],
                action / 2,
            );
            if result.is_err() {
                prop_assert_eq!(&model, &before);
            }
            model.check_invariants().unwrap();
        }

        close_scope(&mut model, scope);
        let view = model.scope(scope).unwrap();
        prop_assert_eq!(view.free_credits, initial);
        prop_assert_eq!(view.closure_steps, view.closure_target_count);
        for token in tokens {
            for effect in [
                token.syscall(),
                token.network(),
                token.readiness(),
                token.buffer(),
            ] {
                prop_assert!(model.effect(effect.effect()).unwrap().phase.is_terminal());
                prop_assert_eq!(model.effect(effect.effect()).unwrap().terminalizations, 1);
            }
        }
    }
}
