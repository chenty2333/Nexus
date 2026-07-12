//! Loom schedules operations against the actual `RuntimeNetModel` coordinator.
//!
//! `loom::sync::Mutex` supplies only the outer kernel gate. Every transition,
//! receipt validation, typed-credit update, and invariant check below executes
//! the production safe-Rust oracle rather than a disconnected surrogate.

use cser_model::{
    ScopeId, ScopeState,
    runtime_net::{
        NetCredits, NetDomain, NetServiceId, RuntimeNetBindings, RuntimeNetClosureStep,
        RuntimeNetModel, RuntimeNetRevokeTicket, RuntimeNetServices, RuntimeNetToken,
    },
};
use loom::{
    model,
    sync::{Arc, Mutex},
    thread,
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
    let mut oracle = RuntimeNetModel::new();
    let (scope, bindings) = oracle
        .create_scope(services(), NetCredits::ONE_REQUEST)
        .unwrap();
    let token = oracle.register_loopback(bindings).unwrap();
    (oracle, scope, bindings, token)
}

fn prepare_all(oracle: &mut RuntimeNetModel, bindings: RuntimeNetBindings, token: RuntimeNetToken) {
    oracle
        .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall())
        .unwrap();
    oracle
        .prepare_network(bindings.get(NetDomain::Network), token.network())
        .unwrap();
    oracle
        .prepare_buffer(bindings.get(NetDomain::Network), token.buffer())
        .unwrap();
    oracle
        .prepare_readiness(bindings.get(NetDomain::Readiness), token.readiness())
        .unwrap();
}

fn close_with_ticket(oracle: &mut RuntimeNetModel, ticket: RuntimeNetRevokeTicket) {
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        assert!(iterations <= 16);
        match oracle.revoke_next(ticket).unwrap() {
            Some(RuntimeNetClosureStep::Aborted(_) | RuntimeNetClosureStep::Drained(_)) => {}
            Some(RuntimeNetClosureStep::AwaitingGuestReply(publication)) => {
                oracle.publish_guest_reply(publication).unwrap();
            }
            None => break,
        }
    }
    oracle.revoke_complete(ticket).unwrap();
    oracle.check_invariants().unwrap();
}

#[test]
fn loom_net_commit_and_root_revoke_share_the_actual_authority_gate() {
    model(|| {
        let (mut oracle, scope, bindings, token) = setup();
        prepare_all(&mut oracle, bindings, token);
        let coordinator = Arc::new(Mutex::new(oracle));
        let commit_coordinator = coordinator.clone();
        let revoke_coordinator = coordinator.clone();

        let commit = thread::spawn(move || {
            commit_coordinator.lock().unwrap().commit_network(
                bindings.get(NetDomain::Network),
                token.network(),
                token.buffer(),
            )
        });
        let revoke = thread::spawn(move || {
            revoke_coordinator
                .lock()
                .unwrap()
                .revoke_begin(scope)
                .unwrap()
        });

        let committed = commit.join().unwrap().is_ok();
        let ticket = revoke.join().unwrap();
        let mut oracle = coordinator.lock().unwrap();
        close_with_ticket(&mut oracle, ticket);
        let view = oracle.scope(scope).unwrap();
        assert_eq!(view.state, ScopeState::Revoked);
        assert_eq!(view.network_publications, u64::from(committed));
        assert_eq!(view.readiness_publications, 0);
        assert_eq!(view.guest_replies, 0);
        assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
    });
}

#[test]
fn loom_ready_commit_and_revoke_choose_one_kernel_owned_publication_outcome() {
    model(|| {
        let (mut oracle, scope, bindings, token) = setup();
        prepare_all(&mut oracle, bindings, token);
        let net = oracle
            .commit_network(
                bindings.get(NetDomain::Network),
                token.network(),
                token.buffer(),
            )
            .unwrap();
        let coordinator = Arc::new(Mutex::new(oracle));
        let ready_coordinator = coordinator.clone();
        let revoke_coordinator = coordinator.clone();

        let ready = thread::spawn(move || {
            ready_coordinator.lock().unwrap().commit_ready(
                bindings.get(NetDomain::Readiness),
                token.readiness(),
                net,
            )
        });
        let revoke = thread::spawn(move || {
            revoke_coordinator
                .lock()
                .unwrap()
                .revoke_begin(scope)
                .unwrap()
        });

        let ready_won = ready.join().unwrap().is_ok();
        let ticket = revoke.join().unwrap();
        let mut oracle = coordinator.lock().unwrap();
        close_with_ticket(&mut oracle, ticket);
        let view = oracle.scope(scope).unwrap();
        assert_eq!(view.network_publications, 1);
        assert_eq!(view.readiness_publications, u64::from(ready_won));
        assert_eq!(view.ready_deliveries, u64::from(ready_won));
        assert_eq!(view.guest_replies, 0);
        assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
    });
}

#[test]
fn loom_netd_crash_fences_a_racing_completion_on_the_actual_binding_epoch() {
    model(|| {
        let (mut oracle, scope, bindings, token) = setup();
        oracle
            .prepare_syscall(bindings.get(NetDomain::Personality), token.syscall())
            .unwrap();
        oracle
            .prepare_network(bindings.get(NetDomain::Network), token.network())
            .unwrap();
        oracle
            .prepare_buffer(bindings.get(NetDomain::Network), token.buffer())
            .unwrap();
        let coordinator = Arc::new(Mutex::new(oracle));
        let commit_coordinator = coordinator.clone();
        let crash_coordinator = coordinator.clone();

        let completion = thread::spawn(move || {
            commit_coordinator.lock().unwrap().commit_network(
                bindings.get(NetDomain::Network),
                token.network(),
                token.buffer(),
            )
        });
        let crash = thread::spawn(move || {
            crash_coordinator
                .lock()
                .unwrap()
                .crash(bindings.get(NetDomain::Network))
                .unwrap()
        });

        let completion_won = completion.join().unwrap().is_ok();
        crash.join().unwrap();
        let mut oracle = coordinator.lock().unwrap();
        assert!(
            oracle
                .prepare_network(bindings.get(NetDomain::Network), token.network())
                .is_err(),
            "the pre-crash netd binding must remain fenced"
        );
        let ticket = oracle.revoke_begin(scope).unwrap();
        close_with_ticket(&mut oracle, ticket);
        let view = oracle.scope(scope).unwrap();
        assert_eq!(view.network_publications, u64::from(completion_won));
        assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
    });
}

#[test]
fn loom_guest_reply_ack_and_root_completion_share_the_actual_publication_gate() {
    model(|| {
        let (mut oracle, scope, bindings, token) = setup();
        prepare_all(&mut oracle, bindings, token);
        let net = oracle
            .commit_network(
                bindings.get(NetDomain::Network),
                token.network(),
                token.buffer(),
            )
            .unwrap();
        let ready = oracle
            .commit_ready(bindings.get(NetDomain::Readiness), token.readiness(), net)
            .unwrap();
        oracle
            .consume_buffer(bindings.get(NetDomain::Network), token.buffer(), net)
            .unwrap();
        oracle.deliver_ready(ready).unwrap();
        oracle
            .complete_network(bindings.get(NetDomain::Network), token.network())
            .unwrap();
        let publication = oracle
            .commit_guest_reply(
                bindings.get(NetDomain::Personality),
                token.syscall(),
                ready,
                4,
            )
            .unwrap();
        let coordinator = Arc::new(Mutex::new(oracle));
        let publish_coordinator = coordinator.clone();
        let revoke_coordinator = coordinator.clone();

        let publish = thread::spawn(move || {
            publish_coordinator
                .lock()
                .unwrap()
                .publish_guest_reply(publication)
                .unwrap();
        });
        let revoke = thread::spawn(move || {
            revoke_coordinator
                .lock()
                .unwrap()
                .revoke_begin(scope)
                .unwrap()
        });

        publish.join().unwrap();
        let ticket = revoke.join().unwrap();
        let mut oracle = coordinator.lock().unwrap();
        close_with_ticket(&mut oracle, ticket);
        let view = oracle.scope(scope).unwrap();
        assert_eq!(view.guest_replies, 1);
        assert_eq!(view.pending_publications, 0);
        assert_eq!(view.free_credits, NetCredits::ONE_REQUEST);
        assert_eq!(view.state, ScopeState::Revoked);
    });
}
