// SPDX-License-Identifier: MPL-2.0

use super::*;

fn request(request_id: u64, command: PeerCommand) -> PeerRequest {
    PeerRequest {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id,
        command,
    }
}

fn execute(peer: &mut ProductionEffectPeer, request: PeerRequest) -> PeerResponse {
    serde_json::from_slice(&peer.execute_line(&serde_json::to_vec(&request).unwrap())).unwrap()
}

fn config() -> PeerConfig {
    PeerConfig {
        scope_id: 10,
        scope_generation: 1,
        authority_epoch: 7,
        binding_epoch: 1,
        supervisor_id: 11,
        supervisor_generation: 1,
        task_id: 12,
        task_generation: 1,
        credit_class: 1,
        credit_limit: 4,
    }
}

fn intent() -> NativePrepareIntent {
    NativePrepareIntent {
        handoff_id: 20,
        log_identity: 21,
        intent_position: 22,
        service_incarnation: 23,
        key_identity: 24,
        request_digest: 25,
    }
}

fn decision(freeze_generation: u64) -> NativeOwnershipDecision {
    let intent = intent();
    NativeOwnershipDecision {
        handoff_id: intent.handoff_id,
        freeze_generation,
        log_identity: intent.log_identity,
        decision_position: 26,
        service_incarnation: intent.service_incarnation,
        key_identity: intent.key_identity,
        request_digest: intent.request_digest,
    }
}

#[test]
fn empty_production_cohort_closes_and_replays_exact_bytes() {
    let mut peer = ProductionEffectPeer::new();
    assert_eq!(
        execute(&mut peer, request(1, PeerCommand::Initialize(config()))).status,
        ResponseStatus::Ok
    );
    let freeze = execute(&mut peer, request(2, PeerCommand::Freeze(intent())));
    let NativeReceiptPayload::AdmissionFrozen(frozen) = freeze.receipt.unwrap().payload else {
        panic!("missing native freeze")
    };
    assert_eq!(frozen.readiness, NativeReadiness::ReadyToCommit);

    let close_request = request(
        3,
        PeerCommand::CloseStep(decision(frozen.freeze_generation)),
    );
    let encoded = serde_json::to_vec(&close_request).unwrap();
    let first = peer.execute_line(&encoded);
    let replay = peer.execute_line(&encoded);
    assert_eq!(first, replay);
    let response: PeerResponse = serde_json::from_slice(&first).unwrap();
    let NativeReceiptPayload::ClosureProgress(progress) = response.receipt.unwrap().payload else {
        panic!("missing close progress")
    };
    assert_eq!(progress.status, NativeHandoffStatus::Closed);
    assert_eq!(progress.live_effects, 0);
    assert!(progress.terminal_manifest_digest.is_some());
}

#[test]
fn freeze_blocks_commit_then_exact_abort_reopens_production_admission() {
    let mut peer = ProductionEffectPeer::new();
    execute(&mut peer, request(1, PeerCommand::Initialize(config())));
    let registration = RegisterEffect {
        client_effect: 30,
        operation_class: 31,
        syscall_number: 32,
        syscall_arguments: [0; 6],
        credit_units: 1,
        publication_required: false,
    };
    execute(&mut peer, request(2, PeerCommand::Register(registration)));
    execute(
        &mut peer,
        request(
            3,
            PeerCommand::Prepare(EffectSelector {
                client_effect: 30,
                binding_epoch: 1,
            }),
        ),
    );
    let freeze = execute(&mut peer, request(4, PeerCommand::Freeze(intent())));
    let NativeReceiptPayload::AdmissionFrozen(frozen) = freeze.receipt.unwrap().payload else {
        panic!("missing native freeze")
    };
    assert_eq!(frozen.readiness, NativeReadiness::NeedsAbort);
    let rejected = execute(
        &mut peer,
        request(
            5,
            PeerCommand::Commit(CommitEffect {
                client_effect: 30,
                binding_epoch: 1,
                result: 0,
                domain_revision: 1,
            }),
        ),
    );
    assert_eq!(rejected.error.unwrap().code, "admission-frozen");
    let thawed = execute(
        &mut peer,
        request(6, PeerCommand::Thaw(decision(frozen.freeze_generation))),
    );
    assert_eq!(thawed.status, ResponseStatus::Ok);
    assert_eq!(
        execute(
            &mut peer,
            request(
                7,
                PeerCommand::Commit(CommitEffect {
                    client_effect: 30,
                    binding_epoch: 1,
                    result: 0,
                    domain_revision: 1,
                }),
            ),
        )
        .status,
        ResponseStatus::Ok
    );
    let next = RegisterEffect {
        client_effect: 40,
        ..registration
    };
    assert_eq!(
        execute(&mut peer, request(8, PeerCommand::Register(next))).status,
        ResponseStatus::Ok
    );
}

#[test]
fn committed_completion_can_progress_while_admission_is_frozen() {
    let mut peer = ProductionEffectPeer::new();
    execute(&mut peer, request(1, PeerCommand::Initialize(config())));
    execute(
        &mut peer,
        request(
            2,
            PeerCommand::Register(RegisterEffect {
                client_effect: 45,
                operation_class: 46,
                syscall_number: 47,
                syscall_arguments: [0; 6],
                credit_units: 1,
                publication_required: true,
            }),
        ),
    );
    execute(
        &mut peer,
        request(
            3,
            PeerCommand::Prepare(EffectSelector {
                client_effect: 45,
                binding_epoch: 1,
            }),
        ),
    );
    execute(
        &mut peer,
        request(
            4,
            PeerCommand::Commit(CommitEffect {
                client_effect: 45,
                binding_epoch: 1,
                result: 8,
                domain_revision: 1,
            }),
        ),
    );
    let freeze = execute(&mut peer, request(5, PeerCommand::Freeze(intent())));
    let NativeReceiptPayload::AdmissionFrozen(frozen) = freeze.receipt.unwrap().payload else {
        panic!("missing native freeze")
    };

    let completed = execute(
        &mut peer,
        request(
            6,
            PeerCommand::Complete(CompleteEffect {
                client_effect: 45,
                binding_epoch: 1,
                result: 8,
            }),
        ),
    );
    let NativeReceiptPayload::EffectCompleted(completed) = completed.receipt.unwrap().payload
    else {
        panic!("missing native completion")
    };
    assert!(completed.publication_pending);
    let query = execute(&mut peer, request(7, PeerCommand::Query));
    let NativeReceiptPayload::HandoffQuery(query) = query.receipt.unwrap().payload else {
        panic!("missing native query")
    };
    assert_eq!(query.readiness, Some(NativeReadiness::PublicationPending));
    execute(
        &mut peer,
        request(
            8,
            PeerCommand::AcknowledgePublication(EffectSelector {
                client_effect: 45,
                binding_epoch: 1,
            }),
        ),
    );
    let closed = execute(
        &mut peer,
        request(
            9,
            PeerCommand::CloseStep(decision(frozen.freeze_generation)),
        ),
    );
    let NativeReceiptPayload::ClosureProgress(closed) = closed.receipt.unwrap().payload else {
        panic!("missing native closure")
    };
    assert_eq!(closed.status, NativeHandoffStatus::Closed);
}

#[test]
fn committed_effect_drains_through_explicit_publication_ack_before_closure() {
    let mut peer = ProductionEffectPeer::new();
    execute(&mut peer, request(1, PeerCommand::Initialize(config())));
    execute(
        &mut peer,
        request(
            2,
            PeerCommand::Register(RegisterEffect {
                client_effect: 50,
                operation_class: 51,
                syscall_number: 52,
                syscall_arguments: [0; 6],
                credit_units: 1,
                publication_required: true,
            }),
        ),
    );
    execute(
        &mut peer,
        request(
            3,
            PeerCommand::Prepare(EffectSelector {
                client_effect: 50,
                binding_epoch: 1,
            }),
        ),
    );
    execute(
        &mut peer,
        request(
            4,
            PeerCommand::Commit(CommitEffect {
                client_effect: 50,
                binding_epoch: 1,
                result: 9,
                domain_revision: 1,
            }),
        ),
    );
    let freeze = execute(&mut peer, request(5, PeerCommand::Freeze(intent())));
    let NativeReceiptPayload::AdmissionFrozen(frozen) = freeze.receipt.unwrap().payload else {
        panic!("missing native freeze")
    };
    assert_eq!(frozen.committed_at_freeze, 1);
    assert_eq!(frozen.readiness, NativeReadiness::ReadyToCommit);

    let first = execute(
        &mut peer,
        request(
            6,
            PeerCommand::CloseStep(decision(frozen.freeze_generation)),
        ),
    );
    let NativeReceiptPayload::ClosureProgress(first) = first.receipt.unwrap().payload else {
        panic!("missing close step")
    };
    assert_eq!(first.status, NativeHandoffStatus::Closing);
    assert_eq!(first.native_effect, Some(50));
    assert!(first.publication_pending);

    execute(
        &mut peer,
        request(
            7,
            PeerCommand::AcknowledgePublication(EffectSelector {
                client_effect: 50,
                binding_epoch: 1,
            }),
        ),
    );
    let closed = execute(
        &mut peer,
        request(
            8,
            PeerCommand::CloseStep(decision(frozen.freeze_generation)),
        ),
    );
    let NativeReceiptPayload::ClosureProgress(closed) = closed.receipt.unwrap().payload else {
        panic!("missing terminal closure")
    };
    assert_eq!(closed.status, NativeHandoffStatus::Closed);
    assert_eq!(closed.live_effects, 0);
    assert_eq!(closed.pending_publications, 0);
}

#[test]
fn service_crash_rebind_adopts_production_handles_and_fences_old_binding() {
    let mut peer = ProductionEffectPeer::new();
    execute(&mut peer, request(1, PeerCommand::Initialize(config())));
    let registered = execute(
        &mut peer,
        request(
            2,
            PeerCommand::Register(RegisterEffect {
                client_effect: 60,
                operation_class: 61,
                syscall_number: 62,
                syscall_arguments: [0; 6],
                credit_units: 1,
                publication_required: false,
            }),
        ),
    );
    let NativeReceiptPayload::EffectRegistered(registered) = registered.receipt.unwrap().payload
    else {
        panic!("missing production registration")
    };
    assert_eq!(registered.binding_epoch, 1);
    execute(
        &mut peer,
        request(
            3,
            PeerCommand::Prepare(EffectSelector {
                client_effect: 60,
                binding_epoch: 1,
            }),
        ),
    );
    let old_handle = peer
        .session
        .as_ref()
        .unwrap()
        .effects
        .get(&60)
        .unwrap()
        .handle;

    let crash = request(
        4,
        PeerCommand::CrashService(CrashService {
            supervisor_id: 11,
            supervisor_generation: 1,
            binding_epoch: 1,
        }),
    );
    let encoded_crash = serde_json::to_vec(&crash).unwrap();
    let first_crash = peer.execute_line(&encoded_crash);
    assert_eq!(peer.execute_line(&encoded_crash), first_crash);
    let crashed: PeerResponse = serde_json::from_slice(&first_crash).unwrap();
    let crashed_receipt = crashed.receipt.unwrap();
    assert!(crashed_receipt.verify_integrity().unwrap());
    let NativeReceiptPayload::ServiceCrashed(crashed) = crashed_receipt.payload else {
        panic!("missing production crash receipt")
    };
    assert_eq!(crashed.previous_binding_epoch, 1);
    assert_eq!(crashed.crashed_binding_epoch, 2);
    assert_eq!(crashed.cohort.len(), 1);
    assert_eq!(crashed.cohort[0].client_effect, 60);
    assert_eq!(crashed.cohort[0].binding_epoch, 1);

    let stale_during_crash = execute(
        &mut peer,
        request(
            5,
            PeerCommand::Commit(CommitEffect {
                client_effect: 60,
                binding_epoch: 1,
                result: 8,
                domain_revision: 1,
            }),
        ),
    );
    assert_eq!(stale_during_crash.error.unwrap().code, "stale-binding");

    let rebind = request(
        6,
        PeerCommand::RebindService(RebindService {
            crashed_binding_epoch: 2,
            replacement_supervisor_id: 11,
            replacement_supervisor_generation: 2,
        }),
    );
    let encoded_rebind = serde_json::to_vec(&rebind).unwrap();
    let first_rebind = peer.execute_line(&encoded_rebind);
    assert_eq!(peer.execute_line(&encoded_rebind), first_rebind);
    let rebound: PeerResponse = serde_json::from_slice(&first_rebind).unwrap();
    let rebound_receipt = rebound.receipt.unwrap();
    assert!(rebound_receipt.verify_integrity().unwrap());
    let NativeReceiptPayload::ServiceRebound(rebound) = rebound_receipt.payload else {
        panic!("missing production rebind receipt")
    };
    assert_eq!(rebound.supervisor_generation, 2);
    assert_eq!(rebound.binding_epoch, 2);
    assert_eq!(rebound.recovery_remaining, 0);
    assert_eq!(rebound.adopted.len(), 1);
    assert_eq!(rebound.adopted[0].client_effect, 60);
    assert_eq!(rebound.adopted[0].previous_binding_epoch, 1);
    assert_eq!(rebound.adopted[0].binding_epoch, 2);

    let session = peer.session.as_ref().unwrap();
    assert_eq!(
        session.registry.descriptor(session.supervisor, old_handle),
        Err(RegistryError::StaleBinding)
    );

    let stale_after_rebind = execute(
        &mut peer,
        request(
            7,
            PeerCommand::Commit(CommitEffect {
                client_effect: 60,
                binding_epoch: 1,
                result: 8,
                domain_revision: 1,
            }),
        ),
    );
    assert_eq!(stale_after_rebind.error.unwrap().code, "stale-binding");
    let stale_service = execute(
        &mut peer,
        request(
            8,
            PeerCommand::CrashService(CrashService {
                supervisor_id: 11,
                supervisor_generation: 1,
                binding_epoch: 1,
            }),
        ),
    );
    assert_eq!(stale_service.error.unwrap().code, "stale-binding");

    let committed = execute(
        &mut peer,
        request(
            9,
            PeerCommand::Commit(CommitEffect {
                client_effect: 60,
                binding_epoch: 2,
                result: 8,
                domain_revision: 1,
            }),
        ),
    );
    let NativeReceiptPayload::EffectCommitted(committed) = committed.receipt.unwrap().payload
    else {
        panic!("replacement could not commit adopted effect")
    };
    assert_eq!(committed.binding_epoch, 2);
    assert!(!committed.registry_replay);
}
