// SPDX-License-Identifier: MPL-2.0

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

use nexus_effect_peer::{
    CommitEffect, CrashService, EffectSelector, NativeHandoffStatus, NativePrepareIntent,
    NativeReadiness, NativeReceiptPayload, PeerCommand, PeerConfig, PeerRequest, PeerResponse,
    REQUEST_SCHEMA, RebindService, RegisterEffect, ResponseStatus,
};

fn request(request_id: u64, command: PeerCommand) -> String {
    serde_json::to_string(&PeerRequest {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id,
        command,
    })
    .unwrap()
}

fn send(
    input: &mut impl Write,
    output: &mut impl BufRead,
    request: &str,
) -> (String, PeerResponse) {
    writeln!(input, "{request}").unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let response = serde_json::from_str(line.trim_end()).unwrap();
    (line, response)
}

#[test]
fn stdio_peer_runs_production_registry_and_replays_lost_ack() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus-effect-peer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());

    let initialize = request(
        1,
        PeerCommand::Initialize(PeerConfig {
            scope_id: 100,
            scope_generation: 1,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor_id: 101,
            supervisor_generation: 1,
            task_id: 102,
            task_generation: 1,
            credit_class: 1,
            credit_limit: 4,
        }),
    );
    assert_eq!(
        send(&mut input, &mut output, &initialize).1.status,
        ResponseStatus::Ok
    );

    let freeze = request(
        2,
        PeerCommand::Freeze(NativePrepareIntent {
            handoff_id: 110,
            log_identity: 111,
            intent_position: 112,
            service_incarnation: 113,
            key_identity: 114,
            request_digest: 115,
        }),
    );
    let (_, frozen) = send(&mut input, &mut output, &freeze);
    let NativeReceiptPayload::AdmissionFrozen(frozen) = frozen.receipt.unwrap().payload else {
        panic!("process did not return a native freeze receipt")
    };
    assert_eq!(frozen.readiness, NativeReadiness::ReadyToCommit);
    assert_ne!(frozen.registry_instance, 0);

    let close = request(
        3,
        PeerCommand::CloseStep(nexus_effect_peer::NativeOwnershipDecision {
            handoff_id: 110,
            freeze_generation: frozen.freeze_generation,
            log_identity: 111,
            decision_position: 116,
            service_incarnation: 113,
            key_identity: 114,
            request_digest: 115,
        }),
    );
    let (first_bytes, first) = send(&mut input, &mut output, &close);
    let (replayed_bytes, replayed) = send(&mut input, &mut output, &close);
    assert_eq!(first_bytes, replayed_bytes);
    assert_eq!(first, replayed);
    let NativeReceiptPayload::ClosureProgress(progress) = first.receipt.unwrap().payload else {
        panic!("process did not return native closure")
    };
    assert_eq!(progress.status, NativeHandoffStatus::Closed);

    let shutdown = request(4, PeerCommand::Shutdown);
    assert_eq!(
        send(&mut input, &mut output, &shutdown).1.status,
        ResponseStatus::Ok
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn stdio_peer_crashes_rebinds_and_replays_the_exact_adoption_receipt() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus-effect-peer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());

    let initialize = request(
        1,
        PeerCommand::Initialize(PeerConfig {
            scope_id: 200,
            scope_generation: 1,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor_id: 201,
            supervisor_generation: 1,
            task_id: 202,
            task_generation: 1,
            credit_class: 1,
            credit_limit: 2,
        }),
    );
    assert_eq!(
        send(&mut input, &mut output, &initialize).1.status,
        ResponseStatus::Ok
    );
    let register = request(
        2,
        PeerCommand::Register(RegisterEffect {
            client_effect: 210,
            operation_class: 211,
            syscall_number: 212,
            syscall_arguments: [0; 6],
            credit_units: 1,
            publication_required: false,
        }),
    );
    assert_eq!(
        send(&mut input, &mut output, &register).1.status,
        ResponseStatus::Ok
    );
    let prepare = request(
        3,
        PeerCommand::Prepare(EffectSelector {
            client_effect: 210,
            binding_epoch: 1,
        }),
    );
    assert_eq!(
        send(&mut input, &mut output, &prepare).1.status,
        ResponseStatus::Ok
    );

    let crash = request(
        4,
        PeerCommand::CrashService(CrashService {
            supervisor_id: 201,
            supervisor_generation: 1,
            binding_epoch: 1,
        }),
    );
    let (_, crashed) = send(&mut input, &mut output, &crash);
    let NativeReceiptPayload::ServiceCrashed(crashed) = crashed.receipt.unwrap().payload else {
        panic!("process did not return a native crash receipt")
    };
    assert_eq!(crashed.crashed_binding_epoch, 2);
    assert_eq!(crashed.cohort.len(), 1);

    let rebind = request(
        5,
        PeerCommand::RebindService(RebindService {
            crashed_binding_epoch: 2,
            replacement_supervisor_id: 201,
            replacement_supervisor_generation: 2,
        }),
    );
    let (first_bytes, first) = send(&mut input, &mut output, &rebind);
    let (replayed_bytes, replayed) = send(&mut input, &mut output, &rebind);
    assert_eq!(first_bytes, replayed_bytes);
    assert_eq!(first, replayed);
    let NativeReceiptPayload::ServiceRebound(rebound) = first.receipt.unwrap().payload else {
        panic!("process did not return a native rebind receipt")
    };
    assert_eq!(rebound.binding_epoch, 2);
    assert_eq!(rebound.adopted.len(), 1);
    assert_eq!(rebound.recovery_remaining, 0);

    let stale_commit = request(
        6,
        PeerCommand::Commit(CommitEffect {
            client_effect: 210,
            binding_epoch: 1,
            result: 0,
            domain_revision: 1,
        }),
    );
    let (_, stale) = send(&mut input, &mut output, &stale_commit);
    assert_eq!(stale.error.unwrap().code, "stale-binding");
    let replacement_commit = request(
        7,
        PeerCommand::Commit(CommitEffect {
            client_effect: 210,
            binding_epoch: 2,
            result: 0,
            domain_revision: 1,
        }),
    );
    assert_eq!(
        send(&mut input, &mut output, &replacement_commit).1.status,
        ResponseStatus::Ok
    );

    let shutdown = request(8, PeerCommand::Shutdown);
    assert_eq!(
        send(&mut input, &mut output, &shutdown).1.status,
        ResponseStatus::Ok
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}
