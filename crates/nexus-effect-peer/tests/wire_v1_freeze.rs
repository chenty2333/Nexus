// SPDX-License-Identifier: MPL-2.0

use nexus_effect_peer::*;
use serde::{Deserialize, Serialize};

const CONTRACT: &str = include_str!("../../../status/effect-peer-native-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeContract {
    schema: String,
    contract_id: String,
    status: String,
    protocol_major: u32,
    transport: String,
    canonical_encoding: String,
    request_schema: String,
    response_schema: String,
    receipt_schema: String,
    authentication_boundary: String,
    canonical_snapshot_sha256: String,
    operations: Vec<String>,
    receipt_kinds: Vec<String>,
    change_policy: ChangePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePolicy {
    additive_v1_changes_allowed: bool,
    compatible_bugfixes: String,
    new_capabilities: String,
    extension_requirement: String,
}

#[derive(Serialize)]
struct WireSnapshot {
    request_schema: &'static str,
    response_schema: &'static str,
    receipt_schema: &'static str,
    authentication_boundary: &'static str,
    requests: Vec<String>,
    responses: Vec<String>,
    error_response: String,
    response_statuses: Vec<String>,
    readiness_values: Vec<String>,
    handoff_statuses: Vec<String>,
    progress_option_shapes: Vec<String>,
}

#[test]
fn native_wire_v1_matches_frozen_contract() {
    let contract: FreezeContract =
        serde_json::from_str(CONTRACT).expect("parse v1 freeze contract");
    assert_eq!(contract.schema, "nexus.effect-peer.wire-freeze.v1");
    assert_eq!(contract.contract_id, "nexus-effect-peer-native-v1");
    assert_eq!(contract.status, "frozen");
    assert_eq!(contract.protocol_major, 1);
    assert_eq!(contract.transport, "bounded-json-lines-lf");
    assert_eq!(
        contract.canonical_encoding,
        "serde-struct-field-order-compact-json"
    );
    assert_eq!(contract.request_schema, REQUEST_SCHEMA);
    assert_eq!(contract.response_schema, RESPONSE_SCHEMA);
    assert_eq!(contract.receipt_schema, RECEIPT_SCHEMA);
    assert_eq!(contract.authentication_boundary, AUTHENTICATION_BOUNDARY);
    assert!(!contract.change_policy.additive_v1_changes_allowed);
    assert_eq!(
        contract.change_policy.compatible_bugfixes,
        "preserve-all-frozen-v1-serde-shapes-and-semantics"
    );
    assert_eq!(
        contract.change_policy.new_capabilities,
        "new-major-version-or-explicit-versioned-extension"
    );
    assert_eq!(
        contract.change_policy.extension_requirement,
        "distinct-schema-identifiers-and-independent-freeze-contract"
    );

    let requests = request_fixtures();
    let operations: Vec<String> = requests
        .iter()
        .map(|request| {
            assert_peer_command_v1(&request.command);
            serde_json::to_value(request).unwrap()["command"]["operation"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(operations, contract.operations);

    let responses = response_fixtures();
    let receipt_kinds: Vec<String> = responses
        .iter()
        .map(|response| {
            let receipt = response.receipt.as_ref().unwrap();
            assert_native_receipt_kind_v1(receipt.kind);
            assert_native_receipt_payload_v1(&receipt.payload);
            serde_json::to_value(response).unwrap()["receipt"]["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(receipt_kinds, contract.receipt_kinds);

    let response_statuses = [ResponseStatus::Ok, ResponseStatus::Error];
    response_statuses.iter().for_each(assert_response_status_v1);
    let readiness_values = [
        NativeReadiness::ReadyToCommit,
        NativeReadiness::NeedsAbort,
        NativeReadiness::PublicationPending,
        NativeReadiness::BlockedRetained,
    ];
    readiness_values
        .iter()
        .copied()
        .for_each(assert_native_readiness_v1);
    let handoff_statuses = [
        NativeHandoffStatus::Frozen,
        NativeHandoffStatus::Aborted,
        NativeHandoffStatus::Closing,
        NativeHandoffStatus::Retained,
        NativeHandoffStatus::Closed,
    ];
    handoff_statuses
        .iter()
        .copied()
        .for_each(assert_native_handoff_status_v1);

    let snapshot = WireSnapshot {
        request_schema: REQUEST_SCHEMA,
        response_schema: RESPONSE_SCHEMA,
        receipt_schema: RECEIPT_SCHEMA,
        authentication_boundary: AUTHENTICATION_BOUNDARY,
        requests: requests
            .iter()
            .map(|request| serde_json::to_string(request).unwrap())
            .collect(),
        responses: responses
            .iter()
            .map(|response| serde_json::to_string(response).unwrap())
            .collect(),
        error_response: serde_json::to_string(&PeerResponse::error(
            99,
            "frozen-error",
            "native v1 error detail",
        ))
        .unwrap(),
        response_statuses: serialize_values(response_statuses),
        readiness_values: serialize_values(readiness_values),
        handoff_statuses: serialize_values(handoff_statuses),
        progress_option_shapes: progress_option_fixtures()
            .iter()
            .map(|payload| serde_json::to_string(payload).unwrap())
            .collect(),
    };
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(
        sha256_hex(&snapshot_bytes),
        contract.canonical_snapshot_sha256,
        "native wire v1 changed; new capabilities require v2 or an explicitly versioned extension"
    );
}

#[test]
fn native_wire_v1_decoder_rejects_noncontract_shapes() {
    for request in request_fixtures() {
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<PeerRequest>(&encoded).unwrap(),
            request
        );
    }
    for response in response_fixtures() {
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            serde_json::from_slice::<PeerResponse>(&encoded).unwrap(),
            response
        );
    }

    let missing_request_id = concat!(
        "{\"schema\":\"nexus.effect-peer.request.v1\",",
        "\"command\":{\"operation\":\"shutdown\"}}"
    );
    assert!(serde_json::from_str::<PeerRequest>(missing_request_id).is_err());

    let unknown_request_field = concat!(
        "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":1,",
        "\"command\":{\"operation\":\"shutdown\"},\"extension\":true}"
    );
    assert!(serde_json::from_str::<PeerRequest>(unknown_request_field).is_err());

    let unknown_operation = concat!(
        "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":1,",
        "\"command\":{\"operation\":\"future-operation\"}}"
    );
    assert!(serde_json::from_str::<PeerRequest>(unknown_operation).is_err());

    assert!(serde_json::from_str::<ResponseStatus>("\"pending\"").is_err());
    assert!(serde_json::from_str::<NativeReceiptKind>("\"future-receipt\"").is_err());
    assert!(serde_json::from_str::<NativeReadiness>("\"future-readiness\"").is_err());
    assert!(serde_json::from_str::<NativeHandoffStatus>("\"future-status\"").is_err());
    assert!(serde_json::from_str::<NativeReceiptPayload>("{\"kind\":\"future-payload\"}").is_err());
}

fn assert_peer_command_v1(command: &PeerCommand) {
    match command {
        PeerCommand::Initialize(_)
        | PeerCommand::Register(_)
        | PeerCommand::Prepare(_)
        | PeerCommand::Commit(_)
        | PeerCommand::Complete(_)
        | PeerCommand::AcknowledgePublication(_)
        | PeerCommand::CrashService(_)
        | PeerCommand::RebindService(_)
        | PeerCommand::Freeze(_)
        | PeerCommand::AbortUncommitted
        | PeerCommand::Thaw(_)
        | PeerCommand::CloseStep(_)
        | PeerCommand::Query
        | PeerCommand::Shutdown => {}
    }
}

fn assert_response_status_v1(status: &ResponseStatus) {
    match status {
        ResponseStatus::Ok | ResponseStatus::Error => {}
    }
}

fn assert_native_receipt_kind_v1(kind: NativeReceiptKind) {
    match kind {
        NativeReceiptKind::Initialized
        | NativeReceiptKind::EffectRegistered
        | NativeReceiptKind::EffectPrepared
        | NativeReceiptKind::EffectCommitted
        | NativeReceiptKind::EffectCompleted
        | NativeReceiptKind::PublicationAcknowledged
        | NativeReceiptKind::ServiceCrashed
        | NativeReceiptKind::ServiceRebound
        | NativeReceiptKind::AdmissionFrozen
        | NativeReceiptKind::UncommittedAborted
        | NativeReceiptKind::AdmissionThawed
        | NativeReceiptKind::ClosureProgress
        | NativeReceiptKind::HandoffQuery
        | NativeReceiptKind::Shutdown => {}
    }
}

fn assert_native_receipt_payload_v1(payload: &NativeReceiptPayload) {
    match payload {
        NativeReceiptPayload::Initialized(_)
        | NativeReceiptPayload::EffectRegistered(_)
        | NativeReceiptPayload::EffectPrepared(_)
        | NativeReceiptPayload::EffectCommitted(_)
        | NativeReceiptPayload::EffectCompleted(_)
        | NativeReceiptPayload::PublicationAcknowledged(_)
        | NativeReceiptPayload::ServiceCrashed(_)
        | NativeReceiptPayload::ServiceRebound(_)
        | NativeReceiptPayload::AdmissionFrozen(_)
        | NativeReceiptPayload::UncommittedAborted(_)
        | NativeReceiptPayload::AdmissionThawed(_)
        | NativeReceiptPayload::ClosureProgress(_)
        | NativeReceiptPayload::HandoffQuery(_)
        | NativeReceiptPayload::Shutdown => {}
    }
}

fn assert_native_readiness_v1(readiness: NativeReadiness) {
    match readiness {
        NativeReadiness::ReadyToCommit
        | NativeReadiness::NeedsAbort
        | NativeReadiness::PublicationPending
        | NativeReadiness::BlockedRetained => {}
    }
}

fn assert_native_handoff_status_v1(status: NativeHandoffStatus) {
    match status {
        NativeHandoffStatus::Frozen
        | NativeHandoffStatus::Aborted
        | NativeHandoffStatus::Closing
        | NativeHandoffStatus::Retained
        | NativeHandoffStatus::Closed => {}
    }
}

fn request_fixtures() -> Vec<PeerRequest> {
    let config = PeerConfig {
        scope_id: 11,
        scope_generation: 2,
        authority_epoch: 3,
        binding_epoch: 4,
        supervisor_id: 12,
        supervisor_generation: 5,
        task_id: 13,
        task_generation: 6,
        credit_class: 7,
        credit_limit: 8,
    };
    let selector = EffectSelector {
        client_effect: 21,
        binding_epoch: 4,
    };
    let decision = NativeOwnershipDecision {
        handoff_id: 31,
        freeze_generation: 32,
        log_identity: 33,
        decision_position: 34,
        service_incarnation: 35,
        key_identity: 36,
        request_digest: 37,
    };
    let commands = vec![
        PeerCommand::Initialize(config),
        PeerCommand::Register(RegisterEffect {
            client_effect: 21,
            operation_class: 22,
            syscall_number: 23,
            syscall_arguments: [24, 25, 26, 27, 28, 29],
            credit_units: 2,
            publication_required: true,
        }),
        PeerCommand::Prepare(selector),
        PeerCommand::Commit(CommitEffect {
            client_effect: 21,
            binding_epoch: 4,
            result: -5,
            domain_revision: 38,
        }),
        PeerCommand::Complete(CompleteEffect {
            client_effect: 21,
            binding_epoch: 4,
            result: -5,
        }),
        PeerCommand::AcknowledgePublication(selector),
        PeerCommand::CrashService(CrashService {
            supervisor_id: 12,
            supervisor_generation: 5,
            binding_epoch: 4,
        }),
        PeerCommand::RebindService(RebindService {
            crashed_binding_epoch: 5,
            replacement_supervisor_id: 14,
            replacement_supervisor_generation: 6,
        }),
        PeerCommand::Freeze(NativePrepareIntent {
            handoff_id: 31,
            log_identity: 33,
            intent_position: 30,
            service_incarnation: 35,
            key_identity: 36,
            request_digest: 37,
        }),
        PeerCommand::AbortUncommitted,
        PeerCommand::Thaw(decision),
        PeerCommand::CloseStep(decision),
        PeerCommand::Query,
        PeerCommand::Shutdown,
    ];
    commands
        .into_iter()
        .enumerate()
        .map(|(index, command)| PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: u64::try_from(index + 1).unwrap(),
            command,
        })
        .collect()
}

fn response_fixtures() -> Vec<PeerResponse> {
    let selector = EffectSelector {
        client_effect: 21,
        binding_epoch: 4,
    };
    let progress = |status, readiness, sequence| HandoffProgressPayload {
        status,
        readiness,
        freeze_generation: 32,
        scope_revision: sequence,
        authority_epoch: 3,
        binding_epoch: 4,
        live_effects: 1,
        pending_publications: 1,
        native_effect: Some(41),
        publication_pending: true,
        terminal_manifest_digest: Some(42),
    };
    let payloads = vec![
        NativeReceiptPayload::Initialized(InitializedPayload {
            process_id: 1000,
            boot_incarnation: 1,
            config: PeerConfig {
                scope_id: 11,
                scope_generation: 2,
                authority_epoch: 3,
                binding_epoch: 4,
                supervisor_id: 12,
                supervisor_generation: 5,
                task_id: 13,
                task_generation: 6,
                credit_class: 7,
                credit_limit: 8,
            },
        }),
        NativeReceiptPayload::EffectRegistered(RegisteredPayload {
            client_effect: 21,
            native_effect_id: 40,
            native_effect_generation: 1,
            authority_epoch: 3,
            binding_epoch: 4,
        }),
        NativeReceiptPayload::EffectPrepared(selector),
        NativeReceiptPayload::EffectCommitted(CommittedPayload {
            client_effect: 21,
            native_effect_id: 40,
            binding_epoch: 4,
            commit_sequence: 43,
            result: -5,
            domain_revision: 38,
            registry_replay: false,
        }),
        NativeReceiptPayload::EffectCompleted(CompletedPayload {
            client_effect: 21,
            binding_epoch: 4,
            terminal_sequence: 44,
            publication_pending: true,
        }),
        NativeReceiptPayload::PublicationAcknowledged(selector),
        NativeReceiptPayload::ServiceCrashed(ServiceCrashedPayload {
            scope_id: 11,
            scope_generation: 2,
            supervisor_id: 12,
            supervisor_generation: 5,
            previous_binding_epoch: 4,
            crashed_binding_epoch: 5,
            cohort: vec![CrashedEffectPayload {
                client_effect: 21,
                native_effect_id: 40,
                native_effect_generation: 1,
                binding_epoch: 4,
            }],
        }),
        NativeReceiptPayload::ServiceRebound(ServiceReboundPayload {
            scope_id: 11,
            scope_generation: 2,
            supervisor_id: 14,
            supervisor_generation: 6,
            binding_epoch: 5,
            adopted: vec![AdoptedEffectPayload {
                client_effect: 21,
                native_effect_id: 40,
                native_effect_generation: 1,
                previous_binding_epoch: 4,
                binding_epoch: 5,
            }],
            recovery_remaining: 0,
        }),
        NativeReceiptPayload::AdmissionFrozen(FreezePayload {
            handoff_id: 31,
            registry_instance: 45,
            boot_incarnation: 1,
            scope_id: 11,
            scope_generation: 2,
            authority_epoch: 3,
            binding_epoch: 4,
            frozen_scope_revision: 46,
            freeze_generation: 32,
            cohort_digest: 47,
            classification_digest: 48,
            cohort_size: 1,
            committed_at_freeze: 1,
            readiness: NativeReadiness::ReadyToCommit,
        }),
        NativeReceiptPayload::UncommittedAborted(AbortProgressPayload {
            aborted: 1,
            publication_effects: vec![21],
            readiness: NativeReadiness::PublicationPending,
        }),
        NativeReceiptPayload::AdmissionThawed(ThawPayload {
            handoff_id: 31,
            freeze_generation: 32,
            decision_position: 34,
            source_recovery_required: true,
        }),
        NativeReceiptPayload::ClosureProgress(progress(
            NativeHandoffStatus::Closing,
            Some(NativeReadiness::BlockedRetained),
            49,
        )),
        NativeReceiptPayload::HandoffQuery(progress(NativeHandoffStatus::Closed, None, 50)),
        NativeReceiptPayload::Shutdown,
    ];

    let mut previous = None;
    payloads
        .into_iter()
        .enumerate()
        .map(|(index, payload)| {
            let sequence = u64::try_from(index + 1).unwrap();
            let receipt = NativeReceipt::new(
                sequence,
                sha256_hex(format!("request-{sequence}").as_bytes()),
                previous.clone(),
                payload,
            )
            .unwrap();
            previous = Some(receipt.receipt_sha256.clone());
            PeerResponse::success(sequence, receipt)
        })
        .collect()
}

fn progress_option_fixtures() -> Vec<HandoffProgressPayload> {
    (0_u8..8)
        .map(|mask| HandoffProgressPayload {
            status: NativeHandoffStatus::Closing,
            readiness: (mask & 0b001 != 0).then_some(NativeReadiness::BlockedRetained),
            freeze_generation: 32,
            scope_revision: u64::from(mask) + 60,
            authority_epoch: 3,
            binding_epoch: 4,
            live_effects: 1,
            pending_publications: 1,
            native_effect: (mask & 0b010 != 0).then_some(41),
            publication_pending: true,
            terminal_manifest_digest: (mask & 0b100 != 0).then_some(42),
        })
        .collect()
}

fn serialize_values<T: Serialize, const N: usize>(values: [T; N]) -> Vec<String> {
    values
        .iter()
        .map(|value| serde_json::to_string(value).unwrap())
        .collect()
}
