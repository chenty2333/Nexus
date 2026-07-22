// SPDX-License-Identifier: MPL-2.0

use nexus_effect_peer_wire::{
    AUTHENTICATION_BOUNDARY, NativeHandoffStatus, NativeReadiness, NativeReceiptKind,
    NativeReceiptPayload, PeerCommand, PeerRequest, PeerResponse, RECEIPT_SCHEMA, REQUEST_SCHEMA,
    RESPONSE_SCHEMA, ResponseStatus,
    frozen_v1::{
        CONTRACT_JSON, CONTRACT_SHA256, SNAPSHOT_SHA256, canonical_snapshot_sha256, request_corpus,
        response_corpus,
    },
    sha256_hex,
};
use serde::Deserialize;

const REPOSITORY_CONTRACT: &str = include_str!("../../../status/effect-peer-native-v1.json");

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

#[test]
fn package_contract_and_corpus_match_the_repository_freeze() {
    assert_eq!(CONTRACT_JSON, REPOSITORY_CONTRACT);
    assert_eq!(sha256_hex(CONTRACT_JSON.as_bytes()), CONTRACT_SHA256);
    let contract: FreezeContract = serde_json::from_str(CONTRACT_JSON).unwrap();
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
    assert_eq!(contract.canonical_snapshot_sha256, SNAPSHOT_SHA256);
    assert_eq!(canonical_snapshot_sha256().unwrap(), SNAPSHOT_SHA256);
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

    let requests = request_corpus();
    let operations = requests
        .iter()
        .map(|request| {
            assert_command_is_frozen(&request.command);
            serde_json::to_value(request).unwrap()["command"]["operation"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(operations, contract.operations);

    let responses = response_corpus().unwrap();
    let receipt_kinds = responses
        .iter()
        .map(|response| {
            let receipt = response.receipt.as_ref().unwrap();
            assert_receipt_is_frozen(receipt.kind, &receipt.payload);
            serde_json::to_value(response).unwrap()["receipt"]["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(receipt_kinds, contract.receipt_kinds);
}

#[test]
fn current_decoder_rejects_noncontract_shapes() {
    for request in request_corpus() {
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<PeerRequest>(&encoded).unwrap(),
            request
        );
    }
    for response in response_corpus().unwrap() {
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

fn assert_command_is_frozen(command: &PeerCommand) {
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

fn assert_receipt_is_frozen(kind: NativeReceiptKind, payload: &NativeReceiptPayload) {
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
