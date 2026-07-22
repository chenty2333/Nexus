// SPDX-License-Identifier: MPL-2.0

//! Stable native-v1 contract bytes and canonical fixture generator.
//!
//! The corpus is producer-owned source material for independent consumers to
//! recompute the frozen serde snapshot. It is not runtime evidence, process
//! authentication, or a neutral handoff receipt.

use serde::Serialize;

use crate::*;

/// Byte-identical package-local copy of the repository freeze contract.
pub const CONTRACT_JSON: &str = include_str!("../contract/effect-peer-native-v1.json");
/// SHA-256 of [`CONTRACT_JSON`] at the native-v1 freeze.
pub const CONTRACT_SHA256: &str =
    "d9bec4547eb0d09a081033e619bb16179c36d992db2b754659594831e21737d2";
/// Frozen SHA-256 of [`canonical_snapshot_bytes`].
pub const SNAPSHOT_SHA256: &str =
    "036bfa21c9c1359755d9cf9a8223e39b7ea1d4793bf4fa948efbf75c9fa52b08";

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

/// Generates the ordered request fixture for every frozen native-v1 command.
#[must_use]
pub fn request_corpus() -> Vec<PeerRequest> {
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
            request_id: u64::try_from(index + 1).expect("native-v1 fixture index fits u64"),
            command,
        })
        .collect()
}

/// Generates the ordered response fixture for every frozen receipt kind.
pub fn response_corpus() -> Result<Vec<PeerResponse>, serde_json::Error> {
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
    let mut responses = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.into_iter().enumerate() {
        let sequence = u64::try_from(index + 1).expect("native-v1 fixture index fits u64");
        let receipt = NativeReceipt::new(
            sequence,
            sha256_hex(format!("request-{sequence}").as_bytes()),
            previous.clone(),
            payload,
        )?;
        previous = Some(receipt.receipt_sha256.clone());
        responses.push(PeerResponse::success(sequence, receipt));
    }
    Ok(responses)
}

/// Generates the eight optional-field shapes frozen for progress receipts.
#[must_use]
pub fn progress_option_corpus() -> Vec<HandoffProgressPayload> {
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

/// Recomputes the exact producer-owned native-v1 canonical snapshot bytes.
pub fn canonical_snapshot_bytes() -> Result<Vec<u8>, serde_json::Error> {
    let requests = request_corpus();
    let responses = response_corpus()?;
    let snapshot = WireSnapshot {
        request_schema: REQUEST_SCHEMA,
        response_schema: RESPONSE_SCHEMA,
        receipt_schema: RECEIPT_SCHEMA,
        authentication_boundary: AUTHENTICATION_BOUNDARY,
        requests: serialize_iter(requests.iter())?,
        responses: serialize_iter(responses.iter())?,
        error_response: serde_json::to_string(&PeerResponse::error(
            99,
            "frozen-error",
            "native v1 error detail",
        ))?,
        response_statuses: serialize_iter([ResponseStatus::Ok, ResponseStatus::Error].iter())?,
        readiness_values: serialize_iter(
            [
                NativeReadiness::ReadyToCommit,
                NativeReadiness::NeedsAbort,
                NativeReadiness::PublicationPending,
                NativeReadiness::BlockedRetained,
            ]
            .iter(),
        )?,
        handoff_statuses: serialize_iter(
            [
                NativeHandoffStatus::Frozen,
                NativeHandoffStatus::Aborted,
                NativeHandoffStatus::Closing,
                NativeHandoffStatus::Retained,
                NativeHandoffStatus::Closed,
            ]
            .iter(),
        )?,
        progress_option_shapes: serialize_iter(progress_option_corpus().iter())?,
    };
    serde_json::to_vec(&snapshot)
}

/// Recomputes the SHA-256 of [`canonical_snapshot_bytes`].
pub fn canonical_snapshot_sha256() -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&canonical_snapshot_bytes()?))
}

fn serialize_iter<'a, T: 'a + Serialize>(
    values: impl IntoIterator<Item = &'a T>,
) -> Result<Vec<String>, serde_json::Error> {
    values.into_iter().map(serde_json::to_string).collect()
}
