// SPDX-License-Identifier: MPL-2.0

//! Frozen serde types and canonical encoding for
//! `nexus-effect-peer-native-v1`.
//!
//! This crate owns only the independently consumable native-v1 wire. It has
//! no Registry, process server, ownership-log, or neutral-handoff dependency.

pub mod frozen_v1;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const REQUEST_SCHEMA: &str = "nexus.effect-peer.request.v1";
pub const RESPONSE_SCHEMA: &str = "nexus.effect-peer.response.v1";
pub const RECEIPT_SCHEMA: &str = "nexus.effect-peer.native-receipt.v1";
pub const AUTHENTICATION_BOUNDARY: &str = "sha256-integrity-only-not-authenticity";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRequest {
    pub schema: String,
    pub request_id: u64,
    pub command: PeerCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "kebab-case")]
pub enum PeerCommand {
    Initialize(PeerConfig),
    Register(RegisterEffect),
    Prepare(EffectSelector),
    Commit(CommitEffect),
    Complete(CompleteEffect),
    AcknowledgePublication(EffectSelector),
    CrashService(CrashService),
    RebindService(RebindService),
    Freeze(NativePrepareIntent),
    AbortUncommitted,
    Thaw(NativeOwnershipDecision),
    CloseStep(NativeOwnershipDecision),
    Query,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub task_id: u64,
    pub task_generation: u64,
    pub credit_class: u16,
    pub credit_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterEffect {
    pub client_effect: u64,
    pub operation_class: u32,
    pub syscall_number: u64,
    pub syscall_arguments: [u64; 6],
    pub credit_units: u64,
    pub publication_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSelector {
    pub client_effect: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitEffect {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub result: i64,
    pub domain_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteEffect {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub result: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashService {
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebindService {
    pub crashed_binding_epoch: u64,
    pub replacement_supervisor_id: u64,
    pub replacement_supervisor_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrepareIntent {
    pub handoff_id: u64,
    pub log_identity: u64,
    pub intent_position: u64,
    pub service_incarnation: u64,
    pub key_identity: u64,
    pub request_digest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnershipDecision {
    pub handoff_id: u64,
    pub freeze_generation: u64,
    pub log_identity: u64,
    pub decision_position: u64,
    pub service_incarnation: u64,
    pub key_identity: u64,
    pub request_digest: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseStatus {
    Ok,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerResponse {
    pub schema: String,
    pub request_id: u64,
    pub status: ResponseStatus,
    pub receipt: Option<NativeReceipt>,
    pub error: Option<NativeError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReceipt {
    pub schema: String,
    pub sequence: u64,
    pub kind: NativeReceiptKind,
    pub request_sha256: String,
    pub previous_receipt_sha256: Option<String>,
    pub payload_sha256: String,
    pub authentication_boundary: String,
    pub payload: NativeReceiptPayload,
    pub receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReceiptKind {
    Initialized,
    EffectRegistered,
    EffectPrepared,
    EffectCommitted,
    EffectCompleted,
    PublicationAcknowledged,
    ServiceCrashed,
    ServiceRebound,
    AdmissionFrozen,
    UncommittedAborted,
    AdmissionThawed,
    ClosureProgress,
    HandoffQuery,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum NativeReceiptPayload {
    Initialized(InitializedPayload),
    EffectRegistered(RegisteredPayload),
    EffectPrepared(EffectSelector),
    EffectCommitted(CommittedPayload),
    EffectCompleted(CompletedPayload),
    PublicationAcknowledged(EffectSelector),
    ServiceCrashed(ServiceCrashedPayload),
    ServiceRebound(ServiceReboundPayload),
    AdmissionFrozen(FreezePayload),
    UncommittedAborted(AbortProgressPayload),
    AdmissionThawed(ThawPayload),
    ClosureProgress(HandoffProgressPayload),
    HandoffQuery(HandoffProgressPayload),
    Shutdown,
}

impl NativeReceiptPayload {
    pub const fn receipt_kind(&self) -> NativeReceiptKind {
        match self {
            Self::Initialized(_) => NativeReceiptKind::Initialized,
            Self::EffectRegistered(_) => NativeReceiptKind::EffectRegistered,
            Self::EffectPrepared(_) => NativeReceiptKind::EffectPrepared,
            Self::EffectCommitted(_) => NativeReceiptKind::EffectCommitted,
            Self::EffectCompleted(_) => NativeReceiptKind::EffectCompleted,
            Self::PublicationAcknowledged(_) => NativeReceiptKind::PublicationAcknowledged,
            Self::ServiceCrashed(_) => NativeReceiptKind::ServiceCrashed,
            Self::ServiceRebound(_) => NativeReceiptKind::ServiceRebound,
            Self::AdmissionFrozen(_) => NativeReceiptKind::AdmissionFrozen,
            Self::UncommittedAborted(_) => NativeReceiptKind::UncommittedAborted,
            Self::AdmissionThawed(_) => NativeReceiptKind::AdmissionThawed,
            Self::ClosureProgress(_) => NativeReceiptKind::ClosureProgress,
            Self::HandoffQuery(_) => NativeReceiptKind::HandoffQuery,
            Self::Shutdown => NativeReceiptKind::Shutdown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializedPayload {
    pub process_id: u32,
    pub boot_incarnation: u64,
    pub config: PeerConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub binding_epoch: u64,
    pub commit_sequence: u64,
    pub result: i64,
    pub domain_revision: u64,
    pub registry_replay: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPayload {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub terminal_sequence: u64,
    pub publication_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashedEffectPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCrashedPayload {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub previous_binding_epoch: u64,
    pub crashed_binding_epoch: u64,
    pub cohort: Vec<CrashedEffectPayload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedEffectPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub previous_binding_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReboundPayload {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub binding_epoch: u64,
    pub adopted: Vec<AdoptedEffectPayload>,
    pub recovery_remaining: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReadiness {
    ReadyToCommit,
    NeedsAbort,
    PublicationPending,
    BlockedRetained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezePayload {
    pub handoff_id: u64,
    pub registry_instance: u64,
    pub boot_incarnation: u64,
    pub scope_id: u64,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub frozen_scope_revision: u64,
    pub freeze_generation: u64,
    pub cohort_digest: u64,
    pub classification_digest: u64,
    pub cohort_size: usize,
    pub committed_at_freeze: usize,
    pub readiness: NativeReadiness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortProgressPayload {
    pub aborted: usize,
    pub publication_effects: Vec<u64>,
    pub readiness: NativeReadiness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThawPayload {
    pub handoff_id: u64,
    pub freeze_generation: u64,
    pub decision_position: u64,
    pub source_recovery_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeHandoffStatus {
    Frozen,
    Aborted,
    Closing,
    Retained,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffProgressPayload {
    pub status: NativeHandoffStatus,
    pub readiness: Option<NativeReadiness>,
    pub freeze_generation: u64,
    pub scope_revision: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub live_effects: usize,
    pub pending_publications: usize,
    pub native_effect: Option<u64>,
    pub publication_pending: bool,
    pub terminal_manifest_digest: Option<u64>,
}

impl PeerResponse {
    pub fn success(request_id: u64, receipt: NativeReceipt) -> Self {
        Self {
            schema: RESPONSE_SCHEMA.to_owned(),
            request_id,
            status: ResponseStatus::Ok,
            receipt: Some(receipt),
            error: None,
        }
    }

    pub fn error(request_id: u64, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            schema: RESPONSE_SCHEMA.to_owned(),
            request_id,
            status: ResponseStatus::Error,
            receipt: None,
            error: Some(NativeError {
                code: code.into(),
                detail: detail.into(),
            }),
        }
    }
}

impl NativeReceipt {
    pub fn new(
        sequence: u64,
        request_sha256: String,
        previous_receipt_sha256: Option<String>,
        payload: NativeReceiptPayload,
    ) -> Result<Self, serde_json::Error> {
        let kind = payload.receipt_kind();
        let payload_sha256 = sha256_hex(&serde_json::to_vec(&payload)?);
        let digest_input = ReceiptDigestInput {
            schema: RECEIPT_SCHEMA,
            sequence,
            kind,
            request_sha256: &request_sha256,
            previous_receipt_sha256: previous_receipt_sha256.as_deref(),
            payload_sha256: &payload_sha256,
            authentication_boundary: AUTHENTICATION_BOUNDARY,
            payload: &payload,
        };
        let receipt_sha256 = sha256_hex(&serde_json::to_vec(&digest_input)?);
        Ok(Self {
            schema: RECEIPT_SCHEMA.to_owned(),
            sequence,
            kind,
            request_sha256,
            previous_receipt_sha256,
            payload_sha256,
            authentication_boundary: AUTHENTICATION_BOUNDARY.to_owned(),
            payload,
            receipt_sha256,
        })
    }

    pub fn verify_integrity(&self) -> Result<bool, serde_json::Error> {
        if self.schema != RECEIPT_SCHEMA
            || self.kind != self.payload.receipt_kind()
            || self.authentication_boundary != AUTHENTICATION_BOUNDARY
        {
            return Ok(false);
        }
        let payload_sha256 = sha256_hex(&serde_json::to_vec(&self.payload)?);
        if self.payload_sha256 != payload_sha256 {
            return Ok(false);
        }
        let digest_input = ReceiptDigestInput {
            schema: RECEIPT_SCHEMA,
            sequence: self.sequence,
            kind: self.kind,
            request_sha256: &self.request_sha256,
            previous_receipt_sha256: self.previous_receipt_sha256.as_deref(),
            payload_sha256: &self.payload_sha256,
            authentication_boundary: AUTHENTICATION_BOUNDARY,
            payload: &self.payload,
        };
        Ok(self.receipt_sha256 == sha256_hex(&serde_json::to_vec(&digest_input)?))
    }
}

pub fn canonical_request_bytes(request: &PeerRequest) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(request)
}

pub fn request_sha256(request: &PeerRequest) -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&canonical_request_bytes(request)?))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Serialize)]
struct ReceiptDigestInput<'a> {
    schema: &'static str,
    sequence: u64,
    kind: NativeReceiptKind,
    request_sha256: &'a str,
    previous_receipt_sha256: Option<&'a str>,
    payload_sha256: &'a str,
    authentication_boundary: &'static str,
    payload: &'a NativeReceiptPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_receipt_binds_payload_and_parent() {
        let receipt =
            NativeReceipt::new(1, "1".repeat(64), None, NativeReceiptPayload::Shutdown).unwrap();
        assert!(receipt.verify_integrity().unwrap());

        let mut changed = receipt;
        changed.previous_receipt_sha256 = Some("2".repeat(64));
        assert!(!changed.verify_integrity().unwrap());
    }

    #[test]
    fn service_recovery_commands_have_strict_v1_wire_shapes() {
        let crash = PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: 7,
            command: PeerCommand::CrashService(CrashService {
                supervisor_id: 11,
                supervisor_generation: 1,
                binding_epoch: 3,
            }),
        };
        assert_eq!(
            serde_json::to_string(&crash).unwrap(),
            concat!(
                "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":7,",
                "\"command\":{\"operation\":\"crash-service\",\"body\":{",
                "\"supervisor_id\":11,\"supervisor_generation\":1,\"binding_epoch\":3}}}"
            )
        );

        let rebind = PeerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: 8,
            command: PeerCommand::RebindService(RebindService {
                crashed_binding_epoch: 4,
                replacement_supervisor_id: 11,
                replacement_supervisor_generation: 2,
            }),
        };
        assert_eq!(
            serde_json::to_string(&rebind).unwrap(),
            concat!(
                "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":8,",
                "\"command\":{\"operation\":\"rebind-service\",\"body\":{",
                "\"crashed_binding_epoch\":4,\"replacement_supervisor_id\":11,",
                "\"replacement_supervisor_generation\":2}}}"
            )
        );

        let unknown = concat!(
            "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":7,",
            "\"command\":{\"operation\":\"crash-service\",\"body\":{",
            "\"supervisor_id\":11,\"supervisor_generation\":1,\"binding_epoch\":3,",
            "\"forged\":true}}}"
        );
        assert!(serde_json::from_str::<PeerRequest>(unknown).is_err());

        let unbound_selector = concat!(
            "{\"schema\":\"nexus.effect-peer.request.v1\",\"request_id\":9,",
            "\"command\":{\"operation\":\"prepare\",\"body\":{",
            "\"client_effect\":30}}}"
        );
        assert!(serde_json::from_str::<PeerRequest>(unbound_selector).is_err());
    }
}
