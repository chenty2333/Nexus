#![allow(dead_code)]

use cser_model::handoff_admission::{
    FreezeReceipt, HandoffAdmissionModel, HandoffId, LogPosition, OwnershipAbortReceipt,
    OwnershipCommitReceipt, PrepareIntent,
};

pub const HANDOFF: HandoffId = HandoffId::new(41);
pub const LOG_IDENTITY: u64 = 51;
pub const SERVICE_INCARNATION: u64 = 61;
pub const KEY_IDENTITY: u64 = 71;

pub fn model() -> HandoffAdmissionModel {
    HandoffAdmissionModel::new(11, 21, 31, 5, 3)
}

pub const fn intent() -> PrepareIntent {
    PrepareIntent {
        handoff: HANDOFF,
        log_identity: LOG_IDENTITY,
        intent_position: LogPosition::new(1),
        service_incarnation: SERVICE_INCARNATION,
        key_identity: KEY_IDENTITY,
    }
}

pub fn abort_receipt(freeze: &FreezeReceipt) -> OwnershipAbortReceipt {
    OwnershipAbortReceipt {
        handoff: freeze.handoff(),
        freeze_generation: freeze.freeze_generation(),
        log_identity: LOG_IDENTITY,
        decision_position: LogPosition::new(2),
        service_incarnation: SERVICE_INCARNATION,
        key_identity: KEY_IDENTITY,
    }
}

pub fn commit_receipt(freeze: &FreezeReceipt) -> OwnershipCommitReceipt {
    OwnershipCommitReceipt {
        handoff: freeze.handoff(),
        freeze_generation: freeze.freeze_generation(),
        log_identity: LOG_IDENTITY,
        decision_position: LogPosition::new(2),
        service_incarnation: SERVICE_INCARNATION,
        key_identity: KEY_IDENTITY,
    }
}
