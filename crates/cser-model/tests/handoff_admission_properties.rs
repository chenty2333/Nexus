#[path = "handoff_admission_support/mod.rs"]
mod support;

use cser_model::handoff_admission::{
    HandoffAdmissionError, HandoffId, LogPosition, OwnershipCommitReceipt,
};
use proptest::prelude::*;
use support::{KEY_IDENTITY, LOG_IDENTITY, SERVICE_INCARNATION, commit_receipt, intent, model};

proptest! {
    #[test]
    fn decision_identity_substitutions_reject_without_mutation(
        field in 0_u8..6,
        delta in 1_u64..100,
    ) {
        let mut model = model();
        let effect = model.register_effect().unwrap();
        model.record_intent(intent()).unwrap();
        let frozen = model.freeze_admission().unwrap();
        model.abort_uncommitted(&frozen.receipt).unwrap();
        let mut receipt = commit_receipt(&frozen.receipt);
        match field {
            0 => receipt.handoff = HandoffId::new(receipt.handoff.get().saturating_add(delta)),
            1 => receipt.freeze_generation = receipt.freeze_generation.saturating_add(delta),
            2 => receipt.log_identity = LOG_IDENTITY.saturating_add(delta),
            3 => receipt.decision_position = LogPosition::new(1),
            4 => receipt.service_incarnation = SERVICE_INCARNATION.saturating_add(delta),
            _ => receipt.key_identity = KEY_IDENTITY.saturating_add(delta),
        }
        let before = model.clone();
        let result = model.commit_close(receipt);
        prop_assert!(matches!(
            result,
            Err(HandoffAdmissionError::ReceiptMismatch | HandoffAdmissionError::StaleDecision)
        ));
        prop_assert!(model.effect_disposition(effect).is_ok());
        prop_assert_eq!(model, before);
    }

    #[test]
    fn arbitrary_pre_freeze_effect_population_preserves_all_invariants(
        states in prop::collection::vec(0_u8..3, 0..8),
    ) {
        let mut model = model();
        for state in states {
            let effect = model.register_effect().unwrap();
            if state >= 1 {
                model.prepare_effect(effect).unwrap();
            }
            if state == 2 {
                model.commit_effect(effect).unwrap();
            }
        }
        model.record_intent(intent()).unwrap();
        let frozen = model.freeze_admission().unwrap();
        model.abort_uncommitted(&frozen.receipt).unwrap();
        model.check_invariants().unwrap();
    }

    #[test]
    fn exact_commit_replay_never_advances_authority_twice(extra_replays in 0_usize..12) {
        let mut model = model();
        model.register_effect().unwrap();
        model.record_intent(intent()).unwrap();
        let frozen = model.freeze_admission().unwrap();
        model.abort_uncommitted(&frozen.receipt).unwrap();
        let receipt: OwnershipCommitReceipt = commit_receipt(&frozen.receipt);
        let first = model.commit_close(receipt).unwrap();
        let epoch = model.authority_epoch();
        for _ in 0..extra_replays {
            prop_assert_eq!(model.commit_close(receipt).unwrap(), first.clone());
            prop_assert_eq!(model.authority_epoch(), epoch);
        }
        model.check_invariants().unwrap();
    }
}
