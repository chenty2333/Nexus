// SPDX-License-Identifier: MPL-2.0

use nexus_portal_abi::{
    AbiResponse, CapabilityOffer, ClosureReceipt, ClosureStatus, Digest, EffectHandle,
    EffectObservation, EffectPhase, ErrorResponse, LifecycleFlags, LifecycleReceipt,
    MAX_MUTATION_BODY_SIZE, MAX_RESPONSE_BODY_SIZE, NegotiatedCapabilities, NegotiatedResponse,
    OutcomeKind, PortalCapabilities, PortalErrorCode, PortalFailure, ProviderCapabilities,
    ReceiptHandle, ReceiptKind, ReceiptObservation, ReceiptStatus, ResponseBody, RetryClass,
    ScopeHandle, ScopeObservation, ScopePhase, SessionHandle,
};

fn handle(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn digest(byte: u8) -> Digest {
    Digest::from_wire_bytes([byte; 32])
}

fn lifecycle_receipt() -> LifecycleReceipt {
    LifecycleReceipt::new(
        ScopeHandle::from_wire_bytes(handle(1)),
        EffectHandle::from_wire_bytes(handle(2)),
        ReceiptHandle::from_wire_bytes(handle(3)),
        4,
        5,
        6,
        EffectPhase::Committed,
        ReceiptKind::EffectCommitted,
        LifecycleFlags::PUBLICATION_PENDING,
        digest(7),
        digest(8),
    )
    .unwrap()
}

fn assert_round_trip<T: ResponseBody + core::fmt::Debug + PartialEq>(value: T) {
    assert!(T::WIRE_SIZE <= MAX_RESPONSE_BODY_SIZE);
    let mut bytes = vec![0; T::WIRE_SIZE];
    value.encode_wire(&mut bytes).unwrap();
    assert_eq!(T::decode_wire(&bytes).unwrap(), value);
    for size in [T::WIRE_SIZE.saturating_sub(1), T::WIRE_SIZE + 1] {
        if size == T::WIRE_SIZE {
            continue;
        }
        assert_eq!(
            T::decode_wire(&vec![0; size]).unwrap_err().code(),
            PortalErrorCode::BodySizeMismatch,
        );
    }
}

#[test]
fn every_bounded_response_round_trips_at_its_frozen_size() {
    let offer = CapabilityOffer {
        portal: PortalCapabilities::all(),
        provider: ProviderCapabilities::all(),
    };
    assert_eq!(MAX_MUTATION_BODY_SIZE, 128);
    assert_eq!(MAX_RESPONSE_BODY_SIZE, 256);
    assert_eq!(AbiResponse::WIRE_SIZE, 64);
    assert_eq!(NegotiatedResponse::WIRE_SIZE, 48);
    assert_eq!(nexus_portal_abi::ScopeCreatedResponse::WIRE_SIZE, 120);
    assert_eq!(LifecycleReceipt::WIRE_SIZE, 144);
    assert_eq!(ClosureReceipt::WIRE_SIZE, 176);
    assert_eq!(ScopeObservation::WIRE_SIZE, 112);
    assert_eq!(EffectObservation::WIRE_SIZE, 144);
    assert_eq!(ReceiptObservation::WIRE_SIZE, 112);
    assert_eq!(ErrorResponse::WIRE_SIZE, 96);

    assert_round_trip(AbiResponse::new(offer));
    assert_round_trip(
        NegotiatedResponse::new(
            SessionHandle::from_wire_bytes(handle(9)),
            NegotiatedCapabilities {
                portal: PortalCapabilities::QUERY_SCOPE | PortalCapabilities::EFFECT_LIFECYCLE,
                provider: ProviderCapabilities::EFFECT_CLOSURE
                    | ProviderCapabilities::SESSION_QUERY,
            },
        )
        .unwrap(),
    );
    assert_round_trip(
        nexus_portal_abi::ScopeCreatedResponse::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            ReceiptHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            digest(6),
            digest(7),
        )
        .unwrap(),
    );
    assert_round_trip(lifecycle_receipt());
    assert_round_trip(
        ClosureReceipt::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            ReceiptHandle::from_wire_bytes(handle(2)),
            4,
            5,
            6,
            ClosureStatus::Closed,
            0,
            0,
            0,
            digest(7),
            digest(8),
            digest(9),
        )
        .unwrap(),
    );
    assert_round_trip(
        ScopeObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            2,
            3,
            4,
            ScopePhase::Closing,
            5,
            6,
            7,
            ReceiptHandle::NULL,
            digest(8),
        )
        .unwrap(),
    );
    assert_round_trip(
        EffectObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            EffectHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            EffectPhase::OutcomeRecorded,
            Some(OutcomeKind::Data),
            LifecycleFlags::empty(),
            ReceiptHandle::from_wire_bytes(handle(6)),
            digest(7),
            digest(8),
        )
        .unwrap(),
    );
    assert_round_trip(
        ReceiptObservation::new(
            ReceiptHandle::from_wire_bytes(handle(1)),
            2,
            3,
            4,
            ReceiptKind::OutcomeRecorded,
            ReceiptStatus::Consumed,
            digest(5),
            digest(6),
        )
        .unwrap(),
    );
    assert_round_trip(ErrorResponse::new(
        PortalFailure::new(PortalErrorCode::Conflict, RetryClass::Never, 11)
            .with_epochs(12, 13)
            .with_digests(digest(14), digest(15)),
    ));
}

#[test]
fn lifecycle_response_has_stable_little_endian_fields() {
    let receipt = lifecycle_receipt();
    let mut bytes = [0; LifecycleReceipt::WIRE_SIZE];
    receipt.encode_wire(&mut bytes).unwrap();
    assert_eq!(&bytes[0..16], &handle(1));
    assert_eq!(&bytes[16..32], &handle(2));
    assert_eq!(&bytes[32..48], &handle(3));
    assert_eq!(&bytes[48..56], &4_u64.to_le_bytes());
    assert_eq!(&bytes[56..64], &5_u64.to_le_bytes());
    assert_eq!(&bytes[64..72], &6_u64.to_le_bytes());
    assert_eq!(
        &bytes[72..74],
        &EffectPhase::Committed.wire_value().to_le_bytes()
    );
    assert_eq!(
        &bytes[74..76],
        &ReceiptKind::EffectCommitted.wire_value().to_le_bytes(),
    );
    assert_eq!(
        &bytes[76..80],
        &LifecycleFlags::PUBLICATION_PENDING.bits().to_le_bytes(),
    );
    assert_eq!(&bytes[80..112], &[7; 32]);
    assert_eq!(&bytes[112..144], &[8; 32]);
}

#[test]
fn response_unknown_enum_flags_reserved_and_conflicting_closure_fail_closed() {
    let mut lifecycle = [0; LifecycleReceipt::WIRE_SIZE];
    lifecycle_receipt().encode_wire(&mut lifecycle).unwrap();
    lifecycle[72..74].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        LifecycleReceipt::decode_wire(&lifecycle)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidEnum,
    );
    lifecycle_receipt().encode_wire(&mut lifecycle).unwrap();
    lifecycle[76..80].copy_from_slice(&(1_u32 << 31).to_le_bytes());
    assert_eq!(
        LifecycleReceipt::decode_wire(&lifecycle)
            .unwrap_err()
            .code(),
        PortalErrorCode::UnknownFlags,
    );

    let error = ErrorResponse::new(PortalFailure::new(
        PortalErrorCode::Conflict,
        RetryClass::Never,
        0,
    ));
    let mut error_bytes = [0; ErrorResponse::WIRE_SIZE];
    error.encode_wire(&mut error_bytes).unwrap();
    error_bytes[4] = 1;
    assert_eq!(
        ErrorResponse::decode_wire(&error_bytes).unwrap_err().code(),
        PortalErrorCode::NonZeroTail,
    );

    assert_eq!(
        ClosureReceipt::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            ReceiptHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            ClosureStatus::Closed,
            1,
            0,
            0,
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );

    assert_eq!(
        NegotiatedResponse::new(
            SessionHandle::from_wire_bytes(handle(1)),
            NegotiatedCapabilities {
                portal: PortalCapabilities::from_bits_retain(1_u64 << 63),
                provider: ProviderCapabilities::empty(),
            },
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::UnknownCapability,
    );
    assert_eq!(
        NegotiatedResponse::new(
            SessionHandle::from_wire_bytes(handle(1)),
            NegotiatedCapabilities {
                portal: PortalCapabilities::empty(),
                provider: ProviderCapabilities::from_bits_retain(1_u64 << 63),
            },
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::UnknownCapability,
    );
}

#[test]
fn effect_flags_outcomes_and_closure_counts_form_consistent_states() {
    let retained_flags = LifecycleFlags::TERMINAL | LifecycleFlags::RETAINED;
    assert!(
        LifecycleReceipt::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            EffectHandle::from_wire_bytes(handle(2)),
            ReceiptHandle::from_wire_bytes(handle(3)),
            4,
            5,
            6,
            EffectPhase::Retained,
            ReceiptKind::EffectCompleted,
            retained_flags,
            digest(7),
            digest(8),
        )
        .is_ok()
    );
    assert_eq!(
        LifecycleReceipt::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            EffectHandle::from_wire_bytes(handle(2)),
            ReceiptHandle::from_wire_bytes(handle(3)),
            4,
            5,
            6,
            EffectPhase::Retained,
            ReceiptKind::EffectCompleted,
            LifecycleFlags::TERMINAL,
            digest(7),
            digest(8),
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );

    let observation = |phase, outcome_kind, flags| {
        EffectObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            EffectHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            phase,
            outcome_kind,
            flags,
            ReceiptHandle::from_wire_bytes(handle(6)),
            digest(7),
            digest(8),
        )
    };
    assert_eq!(
        observation(
            EffectPhase::Registered,
            Some(OutcomeKind::Data),
            LifecycleFlags::empty(),
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );
    assert_eq!(
        observation(EffectPhase::Completed, None, LifecycleFlags::TERMINAL,)
            .unwrap_err()
            .code(),
        PortalErrorCode::Conflict,
    );
    assert!(
        observation(EffectPhase::Retained, None, retained_flags).is_ok(),
        "retained work may precede a canonical outcome",
    );
    assert_eq!(
        observation(
            EffectPhase::Retained,
            Some(OutcomeKind::Indeterminate),
            LifecycleFlags::TERMINAL,
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );

    let closure = |status, live, pending, retained, closure_digest| {
        ClosureReceipt::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            ReceiptHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            status,
            live,
            pending,
            retained,
            closure_digest,
            digest(7),
            digest(8),
        )
    };
    assert_eq!(
        closure(ClosureStatus::Closed, 0, 0, 0, Digest::ZERO)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidDigest,
    );
    assert_eq!(
        closure(ClosureStatus::Closing, 0, 0, 0, digest(6))
            .unwrap_err()
            .code(),
        PortalErrorCode::Conflict,
    );
    assert!(closure(ClosureStatus::Closing, 1, 0, 0, digest(6)).is_ok());
    assert_eq!(
        closure(ClosureStatus::Retained, 1, 0, 1, digest(6))
            .unwrap_err()
            .code(),
        PortalErrorCode::Conflict,
    );
    assert!(closure(ClosureStatus::Retained, 0, 0, 1, digest(6)).is_ok());

    assert_eq!(
        ScopeObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            2,
            3,
            4,
            ScopePhase::Revoked,
            1,
            0,
            0,
            ReceiptHandle::NULL,
            digest(8),
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );
    assert!(
        ScopeObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            2,
            3,
            4,
            ScopePhase::Revoked,
            0,
            0,
            1,
            ReceiptHandle::from_wire_bytes(handle(9)),
            digest(8),
        )
        .is_ok()
    );
}

#[test]
fn response_enum_discriminants_reject_every_unassigned_value() {
    for value in u16::MIN..=u16::MAX {
        assert_eq!(
            EffectPhase::from_wire_value(value),
            [
                EffectPhase::Registered,
                EffectPhase::Prepared,
                EffectPhase::Committed,
                EffectPhase::OutcomeRecorded,
                EffectPhase::Completed,
                EffectPhase::Aborted,
                EffectPhase::Retained,
            ]
            .into_iter()
            .find(|item| item.wire_value() == value),
        );
        assert_eq!(
            ReceiptKind::from_wire_value(value),
            [
                ReceiptKind::ScopeCreated,
                ReceiptKind::EffectRegistered,
                ReceiptKind::EffectPrepared,
                ReceiptKind::EffectCommitted,
                ReceiptKind::OutcomeRecorded,
                ReceiptKind::EffectCompleted,
                ReceiptKind::ScopeRevoked,
                ReceiptKind::Closure,
            ]
            .into_iter()
            .find(|item| item.wire_value() == value),
        );
        assert_eq!(
            ScopePhase::from_wire_value(value),
            [ScopePhase::Active, ScopePhase::Closing, ScopePhase::Revoked]
                .into_iter()
                .find(|item| item.wire_value() == value),
        );
        assert_eq!(
            ClosureStatus::from_wire_value(value),
            [
                ClosureStatus::Closing,
                ClosureStatus::Closed,
                ClosureStatus::Retained,
            ]
            .into_iter()
            .find(|item| item.wire_value() == value),
        );
        assert_eq!(
            ReceiptStatus::from_wire_value(value),
            [
                ReceiptStatus::Live,
                ReceiptStatus::Consumed,
                ReceiptStatus::Retained,
            ]
            .into_iter()
            .find(|item| item.wire_value() == value),
        );
        assert_eq!(
            RetryClass::from_wire_value(value),
            [
                RetryClass::Never,
                RetryClass::ExactRequest,
                RetryClass::AfterQuery,
                RetryClass::AfterCapacity,
                RetryClass::NewSession,
            ]
            .into_iter()
            .find(|item| item.wire_value() == value),
        );
    }
}
