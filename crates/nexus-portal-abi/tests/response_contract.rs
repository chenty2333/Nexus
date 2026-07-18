// SPDX-License-Identifier: MPL-2.0

use nexus_portal_abi::{
    AbiResponse, CapabilityOffer, ClosureReceipt, ClosureStatus, Digest, EffectHandle,
    EffectObservation, EffectOutcomeObservation, EffectPhase, ErrorResponse, LifecycleFlags,
    LifecycleReceipt, MAX_MUTATION_BODY_SIZE, MAX_RESPONSE_BODY_SIZE, NegotiatedCapabilities,
    NegotiatedResponse, OutcomeKind, PortalCapabilities, PortalErrorCode, PortalFailure,
    PortalLimits, ProviderCapabilities, ReceiptHandle, ReceiptKind, ReceiptObservation,
    ReceiptStatus, ResponseBody, RetryClass, ScopeHandle, ScopeObservation, ScopePhase,
    SessionHandle,
};

fn handle(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn digest(byte: u8) -> Digest {
    Digest::from_wire_bytes([byte; 32])
}

fn outcome(kind: OutcomeKind) -> EffectOutcomeObservation {
    EffectOutcomeObservation::new(kind, -5, digest(0xa5)).unwrap()
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
    assert_eq!(AbiResponse::WIRE_SIZE, 80);
    assert_eq!(NegotiatedResponse::WIRE_SIZE, 48);
    assert_eq!(nexus_portal_abi::ScopeCreatedResponse::WIRE_SIZE, 120);
    assert_eq!(LifecycleReceipt::WIRE_SIZE, 144);
    assert_eq!(ClosureReceipt::WIRE_SIZE, 176);
    assert_eq!(ScopeObservation::WIRE_SIZE, 120);
    assert_eq!(EffectObservation::WIRE_SIZE, 216);
    assert_eq!(ReceiptObservation::WIRE_SIZE, 112);
    assert_eq!(ErrorResponse::WIRE_SIZE, 96);

    assert_round_trip(
        AbiResponse::with_limits(offer, PortalLimits::new(3, 4, 8, 2, 16, 32, 24, 7).unwrap())
            .unwrap(),
    );
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
            9,
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
            Some(outcome(OutcomeKind::Data)),
            None,
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
fn abi_response_reports_exact_endpoint_limits_and_rejects_partial_limits() {
    let offer = CapabilityOffer {
        portal: PortalCapabilities::all(),
        provider: ProviderCapabilities::all(),
    };
    let limits = PortalLimits::new(3, 4, 8, 2, 16, 32, 24, 7).unwrap();
    let response = AbiResponse::with_limits(offer, limits).unwrap();
    assert_eq!(response.limits(), limits);
    assert_eq!(limits.max_scopes(), 3);
    assert_eq!(limits.max_effects_per_scope(), 4);
    assert_eq!(limits.max_effect_selectors(), 8);
    assert_eq!(limits.max_tombstones_per_scope(), 2);
    assert_eq!(limits.max_queue_credits_per_scope(), 16);
    assert_eq!(limits.max_page_credits_per_scope(), 32);
    assert_eq!(limits.max_receipts(), 24);
    assert_eq!(limits.max_replay_entries(), 7);

    let mut bytes = [0; AbiResponse::WIRE_SIZE];
    response.encode_wire(&mut bytes).unwrap();
    for (offset, value) in [
        (40, 3_u32),
        (44, 4),
        (48, 8),
        (52, 2),
        (56, 16),
        (60, 32),
        (64, 24),
        (68, 7),
    ] {
        assert_eq!(&bytes[offset..offset + 4], &value.to_le_bytes());
    }
    assert_eq!(&bytes[72..80], &[0; 8]);
    assert_eq!(AbiResponse::decode_wire(&bytes).unwrap(), response);

    for (offset, value, expected_offset) in [
        (40, 0_u32, 40_usize),
        (44, 0, 44),
        (48, 0, 48),
        (52, 5, 52),
        (56, 0, 56),
        (60, 0, 60),
        (64, 0, 64),
        (68, 0, 68),
    ] {
        let mut invalid = bytes;
        invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let error = AbiResponse::decode_wire(&invalid).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::LimitExceeded);
        assert_eq!(error.offset(), expected_offset);
    }

    let mut reserved = bytes;
    reserved[72] = 1;
    let error = AbiResponse::decode_wire(&reserved).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::NonZeroTail);
    assert_eq!(error.offset(), 72);
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
fn query_observations_have_exact_little_endian_golden_vectors() {
    let scope = ScopeObservation::new(
        ScopeHandle::from_wire_bytes(handle(1)),
        2,
        3,
        4,
        5,
        ScopePhase::Closing,
        6,
        7,
        8,
        ReceiptHandle::from_wire_bytes(handle(9)),
        digest(10),
    )
    .unwrap();
    assert_eq!(scope.domain_revision(), 5);
    let mut scope_bytes = [0; ScopeObservation::WIRE_SIZE];
    scope.encode_wire(&mut scope_bytes).unwrap();
    let scope_golden = [
        &[1; 16][..],
        &[2, 0, 0, 0, 0, 0, 0, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0],
        &[4, 0, 0, 0, 0, 0, 0, 0],
        &[5, 0, 0, 0, 0, 0, 0, 0],
        &[2, 0],
        &[0; 6],
        &[6, 0, 0, 0],
        &[7, 0, 0, 0],
        &[8, 0, 0, 0],
        &[0; 4],
        &[9; 16],
        &[10; 32],
    ]
    .concat();
    assert_eq!(scope_bytes.as_slice(), scope_golden);

    let effect = EffectObservation::new(
        ScopeHandle::from_wire_bytes(handle(1)),
        EffectHandle::from_wire_bytes(handle(2)),
        3,
        4,
        5,
        EffectPhase::Completed,
        Some(EffectOutcomeObservation::new(OutcomeKind::Error, -5, digest(6)).unwrap()),
        Some(digest(7)),
        LifecycleFlags::TERMINAL,
        ReceiptHandle::from_wire_bytes(handle(8)),
        digest(9),
        digest(10),
    )
    .unwrap();
    assert_eq!(effect.outcome().unwrap().kind(), OutcomeKind::Error);
    assert_eq!(effect.outcome().unwrap().result(), -5);
    assert_eq!(effect.outcome().unwrap().digest(), digest(6));
    assert_eq!(effect.terminal_digest(), Some(digest(7)));
    let mut effect_bytes = [0; EffectObservation::WIRE_SIZE];
    effect.encode_wire(&mut effect_bytes).unwrap();
    let effect_golden = [
        &[1; 16][..],
        &[2; 16],
        &[3, 0, 0, 0, 0, 0, 0, 0],
        &[4, 0, 0, 0, 0, 0, 0, 0],
        &[5, 0, 0, 0, 0, 0, 0, 0],
        &[5, 0],
        &[2, 0],
        &[4, 0, 0, 0],
        &[0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[6; 32],
        &[7; 32],
        &[8; 16],
        &[9; 32],
        &[10; 32],
    ]
    .concat();
    assert_eq!(effect_bytes.as_slice(), effect_golden);
}

#[test]
fn effect_observation_wire_rejects_partial_outcomes_and_reports_digest_offsets() {
    let registered = EffectObservation::new(
        ScopeHandle::from_wire_bytes(handle(1)),
        EffectHandle::from_wire_bytes(handle(2)),
        3,
        4,
        5,
        EffectPhase::Registered,
        None,
        None,
        LifecycleFlags::empty(),
        ReceiptHandle::NULL,
        digest(9),
        digest(10),
    )
    .unwrap();
    let mut bytes = [0; EffectObservation::WIRE_SIZE];
    registered.encode_wire(&mut bytes).unwrap();
    bytes[64] = 1;
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::Conflict);
    assert_eq!(error.offset(), 64);

    registered.encode_wire(&mut bytes).unwrap();
    bytes[72] = 1;
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::Conflict);
    assert_eq!(error.offset(), 64);

    registered.encode_wire(&mut bytes).unwrap();
    bytes[58..60].copy_from_slice(&OutcomeKind::Data.wire_value().to_le_bytes());
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::InvalidDigest);
    assert_eq!(error.offset(), 72);

    registered.encode_wire(&mut bytes).unwrap();
    bytes[152..184].fill(0);
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::InvalidDigest);
    assert_eq!(error.offset(), 152);

    registered.encode_wire(&mut bytes).unwrap();
    bytes[184..216].fill(0);
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::InvalidDigest);
    assert_eq!(error.offset(), 184);

    let completed = EffectObservation::new(
        ScopeHandle::from_wire_bytes(handle(1)),
        EffectHandle::from_wire_bytes(handle(2)),
        3,
        4,
        5,
        EffectPhase::Completed,
        Some(outcome(OutcomeKind::Data)),
        Some(digest(7)),
        LifecycleFlags::TERMINAL,
        ReceiptHandle::NULL,
        digest(9),
        digest(10),
    )
    .unwrap();
    completed.encode_wire(&mut bytes).unwrap();
    bytes[58..60].copy_from_slice(&OutcomeKind::Indeterminate.wire_value().to_le_bytes());
    let error = EffectObservation::decode_wire(&bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::Conflict);
    assert_eq!(error.offset(), 58);
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

    let dangling_completion = ProviderCapabilities::EFFECT_COMPLETION;
    let invalid_abi = AbiResponse::new(CapabilityOffer {
        portal: PortalCapabilities::all(),
        provider: dangling_completion,
    });
    let mut abi_bytes = [0; AbiResponse::WIRE_SIZE];
    let error = invalid_abi.encode_wire(&mut abi_bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::MissingRequiredCapability);
    assert_eq!(error.offset(), 32);

    AbiResponse::new(CapabilityOffer {
        portal: PortalCapabilities::all(),
        provider: ProviderCapabilities::all(),
    })
    .encode_wire(&mut abi_bytes)
    .unwrap();
    abi_bytes[32..40].copy_from_slice(&dangling_completion.bits().to_le_bytes());
    let error = AbiResponse::decode_wire(&abi_bytes).unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::MissingRequiredCapability);
    assert_eq!(error.offset(), 32);

    let error = NegotiatedResponse::new(
        SessionHandle::from_wire_bytes(handle(1)),
        NegotiatedCapabilities {
            portal: PortalCapabilities::empty(),
            provider: dangling_completion,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), PortalErrorCode::MissingRequiredCapability);
    assert_eq!(error.offset(), 24);
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

    let observation = |phase, outcome, terminal_digest, flags| {
        EffectObservation::new(
            ScopeHandle::from_wire_bytes(handle(1)),
            EffectHandle::from_wire_bytes(handle(2)),
            3,
            4,
            5,
            phase,
            outcome,
            terminal_digest,
            flags,
            ReceiptHandle::from_wire_bytes(handle(6)),
            digest(7),
            digest(8),
        )
    };
    for phase in [
        EffectPhase::Registered,
        EffectPhase::Prepared,
        EffectPhase::Committed,
    ] {
        assert!(observation(phase, None, None, LifecycleFlags::empty()).is_ok());
        assert_eq!(
            observation(
                phase,
                Some(outcome(OutcomeKind::Data)),
                None,
                LifecycleFlags::empty(),
            )
            .unwrap_err()
            .code(),
            PortalErrorCode::Conflict,
        );
        assert_eq!(
            observation(phase, None, Some(digest(9)), LifecycleFlags::empty())
                .unwrap_err()
                .code(),
            PortalErrorCode::Conflict,
        );
    }

    assert!(
        observation(
            EffectPhase::OutcomeRecorded,
            Some(outcome(OutcomeKind::Error)),
            None,
            LifecycleFlags::empty(),
        )
        .is_ok()
    );
    assert_eq!(
        observation(
            EffectPhase::OutcomeRecorded,
            None,
            None,
            LifecycleFlags::empty(),
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );

    for terminal_digest in [None, Some(digest(9))] {
        assert!(
            observation(
                EffectPhase::Completed,
                Some(outcome(OutcomeKind::Data)),
                terminal_digest,
                LifecycleFlags::TERMINAL,
            )
            .is_ok(),
            "terminal manifest digest is optional in the session-local projection",
        );
        assert!(
            observation(
                EffectPhase::Aborted,
                None,
                terminal_digest,
                LifecycleFlags::TERMINAL,
            )
            .is_ok(),
        );
        assert!(
            observation(
                EffectPhase::Retained,
                Some(outcome(OutcomeKind::Indeterminate)),
                terminal_digest,
                retained_flags,
            )
            .is_ok(),
        );
    }
    assert_eq!(
        observation(
            EffectPhase::Completed,
            None,
            Some(digest(9)),
            LifecycleFlags::TERMINAL,
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );
    assert_eq!(
        observation(
            EffectPhase::Completed,
            Some(outcome(OutcomeKind::Indeterminate)),
            Some(digest(9)),
            LifecycleFlags::TERMINAL,
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::Conflict,
    );
    assert!(
        observation(EffectPhase::Retained, None, None, retained_flags).is_ok(),
        "retained work may precede a canonical outcome",
    );
    assert_eq!(
        observation(
            EffectPhase::Retained,
            Some(outcome(OutcomeKind::Indeterminate)),
            None,
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
            5,
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
            5,
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
