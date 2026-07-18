// SPDX-License-Identifier: MPL-2.0

use nexus_portal_abi::{
    CommitEffectRequest, CompleteEffectRequest, CompletionDisposition, CreditKind, Digest,
    EffectHandle, MutationContext, Opcode, OutcomeKind, PortalErrorCode, PrepareEffectRequest,
    RecordOutcomeRequest, RegisterEffectRequest, RegisterFlags, RequestBody, RevokeReason,
    RevokeScopeRequest, ScopeHandle, SessionHandle,
};

fn digest(byte: u8) -> Digest {
    Digest::from_wire_bytes([byte; 32])
}

fn context() -> MutationContext {
    MutationContext::new(
        SessionHandle::from_wire_bytes([0x11; 16]),
        3,
        4,
        digest(0x22),
    )
    .unwrap()
}

fn effect() -> EffectHandle {
    EffectHandle::from_wire_bytes([0x55; 16])
}

fn assert_wrong_sizes_reject<T: RequestBody + core::fmt::Debug>(request: &T) {
    for size in 0..=T::WIRE_SIZE + 1 {
        if size == T::WIRE_SIZE {
            continue;
        }
        assert_eq!(
            T::decode_wire(&vec![0; size]).unwrap_err().code(),
            PortalErrorCode::BodySizeMismatch,
            "opcode={:?} size={size}",
            T::OPCODE,
        );
        let mut output = vec![0xa5; size];
        let before = output.clone();
        assert_eq!(
            request.encode_wire(&mut output).unwrap_err().code(),
            PortalErrorCode::BodySizeMismatch,
        );
        assert_eq!(output, before);
    }
}

#[test]
fn lifecycle_opcodes_sizes_and_exact_round_trips_are_frozen() {
    let register = RegisterEffectRequest::new(
        context(),
        ScopeHandle::from_wire_bytes([0x33; 16]),
        EffectHandle::from_wire_bytes([0x44; 16]),
        0x1122_3344,
        RegisterFlags::PUBLICATION_REQUIRED,
        CreditKind::Page,
        5,
    )
    .unwrap();
    let prepare = PrepareEffectRequest::new(context(), effect()).unwrap();
    let commit = CommitEffectRequest::new(context(), effect(), 9).unwrap();
    let outcome =
        RecordOutcomeRequest::new(context(), effect(), OutcomeKind::Error, -5, digest(0x66))
            .unwrap();
    let complete = CompleteEffectRequest::new(
        context(),
        effect(),
        CompletionDisposition::Completed,
        digest(0x77),
    )
    .unwrap();
    let revoke = RevokeScopeRequest::new(
        context(),
        ScopeHandle::from_wire_bytes([0x33; 16]),
        RevokeReason::Deadline,
    )
    .unwrap();

    assert_eq!(RegisterEffectRequest::OPCODE, Opcode::Register);
    assert_eq!(RegisterEffectRequest::WIRE_SIZE, 112);
    assert_eq!(register.credit_kind(), CreditKind::Page);
    assert_eq!(register.credit_units(), 5);
    assert_eq!(PrepareEffectRequest::OPCODE, Opcode::Prepare);
    assert_eq!(PrepareEffectRequest::WIRE_SIZE, 88);
    assert_eq!(CommitEffectRequest::OPCODE, Opcode::Commit);
    assert_eq!(CommitEffectRequest::WIRE_SIZE, 96);
    assert_eq!(RecordOutcomeRequest::OPCODE, Opcode::RecordOutcome);
    assert_eq!(RecordOutcomeRequest::WIRE_SIZE, 128);
    assert_eq!(CompleteEffectRequest::OPCODE, Opcode::Complete);
    assert_eq!(CompleteEffectRequest::WIRE_SIZE, 120);
    assert_eq!(RevokeScopeRequest::OPCODE, Opcode::Revoke);
    assert_eq!(RevokeScopeRequest::WIRE_SIZE, 88);

    assert_wrong_sizes_reject(&register);
    assert_wrong_sizes_reject(&prepare);
    assert_wrong_sizes_reject(&commit);
    assert_wrong_sizes_reject(&outcome);
    assert_wrong_sizes_reject(&complete);
    assert_wrong_sizes_reject(&revoke);

    macro_rules! round_trip {
        ($request:expr, $type:ty) => {{
            let mut bytes = vec![0; <$type>::WIRE_SIZE];
            $request.encode_wire(&mut bytes).unwrap();
            assert_eq!(<$type>::decode_wire(&bytes).unwrap(), $request);
        }};
    }
    round_trip!(register, RegisterEffectRequest);
    round_trip!(prepare, PrepareEffectRequest);
    round_trip!(commit, CommitEffectRequest);
    round_trip!(outcome, RecordOutcomeRequest);
    round_trip!(complete, CompleteEffectRequest);
    round_trip!(revoke, RevokeScopeRequest);
}

#[test]
fn register_request_has_one_exact_little_endian_golden_vector() {
    let request = RegisterEffectRequest::new(
        context(),
        ScopeHandle::from_wire_bytes([0x33; 16]),
        EffectHandle::from_wire_bytes([0x44; 16]),
        0x1122_3344,
        RegisterFlags::PUBLICATION_REQUIRED,
        CreditKind::Page,
        5,
    )
    .unwrap();
    let mut output = [0; RegisterEffectRequest::WIRE_SIZE];
    request.encode_wire(&mut output).unwrap();
    let expected: [u8; RegisterEffectRequest::WIRE_SIZE] = [
        // session
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, // authority epoch, binding epoch
        3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, // request digest
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, // scope, optional parent effect
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44, 0x44, // operation class, flags, credit units, reserved
        0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0,
    ];
    assert_eq!(output, expected);
}

#[test]
fn reserved_unknown_enum_zero_digest_and_null_identity_fail_closed() {
    let register = RegisterEffectRequest::new(
        context(),
        ScopeHandle::from_wire_bytes([0x33; 16]),
        EffectHandle::NULL,
        1,
        RegisterFlags::empty(),
        CreditKind::Queue,
        1,
    )
    .unwrap();
    let mut register_bytes = [0; RegisterEffectRequest::WIRE_SIZE];
    register.encode_wire(&mut register_bytes).unwrap();
    register_bytes[108..110].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        RegisterEffectRequest::decode_wire(&register_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidEnum,
    );
    register.encode_wire(&mut register_bytes).unwrap();
    register_bytes[110] = 1;
    assert_eq!(
        RegisterEffectRequest::decode_wire(&register_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::NonZeroTail,
    );

    let prepare = PrepareEffectRequest::new(context(), effect()).unwrap();
    let mut prepare_bytes = [0; PrepareEffectRequest::WIRE_SIZE];
    prepare.encode_wire(&mut prepare_bytes).unwrap();
    prepare_bytes[80] = 1;
    assert_eq!(
        PrepareEffectRequest::decode_wire(&prepare_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::NonZeroTail,
    );

    let outcome =
        RecordOutcomeRequest::new(context(), effect(), OutcomeKind::Data, 4, digest(0x66)).unwrap();
    let mut outcome_bytes = [0; RecordOutcomeRequest::WIRE_SIZE];
    outcome.encode_wire(&mut outcome_bytes).unwrap();
    outcome_bytes[80..82].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        RecordOutcomeRequest::decode_wire(&outcome_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidEnum,
    );
    outcome.encode_wire(&mut outcome_bytes).unwrap();
    outcome_bytes[82] = 1;
    assert_eq!(
        RecordOutcomeRequest::decode_wire(&outcome_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::NonZeroTail,
    );
    outcome.encode_wire(&mut outcome_bytes).unwrap();
    outcome_bytes[32..64].fill(0);
    assert_eq!(
        RecordOutcomeRequest::decode_wire(&outcome_bytes)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidDigest,
    );

    assert_eq!(
        MutationContext::new(SessionHandle::NULL, 1, 1, digest(1))
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidSession,
    );
    assert_eq!(
        MutationContext::new(SessionHandle::from_wire_bytes([1; 16]), 1, 1, Digest::ZERO,)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidDigest,
    );
    assert_eq!(
        PrepareEffectRequest::new(context(), EffectHandle::NULL)
            .unwrap_err()
            .code(),
        PortalErrorCode::InvalidHandle,
    );
}

#[test]
fn lifecycle_enum_discriminants_are_exhaustive() {
    for value in u16::MIN..=u16::MAX {
        assert_eq!(
            CreditKind::from_wire_value(value),
            [CreditKind::Queue, CreditKind::Page]
                .into_iter()
                .find(|kind| kind.wire_value() == value),
        );
        assert_eq!(
            OutcomeKind::from_wire_value(value),
            [
                OutcomeKind::Data,
                OutcomeKind::Error,
                OutcomeKind::Indeterminate
            ]
            .into_iter()
            .find(|kind| kind.wire_value() == value),
        );
        assert_eq!(
            CompletionDisposition::from_wire_value(value),
            [
                CompletionDisposition::Completed,
                CompletionDisposition::AbortedBeforeCommit,
            ]
            .into_iter()
            .find(|kind| kind.wire_value() == value),
        );
        assert_eq!(
            RevokeReason::from_wire_value(value),
            [
                RevokeReason::Requested,
                RevokeReason::ServiceFailure,
                RevokeReason::Deadline,
                RevokeReason::ResourcePressure,
            ]
            .into_iter()
            .find(|kind| kind.wire_value() == value),
        );
    }
}
