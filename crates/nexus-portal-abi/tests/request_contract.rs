// SPDX-License-Identifier: MPL-2.0

use core::mem::{align_of, size_of};

use nexus_portal_abi::{
    CapabilityRequest, CreateScopeFlags, CreateScopeRequest, Digest, EffectHandle, HANDLE_SIZE,
    HeaderFlags, MAX_EFFECTS_PER_SCOPE, MAX_MESSAGE_SIZE, MAX_PAGE_CREDITS_PER_SCOPE,
    MAX_QUEUE_CREDITS_PER_SCOPE, MAX_TOMBSTONES_PER_SCOPE, MessageHeader, MessageKind,
    NegotiateRequest, Opcode, PortalCapabilities, PortalErrorCode, ProviderCapabilities,
    QueryAbiRequest, QueryEffectRequest, QueryReceiptRequest, QueryScopeRequest, ReceiptHandle,
    RequestBody, ScopeHandle, SessionHandle, decode_message, encode_message,
};

fn assert_wrong_sizes_reject<T: RequestBody + core::fmt::Debug>(request: &T) {
    for size in 0..=T::WIRE_SIZE + 1 {
        if size == T::WIRE_SIZE {
            continue;
        }
        let input = vec![0; size];
        assert_eq!(
            T::decode_wire(&input).unwrap_err().code(),
            PortalErrorCode::BodySizeMismatch,
            "opcode={:?} size={size}",
            T::OPCODE
        );
        let mut output = vec![0xa5; size];
        let before = output.clone();
        assert_eq!(
            request.encode_wire(&mut output).unwrap_err().code(),
            PortalErrorCode::BodySizeMismatch
        );
        assert_eq!(output, before);
    }
}

#[test]
fn opaque_handles_are_exact_bytes_without_semantic_unpacking() {
    let bytes = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let scope = ScopeHandle::from_wire_bytes(bytes);
    let effect = EffectHandle::from_wire_bytes(bytes);
    let receipt = ReceiptHandle::from_wire_bytes(bytes);
    let session = SessionHandle::from_wire_bytes(bytes);
    assert_eq!(scope.to_wire_bytes(), bytes);
    assert_eq!(effect.to_wire_bytes(), bytes);
    assert_eq!(receipt.to_wire_bytes(), bytes);
    assert_eq!(session.to_wire_bytes(), bytes);
    assert!(!scope.is_null());
    assert!(ScopeHandle::NULL.is_null());
    assert_eq!(HANDLE_SIZE, 16);
    assert_eq!(size_of::<ScopeHandle>(), HANDLE_SIZE);
    assert_eq!(size_of::<EffectHandle>(), HANDLE_SIZE);
    assert_eq!(size_of::<ReceiptHandle>(), HANDLE_SIZE);
    assert_eq!(size_of::<SessionHandle>(), HANDLE_SIZE);
    assert_eq!(align_of::<ScopeHandle>(), 1);
    assert_eq!(align_of::<EffectHandle>(), 1);
    assert_eq!(align_of::<ReceiptHandle>(), 1);
    assert_eq!(align_of::<SessionHandle>(), 1);
}

#[test]
fn every_request_type_pins_an_opcode_and_exact_body_size() {
    assert_eq!(QueryAbiRequest::OPCODE, Opcode::QueryAbi);
    assert_eq!(QueryAbiRequest::WIRE_SIZE, 0);
    assert_eq!(NegotiateRequest::OPCODE, Opcode::Negotiate);
    assert_eq!(NegotiateRequest::WIRE_SIZE, 32);
    assert_eq!(CreateScopeRequest::OPCODE, Opcode::CreateScope);
    assert_eq!(CreateScopeRequest::WIRE_SIZE, 104);
    assert_eq!(QueryScopeRequest::OPCODE, Opcode::QueryScope);
    assert_eq!(QueryScopeRequest::WIRE_SIZE, HANDLE_SIZE);
    assert_eq!(QueryEffectRequest::OPCODE, Opcode::QueryEffect);
    assert_eq!(QueryEffectRequest::WIRE_SIZE, HANDLE_SIZE);
    assert_eq!(QueryReceiptRequest::OPCODE, Opcode::QueryReceipt);
    assert_eq!(QueryReceiptRequest::WIRE_SIZE, HANDLE_SIZE);

    assert_wrong_sizes_reject(&QueryAbiRequest::new());
    assert_wrong_sizes_reject(&NegotiateRequest::new(CapabilityRequest {
        requested_portal: PortalCapabilities::empty(),
        required_portal: PortalCapabilities::empty(),
        requested_provider: ProviderCapabilities::empty(),
        required_provider: ProviderCapabilities::empty(),
    }));
    assert_wrong_sizes_reject(
        &CreateScopeRequest::new(
            SessionHandle::from_wire_bytes([1; HANDLE_SIZE]),
            ScopeHandle::NULL,
            0,
            0,
            Digest::from_wire_bytes([2; 32]),
            CreateScopeFlags::empty(),
            1,
            1,
            0,
            0,
        )
        .unwrap(),
    );
    assert_wrong_sizes_reject(&QueryScopeRequest::new(ScopeHandle::NULL));
    assert_wrong_sizes_reject(&QueryEffectRequest::new(EffectHandle::NULL));
    assert_wrong_sizes_reject(&QueryReceiptRequest::new(ReceiptHandle::NULL));
}

#[test]
fn negotiate_request_has_one_exact_little_endian_golden_vector() {
    let request = NegotiateRequest::new(CapabilityRequest {
        requested_portal: PortalCapabilities::QUERY_ABI | PortalCapabilities::CREATE_SCOPE,
        required_portal: PortalCapabilities::NEGOTIATE,
        requested_provider: ProviderCapabilities::LOGICAL_REQUEST,
        required_provider: ProviderCapabilities::EFFECT_CLOSURE,
    });
    let mut output = [0; NegotiateRequest::WIRE_SIZE];
    request.encode_wire(&mut output).unwrap();
    let expected = [
        0x05, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 0,
        0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(output, expected);
    assert_eq!(NegotiateRequest::decode_wire(&output).unwrap(), request);

    for offset in [0, 8, 16, 24] {
        let mut unknown = output;
        unknown[offset..offset + 8].copy_from_slice(&(1_u64 << 63).to_le_bytes());
        let error = NegotiateRequest::decode_wire(&unknown).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::UnknownCapability);
        assert_eq!(error.offset(), offset);
    }
}

#[test]
fn create_scope_request_has_one_exact_little_endian_golden_vector() {
    let parent_bytes = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let session_bytes = core::array::from_fn(|index| 0xf0 + u8::try_from(index).unwrap());
    let digest_bytes = core::array::from_fn(|index| 0xa0 + u8::try_from(index).unwrap());
    let request = CreateScopeRequest::new(
        SessionHandle::from_wire_bytes(session_bytes),
        ScopeHandle::from_wire_bytes(parent_bytes),
        0x1122_3344_5566_7788,
        0x99aa_bbcc_ddee_ff00,
        Digest::from_wire_bytes(digest_bytes),
        CreateScopeFlags::ALLOW_CHILD_SCOPES,
        MAX_EFFECTS_PER_SCOPE,
        MAX_TOMBSTONES_PER_SCOPE,
        3,
        4,
    )
    .unwrap();
    let mut output = [0; CreateScopeRequest::WIRE_SIZE];
    request.encode_wire(&mut output).unwrap();
    let expected = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x88, 0x77, 0x66, 0x55, 0x44,
        0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0xa0, 0xa1, 0xa2, 0xa3,
        0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2,
        0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 1, 0, 0, 0,
        0, 0x10, 0, 0, 0, 0x04, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(output, expected);
    assert_eq!(CreateScopeRequest::decode_wire(&output).unwrap(), request);
}

#[test]
fn create_scope_limits_and_reserved_fields_fail_closed() {
    let valid = CreateScopeRequest::new(
        SessionHandle::from_wire_bytes([1; HANDLE_SIZE]),
        ScopeHandle::NULL,
        0,
        0,
        Digest::from_wire_bytes([2; 32]),
        CreateScopeFlags::empty(),
        1,
        1,
        MAX_QUEUE_CREDITS_PER_SCOPE,
        MAX_PAGE_CREDITS_PER_SCOPE,
    )
    .unwrap();
    let mut encoded = [0; CreateScopeRequest::WIRE_SIZE];
    valid.encode_wire(&mut encoded).unwrap();

    let invalid_values = [
        (84, 0_u32),
        (84, MAX_EFFECTS_PER_SCOPE + 1),
        (88, 0),
        (88, 2),
        (88, MAX_TOMBSTONES_PER_SCOPE + 1),
        (92, MAX_QUEUE_CREDITS_PER_SCOPE + 1),
        (96, MAX_PAGE_CREDITS_PER_SCOPE + 1),
    ];
    for (offset, value) in invalid_values {
        let mut mutated = encoded;
        mutated[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let error = CreateScopeRequest::decode_wire(&mutated).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::LimitExceeded);
        assert_eq!(error.offset(), offset);
    }

    let mut unknown_flags = encoded;
    unknown_flags[80..84].copy_from_slice(&(1_u32 << 31).to_le_bytes());
    assert_eq!(
        CreateScopeRequest::decode_wire(&unknown_flags)
            .unwrap_err()
            .code(),
        PortalErrorCode::UnknownFlags
    );

    for offset in 100..104 {
        let mut nonzero_reserved = encoded;
        nonzero_reserved[offset] = 1;
        let error = CreateScopeRequest::decode_wire(&nonzero_reserved).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::NonZeroTail);
        assert_eq!(error.offset(), 100);
    }
}

#[test]
fn each_query_body_is_exactly_its_opaque_handle() {
    let bytes = [0x5a; HANDLE_SIZE];
    let scope = QueryScopeRequest::new(ScopeHandle::from_wire_bytes(bytes));
    let effect = QueryEffectRequest::new(EffectHandle::from_wire_bytes(bytes));
    let receipt = QueryReceiptRequest::new(ReceiptHandle::from_wire_bytes(bytes));

    let mut output = [0; HANDLE_SIZE];
    scope.encode_wire(&mut output).unwrap();
    assert_eq!(output, bytes);
    assert_eq!(QueryScopeRequest::decode_wire(&output).unwrap(), scope);
    effect.encode_wire(&mut output).unwrap();
    assert_eq!(QueryEffectRequest::decode_wire(&output).unwrap(), effect);
    receipt.encode_wire(&mut output).unwrap();
    assert_eq!(QueryReceiptRequest::decode_wire(&output).unwrap(), receipt);
}

#[test]
fn fixed_request_body_composes_with_message_framing() {
    let request = QueryEffectRequest::new(EffectHandle::from_wire_bytes([0x3c; HANDLE_SIZE]));
    let mut body = [0; QueryEffectRequest::WIRE_SIZE];
    request.encode_wire(&mut body).unwrap();
    let header = MessageHeader::new(
        MessageKind::Request,
        QueryEffectRequest::OPCODE,
        HeaderFlags::EXPECT_REPLY,
        42,
    )
    .unwrap();
    let mut message = [0; MAX_MESSAGE_SIZE];
    let length = encode_message(header, &body, &mut message).unwrap();
    let decoded = decode_message(&message[..length]).unwrap();
    assert_eq!(decoded.header.opcode(), QueryEffectRequest::OPCODE);
    assert_eq!(
        QueryEffectRequest::decode_wire(decoded.body).unwrap(),
        request
    );
}
