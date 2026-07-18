// SPDX-License-Identifier: MPL-2.0

use nexus_portal_abi::{
    BASE_HEADER_SIZE, HEADER_MAGIC, HeaderFlags, MAX_BODY_SIZE, MAX_HEADER_SIZE, MAX_MESSAGE_SIZE,
    MessageHeader, MessageKind, Opcode, PortalErrorCode, VERSION_MAJOR, VERSION_MINOR,
    decode_message, encode_message,
};

fn base_vector() -> Vec<u8> {
    let header = MessageHeader::new(
        MessageKind::Request,
        Opcode::QueryEffect,
        HeaderFlags::EXPECT_REPLY,
        0x1122_3344_5566_7788,
    )
    .unwrap();
    let mut output = vec![0xa5; MAX_MESSAGE_SIZE];
    let length = encode_message(header, &[0xaa, 0xbb, 0xcc], &mut output).unwrap();
    output.truncate(length);
    output
}

#[test]
fn base_header_has_one_exact_little_endian_golden_vector() {
    let encoded = base_vector();
    let expected = [
        0x20, 0x00, b'N', b'X', b'P', b'2', 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
        0x22, 0x11, 0xaa, 0xbb, 0xcc,
    ];
    assert_eq!(encoded, expected);
    assert_eq!(HEADER_MAGIC, *b"NXP2");
    assert_eq!(VERSION_MAJOR, 2);
    assert_eq!(VERSION_MINOR, 0);

    let decoded = decode_message(&encoded).unwrap();
    assert_eq!(decoded.header.header_size(), BASE_HEADER_SIZE);
    assert_eq!(decoded.header.kind(), MessageKind::Request);
    assert_eq!(decoded.header.opcode(), Opcode::QueryEffect);
    assert_eq!(decoded.header.flags(), HeaderFlags::EXPECT_REPLY);
    assert_eq!(decoded.header.request_id(), 0x1122_3344_5566_7788);
    assert_eq!(decoded.body, [0xaa, 0xbb, 0xcc]);
}

#[test]
fn bounded_zero_header_tail_round_trips_and_is_initialized() {
    let header = MessageHeader::new(
        MessageKind::Response,
        Opcode::QueryScope,
        HeaderFlags::FINAL,
        7,
    )
    .unwrap()
    .with_header_size(40)
    .unwrap();
    let mut output = [0xa5; MAX_MESSAGE_SIZE];
    let length = encode_message(header, &[1, 2], &mut output).unwrap();
    assert_eq!(length, 42);
    assert_eq!(&output[BASE_HEADER_SIZE..40], &[0; 8]);
    assert_eq!(output[42], 0xa5);

    let decoded = decode_message(&output[..length]).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.body, [1, 2]);

    let largest = header.with_header_size(MAX_HEADER_SIZE).unwrap();
    let length = encode_message(largest, &[], &mut output).unwrap();
    assert_eq!(length, MAX_HEADER_SIZE);
    assert!(
        output[BASE_HEADER_SIZE..MAX_HEADER_SIZE]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn every_short_fixed_header_fails_closed() {
    let encoded = base_vector();
    for length in 0..BASE_HEADER_SIZE {
        let error = decode_message(&encoded[..length]).unwrap_err();
        assert_eq!(
            error.code(),
            PortalErrorCode::HeaderTooShort,
            "length={length}"
        );
        assert_eq!(error.offset(), length);
    }
}

#[test]
fn malformed_header_fields_and_lengths_fail_closed() {
    let cases: &[(usize, &[u8], PortalErrorCode)] = &[
        (2, b"B", PortalErrorCode::BadMagic),
        (6, &[3, 0], PortalErrorCode::UnsupportedVersion),
        (8, &[1, 0], PortalErrorCode::UnsupportedVersion),
        (10, &[0xff, 0xff], PortalErrorCode::UnknownMessageKind),
        (12, &[0xff, 0xff], PortalErrorCode::UnknownOpcode),
        (14, &[1, 0], PortalErrorCode::NonZeroTail),
        (16, &[0, 0, 0, 0x80], PortalErrorCode::UnknownFlags),
        (20, &[0xff, 0xff, 0xff, 0xff], PortalErrorCode::BodyTooLarge),
    ];
    for (offset, replacement, expected) in cases {
        let mut encoded = base_vector();
        encoded[*offset..*offset + replacement.len()].copy_from_slice(replacement);
        assert_eq!(decode_message(&encoded).unwrap_err().code(), *expected);
    }

    for header_size in [0_u16, 1, 31, 65, u16::MAX] {
        let mut encoded = base_vector();
        encoded[..2].copy_from_slice(&header_size.to_le_bytes());
        assert_eq!(
            decode_message(&encoded).unwrap_err().code(),
            PortalErrorCode::InvalidHeaderSize
        );
    }

    let mut wrong_body_length = base_vector();
    wrong_body_length[20..24].copy_from_slice(&4_u32.to_le_bytes());
    assert_eq!(
        decode_message(&wrong_body_length).unwrap_err().code(),
        PortalErrorCode::MessageLengthMismatch
    );

    let mut trailing = base_vector();
    trailing.push(0);
    assert_eq!(
        decode_message(&trailing).unwrap_err().code(),
        PortalErrorCode::MessageLengthMismatch
    );
}

#[test]
fn nonzero_extension_tail_and_context_invalid_flags_fail_closed() {
    let header = MessageHeader::new(
        MessageKind::Request,
        Opcode::QueryAbi,
        HeaderFlags::EXPECT_REPLY,
        9,
    )
    .unwrap()
    .with_header_size(40)
    .unwrap();
    let mut output = [0; MAX_MESSAGE_SIZE];
    let length = encode_message(header, &[], &mut output).unwrap();
    for offset in BASE_HEADER_SIZE..40 {
        let mut mutated = output[..length].to_vec();
        mutated[offset] = 1;
        let error = decode_message(&mutated).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::NonZeroTail);
        assert_eq!(error.offset(), offset);
    }

    let mut final_request = base_vector();
    final_request[16..20].copy_from_slice(&HeaderFlags::FINAL.bits().to_le_bytes());
    assert_eq!(
        decode_message(&final_request).unwrap_err().code(),
        PortalErrorCode::UnknownFlags
    );
    assert_eq!(
        MessageHeader::new(
            MessageKind::Request,
            Opcode::QueryAbi,
            HeaderFlags::FINAL,
            1,
        )
        .unwrap_err()
        .code(),
        PortalErrorCode::UnknownFlags
    );
}

#[test]
fn all_unknown_single_header_flag_bits_are_rejected() {
    for bit in 2..u32::BITS {
        let unknown = HeaderFlags::from_bits_retain(1_u32 << bit);
        let error =
            MessageHeader::new(MessageKind::Request, Opcode::QueryAbi, unknown, 1).unwrap_err();
        assert_eq!(error.code(), PortalErrorCode::UnknownFlags, "bit={bit}");
    }
}

#[test]
fn encode_rejects_oversize_or_short_output_without_writing() {
    let header = MessageHeader::new(
        MessageKind::Request,
        Opcode::QueryAbi,
        HeaderFlags::empty(),
        1,
    )
    .unwrap();
    let oversized = vec![0; MAX_BODY_SIZE + 1];
    let mut output = [0xa5; MAX_MESSAGE_SIZE];
    let before = output;
    assert_eq!(
        encode_message(header, &oversized, &mut output)
            .unwrap_err()
            .code(),
        PortalErrorCode::BodyTooLarge
    );
    assert_eq!(output, before);

    let mut short = [0xa5; BASE_HEADER_SIZE - 1];
    let before = short;
    assert_eq!(
        encode_message(header, &[], &mut short).unwrap_err().code(),
        PortalErrorCode::MessageLengthMismatch
    );
    assert_eq!(short, before);
}

#[test]
fn message_kind_and_opcode_discriminants_are_exhaustive() {
    let kinds = [
        (MessageKind::Request, 1_u16),
        (MessageKind::Response, 2),
        (MessageKind::Error, 3),
    ];
    for value in u16::MIN..=u16::MAX {
        let expected = kinds
            .iter()
            .find(|(_, raw)| *raw == value)
            .map(|(kind, _)| *kind);
        assert_eq!(MessageKind::from_wire_value(value), expected);
    }
    for (kind, value) in kinds {
        assert_eq!(kind.wire_value(), value);
    }

    let opcodes = [
        (Opcode::QueryAbi, 0x0001_u16),
        (Opcode::Negotiate, 0x0002),
        (Opcode::CreateScope, 0x0100),
        (Opcode::QueryScope, 0x0101),
        (Opcode::QueryEffect, 0x0102),
        (Opcode::QueryReceipt, 0x0103),
        (Opcode::Register, 0x0200),
        (Opcode::Prepare, 0x0201),
        (Opcode::Commit, 0x0202),
        (Opcode::RecordOutcome, 0x0203),
        (Opcode::Complete, 0x0204),
        (Opcode::Revoke, 0x0205),
    ];
    for value in u16::MIN..=u16::MAX {
        let expected = opcodes
            .iter()
            .find(|(_, raw)| *raw == value)
            .map(|(opcode, _)| *opcode);
        assert_eq!(Opcode::from_wire_value(value), expected);
    }
    for (opcode, value) in opcodes {
        assert_eq!(opcode.wire_value(), value);
    }
}

#[test]
fn portal_error_codes_are_exhaustive_and_stable() {
    let codes = [
        PortalErrorCode::HeaderTooShort,
        PortalErrorCode::BadMagic,
        PortalErrorCode::UnsupportedVersion,
        PortalErrorCode::UnknownMessageKind,
        PortalErrorCode::UnknownOpcode,
        PortalErrorCode::UnknownFlags,
        PortalErrorCode::InvalidHeaderSize,
        PortalErrorCode::BodyTooLarge,
        PortalErrorCode::MessageLengthMismatch,
        PortalErrorCode::NonZeroTail,
        PortalErrorCode::BodySizeMismatch,
        PortalErrorCode::LimitExceeded,
        PortalErrorCode::UnknownCapability,
        PortalErrorCode::MissingRequiredCapability,
        PortalErrorCode::InvalidHandle,
        PortalErrorCode::StaleHandle,
        PortalErrorCode::CallerMismatch,
        PortalErrorCode::GenerationMismatch,
        PortalErrorCode::ReceiptConsumed,
        PortalErrorCode::NotFound,
        PortalErrorCode::NoCredit,
        PortalErrorCode::Backpressure,
        PortalErrorCode::Conflict,
        PortalErrorCode::PermissionDenied,
        PortalErrorCode::InternalInvariant,
        PortalErrorCode::NegotiationRequired,
        PortalErrorCode::CapabilityNotNegotiated,
        PortalErrorCode::InvalidEnum,
        PortalErrorCode::InvalidDigest,
        PortalErrorCode::InvalidRequestId,
        PortalErrorCode::InvalidSession,
        PortalErrorCode::OutOfOrder,
    ];
    for (index, code) in codes.iter().enumerate() {
        assert_eq!(code.wire_value(), u16::try_from(index + 1).unwrap());
    }
    for value in u16::MIN..=u16::MAX {
        let expected = codes
            .iter()
            .copied()
            .find(|code| code.wire_value() == value);
        assert_eq!(PortalErrorCode::from_wire_value(value), expected);
    }
}
