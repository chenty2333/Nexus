// SPDX-License-Identifier: MPL-2.0

//! Fixed little-endian portal message framing.
//!
//! The 32-byte understood prefix is stable:
//!
//! | Offset | Width | Field |
//! | ---: | ---: | --- |
//! | 0 | 2 | header size |
//! | 2 | 4 | `NXP2` magic |
//! | 6 | 2 | major version |
//! | 8 | 2 | minor version |
//! | 10 | 2 | message kind |
//! | 12 | 2 | opcode |
//! | 14 | 2 | zero reserved field |
//! | 16 | 4 | flags |
//! | 20 | 4 | body length |
//! | 24 | 8 | request id |
//!
//! A declared header larger than 32 bytes carries only a zero extension tail in
//! this preview.  This permits a future parser to recognize the envelope while
//! current code fails closed on semantics it does not understand.

use bitflags::bitflags;
use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{PortalErrorCode, PortalWireError};

/// Magic bytes identifying the `nexus.portal.v2` preview.
pub const HEADER_MAGIC: [u8; 4] = *b"NXP2";
/// Supported portal protocol major version.
pub const VERSION_MAJOR: u16 = 2;
/// Supported portal protocol minor version.
pub const VERSION_MINOR: u16 = 0;
/// Byte width of the understood header prefix.
pub const BASE_HEADER_SIZE: usize = 32;
/// Largest accepted header, including a zero-filled extension tail.
pub const MAX_HEADER_SIZE: usize = 64;
/// Largest accepted message body.
pub const MAX_BODY_SIZE: usize = 4096;
/// Largest accepted complete message.
pub const MAX_MESSAGE_SIZE: usize = MAX_HEADER_SIZE + MAX_BODY_SIZE;

const HEADER_SIZE_OFFSET: usize = 0;
const MAGIC_OFFSET: usize = 2;
const VERSION_OFFSET: usize = 6;
const KIND_OFFSET: usize = 10;
const OPCODE_OFFSET: usize = 12;
const RESERVED_OFFSET: usize = 14;
const FLAGS_OFFSET: usize = 16;
const BODY_LENGTH_OFFSET: usize = 20;

bitflags! {
    /// Flags understood by the portal-v2 header.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct HeaderFlags: u32 {
        /// A request asks the endpoint to emit one terminal response.
        const EXPECT_REPLY = 1 << 0;
        /// A response or error is the terminal response for its request id.
        const FINAL = 1 << 1;
    }
}

/// Kind of message carried by the portal framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageKind {
    /// Caller-to-portal request.
    Request = 1,
    /// Successful portal response.
    Response = 2,
    /// Typed portal error response.
    Error = 3,
}

impl MessageKind {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a wire discriminant, rejecting unassigned values.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Operation carried by a portal-v2 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Opcode {
    /// Query version, fixed limits, and offered capabilities.
    QueryAbi = 0x0001,
    /// Negotiate optional and required capabilities.
    Negotiate = 0x0002,
    /// Create one bounded causal scope.
    CreateScope = 0x0100,
    /// Query a scope by opaque handle.
    QueryScope = 0x0101,
    /// Query an effect by opaque handle.
    QueryEffect = 0x0102,
    /// Query a receipt by opaque handle.
    QueryReceipt = 0x0103,
    /// Register one effect under a bounded scope.
    Register = 0x0200,
    /// Prepare one registered effect.
    Prepare = 0x0201,
    /// Commit one prepared effect.
    Commit = 0x0202,
    /// Record one canonical backend outcome.
    RecordOutcome = 0x0203,
    /// Terminalize one effect after its required outcome.
    Complete = 0x0204,
    /// Freeze one scope authority epoch and begin closure.
    Revoke = 0x0205,
}

impl Opcode {
    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Parses a wire discriminant, rejecting unassigned values.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::QueryAbi),
            0x0002 => Some(Self::Negotiate),
            0x0100 => Some(Self::CreateScope),
            0x0101 => Some(Self::QueryScope),
            0x0102 => Some(Self::QueryEffect),
            0x0103 => Some(Self::QueryReceipt),
            0x0200 => Some(Self::Register),
            0x0201 => Some(Self::Prepare),
            0x0202 => Some(Self::Commit),
            0x0203 => Some(Self::RecordOutcome),
            0x0204 => Some(Self::Complete),
            0x0205 => Some(Self::Revoke),
            _ => None,
        }
    }

    /// Reports whether the opcode can mutate backend state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::CreateScope
                | Self::Register
                | Self::Prepare
                | Self::Commit
                | Self::RecordOutcome
                | Self::Complete
                | Self::Revoke
        )
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireHeader {
    header_size: U16<LittleEndian>,
    magic: [u8; 4],
    major: U16<LittleEndian>,
    minor: U16<LittleEndian>,
    kind: U16<LittleEndian>,
    opcode: U16<LittleEndian>,
    reserved: U16<LittleEndian>,
    flags: U32<LittleEndian>,
    body_length: U32<LittleEndian>,
    request_id: U64<LittleEndian>,
}

const _: () = assert!(core::mem::size_of::<WireHeader>() == BASE_HEADER_SIZE);
const _: () = assert!(core::mem::align_of::<WireHeader>() == 1);

/// Validated semantic fields of a portal message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    header_size: usize,
    kind: MessageKind,
    opcode: Opcode,
    flags: HeaderFlags,
    request_id: u64,
}

impl MessageHeader {
    /// Creates a base-size validated header.
    pub fn new(
        kind: MessageKind,
        opcode: Opcode,
        flags: HeaderFlags,
        request_id: u64,
    ) -> Result<Self, PortalWireError> {
        validate_flags(kind, flags)?;
        Ok(Self {
            header_size: BASE_HEADER_SIZE,
            kind,
            opcode,
            flags,
            request_id,
        })
    }

    /// Selects a bounded header size; added bytes encode as zero.
    pub fn with_header_size(mut self, header_size: usize) -> Result<Self, PortalWireError> {
        validate_header_size(header_size)?;
        self.header_size = header_size;
        Ok(self)
    }

    /// Returns the declared header size.
    #[must_use]
    pub const fn header_size(self) -> usize {
        self.header_size
    }

    /// Returns the message kind.
    #[must_use]
    pub const fn kind(self) -> MessageKind {
        self.kind
    }

    /// Returns the operation selector.
    #[must_use]
    pub const fn opcode(self) -> Opcode {
        self.opcode
    }

    /// Returns validated header flags.
    #[must_use]
    pub const fn flags(self) -> HeaderFlags {
        self.flags
    }

    /// Returns the caller-selected request id.
    ///
    /// Read-only requests use it as an ephemeral correlation id that may be
    /// reused after the terminal response. A successfully negotiated id and
    /// each replay-admitted mutation id are instead reserved for that session
    /// as durable idempotency keys.
    #[must_use]
    pub const fn request_id(self) -> u64 {
        self.request_id
    }
}

/// A validated portal message borrowing its exact body bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalMessage<'a> {
    /// Validated header fields.
    pub header: MessageHeader,
    /// Exact bounded body bytes following the declared header.
    pub body: &'a [u8],
}

fn validate_header_size(header_size: usize) -> Result<(), PortalWireError> {
    if !(BASE_HEADER_SIZE..=MAX_HEADER_SIZE).contains(&header_size) {
        return Err(PortalWireError::new(
            PortalErrorCode::InvalidHeaderSize,
            HEADER_SIZE_OFFSET,
        ));
    }
    Ok(())
}

fn validate_flags(kind: MessageKind, flags: HeaderFlags) -> Result<(), PortalWireError> {
    if HeaderFlags::from_bits(flags.bits()).is_none() {
        return Err(PortalWireError::new(
            PortalErrorCode::UnknownFlags,
            FLAGS_OFFSET,
        ));
    }
    let allowed = match kind {
        MessageKind::Request => HeaderFlags::EXPECT_REPLY,
        MessageKind::Response | MessageKind::Error => HeaderFlags::FINAL,
    };
    if !(flags & !allowed).is_empty() {
        return Err(PortalWireError::new(
            PortalErrorCode::UnknownFlags,
            FLAGS_OFFSET,
        ));
    }
    Ok(())
}

/// Decodes and validates one complete portal message.
///
/// The function rejects unknown versions, kinds, opcodes, and flags; non-zero
/// reserved or extension bytes; oversized bodies; arithmetic overflow; and any
/// trailing or missing bytes.
pub fn decode_message(input: &[u8]) -> Result<PortalMessage<'_>, PortalWireError> {
    if input.len() < BASE_HEADER_SIZE {
        return Err(PortalWireError::new(
            PortalErrorCode::HeaderTooShort,
            input.len(),
        ));
    }
    let (raw, _) = WireHeader::ref_from_prefix(input)
        .map_err(|_| PortalWireError::new(PortalErrorCode::HeaderTooShort, input.len()))?;

    let header_size = usize::from(raw.header_size.get());
    validate_header_size(header_size)?;
    if raw.magic != HEADER_MAGIC {
        return Err(PortalWireError::new(
            PortalErrorCode::BadMagic,
            MAGIC_OFFSET,
        ));
    }
    if raw.major.get() != VERSION_MAJOR || raw.minor.get() != VERSION_MINOR {
        return Err(PortalWireError::new(
            PortalErrorCode::UnsupportedVersion,
            VERSION_OFFSET,
        ));
    }
    let kind = MessageKind::from_wire_value(raw.kind.get())
        .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownMessageKind, KIND_OFFSET))?;
    let opcode = Opcode::from_wire_value(raw.opcode.get())
        .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownOpcode, OPCODE_OFFSET))?;
    if raw.reserved.get() != 0 {
        return Err(PortalWireError::new(
            PortalErrorCode::NonZeroTail,
            RESERVED_OFFSET,
        ));
    }
    let flags = HeaderFlags::from_bits(raw.flags.get())
        .ok_or_else(|| PortalWireError::new(PortalErrorCode::UnknownFlags, FLAGS_OFFSET))?;
    validate_flags(kind, flags)?;

    if input.len() < header_size {
        return Err(PortalWireError::new(
            PortalErrorCode::MessageLengthMismatch,
            input.len(),
        ));
    }
    if let Some(position) = input[BASE_HEADER_SIZE..header_size]
        .iter()
        .position(|byte| *byte != 0)
    {
        return Err(PortalWireError::new(
            PortalErrorCode::NonZeroTail,
            BASE_HEADER_SIZE + position,
        ));
    }

    let body_length = usize::try_from(raw.body_length.get()).map_err(|_| {
        PortalWireError::new(PortalErrorCode::MessageLengthMismatch, BODY_LENGTH_OFFSET)
    })?;
    if body_length > MAX_BODY_SIZE {
        return Err(PortalWireError::new(
            PortalErrorCode::BodyTooLarge,
            BODY_LENGTH_OFFSET,
        ));
    }
    let total_length = header_size.checked_add(body_length).ok_or_else(|| {
        PortalWireError::new(PortalErrorCode::MessageLengthMismatch, BODY_LENGTH_OFFSET)
    })?;
    if total_length > MAX_MESSAGE_SIZE || input.len() != total_length {
        return Err(PortalWireError::new(
            PortalErrorCode::MessageLengthMismatch,
            input.len(),
        ));
    }

    Ok(PortalMessage {
        header: MessageHeader {
            header_size,
            kind,
            opcode,
            flags,
            request_id: raw.request_id.get(),
        },
        body: &input[header_size..total_length],
    })
}

/// Encodes one complete portal message into a caller-owned buffer.
///
/// The returned length is the initialized prefix of `output`.  Header extension
/// bytes are always zeroed.  The function does not allocate or partially encode
/// a message when validation fails.
pub fn encode_message(
    header: MessageHeader,
    body: &[u8],
    output: &mut [u8],
) -> Result<usize, PortalWireError> {
    validate_header_size(header.header_size)?;
    validate_flags(header.kind, header.flags)?;
    if body.len() > MAX_BODY_SIZE {
        return Err(PortalWireError::new(
            PortalErrorCode::BodyTooLarge,
            BODY_LENGTH_OFFSET,
        ));
    }
    let body_length = u32::try_from(body.len()).map_err(|_| {
        PortalWireError::new(PortalErrorCode::MessageLengthMismatch, BODY_LENGTH_OFFSET)
    })?;
    let total_length = header.header_size.checked_add(body.len()).ok_or_else(|| {
        PortalWireError::new(PortalErrorCode::MessageLengthMismatch, BODY_LENGTH_OFFSET)
    })?;
    if total_length > MAX_MESSAGE_SIZE || output.len() < total_length {
        return Err(PortalWireError::new(
            PortalErrorCode::MessageLengthMismatch,
            output.len(),
        ));
    }
    let header_size = u16::try_from(header.header_size).map_err(|_| {
        PortalWireError::new(PortalErrorCode::InvalidHeaderSize, HEADER_SIZE_OFFSET)
    })?;
    let raw = WireHeader {
        header_size: U16::new(header_size),
        magic: HEADER_MAGIC,
        major: U16::new(VERSION_MAJOR),
        minor: U16::new(VERSION_MINOR),
        kind: U16::new(header.kind.wire_value()),
        opcode: U16::new(header.opcode.wire_value()),
        reserved: U16::new(0),
        flags: U32::new(header.flags.bits()),
        body_length: U32::new(body_length),
        request_id: U64::new(header.request_id),
    };

    output[..BASE_HEADER_SIZE].copy_from_slice(raw.as_bytes());
    output[BASE_HEADER_SIZE..header.header_size].fill(0);
    output[header.header_size..total_length].copy_from_slice(body);
    Ok(total_length)
}
