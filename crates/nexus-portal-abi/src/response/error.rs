// SPDX-License-Identifier: MPL-2.0

//! Provider-neutral typed failures and their fixed wire response.

use zerocopy::byteorder::{LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::request::require_size;
use crate::{Digest, PortalErrorCode, PortalWireError};

use super::{ResponseBody, RetryClass};

/// Provider-neutral typed failure before error-body encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalFailure {
    code: PortalErrorCode,
    retry: RetryClass,
    detail: u32,
    authority_epoch: u64,
    binding_epoch: u64,
    presented_digest: Digest,
    existing_digest: Digest,
}

impl PortalFailure {
    /// Creates a typed failure without authority or conflict details.
    #[must_use]
    pub const fn new(code: PortalErrorCode, retry: RetryClass, detail: u32) -> Self {
        Self {
            code,
            retry,
            detail,
            authority_epoch: 0,
            binding_epoch: 0,
            presented_digest: Digest::ZERO,
            existing_digest: Digest::ZERO,
        }
    }

    /// Attaches the authoritative epochs observed at failure.
    #[must_use]
    pub const fn with_epochs(mut self, authority_epoch: u64, binding_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self.binding_epoch = binding_epoch;
        self
    }

    /// Attaches conflicting presented and existing digests.
    #[must_use]
    pub const fn with_digests(mut self, presented: Digest, existing: Digest) -> Self {
        self.presented_digest = presented;
        self.existing_digest = existing;
        self
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(self) -> PortalErrorCode {
        self.code
    }

    /// Returns retry policy.
    #[must_use]
    pub const fn retry(self) -> RetryClass {
        self.retry
    }

    /// Returns provider-defined bounded detail.
    #[must_use]
    pub const fn detail(self) -> u32 {
        self.detail
    }

    /// Returns the observed authority epoch, or zero when unavailable.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Returns the observed binding epoch, or zero when unavailable.
    #[must_use]
    pub const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    /// Returns the presented digest, or zero when not applicable.
    #[must_use]
    pub const fn presented_digest(self) -> Digest {
        self.presented_digest
    }

    /// Returns the existing digest, or zero when not applicable.
    #[must_use]
    pub const fn existing_digest(self) -> Digest {
        self.existing_digest
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct WireErrorResponse {
    code: U16<LittleEndian>,
    retry: U16<LittleEndian>,
    reserved0: U32<LittleEndian>,
    detail: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    authority_epoch: U64<LittleEndian>,
    binding_epoch: U64<LittleEndian>,
    presented_digest: [u8; 32],
    existing_digest: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<WireErrorResponse>() == 96);
const _: () = assert!(core::mem::align_of::<WireErrorResponse>() == 1);

/// Fixed typed error response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    failure: PortalFailure,
}

impl ErrorResponse {
    /// Wraps a provider-neutral failure for wire encoding.
    #[must_use]
    pub const fn new(failure: PortalFailure) -> Self {
        Self { failure }
    }

    /// Returns the typed failure.
    #[must_use]
    pub const fn failure(self) -> PortalFailure {
        self.failure
    }
}

impl ResponseBody for ErrorResponse {
    const WIRE_SIZE: usize = 96;

    fn decode_wire(input: &[u8]) -> Result<Self, PortalWireError> {
        require_size(input, Self::WIRE_SIZE)?;
        let raw = *WireErrorResponse::ref_from_bytes(input)
            .map_err(|_| PortalWireError::new(PortalErrorCode::BodySizeMismatch, input.len()))?;
        if raw.reserved0.get() != 0 || raw.reserved1.get() != 0 {
            return Err(PortalWireError::new(PortalErrorCode::NonZeroTail, 4));
        }
        let code = PortalErrorCode::from_wire_value(raw.code.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 0))?;
        let retry = RetryClass::from_wire_value(raw.retry.get())
            .ok_or_else(|| PortalWireError::new(PortalErrorCode::InvalidEnum, 2))?;
        Ok(Self::new(
            PortalFailure::new(code, retry, raw.detail.get())
                .with_epochs(raw.authority_epoch.get(), raw.binding_epoch.get())
                .with_digests(
                    Digest::from_wire_bytes(raw.presented_digest),
                    Digest::from_wire_bytes(raw.existing_digest),
                ),
        ))
    }

    fn encode_wire(&self, output: &mut [u8]) -> Result<(), PortalWireError> {
        require_size(output, Self::WIRE_SIZE)?;
        let failure = self.failure;
        let raw = WireErrorResponse {
            code: U16::new(failure.code.wire_value()),
            retry: U16::new(failure.retry.wire_value()),
            reserved0: U32::new(0),
            detail: U32::new(failure.detail),
            reserved1: U32::new(0),
            authority_epoch: U64::new(failure.authority_epoch),
            binding_epoch: U64::new(failure.binding_epoch),
            presented_digest: failure.presented_digest.to_wire_bytes(),
            existing_digest: failure.existing_digest.to_wire_bytes(),
        };
        output.copy_from_slice(raw.as_bytes());
        Ok(())
    }
}
