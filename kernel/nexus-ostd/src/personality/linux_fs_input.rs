// SPDX-License-Identifier: MPL-2.0

//! Pure, host-testable input validation for the bounded runtime filesystem.

pub(crate) const MAX_RUNTIME_FS_GUEST_COPY: usize = 4096;
pub(crate) const MAX_RUNTIME_FS_C_STRING: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsGuestCopyDirection {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsGuestAccessError {
    LengthExceedsLimit {
        requested: usize,
        limit: usize,
    },
    AddressOverflow {
        address: usize,
        length: usize,
    },
    InvalidRange {
        direction: FsGuestCopyDirection,
        address: usize,
        length: usize,
    },
    Unmapped {
        direction: FsGuestCopyDirection,
        address: usize,
        length: usize,
    },
    Partial {
        direction: FsGuestCopyDirection,
        expected: usize,
        copied: usize,
    },
    MissingNul {
        limit: usize,
    },
}

pub(crate) fn validate_guest_range(
    address: usize,
    length: usize,
    limit: usize,
) -> Result<(), FsGuestAccessError> {
    if length > limit {
        return Err(FsGuestAccessError::LengthExceedsLimit {
            requested: length,
            limit,
        });
    }
    if address.checked_add(length).is_none() {
        return Err(FsGuestAccessError::AddressOverflow { address, length });
    }
    Ok(())
}

pub(crate) const fn unmapped_guest_range(
    direction: FsGuestCopyDirection,
    address: usize,
    length: usize,
) -> FsGuestAccessError {
    FsGuestAccessError::Unmapped {
        direction,
        address,
        length,
    }
}

pub(crate) fn validate_guest_copy(
    direction: FsGuestCopyDirection,
    expected: usize,
    copied: usize,
) -> Result<(), FsGuestAccessError> {
    if copied != expected {
        return Err(FsGuestAccessError::Partial {
            direction,
            expected,
            copied,
        });
    }
    Ok(())
}

pub(crate) fn find_c_string_end(bytes: &[u8], limit: usize) -> Result<usize, FsGuestAccessError> {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(FsGuestAccessError::MissingNul { limit })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_length_before_allocation() {
        assert_eq!(
            validate_guest_range(
                0x1000,
                MAX_RUNTIME_FS_GUEST_COPY + 1,
                MAX_RUNTIME_FS_GUEST_COPY
            ),
            Err(FsGuestAccessError::LengthExceedsLimit {
                requested: MAX_RUNTIME_FS_GUEST_COPY + 1,
                limit: MAX_RUNTIME_FS_GUEST_COPY,
            })
        );
    }

    #[test]
    fn rejects_wrapping_address_range() {
        assert_eq!(
            validate_guest_range(usize::MAX, 2, MAX_RUNTIME_FS_GUEST_COPY),
            Err(FsGuestAccessError::AddressOverflow {
                address: usize::MAX,
                length: 2,
            })
        );
    }

    #[test]
    fn distinguishes_unmapped_and_partial_copies() {
        assert_eq!(
            unmapped_guest_range(FsGuestCopyDirection::Read, 0x8000, 4),
            FsGuestAccessError::Unmapped {
                direction: FsGuestCopyDirection::Read,
                address: 0x8000,
                length: 4,
            }
        );
        assert_eq!(
            validate_guest_copy(FsGuestCopyDirection::Write, 4, 2),
            Err(FsGuestAccessError::Partial {
                direction: FsGuestCopyDirection::Write,
                expected: 4,
                copied: 2,
            })
        );
    }

    #[test]
    fn rejects_string_without_nul_inside_bound() {
        assert_eq!(
            find_c_string_end(b"abcd", 4),
            Err(FsGuestAccessError::MissingNul { limit: 4 })
        );
        assert_eq!(find_c_string_end(b"ab\0d", 4), Ok(2));
    }
}
