// SPDX-License-Identifier: MPL-2.0

//! Fixed-scratch positioned input used by cold journal recovery.

use core::fmt;

use crate::{Digest, Freshness, RecoveryBinding};

/// One provider-stable view of a logical recovery image.
///
/// The token is passed back on every positioned read so a provider with more
/// than one retained copy cannot accidentally read from a different copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverySourceSnapshot<T> {
    token: T,
    logical_len: u64,
}

impl<T: Copy> RecoverySourceSnapshot<T> {
    /// Creates a snapshot descriptor for one exact provider token and length.
    pub const fn new(token: T, logical_len: u64) -> Self {
        Self { token, logical_len }
    }

    /// Returns the provider-specific stable-view token.
    pub const fn token(self) -> T {
        self.token
    }

    /// Returns the exact logical byte length of this view.
    pub const fn logical_len(self) -> u64 {
        self.logical_len
    }
}

/// Positioned, stable recovery input suitable for `no_std` embeddings.
///
/// From a successful [`Self::begin_snapshot`] through the corresponding
/// [`Self::validate_snapshot`], reads for that token must describe one
/// immutable logical byte stream. Short reads, a changed candidate, and media
/// errors must be returned as `Error`; methods must not panic. This semantic
/// stability contract is necessary because fixed-scratch recovery reads a
/// checkpoint more than once instead of retaining its complete image.
pub trait JournalRecoverySource {
    /// Provider-specific read or stability failure.
    type Error;
    /// Copyable identity of one stable source view.
    type Snapshot: Copy + Eq;

    /// Begins one stable logical view.
    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error>;

    /// Completely fills `output` from the exact stable view.
    fn read_exact_at(
        &mut self,
        snapshot: Self::Snapshot,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Confirms that the view did not change during the preceding reads.
    fn validate_snapshot(&mut self, snapshot: Self::Snapshot) -> Result<(), Self::Error>;
}

/// Exact non-authorizing journal coordinates used to inspect candidates.
///
/// Candidate inspection cannot recover an engine or create authority. The
/// later engine entry point must independently consume a trusted
/// `RecoveryAnchor` carrying the same coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryExpectation {
    binding: RecoveryBinding,
    freshness: Freshness,
    revision: u64,
    head: Digest,
}

impl RecoveryExpectation {
    /// Creates candidate-selection coordinates supplied by a trusted anchor.
    pub(crate) const fn new(
        binding: RecoveryBinding,
        freshness: Freshness,
        revision: u64,
        head: Digest,
    ) -> Self {
        Self {
            binding,
            freshness,
            revision,
            head,
        }
    }

    pub(super) const fn binding(self) -> RecoveryBinding {
        self.binding
    }

    pub(super) const fn freshness(self) -> Freshness {
        self.freshness
    }

    pub(super) const fn revision(self) -> u64 {
        self.revision
    }

    pub(super) const fn head(self) -> Digest {
        self.head
    }
}

/// Failure from checked positioned cursor movement or source I/O.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReadAtError<E> {
    /// The caller supplied an empty scratch buffer.
    EmptyScratch,
    /// A requested range overflowed or crossed the cursor's admitted range.
    OutOfRange,
    /// The recovery provider rejected a read.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for ReadAtError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScratch => formatter.write_str("recovery scratch buffer is empty"),
            Self::OutOfRange => formatter.write_str("recovery read crossed its admitted range"),
            Self::Source(error) => write!(formatter, "recovery source read failed: {error}"),
        }
    }
}

/// A bounded positioned cursor which never retains a source-owned borrow.
pub(crate) struct ReadAtCursor<'a, S: JournalRecoverySource> {
    source: &'a mut S,
    snapshot: S::Snapshot,
    position: u64,
    end: u64,
    scratch: &'a mut [u8],
}

impl<'a, S: JournalRecoverySource> ReadAtCursor<'a, S> {
    /// Creates a cursor over exactly `start..start + len`.
    pub(crate) fn new(
        source: &'a mut S,
        snapshot: S::Snapshot,
        source_len: u64,
        start: u64,
        len: u64,
        scratch: &'a mut [u8],
    ) -> Result<Self, ReadAtError<S::Error>> {
        if scratch.is_empty() {
            return Err(ReadAtError::EmptyScratch);
        }
        let end = start.checked_add(len).ok_or(ReadAtError::OutOfRange)?;
        if end > source_len {
            return Err(ReadAtError::OutOfRange);
        }
        Ok(Self {
            source,
            snapshot,
            position: start,
            end,
            scratch,
        })
    }

    /// Returns the unread byte count in this admitted range.
    pub(crate) fn remaining(&self) -> u64 {
        self.end - self.position
    }

    /// Returns the next absolute source offset.
    #[cfg(test)]
    pub(crate) const fn position(&self) -> u64 {
        self.position
    }

    /// Reads a caller-owned buffer, crossing provider chunks as needed.
    pub(crate) fn read_exact(
        &mut self,
        mut output: &mut [u8],
    ) -> Result<(), ReadAtError<S::Error>> {
        let requested = u64::try_from(output.len()).map_err(|_| ReadAtError::OutOfRange)?;
        if requested > self.remaining() {
            return Err(ReadAtError::OutOfRange);
        }
        while !output.is_empty() {
            let amount = output.len().min(self.scratch.len());
            self.source
                .read_exact_at(self.snapshot, self.position, &mut self.scratch[..amount])
                .map_err(ReadAtError::Source)?;
            output[..amount].copy_from_slice(&self.scratch[..amount]);
            self.position = self
                .position
                .checked_add(amount as u64)
                .ok_or(ReadAtError::OutOfRange)?;
            output = &mut output[amount..];
        }
        Ok(())
    }

    /// Streams bytes through the fixed scratch buffer without materializing
    /// the complete requested range.
    pub(crate) fn stream_bytes(
        &mut self,
        len: u64,
        mut consume: impl FnMut(&[u8]),
    ) -> Result<(), ReadAtError<S::Error>> {
        if len > self.remaining() {
            return Err(ReadAtError::OutOfRange);
        }
        let mut remaining = len;
        while remaining != 0 {
            let amount = usize::try_from(remaining.min(self.scratch.len() as u64))
                .map_err(|_| ReadAtError::OutOfRange)?;
            self.source
                .read_exact_at(self.snapshot, self.position, &mut self.scratch[..amount])
                .map_err(ReadAtError::Source)?;
            consume(&self.scratch[..amount]);
            self.position = self
                .position
                .checked_add(amount as u64)
                .ok_or(ReadAtError::OutOfRange)?;
            remaining -= amount as u64;
        }
        Ok(())
    }

    /// Reads one little-endian `u16`, including across a one-byte scratch.
    #[cfg(test)]
    pub(crate) fn u16(&mut self) -> Result<u16, ReadAtError<S::Error>> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u32`, including across a one-byte scratch.
    #[cfg(test)]
    pub(crate) fn u32(&mut self) -> Result<u32, ReadAtError<S::Error>> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u64`, including across a one-byte scratch.
    #[cfg(test)]
    pub(crate) fn u64(&mut self) -> Result<u64, ReadAtError<S::Error>> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

/// Borrowed slice adapter used to compare read-at and contiguous scanners.
pub(crate) struct SliceRecoverySource<'a> {
    bytes: &'a [u8],
}

/// Impossible for scanner-admitted ranges; retained to keep the adapter
/// non-panicking when exercised directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SliceRecoveryError;

impl<'a> SliceRecoverySource<'a> {
    /// Wraps one immutable byte slice as a stable recovery view.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl JournalRecoverySource for SliceRecoverySource<'_> {
    type Error = SliceRecoveryError;
    type Snapshot = usize;

    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
        Ok(RecoverySourceSnapshot::new(
            self.bytes.len(),
            self.bytes.len() as u64,
        ))
    }

    fn read_exact_at(
        &mut self,
        snapshot: Self::Snapshot,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if snapshot != self.bytes.len() {
            return Err(SliceRecoveryError);
        }
        let start = usize::try_from(offset).map_err(|_| SliceRecoveryError)?;
        let end = start.checked_add(output.len()).ok_or(SliceRecoveryError)?;
        let source = self.bytes.get(start..end).ok_or(SliceRecoveryError)?;
        output.copy_from_slice(source);
        Ok(())
    }

    fn validate_snapshot(&mut self, snapshot: Self::Snapshot) -> Result<(), Self::Error> {
        (snapshot == self.bytes.len())
            .then_some(())
            .ok_or(SliceRecoveryError)
    }
}
