// SPDX-License-Identifier: MPL-2.0

use crate::effect::EffectToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaQuiesceError {
    IotlbInvalidationUnavailable,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Quiesced;

pub trait DmaQuiescer {
    fn unmap_invalidate_and_wait(&self, token: EffectToken) -> Result<Quiesced, DmaQuiesceError>;
}

/// OSTD 0.18 removes the page-table entry but does not expose a completed
/// IOTLB invalidation operation. Refuse to report quiescence until that exists.
pub struct Ostd018FailClosed;

impl DmaQuiescer for Ostd018FailClosed {
    fn unmap_invalidate_and_wait(&self, _token: EffectToken) -> Result<Quiesced, DmaQuiesceError> {
        Err(DmaQuiesceError::IotlbInvalidationUnavailable)
    }
}
