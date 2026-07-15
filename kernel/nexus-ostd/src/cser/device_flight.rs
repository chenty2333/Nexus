// SPDX-License-Identifier: MPL-2.0

//! Kernel-owned semantic spine for one device-backed CSER flight.
//!
//! This module deliberately contains only Registry-issued identities,
//! receipts, and obligations. Hardware typestate and workload payload remain
//! owned by their adapters; in particular, this is not a second ledger and it
//! never reconstructs Registry state from a projection or history scan.

use core::num::NonZeroU64;

use crate::effect_registry::{
    CommitMetadata, DeviceBatchCommitReceipt, DeviceBatchEnrollmentReceipt, DeviceCloseError,
    DeviceCloseOperationId, DeviceCloseOutcome, DeviceEnvelope, DevicePrecommitCloseReceipt,
    DevicePublishedObligation, DeviceResetTicket, EffectRegistry, KernelRootAuthority,
    PortalHandle, RegistryError, RevokeSelection, ScopeKey,
};

/// Immutable correlation identity shared by task, recovery, and IRQ actors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceFlightKey {
    operation: DeviceCloseOperationId,
    cookie: NonZeroU64,
    envelope: DeviceEnvelope,
}

impl DeviceFlightKey {
    fn from_operation(operation: DeviceCloseOperationId) -> Option<Self> {
        Some(Self {
            operation,
            cookie: NonZeroU64::new(operation.caller_nonce())?,
            envelope: operation.device(),
        })
    }

    pub(crate) const fn operation(self) -> DeviceCloseOperationId {
        self.operation
    }

    pub(crate) const fn cookie(self) -> u64 {
        self.cookie.get()
    }

    pub(crate) const fn envelope(self) -> DeviceEnvelope {
        self.envelope
    }
}

/// Mints one flight key from the Registry-owned operation identity.
///
/// `NonZeroU64` keeps the zero cookie unavailable by construction. The device
/// envelope is copied only from the minted operation, never accepted as a
/// second caller-supplied identity.
pub(crate) fn mint_device_flight_key(
    registry: &EffectRegistry,
    enrollment: &DeviceBatchEnrollmentReceipt,
    cookie: NonZeroU64,
) -> Result<DeviceFlightKey, RegistryError> {
    let operation = registry.mint_device_close_operation(enrollment, cookie.get())?;
    DeviceFlightKey::from_operation(operation).ok_or(RegistryError::InvalidGeneration)
}

/// Semantic ownership returned by a successful or recovered device commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublishedSemantic {
    key: DeviceFlightKey,
    batch: DeviceBatchCommitReceipt,
    selection: RevokeSelection,
}

impl PublishedSemantic {
    fn new(
        key: DeviceFlightKey,
        batch: DeviceBatchCommitReceipt,
        selection: RevokeSelection,
    ) -> Self {
        Self {
            key,
            batch,
            selection,
        }
    }

    pub(crate) const fn key(&self) -> DeviceFlightKey {
        self.key
    }

    pub(crate) const fn batch(&self) -> &DeviceBatchCommitReceipt {
        &self.batch
    }

    pub(crate) const fn selection(&self) -> &RevokeSelection {
        &self.selection
    }
}

/// Semantic ownership for a cohort closed before device publication.
///
/// A pending device root has no normal close operation yet, so precommit
/// correlation deliberately uses only a nonzero runtime cookie and the complete
/// authoritative Registry receipt. It never fabricates a
/// [`DeviceCloseOperationId`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrecommitCloseSemantic {
    cookie: NonZeroU64,
    receipt: DevicePrecommitCloseReceipt,
}

impl PrecommitCloseSemantic {
    fn from_registry_receipt(cookie: NonZeroU64, receipt: DevicePrecommitCloseReceipt) -> Self {
        Self { cookie, receipt }
    }

    pub(crate) const fn cookie(&self) -> u64 {
        self.cookie.get()
    }

    pub(crate) const fn selection(&self) -> &RevokeSelection {
        &self.receipt.selection
    }

    pub(crate) const fn enrollment(&self) -> &DeviceBatchEnrollmentReceipt {
        &self.receipt.enrollment
    }

    pub(crate) const fn reset_ticket(&self) -> &DeviceResetTicket {
        &self.receipt.reset_ticket
    }

    pub(crate) const fn receipt(&self) -> &DevicePrecommitCloseReceipt {
        &self.receipt
    }
}

/// Closes an already enrolled unpublished cohort through the Registry's one
/// failure-atomic production transition.
pub(crate) fn close_enrolled_device_flight_precommit_with_apply<T>(
    registry: &mut EffectRegistry,
    enrollment: &DeviceBatchEnrollmentReceipt,
    cookie: NonZeroU64,
    apply_hardware: impl FnOnce(&DeviceResetTicket) -> T,
) -> Result<(PrecommitCloseSemantic, T), RegistryError> {
    let (receipt, hardware) =
        registry.close_enrolled_device_precommit_with_apply(enrollment, apply_hardware)?;
    Ok((
        PrecommitCloseSemantic::from_registry_receipt(cookie, receipt),
        hardware,
    ))
}

/// Freezes and closes a pending unpublished device root without inventing a
/// normal close operation for it.
pub(crate) fn close_pending_device_flight_precommit_with_apply<T>(
    registry: &mut EffectRegistry,
    scope: ScopeKey,
    cookie: NonZeroU64,
    apply_hardware: impl FnOnce(&DeviceResetTicket) -> T,
) -> Result<(PrecommitCloseSemantic, T), RegistryError> {
    let (receipt, hardware) =
        registry.close_pending_device_precommit_with_apply(scope, apply_hardware)?;
    Ok((
        PrecommitCloseSemantic::from_registry_receipt(cookie, receipt),
        hardware,
    ))
}

/// Adapter-level reason that a published obligation remains retained.
///
/// This classification never replaces the authoritative Registry error stored
/// beside the obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetainReason {
    TransitionRejected,
    HardwareAuthorityUnavailable,
    SemanticIdentityMismatch,
}

/// Discoverable fail-closed state for a batch that may already be published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedSemantic {
    attempted_cookie: NonZeroU64,
    key: Option<DeviceFlightKey>,
    obligation: DevicePublishedObligation,
    error: RegistryError,
    reason: RetainReason,
}

impl RetainedSemantic {
    fn new(
        key: DeviceFlightKey,
        obligation: DevicePublishedObligation,
        error: RegistryError,
        reason: RetainReason,
    ) -> Self {
        let exact_key = if obligation.operation() == Some(key.operation()) {
            Some(key)
        } else {
            None
        };
        Self {
            attempted_cookie: key.cookie,
            key: exact_key,
            obligation,
            error,
            reason: if exact_key.is_some() {
                reason
            } else {
                RetainReason::SemanticIdentityMismatch
            },
        }
    }

    pub(crate) const fn cookie(&self) -> u64 {
        self.attempted_cookie.get()
    }

    pub(crate) const fn key(&self) -> Option<DeviceFlightKey> {
        self.key
    }

    pub(crate) const fn obligation(&self) -> &DevicePublishedObligation {
        &self.obligation
    }

    pub(crate) const fn error(&self) -> &RegistryError {
        &self.error
    }

    pub(crate) const fn reason(&self) -> RetainReason {
        self.reason
    }

    /// Converts only a Registry-confirmed published error into retained
    /// semantic ownership. An unpublished error is returned unchanged because
    /// it carries no published obligation and must use precommit closure.
    // Preserve the inline published obligation across this allocation-free
    // conversion; callers must retain the exact recovery authority on error.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_close_error(
        key: DeviceFlightKey,
        reason: RetainReason,
        close_error: DeviceCloseError,
    ) -> Result<Self, DeviceCloseError> {
        match close_error {
            DeviceCloseError::Published { obligation, error } => {
                Ok(Self::new(key, obligation, error, reason))
            }
            unpublished @ DeviceCloseError::Unpublished(_) => Err(unpublished),
        }
    }
}

/// Semantic successor of the Registry's applied/recovered close operation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeviceFlightCloseOutcome<T> {
    Applied {
        published: PublishedSemantic,
        publication: T,
    },
    Recovered {
        published: PublishedSemantic,
    },
}

impl<T> DeviceFlightCloseOutcome<T> {
    pub(crate) const fn published(&self) -> &PublishedSemantic {
        match self {
            Self::Applied { published, .. } | Self::Recovered { published } => published,
        }
    }
}

/// Runs the production Registry transition and adds only immutable flight
/// correlation to its authoritative outcome.
///
/// The hardware closure is forwarded unchanged and is therefore called exactly
/// when the Registry reports `Applied`. `Recovered` reuses the original batch
/// and revoke selection without invoking the closure or maintaining a side
/// cache in this module.
// This facade preserves the Registry's allocation-free post-publication error
// contract, including the full inline obligation.
#[allow(clippy::result_large_err)]
pub(crate) fn commit_or_recover_device_flight_with_apply<T>(
    registry: &mut EffectRegistry,
    key: DeviceFlightKey,
    authority: KernelRootAuthority,
    enrollment: &DeviceBatchEnrollmentReceipt,
    commits: &[(PortalHandle, CommitMetadata)],
    publish: impl FnOnce(&DeviceBatchCommitReceipt) -> T,
) -> Result<DeviceFlightCloseOutcome<T>, DeviceCloseError> {
    match registry.commit_or_recover_device_close_with_apply(
        key.operation(),
        authority,
        enrollment,
        commits,
        publish,
    )? {
        DeviceCloseOutcome::Applied {
            receipt,
            publication,
            selection,
        } => Ok(DeviceFlightCloseOutcome::Applied {
            published: PublishedSemantic::new(key, receipt, selection),
            publication,
        }),
        DeviceCloseOutcome::Recovered { receipt, selection } => {
            Ok(DeviceFlightCloseOutcome::Recovered {
                published: PublishedSemantic::new(key, receipt, selection),
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn retained_semantic_self_test() {
    let fixture = crate::effect_registry::retained_semantic_test_fixture();
    let exact_key = DeviceFlightKey::from_operation(fixture.exact_operation).unwrap();
    let exact = RetainedSemantic::from_close_error(
        exact_key,
        RetainReason::TransitionRejected,
        DeviceCloseError::Published {
            obligation: fixture.obligation.clone(),
            error: fixture.error.clone(),
        },
    )
    .unwrap();
    assert_eq!(exact.cookie(), exact_key.cookie());
    assert_eq!(exact.key(), Some(exact_key));
    assert_eq!(exact.reason(), RetainReason::TransitionRejected);
    assert_eq!(exact.obligation(), &fixture.obligation);
    assert_eq!(exact.error(), &fixture.error);

    let foreign_key = DeviceFlightKey::from_operation(fixture.foreign_operation).unwrap();
    let foreign = RetainedSemantic::from_close_error(
        foreign_key,
        RetainReason::HardwareAuthorityUnavailable,
        DeviceCloseError::Published {
            obligation: fixture.obligation.clone(),
            error: fixture.error.clone(),
        },
    )
    .unwrap();
    assert_eq!(foreign.cookie(), foreign_key.cookie());
    assert_eq!(foreign.key(), None);
    assert_eq!(foreign.reason(), RetainReason::SemanticIdentityMismatch);
    assert_eq!(foreign.obligation(), &fixture.obligation);
    assert_eq!(foreign.error(), &fixture.error);
}
