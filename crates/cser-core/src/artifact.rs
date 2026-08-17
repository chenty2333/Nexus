// SPDX-License-Identifier: MPL-2.0

//! Recovery-artifact retention protocol.
//!
//! This module only binds the identity of an artifact lease and checks the
//! logical pin/release state machine.  It deliberately does not store an
//! artifact, verify a receipt, perform cryptography, or perform garbage
//! collection.  Those responsibilities remain with the embedding and its
//! artifact authority.

use crate::{
    ComponentId, Digest, EffectId, OperationId, ProviderCoordinate, RecoveryArtifactId,
    VerificationError, VerifierBinding, VerifierIdentity,
};

/// Errors returned by the recovery-artifact lease protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactProtocolError {
    /// A digest that identifies a catalog, schema, verifier set, closure, or
    /// release stamp was the reserved all-zero digest.
    ZeroDigest,
    /// A release nonce was zero and therefore could not identify one release
    /// authorization.
    ZeroNonce,
    /// A release was requested before the lease entered the pinned state.
    ReleaseNotAuthorized,
    /// A second release identity was presented for an already authorized
    /// lease.  Reissuing the existing permit is available through
    /// [`ArtifactLeaseState::reissue_release_permit`].
    ReleaseAlreadyAuthorized,
    /// A transition was requested after the lease had already been released.
    AlreadyReleased,
    /// The presented permit was bound to another artifact tuple.
    BindingMismatch,
    /// The presented permit was bound to another pin stamp.
    PinStampMismatch,
    /// The presented permit carried another release operation or nonce.
    ReleaseIdentityMismatch,
}

/// Exact verifier bindings used to authenticate pin and release receipts for
/// one provider generation. Artifact storage and authentication remain an
/// embedding concern; CSER only retains these immutable identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactReceiptBindings {
    pin: VerifierBinding,
    release: VerifierBinding,
}

impl ArtifactReceiptBindings {
    /// Creates the exact pin/release verifier pair.
    pub const fn new(pin: VerifierBinding, release: VerifierBinding) -> Self {
        Self { pin, release }
    }

    /// Returns the verifier binding required to authenticate a pin receipt.
    pub const fn pin(self) -> VerifierBinding {
        self.pin
    }

    /// Returns the verifier binding required to authenticate a release receipt.
    pub const fn release(self) -> VerifierBinding {
        self.release
    }
}

/// Read-only challenge for an artifact pin receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactPinChallenge {
    binding: ArtifactBinding,
    expected_verifier_binding: VerifierBinding,
}

impl ArtifactPinChallenge {
    pub(crate) const fn new(
        binding: ArtifactBinding,
        expected_verifier_binding: VerifierBinding,
    ) -> Self {
        Self {
            binding,
            expected_verifier_binding,
        }
    }

    /// Returns the exact artifact coordinates being pinned.
    pub const fn binding(self) -> ArtifactBinding {
        self.binding
    }

    /// Returns the exact provider-bound verifier identity expected by Core.
    pub const fn expected_verifier_binding(self) -> VerifierBinding {
        self.expected_verifier_binding
    }
}

/// Read-only challenge for an artifact release receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactReleaseChallenge {
    binding: ArtifactBinding,
    pin_stamp: Digest,
    release_operation: OperationId,
    nonce: u64,
    expected_verifier_binding: VerifierBinding,
}

impl ArtifactReleaseChallenge {
    pub(crate) const fn new(
        binding: ArtifactBinding,
        pin_stamp: Digest,
        release_operation: OperationId,
        nonce: u64,
        expected_verifier_binding: VerifierBinding,
    ) -> Self {
        Self {
            binding,
            pin_stamp,
            release_operation,
            nonce,
            expected_verifier_binding,
        }
    }

    /// Returns the exact artifact coordinates being released.
    pub const fn binding(self) -> ArtifactBinding {
        self.binding
    }

    /// Returns the original pin receipt stamp.
    pub const fn pin_stamp(self) -> Digest {
        self.pin_stamp
    }

    /// Returns the idempotent release operation identity.
    pub const fn release_operation(self) -> OperationId {
        self.release_operation
    }

    /// Returns the durable release nonce.
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Returns the exact provider-bound verifier identity expected by Core.
    pub const fn expected_verifier_binding(self) -> VerifierBinding {
        self.expected_verifier_binding
    }
}

/// Trusted adapter for artifact pin receipts.
pub trait ArtifactPinVerifier {
    /// Embedding-specific receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Verifies and canonicalizes one exact pin receipt.
    fn verify(
        &self,
        challenge: &ArtifactPinChallenge,
        receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError>;
}

/// Trusted adapter for artifact release receipts.
pub trait ArtifactReleaseVerifier {
    /// Embedding-specific receipt type.
    type Receipt: ?Sized;

    /// Returns the configured verifier identity.
    fn identity(&self) -> VerifierIdentity;

    /// Verifies and canonicalizes one exact release receipt.
    fn verify(
        &self,
        challenge: &ArtifactReleaseChallenge,
        receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError>;
}

/// The exact semantic coordinates retained by one recovery artifact lease.
///
/// All four digests are part of the identity.  A caller cannot construct a
/// binding containing a zero digest; the constructor is the only creation
/// path and validates the tuple before returning it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactBinding {
    artifact: RecoveryArtifactId,
    provider: ProviderCoordinate,
    operation: OperationId,
    effect: EffectId,
    component: ComponentId,
    catalog_digest: Digest,
    schema_digest: Digest,
    verifier_set_digest: Digest,
    closure_digest: Digest,
}

impl ArtifactBinding {
    /// Creates an exact, digest-bound recovery-artifact tuple.
    // This is the canonical checked constructor for one fixed-width protocol
    // tuple. Grouping fields into an unchecked options bag would make it
    // easier to omit an identity coordinate at call sites.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        artifact: RecoveryArtifactId,
        provider: ProviderCoordinate,
        operation: OperationId,
        effect: EffectId,
        component: ComponentId,
        catalog_digest: Digest,
        schema_digest: Digest,
        verifier_set_digest: Digest,
        closure_digest: Digest,
    ) -> Result<Self, ArtifactProtocolError> {
        if catalog_digest.is_zero()
            || schema_digest.is_zero()
            || verifier_set_digest.is_zero()
            || closure_digest.is_zero()
        {
            return Err(ArtifactProtocolError::ZeroDigest);
        }

        Ok(Self {
            artifact,
            provider,
            operation,
            effect,
            component,
            catalog_digest,
            schema_digest,
            verifier_set_digest,
            closure_digest,
        })
    }

    /// Returns the retained artifact identity.
    pub const fn artifact(self) -> RecoveryArtifactId {
        self.artifact
    }

    /// Returns the retained artifact identity.
    pub const fn artifact_id(self) -> RecoveryArtifactId {
        self.artifact
    }

    /// Returns the exact provider generation bound to the artifact.
    pub const fn provider(self) -> ProviderCoordinate {
        self.provider
    }

    /// Returns the operation that caused the retained effect.
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the escaped effect identity.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the catalog digest used to interpret the effect.
    pub const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }

    /// Returns the receipt schema digest needed during recovery.
    pub const fn schema_digest(self) -> Digest {
        self.schema_digest
    }

    /// Returns the exact verifier-set digest needed during recovery.
    pub const fn verifier_set_digest(self) -> Digest {
        self.verifier_set_digest
    }

    /// Returns the artifact-closure digest.
    pub const fn closure_digest(self) -> Digest {
        self.closure_digest
    }

    /// Returns the component slot whose recovery depends on this artifact.
    pub const fn component(self) -> ComponentId {
        self.component
    }

    /// Returns all binding coordinates in their canonical order.
    pub const fn exact_tuple(
        self,
    ) -> (
        RecoveryArtifactId,
        ProviderCoordinate,
        OperationId,
        EffectId,
        ComponentId,
        Digest,
        Digest,
        Digest,
        Digest,
    ) {
        (
            self.artifact,
            self.provider,
            self.operation,
            self.effect,
            self.component,
            self.catalog_digest,
            self.schema_digest,
            self.verifier_set_digest,
            self.closure_digest,
        )
    }
}

/// Durable state of one artifact retention lease.
///
/// There is intentionally no public unbound variant.  A lease enters this
/// state machine only through [`ArtifactLeaseState::pin`], which requires a
/// validated binding and a non-zero pin stamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactLeaseState {
    /// The artifact is retained for the exact binding and pin stamp.
    Pinned {
        /// Immutable artifact dependency coordinates.
        binding: ArtifactBinding,
        /// Receipt stamp proving that the closure was pinned.
        pin_stamp: Digest,
    },
    /// Release has been durably authorized but the artifact authority has not
    /// yet confirmed unpinning.
    ReleaseAuthorized {
        /// Immutable artifact dependency coordinates.
        binding: ArtifactBinding,
        /// Original receipt stamp proving the pin.
        pin_stamp: Digest,
        /// Exact idempotent operation authorized to unpin the closure.
        release_operation: OperationId,
        /// Durable permit nonce; reissue must preserve this value.
        nonce: u64,
    },
    /// The artifact authority has confirmed physical release.
    Released {
        /// Immutable artifact dependency coordinates.
        binding: ArtifactBinding,
        /// Original receipt stamp proving the pin.
        pin_stamp: Digest,
        /// Receipt stamp proving that the closure was released.
        release_stamp: Digest,
    },
}

impl ArtifactLeaseState {
    /// Pins an artifact before any release operation can be authorized.
    pub const fn pin(
        binding: ArtifactBinding,
        pin_stamp: Digest,
    ) -> Result<Self, ArtifactProtocolError> {
        if pin_stamp.is_zero() {
            return Err(ArtifactProtocolError::ZeroDigest);
        }
        Ok(Self::Pinned { binding, pin_stamp })
    }

    /// Alias for [`ArtifactLeaseState::pin`] emphasizing the resulting state.
    pub const fn pinned(
        binding: ArtifactBinding,
        pin_stamp: Digest,
    ) -> Result<Self, ArtifactProtocolError> {
        Self::pin(binding, pin_stamp)
    }

    /// Returns the exact binding retained by this lease.
    pub const fn binding(&self) -> ArtifactBinding {
        match self {
            Self::Pinned { binding, .. }
            | Self::ReleaseAuthorized { binding, .. }
            | Self::Released { binding, .. } => *binding,
        }
    }

    /// Returns the original durable pin stamp.
    pub const fn pin_stamp(&self) -> Digest {
        match self {
            Self::Pinned { pin_stamp, .. }
            | Self::ReleaseAuthorized { pin_stamp, .. }
            | Self::Released { pin_stamp, .. } => *pin_stamp,
        }
    }

    /// Returns the release operation after release authorization, if any.
    pub const fn release_operation(&self) -> Option<OperationId> {
        match self {
            Self::ReleaseAuthorized {
                release_operation, ..
            } => Some(*release_operation),
            Self::Pinned { .. } | Self::Released { .. } => None,
        }
    }

    /// Returns the release nonce after release authorization, if any.
    pub const fn release_nonce(&self) -> Option<u64> {
        match self {
            Self::ReleaseAuthorized { nonce, .. } => Some(*nonce),
            Self::Pinned { .. } | Self::Released { .. } => None,
        }
    }

    /// Returns the release confirmation stamp, if the artifact was released.
    pub const fn release_stamp(&self) -> Option<Digest> {
        match self {
            Self::Released { release_stamp, .. } => Some(*release_stamp),
            Self::Pinned { .. } | Self::ReleaseAuthorized { .. } => None,
        }
    }

    /// Authorizes one release identity for a pinned artifact.
    ///
    /// The returned permit is private-state-derived and carries the same
    /// exact tuple as the authorized state.  A caller must present that
    /// permit to [`ArtifactLeaseState::confirm_release`].
    pub fn authorize_release(
        self,
        release_operation: OperationId,
        nonce: u64,
    ) -> Result<(Self, ArtifactReleasePermit), ArtifactProtocolError> {
        match self {
            Self::Pinned { binding, pin_stamp } => {
                if nonce == 0 {
                    return Err(ArtifactProtocolError::ZeroNonce);
                }
                let permit = ArtifactReleasePermit {
                    binding,
                    pin_stamp,
                    release_operation,
                    nonce,
                };
                Ok((
                    Self::ReleaseAuthorized {
                        binding,
                        pin_stamp,
                        release_operation,
                        nonce,
                    },
                    permit,
                ))
            }
            Self::ReleaseAuthorized { .. } => Err(ArtifactProtocolError::ReleaseAlreadyAuthorized),
            Self::Released { .. } => Err(ArtifactProtocolError::AlreadyReleased),
        }
    }

    /// Reissues an equivalent permit for the same authorized state.
    ///
    /// Reissue is deliberately separate from authorization: it cannot create
    /// a new release operation or nonce and is idempotent for the durable
    /// authorized tuple.
    pub fn reissue_release_permit(&self) -> Result<ArtifactReleasePermit, ArtifactProtocolError> {
        match self {
            Self::ReleaseAuthorized {
                binding,
                pin_stamp,
                release_operation,
                nonce,
            } => Ok(ArtifactReleasePermit {
                binding: *binding,
                pin_stamp: *pin_stamp,
                release_operation: *release_operation,
                nonce: *nonce,
            }),
            Self::Pinned { .. } => Err(ArtifactProtocolError::ReleaseNotAuthorized),
            Self::Released { .. } => Err(ArtifactProtocolError::AlreadyReleased),
        }
    }

    /// Returns a permit for this state, if release is already authorized.
    pub fn release_permit(&self) -> Result<ArtifactReleasePermit, ArtifactProtocolError> {
        self.reissue_release_permit()
    }

    /// Confirms physical release using the exact authorized permit.
    pub fn confirm_release(
        self,
        permit: ArtifactReleasePermit,
        release_stamp: Digest,
    ) -> Result<Self, ArtifactProtocolError> {
        match self {
            Self::Pinned { .. } => Err(ArtifactProtocolError::ReleaseNotAuthorized),
            Self::Released { .. } => Err(ArtifactProtocolError::AlreadyReleased),
            Self::ReleaseAuthorized {
                binding,
                pin_stamp,
                release_operation,
                nonce,
            } => {
                if permit.binding != binding {
                    return Err(ArtifactProtocolError::BindingMismatch);
                }
                if permit.pin_stamp != pin_stamp {
                    return Err(ArtifactProtocolError::PinStampMismatch);
                }
                if permit.release_operation != release_operation || permit.nonce != nonce {
                    return Err(ArtifactProtocolError::ReleaseIdentityMismatch);
                }
                if release_stamp.is_zero() {
                    return Err(ArtifactProtocolError::ZeroDigest);
                }
                Ok(Self::Released {
                    binding,
                    pin_stamp,
                    release_stamp,
                })
            }
        }
    }
}

/// Linear-by-convention release authorization derived from one authorized
/// lease state.
///
/// The fields and constructor are private.  A permit can only be obtained by
/// authorizing a pinned lease or reissuing the exact permit from an already
/// authorized state.  The type intentionally does not implement `Clone` or
/// `Copy`; callers should consume it at the confirmation boundary.
#[must_use = "a release permit must be presented to confirm artifact release"]
#[derive(Debug, Eq, PartialEq)]
pub struct ArtifactReleasePermit {
    binding: ArtifactBinding,
    pin_stamp: Digest,
    release_operation: OperationId,
    nonce: u64,
}

impl ArtifactReleasePermit {
    pub(crate) const fn from_parts(
        binding: ArtifactBinding,
        pin_stamp: Digest,
        release_operation: OperationId,
        nonce: u64,
    ) -> Self {
        Self {
            binding,
            pin_stamp,
            release_operation,
            nonce,
        }
    }

    /// Returns the exact artifact binding carried by this permit.
    pub const fn binding(&self) -> ArtifactBinding {
        self.binding
    }

    /// Returns the original pin stamp carried by this permit.
    pub const fn pin_stamp(&self) -> Digest {
        self.pin_stamp
    }

    /// Returns the release operation carried by this permit.
    pub const fn release_operation(&self) -> OperationId {
        self.release_operation
    }

    /// Returns the release nonce carried by this permit.
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the complete permit tuple in canonical comparison order.
    pub const fn exact_tuple(&self) -> (ArtifactBinding, Digest, OperationId, u64) {
        (
            self.binding,
            self.pin_stamp,
            self.release_operation,
            self.nonce,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactBinding, ArtifactLeaseState, ArtifactProtocolError};
    use crate::{
        ComponentId, Digest, EffectId, OperationId, ProviderCoordinate, ProviderGeneration,
        ProviderId, RecoveryArtifactId, RootId, WorldId,
    };

    fn id<T>(result: Result<T, crate::IdentityError>) -> T {
        result.expect("test identity is non-zero")
    }

    fn binding(suffix: u8) -> ArtifactBinding {
        ArtifactBinding::new(
            id(RecoveryArtifactId::new(9)),
            ProviderCoordinate::new(
                id(WorldId::new(1)),
                id(ProviderId::new(2)),
                id(ProviderGeneration::new(3)),
            ),
            id(OperationId::new(4)),
            id(EffectId::new(id(RootId::new(5)), 6)),
            id(ComponentId::new(7)),
            Digest::new([suffix; 32]),
            Digest::new([suffix.wrapping_add(1); 32]),
            Digest::new([suffix.wrapping_add(2); 32]),
            Digest::new([suffix.wrapping_add(3); 32]),
        )
        .expect("test binding is digest-complete")
    }

    fn pinned() -> ArtifactLeaseState {
        ArtifactLeaseState::pin(binding(1), Digest::new([10; 32])).expect("pin succeeds")
    }

    #[test]
    fn pin_requires_non_zero_stamp_and_release_follows_pin() {
        assert_eq!(
            ArtifactLeaseState::pin(binding(1), Digest::ZERO),
            Err(ArtifactProtocolError::ZeroDigest)
        );
        assert_eq!(
            pinned().release_permit(),
            Err(ArtifactProtocolError::ReleaseNotAuthorized)
        );

        let (authorized, permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("pinned lease accepts release authorization");
        assert_eq!(
            authorized.release_operation(),
            Some(id(OperationId::new(11)))
        );
        assert_eq!(authorized.release_nonce(), Some(12));
        assert_eq!(permit.binding(), binding(1));
    }

    #[test]
    fn binding_and_release_identity_are_exact() {
        let (authorized, _foreign_unused_permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");

        let (_, foreign_permit) = ArtifactLeaseState::pin(binding(20), Digest::new([10; 32]))
            .expect("foreign pin succeeds")
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("foreign authorization succeeds");
        assert_eq!(
            authorized.confirm_release(foreign_permit, Digest::new([13; 32])),
            Err(ArtifactProtocolError::BindingMismatch)
        );

        let (authorized, permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");
        let (_, new_identity) = ArtifactLeaseState::pin(binding(1), Digest::new([10; 32]))
            .expect("pin succeeds")
            .authorize_release(id(OperationId::new(14)), 15)
            .expect("new identity can exist on another lease");
        assert_eq!(
            authorized.confirm_release(new_identity, Digest::new([13; 32])),
            Err(ArtifactProtocolError::ReleaseIdentityMismatch)
        );
        assert_eq!(permit.binding(), binding(1));
    }

    #[test]
    fn authorized_state_reissues_the_same_permit() {
        let (authorized, first) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");
        let second = authorized
            .reissue_release_permit()
            .expect("authorized state can reissue");
        assert_eq!(first, second);
        assert_eq!(first.exact_tuple(), second.exact_tuple());
        assert_eq!(
            authorized
                .authorize_release(id(OperationId::new(14)), 15)
                .unwrap_err(),
            ArtifactProtocolError::ReleaseAlreadyAuthorized
        );
    }

    #[test]
    fn confirm_release_is_terminal_and_checks_stamp() {
        let (authorized, permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");
        assert_eq!(
            authorized.confirm_release(permit, Digest::ZERO),
            Err(ArtifactProtocolError::ZeroDigest)
        );

        let (authorized, permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");
        let released = authorized
            .confirm_release(permit, Digest::new([13; 32]))
            .expect("release confirmation succeeds");
        assert_eq!(released.release_stamp(), Some(Digest::new([13; 32])));
        assert_eq!(
            released.release_permit(),
            Err(ArtifactProtocolError::AlreadyReleased)
        );
        assert_eq!(
            released
                .confirm_release(
                    pinned()
                        .authorize_release(id(OperationId::new(11)), 12)
                        .unwrap()
                        .1,
                    Digest::new([14; 32])
                )
                .unwrap_err(),
            ArtifactProtocolError::AlreadyReleased
        );
    }

    #[test]
    fn zero_nonce_and_reverse_transitions_fail_closed() {
        assert_eq!(
            pinned().authorize_release(id(OperationId::new(11)), 0),
            Err(ArtifactProtocolError::ZeroNonce)
        );

        let (authorized, permit) = pinned()
            .authorize_release(id(OperationId::new(11)), 12)
            .expect("authorization succeeds");
        assert_eq!(
            authorized.reissue_release_permit().unwrap().exact_tuple(),
            permit.exact_tuple()
        );
        let released = authorized
            .confirm_release(permit, Digest::new([13; 32]))
            .expect("release succeeds");
        assert_eq!(
            released.reissue_release_permit(),
            Err(ArtifactProtocolError::AlreadyReleased)
        );
    }
}
