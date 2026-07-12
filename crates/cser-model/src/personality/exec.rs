//! Failure-atomic executable-image successor over the common effect registry.
//!
//! Staged segments, TLS, and stack metadata remain kernel-private until one
//! `ExecCommit` atomically changes the current image.  Crash recovery requires
//! explicit adoption of the transaction and every segment; revocation before
//! commit preserves the old image, while revocation after commit never rolls
//! the newly published image back.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{EffectId, ScopeId};

use super::registry::{
    EffectRegistry, RegistryBudget, RegistryCommitReceipt, RegistryCreditClass, RegistryEffectKind,
    RegistryEffectState, RegistryEffectToken, RegistryError, RegistryReadyToken,
    RegistryRecoverySnapshot, RegistryResourceKey, RegistryResources, RegistryRevocationStep,
    RegistryScopeView,
};
use super::{PersonalityBindingToken, PersonalityId, TaskId};

/// Stable executable-image identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ImageId(u64);

impl ImageId {
    /// Constructs a nonzero abstract image identity.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Kernel-private staged layout metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecLayout {
    /// Initial thread-local-storage base.
    pub tls_base: u64,
    /// Initial user stack pointer.
    pub stack_pointer: u64,
}

/// Generational identity of one staged exec transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecToken {
    transaction: RegistryEffectToken,
}

impl ExecToken {
    /// Returns the common transaction effect.
    #[must_use]
    pub const fn transaction(self) -> RegistryEffectToken {
        self.transaction
    }

    /// Returns the stable transaction effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.transaction.effect()
    }
}

/// Immutable proof of the unique whole-image publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecCommitReceipt {
    token: ExecToken,
    sequence: u64,
    previous_image: Option<ImageId>,
    image: ImageId,
    segment_effects: Vec<EffectId>,
    layout: ExecLayout,
    commits: Vec<RegistryCommitReceipt>,
}

impl ExecCommitReceipt {
    /// Returns the transaction identity at commit.
    #[must_use]
    pub const fn token(&self) -> ExecToken {
        self.token
    }

    /// Returns the unique domain commit sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the image visible before the atomic commit.
    #[must_use]
    pub const fn previous_image(&self) -> Option<ImageId> {
        self.previous_image
    }

    /// Returns the image published by the commit.
    #[must_use]
    pub const fn image(&self) -> ImageId {
        self.image
    }

    /// Returns the complete frozen staged segment set.
    #[must_use]
    pub fn segment_effects(&self) -> &[EffectId] {
        &self.segment_effects
    }

    /// Returns the frozen TLS/stack layout.
    #[must_use]
    pub const fn layout(&self) -> ExecLayout {
        self.layout
    }
}

/// Read-only scope projection.  Staged image metadata is intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecScopeView {
    /// Common lifecycle and typed-credit registry.
    pub registry: RegistryScopeView,
    /// Only the image already published by `ExecCommit`.
    pub current_image: Option<ImageId>,
    /// Whether one kernel-private staging transaction exists.
    pub staging: bool,
}

/// Exact generic and exec-domain crash image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecRecoverySnapshot {
    registry: RegistryRecoverySnapshot,
    domain: ExecDomainSnapshot,
}

impl ExecRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.registry.scope()
    }

    /// Returns the prospective replacement service.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.registry.personality()
    }
}

/// Ready proof wrapping the common lifecycle proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecReadyToken {
    registry: RegistryReadyToken,
}

/// One domain-aware closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecRevocationStep {
    /// A committed image transaction and all segments were drained together.
    DrainedCommit {
        /// Transaction effect.
        transaction: EffectId,
    },
    /// One uncommitted generic effect was aborted.
    Generic(RegistryRevocationStep),
}

/// Rejected executable-image transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    /// Common registry rejection.
    Registry(RegistryError),
    /// Image or layout identity is invalid.
    InvalidImage,
    /// One scope already has an unfinished transaction.
    StagingBusy,
    /// Token is forged, stale, or names another transaction.
    InvalidToken,
    /// Transaction state does not permit this action.
    InvalidState,
    /// Presented receipt differs from the immutable commit receipt.
    ReceiptMismatch,
    /// Recovery image changed before ready.
    StaleRecoverySnapshot,
    /// Bounded counter overflow.
    CounterOverflow,
    /// Internal domain/registry refinement failed.
    InvariantViolation(&'static str),
}

impl From<RegistryError> for ExecError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecState {
    Staged,
    Committed,
    Completed,
    Revoking,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecRecord {
    token: ExecToken,
    owner: TaskId,
    image: ImageId,
    layout: ExecLayout,
    segments: Vec<RegistryEffectToken>,
    state: ExecState,
    receipt: Option<ExecCommitReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecScopeRecord {
    current_image: Option<ImageId>,
    staging: Option<EffectId>,
    transactions: BTreeSet<EffectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecDomainSnapshot {
    current_image: Option<ImageId>,
    staging: Option<EffectId>,
    transactions: Vec<ExecRecord>,
}

/// Deterministic `no_std + alloc` exec transaction successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecModel {
    registry: EffectRegistry,
    next_commit: u64,
    scopes: BTreeMap<ScopeId, ExecScopeRecord>,
    transactions: BTreeMap<EffectId, ExecRecord>,
    segment_owner: BTreeMap<EffectId, EffectId>,
}

impl Default for ExecModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecModel {
    /// Creates an empty exec successor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registry: EffectRegistry::new(),
            next_commit: 1,
            scopes: BTreeMap::new(),
            transactions: BTreeMap::new(),
            segment_owner: BTreeMap::new(),
        }
    }

    /// Creates one scope with an optional already-current image.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
        budget: RegistryBudget,
        current_image: Option<ImageId>,
    ) -> Result<(ScopeId, PersonalityBindingToken), ExecError> {
        if current_image.is_some_and(|image| !Self::valid_image(image)) {
            return Err(ExecError::InvalidImage);
        }
        let (scope, binding) = self.registry.create_scope(personality, budget)?;
        self.scopes.insert(
            scope,
            ExecScopeRecord {
                current_image,
                staging: None,
                transactions: BTreeSet::new(),
            },
        );
        Ok((scope, binding))
    }

    /// Stages an invisible executable image and all segment effects atomically.
    pub fn stage(
        &mut self,
        binding: PersonalityBindingToken,
        owner: TaskId,
        image: ImageId,
        segment_count: usize,
        layout: ExecLayout,
    ) -> Result<ExecToken, ExecError> {
        if !Self::valid_image(image)
            || segment_count == 0
            || layout.tls_base == 0
            || layout.stack_pointer == 0
        {
            return Err(ExecError::InvalidImage);
        }
        let local = self.local_scope(binding.scope())?;
        if local.staging.is_some()
            || local.transactions.iter().any(|effect| {
                self.transactions.get(effect).is_some_and(|record| {
                    matches!(
                        record.state,
                        ExecState::Staged | ExecState::Committed | ExecState::Revoking
                    )
                })
            })
        {
            return Err(ExecError::StagingBusy);
        }
        if local.transactions.iter().any(|effect| {
            self.transactions
                .get(effect)
                .is_some_and(|record| record.image == image)
        }) {
            return Err(ExecError::InvalidImage);
        }
        let segment_resources = (0..segment_count)
            .map(|index| Self::segment_resource(image, index))
            .collect::<Result<Vec<_>, _>>()?;
        let checkpoint = self.registry.clone();
        let transaction = self.registry.register(
            binding,
            owner,
            RegistryEffectKind::ExecTransaction,
            RegistryResources::one(Self::image_resource(image)),
            RegistryCreditClass::Continuation,
        )?;
        let mut segments = Vec::with_capacity(segment_count);
        for resource in segment_resources {
            let segment = match self.registry.register(
                binding,
                owner,
                RegistryEffectKind::ExecSegment,
                RegistryResources::pair(Self::image_resource(image), resource),
                RegistryCreditClass::ExecSegment,
            ) {
                Ok(segment) => segment,
                Err(error) => {
                    self.registry = checkpoint;
                    return Err(error.into());
                }
            };
            segments.push(segment);
        }
        let token = ExecToken { transaction };
        self.transactions.insert(
            token.effect(),
            ExecRecord {
                token,
                owner,
                image,
                layout,
                segments: segments.clone(),
                state: ExecState::Staged,
                receipt: None,
            },
        );
        for segment in segments {
            self.segment_owner.insert(segment.effect(), token.effect());
        }
        let scope = self.local_scope_mut(binding.scope())?;
        scope.staging = Some(token.effect());
        scope.transactions.insert(token.effect());
        Ok(token)
    }

    /// Atomically publishes every segment, TLS, stack, and the new image.
    pub fn commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: ExecToken,
    ) -> Result<ExecCommitReceipt, ExecError> {
        let record = self.validate_token(token)?.clone();
        if record.state != ExecState::Staged {
            return Err(ExecError::InvalidState);
        }
        let sequence = self.next_commit;
        let next = sequence.checked_add(1).ok_or(ExecError::CounterOverflow)?;
        let mut requests = Vec::with_capacity(record.segments.len() + 1);
        requests.push((record.token.transaction, sequence));
        requests.extend(
            record
                .segments
                .iter()
                .copied()
                .map(|segment| (segment, sequence)),
        );
        let commits = self.registry.commit_many(binding, &requests)?;
        let previous_image = self.local_scope(binding.scope())?.current_image;
        let receipt = ExecCommitReceipt {
            token,
            sequence,
            previous_image,
            image: record.image,
            segment_effects: record
                .segments
                .iter()
                .map(|segment| segment.effect())
                .collect(),
            layout: record.layout,
            commits,
        };
        self.next_commit = next;
        let local = self.local_scope_mut(binding.scope())?;
        local.current_image = Some(record.image);
        local.staging = None;
        let record = self
            .transactions
            .get_mut(&token.effect())
            .expect("validated transaction remains present");
        record.state = ExecState::Committed;
        record.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Consumes the exec continuation after the image is already current.
    pub fn complete(&mut self, receipt: &ExecCommitReceipt) -> Result<(), ExecError> {
        let effect = receipt.token.effect();
        let record = self
            .transactions
            .get(&effect)
            .ok_or(ExecError::ReceiptMismatch)?;
        if record.state != ExecState::Committed || record.receipt.as_ref() != Some(receipt) {
            return Err(ExecError::ReceiptMismatch);
        }
        self.registry.complete_many(&receipt.commits)?;
        self.transactions
            .get_mut(&effect)
            .expect("validated transaction remains present")
            .state = ExecState::Completed;
        Ok(())
    }

    /// Fences a crashed exec service.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), ExecError> {
        self.registry.crash(binding)?;
        Ok(())
    }

    /// Selects common kernel fallback.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), ExecError> {
        self.registry.fallback_pick(scope)?;
        Ok(())
    }

    /// Captures an exact registry plus staged-image recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<ExecRecoverySnapshot, ExecError> {
        Ok(ExecRecoverySnapshot {
            registry: self.registry.recovery_snapshot(scope, personality)?,
            domain: self.domain_snapshot(scope)?,
        })
    }

    /// Accepts readiness only while the complete image remains exact.
    pub fn ready(&mut self, snapshot: &ExecRecoverySnapshot) -> Result<ExecReadyToken, ExecError> {
        let current = self.recovery_snapshot(snapshot.scope(), snapshot.personality())?;
        if current != *snapshot {
            return Err(ExecError::StaleRecoverySnapshot);
        }
        Ok(ExecReadyToken {
            registry: self.registry.ready(&snapshot.registry)?,
        })
    }

    /// Installs a ready replacement without implicit adoption.
    pub fn rebind(&mut self, ready: ExecReadyToken) -> Result<PersonalityBindingToken, ExecError> {
        Ok(self.registry.rebind(ready.registry)?)
    }

    /// Explicitly adopts one transaction or segment effect.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: RegistryEffectToken,
    ) -> Result<RegistryEffectToken, ExecError> {
        let adopted = self.registry.adopt(binding, token)?;
        let transaction = self
            .segment_owner
            .get(&token.effect())
            .copied()
            .unwrap_or(token.effect());
        let record =
            self.transactions
                .get_mut(&transaction)
                .ok_or(ExecError::InvariantViolation(
                    "registry effect lacks exec-domain transaction",
                ))?;
        if record.token.transaction.effect() == token.effect() {
            record.token.transaction = adopted;
        } else if let Some(segment) = record
            .segments
            .iter_mut()
            .find(|segment| segment.effect() == token.effect())
        {
            *segment = adopted;
        } else {
            return Err(ExecError::InvariantViolation(
                "segment owner index disagrees with transaction",
            ));
        }
        Ok(adopted)
    }

    /// Closes authority explicitly.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), ExecError> {
        self.registry.revoke_begin(scope)?;
        Ok(())
    }

    /// Performs one domain-aware closure step.
    pub fn revoke_next(&mut self, scope: ScopeId) -> Result<Option<ExecRevocationStep>, ExecError> {
        if let Some(transaction) = self
            .local_scope(scope)?
            .transactions
            .iter()
            .find(|effect| {
                self.transactions
                    .get(effect)
                    .is_some_and(|record| record.state == ExecState::Committed)
            })
            .copied()
        {
            let receipt = self
                .transactions
                .get(&transaction)
                .and_then(|record| record.receipt.clone())
                .ok_or(ExecError::InvariantViolation(
                    "committed transaction lacks receipt",
                ))?;
            self.complete(&receipt)?;
            return Ok(Some(ExecRevocationStep::DrainedCommit { transaction }));
        }
        let Some(step) = self.registry.revoke_next(scope)? else {
            return Ok(None);
        };
        let effect = match step {
            RegistryRevocationStep::Drained { effect }
            | RegistryRevocationStep::Aborted { effect } => effect,
        };
        let transaction = self.segment_owner.get(&effect).copied().unwrap_or(effect);
        if let Some(record) = self.transactions.get_mut(&transaction) {
            record.state = ExecState::Revoking;
            let all_terminal = core::iter::once(record.token.transaction)
                .chain(record.segments.iter().copied())
                .all(|token| {
                    self.registry
                        .effect(token.effect())
                        .is_some_and(|view| view.state.is_terminal())
                });
            if all_terminal {
                record.state = ExecState::Aborted;
                let local = self.local_scope_mut(scope)?;
                if local.staging == Some(transaction) {
                    local.staging = None;
                }
            }
        }
        Ok(Some(ExecRevocationStep::Generic(step)))
    }

    /// Publishes closure only after every transaction is terminal.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), ExecError> {
        if self.local_scope(scope)?.staging.is_some()
            || self.local_scope(scope)?.transactions.iter().any(|effect| {
                self.transactions.get(effect).is_some_and(|record| {
                    !matches!(record.state, ExecState::Completed | ExecState::Aborted)
                })
            })
        {
            return Err(ExecError::InvariantViolation(
                "exec domain is not quiescent",
            ));
        }
        self.registry.revoke_complete(scope)?;
        Ok(())
    }

    /// Returns a public scope projection without staged image metadata.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<ExecScopeView> {
        let registry = self.registry.scope(scope)?;
        let local = self.scopes.get(&scope)?;
        Some(ExecScopeView {
            registry,
            current_image: local.current_image,
            staging: local.staging.is_some(),
        })
    }

    /// Returns the current token for one transaction after adoption.
    #[must_use]
    pub fn transaction(&self, effect: EffectId) -> Option<ExecToken> {
        self.transactions.get(&effect).map(|record| record.token)
    }

    /// Returns current segment tokens for explicit recovery adoption.
    #[must_use]
    pub fn segments(&self, effect: EffectId) -> Option<Vec<RegistryEffectToken>> {
        self.transactions
            .get(&effect)
            .map(|record| record.segments.clone())
    }

    /// Audits atomic image visibility, receipts, credits, and registry state.
    pub fn check_invariants(&self) -> Result<(), ExecError> {
        self.registry
            .check_invariants()
            .map_err(|_| ExecError::InvariantViolation("registry invariant"))?;
        for (scope, local) in &self.scopes {
            if local
                .current_image
                .is_some_and(|image| !Self::valid_image(image))
            {
                return Err(ExecError::InvariantViolation("invalid current image"));
            }
            let expected_staging: Vec<_> = local
                .transactions
                .iter()
                .filter(|effect| {
                    self.transactions.get(effect).is_some_and(|record| {
                        matches!(record.state, ExecState::Staged | ExecState::Revoking)
                    })
                })
                .copied()
                .collect();
            if expected_staging.len() > 1 || expected_staging.first().copied() != local.staging {
                return Err(ExecError::InvariantViolation("staging index mismatch"));
            }
            for effect in &local.transactions {
                let record = self
                    .transactions
                    .get(effect)
                    .ok_or(ExecError::InvariantViolation(
                        "scope names missing transaction",
                    ))?;
                if record.token.transaction.scope() != *scope
                    || record.token.effect() != *effect
                    || !Self::valid_image(record.image)
                    || record.segments.is_empty()
                    || record.layout.tls_base == 0
                    || record.layout.stack_pointer == 0
                {
                    return Err(ExecError::InvariantViolation(
                        "invalid transaction identity",
                    ));
                }
                let mut generic_states = Vec::with_capacity(record.segments.len() + 1);
                for token in core::iter::once(record.token.transaction)
                    .chain(record.segments.iter().copied())
                {
                    generic_states.push(
                        self.registry
                            .effect(token.effect())
                            .ok_or(ExecError::InvariantViolation(
                                "transaction effect missing registry record",
                            ))?
                            .state,
                    );
                }
                let valid = match record.state {
                    ExecState::Staged => {
                        record.receipt.is_none()
                            && generic_states
                                .iter()
                                .all(|state| *state == RegistryEffectState::Registered)
                            && local.current_image != Some(record.image)
                    }
                    ExecState::Committed => {
                        record.receipt.is_some()
                            && generic_states
                                .iter()
                                .all(|state| *state == RegistryEffectState::Committed)
                            && local.current_image == Some(record.image)
                    }
                    ExecState::Completed => {
                        record.receipt.is_some()
                            && generic_states
                                .iter()
                                .all(|state| *state == RegistryEffectState::Completed)
                    }
                    ExecState::Revoking => {
                        record.receipt.is_none()
                            && generic_states.iter().any(|state| state.is_terminal())
                    }
                    ExecState::Aborted => {
                        record.receipt.is_none()
                            && generic_states
                                .iter()
                                .all(|state| *state == RegistryEffectState::Aborted)
                            && local.current_image != Some(record.image)
                    }
                };
                if !valid {
                    return Err(ExecError::InvariantViolation(
                        "transaction registry refinement",
                    ));
                }
                for segment in &record.segments {
                    if self.segment_owner.get(&segment.effect()) != Some(effect) {
                        return Err(ExecError::InvariantViolation(
                            "segment owner index mismatch",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_token(&self, token: ExecToken) -> Result<&ExecRecord, ExecError> {
        self.transactions
            .get(&token.effect())
            .filter(|record| record.token == token)
            .ok_or(ExecError::InvalidToken)
    }

    fn domain_snapshot(&self, scope: ScopeId) -> Result<ExecDomainSnapshot, ExecError> {
        let local = self.local_scope(scope)?;
        Ok(ExecDomainSnapshot {
            current_image: local.current_image,
            staging: local.staging,
            transactions: local
                .transactions
                .iter()
                .map(|effect| {
                    self.transactions
                        .get(effect)
                        .cloned()
                        .ok_or(ExecError::InvariantViolation(
                            "snapshot missing transaction",
                        ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn local_scope(&self, scope: ScopeId) -> Result<&ExecScopeRecord, ExecError> {
        self.scopes.get(&scope).ok_or(ExecError::InvariantViolation(
            "registry scope lacks exec domain",
        ))
    }

    fn local_scope_mut(&mut self, scope: ScopeId) -> Result<&mut ExecScopeRecord, ExecError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(ExecError::InvariantViolation(
                "registry scope lacks exec domain",
            ))
    }

    const fn image_resource(image: ImageId) -> RegistryResourceKey {
        RegistryResourceKey::new(0x4000_0000_0000_0000 | image.0)
    }

    fn segment_resource(image: ImageId, index: usize) -> Result<RegistryResourceKey, ExecError> {
        let index = u64::try_from(index).map_err(|_| ExecError::CounterOverflow)?;
        let mixed = image
            .0
            .checked_mul(256)
            .and_then(|value| value.checked_add(index))
            .ok_or(ExecError::CounterOverflow)?;
        Ok(RegistryResourceKey::new(0x5000_0000_0000_0000 | mixed))
    }

    const fn valid_image(image: ImageId) -> bool {
        image.0 > 0 && image.0 < (1_u64 << 48)
    }
}
