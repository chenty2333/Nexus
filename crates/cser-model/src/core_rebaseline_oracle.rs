//! Independent normalized oracle for the CSER core rebaseline.
//!
//! This module intentionally does not share commands, tokens, codecs, or
//! transition helpers with `cser-core`.  It models only the normalized
//! settlement and device-freshness projections needed for differential
//! evidence.  An evidence harness may translate production projections into
//! these enums, but the oracle itself remains a separate implementation.

/// Normalized rejection emitted by the independent oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleError {
    /// Revocation or an earlier terminal transition closed the gate.
    GateClosed,
    /// A settlement claimant already owns the gate.
    GateClaimed,
    /// A settlement operation named a claimant that no longer owns the gate.
    StaleClaim,
    /// A root operation named an incarnation or binding that is no longer live.
    StaleIncarnation,
    /// A revoke observation named an authority epoch that has since advanced.
    StaleAuthorityEpoch,
    /// The root has not reached the recovery state required by the operation.
    WrongRecoveryState,
    /// The estate commit state does not admit the requested operation.
    WrongCommitState,
    /// The operation is not legal at the current settlement stage.
    WrongSettlementStage,
    /// Retirement evidence names an inactive device generation.
    StaleEvidence,
    /// A causal retirement prerequisite has not yet been accepted.
    EvidenceOutOfOrder,
    /// A device generation did not advance monotonically.
    FreshnessRollback,
    /// The resource was already retired by accepted evidence.
    AlreadyRetired,
}

/// Normalized public settlement projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleSettlement {
    /// One claimant or revocation may still win.
    Open {
        /// Monotonic claim generation.
        generation: u64,
    },
    /// A named incarnation owns the settlement gate.
    Claimed {
        /// Incarnation generation of the claimant.
        claimant: u64,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// External apply intent is durable.
    ApplyIntentDurable {
        /// Incarnation generation of the claimant.
        claimant: u64,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// External apply occurred but durable settlement did not.
    AppliedUnacknowledged {
        /// Incarnation generation of the claimant.
        claimant: u64,
        /// Monotonic claim generation.
        generation: u64,
    },
    /// A crashed claimant requires exact reconciliation.
    ReconciliationRequired {
        /// Generation available to the next claimant.
        generation: u64,
        /// Whether the previous external apply was observed.
        applied: bool,
    },
    /// Settlement completed exactly once.
    Settled,
    /// Revocation won before a claimant.
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimStage {
    Fresh,
    Intent,
    Applied,
    ReconcileIntent,
    ReconcileApplied,
}

/// Small independent state machine for successor settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementOracle {
    settlement: OracleSettlement,
    claim_stage: Option<ClaimStage>,
}

impl SettlementOracle {
    /// Opens a settlement gate at a non-zero generation.
    #[must_use]
    pub const fn open(generation: u64) -> Self {
        assert!(generation != 0, "claim generation must be non-zero");
        Self {
            settlement: OracleSettlement::Open { generation },
            claim_stage: None,
        }
    }

    /// Returns the normalized public projection.
    #[must_use]
    pub const fn projection(self) -> OracleSettlement {
        self.settlement
    }

    /// Claims an open or reconciliation gate for one incarnation generation.
    pub fn claim(&mut self, claimant: u64) -> Result<(), OracleError> {
        let (generation, stage) = match self.settlement {
            OracleSettlement::Open { generation } => (generation, ClaimStage::Fresh),
            OracleSettlement::ReconciliationRequired {
                generation,
                applied,
            } => (
                generation,
                if applied {
                    ClaimStage::ReconcileApplied
                } else {
                    ClaimStage::ReconcileIntent
                },
            ),
            OracleSettlement::Claimed { .. }
            | OracleSettlement::ApplyIntentDurable { .. }
            | OracleSettlement::AppliedUnacknowledged { .. } => {
                return Err(OracleError::GateClaimed);
            }
            OracleSettlement::Settled | OracleSettlement::Revoked => {
                return Err(OracleError::GateClosed);
            }
        };
        self.settlement = OracleSettlement::Claimed {
            claimant,
            generation,
        };
        self.claim_stage = Some(stage);
        Ok(())
    }

    /// Records a write-ahead apply intent for a fresh claim.
    pub fn record_apply_intent(&mut self, claimant: u64) -> Result<(), OracleError> {
        let generation = self.exact_claim(claimant)?;
        if self.claim_stage != Some(ClaimStage::Fresh) {
            return Err(OracleError::WrongSettlementStage);
        }
        self.settlement = OracleSettlement::ApplyIntentDurable {
            claimant,
            generation,
        };
        self.claim_stage = Some(ClaimStage::Intent);
        Ok(())
    }

    /// Records exact evidence that an intended or reconciled apply occurred.
    pub fn record_applied(&mut self, claimant: u64) -> Result<(), OracleError> {
        let generation = self.exact_claim(claimant)?;
        self.claim_stage = Some(match self.claim_stage {
            Some(ClaimStage::Intent) => ClaimStage::Applied,
            Some(ClaimStage::ReconcileIntent) => ClaimStage::ReconcileApplied,
            _ => return Err(OracleError::WrongSettlementStage),
        });
        self.settlement = OracleSettlement::AppliedUnacknowledged {
            claimant,
            generation,
        };
        Ok(())
    }

    /// Settles an externally applied obligation.
    pub fn settle(&mut self, claimant: u64) -> Result<(), OracleError> {
        self.exact_claim(claimant)?;
        if !matches!(
            self.claim_stage,
            Some(ClaimStage::Applied | ClaimStage::ReconcileApplied)
        ) {
            return Err(OracleError::WrongSettlementStage);
        }
        self.settlement = OracleSettlement::Settled;
        self.claim_stage = None;
        Ok(())
    }

    /// Lets revocation compete through the same settlement gate.
    pub fn begin_revoke(&mut self) -> Result<(), OracleError> {
        match self.settlement {
            OracleSettlement::Open { .. } | OracleSettlement::ReconciliationRequired { .. } => {
                self.settlement = OracleSettlement::Revoked;
                self.claim_stage = None;
                Ok(())
            }
            OracleSettlement::Claimed { .. }
            | OracleSettlement::ApplyIntentDurable { .. }
            | OracleSettlement::AppliedUnacknowledged { .. } => Err(OracleError::GateClaimed),
            OracleSettlement::Settled | OracleSettlement::Revoked => Err(OracleError::GateClosed),
        }
    }

    /// Fences a crashed claimant and conservatively reopens or reconciles.
    pub fn crash(&mut self) {
        self.settlement = match (self.settlement, self.claim_stage) {
            (OracleSettlement::Open { generation }, _) => OracleSettlement::Open { generation },
            (OracleSettlement::Claimed { generation, .. }, Some(ClaimStage::ReconcileIntent)) => {
                OracleSettlement::ReconciliationRequired {
                    generation: next_generation(generation),
                    applied: false,
                }
            }
            (OracleSettlement::Claimed { generation, .. }, Some(ClaimStage::ReconcileApplied)) => {
                OracleSettlement::ReconciliationRequired {
                    generation: next_generation(generation),
                    applied: true,
                }
            }
            (OracleSettlement::Claimed { generation, .. }, _) => OracleSettlement::Open {
                generation: next_generation(generation),
            },
            (OracleSettlement::ApplyIntentDurable { generation, .. }, _) => {
                OracleSettlement::ReconciliationRequired {
                    generation: next_generation(generation),
                    applied: false,
                }
            }
            (OracleSettlement::AppliedUnacknowledged { generation, .. }, _) => {
                OracleSettlement::ReconciliationRequired {
                    generation: next_generation(generation),
                    applied: true,
                }
            }
            (
                OracleSettlement::ReconciliationRequired {
                    generation,
                    applied,
                },
                _,
            ) => OracleSettlement::ReconciliationRequired {
                generation: next_generation(generation),
                applied,
            },
            (OracleSettlement::Settled, _) => OracleSettlement::Settled,
            (OracleSettlement::Revoked, _) => OracleSettlement::Revoked,
        };
        self.claim_stage = None;
    }

    fn exact_claim(&self, claimant: u64) -> Result<u64, OracleError> {
        match self.settlement {
            OracleSettlement::Claimed {
                claimant: expected,
                generation,
            }
            | OracleSettlement::ApplyIntentDurable {
                claimant: expected,
                generation,
            }
            | OracleSettlement::AppliedUnacknowledged {
                claimant: expected,
                generation,
            } if expected == claimant => Ok(generation),
            _ => Err(OracleError::StaleClaim),
        }
    }
}

/// Authority state of one estate, kept separate from its surviving obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleAuthorityState {
    /// The current principal may still perform new effect actions.
    Active,
    /// Principal authority is gone and the kernel estate owns recovery.
    Fenced,
    /// Revocation permanently closed principal and successor authority.
    Revoked,
}

/// Commit class of the bounded authority/recovery oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleCommitState {
    /// The effect has not crossed its external commit point and may be adopted.
    Precommit,
    /// The effect crossed commit and only its settlement obligation may be claimed.
    Postcommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OracleRootState {
    Live,
    Fenced,
}

/// Exact observation used by `BeginRevoke`.
///
/// The production command binds the currently live incarnation, root binding,
/// and estate authority epoch. Keeping all three coordinates in this oracle
/// makes an observation stale if adoption or another recovery transition wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityObservation {
    incarnation: u64,
    binding_generation: u64,
    authority_epoch: u64,
}

impl AuthorityObservation {
    /// Returns the observed live incarnation generation.
    #[must_use]
    pub const fn incarnation(self) -> u64 {
        self.incarnation
    }

    /// Returns the observed root binding generation.
    #[must_use]
    pub const fn binding_generation(self) -> u64 {
        self.binding_generation
    }

    /// Returns the observed estate authority epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    /// Substitutes the incarnation for negative testing.
    #[must_use]
    pub const fn with_incarnation(mut self, incarnation: u64) -> Self {
        self.incarnation = incarnation;
        self
    }

    /// Substitutes the binding generation for negative testing.
    #[must_use]
    pub const fn with_binding_generation(mut self, binding_generation: u64) -> Self {
        self.binding_generation = binding_generation;
        self
    }

    /// Substitutes the authority epoch for negative testing.
    #[must_use]
    pub const fn with_authority_epoch(mut self, authority_epoch: u64) -> Self {
        self.authority_epoch = authority_epoch;
        self
    }
}

/// Exact one-shot settlement bearer returned to a successor.
///
/// The generation and nonce distinguish a stale claimant after any later
/// crash, even if a caller retains a copy for negative testing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleSettlementClaim {
    claimant: u64,
    generation: u64,
    nonce: u64,
}

impl OracleSettlementClaim {
    /// Returns the claimant incarnation generation.
    #[must_use]
    pub const fn claimant(self) -> u64 {
        self.claimant
    }

    /// Returns the settlement generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the claim nonce.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Substitutes the claimant for negative testing.
    #[must_use]
    pub const fn with_claimant(mut self, claimant: u64) -> Self {
        self.claimant = claimant;
        self
    }

    /// Substitutes the settlement generation for negative testing.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Substitutes the nonce for negative testing.
    #[must_use]
    pub const fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
}

/// Stable projection of the bounded authority, crash, and settlement oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstateOracleProjection {
    /// Whether this estate is precommit or postcommit.
    pub commit: OracleCommitState,
    /// Current estate authority, independent of obligation liveness.
    pub authority: OracleAuthorityState,
    /// Monotonic authority epoch.
    pub authority_epoch: u64,
    /// Current live incarnation, or `None` between fence and rebind.
    pub live_incarnation: Option<u64>,
    /// Last installed root binding generation.
    pub binding_generation: u64,
    /// Number of accepted incarnation fences.
    pub crash_generation: u64,
    /// Postcommit settlement state; absent for a precommit estate.
    pub settlement: Option<OracleSettlement>,
    /// Number of durable external apply intents.
    pub apply_intents: u64,
    /// Number of verified external applies.
    pub external_applies: u64,
    /// Number of terminal settlement acknowledgements.
    pub settlements: u64,
    /// Number of successful state-changing commands.
    pub revision: u64,
}

/// Independent bounded oracle for the production authority/recovery command path.
///
/// This model keeps root liveness, estate authority, and settlement obligation
/// separate. A crash fences authority immediately. A precommit orphan may be
/// explicitly adopted, while a postcommit estate can never return to `Active`
/// after a fence: a successor receives only a settlement claim. `BeginRevoke`
/// races both paths at the exact observed authority epoch, and a later crash
/// invalidates every old settlement bearer without losing durable intent or
/// apply knowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstateOracle {
    commit: OracleCommitState,
    authority: OracleAuthorityState,
    authority_epoch: u64,
    root_state: OracleRootState,
    live_incarnation: Option<u64>,
    last_incarnation: u64,
    binding_generation: u64,
    crash_generation: u64,
    settlement: Option<SettlementOracle>,
    active_claim_nonce: Option<u64>,
    next_claim_nonce: u64,
    apply_intents: u64,
    external_applies: u64,
    settlements: u64,
    revision: u64,
}

impl EstateOracle {
    /// Creates a live uncommitted estate under one non-zero incarnation/binding.
    #[must_use]
    pub const fn precommit(incarnation: u64, binding_generation: u64) -> Self {
        assert!(incarnation != 0, "incarnation must be non-zero");
        assert!(
            binding_generation != 0,
            "binding generation must be non-zero"
        );
        Self::new(
            OracleCommitState::Precommit,
            incarnation,
            binding_generation,
        )
    }

    /// Creates a live committed estate with one open settlement obligation.
    #[must_use]
    pub const fn postcommit(incarnation: u64, binding_generation: u64) -> Self {
        assert!(incarnation != 0, "incarnation must be non-zero");
        assert!(
            binding_generation != 0,
            "binding generation must be non-zero"
        );
        Self::new(
            OracleCommitState::Postcommit,
            incarnation,
            binding_generation,
        )
    }

    const fn new(commit: OracleCommitState, incarnation: u64, binding_generation: u64) -> Self {
        Self {
            commit,
            authority: OracleAuthorityState::Active,
            authority_epoch: 1,
            root_state: OracleRootState::Live,
            live_incarnation: Some(incarnation),
            last_incarnation: incarnation,
            binding_generation,
            crash_generation: 0,
            settlement: match commit {
                OracleCommitState::Precommit => None,
                OracleCommitState::Postcommit => Some(SettlementOracle::open(1)),
            },
            active_claim_nonce: None,
            next_claim_nonce: 1,
            apply_intents: 0,
            external_applies: 0,
            settlements: 0,
            revision: 0,
        }
    }

    /// Returns the complete stable projection used by race assertions.
    #[must_use]
    pub const fn projection(self) -> EstateOracleProjection {
        EstateOracleProjection {
            commit: self.commit,
            authority: self.authority,
            authority_epoch: self.authority_epoch,
            live_incarnation: self.live_incarnation,
            binding_generation: self.binding_generation,
            crash_generation: self.crash_generation,
            settlement: match self.settlement {
                Some(settlement) => Some(settlement.projection()),
                None => None,
            },
            apply_intents: self.apply_intents,
            external_applies: self.external_applies,
            settlements: self.settlements,
            revision: self.revision,
        }
    }

    /// Captures the exact live coordinates consumed by `begin_revoke`.
    pub fn observe_authority(&self) -> Result<AuthorityObservation, OracleError> {
        if self.root_state != OracleRootState::Live {
            return Err(OracleError::WrongRecoveryState);
        }
        Ok(AuthorityObservation {
            incarnation: self
                .live_incarnation
                .ok_or(OracleError::WrongRecoveryState)?,
            binding_generation: self.binding_generation,
            authority_epoch: self.authority_epoch,
        })
    }

    /// Fences one exact live incarnation and preserves its estate.
    ///
    /// For postcommit work this also reclaims an outstanding settlement claim.
    /// A durable intent becomes reconciliation-required; a fresh claim simply
    /// reopens at the next generation.
    pub fn fence_incarnation(
        &mut self,
        crashed: u64,
        binding_generation: u64,
    ) -> Result<(), OracleError> {
        self.require_live(crashed, binding_generation)?;
        self.root_state = OracleRootState::Fenced;
        self.live_incarnation = None;
        self.crash_generation = next_generation(self.crash_generation);
        if self.authority == OracleAuthorityState::Active {
            self.authority_epoch = next_generation(self.authority_epoch);
            self.authority = OracleAuthorityState::Fenced;
        }
        if let Some(settlement) = self.settlement.as_mut() {
            settlement.crash();
        }
        self.active_claim_nonce = None;
        self.bump_revision();
        Ok(())
    }

    /// Installs a fresh root incarnation after an already-validated recovery
    /// snapshot and Ready transition.
    ///
    /// Snapshot identity is outside this small oracle; the method models the
    /// production `Rebind` postcondition and enforces monotonic coordinates.
    pub fn rebind(&mut self, successor: u64, binding_generation: u64) -> Result<(), OracleError> {
        if self.root_state != OracleRootState::Fenced {
            return Err(OracleError::WrongRecoveryState);
        }
        if successor == 0
            || successor <= self.last_incarnation
            || binding_generation <= self.binding_generation
        {
            return Err(OracleError::StaleIncarnation);
        }
        self.root_state = OracleRootState::Live;
        self.live_incarnation = Some(successor);
        self.last_incarnation = successor;
        self.binding_generation = binding_generation;
        self.bump_revision();
        Ok(())
    }

    /// Explicitly adopts one precommit orphan into the rebound incarnation.
    ///
    /// Postcommit estates reject this path: their authority remains fenced and
    /// only `claim_settlement` can transfer an obligation to a successor.
    pub fn adopt_effect(
        &mut self,
        successor: u64,
        binding_generation: u64,
    ) -> Result<(), OracleError> {
        self.require_live(successor, binding_generation)?;
        if self.authority == OracleAuthorityState::Revoked {
            return Err(OracleError::GateClosed);
        }
        if self.commit != OracleCommitState::Precommit
            || self.authority != OracleAuthorityState::Fenced
        {
            return Err(OracleError::WrongCommitState);
        }
        self.authority_epoch = next_generation(self.authority_epoch);
        self.authority = OracleAuthorityState::Active;
        self.bump_revision();
        Ok(())
    }

    /// Claims one postcommit settlement obligation for the exact live successor.
    pub fn claim_settlement(
        &mut self,
        claimant: u64,
    ) -> Result<OracleSettlementClaim, OracleError> {
        self.require_live(claimant, self.binding_generation)?;
        if self.authority == OracleAuthorityState::Revoked {
            return Err(OracleError::GateClosed);
        }
        if self.commit != OracleCommitState::Postcommit
            || !matches!(
                self.authority,
                OracleAuthorityState::Active | OracleAuthorityState::Fenced
            )
        {
            return Err(OracleError::WrongCommitState);
        }
        let settlement = self
            .settlement
            .as_mut()
            .ok_or(OracleError::WrongSettlementStage)?;
        let generation = match settlement.projection() {
            OracleSettlement::Open { generation }
            | OracleSettlement::ReconciliationRequired { generation, .. } => generation,
            OracleSettlement::Claimed { .. }
            | OracleSettlement::ApplyIntentDurable { .. }
            | OracleSettlement::AppliedUnacknowledged { .. } => {
                return Err(OracleError::GateClaimed);
            }
            OracleSettlement::Settled | OracleSettlement::Revoked => {
                return Err(OracleError::GateClosed);
            }
        };
        settlement.claim(claimant)?;
        let nonce = self.next_claim_nonce;
        self.next_claim_nonce = next_generation(self.next_claim_nonce);
        self.active_claim_nonce = Some(nonce);
        self.bump_revision();
        Ok(OracleSettlementClaim {
            claimant,
            generation,
            nonce,
        })
    }

    /// Records the first and only durable external apply intent.
    pub fn record_apply_intent(&mut self, claim: OracleSettlementClaim) -> Result<(), OracleError> {
        self.require_claim(claim)?;
        if self.apply_intents != 0 {
            return Err(OracleError::WrongSettlementStage);
        }
        self.settlement
            .as_mut()
            .ok_or(OracleError::WrongSettlementStage)?
            .record_apply_intent(claim.claimant)?;
        self.apply_intents = 1;
        self.bump_revision();
        Ok(())
    }

    /// Records verified evidence that the external apply happened once.
    pub fn record_applied(&mut self, claim: OracleSettlementClaim) -> Result<(), OracleError> {
        self.require_claim(claim)?;
        if self.external_applies != 0 {
            return Err(OracleError::WrongSettlementStage);
        }
        self.settlement
            .as_mut()
            .ok_or(OracleError::WrongSettlementStage)?
            .record_applied(claim.claimant)?;
        self.external_applies = 1;
        self.bump_revision();
        Ok(())
    }

    /// Acknowledges terminal settlement exactly once.
    pub fn settle(&mut self, claim: OracleSettlementClaim) -> Result<(), OracleError> {
        self.require_claim(claim)?;
        if self.settlements != 0 {
            return Err(OracleError::GateClosed);
        }
        self.settlement
            .as_mut()
            .ok_or(OracleError::WrongSettlementStage)?
            .settle(claim.claimant)?;
        self.active_claim_nonce = None;
        self.settlements = 1;
        self.bump_revision();
        Ok(())
    }

    /// Races revocation against precommit adoption or postcommit settlement.
    ///
    /// A committed revoke closes only successor authority. The settlement value
    /// remains live in kernel custody, matching the production rule that process
    /// death or revocation cannot erase an already-created obligation.
    pub fn begin_revoke(&mut self, observation: AuthorityObservation) -> Result<(), OracleError> {
        self.require_live(observation.incarnation, observation.binding_generation)?;
        if observation.authority_epoch != self.authority_epoch {
            return Err(OracleError::StaleAuthorityEpoch);
        }
        if self.authority == OracleAuthorityState::Revoked {
            return Err(OracleError::GateClosed);
        }
        if self.commit == OracleCommitState::Postcommit {
            match self
                .settlement
                .ok_or(OracleError::WrongSettlementStage)?
                .projection()
            {
                OracleSettlement::Open { .. } | OracleSettlement::ReconciliationRequired { .. } => {
                }
                OracleSettlement::Claimed { .. }
                | OracleSettlement::ApplyIntentDurable { .. }
                | OracleSettlement::AppliedUnacknowledged { .. } => {
                    return Err(OracleError::GateClaimed);
                }
                OracleSettlement::Settled | OracleSettlement::Revoked => {
                    return Err(OracleError::GateClosed);
                }
            }
        }
        self.authority_epoch = next_generation(self.authority_epoch);
        self.authority = OracleAuthorityState::Revoked;
        self.active_claim_nonce = None;
        self.bump_revision();
        Ok(())
    }

    /// Checks the bounded conservation and authority/obligation separation rules.
    #[must_use]
    pub fn check_invariants(&self) -> bool {
        if self.authority_epoch == 0
            || self.last_incarnation == 0
            || self.binding_generation == 0
            || self.next_claim_nonce == 0
            || self.apply_intents > 1
            || self.external_applies > 1
            || self.settlements > 1
            || self.external_applies > self.apply_intents
        {
            return false;
        }
        if (self.root_state == OracleRootState::Live) != self.live_incarnation.is_some() {
            return false;
        }
        if self.authority == OracleAuthorityState::Fenced && self.crash_generation == 0 {
            return false;
        }
        match (self.commit, self.settlement) {
            (OracleCommitState::Precommit, None) => {
                self.active_claim_nonce.is_none()
                    && self.apply_intents == 0
                    && self.external_applies == 0
                    && self.settlements == 0
            }
            (OracleCommitState::Postcommit, Some(settlement)) => {
                if self.crash_generation != 0 && self.authority == OracleAuthorityState::Active {
                    return false;
                }
                let has_claim = matches!(
                    settlement.projection(),
                    OracleSettlement::Claimed { .. }
                        | OracleSettlement::ApplyIntentDurable { .. }
                        | OracleSettlement::AppliedUnacknowledged { .. }
                );
                has_claim == self.active_claim_nonce.is_some()
                    && (settlement.projection() == OracleSettlement::Settled)
                        == (self.settlements == 1)
            }
            _ => false,
        }
    }

    fn require_live(&self, incarnation: u64, binding_generation: u64) -> Result<(), OracleError> {
        if self.root_state != OracleRootState::Live {
            return Err(OracleError::WrongRecoveryState);
        }
        if self.live_incarnation != Some(incarnation)
            || self.binding_generation != binding_generation
        {
            return Err(OracleError::StaleIncarnation);
        }
        Ok(())
    }

    fn require_claim(&self, claim: OracleSettlementClaim) -> Result<(), OracleError> {
        if self.active_claim_nonce != Some(claim.nonce) {
            return Err(OracleError::StaleClaim);
        }
        match self
            .settlement
            .ok_or(OracleError::WrongSettlementStage)?
            .projection()
        {
            OracleSettlement::Claimed {
                claimant,
                generation,
            }
            | OracleSettlement::ApplyIntentDurable {
                claimant,
                generation,
            }
            | OracleSettlement::AppliedUnacknowledged {
                claimant,
                generation,
            } if claimant == claim.claimant && generation == claim.generation => Ok(()),
            _ => Err(OracleError::StaleClaim),
        }
    }

    fn bump_revision(&mut self) {
        self.revision = next_generation(self.revision);
    }
}

/// Independent freshness and retirement oracle for one device resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceOracle {
    enrolled_generation: u64,
    active_generation: u64,
    reset_observed: bool,
    retained: bool,
}

impl DeviceOracle {
    /// Creates one retained resource under a non-zero device generation.
    #[must_use]
    pub const fn retained(device_generation: u64) -> Self {
        assert!(device_generation != 0, "device generation must be non-zero");
        Self {
            enrolled_generation: device_generation,
            active_generation: device_generation,
            reset_observed: false,
            retained: true,
        }
    }

    /// Returns the active device generation.
    #[must_use]
    pub const fn device_generation(self) -> u64 {
        self.active_generation
    }

    /// Reports whether evidence has not yet retired the resource.
    #[must_use]
    pub const fn is_retained(self) -> bool {
        self.retained
    }

    /// Advances the active device generation monotonically.
    pub fn advance_device(&mut self, generation: u64) -> Result<(), OracleError> {
        if generation <= self.active_generation {
            return Err(OracleError::FreshnessRollback);
        }
        self.active_generation = generation;
        Ok(())
    }

    /// Accepts reset evidence for the exact enrolled generation only after the
    /// verifier observes a strictly newer active device generation.
    pub fn submit_reset(
        &mut self,
        subject_generation: u64,
        observation_generation: u64,
    ) -> Result<(), OracleError> {
        if !self.retained {
            return Err(OracleError::AlreadyRetired);
        }
        if subject_generation != self.enrolled_generation
            || observation_generation != self.active_generation
            || observation_generation <= subject_generation
        {
            return Err(OracleError::StaleEvidence);
        }
        self.reset_observed = true;
        Ok(())
    }

    /// Accepts IOTLB/IRQ drain evidence for the exact old generation only
    /// after the matching reset prerequisite.
    pub fn submit_after_reset(
        &mut self,
        subject_generation: u64,
        observation_generation: u64,
    ) -> Result<(), OracleError> {
        if !self.retained {
            return Err(OracleError::AlreadyRetired);
        }
        if !self.reset_observed {
            return Err(OracleError::EvidenceOutOfOrder);
        }
        if subject_generation != self.enrolled_generation
            || observation_generation != self.active_generation
            || observation_generation <= subject_generation
        {
            return Err(OracleError::StaleEvidence);
        }
        self.retained = false;
        Ok(())
    }
}

const fn next_generation(generation: u64) -> u64 {
    match generation.checked_add(1) {
        Some(next) => next,
        None => panic!("bounded oracle generation exhausted"),
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceOracle, OracleError, OracleSettlement, SettlementOracle};

    #[test]
    fn reconciliation_claim_crash_preserves_prior_intent() {
        let mut oracle = SettlementOracle::open(1);
        oracle.claim(2).unwrap();
        oracle.record_apply_intent(2).unwrap();
        oracle.crash();
        oracle.claim(3).unwrap();
        oracle.crash();
        assert_eq!(
            oracle.projection(),
            OracleSettlement::ReconciliationRequired {
                generation: 3,
                applied: false,
            }
        );
    }

    #[test]
    fn reconciliation_claim_crash_preserves_prior_apply() {
        let mut oracle = SettlementOracle::open(1);
        oracle.claim(2).unwrap();
        oracle.record_apply_intent(2).unwrap();
        oracle.record_applied(2).unwrap();
        oracle.crash();
        oracle.claim(3).unwrap();
        oracle.crash();
        assert_eq!(
            oracle.projection(),
            OracleSettlement::ReconciliationRequired {
                generation: 3,
                applied: true,
            }
        );
    }

    #[test]
    fn device_retirement_binds_old_subject_new_observation_and_order() {
        let mut oracle = DeviceOracle::retained(1);
        assert_eq!(oracle.submit_reset(1, 1), Err(OracleError::StaleEvidence));
        oracle.advance_device(2).unwrap();
        assert_eq!(
            oracle.submit_after_reset(1, 2),
            Err(OracleError::EvidenceOutOfOrder)
        );
        assert_eq!(oracle.submit_reset(2, 2), Err(OracleError::StaleEvidence));
        oracle.submit_reset(1, 2).unwrap();
        oracle.submit_after_reset(1, 2).unwrap();
        assert!(!oracle.is_retained());
    }
}
