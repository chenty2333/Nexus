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
