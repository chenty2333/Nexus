use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{
    BindingToken, Budget, BudgetDisposition, EffectId, EffectState, EffectView, InvariantViolation,
    ModelError, RevocationProgress, RevocationStep, ScopeId, ScopeState, ScopeView, SupervisorId,
    TraceAction, TraceEvent, TraceOutcome,
};

#[derive(Clone, Debug)]
struct ScopeRecord {
    state: ScopeState,
    epoch: u64,
    binding_epoch: u64,
    supervisor: Option<SupervisorId>,
    initial_budget: Budget,
    free_budget: Budget,
    spent_budget: Budget,
    live_effects: BTreeSet<EffectId>,
    revocation: Option<RevocationRecord>,
    fallback_pending: bool,
    fallback_selected: bool,
}

#[derive(Clone, Copy, Debug)]
struct RevocationRecord {
    closed_epoch: u64,
    target_count: usize,
    steps: usize,
}

#[derive(Clone, Copy, Debug)]
struct EffectRecord {
    scope: ScopeId,
    scope_epoch: u64,
    binding_epoch: u64,
    state: EffectState,
    budget: Budget,
    budget_disposition: BudgetDisposition,
    terminalizations: u8,
}

/// Deterministic executable state machine for CSER protocol exploration.
///
/// The model is single-threaded on purpose. Concurrency is represented by
/// choosing different valid action orders, which makes race witnesses stable
/// and permits direct comparison with a finite-state specification.
#[derive(Clone, Debug)]
pub struct Model {
    next_scope: u64,
    next_effect: u64,
    scopes: BTreeMap<ScopeId, ScopeRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
    trace: Vec<TraceEvent>,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// Creates an empty reference model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_effect: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates an active authority scope and its initial supervisor binding.
    pub fn create_scope(
        &mut self,
        supervisor: SupervisorId,
        budget: Budget,
    ) -> Result<(ScopeId, BindingToken), ModelError> {
        let scope = self.take_scope_id()?;
        let binding_epoch = 1;
        self.scopes.insert(
            scope,
            ScopeRecord {
                state: ScopeState::Active,
                epoch: 1,
                binding_epoch,
                supervisor: Some(supervisor),
                initial_budget: budget,
                free_budget: budget,
                spent_budget: Budget::ZERO,
                live_effects: BTreeSet::new(),
                revocation: None,
                fallback_pending: false,
                fallback_selected: false,
            },
        );
        self.push_trace(
            TraceAction::CreateScope,
            scope,
            None,
            1,
            binding_epoch,
            None,
            None,
            TraceOutcome::SupervisorBound(supervisor),
        );
        Ok((scope, BindingToken::new(scope, supervisor, binding_epoch)))
    }

    /// Registers an effect, atomically splitting credits from the scope's free
    /// budget into an exclusive held grant.
    pub fn register(
        &mut self,
        binding: BindingToken,
        budget: Budget,
    ) -> Result<EffectId, ModelError> {
        if budget == Budget::ZERO {
            return Err(ModelError::ZeroBudget);
        }

        let (scope_epoch, binding_epoch, available) = {
            let scope = self.validate_active_binding(binding)?;
            (scope.epoch, scope.binding_epoch, scope.free_budget)
        };
        if available.units() < budget.units() {
            return Err(ModelError::BudgetExhausted {
                requested: budget,
                available,
            });
        }

        let effect = self.take_effect_id()?;
        let free_after = available
            .units()
            .checked_sub(budget.units())
            .ok_or(ModelError::InvariantViolation("budget underflow"))?;
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(ModelError::UnknownScope(binding.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_effects.insert(effect);
        self.effects.insert(
            effect,
            EffectRecord {
                scope: binding.scope,
                scope_epoch,
                binding_epoch,
                state: EffectState::Registered,
                budget,
                budget_disposition: BudgetDisposition::Held,
                terminalizations: 0,
            },
        );
        self.push_trace(
            TraceAction::Register,
            binding.scope,
            Some(effect),
            scope_epoch,
            binding_epoch,
            None,
            Some(EffectState::Registered),
            TraceOutcome::BudgetHeld(budget),
        );
        Ok(effect)
    }

    /// Moves a registered effect to the prepared state.
    pub fn prepare(&mut self, binding: BindingToken, effect: EffectId) -> Result<(), ModelError> {
        let (scope_epoch, binding_epoch, state) = {
            let (scope, effect_record) = self.validate_effect_authority(binding, effect)?;
            (scope.epoch, scope.binding_epoch, effect_record.state)
        };
        if state != EffectState::Registered {
            return Err(ModelError::InvalidEffectState { state });
        }

        self.effects
            .get_mut(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?
            .state = EffectState::Prepared;
        self.push_trace(
            TraceAction::Prepare,
            binding.scope,
            Some(effect),
            scope_epoch,
            binding_epoch,
            Some(EffectState::Registered),
            Some(EffectState::Prepared),
            TraceOutcome::Applied,
        );
        Ok(())
    }

    /// Linearizes an externally visible effect.
    ///
    /// This is the only transition that changes a held grant into spent
    /// credits. It requires an active scope, a live supervisor, matching
    /// authority and binding epochs, and the `Prepared` state.
    pub fn commit(&mut self, binding: BindingToken, effect: EffectId) -> Result<(), ModelError> {
        let (scope_epoch, binding_epoch, state, budget, disposition, spent) = {
            let (scope, effect_record) = self.validate_effect_authority(binding, effect)?;
            (
                scope.epoch,
                scope.binding_epoch,
                effect_record.state,
                effect_record.budget,
                effect_record.budget_disposition,
                scope.spent_budget,
            )
        };
        if state != EffectState::Prepared {
            return Err(if state.is_terminal() {
                ModelError::AlreadyTerminal
            } else {
                ModelError::InvalidEffectState { state }
            });
        }
        if disposition != BudgetDisposition::Held {
            return Err(ModelError::InvariantViolation(
                "prepared effect does not hold its budget",
            ));
        }
        let spent_after = spent
            .units()
            .checked_add(budget.units())
            .ok_or(ModelError::CounterOverflow)?;

        let effect_record = self
            .effects
            .get_mut(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        effect_record.state = EffectState::Committed;
        effect_record.budget_disposition = BudgetDisposition::Spent;
        self.scopes
            .get_mut(&binding.scope)
            .ok_or(ModelError::UnknownScope(binding.scope))?
            .spent_budget = Budget::new(spent_after);
        self.push_trace(
            TraceAction::Commit,
            binding.scope,
            Some(effect),
            scope_epoch,
            binding_epoch,
            Some(EffectState::Prepared),
            Some(EffectState::Committed),
            TraceOutcome::BudgetSpent(budget),
        );
        Ok(())
    }

    /// Completes a committed effect or an effect already being drained.
    ///
    /// Completion is a trusted device/kernel event rather than a supervisor
    /// reply, so it does not require a binding token. It cannot retroactively
    /// turn an uncommitted effect into a committed one.
    pub fn complete(&mut self, effect: EffectId) -> Result<(), ModelError> {
        let record = *self
            .effects
            .get(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        if record.state.is_terminal() {
            return Err(ModelError::AlreadyTerminal);
        }
        if !matches!(record.state, EffectState::Committed | EffectState::Draining) {
            return Err(ModelError::InvalidEffectState {
                state: record.state,
            });
        }
        if record.budget_disposition != BudgetDisposition::Spent {
            return Err(ModelError::InvariantViolation(
                "committed effect does not have spent budget",
            ));
        }
        self.ensure_live_index(record.scope, effect)?;

        let terminalizations = record
            .terminalizations
            .checked_add(1)
            .ok_or(ModelError::CounterOverflow)?;
        let effect_record = self
            .effects
            .get_mut(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        effect_record.state = EffectState::Completed;
        effect_record.terminalizations = terminalizations;
        let (authority_epoch, binding_epoch) = {
            let scope = self
                .scopes
                .get_mut(&record.scope)
                .ok_or(ModelError::UnknownScope(record.scope))?;
            scope.live_effects.remove(&effect);
            (scope.epoch, scope.binding_epoch)
        };
        self.push_trace(
            TraceAction::Complete,
            record.scope,
            Some(effect),
            authority_epoch,
            binding_epoch,
            Some(record.state),
            Some(EffectState::Completed),
            TraceOutcome::Applied,
        );
        Ok(())
    }

    /// Linearizes revocation by closing the scope, advancing its authority
    /// epoch, and freezing the target count in its reverse index.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), ModelError> {
        let (closed_epoch, new_epoch, binding_epoch, target_count) = {
            let record = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if record.state != ScopeState::Active {
                return Err(ModelError::InvalidScopeState {
                    state: record.state,
                });
            }
            (
                record.epoch,
                record
                    .epoch
                    .checked_add(1)
                    .ok_or(ModelError::CounterOverflow)?,
                record.binding_epoch,
                record.live_effects.len(),
            )
        };

        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(ModelError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.epoch = new_epoch;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            steps: 0,
        });
        self.push_trace(
            TraceAction::RevokeBegin,
            scope,
            None,
            new_epoch,
            binding_epoch,
            None,
            None,
            TraceOutcome::RevocationStarted {
                closed_epoch,
                target_count,
            },
        );
        Ok(())
    }

    /// Performs one deterministic unit of cancellation or drainage work.
    ///
    /// Each initially live effect needs at most two calls: one to enter
    /// `Cancelling`/`Draining`, and one to reach `Aborted`/`Completed`.
    pub fn revoke_step(&mut self, scope: ScopeId) -> Result<Option<RevocationStep>, ModelError> {
        let (effect, authority_epoch, binding_epoch, closed_epoch) = {
            let record = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if record.state != ScopeState::Closing {
                return Err(ModelError::InvalidScopeState {
                    state: record.state,
                });
            }
            let revocation = record.revocation.ok_or(ModelError::InvariantViolation(
                "closing scope lacks revocation metadata",
            ))?;
            let Some(effect) = record.live_effects.first().copied() else {
                return Ok(None);
            };
            (
                effect,
                record.epoch,
                record.binding_epoch,
                revocation.closed_epoch,
            )
        };
        let effect_record = *self
            .effects
            .get(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        if effect_record.scope != scope || effect_record.scope_epoch != closed_epoch {
            return Err(ModelError::InvariantViolation(
                "reverse index contains an effect outside the closed epoch",
            ));
        }

        let from = effect_record.state;
        let (to, disposition, terminalized, outcome) = match from {
            EffectState::Registered | EffectState::Prepared => (
                EffectState::Cancelling,
                BudgetDisposition::Held,
                false,
                TraceOutcome::Applied,
            ),
            EffectState::Cancelling => (
                EffectState::Aborted,
                BudgetDisposition::Returned,
                true,
                TraceOutcome::BudgetReturned(effect_record.budget),
            ),
            EffectState::Committed => (
                EffectState::Draining,
                BudgetDisposition::Spent,
                false,
                TraceOutcome::Applied,
            ),
            EffectState::Draining => (
                EffectState::Completed,
                BudgetDisposition::Spent,
                true,
                TraceOutcome::Applied,
            ),
            EffectState::Completed | EffectState::Aborted => {
                return Err(ModelError::InvariantViolation(
                    "terminal effect remained in reverse index",
                ));
            }
        };

        let returned_free = if to == EffectState::Aborted {
            if effect_record.budget_disposition != BudgetDisposition::Held {
                return Err(ModelError::InvariantViolation(
                    "cancelled effect did not hold its budget",
                ));
            }
            let current_free = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?
                .free_budget;
            Some(
                current_free
                    .units()
                    .checked_add(effect_record.budget.units())
                    .ok_or(ModelError::CounterOverflow)?,
            )
        } else {
            None
        };
        let terminalizations = if terminalized {
            effect_record
                .terminalizations
                .checked_add(1)
                .ok_or(ModelError::CounterOverflow)?
        } else {
            effect_record.terminalizations
        };

        let effect_mut = self
            .effects
            .get_mut(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        effect_mut.state = to;
        effect_mut.budget_disposition = disposition;
        effect_mut.terminalizations = terminalizations;
        {
            let scope_mut = self
                .scopes
                .get_mut(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if let Some(free) = returned_free {
                scope_mut.free_budget = Budget::new(free);
            }
            if terminalized {
                scope_mut.live_effects.remove(&effect);
            }
            let revocation =
                scope_mut
                    .revocation
                    .as_mut()
                    .ok_or(ModelError::InvariantViolation(
                        "closing scope lacks revocation metadata",
                    ))?;
            revocation.steps = revocation
                .steps
                .checked_add(1)
                .ok_or(ModelError::CounterOverflow)?;
        }
        self.push_trace(
            TraceAction::RevokeStep,
            scope,
            Some(effect),
            authority_epoch,
            binding_epoch,
            Some(from),
            Some(to),
            outcome,
        );
        Ok(Some(RevocationStep {
            effect,
            from,
            to,
            terminalized,
        }))
    }

    /// Publishes quiescent closure after the per-scope reverse index is empty.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), ModelError> {
        let (authority_epoch, binding_epoch, remaining, progress) = {
            let record = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if record.state != ScopeState::Closing {
                return Err(ModelError::InvalidScopeState {
                    state: record.state,
                });
            }
            (
                record.epoch,
                record.binding_epoch,
                record.live_effects.len(),
                record.revocation.ok_or(ModelError::InvariantViolation(
                    "closing scope lacks revocation metadata",
                ))?,
            )
        };
        if remaining != 0 {
            return Err(ModelError::RevocationNotQuiescent { remaining });
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(ModelError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.push_trace(
            TraceAction::RevokeComplete,
            scope,
            None,
            authority_epoch,
            binding_epoch,
            None,
            None,
            TraceOutcome::RevocationFinished {
                target_count: progress.target_count,
                steps: progress.steps,
            },
        );
        Ok(())
    }

    /// Fences a failed supervisor and makes kernel fallback selection pending.
    pub fn crash(&mut self, binding: BindingToken) -> Result<(), ModelError> {
        let (authority_epoch, old_binding_epoch, new_binding_epoch) = {
            let record = self.validate_active_binding(binding)?;
            (
                record.epoch,
                record.binding_epoch,
                record
                    .binding_epoch
                    .checked_add(1)
                    .ok_or(ModelError::CounterOverflow)?,
            )
        };
        let record = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(ModelError::UnknownScope(binding.scope))?;
        record.binding_epoch = new_binding_epoch;
        record.supervisor = None;
        record.fallback_pending = true;
        record.fallback_selected = false;
        self.push_trace(
            TraceAction::Crash,
            binding.scope,
            None,
            authority_epoch,
            new_binding_epoch,
            None,
            None,
            TraceOutcome::BindingAdvanced { old_binding_epoch },
        );
        Ok(())
    }

    /// Selects the kernel fallback while a policy supervisor is unavailable.
    ///
    /// Once selected, fallback remains active until `rebind` linearizes a
    /// replacement supervisor's completed snapshot/ready handshake. Closing
    /// and revoked scopes may finish a pending fallback selection, but cannot
    /// be rebound.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), ModelError> {
        let (authority_epoch, binding_epoch) = {
            let record = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if record.supervisor.is_some() || !record.fallback_pending {
                return Err(ModelError::FallbackUnavailable);
            }
            (record.epoch, record.binding_epoch)
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(ModelError::UnknownScope(scope))?;
        record.fallback_pending = false;
        record.fallback_selected = true;
        self.push_trace(
            TraceAction::FallbackPick,
            scope,
            None,
            authority_epoch,
            binding_epoch,
            None,
            None,
            TraceOutcome::FallbackSelected,
        );
        Ok(())
    }

    /// Installs a replacement supervisor after its snapshot/ready handshake.
    ///
    /// This is the rebind linearization point. It deactivates the kernel
    /// fallback but does not implicitly adopt any orphan effects.
    pub fn rebind(
        &mut self,
        scope: ScopeId,
        supervisor: SupervisorId,
    ) -> Result<BindingToken, ModelError> {
        let (authority_epoch, binding_epoch) = {
            let record = self
                .scopes
                .get(&scope)
                .ok_or(ModelError::UnknownScope(scope))?;
            if record.state != ScopeState::Active {
                return Err(ModelError::InvalidScopeState {
                    state: record.state,
                });
            }
            if record.supervisor.is_some() {
                return Err(ModelError::SupervisorAlreadyBound);
            }
            if !record.fallback_selected {
                return Err(ModelError::FallbackUnavailable);
            }
            (record.epoch, record.binding_epoch)
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(ModelError::UnknownScope(scope))?;
        record.supervisor = Some(supervisor);
        record.fallback_pending = false;
        record.fallback_selected = false;
        self.push_trace(
            TraceAction::Rebind,
            scope,
            None,
            authority_epoch,
            binding_epoch,
            None,
            None,
            TraceOutcome::SupervisorBound(supervisor),
        );
        Ok(BindingToken::new(scope, supervisor, binding_epoch))
    }

    /// Explicitly moves an orphan, uncommitted effect to the current binding.
    pub fn adopt(&mut self, binding: BindingToken, effect: EffectId) -> Result<(), ModelError> {
        let (authority_epoch, binding_epoch, old_binding, state) = {
            let scope = self.validate_active_binding(binding)?;
            let effect_record = self
                .effects
                .get(&effect)
                .ok_or(ModelError::UnknownEffect(effect))?;
            if effect_record.scope != binding.scope {
                return Err(ModelError::EffectScopeMismatch);
            }
            if effect_record.scope_epoch != scope.epoch {
                return Err(ModelError::EpochFenced {
                    effect_epoch: effect_record.scope_epoch,
                    current_epoch: scope.epoch,
                });
            }
            if !matches!(
                effect_record.state,
                EffectState::Registered | EffectState::Prepared
            ) || effect_record.binding_epoch == scope.binding_epoch
            {
                return Err(ModelError::NotAdoptable);
            }
            (
                scope.epoch,
                scope.binding_epoch,
                effect_record.binding_epoch,
                effect_record.state,
            )
        };
        self.effects
            .get_mut(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?
            .binding_epoch = binding_epoch;
        self.push_trace(
            TraceAction::Adopt,
            binding.scope,
            Some(effect),
            authority_epoch,
            binding_epoch,
            Some(state),
            Some(state),
            TraceOutcome::EffectAdopted {
                old_binding_epoch: old_binding,
            },
        );
        Ok(())
    }

    /// Returns a read-only projection of a scope.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<ScopeView> {
        self.scopes.get(&scope).map(|record| ScopeView {
            state: record.state,
            epoch: record.epoch,
            binding_epoch: record.binding_epoch,
            supervisor: record.supervisor,
            initial_budget: record.initial_budget,
            free_budget: record.free_budget,
            spent_budget: record.spent_budget,
            live_effects: record.live_effects.len(),
            revocation: record.revocation.map(|revocation| RevocationProgress {
                closed_epoch: revocation.closed_epoch,
                target_count: revocation.target_count,
                steps: revocation.steps,
                remaining: record.live_effects.len(),
            }),
            fallback_pending: record.fallback_pending,
            fallback_selected: record.fallback_selected,
        })
    }

    /// Returns a read-only projection of an effect.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<EffectView> {
        self.effects.get(&effect).map(|record| EffectView {
            scope: record.scope,
            scope_epoch: record.scope_epoch,
            binding_epoch: record.binding_epoch,
            state: record.state,
            budget: record.budget,
            budget_disposition: record.budget_disposition,
            terminalizations: record.terminalizations,
        })
    }

    /// Returns the current token when a live supervisor is installed.
    #[must_use]
    pub fn current_binding(&self, scope: ScopeId) -> Option<BindingToken> {
        let record = self.scopes.get(&scope)?;
        if record.state != ScopeState::Active {
            return None;
        }
        let supervisor = record.supervisor?;
        Some(BindingToken::new(scope, supervisor, record.binding_epoch))
    }

    /// Returns the deterministic contents of a scope's live reverse index.
    pub fn live_effects(&self, scope: ScopeId) -> Result<Vec<EffectId>, ModelError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(ModelError::UnknownScope(scope))?;
        Ok(record.live_effects.iter().copied().collect())
    }

    /// Returns successful actions in their total linearization order.
    #[must_use]
    pub fn trace(&self) -> &[TraceEvent] {
        &self.trace
    }

    /// Audits conservation, fencing metadata, reverse indexes, and the
    /// single-terminalization/work-bound properties across the full model.
    pub fn check_invariants(&self) -> Result<(), InvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let mut expected_live = BTreeSet::new();
            let mut held = 0u128;
            let mut spent = 0u128;

            for (effect_id, effect) in self
                .effects
                .iter()
                .filter(|(_, effect)| effect.scope == *scope_id)
            {
                if effect.scope_epoch > scope.epoch {
                    return Err(InvariantViolation::FutureEffectEpoch(*effect_id));
                }
                if !effect.state.is_terminal() {
                    expected_live.insert(*effect_id);
                }
                let expected_disposition = match effect.state {
                    EffectState::Registered | EffectState::Prepared | EffectState::Cancelling => {
                        BudgetDisposition::Held
                    }
                    EffectState::Committed | EffectState::Draining | EffectState::Completed => {
                        BudgetDisposition::Spent
                    }
                    EffectState::Aborted => BudgetDisposition::Returned,
                };
                if effect.budget_disposition != expected_disposition {
                    return Err(InvariantViolation::EffectBudgetState(*effect_id));
                }
                match effect.budget_disposition {
                    BudgetDisposition::Held => held += u128::from(effect.budget.units()),
                    BudgetDisposition::Spent => spent += u128::from(effect.budget.units()),
                    BudgetDisposition::Returned => {}
                }
                let expected_terminalizations = u8::from(effect.state.is_terminal());
                if effect.terminalizations != expected_terminalizations {
                    return Err(InvariantViolation::Terminalization(*effect_id));
                }
            }

            if expected_live != scope.live_effects {
                return Err(InvariantViolation::LiveReverseIndex(*scope_id));
            }
            if u128::from(scope.spent_budget.units()) != spent {
                return Err(InvariantViolation::SpentAccounting(*scope_id));
            }
            let accounted = u128::from(scope.free_budget.units()) + held + spent;
            if accounted != u128::from(scope.initial_budget.units()) {
                return Err(InvariantViolation::BudgetConservation(*scope_id));
            }
            match scope.state {
                ScopeState::Active if scope.revocation.is_some() => {
                    return Err(InvariantViolation::RevocationMetadata(*scope_id));
                }
                ScopeState::Closing | ScopeState::Revoked if scope.revocation.is_none() => {
                    return Err(InvariantViolation::RevocationMetadata(*scope_id));
                }
                _ => {}
            }
            if scope.state == ScopeState::Revoked && !scope.live_effects.is_empty() {
                return Err(InvariantViolation::RevokedScopeLive(*scope_id));
            }
            if let Some(revocation) = scope.revocation {
                let bound = revocation.target_count.saturating_mul(2);
                if revocation.steps > bound {
                    return Err(InvariantViolation::RevocationWorkBound(*scope_id));
                }
            }
            let fallback_valid = match scope.supervisor {
                Some(_) => !scope.fallback_pending && !scope.fallback_selected,
                None => scope.fallback_pending ^ scope.fallback_selected,
            };
            if !fallback_valid {
                return Err(InvariantViolation::FallbackState(*scope_id));
            }
        }

        for (effect_id, effect) in &self.effects {
            if !self.scopes.contains_key(&effect.scope) {
                return Err(InvariantViolation::OrphanEffect(*effect_id));
            }
        }
        Ok(())
    }

    fn validate_active_binding(&self, binding: BindingToken) -> Result<&ScopeRecord, ModelError> {
        let scope = self
            .scopes
            .get(&binding.scope)
            .ok_or(ModelError::UnknownScope(binding.scope))?;
        if binding.binding_epoch != scope.binding_epoch {
            return Err(ModelError::StaleBinding {
                presented: binding.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        match scope.supervisor {
            Some(supervisor) if supervisor == binding.supervisor => {}
            Some(_) => return Err(ModelError::WrongSupervisor),
            None => return Err(ModelError::SupervisorUnavailable),
        }
        if scope.state != ScopeState::Active {
            return Err(ModelError::InvalidScopeState { state: scope.state });
        }
        Ok(scope)
    }

    fn validate_effect_authority(
        &self,
        binding: BindingToken,
        effect: EffectId,
    ) -> Result<(&ScopeRecord, &EffectRecord), ModelError> {
        let scope = self.validate_active_binding(binding)?;
        let effect_record = self
            .effects
            .get(&effect)
            .ok_or(ModelError::UnknownEffect(effect))?;
        if effect_record.scope != binding.scope {
            return Err(ModelError::EffectScopeMismatch);
        }
        if effect_record.scope_epoch != scope.epoch {
            return Err(ModelError::EpochFenced {
                effect_epoch: effect_record.scope_epoch,
                current_epoch: scope.epoch,
            });
        }
        if effect_record.binding_epoch != binding.binding_epoch {
            return Err(ModelError::EffectBindingFenced {
                effect_binding: effect_record.binding_epoch,
                current_binding: binding.binding_epoch,
            });
        }
        Ok((scope, effect_record))
    }

    fn ensure_live_index(&self, scope: ScopeId, effect: EffectId) -> Result<(), ModelError> {
        let scope_record = self
            .scopes
            .get(&scope)
            .ok_or(ModelError::UnknownScope(scope))?;
        if !scope_record.live_effects.contains(&effect) {
            return Err(ModelError::InvariantViolation(
                "nonterminal effect missing from reverse index",
            ));
        }
        Ok(())
    }

    fn take_scope_id(&mut self) -> Result<ScopeId, ModelError> {
        let raw = self.next_scope;
        self.next_scope = raw.checked_add(1).ok_or(ModelError::CounterOverflow)?;
        Ok(ScopeId::new(raw))
    }

    fn take_effect_id(&mut self) -> Result<EffectId, ModelError> {
        let raw = self.next_effect;
        self.next_effect = raw.checked_add(1).ok_or(ModelError::CounterOverflow)?;
        Ok(EffectId::new(raw))
    }

    #[allow(clippy::too_many_arguments)]
    fn push_trace(
        &mut self,
        action: TraceAction,
        scope: ScopeId,
        effect: Option<EffectId>,
        authority_epoch: u64,
        binding_epoch: u64,
        from: Option<EffectState>,
        to: Option<EffectState>,
        outcome: TraceOutcome,
    ) {
        self.trace.push(TraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            effect,
            authority_epoch,
            binding_epoch,
            from,
            to,
            outcome,
        });
    }
}
