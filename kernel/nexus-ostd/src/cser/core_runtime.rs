// SPDX-License-Identifier: MPL-2.0

//! Production OSTD ownership boundary for the portable CSER core.
//!
//! This module owns no global instance. The production bootstrap constructs one
//! recovered owner and shares it with every ingress adapter that may mutate the
//! engine.
//!
//! Transactions hold an OSTD sleepable [`Mutex`] across the journal append and
//! durability barrier required by [`Engine::transact_durable`].  Consequently callers
//! must enter through a manager/task context which may block.  IRQ handlers,
//! atomic callbacks, and code already holding a spin lock may only enqueue work
//! for that owner; they must never call [`OstdCserRuntime::transact`] directly.

use cser_core::{
    Command, CoreError, CoreLimits, Digest, DomainCatalog, Engine, JournalRepair, RecoveryAnchor,
    TransitionDurability, TransitionReceipt, TxError,
};
use ostd::{prelude::*, sync::Mutex};

/// Exact replay boundary returned before a recovered runtime becomes eligible
/// for later publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OstdRecoveryBoundary {
    acknowledged_revision: u64,
    acknowledged_head: Digest,
    journal_repair: Option<JournalRepair>,
}

impl OstdRecoveryBoundary {
    /// Returns the last replayed journal revision.
    pub(crate) const fn acknowledged_revision(self) -> u64 {
        self.acknowledged_revision
    }

    /// Returns the exact replayed journal head.
    pub(crate) const fn acknowledged_head(self) -> Digest {
        self.acknowledged_head
    }

    /// Returns the first incomplete-tail byte, if recovery found one.
    ///
    /// The core keeps such an engine recovery-blocked until storage repairs the
    /// tail and recovery is run again.
    pub(crate) const fn torn_tail(self) -> Option<usize> {
        match self.journal_repair {
            Some(JournalRepair::TornTail { offset }) => Some(offset),
            Some(JournalRepair::UnanchoredSuffix { .. }) | None => None,
        }
    }

    /// Returns the exact suffix repair required before activation.
    pub(crate) const fn journal_repair(self) -> Option<JournalRepair> {
        self.journal_repair
    }
}

#[derive(Debug)]
struct RuntimeState<P> {
    engine: Engine,
    persistence: P,
}

/// Single-writer OSTD owner of one portable CSER engine and its journal.
///
/// Construction alone does not publish the runtime. Production bootstrap must
/// install exactly one recovered instance before opening ingress.
#[derive(Debug)]
pub(crate) struct OstdCserRuntime<P> {
    state: Mutex<RuntimeState<P>>,
}

impl<P> OstdCserRuntime<P> {
    /// Wraps an already-created engine and its transition durability provider
    /// without activating any kernel ingress.
    ///
    /// Reply and DMA adapters must share this owner after the production
    /// cutover. Domain-specific physical custody lives outside the core, while
    /// every semantic transition and durability decision is serialized here.
    pub(crate) const fn from_engine(engine: Engine, persistence: P) -> Self {
        Self {
            state: Mutex::new(RuntimeState {
                engine,
                persistence,
            }),
        }
    }

    /// Replays a journal under a mandatory trusted anchor.
    ///
    /// The caller retains responsibility for obtaining `bytes` and the anchor
    /// from independent persistent providers.  A returned torn-tail boundary
    /// is not permission to publish the runtime.
    pub(crate) fn recover(
        catalog: DomainCatalog,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
        persistence: P,
    ) -> Result<(Self, OstdRecoveryBoundary), CoreError> {
        let report = Engine::recover(catalog, limits, anchor, bytes)?;
        let boundary = OstdRecoveryBoundary {
            acknowledged_revision: report.acknowledged_revision(),
            acknowledged_head: report.acknowledged_head(),
            journal_repair: report.journal_repair(),
        };
        Ok((
            Self::from_engine(report.into_engine(), persistence),
            boundary,
        ))
    }

    /// Runs a read-only operation under the authoritative writer lock.
    pub(crate) fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        let state = self.state.lock();
        operation(&state.engine)
    }

    /// Runs a read-only durability-provider observation under the same owner
    /// lock as the engine.
    ///
    /// This is for diagnostics and provider lifecycle checks only. It cannot
    /// append journal bytes or advance a trusted anchor.
    pub(crate) fn observe_persistence<R>(&self, operation: impl FnOnce(&P) -> R) -> R {
        let state = self.state.lock();
        operation(&state.persistence)
    }
}

impl<P: TransitionDurability> OstdCserRuntime<P> {
    /// Executes one core transition and its exact durable append/barrier.
    ///
    /// This method may block and therefore is manager/task-context only.  A
    /// persistence failure leaves the engine recovery-required exactly as
    /// specified by `cser-core`.
    pub(crate) fn transact<C>(&self, command: C) -> Result<TransitionReceipt, TxError<P::Error>>
    where
        C: Into<Command>,
    {
        let mut state = self.state.lock();
        let RuntimeState {
            engine,
            persistence,
        } = &mut *state;
        engine.transact_durable(command, persistence)
    }
}
