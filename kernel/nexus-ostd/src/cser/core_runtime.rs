// SPDX-License-Identifier: MPL-2.0

//! Development-only OSTD ownership boundary for the portable CSER core.
//!
//! This module deliberately owns no global instance and is not connected to
//! portal, supervisor, filesystem, IRQ, or device ingress.  It establishes the
//! shape of a future cold cutover without creating a live second writer beside
//! `EffectRegistry`.
//!
//! Transactions hold an OSTD sleepable [`Mutex`] across the journal append and
//! durability barrier required by [`Engine::transact_durable`].  Consequently callers
//! must enter through a manager/task context which may block.  IRQ handlers,
//! atomic callbacks, and code already holding a spin lock may only enqueue work
//! for that owner; they must never call [`OstdCserRuntime::transact`] directly.

use cser_core::{
    BootGeneration, ChargeAccountId, Command, CommandRequest, CoreError, CoreLimits, Digest,
    DomainCatalog, EffectId, Engine, Freshness, JournalGeneration, JournalRecord, JournalRepair,
    PrincipalId, PrincipalIncarnation, REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION, RecoveryAnchor,
    RegistryInstance, RootId, TransitionDurability, TransitionReceipt, TxError, standard_catalog,
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
/// Construction alone does not publish the runtime.  The eventual production
/// cutover must install exactly one recovered instance before opening ingress
/// and must remove the old Registry path in the same change.
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

    /// Executes one explicitly non-durable development transition.
    ///
    /// This exists only in the mutually-exclusive runtime spike so real OSTD
    /// task lifecycle wiring can be exercised before a platform journal
    /// provider exists.  It must not be used by a production ingress or cited
    /// as reboot-persistence evidence.
    pub(crate) fn transact_volatile<C>(&self, command: C) -> Result<TransitionReceipt, CoreError>
    where
        C: Into<Command>,
    {
        let mut state = self.state.lock();
        state.engine.transact_volatile(command)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnavailableJournalError {
    NoDurableProvider,
}

pub(crate) struct UnavailableJournal;

impl TransitionDurability for UnavailableJournal {
    type Error = UnavailableJournalError;

    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
    ) -> Result<(), Self::Error> {
        assert!(!record.bytes().is_empty());
        assert_ne!(resulting_freshness.boot().get(), 0);
        Err(UnavailableJournalError::NoDurableProvider)
    }
}

/// Exercises the mutually-exclusive runtime entry point without fabricating a
/// persistence receipt.
///
/// The compile spike has no OSTD durable-journal provider yet.  Its boot path
/// therefore attempts one real core transaction, requires persistence to fail,
/// and checks that the engine latches recovery-required instead of publishing
/// the candidate estate.
pub(crate) fn run_boot_probe() {
    let root = RootId::new(1).expect("spike root is non-zero");
    let principal = PrincipalId::new(1).expect("spike principal is non-zero");
    let origin = PrincipalIncarnation::new(principal, 1).expect("spike incarnation is non-zero");
    let freshness = Freshness::new(
        BootGeneration::new(1).expect("spike boot is non-zero"),
        RegistryInstance::new(1).expect("spike Registry is non-zero"),
        1,
        cser_core::DeviceGeneration::new(1).expect("spike device generation is non-zero"),
        JournalGeneration::new(1).expect("spike journal is non-zero"),
    )
    .expect("spike freshness is complete");
    let engine = Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness);
    let runtime = OstdCserRuntime::from_engine(engine, UnavailableJournal);
    let command = CommandRequest::CreateEstate {
        effect: EffectId::new(root, 1).expect("spike effect is non-zero"),
        origin,
        binding_generation: 1,
        domain: REPLY_DOMAIN,
        obligation: REPLY_OBLIGATION_PUBLICATION,
        charge_account: ChargeAccountId::new(1).expect("spike account is non-zero"),
    };

    assert!(matches!(
        runtime.transact(command),
        Err(TxError::Persist(UnavailableJournalError::NoDurableProvider))
    ));
    let (revision, estate_absent, recovery_required) = runtime.observe(|engine| {
        (
            engine.revision(),
            engine
                .estate(EffectId::new(root, 1).expect("spike effect is non-zero"))
                .is_none(),
            engine.pressure().persistence_recovery_required,
        )
    });
    assert_eq!(revision, 0);
    assert!(estate_absent);
    assert!(recovery_required);
    println!(
        "CSER_CORE_RUNTIME_SPIKE PASS writer=portable_core legacy_runtime=false \
         live_ingress=false durable_provider=unavailable fail_closed=true"
    );
}
