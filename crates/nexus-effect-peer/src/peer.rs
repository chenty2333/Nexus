// SPDX-License-Identifier: MPL-2.0

use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

use cser_transition_gates::handoff::{
    HandoffId, LogPosition, OwnershipDecision, OwnershipDecisionReceipt, PrepareIntent,
};

use crate::wire::*;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod production_registry;

use production_registry::{
    CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
    EffectRegistry, HandoffFreezeReadiness, PortalHandle, ProductionHandoffFreezeReceipt,
    ProductionHandoffProgress, PublicationMode, PublicationTicket, RegisterRequest, RegistryError,
    RevokeDisposition, ScopeConfig, ScopeKey, SyscallDescriptor, TaskKey, TerminalRequest,
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const BOOT_INCARNATION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedLine {
    Eof,
    Complete,
    TooLarge,
}

#[derive(Clone)]
struct StoredEffect {
    handle: PortalHandle,
    commit: Option<CommitReceipt>,
}

#[derive(Clone, Copy)]
struct StoredFreeze {
    intent: NativePrepareIntent,
    receipt: ProductionHandoffFreezeReceipt,
}

struct PeerSession {
    registry: EffectRegistry,
    scope: ScopeKey,
    supervisor: TaskKey,
    task: TaskKey,
    credit: CreditClass,
    effects: BTreeMap<u64, StoredEffect>,
    publications: BTreeMap<u64, PublicationTicket>,
    freeze: Option<StoredFreeze>,
}

#[derive(Clone)]
struct CachedResponse {
    request: Vec<u8>,
    response: Vec<u8>,
}

pub struct ProductionEffectPeer {
    session: Option<PeerSession>,
    responses: BTreeMap<u64, CachedResponse>,
    next_sequence: u64,
    previous_receipt: Option<String>,
    shutdown: bool,
}

impl ProductionEffectPeer {
    pub fn new() -> Self {
        Self {
            session: None,
            responses: BTreeMap::new(),
            next_sequence: 0,
            previous_receipt: None,
            shutdown: false,
        }
    }

    pub const fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    pub fn execute_line(&mut self, line: &[u8]) -> Vec<u8> {
        if line.len() > MAX_REQUEST_BYTES {
            return request_too_large_response();
        }
        let request: PeerRequest = match serde_json::from_slice(line) {
            Ok(request) => request,
            Err(error) => {
                return encode_response(&PeerResponse::error(0, "invalid-json", error.to_string()));
            }
        };
        let canonical = match canonical_request_bytes(&request) {
            Ok(bytes) => bytes,
            Err(error) => {
                return encode_response(&PeerResponse::error(
                    request.request_id,
                    "invalid-request",
                    error.to_string(),
                ));
            }
        };
        if let Some(cached) = self.responses.get(&request.request_id) {
            return if cached.request == canonical {
                cached.response.clone()
            } else {
                encode_response(&PeerResponse::error(
                    request.request_id,
                    "request-id-conflict",
                    "request ID was reused with different canonical bytes",
                ))
            };
        }

        let response = self.execute(request, &canonical);
        let encoded = encode_response(&response);
        self.responses.insert(
            response.request_id,
            CachedResponse {
                request: canonical,
                response: encoded.clone(),
            },
        );
        encoded
    }

    fn execute(&mut self, request: PeerRequest, canonical: &[u8]) -> PeerResponse {
        if request.schema != REQUEST_SCHEMA {
            return PeerResponse::error(
                request.request_id,
                "schema-mismatch",
                format!("expected {REQUEST_SCHEMA}, got {}", request.schema),
            );
        }
        if request.request_id == 0 {
            return PeerResponse::error(0, "invalid-request", "request_id must be nonzero");
        }
        if self.shutdown {
            return PeerResponse::error(
                request.request_id,
                "peer-shutdown",
                "the peer already accepted shutdown",
            );
        }
        let sequence = match self.next_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                return PeerResponse::error(
                    request.request_id,
                    "counter-overflow",
                    "native receipt sequence exhausted",
                );
            }
        };
        let payload = match self.dispatch(request.command) {
            Ok(payload) => payload,
            Err(error) => {
                return PeerResponse::error(request.request_id, error.code, error.detail);
            }
        };
        if let Some(session) = self.session.as_ref()
            && let Err(error) = session.registry.check_invariants()
        {
            return PeerResponse::error(
                request.request_id,
                "registry-invariant",
                format!("{error:?}"),
            );
        }
        let receipt = match NativeReceipt::new(
            sequence,
            sha256_hex(canonical),
            self.previous_receipt.clone(),
            payload,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return PeerResponse::error(
                    request.request_id,
                    "receipt-encoding",
                    error.to_string(),
                );
            }
        };
        self.next_sequence = sequence;
        self.previous_receipt = Some(receipt.receipt_sha256.clone());
        PeerResponse::success(request.request_id, receipt)
    }

    fn dispatch(&mut self, command: PeerCommand) -> Result<NativeReceiptPayload, PeerFailure> {
        match command {
            PeerCommand::Initialize(config) => self.initialize(config),
            PeerCommand::Register(request) => self.register(request),
            PeerCommand::Prepare(selector) => self.prepare(selector),
            PeerCommand::Commit(request) => self.commit(request),
            PeerCommand::Complete(request) => self.complete(request),
            PeerCommand::AcknowledgePublication(selector) => self.acknowledge_publication(selector),
            PeerCommand::CrashService(request) => self.crash_service(request),
            PeerCommand::RebindService(request) => self.rebind_service(request),
            PeerCommand::Freeze(intent) => self.freeze(intent),
            PeerCommand::AbortUncommitted => self.abort_uncommitted(),
            PeerCommand::Thaw(decision) => self.thaw(decision),
            PeerCommand::CloseStep(decision) => self.close_step(decision),
            PeerCommand::Query => self.query(),
            PeerCommand::Shutdown => {
                self.shutdown = true;
                Ok(NativeReceiptPayload::Shutdown)
            }
        }
    }

    fn initialize(&mut self, config: PeerConfig) -> Result<NativeReceiptPayload, PeerFailure> {
        if self.session.is_some() {
            return Err(PeerFailure::new(
                "already-initialized",
                "one process owns one Registry",
            ));
        }
        validate_config(config)?;
        let scope = ScopeKey::new(config.scope_id, config.scope_generation);
        let supervisor = TaskKey::new(config.supervisor_id, config.supervisor_generation);
        let task = TaskKey::new(config.task_id, config.task_generation);
        let credit = CreditClass::new(config.credit_class);
        let mut registry = EffectRegistry::new();
        registry.create_scope(ScopeConfig {
            key: scope,
            authority_epoch: config.authority_epoch,
            binding_epoch: config.binding_epoch,
            supervisor,
            credits: alloc::vec![CreditLimit::new(credit, config.credit_limit)],
        })?;
        self.session = Some(PeerSession {
            registry,
            scope,
            supervisor,
            task,
            credit,
            effects: BTreeMap::new(),
            publications: BTreeMap::new(),
            freeze: None,
        });
        Ok(NativeReceiptPayload::Initialized(InitializedPayload {
            process_id: std::process::id(),
            boot_incarnation: BOOT_INCARNATION,
            config,
        }))
    }

    fn register(&mut self, request: RegisterEffect) -> Result<NativeReceiptPayload, PeerFailure> {
        if request.client_effect == 0 || request.credit_units == 0 {
            return Err(PeerFailure::invalid(
                "effect and credit units must be nonzero",
            ));
        }
        let session = self.session_mut()?;
        if session.effects.contains_key(&request.client_effect) {
            return Err(PeerFailure::new(
                "effect-conflict",
                "client effect identity already exists",
            ));
        }
        let number = usize::try_from(request.syscall_number)
            .map_err(|_| PeerFailure::invalid("syscall number does not fit usize"))?;
        let mut arguments = [0_usize; 6];
        for (target, source) in arguments.iter_mut().zip(request.syscall_arguments) {
            *target = usize::try_from(source)
                .map_err(|_| PeerFailure::invalid("syscall argument does not fit usize"))?;
        }
        let registered = session.registry.register(RegisterRequest {
            scope: session.scope,
            task: session.task,
            operation: production_registry::OperationClass::new(request.operation_class),
            descriptor: SyscallDescriptor::new(number, arguments),
            resources: alloc::vec![],
            credits: alloc::vec![CreditCharge::new(session.credit, request.credit_units)],
            publication: if request.publication_required {
                PublicationMode::Required
            } else {
                PublicationMode::None
            },
        })?;
        let payload = RegisteredPayload {
            client_effect: request.client_effect,
            native_effect_id: registered.identity.effect().id(),
            native_effect_generation: registered.identity.effect().generation(),
            authority_epoch: registered.identity.authority_epoch(),
            binding_epoch: registered.identity.binding_epoch(),
        };
        session.effects.insert(
            request.client_effect,
            StoredEffect {
                handle: registered.handle,
                commit: None,
            },
        );
        Ok(NativeReceiptPayload::EffectRegistered(payload))
    }

    fn prepare(&mut self, selector: EffectSelector) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        session.require_binding(selector.binding_epoch)?;
        let handle = session.effect(selector.client_effect)?.handle;
        session.registry.prepare(session.supervisor, handle)?;
        Ok(NativeReceiptPayload::EffectPrepared(selector))
    }

    fn commit(&mut self, request: CommitEffect) -> Result<NativeReceiptPayload, PeerFailure> {
        if request.domain_revision == 0 {
            return Err(PeerFailure::invalid("domain revision must be nonzero"));
        }
        let session = self.session_mut()?;
        session.require_binding(request.binding_epoch)?;
        let handle = session.effect(request.client_effect)?.handle;
        let outcome = session.registry.commit(
            session.supervisor,
            handle,
            CommitMetadata::new(request.result, request.domain_revision),
        )?;
        let (receipt, registry_replay) = match outcome {
            CommitOutcome::Applied(receipt) => (receipt, false),
            CommitOutcome::AlreadyCommitted(receipt) => (receipt, true),
        };
        let payload = CommittedPayload {
            client_effect: request.client_effect,
            native_effect_id: receipt.effect().id(),
            binding_epoch: request.binding_epoch,
            commit_sequence: receipt.sequence(),
            result: receipt.result(),
            domain_revision: receipt.domain_revision(),
            registry_replay,
        };
        session.effect_mut(request.client_effect)?.commit = Some(receipt);
        Ok(NativeReceiptPayload::EffectCommitted(payload))
    }

    fn complete(&mut self, request: CompleteEffect) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        session.require_binding(request.binding_epoch)?;
        let effect = session.effect(request.client_effect)?.clone();
        let commit = effect.commit.ok_or_else(|| {
            PeerFailure::new(
                "effect-not-committed",
                "provider completion requires the production commit receipt",
            )
        })?;
        if request.result != commit.result() {
            return Err(PeerFailure::new(
                "completion-conflict",
                "provider result differs from the production commit receipt",
            ));
        }
        let terminal = session.registry.stage_kernel_completion(&commit)?;
        let publication_pending = terminal.publication.is_some();
        if let Some(ticket) = terminal.publication {
            session.publications.insert(request.client_effect, ticket);
        }
        Ok(NativeReceiptPayload::EffectCompleted(CompletedPayload {
            client_effect: request.client_effect,
            binding_epoch: request.binding_epoch,
            terminal_sequence: terminal.receipt.sequence(),
            publication_pending,
        }))
    }

    fn acknowledge_publication(
        &mut self,
        selector: EffectSelector,
    ) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        session.require_binding(selector.binding_epoch)?;
        let ticket = session
            .publications
            .get(&selector.client_effect)
            .cloned()
            .ok_or_else(|| PeerFailure::new("publication-not-found", "no pending publication"))?;
        session.registry.acknowledge_publication(&ticket)?;
        session.publications.remove(&selector.client_effect);
        Ok(NativeReceiptPayload::PublicationAcknowledged(selector))
    }

    fn crash_service(
        &mut self,
        request: CrashService,
    ) -> Result<NativeReceiptPayload, PeerFailure> {
        if request.supervisor_id == 0
            || request.supervisor_generation == 0
            || request.binding_epoch == 0
        {
            return Err(PeerFailure::invalid(
                "crash service identity and binding epoch must be nonzero",
            ));
        }
        let session = self.session_mut()?;
        let presented = TaskKey::new(request.supervisor_id, request.supervisor_generation);
        let projection = session.registry.scope_projection(session.scope)?;
        if projection.binding_epoch != request.binding_epoch
            || projection.supervisor != Some(presented)
            || session.supervisor != presented
        {
            return Err(PeerFailure::stale_binding(
                "crash request does not name the active production service binding",
            ));
        }

        let receipt = session.registry.crash(session.scope, presented)?;
        let mut cohort = Vec::with_capacity(receipt.cohort.len());
        for native in &receipt.cohort {
            let client_effect = session.client_effect(*native)?;
            let effect = session.effect(client_effect)?;
            cohort.push(CrashedEffectPayload {
                client_effect,
                native_effect_id: native.id(),
                native_effect_generation: native.generation(),
                binding_epoch: effect.handle.binding_epoch(),
            });
        }
        Ok(NativeReceiptPayload::ServiceCrashed(
            ServiceCrashedPayload {
                scope_id: receipt.scope.id(),
                scope_generation: receipt.scope.generation(),
                supervisor_id: presented.id(),
                supervisor_generation: presented.generation(),
                previous_binding_epoch: receipt.previous_binding_epoch,
                crashed_binding_epoch: receipt.binding_epoch,
                cohort,
            },
        ))
    }

    fn rebind_service(
        &mut self,
        request: RebindService,
    ) -> Result<NativeReceiptPayload, PeerFailure> {
        if request.crashed_binding_epoch == 0
            || request.replacement_supervisor_id == 0
            || request.replacement_supervisor_generation == 0
        {
            return Err(PeerFailure::invalid(
                "rebind service identity and crashed binding epoch must be nonzero",
            ));
        }
        let session = self.session_mut()?;
        let projection = session.registry.scope_projection(session.scope)?;
        if projection.binding_epoch != request.crashed_binding_epoch
            || projection.supervisor.is_some()
            || !projection.fallback_running
        {
            return Err(PeerFailure::stale_binding(
                "rebind request does not name the current crashed production binding",
            ));
        }
        let replacement = TaskKey::new(
            request.replacement_supervisor_id,
            request.replacement_supervisor_generation,
        );
        let snapshot = session
            .registry
            .recovery_snapshot(session.scope, replacement)?;

        // Resolve the complete adapter mapping before the first irreversible
        // rebind/adopt transition. Every recovery member came from this
        // process-owned Registry, so a missing mapping is an adapter invariant
        // failure rather than a reason to partially rebind.
        let mut clients = BTreeMap::new();
        for effect in &snapshot.effects {
            clients.insert(effect.effect, session.client_effect(effect.effect)?);
        }

        session
            .registry
            .ready(session.scope, replacement, &snapshot)?;
        let rebound = session.registry.rebind(session.scope, replacement)?;
        let mut adopted = Vec::with_capacity(snapshot.effects.len());
        while let Some(item) = session.registry.recover_next(session.scope, replacement)? {
            let native = item.handle.effect();
            let client_effect = *clients.get(&native).ok_or_else(|| {
                PeerFailure::new(
                    "effect-not-found",
                    "production recovery member has no adapter mapping",
                )
            })?;
            let previous_binding_epoch = item.handle.binding_epoch();
            let handle = session
                .registry
                .adopt(session.scope, replacement, item.handle)?;
            session.effect_mut(client_effect)?.handle = handle;
            adopted.push(AdoptedEffectPayload {
                client_effect,
                native_effect_id: native.id(),
                native_effect_generation: native.generation(),
                previous_binding_epoch,
                binding_epoch: handle.binding_epoch(),
            });
        }
        let recovery_remaining = session.registry.recovery_remaining(session.scope)?;
        if recovery_remaining != 0 {
            return Err(PeerFailure::new(
                "recovery-incomplete",
                "production recovery still has unadopted effects",
            ));
        }
        session.supervisor = replacement;
        Ok(NativeReceiptPayload::ServiceRebound(
            ServiceReboundPayload {
                scope_id: rebound.scope.id(),
                scope_generation: rebound.scope.generation(),
                supervisor_id: rebound.supervisor.id(),
                supervisor_generation: rebound.supervisor.generation(),
                binding_epoch: rebound.binding_epoch,
                adopted,
                recovery_remaining,
            },
        ))
    }

    fn freeze(&mut self, intent: NativePrepareIntent) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        if let Some(existing) = session.freeze
            && existing.intent != intent
        {
            return Err(PeerFailure::new(
                "freeze-conflict",
                "a different handoff already owns the gate",
            ));
        }
        let native_intent = prepare_intent(intent)?;
        let receipt = session
            .registry
            .freeze_admission(session.scope, native_intent)?;
        session.freeze = Some(StoredFreeze { intent, receipt });
        Ok(NativeReceiptPayload::AdmissionFrozen(freeze_payload(
            receipt,
        )))
    }

    fn abort_uncommitted(&mut self) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        let freeze = session.freeze.ok_or_else(PeerFailure::not_frozen)?;
        let progress = session
            .registry
            .abort_handoff_uncommitted(session.scope, freeze.receipt)?;
        let mut publication_effects = Vec::new();
        for ticket in progress.publications {
            let client = session.client_effect(ticket.effect())?;
            session.publications.insert(client, ticket);
            publication_effects.push(client);
        }
        Ok(NativeReceiptPayload::UncommittedAborted(
            AbortProgressPayload {
                aborted: progress.aborted,
                publication_effects,
                readiness: readiness(progress.readiness),
            },
        ))
    }

    fn thaw(
        &mut self,
        decision: NativeOwnershipDecision,
    ) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        let freeze = session.freeze.ok_or_else(PeerFailure::not_frozen)?;
        validate_decision(freeze, decision)?;
        let receipt = ownership_decision(freeze, decision, OwnershipDecision::Abort)?;
        let thaw = session.registry.unfreeze_handoff(session.scope, receipt)?;
        Ok(NativeReceiptPayload::AdmissionThawed(ThawPayload {
            handoff_id: decision.handoff_id,
            freeze_generation: decision.freeze_generation,
            decision_position: decision.decision_position,
            source_recovery_required: thaw.source_recovery_required(),
        }))
    }

    fn close_step(
        &mut self,
        decision: NativeOwnershipDecision,
    ) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        let freeze = session.freeze.ok_or_else(PeerFailure::not_frozen)?;
        validate_decision(freeze, decision)?;
        let receipt = ownership_decision(freeze, decision, OwnershipDecision::Commit)?;
        let progress = session
            .registry
            .commit_handoff_close(session.scope, receipt)?;
        let payload = match progress {
            ProductionHandoffProgress::Closing(selection) => {
                if let Some(next) = session.registry.revoke_next(&selection)? {
                    let client = session.client_effect(next.effect)?;
                    let terminal_request = match next.disposition {
                        RevokeDisposition::Abort => TerminalRequest::aborted(-125),
                        RevokeDisposition::Drain(commit) => {
                            TerminalRequest::completed_by(commit.result(), commit)
                        }
                    };
                    let terminal = session.registry.stage_revoke_terminal(
                        &selection,
                        next.effect,
                        terminal_request,
                    )?;
                    let publication_pending = terminal.publication.is_some();
                    if let Some(ticket) = terminal.publication {
                        session.publications.insert(client, ticket);
                    }
                    progress_payload(
                        session,
                        NativeHandoffStatus::Closing,
                        None,
                        Some(client),
                        publication_pending,
                        None,
                    )?
                } else {
                    session.registry.revoke_complete(&selection)?;
                    closed_or_current_payload(session)?
                }
            }
            ProductionHandoffProgress::Retained(_) => progress_payload(
                session,
                NativeHandoffStatus::Retained,
                None,
                None,
                false,
                None,
            )?,
            ProductionHandoffProgress::Closed(closure) => progress_payload(
                session,
                NativeHandoffStatus::Closed,
                None,
                None,
                false,
                Some(closure.terminal_manifest_digest()),
            )?,
            ProductionHandoffProgress::Frozen(value) => progress_payload(
                session,
                NativeHandoffStatus::Frozen,
                Some(readiness(value)),
                None,
                false,
                None,
            )?,
            ProductionHandoffProgress::Aborted(_) => progress_payload(
                session,
                NativeHandoffStatus::Aborted,
                None,
                None,
                false,
                None,
            )?,
        };
        Ok(NativeReceiptPayload::ClosureProgress(payload))
    }

    fn query(&mut self) -> Result<NativeReceiptPayload, PeerFailure> {
        let session = self.session_mut()?;
        Ok(NativeReceiptPayload::HandoffQuery(
            closed_or_current_payload(session)?,
        ))
    }

    fn session_mut(&mut self) -> Result<&mut PeerSession, PeerFailure> {
        self.session
            .as_mut()
            .ok_or_else(|| PeerFailure::new("not-initialized", "initialize the peer first"))
    }
}

impl Default for ProductionEffectPeer {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerSession {
    fn require_binding(&self, binding_epoch: u64) -> Result<(), PeerFailure> {
        if binding_epoch == 0 {
            return Err(PeerFailure::invalid("binding epoch must be nonzero"));
        }
        let current = self.registry.scope_projection(self.scope)?.binding_epoch;
        if binding_epoch != current {
            return Err(PeerFailure::stale_binding(format!(
                "presented binding epoch {binding_epoch}, current production binding epoch {current}",
            )));
        }
        Ok(())
    }

    fn effect(&self, client: u64) -> Result<&StoredEffect, PeerFailure> {
        self.effects
            .get(&client)
            .ok_or_else(|| PeerFailure::new("effect-not-found", "unknown client effect"))
    }

    fn effect_mut(&mut self, client: u64) -> Result<&mut StoredEffect, PeerFailure> {
        self.effects
            .get_mut(&client)
            .ok_or_else(|| PeerFailure::new("effect-not-found", "unknown client effect"))
    }

    fn client_effect(&self, native: production_registry::EffectKey) -> Result<u64, PeerFailure> {
        self.effects
            .iter()
            .find_map(|(client, effect)| (effect.handle.effect() == native).then_some(*client))
            .ok_or_else(|| {
                PeerFailure::new("effect-not-found", "native effect has no adapter mapping")
            })
    }
}

pub fn serve<R: BufRead, W: Write>(mut input: R, mut output: W) -> io::Result<()> {
    let mut peer = ProductionEffectPeer::new();
    let mut line = Vec::with_capacity(MAX_REQUEST_BYTES);
    loop {
        let response = match read_bounded_line(&mut input, &mut line)? {
            BoundedLine::Eof => return Ok(()),
            BoundedLine::Complete => peer.execute_line(&line),
            BoundedLine::TooLarge => request_too_large_response(),
        };
        output.write_all(&response)?;
        output.write_all(b"\n")?;
        output.flush()?;
        if peer.is_shutdown() {
            return Ok(());
        }
    }
}

fn read_bounded_line<R: BufRead>(input: &mut R, line: &mut Vec<u8>) -> io::Result<BoundedLine> {
    line.clear();
    let mut saw_input = false;
    let mut pending_carriage_returns = 0usize;
    let mut too_large = false;

    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if saw_input {
                Ok(if too_large {
                    BoundedLine::TooLarge
                } else {
                    BoundedLine::Complete
                })
            } else {
                Ok(BoundedLine::Eof)
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let content_len = newline.unwrap_or(available.len());
        saw_input = true;

        if !too_large {
            for byte in &available[..content_len] {
                if *byte == b'\r' {
                    pending_carriage_returns = pending_carriage_returns.saturating_add(1);
                    continue;
                }

                let remaining = MAX_REQUEST_BYTES - line.len();
                if pending_carriage_returns > remaining {
                    too_large = true;
                    continue;
                }
                line.resize(line.len() + pending_carriage_returns, b'\r');
                pending_carriage_returns = 0;

                if line.len() == MAX_REQUEST_BYTES {
                    too_large = true;
                } else {
                    line.push(*byte);
                }
            }
        }

        let consumed = content_len + usize::from(newline.is_some());
        input.consume(consumed);
        if newline.is_some() {
            return Ok(if too_large {
                BoundedLine::TooLarge
            } else {
                BoundedLine::Complete
            });
        }
    }
}

fn request_too_large_response() -> Vec<u8> {
    encode_response(&PeerResponse::error(
        0,
        "request-too-large",
        format!("request exceeds {MAX_REQUEST_BYTES} bytes"),
    ))
}

fn validate_config(config: PeerConfig) -> Result<(), PeerFailure> {
    if config.scope_id == 0
        || config.scope_generation == 0
        || config.authority_epoch == 0
        || config.binding_epoch == 0
        || config.supervisor_id == 0
        || config.supervisor_generation == 0
        || config.task_id == 0
        || config.task_generation == 0
        || config.credit_class == 0
        || config.credit_limit == 0
    {
        return Err(PeerFailure::invalid(
            "all native identities and limits must be nonzero",
        ));
    }
    Ok(())
}

fn prepare_intent(intent: NativePrepareIntent) -> Result<PrepareIntent, PeerFailure> {
    PrepareIntent::new(
        HandoffId::new(intent.handoff_id).map_err(PeerFailure::gate)?,
        intent.log_identity,
        LogPosition::new(intent.intent_position).map_err(PeerFailure::gate)?,
        intent.service_incarnation,
        intent.key_identity,
        intent.request_digest,
    )
    .map_err(PeerFailure::gate)
}

fn validate_decision(
    freeze: StoredFreeze,
    decision: NativeOwnershipDecision,
) -> Result<(), PeerFailure> {
    if decision.handoff_id != freeze.intent.handoff_id
        || decision.freeze_generation != freeze.receipt.freeze().freeze_generation()
        || decision.log_identity != freeze.intent.log_identity
        || decision.service_incarnation != freeze.intent.service_incarnation
        || decision.key_identity != freeze.intent.key_identity
        || decision.request_digest != freeze.intent.request_digest
    {
        return Err(PeerFailure::new(
            "decision-mismatch",
            "ownership decision does not bind the frozen native identity",
        ));
    }
    Ok(())
}

fn ownership_decision(
    freeze: StoredFreeze,
    decision: NativeOwnershipDecision,
    kind: OwnershipDecision,
) -> Result<OwnershipDecisionReceipt, PeerFailure> {
    OwnershipDecisionReceipt::new(
        freeze.receipt.freeze(),
        LogPosition::new(decision.decision_position).map_err(PeerFailure::gate)?,
        decision.request_digest,
        kind,
    )
    .map_err(PeerFailure::gate)
}

fn freeze_payload(receipt: ProductionHandoffFreezeReceipt) -> FreezePayload {
    let freeze = receipt.freeze();
    let context = freeze.context();
    FreezePayload {
        handoff_id: freeze.intent().handoff().get(),
        registry_instance: context.registry_instance,
        boot_incarnation: context.boot_incarnation,
        scope_id: context.scope_id,
        scope_generation: context.scope_generation,
        authority_epoch: context.authority_epoch,
        binding_epoch: context.binding_epoch,
        frozen_scope_revision: context.scope_revision,
        freeze_generation: freeze.freeze_generation(),
        cohort_digest: context.cohort_digest,
        classification_digest: context.classification_digest,
        cohort_size: receipt.cohort_size(),
        committed_at_freeze: receipt.committed_at_freeze(),
        readiness: readiness(receipt.readiness()),
    }
}

fn readiness(value: HandoffFreezeReadiness) -> NativeReadiness {
    match value {
        HandoffFreezeReadiness::ReadyToCommit => NativeReadiness::ReadyToCommit,
        HandoffFreezeReadiness::NeedsAbort => NativeReadiness::NeedsAbort,
        HandoffFreezeReadiness::PublicationPending => NativeReadiness::PublicationPending,
        HandoffFreezeReadiness::BlockedRetained => NativeReadiness::BlockedRetained,
    }
}

fn closed_or_current_payload(
    session: &mut PeerSession,
) -> Result<HandoffProgressPayload, PeerFailure> {
    let freeze = session.freeze.ok_or_else(PeerFailure::not_frozen)?;
    match session
        .registry
        .query_handoff(session.scope, freeze.receipt.freeze())?
    {
        ProductionHandoffProgress::Frozen(value) => progress_payload(
            session,
            NativeHandoffStatus::Frozen,
            Some(readiness(value)),
            None,
            false,
            None,
        ),
        ProductionHandoffProgress::Aborted(_) => progress_payload(
            session,
            NativeHandoffStatus::Aborted,
            None,
            None,
            false,
            None,
        ),
        ProductionHandoffProgress::Closing(_) => progress_payload(
            session,
            NativeHandoffStatus::Closing,
            None,
            None,
            false,
            None,
        ),
        ProductionHandoffProgress::Retained(_) => progress_payload(
            session,
            NativeHandoffStatus::Retained,
            None,
            None,
            false,
            None,
        ),
        ProductionHandoffProgress::Closed(closure) => progress_payload(
            session,
            NativeHandoffStatus::Closed,
            None,
            None,
            false,
            Some(closure.terminal_manifest_digest()),
        ),
    }
}

fn progress_payload(
    session: &PeerSession,
    status: NativeHandoffStatus,
    readiness: Option<NativeReadiness>,
    native_effect: Option<u64>,
    publication_pending: bool,
    terminal_manifest_digest: Option<u64>,
) -> Result<HandoffProgressPayload, PeerFailure> {
    let freeze = session.freeze.ok_or_else(PeerFailure::not_frozen)?;
    let projection = session.registry.scope_projection(session.scope)?;
    Ok(HandoffProgressPayload {
        status,
        readiness,
        freeze_generation: freeze.receipt.freeze().freeze_generation(),
        scope_revision: projection.revision,
        authority_epoch: projection.authority_epoch,
        binding_epoch: projection.binding_epoch,
        live_effects: projection.live_effects,
        pending_publications: projection.pending_publications,
        native_effect,
        publication_pending,
        terminal_manifest_digest,
    })
}

fn encode_response(response: &PeerResponse) -> Vec<u8> {
    serde_json::to_vec(response).unwrap_or_else(|error| {
        format!(
            "{{\"schema\":\"{RESPONSE_SCHEMA}\",\"request_id\":0,\"status\":\"error\",\"receipt\":null,\"error\":{{\"code\":\"response-encoding\",\"detail\":{}}}}}",
            serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "\"encoding failed\"".into())
        )
        .into_bytes()
    })
}

struct PeerFailure {
    code: &'static str,
    detail: String,
}

impl PeerFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self::new("invalid-request", detail)
    }

    fn not_frozen() -> Self {
        Self::new("not-frozen", "freeze admission before this operation")
    }

    fn stale_binding(detail: impl Into<String>) -> Self {
        Self::new("stale-binding", detail)
    }

    fn gate(error: cser_transition_gates::handoff::HandoffGateError) -> Self {
        Self::new("invalid-handoff-identity", format!("{error:?}"))
    }
}

impl From<RegistryError> for PeerFailure {
    fn from(error: RegistryError) -> Self {
        let code = match error {
            RegistryError::StaleBinding => "stale-binding",
            RegistryError::StaleAuthority => "stale-authority",
            RegistryError::NoSupervisor => "no-supervisor",
            RegistryError::RecoveryNotReady => "recovery-not-ready",
            RegistryError::NotAdoptable => "not-adoptable",
            RegistryError::HandoffAdmissionFrozen => "admission-frozen",
            RegistryError::InvalidHandoffReceipt => "invalid-handoff-receipt",
            RegistryError::HandoffNotReady => "handoff-not-ready",
            RegistryError::NotQuiescent => "not-quiescent",
            RegistryError::PublicationPending => "publication-pending",
            RegistryError::InvalidPublication => "invalid-publication",
            _ => "registry-error",
        };
        Self::new(code, format!("{error:?}"))
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
