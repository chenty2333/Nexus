use alloc::collections::{BTreeMap, BTreeSet};

use super::*;

impl Default for RuntimeNetModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeNetModel {
    /// Creates an empty runtime-network oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_effect: 1,
            next_commit_sequence: 1,
            next_publication_sequence: 1,
            next_revoke_sequence: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
        }
    }

    /// Creates one active root scope with three restartable service domains.
    pub fn create_scope(
        &mut self,
        services: RuntimeNetServices,
        credits: NetCredits,
    ) -> Result<(ScopeId, RuntimeNetBindings), RuntimeNetError> {
        self.transaction(|candidate| candidate.create_scope_inner(services, credits))
    }

    fn create_scope_inner(
        &mut self,
        services: RuntimeNetServices,
        credits: NetCredits,
    ) -> Result<(ScopeId, RuntimeNetBindings), RuntimeNetError> {
        for class in [
            NetCreditClass::Control,
            NetCreditClass::Network,
            NetCreditClass::Readiness,
            NetCreditClass::Buffer,
        ] {
            if credits.get(class) == 0 {
                return Err(RuntimeNetError::CreditExhausted(class));
            }
        }
        let service_set: BTreeSet<_> = NetDomain::ALL
            .into_iter()
            .map(|domain| services.get(domain))
            .collect();
        if service_set.len() != NetDomain::ALL.len()
            || service_set.iter().any(|service| service.get() == 0)
        {
            return Err(RuntimeNetError::WrongService);
        }

        let scope = ScopeId::new(self.next_scope);
        self.next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        let authority_epoch = NetAuthorityEpoch::new(1);
        let binding_epoch = NetBindingEpoch::new(1);
        let mut domains = BTreeMap::new();
        for domain in NetDomain::ALL {
            domains.insert(
                domain,
                DomainRecord {
                    binding_epoch,
                    service: Some(services.get(domain)),
                    fallback: NetFallbackState::Standby,
                    revision: 0,
                    recovery_cohort: BTreeSet::new(),
                    ready: None,
                },
            );
        }
        self.scopes.insert(
            scope,
            ScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                socket_generation: SocketGeneration::new(1),
                source_generation: ReadySourceGeneration::new(1),
                domains,
                initial_credits: credits,
                free_credits: credits,
                effects: BTreeSet::new(),
                buffers: BTreeMap::new(),
                network_publications: 0,
                readiness_publications: 0,
                ready_deliveries: 0,
                guest_replies: 0,
                buffer_consumptions: 0,
                revocation: None,
            },
        );
        let binding = |domain| RuntimeNetBindingToken {
            scope,
            domain,
            service: services.get(domain),
            authority_epoch,
            binding_epoch,
        };
        Ok((
            scope,
            RuntimeNetBindings {
                personality: binding(NetDomain::Personality),
                network: binding(NetDomain::Network),
                readiness: binding(NetDomain::Readiness),
            },
        ))
    }

    /// Failure-atomically registers the fixed four-effect loopback graph.
    pub fn register_loopback(
        &mut self,
        bindings: RuntimeNetBindings,
    ) -> Result<RuntimeNetToken, RuntimeNetError> {
        self.transaction(|candidate| candidate.register_loopback_inner(bindings))
    }

    fn register_loopback_inner(
        &mut self,
        bindings: RuntimeNetBindings,
    ) -> Result<RuntimeNetToken, RuntimeNetError> {
        let personality = bindings.get(NetDomain::Personality);
        let scope = personality.scope;
        for domain in NetDomain::ALL {
            let binding = bindings.get(domain);
            if binding.scope != scope || binding.domain != domain {
                return Err(RuntimeNetError::WrongDomain);
            }
            self.validate_binding(binding)?;
        }
        let scope_record = self.scope_record(scope)?;
        if !scope_record.free_credits.contains(NetCredits::ONE_REQUEST) {
            let exhausted = [
                NetCreditClass::Control,
                NetCreditClass::Network,
                NetCreditClass::Readiness,
                NetCreditClass::Buffer,
            ]
            .into_iter()
            .find(|class| scope_record.free_credits.get(*class) == 0)
            .unwrap_or(NetCreditClass::Control);
            return Err(RuntimeNetError::CreditExhausted(exhausted));
        }
        let authority_epoch = scope_record.authority_epoch;
        let socket_generation = scope_record.socket_generation;
        let source_generation = scope_record.source_generation;
        let free = scope_record
            .free_credits
            .checked_sub(NetCredits::ONE_REQUEST)
            .ok_or(RuntimeNetError::InvariantViolation(
                "registration credit underflow",
            ))?;

        let syscall_id = self.take_effect_id()?;
        let network_id = self.take_effect_id()?;
        let readiness_id = self.take_effect_id()?;
        let buffer_id = self.take_effect_id()?;
        let make_token =
            |effect, parent, kind, binding: RuntimeNetBindingToken| RuntimeNetEffectToken {
                scope,
                effect,
                parent,
                kind,
                authority_epoch,
                binding_epoch: binding.binding_epoch,
                socket_generation,
                source_generation,
            };
        let token = RuntimeNetToken {
            syscall: make_token(
                syscall_id,
                None,
                NetEffectKind::Syscall,
                bindings.get(NetDomain::Personality),
            ),
            network: make_token(
                network_id,
                Some(syscall_id),
                NetEffectKind::NetOperation,
                bindings.get(NetDomain::Network),
            ),
            readiness: make_token(
                readiness_id,
                Some(network_id),
                NetEffectKind::ReadinessWait,
                bindings.get(NetDomain::Readiness),
            ),
            buffer: make_token(
                buffer_id,
                Some(network_id),
                NetEffectKind::BufferLease,
                bindings.get(NetDomain::Network),
            ),
        };
        for effect_token in [token.syscall, token.network, token.readiness, token.buffer] {
            self.effects.insert(
                effect_token.effect,
                EffectRecord {
                    token: effect_token,
                    phase: NetEffectPhase::Registered,
                    credit: effect_token.kind.credit(),
                    commit_sequence: None,
                    terminalizations: 0,
                    net_receipt: None,
                    ready_receipt: None,
                    publication: None,
                    guest_published: false,
                },
            );
        }
        let scope_record = self.scope_record_mut(scope)?;
        scope_record.free_credits = free;
        scope_record
            .effects
            .extend([syscall_id, network_id, readiness_id, buffer_id]);
        for domain in NetDomain::ALL {
            self.bump_domain_revision(scope, domain)?;
        }
        Ok(token)
    }

    /// Prepares the syscall continuation without publishing a guest result.
    pub fn prepare_syscall(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        self.prepare_effect(binding, token, NetEffectKind::Syscall)
    }

    /// Prepares the loopback operation without publishing payload bytes.
    pub fn prepare_network(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        self.prepare_effect(binding, token, NetEffectKind::NetOperation)
    }

    /// Prepares a readiness wait without publishing readiness.
    pub fn prepare_readiness(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        self.prepare_effect(binding, token, NetEffectKind::ReadinessWait)
    }

    /// Prepares ownership for the fixed four-byte payload.
    pub fn prepare_buffer(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        self.prepare_effect(binding, token, NetEffectKind::BufferLease)
    }

    fn prepare_effect(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
        kind: NetEffectKind,
    ) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| candidate.prepare_effect_inner(binding, token, kind))
    }

    fn prepare_effect_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
        kind: NetEffectKind,
    ) -> Result<(), RuntimeNetError> {
        let record = *self.validate_service_effect(binding, token, kind)?;
        self.validate_generation(token)?;
        if record.phase != NetEffectPhase::Registered {
            return Err(RuntimeNetError::InvalidEffectState(record.phase));
        }
        self.effect_record_mut(token.effect)?.phase = NetEffectPhase::Prepared;
        self.bump_domain_revision(token.scope, kind.domain())
    }

    /// Atomically publishes the fixed payload and its retained buffer lease.
    pub fn commit_network(
        &mut self,
        binding: RuntimeNetBindingToken,
        network: RuntimeNetEffectToken,
        buffer: RuntimeNetEffectToken,
    ) -> Result<NetCommitReceipt, RuntimeNetError> {
        self.transaction(|candidate| candidate.commit_network_inner(binding, network, buffer))
    }

    fn commit_network_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        network: RuntimeNetEffectToken,
        buffer: RuntimeNetEffectToken,
    ) -> Result<NetCommitReceipt, RuntimeNetError> {
        let network_record =
            *self.validate_service_effect(binding, network, NetEffectKind::NetOperation)?;
        let buffer_record =
            *self.validate_service_effect(binding, buffer, NetEffectKind::BufferLease)?;
        self.validate_generation(network)?;
        self.validate_generation(buffer)?;
        if network_record.phase != NetEffectPhase::Prepared {
            return Err(if network_record.phase == NetEffectPhase::Committed {
                RuntimeNetError::AlreadyCommitted
            } else {
                RuntimeNetError::InvalidEffectState(network_record.phase)
            });
        }
        if buffer_record.phase != NetEffectPhase::Prepared {
            return Err(RuntimeNetError::InvalidEffectState(buffer_record.phase));
        }
        if buffer.parent != Some(network.effect) || network.parent.is_none() {
            return Err(RuntimeNetError::WrongDomain);
        }
        let syscall = network
            .parent
            .ok_or(RuntimeNetError::InvariantViolation("network lacks syscall"))?;
        let syscall_phase = self.effect_record(syscall)?.phase;
        if syscall_phase != NetEffectPhase::Prepared {
            return Err(RuntimeNetError::InvalidEffectState(syscall_phase));
        }

        let socket_generation = SocketGeneration::new(
            self.scope_record(network.scope)?
                .socket_generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeNetError::CounterOverflow)?,
        );
        let sequence = self.take_commit_sequence()?;
        let receipt = NetCommitReceipt {
            scope: network.scope,
            effect: network.effect,
            buffer_effect: buffer.effect,
            sequence,
            socket_generation,
            payload: LOOPBACK_PAYLOAD,
        };
        let scope = self.scope_record_mut(network.scope)?;
        scope.socket_generation = socket_generation;
        scope.network_publications = scope
            .network_publications
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        if scope
            .buffers
            .insert(
                buffer.effect,
                BufferRecord {
                    effect: buffer.effect,
                    network_effect: network.effect,
                    net_sequence: sequence,
                    payload: LOOPBACK_PAYLOAD,
                },
            )
            .is_some()
        {
            return Err(RuntimeNetError::InvalidBufferLease);
        }
        for effect in [network.effect, buffer.effect] {
            let record = self.effect_record_mut(effect)?;
            record.phase = NetEffectPhase::Committed;
            record.commit_sequence = Some(sequence);
            record.net_receipt = Some(receipt);
        }
        self.bump_domain_revision(network.scope, NetDomain::Network)?;
        Ok(receipt)
    }

    /// Publishes readiness only from one exact immutable `NetCommit` receipt.
    pub fn commit_ready(
        &mut self,
        binding: RuntimeNetBindingToken,
        readiness: RuntimeNetEffectToken,
        network: NetCommitReceipt,
    ) -> Result<ReadyCommitReceipt, RuntimeNetError> {
        self.transaction(|candidate| candidate.commit_ready_inner(binding, readiness, network))
    }

    fn commit_ready_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        readiness: RuntimeNetEffectToken,
        network: NetCommitReceipt,
    ) -> Result<ReadyCommitReceipt, RuntimeNetError> {
        let record =
            *self.validate_service_effect(binding, readiness, NetEffectKind::ReadinessWait)?;
        self.validate_generation(readiness)?;
        self.validate_net_receipt(network)?;
        if record.phase != NetEffectPhase::Prepared {
            return Err(if record.phase == NetEffectPhase::Committed {
                RuntimeNetError::AlreadyCommitted
            } else {
                RuntimeNetError::InvalidEffectState(record.phase)
            });
        }
        if readiness.parent != Some(network.effect) {
            return Err(RuntimeNetError::InvalidNetReceipt);
        }
        let buffer = self.effect_record(network.buffer_effect)?;
        if buffer.phase != NetEffectPhase::Committed
            || !self
                .scope_record(readiness.scope)?
                .buffers
                .contains_key(&network.buffer_effect)
        {
            return Err(RuntimeNetError::InvalidBufferLease);
        }
        let source_generation = ReadySourceGeneration::new(
            self.scope_record(readiness.scope)?
                .source_generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeNetError::CounterOverflow)?,
        );
        let sequence = self.take_commit_sequence()?;
        let receipt = ReadyCommitReceipt {
            scope: readiness.scope,
            effect: readiness.effect,
            network_effect: network.effect,
            network_sequence: network.sequence,
            sequence,
            source_generation,
        };
        let scope = self.scope_record_mut(readiness.scope)?;
        scope.source_generation = source_generation;
        scope.readiness_publications = scope
            .readiness_publications
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        let effect = self.effect_record_mut(readiness.effect)?;
        effect.phase = NetEffectPhase::Committed;
        effect.commit_sequence = Some(sequence);
        effect.ready_receipt = Some(receipt);
        self.bump_domain_revision(readiness.scope, NetDomain::Readiness)?;
        Ok(receipt)
    }

    /// Consumes the exact visible payload and returns its buffer credit.
    pub fn consume_buffer(
        &mut self,
        binding: RuntimeNetBindingToken,
        buffer: RuntimeNetEffectToken,
        network: NetCommitReceipt,
    ) -> Result<[u8; 4], RuntimeNetError> {
        self.transaction(|candidate| candidate.consume_buffer_inner(binding, buffer, network))
    }

    fn consume_buffer_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        buffer: RuntimeNetEffectToken,
        network: NetCommitReceipt,
    ) -> Result<[u8; 4], RuntimeNetError> {
        let record = *self.validate_service_effect(binding, buffer, NetEffectKind::BufferLease)?;
        self.validate_net_receipt(network)?;
        if record.phase != NetEffectPhase::Committed
            || record.net_receipt != Some(network)
            || network.buffer_effect != buffer.effect
        {
            return Err(RuntimeNetError::InvalidBufferLease);
        }
        let retained = self
            .scope_record_mut(buffer.scope)?
            .buffers
            .remove(&buffer.effect)
            .ok_or(RuntimeNetError::InvalidBufferLease)?;
        if retained.effect != buffer.effect
            || retained.network_effect != network.effect
            || retained.net_sequence != network.sequence
            || retained.payload != network.payload
        {
            return Err(RuntimeNetError::InvalidBufferLease);
        }
        let scope = self.scope_record_mut(buffer.scope)?;
        scope.buffer_consumptions = scope
            .buffer_consumptions
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        self.terminalize(buffer.effect, NetEffectPhase::Completed)?;
        Ok(retained.payload)
    }

    /// Delivers one immutable readiness receipt through the kernel-owned path.
    ///
    /// Delivery intentionally requires no user-service binding and therefore
    /// remains valid across a readiness-service crash or root closure.
    pub fn deliver_ready(&mut self, receipt: ReadyCommitReceipt) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| candidate.deliver_ready_inner(receipt))
    }

    fn deliver_ready_inner(&mut self, receipt: ReadyCommitReceipt) -> Result<(), RuntimeNetError> {
        let record = *self.validate_ready_receipt(receipt)?;
        if record.phase != NetEffectPhase::Committed {
            return Err(RuntimeNetError::InvalidEffectState(record.phase));
        }
        let state = self.scope_record(receipt.scope)?.state;
        if !matches!(state, ScopeState::Active | ScopeState::Closing) {
            return Err(RuntimeNetError::InvalidScopeState(state));
        }
        let closing = state == ScopeState::Closing;
        let scope = self.scope_record_mut(receipt.scope)?;
        scope.ready_deliveries = scope
            .ready_deliveries
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        self.terminalize(receipt.effect, NetEffectPhase::Completed)?;
        if closing {
            self.record_closure_step(receipt.scope)?;
        }
        Ok(())
    }

    /// Completes a committed network effect after both children are terminal.
    pub fn complete_network(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| {
            let record =
                *candidate.validate_service_effect(binding, token, NetEffectKind::NetOperation)?;
            if record.phase != NetEffectPhase::Committed {
                return Err(RuntimeNetError::InvalidEffectState(record.phase));
            }
            candidate.terminalize(token.effect, NetEffectPhase::Completed)
        })
    }

    /// Commits a guest result after the exact ready branch is terminal.
    ///
    /// The returned ticket is a separate one-shot `GuestReply` obligation.
    pub fn commit_guest_reply(
        &mut self,
        binding: RuntimeNetBindingToken,
        syscall: RuntimeNetEffectToken,
        ready: ReadyCommitReceipt,
        result: i64,
    ) -> Result<GuestReplyTicket, RuntimeNetError> {
        self.transaction(|candidate| {
            candidate.commit_guest_reply_inner(binding, syscall, ready, result)
        })
    }

    fn commit_guest_reply_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        syscall: RuntimeNetEffectToken,
        ready: ReadyCommitReceipt,
        result: i64,
    ) -> Result<GuestReplyTicket, RuntimeNetError> {
        let record = *self.validate_service_effect(binding, syscall, NetEffectKind::Syscall)?;
        self.validate_ready_receipt(ready)?;
        if record.phase != NetEffectPhase::Prepared {
            return Err(if record.phase == NetEffectPhase::Committed {
                RuntimeNetError::AlreadyCommitted
            } else {
                RuntimeNetError::InvalidEffectState(record.phase)
            });
        }
        if self.has_live_children(syscall.effect) {
            return Err(RuntimeNetError::LiveDescendants);
        }
        let readiness = self.effect_record(ready.effect)?;
        let network = readiness
            .token
            .parent
            .ok_or(RuntimeNetError::InvalidReadyReceipt)?;
        if self.effect_record(network)?.token.parent != Some(syscall.effect) {
            return Err(RuntimeNetError::InvalidReadyReceipt);
        }
        let commit_sequence = self.take_commit_sequence()?;
        let ticket_sequence = self.take_publication_sequence()?;
        let ticket = GuestReplyTicket {
            scope: syscall.scope,
            effect: syscall.effect,
            ready_effect: ready.effect,
            ready_sequence: ready.sequence,
            commit_sequence,
            ticket_sequence,
            result,
        };
        let effect = self.effect_record_mut(syscall.effect)?;
        effect.phase = NetEffectPhase::Committed;
        effect.commit_sequence = Some(commit_sequence);
        effect.publication = Some(ticket);
        self.bump_domain_revision(syscall.scope, NetDomain::Personality)?;
        Ok(ticket)
    }

    /// Publishes one committed guest reply and returns its control credit.
    pub fn publish_guest_reply(&mut self, ticket: GuestReplyTicket) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| candidate.publish_guest_reply_inner(ticket))
    }

    fn publish_guest_reply_inner(
        &mut self,
        ticket: GuestReplyTicket,
    ) -> Result<(), RuntimeNetError> {
        let record = *self.effect_record(ticket.effect)?;
        if record.token.scope != ticket.scope
            || record.token.kind != NetEffectKind::Syscall
            || record.commit_sequence != Some(ticket.commit_sequence)
        {
            return Err(RuntimeNetError::InvalidPublication);
        }
        if record.phase.is_terminal() && record.publication.is_none() {
            return Err(RuntimeNetError::AlreadyPublished);
        }
        if record.phase != NetEffectPhase::Committed || record.publication != Some(ticket) {
            return Err(RuntimeNetError::InvalidPublication);
        }
        if self.has_live_children(ticket.effect) {
            return Err(RuntimeNetError::LiveDescendants);
        }
        let ready = record
            .publication
            .ok_or(RuntimeNetError::InvalidPublication)?;
        let ready_record = self.effect_record(ready.ready_effect)?;
        if ready_record
            .ready_receipt
            .is_none_or(|receipt| receipt.sequence != ready.ready_sequence)
        {
            return Err(RuntimeNetError::InvalidPublication);
        }
        let closing = self.scope_record(ticket.scope)?.state == ScopeState::Closing;
        let effect = self.effect_record_mut(ticket.effect)?;
        effect.publication = None;
        effect.guest_published = true;
        self.terminalize(ticket.effect, NetEffectPhase::Completed)?;
        let scope = self.scope_record_mut(ticket.scope)?;
        scope.guest_replies = scope
            .guest_replies
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        if closing {
            self.record_closure_step(ticket.scope)?;
        }
        Ok(())
    }

    /// Fences one crashed service and captures its uncommitted orphan cohort.
    pub fn crash(&mut self, binding: RuntimeNetBindingToken) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| candidate.crash_inner(binding))
    }

    fn crash_inner(&mut self, binding: RuntimeNetBindingToken) -> Result<(), RuntimeNetError> {
        self.validate_binding(binding)?;
        let effects = self.scope_record(binding.scope)?.effects.clone();
        let cohort: BTreeSet<_> = effects
            .into_iter()
            .filter(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    record.token.kind.domain() == binding.domain && record.phase.is_uncommitted()
                })
            })
            .collect();
        let domain = self
            .scope_record(binding.scope)?
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        let binding_epoch = NetBindingEpoch::new(
            domain
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(RuntimeNetError::CounterOverflow)?,
        );
        let domain = self
            .scope_record_mut(binding.scope)?
            .domains
            .get_mut(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        domain.binding_epoch = binding_epoch;
        domain.service = None;
        domain.fallback = NetFallbackState::Required;
        domain.recovery_cohort = cohort;
        domain.ready = None;
        domain.revision = domain
            .revision
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(())
    }

    /// Selects kernel fallback for one crashed service domain.
    pub fn fallback_pick(
        &mut self,
        scope: ScopeId,
        domain: NetDomain,
    ) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| {
            let scope_record = candidate.scope_record(scope)?;
            if scope_record.state != ScopeState::Active {
                return Err(RuntimeNetError::InvalidScopeState(scope_record.state));
            }
            let record = scope_record
                .domains
                .get(&domain)
                .ok_or(RuntimeNetError::WrongDomain)?;
            if record.service.is_some() || record.fallback != NetFallbackState::Required {
                return Err(RuntimeNetError::FallbackUnavailable);
            }
            candidate
                .scope_record_mut(scope)?
                .domains
                .get_mut(&domain)
                .ok_or(RuntimeNetError::WrongDomain)?
                .fallback = NetFallbackState::Running;
            Ok(())
        })
    }

    /// Captures one exact domain-local recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: NetDomain,
        replacement: NetServiceId,
    ) -> Result<RuntimeNetRecoverySnapshot, RuntimeNetError> {
        self.make_recovery_snapshot(scope, domain, replacement)
    }

    /// Accepts replacement readiness only if the complete image is unchanged.
    pub fn ready(
        &mut self,
        snapshot: &RuntimeNetRecoverySnapshot,
    ) -> Result<RuntimeNetReadyToken, RuntimeNetError> {
        self.transaction(|candidate| {
            let current = candidate.make_recovery_snapshot(
                snapshot.scope,
                snapshot.domain,
                snapshot.replacement,
            )?;
            if current != *snapshot {
                return Err(RuntimeNetError::StaleRecoverySnapshot);
            }
            let ready_record = ReadyRecord::from_snapshot(snapshot);
            let domain = candidate
                .scope_record_mut(snapshot.scope)?
                .domains
                .get_mut(&snapshot.domain)
                .ok_or(RuntimeNetError::WrongDomain)?;
            domain.fallback = NetFallbackState::ReplacementReady;
            domain.ready = Some(ready_record);
            Ok(RuntimeNetReadyToken {
                snapshot: snapshot.clone(),
            })
        })
    }

    /// Installs a ready replacement without adopting any orphan effect.
    pub fn rebind(
        &mut self,
        ready: RuntimeNetReadyToken,
    ) -> Result<RuntimeNetBindingToken, RuntimeNetError> {
        self.transaction(|candidate| candidate.rebind_inner(ready))
    }

    fn rebind_inner(
        &mut self,
        ready: RuntimeNetReadyToken,
    ) -> Result<RuntimeNetBindingToken, RuntimeNetError> {
        let snapshot = ready.snapshot;
        let scope = self.scope_record(snapshot.scope)?;
        if scope.state != ScopeState::Active {
            return Err(RuntimeNetError::InvalidScopeState(scope.state));
        }
        let domain = scope
            .domains
            .get(&snapshot.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        let expected = ReadyRecord::from_snapshot(&snapshot);
        if domain.service.is_some()
            || domain.fallback != NetFallbackState::ReplacementReady
            || domain.ready.as_ref() != Some(&expected)
            || domain.binding_epoch != snapshot.binding_epoch
            || domain.revision != snapshot.domain_revision
            || scope.authority_epoch != snapshot.authority_epoch
            || scope.socket_generation != snapshot.socket_generation
            || scope.source_generation != snapshot.source_generation
        {
            return Err(RuntimeNetError::StaleRecoverySnapshot);
        }
        let binding = RuntimeNetBindingToken {
            scope: snapshot.scope,
            domain: snapshot.domain,
            service: snapshot.replacement,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
        };
        let domain = self
            .scope_record_mut(snapshot.scope)?
            .domains
            .get_mut(&snapshot.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        domain.service = Some(snapshot.replacement);
        domain.fallback = NetFallbackState::Standby;
        domain.ready = None;
        Ok(binding)
    }

    /// Returns the next unadopted effect for one rebound domain.
    pub fn recover_next(
        &self,
        binding: RuntimeNetBindingToken,
    ) -> Result<Option<RuntimeNetEffectToken>, RuntimeNetError> {
        self.validate_binding(binding)?;
        let domain = self
            .scope_record(binding.scope)?
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        let Some(effect) = domain.recovery_cohort.first() else {
            return Ok(None);
        };
        Ok(Some(self.effect_record(*effect)?.token))
    }

    /// Explicitly transfers one uncommitted orphan to a replacement binding.
    pub fn adopt(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<RuntimeNetEffectToken, RuntimeNetError> {
        self.transaction(|candidate| candidate.adopt_inner(binding, token))
    }

    fn adopt_inner(
        &mut self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
    ) -> Result<RuntimeNetEffectToken, RuntimeNetError> {
        self.validate_binding(binding)?;
        let record = *self.validate_effect_identity(token)?;
        if record.token.scope != binding.scope
            || record.token.kind.domain() != binding.domain
            || !record.phase.is_uncommitted()
        {
            return Err(RuntimeNetError::NotAdoptable);
        }
        let domain = self
            .scope_record(binding.scope)?
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        if !domain.recovery_cohort.contains(&token.effect)
            || token.binding_epoch == domain.binding_epoch
        {
            return Err(RuntimeNetError::NotAdoptable);
        }
        let mut adopted = token;
        adopted.binding_epoch = domain.binding_epoch;
        self.effect_record_mut(token.effect)?.token = adopted;
        let domain = self
            .scope_record_mut(binding.scope)?
            .domains
            .get_mut(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        domain.recovery_cohort.remove(&token.effect);
        domain.revision = domain
            .revision
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(adopted)
    }

    /// Closes the root authority gate and freezes the exact live cohort.
    pub fn revoke_begin(
        &mut self,
        scope: ScopeId,
    ) -> Result<RuntimeNetRevokeTicket, RuntimeNetError> {
        self.transaction(|candidate| candidate.revoke_begin_inner(scope))
    }

    fn revoke_begin_inner(
        &mut self,
        scope: ScopeId,
    ) -> Result<RuntimeNetRevokeTicket, RuntimeNetError> {
        let (closed_epoch, effects) = {
            let record = self.scope_record(scope)?;
            if record.state != ScopeState::Active {
                return Err(RuntimeNetError::InvalidScopeState(record.state));
            }
            (record.authority_epoch, record.effects.clone())
        };
        let authority_epoch = NetAuthorityEpoch::new(
            closed_epoch
                .get()
                .checked_add(1)
                .ok_or(RuntimeNetError::CounterOverflow)?,
        );
        let sequence = self.next_revoke_sequence;
        self.next_revoke_sequence = self
            .next_revoke_sequence
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        let frozen: BTreeSet<_> = effects
            .iter()
            .copied()
            .filter(|effect| {
                self.effects
                    .get(effect)
                    .is_some_and(|record| !record.phase.is_terminal())
            })
            .collect();
        let ticket = RuntimeNetRevokeTicket {
            scope,
            sequence,
            closed_epoch,
            authority_epoch,
        };
        let scope_record = self.scope_record_mut(scope)?;
        scope_record.state = ScopeState::Closing;
        scope_record.authority_epoch = authority_epoch;
        scope_record.revocation = Some(RevocationRecord {
            ticket,
            frozen,
            closure_steps: 0,
        });
        for domain in scope_record.domains.values_mut() {
            domain.ready = None;
            domain.recovery_cohort.clear();
            if domain.fallback == NetFallbackState::ReplacementReady {
                domain.fallback = NetFallbackState::Running;
            }
        }
        Ok(ticket)
    }

    /// Executes or exposes one deterministic child-first closure step.
    pub fn revoke_next(
        &mut self,
        ticket: RuntimeNetRevokeTicket,
    ) -> Result<Option<RuntimeNetClosureStep>, RuntimeNetError> {
        self.transaction(|candidate| candidate.revoke_next_inner(ticket))
    }

    fn revoke_next_inner(
        &mut self,
        ticket: RuntimeNetRevokeTicket,
    ) -> Result<Option<RuntimeNetClosureStep>, RuntimeNetError> {
        let frozen = self.validate_revoke_ticket(ticket)?.frozen.clone();
        let leaves = self.live_leaves(ticket.scope, &frozen)?;
        let Some(effect) = leaves.first().copied() else {
            return Ok(None);
        };
        let record = *self.effect_record(effect)?;
        if record.token.kind == NetEffectKind::Syscall && record.phase == NetEffectPhase::Committed
        {
            let publication = record
                .publication
                .ok_or(RuntimeNetError::InvariantViolation(
                    "committed syscall lacks publication ticket",
                ))?;
            return Ok(Some(RuntimeNetClosureStep::AwaitingGuestReply(publication)));
        }
        let terminal = if record.phase == NetEffectPhase::Committed {
            if record.token.kind == NetEffectKind::BufferLease {
                self.scope_record_mut(record.token.scope)?
                    .buffers
                    .remove(&effect)
                    .ok_or(RuntimeNetError::InvalidBufferLease)?;
            }
            if record.token.kind == NetEffectKind::ReadinessWait {
                let scope = self.scope_record_mut(record.token.scope)?;
                scope.ready_deliveries = scope
                    .ready_deliveries
                    .checked_add(1)
                    .ok_or(RuntimeNetError::CounterOverflow)?;
            }
            NetEffectPhase::Completed
        } else if record.phase.is_uncommitted() {
            NetEffectPhase::Aborted
        } else {
            return Err(RuntimeNetError::InvalidEffectState(record.phase));
        };
        self.terminalize(effect, terminal)?;
        self.record_closure_step(ticket.scope)?;
        Ok(Some(if terminal == NetEffectPhase::Completed {
            RuntimeNetClosureStep::Drained(effect)
        } else {
            RuntimeNetClosureStep::Aborted(effect)
        }))
    }

    /// Publishes `Revoked` only after all frozen effects and credits close.
    pub fn revoke_complete(
        &mut self,
        ticket: RuntimeNetRevokeTicket,
    ) -> Result<(), RuntimeNetError> {
        self.transaction(|candidate| candidate.revoke_complete_inner(ticket))
    }

    fn revoke_complete_inner(
        &mut self,
        ticket: RuntimeNetRevokeTicket,
    ) -> Result<(), RuntimeNetError> {
        let revocation = self.validate_revoke_ticket(ticket)?;
        let scope = self.scope_record(ticket.scope)?;
        let all_terminal = revocation.frozen.iter().all(|effect| {
            self.effects
                .get(effect)
                .is_some_and(|record| record.phase.is_terminal())
        });
        let pending_publications = revocation.frozen.iter().any(|effect| {
            self.effects
                .get(effect)
                .is_some_and(|record| record.publication.is_some())
        });
        if !all_terminal
            || pending_publications
            || !scope.buffers.is_empty()
            || scope.free_credits != scope.initial_credits
            || revocation.closure_steps != revocation.frozen.len()
        {
            return Err(RuntimeNetError::NotQuiescent);
        }
        self.scope_record_mut(ticket.scope)?.state = ScopeState::Revoked;
        Ok(())
    }
}
