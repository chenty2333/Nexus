use alloc::collections::{BTreeMap, BTreeSet};

use super::*;

impl Default for RuntimeFsModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeFsModel {
    /// Creates an empty runtime-filesystem oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_effect: 1,
            next_commit_sequence: 1,
            next_publication_sequence: 1,
            next_revoke_sequence: 1,
            next_tombstone: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
        }
    }

    /// Creates one active root scope with four independently restartable domains.
    pub fn create_scope(
        &mut self,
        services: RuntimeFsServices,
        credits: FsCredits,
    ) -> Result<(ScopeId, RuntimeFsBindings), RuntimeFsError> {
        self.transaction(|candidate| candidate.create_scope_inner(services, credits))
    }

    fn create_scope_inner(
        &mut self,
        services: RuntimeFsServices,
        credits: FsCredits,
    ) -> Result<(ScopeId, RuntimeFsBindings), RuntimeFsError> {
        for class in [
            FsCreditClass::Control,
            FsCreditClass::Memory,
            FsCreditClass::Filesystem,
            FsCreditClass::Dma,
        ] {
            if credits.get(class) == 0 {
                return Err(RuntimeFsError::CreditExhausted(class));
            }
        }
        let service_set: BTreeSet<_> = FsDomain::ALL
            .into_iter()
            .map(|domain| services.get(domain))
            .collect();
        if service_set.len() != FsDomain::ALL.len()
            || service_set.iter().any(|service| service.get() == 0)
        {
            return Err(RuntimeFsError::WrongService);
        }

        let scope = ScopeId::new(self.next_scope);
        self.next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);
        let mut domains = BTreeMap::new();
        for domain in FsDomain::ALL {
            domains.insert(
                domain,
                DomainRecord {
                    binding_epoch,
                    service: Some(services.get(domain)),
                    fallback: FsFallbackState::Standby,
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
                address_space_generation: AddressSpaceGeneration::new(1),
                inode_generation: InodeGeneration::new(1),
                device_generation: DeviceGeneration::new(1),
                domains,
                initial_credits: credits,
                free_credits: credits,
                effects: BTreeSet::new(),
                inode_version: 0,
                inode_word: 0,
                mapping_publications: 0,
                pwrite_publications: 0,
                avail_index: 0,
                reply_publications: 0,
                revocation: None,
            },
        );
        let binding = |domain| RuntimeFsBindingToken {
            scope,
            domain,
            service: services.get(domain),
            authority_epoch,
            binding_epoch,
        };
        Ok((
            scope,
            RuntimeFsBindings {
                personality: binding(FsDomain::Personality),
                pager: binding(FsDomain::Pager),
                filesystem: binding(FsDomain::Filesystem),
                block: binding(FsDomain::Block),
            },
        ))
    }

    /// Failure-atomically registers the fixed four-effect `pwrite64` graph.
    pub fn register_pwrite(
        &mut self,
        bindings: RuntimeFsBindings,
    ) -> Result<RuntimeFsToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.register_pwrite_inner(bindings))
    }

    fn register_pwrite_inner(
        &mut self,
        bindings: RuntimeFsBindings,
    ) -> Result<RuntimeFsToken, RuntimeFsError> {
        let personality = bindings.get(FsDomain::Personality);
        let scope = personality.scope;
        for domain in FsDomain::ALL {
            let binding = bindings.get(domain);
            if binding.scope != scope || binding.domain != domain {
                return Err(RuntimeFsError::WrongDomain);
            }
            self.validate_binding(binding)?;
        }
        let scope_record = self.scope_record(scope)?;
        if !scope_record.free_credits.contains(FsCredits::ONE_REQUEST) {
            let exhausted = [
                FsCreditClass::Control,
                FsCreditClass::Memory,
                FsCreditClass::Filesystem,
                FsCreditClass::Dma,
            ]
            .into_iter()
            .find(|class| scope_record.free_credits.get(*class) == 0)
            .unwrap_or(FsCreditClass::Control);
            return Err(RuntimeFsError::CreditExhausted(exhausted));
        }
        let authority_epoch = scope_record.authority_epoch;
        let address_space_generation = scope_record.address_space_generation;
        let inode_generation = scope_record.inode_generation;
        let device_generation = scope_record.device_generation;
        let free = scope_record
            .free_credits
            .checked_sub(FsCredits::ONE_REQUEST)
            .ok_or(RuntimeFsError::InvariantViolation(
                "registration credit underflow",
            ))?;

        let syscall_id = self.take_effect_id()?;
        let pager_id = self.take_effect_id()?;
        let filesystem_id = self.take_effect_id()?;
        let block_id = self.take_effect_id()?;
        let make_token =
            |effect, parent, kind, binding: RuntimeFsBindingToken| RuntimeFsEffectToken {
                scope,
                effect,
                parent,
                kind,
                authority_epoch,
                binding_epoch: binding.binding_epoch,
                address_space_generation,
                inode_generation,
                device_generation,
            };
        let token = RuntimeFsToken {
            syscall: make_token(
                syscall_id,
                None,
                FsEffectKind::Syscall,
                bindings.get(FsDomain::Personality),
            ),
            pager: make_token(
                pager_id,
                Some(syscall_id),
                FsEffectKind::PagerMap,
                bindings.get(FsDomain::Pager),
            ),
            filesystem: make_token(
                filesystem_id,
                Some(syscall_id),
                FsEffectKind::FsOperation,
                bindings.get(FsDomain::Filesystem),
            ),
            block: make_token(
                block_id,
                Some(filesystem_id),
                FsEffectKind::BlockRequest,
                bindings.get(FsDomain::Block),
            ),
        };

        for effect_token in [token.syscall, token.pager, token.filesystem, token.block] {
            self.effects.insert(
                effect_token.effect,
                EffectRecord {
                    token: effect_token,
                    phase: FsEffectPhase::Registered,
                    credit: effect_token.kind.credit(),
                    commit_sequence: None,
                    terminalizations: 0,
                    dma_state: if effect_token.kind == FsEffectKind::BlockRequest {
                        FsDmaState::Reserved
                    } else {
                        FsDmaState::NotApplicable
                    },
                    dma_attempt: 0,
                    device_completed: false,
                    block_receipt: None,
                    publication: None,
                    tombstone: None,
                },
            );
        }
        let scope_record = self.scope_record_mut(scope)?;
        scope_record.free_credits = free;
        scope_record
            .effects
            .extend([syscall_id, pager_id, filesystem_id, block_id]);
        for domain in FsDomain::ALL {
            self.bump_domain_revision(scope, domain)?;
        }
        Ok(token)
    }

    /// Prepares the syscall continuation without publishing a guest result.
    pub fn prepare_syscall(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.prepare_effect(binding, token, FsEffectKind::Syscall)
    }

    /// Prepares the pager mapping without publishing a PTE.
    pub fn prepare_pager_map(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.prepare_effect(binding, token, FsEffectKind::PagerMap)
    }

    /// Prepares the filesystem operation without changing inode contents.
    pub fn prepare_filesystem(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.prepare_effect(binding, token, FsEffectKind::FsOperation)
    }

    /// Prepares the block request and installs its retained DMA mapping.
    pub fn prepare_block(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.prepare_effect(binding, token, FsEffectKind::BlockRequest)
    }

    fn prepare_effect(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
        kind: FsEffectKind,
    ) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| candidate.prepare_effect_inner(binding, token, kind))
    }

    fn prepare_effect_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
        kind: FsEffectKind,
    ) -> Result<(), RuntimeFsError> {
        let record = *self.validate_service_effect(binding, token, kind)?;
        self.validate_generation(token)?;
        if record.phase != FsEffectPhase::Registered {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        let target = self.effect_record_mut(token.effect)?;
        target.phase = FsEffectPhase::Prepared;
        if kind == FsEffectKind::BlockRequest {
            if target.dma_state != FsDmaState::Reserved {
                return Err(RuntimeFsError::InvalidDmaState(target.dma_state));
            }
            target.dma_state = FsDmaState::Mapped;
        }
        self.bump_domain_revision(token.scope, kind.domain())
    }

    /// Atomically publishes the pager PTE and local TLB synchronization receipt.
    pub fn commit_pager_map(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<PagerMapReceipt, RuntimeFsError> {
        self.transaction(|candidate| candidate.commit_pager_map_inner(binding, token))
    }

    fn commit_pager_map_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<PagerMapReceipt, RuntimeFsError> {
        let record = *self.validate_service_effect(binding, token, FsEffectKind::PagerMap)?;
        self.validate_generation(token)?;
        if record.phase != FsEffectPhase::Prepared {
            return Err(if record.phase == FsEffectPhase::Committed {
                RuntimeFsError::AlreadyCommitted
            } else {
                RuntimeFsError::InvalidEffectState(record.phase)
            });
        }
        let generation = AddressSpaceGeneration::new(
            self.scope_record(token.scope)?
                .address_space_generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeFsError::CounterOverflow)?,
        );
        let sequence = self.take_commit_sequence()?;
        let scope = self.scope_record_mut(token.scope)?;
        scope.address_space_generation = generation;
        scope.mapping_publications = scope
            .mapping_publications
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let effect = self.effect_record_mut(token.effect)?;
        effect.phase = FsEffectPhase::Committed;
        effect.commit_sequence = Some(sequence);
        self.bump_domain_revision(token.scope, FsDomain::Pager)?;
        Ok(PagerMapReceipt {
            effect: token.effect,
            sequence,
            generation,
        })
    }

    /// Atomically publishes the bounded inode word `b"xy"` and advances its generation.
    pub fn commit_pwrite(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<PwriteReceipt, RuntimeFsError> {
        self.transaction(|candidate| candidate.commit_pwrite_inner(binding, token))
    }

    fn commit_pwrite_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<PwriteReceipt, RuntimeFsError> {
        let record = *self.validate_service_effect(binding, token, FsEffectKind::FsOperation)?;
        self.validate_generation(token)?;
        if record.phase != FsEffectPhase::Prepared {
            return Err(if record.phase == FsEffectPhase::Committed {
                RuntimeFsError::AlreadyCommitted
            } else {
                RuntimeFsError::InvalidEffectState(record.phase)
            });
        }
        let parent = record
            .token
            .parent
            .ok_or(RuntimeFsError::InvariantViolation(
                "filesystem effect lacks syscall",
            ))?;
        if self.effect_record(parent)?.phase != FsEffectPhase::Prepared {
            return Err(RuntimeFsError::InvalidEffectState(
                self.effect_record(parent)?.phase,
            ));
        }
        let generation = InodeGeneration::new(
            self.scope_record(token.scope)?
                .inode_generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeFsError::CounterOverflow)?,
        );
        let version = self
            .scope_record(token.scope)?
            .inode_version
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let sequence = self.take_commit_sequence()?;
        let scope = self.scope_record_mut(token.scope)?;
        scope.inode_generation = generation;
        scope.inode_version = version;
        scope.inode_word = 0x0000_7879;
        scope.pwrite_publications = scope
            .pwrite_publications
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let effect = self.effect_record_mut(token.effect)?;
        effect.phase = FsEffectPhase::Committed;
        effect.commit_sequence = Some(sequence);
        self.bump_domain_revision(token.scope, FsDomain::Filesystem)?;
        Ok(PwriteReceipt {
            effect: token.effect,
            sequence,
            generation,
            version,
            word: 0x0000_7879,
        })
    }

    /// Release-publishes the mediated block request's abstract `avail.idx`.
    pub fn commit_block(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<BlockCommitReceipt, RuntimeFsError> {
        self.transaction(|candidate| candidate.commit_block_inner(binding, token))
    }

    fn commit_block_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<BlockCommitReceipt, RuntimeFsError> {
        let record = *self.validate_service_effect(binding, token, FsEffectKind::BlockRequest)?;
        self.validate_generation(token)?;
        if record.phase != FsEffectPhase::Prepared {
            return Err(if record.phase == FsEffectPhase::Committed {
                RuntimeFsError::AlreadyCommitted
            } else {
                RuntimeFsError::InvalidEffectState(record.phase)
            });
        }
        if record.dma_state != FsDmaState::Mapped {
            return Err(RuntimeFsError::InvalidDmaState(record.dma_state));
        }
        let parent = record
            .token
            .parent
            .ok_or(RuntimeFsError::InvariantViolation(
                "block effect lacks filesystem",
            ))?;
        if self.effect_record(parent)?.phase != FsEffectPhase::Committed {
            return Err(RuntimeFsError::InvalidEffectState(
                self.effect_record(parent)?.phase,
            ));
        }
        let sequence = self.take_commit_sequence()?;
        let avail_index = self
            .scope_record(token.scope)?
            .avail_index
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let device_generation = self.scope_record(token.scope)?.device_generation;
        let receipt = BlockCommitReceipt {
            effect: token.effect,
            sequence,
            device_generation,
            avail_index,
        };
        self.scope_record_mut(token.scope)?.avail_index = avail_index;
        let effect = self.effect_record_mut(token.effect)?;
        effect.phase = FsEffectPhase::Committed;
        effect.commit_sequence = Some(sequence);
        effect.block_receipt = Some(receipt);
        self.bump_domain_revision(token.scope, FsDomain::Block)?;
        Ok(receipt)
    }

    /// Accepts one exact current-generation device completion and starts IOTLB closure.
    pub fn observe_block_completion(
        &mut self,
        receipt: BlockCommitReceipt,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.observe_block_completion_inner(receipt))
    }

    fn observe_block_completion_inner(
        &mut self,
        receipt: BlockCommitReceipt,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        let record = *self.effect_record(receipt.effect)?;
        if record.token.kind != FsEffectKind::BlockRequest || record.block_receipt != Some(receipt)
        {
            return Err(RuntimeFsError::EffectIdentityMismatch);
        }
        let scope = self.scope_record(record.token.scope)?;
        if receipt.device_generation != scope.device_generation {
            return Err(RuntimeFsError::StaleDeviceGeneration {
                presented: receipt.device_generation,
                current: scope.device_generation,
            });
        }
        if record.phase != FsEffectPhase::Committed {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        if record.device_completed {
            return Err(RuntimeFsError::AlreadyCompleted);
        }
        if record.dma_state != FsDmaState::Mapped {
            return Err(RuntimeFsError::InvalidDmaState(record.dma_state));
        }
        let attempt = record
            .dma_attempt
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let effect = self.effect_record_mut(receipt.effect)?;
        effect.device_completed = true;
        effect.dma_state = FsDmaState::IotlbInFlight;
        effect.dma_attempt = attempt;
        self.bump_domain_revision(record.token.scope, FsDomain::Block)?;
        let revoke_sequence = self
            .scope_record(record.token.scope)?
            .revocation
            .as_ref()
            .map_or(0, |revocation| revocation.ticket.sequence);
        Ok(FsDmaRecoveryToken {
            scope: record.token.scope,
            effect: receipt.effect,
            revoke_sequence,
            attempt,
            device_generation: receipt.device_generation,
            kind: FsDmaRecoveryKind::Iotlb,
        })
    }

    /// Completes a committed pager effect after its mapping obligation is stable.
    pub fn complete_pager_map(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| {
            let record =
                *candidate.validate_service_effect(binding, token, FsEffectKind::PagerMap)?;
            if record.phase != FsEffectPhase::Committed {
                return Err(RuntimeFsError::InvalidEffectState(record.phase));
            }
            candidate.terminalize(token.effect, FsEffectPhase::Completed)
        })
    }

    /// Completes a committed filesystem effect after its block child is terminal.
    pub fn complete_filesystem(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| {
            let record =
                *candidate.validate_service_effect(binding, token, FsEffectKind::FsOperation)?;
            if record.phase != FsEffectPhase::Committed {
                return Err(RuntimeFsError::InvalidEffectState(record.phase));
            }
            candidate.terminalize(token.effect, FsEffectPhase::Completed)
        })
    }

    /// Commits the Linux syscall result after both causal branches are terminal.
    ///
    /// The returned ticket is an independent one-shot publication obligation.
    pub fn commit_syscall_reply(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
        result: i64,
    ) -> Result<FsPublicationTicket, RuntimeFsError> {
        self.transaction(|candidate| candidate.commit_syscall_reply_inner(binding, token, result))
    }

    fn commit_syscall_reply_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
        result: i64,
    ) -> Result<FsPublicationTicket, RuntimeFsError> {
        let record = *self.validate_service_effect(binding, token, FsEffectKind::Syscall)?;
        if record.phase != FsEffectPhase::Prepared {
            return Err(if record.phase == FsEffectPhase::Committed {
                RuntimeFsError::AlreadyCommitted
            } else {
                RuntimeFsError::InvalidEffectState(record.phase)
            });
        }
        if self.has_live_children(token.effect) {
            return Err(RuntimeFsError::LiveDescendants);
        }
        let commit_sequence = self.take_commit_sequence()?;
        let ticket_sequence = self.take_publication_sequence()?;
        let ticket = FsPublicationTicket {
            scope: token.scope,
            effect: token.effect,
            commit_sequence,
            ticket_sequence,
            result,
        };
        let effect = self.effect_record_mut(token.effect)?;
        effect.phase = FsEffectPhase::Committed;
        effect.commit_sequence = Some(commit_sequence);
        effect.publication = Some(ticket);
        self.bump_domain_revision(token.scope, FsDomain::Personality)?;
        Ok(ticket)
    }

    /// Publishes one committed guest reply and returns its control credit.
    pub fn publish_reply(&mut self, ticket: FsPublicationTicket) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| candidate.publish_reply_inner(ticket))
    }

    fn publish_reply_inner(&mut self, ticket: FsPublicationTicket) -> Result<(), RuntimeFsError> {
        let record = *self.effect_record(ticket.effect)?;
        if record.token.scope != ticket.scope
            || record.token.kind != FsEffectKind::Syscall
            || record.commit_sequence != Some(ticket.commit_sequence)
        {
            return Err(RuntimeFsError::InvalidPublication);
        }
        if record.phase.is_terminal() && record.publication.is_none() {
            return Err(RuntimeFsError::AlreadyPublished);
        }
        if record.phase != FsEffectPhase::Committed || record.publication != Some(ticket) {
            return Err(RuntimeFsError::InvalidPublication);
        }
        if self.has_live_children(ticket.effect) {
            return Err(RuntimeFsError::LiveDescendants);
        }
        let closing = self.scope_record(ticket.scope)?.state == ScopeState::Closing;
        self.terminalize(ticket.effect, FsEffectPhase::Completed)?;
        let scope = self.scope_record_mut(ticket.scope)?;
        scope.reply_publications = scope
            .reply_publications
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        if closing {
            self.record_closure_step(ticket.scope)?;
        }
        Ok(())
    }

    /// Fences one crashed service and captures only its uncommitted orphan work.
    pub fn crash(&mut self, binding: RuntimeFsBindingToken) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| candidate.crash_inner(binding))
    }

    fn crash_inner(&mut self, binding: RuntimeFsBindingToken) -> Result<(), RuntimeFsError> {
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
            .ok_or(RuntimeFsError::WrongDomain)?;
        let binding_epoch = BindingEpoch::new(
            domain
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(RuntimeFsError::CounterOverflow)?,
        );
        let domain = self
            .scope_record_mut(binding.scope)?
            .domains
            .get_mut(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        domain.binding_epoch = binding_epoch;
        domain.service = None;
        domain.fallback = FsFallbackState::Required;
        domain.recovery_cohort = cohort;
        domain.ready = None;
        domain.revision = domain
            .revision
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(())
    }

    /// Selects kernel fallback for one crashed service domain.
    pub fn fallback_pick(
        &mut self,
        scope: ScopeId,
        domain: FsDomain,
    ) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| {
            let scope_record = candidate.scope_record(scope)?;
            if scope_record.state != ScopeState::Active {
                return Err(RuntimeFsError::InvalidScopeState(scope_record.state));
            }
            let record = scope_record
                .domains
                .get(&domain)
                .ok_or(RuntimeFsError::WrongDomain)?;
            if record.service.is_some() || record.fallback != FsFallbackState::Required {
                return Err(RuntimeFsError::FallbackUnavailable);
            }
            candidate
                .scope_record_mut(scope)?
                .domains
                .get_mut(&domain)
                .ok_or(RuntimeFsError::WrongDomain)?
                .fallback = FsFallbackState::Running;
            Ok(())
        })
    }

    /// Captures one exact domain-local recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: FsDomain,
        replacement: ServiceId,
    ) -> Result<RuntimeFsRecoverySnapshot, RuntimeFsError> {
        self.make_recovery_snapshot(scope, domain, replacement)
    }

    /// Accepts replacement readiness only if the complete image is unchanged.
    pub fn ready(
        &mut self,
        snapshot: &RuntimeFsRecoverySnapshot,
    ) -> Result<RuntimeFsReadyToken, RuntimeFsError> {
        self.transaction(|candidate| {
            let current = candidate.make_recovery_snapshot(
                snapshot.scope,
                snapshot.domain,
                snapshot.replacement,
            )?;
            if current != *snapshot {
                return Err(RuntimeFsError::StaleRecoverySnapshot);
            }
            let ready_record = ReadyRecord::from_snapshot(snapshot);
            let domain = candidate
                .scope_record_mut(snapshot.scope)?
                .domains
                .get_mut(&snapshot.domain)
                .ok_or(RuntimeFsError::WrongDomain)?;
            domain.fallback = FsFallbackState::ReplacementReady;
            domain.ready = Some(ready_record);
            Ok(RuntimeFsReadyToken {
                snapshot: snapshot.clone(),
            })
        })
    }

    /// Installs a ready replacement without adopting any orphan effect.
    pub fn rebind(
        &mut self,
        ready: RuntimeFsReadyToken,
    ) -> Result<RuntimeFsBindingToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.rebind_inner(ready))
    }

    fn rebind_inner(
        &mut self,
        ready: RuntimeFsReadyToken,
    ) -> Result<RuntimeFsBindingToken, RuntimeFsError> {
        let snapshot = ready.snapshot;
        let scope = self.scope_record(snapshot.scope)?;
        if scope.state != ScopeState::Active {
            return Err(RuntimeFsError::InvalidScopeState(scope.state));
        }
        let domain = scope
            .domains
            .get(&snapshot.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        let expected = ReadyRecord::from_snapshot(&snapshot);
        if domain.service.is_some()
            || domain.fallback != FsFallbackState::ReplacementReady
            || domain.ready.as_ref() != Some(&expected)
            || domain.binding_epoch != snapshot.binding_epoch
            || domain.revision != snapshot.domain_revision
            || scope.authority_epoch != snapshot.authority_epoch
            || scope.address_space_generation != snapshot.address_space_generation
            || scope.inode_generation != snapshot.inode_generation
            || scope.device_generation != snapshot.device_generation
        {
            return Err(RuntimeFsError::StaleRecoverySnapshot);
        }
        let binding = RuntimeFsBindingToken {
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
            .ok_or(RuntimeFsError::WrongDomain)?;
        domain.service = Some(snapshot.replacement);
        domain.fallback = FsFallbackState::Standby;
        domain.ready = None;
        Ok(binding)
    }

    /// Returns the next unadopted effect for one rebound domain.
    pub fn recover_next(
        &self,
        binding: RuntimeFsBindingToken,
    ) -> Result<Option<RuntimeFsEffectToken>, RuntimeFsError> {
        self.validate_binding(binding)?;
        let domain = self
            .scope_record(binding.scope)?
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        let Some(effect) = domain.recovery_cohort.first() else {
            return Ok(None);
        };
        Ok(Some(self.effect_record(*effect)?.token))
    }

    /// Explicitly transfers one uncommitted orphan effect to a replacement binding.
    pub fn adopt(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<RuntimeFsEffectToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.adopt_inner(binding, token))
    }

    fn adopt_inner(
        &mut self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
    ) -> Result<RuntimeFsEffectToken, RuntimeFsError> {
        self.validate_binding(binding)?;
        let record = *self.validate_effect_identity(token)?;
        if record.token.scope != binding.scope
            || record.token.kind.domain() != binding.domain
            || !record.phase.is_uncommitted()
        {
            return Err(RuntimeFsError::NotAdoptable);
        }
        let domain = self
            .scope_record(binding.scope)?
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        if !domain.recovery_cohort.contains(&token.effect)
            || token.binding_epoch == domain.binding_epoch
        {
            return Err(RuntimeFsError::NotAdoptable);
        }
        let mut adopted = token;
        adopted.binding_epoch = domain.binding_epoch;
        self.effect_record_mut(token.effect)?.token = adopted;
        let domain = self
            .scope_record_mut(binding.scope)?
            .domains
            .get_mut(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        domain.recovery_cohort.remove(&token.effect);
        domain.revision = domain
            .revision
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(adopted)
    }

    /// Closes the root authority gate and freezes the exact live effect cohort.
    pub fn revoke_begin(
        &mut self,
        scope: ScopeId,
    ) -> Result<RuntimeFsRevokeTicket, RuntimeFsError> {
        self.transaction(|candidate| candidate.revoke_begin_inner(scope))
    }

    fn revoke_begin_inner(
        &mut self,
        scope: ScopeId,
    ) -> Result<RuntimeFsRevokeTicket, RuntimeFsError> {
        let (closed_epoch, effects) = {
            let record = self.scope_record(scope)?;
            if record.state != ScopeState::Active {
                return Err(RuntimeFsError::InvalidScopeState(record.state));
            }
            (record.authority_epoch, record.effects.clone())
        };
        let authority_epoch = AuthorityEpoch::new(
            closed_epoch
                .get()
                .checked_add(1)
                .ok_or(RuntimeFsError::CounterOverflow)?,
        );
        let sequence = self.next_revoke_sequence;
        self.next_revoke_sequence = self
            .next_revoke_sequence
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let frozen: BTreeSet<_> = effects
            .iter()
            .copied()
            .filter(|effect| {
                self.effects
                    .get(effect)
                    .is_some_and(|record| !record.phase.is_terminal())
            })
            .collect();
        let ticket = RuntimeFsRevokeTicket {
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
            if domain.fallback == FsFallbackState::ReplacementReady {
                domain.fallback = FsFallbackState::Running;
            }
        }
        Ok(ticket)
    }

    /// Executes or exposes one deterministic child-first closure step.
    pub fn revoke_next(
        &mut self,
        ticket: RuntimeFsRevokeTicket,
    ) -> Result<Option<RuntimeFsClosureStep>, RuntimeFsError> {
        self.transaction(|candidate| candidate.revoke_next_inner(ticket))
    }

    fn revoke_next_inner(
        &mut self,
        ticket: RuntimeFsRevokeTicket,
    ) -> Result<Option<RuntimeFsClosureStep>, RuntimeFsError> {
        let frozen = self.validate_revoke_ticket(ticket)?.frozen.clone();
        let leaves = self.live_leaves(ticket.scope, &frozen)?;
        let Some(effect) = leaves.first().copied() else {
            return Ok(None);
        };
        let record = *self.effect_record(effect)?;
        if record.token.kind == FsEffectKind::BlockRequest {
            return self.close_block_effect(ticket, record);
        }
        if record.token.kind == FsEffectKind::Syscall && record.phase == FsEffectPhase::Committed {
            let publication = record
                .publication
                .ok_or(RuntimeFsError::InvariantViolation(
                    "committed syscall lacks publication ticket",
                ))?;
            return Ok(Some(RuntimeFsClosureStep::AwaitingReply(publication)));
        }
        let terminal = if record.phase == FsEffectPhase::Committed {
            FsEffectPhase::Completed
        } else if record.phase.is_uncommitted() {
            FsEffectPhase::Aborted
        } else {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        };
        self.terminalize(effect, terminal)?;
        self.record_closure_step(ticket.scope)?;
        Ok(Some(if terminal == FsEffectPhase::Completed {
            RuntimeFsClosureStep::Completed(effect)
        } else {
            RuntimeFsClosureStep::Aborted(effect)
        }))
    }

    fn close_block_effect(
        &mut self,
        ticket: RuntimeFsRevokeTicket,
        record: EffectRecord,
    ) -> Result<Option<RuntimeFsClosureStep>, RuntimeFsError> {
        match (record.phase, record.dma_state) {
            (FsEffectPhase::Registered, FsDmaState::Reserved) => {
                self.effect_record_mut(record.token.effect)?.dma_state = FsDmaState::Released;
                self.terminalize(record.token.effect, FsEffectPhase::Aborted)?;
                self.record_closure_step(ticket.scope)?;
                Ok(Some(RuntimeFsClosureStep::Aborted(record.token.effect)))
            }
            (FsEffectPhase::Prepared, FsDmaState::Mapped) => {
                let recovery =
                    self.start_dma_recovery(ticket, record.token.effect, FsDmaRecoveryKind::Iotlb)?;
                Ok(Some(RuntimeFsClosureStep::NeedsDma(recovery)))
            }
            (FsEffectPhase::Committed, FsDmaState::Mapped) => {
                let recovery =
                    self.start_dma_recovery(ticket, record.token.effect, FsDmaRecoveryKind::Reset)?;
                Ok(Some(RuntimeFsClosureStep::NeedsDma(recovery)))
            }
            (FsEffectPhase::Prepared, FsDmaState::IotlbInFlight)
            | (FsEffectPhase::Committed, FsDmaState::IotlbInFlight) => {
                let recovery =
                    self.current_dma_token(ticket, record.token.effect, FsDmaRecoveryKind::Iotlb)?;
                Ok(Some(RuntimeFsClosureStep::AwaitingDma(recovery)))
            }
            (FsEffectPhase::Committed, FsDmaState::ResetInFlight) => {
                let recovery =
                    self.current_dma_token(ticket, record.token.effect, FsDmaRecoveryKind::Reset)?;
                Ok(Some(RuntimeFsClosureStep::AwaitingDma(recovery)))
            }
            (FsEffectPhase::Tombstoned, FsDmaState::ResetTimedOut)
            | (FsEffectPhase::Tombstoned, FsDmaState::IotlbTimedOut) => {
                let tombstone = record
                    .tombstone
                    .ok_or(RuntimeFsError::InvariantViolation(
                        "tombstoned block lacks tombstone",
                    ))?
                    .token;
                Ok(Some(RuntimeFsClosureStep::RetainedTombstone(tombstone)))
            }
            (_, FsDmaState::Released) if !record.phase.is_terminal() => {
                let terminal = if record.phase == FsEffectPhase::Committed {
                    FsEffectPhase::Completed
                } else {
                    FsEffectPhase::Aborted
                };
                self.terminalize(record.token.effect, terminal)?;
                self.record_closure_step(ticket.scope)?;
                Ok(Some(if terminal == FsEffectPhase::Completed {
                    RuntimeFsClosureStep::Completed(record.token.effect)
                } else {
                    RuntimeFsClosureStep::Aborted(record.token.effect)
                }))
            }
            _ => Err(RuntimeFsError::InvalidDmaState(record.dma_state)),
        }
    }

    fn start_dma_recovery(
        &mut self,
        ticket: RuntimeFsRevokeTicket,
        effect: EffectId,
        kind: FsDmaRecoveryKind,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        self.validate_revoke_ticket(ticket)?;
        let record = *self.effect_record(effect)?;
        if record.dma_state != FsDmaState::Mapped {
            return Err(RuntimeFsError::InvalidDmaState(record.dma_state));
        }
        if kind == FsDmaRecoveryKind::Reset && record.phase != FsEffectPhase::Committed {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        if kind == FsDmaRecoveryKind::Iotlb && record.phase != FsEffectPhase::Prepared {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        let attempt = record
            .dma_attempt
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let target = self.effect_record_mut(effect)?;
        target.dma_attempt = attempt;
        target.dma_state = match kind {
            FsDmaRecoveryKind::Reset => FsDmaState::ResetInFlight,
            FsDmaRecoveryKind::Iotlb => FsDmaState::IotlbInFlight,
        };
        self.bump_domain_revision(record.token.scope, FsDomain::Block)?;
        Ok(FsDmaRecoveryToken {
            scope: ticket.scope,
            effect,
            revoke_sequence: ticket.sequence,
            attempt,
            device_generation: self.scope_record(ticket.scope)?.device_generation,
            kind,
        })
    }

    /// Converts an in-flight reset or IOTLB operation into an honest tombstone.
    pub fn dma_timeout(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsTombstoneToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.dma_timeout_inner(recovery))
    }

    fn dma_timeout_inner(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsTombstoneToken, RuntimeFsError> {
        let record = *self.validate_dma_recovery(recovery)?;
        if self.scope_record(recovery.scope)?.state != ScopeState::Closing {
            return Err(RuntimeFsError::InvalidScopeState(
                self.scope_record(recovery.scope)?.state,
            ));
        }
        if record.tombstone.is_some() {
            return Err(RuntimeFsError::StaleDmaAttempt);
        }
        let tombstone = FsTombstoneToken {
            id: self.take_tombstone_id()?,
            scope: recovery.scope,
            effect: recovery.effect,
            revoke_sequence: recovery.revoke_sequence,
            attempt: recovery.attempt,
            device_generation: recovery.device_generation,
            kind: recovery.kind,
        };
        let target = self.effect_record_mut(recovery.effect)?;
        target.tombstone = Some(TombstoneRecord {
            token: tombstone,
            prior_phase: record.phase,
        });
        target.phase = FsEffectPhase::Tombstoned;
        target.dma_state = match recovery.kind {
            FsDmaRecoveryKind::Reset => FsDmaState::ResetTimedOut,
            FsDmaRecoveryKind::Iotlb => FsDmaState::IotlbTimedOut,
        };
        self.bump_domain_revision(recovery.scope, FsDomain::Block)?;
        Ok(tombstone)
    }

    /// Retries one exact retained tombstone without changing effect identity.
    pub fn retry_tombstone(
        &mut self,
        tombstone: FsTombstoneToken,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.retry_tombstone_inner(tombstone))
    }

    fn retry_tombstone_inner(
        &mut self,
        tombstone: FsTombstoneToken,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        let scope = self.scope_record(tombstone.scope)?;
        if scope.state != ScopeState::Closing
            || scope
                .revocation
                .as_ref()
                .is_none_or(|revocation| revocation.ticket.sequence != tombstone.revoke_sequence)
        {
            return Err(RuntimeFsError::StaleRevokeTicket);
        }
        if tombstone.device_generation != scope.device_generation {
            return Err(RuntimeFsError::StaleDeviceGeneration {
                presented: tombstone.device_generation,
                current: scope.device_generation,
            });
        }
        let record = *self.effect_record(tombstone.effect)?;
        let retained = record.tombstone.ok_or(RuntimeFsError::StaleTombstone)?;
        if retained.token != tombstone
            || record.phase != FsEffectPhase::Tombstoned
            || record.dma_attempt != tombstone.attempt
        {
            return Err(RuntimeFsError::StaleTombstone);
        }
        let attempt = tombstone
            .attempt
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        let target = self.effect_record_mut(tombstone.effect)?;
        target.phase = retained.prior_phase;
        target.dma_attempt = attempt;
        target.dma_state = match tombstone.kind {
            FsDmaRecoveryKind::Reset => FsDmaState::ResetInFlight,
            FsDmaRecoveryKind::Iotlb => FsDmaState::IotlbInFlight,
        };
        target.tombstone = None;
        self.bump_domain_revision(tombstone.scope, FsDomain::Block)?;
        Ok(FsDmaRecoveryToken {
            scope: tombstone.scope,
            effect: tombstone.effect,
            revoke_sequence: tombstone.revoke_sequence,
            attempt,
            device_generation: tombstone.device_generation,
            kind: tombstone.kind,
        })
    }

    /// Acknowledges reset, advances device generation, and starts IOTLB invalidation.
    pub fn acknowledge_reset(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        self.transaction(|candidate| candidate.acknowledge_reset_inner(recovery))
    }

    fn acknowledge_reset_inner(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        if recovery.kind != FsDmaRecoveryKind::Reset {
            return Err(RuntimeFsError::InvalidDmaState(
                self.effect_record(recovery.effect)?.dma_state,
            ));
        }
        let record = *self.validate_dma_recovery(recovery)?;
        if record.phase != FsEffectPhase::Committed {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        let generation = DeviceGeneration::new(
            self.scope_record(recovery.scope)?
                .device_generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeFsError::CounterOverflow)?,
        );
        self.scope_record_mut(recovery.scope)?.device_generation = generation;
        let effect = self.effect_record_mut(recovery.effect)?;
        effect.token.device_generation = generation;
        effect.dma_state = FsDmaState::IotlbInFlight;
        self.bump_domain_revision(recovery.scope, FsDomain::Block)?;
        Ok(FsDmaRecoveryToken {
            device_generation: generation,
            kind: FsDmaRecoveryKind::Iotlb,
            ..recovery
        })
    }

    /// Acknowledges synchronous IOTLB completion and returns the retained DMA credit.
    pub fn acknowledge_iotlb(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsEffectPhase, RuntimeFsError> {
        self.transaction(|candidate| candidate.acknowledge_iotlb_inner(recovery))
    }

    fn acknowledge_iotlb_inner(
        &mut self,
        recovery: FsDmaRecoveryToken,
    ) -> Result<FsEffectPhase, RuntimeFsError> {
        if recovery.kind != FsDmaRecoveryKind::Iotlb {
            return Err(RuntimeFsError::InvalidDmaState(
                self.effect_record(recovery.effect)?.dma_state,
            ));
        }
        let record = *self.validate_dma_recovery(recovery)?;
        if !matches!(
            record.phase,
            FsEffectPhase::Prepared | FsEffectPhase::Committed
        ) {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        self.effect_record_mut(recovery.effect)?.dma_state = FsDmaState::Released;
        let terminal = if record.phase == FsEffectPhase::Committed {
            FsEffectPhase::Completed
        } else {
            FsEffectPhase::Aborted
        };
        self.terminalize(recovery.effect, terminal)?;
        if self.scope_record(recovery.scope)?.state == ScopeState::Closing {
            self.record_closure_step(recovery.scope)?;
        }
        Ok(terminal)
    }

    fn record_closure_step(&mut self, scope: ScopeId) -> Result<(), RuntimeFsError> {
        let revocation = self
            .scope_record_mut(scope)?
            .revocation
            .as_mut()
            .ok_or(RuntimeFsError::StaleRevokeTicket)?;
        revocation.closure_steps = revocation
            .closure_steps
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(())
    }

    /// Publishes `Revoked` only after every frozen effect and credit is closed.
    pub fn revoke_complete(&mut self, ticket: RuntimeFsRevokeTicket) -> Result<(), RuntimeFsError> {
        self.transaction(|candidate| candidate.revoke_complete_inner(ticket))
    }

    fn revoke_complete_inner(
        &mut self,
        ticket: RuntimeFsRevokeTicket,
    ) -> Result<(), RuntimeFsError> {
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
        let tombstones = revocation.frozen.iter().any(|effect| {
            self.effects
                .get(effect)
                .is_some_and(|record| record.tombstone.is_some())
        });
        if !all_terminal
            || pending_publications
            || tombstones
            || scope.free_credits != scope.initial_credits
            || revocation.closure_steps != revocation.frozen.len()
        {
            return Err(RuntimeFsError::NotQuiescent);
        }
        self.scope_record_mut(ticket.scope)?.state = ScopeState::Revoked;
        Ok(())
    }
}
