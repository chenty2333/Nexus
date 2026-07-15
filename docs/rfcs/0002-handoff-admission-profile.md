# RFC 0002: reversible handoff admission and local effect closure

- Status: **Draft / prospective first-round research contract**
- Target: an out-of-tree vISA/Nexus refinement experiment
- Supersedes: nothing
- Changes accepted `v0.1.0` claims: **no**
- Changes RFC 0001 phase acceptance: **no**

## Claim discipline

This RFC defines the Nexus-owned half of a possible cross-host handoff. It does
not make Nexus a distributed coordinator, ownership ledger, state exporter,
attestation verifier, or destination runtime. The original first-round result
is an independent model; the later v2 lane records an in-memory production
Registry refinement and same-boot host-process adapter, not OSTD execution or a
deployment result.

The first round is complete only when one source-bound research receipt binds
this RFC, the fixed fault matrix, the declarative TLA+ successor, the independent
safe-Rust oracle and tests, and the research runner. The result is bounded
`Specified` and `Checked` local semantics. It is not OSTD observation, host
reboot recovery, malicious rollback resistance, or vISA Stage 5 acceptance.

## Hypothesis

The local hypothesis is:

> Given one typed decision from a non-equivocating ownership log, a Nexus scope
> can reversibly freeze effect admission without advancing its authority epoch,
> classify one stable causal cohort, thaw only after an authoritative abort, or
> irreversibly fence and close only after an authoritative commit, while
> preserving honest committed-effect drain, publication, and tombstone state.

The joint vISA/Nexus hypothesis belongs to the neutral composition artifact.
This RFC supplies only the local refinement obligation consumed by that model.

## First-round fault and trust boundary

The checked fault model includes:

- source service and coordinator crash-stop/restart in the same kernel boot;
- retry, duplication, reordering, and lost acknowledgements;
- freeze racing with effect registration or first commit;
- source binding replacement after freeze;
- duplicate close and conflicting abort/commit inputs; and
- pre-decision and post-commit retained tombstones.

The first round places the following mechanisms in the TCB:

- one non-equivocating, rollback-free ownership decision log;
- the decision log's service incarnation, key identity, and monotonic position;
- provider enforcement of the durable owner/fencing epoch;
- KMS and storage that do not roll back or fork; and
- the secure transport used to obtain typed decision receipts.

The first round excludes:

- host or kernel reboot and restoration of the in-memory Registry;
- malicious storage rollback, log equivocation, or key compromise;
- TEE, attestation, confidential transport, or secret continuity;
- device-internal state migration;
- OSTD `SpinLock`, IRQ, memory-ordering, or real SMP refinement;
- E2B, Firecracker, TheKernel, or product integration; and
- general exactly-once execution for external providers.

An implementation or paper that removes any TCB assumption must introduce a
new acceptance contract. A signature, nonce, or handoff identifier alone is
not a freshness proof.

## Ownership boundary

Nexus owns:

- boot-local Registry, scope, binding, effect, and publication identities;
- the local admission gate and frozen cohort;
- effect classification at the freeze linearization point;
- abort, drain, terminalization, retained tombstone, and closure progress; and
- failure-atomic verification of typed abort and commit decisions.

Nexus does not own:

- portable snapshots or component state;
- global owner, lease epoch, or cross-host freshness;
- destination preparation, reauthorization, or activation;
- the ownership decision log, KMS, verifier, or secure channel; or
- reconciliation policy for an external provider.

The neutral composition artifact owns the handshake, cross-system mapping,
joint verifier, and refinement relation. vISA and Nexus epochs remain distinct
and are never compared by numeric equality.

## Identity contract

Every handoff input and receipt binds:

```text
LocalHandoffIdentity {
    handoff_id,
    decision_log_identity,
    intent_log_position,
    decision_service_incarnation,
    decision_key_identity,
    registry_instance,
    boot_incarnation,
    scope_id,
    authority_epoch,
    binding_epoch,
    freeze_generation,
    frozen_scope_revision,
    cohort_digest,
    classification_digest,
}
```

The first-round oracle uses finite identifiers and deterministic digest
projections. Cryptographic signing and boot-incarnation provisioning remain
outside Nexus and inside the stated TCB.

## Orthogonal state machines

The existing authority lifecycle remains:

```text
ScopePhase = Active | Closing | Revoked
```

The handoff gate is orthogonal:

```text
HandoffGate =
    Open
  | Frozen {
        handoff_id,
        intent_log_position,
        freeze_generation,
        frozen_scope_revision,
        cohort_digest,
        classification_digest,
    }
```

Freeze does not advance `authority_epoch`, clear the current supervisor, or
claim source closure. Commit-close advances the epoch and enters the existing
irreversible `Closing` lifecycle.

## Transition contract

### Intent

`PrepareIntent` is durably recorded before Nexus may freeze. It identifies one
recoverable decision-log entry but does not change the global owner. A crash
after intent and before freeze leaves the source active and permits the intent
to be aborted or retried.

### Freeze

`FreezeAdmission` linearizes with every transition that can alter the frozen
cohort or its classification. Once it succeeds:

- new Register, Prepare, first Commit, resource move, and ordinary rebind are
  rejected without semantic mutation;
- the exact live cohort and every effect disposition are digest-bound;
- already committed effects may complete, drain, or become retained;
- uncommitted effects may be explicitly aborted;
- closure-owned completion publication may cross the runtime lock once; and
- an unknown ownership decision keeps the source frozen and destination
  unauthorized.

The classification is:

```text
EffectClassification =
    UncommittedAbortable
  | CommittedDrainable
  | CompletedPublicationPending
  | Terminal
  | RetainedTombstone
```

A pre-decision retained tombstone makes the handoff `Blocked`. It cannot be
converted into `ReadyToCommit` without explicit reconciliation.

The current production refinement also rejects `FreezeAdmission` before its
linearization point when the scope owns a pending or enrolled but unpublished
device root. The existing device precommit close is an irreversible local
revoke and therefore cannot be repurposed while the external decision is
unknown. A later profile may add a receipt-bound reversible device cancel; this
round makes no such claim.

### Abort

`Unfreeze` requires a typed `OwnershipAbortReceipt` that matches the frozen
handoff, generation, decision-log identity, service incarnation, key identity,
and a monotonic decision position after the intent position.

The exact same abort receipt replays the original result. A conflicting commit
receipt is rejected. If the source binding crashed while frozen, abort opens the
gate but returns `SourceRecoveryRequired`; normal execution resumes only after
an explicit current-binding recovery.

### Commit and close

`CommitClose` requires a typed `OwnershipCommitReceipt`. Before accepting it,
Nexus requires every frozen uncommitted effect to be aborted and every
pre-decision retained tombstone to be reconciled. Acceptance:

1. records the immutable decision identity;
2. advances the local authority epoch;
3. fences the source principal and all service bindings;
4. enters `ScopePhase::Closing`; and
5. returns durable-looking local progress for this boot, not global ownership.

The operation is idempotent by `(handoff_id, freeze_generation,
decision_log_identity, decision_position)`. Repeated calls return the same
progress and never repeat external publication.

Committed descendants may still drain after the global decision. Their
completion publication is closure-owned, must belong to the frozen committed
cohort, and cannot grant source execution authority. A post-commit tombstone
returns `Retained` and requires destination recovery; it never rolls ownership
back and never authorizes destination activation.

### Closure and activation authorization

`ClosureReceipt` is emitted only after:

- every frozen effect is terminal;
- no completion publication remains unacknowledged;
- no retained tombstone remains;
- all frozen credits have been returned or terminally accounted; and
- the scope has entered `Revoked`.

Nexus does not activate a destination. The neutral verifier may authorize
activation only after accepting this exact closure receipt together with the
matching ownership commit receipt and mapping receipt.

## Required local API shape

```text
freeze_admission(intent_ref)
    -> FreezeReceipt { ReadyToCommit | Blocked }

query_handoff(handoff_id, freeze_generation)
    -> HandoffProgress

abort_uncommitted(freeze_receipt)
    -> AbortProgress

unfreeze(ownership_abort_receipt)
    -> ThawReceipt | SourceRecoveryRequired

commit_close(ownership_commit_receipt)
    -> Pending | Retained | Closed(ClosureReceipt)

verify_closure(closure_receipt)
    -> Verified | Rejected
```

These names define semantics, not an authorization to add production methods
in the first round.

## Safety properties

The local model and neutral composition must preserve:

```text
AtMostOneExecutionAuthority
NoPostFreezeUntrackedEffect
AbortImpliesNoDestinationAuthority
CommitDecisionImpliesSourcePrincipalFenced
PostCommitPublicationImpliesPreFreezeCommittedAndClosureOwned
UnknownDecisionImpliesRemainFrozen
DestinationActivationRequiresSourceClosure
EveryReceiptBindsOneDecisionAndOneCohort
StaleBindingCannotPublish
TombstoneCannotBeInterpretedAsClosure
```

`CommitDecisionImpliesSourcePrincipalFenced` does not forbid a closure-owned
completion for an effect already committed at freeze. The stronger literal
property "commit implies no source-side publication" is rejected because it
would make honest drain impossible.

## Fixed falsification matrix

The normative first-round cells live in
`evaluation/handoff-admission/fault-matrix.toml`. Every row has one TLA+
reachability witness and one safe-Rust sequence test. The runner rejects a
missing, duplicated, reordered, renamed, or extra row.

Any of the following kills the local hypothesis:

- a Register, Prepare, first Commit, or resource mutation succeeds after freeze;
- abort and commit both become authoritative for one freeze generation;
- an abort receipt authorizes destination execution;
- a commit decision leaves the source principal able to act;
- a stale binding publishes or consumes a frozen completion;
- duplicate close republishes or advances closure twice;
- a retained tombstone verifies as closure; or
- activation becomes authorized before exact source closure.

## First-round exit contract

The first round exits only when:

1. the fixed matrix validates as an exact ten-row contract;
2. the complete bounded safety and conditional-progress TLA+ configurations
   pass;
3. all ten named reachability witnesses are observed;
4. the independent safe-Rust sequence, property, and Loom gates pass;
5. negative receipt substitutions reject without state mutation;
6. one receipt binds every normative source and generated log by SHA-256;
7. the receipt records a dirty-worktree bit and exact Git revision; and
8. the normative first-round matrix states
   `production_registry_modified=false`, while the v2 receipt separately
   states `production_registry_modified=true` for the production
   `EffectRegistry` refinement lane,
   `host_reboot_claimed=false`, and `malicious_rollback_claimed=false`.

The first-round receipt does not close RFC 0001, enter the canonical `v0.1.0`
manifest, or authorize an implementation claim.

The later v2 research receipt preserves this independent first-round section
and adds a separately identified production-source refinement. It binds the
dependency-free admission gate and the production `EffectRegistry`, reports
`production_registry_modified=true` and
`production_registry_refinement_checked=true`, and still reports
`joint_visa_execution_claimed=false` and `real_ostd_smp_claimed=false`. It does
not retroactively change what the first-round matrix established.

## Later phases

The in-memory production Registry mapping and exact same-boot Nexus-native wire
adapter are now implemented and checked. The adapter intentionally leaves
retained-device/tombstone control unsupported until it can retain and present
the production device receipts instead of projecting an external enum. Later
work must still qualify the clean exact-SHA Nexus peer against the neutral vISA
composition verifier, exercise one logical request with lost ACK, refine real
lock/IRQ/SMP ordering, and finally add a persistent local handoff record with
boot-time fail-closed recovery. Each step requires its own committed acceptance
contract and source-bound evidence.
