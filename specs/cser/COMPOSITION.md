# System-wide CSER composition semantics

`CompositionCser.tla` is the bounded Stage 6C protocol model for composing the
five existing Nexus mechanism domains under one authority scope:

```text
Scheduler  Pager  Personality  Readiness  VirtIo
```

It is not a model of five nested authority scopes. There is exactly one root
scope, one root authority epoch, and one root registration/commit gate. Each
domain keeps a local registry and an independent binding epoch. The VirtIO
adapter additionally keeps a device generation. A local `domain_scope` in an
implementation is therefore only a reverse-index key; it cannot mint authority
or complete root revocation by itself.

The model fixes the cross-domain coordination contract. It does not merge the
five registries into one globally locked object and does not replace the more
detailed scheduler, pager, personality, readiness, or VirtIO successor models.

## Bounded causal graph

The exhaustive instance contains one effect per domain and this fixed graph:

```text
Root -> EPersonality -> EPager -> EScheduler
                    \-> EReadiness -> EVirtIo
```

`DeriveEffect` is one atomic transition. It:

- requires the root gate to be open at the current authority epoch;
- requires the target domain to be bound;
- requires the fixed parent to exist, remain live, and carry its source
  domain's current binding;
- installs the immutable parent, authority, and binding fields;
- delegates exactly one typed root-ledger credit to the child effect.

The five credits have distinct types (`Control`, `Memory`, `Cpu`, `Wait`, and
`Dma`) so a transition cannot compensate for a missing DMA credit by creating
an unrelated control credit. The immutable `creditSource` records the causal
parent through which each root-ledger credit was delegated. Terminalization
returns the same typed credit. `TypedCreditConservation` checks every type in
every reachable state.

This is not a parent-owned sub-balance model: deriving a child does not debit a
separate numeric balance stored on its parent effect. The model proves unique
ownership in the root typed ledger plus immutable causal provenance. A future
parent-partitioned credit refinement would need another conservation check.

The fixed graph is a model-checking bound, not a proposed restriction on the
implementation graph. It contains both a fork and chains of length three, but
does not prove arbitrary acyclic graphs, repeated effect IDs, or arbitrary
scope nesting.

## Independent generation domains

The model deliberately keeps three kinds of generation separate:

| Generation | Advanced by | Consequence |
| --- | --- | --- |
| root `authorityEpoch` | `RevokeBegin` | closes derivation and commit in every domain |
| `bindingEpoch[d]` | crash of domain `d` | fences only that service binding |
| VirtIO `deviceGeneration` | successful tombstone retry | fences the retained old device generation |

The finite bound permits one service crash globally. A crash advances exactly
one entry of the five-element binding function. It freezes that domain's exact
uncommitted recovery cohort; committed effects remain kernel-owned. Recovery
must follow:

```text
Crash -> Snapshot -> Ready -> Rebind -> explicit Adopt
```

Only an uncommitted effect in the captured cohort can be adopted. The adopted
effect receives the new local binding epoch while the other four domain epochs
remain unchanged. The action property `DomainBindingIsolation` checks that one
domain crash cannot advance a peer binding.

## Commit and root revocation

`Commit` is accepted only while all of these facts hold in the same state:

- the root scope is `Active` and its gate is `Open`;
- the effect carries the current root authority epoch;
- its domain is `Bound`;
- its effect binding equals that domain's current binding epoch.

`RevokeBegin` is the single root linearization point. It atomically:

1. freezes the exact set of existing records;
2. freezes the live closing-effect cohort;
3. derives the participating-domain cohort from those live effects;
4. records which effects were already committed;
5. closes the root gate and advances the authority epoch;
6. creates one `Pending` receipt slot per participating domain.

After that transition, neither a new descendant nor another commit is legal.
Closure visits only the frozen effects. It is child-first: an uncommitted
effect becomes `Aborted`, while an already committed effect becomes
`Completed`. A parent cannot terminalize while an already derived child is
still live. Causal records are retained, so terminal descendants cannot become
orphans through record deletion.

The model records `closureTargetCount = Cardinality(closingEffects)` and
increments `closureSteps` exactly once per frozen live effect. This checks
scope-local exact work in the finite instance. It is not an asymptotic proof of
`O(k)`, lock scalability, or the absence of a global scan in Rust; those remain
implementation and evaluation obligations.

## Exact closure receipts

Domains outside the frozen cohort are `NotRequired`; they cannot issue a
closure receipt. A participating domain changes `Pending -> Closed` exactly
once, only after every frozen effect owned by that domain is terminal. Receipt
issuance consumes one shared `nextReceiptSequence`; it is not a per-domain
counter and is not reset by `RevokeBegin`. The per-domain field retains the
last globally allocated sequence, while retained timeout evidence keeps its
own earlier sequence. All nonzero issued sequences are globally unique,
gap-free, and strictly below the next value.

The bounded TLA+ ticket payload captures `closingEpoch`, the issuing domain's
`bindingEpoch`, and, for VirtIO, `deviceGeneration`. The Rust/OSTD refinement
adds concrete scope/effect identity and ticket revision fields; cryptographic
authentication and unforgeable handles remain implementation responsibilities,
not extra authority scopes in this model.

Root `RevokeComplete` is enabled only when:

- every frozen effect is terminal;
- every frozen domain has a fresh `Closed` receipt;
- `closureSteps` equals the frozen effect count;
- all five typed credits have returned;
- no tombstone is retained.

Consequently `Revoked` means exact quiescent closure, rather than merely “all
domains were notified.” A duplicate, missing, out-of-cohort, stale, or
premature receipt cannot satisfy the completion guard.

## Honest VirtIO timeout and retry

If the committed VirtIO child cannot quiesce during root closure, the bounded
environment may execute:

```text
Pending
  -> TimedOut(seq=t, Tombstoned, DMA credit retained)
  -> RetryTombstone(device generation 0 -> 1)
  -> Pending
  -> reject replayed TimedOut(seq=t), with no closure side effect
  -> Closed(seq=c), where c > t
```

`TimedOut` is not a terminal effect outcome and is not a successful closure
receipt. The same immutable effect identity, captured device generation, and
DMA credit remain held; the root must stay `Closing`. Retry invalidates that
timeout receipt, advances the independent device generation, and reopens only
the VirtIO receipt slot. Presenting the retained old timeout sequence and old
device generation is an explicit failure-atomic reject action. Once the
retained effect is safely terminalized, the domain consumes a fresh global
sequence for `Closed`; an invariant requires it to be strictly newer than the
timed-out sequence. The coverage graph still contains the minimal ordering
`TimedOut(seq=1) -> Closed(seq=2)`, but correctness does not hard-code those
ordinals—other domains may issue receipts between them.

Retry is an environment action and has no fairness assumption. A permanent
timeout may therefore leave the scope honestly in `Closing` forever. The model
checks only conditional kernel progress once all real terminal outcomes and
receipts exist.

## Checked properties

Both configurations check these state invariants:

- root authority/gate state consistency;
- immutable, non-orphan causal identity;
- one legal state and at most one terminalization per effect;
- per-type root-ledger credit conservation;
- crash and recovery cohort isolation;
- frozen effect/domain closure cohorts;
- post-revoke commit and derivation exclusion;
- exact closure receipts with globally unique, monotone sequences;
- honest retained timeout resources and device generation;
- exact quiescent `Revoked` completion.

The action configuration additionally checks:

- immutable parent edges;
- the full authority/binding gate on every commit transition;
- one-domain-only binding advancement;
- one global receipt allocator that advances by exactly one per issuance;
- failure-atomic rejection of a replayed stale timeout receipt;
- conditional `ReadyForRevokeComplete -> Revoked` progress;
- conditional progress for every ready domain receipt.

Only the kernel process is weakly fair. Service crash, replacement progress,
timeout, retry, and stale receipt presentation are environment actions and
receive no fairness assumption.

## Reachability gates

`check.sh` requires expected counterexamples to four deliberately false
invariants. They prove that the graph contains concrete traces for:

1. all five effects frozen under one root revoke, followed by five exact
   closure receipts and quiescent completion;
2. pager crash/snapshot/ready/rebind/adopt while all four peer binding epochs
   remain unchanged;
3. a closing cohort in which committed effects complete and uncommitted
   effects abort;
4. a committed VirtIO timeout retaining its tombstone and DMA credit, followed
   by retry, device-generation advance, rejection of the stale sequence-1
   receipt, a fresh sequence-2 receipt, and final root closure. This witness
   deliberately proves that the minimal adjacent ordering remains reachable;
   the safety invariants cover arbitrary globally allocated ordinals.

These are reachability witnesses, not ignored safety violations. The script
fails if the named counterexample is absent or TLC reports a different error.

## Complete TLC results

With the repository-pinned `tla2tools.jar` 1.8.0, both configurations explore
the complete bounded graph:

```text
1,236,504 states generated
965,051 distinct states found
0 states left on queue
complete graph depth 31
```

The action configuration checks six temporal branches. All state invariants,
action properties, conditional liveness properties, and four reachability
witnesses pass. On the recorded 16-worker run, the safety graph completed in
12 seconds, the action graph in 1 minute 29 seconds, and the complete
`check.sh CompositionCser` gate—including all four witnesses—took 112.57
seconds.

Run only this family inside the pinned development container with:

```sh
TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar \
  ./specs/cser/check.sh CompositionCser
```

After editing the PlusCal block, regenerate its checked-in transition relation:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 10000 CompositionCser.tla
```

## Exact boundary

This model is a bounded protocol proof for one root scope, five semantically
distinct domains, one fixed five-effect causal graph, one typed root-ledger
credit per effect, at most one service crash, and at most one VirtIO
timeout/retry. It abstracts each detailed local-domain state machine behind
`Registered`, `Committed`, and terminal outcomes.

It does not model arbitrary DAGs, multiple root scopes, nested authority,
multiple crashes, SMP locking, real DMA/IOTLB operations, payload semantics,
runtime filesystem/network services, cryptographic receipt authentication,
parent-owned credit partitions, or asymptotic `k/N` cost. It also does not by
itself establish the final CSER contribution claim. Those require the
Rust/OSTD adapters, integrated QEMU fault paths, and the later complete
verification and evaluation stages.
