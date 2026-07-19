# RFC 0004: bounded authority and replay lanes

Status: implementation contract; no production or observed capability claim.

This RFC narrows two implementation choices left open by RFC 0003:

1. how an in-kernel linear bearer remains small without weakening its causal
   fences; and
2. how Nexus retains exact replay evidence with finite memory without unsafe
   time- or pressure-based eviction.

It applies to the private causal-infrastructure child of the one authoritative
`EffectRegistry`. It does not change frozen effect-peer native wire v1 and it
does not make portal request IDs into Registry authority.

## Borrowed mechanisms and owned semantics

The design borrows three mature shapes:

- the seL4 capability model as precedent for an opaque, kernel-owned,
  non-forgeable invocation token and one-shot reply authority;
- NFSv4.1 sessions as precedent for bounding outstanding operations with a
  fixed slot table and advancing a per-slot sequence only when the prior use is
  known; and
- RIFL as precedent for retaining a completed result and moving the replay
  metadata with the object whose operation it protects.

These are semantic precedents, not imported implementations. Nexus owns the
root identity, ancestry, authority and binding epochs, bearer generations,
commit and publication gates, retained ownership, closure rules, and the exact
acknowledgement that makes compaction or reuse safe.

The principal references are the
[seL4 reference manual](https://sel4.systems/Info/Docs/seL4-manual-latest.pdf),
[RFC 8881 section 2.10.6](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.6),
and the
[RIFL paper](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf).
IOTLB completion and frame reuse additionally follow the invalidation-before-
reuse constraint described by the
[Linux generic page-table documentation](https://docs.kernel.org/next/driver-api/generic_pt.html).

## Compact in-kernel bearer

A bearer is not a wire ABI and is never serialized directly. Its target layout
is:

```text
AuthorityKey {
    registry_instance,
    exact_scope,
    root_authority_epoch,
}

BearerKey<State> {
    authority,
    slot_id,
    object_generation,
    bearer_generation,
    nonce,
    sealed_state_marker,
}
```

The following limits are compile-time gates on the pinned toolchain, expressed
as upper bounds rather than exact Rust ABI promises:

```text
AuthorityKey                         <= 32 bytes
BearerKey<State>                     <= 64 bytes
fallible linear input                <= 96 bytes
LinearFailure<input>                 <= 120 bytes
```

`BearerKey<State>` has private fields and is neither `Copy` nor `Clone`.
`State` is a sealed zero-sized marker. A portal object table may own a bearer
and expose a boot-local opaque selector, but user space cannot construct or
serialize the bearer itself.

The compact key deliberately does not duplicate the full descriptor, root
effect, immutable parent, workload, domain fences, source fences, VM identity,
device session, queue coordinate, or receipt. The selected authoritative
record retains all of them. Every action validates, in order:

1. authoritative ledger mode;
2. registry instance;
3. exact scope and root authority epoch;
4. slot, object generation, nonce, and bearer generation;
5. immutable root, workload, and parent;
6. primary and every secondary binding fence;
7. family-specific VM, task, queue, device, or portal coordinates; and
8. the phase named by the sealed state marker.

The composition of the compact key and the selected authoritative record is
the RFC 0003 obligation identity. Omitting a duplicated field from the key does
not omit its validation.

Slot reuse advances `object_generation` and changes `nonce`. Every successful
state transition or adoption advances `bearer_generation`. Old keys therefore
remain stale across both ABA reuse and fenced recovery.

## Prepare, apply, and linear failure

Every consuming transition follows this shape:

```text
prepare(&live, &input) -> Result<Plan, LinearFailure<Input>>
apply(&mut live, input, plan) -> Success
```

Prepare performs all lookup, identity, phase, quota, allocation, arithmetic,
receipt, revision, and candidate-ancestry checks. Failure returns the original
linear input byte-for-byte in authority terms and leaves the complete Registry
projection unchanged.

Apply starts only after prepare succeeds. It performs fixed-slot mutations,
installs checked successors, and writes bounded diagnostics. It does not
allocate, invoke an external callback, execute unchecked arithmetic, or return
`Result`.

Candidate ledgers may stage records and return non-authority plans. They cannot
mint a live bearer. A successor bearer is minted only after the authoritative
outer Registry installs the exact prevalidated candidate.

Exact replay does not revive an old bearer. It returns a canonical stored
projection:

```text
TransitionOutcome::Applied(successor)
TransitionOutcome::Recovered(projection)
```

## External apply descriptors are not authority

Queue publication, continuation wake, reply publication, device programming,
reset, and IOTLB invalidation use a split result:

```text
ApplyIntent {
    authority: one_shot_compact_bearer,
    plan: ApplyPlan {
        descriptor: copyable_external_coordinates,
    },
}
```

The intent itself is linear. The caller may copy only its plan to perform or
replay the external action, then consume the separate authority.
Only the one-shot authority can acknowledge it. Acknowledgement reloads the
authoritative record and verifies the descriptor generation, nonce, digest,
and external receipt. Possession of copied coordinates alone never authorizes
an acknowledgement or state transition.

When a completed publication is later adopted across a source-binding fence,
its acknowledgement remains immutable historical evidence for the exact
publication epoch. The adopted record advances its current binding epoch and
uses the retained acknowledgement to gate resume; it never rewrites the old
external receipt to look as though publication happened under the replacement
epoch.

Fallible boundaries that would consume two authorities are redesigned as one
composite owner. In particular:

- a service exchange jointly owns its response continuation until completion
  or cancellation releases one continuation bearer; and
- a service execution jointly owns its pre-reserved fault event until normal
  exit or an observed fault produces one supervisor cause.

## Bounded replay lane

Each replay lane is selected by:

```text
(exact root lane, InfrastructureKind, lane_id)
```

It has one current generation and one request digest. The required ordering is:

```text
generation < current       -> StaleGeneration
generation = current,
  same digest              -> canonical replay projection
generation = current,
  different digest         -> IdentityConflict
generation > current + 1   -> MisorderedGeneration
generation = current + 1   -> admitted only after authenticated successor ack
                               or irreversible root domination
```

A lane entry has bounded in-place retention states:

```text
Full          complete locator, receipt, and replay projection
AckedRetained authenticated successor known; safety-critical locator retained
Compact       digest, generation high-water, terminal class, and proof locator
```

Age, memory pressure, TTL, LRU position, process exit, and portal-session loss
are never sufficient to advance or evict a lane. When no authenticated ack or
irreversible root fence exists, exhaustion returns typed backpressure before a
new mutation.

Compaction is family-specific. It must retain enough information to reject a
conflicting retry and to recover the canonical result. At minimum:

- reply payload/publication/backend coordinates remain Full until guest ack or
  an authenticated successor;
- service queue and response locators remain Full until release;
- delayed actor and transport locators remain Full until target consumption or
  a root fence;
- continuation publication and wake coordinates remain Full until consumption;
- reset, IOTLB, device closure, and unmaterialized hardware ownership remain
  Full until release; and
- quarantined deadline and retained recovery evidence remain Full until an
  explicit reconciliation receipt.

## Bounded root lanes

Scope IDs are backed by a finite root-lane table. At most one exact generation
of a scope ID is active. The table retains a generation high-water after
closure.

A same-generation create is exact replay or conflict according to its digest.
A lower generation is stale. The next generation is admitted only after the
prior root is irreversibly fenced, every live obligation is terminal, and no
retained owner or uncompacted replay locator blocks reuse. No path creates an
unbounded `Vec` of historical roots.

Root domination may remove a child lane only when the root closure proof makes
every future child invocation incapable of mutation and the retained root
high-water still rejects stale scope generations. A closure receipt is not a
blanket permission to discard an unresolved device or IOTLB owner.

## Portal replay is a separate layer

The portal-v2 dispatcher retains exact encoded responses for a finite session.
That cache protects request dispatch and provides byte-identical retries. It is
not the Registry replay ledger because it is populated around backend calls,
is scoped to one dispatcher session, and does not own causal records after the
session ends.

The Registry independently validates every opaque handle, generation, digest,
phase, and receipt. Losing or replacing a portal dispatcher cannot lose effect
authority or permit a mutation to execute twice.

## Acceptance gates

Implementation is not complete until tests prove:

- compile-time layout upper bounds for every real linear input;
- foreign registry, wrong scope generation, stale authority epoch, stale
  binding, old bearer generation, reused object generation, and nonce mismatch;
- copied external descriptors cannot acknowledge without authority;
- exact retry returns the canonical projection and conflicting retry does not
  mutate;
- no TTL, LRU, or pressure path removes unacknowledged replay evidence;
- lane exhaustion backpressures before mutation;
- root generation reuse is blocked by every live or retained owner;
- reset and IOTLB completion precede DMA frame reuse; and
- candidate installation mints authority only after one failure-atomic outer
  Registry commit.

Passing host tests or Clippy layout gates is contract evidence only. A causal
matrix row becomes source-mapped only after the same transition is called by
the selected production OSTD path, and becomes observed only with exact-revision
QEMU/runtime evidence.
