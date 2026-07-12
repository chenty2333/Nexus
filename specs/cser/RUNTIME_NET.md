# Bounded runtime-network CSER successor

`RuntimeNetCser.tla` is the bounded formal successor for the retained
`linux-runtime-net-smoke` pressure input. It composes one root authority
across three independently rebound service domains without changing the
earlier baseline, personality-readiness, composition, or runtime-filesystem
models:

```text
Root
  `- Syscall (Personality / Control)
       `- NetOperation (Network / Network)
            +- ReadinessWait (Readiness / Readiness)
            `- BufferLease (Network / Buffer)
```

This is a finite in-memory loopback protocol model, not a network stack or a
Linux socket ABI model. The retained guest and OSTD/QEMU slice remain
responsible for syscall decoding, address validation, descriptor behavior,
and the exact ping/pong oracle. This module freezes the causal graph, three
publication points, generation fences, crash recovery, typed-credit
ownership, and root-closure rules that an implementation must refine.

## Exact retained guest boundary

The successful retained guest path executes **22 syscall invocations**:

1. create an IPv4 stream listener with `socket`;
2. enable `SO_REUSEADDR` with `setsockopt`;
3. bind it to `127.0.0.1:4242`;
4. use `getsockname` to verify the listener family, port, and address;
5. call `listen` with backlog four;
6. create the IPv4 stream client;
7. enable `TCP_NODELAY` on the client;
8. connect the client to the retained listener address;
9. use `getpeername` to verify the client's peer family and port;
10. use `accept4` and require a nonzero peer port;
11. use `getsockname` on the client and match the accepted peer tuple;
12. write exactly four bytes, `ping`, from the client;
13. read and compare exactly four `ping` bytes on the accepted socket;
14. write exactly four bytes, `pong`, from the accepted socket;
15. read and compare exactly four `pong` bytes on the client;
16. call `shutdown(client, SHUT_WR)`;
17. read EOF on the accepted socket;
18. through 20. close the accepted, client, and listener descriptors;
21. write exactly `runtime net ok\n` once;
22. exit with status zero.

The source has 23 static `syscall` instructions because every failure path
shares one additional `fail_exit` instruction. Assertion labels are not extra
successful syscalls.

The formal instance deliberately collapses that 22-call ABI to one abstract
four-byte payload, `Ping4`. The bidirectional ping/pong exchange becomes one
`NetCommit`, one derived `ReadyCommit`, one explicit buffer consumption or
closure drain, and one `GuestReply` ticket/publication. Port allocation,
descriptor tables, sockaddr layout, `SO_REUSEADDR`, `TCP_NODELAY`, and EOF
details stay in the executable oracle.

## Fixed lifecycle and typed credits

`CreateScope` installs the initial personality, network, and readiness
bindings. `RegisterGraph` then reserves the complete causal graph atomically.
Every effect captures the current root authority, its own service binding,
and its applicable resource generation while taking exactly one credit:

```text
Control   = 1
Network   = 1
Readiness = 1
Buffer    = 1
```

Effects move through:

```text
Unused -> Registered -> Prepared -> Committed -> Completed
                              `-----------------> Aborted
```

Only root closure can select `Aborted`, and only for an effect that has not
crossed its own commit point. Every effect terminalizes at most once. A live
effect retains its typed credit; terminalization returns that exact class.

The socket projection distinguishes private setup from publication:

```text
Closed -> Listening -> Pending -> Connected -> HalfClosed
```

`Listening` and `Pending` are staged states. If root revocation wins before
`NetCommit`, child-first abort returns the projection to `Closed` without a
payload or generation advance. `Connected` is reached only at `NetCommit`;
after both children terminalize, the committed network operation reaches
`HalfClosed`. Thus precommit setup may be discarded, while committed socket
history is never relabeled as an abort.

## Safe-Rust refinement mapping

The deterministic protocol oracle is rooted at
`crates/cser-model/src/runtime_net/`. It is a `no_std + alloc` state machine,
not the OSTD socket implementation itself.

| PlusCal state or action | Safe-Rust refinement |
| --- | --- |
| root scope, authority, and three domain bindings | `RuntimeNetModel`, `RuntimeNetBindings`, and `RuntimeNetBindingToken` |
| fixed causal graph and captured full identities | `RuntimeNetToken` and four `RuntimeNetEffectToken` values |
| four one-unit ledgers | `NetCredits` and `NetCreditClass` |
| `NetCommit` | `commit_network` and immutable `NetCommitReceipt` |
| `ReadyCommit` and kernel-owned delivery | `commit_ready`, immutable `ReadyCommitReceipt`, and binding-free `deliver_ready(exact_receipt)` |
| `GuestReplyCommit` and one-shot publication | `commit_guest_reply`, `GuestReplyTicket`, and `publish_guest_reply` |
| retained `Ping4` lease | the scope buffer reverse index plus `consume_buffer` or committed `revoke_next` drain |
| crash/snapshot/ready/rebind/adopt | `crash`, `fallback_pick`, `recovery_snapshot`, `ready`, `rebind`, and `adopt` |
| frozen child-first root closure | `RuntimeNetRevokeTicket`, `revoke_next`, and `revoke_complete` |

The Rust instance can create more than one scope or fixed request graph so it
can test cross-scope receipts and stale generations. The TLA+ instance fixes
one scope and one graph so the complete interleaving graph remains tractable.
Those extra sequential test dimensions do not widen the network-stack claim.

## Independent generations and publication points

The bounded instance keeps six independent generation dimensions:

- root `authorityEpoch`, advanced only by `RevokeBegin`;
- personality, network, and readiness `bindingEpoch` values, advanced only by
  a crash in that exact domain;
- `socketGeneration`, advanced only by `NetCommit`;
- `sourceGeneration`, advanced only by `ReadyCommit`.

The three publication points are intentionally separate:

1. `NetCommit` atomically commits `NetOperation` and `BufferLease`, publishes
   `Connected`, retains `Ping4` in the queue, makes the source ready, and
   advances the socket generation once.
2. `ReadyCommit` consumes the exact immutable network receipt, commits the
   readiness wait, freezes its socket/source generations and payload, and
   advances the source generation once. A later fair kernel step delivers the
   frozen receipt exactly once.
3. `GuestReplyCommit` requires a completed network operation and delivered
   readiness receipt. It freezes `LoopbackOK` into a one-shot ticket; a later
   fair kernel step publishes the guest reply exactly once.

This separation admits all required asymmetric histories:

- if `NetCommit` wins before revoke, connected state and the retained payload
  are never rolled back; committed children drain to completion;
- if revoke wins before `NetCommit`, `NetOperation` and `BufferLease` abort,
  the socket returns to `Closed`, the buffer remains `Empty`, and neither a
  readiness receipt nor guest reply can appear;
- if `ReadyCommit` wins but revoke closes the root before guest commit, the
  immutable readiness receipt still drains once while the syscall aborts and
  no guest reply is fabricated;
- if revoke follows `NetCommit` but precedes `ReadyCommit`, the queued network
  publication remains historical fact, the readiness wait aborts, and the
  guest reply remains absent.

## Buffer visibility and root closure

`BufferLease` owns the fixed payload and the only `Buffer` credit. After
`NetCommit`, the invariant is exact: a queued payload corresponds to one live,
committed lease and `freeCredits["Buffer"] = 0`.

There are two distinct ways to release it:

- an active, current-binding network service explicitly consumes the peer
  payload, increments `bufferConsumptionCount`, and returns the credit;
- after `RevokeBegin`, the fair kernel may drain the committed lease during
  child-first closure, increments `bufferClosureCount`, and returns the
  credit without claiming that the peer consumed the bytes.

Both transitions remove current queue ownership, but neither erases the
immutable `NetCommit` receipt or its `Ping4` history. The two counters cannot
both advance. This preserves the distinction between observed peer delivery
and root-owned resource closure.

## Crash, fallback, snapshot, rebind, and adopt

Each service domain can crash once in the finite instance. A crash advances
only that domain's binding. The service-visible recovery snapshot and adoption
cohort contain only old-binding uncommitted effects. A generic registry may
transiently freeze a wider live set in its internal crash receipt, but exact
committed receipts are kernel-owned, are removed before the recovery snapshot,
and are never adopted.

Recovery follows the explicit protocol:

```text
Crash -> FallbackPick -> RecoverySnapshot -> Ready -> Rebind -> Adopt
```

Kernel fallback selection is fair. Snapshot, ready proof, rebind, and adoption
are user-service actions and receive no fairness assumption. A snapshot fixes
the domain binding, exact uncommitted cohort, socket generation, and source
generation. A publication that changes either generation invalidates an
outstanding ready proof; the replacement must capture and validate a fresh
snapshot. Rebind adopts nothing implicitly. Each old-binding uncommitted
effect must pass through its own `Adopt` transition before it can prepare or
commit under the replacement.

A committed readiness receipt is different: it may drain while its service is
down, during recovery, or after root closure. Only attempts to operate on an
uncommitted old-binding effect are fenced. This is the bounded distinction
between a service-owned action and an already committed kernel obligation.

## Stale-token rejection

The reject-enabled graph presents all seven stale/replay classes:

- closed root authority;
- old personality binding;
- old network binding;
- old readiness binding;
- pre-`NetCommit` socket generation;
- pre-`ReadyCommit` source generation;
- a duplicate terminal completion.

The rejection action may update only the bounded `rejectKinds` audit set.
`RejectSideEffectFreedom` compares the complete semantic projection: scope and
gate, all effect identities and lifecycles, typed credits, every generation,
domain phases and recovery snapshots, adoption state, socket/source/buffer
state, immutable receipts, publication and terminal counters, and the frozen
closure cohort. A stale presentation cannot partially mutate any of them.

## Implementation companion evidence contract

The successful 22-syscall QEMU trace establishes the retained ABI path and one
netd crash/adopt history. It does not, by itself, establish every race in this
formal graph. Implementation acceptance therefore needs separate bounded
companion scopes for the following four histories. These are implementation
`Observed` evidence refining the TLA+ `Checked` state predicates; they are not
additional claims about TCP/IP breadth.

Each companion marker should be emitted exactly once, in causal order, and be
matched as an exact line by the serial oracle. Suggested schemas use `<...>`
for deterministic run-local identities:

```text
NETWORK_COMPANION READY_REVOKE PASS case=ready-first scope=<id> winner=ReadyCommit order=ready_commit_before_revoke net_publications=1 ready_publications=1 ready_deliveries=1 wait_final=Completed guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true

NETWORK_COMPANION READY_REVOKE PASS case=revoke-first scope=<id> winner=RevokeBegin order=revoke_before_ready ready_commit_result=StaleAuthority net_publications=1 ready_publications=0 ready_deliveries=0 wait_final=Aborted guest_commits=0 guest_replies=0 buffer_disposition=ClosureDrain credits=Free quiescent=true bounded=true single_cpu=true
```

Each case must also emit two exact transition receipts before its summary. The
ready-first scope orders `step=ReadyCommit` before `step=RevokeBegin`; the
revoke-first scope orders `step=RevokeBegin` before
`step=ReadyCommitReject result=StaleAuthority`. The serial oracle binds these
four receipts and must reject a within-case swap or deletion.

The two cases must use fresh scopes. The first must show that an accepted
`ReadyCommit` survives root closure and delivers exactly once without
fabricating a guest reply. The second must retain the earlier `NetCommit` but
show that a post-revoke ready attempt returns `StaleAuthority` with zero ready
or guest publication. Exact serial order, not only the printed `order` field,
must establish which transition won.

```text
NETWORK_COMPANION PERSONALITY_CRASH PASS scope=<id> old_binding=<n> new_binding=<n+1> send_phase_at_crash=Committed send_disposition=Drain send_replies=1 receive_phase_at_crash=Prepared receive_disposition=Abort receive_replies=0 committed_adoptions=0 terminalizations=2 credits=Free quiescent=true bounded=true single_cpu=true
```

This companion must freeze two sibling syscall continuations under one
personality crash: an already committed send drains and publishes its one
pending reply, while a receive that never crossed its commit gate aborts with
no reply. The committed send must not enter the adoption cohort. The marker
must not collapse both outcomes to a generic “recovered” boolean.

```text
NETWORK_COMPANION BUFFER_REPLY PASS scope=<id> net_sequence=<n> buffer_effect=<id> payload=ping bytes=4 visible_before=1 buffer_credit_before=Held guest_commits_before=0 guest_replies_before=0 peer_consumptions=0 closure_drains=1 visible_after=0 buffer_credit_after=Free net_publications_after=1 guest_replies_after=0 immutable_history=true quiescent=true bounded=true single_cpu=true
```

The before-projection must be sampled after `NetCommit` and before any ready or
guest commit. Closure may remove live queue ownership, but `net_publications`
and the retained receipt payload must remain unchanged. `peer_consumptions=0`
and `closure_drains=1` keep root-owned release distinct from observed peer
delivery.

```text
NETWORK_COMPANION STALE_GENERATION PASS kind=socket scope=<id> effect=<id> presented=<old> current=<new> result=StaleSocketGeneration projection_before=<fingerprint> projection_after=<same-fingerprint> full_projection_unchanged=true mutation=false bounded=true single_cpu=true

NETWORK_COMPANION STALE_GENERATION PASS kind=source scope=<id> effect=<id> presented=<old> current=<new> result=StaleSourceGeneration projection_before=<fingerprint> projection_after=<same-fingerprint> full_projection_unchanged=true mutation=false bounded=true single_cpu=true
```

Before printing either stale-generation marker, the implementation harness
must compare the complete model/protocol projection for equality. The stable
fingerprint should cover at least scope/gate state, all four effect identities
and phases, four credit balances, the three binding epochs, socket/source
generations, recovery cohort and ready proof, retained buffers and receipts,
publication/delivery/terminal counters, and closure metadata. The oracle must
require equal before/after fingerprints, the specific typed error, and
`mutation=false`; a self-reported `full_projection_unchanged=true` alone is
insufficient.

All four companion families must retain the explicit boundary fields
`bounded=true` and `single_cpu=true`. Their oracle must reject any line that
claims `smoltcp=true`, `virtio_net=true`, `external_packets=true`, or
`tcp_breadth=true`. They establish bounded in-memory protocol refinement only.

## Checked properties

Both TLC configurations check:

- type, root-gate, and atomic fixed-graph discipline;
- immutable causal parents and domain-kind relationships;
- lifecycle cohesion and single terminalization;
- conservation of all four typed credits;
- failure-atomic network publication and persistent payload history;
- independent readiness and guest publication discipline;
- per-domain crash isolation, exact snapshot validation, and explicit adopt;
- a frozen child-first root-closure cohort;
- post-revoke commit and derivation exclusion;
- quiescent `Revoked` state;
- action-level commit-gate checks, generation isolation, adoption discipline,
  receipt immutability, and full-projection reject freedom.

`RuntimeNetCserMC.cfg` additionally checks fair-kernel fallback, committed
readiness delivery, committed guest publication, committed buffer closure,
network drain once both children are terminal, and conditional
`RevokeComplete`. It disables reject enumeration to keep the temporal graph
compact. No prepare, consume, snapshot, ready, rebind, or adopt action is made
fair, so the model does not assume that a crashed user service or peer keeps
making progress.

## Required coverage witnesses

The reject-enabled safety configuration must violate each deliberately false
coverage invariant:

| Invariant | Required reachable history |
| --- | --- |
| `LoopbackClosureAbsent` | all three commits publish once, peer consume is distinguished from closure, every effect completes, and the root revokes with all four credits free |
| `RevokeBeforeNetCommitAbsent` | prepared private setup loses to revoke; all four effects abort and socket/buffer/publication state remains at its initial projection |
| `NetdCrashAdoptAcceptAbsent` | both uncommitted network-domain effects survive crash/snapshot/ready/rebind, are explicitly adopted, and `NetCommit` is then accepted once |
| `ReadinessBeforeRevokeAbsent` | `ReadyCommit` wins, its receipt drains, revoke aborts the still-uncommitted syscall, and no guest reply is published |
| `RevokeBeforeReadinessAbsent` | `NetCommit` is retained, revoke fences `ReadyCommit`, the committed network children drain, and readiness/reply remain absent |
| `PersonalityCrashDrainAbortAbsent` | personality crashes with an uncommitted syscall while committed network/readiness work drains; revoke aborts the old-binding syscall with no reply |
| `BufferVisibleReplyAbsentAbsent` | `Ping4` is visibly queued, the Buffer credit remains held, and both guest commit and guest publication are still zero |
| `StaleTokenFencesAbsent` | all three old bindings, root authority, socket/source generations, and duplicate completion are rejected in one history without semantic mutation |

These witnesses cover each publication/revoke order, both buffer-release
owners, committed readiness across crash, explicit netd adoption, personality
abort after child commit, and every generation fence. They do not enumerate
the full 22-syscall ABI.

## Reproduction

After changing the PlusCal block, regenerate the checked-in transition
relation with the pinned development image:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 10000 RuntimeNetCser.tla
```

Run the complete reject-enabled and action graphs with:

```sh
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -cleanup -workers auto \
  -config RuntimeNetCserSafetyMC.cfg RuntimeNetCser.tla

java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -cleanup -workers auto \
  -config RuntimeNetCserMC.cfg RuntimeNetCser.tla
```

Using `pcal.trans` 1.12 and TLC 2026.07.09.134028 from
`nexus/cser-dev:aa2f1d8f6c5100f7`, the initial checked graphs were:

| Configuration | Generated states | Distinct states | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `RuntimeNetCserSafetyMC.cfg` | 3,698,288 | 720,002 | 42 | no error |
| `RuntimeNetCserMC.cfg` | 28,449 | 14,328 | 35 | no error |

The action graph checked eight temporal branches over 114,624 total distinct
branch states. All eight coverage invariants above were independently
observed with the safety configuration.

## Exact non-claims

This successor is bounded to one root, one fixed four-effect graph, one
four-byte abstract payload, one unit of each credit class, one crash per
domain, one network publication, one readiness publication, one guest reply,
and one terminalization per effect. It proves only fixed bounded in-memory
IPv4-loopback protocol semantics.

It does **not** prove:

- smoltcp correctness or any production network stack;
- VirtIO-net, Ethernet, IPv4, TCP packet parsing, or packet processing;
- TCP handshake, retransmission, windows, congestion control, or checksums;
- external packet output, durable external effects, or remote-peer behavior;
- multi-client service, arbitrary sockets, backpressure, partial I/O, or
  general Linux socket compatibility;
- SMP queue locking, interrupt correctness, memory ordering, or lost-wakeup
  freedom;
- a production portal, generic multi-domain registry, or identity-preserving
  physical-device composition.
