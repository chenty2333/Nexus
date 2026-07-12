# Two-key private futex requeue CSER refinement

`PersonalityFutexRequeueCser.tla` is the bounded Stage 6B.2 successor to the
checked Stage 6B.1 `PersonalityFutexCser.tla`.  The predecessor remains an
unchanged one-key wait/wake checkpoint.  This successor adds exactly the
semantic delta needed before the retained Round 4 workload can be refined:

- two private keys in one address-space generation;
- two wait continuations;
- one `FUTEX_REQUEUE_PRIVATE` controller with `max_wake <= 1` and
  `max_requeue <= 1`;
- one target-key wake controller;
- current-binding selection, crash/snapshot/rebind/adopt, recovery-watchdog
  revocation, immutable receipts, and typed wait/control/timer credits.

It is a finite protocol model, not a general Linux futex implementation or an
SMP locking proof.

## Origin identity and current resource membership

A wait's authenticated syscall identity retains its original private key.  A
separate `queuedOn` field records its current queue membership:

```text
originKey = KeyA             // immutable token identity
queuedOn  = KeyA or KeyB     // mutable domain index membership
```

This separation is required by requeue.  Rewriting the original token would
turn a valid old token into a forged identity, while continuing to use only
the origin key would let `WAKE(A)` incorrectly select a waiter already moved
to B.

The executable Rust successor makes the same separation in the common
registry: `RegistryEffectToken.resources()` is immutable origin identity,
while `RegistryEffectView.current_resources` and the scope-local by-resource
reverse index move atomically.

## Requeue linearization and publication

`RequeueCommit` is atomic with `RevokeBegin`.  For source queue `A`, it freezes
disjoint sets `W` and `M`:

```text
W = at most one current-binding waiter selected for wake
M = at most one remaining current-binding waiter selected for migration

queueA' = queueA minus (W union M)
queueB' = queueB union M
result  = Cardinality(W) + Cardinality(M)
```

Every `W` waiter becomes committed and is terminalized with the controller by
the later kernel-owned `KernelPublish`.  Every `M` waiter remains registered,
pending, and charged for exactly one wait credit.  It preserves its effect,
task, authority, binding, continuation, and origin key; only current resource
membership and one bounded migration counter change.

The separation is intentional:

```text
RequeueCommit
  -> freezes queue movement, woken/moved partition, and Linux result

KernelPublish
  -> consumes controller plus W once
  -> never consumes, reselects, or remigrates M
```

The Rust `EffectRegistry::commit_with_moves` applies the corresponding generic
commit set and current-resource move set under one failure-atomic transition.

## Linux return result

The model returns the total affected count:

```text
affected = woken + requeued
```

This follows current Linux `kernel/futex/requeue.c`, whose plain requeue path
increments one `task_count` for both woken and moved waiters and returns that
count.  Some man-pages releases still describe plain `FUTEX_REQUEUE` as
returning only the woken count; the retained Nexus input must not reproduce
that documentation discrepancy as a personality ABI.

The bounded graph reaches both relevant Round 4 cases:

- wake one plus move one returns `2`;
- move-only recovery requeue returns `1`.

## Crash, binding, and adoption

Personality-owned wake and requeue commits may select only a waiter whose
authority and binding match the current service.  Queue-head priority is
strict: a fresh replacement cannot skip, wake, or implicitly migrate an
old-binding head in order to reach a newer waiter behind it.  It first performs
exact snapshot, ready, rebind, and per-effect adoption (or lets watchdog
closure abort the scope).

A crash after commit does not invalidate the immutable receipt.  Kernel
publication can consume a crash-before-publication receipt without adoption;
adoption only updates personality ownership and never changes queue location,
frozen partition, result, migration count, or credit.

## Revocation outcomes

The two authority orders have explicit outcomes:

```text
RequeueCommit before RevokeBegin
  -> controller and W drain to Completed
  -> M remains an uncommitted wait and aborts unless a target wake committed

RevokeBegin before RequeueCommit
  -> no W or M is installed
  -> no queue movement crosses the closed authority gate
  -> captured controller and queued waits abort
```

Recovery-watchdog expiry uses the same revoke path.  It never fabricates Linux
`ETIMEDOUT`.

## Checked properties

Both configurations check state properties for:

- exact disjoint A/B queue partition;
- frozen `woken`, `moved`, and affected-count receipt;
- migration identity and wait-credit preservation;
- single continuation consumption and terminalization;
- wait/control/timer budget conservation;
- exact recovery cohort and snapshot revision;
- post-revoke commit and migration exclusion;
- fixed closure accounting and quiescent closure.

The reject-enabled graph additionally executes stale-binding rejection and
checks `RejectSideEffectFreedom`.  Action properties check current-binding
selection and that adoption preserves all futex state.  Weak fairness applies
only to kernel fallback, committed publication, watchdog/closure work.

With the pinned Nexus TLA+ image and automatic worker selection (16 workers on
the recorded host), the complete runs are:

```text
reject-enabled safety:
  4,786,581 states generated
  1,927,174 distinct states
  complete graph depth 27

action/liveness:
  247,047 states generated
  140,473 distinct states
  complete graph depth 23
  4 temporal branches over 561,892 total distinct branch states
```

Six reachability witnesses additionally require result-two, move-only, strict
old-head/current-tail binding fencing, both revoke orders, and target-key wake
scenarios.

## Run

From the repository root, the normal gate is:

```sh
./x spec
```

For the successor only:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/repo" -w /repo/specs/cser \
  nexus/cser-dev:746c558886de98a4 \
  ./check.sh PersonalityFutexRequeueCser
```

Edit the PlusCal algorithm, then regenerate with `pcal.trans -nocfg
-lineWidth 10000`; committed generated `Init`/`Next` must not be edited by
hand.

## Boundary

The successor deliberately excludes:

- counts above one in a single wake/requeue controller;
- `FUTEX_CMP_REQUEUE`, PI, robust, shared futexes, and Linux wait timeout;
- unmap/key invalidation and address-space teardown;
- waiter priority rules or a Linux FIFO compatibility claim;
- SMP bucket locking, memory ordering, and lost-wakeup proof;
- concrete task clone/mmap/exit operations and guest execution from the formal
  state space.

The independent pinned OSTD/QEMU refinement now executes the adapted retained
Round 4 input, including its bounded mmap, clone, two-key requeue, recovery,
and thread-exit path. That observation remains a separate single-CPU
implementation receipt; it does not widen this checked finite-state boundary
or establish general Linux futex semantics.
