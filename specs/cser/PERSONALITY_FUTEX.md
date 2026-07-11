# Private futex CSER refinement

`PersonalityFutexCser.tla` is the Stage 6B.1 successor to the checked Stage 6A
`PersonalityCser.tla` model. Stage 6A remains unchanged. This successor fixes
the smallest futex protocol needed to refine the concurrent Rust personality
model:

- one restartable Linux personality scope;
- one private futex key;
- one wait syscall and one wake syscall;
- `max_wake = 1`;
- one possible personality crash/rebind generation;
- one wait-slot credit, one wake-continuation credit, and one
  recovery-watchdog timer credit.

This is a protocol model, not a general Linux futex implementation. In
particular, it does not import Linux timeout semantics into the CSER recovery
watchdog.

## Full identity and one-shot authority

Every captured call owns this kernel-visible identity:

```text
FutexToken {
    scope
    call
    task
    operation             // Wait or Wake
    key                   // the one private FutexKey
    authority_epoch
    binding_epoch
}
```

`PrivateKey` abstracts the complete private-key identity selected by the
personality, normally an address-space identity plus a user virtual address.
It is not merely the integer value stored at that address. `NoKey` is only an
invalid-token sentinel.

The finite rejection transition presents every bounded combination of call,
task, operation, key, authority generation, and binding generation for an
already selected call. The scope field is fixed because the model contains
exactly one typed scope. A concrete portal must reject a wrong scope before
this generation gate using an opaque typed handle.

Only a token whose full identity matches the recorded call and both current
generation gates can drive a personality-owned transition. A rejected token
changes only `rejectCount` and `lastRejectedPresentedCall`. The reject-enabled
safety configuration checks `RejectSideEffectFreedom` as an action property,
so this guarantee is exercised by real rejection transitions rather than
being vacuously true in the smaller liveness graph.

Every syscall continuation starts `Pending` and is consumed once into exactly
one of `Replied` or `Aborted`. Separate counters check single reply
publication, terminalization, resume, abort, EAGAIN delivery, wake
publication, and wake commitment. Capturing the wake call also reserves one
explicit wake-continuation credit; the finite `WakeCall` identifier is not
silently treated as a resource budget.

## Wait registration and compare mismatch

The modeled wait paths are:

```text
compare mismatch:
Captured -> ReplyPrepared(WaitEagain) -> Completed

compare match:
Captured --WaitRegister--> WaitRegistered
             -> WaitCommitted -> Completed

             -> Aborted       // if authority revocation wins first
```

`WaitRegister` is the atomic abstraction of all of the following:

```text
read and compare the futex word
  + acquire the matching bucket/queue serialization point
  + enqueue this exact wait call
  + reserve one wait-slot credit
```

The concrete implementation must refine that step with user-memory access,
bucket locking, and revalidation. This finite model deliberately does not
pretend to prove those SMP details.

A compare mismatch prepares and publishes Linux `EAGAIN`. It never enters the
wait queue, never reserves the wait-slot credit, and cannot later be selected
by `WakeCommit`. The continuation still progresses through its one-shot reply
state; “no side effect” here means no futex queue, selection, or credit side
effect, not that the syscall record itself remains `Captured`.

## Wake commit and publication

The wake path separates its linearization point from task-state publication:

```text
Captured --WakeCommit--> WakeCommitted --KernelWakePublish--> Completed
```

`WakeCommit` is atomic with `RevokeBegin` on the `Active` scope gate. It freezes
both the selected set and the Linux result:

- if the exact current-generation wait is `WaitRegistered`, it removes that
  wait from the queue, commits both calls, selects `{WaitCall}`, and fixes the
  wake result to `1`;
- otherwise it selects the empty set, commits only the wake caller, and fixes
  the result to `0`.

Nothing after `WakeCommit` may change the selected set or count. Notification,
scheduling, and later recovery are not alternate wake linearization points.

`KernelWakePublish` is kernel-owned and weakly fair. For result `1`, it
atomically consumes and replies to both continuations, resumes both tasks once,
publishes exactly one waiter wake, and returns the wait-slot credit. For result
`0`, it consumes and resumes only the wake caller. Both result paths return the
wake-continuation credit. This avoids a state in which the wake caller reports
`1` while the selected waiter can still be independently aborted.

The two authority races therefore have explicit outcomes:

```text
WakeCommit before RevokeBegin
  -> the frozen committed wake is drained to Completed
  -> a selected waiter is completed in the same closure step

RevokeBegin before WakeCommit
  -> no later WakeCommit can cross the closed authority gate
  -> the uncommitted wait/wake calls abort independently
```

If normal kernel publication wins before revocation, those already completed
calls are not counted again by closure. If revocation follows a committed
count-zero wake, closure completes the wake caller while any independent
uncommitted wait is aborted.

## Cross-model refinement mapping

The pure Rust successor model intentionally folds abstract capture and commit
for a wake into one atomic `wake_commit` API call. One Rust transition therefore
refines this TLA+ prefix:

```text
TLA+:  CaptureWake; WakeCommit
Rust:  wake_commit
```

The TLA+ wake-continuation credit is acquired at `CaptureWake`, the earliest
state in which the continuation is live. Rust has no externally visible
captured/pre-commit wake state, so its atomic `wake_commit` acquires the same
credit while refining that two-step abstract prefix. This is a deliberate
refinement/stuttering boundary, not a claim that action names are
state-for-state identical. Both models return the credit exactly once through
kernel wake publication or closure.

The fixed one-wait/one-wake TLA+ graph makes no data-structure complexity
claim. The current Rust model takes the wait-queue head in `O(1)` and maintains
the committed-wake index with a `BTreeSet`, honestly making that operation
`O(log k)`. Those implementation measurements and index-selection counters
are evidence outside this finite-state specification; they must not be
reported as a TLA+-proved `O(1)` or `O(k)` result.

## Crash, revisioned snapshot, rebind, and adoption

`Crash` advances only the personality binding generation, fences the failed
service, and requires kernel scheduler fallback. It records the exact
old-binding live cohort. A nonempty cohort arms the recovery watchdog and
reserves its one timer credit; an empty-cohort crash does neither.

Recovery uses this sequence:

```text
Crash(bindingEpoch++, recoveryRevision++)
  -> KernelFallback
  -> Snapshot(recoveryRevision, exact futex image)
  -> Ready(exact revision and image still current)
  -> Rebind
  -> Adopt each surviving old-binding call explicitly
```

A snapshot contains authority and binding generations, `recoveryRevision`,
the live set, every call phase, adoption counters, queue membership, frozen
selection, and frozen wake result. The captured image is immutable for its
revision. If it becomes stale, `Snapshot` may replace it only with a fresh
capture at a later recovery revision.

Kernel wake publication can legitimately terminalize a committed call after a
snapshot was captured. When that happens while the service is down, the kernel
advances `recoveryRevision` and changes a previously accepted `Ready` back to
`None`. The old image remains auditable, but `Ready` and `Rebind` both require:

```text
snapshotRevision = recoveryRevision
snapshot live/call/queue/selection/result/adopt image = current image
```

Thus a stale snapshot cannot rebind even though it remains structurally valid.
`SnapshotDiscipline` additionally checks that stale snapshot members removed
from the current live set are terminal and were not adopted after capture.

`Rebind` installs the replacement endpoint but transfers no call implicitly.
`Adopt` is a separate per-call transition that changes only binding ownership
and the recovery cohort. It preserves queue membership, selected/count state,
prepared replies, continuation state, and all three resource ledgers. A
committed wake may instead finish through the kernel path without being
adopted.

## Recovery watchdog is not Linux timeout

The watchdog bounds recovery of the exact orphan cohort created by `Crash`.
It is not attached to the ordinary futex wait and has no `ETIMEDOUT` reply
label.

If every orphan is adopted or terminalized, kernel closure cancels the
watchdog and returns its timer credit. This remains legal when an adopted
no-timeout wait is still `WaitRegistered`: ownership recovery has completed
even though the Linux wait has not.

Cancellation records stable evidence rather than depending on future global
state:

```text
deadlineCohort
deadlineCancelReason       // before or after expiry
cancelledCohort
cancelledCrashBinding
```

For every member of the recorded cancelled cohort, the invariant requires
either a terminal call or adoption into that crash binding. A later unrelated
call cannot invalidate this historical evidence.

If the watchdog expires after the cohort has already become empty, it is
cancelled and its credit is returned. If it expires with any orphan remaining,
the kernel starts `RevokeBegin`; closure then completes committed wake work,
aborts uncommitted calls, and returns the timer credit. No path converts this
recovery failure into Linux futex `ETIMEDOUT`.

## Budget conservation and quiescent closure

The model has three independent renewable credits:

- the wait credit is held only by `WaitRegistered` or `WaitCommitted` and is
  returned by wake publication or abort;
- the wake-continuation credit is acquired by `CaptureWake`, remains held
  through `WakeCommitted`, and is returned by normal kernel publication,
  committed closure drain, or uncommitted abort;
- the timer credit is held only by an armed, expired, or closing recovery
  watchdog and is returned by cancellation or authority closure.

All three conservation equations hold in every reachable state:

```text
free_wait + held_wait = 1
free_wake + held_wake = 1
free_timer + held_timer = 1
```

The wake credit belongs to the wake call; it is not a fourth closure effect.
Consequently, returning it is part of terminalizing that call and does not
increment `closureTargetCount` a second time.

`RevokeBegin` fixes `liveAtClose`, `committedAtClose`, the wake/adoption audit
counts, and `closureTargetCount`. The target is the number of live calls plus
one if the timer credit is held. Closure increments by two when a count-one
committed wake terminalizes its caller and selected waiter together, by one
for a count-zero wake or an independently aborted call, and by one when it
returns the timer credit.

`Revoked` is legal only when the fixed work target is met, no call is live, no
task is blocked, the queue is empty, and all three credits are reusable.
Committed calls captured at `RevokeBegin` must be `Completed`; every other
live call at that point must be `Aborted`.

## Fairness boundary

Weak fairness is assigned only to four kernel-owned processes:

- scheduler fallback;
- committed wake publication;
- recovery-watchdog expiry;
- watchdog cancellation and authority closure.

The personality/environment process is not fair. The model does not assume
that it eventually registers a wait, commits a wake, publishes an EAGAIN
reply, requests a snapshot, reports ready, rebinds, adopts an orphan, or starts
an explicit revoke.

In particular, there is intentionally no property saying that an ordinary
no-timeout `WaitRegistered` call eventually completes. It may remain queued
forever if no wake or revocation occurs. Checked liveness is conditional on
kernel-owned work already being enabled: fallback cannot remain `Required`, a
committed selected wake cannot remain unpublished while the scope stays
active, an armed watchdog cannot remain armed, an expired deadline cannot
remain unresolved, and a closing scope reaches `Revoked` under kernel closure
fairness.

## Checked configurations and results

Both committed configurations use one wait call, one wake call, two distinct
tasks, one private key, `MaxBinding = 1`, `MaxAttempts = 2`, one wait credit,
one wake-continuation credit, and one timer credit. `MaxAttempts = 2` permits
one bounded rejected token presentation before a possible valid presentation.
Neither configuration uses symmetry reduction.

`PersonalityFutexCserSafetyMC.cfg` sets `EnableRejects = TRUE`. It checks all
state invariants plus the real reject-enabled `RejectSideEffectFreedom` action
property. A clean four-worker run in the pinned container completed with:

```text
493,869 states generated
29,407 distinct states found
0 states left on queue
complete graph depth 20
```

`PersonalityFutexCserMC.cfg` sets `EnableRejects = FALSE` to remove irrelevant
invalid-token branching from the action/liveness graph. It checks the same
state invariants, the non-rejection action properties, and the weak-fair
progress claims. TLC completed with:

```text
5,192 states generated
3,521 distinct states found
0 states left on queue
complete graph depth 18
7 temporal branches checked over 24,647 total distinct branch states
```

Five temporary reject-enabled coverage configurations were run only after the
complete safety graph passed. Each stopped on its requested negated invariant
and no other error:

| Expected invariant violation | Reachable scenario |
| --- | --- |
| `MismatchAbsent` | compare mismatch reaches one EAGAIN without queue or credit ownership |
| `CrashAdoptCancelAbsent` | registered wait survives crash, rebind, explicit adoption, and watchdog cancellation |
| `WakeBeforeRevokeAbsent` | wake commits first and closure preserves the completed selected waiter |
| `RevokeBeforeWakeAbsent` | revocation commits first and the unselected wait aborts |
| `WatchdogRevokeAbsent` | recovery watchdog expires with an orphan and drives revoke to quiescent closure |

These are reachability witnesses, not safety failures. Their generated-state
counts and reported traversal depths are partial, worker-dependent stop data
and are deliberately not presented as complete-graph measurements.

The runs used container image `nexus/cser-dev:746c558886de98a4`. TLC reported
`TLC2 Version 2026.07.09.134028 (rev: 227f61b)`, and PlusCal reported
`pcal.trans Version 1.12 of 01 July 2024`.

## Run and regenerate

Edit the PlusCal algorithm block, not the generated `Init`/`Next` relation.
From the repository root, regenerate with:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/repo" \
  -w /repo/specs/cser \
  nexus/cser-dev:746c558886de98a4 \
  /opt/java/openjdk/bin/java \
  -cp /opt/tla2tools/tla2tools.jar \
  pcal.trans -nocfg -lineWidth 10000 PersonalityFutexCser.tla
```

Run the complete safety and action/liveness graphs inside the same image:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/repo" -w /repo/specs/cser \
  nexus/cser-dev:746c558886de98a4 \
  /opt/java/openjdk/bin/java -XX:+UseParallelGC \
  -cp /opt/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup -workers 4 \
  -config PersonalityFutexCserSafetyMC.cfg PersonalityFutexCser.tla

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/repo" -w /repo/specs/cser \
  nexus/cser-dev:746c558886de98a4 \
  /opt/java/openjdk/bin/java -XX:+UseParallelGC \
  -cp /opt/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup -workers 4 \
  -config PersonalityFutexCserMC.cfg PersonalityFutexCser.tla
```

The repository-wide `./x spec`/`./x verify` gate explicitly includes this
successor, runs its translation-drift check, complete safety and
action/liveness graphs, and all five reachability witnesses.

## Model boundary

This finite successor deliberately excludes:

- futex requeue and compare-requeue;
- priority-inheritance futexes;
- signals, restartable syscalls, and signal interruption;
- process-shared futex keys;
- robust futex lists and owner death;
- Linux wait timeouts and clock selection;
- wake counts other than zero or one;
- multiple waiters, multiple keys, ID reuse, or hash-bucket collisions;
- spurious wakeups, task exit, exec, and address-space teardown;
- real user-memory faults during compare;
- SMP locking, atomic memory ordering, and scheduler run-queue visibility;
- multiple personality services, nested scopes, and durable recovery storage.

Consequently, the model does not claim Linux futex completeness or general
Linux compatibility. The next implementation refinement must preserve these
linearization and recovery rules while adding concrete bucket locking,
guest-memory access, task scheduling, crash injection, and multi-waiter tests.
