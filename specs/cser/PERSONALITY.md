# Linux personality CSER refinement

`PersonalityCser.tla` is the Stage 6A successor to the baseline, pager, and
mediated-I/O specifications. It models one restartable user-space Linux
personality scope and only the two operations needed by the first bounded
`linux-hello` slice: `write` and `exit_group`.

This is a continuation and recovery protocol, not a Linux implementation. It
does not define syscall numbers, argument decoding, ELF loading, descriptor
tables, guest memory copying, or the backend that eventually carries output.

## Two distinct publication points

Every captured syscall owns this identity:

```text
SyscallToken {
    scope
    syscall
    operation
    authority_epoch
    binding_epoch
}
```

The normal state paths differ intentionally:

```text
write:
Captured -> ReplyPrepared -> BackendCommitted -> Completed
                              ^                  ^
                              |                  |
                    BackendCommit          Reply + resume

exit_group:
Captured -> ReplyPrepared ---------------------> Completed
                                                  |
                                           Reply + process exit
```

`BackendCommit` is the external-output linearization point for `write`. It
creates exactly one kernel-owned output obligation but neither publishes the
guest return nor consumes the continuation. `Reply` is a later atomic portal
operation that revalidates authority and binding generations, publishes one
guest result, consumes the continuation, and resumes the task once.

This separation makes the crash window explicit. If the personality crashes
after `BackendCommit` and before `Reply`, recovery must preserve that existing
obligation. The replacement may explicitly adopt and reply to it, but it
cannot commit the output a second time. If authority revocation wins instead,
kernel closure completes the already committed write and publishes its one
return; it does not rename the operation `Aborted` or pretend that output was
rolled back.

`exit_group` has no backend-output transition. Its successful `Reply`
terminalizes the modeled process once and never resumes the trapped task. An
uncommitted `write` or `exit_group` that loses the race to revocation is
aborted once.

The finite model uses semantic labels rather than result values. In
particular, `WriteReturned` does not model partial writes, errno, descriptor
state, or whether a concrete downstream device effect is itself already
committed. Those details must refine this protocol without collapsing
`BackendCommit` and `Reply` into one event.

## Crash, snapshot, and explicit adoption

Only `Crash` advances `bindingEpoch`. It removes the live personality,
requires kernel scheduler fallback, and leaves captured replies and committed
write obligations owned by the scope. Recovery is deliberately a four-step
handshake:

```text
Crash
  -> FallbackPick
  -> Snapshot exact live continuation set
  -> Ready(snapshot authority, binding, live set)
  -> Rebind
  -> Adopt each orphan explicitly
```

Binding zero is bootstrapped. Every later rebound generation must first appear
in the snapshot and ready histories. `Snapshot` records the current authority,
post-crash binding, and exact nonterminal syscall set. `Ready` and `Rebind`
require that record to remain current. Neither action changes a generation.

Rebind installs a new endpoint but does not silently transfer any reply
authority. `Adopt` is legal only for a current-authority `Captured`,
`ReplyPrepared`, or `BackendCommitted` continuation still carrying an older
binding. Adoption changes only that binding field. It preserves the prepared
reply and any prior backend commitment.

`ReplyAccept` presents both token generations. A pre-crash token is rejected
after adoption even if every other gate is valid. The bounded rejection action
changes only audit history; an action property checks that it cannot change
syscall, continuation, delivery, generation, snapshot, or closure state.

No recovery environment action is fair. The model does not assume that a
snapshot is requested, a replacement becomes ready, an orphan is adopted, or
a personality reply arrives. Kernel fallback is fair while still needed; an
explicit authority closure may supersede it.

## Revocation closure

`RevokeBegin` is atomic:

```text
authorityEpoch++
Active -> Closing
stop personality replies and backend commits
snapshot the scope-local live continuation count
```

The weakly fair kernel closure process terminalizes each continuation from the
closing epoch:

- `Captured` and `ReplyPrepared` become `Aborted`, consuming the continuation
  and delivering one terminal abort;
- `BackendCommitted` must be a `write`; it becomes `Completed`, preserving its
  single output commitment and publishing one return/resume;
- a syscall already terminal before closure is not visited again.

`RevokeComplete` is enabled only after every closing-epoch continuation is
terminal. `closureTargetCount` is fixed at `RevokeBegin`, while `closureSteps`
increments once per visited live continuation. The checked accounting relation
is:

```text
closureSteps + remaining_closing_epoch_live = closureTargetCount
```

This is the finite reverse-index work bound. It establishes no wall-clock or
production `O(k)` performance result.

## Checked properties and witnesses

Both model-checking configurations verify:

- state and token-domain type safety;
- exact lifecycle consistency for `write` and `exit_group`;
- at most one backend commitment, reply publication, continuation
  consumption, terminalization, resume, process exit, or abort;
- a `write` reply always following its unique backend commitment;
- `exit_group` never acquiring a backend obligation or resuming its caller;
- full authority/binding token fencing and one-entry rejection accounting;
- `Snapshot -> Ready -> Rebind`, followed by explicit per-syscall adoption;
- old-binding exclusion before adoption and after a new binding is installed;
- post-revoke exclusion of new backend commits and user-space replies;
- exact closure work accounting and quiescent closure.

The non-symmetric action/liveness configuration additionally checks:

- rejected replies are failure-atomic apart from bounded audit fields;
- `Crash` changes only the binding generation and `RevokeBegin` changes only
  the authority generation;
- kernel fallback reaches `Running`, unless authority closure makes it
  unnecessary and changes the state to `Closed`;
- every closing-epoch live continuation terminalizes and every closing scope
  reaches `Revoked`, using only kernel-process weak fairness.

The gate asks TLC to find three deliberate invariant violations as coverage
witnesses:

1. a `write` crosses `BackendCommit`, the personality crashes before `Reply`,
   a replacement snapshots/rebinds/adopts it, the old-binding reply is
   rejected, and the current token resumes exactly once;
2. `exit_group` completes with one process exit and zero resumes;
3. one committed write and one uncommitted syscall coexist at
   `RevokeBegin`, after which closure completes the former and aborts the
   latter before reaching `Revoked`.

With the pinned TLA+ tools and the committed bounds, the complete graphs are:

```text
PersonalityCserSafetyMC.cfg (2 syscall IDs, symmetry, invariants):
20,478 states generated
12,802 distinct states found
0 states left on queue
complete graph depth 20

PersonalityCserMC.cfg (1 syscall ID, no symmetry, action/liveness):
629 states generated
507 distinct states found
0 states left on queue
complete graph depth 14
```

The coverage runs stop at the expected witness and therefore are not complete
state-graph counts. `COVERAGE_RESULT PASS` means the requested scenario was
reachable and the failure was the deliberately appended `*Absent` invariant,
not a safety-gate error.

## Run and regenerate

The supported repository entry point checks PlusCal translation drift before
running TLC:

```sh
./x spec
```

Inside the pinned development container, run only this refinement with:

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar \
  ./specs/cser/check.sh PersonalityCser
```

When changing the state machine, edit only the PlusCal block and regenerate
the checked-in transition relation:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 1000 PersonalityCser.tla
```

## Model boundary

The safety graph has two one-shot syscall identifiers, one scope, one possible
crash/rebind generation, and bounded reply audit history. The liveness graph
uses one syscall identifier. Neither graph models task IDs, concurrent
syscalls from one task, ID reuse, multiple personalities, nested scopes,
physical time, durable recovery storage, kernel locking, SMP memory ordering,
guest-memory faults, signals, cancellation during a concrete backend call, or
cross-scope effect lineage.

`Snapshot` abstracts an exact kernel-visible orphan set, not a durable
personality-process snapshot. `BackendCommit` is an abstract obligation and
does not prove output deduplication in a real console, filesystem, network, or
VirtIO backend. A presented token varies only the authority and binding fields
of an already selected typed syscall; wrong scope, syscall, task, operation,
and post-terminal duplicate attempts are outside this finite input space and
must be rejected by opaque kernel handles and terminal-state checks. The Stage
6 implementation must refine this model with those capabilities and inject
crashes around the real capture, commit, reply, snapshot, and rebind
publications.
