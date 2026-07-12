# Bounded runtime-filesystem CSER successor

`RuntimeFsCser.tla` is the bounded formal successor for the retained
`linux-runtime-fs-smoke` pressure input. It composes one root authority across
four independently rebound domains without changing the earlier five-domain
`CompositionCser` baseline:

```text
Root
  `- Syscall (Personality / Control)
       +- PagerMap (Pager / Memory)
       `- FsOp (Filesystem / FilesystemCredit)
            `- BlockReq (Block / Dma)
```

This is a finite protocol model, not a filesystem or Linux ABI model. The
OSTD/QEMU slice must execute the exact guest and its syscall contract; this
module freezes the lifecycle, publication, generation-fencing, and credit
rules that the implementation must refine.

## Exact retained guest boundary

The successful guest path issues **14 syscall invocations**:

1. `openat(AT_FDCWD, "/bin/linux-runtime-fs-smoke", O_RDONLY, 0)`;
2. `pread64` four executable bytes and require `7f 45 4c 46`;
3. `statx(fd, "", AT_EMPTY_PATH, 0x17ff, ...)` and require exact mask,
   regular-file mode, and nonzero size;
4. `newfstatat(fd, "", ..., AT_EMPTY_PATH)` and require nonzero size;
5. `openat(AT_FDCWD, "/tmp/runtime-fs.bin",
   O_CREAT|O_TRUNC|O_RDWR, 0644)`;
6. `pwrite64(tmpfd, "xy", 2, 2)`;
7. `pread64(tmpfd, ..., 4, 0)` and require `00 00 78 79`;
8. `openat(AT_FDCWD, "/proc/self", O_DIRECTORY, 0)`;
9. `readlinkat(procfd, "exe", ..., 128)` and require the exact executable
   path without counting a trailing NUL;
10. through 12. close the three descriptors;
13. write exactly `runtime fs ok\n` once;
14. exit with status zero.

The source contains 15 static `syscall` instructions because every failure
label shares one additional `fail_exit` instruction. `fail_16` is an assertion
label, not a claim that the successful trace contains 16 syscalls.

The formal payload collapses that ABI to one `FsOp` publication:
`inodeBytes = "Zeros"` becomes `"HoleXY"`, while `inodeGeneration` advances
from zero to one. Stat, path, descriptor, and copyin/copyout details stay in
the implementation oracle.

## State and generation boundary

Every effect begins `Unused`, then may enter `Registered`, `Prepared`, and
`Committed`. Non-block effects finish as `Completed` or `Aborted`. The block
request additionally uses:

```text
Prepared -> Cancelling -> IOTLB Ack -> Aborted

Committed -> DeviceCompleted ----+
          `-> ResetIndeterminate -+-> IOTLB Ack -> Completed

Committed or invalidating state -> Tombstoned -> Retry -> retained state
```

`Completed` after `ResetIndeterminate` means resource closure is complete; the
frozen external outcome remains `IndeterminateAfterReset`. A committed effect
is never relabeled as aborted.

The generations are intentionally independent:

- root `authorityEpoch` advances only at `RevokeBegin`;
- each domain's `bindingEpoch` advances only when that service crashes;
- `addressSpaceGeneration` advances with the one pager map publication;
- `inodeGeneration` advances with the one pwrite publication;
- `deviceGeneration` advances only after `ResetAck`.

Registration captures all applicable generations. Prepare and commit check the
captured full token rather than refreshing any field. The reject-enabled graph
can independently present stale authority, binding, address-space, inode,
device, and timeout-receipt tokens. A reject changes only `rejectKinds`.

## Linearization points

- `PagerMap` commit publishes one PTE under the current authority, binding, and
  address-space generation. The finite transition records the required TLB
  synchronization in the same abstract step; a concrete adapter must preserve
  the PTE-then-TLB order.
- `FsOp` commit atomically publishes `HoleXY` and increments the inode version.
  A staged write remains `Zeros` if revocation wins first.
- `BlockReq` commit abstracts the audited Release publication of
  `avail.idx`. Notification is not a commit point.
- `Syscall` commit freezes a backend result. `replyPublicationCount` advances
  only in a later child-first kernel transition, representing one publication
  ticket acknowledgement.
- `RevokeBegin` freezes the exact live cohort, advances authority, and closes
  every old-authority commit gate in one step.
- `ResetAck` makes the old device generation quiescent but does not release the
  DMA credit. Only `IotlbAck` makes the owner and credit reusable.

This separation admits the required asymmetric history: `FsOp` can commit,
then root revocation can abort a still-uncommitted `Syscall`. The write remains
visible while the guest reply remains absent. If `Syscall` already committed,
it instead drains one reply and cannot become aborted.

## Credits and closure

The root ledger starts with one unit of each fixed type:

```text
Control = 1
Memory = 1
FilesystemCredit = 1
Dma = 1
```

Registration transfers exactly one typed credit to the corresponding live
effect. A precommit non-DMA abort returns its credit immediately. A prepared
block request has a real mapping, so cancellation retains `Dma` until IOTLB
acknowledgement. A committed request retains the same credit through device
completion, reset, reset timeout, invalidation timeout, and tombstone retry.

`RevokeComplete` is enabled only when every effect in the frozen closing cohort
is terminal, all four credits are free, and no tombstone remains. Reset and
IOTLB acknowledgements are environment actions with no fairness assumption.
Consequently the model proves only conditional revocation progress: once the
honest closure predicate is reached, the fair kernel completes revocation. A
permanent external timeout correctly leaves the root in `Closing`.

## Checked properties

Both TLC configurations check:

- type and root-gate discipline;
- immutable causal parent identity;
- lifecycle cohesion and single terminalization;
- typed-credit conservation;
- one pager publication with generation advance and TLB synchronization;
- failure-atomic pwrite visibility;
- split block commit, terminal outcome, DMA, and guest-reply publication;
- binding isolation plus explicit crash/snapshot/ready/rebind/adopt recovery;
- frozen close cohort and post-revoke commit/derivation exclusion;
- timeout honesty and quiescent closure;
- action-level causal-edge immutability, commit-gate checks, binding isolation,
  and stale-reject side-effect freedom.

`RuntimeFsCserMC.cfg` additionally checks conditional revocation progress. It
disables reject enumeration to keep the temporal graph compact;
`RuntimeFsCserSafetyMC.cfg` enables all stale-token branches.

## Required coverage witnesses

The reject-enabled safety configuration must violate each deliberately false
coverage invariant:

| Invariant | Required reachable history |
| --- | --- |
| `FourDomainPwriteClosureAbsent` | all four effects commit, close child-first, publish one reply, and return all credits |
| `RevokeBeforePwriteAbsent` | revocation wins before FS commit; bytes/version remain unchanged and no reply is published |
| `PagerCrashAdoptMapAbsent` | pager crashes before publication, explicitly adopts, then publishes one PTE/TLB result |
| `FsCrashAdoptWriteAbsent` | filesystem crashes before publication, explicitly adopts, then publishes `HoleXY` once |
| `BlockCrashDeviceDrainAbsent` | block service crashes after queue commit; kernel/device completion drains without adoption |
| `ResetTimeoutRetryClosureAbsent` | reset timeout retains DMA, retry acknowledges reset, IOTLB closes, and root revokes |
| `IotlbTimeoutRetryClosureAbsent` | invalidation timeout retains DMA and outcome, retry acknowledges, and root revokes |
| `StaleTokenFencesAbsent` | all five stale generation classes plus a stale timeout receipt are rejected without mutation |

These witnesses cover the two pwrite/revoke orders, both publication-recovery
paths, committed block-service failure, both tombstone classes, and every
generation fence. They do not enumerate the complete 14-syscall ABI.

## Reproduction

After changing the PlusCal block, regenerate the checked-in transition relation
inside the pinned development container:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 10000 RuntimeFsCser.tla
```

Run the complete reject-enabled and action graphs with:

```sh
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -cleanup -workers auto \
  -config RuntimeFsCserSafetyMC.cfg RuntimeFsCser.tla

java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -cleanup -workers auto \
  -config RuntimeFsCserMC.cfg RuntimeFsCser.tla
```

Using `pcal.trans` 1.12 and TLC 2026.07.09.134028 from
`nexus/cser-dev:aa2f1d8f6c5100f7`, the initial checked graphs were:

| Configuration | Generated states | Distinct states | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `RuntimeFsCserSafetyMC.cfg` | 2,262,368 | 635,313 | 35 | no error |
| `RuntimeFsCserMC.cfg` | 80,108 | 44,768 | 29 | no error |

All eight coverage invariants above were independently observed with the safety
configuration. Repository integration should run the safety graph, the eight
`expect_reachable` checks, and then the action graph, in that order.

## Exact non-claims

This successor is bounded to one root, four effects, four one-unit credits, one
crash, one pwrite publication, one pager map, one block request, one reset
generation advance, and at most one timeout/retry of each kind. It does not
prove arbitrary DAGs, multiple inodes or requests, pathname races, descriptor
tables, page-cache coherence, durable writes, flush ordering, a production VFS,
same-boot or identity-preserving VirtIO composition, physical-device behavior,
SMP locking/liveness, general Linux compatibility, or runtime networking.
