# Retained Linux guest inputs

This directory contains small Linux x86-64 C/assembly programs retained as
compatibility-pressure inputs. They are not a retained Starnix
implementation, and they do not define Nexus's native ABI or research identity.

`sources/` is an exact copy of the 34 source files previously built from
`user/linux-*` at repository commit
`8d5d07e35b0051bd4ef001224714decc0615ff49`. `SOURCES.toml` maps every copy to
its original path and SHA-256 digest. The legacy implementation tree has been
deleted; Git history and these hashed inputs now carry the remaining provenance.

`COMPATIBILITY.toml` records the behavior each workload was intended to
exercise. It deliberately refers to Linux behavior rather than old component
URLs, sidecar VMOs, stop packets, or `zx_*` calls. Only the six `core` entries
form the bounded Stage 6 gate and carry mandatory CSER injection profiles;
`stretch` entries add optional breadth, while `archive-input` entries carry no
implementation commitment. A Linux-personality harness may refine the build
and success protocol while keeping these inputs as pressure tests.

## Current Stage 6 use

`linux-hello` is the first and currently only executed retained core workload. The
Docker-pinned `experiments/ostd-cser-spike/scripts/build-guest.sh` builds an
x86-64 static `ET_EXEC` directly from the unchanged retained `hello.S`; it does
not copy or rewrite a second source tree. The gate fixes both the retained
source SHA-256
`50690500a3cfac0f412da66d3d5d7f32b9b4da2a96a38d6d21c3ef12ea141490`
and the reproducible container-built ELF SHA-256
`1dae72e6d4a5c9144e94580a8e2a8280cb36f725d66046baed77562051b2f1a4`.
The generated ELF lives only in the isolated experiment and is not a new
provenance source.

That one bounded retained-workload receipt does not complete Stage 6. The other
five core workloads—futex, epoll, dynamic PIE, runtime filesystem, and runtime
network—have not run on the new personality. Stage 6B.1 now separately executes
Nexus-owned raw waiter, waker, and personality probes for one private-futex
wait/wake recovery contract; those probes are an implementation observation,
not execution of the retained Round 4 core input. The remaining retained
sources are still pressure candidates or archive inputs, not compatibility
claims.

### Retained futex input audit

An exact retained source is provenance, not automatically a Linux conformance
oracle. `linux-round4-futex-smoke` preserves one old personality assumption:
after `FUTEX_REQUEUE_PRIVATE` wakes one waiter and requeues one waiter, it
accepts a return value of `1`. Linux's `futex_requeue` implementation counts
both affected waiters and returns `2`; the fallback path likewise expects `0`
after moving one waiter, where Linux returns `1`. In the audited host run, both
waiters had reached the kernel queue, so the first requeue returned `2` and the
unchanged program looped. If only one waiter is queued at that instant, the
later recovery requeue can instead move the late waiter and return `1`; the
second legacy assertion rejects that result as well.

The archived source and its digest remain unchanged. The compatibility catalog
therefore marks this workload `adaptation_required`. A Stage 6 futex gate must
either apply a visible, reproducible adaptation to a temporary build copy or
introduce a separately catalogued Nexus-owned input. It must also pass a host
Linux behavior oracle. Implementing the old return convention in the Nexus
personality is not acceptable.

The futex gate is deliberately split. Stage 6B.1 is now **semantics complete and
bounded OSTD/QEMU slice complete / Observed** for one private key, one waiter,
one waker, `max_wake = 1`, and one CPU. Its raw probes observe a mismatch
returning `EAGAIN` without an effect, atomic compare/enqueue, personality
crash/rebind/adopt, watchdog cancellation and expiry, frozen wake selection,
post-revoke stale rejection without mutation, one committed drain, one
uncommitted abort path, and full wait/wake/timer-credit return. The watchdog is
a CSER recovery deadline and never reports a Linux futex timeout.

This micro-slice has no requeue, clone, mmap, thread-exit, Linux timeout, or
lost-wakeup/SMP proof, and its futex indexes are not a unified syscall/futex
registry. Stage 6B.2 must add two-key atomic requeue plus the retained program's
`mmap`, `clone`, thread-exit, write, and process-exit plumbing and then run the
explicitly adapted full Round 4 program. Passing only 6B.1 does not complete the
core futex workload or Stage 6.

## Build profiles

- `static-raw`: `clang --target=x86_64-unknown-linux-gnu`, `-nostdlib`, static,
  non-PIE, `_start` entry.
- `dynamic-exec-raw`: `-nostdlib` ET_EXEC with an explicit `PT_INTERP`.
- `shared-interpreter-raw`: `-nostdlib -shared -fPIC` interpreter payload.
- `dynamic-pie-raw`: `-nostdlib -fPIE -pie` with an explicit `PT_INTERP`.
- `glibc-pie`: normal host C compilation as PIE with a pinned guest glibc and
  loader supplied later by the Docker guest-artifact build.

The original sources intentionally contain raw Linux syscall numbers and
layout constants. They are executable test inputs, not a constants library.
New Linux-personality code must use maintained Linux UAPI sources rather than
copying constants out of these files.

Some exact inputs also preserve a legacy-specific expectation. Such cases have
an `adaptation_required` entry in the compatibility catalog. Adaptation applies
to the future generated test artifact or result interpretation; the hashed
source copy remains unchanged.

BusyBox, glibc, the dynamic loader, and runtime libraries are external pinned
guest artifacts and are not copied into this directory.
