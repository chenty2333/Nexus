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

All six bounded core inputs now execute in the Docker-pinned OSTD/QEMU
personality: `linux-hello`, an explicitly adapted Round 4 futex input, an
explicitly adapted Round 5 epoll input, the retained dynamic-PIE launcher/main/
interpreter set, the unchanged runtime-filesystem input, and the unchanged
runtime-network input. These are narrow pressure receipts, not a general
Linux-compatibility claim. The old five-domain composition remains frozen with
`runtime_fs=false` and `runtime_net=false`; the additive seven-domain Linux I/O
successor consumes the two already-revoked workload receipts only as same-boot
prerequisites and creates a fresh root/effect cohort.

`kernel/nexus-ostd/scripts/build-guest.sh` builds the static
`linux-hello` `ET_EXEC` directly from the unchanged retained `hello.S`; it does
not copy or rewrite a second source tree. The gate fixes both the retained source SHA-256
`50690500a3cfac0f412da66d3d5d7f32b9b4da2a96a38d6d21c3ef12ea141490`
and the reproducible container-built ELF SHA-256
`1dae72e6d4a5c9144e94580a8e2a8280cb36f725d66046baed77562051b2f1a4`.
The generated ELF lives only in the isolated experiment and is not a new
provenance source.

Stage 6A and 6B.1 remain independent predecessor evidence. Stage 6B.2 adds a
personality-local common effect registry and the three later receipts; it does
not merge scheduler, pager, personality, and VirtIO into one cross-service
registry. Remaining retained sources are pressure candidates or archive
inputs, not compatibility claims.

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
therefore marks this workload `adaptation_required`. Stage 6B.2 applies
`adaptations/round4-futex-modern-requeue.patch` only to a temporary build copy,
runs the adapted program on host Linux, fixes the resulting artifact digest,
and then executes that exact ELF in QEMU. Implementing the old return convention
in the Nexus personality remains unacceptable.

The futex gate is deliberately split. Stage 6B.1 is now **semantics complete and
bounded OSTD/QEMU slice complete / Observed** for one private key, one waiter,
one waker, `max_wake = 1`, and one CPU. Its raw probes observe a mismatch
returning `EAGAIN` without an effect, atomic compare/enqueue, personality
crash/rebind/adopt, watchdog cancellation and expiry, frozen wake selection,
post-revoke stale rejection without mutation, one committed drain, one
uncommitted abort path, and full wait/wake/timer-credit return. The watchdog is
a CSER recovery deadline and never reports a Linux futex timeout.

The Stage 6B.2 successor now supplies that missing bounded core path: two-key
atomic requeue, eight anonymous pages, three clone tasks sharing one `VmSpace`,
thread and process exit, a frozen `woken + moved = 2` receipt, crash/rebind with
three explicit adoptions, and failure-atomic old-binding rejection. Strict
positive and negative serial oracles require FIFO movement, single
terminalization, both closure orderings, empty indexes, and returned credits.
The result remains single-CPU and excludes Linux timeout, unmap invalidation,
signals, shared/PI/robust futexes, and lost-wakeup/SMP proof.

### Retained epoll input audit

`linux-round5-epoll-smoke` also preserves one non-Linux expectation: it tries
to add a regular file to epoll and expects immediate `EPOLLIN`. Linux returns
`EPERM`. `adaptations/round5-epoll-linux-regular-file.patch` changes only that
tail in the temporary copy; pipe edge-triggered, pipe one-shot, and socketpair
level-triggered checks remain intact. A host semantic companion fixes the
source, patch, and adapted-source digests, while QEMU executes the full adapted
ELF and requires the exact 23-syscall receipt. A Nexus-owned readiness
lifecycle companion separately checks atomic sample-and-arm, generational
subscriptions, ready/timeout/revoke races, crash/rebind/adopt, one-shot
publication, and quiescent closure. Opening the fixed `/bin/linux-hello`
artifact is a bounded in-memory lookup, not a runtime-filesystem result.

### Retained dynamic PIE input audit

The dynamic core slice keeps all three retained sources unchanged. A fixed
static launcher really invokes `execve`; the bounded loader stages an ET_DYN
main and ET_DYN interpreter, each with four `PT_LOAD` segments, plus TLS/TCB and
the initial stack. A pre-commit personality crash requires eleven explicit
adoptions before one atomic image commit and lock-external `VmSpace`
publication. The guest checks auxv and both TLS images before printing exactly
`dynamic pie ok`. Explicit FS-base load/save is observed only for one CPU and
one TLS-bearing task; this is not a general dynamic linker, relocation, libc,
or multi-task TLS implementation.

### Retained runtime-filesystem input audit

`linux-runtime-fs-smoke` is executed without source adaptation. The build gate
fixes source SHA
`c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f`
and static-ELF SHA
`0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef`.
Pinned QEMU observes its exact 14 syscall invocations: executable and temporary
file opens, ELF and sparse-offset reads, `statx`, `newfstatat(AT_EMPTY_PATH)`,
`pwrite64`, relative `/proc/self/exe` `readlinkat`, closes, stdout, and `exit`.
The strict oracle checks every receipt in order plus duplicate/count/digest/
lifecycle mutations.

The implementation is deliberately bounded in memory. A four-domain lifecycle
companion supplies pager/filesystem/personality recovery, both write/revoke
orders, and separate reset/IOTLB owner-retaining tombstones. A host oracle joins
the source/ELF/sector/image digests to the independent real Stage 5B receipt as
component consistency only. It does not establish a VFS, persistence, durable
writes, real DMA in the primary boot, same-boot identity, or SMP behavior.

### Retained runtime-network input audit

`linux-runtime-net-smoke` is executed without source adaptation. The build gate
fixes source SHA
`65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf`
and static-ELF SHA
`8cdd5864c07e51e91d9e0a6ec94e4d7d6438db2fbb39d513bfb7c5624d32f549`.
Pinned one-CPU QEMU observes its exact 22-syscall success path over one bounded
in-memory IPv4 listener, client, and accepted socket: setup and name checks,
accept, exact four-byte ping/pong, `SHUT_WR`/EOF, three closes, stdout, and
exit. Kernel-owned readiness and Control, Network, Readiness, and Buffer credit
ownership remain explicit.

A real OSTD `UserMode` netd-v1 completes the first nine network operations,
prepares accept, and page-faults. Netd-v2 performs snapshot/Ready/rebind and
explicit adoption, rejects the stale v1 binding without changing the full
semantic projection, commits the frozen accept, and completes the remaining
operations. Strict positive and mutation-negative oracles bind the retained
source/ELF, exact syscall and recovery order, one-shot publication, and honest
limitation markers. This does not establish smoltcp, real TCP breadth, external
packets, VirtIO-net, a NIC, multiple connections/backpressure, or SMP.

## Build profiles

- `static-raw`: `clang --target=x86_64-unknown-linux-gnu`, `-nostdlib`, static,
  non-PIE, `_start` entry.
- `dynamic-exec-raw`: `-nostdlib` ET_EXEC with an explicit `PT_INTERP`.
- `shared-interpreter-raw`: `-nostdlib -shared -fPIC` interpreter payload.
- `dynamic-pie-raw`: `-nostdlib -fPIE -pie` with an explicit `PT_INTERP`.
- `glibc-pie`: normal host C compilation as PIE with a pinned guest glibc and
  general runtime loader still to be supplied by a future guest-artifact build;
  the current raw interpreter is only the bounded dynamic-PIE core probe.

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
