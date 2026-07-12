# Retained Linux input adaptations

Retained inputs preserve provenance, including obsolete assumptions. This
directory makes every necessary semantic correction visible and reproducible;
it never edits the hashed archive copy in `../sources/`.

## Round 4 futex

This directory prepares one reproducible Stage 6B.2 input without changing the
archived `linux-round4-futex-smoke` source or treating its legacy expectation as
Linux ABI.

The retained program asks `FUTEX_REQUEUE_PRIVATE` to wake one waiter and move
one waiter, but accepts only a return value of `1`. Linux returns the total
number of affected waiters, so that operation returns `2` when both waiters
were already queued. Its recovery loop likewise accepts only `0` after moving
one waiter, where Linux returns `1`.

`round4-futex-modern-requeue.patch` changes only those two result checks:

- the first requeue accepts `1` or `2`, covering whether one or both waiters
  had reached the kernel queue;
- the recovery requeue accepts `0` or `1`, covering whether it moved the late
  waiter.

The patch applies only to a temporary build copy. The retained source remains
the exact copy recorded in `../SOURCES.toml`.

## Host oracle

The current input-preparation check can run from anywhere on a native x86-64
Linux host that provides the commands validated by the script. Another host
architecture additionally needs a configured x86-64 `binfmt` runner:

```sh
tests/guest/linux/adaptations/verify-round4-futex-adaptation.sh
```

The oracle:

1. checks the retained source and patch SHA-256 digests;
2. copies the retained source into a temporary directory;
3. applies the unified patch with `patch --fuzz=0`;
4. builds it with the project's current `static-raw` clang and linker flags;
5. requires an ELF64, little-endian, x86-64 `ET_EXEC` with no `PT_INTERP`, no
   `PT_DYNAMIC`, and no writable-executable `PT_LOAD`;
6. runs it under a strict timeout and requires exit status zero, empty stderr,
   and stdout exactly equal to `round4 futex ok\n`;
7. prints the generated artifact SHA-256 digest.

Inputs fixed by the oracle:

```text
retained source SHA-256: f435e87ea3ded433ba330b48222ece776b72d77ae9dcba4dc348bb5e37d20c56
adaptation patch SHA-256: 4269a03e573b3c23fbeb1570238b2ba30ec9e1e95e3b8f5d43b206a027490a3b
adapted source SHA-256: 9c1efb1dbe4db7f87d8eebf80f289dea8b71f896636362a34f27320424e4e8de
pinned Docker artifact SHA-256: c31cfc57e562e5be0e9558e5017a579b4353a016898113b07cbb467d31a2b7ca
```

The generated ELF digest also depends on the clang/linker versions.
`experiments/ostd-cser-spike/scripts/build-round4.sh` now performs the same
digest, temporary-patch, ELF, host-execution, and exact-stdout checks inside the
pinned OSTD image before emitting the artifact above. The standalone script is
an input audit, not a second supported host workflow.

## Claim boundary

A passing host marker proves only that the adapted input follows the expected
Linux control flow. The independent pinned QEMU receipt now additionally
observes an atomic A-to-B move under the common registry transaction lock,
preserved waiter identity and credit, a frozen affected count, single
terminalization, crash/rebind/adopt, and both closure orderings. Those bounded
receipts do not prove SMP lost-wakeup ordering or general futex compatibility.

This directory remains input preparation. The implementation and strict oracle
live in the isolated OSTD experiment; neither artifact constitutes a general
Linux futex claim.

## Round 5 epoll

The retained `linux-round5-epoll-smoke` input assumes that
`epoll_ctl(EPOLL_CTL_ADD)` accepts a regular file and then reports it as
immediately readable. Linux instead rejects regular-file targets with
`EPERM`; regular files are always ready through `poll(2)`/`select(2)`, but are
not pollable epoll sources.

`round5-epoll-linux-regular-file.patch` changes only that legacy tail of the
program. The temporary build still opens `/bin/linux-hello`, then requires the
regular-file `epoll_ctl` call to return `-EPERM`; all preceding pipe ET,
pipe ONESHOT, and socketpair LT checks remain unchanged.

Run the preparation oracle with:

```sh
tests/guest/linux/adaptations/verify-round5-epoll-adaptation.sh
```

The oracle fixes the retained source, patch, and adapted-source digests; builds
and inspects the static ELF; and executes a native Linux companion proving the
regular-file `EPERM` result. It deliberately does not claim a full host run of
the retained program because `/bin/linux-hello` is a Nexus guest artifact.
The full adapted workload now runs in the pinned OSTD/QEMU slice.

Inputs fixed by the oracle:

```text
retained source SHA-256: 21d322d582465c939367977e6b7f23474ccedebacfa6d5f27ec97d979a9bb13c
adaptation patch SHA-256: cf19e05067a79fec35f0a5ed57e5f302129707a7b0dd57affc93bed56903026b
adapted source SHA-256: 1aad9899aceb23cd2e21c067a96bffed92543fa7bbd92e91f4d807a0e4843205
pinned Docker artifact SHA-256: 1ff6f21480064d8ec84a8e58bef60c54733707fd13b1b2e46ab856daad8fc3f7
```

The Nexus-owned readiness companion separately observes an immediately-ready
generic source, atomic sample-and-arm, timeout/revoke arbitration, stale
generation rejection, crash/rebind with explicit adoption, and quiescent
closure. None of those observations changes Linux's regular-file epoll rule or
establishes a runtime filesystem.
