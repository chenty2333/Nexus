# Round 4 futex input adaptation

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
```

The generated ELF digest also depends on the clang/linker versions. This script
is not yet a second supported host build workflow: the final Stage 6B.2 gate
must invoke it from the pinned OSTD experiment image through `./x` before fixing
an artifact digest for Nexus execution. The root verification image does not
currently contain clang or `patch`.

## Claim boundary

A passing host marker proves only that the adapted input follows the expected
Linux control flow. It cannot prove that Nexus atomically moved one waiter from
futex A to futex B, preserved the same CSER effect and credit during migration,
or terminalized each waiter once. The future Nexus gate must establish those
facts from kernel/personality trace receipts in addition to checking the marker
and guest exit status.

This directory is Stage 6B.2 input preparation. It does not implement futexes,
complete the Round 4 core workload on Nexus, or constitute a general Linux
futex compatibility claim.
