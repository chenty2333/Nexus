# Nexus OSTD kernel

This directory is the OSTD embedding of the CSER Core. Its supported developer
interface is the root command:

```text
cargo nexus {kernel,system,clean}
```

The root workspace follows rolling `nightly`. xtask reads the local rustup
toolchain manifest for its release date, builds or verifies the corresponding
dated-nightly OSDK/QEMU image, and verifies the image's `rustc` commit hash.
Cargo owns the root alias and xtask; this directory's `OSDK.toml` owns the OSDK
profiles and QEMU settings; the root `Dockerfile` owns the image contents.
Docker and `swtpm` are host responsibilities. The TPM fixture daemon remains on
the host and QEMU reaches it through the controlled system run.

## Profiles

Only four OSDK profiles are supported:

| Profile | Role |
| --- | --- |
| `cser-production` | Persistent production-kernel system profile. |
| `cser-core-reply-recovery` | Focused reply recovery profile. |
| `cser-core-dma-recovery` | DMA IRQ pre-escape fail-closed capability profile; controller quiescence is not yet supported. |
| `cser-pio-journal-ktest` | Focused production two-bank ATA PIO journal profile. |

`cser-production` is the single installed kernel path. The focused profiles
exercise the same typed core interfaces and do not create another lifecycle
owner. Cargo-OSDK creates a runner workspace without propagating `--locked`;
the reviewed `osdk-runner-base/` inputs, with their own lockfile, are compared
directly after each run, and generated test runners must resolve the exact OSDK
0.18.1 packages.

## System verification

`cargo nexus system` runs the production PIO safety/recovery gates, focused
reply recovery, the DMA IRQ fail-closed capability gate,
typed predecessor rejection, then four `cser-production` QEMU boots over the
same temporary journal, outbox, and TPM-fixture state. It is the only
supported persistent kernel execution path. The unselected vNext journal tests
remain developer ktests and are not release gates.

The temporary state lives under `kernel/nexus-ostd/target/nexus/system/` and is
removed after a successful system run. A failed run retains it for diagnosis;
`cargo nexus clean` removes it.

## Evidence boundary

The system path exercises the declared QEMU protocol and its retained guest
state. It does not establish physical-hardware DMA quiescence, power-loss
durability, TPM anti-rollback, or host-physical page identity.
