# Nexus OSTD kernel

This directory is the OSTD embedding of the CSER Core. Its supported developer
interface is the root command:

```text
cargo nexus {kernel,system,seal,clean}
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
| `cser-pio-journal-ktest` | Focused ATA PIO journal profile. |

`cser-production` is the single installed kernel path. The focused profiles
exercise the same typed core interfaces and do not create another lifecycle
owner. Cargo-OSDK creates a runner workspace without propagating `--locked`;
the reviewed `osdk-runner-base/` snapshot, with its own lockfile, is checked
unchanged as the sole controlled runner-lock exception.

## System and seal

`cargo nexus system` runs the PIO profile, focused reply recovery, the DMA IRQ
fail-closed capability gate,
typed predecessor rejection, then four `cser-production` QEMU boots over the
same retained raw journal, outbox, and TPM-fixture state. It is the only
supported persistent kernel execution path.

`cargo nexus seal` first requires a clean Git snapshot, then uses that same
system path. On success it records the dist date plus verified `rustc` commit
date and hash, and publishes only `combined-receipt.txt` and its checksum to
`target/nexus/public/`. Raw journals, logs, media, and TPM-fixture state are
local-only and are never uploaded. `cargo nexus clean` preserves raw artifacts;
use `cargo nexus clean --raw` to delete them explicitly.

## Evidence boundary

The system path exercises the declared QEMU protocol and its retained guest
state. It does not establish physical-hardware DMA quiescence, power-loss
durability, TPM anti-rollback, or host-physical page identity.
