# Nexus kernel

`kernel/` contains the maintained OSTD embedding of the Nexus CSER Core.
`nexus-ostd/` is an isolated cargo-osdk workspace, while the root workspace
keeps the portable core and independent model oracle separate from the kernel
implementation.

The kernel is reached only through:

```text
cargo nexus kernel
cargo nexus system
cargo nexus seal
```

The root rolling nightly launches xtask. xtask reads the local rustup toolchain
manifest for its release date, uses the matching dated-nightly OSDK/QEMU image,
and verifies the image's `rustc` commit hash; the root `Dockerfile` owns that
image. `OSDK.toml` owns the kernel's four profiles, and the host owns Docker
plus the `swtpm` fixture daemon used by the controlled QEMU path.

The four profiles are `cser-production`, `cser-core-reply-recovery`,
`cser-core-dma-recovery`, and `cser-pio-journal-ktest`. The first is the
persistent system profile; reply is a focused recovery profile, while DMA
currently proves only pre-escape fail-closed behavior when controller callback
synchronization is unavailable; the PIO profile is a focused journal check. Cargo-OSDK's generated runner does not
receive `--locked`, so the reviewed `osdk-runner-base/` snapshot and its own
lockfile are checked unchanged as the sole controlled exception.

`cargo nexus system` exercises ATA PIO persistence, focused reply recovery, the
DMA IRQ fail-closed capability gate, typed predecessor rejection, and four production boots over retained
raw state. `cargo nexus seal` requires a clean Git snapshot, follows that same
path, records the dist date plus verified `rustc` commit date and hash, and
copies only a sanitized receipt and checksum to `target/nexus/public/`. Raw
artifacts stay local; `cargo nexus clean` preserves them, while
`cargo nexus clean --raw` removes them explicitly.

The QEMU protocol profile is evidence for its declared emulated configuration.
It does not establish physical-hardware behavior.
