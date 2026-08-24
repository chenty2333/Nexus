# Contributing to Nexus

Nexus is a research codebase with no external compatibility users. Breaking
changes are acceptable when they simplify the authoritative model, strengthen a
safety boundary, or remove obsolete machinery.

Read the [terrain](maproom/terrain.md), [basecamp](maproom/basecamp.md),
[route](maproom/route.md), and [hazards](maproom/hazards.md) before substantive
work. Do not create another roadmap, architecture ledger, evidence ledger, or
status file outside `maproom/`.

## Supported workflow

Use only this interface:

```text
cargo nexus {check,test,kernel,system,clean}
```

| Command | Purpose |
| --- | --- |
| `cargo nexus check` | Check the portable workspace and bare-metal profiles. |
| `cargo nexus test` | Run endpoint/provider reference tests plus portable core and model tests. |
| `cargo nexus kernel` | Validate and build the OSTD kernel in the exact image. |
| `cargo nexus system` | Exercise ATA PIO persistence, focused reply recovery, the DMA IRQ fail-closed gate, predecessor rejection, and four persistent QEMU boots. |
| `cargo nexus clean` | Remove build output and temporary system-run state. |

The root Cargo workspace uses its rolling `nightly`. xtask reads the local
rustup toolchain manifest for its release date, builds or verifies the matching
dated-nightly OSDK/QEMU image, and checks the image's `rustc` commit hash. Do
not substitute a date by hand: image identity and the compiler that launched
xtask must agree.

Cargo owns the root workspace and `nexus` alias; `OSDK.toml` owns the four
kernel profiles; the root `Dockerfile` owns the OSTD/cargo-osdk/QEMU build
image; the host owns Docker and `swtpm`. The host TPM fixture remains outside
the container, and the controlled QEMU run connects to it. Cargo-OSDK's
generated runner does not inherit `--locked`; the reviewed
`kernel/nexus-ostd/osdk-runner-base/` inputs and lockfile are the sole
controlled exception and are compared directly after each run. Generated test
runners must resolve the exact OSDK 0.18.1 packages.

## Change discipline

- Keep one authoritative semantic path; do not dual-write a historical model.
- Preserve exact claim coordinates, fencing generations, journal-before-anchor
  ordering, and evidence-specific retirement.
- Do not convert timeout, unavailable transport, missing telemetry, or a
  nonterminal endpoint state into business failure.
- Keep endpoint/provider reference tests and model oracles independent of
  production transition helpers.
- Prefer focused regression tests for the changed invariant.

## Evidence and documentation

Every checked or observed claim must identify its source revision, environment,
workload, and evidence source. A newer implementation does not inherit older
evidence automatically. Do not edit an immutable bundle to describe newer
code.

Raw operation/effect/resource identities, databases, logs, media, TPM state,
absolute paths, container identifiers, and keys are not public evidence.

Maproom maintenance is user-directed. Update terrain, basecamp, route, or
hazards only when the user requests the relevant change. Keep general
development conventions here, and keep the README a concise entry point.

## Publication boundary

Do not configure, synchronize, push, publish, or submit the sibling
`nexus-hotos` paper repository without explicit user authorization.
