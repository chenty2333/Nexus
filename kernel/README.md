# Nexus kernel prototypes

`kernel/` contains implementation code that has graduated from an API or
feasibility experiment into the maintained Nexus kernel prototype.

`nexus-ostd/` is deliberately an isolated cargo-osdk workspace. The root Cargo
workspace remains the independent CSER reference model, while the kernel uses a
pinned OSTD/OSDK toolchain and its own immutable lock and generated runner-base
graph. The separation prevents the executable oracle from silently sharing the
kernel's transition implementation.

Within `nexus-ostd/src/`, physical source layout records responsibility without
changing the established crate-root API:

- `cser/` owns scope/effect registry and composition coordination;
- `domains/` owns scheduler, pager, and readiness refinements;
- `personality/` owns bounded Linux compatibility-pressure harnesses;
- `probes/` records platform feasibility boundaries.

The Linux and QEMU paths remain bounded evidence harnesses. Their presence in
the formal prototype does not turn Linux compatibility into Nexus's research
identity or claim runtime filesystem/network support.

Use only the repository-root `./x` as the public developer interface. The
private `nexus-ostd/x` entrypoint is a backend retained for isolation and
reproducibility.
