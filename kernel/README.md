# Nexus kernel prototypes

`kernel/` contains implementation code that has graduated from an API or
feasibility experiment into the maintained Nexus kernel prototype.

`nexus-ostd/` is deliberately an isolated cargo-osdk workspace. The root Cargo
workspace contains the independent `cser-model` oracle and the separate
`cser-transition-gates` production-source Loom harness, while the kernel uses a
pinned OSTD/OSDK toolchain and its own immutable lock and generated runner-base
graph. The separation prevents the executable oracle from silently sharing the
kernel's transition implementation; the transition-gate crate checks the exact
released source boundary without becoming the kernel implementation.

Within `nexus-ostd/src/`, physical source layout records responsibility without
changing the established crate-root API:

- `cser/` owns scope/effect registry and composition coordination;
- `domains/` owns scheduler, pager, and readiness refinements;
- `personality/` owns bounded Linux compatibility-pressure harnesses;
- `probes/` records platform feasibility boundaries.

The Linux and QEMU paths remain bounded evidence harnesses. All six fixed Linux
core inputs now have bounded Checked/Observed receipts, including the separate
runtime-filesystem and runtime-network successors. Their presence in the
formal prototype does not turn Linux compatibility into Nexus's research
identity or claim general filesystem, TCP/IP, external-packet, VirtIO-net/NIC,
or SMP support. The historical five-domain composition receipt remains frozen
with `runtime_fs=false` and `runtime_net=false`. Its additive seven-domain
successor uses a fresh root cohort and bounded filesystem/network adapters; it
does not preserve the retained workload effects or Stage 5B device identity.

Use only the repository-root `./x` as the public developer interface. The
private `nexus-ostd/x` entrypoint is a backend retained for isolation and
reproducibility.
