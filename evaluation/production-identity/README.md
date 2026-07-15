# Production-identity Phase 1 contracts

This directory freezes the machine-readable inputs for the RFC 0001 Phase 1
research gate. `transition-map.toml` maps each bounded abstract transition to
the independent safe-Rust oracle and the current production Registry source
target. `fault-matrix.toml` freezes the exact later fault population before
production execution begins.

Evidence states have deliberately narrow meanings:

- `checked`: exercised by the committed TLA+ and/or independent safe-Rust
  oracle named by the row. It does not mean that the production path ran.
- `observed`: executed through the shared production Registry and recorded with
  the complete required observation fields. Phase 1 has zero such rows.
- `planned`: source target and expected behavior are frozen, but the exact
  production or hardware execution has not happened.

The Phase 1 receipt therefore binds 22 transition rows, 35 fault cells, the
exact `5 + 3 + 3` Rust integration-test population, and zero production
observations. In particular, Loom remains an abstract concurrency check rather
than evidence for OSTD locks, IRQ masking, memory ordering, or 2/4-vCPU QEMU
execution.
