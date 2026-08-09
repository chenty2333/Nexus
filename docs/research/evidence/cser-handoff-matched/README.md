# Matched logical handoff QEMU evidence

This directory records the sanitized result of the bounded single-hop handoff
experiment on 2026-08-10. The executable core, kernel, and host paths are bound
to Nexus commit `4867829327dd020018d60a51cd981b6184946197`; those paths were
committed without modification after the successful run.

The strict runner completed five crash cuts for each of the CSER and strongest
workload-specific baseline variants. All ten rows used a label-checked QEMU
container kill. Each row then completed two recovery boots with the same
descriptor and terminal handoff state. The host independently required one
successful terminal endpoint row and one matching provider application for
both the source and child, yielding twenty exact endpoint/provider ledger
pairs. `summary.json` is the unmodified strict summarizer output.

The result is intentionally logical-only: every guest receipt reported
`scope=logical` and `device_actions=0`. It establishes the bounded descriptor,
custody overlap, atomic parent-release/child-intent pivot, exact-404 retry, and
stable replay behavior in QEMU/TCG. It is not DMA or physical-quiescence
evidence, a remote-authentication result, a general workflow graph, or a
performance advantage claim. The strongest baseline uses its own fixed ATA
record and TPM tip and does not call the CSER engine or verifier authority.

The local raw metrics contain trial identities and paths and are therefore not
published. `manifest.json` retains only their fixed roles and SHA-256 digests.
SQLite databases, provider databases, serial logs, media, TPM state, container
IDs, namespaces, authorities, effects, run IDs, and descriptor digests remain
local.
