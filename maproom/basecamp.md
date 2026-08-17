Maintenance constraint: the user decides when this file is updated. Unless the
user explicitly requests an update to `maproom/basecamp.md`, treat it as
read-only rather than changing it merely because work progressed.

# Nexus basecamp

## Current position

Nexus is an experimental CSER operating-system substrate. The portable core is
the semantic owner for escaped-effect state and the OSTD kernel is its
production embedding. Current contract coordinates are API profile 4,
standard catalog 7, projection 8, recovery snapshot 4, and journal schema 8.
The legacy journal remains the default; the same-segment vNext journal remains
opt-in and experimental.

The current core owns bounded catalog admission, estates and composite effects,
logical and physical claims, exact custody, fencing, settlement, retirement
evidence, journal replay, and checkpoints. The trusted-local endpoint provides
durable asynchronous Accepted/Pending recovery by exact operation identity.
The bounded CSER3 handoff verifies a canonical child descriptor and gates child
first observation on the atomic parent-release/child-intent transition.

The independent model crate retains the normalized oracles used by current
differential and Loom checks. The OSTD embedding supplies the current ATA/TPM
persistence, reply and DMA paths, async endpoint adapter, bounded handoff, and
independent handoff baseline.

## Selected next phase

The user has selected a CSER Core rebaseline as the next project phase. Its
target is a provider-generation-aware, artifact-retaining, domain-extensible
portable effect authority whose ordinary transition cost depends primarily on
touched state rather than total unrelated live state.

This phase may make breaking changes to the public API, command grammar,
catalog, projection, recovery snapshot, journal, and on-disk formats. There are
no external consumers requiring compatibility shims; predecessor formats may
be rejected explicitly. The semantic model will be rebaselined before the
transition engine and persistence paths are optimized.

DeepSeek Harness is a possible later consumer and a useful logical-effect
design pressure, not a dependency of this route. The self-owned reference
surfaces remain the portable core, OSTD embedding, trusted-local asynchronous
endpoint, reply/DMA profiles, and provider-retirement workloads introduced by
the new profile.

## Toolchain position

The repository has selected a newer Rust toolchain, but the source has not yet
been migrated to it. No successful build or test result on that toolchain is
currently claimed. The first outcome of the new phase is a mechanical
toolchain baseline separated from semantic and performance changes.

## Evidence boundary

Current public development evidence consists of the final asynchronous/vNext
bundle and the matched logical handoff bundle. The former combines bounded
QEMU, portable state-profile, journal-fill, and sanitized applicability
observations. The latter covers five crash cuts for CSER and the independent
baseline with two recovery boots per row.

The handoff evidence predates the later exact-coordinate custody-conservation
refinement. Focused core checks cover that refinement, but the earlier QEMU
bundle is not represented as a rerun of the later source. The handoff workload
is logical-only and provides no physical-device result.

These evidence bodies apply only to their recorded source and current semantic
profiles. They do not validate the selected rebaseline, its future persistence
format, or its performance. New claims require new execution evidence after
the corresponding implementation stabilizes. The archived v0.1.0 release
remains the historical record.

## Repository position

The recent consolidation retired duplicated architecture, vision, narrative,
artifact, rework, RFC, evaluation, vertical-slice specification, TLC replay,
frozen-wire, and unused research-gate material. The active workspace keeps the
portable core, independent differential oracles, production OSTD checks,
async/handoff host tests, and the two current evidence bodies.

Remote trust policy, a general provider resolver, dynamic plugin loading,
multi-tenancy policy, an SDK, a general workflow graph, and physical-hardware
generalization remain outside the CSER Core rebaseline. The sibling paper
checkout remains outside any synchronization, publication, or submission
workflow unless the user separately authorizes it.
