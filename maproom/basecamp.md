Maintenance constraint: the user decides when this file is updated. Unless the
user explicitly requests an update to `maproom/basecamp.md`, treat it as
read-only rather than changing it merely because work progressed.

# Nexus basecamp

## Current position

Nexus is an experimental CSER operating-system substrate. The portable core is
the semantic owner for escaped-effect state and the OSTD kernel is its current
embedding. The completed internal rebaseline establishes API profile 6,
standard catalog 8, projection 10, recovery snapshot 6, normalized trace 3,
journal schema 10, checkpoint envelope 3, and whole-state image 3.

The core now binds effects to worlds, provider generations, operations, charge
accounts, immutable verifier implementations, and recovery-artifact leases. It
owns provider effect fencing, settlement-only authority, bounded composite
admission, logical and physical claims, exact custody, artifact pin/release,
retirement evidence, journal replay, checkpoints, and fail-closed recovery.
Harness-shaped logical claims are expressed through a sealed catalog without
adding a plugin loader, resolver, dependency injector, or workflow engine.

There is now one active composite grammar. Root/principal/raw-binding identity,
singleton estate/effect commands, the compatibility engine mode, and the
global verifier-epoch fallback are gone. Effects derive operations from typed
identities; executor and provider generations are exact coordinates; each
accepted receipt resolves through immutable provider verifier authority.

Transition preparation builds exact replacement roots and scalars rather than
a whole-state candidate. Projection touches are coupled to mutation, and
post-persistence publication is an infallible assignment-only step. Released
effects retain immutable verification provenance after live provider drain
accounting is removed. Recovery and checkpoints continue to rebuild all
derived indexes and the canonical projection as a full oracle.

The independent model crate retains normalized differential and concurrency
oracles. The OSTD owner, reply/DMA adapters, persistence, TPM layout, recovery,
bounded handoff, and static cutover use the new grammar. The root workspace is
on Rust 1.95; OSTD retains its pinned nightly toolchain.

## Current completion boundary

The semantic, transition-engine, persistence-format, model, and OSTD migration
selected for the Profile 6 rebaseline is complete on `main`. Clean-source Core
and independent-model checks, concurrency oracles, production cutover gates,
reply and DMA QEMU paths, predecessor rejection, TPM-backed recovery, and the
four-boot persistent workload pass against the same final source.

The portable no-persistence profile shows a decision-relevant improvement at
the largest fixed comparison point: prepared publication costs about sixty-two
percent less than the clean Profile 5 baseline, while the complete measured
transition costs about twenty-eight percent less. These measurements support
the delta architecture; they do not characterize durable I/O or physical
hardware behavior.

Legacy deletion and the prepared-delta conversion are no longer unfinished
work. The next phase begins from Profile 6 as the new baseline: review the full
Nexus/CSER authority and recovery closure for latent correctness defects, fix
verified findings, then use measured costs to reduce bounded record cloning,
persistence overhead, and checkpoint overhead without weakening the durable
publication boundary.

DeepSeek Harness is a possible later consumer and a useful logical-effect
design pressure, not a dependency of this route. The self-owned reference
surfaces remain the portable core, OSTD embedding, trusted-local asynchronous
endpoint, reply/DMA profiles, and provider-retirement workloads introduced by
the new profile.

## Evidence boundary

Current public development evidence consists of the historical asynchronous/
vNext bundle and the matched logical handoff bundle. The former combines
bounded QEMU, portable state-profile, journal-fill, and sanitized applicability
observations. The latter covers five crash cuts for CSER and the independent
baseline with two recovery boots per row.

The handoff evidence predates the later exact-coordinate custody-conservation
refinement. Focused core checks cover that refinement, but the earlier QEMU
bundle is not represented as a rerun of the later source. The handoff workload
is logical-only and provides no physical-device result.

These evidence bodies apply only to their recorded older source. They do not
validate Profile 6 or the prepared-delta engine. The clean-source Profile 6
verification and local performance comparison are current development and
system evidence, not a new sealed public evidence body. The archived v0.1.0
release remains the historical record.

## Repository position

The recent consolidation retired duplicated architecture, vision, narrative,
artifact, rework, RFC, evaluation, vertical-slice specification, TLC replay,
frozen-wire, and unused research-gate material. The active workspace keeps the
portable core, independent differential oracles, production OSTD checks,
async/handoff host tests, and two immutable historical evidence bodies.

The repository retains its active bare-metal target configuration, pinned Rust
toolchains, OSTD/VirtIO patch chain, and a thin root `x` front door. The root
and kernel `x` layers, toolchain pins, citation metadata, dependency patches,
and historical evidence remain active build or provenance inputs; they are not
legacy semantic owners and are not deleted as part of the Core cut.

Remote trust policy, a general provider resolver, dynamic plugin loading,
multi-tenancy policy, an SDK, a general workflow graph, and physical-hardware
generalization remain outside the CSER Core rebaseline. The sibling paper
checkout remains outside any synchronization, publication, or submission
workflow unless the user separately authorizes it.
