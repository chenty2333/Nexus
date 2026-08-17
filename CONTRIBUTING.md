# Contributing to Nexus

Nexus is a research codebase with no external compatibility users. Breaking
changes are acceptable when they simplify the authoritative model, strengthen a
safety boundary, or remove obsolete research machinery.

Read these before substantive work:

- [maproom/terrain.md](maproom/terrain.md)
- [maproom/basecamp.md](maproom/basecamp.md)
- [maproom/route.md](maproom/route.md)
- [maproom/hazards.md](maproom/hazards.md)

Do not introduce another current roadmap, architecture ledger, evidence claim
ledger, or status file outside `maproom/`.

## Supported workflow

Use the root `./x` entry point:

| Command | Purpose |
| --- | --- |
| `./x doctor` | Validate Docker, repository layout, and pinned toolchain |
| `./x build` | Build the host workspace and OSTD kernel |
| `./x test --unit` | Run current host unit and differential tests |
| `./x test --quick` | Run host checks plus the kernel static gate |
| `./x test --system` | Run the current persistent recovery system path |
| `./x test --full` | Run the complete supported local verification path |
| `./x check` | Run schema, Rust, host experiment, and kernel checks |
| `./x fmt` | Format the current Rust workspaces |
| `./x verify` | Seal the current clean-source production recovery gate |
| `./x clean --all` | Remove generated caches and local run evidence |

The root container is intentionally independent of host Rust. The OSTD kernel
has a separate pinned build graph under `kernel/nexus-ostd`.

## Change discipline

- Keep one authoritative semantic path. Do not dual-write a historical state
  machine and the current core.
- Add a core transition only when a smaller adapter/runtime policy cannot
  enforce the required invariant.
- Preserve exact claim coordinates, fencing generations, journal-before-anchor
  ordering, and evidence-specific retirement.
- Do not translate timeout, unavailable transport, missing telemetry, or
  nonterminal endpoint state into business failure.
- Keep the independent current oracles independent: do not call production
  transition helpers to compute their expected result.
- Prefer focused tests for the changed invariant. Historical gate shapes and
  frozen receipt populations are not compatibility obligations on current
  main.

## Evidence changes

Every checked or observed claim must identify its code revision, environment,
workload, and source. A newer implementation does not inherit an older
source-bound bundle automatically.

Do not edit a committed evidence bundle to make it describe newer code. Capture
a new bundle when the new claim needs execution evidence, or state that the old
bundle applies only to its recorded source commit.

Public evidence must exclude raw operation/effect/resource identities,
databases, logs, media, TPM state, absolute paths, container identifiers, and
HMAC keys. Missing evidence remains unknown or right-censored.

## Documentation changes

Maproom maintenance is user-directed. Do not update terrain, basecamp, or route
merely because work progressed or seems worth recording. When the user asks
for an update, change only the relevant document:

- conceptual or semantic reasoning: `maproom/terrain.md`;
- deliberately established current position: `maproom/basecamp.md`;
- user-selected high-level direction: `maproom/route.md`;
- verified project-specific failure modes: `maproom/hazards.md`.

General development conventions belong in this contributing guide, not in the
hazards file. Status feeds, session logs, result ledgers, and detailed execution
plans do not belong in the maproom.

README should remain a concise entry point. Historical states belong to Git
history, tags, and release archives rather than duplicated archive trees on
current main.

## Publication boundary

Do not configure, synchronize, push, publish, or submit the sibling
`nexus-hotos` paper repository without explicit user authorization. Local code
or documentation cleanup in Nexus does not grant that authorization.
