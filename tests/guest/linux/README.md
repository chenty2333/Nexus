# Retained Linux guest inputs

This directory contains small Linux x86-64 C/assembly programs retained as
future compatibility-pressure inputs. They are not a retained Starnix
implementation, and they do not define Nexus's native ABI or research identity.

`sources/` is an exact copy of the 34 source files previously built from
`user/linux-*` at repository commit
`8d5d07e35b0051bd4ef001224714decc0615ff49`. `SOURCES.toml` maps every copy to
its original path and SHA-256 digest. The old paths remain temporarily only so
the larger legacy deletion can happen after the new build and CI cut over.

`COMPATIBILITY.toml` records the behavior each workload was intended to
exercise. It deliberately refers to Linux behavior rather than old component
URLs, sidecar VMOs, stop packets, or `zx_*` calls. Only the six `core` entries
form the bounded Stage 6 gate and carry mandatory CSER injection profiles;
`stretch` entries add optional breadth, while `archive-input` entries carry no
implementation commitment. A future Linux-personality harness may refine the
build and success protocol while keeping these inputs as pressure tests.

## Build profiles

- `static-raw`: `clang --target=x86_64-unknown-linux-gnu`, `-nostdlib`, static,
  non-PIE, `_start` entry.
- `dynamic-exec-raw`: `-nostdlib` ET_EXEC with an explicit `PT_INTERP`.
- `shared-interpreter-raw`: `-nostdlib -shared -fPIC` interpreter payload.
- `dynamic-pie-raw`: `-nostdlib -fPIE -pie` with an explicit `PT_INTERP`.
- `glibc-pie`: normal host C compilation as PIE with a pinned guest glibc and
  loader supplied later by the Docker guest-artifact build.

The original sources intentionally contain raw Linux syscall numbers and
layout constants. They are executable test inputs, not a constants library.
New Linux-personality code must use maintained Linux UAPI sources rather than
copying constants out of these files.

Some exact inputs also preserve a legacy-specific expectation. Such cases have
an `adaptation_required` entry in the compatibility catalog. Adaptation applies
to the future generated test artifact or result interpretation; the hashed
source copy remains unchanged.

BusyBox, glibc, the dynamic loader, and runtime libraries are external pinned
guest artifacts and are not copied into this directory.
