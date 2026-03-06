# Futex Semantics

Axle intends to expose a Zircon-shaped `zx_futex_*` ABI, but its futex key
semantics are a deliberate compatibility divergence.

- Stock Zircon documents futex identity as process-local and based on the
  userspace virtual address.
- Axle keys futexes by `(global VMO identity, offset)` when the mapping is
  backed by a globally identified VMO.
- Anonymous mappings without a shared VMO identity fall back to a private key
  derived from `(process_id, page_base, byte_offset)`.

This matches the Axle roadmap's shared-memory model and keeps shared mappings
stable across aliases, at the cost of not matching stock Zircon futex identity
exactly.
