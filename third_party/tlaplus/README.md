# Pinned TLA+ tools

Nexus vendors the exact `tla2tools.jar` bytes used by the accepted v0.1
verification run. The upstream `v1.8.0` release is a mutable prerelease whose
workflow deletes and replaces the same-named asset, so a release URL plus a
checksum is fail-closed but is not a durable source of the checked bytes.

The pinned snapshot lives under `1.8.0-227f61b/`. Its `PROVENANCE.json`
records the upstream workflow run, source revision, former asset identity,
build metadata, recovery image, and both full and normalized payload digests.
`SHA256SUMS` and the Docker build independently verify the complete JAR, while
the Docker build also checks the reported TLC version and source revision.

Current-main verification then checks the installed
`/opt/tla2tools/tla2tools.jar` byte-for-byte against this vendored copy before
any specification runs. The same `run_xtask verify` container seals
`target/verification/.formal-verifier.json` after the model/spec gate; every
TLC and PlusCal log must carry the exact pinned version line. The model/spec
receipt names the runtime receipt digest as its prerequisite, and the
`nexus.verification.v6` manifest plus bundle retain the runtime receipt and all
four files in this directory. This records the TLA+ formal verifier, not the
identity of every Rust, Java, QEMU, OSDK, or guest-build tool.

These additions are a post-`v0.1.0` reproducibility successor. They preserve
the bytes used by that accepted run but do not move or rewrite the historical
tag, release assets, DOI record, or its frozen artifact schema.

The upstream project and the vendored JAR are distributed under the terms
recorded in `LICENSE.upstream`; dependency notices remain embedded in the
unmodified fat JAR.
