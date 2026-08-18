# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE} AS build

RUN rustup target add --toolchain nightly-2026-04-03 x86_64-unknown-none \
    && rustup component add --toolchain nightly-2026-04-03 rustfmt clippy \
    && cargo install cargo-osdk --version 0.18.0 --locked

COPY crates/nexus-ostd-virtio /crates/nexus-ostd-virtio

ARG OSTD_CRATE_SHA256=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
ARG OSTD_CRATE_URL=https://static.crates.io/crates/ostd/ostd-0.18.0.crate
ARG VIRTIO_DRIVERS_CRATE_SHA256=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
ARG VIRTIO_DRIVERS_CRATE_URL=https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.13.0.crate
ARG SPIN_CRATE_SHA256=6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67
ARG SPIN_CRATE_URL=https://static.crates.io/crates/spin/spin-0.9.8.crate
ARG OSDK_TEST_KERNEL_CRATE_SHA256=275faff80a915be872fdf0bfbe94bc6e4a80debbd4706123be55b72d3f30de25
ARG OSDK_TEST_KERNEL_CRATE_URL=https://static.crates.io/crates/osdk-test-kernel/osdk-test-kernel-0.18.0.crate
COPY patches/ostd-0.18.0-cser.patch /tmp/nexus-patches/ostd-0.18.0-cser.patch
COPY kernel/nexus-ostd/patches/ostd-0.18.0-cser-arena.patch \
    /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch
COPY patches/virtio-drivers-0.13.0-cser.patch \
    /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch
COPY patches/virtio-drivers-0.13.0-LICENSE-MIT \
    /tmp/nexus-patches/virtio-drivers-0.13.0-LICENSE-MIT
COPY kernel/nexus-ostd/patches/virtio-drivers-0.13.0.lock \
    /tmp/nexus-patches/virtio-drivers-0.13.0.lock
COPY tools/ostd/assert-cser-patch.sh /usr/local/bin/assert-ostd-cser-patch
COPY kernel/nexus-ostd/patches/assert-ostd-cser-arena-patch.sh \
    /usr/local/bin/assert-ostd-cser-arena-patch
COPY tools/virtio/assert-cser-patch.sh /usr/local/bin/assert-virtio-cser-patch
COPY tools/virtio/assert-production-substrate.sh \
    /usr/local/bin/assert-production-virtio-substrate
RUN set -eu; \
    mkdir -p /opt/nexus-source /opt/nexus-ostd /opt/nexus-virtio /opt/nexus-spin \
        /opt/nexus-osdk-test-kernel; \
    archive=/opt/nexus-source/ostd-0.18.0.crate; \
    curl --fail --silent --show-error --location "$OSTD_CRATE_URL" --output "$archive"; \
    echo "${OSTD_CRATE_SHA256}  ${archive}" | sha256sum -c -; \
    tar -xzf "$archive" -C /opt/nexus-ostd; \
    patch --batch --forward -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    patch --batch --dry-run --reverse -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    /usr/local/bin/assert-ostd-cser-patch \
        /tmp/nexus-patches/ostd-0.18.0-cser.patch \
        /opt/nexus-ostd/ostd-0.18.0; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch; \
    patch --fuzz=0 --batch --dry-run --reverse \
        -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch; \
    virtio_archive=/opt/nexus-source/virtio-drivers-0.13.0.crate; \
    curl --fail --silent --show-error --location "$VIRTIO_DRIVERS_CRATE_URL" \
        --output "$virtio_archive"; \
    echo "${VIRTIO_DRIVERS_CRATE_SHA256}  ${virtio_archive}" | sha256sum -c -; \
    tar -xzf "$virtio_archive" -C /opt/nexus-virtio; \
    spin_archive=/opt/nexus-source/spin-0.9.8.crate; \
    curl --fail --silent --show-error --location "$SPIN_CRATE_URL" \
        --output "$spin_archive"; \
    echo "${SPIN_CRATE_SHA256}  ${spin_archive}" | sha256sum -c -; \
    tar -xzf "$spin_archive" -C /opt/nexus-spin; \
    osdk_test_kernel_archive=/opt/nexus-source/osdk-test-kernel-0.18.0.crate; \
    curl --fail --silent --show-error --location "$OSDK_TEST_KERNEL_CRATE_URL" \
        --output "$osdk_test_kernel_archive"; \
    echo "${OSDK_TEST_KERNEL_CRATE_SHA256}  ${osdk_test_kernel_archive}" \
        | sha256sum -c -; \
    tar -xzf "$osdk_test_kernel_archive" -C /opt/nexus-osdk-test-kernel; \
    patch --batch --forward -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    patch --batch --dry-run --reverse \
        -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    cp /tmp/nexus-patches/virtio-drivers-0.13.0.lock \
        /opt/nexus-virtio/virtio-drivers-0.13.0/Cargo.lock; \
    chmod -R a+rX /opt/nexus-source /opt/nexus-ostd /opt/nexus-virtio \
        /opt/nexus-spin /opt/nexus-osdk-test-kernel; \
    /usr/local/bin/assert-ostd-cser-arena-patch \
        /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch \
        /opt/nexus-ostd/ostd-0.18.0 \
        /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    /usr/local/bin/assert-virtio-cser-patch \
        /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch \
        /opt/nexus-virtio/virtio-drivers-0.13.0 \
        /tmp/nexus-patches/virtio-drivers-0.13.0-LICENSE-MIT; \
    /usr/local/bin/assert-production-virtio-substrate \
        /crates/nexus-ostd-virtio/src/production.rs \
        /crates/nexus-ostd-virtio/src/lib.rs \
        /crates/nexus-ostd-virtio/src/pci.rs
COPY patches/cser-cargo-config.toml /root/.cargo/config.toml
COPY .dockerignore /nexus-source-inputs/repo.dockerignore
COPY Cargo.toml Cargo.lock /nexus-source-inputs/
COPY tests/guest/linux/sources/linux-runtime-fs-smoke/runtime_fs_smoke.S \
    /nexus-source-inputs/runtime_fs_smoke.S
COPY kernel/nexus-ostd/patches/osdk-test-kernel-fetch.toml \
    /tmp/nexus-osdk-test-kernel-fetch/Cargo.toml
COPY kernel/nexus-ostd/patches/osdk-test-kernel-fetch.lock \
    /tmp/nexus-osdk-test-kernel-fetch/Cargo.lock
COPY kernel/nexus-ostd/patches/osdk-test-kernel-fetch.rs \
    /tmp/nexus-osdk-test-kernel-fetch/src/lib.rs
RUN cargo fetch --locked --manifest-path /tmp/nexus-osdk-test-kernel-fetch/Cargo.toml \
    && rm -rf /tmp/nexus-osdk-test-kernel-fetch
RUN cargo test --manifest-path /opt/nexus-virtio/virtio-drivers-0.13.0/Cargo.toml \
        --lib --no-default-features --locked \
    && rm -rf /opt/nexus-virtio/virtio-drivers-0.13.0/target \
    && rm -f /opt/nexus-virtio/virtio-drivers-0.13.0/Cargo.lock \
        /tmp/nexus-patches/virtio-drivers-0.13.0.lock

COPY kernel/nexus-ostd/src/lib.rs /kernel/nexus-ostd/src/lib.rs
COPY kernel/nexus-ostd/src/cser/core_device_quarantine.rs \
    kernel/nexus-ostd/src/cser/core_dma_adapter.rs \
    kernel/nexus-ostd/src/cser/core_dma_arena_allocator.rs \
    kernel/nexus-ostd/src/cser/core_persistent_runtime.rs \
    kernel/nexus-ostd/src/cser/core_pio_journal.rs \
    kernel/nexus-ostd/src/cser/core_portal_vnext.rs \
    kernel/nexus-ostd/src/cser/core_production_registry.rs \
    kernel/nexus-ostd/src/cser/core_qemu_persistent_boot.rs \
    kernel/nexus-ostd/src/cser/core_reboot.rs \
    kernel/nexus-ostd/src/cser/core_reply_adapter.rs \
    kernel/nexus-ostd/src/cser/core_reply_outbox.rs \
    kernel/nexus-ostd/src/cser/core_runtime.rs \
    kernel/nexus-ostd/src/cser/core_supervisor_vnext.rs \
    kernel/nexus-ostd/src/cser/core_tpm_anchor.rs \
    /kernel/nexus-ostd/src/cser/
COPY kernel/nexus-ostd/cser-production-sources.txt \
    /kernel/nexus-ostd/cser-production-sources.txt

# cargo-osdk's -Zbuild-std and generated runner packages have dependencies that
# a plain `cargo fetch --target` does not discover. Prime the real graph while
# the image is built, then make every mounted-workspace invocation offline.
COPY kernel/nexus-ostd/Cargo.toml \
    kernel/nexus-ostd/Cargo.lock \
    kernel/nexus-ostd/rust-toolchain.toml \
    kernel/nexus-ostd/OSDK.toml \
    /tmp/nexus-ostd-inputs/
COPY kernel/nexus-ostd/osdk-runner-base /tmp/nexus-ostd-inputs/osdk-runner-base
COPY kernel/nexus-ostd/scripts/build-runtime-fs.sh \
    kernel/nexus-ostd/scripts/assert-runtime-fs-artifacts.sh \
    kernel/nexus-ostd/scripts/build-runtime-fs-block-image.sh \
    kernel/nexus-ostd/scripts/assert-runtime-fs-block-image.sh \
    /tmp/nexus-ostd-inputs/scripts/
COPY crates/cser-core /crates/cser-core
COPY crates/cser-model /crates/cser-model
# The catalog-digest helper runs against the repository workspace lockfile in
# the network-disabled runtime container. Prime that exact locked host graph
# while building the pinned image so helper execution cannot consult a registry.
RUN --mount=type=bind,source=.,target=/repo,readonly \
    set -eu; \
    mkdir -p /tmp/nexus-cser-cargo-home; \
    ln -s /root/.cargo/registry /tmp/nexus-cser-cargo-home/registry; \
    cd /tmp; \
    HOME=/tmp/nexus-cser-cargo-home \
        CARGO_HOME=/tmp/nexus-cser-cargo-home \
        RUSTUP_HOME=/root/.rustup \
        cargo fetch --locked --manifest-path /repo/Cargo.toml; \
    rm -rf -- /tmp/nexus-cser-cargo-home
RUN --mount=type=bind,source=kernel/nexus-ostd,target=/tmp/nexus-ostd-source,readonly \
    cmp /tmp/nexus-ostd-inputs/Cargo.toml /tmp/nexus-ostd-source/Cargo.toml \
    && cmp /tmp/nexus-ostd-inputs/Cargo.lock /tmp/nexus-ostd-source/Cargo.lock \
    && cmp /tmp/nexus-ostd-inputs/rust-toolchain.toml \
        /tmp/nexus-ostd-source/rust-toolchain.toml \
    && cmp /tmp/nexus-ostd-inputs/OSDK.toml /tmp/nexus-ostd-source/OSDK.toml \
    && diff -ru /tmp/nexus-ostd-inputs/osdk-runner-base \
        /tmp/nexus-ostd-source/osdk-runner-base \
    && cmp /tmp/nexus-ostd-inputs/scripts/build-runtime-fs.sh \
        /tmp/nexus-ostd-source/scripts/build-runtime-fs.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/assert-runtime-fs-artifacts.sh \
        /tmp/nexus-ostd-source/scripts/assert-runtime-fs-artifacts.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/build-runtime-fs-block-image.sh \
        /tmp/nexus-ostd-source/scripts/build-runtime-fs-block-image.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/assert-runtime-fs-block-image.sh \
        /tmp/nexus-ostd-source/scripts/assert-runtime-fs-block-image.sh \
    && rm -rf /work \
    && cp -a /tmp/nexus-ostd-source /work \
    && cd /work \
    && NEXUS_RUNTIME_FS_SOURCE=/nexus-source-inputs/runtime_fs_smoke.S \
        bash scripts/build-runtime-fs.sh guest/linux-runtime-fs.elf \
    && mkdir -p /opt/nexus-fixtures \
    && bash scripts/build-runtime-fs-block-image.sh \
        guest/linux-runtime-fs.elf /opt/nexus-fixtures/runtime-fs-block.raw \
    && bash scripts/assert-runtime-fs-block-image.sh \
        guest/linux-runtime-fs.elf /opt/nexus-fixtures/runtime-fs-block.raw \
    && test "$(stat -c %a /opt/nexus-fixtures/runtime-fs-block.raw)" = 444 \
    && cargo check --locked --target x86_64-unknown-none \
        --no-default-features --features cser-production \
    && cargo check --locked --target x86_64-unknown-none \
        --no-default-features --features cser-core-reply-recovery \
    && cargo check --locked --target x86_64-unknown-none \
        --no-default-features --features cser-core-dma-recovery \
    && cargo check --locked --target x86_64-unknown-none \
        --no-default-features --features cser-core-tpm-anchor \
    && cargo osdk check --locked \
    && rm -rf target/osdk/nexus-kernel-run-base \
    && mkdir -p target/osdk \
    && cp -a /tmp/nexus-ostd-inputs/osdk-runner-base \
        target/osdk/nexus-kernel-run-base \
    && chmod a-w target/osdk/nexus-kernel-run-base/Cargo.lock \
    && cargo fetch --manifest-path target/osdk/nexus-kernel-run-base/Cargo.toml --locked \
    && CARGO_NET_OFFLINE=true cargo osdk build --scheme cser-production \
    && cmp /tmp/nexus-ostd-inputs/Cargo.lock /work/Cargo.lock \
    && sed -i 's/[[:space:]]\+$//' target/osdk/nexus-kernel-run-base/*.ld \
    && diff -ru /tmp/nexus-ostd-inputs/osdk-runner-base \
        /work/target/osdk/nexus-kernel-run-base \
    && rm -rf /work/target /work/guest/*.bin /work/guest/*.elf \
    && rm -rf /tmp/nexus-ostd-inputs

# The upstream image stores its toolchain and firmware below a mode-0700
# /root. Make only the traversal/read bits and Cargo's small lock databases
# available to the invoking host UID. Moving or recursively chmodding the
# multi-gigabyte toolchain would copy it into a new image layer.
RUN chmod 0755 /root \
    && find /root/.cargo /root/.rustup -type d ! -perm -0005 -exec chmod o+rx {} + \
    && find /root/.cargo /root/.rustup -type f ! -perm -0004 -exec chmod o+r {} + \
    && for lock in /root/.cargo/.package-cache /root/.cargo/.global-cache; do \
        if [ -e "$lock" ]; then chmod a+rw "$lock"; fi; \
    done

ENV CARGO_HOME=/root/.cargo \
    RUSTUP_HOME=/root/.rustup \
    CARGO_NET_OFFLINE=true \
    PATH=/root/.cargo/bin:/usr/local/grub/bin:/usr/local/qemu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /work

# Audit the immutable build-stage snapshot with a fresh pinned toolchain. No
# repository-controlled build step executes in this stage, and both the
# candidate root and source context are mounted read-only. The source-proof
# enumerator in the pinned x front door is the canonical, sorted, path-bound
# closure for every copied and compiled Nexus input. Compare the verifier
# program before executing it, then run that candidate copy with an empty,
# explicit environment so an unreviewed build-stage script cannot choose the
# proof authority.
FROM ${OSDK_IMAGE} AS cser-verifier
RUN --network=none \
    --mount=type=bind,from=build,source=/,target=/candidate-root,readonly \
    --mount=type=bind,source=kernel/nexus-ostd,target=/expected-kernel,readonly \
    --mount=type=bind,source=.,target=/expected-repo,readonly \
    set -eu; \
    test ! -e /candidate-root/nexus-cser-verified; \
    test ! -L /candidate-root/nexus-cser-verified; \
    test ! -e /verified; \
    test ! -L /verified; \
    test -f /expected-kernel/x; \
    test ! -L /expected-kernel/x; \
    test -x /expected-kernel/x; \
    test -f /candidate-root/work/x; \
    test ! -L /candidate-root/work/x; \
    test -x /candidate-root/work/x; \
    cmp -- /expected-kernel/x /candidate-root/work/x; \
    /usr/bin/env -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LC_ALL=C \
        NEXUS_SOURCE_PROOF_MODE=verify \
        NEXUS_SOURCE_PROOF_REPO_ROOT=/expected-repo \
        NEXUS_SOURCE_PROOF_KERNEL_ROOT=/expected-kernel \
        NEXUS_SOURCE_PROOF_CANDIDATE_ROOT=/candidate-root \
        /usr/bin/bash -p /candidate-root/work/x > /verified; \
    chmod 0444 /verified; \
    test -f /verified; \
    test ! -L /verified; \
    test "$(/usr/bin/stat -c %a /verified)" = 444

# The sole final-stage mutation creates a direct-root, read-only proof marker.
# The verifier first proved that the build snapshot did not already own this
# path, so this COPY cannot traverse a repository-controlled parent symlink.
FROM build AS final
COPY --from=cser-verifier /verified /nexus-cser-verified
