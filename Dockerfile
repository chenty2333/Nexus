# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The upstream OSDK image supplies QEMU, GRUB, OVMF, and the guest-image
# utilities. The nightly itself is selected by the front door from `rustc
# -Vv`; there is deliberately no date fallback here.
ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

ARG RUST_NIGHTLY_DATE
ARG OSTD_CRATE_SHA256=fc4be80e7273b7a27b7a69ba2be5d50e11df12e8709f9ad120364d9a02088fba
ARG OSTD_CRATE_URL=https://static.crates.io/crates/ostd/ostd-0.18.1.crate
ARG VIRTIO_DRIVERS_CRATE_SHA256=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
ARG VIRTIO_DRIVERS_CRATE_URL=https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.13.0.crate

ENV RUSTUP_MAX_RETRIES=10

RUN --mount=type=cache,target=/root/.rustup/downloads \
    test -n "${RUST_NIGHTLY_DATE}" \
    && case "${RUST_NIGHTLY_DATE}" in ????-??-??) ;; *) exit 1 ;; esac \
    && rustup toolchain install "nightly-${RUST_NIGHTLY_DATE}" --profile minimal \
    && rustup target add --toolchain "nightly-${RUST_NIGHTLY_DATE}" x86_64-unknown-none \
    && rustup component add --toolchain "nightly-${RUST_NIGHTLY_DATE}" \
        rust-src rustc-dev llvm-tools-preview \
    && rustup default "nightly-${RUST_NIGHTLY_DATE}" \
    && cargo +"nightly-${RUST_NIGHTLY_DATE}" install cargo-osdk --version 0.18.1 --locked \
    && command -v qemu-system-x86_64 \
    && command -v grub-mkrescue \
    && command -v xorriso \
    && command -v mkfs.ext2 \
    && command -v mcopy \
    && test -r /root/ovmf/release/OVMF.fd \
    && test -r /root/ovmf/release/OVMF_VARS.fd

ENV RUSTUP_TOOLCHAIN=nightly-${RUST_NIGHTLY_DATE}

# Keep the audited OSTD/VirtIO dependency sources under fixed image paths.
# All other dependencies use the single crates.io graph locked by the kernel.
COPY patches/cser-cargo-config.toml /root/.cargo/config.toml
COPY patches/ostd-0.18.1-cser.patch /tmp/nexus-patches/ostd-0.18.1-cser.patch
COPY kernel/nexus-ostd/patches/ostd-0.18.1-cser-arena.patch /tmp/nexus-patches/ostd-0.18.1-cser-arena.patch
COPY patches/virtio-drivers-0.13.0-cser.patch /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch

RUN set -eu; \
    mkdir -p /opt/nexus-ostd /opt/nexus-virtio; \
    curl --fail --silent --show-error --location "$OSTD_CRATE_URL" \
        --output /tmp/ostd-0.18.1.crate; \
    echo "${OSTD_CRATE_SHA256}  /tmp/ostd-0.18.1.crate" | sha256sum -c -; \
    tar -xzf /tmp/ostd-0.18.1.crate -C /opt/nexus-ostd; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-ostd/ostd-0.18.1 -p1 \
        < /tmp/nexus-patches/ostd-0.18.1-cser.patch; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-ostd/ostd-0.18.1 -p1 \
        < /tmp/nexus-patches/ostd-0.18.1-cser-arena.patch; \
    curl --fail --silent --show-error --location "$VIRTIO_DRIVERS_CRATE_URL" \
        --output /tmp/virtio-drivers-0.13.0.crate; \
    echo "${VIRTIO_DRIVERS_CRATE_SHA256}  /tmp/virtio-drivers-0.13.0.crate" | sha256sum -c -; \
    tar -xzf /tmp/virtio-drivers-0.13.0.crate -C /opt/nexus-virtio; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    chmod -R a+rX /opt/nexus-ostd /opt/nexus-virtio

# Fetch the exact root, kernel, generated-runner, and OSDK test graphs while
# the build has network access. Runtime containers mount their worktree at
# /work and run with CARGO_NET_OFFLINE enabled below.
COPY Cargo.toml Cargo.lock /tmp/nexus-root/
COPY crates/cser-core /tmp/nexus-root/crates/cser-core
COPY crates/cser-model /tmp/nexus-root/crates/cser-model
COPY tools/xtask /tmp/nexus-root/tools/xtask
COPY kernel/nexus-ostd /work
COPY crates/cser-core /crates/cser-core
COPY crates/nexus-ostd-virtio /crates/nexus-ostd-virtio
COPY kernel/nexus-ostd/guest/runtime_fs_smoke.S /tmp/nexus-runtime-fs/runtime_fs_smoke.S

RUN set -eu; \
    mv /root/.cargo/config.toml /tmp/nexus-kernel-cargo-config.toml; \
    cargo fetch --locked \
        --manifest-path "$(rustc --print sysroot)/lib/rustlib/src/rust/library/sysroot/Cargo.toml"; \
    cargo fetch --locked --manifest-path /tmp/nexus-root/Cargo.toml; \
    mv /tmp/nexus-kernel-cargo-config.toml /root/.cargo/config.toml; \
    cargo fetch --locked --manifest-path /work/Cargo.toml; \
    mkdir -p /work/target/osdk; \
    cp -a /work/osdk-runner-base /work/target/osdk/nexus-kernel-run-base; \
    cargo fetch --locked --manifest-path /work/target/osdk/nexus-kernel-run-base/Cargo.toml; \
    cargo fetch --locked --manifest-path /work/patches/osdk-test-kernel-fetch/Cargo.toml; \
    cd /work; \
    NEXUS_RUNTIME_FS_SOURCE=/tmp/nexus-runtime-fs/runtime_fs_smoke.S \
        bash scripts/build-runtime-fs.sh guest/linux-runtime-fs.elf; \
    mkdir -p /opt/nexus-fixtures; \
    bash scripts/build-runtime-fs-block-image.sh \
        guest/linux-runtime-fs.elf /opt/nexus-fixtures/runtime-fs-block.raw; \
    chmod a+r /opt/nexus-fixtures/runtime-fs-block.raw; \
    rm -rf /tmp/nexus-root /tmp/nexus-runtime-fs /work

# The base image keeps its tools below /root. Make them usable by the host UID
# selected by the workflow while retaining Cargo's cache locks as writable.
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
