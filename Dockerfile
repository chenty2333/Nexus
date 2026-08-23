# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The upstream OSDK image supplies QEMU, GRUB, OVMF, and the guest-image
# utilities. The nightly itself is selected by the front door from `rustc
# -Vv`; there is deliberately no date fallback here.
ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

ARG RUST_NIGHTLY_DATE
ARG OSTD_CRATE_SHA256=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
ARG OSTD_CRATE_URL=https://static.crates.io/crates/ostd/ostd-0.18.0.crate
ARG VIRTIO_DRIVERS_CRATE_SHA256=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
ARG VIRTIO_DRIVERS_CRATE_URL=https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.13.0.crate
ARG SPIN_CRATE_SHA256=6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67
ARG SPIN_CRATE_URL=https://static.crates.io/crates/spin/spin-0.9.8.crate

ENV RUSTUP_MAX_RETRIES=10

RUN --mount=type=cache,target=/root/.rustup/downloads \
    test -n "${RUST_NIGHTLY_DATE}" \
    && case "${RUST_NIGHTLY_DATE}" in ????-??-??) ;; *) exit 1 ;; esac \
    && rustup toolchain install "nightly-${RUST_NIGHTLY_DATE}" --profile minimal \
    && rustup target add --toolchain "nightly-${RUST_NIGHTLY_DATE}" x86_64-unknown-none \
    && rustup component add --toolchain "nightly-${RUST_NIGHTLY_DATE}" \
        rust-src rustc-dev llvm-tools-preview \
    && cargo +"nightly-${RUST_NIGHTLY_DATE}" install cargo-osdk --version 0.18.0 --locked \
    && command -v qemu-system-x86_64 \
    && command -v grub-mkrescue \
    && command -v xorriso \
    && command -v mkfs.ext2 \
    && command -v mcopy \
    && test -r /root/ovmf/release/OVMF.fd \
    && test -r /root/ovmf/release/OVMF_VARS.fd

ARG UNWINDING_CRATE_SHA256=60612c845ef41699f39dc8c5391f252942c0a88b7d15da672eff0d14101bbd6d
ARG UNWINDING_CRATE_URL=https://static.crates.io/crates/unwinding/unwinding-0.2.8.crate
ARG X86_64_CRATE_SHA256=c101112411baafbb4bf8d33e4c4a80ab5b02d74d2612331c61e8192fc9710491
ARG X86_64_CRATE_URL=https://static.crates.io/crates/x86_64/x86_64-0.14.13.crate
ARG RUSTC_LIBC_CRATE_SHA256=b5b646652bf6661599e1da8901b3b9522896f01e736bad5f723fe7a3a27f899d
ARG RUSTC_LIBC_CRATE_URL=https://static.crates.io/crates/libc/libc-0.2.183.crate
ARG RUSTC_DEMANGLE_CRATE_SHA256=b50b8869d9fc858ce7266cce0194bd74df58b9d0e3f6df3a9fc8eb470d95c09d
ARG RUSTC_DEMANGLE_CRATE_URL=https://static.crates.io/crates/rustc-demangle/rustc-demangle-0.1.27.crate
ARG RUSTC_LITERAL_ESCAPER_CRATE_SHA256=8be87abb9e40db7466e0681dc8ecd9dcfd40360cb10b4c8fe24a7c4c3669b198
ARG RUSTC_LITERAL_ESCAPER_CRATE_URL=https://static.crates.io/crates/rustc-literal-escaper/rustc-literal-escaper-0.0.7.crate

ENV RUSTUP_TOOLCHAIN=nightly-${RUST_NIGHTLY_DATE}

# Keep patched dependency sources under fixed image paths. The global config
# supplies OSDK's OSTD/VirtIO patches and the fixed-new-nightly compatibility
# paths required by both direct kernel checks and OSDK's nested Cargo build.
COPY patches/cser-cargo-config.toml /root/.cargo/config.toml
COPY patches/ostd-0.18.0-cser.patch /tmp/nexus-patches/ostd-0.18.0-cser.patch
COPY kernel/nexus-ostd/patches/ostd-0.18.0-cser-arena.patch /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch
COPY patches/unwinding-0.2.8-rustc-catch-unwind-bool.patch /tmp/nexus-patches/unwinding-0.2.8-rustc-catch-unwind-bool.patch
COPY patches/virtio-drivers-0.13.0-cser.patch /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch
COPY patches/x86_64-0.14.13-rustc-step.patch /tmp/nexus-patches/x86_64-0.14.13-rustc-step.patch

RUN set -eu; \
    mkdir -p /opt/nexus-ostd /opt/nexus-virtio /opt/nexus-spin /opt/nexus-unwinding /opt/nexus-x86_64; \
    curl --fail --silent --show-error --location "$OSTD_CRATE_URL" \
        --output /tmp/ostd-0.18.0.crate; \
    echo "${OSTD_CRATE_SHA256}  /tmp/ostd-0.18.0.crate" | sha256sum -c -; \
    tar -xzf /tmp/ostd-0.18.0.crate -C /opt/nexus-ostd; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser-arena.patch; \
    curl --fail --silent --show-error --location "$VIRTIO_DRIVERS_CRATE_URL" \
        --output /tmp/virtio-drivers-0.13.0.crate; \
    echo "${VIRTIO_DRIVERS_CRATE_SHA256}  /tmp/virtio-drivers-0.13.0.crate" | sha256sum -c -; \
    tar -xzf /tmp/virtio-drivers-0.13.0.crate -C /opt/nexus-virtio; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    curl --fail --silent --show-error --location "$SPIN_CRATE_URL" \
        --output /tmp/spin-0.9.8.crate; \
    echo "${SPIN_CRATE_SHA256}  /tmp/spin-0.9.8.crate" | sha256sum -c -; \
    tar -xzf /tmp/spin-0.9.8.crate -C /opt/nexus-spin; \
    curl --fail --silent --show-error --location "$UNWINDING_CRATE_URL" \
        --output /tmp/unwinding-0.2.8.crate; \
    echo "${UNWINDING_CRATE_SHA256}  /tmp/unwinding-0.2.8.crate" | sha256sum -c -; \
    tar -xzf /tmp/unwinding-0.2.8.crate -C /opt/nexus-unwinding; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-unwinding/unwinding-0.2.8 -p1 \
        < /tmp/nexus-patches/unwinding-0.2.8-rustc-catch-unwind-bool.patch; \
    curl --fail --silent --show-error --location "$X86_64_CRATE_URL" \
        --output /tmp/x86_64-0.14.13.crate; \
    echo "${X86_64_CRATE_SHA256}  /tmp/x86_64-0.14.13.crate" | sha256sum -c -; \
    tar -xzf /tmp/x86_64-0.14.13.crate -C /opt/nexus-x86_64; \
    patch --fuzz=0 --batch --forward -d /opt/nexus-x86_64/x86_64-0.14.13 -p1 \
        < /tmp/nexus-patches/x86_64-0.14.13-rustc-step.patch; \
    curl --fail --silent --show-error --location "$RUSTC_LIBC_CRATE_URL" \
        --output /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/libc-0.2.183.crate; \
    echo "${RUSTC_LIBC_CRATE_SHA256}  /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/libc-0.2.183.crate" \
        | sha256sum -c -; \
    tar -xzf /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/libc-0.2.183.crate \
        -C /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f; \
    printf '%s' '{"v":1}' \
        > /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libc-0.2.183/.cargo-ok; \
    curl --fail --silent --show-error --location "$RUSTC_DEMANGLE_CRATE_URL" \
        --output /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-demangle-0.1.27.crate; \
    echo "${RUSTC_DEMANGLE_CRATE_SHA256}  /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-demangle-0.1.27.crate" \
        | sha256sum -c -; \
    tar -xzf /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-demangle-0.1.27.crate \
        -C /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f; \
    printf '%s' '{"v":1}' \
        > /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustc-demangle-0.1.27/.cargo-ok; \
    curl --fail --silent --show-error --location "$RUSTC_LITERAL_ESCAPER_CRATE_URL" \
        --output /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-literal-escaper-0.0.7.crate; \
    echo "${RUSTC_LITERAL_ESCAPER_CRATE_SHA256}  /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-literal-escaper-0.0.7.crate" \
        | sha256sum -c -; \
    tar -xzf /root/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/rustc-literal-escaper-0.0.7.crate \
        -C /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f; \
    printf '%s' '{"v":1}' \
        > /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustc-literal-escaper-0.0.7/.cargo-ok; \
    chmod -R a+rX /opt/nexus-ostd /opt/nexus-virtio /opt/nexus-spin /opt/nexus-unwinding /opt/nexus-x86_64

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
