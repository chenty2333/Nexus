# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

RUN rustup target add --toolchain nightly-2026-04-03 x86_64-unknown-none \
    && cargo install cargo-osdk --version 0.18.0 --locked

COPY --from=nexus-root crates/cser-transition-gates /crates/cser-transition-gates
COPY --from=nexus-root crates/nexus-ostd-virtio /crates/nexus-ostd-virtio
COPY --from=nexus-root tools/ostd/assert-cser-patch.sh \
    /usr/local/bin/assert-ostd-cser-patch
COPY --from=nexus-root tools/virtio/assert-cser-patch.sh \
    /usr/local/bin/assert-virtio-cser-patch
COPY --from=nexus-root tools/virtio/assert-production-substrate.sh \
    /usr/local/bin/assert-production-virtio-substrate

ARG OSTD_CRATE_SHA256=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
ARG OSTD_CRATE_URL=https://static.crates.io/crates/ostd/ostd-0.18.0.crate
ARG VIRTIO_DRIVERS_CRATE_SHA256=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
ARG VIRTIO_DRIVERS_CRATE_URL=https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.13.0.crate

COPY --from=nexus-root kernel/nexus-ostd/src/cser/effect_registry.rs \
    /kernel/nexus-ostd/src/cser/effect_registry.rs
COPY --from=nexus-root kernel/nexus-ostd/Cargo.toml \
    kernel/nexus-ostd/Cargo.lock \
    /kernel/nexus-ostd/

# Build the audited overlays from exact crates.io archives: OSTD remains under
# MPL-2.0, while virtio-drivers and its split-publication patch are MIT. The
# complete patched sources exist only in the image; they are never vendored.
COPY --from=nexus-root patches/ostd-0.18.0-cser.patch \
    /tmp/nexus-patches/ostd-0.18.0-cser.patch
COPY --from=nexus-root patches/virtio-drivers-0.13.0-cser.patch \
    /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch
COPY --from=nexus-root patches/virtio-drivers-0.13.0-LICENSE-MIT \
    /tmp/nexus-patches/virtio-drivers-0.13.0-LICENSE-MIT
COPY LICENSE-MPL-2.0 /opt/nexus-ostd/LICENSE-MPL-2.0
RUN set -eu; \
    mkdir -p /opt/nexus-source /opt/nexus-ostd /opt/nexus-virtio; \
    archive=/opt/nexus-source/ostd-0.18.0.crate; \
    curl --fail --silent --show-error --location "$OSTD_CRATE_URL" --output "$archive"; \
    echo "${OSTD_CRATE_SHA256}  ${archive}" | sha256sum -c -; \
    tar -xzf "$archive" -C /opt/nexus-ostd; \
    patch --batch --forward -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    patch --batch --dry-run --reverse -d /opt/nexus-ostd/ostd-0.18.0 -p1 \
        < /tmp/nexus-patches/ostd-0.18.0-cser.patch; \
    virtio_archive=/opt/nexus-source/virtio-drivers-0.13.0.crate; \
    curl --fail --silent --show-error --location "$VIRTIO_DRIVERS_CRATE_URL" \
        --output "$virtio_archive"; \
    echo "${VIRTIO_DRIVERS_CRATE_SHA256}  ${virtio_archive}" | sha256sum -c -; \
    tar -xzf "$virtio_archive" -C /opt/nexus-virtio; \
    patch --batch --forward -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    patch --batch --dry-run --reverse \
        -d /opt/nexus-virtio/virtio-drivers-0.13.0 -p1 \
        < /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch; \
    chmod -R a+rX /opt/nexus-source /opt/nexus-ostd /opt/nexus-virtio; \
    /usr/local/bin/assert-virtio-cser-patch \
        /tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch \
        /opt/nexus-virtio/virtio-drivers-0.13.0 \
        /tmp/nexus-patches/virtio-drivers-0.13.0-LICENSE-MIT; \
    /usr/local/bin/assert-production-virtio-substrate \
        /crates/nexus-ostd-virtio/src/production.rs \
        /crates/nexus-ostd-virtio/src/lib.rs \
        /crates/nexus-ostd-virtio/src/portal.rs

COPY assets/sector0.txt /opt/nexus-fixtures/sector0.txt
RUN set -eu; \
    truncate -s 1048576 /opt/nexus-fixtures/sector0.raw; \
    dd if=/opt/nexus-fixtures/sector0.txt of=/opt/nexus-fixtures/sector0.raw \
        conv=notrunc status=none; \
    sector_hash=$(dd if=/opt/nexus-fixtures/sector0.raw bs=512 count=1 status=none \
        | sha256sum | cut -d ' ' -f1); \
    test "$sector_hash" = 9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc; \
    echo '27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254  /opt/nexus-fixtures/sector0.raw' \
        | sha256sum -c -; \
    chmod 0444 /opt/nexus-fixtures/sector0.txt /opt/nexus-fixtures/sector0.raw

COPY --from=nexus-root patches/cser-cargo-config.toml \
    /root/.cargo/config.toml
RUN cargo test --manifest-path /opt/nexus-virtio/virtio-drivers-0.13.0/Cargo.toml \
        --lib --no-default-features \
    && rm -rf /opt/nexus-virtio/virtio-drivers-0.13.0/target

# Prime cargo-osdk's real build and generated runner graphs while networking is
# available.  Mounted-workspace checks below run offline and as the host UID.
COPY Cargo.toml Cargo.lock rust-toolchain.toml OSDK.toml /tmp/nexus-inputs/
COPY osdk-runner-base /tmp/nexus-inputs/osdk-runner-base
RUN --mount=type=bind,source=.,target=/tmp/nexus-source,readonly \
    cmp /tmp/nexus-inputs/Cargo.toml /tmp/nexus-source/Cargo.toml \
    && cmp /tmp/nexus-inputs/Cargo.lock /tmp/nexus-source/Cargo.lock \
    && cmp /tmp/nexus-inputs/rust-toolchain.toml /tmp/nexus-source/rust-toolchain.toml \
    && cmp /tmp/nexus-inputs/OSDK.toml /tmp/nexus-source/OSDK.toml \
    && diff -ru /tmp/nexus-inputs/osdk-runner-base /tmp/nexus-source/osdk-runner-base \
    && test ! -e /tmp/nexus-source/patch-work \
    && rm -rf /work \
    && cp -a /tmp/nexus-source /work \
    && mkdir -p /work/target/osdk \
    && cp -a /tmp/nexus-inputs/osdk-runner-base \
        /work/target/osdk/ostd-virtio-cser-spike-run-base \
    && chmod a-w /work/target/osdk/ostd-virtio-cser-spike-run-base/Cargo.lock \
    && cd /work \
    && cargo fmt --all -- --check \
    && cargo fmt --manifest-path /crates/nexus-ostd-virtio/Cargo.toml -- --check \
    && CARGO_TARGET_DIR=/work/target/facade-check \
        cargo check --manifest-path /crates/nexus-ostd-virtio/Cargo.toml \
        --locked --target x86_64-unknown-none \
    && bash scripts/assert-patch.sh \
    && bash scripts/check-facade-boundary.sh \
    && bash scripts/check-io-gate.sh \
    && cargo osdk check --locked \
    && cargo clippy --locked --target x86_64-unknown-none --lib -- \
        -D warnings -A unexpected_cfgs -A clippy::result_large_err \
    && cargo osdk build \
    && cmp /tmp/nexus-inputs/Cargo.lock /work/Cargo.lock \
    && diff -ru /tmp/nexus-inputs/osdk-runner-base \
        /work/target/osdk/ostd-virtio-cser-spike-run-base \
    && rm -rf /work /tmp/nexus-inputs

# The upstream image keeps toolchains and OVMF under mode-0700 /root. Expose
# read/traverse access, but do not duplicate those multi-gigabyte trees.
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
