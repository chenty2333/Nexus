# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

RUN rustup target add --toolchain nightly-2026-04-03 x86_64-unknown-none \
    && cargo install cargo-osdk --version 0.18.0 --locked

# cargo-osdk's -Zbuild-std and generated runner packages have dependencies that
# a plain `cargo fetch --target` does not discover. Prime the real graph while
# the image is built, then make every mounted-workspace invocation offline.
COPY experiments/ostd-cser-spike/Cargo.toml \
    experiments/ostd-cser-spike/Cargo.lock \
    experiments/ostd-cser-spike/rust-toolchain.toml \
    experiments/ostd-cser-spike/OSDK.toml \
    /tmp/ostd-cser-inputs/
COPY experiments/ostd-cser-spike/osdk-runner-base /tmp/ostd-cser-inputs/osdk-runner-base
COPY experiments/ostd-cser-spike/userspace/personality /tmp/ostd-cser-inputs/personality
COPY tests/guest/linux/sources/linux-hello/hello.S /tmp/ostd-cser-inputs/linux-hello.S
RUN --mount=type=bind,source=experiments/ostd-cser-spike,target=/tmp/ostd-cser-source,readonly \
    cmp /tmp/ostd-cser-inputs/Cargo.toml /tmp/ostd-cser-source/Cargo.toml \
    && cmp /tmp/ostd-cser-inputs/Cargo.lock /tmp/ostd-cser-source/Cargo.lock \
    && cmp /tmp/ostd-cser-inputs/rust-toolchain.toml \
        /tmp/ostd-cser-source/rust-toolchain.toml \
    && cmp /tmp/ostd-cser-inputs/OSDK.toml /tmp/ostd-cser-source/OSDK.toml \
    && diff -ru /tmp/ostd-cser-inputs/osdk-runner-base \
        /tmp/ostd-cser-source/osdk-runner-base \
    && diff -ru /tmp/ostd-cser-inputs/personality \
        /tmp/ostd-cser-source/userspace/personality \
    && rm -rf /work \
    && cp -a /tmp/ostd-cser-source /work \
    && mkdir -p /work/target/osdk \
    && cp -a /tmp/ostd-cser-inputs/osdk-runner-base \
        /work/target/osdk/ostd-cser-spike-run-base \
    && cd /work \
    && NEXUS_LINUX_HELLO_SOURCE=/tmp/ostd-cser-inputs/linux-hello.S \
        bash scripts/build-guest.sh \
    && cargo osdk check --locked \
    && cargo osdk build \
    && cmp /tmp/ostd-cser-inputs/Cargo.lock /work/Cargo.lock \
    && diff -ru /tmp/ostd-cser-inputs/osdk-runner-base \
        /work/target/osdk/ostd-cser-spike-run-base \
    && rm -rf /work /tmp/ostd-cser-inputs

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
